use core::task::{Context, Poll};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::{future::Future, net::SocketAddr};

use futures_util::ready;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::rt::TokioIo;
use rustls::{ServerConfig, ServerConnection};
use tokio::net::TcpListener;
use tokio::net::TcpStream;

mod builder;
pub use builder::AcceptorBuilder;
use builder::WantsTlsConfig;

/// A TLS acceptor that can be used with hyper servers.
pub struct TlsAcceptor<L = TcpListener> {
    config: Arc<ServerConfig>,
    listener: L,
}

/// An Acceptor for the `https` scheme.
impl TlsAcceptor {
    /// Provides a builder for a `TlsAcceptor`.
    pub fn builder() -> AcceptorBuilder<WantsTlsConfig> {
        AcceptorBuilder::new()
    }

    /// Creates a new `TlsAcceptor` from a `ServerConfig` and an `TcpListener`.
    pub fn new(config: Arc<ServerConfig>, listener: TcpListener) -> Self {
        Self { config, listener }
    }

    /// Accepts a new connection.
    pub async fn accept(&mut self) -> Result<(TlsStream, SocketAddr), io::Error> {
        let (sock, addr) = self.listener.accept().await?;
        Ok((
            TlsStream::new(TokioIo::new(sock), self.config.clone()),
            addr,
        ))
    }
}

impl<C, L> From<(C, L)> for TlsAcceptor
where
    C: Into<Arc<ServerConfig>>,
    L: Into<TcpListener>,
{
    fn from((config, listener): (C, L)) -> Self {
        Self::new(config.into(), listener.into())
    }
}

/// A TLS stream constructed by a [`TlsAcceptor`].
// tokio_rustls::server::TlsStream doesn't expose constructor methods,
// so we have to TlsAcceptor::accept and handshake to have access to it
// TlsStream implements AsyncRead/AsyncWrite by handshaking with tokio_rustls::Accept first
pub struct TlsStream<C = TokioIo<TcpStream>> {
    state: State<C>,
}

impl<C: Read + Write + Unpin> TlsStream<C> {
    fn new(stream: C, config: Arc<ServerConfig>) -> Self {
        let accept = tokio_rustls::TlsAcceptor::from(config).accept(TokioIo::new(stream));
        Self {
            state: State::Handshaking(accept),
        }
    }
    /// Returns a reference to the underlying IO stream.
    ///
    /// This should always return `Some`, except if an error has already been yielded.
    pub fn io(&self) -> Option<&C> {
        match &self.state {
            State::Handshaking(accept) => accept.get_ref().map(TokioIo::inner),
            State::Streaming(stream) => Some(stream.inner().get_ref().0.inner()),
        }
    }

    /// Returns a reference to the underlying [`rustls::ServerConnection'].
    ///
    /// This will start yielding `Some` only after the handshake has completed.
    pub fn connection(&self) -> Option<&ServerConnection> {
        match &self.state {
            State::Handshaking(_) => None,
            State::Streaming(stream) => Some(stream.inner().get_ref().1),
        }
    }
}

impl<C: Read + Write + Unpin> Read for TlsStream<C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let pin = self.get_mut();
        let accept = match &mut pin.state {
            State::Handshaking(accept) => accept,
            State::Streaming(stream) => return Pin::new(stream).poll_read(cx, buf),
        };

        let mut stream = match ready!(Pin::new(accept).poll(cx)) {
            Ok(stream) => TokioIo::new(stream),
            Err(err) => return Poll::Ready(Err(err)),
        };

        let result = Pin::new(&mut stream).poll_read(cx, buf);
        pin.state = State::Streaming(stream);
        result
    }
}

impl<C: Read + Write + Unpin> Write for TlsStream<C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let pin = self.get_mut();
        let accept = match &mut pin.state {
            State::Handshaking(accept) => accept,
            State::Streaming(stream) => return Pin::new(stream).poll_write(cx, buf),
        };

        let mut stream = match ready!(Pin::new(accept).poll(cx)) {
            Ok(stream) => TokioIo::new(stream),
            Err(err) => return Poll::Ready(Err(err)),
        };

        let result = Pin::new(&mut stream).poll_write(cx, buf);
        pin.state = State::Streaming(stream);
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

enum State<C> {
    Handshaking(tokio_rustls::Accept<TokioIo<C>>),
    Streaming(TokioIo<tokio_rustls::server::TlsStream<TokioIo<C>>>),
}
