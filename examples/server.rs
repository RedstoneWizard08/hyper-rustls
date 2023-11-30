//! Simple HTTPS echo service based on hyper-rustls
//!
//! First parameter is the mandatory port to use.
//! Certificate and private key are hardcoded to sample files.
//! hyper will automatically use HTTP/2 if a client starts talking HTTP/2,
//! otherwise HTTP/1.1 will be used.

#![cfg(feature = "acceptor")]

use std::net::SocketAddr;
use std::vec::Vec;
use std::{env, fs, io};

use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_rustls::TlsAcceptor;
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder;
use tokio::net::TcpListener;

fn main() {
    // Serve an echo service over HTTPS, with proper error handling.
    if let Err(e) = run_server() {
        eprintln!("FAILED: {}", e);
        std::process::exit(1);
    }
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

#[tokio::main]
async fn run_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // First parameter is port number (optional, defaults to 1337)
    let port = match env::args().nth(1) {
        Some(ref p) => p.to_owned(),
        None => "1337".to_owned(),
    };
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse()?;

    // Load public certificate.
    let certs = load_certs("examples/sample.pem")?;
    // Load private key.
    let key = load_private_key("examples/sample.rsa")?;
    // Build TLS configuration.

    // Create a TCP listener via tokio.
    let incoming = TcpListener::bind(&addr).await?;
    let mut acceptor = TlsAcceptor::builder()
        .with_single_cert(certs, key)
        .map_err(|e| error(format!("{}", e)))?
        .with_all_versions_alpn()
        .with_incoming(incoming);

    let service = service_fn(echo);

    loop {
        let (tcp_stream, _remote_addr) = acceptor.accept().await.unwrap();
        if let Err(err) = Builder::new(TokioExecutor::new())
            .serve_connection(tcp_stream, service)
            .await
        {
            eprintln!("failed to serve connection: {err:#}");
        }
    }
}

// Custom echo service, handling two different routes and a
// catch-all 404 responder.
async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let mut response = Response::new(Full::default());
    match (req.method(), req.uri().path()) {
        // Help route.
        (&Method::GET, "/") => {
            *response.body_mut() = Full::from("Try POST /echo\n");
        }
        // Echo service route.
        (&Method::POST, "/echo") => {
            *response.body_mut() = Full::from(
                req.into_body()
                    .collect()
                    .await?
                    .to_bytes(),
            );
        }
        // Catch-all 404.
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    };
    Ok(response)
}

// Load public certificate from file.
fn load_certs(filename: &str) -> io::Result<Vec<rustls::Certificate>> {
    // Open certificate file.
    let certfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificate.
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|_| error("failed to load certificate".into()))?;
    Ok(certs
        .into_iter()
        .map(rustls::Certificate)
        .collect())
}

// Load private key from file.
fn load_private_key(filename: &str) -> io::Result<rustls::PrivateKey> {
    // Open keyfile.
    let keyfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);

    // Load and return a single private key.
    let keys = rustls_pemfile::rsa_private_keys(&mut reader)
        .map_err(|_| error("failed to load private key".into()))?;
    if keys.len() != 1 {
        return Err(error("expected a single private key".into()));
    }

    Ok(rustls::PrivateKey(keys[0].clone()))
}
