//! Connection management for the Deboa HTTP client.
//!
//! This module provides the building blocks for managing HTTP connections,
//! including connection pooling and protocol-specific implementations.
//!
//! # Architecture
//!
//! - [`http`]: Core HTTP protocol implementations (HTTP/1.1, HTTP/2)
//! - [`pool`]: Connection pooling for efficient request handling
//!
//! # Features
//!
//! - Automatic connection pooling
//! - Protocol negotiation (HTTP/1.1, HTTP/2)
//! - Connection lifecycle management
//! - Thread-safe connection handling
//! ```
use crate::cert::{DeboaCertificate, DeboaIdentity};
#[cfg(feature = "native-tls")]
use crate::client::tls;
#[cfg(feature = "rust-tls")]
use crate::client::tls::rustls::tcp::connect as tls_connect;
#[cfg(feature = "http3")]
use crate::client::tls::rustls::udp::connect as quinn_connect;
use crate::rt::stream::TokioStream;
use deboa::request::Http1Request;
#[cfg(feature = "http2")]
use deboa::request::Http2Request;
use deboa::{
    conn::{ConnectionConfig, HttpConnectionDispatcher, ProtoConnection},
    errors::{ConnectionError, DeboaError, RequestError},
    response::DeboaResponse,
    Result,
};
#[cfg(feature = "http3")]
use deboa_h3::generic::Http3Request;
use http::{Request, Version};
use hyper_body_utils::HttpBody;
use std::{error::Error, marker::PhantomData, net::IpAddr, time::Duration};
use tokio::net::TcpStream;

/// Connection pooling for efficient HTTP connections.
///
/// This module provides connection pooling functionality to reuse connections
/// across multiple requests, reducing latency and resource usage.
///
/// # Features
///
/// - Automatic connection reuse
/// - Connection lifecycle management
/// - Thread-safe operation
/// - Configurable pool size (coming soon)
pub mod pool;

pub(crate) type Http1Connection = BaseHttpConnection<Http1Request, HttpBody, HttpBody>;
#[cfg(feature = "http2")]
pub(crate) type Http2Connection = BaseHttpConnection<Http2Request, HttpBody, HttpBody>;
#[cfg(feature = "http3")]
pub(crate) type Http3Connection = BaseHttpConnection<Http3Request, HttpBody, HttpBody>;

/// Enum that represents the connection type.
///
/// # Variants
///
/// * `Http1` - The HTTP/1.1 connection.
/// * `Http2` - The HTTP/2 connection.
/// * `Http3` - The HTTP/3 connection.
pub enum DeboaConnection {
    /// HTTP/1.1 connection.
    Http1(Box<Http1Connection>),
    /// HTTP/2 connection.
    #[cfg(feature = "http2")]
    Http2(Box<Http2Connection>),
    /// HTTP/3 connection.
    #[cfg(feature = "http3")]
    Http3(Box<Http3Connection>),
}

impl DeboaConnection {
    /// Initialize a new HTTP/1.1 connection
    pub fn http1(conn: Http1Connection) -> Self {
        DeboaConnection::Http1(Box::new(conn))
    }

    #[cfg(feature = "http2")]
    /// Initialize a new HTTP/2 connection
    pub fn http2(conn: Http2Connection) -> Self {
        DeboaConnection::Http2(Box::new(conn))
    }

    #[cfg(feature = "http3")]
    /// Initialize a new HTTP/3 connection
    pub fn http3(conn: Http3Connection) -> Self {
        DeboaConnection::Http3(Box::new(conn))
    }

    async fn send(&mut self, request: Request<HttpBody>) -> Result<DeboaResponse> {
        match self {
            DeboaConnection::Http1(ref mut conn) => {
                let (parts, body) = conn
                    .sender
                    .send_request(request)
                    .await
                    .map_err(|e| {
                        println!("Error: {:?}", e.source());
                        DeboaError::Request(RequestError::Send { message: e.to_string() })
                    })?
                    .into_parts();

                Ok(DeboaResponse::new(http::Response::from_parts(parts, HttpBody::incoming(body))))
            }
            #[cfg(feature = "http2")]
            DeboaConnection::Http2(ref mut conn) => {
                let (parts, body) = conn
                    .sender
                    .send_request(request)
                    .await
                    .map_err(|e| {
                        DeboaError::Request(RequestError::Send { message: e.to_string() })
                    })?
                    .into_parts();

                Ok(DeboaResponse::new(http::Response::from_parts(parts, HttpBody::incoming(body))))
            }
            #[cfg(feature = "http3")]
            DeboaConnection::Http3(ref mut conn) => {
                let response = conn
                    .sender
                    .send_request(request)
                    .await
                    .map_err(|e| {
                        DeboaError::Request(RequestError::Send { message: e.to_string() })
                    })?;

                Ok(DeboaResponse::new(response))
            }
            #[allow(unreachable_patterns, clippy::needless_return)]
            _ => {
                return Err(DeboaError::UnsupportedProtocol);
            }
        }
    }
}

impl HttpConnectionDispatcher for DeboaConnection {
    /// Send a request over the connection.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to send the request to.
    /// * `request` - The request to send.
    ///
    /// # Returns
    ///
    /// * `Result<DeboaResponse>` - The response or error.
    async fn send_request(
        &mut self,
        request: Request<HttpBody>,
        timeout: Duration,
    ) -> Result<DeboaResponse> {
        tokio::time::timeout(timeout, self.send(request))
            .await
            .map_err(|_| {
                DeboaError::Request(RequestError::Send { message: "Request timed out".to_string() })
            })?
    }
}

/// Struct that represents the connection.
///
/// # Fields
///
/// * `sender` - The sender to use.
pub struct BaseHttpConnection<Sender, ReqBody, ResBody> {
    pub(crate) sender: Sender,
    pub(crate) req_body: PhantomData<ReqBody>,
    pub(crate) res_body: PhantomData<ResBody>,
}

impl<Sender, ReqBody, ResBody> BaseHttpConnection<Sender, ReqBody, ResBody> {
    pub(crate) fn new(sender: Sender) -> Self {
        Self { sender, req_body: PhantomData, res_body: PhantomData }
    }
}

async fn create_connection<'a>(
    ip: &IpAddr,
    config: &ConnectionConfig<'a, DeboaIdentity, DeboaCertificate>,
) -> Result<DeboaConnection> {
    match config.scheme() {
        "http" | "ws" => create_plain_connection(ip, config).await,
        "https" | "wss" => create_secure_connection(ip, config).await,
        &_ => {
            panic!("Scheme not supported")
        }
    }
}

// TODO: For now leave here, as I don't have plans to make more reusable than this
pub(crate) async fn plain_stream_connect<'a>(ip: &IpAddr, port: u16) -> Result<TcpStream> {
    let stream = TcpStream::connect(format!("{}:{}", ip, port))
        .await
        .map_err(|e| DeboaError::Connection(ConnectionError::Tcp { message: e.to_string() }))?;

    Ok(stream)
}

/// Create a new plain connection.
pub async fn create_plain_connection<'a>(
    ip: &IpAddr,
    config: &'a ConnectionConfig<'a, DeboaIdentity, DeboaCertificate>,
) -> Result<DeboaConnection> {
    let stream = TokioStream::Plain(plain_stream_connect(ip, config.port()).await?);
    let conn = if !config.prior_knowledge() {
        DeboaConnection::http1(Http1Connection::connect(stream).await?)
    } else {
        match *config.protocol_version() {
            Version::HTTP_11 => DeboaConnection::http1(Http1Connection::connect(stream).await?),
            #[cfg(feature = "http2")]
            Version::HTTP_2 => DeboaConnection::http2(Http2Connection::connect(stream).await?),
            _ => {
                return Err(DeboaError::UnsupportedProtocol);
            }
        }
    };

    Ok(conn)
}

// TODO: NativeTls is the açternative SecureConnection implementation which can be provided to client
#[cfg(feature = "native-tls")]
/// Create a new connection..into()
pub async fn create_secure_connection<'a>(
    ip: &IpAddr,
    config: &'a ConnectionConfig<'a, DeboaIdentity, DeboaCertificate>,
) -> Result<DeboaConnection> {
    let tls_stream = tls::native::connect(*ip, config).await?;
    let conn = if !config.prior_knowledge() {
        // TODO: Restore Native TLS support
        DeboaConnection::http1(Http1Connection::connect(tls_stream).await?)
    } else {
        match *config.protocol_version() {
            Version::HTTP_11 => DeboaConnection::http1(Http1Connection::connect(tls_stream).await?),
            #[cfg(feature = "http2")]
            Version::HTTP_2 => DeboaConnection::http2(Http2Connection::connect(tls_stream).await?),
            _ => {
                return Err(DeboaError::UnsupportedProtocol);
            }
        }
    };

    Ok(conn)
}

// TODO: Rustls is the default SecureConnection implementation, but no ALPN handling
#[cfg(feature = "rust-tls")]
/// Create a new connection.
pub async fn create_secure_connection<'a>(
    ip: &IpAddr,
    config: &'a ConnectionConfig<'a, DeboaIdentity, DeboaCertificate>,
) -> Result<DeboaConnection> {
    let conn = if !config.prior_knowledge() {
        DeboaConnection::http1(Http1Connection::connect(tls_connect(ip, config).await?).await?)
    } else {
        match *config.protocol_version() {
            Version::HTTP_11 => DeboaConnection::http1(
                Http1Connection::connect(tls_connect(ip, config).await?).await?,
            ),
            #[cfg(feature = "http2")]
            Version::HTTP_2 => DeboaConnection::http2(
                Http2Connection::connect(tls_connect(ip, config).await?).await?,
            ),
            #[cfg(feature = "http3")]
            Version::HTTP_3 => DeboaConnection::http3(
                Http3Connection::connect(quinn_connect(ip, config).await?).await?,
            ),
            _ => {
                return Err(DeboaError::UnsupportedProtocol);
            }
        }
    };

    Ok(conn)
}
