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
#[cfg(feature = "rust-tls")]
use crate::client::tls::rustls::RustlsStreamFactory;
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
use log::info;
use std::{borrow::Cow, error::Error, marker::PhantomData, net::IpAddr, time::Duration};
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

                Ok(DeboaResponse::new(http::Response::from_parts(
                    parts,
                    HttpBody::from_incoming(body),
                )))
            }
            #[cfg(feature = "http2")]
            DeboaConnection::Http2(ref mut conn) => {
                println!("Request: {:?}", request.version());
                let (parts, body) = conn
                    .sender
                    .send_request(request)
                    .await
                    .map_err(|e| {
                        DeboaError::Request(RequestError::Send { message: e.to_string() })
                    })?
                    .into_parts();

                Ok(DeboaResponse::new(http::Response::from_parts(
                    parts,
                    HttpBody::from_incoming(body),
                )))
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

pub(crate) struct TcpStreamSelector {}

impl TcpStreamSelector {
    pub async fn connect<'a>(
        ip: &IpAddr,
        config: &ConnectionConfig<'a, DeboaIdentity, DeboaCertificate>,
    ) -> Result<TokioStream> {
        let stream = match config.scheme() {
            "http" | "ws" => {
                let tcp_stream = TcpStream::connect(format!("{}:{}", ip, config.port()))
                    .await
                    .map_err(|e| {
                        DeboaError::Connection(ConnectionError::Tcp { message: e.to_string() })
                    })?;
                TokioStream::Plain(tcp_stream)
            }
            "https" | "wss" => TokioStream::Tls(Box::new(
                RustlsStreamFactory::connect(ip, config.port(), config).await?,
            )),
            &_ => {
                panic!("Scheme not supported")
            }
        };

        Ok(stream)
    }
}

pub(crate) struct TcpStreamFactory {}

impl TcpStreamFactory {
    pub async fn connect<'a>(ip: &IpAddr, port: u16) -> Result<TcpStream> {
        let stream = TcpStream::connect(format!("{}:{}", ip, port))
            .await
            .map_err(|e| DeboaError::Connection(ConnectionError::Tcp { message: e.to_string() }))?;

        Ok(stream)
    }
}

/// Factory for creating connections.
pub(crate) struct ConnectionFactory {}

impl ConnectionFactory {
    /// Create a new connection.
    pub async fn create_connection<'a>(
        config: &'a ConnectionConfig<'a, DeboaIdentity, DeboaCertificate>,
        ip: &IpAddr,
    ) -> Result<DeboaConnection> {
        let conn = if !config.prior_knowledge() {
            match config.scheme() {
                "http" | "ws" => {
                    let stream =
                        TokioStream::Plain(TcpStreamFactory::connect(ip, config.port()).await?);
                    let conn = Http1Connection::connect(stream).await?;
                    DeboaConnection::http1(conn)
                }
                "https" | "wss" => {
                    let tls_stream =
                        RustlsStreamFactory::connect(ip, config.port(), config).await?;

                    if let Some(alpn) = tls_stream
                        .get_ref()
                        .1
                        .alpn_protocol()
                    {
                        let Cow::Borrowed(alpn_code) = String::from_utf8_lossy(alpn) else {
                            return Err(DeboaError::Connection(ConnectionError::Tcp {
                                message: "Invalid ALPN code".to_string(),
                            }));
                        };

                        let version: Version = deboa::Alpn::new(alpn_code).into();
                        info!("ALPN info found, switching connection to {:?}", version);
                        match version {
                            Version::HTTP_11 | Version::HTTP_3 => {
                                let conn = Http1Connection::connect(TokioStream::Tls(Box::new(
                                    tls_stream,
                                )))
                                .await?;
                                DeboaConnection::http1(conn)
                            }
                            #[cfg(feature = "http2")]
                            Version::HTTP_2 => {
                                let conn = Http2Connection::connect(TokioStream::Tls(Box::new(
                                    tls_stream,
                                )))
                                .await?;
                                DeboaConnection::http2(conn)
                            }
                            _ => {
                                return Err(DeboaError::UnsupportedProtocol);
                            }
                        }
                    } else {
                        info!("No ALPN info available, falling back to HTTP/1.1");
                        let conn = Http1Connection::connect(TokioStream::Tls(Box::new(tls_stream)))
                            .await?;
                        DeboaConnection::http1(conn)
                    }
                }
                &_ => {
                    panic!("Scheme not supported")
                }
            }
        } else {
            match *config.protocol_version() {
                Version::HTTP_11 => {
                    let stream = TcpStreamSelector::connect(ip, config).await?;
                    let conn = Http1Connection::connect(stream).await?;
                    DeboaConnection::http1(conn)
                }
                #[cfg(feature = "http2")]
                Version::HTTP_2 => {
                    let stream = TcpStreamSelector::connect(ip, config).await?;
                    let conn = Http2Connection::connect(stream).await?;
                    DeboaConnection::http2(conn)
                }
                #[cfg(all(feature = "http3", feature = "rust-tls"))]
                Version::HTTP_3 => {
                    let stream = {
                        use crate::client::tls::rustls::{udp::connect, TlsConnectionBuilder};
                        use quinn::Endpoint;
                        use std::net::SocketAddr;

                        let mut client_endpoint =
                            Endpoint::client(SocketAddr::new(*config.client_bind_addr(), 0))
                                .map_err(|e| {
                                    DeboaError::Connection(ConnectionError::Udp {
                                        message: e.to_string(),
                                    })
                                })?;

                        let tls_config = TlsConnectionBuilder::default()
                            .certificate(config.certificate())
                            .identity(config.identity())
                            .build_config()?;

                        connect(
                            tls_config,
                            &mut client_endpoint,
                            SocketAddr::new(*ip, config.port()),
                            config.host(),
                        )
                        .await?
                    };
                    let conn = Http3Connection::connect(stream).await?;
                    DeboaConnection::http3(conn)
                }
                _ => {
                    return Err(DeboaError::UnsupportedProtocol);
                }
            }
        };

        Ok(conn)
    }
}
