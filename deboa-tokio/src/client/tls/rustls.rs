//! TLS implementation using rustls

use std::{borrow::Cow, net::IpAddr, sync::Arc};

use crate::{
    cert::{DeboaCertificate, DeboaIdentity},
    client::http::conn::TcpStreamFactory,
};
use deboa::{
    conn::ConnectionConfig,
    errors::{ConnectionError, DeboaError},
    Result,
};
use http::Version;
use log::info;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ClientConfig,
};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

pub(crate) struct RustlsStreamFactory {}

impl RustlsStreamFactory {
    pub async fn connect<'a>(
        ip: &IpAddr,
        port: u16,
        config: &'a ConnectionConfig<'a, DeboaIdentity, DeboaCertificate>,
    ) -> Result<TlsStream<TcpStream>> {
        let tcp_stream = TcpStreamFactory::connect(ip, port).await?;
        connect_with_rustls(tcp_stream, config).await
    }
}

/// Builder for TLS connections using rustls
pub struct TlsConnectionBuilder<'a> {
    identity: Option<&'a DeboaIdentity>,
    certificate: Option<&'a DeboaCertificate>,
    skip_server_verification: bool,
    alpn: Vec<Vec<u8>>,
}

impl Default for TlsConnectionBuilder<'_> {
    fn default() -> Self {
        Self {
            identity: None,
            certificate: None,
            skip_server_verification: false,
            alpn: Vec::new(),
        }
    }
}

impl<'a> TlsConnectionBuilder<'a> {
    /// Set the identity to use for the connection
    pub fn identity(mut self, identity: Option<&'a DeboaIdentity>) -> Self {
        self.identity = identity;
        self
    }

    /// Set the certificate to use for the connection
    pub fn certificate(mut self, certificate: Option<&'a DeboaCertificate>) -> Self {
        self.certificate = certificate;
        self
    }

    /// Skip server verification
    pub fn skip_server_verification(mut self, skip_server_verification: bool) -> Self {
        self.skip_server_verification = skip_server_verification;
        self
    }

    /// Set the ALPN protocols to use for the connection
    pub fn alpn(mut self, alpn: Vec<Vec<u8>>) -> Self {
        self.alpn = alpn;
        self
    }

    /// Build the TLS client configuration
    pub fn build_config(self) -> Result<ClientConfig> {
        let client_config = {
            if self.skip_server_verification {
                ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(
                        deboa_tls::rustls::verify::SkipServerVerification::default(),
                    ))
                    .with_no_client_auth()
            } else {
                // TODO: Add support to ECH

                #[cfg(feature = "__webpki_rustls_verifier")]
                let config = {
                    let config = ClientConfig::builder_with_protocol_versions(rustls::ALL_VERSIONS);

                    let mut root_store =
                        rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
                    let config = if let Some(ca) = self.certificate {
                        let cert = ca
                            .try_into()
                            .map_err(|e| {
                                DeboaError::Connection(ConnectionError::Tls {
                                    message: format!("Invalid CA certificate: {}", e),
                                })
                            })?;

                        root_store
                            .add(cert)
                            .map_err(|e| {
                                DeboaError::Connection(ConnectionError::Tls {
                                    message: format!(
                                        "Could not add CA certificate to the store: {}",
                                        e
                                    ),
                                })
                            })?;

                        config.with_root_certificates(root_store)
                    } else {
                        config.with_root_certificates(root_store)
                    };

                    config
                };

                #[cfg(feature = "__platform_rustls_verifier")]
                let config = {
                    use rustls_platform_verifier::BuilderVerifierExt;
                    rustls::ClientConfig::builder_with_protocol_versions(rustls::ALL_VERSIONS)
                        .with_platform_verifier()
                        .map_err(|e| {
                            DeboaError::Connection(ConnectionError::Tls {
                                message: format!("Failed to load platform verifier: {}", e),
                            })
                        })?
                };

                let mut config = if let Some(id) = self.identity {
                    let pair: (CertificateDer<'_>, PrivateKeyDer<'_>) = id
                        .try_into()
                        .map_err(|e| {
                            DeboaError::Connection(ConnectionError::Tls {
                                message: format!("Invalid client identity: {}", e),
                            })
                        })?;

                    config
                        .with_client_auth_cert(vec![pair.0], pair.1)
                        .map_err(|e| {
                            DeboaError::Connection(ConnectionError::Tls {
                                message: format!("Failed to set client identity: {}", e),
                            })
                        })?
                } else {
                    config.with_no_client_auth()
                };

                config.enable_early_data = true;

                config.alpn_protocols = self.alpn;

                config
            }
        };

        Ok(client_config)
    }
}

/// Create a TlsStream out of TcpStream
pub async fn connect_with_rustls<'a>(
    tcp_stream: TcpStream,
    config: &ConnectionConfig<'a, DeboaIdentity, DeboaCertificate>,
) -> Result<TlsStream<TcpStream>> {
    use crate::client::tls::rustls::{tcp::connect, TlsConnectionBuilder};
    let tls_config = TlsConnectionBuilder::default()
        .certificate(config.certificate())
        .identity(config.identity())
        .build_config()?;

    let stream = connect(tls_config, tcp_stream, config.host()).await?;

    if let Some(alpn) = stream
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
        Ok(stream)
    } else {
        info!("No ALPN info available, falling back to HTTP/1.1");
        Ok(stream)
    }
}

/// TCP connection module for TLS
pub mod tcp {
    use deboa::{
        errors::{ConnectionError, DeboaError},
        Result,
    };
    use rustls::ClientConfig;
    use rustls_pki_types::ServerName;
    use std::sync::Arc;
    use tokio::net::TcpStream;
    use tokio_rustls::{client::TlsStream, TlsConnector};

    /// Establish a TLS connection over TCP
    pub async fn connect(
        config: ClientConfig,
        inner_stream: TcpStream,
        host: &str,
    ) -> Result<TlsStream<TcpStream>> {
        let connector = TlsConnector::from(Arc::new(config));

        let hostname = ServerName::try_from(host.to_string())
            .map_err(|e| DeboaError::Connection(ConnectionError::Tls { message: e.to_string() }))?;

        connector
            .connect(hostname, inner_stream)
            .await
            .map_err(|e| {
                DeboaError::Connection(ConnectionError::Tls {
                    message: format!("Could not connect to server: {}", e),
                })
            })
    }
}

#[cfg(feature = "http3")]
/// UDP connection module for TLS
pub mod udp {
    use deboa::{
        errors::{ConnectionError, DeboaError},
        Result,
    };
    use h3_quinn::Connection;
    use quinn::{crypto::rustls::QuicClientConfig, Endpoint};
    use rustls::ClientConfig;
    use std::{net::SocketAddr, sync::Arc};

    /// Establish a TLS connection over UDP
    pub async fn connect(
        config: ClientConfig,
        endpoint: &mut Endpoint,
        socket_addr: SocketAddr,
        host: &str,
    ) -> Result<Connection> {
        let quic_config = QuicClientConfig::try_from(config).map_err(|e| {
            DeboaError::Connection(ConnectionError::Tls {
                message: format!("Could not create QUIC client config: {}", e),
            })
        })?;

        let client_config = quinn::ClientConfig::new(Arc::new(quic_config));
        endpoint.set_default_client_config(client_config);

        let conn = endpoint
            .connect(socket_addr, host)
            .map_err(|e| {
                DeboaError::Connection(ConnectionError::Udp {
                    message: format!("Could not connect to server: {}", e),
                })
            })?;

        let conn = conn
            .await
            .map_err(|e| {
                DeboaError::Connection(ConnectionError::Udp {
                    message: format!("Could not connect to server: {}", e),
                })
            })?;

        let quinn_conn = h3_quinn::Connection::new(conn);

        Ok(quinn_conn)
    }
}
