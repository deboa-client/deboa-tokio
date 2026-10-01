//! TLS implementation using rustls
use crate::cert::{DeboaCertificate, DeboaIdentity};
use deboa::{
    errors::{ConnectionError, DeboaError},
    Result,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ClientConfig,
};
use std::sync::Arc;

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
    /// Set identity to use with connection
    pub fn identity(mut self, identity: Option<&'a DeboaIdentity>) -> Self {
        self.identity = identity;
        self
    }

    /// Set certificate to use with connection
    pub fn certificate(mut self, certificate: Option<&'a DeboaCertificate>) -> Self {
        self.certificate = certificate;
        self
    }

    /// Skip server verification
    pub fn skip_server_verification(mut self, skip_server_verification: bool) -> Self {
        self.skip_server_verification = skip_server_verification;
        self
    }

    /// Set the ALPN protocols this client has support to
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

/// TCP connection module for TLS
pub mod tcp {
    use crate::{
        cert::{DeboaCertificate, DeboaIdentity},
        client::{http::conn::plain_stream_connect, tls::rustls::TlsConnectionBuilder},
        rt::stream::TokioStream,
    };
    use deboa::{
        conn::ConnectionConfig,
        errors::{ConnectionError, DeboaError},
        Result,
    };
    use rustls_pki_types::ServerName;
    use std::{net::IpAddr, sync::Arc};
    use tokio_rustls::TlsConnector;

    /// Connect to a TCP TLS stream
    pub async fn connect<'a>(
        ip: &IpAddr,
        config: &'a ConnectionConfig<'a, DeboaIdentity, DeboaCertificate>,
    ) -> Result<TokioStream> {
        let tcp_stream = plain_stream_connect(ip, config.port()).await?;

        let tls_config = TlsConnectionBuilder::default()
            .certificate(config.certificate())
            .identity(config.identity())
            .build_config()?;

        let connector = TlsConnector::from(Arc::new(tls_config));

        let hostname = ServerName::try_from(
            config
                .host()
                .to_string(),
        )
        .map_err(|e| DeboaError::Connection(ConnectionError::Tls { message: e.to_string() }))?;

        let tls_stream = connector
            .connect(hostname, tcp_stream)
            .await
            .map_err(|e| {
                DeboaError::Connection(ConnectionError::Tls {
                    message: format!("Could not connect to server: {}", e),
                })
            })?;

        Ok(TokioStream::Tls(Box::new(tls_stream)))
    }
}

#[cfg(feature = "http3")]
/// UDP connection module for TLS
pub mod udp {
    use crate::{
        cert::{DeboaCertificate, DeboaIdentity},
        client::tls::rustls::TlsConnectionBuilder,
    };
    use deboa::{
        conn::ConnectionConfig,
        errors::{ConnectionError, DeboaError},
        Result,
    };
    use h3_quinn::Connection;
    use quinn::crypto::rustls::QuicClientConfig;
    use quinn::Endpoint;
    use std::{
        net::{IpAddr, SocketAddr},
        sync::Arc,
    };

    /// Connect to a Quic TLS stream
    pub async fn connect<'a>(
        ip: &IpAddr,
        config: &'a ConnectionConfig<'a, DeboaIdentity, DeboaCertificate>,
    ) -> Result<Connection> {
        let mut endpoint = Endpoint::client(SocketAddr::new(*config.client_bind_addr(), 0))
            .map_err(|e| DeboaError::Connection(ConnectionError::Udp { message: e.to_string() }))?;

        let tls_config = TlsConnectionBuilder::default()
            .certificate(config.certificate())
            .identity(config.identity())
            .build_config()?;

        let quic_config = QuicClientConfig::try_from(tls_config).map_err(|e| {
            DeboaError::Connection(ConnectionError::Tls {
                message: format!("Could not create QUIC client config: {}", e),
            })
        })?;

        let client_config = quinn::ClientConfig::new(Arc::new(quic_config));
        endpoint.set_default_client_config(client_config);

        let conn = endpoint
            .connect(SocketAddr::new(*ip, config.port()), config.host())
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
