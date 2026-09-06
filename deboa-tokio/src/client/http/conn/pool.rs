use crate::{
    cert::{DeboaCertificate, DeboaIdentity},
    client::http::conn::{ConnectionConfig, ConnectionFactory, DeboaConnection},
};
use deboa::{
    dns::DnsResolver,
    errors::{ConnectionError, DeboaError, RequestError},
    Result,
};
use hashbrown::HashMap;
use std::time::Duration;

/// A HttoConnectionPool builder for easy pool creation
pub struct HttpConnectionPoolBuilder {
    max_idle_connections: u32,
    keep_alive_duration: Duration,
}

impl HttpConnectionPoolBuilder {
    /// Set max idle connections
    pub fn max_idle_connections(mut self, max_idle_connections: u32) -> Self {
        self.max_idle_connections = max_idle_connections;
        self
    }

    /// Set keep alive duration
    pub fn keep_alive_duration(mut self, keep_alive_duration: Duration) -> Self {
        self.keep_alive_duration = keep_alive_duration;
        self
    }

    /// Build http connection pool
    pub fn build(self) -> HttpConnectionPool {
        HttpConnectionPool {
            max_idle_connections: self.max_idle_connections,
            keep_alive_duration: self.keep_alive_duration,
            connections: HashMap::new(),
        }
    }
}

/// Struct that represents the HTTP connection pool.
///
/// # Fields
///
/// * `connections` - The connections.
pub struct HttpConnectionPool {
    max_idle_connections: u32,
    keep_alive_duration: Duration,
    connections: HashMap<String, DeboaConnection>,
}

impl AsMut<HttpConnectionPool> for HttpConnectionPool {
    fn as_mut(&mut self) -> &mut HttpConnectionPool {
        self
    }
}

impl Default for HttpConnectionPool {
    fn default() -> Self {
        Self {
            max_idle_connections: 5,
            keep_alive_duration: Duration::from_mins(5),
            connections: HashMap::new(),
        }
    }
}

impl HttpConnectionPool {
    /// Create a new HttpConnectionPool builder
    pub fn builder() -> HttpConnectionPoolBuilder {
        HttpConnectionPoolBuilder {
            max_idle_connections: 5,
            keep_alive_duration: Duration::from_mins(5),
        }
    }

    /// Allow read max idle connections
    ///
    /// # Arguments
    ///
    /// * `u32` - The max idle connections.
    ///
    pub fn max_idle_connections(&self) -> u32 {
        self.max_idle_connections
    }

    /// Allow read keep alive duration
    ///
    /// # Arguments
    ///
    /// * `Durantion` - The keep alive duration.
    ///
    pub fn keep_alive_duration(&self) -> Duration {
        self.keep_alive_duration
    }
}

impl deboa::conn::HttpConnectionPool for HttpConnectionPool {
    type Identity = DeboaIdentity;
    type Certificate = DeboaCertificate;
    type ConnectionDispather = DeboaConnection;
    type ConnectionCache = HashMap<String, DeboaConnection>;

    #[inline]
    fn connections(&self) -> &Self::ConnectionCache {
        &self.connections
    }

    #[inline]
    fn connection_count(&self) -> u32 {
        self.connections
            .len() as u32
    }

    async fn create_connection<'a, D>(
        &mut self,
        config: &ConnectionConfig<'a, Self::Identity, Self::Certificate>,
        dns_resolver: &D,
    ) -> Result<&mut DeboaConnection>
    where
        D: DnsResolver,
    {
        let key = format!("{}:{}", config.host(), config.port());
        if self
            .connections
            .contains_key(&key)
        {
            log::debug!("Connection already exists for {}, reusing.", key);
            return Ok(self
                .connections
                .get_mut(&key)
                .unwrap());
        }

        log::debug!("Creating new connection for {}", key);
        let ips = dns_resolver
            .resolve(
                config
                    .host()
                    .to_string(),
                config.port(),
            )
            .await?;
        let ips = if config
            .client_bind_addr()
            .is_ipv4()
        {
            ips.into_iter()
                .filter(|ip| ip.is_ipv4())
                .collect::<Vec<_>>()
        } else {
            ips.into_iter()
                .filter(|ip| ip.is_ipv6())
                .collect::<Vec<_>>()
        };

        let Some(ip) = ips.first() else {
            return Err(DeboaError::Request(RequestError::Send {
                message: format!("No IP addresses found for hostname: {}", config.host()),
            }));
        };

        let connection = tokio::time::timeout(
            config.connection_timeout(),
            ConnectionFactory::create_connection(config, ip),
        )
        .await
        .map_err(|_| {
            DeboaError::Connection(ConnectionError::Timeout {
                message: format!(
                    "Connection to {} timed out after {:?}",
                    key,
                    config.connection_timeout()
                ),
            })
        })??;

        self.connections
            .insert(key.clone(), connection);

        Ok(self
            .connections
            .get_mut(&key)
            .unwrap())
    }
}
