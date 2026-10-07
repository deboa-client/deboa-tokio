use crate::client::http::conn::{BaseHttpConnection, Http3Connection};
use deboa::{
    conn::{HttpConnection, ProtoConnection},
    errors::{ConnectionError, DeboaError},
    Result,
};
use deboa_h3::generic::{Http3Request, SendRequest};
use futures::future;
use h3_quinn::Connection;
use http::version::Version;

impl HttpConnection for Http3Connection {
    type Sender = Http3Request;
    fn sender(&mut self) -> &mut Self::Sender {
        &mut self.sender
    }
}

impl ProtoConnection for Http3Connection {
    type Connection = Http3Connection;
    type RuntimeStream = Connection;

    #[inline]
    fn protocol_version(&self) -> Version {
        Version::HTTP_3
    }

    async fn connect(conn: Self::RuntimeStream) -> Result<Self::Connection> {
        let (mut conn, sender) = h3::client::new(conn)
            .await
            .map_err(|e| DeboaError::Connection(ConnectionError::Udp { message: e.to_string() }))?;

        let handle = tokio::spawn(async move {
            let error = future::poll_fn(|cx| conn.poll_close(cx)).await;
            if !error.is_h3_no_error() {
                return Err(DeboaError::Connection(ConnectionError::Udp {
                    message: error.to_string(),
                }));
            }
            Ok(())
        });

        Ok(BaseHttpConnection::new(SendRequest::new(sender), handle))
    }
}
