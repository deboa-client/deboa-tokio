//! Deboa HTTP client modules.
//!
//! This module provides DNS resolution, HTTP, TCP, and TLS transport functionality for the Deboa HTTP client.

mod dns;
mod http;
mod tls;

pub use dns::DefaultDnsResolver;
pub use http::conn::DeboaConnection::*;
pub use http::conn::pool::HttpConnectionPool;
