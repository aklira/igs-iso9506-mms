// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Where the client gets its byte streams: a connector opens one stream per connection, so that the
//! client can reconnect (task T2). TCP is the usual one; tests use an in-memory loopback.

use std::future::Future;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::error::Error;
use crate::transport::ByteStream;

/// Opens a byte stream to the peer, for each connection the client makes.
pub trait Connector: Send + 'static {
    /// The stream of one connection.
    type Stream: ByteStream;

    /// Opens a stream to the peer.
    fn connect(&mut self) -> impl Future<Output = Result<Self::Stream, Error>> + Send;
}

/// Connects over TCP to `address`, within `timeout`, with `TCP_NODELAY` set.
#[derive(Debug, Clone)]
pub struct TcpConnector {
    address: String,
    timeout: Duration,
}

impl TcpConnector {
    /// A connector for `address`, such as `"172.31.102.10:102"`.
    pub fn new(address: impl Into<String>, timeout: Duration) -> Self {
        Self {
            address: address.into(),
            timeout,
        }
    }
}

impl Connector for TcpConnector {
    type Stream = TcpStream;

    fn connect(&mut self) -> impl Future<Output = Result<TcpStream, Error>> + Send {
        let address = self.address.clone();
        let limit = self.timeout;
        async move {
            let stream = timeout(limit, TcpStream::connect(address))
                .await
                .map_err(|_| Error::ConnectTimeout)??;
            stream.set_nodelay(true)?;
            Ok(stream)
        }
    }
}
