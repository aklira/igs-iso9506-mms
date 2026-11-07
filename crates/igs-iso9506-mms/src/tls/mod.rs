// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! TLS for MMS over TCP, as IEC 62351-3 profiles it (task X1, decision D-030).
//!
//! A [`TlsBackend`] secures the TCP connections of a client or a server: it runs the handshake, and yields
//! a [`SecureStream`], which the transport of task T1 runs over. The rustls backend ([`RustlsBackend`]) is
//! the one provided. The mutual authentication of the profile is required: the server asks for the client's
//! certificate, and the client checks the server's (clause 6.4.3). The revocation of the certificates is
//! checked against the revocation lists of the settings (clause 6.4.4.4).
//!
//! Not implemented here: the security events of IEC 62351-3 Annex A (decision D-030, gap G16), and the
//! cipher suites that the rustls provider lacks (gap G17), recorded in `docs/capabilities.md`.

mod rustls_backend;
mod settings;

use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::ProtocolVersion;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{client, server};

use crate::connector::Connector;
use crate::error::Error;

pub use rustls_backend::RustlsBackend;
pub use settings::{revocation_from_pem, Identity, TlsSettings, TrustAnchors};

/// A TLS failure: the settings, the certificates, or the handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    /// The settings break a rule of the profile, or name something the backend lacks.
    Invalid(String),
    /// A certificate, a key or a revocation list could not be read or used.
    Identity(String),
    /// The handshake failed: the peer refused, or a certificate did not check out.
    Handshake(String),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(why) => write!(f, "invalid TLS settings: {why}"),
            Self::Identity(why) => write!(f, "TLS identity: {why}"),
            Self::Handshake(why) => write!(f, "the TLS handshake failed: {why}"),
        }
    }
}

impl std::error::Error for TlsError {}

/// A handshake that a backend runs: it yields the secured stream.
pub type Handshake<'a> = Pin<Box<dyn Future<Output = Result<SecureStream, TlsError>> + Send + 'a>>;

/// A TLS implementation of the profile. Object-safe, so that a configuration can hold any backend.
pub trait TlsBackend: Send + Sync {
    /// Secures an outgoing connection. The server certificate must name `host`, a DNS name or an IP
    /// address.
    fn connect<'a>(&'a self, tcp: TcpStream, host: &'a str) -> Handshake<'a>;

    /// Secures an accepted connection. The client certificate is required (clause 6.4.3).
    fn accept<'a>(&'a self, tcp: TcpStream) -> Handshake<'a>;
}

/// A TLS backend, shared by the configurations of a client and a server.
#[derive(Clone)]
pub struct Secure(Arc<dyn TlsBackend>);

impl Secure {
    /// Wraps a backend.
    pub fn new(backend: impl TlsBackend + 'static) -> Self {
        Self(Arc::new(backend))
    }

    /// The backend.
    pub fn backend(&self) -> &dyn TlsBackend {
        self.0.as_ref()
    }
}

impl fmt::Debug for Secure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secure(TLS backend)")
    }
}

/// A stream secured by TLS: a client's or a server's end of the connection.
#[derive(Debug)]
pub enum SecureStream {
    /// The client end.
    Client(client::TlsStream<TcpStream>),
    /// The server end.
    Server(server::TlsStream<TcpStream>),
}

impl SecureStream {
    /// The TLS version that was negotiated, once the handshake has completed: `TLSv1.3` or `TLSv1.2`.
    pub fn protocol_version(&self) -> Option<&'static str> {
        let version = match self {
            Self::Client(stream) => stream.get_ref().1.protocol_version(),
            Self::Server(stream) => stream.get_ref().1.protocol_version(),
        };
        match version? {
            ProtocolVersion::TLSv1_3 => Some("TLSv1.3"),
            ProtocolVersion::TLSv1_2 => Some("TLSv1.2"),
            _ => Some("other"),
        }
    }
}

impl AsyncRead for SecureStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Client(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Server(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for SecureStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Client(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Server(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Client(stream) => Pin::new(stream).poll_flush(cx),
            Self::Server(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Client(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Server(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Connects over TCP to `address` and secures the connection for `host`, within the timeout: the
/// connector of the client (task T2), for a TLS station.
#[derive(Clone)]
pub struct SecureConnector {
    address: String,
    host: String,
    backend: Secure,
    timeout: Duration,
}

impl SecureConnector {
    /// A connector for `address`, whose server certificate names `host`.
    pub fn new(
        address: impl Into<String>,
        host: impl Into<String>,
        backend: Secure,
        timeout: Duration,
    ) -> Self {
        Self {
            address: address.into(),
            host: host.into(),
            backend,
            timeout,
        }
    }
}

impl Connector for SecureConnector {
    type Stream = SecureStream;

    fn connect(&mut self) -> impl Future<Output = Result<SecureStream, Error>> + Send {
        let address = self.address.clone();
        let host = self.host.clone();
        let backend = self.backend.clone();
        let limit = self.timeout;
        async move {
            let tcp = timeout(limit, TcpStream::connect(&address))
                .await
                .map_err(|_| Error::ConnectTimeout)?
                .map_err(Error::Io)?;
            tcp.set_nodelay(true).map_err(Error::Io)?;
            timeout(limit, backend.backend().connect(tcp, &host))
                .await
                .map_err(|_| Error::ConnectTimeout)?
                .map_err(Error::Tls)
        }
    }
}
