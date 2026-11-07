// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The rustls backend of the TLS profile (task X1). It offers TLS 1.2 and TLS 1.3, with the cipher suites
//! of the ring provider, and it checks the certificates of the peers against the trust anchors and the
//! revocation lists (clauses 6.4.1, 6.4.4).
//!
//! The backend needs revocation lists: without one, a revoked certificate would be accepted, and the profile
//! requires the revocation check (clause 6.4.4.4). The lists are those of the settings; their expiry is
//! checked by rustls-webpki.

use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::ServerName;
use rustls::server::WebPkiClientVerifier;
use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, RootCertStore, ServerConfig, SupportedProtocolVersion};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::settings::TlsSettings;
use super::{Handshake, SecureStream, TlsBackend, TlsError};

/// The protocol versions of the profile: TLS 1.2, mandatory, and TLS 1.3, optional (clause 10.3, Table 7).
const VERSIONS: [&SupportedProtocolVersion; 2] = [&TLS12, &TLS13];

/// The client and server configurations of one endpoint, built from its settings.
pub struct RustlsBackend {
    client: Arc<ClientConfig>,
    server: Option<Arc<ServerConfig>>,
}

impl RustlsBackend {
    /// Builds the configurations. Fails when the settings have no trust anchor, or no revocation list
    /// (clause 6.4.4.4), or when the provider cannot provide the versions.
    pub fn new(settings: &TlsSettings) -> Result<Self, TlsError> {
        if settings.revocation().is_empty() {
            return Err(TlsError::Invalid(
                "no revocation list: the revocation of the certificates cannot be checked (clause 6.4.4.4)"
                    .to_string(),
            ));
        }
        let provider = Arc::new(default_provider());
        let roots = roots(settings)?;
        let crls = settings.revocation().to_vec();

        let server_verifier =
            WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone())
                .with_crls(crls.clone())
                .build()
                .map_err(|error| TlsError::Invalid(format!("server certificate check: {error}")))?;
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&VERSIONS)
            .map_err(|error| TlsError::Invalid(error.to_string()))?
            .with_webpki_verifier(server_verifier);
        let client = match settings.identity() {
            Some(identity) => builder
                .with_client_auth_cert(identity.certificates().to_vec(), identity.key())
                .map_err(|error| TlsError::Identity(error.to_string()))?,
            None => builder.with_no_client_auth(),
        };

        let server = match settings.identity() {
            Some(identity) => {
                let client_verifier =
                    WebPkiClientVerifier::builder_with_provider(roots, provider.clone())
                        .with_crls(crls)
                        .build()
                        .map_err(|error| {
                            TlsError::Invalid(format!("client certificate check: {error}"))
                        })?;
                let config = ServerConfig::builder_with_provider(provider)
                    .with_protocol_versions(&VERSIONS)
                    .map_err(|error| TlsError::Invalid(error.to_string()))?
                    .with_client_cert_verifier(client_verifier)
                    .with_single_cert(identity.certificates().to_vec(), identity.key())
                    .map_err(|error| TlsError::Identity(error.to_string()))?;
                Some(Arc::new(config))
            }
            None => None,
        };
        Ok(Self {
            client: Arc::new(client),
            server,
        })
    }
}

fn roots(settings: &TlsSettings) -> Result<Arc<RootCertStore>, TlsError> {
    let mut store = RootCertStore::empty();
    for certificate in settings.trust().certificates() {
        store
            .add(certificate.clone())
            .map_err(|error| TlsError::Identity(format!("trust anchor: {error}")))?;
    }
    Ok(Arc::new(store))
}

impl TlsBackend for RustlsBackend {
    fn connect<'a>(&'a self, tcp: TcpStream, host: &'a str) -> Handshake<'a> {
        Box::pin(async move {
            let name = ServerName::try_from(host.to_string())
                .map_err(|error| TlsError::Invalid(format!("server name {host}: {error}")))?;
            let stream = TlsConnector::from(Arc::clone(&self.client))
                .connect(name, tcp)
                .await
                .map_err(|error| TlsError::Handshake(error.to_string()))?;
            Ok(SecureStream::Client(stream))
        })
    }

    fn accept<'a>(&'a self, tcp: TcpStream) -> Handshake<'a> {
        Box::pin(async move {
            let server = self.server.as_ref().ok_or_else(|| {
                TlsError::Invalid(
                    "this endpoint has no certificate of its own to act as a server".to_string(),
                )
            })?;
            let stream = TlsAcceptor::from(Arc::clone(server))
                .accept(tcp)
                .await
                .map_err(|error| TlsError::Handshake(error.to_string()))?;
            Ok(SecureStream::Server(stream))
        })
    }
}
