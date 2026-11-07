// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The identity, the trust anchors and the revocation lists of a TLS endpoint, read from PEM.

use std::fmt;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};

use super::TlsError;

/// The certificate chain and the private key of an endpoint. The key is not shown by `Debug`.
pub struct Identity {
    certificates: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl Identity {
    /// Reads the certificate chain (PEM) and the private key (PEM, PKCS#8, PKCS#1 or SEC1).
    pub fn from_pem(certificates: &[u8], key: &[u8]) -> Result<Self, TlsError> {
        let certificates = CertificateDer::pem_slice_iter(certificates)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| TlsError::Identity(format!("certificate: {error}")))?;
        if certificates.is_empty() {
            return Err(TlsError::Identity("no certificate in the PEM".to_string()));
        }
        let key = PrivateKeyDer::from_pem_slice(key)
            .map_err(|error| TlsError::Identity(format!("private key: {error}")))?;
        Ok(Self { certificates, key })
    }

    pub(crate) fn certificates(&self) -> &[CertificateDer<'static>] {
        &self.certificates
    }

    pub(crate) fn key(&self) -> PrivateKeyDer<'static> {
        self.key.clone_key()
    }
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Self {
            certificates: self.certificates.clone(),
            key: self.key.clone_key(),
        }
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Identity({} certificates, key not shown)",
            self.certificates.len()
        )
    }
}

/// The trust anchors: the roots whose certificates the peers' certificates must chain to. The profile
/// requires at least five of them (clause 6.4.1); the count is not checked here.
#[derive(Clone, Debug)]
pub struct TrustAnchors(Vec<CertificateDer<'static>>);

impl TrustAnchors {
    /// Reads the trust anchors from PEM: one or more certificates.
    pub fn from_pem(bytes: &[u8]) -> Result<Self, TlsError> {
        let roots = CertificateDer::pem_slice_iter(bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| TlsError::Identity(format!("trust anchor: {error}")))?;
        if roots.is_empty() {
            return Err(TlsError::Identity("no trust anchor in the PEM".to_string()));
        }
        Ok(Self(roots))
    }

    pub(crate) fn certificates(&self) -> &[CertificateDer<'static>] {
        &self.0
    }
}

/// Reads revocation lists (CRL) from PEM.
pub fn revocation_from_pem(
    bytes: &[u8],
) -> Result<Vec<CertificateRevocationListDer<'static>>, TlsError> {
    CertificateRevocationListDer::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| TlsError::Identity(format!("revocation list: {error}")))
}

/// The settings of one TLS endpoint: its identity (needed to act as a server, and as a client that is
/// authenticated), the trust anchors, and the revocation lists.
#[derive(Clone, Debug)]
pub struct TlsSettings {
    identity: Option<Identity>,
    trust: TrustAnchors,
    revocation: Vec<CertificateRevocationListDer<'static>>,
}

impl TlsSettings {
    /// Settings with an identity (`Some`), or without one: a client that is not authenticated cannot
    /// be accepted by a server that requires its certificate.
    pub fn new(identity: Option<Identity>, trust: TrustAnchors) -> Self {
        Self {
            identity,
            trust,
            revocation: Vec::new(),
        }
    }

    /// The revocation lists that the peers' certificates are checked against.
    pub fn with_revocation(mut self, lists: Vec<CertificateRevocationListDer<'static>>) -> Self {
        self.revocation = lists;
        self
    }

    pub(crate) fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }

    pub(crate) fn trust(&self) -> &TrustAnchors {
        &self.trust
    }

    pub(crate) fn revocation(&self) -> &[CertificateRevocationListDer<'static>] {
        &self.revocation
    }
}
