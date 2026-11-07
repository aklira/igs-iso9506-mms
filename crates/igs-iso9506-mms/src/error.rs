// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Errors of the client crate.

use std::fmt;

use igs_iso9506_mms_codec::mms::{RejectPDURejectReason, ServiceError};
use igs_iso9506_mms_link::association::Refusal;
use igs_iso9506_mms_link::config::ConfigError;
use igs_iso9506_mms_link::transport::Cause;

/// Why a transport connection, an association or a request failed, or stopped.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The byte stream failed.
    Io(std::io::Error),
    /// The configuration is not valid.
    Config(ConfigError),
    /// The connection was not established within the connect timeout.
    ConnectTimeout,
    /// The transport connection was closed, for this cause.
    Closed(Cause),
    /// The peer closed the byte stream.
    PeerClosed,
    /// The driver has stopped. The reason is returned by [`crate::Transport::shutdown`].
    Stopped,
    /// The protocol layer reported an event it cannot take: a bug of the driver, or a request the
    /// negotiation does not allow.
    Misuse(&'static str),
    /// The association was refused, by the peer or by the provider.
    Refused(Refusal),
    /// The peer answered the request with an error.
    Service(ServiceError),
    /// The peer rejected the request, with this reason (a Reject PDU).
    Rejected(RejectPDURejectReason),
    /// No answer came within the request timeout, or the association was not established in time.
    Timeout,
    /// The connection ended before the request was answered.
    ConnectionLost,
    /// The client is closed, or was closed while the request waited.
    ClientClosed,
    /// The peer answered the request with the response of another service.
    Unexpected,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "the stream failed: {error}"),
            Self::Config(error) => write!(f, "invalid configuration: {error}"),
            Self::ConnectTimeout => write!(f, "the connection was not established in time"),
            Self::Closed(cause) => write!(f, "the transport connection was closed: {cause:?}"),
            Self::PeerClosed => write!(f, "the peer closed the stream"),
            Self::Stopped => write!(f, "the connection driver has stopped"),
            Self::Misuse(message) => write!(f, "a protocol layer refused an event: {message}"),
            Self::Refused(refusal) => write!(f, "the association was refused: {refusal:?}"),
            Self::Service(error) => write!(f, "the peer answered with an error: {error:?}"),
            Self::Rejected(reason) => write!(f, "the peer rejected the request: {reason:?}"),
            Self::Timeout => write!(f, "no answer within the timeout"),
            Self::ConnectionLost => write!(f, "the connection ended before the answer"),
            Self::ClientClosed => write!(f, "the client is closed"),
            Self::Unexpected => write!(f, "the peer answered with another service"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Config(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ConfigError> for Error {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}
