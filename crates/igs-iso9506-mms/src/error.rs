// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Errors of the client crate.

use std::fmt;

use igs_iso9506_mms_link::config::ConfigError;
use igs_iso9506_mms_link::transport::Cause;

/// Why a transport connection could not be opened, or stopped.
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
    /// The protocol layer reported an event it cannot take: a bug of the driver.
    Misuse(&'static str),
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
