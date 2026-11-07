// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Errors of PPDU decoding and encoding.

use std::fmt;

use crate::ber;

/// Why a PPDU was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The BER encoding is malformed.
    Ber(ber::Error),
    /// A mandatory component is absent.
    Missing(&'static str),
    /// A component that the type does not define, outside a CP PPDU (X.226 §8.5).
    Unexpected(ber::Identifier),
    /// A number or bit with no name assigned, outside a CP PPDU (§8.5.2), or another invalid value.
    InvalidValue(&'static str),
}

impl From<ber::Error> for Error {
    fn from(error: ber::Error) -> Self {
        Self::Ber(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ber(e) => write!(f, "{e}"),
            Self::Missing(what) => write!(f, "{what} absent"),
            Self::Unexpected(id) => write!(f, "unexpected component {id:?}"),
            Self::InvalidValue(what) => write!(f, "invalid {what}"),
        }
    }
}

impl std::error::Error for Error {}
