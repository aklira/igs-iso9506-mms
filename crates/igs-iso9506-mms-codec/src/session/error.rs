// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Errors of SPDU decoding and encoding.

use std::fmt;

/// Why an SPDU or a TSDU was refused. Clauses are those of ITU-T X.225.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The TSDU ends inside an SPDU header or parameter field.
    Truncated,
    /// A length indicator larger than the space left (§8.2.5).
    Length,
    /// SPDUs combined in a way §6.3.7 does not allow, or an empty TSDU.
    Concatenation,
    /// Octets after an SPDU that has no user information field.
    TrailingData,
    /// A mandatory parameter is absent (§8.3).
    MissingParameter(u8),
    /// A parameter with a length or value that its definition does not allow.
    InvalidParameter(u8),
    /// A value too long to encode.
    TooLong,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "SPDU truncated"),
            Self::Length => write!(f, "SPDU length indicator too large"),
            Self::Concatenation => write!(f, "invalid concatenation of SPDUs"),
            Self::TrailingData => write!(f, "octets after the SPDU"),
            Self::MissingParameter(code) => write!(f, "mandatory parameter {code} absent"),
            Self::InvalidParameter(code) => write!(f, "invalid parameter {code}"),
            Self::TooLong => write!(f, "value too long for an SPDU"),
        }
    }
}

impl std::error::Error for Error {}
