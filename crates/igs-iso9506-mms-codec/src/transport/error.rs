// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Errors of TPKT framing and TPDU decoding.

use std::fmt;

/// Why a TPKT or a TPDU was refused.
///
/// TPDU errors carry the offset, from the length indicator, of the octet that caused them, so
/// that the connection can quote the header up to that octet in an ER TPDU (X.224 §13.12.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A TPKT version other than 3 (RFC 1006).
    TpktVersion(u8),
    /// A TPKT length below 7 or above the limit of the decoder.
    TpktLength(usize),
    /// A TPDU larger than a TPKT can carry, on encoding.
    TpduTooLong(usize),
    /// The TPDU ends inside its header.
    Truncated,
    /// A length indicator of 255, below the fixed part, or not below the TPDU size (§13.2.1).
    HeaderLength {
        /// Offset of the octet in fault.
        offset: usize,
    },
    /// A TPDU code that class 0 does not use (§13.1), or a DT TPDU with ROA set.
    InvalidTpduType {
        /// The code octet.
        code: u8,
    },
    /// A parameter code not defined for this TPDU (§13.2.3).
    InvalidParameterCode {
        /// Offset of the octet in fault.
        offset: usize,
    },
    /// A parameter whose length or value is not valid.
    InvalidParameterValue {
        /// Offset of the octet in fault.
        offset: usize,
    },
}

impl Error {
    /// The reject cause of an ER TPDU for this error (X.224 §13.12.3), when there is one.
    pub fn reject_cause(&self) -> Option<u8> {
        match self {
            Self::InvalidParameterCode { .. } => Some(super::reject_cause::INVALID_PARAMETER_CODE),
            Self::InvalidTpduType { .. } => Some(super::reject_cause::INVALID_TPDU_TYPE),
            Self::InvalidParameterValue { .. } => {
                Some(super::reject_cause::INVALID_PARAMETER_VALUE)
            }
            Self::HeaderLength { .. } | Self::Truncated => Some(super::reject_cause::NOT_SPECIFIED),
            Self::TpktVersion(_) | Self::TpktLength(_) | Self::TpduTooLong(_) => None,
        }
    }

    /// Offset of the octet in fault within the TPDU, when known.
    pub fn offset(&self) -> Option<usize> {
        match self {
            Self::HeaderLength { offset }
            | Self::InvalidParameterCode { offset }
            | Self::InvalidParameterValue { offset } => Some(*offset),
            Self::InvalidTpduType { .. } => Some(1),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TpktVersion(v) => write!(f, "TPKT version {v}"),
            Self::TpktLength(n) => write!(f, "TPKT length {n}"),
            Self::TpduTooLong(n) => write!(f, "TPDU of {n} octets too long for a TPKT"),
            Self::Truncated => write!(f, "TPDU truncated"),
            Self::HeaderLength { offset } => {
                write!(f, "invalid TPDU header length at octet {offset}")
            }
            Self::InvalidTpduType { code } => write!(f, "invalid TPDU type 0x{code:02X}"),
            Self::InvalidParameterCode { offset } => {
                write!(f, "invalid parameter code at octet {offset}")
            }
            Self::InvalidParameterValue { offset } => {
                write!(f, "invalid parameter value at octet {offset}")
            }
        }
    }
}

impl std::error::Error for Error {}
