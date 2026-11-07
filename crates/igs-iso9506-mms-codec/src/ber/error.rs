// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Errors of BER decoding and encoding.

use std::fmt;

use super::Identifier;

/// Why a BER encoding was refused. Clauses are those of ITU-T X.690.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input ends inside an identifier, a length or the contents.
    Truncated,
    /// The tag number does not fit in 32 bits.
    TagNumberTooLarge,
    /// A tag number with redundant octets, or below 31 in the high-tag form (§8.1.2.4).
    NonMinimalTagNumber,
    /// The length octet reserved for future use (§8.1.3.5 c).
    ReservedLength,
    /// A length that does not fit in memory addresses.
    LengthTooLarge,
    /// The indefinite length on a primitive encoding (§8.1.3.2 a).
    IndefinitePrimitive,
    /// End-of-contents where no indefinite length is open, or with contents (§8.1.5).
    UnexpectedEndOfContents,
    /// An indefinite length without its end-of-contents (§8.1.3.6.2).
    MissingEndOfContents,
    /// Deeper nesting than the reader accepts.
    DepthExceeded {
        /// The limit of the reader.
        limit: usize,
    },
    /// Octets after the last expected encoding.
    TrailingData,
    /// Another identifier than the one expected.
    UnexpectedIdentifier {
        /// What the caller expected.
        expected: Identifier,
        /// What the input holds.
        found: Identifier,
    },
    /// A primitive encoding where a constructed one is required, or the reverse.
    WrongForm,
    /// A BOOLEAN whose contents are not one octet (§8.2.1).
    InvalidBoolean,
    /// An INTEGER with no contents or with redundant leading octets (§8.3.1, §8.3.2).
    InvalidInteger,
    /// An INTEGER outside the range of the requested Rust type.
    IntegerOutOfRange,
    /// A malformed BIT STRING (§8.6.2, §8.6.4).
    InvalidBitString,
    /// A NULL with contents (§8.8.2).
    InvalidNull,
    /// A malformed or unencodable OBJECT IDENTIFIER (§8.19).
    InvalidObjectIdentifier,
    /// A character outside the character set of the string type.
    InvalidCharacter,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "BER encoding truncated"),
            Self::TagNumberTooLarge => write!(f, "tag number too large"),
            Self::NonMinimalTagNumber => write!(f, "tag number not in its shortest form"),
            Self::ReservedLength => write!(f, "reserved length octet"),
            Self::LengthTooLarge => write!(f, "length too large"),
            Self::IndefinitePrimitive => write!(f, "indefinite length on a primitive encoding"),
            Self::UnexpectedEndOfContents => write!(f, "unexpected end-of-contents"),
            Self::MissingEndOfContents => write!(f, "missing end-of-contents"),
            Self::DepthExceeded { limit } => write!(f, "nesting deeper than {limit}"),
            Self::TrailingData => write!(f, "trailing octets"),
            Self::UnexpectedIdentifier { expected, found } => {
                write!(f, "expected {expected:?}, found {found:?}")
            }
            Self::WrongForm => write!(f, "wrong primitive or constructed form"),
            Self::InvalidBoolean => write!(f, "invalid BOOLEAN"),
            Self::InvalidInteger => write!(f, "invalid INTEGER"),
            Self::IntegerOutOfRange => write!(f, "INTEGER out of range"),
            Self::InvalidBitString => write!(f, "invalid BIT STRING"),
            Self::InvalidNull => write!(f, "invalid NULL"),
            Self::InvalidObjectIdentifier => write!(f, "invalid OBJECT IDENTIFIER"),
            Self::InvalidCharacter => write!(f, "character outside the string type"),
        }
    }
}

impl std::error::Error for Error {}
