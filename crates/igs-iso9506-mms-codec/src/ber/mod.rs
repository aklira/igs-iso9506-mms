// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Basic Encoding Rules, the subset of ITU-T X.690 §8 that the stack needs.
//!
//! Decoding accepts what a BER sender may choose: long or short length forms, the indefinite form
//! for constructed encodings, constructed strings. Encoding always uses the definite form with the
//! fewest length octets, and primitive strings. Nesting is bounded by [`Reader::with_max_depth`](crate::ber::Reader::with_max_depth).

mod error;
mod reader;
mod value;
mod writer;

pub use error::Error;
pub use reader::{Element, Reader, DEFAULT_MAX_DEPTH};
pub use value::{
    bit_string, boolean, enumerated, integer_bytes, integer_i64, integer_u64, null,
    object_identifier, octet_string, string, Charset,
};
pub use writer::Writer;

use crate::schema::TagClass;

/// The identifier octets of an encoding: class, form and tag number (X.690 §8.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identifier {
    /// Class of the tag.
    pub class: TagClass,
    /// Constructed (true) or primitive (false) encoding.
    pub constructed: bool,
    /// Tag number.
    pub number: u32,
}

impl Identifier {
    /// An identifier.
    pub const fn new(class: TagClass, constructed: bool, number: u32) -> Self {
        Self {
            class,
            constructed,
            number,
        }
    }

    /// A primitive universal identifier.
    pub const fn universal(number: u32) -> Self {
        Self::new(TagClass::Universal, false, number)
    }

    /// A context-specific identifier.
    pub const fn context(number: u32, constructed: bool) -> Self {
        Self::new(TagClass::Context, constructed, number)
    }

    /// An application identifier.
    pub const fn application(number: u32, constructed: bool) -> Self {
        Self::new(TagClass::Application, constructed, number)
    }

    /// The same tag with the given form.
    pub const fn with_constructed(self, constructed: bool) -> Self {
        Self::new(self.class, constructed, self.number)
    }

    /// End-of-contents (X.690 §8.1.5).
    pub const END_OF_CONTENTS: Self = Self::universal(0);
    /// BOOLEAN.
    pub const BOOLEAN: Self = Self::universal(1);
    /// INTEGER.
    pub const INTEGER: Self = Self::universal(2);
    /// BIT STRING, primitive.
    pub const BIT_STRING: Self = Self::universal(3);
    /// OCTET STRING, primitive.
    pub const OCTET_STRING: Self = Self::universal(4);
    /// NULL.
    pub const NULL: Self = Self::universal(5);
    /// OBJECT IDENTIFIER.
    pub const OBJECT_IDENTIFIER: Self = Self::universal(6);
    /// EXTERNAL, constructed.
    pub const EXTERNAL: Self = Self::new(TagClass::Universal, true, 8);
    /// ENUMERATED.
    pub const ENUMERATED: Self = Self::universal(10);
    /// UTF8String, primitive.
    pub const UTF8_STRING: Self = Self::universal(12);
    /// SEQUENCE and SEQUENCE OF, constructed.
    pub const SEQUENCE: Self = Self::new(TagClass::Universal, true, 16);
    /// SET and SET OF, constructed.
    pub const SET: Self = Self::new(TagClass::Universal, true, 17);
    /// GeneralizedTime, primitive.
    pub const GENERALIZED_TIME: Self = Self::universal(24);
    /// GraphicString, primitive.
    pub const GRAPHIC_STRING: Self = Self::universal(25);
    /// VisibleString, primitive.
    pub const VISIBLE_STRING: Self = Self::universal(26);
}
