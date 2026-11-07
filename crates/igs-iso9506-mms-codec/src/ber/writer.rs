// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Writing encodings: definite lengths in the fewest octets, primitive strings.

use super::{Charset, Error, Identifier};
use crate::schema::{BitString, ObjectIdentifier, TagClass};

/// Builds BER encodings in a growing buffer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Writer {
    out: Vec<u8>,
}

fn significant(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b != 0) {
        Some(start) => bytes.get(start..).unwrap_or(bytes),
        None => bytes.get(bytes.len().saturating_sub(1)..).unwrap_or(bytes),
    }
}

impl Writer {
    /// An empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// The octets written so far.
    pub fn as_bytes(&self) -> &[u8] {
        &self.out
    }

    /// The octets written.
    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }

    fn identifier(&mut self, id: Identifier) {
        let class = match id.class {
            TagClass::Universal => 0x00,
            TagClass::Application => 0x40,
            TagClass::Context => 0x80,
            TagClass::Private => 0xC0,
        };
        let form = if id.constructed { 0x20 } else { 0x00 };
        if let Ok(low @ 0..=30) = u8::try_from(id.number) {
            self.out.push(class | form | low);
            return;
        }
        self.out.push(class | form | 0x1F);
        // Base 128, most significant group first, bit 8 set on all but the last (§8.1.2.4.2).
        let mut groups = [0u8; 5];
        let mut count = 0usize;
        let mut number = id.number;
        for slot in groups.iter_mut().rev() {
            *slot = (number & 0x7F) as u8;
            number >>= 7;
            count = count.saturating_add(1);
            if number == 0 {
                break;
            }
        }
        let start = groups.len().saturating_sub(count);
        let groups = groups.get(start..).unwrap_or(&[]);
        let last = groups.len().saturating_sub(1);
        for (index, group) in groups.iter().enumerate() {
            self.out
                .push(if index == last { *group } else { group | 0x80 });
        }
    }

    fn length(&mut self, length: usize) {
        if let Ok(short @ 0..=127) = u8::try_from(length) {
            self.out.push(short);
            return;
        }
        let bytes = length.to_be_bytes();
        let bytes = significant(&bytes);
        self.out.push(0x80 | (bytes.len() as u8));
        self.out.extend_from_slice(bytes);
    }

    /// A primitive encoding with the given contents.
    pub fn primitive(&mut self, id: Identifier, contents: &[u8]) {
        self.identifier(id.with_constructed(false));
        self.length(contents.len());
        self.out.extend_from_slice(contents);
    }

    /// A constructed encoding whose contents `body` writes.
    pub fn constructed<E>(
        &mut self,
        id: Identifier,
        body: impl FnOnce(&mut Writer) -> Result<(), E>,
    ) -> Result<(), E> {
        let mut inner = Writer::new();
        body(&mut inner)?;
        self.identifier(id.with_constructed(true));
        self.length(inner.out.len());
        self.out.extend_from_slice(&inner.out);
        Ok(())
    }

    /// Octets already encoded, such as a value kept as raw BER.
    pub fn raw(&mut self, encoded: &[u8]) {
        self.out.extend_from_slice(encoded);
    }

    /// BOOLEAN; true is written as 0xFF, as X.690 §11.1 requires of DER.
    pub fn boolean(&mut self, id: Identifier, value: bool) {
        self.primitive(id, &[if value { 0xFF } else { 0x00 }]);
    }

    /// INTEGER in the fewest octets (§8.3.2).
    pub fn integer(&mut self, id: Identifier, value: i64) {
        let bytes = value.to_be_bytes();
        let mut start = 0usize;
        while let (Some(&a), Some(&b)) = (bytes.get(start), bytes.get(start.saturating_add(1))) {
            let redundant = (a == 0x00 && b & 0x80 == 0) || (a == 0xFF && b & 0x80 != 0);
            if !redundant {
                break;
            }
            start = start.saturating_add(1);
        }
        self.primitive(id, bytes.get(start..).unwrap_or(&bytes));
    }

    /// A non-negative INTEGER from a `u64`, with a leading zero octet when needed for the sign.
    pub fn unsigned(&mut self, id: Identifier, value: u64) {
        let bytes = value.to_be_bytes();
        let magnitude = significant(&bytes);
        if magnitude.first().is_some_and(|b| b & 0x80 != 0) {
            let mut contents = Vec::with_capacity(magnitude.len().saturating_add(1));
            contents.push(0);
            contents.extend_from_slice(magnitude);
            self.primitive(id, &contents);
        } else {
            self.primitive(id, magnitude);
        }
    }

    /// ENUMERATED, written as an INTEGER.
    pub fn enumerated(&mut self, id: Identifier, value: i64) {
        self.integer(id, value);
    }

    /// NULL.
    pub fn null(&mut self, id: Identifier) {
        self.primitive(id, &[]);
    }

    /// BIT STRING, primitive.
    pub fn bit_string(&mut self, id: Identifier, value: &BitString) -> Result<(), Error> {
        if value.unused > 7 || (value.bytes.is_empty() && value.unused != 0) {
            return Err(Error::InvalidBitString);
        }
        let mut contents = Vec::with_capacity(value.bytes.len().saturating_add(1));
        contents.push(value.unused);
        contents.extend_from_slice(&value.bytes);
        self.primitive(id, &contents);
        Ok(())
    }

    /// OCTET STRING, primitive.
    pub fn octet_string(&mut self, id: Identifier, value: &[u8]) {
        self.primitive(id, value);
    }

    /// A restricted character string, primitive, after checking its character set.
    pub fn string(&mut self, id: Identifier, value: &str, charset: Charset) -> Result<(), Error> {
        if !charset.accepts(value) {
            return Err(Error::InvalidCharacter);
        }
        self.primitive(id, value.as_bytes());
        Ok(())
    }

    /// OBJECT IDENTIFIER (§8.19): at least two components, the first at most 2, the second below
    /// 40 when the first is 0 or 1.
    pub fn object_identifier(
        &mut self,
        id: Identifier,
        value: &ObjectIdentifier,
    ) -> Result<(), Error> {
        let (first, second, rest) = match value.0.as_slice() {
            [first, second, rest @ ..] => (*first, *second, rest),
            _ => return Err(Error::InvalidObjectIdentifier),
        };
        if first > 2 || (first < 2 && second >= 40) {
            return Err(Error::InvalidObjectIdentifier);
        }
        let packed = first
            .checked_mul(40)
            .and_then(|v| v.checked_add(second))
            .ok_or(Error::InvalidObjectIdentifier)?;
        let mut contents = Vec::new();
        for arc in std::iter::once(packed).chain(rest.iter().copied()) {
            let mut groups = [0u8; 10];
            let mut count = 0usize;
            let mut v = arc;
            for slot in groups.iter_mut().rev() {
                *slot = (v & 0x7F) as u8;
                v >>= 7;
                count = count.saturating_add(1);
                if v == 0 {
                    break;
                }
            }
            let start = groups.len().saturating_sub(count);
            let groups = groups.get(start..).unwrap_or(&[]);
            let last = groups.len().saturating_sub(1);
            for (index, group) in groups.iter().enumerate() {
                contents.push(if index == last { *group } else { group | 0x80 });
            }
        }
        self.primitive(id, &contents);
        Ok(())
    }
}
