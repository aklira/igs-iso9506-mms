// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Contents octets of the primitive types (X.690 §8.2 to §8.8, §8.19, §8.23).
//!
//! Each function reads an element whatever its tag, so that implicitly tagged values decode too;
//! the caller checks the identifier.

use super::{Element, Error, Identifier};
use crate::schema::{BitString, ObjectIdentifier};

fn primitive<'a>(element: &Element<'a>) -> Result<&'a [u8], Error> {
    if element.identifier.constructed {
        Err(Error::WrongForm)
    } else {
        Ok(element.contents)
    }
}

/// BOOLEAN (§8.2): one octet, any non-zero value is true.
pub fn boolean(element: &Element<'_>) -> Result<bool, Error> {
    match primitive(element)? {
        [octet] => Ok(*octet != 0),
        _ => Err(Error::InvalidBoolean),
    }
}

/// INTEGER contents (§8.3), checked: at least one octet and no redundant leading octet.
pub fn integer_bytes<'a>(element: &Element<'a>) -> Result<&'a [u8], Error> {
    let contents = primitive(element)?;
    match contents {
        [] => Err(Error::InvalidInteger),
        [0x00, second, ..] if second & 0x80 == 0 => Err(Error::InvalidInteger),
        [0xFF, second, ..] if second & 0x80 != 0 => Err(Error::InvalidInteger),
        _ => Ok(contents),
    }
}

/// INTEGER (§8.3) as an `i64`.
pub fn integer_i64(element: &Element<'_>) -> Result<i64, Error> {
    let contents = integer_bytes(element)?;
    if contents.len() > 8 {
        return Err(Error::IntegerOutOfRange);
    }
    let negative = contents.first().is_some_and(|b| b & 0x80 != 0);
    let mut bytes = if negative { [0xFF; 8] } else { [0; 8] };
    let start = 8usize
        .checked_sub(contents.len())
        .ok_or(Error::IntegerOutOfRange)?;
    bytes
        .get_mut(start..)
        .ok_or(Error::IntegerOutOfRange)?
        .copy_from_slice(contents);
    Ok(i64::from_be_bytes(bytes))
}

/// INTEGER (§8.3) as a `u64`; a negative value is out of range.
pub fn integer_u64(element: &Element<'_>) -> Result<u64, Error> {
    let contents = integer_bytes(element)?;
    if contents.first().is_some_and(|b| b & 0x80 != 0) {
        return Err(Error::IntegerOutOfRange);
    }
    // A leading zero octet only carries the sign.
    let magnitude = match contents {
        [0x00, rest @ ..] if !rest.is_empty() => rest,
        _ => contents,
    };
    if magnitude.len() > 8 {
        return Err(Error::IntegerOutOfRange);
    }
    Ok(magnitude
        .iter()
        .fold(0u64, |value, &octet| (value << 8) | u64::from(octet)))
}

/// ENUMERATED (§8.4): encoded as an INTEGER.
pub fn enumerated(element: &Element<'_>) -> Result<i64, Error> {
    integer_i64(element)
}

/// NULL (§8.8): no contents.
pub fn null(element: &Element<'_>) -> Result<(), Error> {
    if primitive(element)?.is_empty() {
        Ok(())
    } else {
        Err(Error::InvalidNull)
    }
}

fn bit_string_primitive(contents: &[u8]) -> Result<BitString, Error> {
    let (&unused, bytes) = contents.split_first().ok_or(Error::InvalidBitString)?;
    if unused > 7 || (bytes.is_empty() && unused != 0) {
        return Err(Error::InvalidBitString);
    }
    Ok(BitString {
        unused,
        bytes: bytes.to_vec(),
    })
}

/// BIT STRING (§8.6), primitive or constructed from BIT STRING segments (§8.6.4); only the last
/// segment may end with unused bits.
pub fn bit_string(element: &Element<'_>) -> Result<BitString, Error> {
    if !element.identifier.constructed {
        return bit_string_primitive(element.contents);
    }
    let mut out = BitString::default();
    let mut children = element.children()?;
    while !children.is_empty() {
        if out.unused != 0 {
            return Err(Error::InvalidBitString);
        }
        let segment = children.read()?;
        if segment.identifier.with_constructed(false) != Identifier::BIT_STRING {
            return Err(Error::InvalidBitString);
        }
        let part = bit_string(&segment)?;
        out.bytes.extend_from_slice(&part.bytes);
        out.unused = part.unused;
    }
    Ok(out)
}

fn append_octets(element: &Element<'_>, out: &mut Vec<u8>) -> Result<(), Error> {
    if !element.identifier.constructed {
        out.extend_from_slice(element.contents);
        return Ok(());
    }
    let mut children = element.children()?;
    while !children.is_empty() {
        let segment = children.read()?;
        if segment.identifier.with_constructed(false) != Identifier::OCTET_STRING {
            return Err(Error::UnexpectedIdentifier {
                expected: Identifier::OCTET_STRING,
                found: segment.identifier,
            });
        }
        append_octets(&segment, out)?;
    }
    Ok(())
}

/// OCTET STRING (§8.7), primitive or constructed from OCTET STRING segments (§8.7.3).
pub fn octet_string(element: &Element<'_>) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    append_octets(element, &mut out)?;
    Ok(out)
}

/// Character sets of the string types that the modules use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    /// VisibleString and GeneralizedTime: printable ASCII, space included.
    Visible,
    /// GraphicString without escape sequences: the same set as VisibleString (D-007).
    Graphic,
    /// UTF8String.
    Utf8,
}

impl Charset {
    /// Whether `text` belongs to the set.
    pub fn accepts(self, text: &str) -> bool {
        match self {
            Self::Visible | Self::Graphic => text.bytes().all(|b| (0x20..=0x7E).contains(&b)),
            Self::Utf8 => true,
        }
    }
}

/// A restricted character string (§8.23): encoded as an OCTET STRING, so primitive or
/// constructed from OCTET STRING segments (§8.23.3).
pub fn string(element: &Element<'_>, charset: Charset) -> Result<String, Error> {
    let octets = octet_string(element)?;
    let text = String::from_utf8(octets).map_err(|_| Error::InvalidCharacter)?;
    if charset.accepts(&text) {
        Ok(text)
    } else {
        Err(Error::InvalidCharacter)
    }
}

/// OBJECT IDENTIFIER (§8.19): subidentifiers in base 128, the first one packing two components.
pub fn object_identifier(element: &Element<'_>) -> Result<ObjectIdentifier, Error> {
    let contents = primitive(element)?;
    if contents.last().is_none_or(|b| b & 0x80 != 0) {
        return Err(Error::InvalidObjectIdentifier);
    }
    let mut arcs = Vec::new();
    let mut value: u64 = 0;
    let mut starting = true;
    for &octet in contents {
        if starting && octet == 0x80 {
            return Err(Error::InvalidObjectIdentifier);
        }
        value = value
            .checked_mul(128)
            .and_then(|v| v.checked_add(u64::from(octet & 0x7F)))
            .ok_or(Error::InvalidObjectIdentifier)?;
        starting = octet & 0x80 == 0;
        if starting {
            if arcs.is_empty() {
                // §8.19.4: the first subidentifier is X * 40 + Y.
                let first = value.min(80) / 40;
                let second = value
                    .checked_sub(
                        first
                            .checked_mul(40)
                            .ok_or(Error::InvalidObjectIdentifier)?,
                    )
                    .ok_or(Error::InvalidObjectIdentifier)?;
                arcs.push(first);
                arcs.push(second);
            } else {
                arcs.push(value);
            }
            value = 0;
        }
    }
    Ok(ObjectIdentifier(arcs))
}
