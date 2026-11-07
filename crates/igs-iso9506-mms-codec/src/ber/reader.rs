// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Reading identifier, length and contents octets (X.690 §8.1).

use super::{Error, Identifier};
use crate::schema::TagClass;

/// Default bound on nesting, counted in constructed encodings entered.
pub const DEFAULT_MAX_DEPTH: usize = 64;

enum Length {
    Definite(usize),
    Indefinite,
}

/// One encoding: its identifier and its contents octets.
///
/// For the indefinite form, `contents` excludes the end-of-contents octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Element<'a> {
    /// Identifier octets.
    pub identifier: Identifier,
    /// Contents octets.
    pub contents: &'a [u8],
    /// Whether the length was in the indefinite form.
    pub indefinite: bool,
    depth: usize,
    max_depth: usize,
}

impl<'a> Element<'a> {
    /// A reader over the nested encodings of a constructed element, one level deeper.
    pub fn children(&self) -> Result<Reader<'a>, Error> {
        if !self.identifier.constructed {
            return Err(Error::WrongForm);
        }
        let depth = self.depth.checked_add(1).ok_or(Error::DepthExceeded {
            limit: self.max_depth,
        })?;
        if depth > self.max_depth {
            return Err(Error::DepthExceeded {
                limit: self.max_depth,
            });
        }
        Ok(Reader {
            data: self.contents,
            depth,
            max_depth: self.max_depth,
        })
    }

    /// The element itself if its identifier is `expected`.
    pub fn expect(self, expected: Identifier) -> Result<Self, Error> {
        if self.identifier == expected {
            Ok(self)
        } else {
            Err(Error::UnexpectedIdentifier {
                expected,
                found: self.identifier,
            })
        }
    }
}

/// A sequence of encodings in a slice of octets.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    depth: usize,
    max_depth: usize,
}

impl<'a> Reader<'a> {
    /// A reader with the default nesting bound.
    pub fn new(data: &'a [u8]) -> Self {
        Self::with_max_depth(data, DEFAULT_MAX_DEPTH)
    }

    /// A reader that refuses to enter more than `max_depth` nested constructed encodings.
    pub fn with_max_depth(data: &'a [u8], max_depth: usize) -> Self {
        Self {
            data,
            depth: 0,
            max_depth,
        }
    }

    /// Whether every octet has been read.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The octets not read yet.
    pub fn remaining(&self) -> &'a [u8] {
        self.data
    }

    /// Nesting level of the encodings this reader yields.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// The identifier of the next encoding, without consuming it.
    pub fn peek_identifier(&self) -> Result<Option<Identifier>, Error> {
        if self.data.is_empty() {
            return Ok(None);
        }
        identifier(self.data).map(|(id, _)| Some(id))
    }

    /// The next encoding.
    pub fn read(&mut self) -> Result<Element<'a>, Error> {
        let (identifier, length, header) = header(self.data)?;
        if identifier == Identifier::END_OF_CONTENTS {
            return Err(Error::UnexpectedEndOfContents);
        }
        let body = self.data.get(header..).ok_or(Error::Truncated)?;
        let (contents, used, indefinite) = match length {
            Length::Definite(n) => (body.get(..n).ok_or(Error::Truncated)?, n, false),
            Length::Indefinite => {
                if !identifier.constructed {
                    return Err(Error::IndefinitePrimitive);
                }
                let (n, used) = indefinite_contents(body, self.depth, self.max_depth)?;
                (body.get(..n).ok_or(Error::Truncated)?, used, true)
            }
        };
        let total = header.checked_add(used).ok_or(Error::LengthTooLarge)?;
        self.data = self.data.get(total..).ok_or(Error::Truncated)?;
        Ok(Element {
            identifier,
            contents,
            indefinite,
            depth: self.depth,
            max_depth: self.max_depth,
        })
    }

    /// The next encoding, which must have the identifier `expected`.
    pub fn read_expected(&mut self, expected: Identifier) -> Result<Element<'a>, Error> {
        self.read()?.expect(expected)
    }

    /// Succeeds only if every octet has been read.
    pub fn finish(self) -> Result<(), Error> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(Error::TrailingData)
        }
    }
}

/// Identifier octets (§8.1.2): the identifier and the number of octets used.
fn identifier(data: &[u8]) -> Result<(Identifier, usize), Error> {
    let (&first, rest) = data.split_first().ok_or(Error::Truncated)?;
    let class = match first >> 6 {
        0 => TagClass::Universal,
        1 => TagClass::Application,
        2 => TagClass::Context,
        _ => TagClass::Private,
    };
    let constructed = first & 0x20 != 0;
    let low = first & 0x1F;
    if low != 0x1F {
        return Ok((Identifier::new(class, constructed, u32::from(low)), 1));
    }
    // High-tag form, §8.1.2.4.2: base 128, most significant first, no leading zero group.
    let mut number: u32 = 0;
    for (index, &octet) in rest.iter().enumerate() {
        if index == 0 && octet == 0x80 {
            return Err(Error::NonMinimalTagNumber);
        }
        number = number
            .checked_mul(128)
            .and_then(|n| n.checked_add(u32::from(octet & 0x7F)))
            .ok_or(Error::TagNumberTooLarge)?;
        if octet & 0x80 == 0 {
            if number < 31 {
                return Err(Error::NonMinimalTagNumber);
            }
            let used = index.checked_add(2).ok_or(Error::Truncated)?;
            return Ok((Identifier::new(class, constructed, number), used));
        }
    }
    Err(Error::Truncated)
}

/// Identifier and length octets: the identifier, the length and the header size.
fn header(data: &[u8]) -> Result<(Identifier, Length, usize), Error> {
    let (identifier, used) = identifier(data)?;
    let rest = data.get(used..).ok_or(Error::Truncated)?;
    let (&first, octets) = rest.split_first().ok_or(Error::Truncated)?;
    let after_first = used.checked_add(1).ok_or(Error::Truncated)?;
    if first < 0x80 {
        return Ok((
            identifier,
            Length::Definite(usize::from(first)),
            after_first,
        ));
    }
    if first == 0x80 {
        return Ok((identifier, Length::Indefinite, after_first));
    }
    if first == 0xFF {
        return Err(Error::ReservedLength);
    }
    // Long form, §8.1.3.5: leading zero octets are a sender's option (note 2).
    let count = usize::from(first & 0x7F);
    let octets = octets.get(..count).ok_or(Error::Truncated)?;
    let mut length: usize = 0;
    for &octet in octets {
        length = length
            .checked_mul(256)
            .and_then(|n| n.checked_add(usize::from(octet)))
            .ok_or(Error::LengthTooLarge)?;
    }
    let total = after_first.checked_add(count).ok_or(Error::Truncated)?;
    Ok((identifier, Length::Definite(length), total))
}

/// Size of the contents of an indefinite-length encoding, and the octets it uses with its
/// end-of-contents. Walks nested encodings without recursion.
fn indefinite_contents(
    body: &[u8],
    depth: usize,
    max_depth: usize,
) -> Result<(usize, usize), Error> {
    let exceeded = Error::DepthExceeded { limit: max_depth };
    let mut position: usize = 0;
    let mut open: usize = 1;
    loop {
        let rest = body.get(position..).ok_or(Error::Truncated)?;
        if rest.is_empty() {
            return Err(Error::MissingEndOfContents);
        }
        let (identifier, length, header) = header(rest)?;
        let start = position;
        position = position.checked_add(header).ok_or(Error::Truncated)?;
        if identifier == Identifier::END_OF_CONTENTS {
            if !matches!(length, Length::Definite(0)) {
                return Err(Error::UnexpectedEndOfContents);
            }
            open = open.checked_sub(1).ok_or(Error::UnexpectedEndOfContents)?;
            if open == 0 {
                return Ok((start, position));
            }
            continue;
        }
        match length {
            Length::Definite(n) => {
                position = position.checked_add(n).ok_or(Error::Truncated)?;
                if position > body.len() {
                    return Err(Error::Truncated);
                }
            }
            Length::Indefinite => {
                if !identifier.constructed {
                    return Err(Error::IndefinitePrimitive);
                }
                open = open.checked_add(1).ok_or(exceeded)?;
                if depth.checked_add(open).is_none_or(|d| d > max_depth) {
                    return Err(exceeded);
                }
            }
        }
    }
}
