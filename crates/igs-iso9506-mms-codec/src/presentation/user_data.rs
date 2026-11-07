// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Values of type User-data (X.226 §8.2, §8.4).

use super::Error;
use crate::ber::{self, Element, Identifier, Reader, Writer};
use crate::schema::{BitString, ObjectIdentifier};

const SIMPLY_ENCODED: Identifier = Identifier::application(0, false);
const FULLY_ENCODED: Identifier = Identifier::application(1, true);
const SINGLE_ASN1_TYPE: Identifier = Identifier::context(0, true);
const OCTET_ALIGNED: Identifier = Identifier::context(1, false);
const ARBITRARY: Identifier = Identifier::context(2, false);

/// How User-data is encoded on a connection (§8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// Simple encoding: the presentation data values alone (§8.4.1).
    Simple,
    /// Full encoding: a list of PDVs with their presentation contexts (§8.4.2).
    Full,
}

/// The presentation data values of one PDV-list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdvValues {
    /// One ASN.1 value encoded with BER: its complete encoding.
    SingleAsn1Type(Vec<u8>),
    /// Values whose encodings are a whole number of octets.
    OctetAligned(Vec<u8>),
    /// Any other values.
    Arbitrary(BitString),
}

/// A PDV-list: presentation data values of one presentation context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdv {
    /// Transfer syntax, when several were proposed for the context (§8.4.2.7).
    pub transfer_syntax: Option<ObjectIdentifier>,
    /// Presentation context identifier.
    pub context_id: i64,
    /// The values.
    pub values: PdvValues,
}

/// A User-data value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserData {
    /// Simply-encoded-data.
    Simple(Vec<u8>),
    /// Fully-encoded-data.
    Full(Vec<Pdv>),
}

fn pdv(element: &Element<'_>) -> Result<Pdv, Error> {
    let element = element.expect(Identifier::SEQUENCE)?;
    let mut parts = element.children()?;
    let mut transfer_syntax = None;
    if parts.peek_identifier()? == Some(Identifier::OBJECT_IDENTIFIER) {
        transfer_syntax = Some(ber::object_identifier(&parts.read()?)?);
    }
    let context_id = ber::integer_i64(&parts.read_expected(Identifier::INTEGER)?)?;
    let value = parts.read()?;
    let values = match value.identifier {
        SINGLE_ASN1_TYPE => {
            // Exactly one complete encoding inside the explicit tag.
            let mut inner = value.children()?;
            inner.read()?;
            inner.finish()?;
            PdvValues::SingleAsn1Type(value.contents.to_vec())
        }
        id if id.with_constructed(false) == OCTET_ALIGNED => {
            PdvValues::OctetAligned(ber::octet_string(&value)?)
        }
        id if id.with_constructed(false) == ARBITRARY => {
            PdvValues::Arbitrary(ber::bit_string(&value)?)
        }
        other => return Err(Error::Unexpected(other)),
    };
    parts.finish()?;
    Ok(Pdv {
        transfer_syntax,
        context_id,
        values,
    })
}

impl UserData {
    /// A User-data value that is an element of another type: tagged APPLICATION 0 or 1.
    pub fn decode_element(element: &Element<'_>) -> Result<Self, Error> {
        match element.identifier {
            id if id.with_constructed(false) == SIMPLY_ENCODED => {
                Ok(Self::Simple(ber::octet_string(element)?))
            }
            FULLY_ENCODED => {
                let mut list = element.children()?;
                let mut pdvs = Vec::new();
                while !list.is_empty() {
                    pdvs.push(pdv(&list.read()?)?);
                }
                Ok(Self::Full(pdvs))
            }
            other => Err(Error::Unexpected(other)),
        }
    }

    /// User-data as the whole user data of a session SPDU (DATA TRANSFER, FINISH, DISCONNECT).
    /// With simple encoding, it is the values alone, without identifier or length (§8.4.1.4 c).
    pub fn decode_data(bytes: &[u8], encoding: Encoding) -> Result<Self, Error> {
        match encoding {
            Encoding::Simple => Ok(Self::Simple(bytes.to_vec())),
            Encoding::Full => {
                let mut reader = Reader::new(bytes);
                let element = reader.read_expected(FULLY_ENCODED)?;
                reader.finish()?;
                Self::decode_element(&element)
            }
        }
    }

    /// Write the value as an element of another type.
    pub fn write(&self, w: &mut Writer) -> Result<(), Error> {
        match self {
            Self::Simple(bytes) => {
                w.octet_string(SIMPLY_ENCODED, bytes);
                Ok(())
            }
            Self::Full(pdvs) => w.constructed(FULLY_ENCODED, |list| {
                for pdv in pdvs {
                    list.constructed(Identifier::SEQUENCE, |seq| {
                        if let Some(syntax) = &pdv.transfer_syntax {
                            seq.object_identifier(Identifier::OBJECT_IDENTIFIER, syntax)?;
                        }
                        seq.integer(Identifier::INTEGER, pdv.context_id);
                        match &pdv.values {
                            PdvValues::SingleAsn1Type(encoding) => {
                                seq.constructed(SINGLE_ASN1_TYPE, |inner| {
                                    inner.raw(encoding);
                                    Ok::<(), Error>(())
                                })?;
                            }
                            PdvValues::OctetAligned(bytes) => {
                                seq.octet_string(OCTET_ALIGNED, bytes)
                            }
                            PdvValues::Arbitrary(bits) => seq.bit_string(ARBITRARY, bits)?,
                        }
                        Ok::<(), Error>(())
                    })?;
                }
                Ok(())
            }),
        }
    }

    /// The user data of a session SPDU carrying this value alone.
    pub fn encode_data(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Simple(bytes) => Ok(bytes.clone()),
            Self::Full(_) => {
                let mut w = Writer::new();
                self.write(&mut w)?;
                Ok(w.into_bytes())
            }
        }
    }
}
