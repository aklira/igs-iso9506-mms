// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! ACSE APDUs in normal mode: AARQ, AARE, RLRQ, RLRE and ABRT (ITU-T X.227 with amendment 1).
//!
//! The APDU types are generated from the ACSE module (see [`crate::generated::types`]). An AP
//! title or AE qualifier is decoded in form 2 (object identifier and integer); form 1, a
//! directory name, is kept as raw BER. As X.227 §7.4 requires, an incoming AARQ ignores the
//! encodings it does not define, while the other APDUs refuse them; bits without a name are kept
//! as received. User information is a list of EXTERNAL values, kept as raw BER and read with
//! [`External`](crate::acse::External).

use crate::asn::{self, Error};
use crate::ber::{self, Charset, Element, Identifier, Reader, Writer};
use crate::schema::{BitString, ObjectIdentifier, RawBer, TagClass};

pub use crate::generated::types::{
    AAREApdu, AAREApduProtocolVersion, AARQApdu, AARQApduProtocolVersion, ABRTApdu, ABRTDiagnostic,
    ABRTSource, ACSEApdu, ACSERequirements, AEInvocationIdentifier, AEQualifier, AEQualifierForm1,
    AEQualifierForm2, APInvocationIdentifier, APTitle, APTitleForm1, APTitleForm2,
    ApplicationContextName, ApplicationContextNameList, AssociateResult, AssociateSourceDiagnostic,
    AssociateSourceDiagnosticAcseServiceProvider, AssociateSourceDiagnosticAcseServiceUser,
    AssociationInformation, AuthenticationValue, AuthenticationValueOther, ImplementationData,
    MechanismName, RLREApdu, RLRQApdu, ReleaseRequestReason, ReleaseResponseReason,
};

/// Abstract syntax of the ACSE APDUs, `acse-as-id` of the ACSE module (X.227 §9).
pub const ABSTRACT_SYNTAX: [u64; 5] = [2, 2, 1, 0, 1];

/// Bit of version 1 in the protocol version (X.227 §7.1.4.1).
pub const VERSION1: usize = 0;

/// Decodes one ACSE APDU that fills `bytes`.
pub fn decode(bytes: &[u8]) -> Result<ACSEApdu, Error> {
    asn::decode_value::<ACSEApdu>(bytes)
}

/// Encodes an ACSE APDU.
pub fn encode(apdu: &ACSEApdu) -> Result<Vec<u8>, Error> {
    asn::encode_value::<ACSEApdu>(apdu)
}

/// Whether a protocol version field offers version 1. An absent field means version 1 (X.227
/// §7.1.3.2, note 3); bits of later versions are ignored (§7.1.4.1).
pub fn offers_version1(protocol_version: Option<&BitString>) -> bool {
    protocol_version.is_none_or(|bits| bits.bit(VERSION1))
}

/// The protocol version with version 1 only, as a requesting ACPM writes it: its last bit is set
/// (X.227 §7.1.4.1).
pub fn version1() -> BitString {
    BitString {
        unused: 7,
        bytes: vec![0x80],
    }
}

/// How the data value of an EXTERNAL is encoded (X.690 §8.18.5 to §8.18.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Encoding {
    /// One ASN.1 value: its complete encoding, exactly one BER encoding.
    SingleAsn1Type(RawBer),
    /// An encoding that is a whole number of octets.
    OctetAligned(Vec<u8>),
    /// Any encoding.
    Arbitrary(BitString),
}

/// An EXTERNAL value, as user information carries it (X.690 §8.18.1).
///
/// In normal mode, the presentation context of the value is given by `indirect_reference`
/// (table 2 of X.690 §8.18.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct External {
    /// Abstract syntax, or transfer syntax with an indirect reference.
    pub direct_reference: Option<ObjectIdentifier>,
    /// Presentation context identifier.
    pub indirect_reference: Option<i64>,
    /// ObjectDescriptor, a GraphicString.
    pub data_value_descriptor: Option<String>,
    /// The data value.
    pub encoding: Encoding,
}

/// ObjectDescriptor, `[UNIVERSAL 7] IMPLICIT GraphicString` (X.680 §48).
const OBJECT_DESCRIPTOR: Identifier = Identifier::universal(7);

fn is(id: Identifier, expected: Identifier) -> bool {
    id.class == expected.class && id.number == expected.number
}

fn context(id: Identifier, number: u32) -> bool {
    id.class == TagClass::Context && id.number == number
}

impl External {
    /// The EXTERNAL that one item of user information holds.
    pub fn decode(raw: &RawBer) -> Result<Self, Error> {
        let mut reader = Reader::new(&raw.0);
        let element = reader.read_expected(Identifier::EXTERNAL)?;
        reader.finish()?;
        Self::decode_element(&element)
    }

    fn decode_element(element: &Element<'_>) -> Result<Self, Error> {
        let ty = "EXTERNAL";
        let mut r = element.children()?;
        let next_is = |r: &Reader<'_>, id: Identifier| {
            r.peek_identifier()
                .map(|next| next.is_some_and(|next| is(next, id)))
        };
        let direct_reference = if next_is(&r, Identifier::OBJECT_IDENTIFIER)? {
            Some(ber::object_identifier(&r.read()?)?)
        } else {
            None
        };
        let indirect_reference = if next_is(&r, Identifier::INTEGER)? {
            Some(ber::integer_i64(&r.read()?)?)
        } else {
            None
        };
        let data_value_descriptor = if next_is(&r, OBJECT_DESCRIPTOR)? {
            Some(ber::string(&r.read()?, Charset::Graphic)?)
        } else {
            None
        };
        if r.is_empty() {
            return Err(Error::Missing {
                ty,
                component: "encoding",
            });
        }
        let e = r.read()?;
        let encoding = if context(e.identifier, 0) {
            let mut inner = e.children()?;
            let value = inner.read()?;
            inner.finish()?;
            Encoding::SingleAsn1Type(asn::raw(&value, None))
        } else if context(e.identifier, 1) {
            Encoding::OctetAligned(ber::octet_string(&e)?)
        } else if context(e.identifier, 2) {
            Encoding::Arbitrary(ber::bit_string(&e)?)
        } else {
            return Err(Error::Unexpected {
                ty,
                found: e.identifier,
            });
        };
        if let Some(extra) = r.peek_identifier()? {
            return Err(Error::Unexpected { ty, found: extra });
        }
        Ok(Self {
            direct_reference,
            indirect_reference,
            data_value_descriptor,
            encoding,
        })
    }

    /// The EXTERNAL as one item of user information.
    pub fn encode(&self) -> Result<RawBer, Error> {
        let mut w = Writer::new();
        w.constructed(Identifier::EXTERNAL, |w| {
            if let Some(oid) = &self.direct_reference {
                w.object_identifier(Identifier::OBJECT_IDENTIFIER, oid)?;
            }
            if let Some(id) = self.indirect_reference {
                w.integer(Identifier::INTEGER, id);
            }
            if let Some(text) = &self.data_value_descriptor {
                w.string(OBJECT_DESCRIPTOR, text, Charset::Graphic)?;
            }
            match &self.encoding {
                Encoding::SingleAsn1Type(value) => {
                    w.constructed(Identifier::context(0, true), |w| {
                        asn::write_raw(w, value, |_| true, None)
                    })?;
                }
                Encoding::OctetAligned(octets) => {
                    w.octet_string(Identifier::context(1, false), octets);
                }
                Encoding::Arbitrary(bits) => w.bit_string(Identifier::context(2, false), bits)?,
            }
            Ok::<(), Error>(())
        })?;
        Ok(RawBer(w.into_bytes()))
    }
}
