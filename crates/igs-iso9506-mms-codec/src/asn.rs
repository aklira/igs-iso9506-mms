// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Runtime of the generated ASN.1 types: how a value is recognised, decoded and encoded in BER.
//!
//! Every generated type implements [`Codec`](crate::asn::Codec), and so do the marker types of
//! this module for the built-in types (X.680 §8.4, table 1). A component tag is applied by
//! [`decode`](crate::asn::decode), [`encode`](crate::asn::encode) and
//! [`accepts`](crate::asn::accepts): an implicit tag replaces the identifier of the value, an
//! explicit tag wraps it (X.690 §8.14). A tag is compared on class and number only, as BER lets
//! a sender choose the form of strings.

use std::fmt;
use std::marker::PhantomData;

use crate::ber::{self, Charset, Element, Identifier, Reader, Writer};
use crate::schema::{BitString, ObjectIdentifier, RawBer, Tag, TagClass, Tagging};

/// Why a value was refused, while decoding or encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The BER layer refused the octets.
    Ber(ber::Error),
    /// A required component is absent.
    Missing {
        /// ASN.1 type.
        ty: &'static str,
        /// Component.
        component: &'static str,
    },
    /// An encoding that no component of the type expects at this place.
    Unexpected {
        /// ASN.1 type.
        ty: &'static str,
        /// Identifier found.
        found: Identifier,
    },
    /// No alternative of a CHOICE has this tag.
    NoAlternative {
        /// ASN.1 type.
        ty: &'static str,
        /// Identifier found.
        found: Identifier,
    },
    /// A value outside the constraint of its type.
    OutOfRange {
        /// ASN.1 type.
        ty: &'static str,
    },
    /// A size outside the constraint of its type.
    WrongSize {
        /// ASN.1 type.
        ty: &'static str,
    },
    /// A value that the prose of its type does not allow: a character outside a permitted
    /// alphabet, a reserved bit set, a malformed format.
    Invalid {
        /// ASN.1 type.
        ty: &'static str,
    },
    /// Octets kept as raw BER that are not exactly one encoding of the expected tag.
    InvalidRaw,
    /// An implicit tag asked of a CHOICE, which X.680 §31.2.9 forbids.
    ImplicitChoice {
        /// ASN.1 type.
        ty: &'static str,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ber(e) => write!(f, "{e}"),
            Self::Missing { ty, component } => write!(f, "{ty}: {component} missing"),
            Self::Unexpected { ty, found } => write!(f, "{ty}: unexpected {found:?}"),
            Self::NoAlternative { ty, found } => write!(f, "{ty}: no alternative for {found:?}"),
            Self::OutOfRange { ty } => write!(f, "{ty}: value out of range"),
            Self::WrongSize { ty } => write!(f, "{ty}: size out of range"),
            Self::Invalid { ty } => write!(f, "{ty}: invalid value"),
            Self::InvalidRaw => write!(f, "raw BER is not one encoding of the expected tag"),
            Self::ImplicitChoice { ty } => write!(f, "{ty}: a CHOICE cannot be tagged implicitly"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ber(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ber::Error> for Error {
    fn from(e: ber::Error) -> Self {
        Self::Ber(e)
    }
}

/// How the values of an ASN.1 type are recognised, decoded and encoded.
pub trait Codec {
    /// The Rust value.
    type Value;

    /// Name of the ASN.1 type, for errors.
    const NAME: &'static str;

    /// Whether an encoding with this identifier holds a value of the type, when its context adds
    /// no tag.
    fn accepts(id: Identifier) -> bool;

    /// Decodes from an element whose identifier the caller has checked, or which an implicit tag
    /// replaced.
    fn decode(element: &Element<'_>) -> Result<Self::Value, Error>;

    /// Encodes; `implicit` replaces the outermost identifier.
    fn encode(
        value: &Self::Value,
        w: &mut Writer,
        implicit: Option<Identifier>,
    ) -> Result<(), Error>;
}

/// The identifier of a tag; the writer sets the form.
pub const fn identifier(tag: Tag) -> Identifier {
    Identifier::new(tag.class, false, tag.number)
}

/// Whether `id` has the class and number of `tag`.
pub fn is_tag(tag: Tag, id: Identifier) -> bool {
    id.class == tag.class && id.number == tag.number
}

/// Whether `id` is the universal tag `number`.
pub fn is_universal(id: Identifier, number: u32) -> bool {
    id.class == TagClass::Universal && id.number == number
}

/// Whether `id` can start a value of `K` under the component tag `tag`.
pub fn accepts<K: Codec>(tag: Option<Tag>, id: Identifier) -> bool {
    match tag {
        Some(tag) => is_tag(tag, id),
        None => K::accepts(id),
    }
}

/// Decodes a value of `K` under the component tag `tag`.
pub fn decode<K: Codec>(tag: Option<Tag>, element: &Element<'_>) -> Result<K::Value, Error> {
    match tag {
        Some(Tag {
            tagging: Tagging::Explicit,
            ..
        }) => explicit(element, K::NAME, K::accepts, K::decode),
        // Either form: the constructed one is the explicit tag, the primitive one the implicit tag (D-034).
        Some(Tag {
            tagging: Tagging::Either,
            ..
        }) if element.identifier.constructed => explicit(element, K::NAME, K::accepts, K::decode),
        _ => K::decode(element),
    }
}

/// Encodes a value of `K` under the component tag `tag`.
pub fn encode<K: Codec>(tag: Option<Tag>, value: &K::Value, w: &mut Writer) -> Result<(), Error> {
    match tag {
        None => K::encode(value, w, None),
        Some(tag) if tag.tagging == Tagging::Implicit => K::encode(value, w, Some(identifier(tag))),
        Some(tag) if tag.tagging == Tagging::Either && w.implicit_either => {
            K::encode(value, w, Some(identifier(tag)))
        }
        Some(tag) => w.constructed(identifier(tag), |w| K::encode(value, w, None)),
    }
}

/// Encodes a component that may be absent.
pub fn encode_optional<K: Codec>(
    tag: Option<Tag>,
    value: &Option<K::Value>,
    w: &mut Writer,
) -> Result<(), Error> {
    match value {
        Some(value) => encode::<K>(tag, value, w),
        None => Ok(()),
    }
}

/// The value inside an explicit tag: exactly one encoding that `accepts` recognises.
pub fn explicit<T>(
    element: &Element<'_>,
    ty: &'static str,
    accepts: fn(Identifier) -> bool,
    decode: fn(&Element<'_>) -> Result<T, Error>,
) -> Result<T, Error> {
    let mut children = element.children()?;
    let inner = children.read()?;
    if !accepts(inner.identifier) {
        return Err(Error::Unexpected {
            ty,
            found: inner.identifier,
        });
    }
    let value = decode(&inner)?;
    children.finish()?;
    Ok(value)
}

/// Refuses an implicit tag on a CHOICE.
pub fn no_implicit(implicit: Option<Identifier>, ty: &'static str) -> Result<(), Error> {
    match implicit {
        Some(_) => Err(Error::ImplicitChoice { ty }),
        None => Ok(()),
    }
}

/// Decodes one value of `K` that fills `bytes`.
pub fn decode_value<K: Codec>(bytes: &[u8]) -> Result<K::Value, Error> {
    let mut reader = Reader::new(bytes);
    let element = reader.read()?;
    if !K::accepts(element.identifier) {
        return Err(Error::Unexpected {
            ty: K::NAME,
            found: element.identifier,
        });
    }
    let value = K::decode(&element)?;
    reader.finish()?;
    Ok(value)
}

/// Encodes one value of `K`.
pub fn encode_value<K: Codec>(value: &K::Value) -> Result<Vec<u8>, Error> {
    let mut w = Writer::new();
    K::encode(value, &mut w, None)?;
    Ok(w.into_bytes())
}

/// Encodes a value, writing the components tagged [`Tagging::Either`] in their implicit form when
/// `implicit_either` is set (IEC 61850-8-1 Annex F.1; D-034).
pub fn encode_value_with<K: Codec>(
    value: &K::Value,
    implicit_either: bool,
) -> Result<Vec<u8>, Error> {
    let mut w = Writer::new();
    w.set_implicit_either(implicit_either);
    K::encode(value, &mut w, None)?;
    Ok(w.into_bytes())
}

/// Reads the components of a SEQUENCE in order.
///
/// When `known` is given, encodings it does not recognise are skipped, as X.227 §7.4 asks of an
/// incoming AARQ; otherwise they are refused.
#[derive(Debug)]
pub struct Components<'a> {
    reader: Reader<'a>,
    next: Option<Element<'a>>,
    ty: &'static str,
    known: Option<fn(Identifier) -> bool>,
}

impl<'a> Components<'a> {
    /// The components of `element`, a SEQUENCE of type `ty`.
    pub fn new(
        element: &Element<'a>,
        ty: &'static str,
        known: Option<fn(Identifier) -> bool>,
    ) -> Result<Self, Error> {
        Ok(Self {
            reader: element.children()?,
            next: None,
            ty,
            known,
        })
    }

    fn fill(&mut self) -> Result<(), Error> {
        while self.next.is_none() && !self.reader.is_empty() {
            let element = self.reader.read()?;
            if self.known.is_some_and(|known| !known(element.identifier)) {
                continue;
            }
            self.next = Some(element);
        }
        Ok(())
    }

    /// The next component if it has the tag of `K` under `tag`.
    pub fn optional<K: Codec>(&mut self, tag: Option<Tag>) -> Result<Option<K::Value>, Error> {
        self.fill()?;
        match self.next {
            Some(element) if accepts::<K>(tag, element.identifier) => {
                self.next = None;
                decode::<K>(tag, &element).map(Some)
            }
            _ => Ok(None),
        }
    }

    /// The next component, which must have the tag of `K` under `tag`.
    pub fn required<K: Codec>(
        &mut self,
        tag: Option<Tag>,
        component: &'static str,
    ) -> Result<K::Value, Error> {
        self.optional::<K>(tag)?.ok_or(Error::Missing {
            ty: self.ty,
            component,
        })
    }

    /// Succeeds if no component is left.
    pub fn finish(mut self) -> Result<(), Error> {
        self.fill()?;
        match self.next {
            Some(element) => Err(Error::Unexpected {
                ty: self.ty,
                found: element.identifier,
            }),
            None => Ok(()),
        }
    }
}

/// An element kept as raw BER, with its identifier, or with `fixed` when given (the universal
/// identifier of a type that an implicit tag may have replaced). The length is rewritten in the
/// definite form.
pub fn raw(element: &Element<'_>, fixed: Option<Identifier>) -> RawBer {
    let id = fixed.map_or(element.identifier, |f| {
        f.with_constructed(element.identifier.constructed)
    });
    let mut w = Writer::new();
    w.element(id, element.contents);
    RawBer(w.into_bytes())
}

/// Writes raw BER after checking it is one encoding that `accepts` recognises; `implicit`
/// replaces its identifier.
pub fn write_raw(
    w: &mut Writer,
    value: &RawBer,
    accepts: fn(Identifier) -> bool,
    implicit: Option<Identifier>,
) -> Result<(), Error> {
    let mut reader = Reader::new(&value.0);
    let element = reader.read().map_err(|_| Error::InvalidRaw)?;
    if !reader.is_empty() || !accepts(element.identifier) {
        return Err(Error::InvalidRaw);
    }
    match implicit {
        Some(id) => w.element(
            id.with_constructed(element.identifier.constructed),
            element.contents,
        ),
        None => w.raw(&value.0),
    }
    Ok(())
}

/// Writes the raw encoding of an alternative out of scope, after checking its tag: a context tag
/// numbered `tag`, from `from` on.
pub fn write_unsupported(w: &mut Writer, tag: u32, from: u32, value: &RawBer) -> Result<(), Error> {
    match Reader::new(&value.0).peek_identifier() {
        Ok(Some(id)) if id.class == TagClass::Context && id.number == tag && tag >= from => {
            write_raw(w, value, |_| true, None)
        }
        _ => Err(Error::InvalidRaw),
    }
}

/// The size that a SIZE constraint measures (X.680 §51.5).
pub trait Measure {
    /// Characters, octets, bits or items.
    fn measure(&self) -> usize;
}

impl Measure for String {
    fn measure(&self) -> usize {
        self.chars().count()
    }
}

impl<T> Measure for Vec<T> {
    fn measure(&self) -> usize {
        self.len()
    }
}

impl Measure for BitString {
    fn measure(&self) -> usize {
        self.bytes
            .len()
            .saturating_mul(8)
            .saturating_sub(usize::from(self.unused))
    }
}

fn within(ranges: &[(i64, i64)], value: i64) -> bool {
    ranges
        .iter()
        .any(|&(low, high)| low <= value && value <= high)
}

/// Checks a value against the inclusive ranges of a constraint.
pub fn check_values(ty: &'static str, ranges: &[(i64, i64)], value: i64) -> Result<(), Error> {
    if within(ranges, value) {
        Ok(())
    } else {
        Err(Error::OutOfRange { ty })
    }
}

/// Checks a size against the inclusive ranges of a constraint.
pub fn check_sizes(
    ty: &'static str,
    ranges: &[(i64, i64)],
    value: &impl Measure,
) -> Result<(), Error> {
    let size = i64::try_from(value.measure()).unwrap_or(i64::MAX);
    if within(ranges, size) {
        Ok(())
    } else {
        Err(Error::WrongSize { ty })
    }
}

macro_rules! primitive {
    ($(#[$doc:meta])* $name:ident, $asn:literal, $value:ty, $id:expr,
     |$e:ident| $decode:expr, |$v:ident, $w:ident, $i:ident| $encode:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name;

        impl Codec for $name {
            type Value = $value;

            const NAME: &'static str = $asn;

            fn accepts(id: Identifier) -> bool {
                is_universal(id, $id.number)
            }

            fn decode($e: &Element<'_>) -> Result<$value, Error> {
                Ok($decode?)
            }

            fn encode(
                $v: &$value,
                $w: &mut Writer,
                implicit: Option<Identifier>,
            ) -> Result<(), Error> {
                let $i = implicit.unwrap_or($id);
                $encode;
                Ok(())
            }
        }
    };
}

primitive!(
    /// BOOLEAN.
    Boolean,
    "BOOLEAN",
    bool,
    Identifier::BOOLEAN,
    |e| ber::boolean(e),
    |v, w, id| w.boolean(id, *v)
);
primitive!(
    /// NULL.
    Null,
    "NULL",
    (),
    Identifier::NULL,
    |e| ber::null(e),
    |_v, w, id| w.null(id)
);
primitive!(
    /// INTEGER, within 64 bits.
    Integer,
    "INTEGER",
    i64,
    Identifier::INTEGER,
    |e| ber::integer_i64(e),
    |v, w, id| w.integer(id, *v)
);
primitive!(
    /// INTEGER, within 128 bits.
    Integer128,
    "INTEGER",
    i128,
    Identifier::INTEGER,
    |e| ber::integer_i128(e),
    |v, w, id| w.integer_i128(id, *v)
);
primitive!(
    /// INTEGER that shall not be negative, within 128 bits.
    Unsigned128,
    "INTEGER",
    u128,
    Identifier::INTEGER,
    |e| ber::integer_u128(e),
    |v, w, id| w.unsigned_u128(id, *v)
);
primitive!(
    /// ENUMERATED.
    Enumerated,
    "ENUMERATED",
    i64,
    Identifier::ENUMERATED,
    |e| ber::enumerated(e),
    |v, w, id| w.enumerated(id, *v)
);
primitive!(
    /// BIT STRING.
    BitStr,
    "BIT STRING",
    BitString,
    Identifier::BIT_STRING,
    |e| ber::bit_string(e),
    |v, w, id| w.bit_string(id, v)?
);
primitive!(
    /// OCTET STRING.
    Octets,
    "OCTET STRING",
    Vec<u8>,
    Identifier::OCTET_STRING,
    |e| ber::octet_string(e),
    |v, w, id| w.octet_string(id, v)
);
primitive!(
    /// OBJECT IDENTIFIER.
    Oid,
    "OBJECT IDENTIFIER",
    ObjectIdentifier,
    Identifier::OBJECT_IDENTIFIER,
    |e| ber::object_identifier(e),
    |v, w, id| w.object_identifier(id, v)?
);
primitive!(
    /// VisibleString.
    Visible,
    "VisibleString",
    String,
    Identifier::VISIBLE_STRING,
    |e| ber::string(e, Charset::Visible),
    |v, w, id| w.string(id, v, Charset::Visible)?
);
primitive!(
    /// GraphicString, without escape sequences (see the BER layer).
    Graphic,
    "GraphicString",
    String,
    Identifier::GRAPHIC_STRING,
    |e| ber::string(e, Charset::Graphic),
    |v, w, id| w.string(id, v, Charset::Graphic)?
);
primitive!(
    /// UTF8String.
    Utf8,
    "UTF8String",
    String,
    Identifier::UTF8_STRING,
    |e| ber::string(e, Charset::Utf8),
    |v, w, id| w.string(id, v, Charset::Utf8)?
);
primitive!(
    /// GeneralizedTime, kept as its characters (VisibleString, X.680 §46.3).
    GeneralizedTime,
    "GeneralizedTime",
    String,
    Identifier::GENERALIZED_TIME,
    |e| ber::string(e, Charset::Visible),
    |v, w, id| w.string(id, v, Charset::Visible)?
);
primitive!(
    /// UTCTime, kept as its characters (VisibleString, X.680 §47.3).
    UtcTime,
    "UTCTime",
    String,
    Identifier::universal(23),
    |e| ber::string(e, Charset::Visible),
    |v, w, id| w.string(id, v, Charset::Visible)?
);

macro_rules! raw_kind {
    ($(#[$doc:meta])* $name:ident, $asn:literal, $number:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name;

        impl Codec for $name {
            type Value = RawBer;

            const NAME: &'static str = $asn;

            fn accepts(id: Identifier) -> bool {
                is_universal(id, $number)
            }

            fn decode(element: &Element<'_>) -> Result<RawBer, Error> {
                Ok(raw(
                    element,
                    Some(Identifier::new(TagClass::Universal, true, $number)),
                ))
            }

            fn encode(
                value: &RawBer,
                w: &mut Writer,
                implicit: Option<Identifier>,
            ) -> Result<(), Error> {
                write_raw(w, value, Self::accepts, implicit)
            }
        }
    };
}

raw_kind!(
    /// EXTERNAL, kept as raw BER with its universal tag.
    External,
    "EXTERNAL",
    8
);
raw_kind!(
    /// EMBEDDED PDV, kept as raw BER with its universal tag.
    EmbeddedPdv,
    "EMBEDDED PDV",
    11
);

/// An open type or ANY: any one encoding, kept as raw BER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Open;

impl Codec for Open {
    type Value = RawBer;

    const NAME: &'static str = "open type";

    fn accepts(_: Identifier) -> bool {
        true
    }

    fn decode(element: &Element<'_>) -> Result<RawBer, Error> {
        Ok(raw(element, None))
    }

    fn encode(value: &RawBer, w: &mut Writer, implicit: Option<Identifier>) -> Result<(), Error> {
        write_raw(w, value, Self::accepts, implicit)
    }
}

/// SEQUENCE OF the values of `K`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListOf<K>(PhantomData<K>);

impl<K: Codec> Codec for ListOf<K> {
    type Value = Vec<K::Value>;

    const NAME: &'static str = "SEQUENCE OF";

    fn accepts(id: Identifier) -> bool {
        is_universal(id, Identifier::SEQUENCE.number)
    }

    fn decode(element: &Element<'_>) -> Result<Self::Value, Error> {
        let mut children = element.children()?;
        let mut out = Vec::new();
        while !children.is_empty() {
            let item = children.read()?;
            if !K::accepts(item.identifier) {
                return Err(Error::Unexpected {
                    ty: K::NAME,
                    found: item.identifier,
                });
            }
            out.push(K::decode(&item)?);
        }
        Ok(out)
    }

    fn encode(
        value: &Self::Value,
        w: &mut Writer,
        implicit: Option<Identifier>,
    ) -> Result<(), Error> {
        w.constructed(implicit.unwrap_or(Identifier::SEQUENCE), |w| {
            value.iter().try_for_each(|item| K::encode(item, w, None))
        })
    }
}

/// A value of `K` behind a box, for recursive types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Boxed<K>(PhantomData<K>);

impl<K: Codec> Codec for Boxed<K> {
    type Value = Box<K::Value>;

    const NAME: &'static str = K::NAME;

    fn accepts(id: Identifier) -> bool {
        K::accepts(id)
    }

    fn decode(element: &Element<'_>) -> Result<Self::Value, Error> {
        K::decode(element).map(Box::new)
    }

    fn encode(
        value: &Self::Value,
        w: &mut Writer,
        implicit: Option<Identifier>,
    ) -> Result<(), Error> {
        K::encode(value, w, implicit)
    }
}
