// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Strategies for property tests: values that the codec writes and reads back unchanged.
//!
//! Every codec kind implements [`Values`](crate::strategy::Values): the built-in types here, the generated types in the
//! generated code. `depth` bounds recursion: a recursive type spends one level per cycle and
//! keeps only its non-recursive alternatives, and empty lists, at depth zero.

use std::fmt::Debug;

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::select;
use proptest::strategy::{BoxedStrategy, Just, Union};

use crate::asn::{self, Codec};
use crate::ber::{Identifier, Writer};
use crate::mms::MAX_MILLISECONDS;
use crate::schema::{BitString, ObjectIdentifier, RawBer, TagClass};

/// The strategy of a codec kind.
pub trait Values: Codec<Value: Debug + Clone + 'static> {
    /// Values of the kind.
    fn values(depth: u32) -> BoxedStrategy<Self::Value>;

    /// Values whose size (characters, octets, bits or items) is within `low..=high`.
    fn sized(_low: usize, _high: usize, depth: u32) -> BoxedStrategy<Self::Value> {
        Self::values(depth)
    }
}

/// Values of `K`.
pub fn values<K: Values>(depth: u32) -> BoxedStrategy<K::Value> {
    K::values(depth)
}

/// Lists of a recursive kind: empty at depth zero.
pub fn cyclic_list<K: Values>(depth: u32) -> BoxedStrategy<Vec<K::Value>> {
    if depth == 0 {
        Just(Vec::new()).boxed()
    } else {
        vec(K::values(depth.saturating_sub(1)), 0..=2).boxed()
    }
}

/// Integers within one of the inclusive ranges.
pub fn ranged(ranges: &'static [(i64, i64)]) -> BoxedStrategy<i64> {
    Union::new(ranges.iter().map(|&(low, high)| (low..=high).boxed())).boxed()
}

/// Values of `K` whose size is within one of the inclusive ranges; large bounds are capped.
pub fn sized<K: Values>(ranges: &'static [(i64, i64)], depth: u32) -> BoxedStrategy<K::Value> {
    let arms = ranges.iter().map(|&(low, high)| {
        let low = usize::try_from(low.max(0)).unwrap_or(0);
        let high = usize::try_from(high.max(0)).unwrap_or(usize::MAX);
        K::sized(low, high.min(low.saturating_add(6)), depth)
    });
    Union::new(arms).boxed()
}

fn printable(low: usize, high: usize) -> BoxedStrategy<String> {
    vec(0x20u8..=0x7E, low..=high)
        .prop_map(|bytes| bytes.into_iter().map(char::from).collect())
        .boxed()
}

fn bit_strings(low: usize, high: usize) -> BoxedStrategy<BitString> {
    (low..=high)
        .prop_flat_map(|bits| {
            let octets = bits.div_ceil(8);
            let unused = octets.saturating_mul(8).saturating_sub(bits) as u8;
            vec(any::<u8>(), octets).prop_map(move |mut bytes| {
                // The unused bits are written as received; zero them as a sender does.
                if let Some(last) = bytes.last_mut() {
                    *last &= 0xFFu8.checked_shl(u32::from(unused)).unwrap_or(0);
                }
                BitString { unused, bytes }
            })
        })
        .boxed()
}

fn object_identifiers() -> BoxedStrategy<ObjectIdentifier> {
    (0u64..=2)
        .prop_flat_map(|first| {
            let second = if first < 2 { 0..40u64 } else { 0..100_000u64 };
            (Just(first), second, vec(any::<u64>(), 0..4))
        })
        .prop_map(|(first, second, rest)| {
            let mut arcs = vec![first, second];
            arcs.extend(rest);
            ObjectIdentifier(arcs)
        })
        .boxed()
}

macro_rules! simple {
    ($kind:ty, $strategy:expr) => {
        impl Values for $kind {
            fn values(_depth: u32) -> BoxedStrategy<Self::Value> {
                $strategy.boxed()
            }
        }
    };
}

simple!(asn::Boolean, any::<bool>());
simple!(asn::Null, Just(()));
simple!(asn::Integer, any::<i64>());
simple!(asn::Integer128, any::<i128>());
simple!(asn::Unsigned128, any::<u128>());
simple!(asn::Enumerated, any::<i64>());
simple!(asn::Oid, object_identifiers());

macro_rules! sized_kind {
    ($kind:ty, $strategy:ident, $default:expr) => {
        impl Values for $kind {
            fn values(_depth: u32) -> BoxedStrategy<Self::Value> {
                $strategy($default.0, $default.1)
            }

            fn sized(low: usize, high: usize, _depth: u32) -> BoxedStrategy<Self::Value> {
                $strategy(low, high)
            }
        }
    };
}

fn octets(low: usize, high: usize) -> BoxedStrategy<Vec<u8>> {
    vec(any::<u8>(), low..=high).boxed()
}

sized_kind!(asn::BitStr, bit_strings, (0, 24));
sized_kind!(asn::Octets, octets, (0, 8));
sized_kind!(asn::Visible, printable, (0, 8));
sized_kind!(asn::Graphic, printable, (0, 8));
sized_kind!(asn::GeneralizedTime, printable, (0, 8));
sized_kind!(asn::UtcTime, printable, (0, 8));

impl Values for asn::Utf8 {
    fn values(_depth: u32) -> BoxedStrategy<String> {
        vec(any::<char>(), 0..=8)
            .prop_map(|chars| chars.into_iter().collect())
            .boxed()
    }
}

impl<K: Values> Values for asn::ListOf<K> {
    fn values(depth: u32) -> BoxedStrategy<Self::Value> {
        vec(K::values(depth), 0..=3).boxed()
    }

    fn sized(low: usize, high: usize, depth: u32) -> BoxedStrategy<Self::Value> {
        vec(K::values(depth), low..=high).boxed()
    }
}

impl<K: Values> Values for asn::Boxed<K> {
    fn values(depth: u32) -> BoxedStrategy<Self::Value> {
        K::values(depth).prop_map(Box::new).boxed()
    }
}

/// One encoding with this identifier: random octets when primitive, a few nested OCTET STRINGs
/// when constructed, so that it stays well formed at every level.
fn encoding(id: Identifier) -> BoxedStrategy<RawBer> {
    let contents = if id.constructed {
        vec(vec(any::<u8>(), 0..4), 0..3)
            .prop_map(|parts| {
                let mut w = Writer::new();
                for part in parts {
                    w.octet_string(Identifier::OCTET_STRING, &part);
                }
                w.into_bytes()
            })
            .boxed()
    } else {
        vec(any::<u8>(), 0..6).boxed()
    };
    contents
        .prop_map(move |contents| {
            let mut w = Writer::new();
            w.element(id, &contents);
            RawBer(w.into_bytes())
        })
        .boxed()
}

/// Encodings with one of these tags, in either form (universal SEQUENCE, SET, EXTERNAL and
/// EMBEDDED PDV are constructed); with context tags from a number on; or with any tag.
pub fn raw_with(
    tags: &'static [(TagClass, u32)],
    context_from: Option<u32>,
    any_tag: bool,
) -> BoxedStrategy<RawBer> {
    let mut ids: Vec<Identifier> = Vec::new();
    for &(class, number) in tags {
        let constructed_only = class == TagClass::Universal && [8, 11, 16, 17].contains(&number);
        ids.push(Identifier::new(class, true, number));
        if !constructed_only {
            ids.push(Identifier::new(class, false, number));
        }
    }
    if let Some(from) = context_from {
        for number in from..from.saturating_add(4) {
            ids.push(Identifier::context(number, false));
            ids.push(Identifier::context(number, true));
        }
    }
    if any_tag {
        ids.extend([
            Identifier::INTEGER,
            Identifier::OCTET_STRING,
            Identifier::SEQUENCE,
            Identifier::context(0, true),
            Identifier::context(40, false),
            Identifier::application(3, true),
        ]);
    }
    select(ids).prop_flat_map(encoding).boxed()
}

impl Values for asn::External {
    fn values(_depth: u32) -> BoxedStrategy<RawBer> {
        raw_with(&[(TagClass::Universal, 8)], None, false)
    }
}

impl Values for asn::EmbeddedPdv {
    fn values(_depth: u32) -> BoxedStrategy<RawBer> {
        raw_with(&[(TagClass::Universal, 11)], None, false)
    }
}

impl Values for asn::Open {
    fn values(_depth: u32) -> BoxedStrategy<RawBer> {
        raw_with(&[], None, true)
    }
}

/// An alternative kept raw: a context tag from `from` on that no alternative uses.
pub fn unsupported(from: u32, used: &'static [u32]) -> BoxedStrategy<(u32, RawBer)> {
    let tags: Vec<u32> = (from..from.saturating_add(100))
        .filter(|t| !used.contains(t))
        .collect();
    select(tags)
        .prop_flat_map(|tag| {
            (
                Just(tag),
                prop_oneof![
                    encoding(Identifier::context(tag, false)),
                    encoding(Identifier::context(tag, true))
                ],
            )
        })
        .boxed()
}

/// Identifiers: 1 to 64 letters, digits, `$` and `_`: the union of ISO 9506-2 §7.5.2 and IEC
/// 61850-8-1 Annex F.3.2 that the codec reads (D-032).
pub fn identifier() -> BoxedStrategy<String> {
    let alphabet: Vec<char> = ('a'..='z')
        .chain('A'..='Z')
        .chain('0'..='9')
        .chain(['$', '_'])
        .collect();
    vec(select(alphabet), 1..=64)
        .prop_map(|chars| chars.into_iter().collect())
        .boxed()
}

/// TimeOfDay octets, in both forms (ISO 9506-2 §7.5.1).
pub fn time_of_day() -> BoxedStrategy<Vec<u8>> {
    (0..=MAX_MILLISECONDS, proptest::option::of(any::<u16>()))
        .prop_map(|(milliseconds, day)| {
            let mut octets = milliseconds.to_be_bytes().to_vec();
            if let Some(day) = day {
                octets.extend_from_slice(&day.to_be_bytes());
            }
            octets
        })
        .boxed()
}

/// FloatingPoint octets: the IEEE forms, and other widths (ISO 9506-2 §14.4.2.2).
pub fn floating_point() -> BoxedStrategy<Vec<u8>> {
    let general = (1usize..=9)
        .prop_flat_map(|octets| {
            let bits = octets.saturating_mul(8);
            (1..bits, vec(any::<u8>(), octets))
        })
        .prop_map(|(width, rest)| {
            let mut out = vec![u8::try_from(width).unwrap_or(u8::MAX)];
            out.extend(rest);
            out
        });
    prop_oneof![
        any::<u32>().prop_map(|bits| {
            let mut out = vec![8];
            out.extend(bits.to_be_bytes());
            out
        }),
        any::<u64>().prop_map(|bits| {
            let mut out = vec![11];
            out.extend(bits.to_be_bytes());
            out
        }),
        general,
    ]
    .boxed()
}
