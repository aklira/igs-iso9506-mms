// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Common MMS types (ISO 9506-2 §7.5, §14.2, §14.4), task C6: round trips, minimum and maximum
//! values. The lengths of the vectors are computed by [`tlv`].

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::float_cmp,
    // Bit patterns are grouped as sign, exponent and fraction.
    clippy::unusual_byte_groupings
)]

use igs_iso9506_mms_codec::asn::{self, Codec, Error};
use igs_iso9506_mms_codec::ber;
use igs_iso9506_mms_codec::mms::{
    AccessResult, Data, DataAccessError, FloatingPoint, Identifier, Integer16, Integer32, Integer8,
    MMSString, ObjectName, ObjectNameDomainSpecific, TimeOfDay, TypeDescription,
    TypeDescriptionArray, TypeDescriptionFloatingPoint, TypeDescriptionStructure,
    TypeDescriptionStructureComponentsItem, TypeSpecification, Unsigned32, Unsigned8,
    MAX_MILLISECONDS,
};
use igs_iso9506_mms_codec::schema::{BitString, ObjectIdentifier};

/// One encoding with a one-octet identifier and a computed length.
fn tlv(id: u8, parts: &[&[u8]]) -> Vec<u8> {
    let contents = parts.concat();
    let n = contents.len();
    let mut out = vec![id];
    if n < 0x80 {
        out.push(n as u8);
    } else {
        out.extend([0x81, n as u8]);
    }
    out.extend(contents);
    out
}

/// Decodes, checks the value, and re-encodes octet for octet.
fn round_trip<K: Codec>(bytes: &[u8], expected: &K::Value)
where
    K::Value: PartialEq + std::fmt::Debug,
{
    let value = asn::decode_value::<K>(bytes).unwrap();
    assert_eq!(&value, expected);
    assert_eq!(asn::encode_value::<K>(&value).unwrap(), bytes);
}

/// The minimal two's complement octets of an integer.
fn int(value: i128) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut start = 0;
    while start < 15
        && ((bytes[start] == 0 && bytes[start + 1] & 0x80 == 0)
            || (bytes[start] == 0xFF && bytes[start + 1] & 0x80 != 0))
    {
        start += 1;
    }
    bytes[start..].to_vec()
}

#[test]
fn integer_types_at_their_limits() {
    fn limits<K: Codec>(min: i128, max: i128, make: fn(i64) -> Result<K::Value, Error>)
    where
        K::Value: PartialEq + std::fmt::Debug,
    {
        for v in [min, max] {
            let value = make(v as i64).unwrap();
            round_trip::<K>(&tlv(0x02, &[&int(v)]), &value);
        }
        for v in [min - 1, max + 1] {
            assert!(make(v as i64).is_err(), "{v}");
            assert!(matches!(
                asn::decode_value::<K>(&tlv(0x02, &[&int(v)])),
                Err(Error::OutOfRange { .. })
            ));
        }
    }
    limits::<Integer8>(-128, 127, Integer8::new);
    limits::<Integer16>(-32_768, 32_767, Integer16::new);
    limits::<Integer32>(-2_147_483_648, 2_147_483_647, Integer32::new);
    limits::<Unsigned8>(0, 127, Unsigned8::new);
    limits::<Unsigned32>(0, 2_147_483_647, Unsigned32::new);
}

#[test]
fn data_integers_hold_128_bits() {
    for v in [i128::MIN, -1, 0, 1, i64::MAX as i128 + 1, i128::MAX] {
        round_trip::<Data>(&tlv(0x85, &[&int(v)]), &Data::Integer(v));
    }
    // unsigned and bcd: up to 2^128 - 1, with a leading zero octet for the sign.
    let mut max = vec![0x00];
    max.extend([0xFF; 16]);
    round_trip::<Data>(&tlv(0x86, &[&max]), &Data::Unsigned(u128::MAX));
    round_trip::<Data>(&tlv(0x86, &[&[0x00]]), &Data::Unsigned(0));
    round_trip::<Data>(&tlv(0x8D, &[&[0x52]]), &Data::Bcd(82));
    // They shall not be negative.
    assert_eq!(
        asn::decode_value::<Data>(&tlv(0x86, &[&[0xFF]])),
        Err(Error::Ber(ber::Error::IntegerOutOfRange))
    );
    assert_eq!(
        asn::decode_value::<Data>(&tlv(0x8D, &[&[0x80]])),
        Err(Error::Ber(ber::Error::IntegerOutOfRange))
    );
    // Beyond 128 bits.
    let mut wide = vec![0x01];
    wide.extend([0x00; 16]);
    assert_eq!(
        asn::decode_value::<Data>(&tlv(0x85, &[&wide])),
        Err(Error::Ber(ber::Error::IntegerOutOfRange))
    );
    let mut wider = vec![0x01];
    wider.extend([0x00; 16]);
    assert!(asn::decode_value::<Data>(&tlv(0x86, &[&wider])).is_err());
}

#[test]
fn every_alternative_of_data() {
    let cases: Vec<(Vec<u8>, Data)> = vec![
        (tlv(0x83, &[&[0xFF]]), Data::Boolean(true)),
        (tlv(0x83, &[&[0x00]]), Data::Boolean(false)),
        (
            tlv(0x84, &[&[0x03, 0xA8]]),
            Data::BitString(BitString {
                unused: 3,
                bytes: vec![0xA8],
            }),
        ),
        (
            tlv(0x87, &[&[0x08, 0x3F, 0x80, 0x00, 0x00]]),
            Data::FloatingPoint(FloatingPoint::from_f32(1.0)),
        ),
        (tlv(0x89, &[&[0x01, 0x02]]), Data::OctetString(vec![1, 2])),
        (tlv(0x89, &[]), Data::OctetString(vec![])),
        (tlv(0x8A, &[b"text"]), Data::VisibleString("text".into())),
        (
            tlv(0x8B, &[b"20261107120000.000Z"]),
            Data::GeneralizedTime("20261107120000.000Z".into()),
        ),
        (
            tlv(0x8C, &[&[0x00, 0x00, 0x03, 0xE8]]),
            Data::BinaryTime(TimeOfDay::from_milliseconds(1000).unwrap()),
        ),
        (
            tlv(0x8E, &[&[0x06, 0xC0]]),
            Data::BooleanArray(BitString {
                unused: 6,
                bytes: vec![0xC0],
            }),
        ),
        (
            tlv(0x8F, &[&[0x28, 0xCA, 0x22, 0x02, 0x01]]),
            Data::ObjId(ObjectIdentifier(vec![1, 0, 9506, 2, 1])),
        ),
        (
            tlv(0x90, &[b"MMS string"]),
            Data::MMSString(MMSString("MMS string".into())),
        ),
    ];
    for (bytes, data) in &cases {
        round_trip::<Data>(bytes, data);
    }
    // An array of a structure, and empty ones.
    let element = tlv(0x85, &[&[0x07]]);
    let structure = tlv(0xA2, &[&element, &tlv(0x83, &[&[0xFF]])]);
    let array = tlv(0xA1, &[&structure, &tlv(0xA2, &[])]);
    round_trip::<Data>(
        &array,
        &Data::Array(vec![
            Data::Structure(vec![Data::Integer(7), Data::Boolean(true)]),
            Data::Structure(vec![]),
        ]),
    );
    round_trip::<Data>(&tlv(0xA1, &[]), &Data::Array(vec![]));
    // Tag [0] is reserved for AccessResult, [8] is reserved.
    for id in [0x80, 0x88] {
        assert!(asn::decode_value::<Data>(&tlv(id, &[&[0]])).is_err());
    }
    // A visible string holds printable ASCII only.
    assert!(asn::decode_value::<Data>(&tlv(0x8A, &[&[0x07]])).is_err());
}

#[test]
fn identifiers() {
    for text in ["a", "LLN0$ST$Mod$stVal", "_9", &"x".repeat(32)] {
        let id = Identifier::new(text.into()).unwrap();
        round_trip::<Identifier>(&tlv(0x1A, &[text.as_bytes()]), &id);
    }
    assert_eq!(
        Identifier::new(String::new()),
        Err(Error::WrongSize { ty: "Identifier" })
    );
    assert_eq!(
        Identifier::new("x".repeat(33)),
        Err(Error::WrongSize { ty: "Identifier" })
    );
    for bad in ["a-b", "a b", "é", "a.b"] {
        assert_eq!(
            Identifier::new(bad.into()),
            Err(Error::Invalid { ty: "Identifier" }),
            "{bad}"
        );
        assert!(asn::decode_value::<Identifier>(&tlv(0x1A, &[bad.as_bytes()])).is_err());
    }
    // Without the char CBB, an Identifier is a VisibleString, not a UTF8String.
    assert!(matches!(
        asn::decode_value::<Identifier>(&tlv(0x0C, &[b"abc"])),
        Err(Error::Unexpected { .. })
    ));
    // Built around the check, it is refused on encoding.
    assert_eq!(
        asn::encode_value::<Identifier>(&Identifier("a-b".into())),
        Err(Error::Invalid { ty: "Identifier" })
    );
}

#[test]
fn object_names() {
    let id = |s: &str| Identifier::new(s.into()).unwrap();
    round_trip::<ObjectName>(&tlv(0x80, &[b"vmd"]), &ObjectName::VmdSpecific(id("vmd")));
    round_trip::<ObjectName>(
        &tlv(
            0xA1,
            &[&tlv(0x1A, &[b"ICCP"]), &tlv(0x1A, &[b"Transfer_Set"])],
        ),
        &ObjectName::DomainSpecific(ObjectNameDomainSpecific {
            domain_id: id("ICCP"),
            item_id: id("Transfer_Set"),
        }),
    );
    round_trip::<ObjectName>(&tlv(0x82, &[b"aa"]), &ObjectName::AaSpecific(id("aa")));
    // The item is required; an implicit Identifier is checked as well.
    assert!(asn::decode_value::<ObjectName>(&tlv(0xA1, &[&tlv(0x1A, &[b"d"])])).is_err());
    assert!(asn::decode_value::<ObjectName>(&tlv(0x80, &[])).is_err());
}

#[test]
fn access_results() {
    round_trip::<AccessResult>(
        &tlv(0x85, &[&[0x2A]]),
        &AccessResult::Success(Data::Integer(42)),
    );
    for code in [0u8, 11] {
        round_trip::<AccessResult>(
            &tlv(0x80, &[&[code]]),
            &AccessResult::Failure(DataAccessError(i64::from(code))),
        );
    }
    assert_eq!(
        asn::decode_value::<AccessResult>(&tlv(0x80, &[&[12]])),
        Err(Error::OutOfRange {
            ty: "DataAccessError"
        })
    );
    assert_eq!(
        AccessResult::Failure(DataAccessError::OBJECT_NON_EXISTENT),
        AccessResult::Failure(DataAccessError(10))
    );
}

#[test]
fn type_specifications() {
    let id = |s: &str| Identifier::new(s.into()).unwrap();
    // typeName [0] is explicit: the module has no tag default.
    round_trip::<TypeSpecification>(
        &tlv(0xA0, &[&tlv(0x80, &[b"T"])]),
        &TypeSpecification::TypeName(ObjectName::VmdSpecific(id("T"))),
    );
    // A structure of a named 32-bit integer and an array of ten floats, then a visible string.
    let integer = tlv(0x85, &[&[0x20]]);
    let float = tlv(0xA7, &[&tlv(0x02, &[&[0x20]]), &tlv(0x02, &[&[0x08]])]);
    let array = tlv(0xA1, &[&tlv(0x81, &[&[0x0A]]), &tlv(0xA2, &[&float])]);
    let first = tlv(0x30, &[&tlv(0x80, &[b"value"]), &tlv(0xA1, &[&integer])]);
    let second = tlv(0x30, &[&tlv(0xA1, &[&array])]);
    let structure = tlv(0xA2, &[&tlv(0xA1, &[&first, &second])]);
    let expected = TypeSpecification::TypeDescription(Box::new(TypeDescription::Structure(
        TypeDescriptionStructure {
            packed: None,
            components: vec![
                TypeDescriptionStructureComponentsItem {
                    component_name: Some(id("value")),
                    component_type: TypeSpecification::TypeDescription(Box::new(
                        TypeDescription::Integer(Unsigned8(32)),
                    )),
                },
                TypeDescriptionStructureComponentsItem {
                    component_name: None,
                    component_type: TypeSpecification::TypeDescription(Box::new(
                        TypeDescription::Array(Box::new(TypeDescriptionArray {
                            packed: None,
                            number_of_elements: Unsigned32(10),
                            element_type: Box::new(TypeSpecification::TypeDescription(Box::new(
                                TypeDescription::FloatingPoint(TypeDescriptionFloatingPoint {
                                    format_width: Unsigned8(32),
                                    exponent_width: Unsigned8(8),
                                }),
                            ))),
                        })),
                    )),
                },
            ],
        },
    )));
    round_trip::<TypeSpecification>(&structure, &expected);
    // mMSString [16] Integer32 is explicit too; boolean [3] is an implicit NULL.
    round_trip::<TypeDescription>(
        &tlv(0xB0, &[&tlv(0x02, &[&[0x40]])]),
        &TypeDescription::MMSString(Integer32(64)),
    );
    round_trip::<TypeDescription>(&tlv(0x83, &[]), &TypeDescription::Boolean);
    // A bit size of 128 is beyond Unsigned8.
    assert!(asn::decode_value::<TypeDescription>(&tlv(0x85, &[&[0x00, 0x80]])).is_err());
}

#[test]
fn times_of_day() {
    for (millis, day) in [
        (0, None),
        (MAX_MILLISECONDS, None),
        (0, Some(0)),
        (MAX_MILLISECONDS, Some(u16::MAX)),
    ] {
        let time = match day {
            None => TimeOfDay::from_milliseconds(millis).unwrap(),
            Some(day) => TimeOfDay::from_milliseconds_and_day(millis, day).unwrap(),
        };
        assert_eq!(time.milliseconds().unwrap(), millis);
        assert_eq!(time.day().unwrap(), day);
        let mut octets = millis.to_be_bytes().to_vec();
        if let Some(day) = day {
            octets.extend(day.to_be_bytes());
        }
        round_trip::<TimeOfDay>(&tlv(0x04, &[&octets]), &time);
    }
    // 2026-11-07 is day 15 651 since 1984-01-01; noon is 43 200 000 ms.
    let noon = TimeOfDay::from_milliseconds_and_day(43_200_000, 15_651).unwrap();
    assert_eq!(noon.0, [0x02, 0x93, 0x2E, 0x00, 0x3D, 0x23]);
    // The top four bits are zero.
    assert_eq!(
        TimeOfDay::from_milliseconds(MAX_MILLISECONDS + 1),
        Err(Error::Invalid { ty: "TimeOfDay" })
    );
    assert_eq!(
        asn::decode_value::<TimeOfDay>(&tlv(0x04, &[&[0x10, 0, 0, 0]])),
        Err(Error::Invalid { ty: "TimeOfDay" })
    );
    for size in [0, 3, 5, 7] {
        assert_eq!(
            asn::decode_value::<TimeOfDay>(&tlv(0x04, &[&vec![0; size]])),
            Err(Error::WrongSize { ty: "TimeOfDay" })
        );
    }
    assert!(TimeOfDay(vec![0; 5]).milliseconds().is_err());
}

#[test]
fn ieee_formats_round_trip() {
    let singles = [
        0.0f32,
        -0.0,
        1.0,
        -2.5,
        f32::MAX,
        f32::MIN,
        f32::MIN_POSITIVE,
        f32::from_bits(1),
        f32::INFINITY,
        f32::NEG_INFINITY,
    ];
    for v in singles {
        let fp = FloatingPoint::from_f32(v);
        assert_eq!(fp.exponent_width().unwrap(), 8);
        assert_eq!(fp.0.len(), 5);
        assert_eq!(fp.to_f32().unwrap().to_bits(), v.to_bits(), "{v}");
        assert_eq!(fp.to_f64().unwrap(), f64::from(v), "{v}");
        round_trip::<FloatingPoint>(&tlv(0x04, &[&fp.0]), &fp);
    }
    let doubles = [
        0.0f64,
        -0.0,
        1.0,
        0.1,
        f64::MAX,
        f64::MIN,
        f64::MIN_POSITIVE,
        f64::from_bits(1),
        f64::from_bits(0x000F_FFFF_FFFF_FFFF),
        f64::INFINITY,
        f64::NEG_INFINITY,
    ];
    for v in doubles {
        let fp = FloatingPoint::from_f64(v);
        assert_eq!(fp.exponent_width().unwrap(), 11);
        assert_eq!(fp.to_f64().unwrap().to_bits(), v.to_bits(), "{v}");
    }
    assert!(FloatingPoint::from_f32(f32::NAN).to_f32().unwrap().is_nan());
    assert!(FloatingPoint::from_f64(f64::NAN).to_f64().unwrap().is_nan());
    assert!(FloatingPoint::from_f64(-f64::NAN)
        .to_f32()
        .unwrap()
        .is_sign_negative());
}

#[test]
fn narrowing_follows_the_rounding_rule() {
    let to_f32 = |v: f64| FloatingPoint::from_f64(v).to_f32().unwrap();
    // The first bit that does not fit is one: rounded up, even at a tie.
    let half_ulp = 1.0 + 2f64.powi(-24);
    assert_eq!(to_f32(half_ulp), 1.0 + 2f32.powi(-23));
    // Below it: truncated.
    assert_eq!(to_f32(1.0 + 2f64.powi(-25)), 1.0);
    assert_eq!(to_f32(0.1), 0.1f32);
    // Too large: an infinity of the same sign; too small: a zero.
    assert_eq!(to_f32(f64::MAX), f32::INFINITY);
    assert_eq!(to_f32(-f64::MAX), f32::NEG_INFINITY);
    assert_eq!(to_f32(1e-50).to_bits(), 0);
    assert_eq!(to_f32(-1e-50).to_bits(), 0x8000_0000);
    // Into the subnormal range: 0.75 of the smallest subnormal rounds up to it, 0.25 to zero.
    let smallest = f64::from(f32::from_bits(1));
    assert_eq!(to_f32(0.75 * smallest).to_bits(), 1);
    assert_eq!(to_f32(0.25 * smallest).to_bits(), 0);
    // A carry out of the largest subnormal gives the smallest normal number.
    let below_normal = f64::from(f32::MIN_POSITIVE) * (1.0 - 2f64.powi(-25));
    assert_eq!(to_f32(below_normal), f32::MIN_POSITIVE);
    // A carry out of the largest finite number gives an infinity.
    let above_max = f64::from(f32::MAX) * (1.0 + 2f64.powi(-24));
    assert_eq!(to_f32(above_max), f32::INFINITY);
}

#[test]
fn other_exponent_widths() {
    let value = |octets: &[u8]| FloatingPoint(octets.to_vec()).to_f64().unwrap();
    // N = 4 with one octet: sign, four exponent bits (bias 7), three fraction bits.
    assert_eq!(value(&[4, 0b0_0111_000]), 1.0);
    assert_eq!(value(&[4, 0b1_0111_000]), -1.0);
    assert_eq!(value(&[4, 0b0_1000_100]), 3.0);
    assert_eq!(value(&[4, 0b0_0000_001]), 2f64.powi(-9));
    assert_eq!(value(&[4, 0b0_0000_000]), 0.0);
    assert_eq!(value(&[4, 0b0_1111_000]), f64::INFINITY);
    assert!(value(&[4, 0b0_1111_001]).is_nan());
    // N = 1: an exponent of zero weighs 2^1.
    assert_eq!(value(&[1, 0b0_0_100000]), 1.0);
    // N = 7 with no fraction bit.
    assert_eq!(value(&[7, 0b0_0111111]), 1.0);
    // N = 15 and a 64-bit fraction: 1.0, then exponents beyond the range of an f64.
    let mut one = vec![15, 0x3F, 0xFF];
    one.extend([0; 8]);
    assert_eq!(value(&one), 1.0);
    let mut huge = vec![15, 0x7F, 0xFE];
    huge.extend([0; 8]);
    assert_eq!(value(&huge), f64::INFINITY);
    let mut tiny = vec![15, 0x00, 0x01];
    tiny.extend([0; 8]);
    assert_eq!(value(&tiny), 0.0);
    // N = 200: a bias far beyond 128 bits.
    let mut wide = vec![200];
    wide.extend([0x3F]);
    wide.extend([0xFF; 24]);
    wide.extend([0x80, 0x00]);
    assert_eq!(value(&wide), 1.0);
}

#[test]
fn malformed_floating_points_are_refused() {
    for octets in [
        vec![],
        vec![8],
        vec![0, 0, 0],
        vec![8, 0x00],
        vec![17, 0, 0],
    ] {
        assert_eq!(
            FloatingPoint(octets.clone()).to_f64(),
            Err(Error::Invalid {
                ty: "FloatingPoint"
            }),
            "{octets:?}"
        );
        assert!(asn::decode_value::<Data>(&tlv(0x87, &[&octets])).is_err());
    }
}
