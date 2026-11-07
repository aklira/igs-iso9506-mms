// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Hand-written BER vectors for each type, and malformed encodings refused with a typed error
//! (task C1). Clauses are those of ITU-T X.690.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use igs_iso9506_mms_codec::ber::{self, Charset, Element, Error, Identifier, Reader, Writer};
use igs_iso9506_mms_codec::schema::{BitString, ObjectIdentifier, TagClass};

fn one(bytes: &[u8]) -> Result<Element<'_>, Error> {
    let mut reader = Reader::new(bytes);
    let element = reader.read()?;
    reader.finish()?;
    Ok(element)
}

fn written(f: impl FnOnce(&mut Writer)) -> Vec<u8> {
    let mut w = Writer::new();
    f(&mut w);
    w.into_bytes()
}

// §8.1.2: identifier octets.

#[test]
fn low_and_high_tag_numbers() {
    let e = one(&[0x9F, 0x1F, 0x00]).unwrap();
    assert_eq!(e.identifier, Identifier::context(31, false));
    let e = one(&[0xBF, 0x81, 0x49, 0x00]).unwrap();
    assert_eq!(e.identifier, Identifier::context(201, true));
    let e = one(&[0x7E, 0x00]).unwrap();
    assert_eq!(e.identifier, Identifier::application(30, true));
    assert_eq!(
        written(|w| w.null(Identifier::context(201, false))),
        [0x9F, 0x81, 0x49, 0x00]
    );
    assert_eq!(
        written(|w| w.null(Identifier::context(30, false))),
        [0x9E, 0x00]
    );
    assert_eq!(
        written(|w| w.null(Identifier::new(TagClass::Private, false, 31))),
        [0xDF, 0x1F, 0x00]
    );
}

#[test]
fn malformed_tag_numbers_are_refused() {
    // §8.1.2.4.2 c): no leading zero group; high form only from 31 on.
    assert_eq!(
        one(&[0x9F, 0x80, 0x1F, 0x00]),
        Err(Error::NonMinimalTagNumber)
    );
    assert_eq!(one(&[0x9F, 0x1E, 0x00]), Err(Error::NonMinimalTagNumber));
    assert_eq!(
        one(&[0x9F, 0x9F, 0xFF, 0xFF, 0xFF, 0x7F, 0x00]),
        Err(Error::TagNumberTooLarge)
    );
    assert_eq!(one(&[0x9F, 0x81]), Err(Error::Truncated));
    assert_eq!(one(&[]), Err(Error::Truncated));
}

// §8.1.3: length octets.

#[test]
fn length_forms() {
    assert_eq!(one(&[0x04, 0x01, 0xAA]).unwrap().contents, [0xAA]);
    assert_eq!(one(&[0x04, 0x81, 0x01, 0xAA]).unwrap().contents, [0xAA]);
    // Note 2 of §8.1.3.5: more length octets than needed is a sender's option.
    assert_eq!(
        one(&[0x04, 0x83, 0x00, 0x00, 0x01, 0xAA]).unwrap().contents,
        [0xAA]
    );
    let long = vec![0x55; 300];
    let bytes = written(|w| w.octet_string(Identifier::OCTET_STRING, &long));
    assert_eq!(&bytes[..4], [0x04, 0x82, 0x01, 0x2C]);
    assert_eq!(one(&bytes).unwrap().contents, long.as_slice());
    let bytes = written(|w| w.octet_string(Identifier::OCTET_STRING, &[0; 200]));
    assert_eq!(&bytes[..3], [0x04, 0x81, 0xC8]);
    let bytes = written(|w| w.octet_string(Identifier::OCTET_STRING, &[0; 127]));
    assert_eq!(&bytes[..2], [0x04, 0x7F]);
}

#[test]
fn malformed_lengths_are_refused() {
    assert_eq!(one(&[0x04, 0xFF, 0x00]), Err(Error::ReservedLength));
    assert_eq!(one(&[0x04, 0x02, 0xAA]), Err(Error::Truncated));
    assert_eq!(
        one(&[0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]),
        Err(Error::Truncated)
    );
    assert_eq!(one(&[0x04, 0x82, 0x01]), Err(Error::Truncated));
    assert_eq!(one(&[0x04]), Err(Error::Truncated));
    let too_many = [0x04, 0x89, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(one(&too_many), Err(Error::LengthTooLarge));
    // §8.1.3.2 a): the indefinite form is for constructed encodings only.
    assert_eq!(
        one(&[0x04, 0x80, 0xAA, 0x00, 0x00]),
        Err(Error::IndefinitePrimitive)
    );
}

// §8.1.3.6 and §8.1.5: indefinite length and end-of-contents.

#[test]
fn indefinite_length() {
    let bytes = [
        0x30, 0x80, 0x02, 0x01, 0x05, 0x30, 0x80, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
        0xFF,
    ];
    let mut reader = Reader::new(&bytes);
    let outer = reader.read().unwrap();
    assert!(outer.indefinite);
    assert_eq!(outer.contents, &bytes[2..11]);
    let mut children = outer.children().unwrap();
    assert_eq!(ber::integer_i64(&children.read().unwrap()).unwrap(), 5);
    let inner = children.read().unwrap();
    assert!(inner.indefinite);
    assert!(ber::null(&inner.children().unwrap().read().unwrap()).is_ok());
    children.finish().unwrap();
    // The next encoding starts after the end-of-contents.
    assert!(ber::boolean(&reader.read().unwrap()).unwrap());
    reader.finish().unwrap();
}

#[test]
fn malformed_end_of_contents_is_refused() {
    assert_eq!(
        one(&[0x30, 0x80, 0x05, 0x00]),
        Err(Error::MissingEndOfContents)
    );
    assert_eq!(
        one(&[0x30, 0x80, 0x00, 0x01, 0x00]),
        Err(Error::UnexpectedEndOfContents)
    );
    assert_eq!(one(&[0x00, 0x00]), Err(Error::UnexpectedEndOfContents));
    let element = one(&[0x30, 0x02, 0x00, 0x00]).unwrap();
    assert_eq!(
        element.children().unwrap().read(),
        Err(Error::UnexpectedEndOfContents)
    );
    assert_eq!(
        one(&[0x30, 0x80, 0x24, 0x80, 0x00, 0x00]),
        Err(Error::MissingEndOfContents)
    );
}

#[test]
fn trailing_data_and_identifier_checks() {
    assert_eq!(one(&[0x05, 0x00, 0x05]), Err(Error::TrailingData));
    let mut reader = Reader::new(&[0x05, 0x00]);
    assert_eq!(reader.peek_identifier(), Ok(Some(Identifier::NULL)));
    assert_eq!(
        reader.read_expected(Identifier::BOOLEAN),
        Err(Error::UnexpectedIdentifier {
            expected: Identifier::BOOLEAN,
            found: Identifier::NULL
        })
    );
    assert!(matches!(
        one(&[0x05, 0x00]).unwrap().children(),
        Err(Error::WrongForm)
    ));
}

// Nesting bound.

fn nested_definite(depth: usize) -> Vec<u8> {
    let mut bytes = vec![0x05, 0x00];
    for _ in 0..depth {
        let mut w = Writer::new();
        w.constructed(Identifier::SEQUENCE, |inner| {
            inner.raw(&bytes);
            Ok::<(), Error>(())
        })
        .unwrap();
        bytes = w.into_bytes();
    }
    bytes
}

fn descend(bytes: &[u8], max_depth: usize) -> Result<usize, Error> {
    let mut element = Reader::with_max_depth(bytes, max_depth).read()?;
    let mut levels = 0;
    while element.identifier.constructed {
        element = element.children()?.read()?;
        levels += 1;
    }
    Ok(levels)
}

#[test]
fn nesting_is_bounded() {
    assert_eq!(descend(&nested_definite(8), 8), Ok(8));
    assert_eq!(
        descend(&nested_definite(9), 8),
        Err(Error::DepthExceeded { limit: 8 })
    );
    let mut indefinite = Vec::new();
    for _ in 0..100_000 {
        indefinite.extend_from_slice(&[0x30, 0x80]);
    }
    for _ in 0..100_000 {
        indefinite.extend_from_slice(&[0x00, 0x00]);
    }
    let run = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || Reader::new(&indefinite).read().map(|_| ()))
        .unwrap();
    assert_eq!(
        run.join().unwrap(),
        Err(Error::DepthExceeded {
            limit: ber::DEFAULT_MAX_DEPTH
        })
    );
}

// §8.2: BOOLEAN.

#[test]
fn boolean_vectors() {
    assert!(!ber::boolean(&one(&[0x01, 0x01, 0x00]).unwrap()).unwrap());
    assert!(ber::boolean(&one(&[0x01, 0x01, 0xFF]).unwrap()).unwrap());
    assert!(ber::boolean(&one(&[0x01, 0x01, 0x01]).unwrap()).unwrap());
    assert_eq!(
        ber::boolean(&one(&[0x01, 0x00]).unwrap()),
        Err(Error::InvalidBoolean)
    );
    assert_eq!(
        ber::boolean(&one(&[0x01, 0x02, 0x00, 0x00]).unwrap()),
        Err(Error::InvalidBoolean)
    );
    assert_eq!(
        ber::boolean(&one(&[0x21, 0x00]).unwrap()),
        Err(Error::WrongForm)
    );
    assert_eq!(
        written(|w| w.boolean(Identifier::BOOLEAN, true)),
        [0x01, 0x01, 0xFF]
    );
    assert_eq!(
        written(|w| w.boolean(Identifier::context(3, false), false)),
        [0x83, 0x01, 0x00]
    );
}

// §8.3 and §8.4: INTEGER and ENUMERATED.

#[test]
fn integer_vectors() {
    let cases: [(i64, &[u8]); 10] = [
        (0, &[0x00]),
        (127, &[0x7F]),
        (128, &[0x00, 0x80]),
        (256, &[0x01, 0x00]),
        (-1, &[0xFF]),
        (-128, &[0x80]),
        (-129, &[0xFF, 0x7F]),
        (65_535, &[0x00, 0xFF, 0xFF]),
        (i64::MAX, &[0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        (i64::MIN, &[0x80, 0, 0, 0, 0, 0, 0, 0]),
    ];
    for (value, contents) in cases {
        let bytes = written(|w| w.integer(Identifier::INTEGER, value));
        assert_eq!(&bytes[2..], contents, "{value}");
        assert_eq!(bytes[1] as usize, contents.len());
        assert_eq!(ber::integer_i64(&one(&bytes).unwrap()), Ok(value));
        assert_eq!(ber::enumerated(&one(&bytes).unwrap()), Ok(value));
    }
}

#[test]
fn unsigned_vectors() {
    let bytes = written(|w| w.unsigned(Identifier::INTEGER, u64::MAX));
    assert_eq!(
        bytes,
        [0x02, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    );
    assert_eq!(ber::integer_u64(&one(&bytes).unwrap()), Ok(u64::MAX));
    assert_eq!(
        ber::integer_i64(&one(&bytes).unwrap()),
        Err(Error::IntegerOutOfRange)
    );
    assert_eq!(
        written(|w| w.unsigned(Identifier::INTEGER, 0)),
        [0x02, 0x01, 0x00]
    );
    assert_eq!(
        written(|w| w.unsigned(Identifier::INTEGER, 200)),
        [0x02, 0x02, 0x00, 0xC8]
    );
    assert_eq!(ber::integer_u64(&one(&[0x02, 0x01, 0x05]).unwrap()), Ok(5));
    assert_eq!(
        ber::integer_u64(&one(&[0x02, 0x01, 0xFF]).unwrap()),
        Err(Error::IntegerOutOfRange)
    );
}

#[test]
fn malformed_integers_are_refused() {
    // §8.3.1: at least one octet. §8.3.2: no redundant leading octet.
    assert_eq!(
        ber::integer_i64(&one(&[0x02, 0x00]).unwrap()),
        Err(Error::InvalidInteger)
    );
    assert_eq!(
        ber::integer_i64(&one(&[0x02, 0x02, 0x00, 0x7F]).unwrap()),
        Err(Error::InvalidInteger)
    );
    assert_eq!(
        ber::integer_i64(&one(&[0x02, 0x02, 0xFF, 0x80]).unwrap()),
        Err(Error::InvalidInteger)
    );
    let nine = [0x02, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(
        ber::integer_i64(&one(&nine).unwrap()),
        Err(Error::IntegerOutOfRange)
    );
    assert_eq!(ber::integer_bytes(&one(&nine).unwrap()).unwrap().len(), 9);
    assert_eq!(
        ber::integer_i64(&one(&[0x22, 0x00]).unwrap()),
        Err(Error::WrongForm)
    );
}

// §8.6: BIT STRING.

#[test]
fn bit_string_vectors() {
    let value = BitString {
        unused: 4,
        bytes: vec![0x0A, 0x3B, 0x5F, 0x29, 0x1C, 0xD0],
    };
    let primitive = [0x03, 0x07, 0x04, 0x0A, 0x3B, 0x5F, 0x29, 0x1C, 0xD0];
    assert_eq!(
        ber::bit_string(&one(&primitive).unwrap()),
        Ok(value.clone())
    );
    let mut w = Writer::new();
    w.bit_string(Identifier::BIT_STRING, &value).unwrap();
    assert_eq!(w.into_bytes(), primitive);
    // The same value in segments, indefinite length (§8.6.4).
    let constructed = [
        0x23, 0x80, 0x03, 0x03, 0x00, 0x0A, 0x3B, 0x03, 0x05, 0x04, 0x5F, 0x29, 0x1C, 0xD0, 0x00,
        0x00,
    ];
    assert_eq!(ber::bit_string(&one(&constructed).unwrap()), Ok(value));
    assert_eq!(
        ber::bit_string(&one(&[0x03, 0x01, 0x00]).unwrap()),
        Ok(BitString::default())
    );
    // Implicitly tagged, as the support options of Initiate.
    let tagged = ber::bit_string(&one(&[0x81, 0x03, 0x05, 0xF1, 0x00]).unwrap()).unwrap();
    assert_eq!((tagged.unused, tagged.bytes), (5, vec![0xF1, 0x00]));
}

#[test]
fn malformed_bit_strings_are_refused() {
    let bad: [&[u8]; 5] = [
        &[0x03, 0x00],
        &[0x03, 0x02, 0x08, 0x00],
        &[0x03, 0x01, 0x03],
        // A segment other than the last with unused bits.
        &[0x23, 0x08, 0x03, 0x02, 0x04, 0xF0, 0x03, 0x02, 0x00, 0xFF],
        // A segment that is not a BIT STRING.
        &[0x23, 0x04, 0x04, 0x02, 0x00, 0xFF],
    ];
    for bytes in bad {
        assert_eq!(
            ber::bit_string(&one(bytes).unwrap()),
            Err(Error::InvalidBitString),
            "{bytes:02X?}"
        );
    }
    let mut w = Writer::new();
    assert_eq!(
        w.bit_string(
            Identifier::BIT_STRING,
            &BitString {
                unused: 8,
                bytes: vec![0]
            }
        ),
        Err(Error::InvalidBitString)
    );
    assert_eq!(
        w.bit_string(
            Identifier::BIT_STRING,
            &BitString {
                unused: 1,
                bytes: vec![]
            }
        ),
        Err(Error::InvalidBitString)
    );
}

// §8.7: OCTET STRING.

#[test]
fn octet_string_vectors() {
    assert_eq!(ber::octet_string(&one(&[0x04, 0x00]).unwrap()), Ok(vec![]));
    assert_eq!(
        ber::octet_string(&one(&[0x04, 0x02, 0x01, 0x02]).unwrap()),
        Ok(vec![1, 2])
    );
    // Constructed, with a constructed segment inside (§8.7.3.2, note 1).
    let nested = [
        0x24, 0x0A, 0x04, 0x01, 0x01, 0x24, 0x05, 0x04, 0x03, 0x02, 0x03, 0x04,
    ];
    assert_eq!(
        ber::octet_string(&one(&nested).unwrap()),
        Ok(vec![1, 2, 3, 4])
    );
    let wrong = [0x24, 0x03, 0x03, 0x01, 0x00];
    assert!(matches!(
        ber::octet_string(&one(&wrong).unwrap()),
        Err(Error::UnexpectedIdentifier { .. })
    ));
    assert_eq!(
        written(|w| w.octet_string(Identifier::context(9, false), &[0xAB])),
        [0x89, 0x01, 0xAB]
    );
}

// §8.8: NULL.

#[test]
fn null_vectors() {
    assert_eq!(ber::null(&one(&[0x05, 0x00]).unwrap()), Ok(()));
    assert_eq!(
        ber::null(&one(&[0x05, 0x01, 0x00]).unwrap()),
        Err(Error::InvalidNull)
    );
    assert_eq!(written(|w| w.null(Identifier::NULL)), [0x05, 0x00]);
}

// §8.19: OBJECT IDENTIFIER.

#[test]
fn object_identifier_vectors() {
    let cases: [(&[u64], &[u8]); 4] = [
        (&[2, 999, 3], &[0x88, 0x37, 0x03]),
        (&[1, 2, 840, 113_549], &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]),
        (&[0, 39], &[0x27]),
        (&[1, 0, 9506, 2, 1], &[0x28, 0xCA, 0x22, 0x02, 0x01]),
    ];
    for (arcs, contents) in cases {
        let oid = ObjectIdentifier(arcs.to_vec());
        let mut w = Writer::new();
        w.object_identifier(Identifier::OBJECT_IDENTIFIER, &oid)
            .unwrap();
        let bytes = w.into_bytes();
        assert_eq!(&bytes[2..], contents, "{arcs:?}");
        assert_eq!(ber::object_identifier(&one(&bytes).unwrap()), Ok(oid));
    }
}

#[test]
fn malformed_object_identifiers_are_refused() {
    let bad: [&[u8]; 4] = [
        &[0x06, 0x00],
        &[0x06, 0x02, 0x80, 0x01],
        &[0x06, 0x01, 0x88],
        &[0x06, 0x02, 0x2A, 0x80],
    ];
    for bytes in bad {
        assert_eq!(
            ber::object_identifier(&one(bytes).unwrap()),
            Err(Error::InvalidObjectIdentifier),
            "{bytes:02X?}"
        );
    }
    let mut w = Writer::new();
    for arcs in [vec![1], vec![3, 1], vec![1, 40], vec![]] {
        assert_eq!(
            w.object_identifier(Identifier::OBJECT_IDENTIFIER, &ObjectIdentifier(arcs)),
            Err(Error::InvalidObjectIdentifier)
        );
    }
    assert!(w.as_bytes().is_empty());
}

// §8.23: restricted character strings.

#[test]
fn string_vectors() {
    let visible = [0x1A, 0x05, b'L', b'L', b'N', b'0', b' '];
    assert_eq!(
        ber::string(&one(&visible).unwrap(), Charset::Visible),
        Ok("LLN0 ".to_owned())
    );
    let segments = [0x3A, 0x08, 0x04, 0x02, b'a', b'b', 0x04, 0x02, b'c', b'd'];
    assert_eq!(
        ber::string(&one(&segments).unwrap(), Charset::Visible),
        Ok("abcd".to_owned())
    );
    let utf8 = [0x0C, 0x02, 0xC3, 0xA9];
    assert_eq!(
        ber::string(&one(&utf8).unwrap(), Charset::Utf8),
        Ok("é".to_owned())
    );
    assert_eq!(
        ber::string(&one(&utf8).unwrap(), Charset::Visible),
        Err(Error::InvalidCharacter)
    );
    assert_eq!(
        ber::string(&one(&[0x1A, 0x01, 0x7F]).unwrap(), Charset::Visible),
        Err(Error::InvalidCharacter)
    );
    assert_eq!(
        ber::string(&one(&[0x19, 0x01, 0x1B]).unwrap(), Charset::Graphic),
        Err(Error::InvalidCharacter)
    );
    assert_eq!(
        ber::string(&one(&[0x0C, 0x01, 0xFF]).unwrap(), Charset::Utf8),
        Err(Error::InvalidCharacter)
    );
    let mut w = Writer::new();
    w.string(Identifier::VISIBLE_STRING, "abc", Charset::Visible)
        .unwrap();
    assert_eq!(w.as_bytes(), [0x1A, 0x03, b'a', b'b', b'c']);
    assert_eq!(
        w.string(Identifier::VISIBLE_STRING, "é", Charset::Visible),
        Err(Error::InvalidCharacter)
    );
}

// §8.9: SEQUENCE, written by nesting.

#[test]
fn constructed_writing() {
    let mut w = Writer::new();
    w.constructed(Identifier::application(0, true), |seq| {
        seq.integer(Identifier::context(0, false), 1);
        seq.constructed(Identifier::context(1, true), |inner| {
            inner.boolean(Identifier::BOOLEAN, true);
            Ok::<(), Error>(())
        })
    })
    .unwrap();
    let bytes = w.into_bytes();
    assert_eq!(
        bytes,
        [0x60, 0x08, 0x80, 0x01, 0x01, 0xA1, 0x03, 0x01, 0x01, 0xFF]
    );
    let outer = one(&bytes)
        .unwrap()
        .expect(Identifier::application(0, true))
        .unwrap();
    let mut children = outer.children().unwrap();
    assert_eq!(
        ber::integer_i64(
            &children
                .read_expected(Identifier::context(0, false))
                .unwrap()
        ),
        Ok(1)
    );
    let inner = children
        .read_expected(Identifier::context(1, true))
        .unwrap();
    assert!(ber::boolean(&inner.children().unwrap().read().unwrap()).unwrap());
    children.finish().unwrap();
}
