// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Typed UtcTime, MMS strings and the form of `TypeDescription.mMSString` (task N3 of igs-iec61850-mms,
//! D-034). The vectors are built from the octet layout of IEC 61850-8-1 Annex F.3.1, Table 36 and ISO
//! 9506-2, not from the codec.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use igs_iso9506_mms_codec::asn::{self, Error};
use igs_iso9506_mms_codec::generated::types::{
    Data, DataMMSString, Integer32, TypeDescription, UtcTime,
};
use igs_iso9506_mms_codec::mms::profile::Profile;
use igs_iso9506_mms_codec::mms::{
    self, check_strings, StringLimits, TimeAccuracy, TimeQuality, UtcTimestamp,
};

/// The quality with no flag and no accuracy: `00000000`.
const NO_FLAG: TimeQuality = TimeQuality {
    leap_second_known: false,
    clock_failure: false,
    clock_not_synchronized: false,
    accuracy: TimeAccuracy::Bits(0),
};

#[test]
fn the_epoch_and_a_known_date_read_from_their_octets() {
    // 1970-01-01 00:00:00 UTC: seconds, fraction and quality are zero.
    let epoch = UtcTimestamp::from_octets([0; 8]).unwrap();
    assert_eq!(
        (epoch.seconds, epoch.fraction, epoch.quality),
        (0, 0, NO_FLAG)
    );
    // 2000-01-01 00:00:00 UTC is 946 684 800 s after the epoch: 0x386D4380 on 32 bits.
    let millennium = UtcTimestamp::from_octets([0x38, 0x6D, 0x43, 0x80, 0, 0, 0, 0]).unwrap();
    assert_eq!(millennium.seconds, 946_684_800);
    assert_eq!(millennium.fraction, 0);
}

#[test]
fn the_fraction_is_the_24_bits_after_the_seconds() {
    // Half a second is 2^23 units of 2^-24 s: the fraction 0x800000 is the three octets 80 00 00.
    let half = UtcTimestamp::from_octets([0, 0, 0, 0, 0x80, 0, 0, 0]).unwrap();
    assert_eq!(half.fraction, 0x80_0000);
    assert_eq!(half.to_octets(), [0, 0, 0, 0, 0x80, 0, 0, 0]);
    // The last unit of the fraction.
    let last = UtcTimestamp::from_octets([0, 0, 0, 1, 0xFF, 0xFF, 0xFF, 0]).unwrap();
    assert_eq!((last.seconds, last.fraction), (1, 0xFF_FFFF));
}

#[test]
fn the_quality_flags_and_accuracy_follow_table_36() {
    // 0xAA = 1 0 1 01010: leap seconds known, clock not synchronised, accuracy of 10 bits.
    let aa = TimeQuality::from_octet(0xAA).unwrap();
    assert!(aa.leap_second_known && aa.clock_not_synchronized && !aa.clock_failure);
    assert_eq!(aa.accuracy, TimeAccuracy::Bits(10));
    // 0x40: clock failure, accuracy 0 bits.
    let failure = TimeQuality::from_octet(0x40).unwrap();
    assert!(failure.clock_failure && !failure.leap_second_known);
    assert_eq!(failure.accuracy, TimeAccuracy::Bits(0));
    // 0x1F = 11111: the accuracy is unspecified; 0x18 = 11000: 24 bits, the largest valid value.
    assert_eq!(
        TimeQuality::from_octet(0x1F).unwrap().accuracy,
        TimeAccuracy::Unspecified
    );
    assert_eq!(
        TimeQuality::from_octet(0x18).unwrap().accuracy,
        TimeAccuracy::Bits(24)
    );
    // 11001 to 11110 are invalid.
    for octet in [0x19, 0x1A, 0x1D, 0x1E] {
        assert_eq!(
            TimeQuality::from_octet(octet),
            Err(Error::Invalid { ty: "TimeQuality" }),
            "{octet:#x}"
        );
    }
}

#[test]
fn a_quality_octet_round_trips() {
    for octet in 0..=u8::MAX {
        if let Ok(quality) = TimeQuality::from_octet(octet) {
            // The bits above the flags and the accuracy are the only ones read: 0x1F covers accuracy 31.
            assert_eq!(quality.to_octet(), octet, "{octet:#x}");
        }
    }
}

#[test]
fn the_octets_must_be_eight() {
    let eight = UtcTime(vec![0, 0, 0, 0, 0, 0, 0, 0]);
    assert!(eight.timestamp().is_ok());
    assert_eq!(
        UtcTime(vec![0; 7]).timestamp(),
        Err(Error::WrongSize { ty: "UtcTime" })
    );
    assert_eq!(
        UtcTime(vec![0; 9]).timestamp(),
        Err(Error::WrongSize { ty: "UtcTime" })
    );
    // A bad quality is refused through the timestamp.
    assert_eq!(
        UtcTime(vec![0, 0, 0, 0, 0, 0, 0, 0x19]).timestamp(),
        Err(Error::Invalid { ty: "TimeQuality" })
    );
}

#[test]
fn a_fraction_wider_than_24_bits_is_refused() {
    assert!(UtcTimestamp::new(0, 0xFF_FFFF, NO_FLAG).is_ok());
    assert_eq!(
        UtcTimestamp::new(0, 0x100_0000, NO_FLAG),
        Err(Error::Invalid { ty: "UtcTime" })
    );
}

#[test]
fn a_timestamp_round_trips_through_its_utc_time() {
    let stamp = UtcTimestamp::new(
        0x6AEF_0832,
        0x58_1062,
        TimeQuality {
            leap_second_known: true,
            clock_failure: false,
            clock_not_synchronized: false,
            accuracy: TimeAccuracy::Bits(20),
        },
    )
    .unwrap();
    let time = UtcTime::from_timestamp(stamp);
    assert_eq!(time.0, [0x6A, 0xEF, 0x08, 0x32, 0x58, 0x10, 0x62, 0x94]);
    assert_eq!(time.timestamp().unwrap(), stamp);
    // The codec carries the same octets in Data (tag [17], Annex F.3.1).
    let bytes = asn::encode_value::<Data>(&Data::UtcTime(time.clone())).unwrap();
    assert_eq!(bytes.get(..2), Some(&[0x91, 0x08][..]));
    assert_eq!(
        asn::decode_value::<Data>(&bytes).unwrap(),
        Data::UtcTime(time)
    );
}

#[test]
fn the_mms_string_of_type_description_is_read_in_either_form() {
    // ISO 9506-2: [16] EXPLICIT Integer32 (B0 03 02 01 40). IEC 61850-8-1 Annex F.1: [16] IMPLICIT (90 01 40).
    let explicit = [0xB0, 0x03, 0x02, 0x01, 0x40];
    let implicit = [0x90, 0x01, 0x40];
    let expected = TypeDescription::MMSString(Integer32(64));
    assert_eq!(
        asn::decode_value::<TypeDescription>(&explicit).unwrap(),
        expected
    );
    assert_eq!(
        asn::decode_value::<TypeDescription>(&implicit).unwrap(),
        expected
    );
}

#[test]
fn the_mms_string_of_type_description_is_written_as_the_profile_asks() {
    let value = TypeDescription::MMSString(Integer32(64));
    // The explicit form is the default; the IEC 61850 profile writes the implicit one (D-034).
    assert_eq!(
        asn::encode_value_with::<TypeDescription>(&value, false).unwrap(),
        [0xB0, 0x03, 0x02, 0x01, 0x40]
    );
    assert_eq!(
        asn::encode_value_with::<TypeDescription>(&value, true).unwrap(),
        [0x90, 0x01, 0x40]
    );
    assert_ne!(
        Profile::TASE2.implicit_mms_string,
        Profile::iec61850(Default::default()).implicit_mms_string
    );
    assert!(Profile::iec61850(Default::default()).implicit_mms_string);
}

#[test]
fn a_utc_time_of_type_description_is_eight_octets_of_data() {
    // TypeDescription utc-time [17] is an implicit NULL (Annex F.2.2): 91 00 in both profiles.
    assert_eq!(
        asn::encode_value_with::<TypeDescription>(&TypeDescription::UtcTime, true).unwrap(),
        [0x91, 0x00]
    );
    assert_eq!(
        asn::decode_value::<TypeDescription>(&[0x91, 0x00]).unwrap(),
        TypeDescription::UtcTime
    );
}

#[test]
fn mms_strings_are_utf8_of_at_most_255_characters_and_1020_octets() {
    let four = "\u{1D11E}"; // a musical symbol: four octets in UTF-8
    assert_eq!(four.len(), 4);
    let full = DataMMSString(four.repeat(255));
    assert_eq!(full.0.len(), 1020, "255 characters of four octets");
    assert_eq!(check_strings_of(full.0.clone()), Ok(()));
    assert!(matches!(
        check_strings_of(four.repeat(256)),
        Err(igs_iso9506_mms_codec::mms::CbbError::DataString { .. })
    ));
}

#[test]
fn malformed_utf8_in_a_data_string_is_refused_by_the_codec() {
    // 0xC3 0x28 is not UTF-8: a UTF8String of two octets that the codec refuses.
    assert!(asn::decode_value::<Data>(&[0x90, 0x02, 0xC3, 0x28]).is_err());
    // A valid UTF-8 string of the same length is read.
    let text = asn::decode_value::<Data>(&[0x90, 0x02, 0xC3, 0xA9]).unwrap();
    assert_eq!(text, Data::MMSString(DataMMSString("é".into())));
}

#[test]
fn the_pdu_encoding_of_the_profile_is_what_the_association_sends() {
    use igs_iso9506_mms_codec::generated::types::{
        AccessResult, ConfirmedResponsePDU, ConfirmedServiceResponse, MMSpdu, ReadResponse,
        Unsigned32,
    };
    // A Read answer carrying an UtcTime: the same octets in both profiles, and the decoder reads them back.
    let pdu = MMSpdu::ConfirmedResponsePDU(ConfirmedResponsePDU {
        invoke_id: Unsigned32(1),
        service: ConfirmedServiceResponse::Read(ReadResponse {
            variable_access_specification: None,
            list_of_access_result: vec![AccessResult::Success(Data::UtcTime(UtcTime(vec![0; 8])))],
        }),
        service_ext: None,
    });
    let tase = mms::encode_for(&pdu, &Profile::TASE2).unwrap();
    let iec = mms::encode_for(&pdu, &Profile::iec61850(Default::default())).unwrap();
    assert_eq!(
        tase, iec,
        "no TypeDescription in this PDU: the profiles write the same octets"
    );
    assert_eq!(mms::decode(&iec).unwrap(), pdu);
}

fn check_strings_of(text: String) -> Result<(), igs_iso9506_mms_codec::mms::CbbError> {
    let pdu = igs_iso9506_mms_codec::generated::types::MMSpdu::ConfirmedResponsePDU(
        igs_iso9506_mms_codec::generated::types::ConfirmedResponsePDU {
            invoke_id: igs_iso9506_mms_codec::generated::types::Unsigned32(1),
            service: igs_iso9506_mms_codec::generated::types::ConfirmedServiceResponse::Read(
                igs_iso9506_mms_codec::generated::types::ReadResponse {
                    variable_access_specification: None,
                    list_of_access_result: vec![
                        igs_iso9506_mms_codec::generated::types::AccessResult::Success(
                            Data::MMSString(DataMMSString(text)),
                        ),
                    ],
                },
            ),
            service_ext: None,
        },
    );
    check_strings(&pdu, &StringLimits::IEC_61850)
}
