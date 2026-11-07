// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Presentation PPDUs (ITU-T X.226 §8), task C4: round trips and hand-written vectors.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use igs_iso9506_mms_codec::ber;
use igs_iso9506_mms_codec::presentation::{
    decode_abort, decode_connect, encode_connect, Abort, AbortProvider, AbortUser, AcceptNormal,
    Connect, ConnectAccept, ConnectNormal, ConnectRefuse, ContextDefinition, ContextResult,
    DefaultContextName, Encoding, Error, Mode, Pdv, PdvValues, UserData,
};
use igs_iso9506_mms_codec::schema::{BitString, ObjectIdentifier};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn oid(arcs: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier(arcs.to_vec())
}

/// User data of the CONNECT and ACCEPT SPDUs, and of one DATA TRANSFER SPDU, observed on the
/// bench (task F5). The inner values are the ACSE and MMS PDUs of the reference peers.
const OBSERVED_CP: &str = "318199a003800101a28191810400000001820400000001a423300f0201010604520100013004060251013010020103060528ca220201300406025101615e305c020101a0576055a107060528ca220203a20706052901876701a30302010ca606060429018767a70302010cbe2f282d020103a028a826800300fde881010582010583010aa416800101810305f100820c03ee1c00000408000079ef18";
const OBSERVED_CPA: &str = "3172a003800101a26b830400000001a512300780010081025101300780010081025101614f304d020101a0486146a107060528ca220203a203020100a305a103020100be2f282d020103a028a926800300fde881010582010583010aa416800101810305f100820c03ee1c000000000000000118";
const OBSERVED_DATA: &str = "610e300c020103a007a0050201018200";

/// Abstract syntax of ACSE, transfer syntax BER, abstract syntax of MMS (by their arcs).
const ACSE: &[u64] = &[2, 2, 1, 0, 1];
const BER: &[u64] = &[2, 1, 1];
const MMS: &[u64] = &[1, 0, 9506, 2, 1];

#[test]
fn observed_connect() {
    let bytes = hex(OBSERVED_CP);
    let (cp, cpc) = decode_connect(&bytes).unwrap();
    assert!(cpc.is_empty());
    assert_eq!(cp.mode, Mode::Normal);
    let normal = cp.normal.as_ref().unwrap();
    assert_eq!(normal.calling_selector.as_deref(), Some(&[0, 0, 0, 1][..]));
    assert_eq!(normal.called_selector.as_deref(), Some(&[0, 0, 0, 1][..]));
    let contexts = normal.context_definitions.as_ref().unwrap();
    assert_eq!(contexts.len(), 2);
    assert_eq!(
        (contexts[0].id, &contexts[0].abstract_syntax),
        (1, &oid(ACSE))
    );
    assert_eq!(
        (contexts[1].id, &contexts[1].abstract_syntax),
        (3, &oid(MMS))
    );
    assert_eq!(contexts[1].transfer_syntaxes, [oid(BER)]);
    let Some(UserData::Full(pdvs)) = &normal.user_data else {
        panic!()
    };
    assert_eq!(pdvs[0].context_id, 1);
    let PdvValues::SingleAsn1Type(acse) = &pdvs[0].values else {
        panic!()
    };
    // An AARQ APDU: [APPLICATION 0], constructed.
    assert_eq!(acse[0], 0x60);
    assert_eq!(encode_connect(&cp, &cpc).unwrap(), bytes);
}

#[test]
fn observed_accept() {
    let bytes = hex(OBSERVED_CPA);
    let cpa = ConnectAccept::decode(&bytes).unwrap();
    let normal = cpa.normal.as_ref().unwrap();
    let results = normal.context_results.as_ref().unwrap();
    assert_eq!(results.len(), 2);
    assert!(results
        .iter()
        .all(|r| r.result == 0 && r.transfer_syntax == Some(oid(BER))));
    assert_eq!(cpa.encode().unwrap(), bytes);
}

#[test]
fn observed_data() {
    let bytes = hex(OBSERVED_DATA);
    let data = UserData::decode_data(&bytes, Encoding::Full).unwrap();
    let UserData::Full(pdvs) = &data else {
        panic!()
    };
    assert_eq!((pdvs.len(), pdvs[0].context_id), (1, 3));
    let PdvValues::SingleAsn1Type(mms) = &pdvs[0].values else {
        panic!()
    };
    // A confirmed-RequestPDU of MMS: [0], constructed.
    assert_eq!(mms[0], 0xA0);
    assert_eq!(data.encode_data().unwrap(), bytes);
}

#[test]
fn connect_with_default_context_and_cpc() {
    let cp = Connect {
        mode: Mode::Normal,
        x410_parameters: None,
        normal: Some(ConnectNormal {
            protocol_version: Some(BitString {
                unused: 7,
                bytes: vec![0x80],
            }),
            context_definitions: Some(vec![ContextDefinition {
                id: 1,
                abstract_syntax: oid(ACSE),
                transfer_syntaxes: vec![oid(BER)],
            }]),
            default_context: Some(DefaultContextName {
                abstract_syntax: oid(MMS),
                transfer_syntax: oid(BER),
            }),
            presentation_requirements: Some(BitString {
                unused: 6,
                bytes: vec![0x00],
            }),
            user_data: Some(UserData::Simple(vec![0x60, 0x00])),
            ..ConnectNormal::default()
        }),
    };
    let cpc = [UserData::Simple(vec![0x60, 0x00])];
    let bytes = encode_connect(&cp, &cpc).unwrap();
    assert_eq!(&bytes[..2], [0x31, 0x33]);
    // [0] mode-selector, then [2] normal-mode parameters.
    assert_eq!(&bytes[2..9], [0xA0, 0x03, 0x80, 0x01, 0x01, 0xA2, 0x2C]);
    // Protocol version: one named bit, version-1.
    assert_eq!(&bytes[9..13], [0x80, 0x02, 0x07, 0x80]);
    // The CPC value after the CP PPDU (§8.3.3).
    assert_eq!(&bytes[bytes.len() - 4..], [0x40, 0x02, 0x60, 0x00]);
    assert_eq!(decode_connect(&bytes).unwrap(), (cp, cpc.to_vec()));
}

#[test]
fn cp_ignores_undefined_elements() {
    // §8.5.1: a [5] element and an unnamed bit are ignored in a CP PPDU.
    let bytes = [
        0x31, 0x0E, 0xA0, 0x03, 0x80, 0x01, 0x01, 0xA2, 0x07, 0x85, 0x01, 0xFF, 0x88, 0x02, 0x00,
        0xFF,
    ];
    let (cp, _) = decode_connect(&bytes).unwrap();
    let normal = cp.normal.unwrap();
    assert_eq!(
        normal.presentation_requirements,
        Some(BitString {
            unused: 0,
            bytes: vec![0xFF]
        })
    );
    assert_eq!(
        decode_connect(&[0x31, 0x00]),
        Err(Error::Missing("mode-selector"))
    );
    assert_eq!(
        decode_connect(&[0x31, 0x05, 0xA0, 0x03, 0x80, 0x01, 0x02]),
        Err(Error::InvalidValue("mode-value"))
    );
}

#[test]
fn accept_rejects_what_cp_would_ignore() {
    // §8.5.2: outside a CP PPDU, an unnamed bit or an undefined element is invalid.
    let unnamed_bit = [
        0x31, 0x0B, 0xA0, 0x03, 0x80, 0x01, 0x01, 0xA2, 0x04, 0x88, 0x02, 0x00, 0x20,
    ];
    assert_eq!(
        ConnectAccept::decode(&unnamed_bit),
        Err(Error::InvalidValue("presentation-requirements"))
    );
    let named = [
        0x31, 0x0B, 0xA0, 0x03, 0x80, 0x01, 0x01, 0xA2, 0x04, 0x88, 0x02, 0x06, 0xC0,
    ];
    assert!(ConnectAccept::decode(&named).is_ok());
    let undefined = [
        0x31, 0x0A, 0xA0, 0x03, 0x80, 0x01, 0x01, 0xA2, 0x03, 0x86, 0x01, 0x00,
    ];
    assert!(matches!(
        ConnectAccept::decode(&undefined),
        Err(Error::Unexpected(_))
    ));
    let bad_result = [
        0x31, 0x10, 0xA0, 0x03, 0x80, 0x01, 0x01, 0xA2, 0x09, 0xA5, 0x07, 0x30, 0x05, 0x80, 0x01,
        0x03, 0x82, 0x00,
    ];
    assert!(ConnectAccept::decode(&bad_result).is_err());
}

#[test]
fn accept_round_trip() {
    let cpa = ConnectAccept {
        mode: Mode::Normal,
        x410_parameters: None,
        normal: Some(AcceptNormal {
            responding_selector: Some(vec![0, 1]),
            context_results: Some(vec![
                ContextResult {
                    result: 0,
                    transfer_syntax: Some(oid(BER)),
                    provider_reason: None,
                },
                ContextResult {
                    result: 2,
                    transfer_syntax: None,
                    provider_reason: Some(1),
                },
            ]),
            user_data: Some(UserData::Full(vec![Pdv {
                transfer_syntax: None,
                context_id: 1,
                values: PdvValues::SingleAsn1Type(vec![0x61, 0x00]),
            }])),
            ..AcceptNormal::default()
        }),
    };
    let bytes = cpa.encode().unwrap();
    assert_eq!(ConnectAccept::decode(&bytes).unwrap(), cpa);
}

#[test]
fn refuse() {
    let cpr = ConnectRefuse {
        provider_reason: Some(5),
        default_context_result: Some(2),
        ..ConnectRefuse::default()
    };
    let bytes = cpr.encode().unwrap();
    assert_eq!(bytes, [0x30, 0x06, 0x87, 0x01, 0x02, 0x8A, 0x01, 0x05]);
    assert_eq!(ConnectRefuse::decode(&bytes).unwrap(), cpr);
    assert_eq!(
        ConnectRefuse::decode(&[0x30, 0x03, 0x8A, 0x01, 0x08]),
        Err(Error::InvalidValue("provider-reason"))
    );
}

#[test]
fn aborts() {
    let arp = Abort::Provider(AbortProvider {
        reason: Some(1),
        event: Some(3),
    });
    let bytes = arp.encode().unwrap();
    assert_eq!(bytes, [0x30, 0x06, 0x80, 0x01, 0x01, 0x81, 0x01, 0x03]);
    assert_eq!(decode_abort(&bytes).unwrap(), arp);
    assert_eq!(
        decode_abort(&[0x30, 0x03, 0x80, 0x01, 0x07]),
        Err(Error::InvalidValue("abort-reason"))
    );
    let aru = Abort::User(AbortUser {
        context_list: Some(vec![(3, oid(BER))]),
        user_data: Some(UserData::Full(vec![Pdv {
            transfer_syntax: None,
            context_id: 1,
            values: PdvValues::SingleAsn1Type(vec![0x64, 0x00]),
        }])),
    });
    let bytes = aru.encode().unwrap();
    assert_eq!(&bytes[..4], [0xA0, 0x16, 0xA0, 0x09]);
    assert_eq!(decode_abort(&bytes).unwrap(), aru);
    assert_eq!(
        decode_abort(&[0x31, 0x00]).unwrap(),
        Abort::UserX410(vec![])
    );
}

#[test]
fn user_data_encodings() {
    // Simple encoding alone: the values without identifier or length (§8.4.1.4 c).
    let simple = UserData::decode_data(&[0xA0, 0x03, 0x02, 0x01, 0x01], Encoding::Simple).unwrap();
    assert_eq!(
        simple.encode_data().unwrap(),
        [0xA0, 0x03, 0x02, 0x01, 0x01]
    );
    // Octet-aligned and arbitrary PDVs, with a transfer syntax name.
    let full = UserData::Full(vec![
        Pdv {
            transfer_syntax: Some(oid(BER)),
            context_id: 3,
            values: PdvValues::OctetAligned(vec![1, 2]),
        },
        Pdv {
            transfer_syntax: None,
            context_id: 5,
            values: PdvValues::Arbitrary(BitString {
                unused: 4,
                bytes: vec![0xF0],
            }),
        },
    ]);
    let bytes = full.encode_data().unwrap();
    assert_eq!(&bytes[..2], [0x61, 0x16]);
    assert_eq!(UserData::decode_data(&bytes, Encoding::Full).unwrap(), full);
}

#[test]
fn malformed_user_data_is_refused() {
    // single-ASN1-type holds exactly one encoding.
    let two = [
        0x61, 0x0B, 0x30, 0x09, 0x02, 0x01, 0x03, 0xA0, 0x04, 0x05, 0x00, 0x05, 0x00,
    ];
    assert_eq!(
        UserData::decode_data(&two, Encoding::Full),
        Err(Error::Ber(ber::Error::TrailingData))
    );
    let no_context = [0x61, 0x06, 0x30, 0x04, 0xA0, 0x02, 0x05, 0x00];
    assert!(UserData::decode_data(&no_context, Encoding::Full).is_err());
    let wrong_choice = [0x61, 0x08, 0x30, 0x06, 0x02, 0x01, 0x03, 0x83, 0x01, 0x00];
    assert!(matches!(
        UserData::decode_data(&wrong_choice, Encoding::Full),
        Err(Error::Unexpected(_))
    ));
    assert!(UserData::decode_data(&[0x61, 0x00, 0x00], Encoding::Full).is_err());
}

/// Found by the property tests of task C8: the encoder wrote numbers and bits that the decoder
/// refuses (X.226 §8.5).
#[test]
fn encoding_applies_the_checks_of_decoding() {
    let accept = |reason: i64, version: BitString| ConnectAccept {
        mode: Mode::Normal,
        x410_parameters: None,
        normal: Some(AcceptNormal {
            protocol_version: Some(version),
            context_results: Some(vec![ContextResult {
                result: 2,
                transfer_syntax: None,
                provider_reason: Some(reason),
            }]),
            ..AcceptNormal::default()
        }),
    };
    let version1 = BitString {
        unused: 7,
        bytes: vec![0x80],
    };
    let bytes = accept(3, version1.clone()).encode().unwrap();
    assert_eq!(
        ConnectAccept::decode(&bytes).unwrap(),
        accept(3, version1.clone())
    );
    assert_eq!(
        accept(4, version1).encode(),
        Err(Error::InvalidValue("provider-reason"))
    );
    let unnamed = BitString {
        unused: 6,
        bytes: vec![0x40],
    };
    assert_eq!(
        accept(0, unnamed).encode(),
        Err(Error::InvalidValue("protocol-version"))
    );
    let refuse = ConnectRefuse {
        provider_reason: Some(8),
        ..ConnectRefuse::default()
    };
    assert!(refuse.encode().is_err());
    let abort = Abort::Provider(AbortProvider {
        reason: Some(7),
        event: None,
    });
    assert!(abort.encode().is_err());
}
