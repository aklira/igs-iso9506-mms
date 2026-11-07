// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Session SPDUs (ITU-T X.225 §8), task C3: round trips and hand-written vectors for each SPDU.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use igs_iso9506_mms_codec::session::{
    decode_tsdu, encode_tsdu, si, Abort, Accept, Connect, ConnectAcceptItem, ConnectionIdentifier,
    DataTransfer, Disconnect, Error, Finish, GiveTokens, Refuse, Spdu, ABORT_TRANSPORT_RELEASED,
    ABORT_USER, FU_DUPLEX, PROTOCOL_VERSION_2,
};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn round_trip(spdus: &[Spdu]) -> Vec<u8> {
    let bytes = encode_tsdu(spdus).unwrap();
    assert_eq!(decode_tsdu(&bytes).unwrap(), spdus, "{bytes:02X?}");
    bytes
}

/// TSDUs observed on the bench (task F5), as the reference client and server send them: CONNECT,
/// ACCEPT, then GIVE TOKENS with DATA TRANSFER. The user data is the presentation layer's.
const OBSERVED_CN: &str = "0db20506130100160102140200023302000134020001c19c318199a003800101a28191810400000001820400000001a423300f0201010604520100013004060251013010020103060528ca220201300406025101615e305c020101a0576055a107060528ca220203a20706052901876701a30302010ca606060429018767a70302010cbe2f282d020103a028a826800300fde881010582010583010aa416800101810305f100820c03ee1c00000408000079ef18";
const OBSERVED_AC: &str = "0e8605061301001601021402000234020001c1743172a003800101a26b830400000001a512300780010081025101300780010081025101614f304d020101a0486146a107060528ca220203a203020100a305a103020100be2f282d020103a028a926800300fde881010582010583010aa416800101810305f100820c03ee1c000000000000000118";
const OBSERVED_DT: &str = "01000100610e300c020103a007a0050201018200";

#[test]
fn observed_connect() {
    let bytes = hex(OBSERVED_CN);
    let spdus = decode_tsdu(&bytes).unwrap();
    let [Spdu::Connect(cn)] = spdus.as_slice() else {
        panic!("{spdus:?}")
    };
    let item = cn.item.as_ref().unwrap();
    assert_eq!(
        (item.protocol_options, item.version_number),
        (0, PROTOCOL_VERSION_2)
    );
    assert_eq!(cn.session_user_requirements, Some(FU_DUPLEX));
    assert_eq!(cn.calling_selector.as_deref(), Some(&[0, 1][..]));
    assert_eq!(cn.called_selector.as_deref(), Some(&[0, 1][..]));
    assert_eq!(cn.user_data.as_ref().unwrap().len(), 0x9C);
    assert_eq!(encode_tsdu(&spdus).unwrap(), bytes);
}

#[test]
fn observed_accept() {
    let bytes = hex(OBSERVED_AC);
    let spdus = decode_tsdu(&bytes).unwrap();
    let [Spdu::Accept(ac)] = spdus.as_slice() else {
        panic!("{spdus:?}")
    };
    assert_eq!(ac.item.as_ref().unwrap().version_number, PROTOCOL_VERSION_2);
    assert_eq!(ac.session_user_requirements, Some(FU_DUPLEX));
    assert_eq!(ac.responding_selector.as_deref(), Some(&[0, 1][..]));
    assert_eq!(encode_tsdu(&spdus).unwrap(), bytes);
}

#[test]
fn observed_data_transfer() {
    let bytes = hex(OBSERVED_DT);
    let spdus = decode_tsdu(&bytes).unwrap();
    let [Spdu::GiveTokens(gt), Spdu::DataTransfer(dt)] = spdus.as_slice() else {
        panic!("{spdus:?}")
    };
    assert_eq!(*gt, GiveTokens::default());
    assert_eq!(dt.user_information, &bytes[4..]);
    assert_eq!(encode_tsdu(&spdus).unwrap(), bytes);
}

#[test]
fn connect_with_every_field() {
    let cn = Spdu::Connect(Connect {
        connection_identifier: Some(ConnectionIdentifier {
            ss_user_reference: Some(b"ref".to_vec()),
            common_reference: Some(b"20261107".to_vec()),
            additional_reference: Some(vec![1]),
        }),
        item: Some(ConnectAcceptItem {
            protocol_options: 0,
            tsdu_maximum_size: Some((0, 2048)),
            version_number: PROTOCOL_VERSION_2,
            token_setting: None,
            other: vec![],
        }),
        session_user_requirements: Some(FU_DUPLEX),
        calling_selector: Some(vec![0, 1]),
        called_selector: Some(vec![0, 2]),
        data_overflow: None,
        user_data: Some(vec![0xAA; 300]),
        other: vec![],
    });
    let bytes = round_trip(&[cn]);
    // SI 13; parameter units in increasing order of their codes (§8.2.6).
    assert_eq!(bytes[0], si::CONNECT);
    assert_eq!(&bytes[1..4], [0xFF, 0x01, 0x5E]);
    assert_eq!(&bytes[4..7], [0x01, 0x12, 0x0A]);
    // 300 octets of user data: the three-octet length indicator (§8.2.5).
    let user = bytes.len() - 304;
    assert_eq!(&bytes[user..user + 4], [0xC1, 0xFF, 0x01, 0x2C]);
}

#[test]
fn large_connect_user_data_uses_the_extended_parameter() {
    let cn = Spdu::Connect(Connect {
        user_data: Some(vec![1; 600]),
        ..Connect::default()
    });
    let bytes = round_trip(&[cn]);
    assert_eq!(&bytes[..6], [si::CONNECT, 0xFF, 0x02, 0x5C, 0xC2, 0xFF]);
    let too_long = Spdu::Connect(Connect {
        user_data: Some(vec![1; 10_241]),
        ..Connect::default()
    });
    assert_eq!(encode_tsdu(&[too_long]), Err(Error::TooLong));
}

#[test]
fn accept_refuse_finish_disconnect() {
    let ac = Spdu::Accept(Accept {
        item: Some(ConnectAcceptItem {
            version_number: PROTOCOL_VERSION_2,
            ..ConnectAcceptItem::default()
        }),
        session_user_requirements: Some(FU_DUPLEX),
        user_data: Some(vec![0x61, 0x00]),
        ..Accept::default()
    });
    assert_eq!(
        round_trip(&[ac]),
        [
            0x0E, 0x10, 0x05, 0x06, 0x13, 0x01, 0x00, 0x16, 0x01, 0x02, 0x14, 0x02, 0x00, 0x02,
            0xC1, 0x02, 0x61, 0x00
        ]
    );
    // Reason 2, rejection by the called SS-user, followed by user data.
    let rf = Spdu::Refuse(Refuse {
        transport_disconnect: Some(1),
        reason: Some(vec![2, 0x61]),
        ..Refuse::default()
    });
    assert_eq!(
        round_trip(&[rf]),
        [0x0C, 0x07, 0x11, 0x01, 0x01, 0x32, 0x02, 0x02, 0x61]
    );
    let fn_ = Spdu::Finish(Finish {
        transport_disconnect: Some(1),
        user_data: Some(vec![0x62]),
        ..Finish::default()
    });
    assert_eq!(
        round_trip(&[fn_]),
        [0x09, 0x06, 0x11, 0x01, 0x01, 0xC1, 0x01, 0x62]
    );
    let dn = Spdu::Disconnect(Disconnect {
        user_data: Some(vec![0x63]),
        ..Disconnect::default()
    });
    assert_eq!(round_trip(&[dn]), [0x0A, 0x03, 0xC1, 0x01, 0x63]);
    assert_eq!(round_trip(&[Spdu::Finish(Finish::default())]), [0x09, 0x00]);
}

#[test]
fn abort_and_abort_accept() {
    let ab = Spdu::Abort(Abort {
        transport_disconnect: ABORT_TRANSPORT_RELEASED | ABORT_USER,
        user_data: Some(vec![0x64]),
        ..Abort::default()
    });
    assert_eq!(
        round_trip(&[ab]),
        [0x19, 0x06, 0x11, 0x01, 0x03, 0xC1, 0x01, 0x64]
    );
    assert_eq!(round_trip(&[Spdu::AbortAccept]), [0x1A, 0x00]);
    // The Transport Disconnect parameter is mandatory (table 19).
    assert_eq!(
        decode_tsdu(&[0x19, 0x03, 0xC1, 0x01, 0x64]),
        Err(Error::MissingParameter(17))
    );
    assert_eq!(
        decode_tsdu(&[0x1A, 0x03, 0x11, 0x01, 0x01]),
        Err(Error::InvalidParameter(0))
    );
}

#[test]
fn give_tokens_and_data_transfer() {
    let gt = Spdu::GiveTokens(GiveTokens {
        token_item: Some(0x01),
        ..GiveTokens::default()
    });
    assert_eq!(round_trip(&[gt]), [0x01, 0x03, 0x10, 0x01, 0x01]);
    let pair = [
        Spdu::GiveTokens(GiveTokens::default()),
        Spdu::DataTransfer(DataTransfer {
            user_information: vec![1, 2, 3],
            ..DataTransfer::default()
        }),
    ];
    assert_eq!(round_trip(&pair), [0x01, 0x00, 0x01, 0x00, 1, 2, 3]);
    let segmented = [
        Spdu::GiveTokens(GiveTokens::default()),
        Spdu::DataTransfer(DataTransfer {
            enclosure: Some(0x01),
            user_information: vec![9],
            ..DataTransfer::default()
        }),
    ];
    assert_eq!(
        round_trip(&segmented),
        [0x01, 0x00, 0x01, 0x03, 0x19, 0x01, 0x01, 9]
    );
}

#[test]
fn concatenation_rules() {
    // DATA TRANSFER is category 2: never alone (§6.3.7).
    let dt = Spdu::DataTransfer(DataTransfer::default());
    assert_eq!(
        encode_tsdu(std::slice::from_ref(&dt)),
        Err(Error::Concatenation)
    );
    assert_eq!(
        encode_tsdu(&[Spdu::AbortAccept, dt]),
        Err(Error::Concatenation)
    );
    assert_eq!(encode_tsdu(&[]), Err(Error::Concatenation));
    // A category 1 SPDU fills its TSDU.
    assert_eq!(
        decode_tsdu(&[0x0A, 0x00, 0x01, 0x00]),
        Err(Error::TrailingData)
    );
    // PLEASE TOKENS before another category 2 SPDU: kept as received.
    let spdus = decode_tsdu(&[0x02, 0x00, 0x32, 0x00, 0xAA]).unwrap();
    assert!(matches!(
        &spdus[..],
        [Spdu::Other { si: 2, .. }, Spdu::Other { si: 50, .. }]
    ));
    assert_eq!(encode_tsdu(&spdus[..1]).unwrap(), [0x02, 0x00]);
}

#[test]
fn other_spdus_are_kept() {
    // NOT FINISHED: outside the functional units of the profile.
    let spdus = decode_tsdu(&[0x08, 0x03, 0xC1, 0x01, 0x07]).unwrap();
    assert_eq!(
        spdus,
        [Spdu::Other {
            si: 8,
            parameters: vec![0xC1, 0x01, 0x07],
            user_information: vec![]
        }]
    );
    assert_eq!(encode_tsdu(&spdus).unwrap(), [0x08, 0x03, 0xC1, 0x01, 0x07]);
    // Unknown parameter codes are valid (§8.2.6) and kept.
    let spdus = decode_tsdu(&[0x09, 0x03, 0x63, 0x01, 0x05]).unwrap();
    let [Spdu::Finish(fn_)] = spdus.as_slice() else {
        panic!()
    };
    assert_eq!(fn_.other, [(0x63, vec![0x05])]);
}

#[test]
fn malformed_spdus_are_refused() {
    assert_eq!(decode_tsdu(&[]), Err(Error::Truncated));
    assert_eq!(decode_tsdu(&[0x0D]), Err(Error::Truncated));
    assert_eq!(decode_tsdu(&[0x0D, 0xFF, 0x00]), Err(Error::Truncated));
    assert_eq!(decode_tsdu(&[0x0D, 0x05, 0x14, 0x02]), Err(Error::Length));
    // A unit running past the parameter field.
    assert_eq!(
        decode_tsdu(&[0x0D, 0x03, 0x14, 0x05, 0x00]),
        Err(Error::Length)
    );
    // Session User Requirements is two octets; selectors at most 16.
    assert_eq!(
        decode_tsdu(&[0x0D, 0x03, 0x14, 0x01, 0x02]),
        Err(Error::InvalidParameter(20))
    );
    let mut long = vec![0x0D, 19, 0x33, 17];
    long.extend([0; 17]);
    assert_eq!(decode_tsdu(&long), Err(Error::InvalidParameter(51)));
    // User Data and Extended User Data together.
    assert_eq!(
        decode_tsdu(&[0x0D, 0x06, 0xC1, 0x01, 0x00, 0xC2, 0x01, 0x00]),
        Err(Error::InvalidParameter(194))
    );
    // Connect/Accept Item without its mandatory Version Number.
    assert_eq!(
        decode_tsdu(&[0x0D, 0x05, 0x05, 0x03, 0x13, 0x01, 0x00]),
        Err(Error::MissingParameter(22))
    );
    assert_eq!(
        decode_tsdu(&[0x0C, 0x02, 0x32, 0x00]),
        Err(Error::InvalidParameter(50))
    );
}

#[test]
fn three_octet_length_indicator_is_read_for_small_values_too() {
    // §8.2.5 asks for one octet below 255; a peer writing three is still understood.
    assert_eq!(
        decode_tsdu(&[0x09, 0xFF, 0x00, 0x00]).unwrap(),
        [Spdu::Finish(Finish::default())]
    );
}

#[test]
fn units_out_of_order_decode_to_the_same_value_as_in_order() {
    // Found by a noise run: an unknown unit before a known one.
    let unordered = [0x09, 0x06, 0x63, 0x01, 0x05, 0x11, 0x01, 0x01];
    let ordered = [0x09, 0x06, 0x11, 0x01, 0x01, 0x63, 0x01, 0x05];
    let spdus = decode_tsdu(&unordered).unwrap();
    assert_eq!(spdus, decode_tsdu(&ordered).unwrap());
    assert_eq!(encode_tsdu(&spdus).unwrap(), ordered);
}
