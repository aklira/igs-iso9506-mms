// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! TPKT framing (RFC 1006) and class 0 TPDUs (ITU-T X.224 §13), task C2.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use igs_iso9506_mms_codec::transport::{
    encode_frame, reason, reject_cause, ConnectionTpdu, DataTpdu, DisconnectRequest, Error,
    ErrorTpdu, FrameDecoder, Parameters, Tpdu, TpduSize, MAX_TPDU,
};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// A CR TPDU as the reference client of the bench sends it, TPKT header removed (observation,
/// task F5). It proposes 8192 octets, which X.224 does not allow in class 0: the decoder keeps
/// it, and the connection decides.
const OBSERVED_CR: &str = "11e00000000100c0010dc2020001c1020001";
const OBSERVED_CC: &str = "11d00001000100c0010dc2020001c1020001";

#[test]
fn observed_connection_tpdus() {
    let cr = hex(OBSERVED_CR);
    let Tpdu::ConnectionRequest(request) = Tpdu::decode(&cr).unwrap() else {
        panic!("not a CR")
    };
    assert_eq!(
        (
            request.dst_ref,
            request.src_ref,
            request.class,
            request.options
        ),
        (0, 1, 0, 0)
    );
    assert_eq!(request.parameters.tpdu_size, Some(TpduSize::S8192));
    assert_eq!(
        request.parameters.called_selector.as_deref(),
        Some(&[0, 1][..])
    );
    assert_eq!(
        request.parameters.calling_selector.as_deref(),
        Some(&[0, 1][..])
    );
    assert_eq!(Tpdu::ConnectionRequest(request).encode().unwrap(), cr);

    let cc = hex(OBSERVED_CC);
    let Tpdu::ConnectionConfirm(confirm) = Tpdu::decode(&cc).unwrap() else {
        panic!("not a CC")
    };
    assert_eq!((confirm.dst_ref, confirm.src_ref), (1, 1));
    assert_eq!(Tpdu::ConnectionConfirm(confirm).encode().unwrap(), cc);
}

#[test]
fn connection_request_built_from_fields() {
    let request = Tpdu::ConnectionRequest(ConnectionTpdu {
        src_ref: 0x1234,
        parameters: Parameters {
            tpdu_size: Some(TpduSize::S1024),
            preferred_max_tpdu_size: Some(8),
            ..Parameters::default()
        },
        ..ConnectionTpdu::default()
    });
    let bytes = request.encode().unwrap();
    assert_eq!(
        bytes,
        [0x0C, 0xE0, 0x00, 0x00, 0x12, 0x34, 0x00, 0xC0, 0x01, 0x0A, 0xF0, 0x01, 0x08]
    );
    assert_eq!(Tpdu::decode(&bytes).unwrap(), request);
    assert_eq!(TpduSize::S1024.octets(), 1024);
    assert_eq!(TpduSize::from_code(14), None);
}

#[test]
fn connection_parameter_rules() {
    // An undefined parameter is ignored in a CR TPDU and refused elsewhere (§13.2.3).
    let cr = [
        0x0C, 0xE0, 0, 0, 0, 1, 0, 0x99, 0x01, 0xAA, 0xC0, 0x01, 0x07, 0x00,
    ];
    let Tpdu::ConnectionRequest(request) = Tpdu::decode(&cr).unwrap() else {
        panic!()
    };
    assert!(request.parameters.other.is_empty());
    let cc = [
        0x0C, 0xD0, 0, 1, 0, 1, 0, 0x99, 0x01, 0xAA, 0xC0, 0x01, 0x07, 0x00,
    ];
    assert_eq!(
        Tpdu::decode(&cc),
        Err(Error::InvalidParameterCode { offset: 7 })
    );
    // A duplicated parameter takes its last value.
    let twice = [
        0x0C, 0xE0, 0, 0, 0, 1, 0, 0xC0, 0x01, 0x0B, 0xC0, 0x01, 0x08, 0x00,
    ];
    let Tpdu::ConnectionRequest(request) = Tpdu::decode(&twice).unwrap() else {
        panic!()
    };
    assert_eq!(request.parameters.tpdu_size, Some(TpduSize::S256));
    assert_eq!(request.user_data, [0x00]);
    // A defined parameter not decoded field by field is kept as received.
    let version = [0x09, 0xE0, 0, 0, 0, 1, 0, 0xC4, 0x01, 0x01];
    let Tpdu::ConnectionRequest(request) = Tpdu::decode(&version).unwrap() else {
        panic!()
    };
    assert_eq!(request.parameters.other, [(0xC4, vec![0x01])]);
}

#[test]
fn invalid_connection_parameters_are_refused() {
    let size = [0x09, 0xE0, 0, 0, 0, 1, 0, 0xC0, 0x01, 0x0E];
    assert_eq!(
        Tpdu::decode(&size),
        Err(Error::InvalidParameterValue { offset: 9 })
    );
    let preferred = [0x09, 0xE0, 0, 0, 0, 1, 0, 0xF0, 0x01, 0x00];
    assert_eq!(
        Tpdu::decode(&preferred),
        Err(Error::InvalidParameterValue { offset: 9 })
    );
    // A parameter running past the header.
    let overrun = [
        0x09, 0xE0, 0, 0, 0, 1, 0, 0xC1, 0x05, 0x00, 0xAA, 0xAA, 0xAA, 0xAA,
    ];
    assert_eq!(
        Tpdu::decode(&overrun),
        Err(Error::InvalidParameterValue { offset: 8 })
    );
    let options = [0x0A, 0xE0, 0, 0, 0, 1, 0, 0xC6, 0x02, 0x00, 0x01];
    assert_eq!(
        Tpdu::decode(&options),
        Err(Error::InvalidParameterValue { offset: 9 })
    );
}

#[test]
fn header_length_rules() {
    // §13.2.1: 255 is reserved; the header must be shorter than the TPDU.
    assert_eq!(
        Tpdu::decode(&[0xFF, 0xF0, 0x80]),
        Err(Error::HeaderLength { offset: 0 })
    );
    assert_eq!(
        Tpdu::decode(&[0x02, 0xF0]),
        Err(Error::HeaderLength { offset: 0 })
    );
    assert_eq!(
        Tpdu::decode(&[0x05, 0xE0, 0, 0, 0, 1]),
        Err(Error::HeaderLength { offset: 0 })
    );
    assert_eq!(Tpdu::decode(&[]), Err(Error::Truncated));
}

#[test]
fn data_tpdu() {
    let bytes = [0x02, 0xF0, 0x80, 0x0D, 0xB2];
    let tpdu = Tpdu::decode(&bytes).unwrap();
    assert_eq!(
        tpdu,
        Tpdu::Data(DataTpdu {
            end_of_tsdu: true,
            number: 0,
            user_data: vec![0x0D, 0xB2]
        })
    );
    assert_eq!(tpdu.encode().unwrap(), bytes);
    let middle = Tpdu::Data(DataTpdu {
        end_of_tsdu: false,
        number: 0,
        user_data: vec![1],
    });
    assert_eq!(middle.encode().unwrap(), [0x02, 0xF0, 0x00, 0x01]);
    // ROA is not used in class 0; class 2 to 4 formats have a longer header.
    assert_eq!(
        Tpdu::decode(&[0x02, 0xF1, 0x80]),
        Err(Error::InvalidTpduType { code: 0xF1 })
    );
    assert_eq!(
        Tpdu::decode(&[0x04, 0xF0, 0, 1, 0x80, 0]),
        Err(Error::HeaderLength { offset: 0 })
    );
    assert_eq!(
        Tpdu::Data(DataTpdu::default()).encode().unwrap(),
        [0x02, 0xF0, 0x00]
    );
}

#[test]
fn disconnect_request() {
    let bytes = [0x06, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00];
    let tpdu = Tpdu::decode(&bytes).unwrap();
    let expected = DisconnectRequest {
        dst_ref: 1,
        src_ref: 2,
        reason: reason::NOT_SPECIFIED,
        ..DisconnectRequest::default()
    };
    assert_eq!(tpdu, Tpdu::DisconnectRequest(expected));
    assert_eq!(tpdu.encode().unwrap(), bytes);
    let info = [0x09, 0x80, 0, 1, 0, 2, 0x03, 0xE0, 0x01, 0x42];
    let Tpdu::DisconnectRequest(dr) = Tpdu::decode(&info).unwrap() else {
        panic!()
    };
    assert_eq!(
        (dr.reason, dr.additional_information),
        (reason::ADDRESS_UNKNOWN, Some(vec![0x42]))
    );
    let unknown = [0x09, 0x80, 0, 1, 0, 2, 0x00, 0xC0, 0x01, 0x07];
    assert_eq!(
        Tpdu::decode(&unknown),
        Err(Error::InvalidParameterCode { offset: 7 })
    );
}

#[test]
fn error_tpdu() {
    let tpdu = Tpdu::Error(ErrorTpdu {
        dst_ref: 7,
        cause: reject_cause::INVALID_TPDU_TYPE,
        invalid_tpdu: Some(vec![0x02, 0x60]),
    });
    let bytes = tpdu.encode().unwrap();
    assert_eq!(
        bytes,
        [0x08, 0x70, 0x00, 0x07, 0x02, 0xC1, 0x02, 0x02, 0x60]
    );
    assert_eq!(Tpdu::decode(&bytes).unwrap(), tpdu);
    assert_eq!(
        Tpdu::decode(&[0x03, 0x70, 0, 7]),
        Err(Error::HeaderLength { offset: 0 })
    );
}

#[test]
fn tpdus_outside_class_0_are_refused_with_their_cause() {
    // DC, ED, AK, EA and RJ TPDUs.
    for code in [0xC0u8, 0x10, 0x61, 0x20, 0x51] {
        let error = Tpdu::decode(&[0x06, code, 0, 1, 0, 1, 0]).unwrap_err();
        assert_eq!(error, Error::InvalidTpduType { code });
        assert_eq!(error.reject_cause(), Some(reject_cause::INVALID_TPDU_TYPE));
        assert_eq!(error.offset(), Some(1));
    }
    assert_eq!(
        Error::InvalidParameterValue { offset: 9 }.reject_cause(),
        Some(reject_cause::INVALID_PARAMETER_VALUE)
    );
    assert_eq!(
        Error::InvalidParameterCode { offset: 7 }.reject_cause(),
        Some(reject_cause::INVALID_PARAMETER_CODE)
    );
}

#[test]
fn encoding_limits() {
    let long = Tpdu::ConnectionRequest(ConnectionTpdu {
        parameters: Parameters {
            calling_selector: Some(vec![0; 256]),
            ..Parameters::default()
        },
        ..ConnectionTpdu::default()
    });
    assert!(long.encode().is_err());
    let data = Tpdu::Data(DataTpdu {
        end_of_tsdu: true,
        number: 0,
        user_data: vec![0; MAX_TPDU],
    });
    assert_eq!(data.encode(), Err(Error::TpduTooLong(MAX_TPDU + 3)));
    assert_eq!(
        encode_frame(&vec![0; MAX_TPDU + 1]),
        Err(Error::TpduTooLong(MAX_TPDU + 1))
    );
    assert_eq!(encode_frame(&vec![0; MAX_TPDU]).unwrap().len(), 65_535);
}

// RFC 1006: TPKT framing and the incremental decoder.

fn stream() -> (Vec<u8>, Vec<Vec<u8>>) {
    let tpdus = vec![
        hex(OBSERVED_CR),
        hex(OBSERVED_CC),
        Tpdu::Data(DataTpdu {
            end_of_tsdu: true,
            number: 0,
            user_data: vec![0xAB; 300],
        })
        .encode()
        .unwrap(),
        Tpdu::Data(DataTpdu {
            end_of_tsdu: false,
            number: 0,
            user_data: vec![],
        })
        .encode()
        .unwrap(),
        [0x06, 0x80, 0, 1, 0, 2, 0].to_vec(),
    ];
    let mut bytes = Vec::new();
    for tpdu in &tpdus {
        bytes.extend(encode_frame(tpdu).unwrap());
    }
    (bytes, tpdus)
}

fn drain(decoder: &mut FrameDecoder, out: &mut Vec<Vec<u8>>) {
    while let Some(tpdu) = decoder.next_tpdu().unwrap() {
        out.push(tpdu);
    }
}

#[test]
fn frame_header() {
    assert_eq!(
        encode_frame(&[0x02, 0xF0, 0x80]).unwrap(),
        [0x03, 0x00, 0x00, 0x07, 0x02, 0xF0, 0x80]
    );
}

#[test]
fn frames_split_at_every_octet_boundary() {
    let (bytes, tpdus) = stream();
    for cut in 0..=bytes.len() {
        let mut decoder = FrameDecoder::new();
        let mut out = Vec::new();
        decoder.push(&bytes[..cut]);
        drain(&mut decoder, &mut out);
        decoder.push(&bytes[cut..]);
        drain(&mut decoder, &mut out);
        assert_eq!(out, tpdus, "cut at {cut}");
        assert_eq!(decoder.buffered(), 0);
    }
}

#[test]
fn frames_one_octet_at_a_time_and_all_at_once() {
    let (bytes, tpdus) = stream();
    let mut decoder = FrameDecoder::new();
    let mut out = Vec::new();
    for octet in &bytes {
        decoder.push(std::slice::from_ref(octet));
        drain(&mut decoder, &mut out);
    }
    assert_eq!(out, tpdus);
    let mut decoder = FrameDecoder::new();
    let mut out = Vec::new();
    decoder.push(&bytes);
    drain(&mut decoder, &mut out);
    assert_eq!(out, tpdus);
    for tpdu in &out {
        Tpdu::decode(tpdu).unwrap();
    }
}

#[test]
fn malformed_frames_are_refused() {
    let mut decoder = FrameDecoder::new();
    decoder.push(&[0x02]);
    assert_eq!(decoder.next_tpdu(), Err(Error::TpktVersion(2)));
    let mut decoder = FrameDecoder::new();
    decoder.push(&[0x03, 0x00, 0x00, 0x06, 0x01, 0x02]);
    assert_eq!(decoder.next_tpdu(), Err(Error::TpktLength(6)));
    let mut decoder = FrameDecoder::with_max_frame(2048 + 4);
    decoder.push(&[0x03, 0x00, 0x08, 0x05]);
    assert_eq!(decoder.next_tpdu(), Err(Error::TpktLength(2053)));
    // The reserved octet is ignored on receipt.
    let mut decoder = FrameDecoder::new();
    decoder.push(&[0x03, 0xFF, 0x00, 0x07, 0x02, 0xF0, 0x80]);
    assert_eq!(decoder.next_tpdu(), Ok(Some(vec![0x02, 0xF0, 0x80])));
    assert_eq!(decoder.next_tpdu(), Ok(None));
}

/// Found by the property tests of task C8: fields wider than their bits were cut on encoding.
#[test]
fn encoding_refuses_fields_wider_than_their_bits() {
    let request = |credit, class, options| {
        Tpdu::ConnectionRequest(ConnectionTpdu {
            credit,
            dst_ref: 0,
            src_ref: 1,
            class,
            options,
            parameters: Parameters::default(),
            user_data: Vec::new(),
        })
    };
    assert!(request(15, 15, 15).encode().is_ok());
    assert_eq!(
        request(16, 0, 0).encode(),
        Err(Error::FieldOutOfRange("credit"))
    );
    assert_eq!(
        request(0, 16, 0).encode(),
        Err(Error::FieldOutOfRange("class"))
    );
    assert_eq!(
        request(0, 0, 16).encode(),
        Err(Error::FieldOutOfRange("options"))
    );
    let data = Tpdu::Data(DataTpdu {
        end_of_tsdu: true,
        number: 128,
        user_data: Vec::new(),
    });
    assert_eq!(data.encode(), Err(Error::FieldOutOfRange("TPDU number")));
    // A parameter of `other` must be one that decoding keeps there.
    let mut parameters = Parameters::default();
    parameters.other.push((0xC0, vec![0x0A]));
    let Tpdu::ConnectionRequest(mut cr) = request(0, 0, 0) else {
        unreachable!()
    };
    cr.parameters = parameters;
    assert_eq!(
        Tpdu::ConnectionRequest(cr).encode(),
        Err(Error::FieldOutOfRange("other parameter"))
    );
}
