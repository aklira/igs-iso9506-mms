// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Tests of the class 0 transport connection (task L2): both roles on a fake clock, with the
//! octets of each side passed to the other by the test itself.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::Duration;

use igs_iso9506_mms_codec::transport::{
    encode_frame, reason, reject_cause, ConnectionTpdu, DataTpdu, DisconnectRequest, ErrorTpdu,
    Parameters, Tpdu, TpduSize,
};
use igs_iso9506_mms_link::config::LinkConfig;
use igs_iso9506_mms_link::transport::{Action, Cause, Connection, Event, Role, MAX_TSDU};

const T0: Duration = Duration::ZERO;

fn config(size: TpduSize) -> LinkConfig {
    LinkConfig {
        tpdu_size: size,
        ..LinkConfig::default()
    }
}

fn connection(role: Role, config: LinkConfig) -> Connection {
    Connection::new(role, config).expect("valid configuration")
}

/// The TPKT frames of the Transmit actions.
fn frames(actions: &[Action]) -> Vec<Vec<u8>> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Transmit(frame) => Some(frame.clone()),
            _ => None,
        })
        .collect()
}

/// Passes the frames of `actions` to `to`, as received octets, and returns its actions.
fn feed(to: &mut Connection, actions: &[Action], now: Duration) -> Vec<Action> {
    frames(actions)
        .into_iter()
        .flat_map(|frame| to.handle(Event::Received(frame), now))
        .collect()
}

fn frame_of(tpdu: &Tpdu) -> Vec<u8> {
    encode_frame(&tpdu.encode().unwrap()).unwrap()
}

/// The TPDU carried by a TPKT frame.
fn tpdu_of(frame: &[u8]) -> Tpdu {
    Tpdu::decode(&frame[4..]).unwrap()
}

fn request(parameters: Parameters, user_data: Vec<u8>) -> Tpdu {
    Tpdu::ConnectionRequest(ConnectionTpdu {
        credit: 0,
        dst_ref: 0,
        src_ref: 7,
        class: 0,
        options: 0,
        parameters,
        user_data,
    })
}

/// Opens a connection between an initiator and a responder with these configurations.
fn open(initiator: LinkConfig, responder: LinkConfig) -> (Connection, Connection) {
    let mut a = connection(Role::Initiator, initiator);
    let mut b = connection(Role::Responder, responder);
    let cr = a.handle(Event::Connect, T0);
    let cc = feed(&mut b, &cr, T0);
    assert!(cc.contains(&Action::Opened));
    let _ = feed(&mut a, &cc, T0);
    assert!(a.is_open() && b.is_open());
    (a, b)
}

fn default_pair() -> (Connection, Connection) {
    open(LinkConfig::default(), LinkConfig::default())
}

// Establishment

#[test]
fn both_ends_open_at_the_size_the_responder_allows() {
    let (a, b) = open(config(TpduSize::S8192), config(TpduSize::S2048));
    assert_eq!(a.agreed_tpdu_size(), TpduSize::S2048);
    assert_eq!(b.agreed_tpdu_size(), TpduSize::S2048);
}

#[test]
fn a_request_without_a_size_is_answered_at_the_default_of_128() {
    let mut b = connection(Role::Responder, LinkConfig::default());
    let cr = frame_of(&request(Parameters::default(), Vec::new()));
    let actions = b.handle(Event::Received(cr), T0);
    assert!(actions.contains(&Action::Opened));
    assert!(b.is_open());
    assert_eq!(b.agreed_tpdu_size(), TpduSize::S128);
    match tpdu_of(&frames(&actions)[0]) {
        Tpdu::ConnectionConfirm(confirm) => {
            assert_eq!(confirm.parameters.tpdu_size, Some(TpduSize::S128));
            assert_eq!(
                confirm.dst_ref, 7,
                "the CC answers the source reference of the CR"
            );
        }
        other => panic!("expected a CC, got {other:?}"),
    }
}

#[test]
fn a_confirm_above_the_proposed_size_is_a_protocol_error() {
    let mut a = connection(Role::Initiator, config(TpduSize::S2048));
    let cr = a.handle(Event::Connect, T0);
    assert_eq!(frames(&cr).len(), 1);
    let confirm = Tpdu::ConnectionConfirm(ConnectionTpdu {
        credit: 0,
        dst_ref: 1,
        src_ref: 9,
        class: 0,
        options: 0,
        parameters: Parameters {
            tpdu_size: Some(TpduSize::S4096),
            ..Parameters::default()
        },
        user_data: Vec::new(),
    });
    let actions = feed(&mut a, &[Action::Transmit(frame_of(&confirm))], T0);
    assert!(actions.contains(&Action::Closed(Cause::Protocol(
        reject_cause::INVALID_PARAMETER_VALUE
    ))));
    assert!(a.is_closed());
    let answer = frames(&actions);
    assert!(
        matches!(tpdu_of(&answer[0]), Tpdu::Error(error) if error.cause == reject_cause::INVALID_PARAMETER_VALUE)
    );
}

#[test]
fn a_called_selector_that_is_not_ours_is_declined_with_address_unknown() {
    let responder = LinkConfig {
        called_tsap: Some(vec![1]),
        ..LinkConfig::default()
    };
    let initiator = LinkConfig {
        called_tsap: Some(vec![2]),
        ..LinkConfig::default()
    };
    let mut a = connection(Role::Initiator, initiator);
    let mut b = connection(Role::Responder, responder);
    let cr = a.handle(Event::Connect, T0);
    let refusal = feed(&mut b, &cr, T0);
    assert!(refusal.contains(&Action::Closed(Cause::Declined(reason::ADDRESS_UNKNOWN))));
    assert!(b.is_closed());
    let closed = feed(&mut a, &refusal, T0);
    assert!(closed.contains(&Action::Closed(Cause::Refused(reason::ADDRESS_UNKNOWN))));
    assert!(a.is_closed());
}

#[test]
fn a_request_with_user_data_is_declined_with_a_dr_of_source_reference_zero() {
    let mut b = connection(Role::Responder, LinkConfig::default());
    let cr = frame_of(&request(Parameters::default(), vec![1, 2, 3]));
    let actions = b.handle(Event::Received(cr), T0);
    assert!(actions.contains(&Action::Closed(Cause::Declined(reason::NOT_SPECIFIED))));
    match tpdu_of(&frames(&actions)[0]) {
        Tpdu::DisconnectRequest(refusal) => {
            assert_eq!(
                refusal.src_ref, 0,
                "X.224 §13.3: an unassigned source reference"
            );
            assert_eq!(refusal.dst_ref, 7);
        }
        other => panic!("expected a DR, got {other:?}"),
    }
}

#[test]
fn the_connect_timeout_is_checked_on_the_fake_clock() {
    let mut a = connection(Role::Initiator, LinkConfig::default());
    let _ = a.handle(Event::Connect, T0);
    assert!(a
        .handle(Event::Tick, Duration::from_millis(9_999))
        .is_empty());
    assert!(!a.is_closed());
    let actions = a.handle(Event::Tick, Duration::from_secs(10));
    assert_eq!(actions, vec![Action::Closed(Cause::Timeout)]);
    assert!(a.is_closed());
}

#[test]
fn a_connection_that_is_not_an_idle_initiator_refuses_to_connect() {
    let mut b = connection(Role::Responder, LinkConfig::default());
    assert!(matches!(
        b.handle(Event::Connect, T0).as_slice(),
        [Action::Misuse(_)]
    ));
    let mut a = connection(Role::Initiator, LinkConfig::default());
    let _ = a.handle(Event::Connect, T0);
    assert!(matches!(
        a.handle(Event::Connect, T0).as_slice(),
        [Action::Misuse(_)]
    ));
}

#[test]
fn a_configuration_that_fails_validation_is_refused_at_creation() {
    let bad = LinkConfig {
        nesting_level: 1,
        ..LinkConfig::default()
    };
    assert!(Connection::new(Role::Initiator, bad).is_err());
}

// Data transfer

#[test]
fn a_tsdu_within_one_tpdu_is_one_dt_with_the_eot_set() {
    let (mut a, mut b) = open(config(TpduSize::S2048), config(TpduSize::S2048));
    let limit = 2048 - 3;
    let tsdu = vec![0xAB; limit];
    let actions = a.handle(Event::Send(tsdu.clone()), T0);
    assert_eq!(frames(&actions).len(), 1);
    assert_eq!(feed(&mut b, &actions, T0), vec![Action::Deliver(tsdu)]);
}

#[test]
fn a_long_tsdu_is_segmented_to_the_agreed_size_and_reassembled() {
    let (mut a, mut b) = open(config(TpduSize::S2048), config(TpduSize::S2048));
    let tsdu: Vec<u8> = (0..5_000u32).map(|i| (i % 251) as u8).collect();
    let actions = a.handle(Event::Send(tsdu.clone()), T0);
    let sent = frames(&actions);
    assert_eq!(sent.len(), 3, "2 045 + 2 045 + 910 octets");
    let mut eots = Vec::new();
    for frame in &sent {
        assert!(frame.len() - 4 <= 2048, "a TPDU is at most the agreed size");
        match tpdu_of(frame) {
            Tpdu::Data(data) => eots.push(data.end_of_tsdu),
            other => panic!("expected a DT, got {other:?}"),
        }
    }
    assert_eq!(eots, vec![false, false, true]);
    assert_eq!(feed(&mut b, &actions, T0), vec![Action::Deliver(tsdu)]);
}

#[test]
fn an_empty_tsdu_is_one_dt_with_no_data() {
    let (mut a, mut b) = default_pair();
    let actions = a.handle(Event::Send(Vec::new()), T0);
    assert_eq!(frames(&actions).len(), 1);
    assert_eq!(
        feed(&mut b, &actions, T0),
        vec![Action::Deliver(Vec::new())]
    );
}

#[test]
fn a_stream_cut_into_single_octets_delivers_the_same_tsdu() {
    let (mut a, mut b) = default_pair();
    let tsdu = b"a whole TSDU, in pieces".to_vec();
    let actions = a.handle(Event::Send(tsdu.clone()), T0);
    let mut delivered = Vec::new();
    for frame in frames(&actions) {
        for octet in frame {
            delivered.extend(b.handle(Event::Received(vec![octet]), T0));
        }
    }
    assert_eq!(delivered, vec![Action::Deliver(tsdu)]);
}

#[test]
fn data_before_the_connection_is_open_is_a_misuse() {
    let mut a = connection(Role::Initiator, LinkConfig::default());
    assert!(matches!(
        a.handle(Event::Send(vec![1]), T0).as_slice(),
        [Action::Misuse(_)]
    ));
    assert!(
        !a.is_open(),
        "nothing was sent, and the connection is still idle"
    );
}

#[test]
fn a_dt_longer_than_the_agreed_size_is_refused() {
    let (_a, mut b) = open(config(TpduSize::S2048), config(TpduSize::S2048));
    let too_long = Tpdu::Data(DataTpdu {
        end_of_tsdu: true,
        number: 0,
        user_data: vec![0; 2048 - 3 + 1],
    });
    let actions = b.handle(Event::Received(frame_of(&too_long)), T0);
    assert!(actions.contains(&Action::Closed(Cause::Protocol(
        reject_cause::NOT_SPECIFIED
    ))));
    assert!(b.is_closed());
}

#[test]
fn an_empty_dt_without_the_eot_is_refused() {
    let (_a, mut b) = default_pair();
    let empty = Tpdu::Data(DataTpdu {
        end_of_tsdu: false,
        number: 0,
        user_data: Vec::new(),
    });
    let actions = b.handle(Event::Received(frame_of(&empty)), T0);
    assert!(actions.contains(&Action::Closed(Cause::Protocol(
        reject_cause::NOT_SPECIFIED
    ))));
}

#[test]
fn a_sequence_longer_than_the_maximum_tsdu_is_refused() {
    let (_a, mut b) = open(config(TpduSize::S2048), config(TpduSize::S2048));
    let chunk = Tpdu::Data(DataTpdu {
        end_of_tsdu: false,
        number: 0,
        user_data: vec![0; 2048 - 3],
    });
    let bytes = frame_of(&chunk);
    let mut refused = false;
    for _ in 0..=MAX_TSDU / (2048 - 3) {
        let actions = b.handle(Event::Received(bytes.clone()), T0);
        if actions.contains(&Action::Closed(Cause::Protocol(
            reject_cause::NOT_SPECIFIED,
        ))) {
            refused = true;
            break;
        }
    }
    assert!(refused, "the reassembly is bounded by MAX_TSDU");
    assert!(b.is_closed());
}

// Release, and the state of the peer

#[test]
fn a_local_release_is_implicit_and_sends_nothing() {
    let (mut a, _b) = default_pair();
    let actions = a.handle(Event::Release, T0);
    assert_eq!(actions, vec![Action::Closed(Cause::Local)]);
    assert!(
        a.handle(Event::Release, T0).is_empty(),
        "closing twice is silent"
    );
}

#[test]
fn a_disconnect_request_while_open_closes_the_peer_without_a_reply() {
    let (_a, mut b) = default_pair();
    let dr = Tpdu::DisconnectRequest(DisconnectRequest {
        dst_ref: 1,
        src_ref: 0,
        reason: reason::CONGESTION,
        additional_information: None,
        user_data: Vec::new(),
    });
    let actions = b.handle(Event::Received(frame_of(&dr)), T0);
    assert_eq!(
        actions,
        vec![Action::Closed(Cause::Released(reason::CONGESTION))]
    );
}

#[test]
fn an_error_tpdu_from_the_peer_closes_the_connection() {
    let (_a, mut b) = default_pair();
    let er = Tpdu::Error(ErrorTpdu {
        dst_ref: 1,
        cause: reject_cause::INVALID_PARAMETER_CODE,
        invalid_tpdu: None,
    });
    let actions = b.handle(Event::Received(frame_of(&er)), T0);
    assert_eq!(
        actions,
        vec![Action::Closed(Cause::Rejected(
            reject_cause::INVALID_PARAMETER_CODE
        ))]
    );
}

#[test]
fn a_tpdu_that_the_state_does_not_allow_is_refused_with_its_quoted_header() {
    let mut b = connection(Role::Responder, LinkConfig::default());
    let confirm = Tpdu::ConnectionConfirm(ConnectionTpdu {
        credit: 0,
        dst_ref: 1,
        src_ref: 2,
        class: 0,
        options: 0,
        parameters: Parameters::default(),
        user_data: Vec::new(),
    });
    let actions = b.handle(Event::Received(frame_of(&confirm)), T0);
    assert!(actions.contains(&Action::Closed(Cause::Protocol(
        reject_cause::INVALID_TPDU_TYPE
    ))));
    match tpdu_of(&frames(&actions)[0]) {
        Tpdu::Error(error) => {
            assert_eq!(error.cause, reject_cause::INVALID_TPDU_TYPE);
            assert_eq!(
                error.invalid_tpdu.map(|q| q.len()),
                Some(2),
                "the length indicator and the code"
            );
        }
        other => panic!("expected an ER, got {other:?}"),
    }
}

#[test]
fn a_garbage_tpdu_is_refused_and_quotes_up_to_the_octet_in_fault() {
    let (_a, mut b) = default_pair();
    // A length indicator of 2 and the code 0x00, which class 0 does not use.
    let garbage = encode_frame(&[2, 0x00, 0x00]).unwrap();
    let actions = b.handle(Event::Received(garbage), T0);
    assert!(actions.contains(&Action::Closed(Cause::Protocol(
        reject_cause::INVALID_TPDU_TYPE
    ))));
    assert!(b.is_closed());
    match tpdu_of(&frames(&actions)[0]) {
        Tpdu::Error(error) => {
            assert_eq!(error.cause, reject_cause::INVALID_TPDU_TYPE);
            assert_eq!(
                error.invalid_tpdu,
                Some(vec![2, 0x00]),
                "up to the code, the octet in fault"
            );
        }
        other => panic!("expected an ER, got {other:?}"),
    }
}

#[test]
fn a_broken_frame_closes_the_connection_without_a_reply() {
    let (_a, mut b) = default_pair();
    let actions = b.handle(Event::Received(vec![2, 0, 0, 7, 0, 0, 0]), T0);
    assert_eq!(actions, vec![Action::Closed(Cause::Framing)]);
}

#[test]
fn a_closed_connection_takes_no_more_input_and_no_more_data() {
    let (mut a, mut b) = default_pair();
    let _ = a.handle(Event::Release, T0);
    assert!(a.handle(Event::Received(vec![0; 8]), T0).is_empty());
    assert!(matches!(
        a.handle(Event::Send(vec![1]), T0).as_slice(),
        [Action::Misuse(_)]
    ));
    let _ = b.handle(Event::Release, T0);
}
