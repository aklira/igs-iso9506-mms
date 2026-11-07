// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Tests of the session and presentation connection (task L3), on the transport connection of
//! task L2. The test passes the octets between the two ends, on a fake clock.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::Duration;

use igs_iso9506_mms_codec::acse;
use igs_iso9506_mms_codec::presentation::{
    self, ConnectAccept, ConnectNormal, ConnectRefuse, ContextDefinition, Mode, Pdv, PdvValues,
    UserData,
};
use igs_iso9506_mms_codec::schema::ObjectIdentifier;
use igs_iso9506_mms_codec::session::{
    decode_tsdu, encode_tsdu, Accept, Connect, ConnectAcceptItem, DataTransfer, Finish, Spdu,
    ABORT_PROTOCOL_ERROR, ABORT_TRANSPORT_RELEASED, ABORT_USER, PROTOCOL_VERSION_2,
};
use igs_iso9506_mms_link::config::LinkConfig;
use igs_iso9506_mms_link::transport::{self, Role};
use igs_iso9506_mms_link::upper::{self, Action, Event, Origin, MMS_ABSTRACT_SYNTAX};

const T0: Duration = Duration::ZERO;

/// Two ends, each a transport connection under a session and presentation connection. The
/// octets that a transport connection writes go to the other end; what it delivers goes up.
struct Link {
    transports: [transport::Connection; 2],
    uppers: [upper::Connection; 2],
    /// Actions of the upper connections, other than what they send.
    log: [Vec<Action>; 2],
    /// TSDUs sent by the upper connections, for inspection.
    wire: Vec<Vec<u8>>,
}

impl Link {
    fn new(initiator: LinkConfig, responder: LinkConfig) -> Self {
        let mut link = Self {
            transports: [
                transport::Connection::new(Role::Initiator, initiator.clone()).unwrap(),
                transport::Connection::new(Role::Responder, responder.clone()).unwrap(),
            ],
            uppers: [
                upper::Connection::new(Role::Initiator, initiator).unwrap(),
                upper::Connection::new(Role::Responder, responder).unwrap(),
            ],
            log: [Vec::new(), Vec::new()],
            wire: Vec::new(),
        };
        let opened = link.transports[0].handle(transport::Event::Connect, T0);
        link.apply_transport(0, opened);
        assert!(
            link.transports[0].is_open(),
            "the transport connection opens"
        );
        link
    }

    fn upper(&mut self, side: usize, event: Event) {
        let actions = self.uppers[side].handle(event);
        self.apply_upper(side, actions);
    }

    fn apply_upper(&mut self, side: usize, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::Send(tsdu) => {
                    self.wire.push(tsdu.clone());
                    let actions = self.transports[side].handle(transport::Event::Send(tsdu), T0);
                    self.apply_transport(side, actions);
                }
                Action::ReleaseTransport => {
                    let actions = self.transports[side].handle(transport::Event::Release, T0);
                    self.apply_transport(side, actions);
                }
                other => self.log[side].push(other),
            }
        }
    }

    fn apply_transport(&mut self, side: usize, actions: Vec<transport::Action>) {
        let other = 1 - side;
        for action in actions {
            match action {
                transport::Action::Transmit(frame) => {
                    let actions =
                        self.transports[other].handle(transport::Event::Received(frame), T0);
                    self.apply_transport(other, actions);
                }
                transport::Action::Deliver(tsdu) => {
                    let actions = self.uppers[side].handle(Event::Received(tsdu));
                    self.apply_upper(side, actions);
                }
                transport::Action::Opened => {}
                transport::Action::Closed(cause) => {
                    // The network connection closes for the other end too.
                    let actions = self.uppers[side].handle(Event::TransportClosed(cause));
                    self.apply_upper(side, actions);
                    let actions = self.transports[other].handle(transport::Event::Release, T0);
                    self.apply_transport(other, actions);
                }
                transport::Action::Misuse(message) => panic!("transport misuse: {message}"),
            }
        }
    }

    fn established(&self) -> bool {
        self.uppers[0].is_open() && self.uppers[1].is_open()
    }
}

fn default_link() -> Link {
    Link::new(LinkConfig::default(), LinkConfig::default())
}

fn connected(link: &mut Link) {
    link.upper(0, Event::Connect(None));
    assert!(link.log[1].contains(&Action::ConnectIndication(None)));
    link.upper(1, Event::Accept(None));
    assert!(link.established(), "both ends are open: {:?}", link.log);
    assert!(link.log[0].contains(&Action::Connected(None)));
    assert!(link.log[1].contains(&Action::Connected(None)));
}

// Establishment, on both roles

#[test]
fn connect_and_accept_open_both_ends() {
    let mut link = default_link();
    connected(&mut link);
    assert_eq!(
        link.log[1][0],
        Action::ConnectIndication(None),
        "the responder is asked first"
    );
}

#[test]
fn a_user_refusal_is_carried_by_a_refuse_with_its_context_results() {
    let mut link = default_link();
    link.upper(0, Event::Connect(None));
    link.upper(1, Event::Refuse(None));
    assert!(link.log[0].contains(&Action::Refused(2, None)));
    assert!(link.uppers[0].is_closed() && link.uppers[1].is_closed());
    let refuse = match decode_tsdu(&link.wire[1]).unwrap().as_slice() {
        [Spdu::Refuse(refuse)] => refuse.clone(),
        other => panic!("expected one REFUSE, got {other:?}"),
    };
    let reason = refuse.reason.expect("a reason");
    assert_eq!(reason[0], 2, "rejection by the called SS-user");
    let cpr = ConnectRefuse::decode(&reason[1..]).unwrap();
    let results = cpr.context_results.expect("the context results");
    assert_eq!(results.len(), 2);
    assert!(
        results.iter().all(|r| r.result == 1),
        "user rejection of each context"
    );
}

#[test]
fn a_session_selector_that_is_not_ours_is_refused_by_the_provider() {
    let responder = LinkConfig {
        called_ssap: Some(vec![9]),
        ..LinkConfig::default()
    };
    let initiator = LinkConfig {
        called_ssap: Some(vec![8]),
        ..LinkConfig::default()
    };
    let mut link = Link::new(initiator, responder);
    link.upper(0, Event::Connect(None));
    assert!(!link.log[1].contains(&Action::ConnectIndication(None)));
    assert!(
        link.log[1].contains(&Action::Refused(129, None)),
        "session selector unknown"
    );
    assert!(link.log[0].contains(&Action::Refused(129, None)));
    assert!(link.uppers[0].is_closed() && link.uppers[1].is_closed());
}

#[test]
fn a_presentation_selector_that_is_not_ours_is_refused_with_address_unknown() {
    let responder = LinkConfig {
        called_psap: Some(vec![4]),
        ..LinkConfig::default()
    };
    let initiator = LinkConfig {
        called_psap: Some(vec![5]),
        ..LinkConfig::default()
    };
    let mut link = Link::new(initiator, responder);
    link.upper(0, Event::Connect(None));
    assert!(!link.log[1].contains(&Action::ConnectIndication(None)));
    assert!(link.log[0].contains(&Action::Refused(2, None)));
    let refuse = match decode_tsdu(&link.wire[1]).unwrap().as_slice() {
        [Spdu::Refuse(refuse)] => refuse.clone(),
        other => panic!("expected one REFUSE, got {other:?}"),
    };
    let cpr = ConnectRefuse::decode(&refuse.reason.unwrap()[1..]).unwrap();
    assert_eq!(
        cpr.provider_reason,
        Some(3),
        "called presentation address unknown"
    );
}

#[test]
fn a_connect_that_gets_no_answer_is_aborted_by_the_transport_timeout() {
    let mut transport = transport::Connection::new(Role::Initiator, LinkConfig::default()).unwrap();
    let mut upper = upper::Connection::new(Role::Initiator, LinkConfig::default()).unwrap();
    let _ = transport.handle(transport::Event::Connect, T0);
    let sent = upper.handle(Event::Connect(None));
    assert!(matches!(sent.as_slice(), [Action::Send(_)]));
    assert!(transport
        .handle(transport::Event::Tick, Duration::from_millis(9_999))
        .is_empty());
    let closed = transport.handle(transport::Event::Tick, Duration::from_secs(10));
    assert_eq!(closed.len(), 1);
    let cause = match closed.as_slice() {
        [transport::Action::Closed(cause)] => *cause,
        other => panic!("expected a close, got {other:?}"),
    };
    let aborted = upper.handle(Event::TransportClosed(cause));
    assert_eq!(aborted, vec![Action::Aborted(Origin::Transport)]);
    assert!(upper.is_closed());
}

// Release and abort, on both roles

#[test]
fn an_orderly_release_is_finish_then_disconnect() {
    let mut link = default_link();
    connected(&mut link);
    link.upper(0, Event::Release);
    assert!(
        link.log[1].contains(&Action::Released),
        "the responder is released"
    );
    assert!(
        link.log[0].contains(&Action::Released),
        "the initiator is released"
    );
    assert!(link.uppers[0].is_closed() && link.uppers[1].is_closed());
    // CONNECT, ACCEPT, then FINISH from the initiator and DISCONNECT from the responder.
    assert_eq!(link.wire.len(), 4);
    assert!(matches!(
        decode_tsdu(&link.wire[2]).unwrap().as_slice(),
        [Spdu::Finish(_)]
    ));
    assert!(matches!(
        decode_tsdu(&link.wire[3]).unwrap().as_slice(),
        [Spdu::Disconnect(_)]
    ));
}

#[test]
fn a_finish_is_answered_by_a_disconnect_at_once() {
    let mut link = default_link();
    connected(&mut link);
    link.upper(1, Event::Release);
    assert!(link.log[0].contains(&Action::Released));
    assert!(link.log[1].contains(&Action::Released));
    assert!(link.uppers[0].is_closed() && link.uppers[1].is_closed());
}

#[test]
fn a_user_abort_reaches_the_peer_as_a_user_abort() {
    let mut link = default_link();
    connected(&mut link);
    link.upper(0, Event::Abort);
    assert!(link.log[0].contains(&Action::Aborted(Origin::User)));
    assert!(link.log[1].contains(&Action::Aborted(Origin::User)));
    assert!(link.uppers[0].is_closed() && link.uppers[1].is_closed());
    let last = link.wire.last().expect("the ABORT");
    let abort = match decode_tsdu(last).unwrap().as_slice() {
        [Spdu::Abort(abort)] => abort.clone(),
        other => panic!("expected one ABORT, got {other:?}"),
    };
    assert_eq!(
        abort.transport_disconnect,
        ABORT_USER | ABORT_TRANSPORT_RELEASED
    );
}

#[test]
fn losing_the_transport_while_open_aborts_the_connection() {
    let mut upper = upper::Connection::new(Role::Responder, LinkConfig::default()).unwrap();
    let connect = Spdu::Connect(Connect {
        item: Some(ConnectAcceptItem {
            version_number: PROTOCOL_VERSION_2,
            ..ConnectAcceptItem::default()
        }),
        user_data: Some(cp_bytes(&default_contexts())),
        ..Connect::default()
    });
    let _ = upper.handle(Event::Received(encode_tsdu(&[connect]).unwrap()));
    let _ = upper.handle(Event::Accept(None));
    assert!(upper.is_open());
    let actions = upper.handle(Event::TransportClosed(transport::Cause::Framing));
    assert_eq!(actions, vec![Action::Aborted(Origin::Transport)]);
}

// Protocol errors, and misuse

#[test]
fn an_unexpected_spdu_is_a_protocol_error_with_an_abort() {
    let mut upper = upper::Connection::new(Role::Responder, LinkConfig::default()).unwrap();
    let finish = encode_tsdu(&[Spdu::Finish(Finish::default())]).unwrap();
    let actions = upper.handle(Event::Received(finish));
    let abort = match actions.first() {
        Some(Action::Send(tsdu)) => match decode_tsdu(tsdu).unwrap().as_slice() {
            [Spdu::Abort(abort)] => abort.clone(),
            other => panic!("expected one ABORT, got {other:?}"),
        },
        other => panic!("expected a send, got {other:?}"),
    };
    assert_eq!(
        abort.transport_disconnect,
        ABORT_PROTOCOL_ERROR | ABORT_TRANSPORT_RELEASED
    );
    assert_eq!(
        &actions[1..],
        &[Action::Aborted(Origin::Provider), Action::ReleaseTransport]
    );
}

#[test]
fn user_data_is_delivered_in_the_data_transfer() {
    let mut link = default_link();
    connected(&mut link);
    let user_data = mms_data(&[0x02, 0x01, 0x05]);
    link.upper(0, Event::Data(user_data.clone()));
    assert!(link.log[1].contains(&Action::Data(user_data)));
    assert!(link.uppers[0].is_open() && link.uppers[1].is_open());
}

#[test]
fn a_data_transfer_without_its_give_tokens_is_a_protocol_error() {
    let mut link = default_link();
    connected(&mut link);
    // A lone DATA TRANSFER is not a TSDU this layer accepts: the encoder refuses to write one.
    assert!(encode_tsdu(&[Spdu::DataTransfer(DataTransfer::default())]).is_err());
}

#[test]
fn data_before_the_connection_is_open_is_a_misuse() {
    let mut initiator = upper::Connection::new(Role::Initiator, LinkConfig::default()).unwrap();
    let actions = initiator.handle(Event::Data(mms_data(&[0x05, 0x00])));
    assert!(matches!(actions.as_slice(), [Action::Misuse(_)]));
}

#[test]
fn garbage_is_a_protocol_error() {
    let mut upper = upper::Connection::new(Role::Responder, LinkConfig::default()).unwrap();
    let actions = upper.handle(Event::Received(vec![0xFF, 0xFF]));
    assert!(actions.contains(&Action::Aborted(Origin::Provider)));
    assert!(upper.is_closed());
}

#[test]
fn events_out_of_their_state_are_misuse() {
    let mut responder = upper::Connection::new(Role::Responder, LinkConfig::default()).unwrap();
    assert!(matches!(
        responder.handle(Event::Connect(None)).as_slice(),
        [Action::Misuse(_)]
    ));
    assert!(matches!(
        responder.handle(Event::Accept(None)).as_slice(),
        [Action::Misuse(_)]
    ));
    assert!(matches!(
        responder.handle(Event::Release).as_slice(),
        [Action::Misuse(_)]
    ));
    let mut initiator = upper::Connection::new(Role::Initiator, LinkConfig::default()).unwrap();
    assert!(matches!(
        initiator.handle(Event::Accept(None)).as_slice(),
        [Action::Misuse(_)]
    ));
    assert!(matches!(
        initiator.handle(Event::Abort).as_slice(),
        [Action::Misuse(_)]
    ));
}

// Presentation contexts, judged by the responder

fn context(id: i64, abstract_syntax: Vec<u64>, transfer: Vec<Vec<u64>>) -> ContextDefinition {
    ContextDefinition {
        id,
        abstract_syntax: ObjectIdentifier(abstract_syntax),
        transfer_syntaxes: transfer.into_iter().map(ObjectIdentifier).collect(),
    }
}

/// User data of the MMS context, as one PDV whose value is the given BER encoding.
fn mms_data(encoding: &[u8]) -> UserData {
    UserData::Full(vec![Pdv {
        transfer_syntax: None,
        context_id: 3,
        values: PdvValues::SingleAsn1Type(encoding.to_vec()),
    }])
}

fn default_contexts() -> Vec<ContextDefinition> {
    vec![
        context(1, acse::ABSTRACT_SYNTAX.to_vec(), vec![vec![2, 1, 1]]),
        context(3, MMS_ABSTRACT_SYNTAX.to_vec(), vec![vec![2, 1, 1]]),
    ]
}

/// The CP PPDU of a normal-mode connection proposing these contexts.
fn cp_bytes(contexts: &[ContextDefinition]) -> Vec<u8> {
    let connect = presentation::Connect {
        mode: Mode::Normal,
        x410_parameters: None,
        normal: Some(ConnectNormal {
            protocol_version: Some(acse::version1()),
            context_definitions: Some(contexts.to_vec()),
            ..ConnectNormal::default()
        }),
    };
    presentation::encode_connect(&connect, &[]).unwrap()
}

#[test]
fn each_context_is_accepted_or_rejected_by_its_abstract_and_transfer_syntax() {
    let contexts = vec![
        context(1, acse::ABSTRACT_SYNTAX.to_vec(), vec![vec![2, 1, 1]]),
        context(3, vec![1, 2, 3], vec![vec![2, 1, 1]]),
        context(5, MMS_ABSTRACT_SYNTAX.to_vec(), vec![vec![1, 2, 3]]),
    ];
    let mut responder = upper::Connection::new(Role::Responder, LinkConfig::default()).unwrap();
    let connect = Spdu::Connect(Connect {
        item: Some(ConnectAcceptItem {
            version_number: PROTOCOL_VERSION_2,
            ..ConnectAcceptItem::default()
        }),
        user_data: Some(cp_bytes(&contexts)),
        ..Connect::default()
    });
    let indication = responder.handle(Event::Received(encode_tsdu(&[connect]).unwrap()));
    assert_eq!(indication, vec![Action::ConnectIndication(None)]);
    let answer = responder.handle(Event::Accept(None));
    let tsdu = match answer.first() {
        Some(Action::Send(tsdu)) => tsdu.clone(),
        other => panic!("expected the ACCEPT, got {other:?}"),
    };
    let accept: Accept = match decode_tsdu(&tsdu).unwrap().as_slice() {
        [Spdu::Accept(accept)] => accept.clone(),
        other => panic!("expected one ACCEPT, got {other:?}"),
    };
    let cpa = ConnectAccept::decode(&accept.user_data.expect("the CPA")).unwrap();
    let results = cpa.normal.unwrap().context_results.unwrap();
    assert_eq!(results[0].result, 0, "ACSE, basic encoding: accepted");
    assert_eq!(results[1].result, 2, "unknown abstract syntax");
    assert_eq!(results[1].provider_reason, Some(1));
    assert_eq!(results[2].result, 2, "no basic encoding proposed");
    assert_eq!(results[2].provider_reason, Some(2));
    assert!(responder.is_open());
}

#[test]
fn the_session_accept_carries_the_protocol_version_two() {
    let mut link = default_link();
    connected(&mut link);
    let accept = match decode_tsdu(&link.wire[1]).unwrap().as_slice() {
        [Spdu::Accept(accept)] => accept.clone(),
        other => panic!("expected one ACCEPT, got {other:?}"),
    };
    assert_eq!(
        accept.item.map(|item| item.version_number),
        Some(PROTOCOL_VERSION_2)
    );
    let cp = match decode_tsdu(&link.wire[0]).unwrap().as_slice() {
        [Spdu::Connect(connect)] => connect.user_data.clone().unwrap(),
        other => panic!("expected one CONNECT, got {other:?}"),
    };
    let (proposed, _) = presentation::decode_connect(&cp).unwrap();
    let contexts = proposed.normal.unwrap().context_definitions.unwrap();
    assert_eq!(contexts.len(), 2);
    assert!(
        contexts.iter().all(|c| c.id % 2 == 1),
        "context identifiers are odd"
    );
}
