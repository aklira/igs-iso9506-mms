// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Tests of the requests of an MMS association (task L5): invoke IDs, outstanding limits, response
//! matching, timeouts on a fake clock, Cancel, Reject, and unconfirmed services.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::Duration;

use igs_iso9506_mms_codec::generated::tables::SERVICE_SUPPORT_OPTIONS;
use igs_iso9506_mms_codec::generated::types::{
    CancelRequestPDU, ConfirmedRequestPDU, ConfirmedServiceRequest, ConfirmedServiceResponse,
    GetNameListResponse, IdentifyRequest, IdentifyResponse, InformationReport,
    InitiateRequestPDUInitRequestDetail, MMSString, ParameterSupportOptions, RejectPDURejectReason,
    RejectPDURejectReasonConfirmedRequestPDU, ServiceErrorErrorClass,
    ServiceErrorErrorClassServicePreempt, ServiceSupportOptions, UnconfirmedService,
    VariableAccessSpecification,
};
use igs_iso9506_mms_codec::mms::{Integer16, Integer8, MMSpdu, Unsigned32};
use igs_iso9506_mms_codec::schema::BitString;
use igs_iso9506_mms_link::association::{self, Answer, Capabilities, MMS_VERSION};
use igs_iso9506_mms_link::config::LinkConfig;
use igs_iso9506_mms_link::requests::{self, Action, Event};
use igs_iso9506_mms_link::transport::{self, Role};
use igs_iso9506_mms_link::upper::Origin;

const T0: Duration = Duration::ZERO;

fn bits(positions: impl Iterator<Item = usize>) -> BitString {
    let positions: Vec<usize> = positions.collect();
    let length = positions.iter().max().map_or(0, |max| max + 1).max(96);
    let octets = length.div_ceil(8);
    let mut bytes = vec![0u8; octets];
    for position in positions {
        bytes[position / 8] |= 0x80 >> (position % 8);
    }
    BitString {
        unused: u8::try_from(octets * 8 - length).unwrap(),
        bytes,
    }
}

/// The bit of a named service, in the service support options.
fn service_bit(name: &str) -> usize {
    SERVICE_SUPPORT_OPTIONS
        .iter()
        .find(|named| named.name == name)
        .expect("a known service")
        .position as usize
}

fn capabilities() -> Capabilities {
    Capabilities {
        parameter_cbb: bits([0usize].into_iter()),
        services: bits(
            ["identify", "cancel", "getNameList", "informationReport"]
                .into_iter()
                .map(service_bit),
        ),
    }
}

fn identify_request() -> ConfirmedServiceRequest {
    ConfirmedServiceRequest::Identify(IdentifyRequest(()))
}

fn identify_response() -> ConfirmedServiceResponse {
    ConfirmedServiceResponse::Identify(IdentifyResponse {
        vendor_name: MMSString("vendor".to_string()),
        model_name: MMSString("model".to_string()),
        revision: MMSString("1".to_string()),
        list_of_abstract_syntaxes: None,
    })
}

/// Two ends with an established association, each a transport connection under requests.
struct Pair {
    transports: [transport::Connection; 2],
    requests: [requests::Requests; 2],
    log: [Vec<Action>; 2],
    now: Duration,
}

impl Pair {
    fn new(initiator: LinkConfig, responder: LinkConfig) -> Self {
        Self::with_responder(initiator, responder, capabilities())
    }

    fn with_responder(
        initiator: LinkConfig,
        responder: LinkConfig,
        responder_caps: Capabilities,
    ) -> Self {
        let mut pair = Self {
            transports: [
                transport::Connection::new(Role::Initiator, initiator.clone()).unwrap(),
                transport::Connection::new(Role::Responder, responder.clone()).unwrap(),
            ],
            requests: [
                requests::Requests::new(Role::Initiator, initiator, capabilities()).unwrap(),
                requests::Requests::new(Role::Responder, responder, responder_caps).unwrap(),
            ],
            log: [Vec::new(), Vec::new()],
            now: T0,
        };
        let opened = pair.transports[0].handle(transport::Event::Connect, T0);
        pair.apply_transport(0, opened);
        pair.associate();
        pair
    }

    fn default_pair() -> Self {
        Self::new(LinkConfig::default(), LinkConfig::default())
    }

    fn associate(&mut self) {
        let proposal = association_request();
        self.act(
            0,
            Event::Association(association::Event::Associate(proposal)),
        );
        self.act(
            1,
            Event::Association(association::Event::Answer(Answer::Accept)),
        );
        assert!(self.requests[0].outstanding() == 0);
        assert!(self.log[0]
            .iter()
            .any(|a| matches!(a, Action::Association(association::Action::Established(_)))));
        assert!(self.log[1]
            .iter()
            .any(|a| matches!(a, Action::Association(association::Action::Established(_)))));
    }

    fn act(&mut self, side: usize, event: Event) {
        let actions = self.requests[side].handle(event, self.now);
        self.apply(side, actions);
    }

    fn apply(&mut self, side: usize, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::Send(tsdu) => {
                    let actions =
                        self.transports[side].handle(transport::Event::Send(tsdu), self.now);
                    self.apply_transport(side, actions);
                }
                Action::ReleaseTransport => {
                    let actions = self.transports[side].handle(transport::Event::Release, self.now);
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
                        self.transports[other].handle(transport::Event::Received(frame), self.now);
                    self.apply_transport(other, actions);
                }
                transport::Action::Deliver(tsdu) => {
                    let event = Event::Association(association::Event::Received(tsdu));
                    self.act(side, event);
                }
                transport::Action::Opened => {}
                transport::Action::Closed(cause) => {
                    let event = Event::Association(association::Event::TransportClosed(cause));
                    self.act(side, event);
                    let actions =
                        self.transports[other].handle(transport::Event::Release, self.now);
                    self.apply_transport(other, actions);
                }
                transport::Action::Misuse(message) => panic!("transport misuse: {message}"),
            }
        }
    }

    /// The Pdus that reached a side, in order (the requests it indicated and its responses).
    fn sent_by(&mut self, side: usize, pdu: MMSpdu) {
        self.act(side, Event::Association(association::Event::Send(pdu)));
    }
}

fn association_request() -> igs_iso9506_mms_codec::mms::InitiateRequestPDU {
    igs_iso9506_mms_codec::mms::InitiateRequestPDU {
        local_detail_calling: None,
        proposed_max_serv_outstanding_calling: Integer16(8),
        proposed_max_serv_outstanding_called: Integer16(8),
        proposed_data_structure_nesting_level: Some(Integer8(2)),
        init_request_detail: InitiateRequestPDUInitRequestDetail {
            proposed_version_number: Integer16(MMS_VERSION),
            proposed_parameter_cbb: ParameterSupportOptions(capabilities().parameter_cbb),
            services_supported_calling: ServiceSupportOptions(capabilities().services),
            additional_supported_calling: None,
            additional_cbb_supported_calling: None,
            privilege_class_identity_calling: None,
        },
    }
}

fn indicated(actions: &[Action]) -> Option<(u32, ConfirmedServiceRequest)> {
    actions.iter().find_map(|action| match action {
        Action::Indication { invoke, service } => Some((*invoke, service.clone())),
        _ => None,
    })
}

// Requests and responses

#[test]
fn a_request_is_answered_by_its_response_with_the_same_invoke_id() {
    let mut pair = Pair::default_pair();
    pair.act(0, Event::Request(identify_request()));
    assert!(pair.log[0].contains(&Action::Requested(1)));
    let (invoke, service) = indicated(&pair.log[1]).expect("the responder is indicated");
    assert_eq!(invoke, 1);
    assert_eq!(service, identify_request());
    pair.act(1, Event::Respond(invoke, Ok(identify_response())));
    assert!(pair.log[0].contains(&Action::Response {
        invoke: 1,
        response: identify_response(),
    }));
    assert_eq!(pair.requests[0].outstanding(), 0);
}

#[test]
fn invoke_ids_are_not_reused_while_outstanding() {
    let mut pair = Pair::default_pair();
    pair.act(0, Event::Request(identify_request()));
    pair.act(0, Event::Request(identify_request()));
    assert!(pair.log[0].contains(&Action::Requested(1)));
    assert!(pair.log[0].contains(&Action::Requested(2)));
    assert_eq!(pair.requests[0].outstanding(), 2);
}

#[test]
fn a_response_with_an_unknown_invoke_id_is_rejected_and_changes_nothing() {
    let mut pair = Pair::default_pair();
    pair.sent_by(
        1,
        MMSpdu::ConfirmedResponsePDU(igs_iso9506_mms_codec::mms::ConfirmedResponsePDU {
            invoke_id: Unsigned32(99),
            service: identify_response(),
            service_ext: None,
        }),
    );
    assert!(pair.log[0]
        .iter()
        .all(|a| !matches!(a, Action::Response { .. })));
    // The initiator rejects it, with the invoke ID it names: the responder logs the reject.
    assert!(pair.log[1].iter().any(|a| matches!(
        a,
        Action::Rejected {
            invoke: Some(99),
            reason: RejectPDURejectReason::ConfirmedResponsePDU(_),
        }
    )));
}

#[test]
fn a_response_to_another_service_is_rejected() {
    let mut pair = Pair::default_pair();
    pair.act(0, Event::Request(identify_request()));
    // A GetNameList response to an Identify request: the initiator rejects it, with the invoke ID.
    let other = ConfirmedServiceResponse::GetNameList(GetNameListResponse {
        list_of_identifier: Vec::new(),
        more_follows: None,
    });
    pair.sent_by(
        1,
        MMSpdu::ConfirmedResponsePDU(igs_iso9506_mms_codec::mms::ConfirmedResponsePDU {
            invoke_id: Unsigned32(1),
            service: other,
            service_ext: None,
        }),
    );
    assert_eq!(
        pair.requests[0].outstanding(),
        1,
        "the request stays outstanding"
    );
    assert!(pair.log[1].iter().any(|a| matches!(
        a,
        Action::Rejected {
            invoke: Some(1),
            reason: RejectPDURejectReason::ConfirmedResponsePDU(_),
        }
    )));
}

#[test]
fn an_error_answers_a_request_and_ends_it() {
    let mut pair = Pair::default_pair();
    pair.act(0, Event::Request(identify_request()));
    let error = cancelled_error();
    pair.act(1, Event::Respond(1, Err(error.clone())));
    assert!(pair.log[0].contains(&Action::Error { invoke: 1, error }));
    assert_eq!(pair.requests[0].outstanding(), 0);
}

fn cancelled_error() -> igs_iso9506_mms_codec::mms::ServiceError {
    igs_iso9506_mms_codec::mms::ServiceError {
        error_class: ServiceErrorErrorClass::ServicePreempt(
            ServiceErrorErrorClassServicePreempt::CANCEL,
        ),
        additional_code: None,
        additional_description: None,
        service_specific_info: None,
    }
}

// Limits

#[test]
fn the_negotiated_outstanding_limit_refuses_the_request_beyond_it() {
    let responder = LinkConfig {
        max_outstanding_calling: 2,
        ..LinkConfig::default()
    };
    let mut pair = Pair::new(LinkConfig::default(), responder);
    pair.act(0, Event::Request(identify_request()));
    pair.act(0, Event::Request(identify_request()));
    pair.act(0, Event::Request(identify_request()));
    assert_eq!(pair.requests[0].outstanding(), 2);
    assert!(pair.log[0].iter().any(|a| matches!(a, Action::Misuse(_))));
}

#[test]
fn a_request_beyond_the_limit_of_the_peer_is_rejected_with_max_serv_outstanding_exceeded() {
    let responder = LinkConfig {
        max_outstanding_calling: 2,
        ..LinkConfig::default()
    };
    let mut pair = Pair::new(LinkConfig::default(), responder);
    // The initiator's own check is bypassed: the requests go to the association directly.
    for invoke in [101, 102, 103] {
        pair.sent_by(
            0,
            MMSpdu::ConfirmedRequestPDU(ConfirmedRequestPDU {
                invoke_id: Unsigned32(invoke),
                list_of_modifiers: None,
                service: identify_request(),
                service_ext: None,
            }),
        );
    }
    let indicated_count = pair.log[1]
        .iter()
        .filter(|a| matches!(a, Action::Indication { .. }))
        .count();
    assert_eq!(indicated_count, 2);
    assert!(pair.log[0].iter().any(|a| matches!(
        a,
        Action::Rejected {
            invoke: Some(103),
            reason: RejectPDURejectReason::ConfirmedRequestPDU(
                RejectPDURejectReasonConfirmedRequestPDU::MAX_SERV_OUTSTANDING_EXCEEDED
            ),
        }
    )));
}

#[test]
fn a_repeated_invoke_id_from_the_peer_is_rejected_as_invalid() {
    let mut pair = Pair::default_pair();
    for _ in 0..2 {
        pair.sent_by(
            0,
            MMSpdu::ConfirmedRequestPDU(ConfirmedRequestPDU {
                invoke_id: Unsigned32(5),
                list_of_modifiers: None,
                service: identify_request(),
                service_ext: None,
            }),
        );
    }
    assert!(pair.log[0].iter().any(|a| matches!(
        a,
        Action::Rejected {
            invoke: Some(5),
            reason: RejectPDURejectReason::ConfirmedRequestPDU(
                RejectPDURejectReasonConfirmedRequestPDU::INVALID_INVOKE_ID
            ),
        }
    )));
}

#[test]
fn a_request_before_the_association_is_a_misuse() {
    let mut requests =
        requests::Requests::new(Role::Initiator, LinkConfig::default(), capabilities()).unwrap();
    let actions = requests.handle(Event::Request(identify_request()), T0);
    assert!(matches!(actions.as_slice(), [Action::Misuse(_)]));
}

// Timeouts

#[test]
fn a_timeout_is_reported_once_and_the_request_stays_outstanding() {
    let mut pair = Pair::default_pair();
    pair.act(0, Event::Request(identify_request()));
    pair.now = Duration::from_secs(29);
    pair.act(0, Event::Tick);
    assert!(!pair.log[0].iter().any(|a| matches!(a, Action::Timeout(_))));
    pair.now = Duration::from_secs(30);
    pair.act(0, Event::Tick);
    assert!(pair.log[0].contains(&Action::Timeout(1)));
    pair.now = Duration::from_secs(60);
    pair.act(0, Event::Tick);
    assert_eq!(
        pair.log[0]
            .iter()
            .filter(|a| matches!(a, Action::Timeout(_)))
            .count(),
        1
    );
    assert_eq!(pair.requests[0].outstanding(), 1);
    // The late response still completes the request.
    pair.act(1, Event::Respond(1, Ok(identify_response())));
    assert!(pair.log[0]
        .iter()
        .any(|a| matches!(a, Action::Response { invoke: 1, .. })));
}

// Cancel

#[test]
fn an_accepted_cancel_is_a_cancel_response_then_the_error_of_the_request() {
    let mut pair = Pair::default_pair();
    pair.act(0, Event::Request(identify_request()));
    pair.act(0, Event::Cancel(1));
    let (invoke, _) = indicated(&pair.log[1]).expect("the responder is indicated");
    assert!(pair.log[1].contains(&Action::CancelIndication(invoke)));
    pair.act(
        1,
        Event::CancelAnswer {
            invoke,
            accepted: true,
        },
    );
    assert!(pair.log[0].contains(&Action::Cancelled(1)));
    let error = pair.log[0].iter().find_map(|a| match a {
        Action::Error { invoke: 1, error } => Some(error.clone()),
        _ => None,
    });
    assert_eq!(error, Some(cancelled_error()));
    assert_eq!(pair.requests[0].outstanding(), 0);
}

#[test]
fn a_refused_cancel_leaves_the_request_to_complete() {
    let mut pair = Pair::default_pair();
    pair.act(0, Event::Request(identify_request()));
    pair.act(0, Event::Cancel(1));
    pair.act(
        1,
        Event::CancelAnswer {
            invoke: 1,
            accepted: false,
        },
    );
    assert!(pair.log[0].contains(&Action::CancelFailed(1)));
    assert_eq!(pair.requests[0].outstanding(), 1);
    pair.act(1, Event::Respond(1, Ok(identify_response())));
    assert!(pair.log[0].contains(&Action::Response {
        invoke: 1,
        response: identify_response(),
    }));
    assert_eq!(pair.requests[0].outstanding(), 0);
}

#[test]
fn a_cancel_of_an_unknown_request_is_refused_without_telling_the_user() {
    let mut pair = Pair::default_pair();
    pair.sent_by(
        0,
        MMSpdu::CancelRequestPDU(CancelRequestPDU(Unsigned32(77))),
    );
    assert!(indicated(&pair.log[1]).is_none());
    assert!(!pair.log[1]
        .iter()
        .any(|a| matches!(a, Action::CancelIndication(_))));
    // The initiator has no request 77: it rejects the Cancel-ErrorPDU, which the responder logs.
    assert!(pair.log[1].iter().any(|a| matches!(
        a,
        Action::Rejected {
            invoke: Some(77),
            ..
        }
    )));
}

#[test]
fn cancelling_twice_is_a_misuse() {
    let mut pair = Pair::default_pair();
    pair.act(0, Event::Request(identify_request()));
    pair.act(0, Event::Cancel(1));
    pair.act(0, Event::Cancel(1));
    assert!(pair.log[0].iter().any(|a| matches!(a, Action::Misuse(_))));
}

// Unconfirmed services

#[test]
fn an_unconfirmed_service_reaches_the_other_end_without_a_state() {
    let mut pair = Pair::default_pair();
    let service = UnconfirmedService::InformationReport(InformationReport {
        variable_access_specification: VariableAccessSpecification::ListOfVariable(Vec::new()),
        list_of_access_result: Vec::new(),
    });
    pair.act(0, Event::Unconfirmed(service.clone()));
    assert!(pair.log[1].contains(&Action::Unconfirmed(service)));
    assert_eq!(pair.requests[0].outstanding(), 0);
}

#[test]
fn an_unconfirmed_service_the_peer_does_not_serve_is_not_sent() {
    let responder = Capabilities {
        parameter_cbb: bits([0usize].into_iter()),
        services: bits(["identify", "cancel"].into_iter().map(service_bit)),
    };
    let mut pair = Pair::with_responder(LinkConfig::default(), LinkConfig::default(), responder);
    let service = UnconfirmedService::InformationReport(InformationReport {
        variable_access_specification: VariableAccessSpecification::ListOfVariable(Vec::new()),
        list_of_access_result: Vec::new(),
    });
    pair.act(0, Event::Unconfirmed(service));
    assert!(pair.log[0].iter().any(|a| matches!(a, Action::Misuse(_))));
    assert!(pair.log[1]
        .iter()
        .all(|a| !matches!(a, Action::Unconfirmed(_))));
}

#[test]
fn an_abort_ends_the_requests_at_both_ends() {
    let mut pair = Pair::default_pair();
    pair.act(0, Event::Request(identify_request()));
    pair.act(0, Event::Association(association::Event::Abort));
    assert!(
        pair.log[0].contains(&Action::Association(association::Action::Aborted(
            Origin::User
        )))
    );
    assert!(
        pair.log[1].contains(&Action::Association(association::Action::Aborted(
            Origin::User
        )))
    );
}

#[allow(dead_code)]
fn unused_reference(_: Option<RejectPDURejectReason>, _: Option<Origin>) {}
