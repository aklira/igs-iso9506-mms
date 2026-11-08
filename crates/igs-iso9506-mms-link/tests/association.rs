// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Tests of the MMS association (task L4) on the transport and presentation connections below it,
//! on both roles. The test passes the octets between the two ends, on a fake clock.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::Duration;

use igs_iso9506_mms_codec::acse::{
    self, AARQApdu, AARQApduProtocolVersion, ACSEApdu, ApplicationContextName,
    AssociationInformation,
};
use igs_iso9506_mms_codec::generated::tables::SERVICE_SUPPORT_OPTIONS;
use igs_iso9506_mms_codec::generated::types::{
    CancelRequestPDU, InitiateRequestPDUInitRequestDetail, ParameterSupportOptions,
    ServiceErrorErrorClass, ServiceErrorErrorClassInitiate, ServiceSupportOptions,
};
use igs_iso9506_mms_codec::mms::{
    InitiateRequestPDU, InitiateResponsePDU, Integer16, Integer8, MMSpdu, Unsigned32,
};
use igs_iso9506_mms_codec::presentation::{self, ConnectNormal, Mode, Pdv, PdvValues, UserData};
use igs_iso9506_mms_codec::schema::{BitString, ObjectIdentifier};
use igs_iso9506_mms_codec::session::{self, encode_tsdu, Spdu};
use igs_iso9506_mms_link::association::{
    self, Action, Answer, Capabilities, Event, Refusal, MMS_APPLICATION_CONTEXT, MMS_VERSION,
};
use igs_iso9506_mms_link::config::LinkConfig;
use igs_iso9506_mms_link::transport::{self, Role};
use igs_iso9506_mms_link::upper::Origin;

const T0: Duration = Duration::ZERO;

/// The bit positions of the named services, as a bit string that covers them all.
fn services(names: &[&str]) -> BitString {
    bits(names.iter().map(|name| {
        SERVICE_SUPPORT_OPTIONS
            .iter()
            .find(|named| named.name == *name)
            .expect("a known service")
            .position as usize
    }))
}

/// Every service of the table, as a bit string.
fn all_services() -> BitString {
    bits(
        SERVICE_SUPPORT_OPTIONS
            .iter()
            .map(|named| usize::try_from(named.position).unwrap()),
    )
}

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

fn capabilities() -> Capabilities {
    Capabilities {
        parameter_cbb: bits([0usize, 1, 2].into_iter()),
        services: all_services(),
    }
}

fn request(
    config: &LinkConfig,
    capabilities: &Capabilities,
    version: i64,
    nesting: Option<i64>,
) -> InitiateRequestPDU {
    InitiateRequestPDU {
        local_detail_calling: None,
        proposed_max_serv_outstanding_calling: Integer16(i64::from(config.max_outstanding_calling)),
        proposed_max_serv_outstanding_called: Integer16(i64::from(config.max_outstanding_called)),
        proposed_data_structure_nesting_level: nesting.map(Integer8),
        init_request_detail: InitiateRequestPDUInitRequestDetail {
            proposed_version_number: Integer16(version),
            proposed_parameter_cbb: ParameterSupportOptions(capabilities.parameter_cbb.clone()),
            services_supported_calling: ServiceSupportOptions(capabilities.services.clone()),
            additional_supported_calling: None,
            additional_cbb_supported_calling: None,
            privilege_class_identity_calling: None,
        },
    }
}

/// Two ends: each a transport connection under an association. Octets pass between them.
struct Pair {
    transports: [transport::Connection; 2],
    associations: [association::Association; 2],
    log: [Vec<Action>; 2],
}

impl Pair {
    fn new(initiator: (LinkConfig, Capabilities), responder: (LinkConfig, Capabilities)) -> Self {
        let mut pair = Self {
            transports: [
                transport::Connection::new(Role::Initiator, initiator.0.clone()).unwrap(),
                transport::Connection::new(Role::Responder, responder.0.clone()).unwrap(),
            ],
            associations: [
                association::Association::new(Role::Initiator, initiator.0, initiator.1).unwrap(),
                association::Association::new(Role::Responder, responder.0, responder.1).unwrap(),
            ],
            log: [Vec::new(), Vec::new()],
        };
        let opened = pair.transports[0].handle(transport::Event::Connect, T0);
        pair.apply_transport(0, opened);
        assert!(
            pair.transports[0].is_open(),
            "the transport connection opens"
        );
        pair
    }

    fn default_pair() -> Self {
        let config = LinkConfig::default();
        Self::new((config.clone(), capabilities()), (config, capabilities()))
    }

    fn association(&mut self, side: usize, event: Event) {
        let actions = self.associations[side].handle(event);
        self.apply(side, actions);
    }

    fn apply(&mut self, side: usize, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::Send(tsdu) => {
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
                    let actions = self.associations[side].handle(Event::Received(tsdu));
                    self.apply(side, actions);
                }
                transport::Action::Opened => {}
                transport::Action::Closed(cause) => {
                    let actions = self.associations[side].handle(Event::TransportClosed(cause));
                    self.apply(side, actions);
                    let actions = self.transports[other].handle(transport::Event::Release, T0);
                    self.apply_transport(other, actions);
                }
                transport::Action::Misuse(message) => panic!("transport misuse: {message}"),
            }
        }
    }

    /// Initiator requests, responder accepts: both are established, or the test says why not.
    fn associate(&mut self, request: InitiateRequestPDU) {
        self.association(0, Event::Associate(request));
        assert!(self.log[1]
            .iter()
            .any(|a| matches!(a, Action::Indication(_))));
        self.association(1, Event::Answer(Answer::Accept));
    }

    fn established_pair(&mut self) {
        let proposal = request(
            &LinkConfig::default(),
            &capabilities(),
            MMS_VERSION,
            Some(2),
        );
        self.associate(proposal);
        assert!(self.log[0]
            .iter()
            .any(|a| matches!(a, Action::Established(_))));
        assert!(self.log[1]
            .iter()
            .any(|a| matches!(a, Action::Established(_))));
    }
}

fn established(actions: &[Action]) -> Option<InitiateResponsePDU> {
    actions.iter().find_map(|action| match action {
        Action::Established(response) => Some(response.clone()),
        _ => None,
    })
}

fn refusal(actions: &[Action]) -> Option<Refusal> {
    actions.iter().find_map(|action| match action {
        Action::Refused(refusal) => Some(refusal.clone()),
        _ => None,
    })
}

// Negotiation

#[test]
fn an_association_is_established_at_the_values_both_ends_allow() {
    let mut pair = Pair::default_pair();
    pair.established_pair();
    let response = established(&pair.log[0]).expect("the initiator is established");
    assert_eq!(response, established(&pair.log[1]).unwrap());
    let detail = &response.init_response_detail;
    assert_eq!(response.negotiated_max_serv_outstanding_calling.0, 8);
    assert_eq!(response.negotiated_max_serv_outstanding_called.0, 8);
    assert_eq!(
        response.negotiated_data_structure_nesting_level,
        Some(Integer8(2))
    );
    assert_eq!(detail.negotiated_version_number.0, MMS_VERSION);
    assert!(pair.associations[0].is_open() && pair.associations[1].is_open());
}

#[test]
fn the_responder_reduces_each_value_to_its_own_limit() {
    let responder = LinkConfig {
        max_outstanding_calling: 3,
        max_outstanding_called: 5,
        nesting_level: 3,
        ..LinkConfig::default()
    };
    let responder_services = services(&["read", "identify"]);
    let mut pair = Pair::new(
        (LinkConfig::default(), capabilities()),
        (
            responder,
            Capabilities {
                parameter_cbb: bits([1usize].into_iter()),
                services: responder_services.clone(),
            },
        ),
    );
    pair.associate(request(
        &LinkConfig::default(),
        &capabilities(),
        MMS_VERSION,
        Some(6),
    ));
    let response = established(&pair.log[0]).expect("established");
    assert_eq!(response.negotiated_max_serv_outstanding_calling.0, 3);
    assert_eq!(response.negotiated_max_serv_outstanding_called.0, 5);
    assert_eq!(
        response.negotiated_data_structure_nesting_level,
        Some(Integer8(3))
    );
    let detail = &response.init_response_detail;
    assert_eq!(
        detail.negotiated_parameter_cbb.0.bytes,
        bits([1usize].into_iter()).bytes
    );
    assert_eq!(
        detail.services_supported_called.0.bytes, responder_services.bytes,
        "the services of the responder, within those proposed"
    );
}

#[test]
fn an_absent_nesting_level_is_unlimited_and_takes_the_responder_limit() {
    let mut pair = Pair::default_pair();
    pair.associate(request(
        &LinkConfig::default(),
        &capabilities(),
        MMS_VERSION,
        None,
    ));
    let response = established(&pair.log[0]).expect("established");
    assert_eq!(
        response.negotiated_data_structure_nesting_level,
        Some(Integer8(2))
    );
}

#[test]
fn the_version_is_the_lower_of_the_two() {
    let mut pair = Pair::default_pair();
    pair.associate(request(&LinkConfig::default(), &capabilities(), 2, Some(2)));
    let response = established(&pair.log[0]).expect("established");
    assert_eq!(response.init_response_detail.negotiated_version_number.0, 2);
}

#[test]
fn a_nesting_level_below_the_tase2_minimum_is_refused_with_its_error() {
    let mut pair = Pair::default_pair();
    pair.associate(request(
        &LinkConfig::default(),
        &capabilities(),
        MMS_VERSION,
        Some(1),
    ));
    let Some(Refusal::Rejected { result, error, .. }) = refusal(&pair.log[0]) else {
        panic!("expected a refusal, got {:?}", pair.log[0]);
    };
    assert_eq!(result, 1, "rejected-permanent");
    let error = error.expect("the Initiate-ErrorPDU");
    assert_eq!(
        error.error_class,
        ServiceErrorErrorClass::Initiate(
            ServiceErrorErrorClassInitiate::NESTING_LEVEL_INSUFFICIENT
        )
    );
    assert!(matches!(
        refusal(&pair.log[1]),
        Some(Refusal::Rejected { .. })
    ));
    assert!(pair.associations[0].is_closed());
}

#[test]
fn no_common_service_is_refused_with_service_cbb_insufficient() {
    let responder = (
        LinkConfig::default(),
        Capabilities {
            parameter_cbb: bits([0usize].into_iter()),
            services: services(&["read"]),
        },
    );
    let mut pair = Pair::new(
        (
            LinkConfig::default(),
            Capabilities {
                parameter_cbb: bits([0usize].into_iter()),
                services: services(&["identify"]),
            },
        ),
        responder,
    );
    pair.associate(request(
        &LinkConfig::default(),
        &Capabilities {
            parameter_cbb: bits([0usize].into_iter()),
            services: services(&["identify"]),
        },
        MMS_VERSION,
        Some(2),
    ));
    let Some(Refusal::Rejected {
        error: Some(error), ..
    }) = refusal(&pair.log[0])
    else {
        panic!("expected a refusal with an error, got {:?}", pair.log[0]);
    };
    assert_eq!(
        error.error_class,
        ServiceErrorErrorClass::Initiate(ServiceErrorErrorClassInitiate::SERVICE_CBB_INSUFFICIENT)
    );
}

#[test]
fn the_outstanding_limit_of_zero_is_refused_with_its_class() {
    let mut pair = Pair::default_pair();
    let mut proposal = request(
        &LinkConfig::default(),
        &capabilities(),
        MMS_VERSION,
        Some(2),
    );
    proposal.proposed_max_serv_outstanding_calling = Integer16(0);
    pair.associate(proposal);
    let Some(Refusal::Rejected {
        error: Some(error), ..
    }) = refusal(&pair.log[0])
    else {
        panic!("expected a refusal, got {:?}", pair.log[0]);
    };
    assert_eq!(
        error.error_class,
        ServiceErrorErrorClass::Initiate(
            ServiceErrorErrorClassInitiate::MAX_SERVICES_OUTSTANDING_CALLING_INSUFFICIENT
        )
    );
}

fn proposed_context(config: LinkConfig) -> Vec<u8> {
    // The application context that the initiator's AARQ carries: the TSDU it sends first.
    let mut initiator =
        association::Association::new(Role::Initiator, config.clone(), capabilities()).unwrap();
    let actions = initiator.handle(Event::Associate(request(
        &config,
        &capabilities(),
        MMS_VERSION,
        Some(2),
    )));
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Send(tsdu) => Some(tsdu.clone()),
            _ => None,
        })
        .flatten()
        .collect()
}

#[test]
fn the_initiator_proposes_the_current_context_by_default() {
    let sent = proposed_context(LinkConfig::default());
    assert!(sent
        .windows(7)
        .any(|w| w == [0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x05]));
    assert!(!sent
        .windows(7)
        .any(|w| w == [0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x03]));
}

#[test]
fn the_initiator_proposes_the_2002_context_when_its_configuration_selects_it() {
    let config = LinkConfig {
        application_context: igs_iso9506_mms_link::config::ApplicationContext::Legacy,
        ..LinkConfig::default()
    };
    let sent = proposed_context(config);
    assert!(sent
        .windows(7)
        .any(|w| w == [0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x03]));
    assert!(!sent
        .windows(7)
        .any(|w| w == [0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x05]));
}

#[test]
fn the_initiator_sends_the_called_ap_title_and_the_ae_qualifiers_when_configured() {
    let config = LinkConfig {
        ap_title: Some(ObjectIdentifier(vec![1, 3, 9999, 1])),
        called_ap_title: Some(ObjectIdentifier(vec![1, 1, 1, 999])),
        calling_ae_qualifier: Some(12),
        called_ae_qualifier: Some(12),
        ..LinkConfig::default()
    };
    let sent = proposed_context(config);
    // called-AP-title (context 2), called-AE-qualifier (context 3), calling-AE-qualifier (context 7), each in form 2 (INTEGER 12).
    assert!(sent
        .windows(8)
        .any(|w| w == [0xA2, 0x06, 0x06, 0x04, 0x29, 0x01, 0x87, 0x67]));
    assert!(sent.windows(5).any(|w| w == [0xA3, 0x03, 0x02, 0x01, 0x0C]));
    assert!(sent.windows(5).any(|w| w == [0xA7, 0x03, 0x02, 0x01, 0x0C]));
}

#[test]
fn the_called_ap_title_and_the_ae_qualifiers_are_absent_by_default() {
    let sent = proposed_context(LinkConfig::default());
    assert!(!sent.windows(5).any(|w| w == [0xA3, 0x03, 0x02, 0x01, 0x0C]));
    assert!(!sent.windows(5).any(|w| w == [0xA7, 0x03, 0x02, 0x01, 0x0C]));
}

// Refused associations

#[test]
fn a_responder_that_rejects_the_request_refuses_the_association() {
    let mut pair = Pair::default_pair();
    pair.association(
        0,
        Event::Associate(request(
            &LinkConfig::default(),
            &capabilities(),
            MMS_VERSION,
            Some(2),
        )),
    );
    pair.association(1, Event::Answer(Answer::Reject));
    assert_eq!(
        refusal(&pair.log[0]),
        Some(Refusal::Rejected {
            result: 1,
            diagnostic: 1,
            error: None,
        })
    );
    assert!(pair.associations[0].is_closed() && pair.associations[1].is_closed());
}

#[test]
fn an_unknown_application_context_is_refused_with_its_diagnostic() {
    let mut responder =
        association::Association::new(Role::Responder, LinkConfig::default(), capabilities())
            .unwrap();
    let other = ApplicationContextName(ObjectIdentifier(vec![1, 0, 9506, 2, 9]));
    let tsdu = connect_with(aarq(other, None));
    let actions = responder.handle(Event::Received(tsdu));
    assert!(actions.contains(&Action::Refused(Refusal::Rejected {
        result: 1,
        diagnostic: 2,
        error: None,
    })));
    assert!(responder.is_closed());
}

#[test]
fn a_responder_accepts_the_legacy_context_and_answers_with_it() {
    // The reference peer proposes 1.0.9506.2.3 (G13, D-027). The AARE carries the name proposed: its
    // object identifier is 06 05 28 CA 22 02 03, and not the one of 1.0.9506.2.5.
    let mut responder =
        association::Association::new(Role::Responder, LinkConfig::default(), capabilities())
            .unwrap();
    let legacy = ApplicationContextName(ObjectIdentifier(vec![1, 0, 9506, 2, 3]));
    let initiate = request(
        &LinkConfig::default(),
        &capabilities(),
        MMS_VERSION,
        Some(2),
    );
    let mms = igs_iso9506_mms_codec::mms::encode(&MMSpdu::InitiateRequestPDU(initiate)).unwrap();
    let external = igs_iso9506_mms_codec::acse::External {
        direct_reference: None,
        indirect_reference: Some(3),
        data_value_descriptor: None,
        encoding: igs_iso9506_mms_codec::acse::Encoding::SingleAsn1Type(
            igs_iso9506_mms_codec::schema::RawBer(mms),
        ),
    };
    let information = AssociationInformation(vec![external.encode().unwrap()]);
    let tsdu = connect_with(aarq(legacy, Some(information)));
    let actions = responder.handle(Event::Received(tsdu));
    assert!(actions
        .iter()
        .any(|action| matches!(action, Action::Indication(_))));
    let answered = responder.handle(Event::Answer(Answer::Accept));
    assert!(answered
        .iter()
        .any(|action| matches!(action, Action::Established(_))));
    let sent: Vec<u8> = answered
        .iter()
        .filter_map(|action| match action {
            Action::Send(tsdu) => Some(tsdu.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    let legacy_oid = [0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x03];
    assert!(sent.windows(legacy_oid.len()).any(|w| w == legacy_oid));
}

#[test]
fn an_indication_without_an_initiate_request_is_refused() {
    let mut responder =
        association::Association::new(Role::Responder, LinkConfig::default(), capabilities())
            .unwrap();
    let context = ApplicationContextName(ObjectIdentifier(MMS_APPLICATION_CONTEXT.to_vec()));
    let tsdu = connect_with(aarq(context, None));
    let actions = responder.handle(Event::Received(tsdu));
    assert!(matches!(
        refusal(&actions),
        Some(Refusal::Rejected { diagnostic: 1, .. })
    ));
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
    let mut pair = Pair::new((initiator, capabilities()), (responder, capabilities()));
    pair.association(
        0,
        Event::Associate(request(
            &LinkConfig::default(),
            &capabilities(),
            MMS_VERSION,
            Some(2),
        )),
    );
    assert_eq!(refusal(&pair.log[0]), Some(Refusal::Provider(129)));
}

#[test]
fn an_answer_without_an_indication_is_a_misuse() {
    let mut responder =
        association::Association::new(Role::Responder, LinkConfig::default(), capabilities())
            .unwrap();
    assert!(matches!(
        responder.handle(Event::Answer(Answer::Accept)).as_slice(),
        [Action::Misuse(_)]
    ));
}

// Data, with the services negotiated

#[test]
fn a_service_both_ends_serve_is_delivered_to_the_other_end() {
    let mut pair = Pair::default_pair();
    pair.established_pair();
    pair.association(
        0,
        Event::Send(MMSpdu::CancelRequestPDU(CancelRequestPDU(Unsigned32(1)))),
    );
    assert!(pair.log[1]
        .iter()
        .any(|a| matches!(a, Action::Pdu(MMSpdu::CancelRequestPDU(_)))));
}

#[test]
fn a_service_the_peer_does_not_serve_is_not_sent() {
    let config = LinkConfig::default();
    let mut pair = Pair::new(
        (config.clone(), capabilities()),
        (
            config,
            Capabilities {
                parameter_cbb: bits([0usize].into_iter()),
                services: services(&["identify"]),
            },
        ),
    );
    pair.associate(request(
        &LinkConfig::default(),
        &capabilities(),
        MMS_VERSION,
        Some(2),
    ));
    pair.association(
        0,
        Event::Send(MMSpdu::CancelRequestPDU(CancelRequestPDU(Unsigned32(1)))),
    );
    assert!(pair.log[0].iter().any(|a| matches!(a, Action::Misuse(_))));
}

#[test]
fn initiate_is_not_sent_within_an_association() {
    let mut pair = Pair::default_pair();
    pair.established_pair();
    let proposal = request(
        &LinkConfig::default(),
        &capabilities(),
        MMS_VERSION,
        Some(2),
    );
    pair.association(0, Event::Send(MMSpdu::InitiateRequestPDU(proposal)));
    assert!(pair.log[0].iter().any(|a| matches!(a, Action::Misuse(_))));
}

// Conclude, and abort

#[test]
fn conclude_releases_the_association_in_the_order_of_annex_a() {
    let mut pair = Pair::default_pair();
    pair.established_pair();
    pair.association(0, Event::Conclude);
    assert!(pair.log[1].contains(&Action::ConcludeIndication));
    assert!(
        pair.log[0].contains(&Action::Concluded),
        "the initiator is released"
    );
    assert!(
        pair.log[1].contains(&Action::Concluded),
        "the responder is released"
    );
    assert!(pair.associations[0].is_closed() && pair.associations[1].is_closed());
}

#[test]
fn an_abort_is_a_user_abort_at_both_ends() {
    let mut pair = Pair::default_pair();
    pair.established_pair();
    pair.association(0, Event::Abort);
    assert!(pair.log[0].contains(&Action::Aborted(Origin::User)));
    assert!(pair.log[1].contains(&Action::Aborted(Origin::User)));
    assert!(pair.associations[0].is_closed() && pair.associations[1].is_closed());
}

#[test]
fn losing_the_transport_during_the_association_aborts_it() {
    let mut pair = Pair::default_pair();
    pair.established_pair();
    let actions = pair.associations[1].handle(Event::TransportClosed(transport::Cause::Framing));
    assert_eq!(actions, vec![Action::Aborted(Origin::Transport)]);
}

#[test]
fn an_association_request_that_gets_no_answer_times_out_with_the_transport() {
    let config = LinkConfig::default();
    let mut association =
        association::Association::new(Role::Initiator, config.clone(), capabilities()).unwrap();
    let mut transport = transport::Connection::new(Role::Initiator, config.clone()).unwrap();
    let _ = transport.handle(transport::Event::Connect, T0);
    let sent = association.handle(Event::Associate(request(
        &config,
        &capabilities(),
        MMS_VERSION,
        Some(2),
    )));
    assert!(matches!(sent.as_slice(), [Action::Send(_)]));
    let closed = transport.handle(transport::Event::Tick, config.connect_timeout);
    let cause = match closed.as_slice() {
        [transport::Action::Closed(cause)] => *cause,
        other => panic!("expected a close, got {other:?}"),
    };
    let actions = association.handle(Event::TransportClosed(cause));
    assert_eq!(actions, vec![Action::Aborted(Origin::Transport)]);
}

// Helpers of the crafted requests

fn aarq(
    context: ApplicationContextName,
    user_information: Option<AssociationInformation>,
) -> ACSEApdu {
    ACSEApdu::Aarq(AARQApdu {
        protocol_version: Some(AARQApduProtocolVersion(acse::version1())),
        application_context_name: context,
        called_ap_title: None,
        called_ae_qualifier: None,
        called_ap_invocation_identifier: None,
        called_ae_invocation_identifier: None,
        calling_ap_title: None,
        calling_ae_qualifier: None,
        calling_ap_invocation_identifier: None,
        calling_ae_invocation_identifier: None,
        sender_acse_requirements: None,
        mechanism_name: None,
        calling_authentication_value: None,
        application_context_name_list: None,
        implementation_information: None,
        user_information,
    })
}

/// A CONNECT TSDU whose presentation user data is this AARQ, in the ACSE context.
fn connect_with(apdu: ACSEApdu) -> Vec<u8> {
    let acse_bytes = acse::encode(&apdu).unwrap();
    let cp = presentation::Connect {
        mode: Mode::Normal,
        x410_parameters: None,
        normal: Some(ConnectNormal {
            protocol_version: Some(acse::version1()),
            user_data: Some(UserData::Full(vec![Pdv {
                transfer_syntax: None,
                context_id: 1,
                values: PdvValues::SingleAsn1Type(acse_bytes),
            }])),
            ..ConnectNormal::default()
        }),
    };
    let cp_bytes = presentation::encode_connect(&cp, &[]).unwrap();
    encode_tsdu(&[Spdu::Connect(session::Connect {
        session_user_requirements: Some(session::FU_DUPLEX),
        user_data: Some(cp_bytes),
        ..session::Connect::default()
    })])
    .unwrap()
}
