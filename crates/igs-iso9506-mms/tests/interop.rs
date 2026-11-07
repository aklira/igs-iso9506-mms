// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Interoperability with the reference peer of the bench (task L6): this stack, run on the host,
//! opens an MMS association with the reference server and runs the services of the scenarios.
//!
//! The scenarios need the bench (`bench/`, task F5). They are ignored by default; run them with
//! `MMS_PEER=127.0.0.1:10102 cargo test -p igs-iso9506-mms --test interop -- --ignored`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::Duration;

use igs_iso9506_mms::{connect_tcp, Transport};
use igs_iso9506_mms_codec::generated::tables::{
    PARAMETER_SUPPORT_OPTIONS, SERVICE_SUPPORT_OPTIONS,
};
use igs_iso9506_mms_codec::generated::types::{
    ConfirmedServiceRequest, ConfirmedServiceResponse, IdentifyRequest,
    InitiateRequestPDUInitRequestDetail, ParameterSupportOptions, ServiceSupportOptions,
};
use igs_iso9506_mms_codec::mms::{InitiateRequestPDU, Integer16, Integer8, MMSpdu};
use igs_iso9506_mms_codec::schema::BitString;
use igs_iso9506_mms_link::association::{self, Action as AssocAction, Capabilities, MMS_VERSION};
use igs_iso9506_mms_link::config::LinkConfig;
use igs_iso9506_mms_link::requests::{Action, Event, Requests};
use igs_iso9506_mms_link::transport::Role;
use igs_iso9506_mms_link::upper::Origin;
use tokio::time::{timeout, Instant};

/// How long the peer may take to answer one PDU.
const ANSWER_TIME: Duration = Duration::from_secs(20);

fn peer_address() -> Option<String> {
    std::env::var("MMS_PEER").ok()
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

/// Everything the table names: this stack proposes all of them, and the peer keeps its own.
fn capabilities() -> Capabilities {
    Capabilities {
        parameter_cbb: bits(
            PARAMETER_SUPPORT_OPTIONS
                .iter()
                .map(|named| named.position as usize),
        ),
        services: bits(
            SERVICE_SUPPORT_OPTIONS
                .iter()
                .map(|named| named.position as usize),
        ),
    }
}

fn proposal(config: &LinkConfig, capabilities: &Capabilities) -> InitiateRequestPDU {
    InitiateRequestPDU {
        local_detail_calling: None,
        proposed_max_serv_outstanding_calling: Integer16(i64::from(config.max_outstanding_calling)),
        proposed_max_serv_outstanding_called: Integer16(i64::from(config.max_outstanding_called)),
        proposed_data_structure_nesting_level: Some(Integer8(i64::from(config.nesting_level))),
        init_request_detail: InitiateRequestPDUInitRequestDetail {
            proposed_version_number: Integer16(MMS_VERSION),
            proposed_parameter_cbb: ParameterSupportOptions(capabilities.parameter_cbb.clone()),
            services_supported_calling: ServiceSupportOptions(capabilities.services.clone()),
            additional_supported_calling: None,
            additional_cbb_supported_calling: None,
            privilege_class_identity_calling: None,
        },
    }
}

/// The client of the scenarios: the requests layer, run over the transport driver of task T1.
struct Client {
    transport: Transport,
    requests: Requests,
    started: Instant,
}

impl Client {
    async fn connect(address: &str) -> Self {
        let config = LinkConfig::default();
        let transport = timeout(ANSWER_TIME, connect_tcp(address, config.clone()))
            .await
            .expect("the TCP connection is made in time")
            .expect("the transport connection is established");
        let requests = Requests::new(Role::Initiator, config, capabilities()).unwrap();
        Self {
            transport,
            requests,
            started: Instant::now(),
        }
    }

    fn now(&self) -> Duration {
        self.started.elapsed()
    }

    /// Hands an event to the requests layer, writes what it sends, and returns what it reports.
    async fn event(&mut self, event: Event) -> Vec<Action> {
        let actions = self.requests.handle(event, self.now());
        let mut reported = Vec::new();
        for action in actions {
            match action {
                Action::Send(tsdu) => self.transport.send(tsdu).await.expect("the TSDU is sent"),
                Action::ReleaseTransport => {}
                other => reported.push(other),
            }
        }
        reported
    }

    /// Reads the peer's PDUs, one TSDU at a time, until one of the reports matches.
    async fn until(&mut self, wanted: impl Fn(&Action) -> bool) -> Vec<Action> {
        let mut seen = Vec::new();
        loop {
            let tsdu = match timeout(ANSWER_TIME, self.transport.recv()).await {
                Ok(Some(tsdu)) => tsdu,
                Ok(None) => panic!("the connection ended; reported so far: {seen:?}"),
                Err(_) => panic!("the peer answers in time; reported so far: {seen:?}"),
            };
            let reported = self
                .event(Event::Association(association::Event::Received(tsdu)))
                .await;
            let found = reported.iter().any(&wanted);
            seen.extend(reported);
            if found {
                return seen;
            }
        }
    }

    async fn associate(&mut self, request: InitiateRequestPDU) -> Vec<Action> {
        self.event(Event::Association(association::Event::Associate(request)))
            .await;
        self.until(|a| {
            matches!(
                a,
                Action::Association(AssocAction::Established(_))
                    | Action::Association(AssocAction::Refused(_))
            )
        })
        .await
    }
}

fn established(actions: &[Action]) -> Option<igs_iso9506_mms_codec::mms::InitiateResponsePDU> {
    actions.iter().find_map(|action| match action {
        Action::Association(AssocAction::Established(response)) => Some(response.clone()),
        _ => None,
    })
}

#[tokio::test]
#[ignore = "needs the bench: MMS_PEER=127.0.0.1:10102"]
async fn the_association_is_negotiated_and_concluded_with_the_reference_server() {
    let Some(address) = peer_address() else {
        eprintln!("MMS_PEER is not set: the scenario is skipped");
        return;
    };
    let mut client = Client::connect(&address).await;
    let request = proposal(&LinkConfig::default(), &capabilities());
    let actions = client.associate(request).await;
    let response = established(&actions).expect("the peer accepts the association");
    let version = response.init_response_detail.negotiated_version_number.0;
    assert!((1..=MMS_VERSION).contains(&version), "version {version}");
    let calling = response.negotiated_max_serv_outstanding_calling.0;
    assert!(
        calling >= 1,
        "the peer allows at least one request: {calling}"
    );
    eprintln!("negotiated: {response:?}");

    // The CONCLUDE request is answered by the MMS CONCLUDE response, as the peer does.
    client
        .event(Event::Association(association::Event::Conclude))
        .await;
    let answered = client
        .until(|a| matches!(a, Action::Other(MMSpdu::ConcludeResponsePDU(_))))
        .await;
    assert!(
        answered
            .iter()
            .any(|a| matches!(a, Action::Other(MMSpdu::ConcludeResponsePDU(_)))),
        "the peer answers the CONCLUDE request"
    );
    // Gap (recorded in docs/capabilities.md): the peer does not answer the ACSE release (RLRQ), so
    // the association is closed by an abort, as the fallback.
    let aborted = client
        .event(Event::Association(association::Event::Abort))
        .await;
    assert!(aborted.contains(&Action::Association(AssocAction::Aborted(Origin::User))));
    client.transport.shutdown().await.ok();
}

#[tokio::test]
#[ignore = "needs the bench: MMS_PEER=127.0.0.1:10102"]
async fn a_confirmed_identify_is_answered_by_the_reference_server() {
    let Some(address) = peer_address() else {
        eprintln!("MMS_PEER is not set: the scenario is skipped");
        return;
    };
    let mut client = Client::connect(&address).await;
    client
        .associate(proposal(&LinkConfig::default(), &capabilities()))
        .await;
    client
        .event(Event::Request(ConfirmedServiceRequest::Identify(
            IdentifyRequest(()),
        )))
        .await;
    let reported = client
        .until(|a| matches!(a, Action::Response { .. } | Action::Error { .. }))
        .await;
    let response = reported.iter().find_map(|a| match a {
        Action::Response { response, .. } => Some(response.clone()),
        _ => None,
    });
    let Some(ConfirmedServiceResponse::Identify(identity)) = response else {
        panic!("expected an identify response, got {reported:?}");
    };
    assert!(
        !identity.vendor_name.0.is_empty(),
        "the peer names its vendor"
    );
    eprintln!("identity: {identity:?}");
    client
        .event(Event::Association(association::Event::Abort))
        .await;
    client.transport.shutdown().await.ok();
}

#[tokio::test]
#[ignore = "needs the bench: MMS_PEER=127.0.0.1:10102"]
async fn an_abort_ends_the_association_on_both_ends() {
    let Some(address) = peer_address() else {
        eprintln!("MMS_PEER is not set: the scenario is skipped");
        return;
    };
    let mut client = Client::connect(&address).await;
    client
        .associate(proposal(&LinkConfig::default(), &capabilities()))
        .await;
    let reported = client
        .event(Event::Association(association::Event::Abort))
        .await;
    assert!(reported.contains(&Action::Association(AssocAction::Aborted(Origin::User))));
    // The peer closes the stream after the ABORT: the driver reads the end of stream.
    let next = timeout(ANSWER_TIME, client.transport.recv())
        .await
        .expect("the stream ends in time");
    assert!(next.is_none(), "no TSDU after the abort");
    client.transport.shutdown().await.ok();
}
