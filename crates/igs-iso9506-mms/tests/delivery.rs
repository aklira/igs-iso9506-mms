// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The delivery of the reports of a server (task N5 of igs-iec61850-mms; AT-06): forced saturation is
//! observable, the order is kept per association, no report reaches another association, and a closed
//! association is refused. The tests run on the current-thread runtime: a publication does not yield, so the
//! queues fill as the test publishes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use igs_iso9506_mms::client::{
    in_scope_capabilities, Client, ClientConfig, Event, Events, Reconnect,
};
use igs_iso9506_mms::server::{
    Delivery, Model, Outbound, Peer, PeerId, Refusal, Server, ServerConfig,
};
use igs_iso9506_mms::vmd::{Identity, Vmd};
use igs_iso9506_mms_codec::generated::types::{
    AccessResult, ConfirmedServiceRequest, ConfirmedServiceResponse, Data, Identifier,
    InformationReport, ObjectName, ServiceError, UnconfirmedService, VariableAccessSpecification,
};
use igs_iso9506_mms_link::config::LinkConfig;
use tokio::time::{sleep, timeout};

const ANSWER: Duration = Duration::from_secs(10);

fn vmd() -> Vmd {
    Vmd::new(Identity {
        vendor: "igs".to_string(),
        model: "delivery".to_string(),
        revision: "1".to_string(),
    })
}

fn client_config() -> ClientConfig {
    ClientConfig {
        reconnect: Reconnect::Never,
        ..ClientConfig::new(LinkConfig::default(), in_scope_capabilities())
    }
}

/// A report that carries `value`, so that the receiver can tell the reports apart.
fn report(value: i128) -> UnconfirmedService {
    UnconfirmedService::InformationReport(InformationReport {
        variable_access_specification: VariableAccessSpecification::VariableListName(
            ObjectName::VmdSpecific(Identifier("RPT".into())),
        ),
        list_of_access_result: vec![AccessResult::Success(Data::Integer(value))],
    })
}

fn value_of(service: &UnconfirmedService) -> Option<i128> {
    match service {
        UnconfirmedService::InformationReport(report) => match report.list_of_access_result.first()
        {
            Some(AccessResult::Success(Data::Integer(value))) => Some(*value),
            _ => None,
        },
        _ => None,
    }
}

/// The next report of an association, within the answer time.
async fn next_report(events: &mut Events) -> Option<UnconfirmedService> {
    timeout(ANSWER, async {
        loop {
            match events.next().await {
                Some(Event::Report(service)) => return Some(service),
                Some(_) => continue,
                None => return None,
            }
        }
    })
    .await
    .unwrap()
}

/// The reports of an association for a short time: none is expected.
async fn reports_within(events: &mut Events, time: Duration) -> Vec<UnconfirmedService> {
    let mut out = Vec::new();
    let _ = timeout(time, async {
        while let Some(event) = events.next().await {
            if let Event::Report(service) = event {
                out.push(service);
            }
        }
    })
    .await;
    out
}

/// The next outcome, within the answer time.
async fn next_outcome(server: &mut Server) -> Delivery {
    timeout(ANSWER, server.next_delivery())
        .await
        .unwrap()
        .unwrap()
}

/// A model that admits every association, records their identities in order, and sends one targeted report to
/// the first association once two are admitted.
struct Targeted {
    admitted: Arc<Mutex<Vec<PeerId>>>,
    report: UnconfirmedService,
    sent: bool,
    vmd: Vmd,
}

impl Model for Targeted {
    fn admit(&mut self, peer: &Peer) -> bool {
        self.admitted.lock().unwrap().push(peer.id);
        true
    }

    fn dispatch(
        &mut self,
        peer: &Peer,
        service: ConfirmedServiceRequest,
    ) -> Result<ConfirmedServiceResponse, ServiceError> {
        <Vmd as Model>::dispatch(&mut self.vmd, peer, service)
    }

    fn poll(&mut self, _now: Duration) -> Vec<Outbound> {
        let admitted = self.admitted.lock().unwrap();
        if self.sent || admitted.len() < 2 {
            return Vec::new();
        }
        self.sent = true;
        vec![Outbound {
            peer: Some(admitted[0]),
            report: self.report.clone(),
        }]
    }
}

#[tokio::test]
async fn a_saturated_association_is_observable_and_refuses_the_next_report() {
    // Each association holds one report: the second publication is refused by both.
    let config = ServerConfig::new(LinkConfig::default()).with_report_queue(1);
    let mut server = Server::bind("127.0.0.1:0", config, vmd()).await.unwrap();
    let address = server.local_address().to_string();
    let (_a, _events_a) = timeout(ANSWER, Client::connect(&address, client_config()))
        .await
        .unwrap()
        .unwrap();
    let (_b, _events_b) = timeout(ANSWER, Client::connect(&address, client_config()))
        .await
        .unwrap()
        .unwrap();
    // The associations are open once the server has queued for them: a publication answers `queued` for each.
    sleep(Duration::from_millis(100)).await;

    // The publications do not yield, so nothing leaves the queues in between.
    let first = server.publish_report(report(1));
    let second = server.publish_report(report(2));
    assert_eq!((first.queued, first.refused), (2, 0));
    assert_eq!((second.queued, second.refused), (0, 2));

    let mut queued = 0;
    let mut saturated = 0;
    for _ in 0..4 {
        match next_outcome(&mut server).await {
            Delivery::Queued { message, .. } if message == first.id => queued += 1,
            Delivery::Refused {
                message,
                reason: Refusal::Saturated,
                ..
            } if message == second.id => saturated += 1,
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    assert_eq!((queued, saturated), (2, 2));
    assert_eq!(server.dropped_deliveries(), 0);
}

#[tokio::test]
async fn the_reports_of_an_association_keep_their_order() {
    let config = ServerConfig::new(LinkConfig::default());
    let server = Server::bind("127.0.0.1:0", config, vmd()).await.unwrap();
    let address = server.local_address().to_string();
    let (_client, mut events) = timeout(ANSWER, Client::connect(&address, client_config()))
        .await
        .unwrap()
        .unwrap();
    sleep(Duration::from_millis(100)).await;

    for value in 1..=3 {
        assert_eq!(server.publish_report(report(value)).queued, 1);
    }
    let mut values = Vec::new();
    for _ in 0..3 {
        values.push(value_of(&next_report(&mut events).await.unwrap()));
    }
    assert_eq!(values, [Some(1), Some(2), Some(3)]);
    server.shutdown().await;
}

#[tokio::test]
async fn a_targeted_report_reaches_only_its_association() {
    let admitted = Arc::new(Mutex::new(Vec::new()));
    let model = Targeted {
        admitted: Arc::clone(&admitted),
        report: report(42),
        sent: false,
        vmd: vmd(),
    };
    let config = ServerConfig::new(LinkConfig::default());
    let mut server = Server::bind_model("127.0.0.1:0", config, model)
        .await
        .unwrap();
    let address = server.local_address().to_string();
    let (_a, mut events_a) = timeout(ANSWER, Client::connect(&address, client_config()))
        .await
        .unwrap()
        .unwrap();
    let (_b, mut events_b) = timeout(ANSWER, Client::connect(&address, client_config()))
        .await
        .unwrap()
        .unwrap();

    // The first association receives it; the second does not.
    let received = next_report(&mut events_a).await.unwrap();
    assert_eq!(value_of(&received), Some(42));
    assert!(reports_within(&mut events_b, Duration::from_millis(300))
        .await
        .is_empty());

    // The outcome is for the first association only, and it was written.
    let first = admitted.lock().unwrap()[0];
    let mut written = false;
    for _ in 0..4 {
        match next_outcome(&mut server).await {
            Delivery::Written { peer, .. } if peer == first => written = true,
            Delivery::Queued { peer, .. } => assert_eq!(peer, first),
            other => panic!("unexpected outcome: {other:?}"),
        }
        if written {
            break;
        }
    }
    assert!(written);
}

#[tokio::test]
async fn a_closed_association_is_no_longer_a_target() {
    let config = ServerConfig::new(LinkConfig::default());
    let server = Server::bind("127.0.0.1:0", config, vmd()).await.unwrap();
    let address = server.local_address().to_string();
    let (a, _events_a) = timeout(ANSWER, Client::connect(&address, client_config()))
        .await
        .unwrap()
        .unwrap();
    let (_b, mut events_b) = timeout(ANSWER, Client::connect(&address, client_config()))
        .await
        .unwrap()
        .unwrap();
    sleep(Duration::from_millis(100)).await;
    timeout(ANSWER, a.close()).await.unwrap().unwrap();
    sleep(Duration::from_millis(300)).await;

    let publication = server.publish_report(report(7));
    assert_eq!(
        (publication.queued, publication.refused),
        (1, 0),
        "only b is open"
    );
    assert_eq!(
        value_of(&next_report(&mut events_b).await.unwrap()),
        Some(7)
    );
    server.shutdown().await;
}

#[tokio::test]
async fn a_zero_report_queue_is_a_configuration_error() {
    let config = ServerConfig::new(LinkConfig::default()).with_report_queue(0);
    let refused = Server::bind("127.0.0.1:0", config, vmd()).await;
    assert!(refused.is_err());
}
