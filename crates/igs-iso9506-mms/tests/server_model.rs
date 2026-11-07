// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The model of a server sees its associations (task S1 of the TASE.2 plan): the calling identity of each association,
//! the admission or the refusal of an association, the release at its end, and the outputs of the model that go to the
//! association they name.

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
use igs_iso9506_mms::server::{Model, Outbound, Peer, PeerId, Server, ServerConfig};
use igs_iso9506_mms::vmd::{Identity, Vmd};
use igs_iso9506_mms_codec::generated::types::{
    APTitle, APTitleForm2, ConfirmedServiceRequest, ConfirmedServiceResponse, InformationReport,
    ServiceError, UnconfirmedService,
};
use igs_iso9506_mms_codec::generated::types::{
    AccessResult, Data, Identifier, ObjectName as MmsName, ObjectNameDomainSpecific,
    VariableAccessSpecification, VariableAccessSpecificationListOfVariableItem,
    VariableSpecification,
};
use igs_iso9506_mms_codec::schema::ObjectIdentifier;
use igs_iso9506_mms_link::config::LinkConfig;
use tokio::time::{sleep, timeout};

const ANSWER: Duration = Duration::from_secs(10);

/// What the model has seen, and what it must send next.
#[derive(Default)]
struct Log {
    admitted: Vec<Peer>,
    released: Vec<PeerId>,
    refuse: bool,
    pending: Option<Outbound>,
}

/// A model that logs its calls, refuses when asked, and sends the outbound it is given once.
struct Stub {
    log: Arc<Mutex<Log>>,
    vmd: Vmd,
}

impl Model for Stub {
    fn admit(&mut self, peer: &Peer) -> bool {
        let mut log = self.log.lock().unwrap();
        log.admitted.push(peer.clone());
        !log.refuse
    }

    fn dispatch(
        &mut self,
        peer: &Peer,
        service: ConfirmedServiceRequest,
    ) -> Result<ConfirmedServiceResponse, ServiceError> {
        <Vmd as Model>::dispatch(&mut self.vmd, peer, service)
    }

    fn released(&mut self, peer: &Peer) {
        self.log.lock().unwrap().released.push(peer.id);
    }

    fn poll(&mut self, _now: Duration) -> Vec<Outbound> {
        self.log
            .lock()
            .unwrap()
            .pending
            .take()
            .into_iter()
            .collect()
    }
}

fn vmd() -> Vmd {
    Vmd::new(Identity {
        vendor: "igs".to_string(),
        model: "model-test".to_string(),
        revision: "1".to_string(),
    })
}

async fn serving(refuse: bool) -> (Server, Arc<Mutex<Log>>) {
    let log = Arc::new(Mutex::new(Log {
        refuse,
        ..Log::default()
    }));
    let model = Stub {
        log: Arc::clone(&log),
        vmd: vmd(),
    };
    let config = ServerConfig {
        poll_interval: Duration::from_millis(5),
        ..ServerConfig::new(LinkConfig::default())
    };
    let server = Server::bind_model("127.0.0.1:0", config, model)
        .await
        .unwrap();
    (server, log)
}

fn client_config(ap_title: Option<Vec<u64>>) -> ClientConfig {
    let link = LinkConfig {
        ap_title: ap_title.map(ObjectIdentifier),
        ..LinkConfig::default()
    };
    ClientConfig {
        reconnect: Reconnect::Never,
        ..ClientConfig::new(link, in_scope_capabilities())
    }
}

async fn connect(
    server: &Server,
    ap_title: Option<Vec<u64>>,
) -> Result<(Client, Events), igs_iso9506_mms::Error> {
    let address = server.local_address().to_string();
    timeout(ANSWER, Client::connect(&address, client_config(ap_title)))
        .await
        .expect("the association is answered in time")
}

/// The next report of the events, skipping the other events, within the answer time.
async fn next_report(events: &mut Events) -> UnconfirmedService {
    loop {
        match timeout(ANSWER, events.next())
            .await
            .expect("an event in time")
        {
            Some(Event::Report(report)) => return report,
            Some(_) => continue,
            None => panic!("the events ended before a report"),
        }
    }
}

#[tokio::test]
async fn the_model_sees_the_calling_ap_title_of_the_association() {
    let (server, log) = serving(false).await;
    let (client, _events) = connect(&server, Some(vec![1, 3, 9999, 1])).await.unwrap();
    let admitted = log.lock().unwrap().admitted.clone();
    assert_eq!(admitted.len(), 1);
    assert_eq!(
        admitted[0].calling.ap_title,
        Some(APTitle::ApTitleForm2(APTitleForm2(ObjectIdentifier(vec![
            1, 3, 9999, 1
        ]))))
    );
    client.close().await.unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn an_association_the_model_refuses_is_not_established() {
    let (server, log) = serving(true).await;
    let outcome = connect(&server, Some(vec![1, 3, 9999, 1])).await;
    assert!(
        outcome.is_err(),
        "the refused association is not established"
    );
    assert!(
        log.lock().unwrap().released.is_empty(),
        "a refused association is not released"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn the_release_is_reported_to_the_model_when_the_client_concludes() {
    let (server, log) = serving(false).await;
    let (client, _events) = connect(&server, None).await.unwrap();
    client.close().await.unwrap();
    // The release is delivered when the association ends: the model is told within a moment.
    for _ in 0..200 {
        if !log.lock().unwrap().released.is_empty() {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    let (released, admitted) = {
        let log = log.lock().unwrap();
        (log.released.clone(), log.admitted.clone())
    };
    assert_eq!(released.len(), 1);
    assert_eq!(released[0], admitted[0].id);
    server.shutdown().await;
}

#[tokio::test]
async fn an_output_for_one_association_reaches_that_association_only() {
    let (server, log) = serving(false).await;
    let (_first, mut first_events) = connect(&server, None).await.unwrap();
    let (_second, mut second_events) = connect(&server, None).await.unwrap();
    let target = log.lock().unwrap().admitted[1].id;
    let report = UnconfirmedService::InformationReport(InformationReport {
        variable_access_specification: VariableAccessSpecification::ListOfVariable(vec![
            VariableAccessSpecificationListOfVariableItem {
                variable_specification: VariableSpecification::Name(MmsName::DomainSpecific(
                    ObjectNameDomainSpecific {
                        domain_id: Identifier("ICC1".to_string()),
                        item_id: Identifier("Flow1".to_string()),
                    },
                )),
                alternate_access: None,
            },
        ]),
        list_of_access_result: vec![AccessResult::Success(Data::Integer(12))],
    });
    log.lock().unwrap().pending = Some(Outbound {
        peer: Some(target),
        report: report.clone(),
    });
    // The second association gets the report it is named in.
    assert_eq!(next_report(&mut second_events).await, report);
    // The first association is not sent it: no report arrives on its events in the time it takes to be sent.
    let other = timeout(Duration::from_millis(300), async {
        loop {
            match first_events.next().await {
                Some(Event::Report(report)) => return Some(report),
                Some(_) => continue,
                None => return None,
            }
        }
    })
    .await;
    assert!(
        other.is_err(),
        "the report of another association was not sent to the first: {other:?}"
    );
    server.shutdown().await;
}
