// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The MMS client (task T2) against a loopback server built from the link layers: each service in
//! scope is answered, and the connection events, the queue, the close, the reconnection and the
//! timeouts are checked. The timeout runs on a paused clock.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::future::Future;
use std::time::Duration;

use igs_iso9506_mms::{
    accept, Client, ClientConfig, ConnectionState, Connector, Error, Event, Events, Reconnect,
};
use igs_iso9506_mms_codec::generated::tables::SERVICE_SUPPORT_OPTIONS;
use igs_iso9506_mms_codec::generated::types::{
    AccessResult, ConfirmedServiceRequest, ConfirmedServiceResponse, Data,
    DefineNamedVariableListRequest, DefineNamedVariableListResponse,
    DeleteNamedVariableListRequest, DeleteNamedVariableListResponse, GetNameListRequest,
    GetNameListRequestObjectScope, GetNameListResponse, GetNamedVariableListAttributesRequest,
    GetNamedVariableListAttributesResponse, GetVariableAccessAttributesRequest,
    GetVariableAccessAttributesResponse, Identifier, IdentifyResponse, InformationReport,
    MMSString, ObjectClass, ObjectClassBasicObjectClass, ObjectName, ReadRequest, ReadResponse,
    ServiceErrorErrorClass, ServiceErrorErrorClassService, TypeDescription, UnconfirmedService,
    Unsigned32, VariableAccessSpecification, WriteRequest, WriteResponse, WriteResponseItemItem,
};
use igs_iso9506_mms_codec::mms::ServiceError;
use igs_iso9506_mms_codec::schema::BitString;
use igs_iso9506_mms_link::association::{self, Action as AssocAction, Answer, Capabilities};
use igs_iso9506_mms_link::config::LinkConfig;
use igs_iso9506_mms_link::requests::{Action, Event as ReqEvent, Requests};
use igs_iso9506_mms_link::transport::Role;
use tokio::io::{duplex, DuplexStream};
use tokio::sync::mpsc;
use tokio::time::Instant;

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

fn service_bit(name: &str) -> usize {
    SERVICE_SUPPORT_OPTIONS
        .iter()
        .find(|named| named.name == name)
        .expect("a known service")
        .position as usize
}

/// The services in scope and the unconfirmed information report.
const SCOPE: [&str; 9] = [
    "getNameList",
    "identify",
    "read",
    "write",
    "getVariableAccessAttributes",
    "defineNamedVariableList",
    "getNamedVariableListAttributes",
    "deleteNamedVariableList",
    "informationReport",
];

fn capabilities() -> Capabilities {
    Capabilities {
        parameter_cbb: bits(
            igs_iso9506_mms_codec::generated::tables::PARAMETER_SUPPORT_OPTIONS
                .iter()
                .map(|named| named.position as usize),
        ),
        services: bits(SCOPE.iter().map(|name| service_bit(name))),
    }
}

/// How the loopback server behaves.
#[derive(Debug, Clone, Copy, Default)]
struct Script {
    /// Read requests fail with a service error.
    read_fails: bool,
    /// An identify first sends an information report.
    reports: bool,
    /// Requests are never answered.
    silent: bool,
    /// The first connection is dropped when a read arrives.
    drop_first_on_read: bool,
    /// Associations are refused.
    refuse: bool,
    /// The outstanding limit of the server, as the calling user.
    outstanding: Option<u16>,
}

fn canned(
    service: &ConfirmedServiceRequest,
    script: Script,
) -> Result<ConfirmedServiceResponse, ServiceError> {
    Ok(match service {
        ConfirmedServiceRequest::Identify(_) => {
            ConfirmedServiceResponse::Identify(IdentifyResponse {
                vendor_name: MMSString("igs".to_string()),
                model_name: MMSString("loopback".to_string()),
                revision: MMSString("1".to_string()),
                list_of_abstract_syntaxes: None,
            })
        }
        ConfirmedServiceRequest::GetNameList(_) => {
            ConfirmedServiceResponse::GetNameList(GetNameListResponse {
                list_of_identifier: vec![Identifier("alpha".to_string())],
                more_follows: Some(false),
            })
        }
        ConfirmedServiceRequest::Read(_) => {
            if script.read_fails {
                return Err(service_error());
            }
            ConfirmedServiceResponse::Read(ReadResponse {
                variable_access_specification: None,
                list_of_access_result: vec![AccessResult::Success(Data::Boolean(true))],
            })
        }
        ConfirmedServiceRequest::Write(_) => {
            ConfirmedServiceResponse::Write(WriteResponse(vec![WriteResponseItemItem::Success]))
        }
        ConfirmedServiceRequest::GetVariableAccessAttributes(_) => {
            ConfirmedServiceResponse::GetVariableAccessAttributes(
                GetVariableAccessAttributesResponse {
                    mms_deletable: false,
                    address: None,
                    type_description: TypeDescription::Boolean,
                    access_control_list: None,
                    meaning: None,
                },
            )
        }
        ConfirmedServiceRequest::DefineNamedVariableList(_) => {
            ConfirmedServiceResponse::DefineNamedVariableList(DefineNamedVariableListResponse(()))
        }
        ConfirmedServiceRequest::GetNamedVariableListAttributes(_) => {
            ConfirmedServiceResponse::GetNamedVariableListAttributes(
                GetNamedVariableListAttributesResponse {
                    mms_deletable: false,
                    list_of_variable: Vec::new(),
                    access_control_list: None,
                },
            )
        }
        ConfirmedServiceRequest::DeleteNamedVariableList(_) => {
            ConfirmedServiceResponse::DeleteNamedVariableList(DeleteNamedVariableListResponse {
                number_matched: Unsigned32(1),
                number_deleted: Unsigned32(1),
            })
        }
        _ => return Err(service_error()),
    })
}

fn service_error() -> ServiceError {
    ServiceError {
        error_class: ServiceErrorErrorClass::Service(ServiceErrorErrorClassService(0)),
        additional_code: None,
        additional_description: None,
        service_specific_info: None,
    }
}

/// The loopback server of one connection: the link layers, answering as the script says.
async fn serve_connection(stream: DuplexStream, script: Script, first: bool) {
    let config = LinkConfig {
        max_outstanding_calling: script
            .outstanding
            .unwrap_or(LinkConfig::default().max_outstanding_calling),
        ..LinkConfig::default()
    };
    let Ok(mut transport) = accept(stream, config.clone()).await else {
        return;
    };
    let mut requests = Requests::new(Role::Responder, config, capabilities()).unwrap();
    // FIFO: the actions of one event are carried out in the order the layers give them.
    let mut work = std::collections::VecDeque::new();
    loop {
        let Some(tsdu) = transport.recv().await else {
            return;
        };
        work.extend(requests.handle(
            ReqEvent::Association(association::Event::Received(tsdu)),
            Duration::ZERO,
        ));
        while let Some(action) = work.pop_front() {
            match action {
                Action::Send(bytes) => {
                    if transport.send(bytes).await.is_err() {
                        return;
                    }
                }
                Action::Association(AssocAction::Indication(_)) => {
                    let answer = if script.refuse {
                        Answer::Reject
                    } else {
                        Answer::Accept
                    };
                    work.extend(requests.handle(
                        ReqEvent::Association(association::Event::Answer(answer)),
                        Duration::ZERO,
                    ));
                }
                Action::Indication { invoke, service } => {
                    if script.silent {
                        continue;
                    }
                    if script.drop_first_on_read
                        && first
                        && matches!(service, ConfirmedServiceRequest::Read(_))
                    {
                        return;
                    }
                    if script.reports && matches!(service, ConfirmedServiceRequest::Identify(_)) {
                        let report = UnconfirmedService::InformationReport(InformationReport {
                            variable_access_specification:
                                VariableAccessSpecification::ListOfVariable(Vec::new()),
                            list_of_access_result: Vec::new(),
                        });
                        work.extend(requests.handle(ReqEvent::Unconfirmed(report), Duration::ZERO));
                    }
                    let result = canned(&service, script);
                    work.extend(requests.handle(ReqEvent::Respond(invoke, result), Duration::ZERO));
                }
                Action::Association(AssocAction::Concluded)
                | Action::Association(AssocAction::Aborted(_)) => return,
                _ => {}
            }
        }
    }
}

/// The loopback connector: each connection is a duplex stream whose other end the server takes.
struct Loopback {
    incoming: mpsc::UnboundedSender<DuplexStream>,
}

impl Connector for Loopback {
    type Stream = DuplexStream;

    fn connect(&mut self) -> impl Future<Output = Result<DuplexStream, Error>> + Send {
        let (client, server) = duplex(65_536);
        let sent = self.incoming.send(server).is_ok();
        async move {
            if sent {
                Ok(client)
            } else {
                Err(Error::ConnectionLost)
            }
        }
    }
}

async fn serve(mut incoming: mpsc::UnboundedReceiver<DuplexStream>, script: Script) {
    let mut index = 0usize;
    while let Some(stream) = incoming.recv().await {
        tokio::spawn(serve_connection(stream, script, index == 0));
        index += 1;
    }
}

fn config(reconnect: Reconnect) -> ClientConfig {
    ClientConfig {
        reconnect,
        ..ClientConfig::new(LinkConfig::default(), capabilities())
    }
}

async fn start_with(script: Script, config: ClientConfig) -> Result<(Client, Events), Error> {
    let (incoming, server_side) = mpsc::unbounded_channel();
    tokio::spawn(serve(server_side, script));
    Client::connect_with(Loopback { incoming }, config).await
}

async fn start(script: Script) -> (Client, Events) {
    start_with(script, config(Reconnect::Never))
        .await
        .expect("the client connects")
}

fn name() -> ObjectName {
    ObjectName::VmdSpecific(Identifier("list".to_string()))
}

// One test per service in scope

#[tokio::test]
async fn identify_is_answered_with_the_identity_of_the_peer() {
    let (client, _events) = start(Script::default()).await;
    let identity = client.identify().await.unwrap();
    assert_eq!(identity.vendor_name.0, "igs");
}

#[tokio::test]
async fn get_name_list_returns_the_names() {
    let (client, _events) = start(Script::default()).await;
    let response = client
        .get_name_list(GetNameListRequest {
            object_class: ObjectClass::BasicObjectClass(
                ObjectClassBasicObjectClass::NAMED_VARIABLE,
            ),
            object_scope: GetNameListRequestObjectScope::VmdSpecific,
            continue_after: None,
        })
        .await
        .unwrap();
    assert_eq!(
        response.list_of_identifier,
        vec![Identifier("alpha".to_string())]
    );
}

#[tokio::test]
async fn read_returns_the_values() {
    let (client, _events) = start(Script::default()).await;
    let response = client
        .read(ReadRequest {
            specification_with_result: None,
            variable_access_specification: VariableAccessSpecification::ListOfVariable(Vec::new()),
        })
        .await
        .unwrap();
    assert!(matches!(
        response.list_of_access_result.as_slice(),
        [AccessResult::Success(Data::Boolean(true))]
    ));
}

#[tokio::test]
async fn write_returns_the_result_of_each_item() {
    let (client, _events) = start(Script::default()).await;
    let response = client
        .write(WriteRequest {
            variable_access_specification: VariableAccessSpecification::ListOfVariable(Vec::new()),
            list_of_data: vec![Data::Boolean(false)],
        })
        .await
        .unwrap();
    assert_eq!(response.0, vec![WriteResponseItemItem::Success]);
}

#[tokio::test]
async fn get_variable_access_attributes_returns_the_type() {
    let (client, _events) = start(Script::default()).await;
    let response = client
        .get_variable_access_attributes(GetVariableAccessAttributesRequest::Name(name()))
        .await
        .unwrap();
    assert_eq!(response.type_description, TypeDescription::Boolean);
}

#[tokio::test]
async fn define_named_variable_list_is_acknowledged() {
    let (client, _events) = start(Script::default()).await;
    client
        .define_named_variable_list(DefineNamedVariableListRequest {
            variable_list_name: name(),
            list_of_variable: Vec::new(),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn get_named_variable_list_attributes_returns_the_list() {
    let (client, _events) = start(Script::default()).await;
    let response = client
        .get_named_variable_list_attributes(GetNamedVariableListAttributesRequest(name()))
        .await
        .unwrap();
    assert!(!response.mms_deletable);
}

#[tokio::test]
async fn delete_named_variable_list_returns_the_counts() {
    let (client, _events) = start(Script::default()).await;
    let response = client
        .delete_named_variable_list(DeleteNamedVariableListRequest {
            scope_of_delete: None,
            list_of_variable_list_name: None,
            domain_name: None,
        })
        .await
        .unwrap();
    assert_eq!(response.number_deleted.0, 1);
}

// Errors, events, queue, close, reconnection, timeouts

#[tokio::test]
async fn a_service_error_of_the_peer_is_returned_to_the_caller() {
    let (client, _events) = start(Script {
        read_fails: true,
        ..Script::default()
    })
    .await;
    let result = client
        .read(ReadRequest {
            specification_with_result: None,
            variable_access_specification: VariableAccessSpecification::ListOfVariable(Vec::new()),
        })
        .await;
    assert!(matches!(result, Err(Error::Service(_))), "{result:?}");
}

#[tokio::test]
async fn an_unconfirmed_report_reaches_the_event_stream() {
    let (client, mut events) = start(Script {
        reports: true,
        ..Script::default()
    })
    .await;
    assert_eq!(
        events.next().await,
        Some(Event::State(ConnectionState::Connected))
    );
    client.identify().await.unwrap();
    assert!(matches!(
        events.next().await,
        Some(Event::Report(UnconfirmedService::InformationReport(_)))
    ));
}

#[tokio::test]
async fn calls_beyond_the_outstanding_limit_wait_their_turn() {
    let (client, _events) = start(Script {
        outstanding: Some(2),
        ..Script::default()
    })
    .await;
    let mut tasks = Vec::new();
    for _ in 0..6 {
        let client = client.clone();
        tasks.push(tokio::spawn(async move { client.identify().await }));
    }
    for task in tasks {
        assert!(task.await.unwrap().is_ok());
    }
}

#[tokio::test]
async fn close_releases_the_association_and_later_calls_fail() {
    let (client, mut events) = start(Script::default()).await;
    client.identify().await.unwrap();
    client.close().await.unwrap();
    assert!(matches!(client.identify().await, Err(Error::ClientClosed)));
    assert_eq!(
        events.next().await,
        Some(Event::State(ConnectionState::Connected))
    );
    assert_eq!(
        events.next().await,
        Some(Event::State(ConnectionState::Closed))
    );
}

#[tokio::test]
async fn the_client_reconnects_and_the_call_in_flight_fails() {
    let script = Script {
        drop_first_on_read: true,
        ..Script::default()
    };
    let reconnect = Reconnect::Backoff {
        initial: Duration::from_millis(10),
        max: Duration::from_millis(100),
        attempts: Some(5),
    };
    let (client, mut events) = start_with(script, config(reconnect)).await.unwrap();
    assert_eq!(
        events.next().await,
        Some(Event::State(ConnectionState::Connected))
    );
    let lost = client
        .read(ReadRequest {
            specification_with_result: None,
            variable_access_specification: VariableAccessSpecification::ListOfVariable(Vec::new()),
        })
        .await;
    assert!(matches!(lost, Err(Error::ConnectionLost)), "{lost:?}");
    assert_eq!(
        events.next().await,
        Some(Event::State(ConnectionState::Disconnected))
    );
    assert_eq!(
        events.next().await,
        Some(Event::State(ConnectionState::Reconnecting { attempt: 1 }))
    );
    assert_eq!(
        events.next().await,
        Some(Event::State(ConnectionState::Connected))
    );
    assert_eq!(client.identify().await.unwrap().vendor_name.0, "igs");
}

#[tokio::test]
async fn without_a_reconnect_policy_the_client_closes_when_the_connection_ends() {
    let script = Script {
        drop_first_on_read: true,
        ..Script::default()
    };
    let (client, mut events) = start(script).await;
    let lost = client
        .read(ReadRequest {
            specification_with_result: None,
            variable_access_specification: VariableAccessSpecification::ListOfVariable(Vec::new()),
        })
        .await;
    assert!(matches!(lost, Err(Error::ConnectionLost)), "{lost:?}");
    assert_eq!(
        events.next().await,
        Some(Event::State(ConnectionState::Connected))
    );
    assert_eq!(
        events.next().await,
        Some(Event::State(ConnectionState::Disconnected))
    );
    assert_eq!(
        events.next().await,
        Some(Event::State(ConnectionState::Closed))
    );
    assert!(matches!(client.identify().await, Err(Error::ClientClosed)));
}

#[tokio::test]
async fn a_refused_association_fails_the_connect() {
    let result = start_with(
        Script {
            refuse: true,
            ..Script::default()
        },
        config(Reconnect::Never),
    )
    .await;
    assert!(
        matches!(result, Err(Error::Refused(_))),
        "{:?}",
        result.map(|_| ())
    );
}

#[tokio::test(start_paused = true)]
async fn a_request_with_no_answer_times_out() {
    let (client, _events) = start(Script {
        silent: true,
        ..Script::default()
    })
    .await;
    let started = Instant::now();
    let result = client.identify().await;
    assert!(matches!(result, Err(Error::Timeout)), "{result:?}");
    assert!(started.elapsed() >= Duration::from_secs(30));
}
