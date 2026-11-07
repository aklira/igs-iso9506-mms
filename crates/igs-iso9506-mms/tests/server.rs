// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The server (task S2), with the client of this repository, over TCP on the loopback. Each service in
//! scope is run by the client, and its answer is checked; the errors, the reports, several clients, the
//! association limit and the shutdown are covered too.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::Duration;

use igs_iso9506_mms::client::in_scope_capabilities;
use igs_iso9506_mms::vmd::{Identity, MemoryVariable, Name, Target, Vmd};
use igs_iso9506_mms::{
    Client, ClientConfig, Error, Event, Events, Reconnect, Server, ServerConfig,
};
use igs_iso9506_mms_codec::generated::types::{
    AccessResult, Data, DataAccessError, DefineNamedVariableListRequest,
    DefineNamedVariableListRequestListOfVariableItem, DeleteNamedVariableListRequest,
    DeleteNamedVariableListRequestScopeOfDelete, GetNameListRequest, GetNameListRequestObjectScope,
    GetNamedVariableListAttributesRequest, GetVariableAccessAttributesRequest, Identifier,
    InformationReport, ObjectClass, ObjectClassBasicObjectClass, ObjectName,
    ObjectNameDomainSpecific, ReadRequest, ServiceError, ServiceErrorErrorClass,
    ServiceErrorErrorClassAccess, ServiceErrorErrorClassDefinition, TypeDescription,
    TypeDescriptionStructure, TypeDescriptionStructureComponentsItem, TypeSpecification,
    UnconfirmedService, Unsigned8, VariableAccessSpecification,
    VariableAccessSpecificationListOfVariableItem, VariableSpecification, WriteRequest,
    WriteResponseItemItem,
};
use igs_iso9506_mms_link::config::LinkConfig;
use tokio::time::timeout;

const ANSWER: Duration = Duration::from_secs(10);

fn name(text: &str) -> Name {
    Name::new(text).unwrap()
}

fn integer(bits: i64) -> TypeDescription {
    TypeDescription::Integer(Unsigned8(bits))
}

/// The model of the tests: domain `D`, a writable and a read-only variable at the VMD, a structure, and
/// seventy named variables, so that a name list needs more than one page.
fn model() -> Vmd {
    let mut vmd = Vmd::new(Identity {
        vendor: "igs".to_string(),
        model: "test server".to_string(),
        revision: "1.0".to_string(),
    });
    vmd.add_domain(name("D")).unwrap();
    vmd.add_variable(
        &Target::vmd(name("speed")),
        Box::new(MemoryVariable::new(integer(32), Data::Integer(5), true).unwrap()),
    )
    .unwrap();
    vmd.add_variable(
        &Target::vmd(name("flag")),
        Box::new(
            MemoryVariable::new(TypeDescription::Boolean, Data::Boolean(true), false).unwrap(),
        ),
    )
    .unwrap();
    let pair = TypeDescription::Structure(TypeDescriptionStructure {
        packed: None,
        components: vec![
            TypeDescriptionStructureComponentsItem {
                component_name: None,
                component_type: TypeSpecification::TypeDescription(Box::new(
                    TypeDescription::Boolean,
                )),
            },
            TypeDescriptionStructureComponentsItem {
                component_name: None,
                component_type: TypeSpecification::TypeDescription(Box::new(integer(16))),
            },
        ],
    });
    vmd.add_variable(
        &Target::in_domain(name("D"), name("pair")),
        Box::new(
            MemoryVariable::new(
                pair,
                Data::Structure(vec![Data::Boolean(false), Data::Integer(7)]),
                true,
            )
            .unwrap(),
        ),
    )
    .unwrap();
    for index in 0..70 {
        vmd.add_variable(
            &Target::vmd(name(&format!("v{index:02}"))),
            Box::new(MemoryVariable::new(integer(16), Data::Integer(index), true).unwrap()),
        )
        .unwrap();
    }
    vmd
}

async fn start() -> Server {
    let config = ServerConfig::new(LinkConfig::default());
    Server::bind("127.0.0.1:0", config, model()).await.unwrap()
}

fn client_config() -> ClientConfig {
    ClientConfig {
        reconnect: Reconnect::Never,
        ..ClientConfig::new(LinkConfig::default(), in_scope_capabilities())
    }
}

async fn connect(server: &Server) -> (Client, Events) {
    timeout(
        ANSWER,
        Client::connect(&server.local_address().to_string(), client_config()),
    )
    .await
    .expect("the association is established in time")
    .expect("the server establishes the association")
}

fn vmd_name(text: &str) -> ObjectName {
    ObjectName::VmdSpecific(Identifier(text.to_string()))
}

fn domain_name(domain: &str, item: &str) -> ObjectName {
    ObjectName::DomainSpecific(ObjectNameDomainSpecific {
        domain_id: Identifier(domain.to_string()),
        item_id: Identifier(item.to_string()),
    })
}

fn one(object: ObjectName) -> VariableAccessSpecification {
    VariableAccessSpecification::ListOfVariable(vec![
        VariableAccessSpecificationListOfVariableItem {
            variable_specification: VariableSpecification::Name(object),
            alternate_access: None,
        },
    ])
}

fn read(object: ObjectName) -> ReadRequest {
    ReadRequest {
        specification_with_result: None,
        variable_access_specification: one(object),
    }
}

fn names(
    class: ObjectClassBasicObjectClass,
    scope: GetNameListRequestObjectScope,
) -> GetNameListRequest {
    GetNameListRequest {
        object_class: ObjectClass::BasicObjectClass(class),
        object_scope: scope,
        continue_after: None,
    }
}

fn service_error_class(error: &Error) -> &ServiceErrorErrorClass {
    match error {
        Error::Service(ServiceError { error_class, .. }) => error_class,
        other => panic!("a service error was expected: {other:?}"),
    }
}

#[tokio::test]
async fn identify_is_answered_with_the_identity_of_the_server() {
    let server = start().await;
    let (client, _events) = connect(&server).await;
    let identity = client.identify().await.unwrap();
    assert_eq!(identity.vendor_name.0, "igs");
    assert_eq!(identity.model_name.0, "test server");
    assert_eq!(identity.revision.0, "1.0");
    client.close().await.unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn get_name_list_lists_the_domains() {
    let server = start().await;
    let (client, _events) = connect(&server).await;
    let page = client
        .get_name_list(names(
            ObjectClassBasicObjectClass::DOMAIN,
            GetNameListRequestObjectScope::VmdSpecific,
        ))
        .await
        .unwrap();
    assert_eq!(page.list_of_identifier, vec![Identifier("D".to_string())]);
    assert_eq!(page.more_follows, Some(false));
    client.close().await.unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn get_name_list_pages_through_the_named_variables() {
    let server = start().await;
    let (client, _events) = connect(&server).await;
    let mut all = Vec::new();
    let mut after: Option<Identifier> = None;
    loop {
        let mut request = names(
            ObjectClassBasicObjectClass::NAMED_VARIABLE,
            GetNameListRequestObjectScope::VmdSpecific,
        );
        request.continue_after = after.clone();
        let page = client.get_name_list(request).await.unwrap();
        all.extend(page.list_of_identifier.iter().map(|n| n.0.clone()));
        if !page.more_follows.unwrap_or(true) {
            break;
        }
        after = page.list_of_identifier.last().cloned();
    }
    // Two variables at the VMD scope and seventy more, in the order of the model.
    assert_eq!(all.len(), 72);
    let mut sorted = all.clone();
    sorted.sort();
    assert_eq!(all, sorted);
    assert!(all.contains(&"speed".to_string()));
    client.close().await.unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn get_name_list_of_a_domain_lists_its_variables() {
    let server = start().await;
    let (client, _events) = connect(&server).await;
    let page = client
        .get_name_list(names(
            ObjectClassBasicObjectClass::NAMED_VARIABLE,
            GetNameListRequestObjectScope::DomainSpecific(Identifier("D".to_string())),
        ))
        .await
        .unwrap();
    assert_eq!(
        page.list_of_identifier,
        vec![Identifier("pair".to_string())]
    );
    client.close().await.unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn read_returns_the_value_and_fails_per_item() {
    let server = start().await;
    let (client, _events) = connect(&server).await;
    let response = client.read(read(vmd_name("speed"))).await.unwrap();
    assert_eq!(
        response.list_of_access_result,
        vec![AccessResult::Success(Data::Integer(5))]
    );
    let response = client.read(read(vmd_name("missing"))).await.unwrap();
    assert_eq!(
        response.list_of_access_result,
        vec![AccessResult::Failure(DataAccessError::OBJECT_NON_EXISTENT)]
    );
    let response = client.read(read(domain_name("D", "pair"))).await.unwrap();
    assert_eq!(
        response.list_of_access_result,
        vec![AccessResult::Success(Data::Structure(vec![
            Data::Boolean(false),
            Data::Integer(7)
        ]))]
    );
    client.close().await.unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn write_is_answered_and_the_value_read_back() {
    let server = start().await;
    let (client, _events) = connect(&server).await;
    let written = client
        .write(WriteRequest {
            variable_access_specification: one(vmd_name("speed")),
            list_of_data: vec![Data::Integer(-12)],
        })
        .await
        .unwrap();
    assert_eq!(written.0, vec![WriteResponseItemItem::Success]);
    let response = client.read(read(vmd_name("speed"))).await.unwrap();
    assert_eq!(
        response.list_of_access_result,
        vec![AccessResult::Success(Data::Integer(-12))]
    );
    // A structure is written as a whole, in the type of the variable.
    let written = client
        .write(WriteRequest {
            variable_access_specification: one(domain_name("D", "pair")),
            list_of_data: vec![Data::Structure(vec![
                Data::Boolean(true),
                Data::Integer(-1),
            ])],
        })
        .await
        .unwrap();
    assert_eq!(written.0, vec![WriteResponseItemItem::Success]);
    client.close().await.unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn write_is_refused_for_a_read_only_variable_and_a_wrong_type() {
    let server = start().await;
    let (client, _events) = connect(&server).await;
    let read_only = client
        .write(WriteRequest {
            variable_access_specification: one(vmd_name("flag")),
            list_of_data: vec![Data::Boolean(false)],
        })
        .await
        .unwrap();
    assert_eq!(
        read_only.0,
        vec![WriteResponseItemItem::Failure(
            DataAccessError::OBJECT_ACCESS_DENIED
        )]
    );
    let wrong_type = client
        .write(WriteRequest {
            variable_access_specification: one(vmd_name("speed")),
            list_of_data: vec![Data::Boolean(true)],
        })
        .await
        .unwrap();
    assert_eq!(
        wrong_type.0,
        vec![WriteResponseItemItem::Failure(
            DataAccessError::TYPE_INCONSISTENT
        )]
    );
    // Nothing changed.
    let response = client.read(read(vmd_name("speed"))).await.unwrap();
    assert_eq!(
        response.list_of_access_result,
        vec![AccessResult::Success(Data::Integer(5))]
    );
    client.close().await.unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn get_variable_access_attributes_returns_the_type() {
    let server = start().await;
    let (client, _events) = connect(&server).await;
    let attributes = client
        .get_variable_access_attributes(GetVariableAccessAttributesRequest::Name(vmd_name("speed")))
        .await
        .unwrap();
    assert_eq!(attributes.type_description, integer(32));
    assert!(!attributes.mms_deletable);
    client.close().await.unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn define_get_and_delete_a_named_variable_list() {
    let server = start().await;
    let (client, _events) = connect(&server).await;
    let members = [vmd_name("speed"), vmd_name("flag")]
        .into_iter()
        .map(|object| DefineNamedVariableListRequestListOfVariableItem {
            variable_specification: VariableSpecification::Name(object),
            alternate_access: None,
        })
        .collect();
    client
        .define_named_variable_list(DefineNamedVariableListRequest {
            variable_list_name: vmd_name("pairlist"),
            list_of_variable: members,
        })
        .await
        .unwrap();

    let attributes = client
        .get_named_variable_list_attributes(GetNamedVariableListAttributesRequest(vmd_name(
            "pairlist",
        )))
        .await
        .unwrap();
    assert_eq!(attributes.list_of_variable.len(), 2);
    assert!(attributes.mms_deletable);

    // The list is read member by member.
    let listed = client
        .read(igs_iso9506_mms_codec::generated::types::ReadRequest {
            specification_with_result: None,
            variable_access_specification: VariableAccessSpecification::VariableListName(vmd_name(
                "pairlist",
            )),
        })
        .await
        .unwrap();
    assert_eq!(
        listed.list_of_access_result,
        vec![
            AccessResult::Success(Data::Integer(5)),
            AccessResult::Success(Data::Boolean(true)),
        ]
    );

    let deleted = client
        .delete_named_variable_list(DeleteNamedVariableListRequest {
            scope_of_delete: None,
            list_of_variable_list_name: Some(vec![vmd_name("pairlist")]),
            domain_name: None,
        })
        .await
        .unwrap();
    assert_eq!(deleted.number_matched.0, 1);
    assert_eq!(deleted.number_deleted.0, 1);
    // Deleting it again matches nothing.
    let again = client
        .delete_named_variable_list(DeleteNamedVariableListRequest {
            scope_of_delete: None,
            list_of_variable_list_name: Some(vec![vmd_name("pairlist")]),
            domain_name: None,
        })
        .await
        .unwrap();
    assert_eq!(again.number_matched.0, 0);
    client.close().await.unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn a_list_of_a_domain_is_deleted_with_its_scope() {
    let server = start().await;
    let (client, _events) = connect(&server).await;
    client
        .define_named_variable_list(DefineNamedVariableListRequest {
            variable_list_name: domain_name("D", "dl"),
            list_of_variable: vec![DefineNamedVariableListRequestListOfVariableItem {
                variable_specification: VariableSpecification::Name(domain_name("D", "pair")),
                alternate_access: None,
            }],
        })
        .await
        .unwrap();
    let deleted = client
        .delete_named_variable_list(DeleteNamedVariableListRequest {
            scope_of_delete: Some(DeleteNamedVariableListRequestScopeOfDelete::DOMAIN),
            list_of_variable_list_name: None,
            domain_name: Some(Identifier("D".to_string())),
        })
        .await
        .unwrap();
    assert_eq!(deleted.number_deleted.0, 1);
    client.close().await.unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn a_definition_that_exists_or_names_a_missing_member_is_an_error() {
    let server = start().await;
    let (client, _events) = connect(&server).await;
    let define = |list: &str, member: &str| DefineNamedVariableListRequest {
        variable_list_name: vmd_name(list),
        list_of_variable: vec![DefineNamedVariableListRequestListOfVariableItem {
            variable_specification: VariableSpecification::Name(vmd_name(member)),
            alternate_access: None,
        }],
    };
    let missing = client
        .define_named_variable_list(define("l1", "missing"))
        .await;
    assert_eq!(
        service_error_class(&missing.unwrap_err()),
        &ServiceErrorErrorClass::Access(ServiceErrorErrorClassAccess::OBJECT_NON_EXISTENT)
    );
    client
        .define_named_variable_list(define("l2", "speed"))
        .await
        .unwrap();
    let exists = client
        .define_named_variable_list(define("l2", "speed"))
        .await;
    assert_eq!(
        service_error_class(&exists.unwrap_err()),
        &ServiceErrorErrorClass::Definition(ServiceErrorErrorClassDefinition::OBJECT_EXISTS)
    );
    client.close().await.unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn an_unconfirmed_report_reaches_the_associations() {
    let server = start().await;
    let (client, mut events) = connect(&server).await;
    let report = UnconfirmedService::InformationReport(InformationReport {
        variable_access_specification: VariableAccessSpecification::VariableListName(vmd_name(
            "RPT",
        )),
        list_of_access_result: vec![AccessResult::Success(Data::Integer(9))],
    });
    assert_eq!(server.publish(report.clone()), 1);
    let received = timeout(ANSWER, async {
        loop {
            match events.next().await {
                Some(Event::Report(service)) => return Some(service),
                Some(_) => continue,
                None => return None,
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(received, Some(report));
    client.close().await.unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn several_clients_run_their_requests_at_once() {
    let server = start().await;
    let mut clients = Vec::new();
    for _ in 0..5 {
        clients.push(connect(&server).await);
    }
    let mut tasks = Vec::new();
    for (index, (client, _events)) in clients.into_iter().enumerate() {
        tasks.push(tokio::spawn(async move {
            let response = client.read(read(vmd_name("speed"))).await.unwrap();
            assert_eq!(
                response.list_of_access_result,
                vec![AccessResult::Success(Data::Integer(5))],
                "client {index}"
            );
            client.close().await.unwrap();
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    server.shutdown().await;
}

#[tokio::test]
async fn a_connection_beyond_the_limit_is_closed() {
    let config = ServerConfig {
        max_associations: 1,
        ..ServerConfig::new(LinkConfig::default())
    };
    let server = Server::bind("127.0.0.1:0", config, model()).await.unwrap();
    let (first, _events) = connect(&server).await;
    let second = timeout(
        ANSWER,
        Client::connect(&server.local_address().to_string(), client_config()),
    )
    .await
    .expect("the answer comes in time");
    assert!(second.is_err(), "the second association is refused");
    first.close().await.unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn shutdown_stops_the_listener() {
    let server = start().await;
    let address = server.local_address();
    server.shutdown().await;
    let attempt = timeout(
        ANSWER,
        Client::connect(&address.to_string(), client_config()),
    )
    .await
    .expect("the attempt ends in time");
    assert!(attempt.is_err());
}
