// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The client matrix against the reference server of the bench (task T4): one scenario per service in
//! scope, run with the client API of this repository. Each scenario prints one row of the matrix, and
//! asserts the outcome the stack is expected to have: a pass, or a recorded gap of
//! `docs/capabilities.md` (rule 10 of `IMPLEMENTATION.md`).
//!
//! The scenarios need the bench (`bench/`, task F5). They are ignored by default; run them with
//! `MMS_PEER=127.0.0.1:10102 cargo test -p igs-iso9506-mms --test interop_matrix -- --ignored --nocapture`.
//! `bench/tests/test_t4_client_matrix.py` runs them with the capture and checks it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::Duration;

use igs_iso9506_mms::client::in_scope_capabilities;
use igs_iso9506_mms::{Client, ClientConfig, Error, Event, Events, Reconnect};
use igs_iso9506_mms_codec::generated::types::{
    AccessResult, Data, DefineNamedVariableListRequest,
    DefineNamedVariableListRequestListOfVariableItem, DeleteNamedVariableListRequest,
    GetNameListRequest, GetNameListRequestObjectScope, GetNamedVariableListAttributesRequest,
    GetVariableAccessAttributesRequest, Identifier, ObjectClass, ObjectClassBasicObjectClass,
    ObjectName, ObjectNameDomainSpecific, ReadRequest, UnconfirmedService,
    VariableAccessSpecification, VariableAccessSpecificationListOfVariableItem,
    VariableSpecification, WriteRequest, WriteResponseItemItem,
};
use igs_iso9506_mms_link::config::LinkConfig;
use tokio::time::timeout;

/// The domain of the reference server: `server_example_basic_io` (libiec61850 v1.6.2.1).
const DOMAIN: &str = "simpleIOGenericIO";
/// A floating-point variable, read-only, with an identifier of 20 characters (within 32, G9).
const FLOAT: &str = "GGIO1$MX$AnIn1$mag$f";
/// A boolean the server accepts to write: the buffered-report enable of an unbuffered report. Its
/// identifier has 30 characters.
const ENABLE: &str = "LLN0$RP$EventsIndexed01$RptEna";
/// The general interrogation of the same report control block: a boolean that makes the server send
/// the report at once.
const INTERROGATION: &str = "LLN0$RP$EventsIndexed01$GI";
/// A list defined by the scenarios, at the VMD scope: the reference server refuses a list whose name is
/// in the domain (`docs/capabilities.md`, G12).
const LIST: &str = "T4List";

/// How long the peer may take to answer one request.
const ANSWER_TIME: Duration = Duration::from_secs(15);

fn peer_address() -> Option<String> {
    std::env::var("MMS_PEER").ok()
}

/// Connects to the reference server. `lenient` takes the parameter CBBs as proposed (G8).
async fn connect(address: &str, lenient: bool) -> (Client, Events) {
    let link = LinkConfig {
        // The reference server answers with data nested deeper than 2 (G10).
        nesting_level: 6,
        request_timeout: ANSWER_TIME,
        ..LinkConfig::default()
    };
    let config = ClientConfig {
        reconnect: Reconnect::Never,
        lenient_parameter_cbbs: lenient,
        ..ClientConfig::new(link, in_scope_capabilities())
    };
    timeout(ANSWER_TIME, Client::connect(address, config))
        .await
        .expect("the association is established in time")
        .expect("the reference server establishes the association")
}

/// One row of the matrix, printed for the bench to collect.
fn row(service: &str, mode: &str, observed: impl std::fmt::Debug) {
    println!("T4-MATRIX | {service} | {mode} | {observed:?}");
}

fn domain_name(item: &str) -> ObjectName {
    ObjectName::DomainSpecific(ObjectNameDomainSpecific {
        domain_id: Identifier(DOMAIN.to_string()),
        item_id: Identifier(item.to_string()),
    })
}

fn vmd_name(item: &str) -> ObjectName {
    ObjectName::VmdSpecific(Identifier(item.to_string()))
}

fn one_variable(item: &str) -> VariableAccessSpecification {
    VariableAccessSpecification::ListOfVariable(vec![
        VariableAccessSpecificationListOfVariableItem {
            variable_specification: VariableSpecification::Name(domain_name(item)),
            alternate_access: None,
        },
    ])
}

fn names_of_class(
    class: ObjectClassBasicObjectClass,
    scope: GetNameListRequestObjectScope,
) -> GetNameListRequest {
    GetNameListRequest {
        object_class: ObjectClass::BasicObjectClass(class),
        object_scope: scope,
        continue_after: None,
    }
}

fn in_domain() -> GetNameListRequestObjectScope {
    GetNameListRequestObjectScope::DomainSpecific(Identifier(DOMAIN.to_string()))
}

/// Writes the boolean `value` to `item`, then reads it back in the same association.
async fn write_bool(
    client: &Client,
    item: &str,
    value: bool,
) -> Result<Vec<WriteResponseItemItem>, Error> {
    let response = client
        .write(WriteRequest {
            variable_access_specification: one_variable(item),
            list_of_data: vec![Data::Boolean(value)],
        })
        .await?;
    Ok(response.0)
}

#[tokio::test]
#[ignore = "needs the bench: MMS_PEER=127.0.0.1:10102"]
async fn identify() {
    let Some(address) = peer_address() else {
        eprintln!("MMS_PEER is not set: the scenario is skipped");
        return;
    };
    let (client, _events) = connect(&address, false).await;
    let identity = client.identify().await.expect("the peer answers Identify");
    row("identify", "conformant", &identity.vendor_name.0);
    assert_eq!(identity.vendor_name.0, "MZ");
    client.close().await.expect("the association is closed");
}

#[tokio::test]
#[ignore = "needs the bench: MMS_PEER=127.0.0.1:10102"]
async fn get_name_list_of_domains() {
    let Some(address) = peer_address() else {
        return;
    };
    let (client, _events) = connect(&address, false).await;
    let names = client
        .get_name_list(names_of_class(
            ObjectClassBasicObjectClass::DOMAIN,
            GetNameListRequestObjectScope::VmdSpecific,
        ))
        .await;
    row("getNameList (domain)", "conformant", &names);
    let names = names.expect("the peer lists its domains");
    assert!(names.list_of_identifier.iter().any(|name| name.0 == DOMAIN));
    client.close().await.expect("the association is closed");
}

#[tokio::test]
#[ignore = "needs the bench: MMS_PEER=127.0.0.1:10102"]
async fn get_name_list_of_named_variables_is_refused_locally_by_default() {
    // G8: the peer negotiates no parameter CBB, so the conformant client refuses the request.
    let Some(address) = peer_address() else {
        return;
    };
    let (client, _events) = connect(&address, false).await;
    let names = client
        .get_name_list(names_of_class(
            ObjectClassBasicObjectClass::NAMED_VARIABLE,
            in_domain(),
        ))
        .await;
    row("getNameList (named variable)", "conformant", &names);
    assert!(matches!(names, Err(Error::Misuse(_))), "G8: {names:?}");
    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "needs the bench: MMS_PEER=127.0.0.1:10102"]
async fn get_name_list_of_named_variable_lists() {
    let Some(address) = peer_address() else {
        return;
    };
    let (client, _events) = connect(&address, true).await;
    let names = client
        .get_name_list(names_of_class(
            ObjectClassBasicObjectClass::NAMED_VARIABLE_LIST,
            in_domain(),
        ))
        .await;
    row("getNameList (named variable list)", "lenient", &names);
    let names = names.expect("the peer lists its named variable lists");
    assert!(names
        .list_of_identifier
        .iter()
        .any(|name| name.0 == "LLN0$Events"));
    client.close().await.expect("the association is closed");
}

#[tokio::test]
#[ignore = "needs the bench: MMS_PEER=127.0.0.1:10102"]
async fn get_name_list_of_named_variables_ends_the_connection() {
    // G9: the peer lists identifiers longer than 32 characters, which the codec refuses.
    let Some(address) = peer_address() else {
        return;
    };
    let (client, _events) = connect(&address, true).await;
    let names = client
        .get_name_list(names_of_class(
            ObjectClassBasicObjectClass::NAMED_VARIABLE,
            in_domain(),
        ))
        .await;
    row("getNameList (named variable)", "lenient", &names);
    assert!(names.is_err(), "G9: the listing is refused: {names:?}");
    let _ = client.abort().await;
}

#[tokio::test]
#[ignore = "needs the bench: MMS_PEER=127.0.0.1:10102"]
async fn read_is_refused_locally_by_default() {
    // G8.
    let Some(address) = peer_address() else {
        return;
    };
    let (client, _events) = connect(&address, false).await;
    let response = client
        .read(ReadRequest {
            specification_with_result: None,
            variable_access_specification: one_variable(FLOAT),
        })
        .await;
    row("read", "conformant", &response);
    assert!(
        matches!(response, Err(Error::Misuse(_))),
        "G8: {response:?}"
    );
    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "needs the bench: MMS_PEER=127.0.0.1:10102"]
async fn read_returns_a_value() {
    let Some(address) = peer_address() else {
        return;
    };
    let (client, _events) = connect(&address, true).await;
    let response = client
        .read(ReadRequest {
            specification_with_result: None,
            variable_access_specification: one_variable(FLOAT),
        })
        .await
        .expect("the peer answers Read");
    row("read", "lenient", &response.list_of_access_result);
    assert!(matches!(
        response.list_of_access_result.first(),
        Some(AccessResult::Success(Data::FloatingPoint(_)))
    ));
    client.close().await.expect("the association is closed");
}

#[tokio::test]
#[ignore = "needs the bench: MMS_PEER=127.0.0.1:10102"]
async fn write_is_answered_and_the_value_read_back() {
    let Some(address) = peer_address() else {
        return;
    };
    let (client, _events) = connect(&address, true).await;
    let written = write_bool(&client, ENABLE, true).await;
    row("write", "lenient", &written);
    assert_eq!(
        written.expect("the peer answers Write"),
        vec![WriteResponseItemItem::Success]
    );
    let read = client
        .read(ReadRequest {
            specification_with_result: None,
            variable_access_specification: one_variable(ENABLE),
        })
        .await
        .expect("the peer answers Read");
    row("read after write", "lenient", &read.list_of_access_result);
    assert!(matches!(
        read.list_of_access_result.first(),
        Some(AccessResult::Success(Data::Boolean(true)))
    ));
    client.close().await.expect("the association is closed");
}

#[tokio::test]
#[ignore = "needs the bench: MMS_PEER=127.0.0.1:10102"]
async fn get_variable_access_attributes_returns_the_type() {
    let Some(address) = peer_address() else {
        return;
    };
    let (client, _events) = connect(&address, true).await;
    let attributes = client
        .get_variable_access_attributes(GetVariableAccessAttributesRequest::Name(domain_name(
            FLOAT,
        )))
        .await;
    row("getVariableAccessAttributes", "lenient", &attributes);
    attributes.expect("the peer answers GetVariableAccessAttributes");
    client.close().await.expect("the association is closed");
}

#[tokio::test]
#[ignore = "needs the bench: MMS_PEER=127.0.0.1:10102"]
async fn define_get_and_delete_a_named_variable_list() {
    let Some(address) = peer_address() else {
        return;
    };
    let (client, _events) = connect(&address, true).await;
    let defined = client
        .define_named_variable_list(DefineNamedVariableListRequest {
            variable_list_name: vmd_name(LIST),
            list_of_variable: [FLOAT, ENABLE]
                .iter()
                .map(|item| DefineNamedVariableListRequestListOfVariableItem {
                    variable_specification: VariableSpecification::Name(domain_name(item)),
                    alternate_access: None,
                })
                .collect(),
        })
        .await;
    row("defineNamedVariableList", "lenient", &defined);
    defined.expect("the peer answers DefineNamedVariableList");

    let attributes = client
        .get_named_variable_list_attributes(GetNamedVariableListAttributesRequest(vmd_name(LIST)))
        .await;
    row("getNamedVariableListAttributes", "lenient", &attributes);
    let attributes = attributes.expect("the peer answers GetNamedVariableListAttributes");
    assert_eq!(attributes.list_of_variable.len(), 2);

    let deleted = client
        .delete_named_variable_list(DeleteNamedVariableListRequest {
            scope_of_delete: None,
            list_of_variable_list_name: Some(vec![vmd_name(LIST)]),
            domain_name: None,
        })
        .await;
    row("deleteNamedVariableList", "lenient", &deleted);
    assert_eq!(
        deleted
            .expect("the peer answers DeleteNamedVariableList")
            .number_deleted
            .0,
        1
    );
    client.close().await.expect("the association is closed");
}

#[tokio::test]
#[ignore = "needs the bench: MMS_PEER=127.0.0.1:10102"]
async fn information_report_is_received_after_a_general_interrogation() {
    let Some(address) = peer_address() else {
        return;
    };
    let (client, mut events) = connect(&address, true).await;
    write_bool(&client, ENABLE, true)
        .await
        .expect("the peer enables the report control block");
    write_bool(&client, INTERROGATION, true)
        .await
        .expect("the peer accepts the general interrogation");
    let report = timeout(ANSWER_TIME, async {
        loop {
            match events.next().await {
                Some(Event::Report(report @ UnconfirmedService::InformationReport(_))) => {
                    return Some(report);
                }
                Some(_) => continue,
                None => return None,
            }
        }
    })
    .await;
    row("informationReport", "lenient", &report);
    assert!(
        matches!(report, Ok(Some(UnconfirmedService::InformationReport(_)))),
        "the report arrives: {report:?}"
    );

    client.close().await.expect("the association is closed");
}
