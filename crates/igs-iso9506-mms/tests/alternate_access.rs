// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Alternate access towards the model (task N4 of igs-iec61850-mms): a model that negotiates `valt` reads
//! the paths of the requests it receives; the generic VMD keeps refusing them; without `valt` the request
//! never reaches the model.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use igs_iso9506_mms::client::{in_scope_capabilities, Client, ClientConfig, Reconnect};
use igs_iso9506_mms::server::access::{self, AccessStep};
use igs_iso9506_mms::server::{Model, Peer, Server, ServerConfig};
use igs_iso9506_mms::vmd::{Identity, Vmd};
use igs_iso9506_mms_codec::generated::types::{
    AccessResult, AlternateAccess, AlternateAccessItemItem, AlternateAccessSelection,
    AlternateAccessSelectionSelectAccess, AlternateAccessSelectionSelectAccessIndexRange,
    ConfirmedServiceRequest, ConfirmedServiceResponse, Data, DataAccessError, Identifier,
    ObjectName, ObjectNameDomainSpecific, ReadRequest, ReadResponse, ServiceError, Unsigned32,
    VariableAccessSpecification, VariableAccessSpecificationListOfVariableItem,
    VariableSpecification,
};
use igs_iso9506_mms_link::config::LinkConfig;
use tokio::time::timeout;

const ANSWER: Duration = Duration::from_secs(10);

fn vmd() -> Vmd {
    Vmd::new(Identity {
        vendor: "igs".to_string(),
        model: "alternate-access".to_string(),
        revision: "1".to_string(),
    })
}

fn client_config() -> ClientConfig {
    ClientConfig {
        reconnect: Reconnect::Never,
        ..ClientConfig::new(LinkConfig::default(), in_scope_capabilities())
    }
}

/// A model that answers the reads that carry an alternate access with the paths it read, and hands the
/// other services to the VMD.
struct Recorder {
    paths: Arc<Mutex<Vec<Vec<AccessStep>>>>,
    vmd: Vmd,
}

impl Model for Recorder {
    fn dispatch(
        &mut self,
        peer: &Peer,
        service: ConfirmedServiceRequest,
    ) -> Result<ConfirmedServiceResponse, ServiceError> {
        if let ConfirmedServiceRequest::Read(read) = &service {
            if let VariableAccessSpecification::ListOfVariable(items) =
                &read.variable_access_specification
            {
                let results = items
                    .iter()
                    .map(|item| match &item.alternate_access {
                        Some(access) => match access::steps(access) {
                            Ok(path) => {
                                self.paths.lock().unwrap().push(path);
                                AccessResult::Success(Data::Integer(7))
                            }
                            Err(error) => AccessResult::Failure(error.data_access_error()),
                        },
                        None => AccessResult::Failure(DataAccessError::OBJECT_ACCESS_UNSUPPORTED),
                    })
                    .collect();
                return Ok(ConfirmedServiceResponse::Read(ReadResponse {
                    variable_access_specification: None,
                    list_of_access_result: results,
                }));
            }
        }
        <Vmd as Model>::dispatch(&mut self.vmd, peer, service)
    }
}

/// A read of one variable, with this alternate access.
fn read_with(access: AlternateAccess) -> ConfirmedServiceRequest {
    ConfirmedServiceRequest::Read(ReadRequest {
        specification_with_result: None,
        variable_access_specification: VariableAccessSpecification::ListOfVariable(vec![
            VariableAccessSpecificationListOfVariableItem {
                variable_specification: VariableSpecification::Name(ObjectName::DomainSpecific(
                    ObjectNameDomainSpecific {
                        domain_id: Identifier("LD0".into()),
                        item_id: Identifier("MMXU1$MX$A".into()),
                    },
                )),
                alternate_access: Some(access),
            },
        ]),
    })
}

fn index(value: i64) -> AlternateAccess {
    AlternateAccess(vec![AlternateAccessItemItem::Unnamed(
        AlternateAccessSelection::SelectAccess(AlternateAccessSelectionSelectAccess::Index(
            Unsigned32(value),
        )),
    )])
}

fn results(response: ConfirmedServiceResponse) -> Vec<AccessResult> {
    match response {
        ConfirmedServiceResponse::Read(read) => read.list_of_access_result,
        other => panic!("not a read answer: {other:?}"),
    }
}

#[tokio::test]
async fn a_model_with_valt_reads_the_path_of_each_item() {
    let paths = Arc::new(Mutex::new(Vec::new()));
    let model = Recorder {
        paths: Arc::clone(&paths),
        vmd: vmd(),
    };
    let config = ServerConfig::new(LinkConfig::default()).with_alternate_access();
    let server = Server::bind_model("127.0.0.1:0", config, model)
        .await
        .unwrap();
    let address = server.local_address().to_string();
    let (client, _events) = timeout(ANSWER, Client::connect(&address, client_config()))
        .await
        .unwrap()
        .unwrap();

    let answer = timeout(ANSWER, client.request(read_with(index(2))))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(results(answer), [AccessResult::Success(Data::Integer(7))]);
    assert_eq!(*paths.lock().unwrap(), [vec![AccessStep::Index(2)]]);
}

#[tokio::test]
async fn the_generic_vmd_keeps_refusing_alternate_access() {
    // The same request, served by the VMD alone, with valt negotiated: each item fails (OBJECT_ACCESS_UNSUPPORTED).
    let config = ServerConfig::new(LinkConfig::default()).with_alternate_access();
    let server = Server::bind("127.0.0.1:0", config, vmd()).await.unwrap();
    let address = server.local_address().to_string();
    let (client, _events) = timeout(ANSWER, Client::connect(&address, client_config()))
        .await
        .unwrap()
        .unwrap();

    let answer = timeout(ANSWER, client.request(read_with(index(2))))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        results(answer),
        [AccessResult::Failure(
            DataAccessError::OBJECT_ACCESS_UNSUPPORTED
        )]
    );
}

#[tokio::test]
async fn without_valt_the_request_never_reaches_the_model() {
    let paths = Arc::new(Mutex::new(Vec::new()));
    let model = Recorder {
        paths: Arc::clone(&paths),
        vmd: vmd(),
    };
    // The default server does not negotiate valt: the client sees that the peer does not serve it.
    let config = ServerConfig::new(LinkConfig::default());
    let server = Server::bind_model("127.0.0.1:0", config, model)
        .await
        .unwrap();
    let address = server.local_address().to_string();
    let (client, _events) = timeout(ANSWER, Client::connect(&address, client_config()))
        .await
        .unwrap()
        .unwrap();

    let refused = timeout(ANSWER, client.request(read_with(index(2))))
        .await
        .unwrap();
    assert!(refused.is_err(), "the request is refused before it is sent");
    assert!(paths.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_path_outside_the_bounds_fails_its_item_before_the_model() {
    let paths = Arc::new(Mutex::new(Vec::new()));
    let model = Recorder {
        paths: Arc::clone(&paths),
        vmd: vmd(),
    };
    let config = ServerConfig::new(LinkConfig::default()).with_alternate_access();
    let server = Server::bind_model("127.0.0.1:0", config, model)
        .await
        .unwrap();
    let address = server.local_address().to_string();
    let (client, _events) = timeout(ANSWER, Client::connect(&address, client_config()))
        .await
        .unwrap()
        .unwrap();

    // A range of no element is valid on the wire and refused by its bounds: the item fails with
    // OBJECT_VALUE_INVALID and the model reads nothing. (The values of the wire are at most 2^31 - 1, so an
    // index cannot overflow: the bounds that remain are the empty range.)
    let empty = AlternateAccess(vec![AlternateAccessItemItem::Unnamed(
        AlternateAccessSelection::SelectAccess(AlternateAccessSelectionSelectAccess::IndexRange(
            AlternateAccessSelectionSelectAccessIndexRange {
                low_index: Unsigned32(0),
                number_of_elements: Unsigned32(0),
            },
        )),
    )]);
    let answer = timeout(ANSWER, client.request(read_with(empty)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        results(answer),
        [AccessResult::Failure(DataAccessError::OBJECT_VALUE_INVALID)]
    );
    assert!(paths.lock().unwrap().is_empty());
}
