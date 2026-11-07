// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! A server and a client in one process, over TCP on the loopback: the quick start of the library.
//!
//! Run it with `cargo run --example loopback`. It needs no network and no certificate.

use std::error::Error;
use std::time::Duration;

use igs_iso9506_mms::client::in_scope_capabilities;
use igs_iso9506_mms::vmd::{Identity, MemoryVariable, Name, Target, Vmd};
use igs_iso9506_mms::{Client, ClientConfig, Reconnect, Server, ServerConfig};
use igs_iso9506_mms_codec::generated::types::{
    AccessResult, Data, Identifier, ObjectName, ReadRequest, TypeDescription, Unsigned8,
    VariableAccessSpecification, VariableAccessSpecificationListOfVariableItem,
    VariableSpecification, WriteRequest, WriteResponseItemItem,
};
use igs_iso9506_mms_link::config::LinkConfig;

/// A VMD with one writable integer variable, `speed`.
fn model() -> Result<Vmd, Box<dyn Error>> {
    let mut vmd = Vmd::new(Identity {
        vendor: "igs".to_string(),
        model: "loopback".to_string(),
        revision: "1.0".to_string(),
    });
    let speed = MemoryVariable::new(
        TypeDescription::Integer(Unsigned8(32)),
        Data::Integer(5),
        true,
    )
    .map_err(|error| format!("the variable: {error:?}"))?;
    vmd.add_variable(&Target::vmd(Name::new("speed")?), Box::new(speed))
        .map_err(|error| format!("the variable: {error:?}"))?;
    Ok(vmd)
}

/// The access to one variable of the VMD, by its name.
fn one(name: &str) -> Result<VariableAccessSpecification, Box<dyn Error>> {
    Ok(VariableAccessSpecification::ListOfVariable(vec![
        VariableAccessSpecificationListOfVariableItem {
            variable_specification: VariableSpecification::Name(ObjectName::VmdSpecific(
                Identifier(name.to_string()),
            )),
            alternate_access: None,
        },
    ]))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    // The server, on a free port of the loopback.
    let server = Server::bind(
        "127.0.0.1:0",
        ServerConfig::new(LinkConfig::default()),
        model()?,
    )
    .await?;
    let address = server.local_address().to_string();
    println!("server listening on {address}");

    // The client: one association, with the services in scope.
    let config = ClientConfig {
        reconnect: Reconnect::Never,
        ..ClientConfig::new(
            LinkConfig {
                request_timeout: Duration::from_secs(10),
                ..LinkConfig::default()
            },
            in_scope_capabilities(),
        )
    };
    let (client, _events) = Client::connect(&address, config).await?;

    let identity = client.identify().await?;
    println!(
        "identity: {} {} {}",
        identity.vendor_name.0, identity.model_name.0, identity.revision.0
    );

    let read = client.read(ReadRequest {
        specification_with_result: None,
        variable_access_specification: one("speed")?,
    });
    if let Some(AccessResult::Success(value)) = read.await?.list_of_access_result.first() {
        println!("speed: {value:?}");
    }

    let written = client
        .write(WriteRequest {
            variable_access_specification: one("speed")?,
            list_of_data: vec![Data::Integer(7)],
        })
        .await?;
    println!("write: {:?}", written.0);
    assert_eq!(written.0, vec![WriteResponseItemItem::Success]);

    client.close().await?;
    server.shutdown().await;
    println!("done");
    Ok(())
}
