// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! A client of an MMS server over TCP: identifies the server and lists its domains.
//!
//! Run it with `cargo run --example client -- 127.0.0.1:10102`, the address of a server (default
//! `127.0.0.1:102`, the RFC 1006 port).

use std::error::Error;
use std::time::Duration;

use igs_iso9506_mms::client::in_scope_capabilities;
use igs_iso9506_mms::{Client, ClientConfig, Reconnect};
use igs_iso9506_mms_codec::generated::types::{
    GetNameListRequest, GetNameListRequestObjectScope, ObjectClass, ObjectClassBasicObjectClass,
};
use igs_iso9506_mms_link::config::LinkConfig;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:102".to_string());
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
    println!("vendor: {}", identity.vendor_name.0);
    println!("model: {}", identity.model_name.0);
    println!("revision: {}", identity.revision.0);

    let domains = client
        .get_name_list(GetNameListRequest {
            object_class: ObjectClass::BasicObjectClass(ObjectClassBasicObjectClass::DOMAIN),
            object_scope: GetNameListRequestObjectScope::VmdSpecific,
            continue_after: None,
        })
        .await?;
    for domain in &domains.list_of_identifier {
        println!("domain: {}", domain.0);
    }
    client.close().await?;
    Ok(())
}
