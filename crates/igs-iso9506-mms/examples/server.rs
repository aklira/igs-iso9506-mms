// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! A server of one VMD over TCP: a domain with a temperature, served until the process is stopped.
//!
//! Run it with `cargo run --example server -- 127.0.0.1:10102` (default `127.0.0.1:102`), then the client
//! example with the same address.

use std::error::Error;

use igs_iso9506_mms::vmd::{Identity, MemoryVariable, Name, Target, Vmd};
use igs_iso9506_mms::{Server, ServerConfig};
use igs_iso9506_mms_codec::generated::types::{
    Data, FloatingPoint, TypeDescription, TypeDescriptionFloatingPoint, Unsigned8,
};
use igs_iso9506_mms_link::config::LinkConfig;

fn model() -> Result<Vmd, Box<dyn Error>> {
    let mut vmd = Vmd::new(Identity {
        vendor: "igs".to_string(),
        model: "example server".to_string(),
        revision: env!("CARGO_PKG_VERSION").to_string(),
    });
    vmd.add_domain(Name::new("plant")?)
        .map_err(|error| format!("the domain: {error:?}"))?;
    // A single precision value: exponent width 8, then the four octets of the IEEE value (21.5).
    let temperature = MemoryVariable::new(
        TypeDescription::FloatingPoint(TypeDescriptionFloatingPoint {
            format_width: Unsigned8(32),
            exponent_width: Unsigned8(8),
        }),
        Data::FloatingPoint(FloatingPoint(vec![8, 0x41, 0xAC, 0, 0])),
        false,
    )
    .map_err(|error| format!("the variable: {error:?}"))?;
    vmd.add_variable(
        &Target::in_domain(Name::new("plant")?, Name::new("temperature")?),
        Box::new(temperature),
    )
    .map_err(|error| format!("the variable: {error:?}"))?;
    Ok(vmd)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:102".to_string());
    let server = Server::bind(&address, ServerConfig::new(LinkConfig::default()), model()?).await?;
    println!("serving on {}; stop with Ctrl-C", server.local_address());
    std::future::pending::<()>().await;
    server.shutdown().await;
    Ok(())
}
