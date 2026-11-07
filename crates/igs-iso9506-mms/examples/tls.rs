// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! A secured server and a secured client in one process, over TLS on the loopback (IEC 62351-3, clause 6.4.3:
//! each side presents its certificate).
//!
//! Run it with the PEM files of the two endpoints and the trust anchors:
//!
//! ```text
//! cargo run --example tls -- <root.pem> <crl.pem> <server.pem> <server.key> <client.pem> <client.key>
//! ```
//!
//! The test material of the repository is in `crates/igs-iso9506-mms/tests/fixtures/tls`; the server
//! certificate names `localhost` and `127.0.0.1`.

use std::error::Error;
use std::time::Duration;

use igs_iso9506_mms::client::in_scope_capabilities;
use igs_iso9506_mms::tls::{
    revocation_from_pem, Identity as TlsIdentity, RustlsBackend, Secure, SecureConnector,
    TlsSettings, TrustAnchors,
};
use igs_iso9506_mms::vmd::{Identity, Vmd};
use igs_iso9506_mms::{Client, ClientConfig, Reconnect, Server, ServerConfig};
use igs_iso9506_mms_link::config::LinkConfig;

fn station(
    root: &[u8],
    crl: &[u8],
    certificate: &[u8],
    key: &[u8],
) -> Result<Secure, Box<dyn Error>> {
    let identity = TlsIdentity::from_pem(certificate, key)?;
    let settings = TlsSettings::new(Some(identity), TrustAnchors::from_pem(root)?)
        .with_revocation(revocation_from_pem(crl)?);
    Ok(Secure::new(RustlsBackend::new(&settings)?))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.len() != 6 {
        return Err(
            "usage: tls <root.pem> <crl.pem> <server.pem> <server.key> <client.pem> <client.key>"
                .into(),
        );
    }
    let [root, crl, server_certificate, server_key, client_certificate, client_key] = paths
        .iter()
        .map(std::fs::read)
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| "six files are needed")?;
    let server_station = station(&root, &crl, &server_certificate, &server_key)?;
    let client_station = station(&root, &crl, &client_certificate, &client_key)?;

    let vmd = Vmd::new(Identity {
        vendor: "igs".to_string(),
        model: "tls example".to_string(),
        revision: "1.0".to_string(),
    });
    let config = ServerConfig::new(LinkConfig::default()).with_tls(server_station);
    let server = Server::bind("127.0.0.1:0", config, vmd).await?;

    // The server's certificate names localhost; the client checks it against that name.
    let connector = SecureConnector::new(
        server.local_address().to_string(),
        "localhost",
        client_station,
        Duration::from_secs(10),
    );
    let client_config = ClientConfig {
        reconnect: Reconnect::Never,
        ..ClientConfig::new(LinkConfig::default(), in_scope_capabilities())
    };
    let (client, _events) = Client::connect_with(connector, client_config).await?;
    let identity = client.identify().await?;
    println!(
        "secured identity: {} {}",
        identity.vendor_name.0, identity.model_name.0
    );
    client.close().await?;
    server.shutdown().await;
    Ok(())
}
