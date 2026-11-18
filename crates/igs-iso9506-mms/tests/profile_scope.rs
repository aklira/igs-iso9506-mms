// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The services that a client or a server advertises follow its profile: the ISO 9506 profile of TASE.2 does not claim the log and
//! file services, which the IEC 61850 profile declares. A regression here would advertise services that TASE.2 does not declare.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use igs_iso9506_mms::client::{in_scope_capabilities, in_scope_capabilities_iec61850};
use igs_iso9506_mms::server::ServerConfig;
use igs_iso9506_mms_codec::generated::tables::SERVICES;
use igs_iso9506_mms_link::config::LinkConfig;

fn advertised(services: &igs_iso9506_mms_codec::schema::BitString, name: &str) -> bool {
    let service = SERVICES
        .iter()
        .find(|s| s.name == name)
        .expect("the service is in the table");
    services.bit(usize::try_from(service.bit.position).expect("a bit position"))
}

#[test]
fn the_tase2_profile_does_not_claim_the_log_or_file_services() {
    let tase2 = in_scope_capabilities();
    assert!(advertised(&tase2.services, "read"));
    assert!(advertised(&tase2.services, "informationReport"));
    for name in [
        "readJournal",
        "fileOpen",
        "fileRead",
        "fileClose",
        "fileDelete",
        "fileDirectory",
    ] {
        assert!(
            !advertised(&tase2.services, name),
            "{name} is not in the TASE.2 profile"
        );
    }
}

#[test]
fn the_iec61850_profile_claims_the_log_and_file_services() {
    let iec = in_scope_capabilities_iec61850();
    for name in [
        "read",
        "informationReport",
        "readJournal",
        "fileOpen",
        "fileRead",
        "fileClose",
        "fileDelete",
        "fileDirectory",
    ] {
        assert!(
            advertised(&iec.services, name),
            "{name} is in the IEC 61850 profile"
        );
    }
}

#[test]
fn a_server_advertises_the_tase2_set_unless_it_takes_the_iec61850_set() {
    let default = ServerConfig::new(LinkConfig::default());
    assert_eq!(
        default.capabilities.services,
        in_scope_capabilities().services
    );
    let iec = ServerConfig::new(LinkConfig::default()).with_iec61850_services();
    assert_eq!(
        iec.capabilities.services,
        in_scope_capabilities_iec61850().services
    );
}
