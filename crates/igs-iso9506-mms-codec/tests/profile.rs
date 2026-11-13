// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Application profiles (task N2 of igs-iec61850-mms, D-033): the rules of IEC 61850-8-1 clause 24
//! for each declared ACSI model, the nesting minimum, and the limits on the strings.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use igs_iso9506_mms_codec::generated::tables::{
    PARAMETER_SUPPORT_OPTIONS, SERVICE_SUPPORT_OPTIONS,
};
use igs_iso9506_mms_codec::mms::profile::{Model, Profile, ProfileError, Side};
use igs_iso9506_mms_codec::mms::StringLimits;
use igs_iso9506_mms_codec::schema::{BitString, NamedBit};

/// A negotiation bit string with the named bits of one table set: the parameter CBBs and the services
/// are negotiated apart, and their bit positions overlap.
fn named(table: &[NamedBit], names: &[&str]) -> BitString {
    let mut bytes = vec![0u8; 12];
    for name in names {
        let position = table
            .iter()
            .find(|named| named.name == *name)
            .map(|named| named.position as usize)
            .unwrap_or_else(|| panic!("no bit named {name}"));
        if let Some(byte) = bytes.get_mut(position / 8) {
            *byte |= 0x80 >> (position % 8);
        }
    }
    BitString { unused: 0, bytes }
}

fn parameters(names: &[&str]) -> BitString {
    named(PARAMETER_SUPPORT_OPTIONS, names)
}

fn services(names: &[&str]) -> BitString {
    named(SERVICE_SUPPORT_OPTIONS, names)
}

fn sorted(mut names: Vec<&'static str>) -> Vec<&'static str> {
    names.sort_unstable();
    names
}

#[test]
fn tase2_adds_no_rule_and_keeps_the_iso_limits() {
    let profile = Profile::TASE2;
    assert_eq!(profile.string_limits, StringLimits::ISO_9506);
    assert!(profile.required_parameters(Side::Server).is_empty());
    assert!(profile.required_services(Side::Client).is_empty());
    assert_eq!(
        profile.check_parameters(Side::Server, &parameters(&[])),
        Ok(())
    );
    assert_eq!(profile.check_services(Side::Client, &services(&[])), Ok(()));
    // The nesting level of TASE.2 is two (IEC 60870-6-702 §5).
    assert_eq!(profile.min_nesting, 2);
    assert!(profile.check_nesting(2).is_ok());
    assert!(profile.check_nesting(1).is_err());
}

#[test]
fn the_logical_node_model_requires_its_cbbs_and_services() {
    let profile = Profile::iec61850(Model {
        logical_nodes: true,
        ..Model::default()
    });
    assert_eq!(profile.string_limits, StringLimits::IEC_61850);
    // Tables 124 and 125, c2: six or more when the logical-node model is declared.
    assert_eq!(profile.min_nesting, 6);
    // Table 128: vnam of the client (c1), str2 and vnam of the server (c1).
    assert_eq!(sorted(profile.required_parameters(Side::Client)), ["vnam"]);
    assert_eq!(
        sorted(profile.required_parameters(Side::Server)),
        ["str2", "vnam"]
    );
    // Table 127: identify is mandatory of the server; getNameList, read and
    // getVariableAccessAttributes follow the logical-node model (c1, c2).
    assert_eq!(
        sorted(profile.required_services(Side::Server)),
        [
            "getNameList",
            "getVariableAccessAttributes",
            "identify",
            "read"
        ]
    );
    assert!(profile.required_services(Side::Client).is_empty());
}

#[test]
fn every_declared_feature_adds_its_cbbs() {
    let profile = Profile::iec61850(Model {
        logical_nodes: true,
        data_sets: true,
        arrays: true,
        logs: false,
    });
    // str1 and valt follow the data sets (client) and the arrays (server); vlis follows the data sets
    // of the server (Table 128, c2 and c3).
    assert_eq!(
        sorted(profile.required_parameters(Side::Client)),
        ["str1", "valt", "vnam"]
    );
    assert_eq!(
        sorted(profile.required_parameters(Side::Server)),
        ["str1", "str2", "valt", "vlis", "vnam"]
    );
    assert!(profile
        .required_services(Side::Server)
        .contains(&"getNamedVariableListAttributes"));
}

#[test]
fn a_model_without_logical_nodes_keeps_the_nesting_of_two() {
    let profile = Profile::iec61850(Model {
        data_sets: true,
        ..Model::default()
    });
    assert_eq!(profile.min_nesting, 2);
    assert_eq!(sorted(profile.required_parameters(Side::Server)), ["vlis"]);
}

#[test]
fn a_missing_cbb_or_service_is_named() {
    let profile = Profile::iec61850(Model {
        logical_nodes: true,
        ..Model::default()
    });
    // Without str2 the server cannot serve the logical nodes.
    let without_str2 = parameters(&["str1", "vnam"]);
    assert_eq!(
        profile.check_parameters(Side::Server, &without_str2),
        Err(ProfileError::ParameterNotNegotiated {
            side: Side::Server,
            cbb: "str2"
        })
    );
    let with_cbbs = parameters(&["str2", "vnam"]);
    assert_eq!(profile.check_parameters(Side::Server, &with_cbbs), Ok(()));
    // Without getNameList, the server does not meet Table 127.
    let without_getnamelist = services(&["identify", "read", "getVariableAccessAttributes"]);
    assert_eq!(
        profile.check_services(Side::Server, &without_getnamelist),
        Err(ProfileError::ServiceNotSupported {
            side: Side::Server,
            service: "getNameList"
        })
    );
    // The client declares nothing beyond vnam.
    assert_eq!(
        profile.check_parameters(Side::Client, &parameters(&["vnam"])),
        Ok(())
    );
}

#[test]
fn a_nesting_below_six_is_refused_with_the_model() {
    let profile = Profile::iec61850(Model {
        logical_nodes: true,
        ..Model::default()
    });
    assert_eq!(
        profile.check_nesting(5),
        Err(ProfileError::NestingBelowProfile {
            level: 5,
            required: 6
        })
    );
    assert!(profile.check_nesting(6).is_ok());
}

#[test]
fn identifiers_of_the_iec_profile_are_up_to_sixty_four_characters() {
    // AT-02: the longest identifier is accepted, one character more is refused by the type.
    use igs_iso9506_mms_codec::mms::Identifier;
    assert!(Identifier::new("x".repeat(64)).is_ok());
    assert!(Identifier::new("x".repeat(65)).is_err());
    assert_eq!(
        Profile::iec61850(Model::default())
            .string_limits
            .max_identifier,
        64
    );
    assert_eq!(Profile::TASE2.string_limits.max_identifier, 32);
}
