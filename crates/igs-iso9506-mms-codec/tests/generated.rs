// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The generated tables and types against the counts of tasks P3 and P4 (task F4).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use igs_iso9506_mms_codec::generated::tables::{
    ADDITIONAL_CBB_OPTIONS, ADDITIONAL_SUPPORT_OPTIONS, ENVIRONMENT_BITS, ERROR_CLASSES, MODIFIERS,
    PARAMETERS, PARAMETER_SUPPORT_OPTIONS, PDUS, PDU_REQUIREMENTS, REJECT_REASONS, SERVICES,
    SERVICE_SUPPORT_OPTIONS,
};
use igs_iso9506_mms_codec::generated::types::{
    AARQApdu, ConfirmedRequestPDU, ConfirmedServiceRequest, Data, TimeOfDay, Unsigned32, TYPE_COUNT,
};
use igs_iso9506_mms_codec::schema::{Family, Presence, Service, SupportOption, TagClass, Tagging};

fn service(name: &str) -> &'static Service {
    SERVICES.iter().find(|s| s.name == name).unwrap()
}

#[test]
fn service_counts() {
    let count = |f| SERVICES.iter().filter(|s| s.family == f).count();
    assert_eq!(count(Family::Confirmed), 85);
    assert_eq!(count(Family::Additional), 23);
    assert_eq!(count(Family::Unconfirmed), 3);
    assert_eq!(PDUS.len(), 14);
    assert_eq!(MODIFIERS.len(), 2);
    assert_eq!(ENVIRONMENT_BITS.len(), 2);
}

#[test]
fn cbb_counts() {
    assert_eq!(SERVICE_SUPPORT_OPTIONS.len(), 93);
    assert_eq!(ADDITIONAL_SUPPORT_OPTIONS.len(), 23);
    assert_eq!(PARAMETER_SUPPORT_OPTIONS.len(), 16);
    assert_eq!(ADDITIONAL_CBB_OPTIONS.len(), 3);
    assert_eq!(PARAMETERS.len(), 19);
}

/// Every service bit belongs to a service, a modifier or an environment service, except the one
/// whose service has no tag (decision of task P3).
#[test]
fn service_bits_are_accounted_for() {
    let carried = SERVICES.len() + MODIFIERS.len() + ENVIRONMENT_BITS.len();
    let bits = SERVICE_SUPPORT_OPTIONS.len() + ADDITIONAL_SUPPORT_OPTIONS.len();
    assert_eq!(bits, carried + 1);
}

#[test]
fn error_and_reject_tables() {
    assert_eq!(ERROR_CLASSES.len(), 13);
    assert_eq!(REJECT_REASONS.len(), 11);
    let total: usize = ERROR_CLASSES.iter().map(|c| c.codes.len()).sum();
    assert_eq!(total, 60);
}

#[test]
fn scope_of_the_profile() {
    let in_scope: Vec<&str> = SERVICES
        .iter()
        .filter(|s| s.in_scope)
        .map(|s| s.name)
        .collect();
    assert_eq!(in_scope.len(), 9);
    assert!(in_scope.contains(&"read"));
    assert!(in_scope.contains(&"informationReport"));
    assert_eq!(PDU_REQUIREMENTS.len(), 10);
    assert_eq!(PDU_REQUIREMENTS.iter().filter(|p| p.in_scope).count(), 7);
    assert_eq!(service("getNameList").client, "o");
    assert_eq!(service("getNameList").server, "m");
}

/// Tag and bit agree at first, then diverge.
#[test]
fn tag_and_bit_are_distinct() {
    let read = service("read");
    assert_eq!((read.tag, read.bit.position), (4, 4));
    let exchange = service("getDataExchangeAttributes");
    assert_eq!((exchange.tag, exchange.bit.position), (80, 85));
    assert_eq!(service("changeAccessControl").cbb, "alterAccessControl");
    assert_eq!(service("createUC").cbb, "createUnitControl");
    assert_eq!(
        service("createUC").bit.option,
        SupportOption::AdditionalService
    );
}

#[test]
fn requirements_keep_their_groups() {
    assert_eq!(
        service("getVariableAccessAttributes").requires,
        &[&["vnam", "vadr"][..]]
    );
    assert_eq!(
        service("defineNamedVariableList").requires,
        &[&["vlis"][..], &["vnam"][..]]
    );
}

/// The service CHOICE keeps the services in scope, and the others decode to `Unsupported`.
#[test]
fn service_choice_is_limited_to_the_scope() {
    assert_eq!(ConfirmedServiceRequest::ALTERNATIVES.len(), 8);
    let tags: Vec<u32> = ConfirmedServiceRequest::ALTERNATIVES
        .iter()
        .map(|m| m.tag.unwrap().number)
        .collect();
    assert_eq!(tags, [1, 2, 4, 5, 6, 11, 12, 13]);
}

#[test]
fn tags_follow_the_tagging_rules() {
    let tag = |name: &str| {
        ConfirmedServiceRequest::ALTERNATIVES
            .iter()
            .find(|m| m.name == name)
            .unwrap()
            .tag
            .unwrap()
    };
    assert_eq!(tag("read").tagging, Tagging::Implicit);
    // No keyword, and the module defaults to explicit tags.
    assert_eq!(
        tag("getVariableAccessAttributes").tagging,
        Tagging::Explicit
    );
    let aarq = AARQApdu::TAG;
    assert_eq!((aarq.class, aarq.number), (TagClass::Application, 0));
    assert_eq!(aarq.tagging, Tagging::Implicit);
}

/// An extension marker does not stop the reading of a CHOICE or a SEQUENCE.
#[test]
fn components_after_extension_markers_are_kept() {
    assert_eq!(Data::ALTERNATIVES.last().unwrap().tag.unwrap().number, 16);
    let last = AARQApdu::COMPONENTS.last().unwrap();
    assert_eq!(last.tag.unwrap().number, 30);
    assert_eq!(last.presence, Presence::Optional);
    let service_ext = ConfirmedRequestPDU::COMPONENTS.last().unwrap();
    assert_eq!(service_ext.tag.unwrap().number, 79);
    assert_eq!(service_ext.tag.unwrap().tagging, Tagging::Explicit);
}

#[test]
fn constraints_are_kept() {
    assert_eq!(TimeOfDay::SIZES, &[(4, 4), (6, 6)]);
    assert_eq!(Unsigned32::VALUES, &[(0, 2_147_483_647)]);
}

#[test]
fn type_count_is_stable() {
    assert_eq!(TYPE_COUNT, 143);
}
