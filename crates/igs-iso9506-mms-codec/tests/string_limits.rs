// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The IEC 61850 union of the MMS types (task N1 of igs-iec61850-mms, D-032): the strings it widens
//! are checked per profile apart from the codec, and the new service error `pdu-size` encodes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use igs_iso9506_mms_codec::generated::types::*;
use igs_iso9506_mms_codec::mms::{self, check_strings, CbbError, StringLimits, Walked};

fn id(text: &str) -> Identifier {
    Identifier::new(text.into()).unwrap()
}

/// A GetNameList answer with these identifiers.
fn names(list: &[&str]) -> MMSpdu {
    MMSpdu::ConfirmedResponsePDU(ConfirmedResponsePDU {
        invoke_id: Unsigned32(1),
        service: ConfirmedServiceResponse::GetNameList(GetNameListResponse {
            list_of_identifier: list.iter().map(|t| id(t)).collect(),
            more_follows: Some(false),
        }),
        service_ext: None,
    })
}

/// An information report naming a list and carrying these data.
fn report(data: Vec<Data>) -> MMSpdu {
    MMSpdu::UnconfirmedPDU(UnconfirmedPDU {
        service: UnconfirmedService::InformationReport(InformationReport {
            variable_access_specification: VariableAccessSpecification::VariableListName(
                ObjectName::DomainSpecific(ObjectNameDomainSpecific {
                    domain_id: id("LD0"),
                    item_id: id("LLN0$DataSet"),
                }),
            ),
            list_of_access_result: data.into_iter().map(AccessResult::Success).collect(),
        }),
        service_ext: None,
    })
}

#[test]
fn identifiers_are_narrowed_by_the_profile() {
    // An identifier of 39 characters, as an IEC 61850 server lists for a report control block
    // attribute (bench of igs-iec61850-mms, task F4).
    let long = "LLN0$BR$EventsBRCBPreConf01$TimeofEntry";
    assert_eq!(long.len(), 39);
    let pdu = names(&["LLN0$ST$Mod$stVal", long]);
    let bytes = mms::encode(&pdu).unwrap();
    assert_eq!(mms::decode(&bytes).unwrap(), pdu);
    assert_eq!(
        check_strings(&pdu, &StringLimits::ISO_9506),
        Err(CbbError::IdentifierLength {
            length: 39,
            limit: 32
        })
    );
    assert_eq!(check_strings(&pdu, &StringLimits::IEC_61850), Ok(()));
    assert_eq!(StringLimits::default(), StringLimits::ISO_9506);
    let limit = names(&[&"x".repeat(32)]);
    assert_eq!(check_strings(&limit, &StringLimits::ISO_9506), Ok(()));
}

#[test]
fn identifiers_in_nested_values_are_reached() {
    // Identifiers of the object name of a report, in encoding order.
    let pdu = report(vec![]);
    let mut seen = Vec::new();
    pdu.walk_strings(&mut |w| {
        seen.push(format!("{w:?}"));
        Ok::<(), ()>(())
    })
    .unwrap();
    assert_eq!(
        seen,
        [r#"Identifier("LD0")"#, r#"Identifier("LLN0$DataSet")"#]
    );
    let _: Walked<'_> = Walked::Identifier("x");
}

#[test]
fn the_mms_string_of_data_follows_the_profile() {
    let nested = |text: &str| {
        report(vec![Data::Structure(vec![
            Data::Boolean(true),
            Data::Array(vec![Data::MMSString(DataMMSString(text.into()))]),
        ])])
    };
    let ascii = nested("on");
    assert_eq!(check_strings(&ascii, &StringLimits::ISO_9506), Ok(()));
    assert_eq!(check_strings(&ascii, &StringLimits::IEC_61850), Ok(()));

    let unicode = nested("Poste é€");
    assert_eq!(
        check_strings(&unicode, &StringLimits::ISO_9506),
        Err(CbbError::DataString {
            reason: "not a VisibleString"
        })
    );
    assert_eq!(check_strings(&unicode, &StringLimits::IEC_61850), Ok(()));

    // 255 characters of up to 4 octets each are allowed; 256 are not (Annex F.3.3).
    let full = nested(&"𝄞".repeat(255));
    assert_eq!(check_strings(&full, &StringLimits::IEC_61850), Ok(()));
    let over = nested(&"a".repeat(256));
    assert!(matches!(
        check_strings(&over, &StringLimits::IEC_61850),
        Err(CbbError::DataString { .. })
    ));
    // The codec itself takes any length: the profile decides (D-032).
    let bytes = mms::encode(&over).unwrap();
    assert_eq!(mms::decode(&bytes).unwrap(), over);
}

#[test]
fn utc_time_values_pass_every_profile() {
    let pdu = report(vec![Data::UtcTime(UtcTime(vec![0; 8]))]);
    assert_eq!(check_strings(&pdu, &StringLimits::ISO_9506), Ok(()));
    let bytes = mms::encode(&pdu).unwrap();
    assert_eq!(mms::decode(&bytes).unwrap(), pdu);
}

#[test]
fn pdu_size_is_a_service_error() {
    // IEC 61850-8-1 Annex F.3.4: value 3 of the service error class.
    assert_eq!(
        ServiceErrorErrorClassService::PDU_SIZE,
        ServiceErrorErrorClassService(3)
    );
}
