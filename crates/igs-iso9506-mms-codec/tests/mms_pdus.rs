// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! MMS PDUs (ISO 9506-2 §7, §8, §10, §14), task C7: a vector per service in scope, observed on
//! the bench, and a test per refusal of `validate_cbb`. Hand-written lengths come from [`tlv`].

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use igs_iso9506_mms_codec::asn::Error;
use igs_iso9506_mms_codec::generated::tables::{
    PARAMETER_SUPPORT_OPTIONS, SERVICE_SUPPORT_OPTIONS,
};
use igs_iso9506_mms_codec::generated::types::*;
use igs_iso9506_mms_codec::mms::{self, validate_cbb, CbbError, Negotiated};
use igs_iso9506_mms_codec::schema::{BitString, RawBer};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// One encoding with a one-octet identifier and a computed length.
fn tlv(id: u8, parts: &[&[u8]]) -> Vec<u8> {
    let contents = parts.concat();
    let n = contents.len();
    let mut out = vec![id];
    if n < 0x80 {
        out.push(n as u8);
    } else {
        out.extend([0x81, n as u8]);
    }
    out.extend(contents);
    out
}

/// PDUs observed on the bench between the libiec61850 reference client and server (task C7).
const IDENTIFY_REQ: &str = "a0050201018200";
const IDENTIFY_RSP: &str = "a11a020101a21580024d5a8108626173696320696f8205312e362e30";
const GET_NAME_LIST_REQ: &str = "a00e020101a109a003800109a1028000";
const GET_NAME_LIST_RSP: &str = "a11d020101a118a0131a1173696d706c65494f47656e65726963494f810100";
const READ_REQ: &str = "a02e020103a429800101a124a122a1201a1173696d706c65494f47656e65726963494f1a0b4c4c4e30244576656e7473";
const READ_RSP: &str = "a139020102a434a024a122a1201a1173696d706c65494f47656e65726963494f1a0b4c4c4e30244576656e7473a10c830100830100830100830100";
const WRITE_REQ: &str = "a03d020106a538a031302fa02da12b1a1173696d706c65494f47656e65726963494f1a164c4c4e30245250244576656e74735243423031244749a003830101";
const WRITE_RSP: &str = "a10702010aa5028100";
const GET_VAA_REQ: &str = "a02d020102a628a026a1241a1173696d706c65494f47656e65726963494f1a0f4747494f3124434f24535043534f31";
const GET_VAA_RSP: &str = "a1818c020109a68186800100a28180a27ea17c307a80044f706572a172a270a16e300c800663746c56616ca1028300302c80066f726967696ea122a220a11e300c80056f72436174a103850108300e80076f724964656e74a1038901c0300d800663746c4e756da1038601083007800154a1029100300a800454657374a1028300300c8005436865636ba1038401fe";
const DEFINE_NVL_REQ: &str = "a081d7020101ab81d1a1281a1173696d706c65494f47656e65726963494f1a134c4c4e3024416e616c6f67756556616c756573a081a43027a025a1231a1173696d706c65494f47656e65726963494f1a0e4747494f31244d5824416e496e313027a025a1231a1173696d706c65494f47656e65726963494f1a0e4747494f31244d5824416e496e323027a025a1231a1173696d706c65494f47656e65726963494f1a0e4747494f31244d5824416e496e333027a025a1231a1173696d706c65494f47656e65726963494f1a0e4747494f31244d5824416e496e34";
const DEFINE_NVL_RSP: &str = "a1050201018b00";
const GET_NVLA_REQ: &str =
    "a027020105ac22a1201a1173696d706c65494f47656e65726963494f1a0b4c4c4e30244576656e7473";
const GET_NVLA_RSP: &str = "a181b4020106ac81ae800100a181a83028a026a1241a1173696d706c65494f47656e65726963494f1a0f4747494f3124535424535043534f313028a026a1241a1173696d706c65494f47656e65726963494f1a0f4747494f3124535424535043534f323028a026a1241a1173696d706c65494f47656e65726963494f1a0f4747494f3124535424535043534f333028a026a1241a1173696d706c65494f47656e65726963494f1a0f4747494f3124535424535043534f34";
const DELETE_NVL_REQ: &str = "a034020103ad2f800100a12aa1281a1173696d706c65494f47656e65726963494f1a134c4c4e3024416e616c6f67756556616c756573";
const DELETE_NVL_RSP: &str = "a10b020103ad06800101810101";
const ERROR: &str = "a20a800101a205a003870102";
const INFORMATION_REPORT: &str = "a366a064a1058003525054a05b8a074576656e74733184030678808601068c060268c0fa3d238a1d73696d706c65494f47656e65726963494f2f4c4c4e30244576656e7473860101840204f083010083010083010083010084020208840202088402020884020208";
const INITIATE_REQ: &str =
    "a826800300fde881010582010583010aa416800101810305f100820c03ee1c00000408000079ef18";
const INITIATE_RSP: &str =
    "a926800300fde881010582010583010aa416800101810305f100820c03ee1c000000000000000118";

/// Decodes, re-encodes, and checks the octets: the same, but for a TRUE that the peer writes
/// as 01 and this codec as FF (D-007).
fn observed(text: &str) -> MMSpdu {
    let bytes = hex(text);
    let pdu = mms::decode(&bytes).unwrap();
    let again = mms::encode(&pdu).unwrap();
    assert_eq!(again.len(), bytes.len(), "{text}");
    for (a, b) in bytes.iter().zip(&again) {
        assert!(a == b || (*a == 0x01 && *b == 0xFF), "{text}");
    }
    assert_eq!(mms::decode(&again).unwrap(), pdu);
    pdu
}

fn request(text: &str) -> ConfirmedServiceRequest {
    match observed(text) {
        MMSpdu::ConfirmedRequestPDU(r) => r.service,
        other => panic!("not a request: {other:?}"),
    }
}

fn response(text: &str) -> ConfirmedServiceResponse {
    match observed(text) {
        MMSpdu::ConfirmedResponsePDU(r) => r.service,
        other => panic!("not a response: {other:?}"),
    }
}

fn initiate() -> (InitiateRequestPDU, InitiateResponsePDU) {
    let MMSpdu::InitiateRequestPDU(request) = observed(INITIATE_REQ) else {
        panic!("not an initiate request");
    };
    let MMSpdu::InitiateResponsePDU(response) = observed(INITIATE_RSP) else {
        panic!("not an initiate response");
    };
    (request, response)
}

#[test]
fn observed_initiate() {
    let (request, response) = initiate();
    assert_eq!(request.local_detail_calling, Some(Integer32(65_000)));
    assert_eq!(request.proposed_max_serv_outstanding_calling, Integer16(5));
    assert_eq!(
        request.proposed_data_structure_nesting_level,
        Some(Integer8(10))
    );
    let detail = &request.init_request_detail;
    assert_eq!(detail.proposed_version_number, Integer16(1));
    // A peer of an earlier version: 11 parameter bits and 85 service bits, no extension.
    assert_eq!(
        igs_iso9506_mms_codec::asn::Measure::measure(&detail.proposed_parameter_cbb.0),
        11
    );
    assert_eq!(
        igs_iso9506_mms_codec::asn::Measure::measure(&detail.services_supported_calling.0),
        85
    );
    assert_eq!(detail.additional_supported_calling, None);
    let negotiated = Negotiated::served_by_called(&response);
    assert_eq!(negotiated.nesting_level, Some(10));
    for (cbb, set) in [
        ("str1", true),
        ("str2", true),
        ("vnam", true),
        ("valt", true),
        ("vadr", false),
        ("vlis", true),
    ] {
        let position = PARAMETER_SUPPORT_OPTIONS
            .iter()
            .find(|b| b.name == cbb)
            .unwrap()
            .position;
        assert_eq!(negotiated.parameters.bit(position as usize), set, "{cbb}");
    }
}

#[test]
fn initiate_ignores_undefined_elements() {
    // An undefined [20] in the PDU and in its detail (ISO 9506-2 §8.2).
    let mut bytes = hex(INITIATE_REQ);
    let known = mms::decode(&bytes).unwrap();
    bytes.splice(2..2, [0x94, 0x01, 0x00]);
    bytes[1] += 3;
    assert_eq!(mms::decode(&bytes).unwrap(), known);
    // Outside the Initiate, the same element is refused.
    let mut read = hex(READ_RSP);
    read.splice(5..5, [0x94, 0x01, 0x00]);
    read[1] += 3;
    assert!(mms::decode(&read).is_err());
}

#[test]
fn a_vector_per_service() {
    let ConfirmedServiceRequest::Identify(_) = request(IDENTIFY_REQ) else {
        panic!()
    };
    let ConfirmedServiceResponse::Identify(identity) = response(IDENTIFY_RSP) else {
        panic!()
    };
    assert_eq!(identity.vendor_name, MMSString("MZ".into()));
    assert_eq!(identity.revision, MMSString("1.6.0".into()));

    let ConfirmedServiceRequest::GetNameList(names) = request(GET_NAME_LIST_REQ) else {
        panic!()
    };
    assert_eq!(
        names.object_class,
        ObjectClass::BasicObjectClass(ObjectClassBasicObjectClass::DOMAIN)
    );
    let ConfirmedServiceResponse::GetNameList(names) = response(GET_NAME_LIST_RSP) else {
        panic!()
    };
    assert_eq!(
        names.list_of_identifier,
        [Identifier("simpleIOGenericIO".into())]
    );
    assert_eq!(names.more_follows, Some(false));

    let ConfirmedServiceRequest::Read(read) = request(READ_REQ) else {
        panic!()
    };
    assert_eq!(read.specification_with_result, Some(true));
    assert!(matches!(
        read.variable_access_specification,
        VariableAccessSpecification::VariableListName(_)
    ));
    let ConfirmedServiceResponse::Read(read) = response(READ_RSP) else {
        panic!()
    };
    assert_eq!(
        read.list_of_access_result,
        vec![AccessResult::Success(Data::Boolean(false)); 4]
    );

    let ConfirmedServiceRequest::Write(write) = request(WRITE_REQ) else {
        panic!()
    };
    assert_eq!(write.list_of_data, [Data::Boolean(true)]);
    let ConfirmedServiceResponse::Write(write) = response(WRITE_RSP) else {
        panic!()
    };
    assert_eq!(write.0, [WriteResponseItemItem::Success]);

    let ConfirmedServiceRequest::GetVariableAccessAttributes(
        GetVariableAccessAttributesRequest::Name(_),
    ) = request(GET_VAA_REQ)
    else {
        panic!()
    };
    let ConfirmedServiceResponse::GetVariableAccessAttributes(attributes) = response(GET_VAA_RSP)
    else {
        panic!()
    };
    assert!(matches!(
        attributes.type_description,
        TypeDescription::Structure(_)
    ));

    let ConfirmedServiceRequest::DefineNamedVariableList(define) = request(DEFINE_NVL_REQ) else {
        panic!()
    };
    assert!(!define.list_of_variable.is_empty());
    let ConfirmedServiceResponse::DefineNamedVariableList(_) = response(DEFINE_NVL_RSP) else {
        panic!()
    };

    let ConfirmedServiceRequest::GetNamedVariableListAttributes(_) = request(GET_NVLA_REQ) else {
        panic!()
    };
    let ConfirmedServiceResponse::GetNamedVariableListAttributes(list) = response(GET_NVLA_RSP)
    else {
        panic!()
    };
    assert!(!list.mms_deletable);

    let ConfirmedServiceRequest::DeleteNamedVariableList(_) = request(DELETE_NVL_REQ) else {
        panic!()
    };
    let ConfirmedServiceResponse::DeleteNamedVariableList(deleted) = response(DELETE_NVL_RSP)
    else {
        panic!()
    };
    assert_eq!(
        (deleted.number_matched, deleted.number_deleted),
        (Unsigned32(1), Unsigned32(1))
    );

    let MMSpdu::UnconfirmedPDU(report) = observed(INFORMATION_REPORT) else {
        panic!()
    };
    let UnconfirmedService::InformationReport(report) = report.service else {
        panic!()
    };
    assert!(!report.list_of_access_result.is_empty());

    let MMSpdu::ConfirmedErrorPDU(error) = observed(ERROR) else {
        panic!()
    };
    assert_eq!(
        error.service_error.error_class,
        ServiceErrorErrorClass::Access(ServiceErrorErrorClassAccess(2))
    );
}

/// Every observed PDU passes the check against the observed negotiation.
#[test]
fn observed_pdus_meet_the_negotiation() {
    let (request, response) = initiate();
    let called = Negotiated::served_by_called(&response);
    let calling = Negotiated::served_by_calling(&request, &response);
    for text in [
        IDENTIFY_REQ,
        IDENTIFY_RSP,
        GET_NAME_LIST_REQ,
        GET_NAME_LIST_RSP,
        READ_REQ,
        READ_RSP,
        WRITE_REQ,
        WRITE_RSP,
        GET_VAA_REQ,
        GET_VAA_RSP,
        DEFINE_NVL_REQ,
        DEFINE_NVL_RSP,
        GET_NVLA_REQ,
        GET_NVLA_RSP,
        DELETE_NVL_REQ,
        DELETE_NVL_RSP,
        ERROR,
    ] {
        assert_eq!(validate_cbb(&observed(text), &called), Ok(()), "{text}");
    }
    // The server reports to the client: the client serves InformationReport.
    assert_eq!(
        validate_cbb(&observed(INFORMATION_REPORT), &calling),
        Ok(())
    );
}

#[test]
fn environment_pdus() {
    let cases: Vec<(Vec<u8>, MMSpdu)> = vec![
        (
            vec![0x8B, 0x00],
            MMSpdu::ConcludeRequestPDU(ConcludeRequestPDU(())),
        ),
        (
            vec![0x8C, 0x00],
            MMSpdu::ConcludeResponsePDU(ConcludeResponsePDU(())),
        ),
        (
            vec![0x85, 0x01, 0x07],
            MMSpdu::CancelRequestPDU(CancelRequestPDU(Unsigned32(7))),
        ),
        (
            vec![0x86, 0x01, 0x07],
            MMSpdu::CancelResponsePDU(CancelResponsePDU(Unsigned32(7))),
        ),
        (
            tlv(0xA4, &[&tlv(0x80, &[&[0x07]]), &tlv(0x81, &[&[0x01]])]),
            MMSpdu::RejectPDU(RejectPDU {
                original_invoke_id: Some(Unsigned32(7)),
                reject_reason: RejectPDURejectReason::ConfirmedRequestPDU(
                    RejectPDURejectReasonConfirmedRequestPDU::UNRECOGNIZED_SERVICE,
                ),
            }),
        ),
        (
            tlv(0xA4, &[&tlv(0x85, &[&[0x01]])]),
            MMSpdu::RejectPDU(RejectPDU {
                original_invoke_id: None,
                reject_reason: RejectPDURejectReason::PduError(
                    RejectPDURejectReasonPduError::INVALID_PDU,
                ),
            }),
        ),
    ];
    for (bytes, pdu) in cases {
        assert_eq!(mms::decode(&bytes).unwrap(), pdu);
        assert_eq!(mms::encode(&pdu).unwrap(), bytes);
    }
    // A reject reason beyond the root of its integer is refused: (0..9) has no extension marker.
    assert!(mms::decode(&tlv(0xA4, &[&tlv(0x81, &[&[0x0A]])])).is_err());
    // A conclude error: [13] with a ServiceError of class conclude ([9]),
    // further-communication-required.
    let error = tlv(0xAD, &[&tlv(0xA0, &[&tlv(0x89, &[&[0x01]])])]);
    let MMSpdu::ConcludeErrorPDU(error) = mms::decode(&error).unwrap() else {
        panic!()
    };
    assert_eq!(
        error.0.error_class,
        ServiceErrorErrorClass::Conclude(ServiceErrorErrorClassConclude(1))
    );
}

/// ISO 9506 defines no `[17]` in Data; the bench peer sends one, a UTC time of IEC 61850: the union
/// of the codec reads it typed (IEC 61850-8-1 Annex F.3.1, D-032). A tag past the union is kept.
#[test]
fn data_beyond_the_last_alternative_is_kept() {
    let utc = tlv(0x91, &[&[0x6A, 0xEF, 0x08, 0x32, 0x58, 0x10, 0x62, 0x00]]);
    let data = mms::decode(&tlv(
        0xA1,
        &[
            &tlv(0x02, &[&[0x01]]),
            &tlv(0xA4, &[&tlv(0xA1, &[&tlv(0xA1, &[&utc])])]),
        ],
    ));
    let MMSpdu::ConfirmedResponsePDU(response) = data.unwrap() else {
        panic!()
    };
    let ConfirmedServiceResponse::Read(read) = &response.service else {
        panic!()
    };
    assert_eq!(
        read.list_of_access_result,
        [AccessResult::Success(Data::Array(vec![Data::UtcTime(
            UtcTime(vec![0x6A, 0xEF, 0x08, 0x32, 0x58, 0x10, 0x62, 0x00])
        )]))]
    );
    let beyond = tlv(0x92, &[&[0x01]]);
    assert_eq!(
        igs_iso9506_mms_codec::asn::decode_value::<Data>(&beyond).unwrap(),
        Data::Unsupported {
            tag: 18,
            raw: RawBer(beyond.clone())
        }
    );
    let pdu = MMSpdu::ConfirmedResponsePDU(response);
    assert_eq!(mms::decode(&mms::encode(&pdu).unwrap()).unwrap(), pdu);
    // [0] is AccessResult's, not Data's.
    assert!(matches!(
        igs_iso9506_mms_codec::asn::decode_value::<Data>(&tlv(0x80, &[&[0x01]])),
        Err(Error::Unexpected { .. })
    ));
    // A raw alternative must keep a tag beyond the last one.
    let wrong = Data::Unsupported {
        tag: 5,
        raw: RawBer(vec![0x85, 0x01, 0x00]),
    };
    assert_eq!(
        igs_iso9506_mms_codec::asn::encode_value::<Data>(&wrong),
        Err(Error::InvalidRaw)
    );
}

// The refusals of validate_cbb, one by one.

fn all() -> Negotiated {
    Negotiated {
        parameters: BitString {
            unused: 6,
            bytes: vec![0xFF, 0xFF, 0xC0],
        },
        services: BitString {
            unused: 3,
            bytes: vec![0xFF; 12],
        },
        nesting_level: None,
    }
}

fn without(name: &str) -> Negotiated {
    let mut n = all();
    let clear = |bits: &mut BitString, position: u32| {
        bits.bytes[position as usize / 8] &= !(0x80 >> (position % 8));
    };
    if let Some(b) = PARAMETER_SUPPORT_OPTIONS.iter().find(|b| b.name == name) {
        clear(&mut n.parameters, b.position);
    } else {
        let b = SERVICE_SUPPORT_OPTIONS
            .iter()
            .find(|b| b.name == name)
            .unwrap();
        clear(&mut n.services, b.position);
    }
    n
}

fn id(text: &str) -> Identifier {
    Identifier::new(text.into()).unwrap()
}

fn named(text: &str) -> VariableSpecification {
    VariableSpecification::Name(ObjectName::VmdSpecific(id(text)))
}

fn confirmed(service: ConfirmedServiceRequest) -> MMSpdu {
    MMSpdu::ConfirmedRequestPDU(ConfirmedRequestPDU {
        invoke_id: Unsigned32(1),
        list_of_modifiers: None,
        service,
        service_ext: None,
    })
}

fn answered(service: ConfirmedServiceResponse) -> MMSpdu {
    MMSpdu::ConfirmedResponsePDU(ConfirmedResponsePDU {
        invoke_id: Unsigned32(1),
        service,
        service_ext: None,
    })
}

fn read_of(item: VariableAccessSpecificationListOfVariableItem) -> MMSpdu {
    confirmed(ConfirmedServiceRequest::Read(ReadRequest {
        specification_with_result: None,
        variable_access_specification: VariableAccessSpecification::ListOfVariable(vec![item]),
    }))
}

fn write_of(data: Data) -> MMSpdu {
    confirmed(ConfirmedServiceRequest::Write(WriteRequest {
        variable_access_specification: VariableAccessSpecification::ListOfVariable(vec![
            VariableAccessSpecificationListOfVariableItem {
                variable_specification: named("v"),
                alternate_access: None,
            },
        ]),
        list_of_data: vec![data],
    }))
}

/// Allowed with everything negotiated, refused without `cbb` with `error`; and it encodes.
fn refused(pdu: &MMSpdu, cbb: &str, error: CbbError) {
    assert_eq!(validate_cbb(pdu, &all()), Ok(()), "{pdu:?}");
    assert_eq!(validate_cbb(pdu, &without(cbb)), Err(error), "{cbb}");
    let bytes = mms::encode(pdu).unwrap();
    assert_eq!(&mms::decode(&bytes).unwrap(), pdu);
}

fn not_negotiated(cbb: &'static str) -> CbbError {
    CbbError::NotNegotiated { cbb }
}

#[test]
fn services_and_modifiers() {
    let identify = confirmed(ConfirmedServiceRequest::Identify(IdentifyRequest(())));
    refused(
        &identify,
        "identify",
        CbbError::NotSupported { name: "identify" },
    );
    let answer = answered(ConfirmedServiceResponse::Write(WriteResponse(vec![
        WriteResponseItemItem::Success,
    ])));
    refused(&answer, "write", CbbError::NotSupported { name: "write" });
    let report = MMSpdu::UnconfirmedPDU(UnconfirmedPDU {
        service: UnconfirmedService::InformationReport(InformationReport {
            variable_access_specification: VariableAccessSpecification::VariableListName(
                ObjectName::VmdSpecific(id("list")),
            ),
            list_of_access_result: vec![],
        }),
        service_ext: None,
    });
    refused(
        &report,
        "informationReport",
        CbbError::NotSupported {
            name: "informationReport",
        },
    );
    refused(
        &MMSpdu::ConcludeRequestPDU(ConcludeRequestPDU(())),
        "conclude",
        CbbError::NotSupported { name: "conclude" },
    );
    refused(
        &MMSpdu::CancelRequestPDU(CancelRequestPDU(Unsigned32(1))),
        "cancel",
        CbbError::NotSupported { name: "cancel" },
    );
    // defineNamedVariableList needs vlis and vnam (the IF directives around it).
    let define = confirmed(ConfirmedServiceRequest::DefineNamedVariableList(
        DefineNamedVariableListRequest {
            variable_list_name: ObjectName::VmdSpecific(id("list")),
            list_of_variable: vec![DefineNamedVariableListRequestListOfVariableItem {
                variable_specification: VariableSpecification::Invalidated,
                alternate_access: None,
            }],
        },
    ));
    refused(&define, "vlis", not_negotiated("vlis"));
    refused(&define, "vnam", not_negotiated("vnam"));
    // A service with no tables entry.
    let unknown = confirmed(ConfirmedServiceRequest::Unsupported {
        tag: 200,
        raw: RawBer(vec![0x9F, 0x81, 0x48, 0x00]),
    });
    assert_eq!(
        validate_cbb(&unknown, &all()),
        Err(CbbError::UnknownService { tag: 200 })
    );
    // A modifier: [0] attaches to an event condition.
    let MMSpdu::ConfirmedRequestPDU(mut modified) = identify.clone() else {
        panic!()
    };
    modified.list_of_modifiers = Some(vec![RawBer(vec![0xA0, 0x00])]);
    let modified = MMSpdu::ConfirmedRequestPDU(modified);
    assert_eq!(validate_cbb(&modified, &all()), Ok(()));
    assert_eq!(
        validate_cbb(&modified, &without("attachToEventCondition")),
        Err(CbbError::NotSupported {
            name: "attachToEventCondition"
        })
    );
    // The extensions of the companion standards need csr or cspi.
    let MMSpdu::ConfirmedRequestPDU(mut extended) = identify else {
        panic!()
    };
    extended.service_ext = Some(RawBer(vec![0xBF, 0x4F, 0x02, 0x80, 0x00]));
    let extended = MMSpdu::ConfirmedRequestPDU(extended);
    assert_eq!(validate_cbb(&extended, &all()), Ok(()));
    let mut neither = without("csr");
    neither.parameters = without("cspi").parameters.clone();
    let position = PARAMETER_SUPPORT_OPTIONS
        .iter()
        .find(|b| b.name == "csr")
        .unwrap()
        .position;
    neither.parameters.bytes[position as usize / 8] &= !(0x80 >> (position % 8));
    assert_eq!(
        validate_cbb(&extended, &neither),
        Err(not_negotiated("csr"))
    );
    assert_eq!(validate_cbb(&extended, &without("csr")), Ok(()));
}

#[test]
fn data_needs_str1_str2_and_the_nesting_level() {
    refused(
        &write_of(Data::Array(vec![Data::Boolean(true)])),
        "str1",
        not_negotiated("str1"),
    );
    refused(
        &write_of(Data::Structure(vec![])),
        "str2",
        not_negotiated("str2"),
    );
    let deep = Data::Structure(vec![Data::Array(vec![Data::Structure(vec![
        Data::Integer(1),
    ])])]);
    let pdu = write_of(deep);
    let limited = |level| Negotiated {
        nesting_level: Some(level),
        ..all()
    };
    assert_eq!(validate_cbb(&pdu, &limited(3)), Ok(()));
    assert_eq!(
        validate_cbb(&pdu, &limited(2)),
        Err(CbbError::Nesting { depth: 3, limit: 2 })
    );
    assert_eq!(
        validate_cbb(&write_of(Data::Integer(1)), &limited(0)),
        Ok(())
    );
    // booleanArray is not under the directive of str1.
    let bits = Data::BooleanArray(BitString {
        unused: 7,
        bytes: vec![0x80],
    });
    assert_eq!(validate_cbb(&write_of(bits), &without("str1")), Ok(()));
}

#[test]
fn variable_specifications() {
    let item = |spec| VariableAccessSpecificationListOfVariableItem {
        variable_specification: spec,
        alternate_access: None,
    };
    refused(&read_of(item(named("v"))), "vnam", not_negotiated("vnam"));
    let address = VariableSpecification::Address(Address::NumericAddress(Unsigned32(16)));
    refused(&read_of(item(address)), "vadr", not_negotiated("vadr"));
    let described =
        VariableSpecification::VariableDescription(VariableSpecificationVariableDescription {
            address: Address::NumericAddress(Unsigned32(16)),
            type_specification: TypeSpecification::TypeDescription(Box::new(
                TypeDescription::Boolean,
            )),
        });
    refused(&read_of(item(described)), "vadr", not_negotiated("vadr"));
    let scattered =
        VariableSpecification::ScatteredAccessDescription(ScatteredAccessDescription(vec![]));
    refused(&read_of(item(scattered)), "vsca", not_negotiated("vsca"));
    let list = confirmed(ConfirmedServiceRequest::Read(ReadRequest {
        specification_with_result: None,
        variable_access_specification: VariableAccessSpecification::VariableListName(
            ObjectName::VmdSpecific(id("l")),
        ),
    }));
    refused(&list, "vlis", not_negotiated("vlis"));
    let by_name = confirmed(ConfirmedServiceRequest::GetVariableAccessAttributes(
        GetVariableAccessAttributesRequest::Name(ObjectName::VmdSpecific(id("v"))),
    ));
    refused(&by_name, "vnam", not_negotiated("vnam"));
    let by_address = confirmed(ConfirmedServiceRequest::GetVariableAccessAttributes(
        GetVariableAccessAttributesRequest::Address(Address::UnconstrainedAddress(vec![1])),
    ));
    refused(&by_address, "vadr", not_negotiated("vadr"));
}

#[test]
fn alternate_access() {
    let with = |selection: AlternateAccessItemItem| {
        read_of(VariableAccessSpecificationListOfVariableItem {
            variable_specification: named("v"),
            alternate_access: Some(AlternateAccess(vec![selection])),
        })
    };
    let all_elements = AlternateAccessItemItem::Unnamed(AlternateAccessSelection::SelectAccess(
        AlternateAccessSelectionSelectAccess::AllElements,
    ));
    refused(&with(all_elements), "valt", not_negotiated("valt"));
    let index = AlternateAccessItemItem::Unnamed(AlternateAccessSelection::SelectAccess(
        AlternateAccessSelectionSelectAccess::Index(Unsigned32(2)),
    ));
    refused(&with(index), "str1", not_negotiated("str1"));
    let component = AlternateAccessItemItem::Unnamed(AlternateAccessSelection::SelectAccess(
        AlternateAccessSelectionSelectAccess::Component(id("c")),
    ));
    refused(&with(component), "str2", not_negotiated("str2"));
    let nested = AlternateAccessItemItem::Unnamed(AlternateAccessSelection::SelectAlternateAccess(
        AlternateAccessSelectionSelectAlternateAccess {
            access_selection:
                AlternateAccessSelectionSelectAlternateAccessAccessSelection::IndexRange(
                    AlternateAccessSelectionSelectAlternateAccessAccessSelectionIndexRange {
                        low_index: Unsigned32(0),
                        number_of_elements: Unsigned32(2),
                    },
                ),
            alternate_access: AlternateAccess(vec![]),
        },
    ));
    refused(&with(nested), "str1", not_negotiated("str1"));
    let named_item = AlternateAccessItemItem::Named(AlternateAccessItemItemNamed {
        component_name: id("c"),
        access: AlternateAccessSelection::SelectAccess(
            AlternateAccessSelectionSelectAccess::AllElements,
        ),
    });
    refused(&with(named_item), "str2", not_negotiated("str2"));
}

fn attributes(description: TypeDescription) -> GetVariableAccessAttributesResponse {
    GetVariableAccessAttributesResponse {
        mms_deletable: false,
        address: None,
        type_description: description,
        access_control_list: None,
        meaning: None,
    }
}

fn attributes_pdu(response: GetVariableAccessAttributesResponse) -> MMSpdu {
    answered(ConfirmedServiceResponse::GetVariableAccessAttributes(
        response,
    ))
}

#[test]
fn type_descriptions_and_attributes() {
    let leaf =
        || TypeSpecification::TypeDescription(Box::new(TypeDescription::Integer(Unsigned8(32))));
    let array = |packed| {
        TypeDescription::Array(Box::new(TypeDescriptionArray {
            packed,
            number_of_elements: Unsigned32(4),
            element_type: Box::new(leaf()),
        }))
    };
    refused(
        &attributes_pdu(attributes(array(None))),
        "str1",
        not_negotiated("str1"),
    );
    refused(
        &attributes_pdu(attributes(array(Some(true)))),
        "vadr",
        not_negotiated("vadr"),
    );
    assert_eq!(
        validate_cbb(
            &attributes_pdu(attributes(array(Some(false)))),
            &without("vadr")
        ),
        Ok(())
    );
    let structure = |name: Option<Identifier>| {
        TypeDescription::Structure(TypeDescriptionStructure {
            packed: None,
            components: vec![TypeDescriptionStructureComponentsItem {
                component_name: name,
                component_type: leaf(),
            }],
        })
    };
    refused(
        &attributes_pdu(attributes(structure(None))),
        "str2",
        not_negotiated("str2"),
    );
    refused(
        &attributes_pdu(attributes(structure(Some(id("c"))))),
        "valt",
        not_negotiated("valt"),
    );
    let deep = attributes(structure(None));
    assert_eq!(
        validate_cbb(
            &attributes_pdu(deep),
            &Negotiated {
                nesting_level: Some(0),
                ..all()
            }
        ),
        Err(CbbError::Nesting { depth: 1, limit: 0 })
    );
    let with = |f: fn(&mut GetVariableAccessAttributesResponse)| {
        let mut response = attributes(TypeDescription::Boolean);
        f(&mut response);
        attributes_pdu(response)
    };
    refused(
        &with(|r| r.address = Some(Address::NumericAddress(Unsigned32(1)))),
        "vadr",
        not_negotiated("vadr"),
    );
    refused(
        &with(|r| r.access_control_list = Some(id("acl"))),
        "aco",
        not_negotiated("aco"),
    );
    refused(
        &with(|r| r.meaning = Some("m".into())),
        "sem",
        not_negotiated("sem"),
    );
    let list = answered(ConfirmedServiceResponse::GetNamedVariableListAttributes(
        GetNamedVariableListAttributesResponse {
            mms_deletable: true,
            list_of_variable: vec![],
            access_control_list: Some(id("acl")),
        },
    ));
    refused(&list, "aco", not_negotiated("aco"));
}

#[test]
fn object_classes() {
    let list = |class| {
        confirmed(ConfirmedServiceRequest::GetNameList(GetNameListRequest {
            object_class: class,
            object_scope: GetNameListRequestObjectScope::VmdSpecific,
            continue_after: None,
        }))
    };
    use ObjectClassBasicObjectClass as C;
    refused(
        &list(ObjectClass::BasicObjectClass(C::NAMED_VARIABLE)),
        "vnam",
        not_negotiated("vnam"),
    );
    refused(
        &list(ObjectClass::BasicObjectClass(C::NAMED_TYPE)),
        "vnam",
        not_negotiated("vnam"),
    );
    refused(
        &list(ObjectClass::BasicObjectClass(C::SCATTERED_ACCESS)),
        "vsca",
        not_negotiated("vsca"),
    );
    refused(
        &list(ObjectClass::BasicObjectClass(C::NAMED_VARIABLE_LIST)),
        "vlis",
        not_negotiated("vlis"),
    );
    refused(
        &list(ObjectClass::CsObjectClass(ObjectClassCsObjectClass(0))),
        "cspi",
        not_negotiated("cspi"),
    );
    assert_eq!(
        validate_cbb(
            &list(ObjectClass::BasicObjectClass(C::DOMAIN)),
            &without("vnam")
        ),
        Ok(())
    );
}
