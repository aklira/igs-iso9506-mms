// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! ACSE APDUs (ITU-T X.227 with amendment 1), task C5: observed APDUs, round trips and
//! hand-written vectors. The lengths of the hand-written vectors are computed by [`tlv`].

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use igs_iso9506_mms_codec::acse::{
    self, AARQApdu, AARQApduProtocolVersion, ABRTApdu, ABRTDiagnostic, ABRTSource, ACSEApdu,
    ACSERequirements, AEInvocationIdentifier, AEQualifier, AEQualifierForm1, AEQualifierForm2,
    APInvocationIdentifier, APTitle, APTitleForm1, APTitleForm2, ApplicationContextName,
    ApplicationContextNameList, AssociateResult, AssociateSourceDiagnostic,
    AssociateSourceDiagnosticAcseServiceProvider, AssociateSourceDiagnosticAcseServiceUser,
    AssociationInformation, AuthenticationValue, Encoding, External, ImplementationData,
    MechanismName, RLREApdu, RLRQApdu, ReleaseRequestReason, ReleaseResponseReason,
};
use igs_iso9506_mms_codec::asn::Error;
use igs_iso9506_mms_codec::ber;
use igs_iso9506_mms_codec::schema::{BitString, ObjectIdentifier, RawBer};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn oid(arcs: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier(arcs.to_vec())
}

/// One encoding with a one-octet identifier; the length is computed, in the short form below
/// 128 octets and in the long form above.
fn tlv(id: u8, parts: &[&[u8]]) -> Vec<u8> {
    let contents = parts.concat();
    let n = contents.len();
    let mut out = vec![id];
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend([0x81, n as u8]);
    } else {
        out.extend([0x82, (n >> 8) as u8, n as u8]);
    }
    out.extend(contents);
    out
}

fn round_trip(bytes: &[u8]) -> ACSEApdu {
    let apdu = acse::decode(bytes).unwrap();
    assert_eq!(acse::encode(&apdu).unwrap(), bytes);
    apdu
}

/// The AARQ inside the CP user data and the AARE inside the CPA user data observed on the bench
/// (task F5; the same PPDUs as in `presentation.rs`).
const OBSERVED_AARQ: &str = "6055a107060528ca220203a20706052901876701a30302010ca606060429018767a70302010cbe2f282d020103a028a826800300fde881010582010583010aa416800101810305f100820c03ee1c00000408000079ef18";
const OBSERVED_AARE: &str = "6146a107060528ca220203a203020100a305a103020100be2f282d020103a028a926800300fde881010582010583010aa416800101810305f100820c03ee1c000000000000000118";

/// Application context name of MMS (ISO 9506-2 annex A), as the peers send it.
const MMS_CONTEXT: &[u64] = &[1, 0, 9506, 2, 3];

fn one_external(info: &Option<AssociationInformation>) -> External {
    let info = info.as_ref().unwrap();
    assert_eq!(info.0.len(), 1);
    External::decode(&info.0[0]).unwrap()
}

#[test]
fn observed_aarq() {
    let ACSEApdu::Aarq(aarq) = round_trip(&hex(OBSERVED_AARQ)) else {
        panic!("not an AARQ");
    };
    assert_eq!(aarq.protocol_version, None);
    assert!(acse::offers_version1(
        aarq.protocol_version.as_ref().map(|v| &v.0)
    ));
    assert_eq!(aarq.application_context_name.0, oid(MMS_CONTEXT));
    assert_eq!(
        aarq.called_ap_title,
        Some(APTitle::ApTitleForm2(APTitleForm2(oid(&[1, 1, 1, 999, 1]))))
    );
    assert_eq!(
        aarq.called_ae_qualifier,
        Some(AEQualifier::AeQualifierForm2(AEQualifierForm2(12)))
    );
    assert_eq!(
        aarq.calling_ap_title,
        Some(APTitle::ApTitleForm2(APTitleForm2(oid(&[1, 1, 1, 999]))))
    );
    assert_eq!(
        aarq.calling_ae_qualifier,
        Some(AEQualifier::AeQualifierForm2(AEQualifierForm2(12)))
    );
    assert_eq!(aarq.sender_acse_requirements, None);
    let external = one_external(&aarq.user_information);
    assert_eq!(external.direct_reference, None);
    assert_eq!(external.indirect_reference, Some(3));
    let Encoding::SingleAsn1Type(value) = &external.encoding else {
        panic!("not a single ASN.1 type");
    };
    // An initiate-RequestPDU of MMS: [8], constructed.
    assert_eq!(value.0[0], 0xA8);
    assert_eq!(
        &external.encode().unwrap(),
        &aarq.user_information.unwrap().0[0]
    );
}

#[test]
fn observed_aare() {
    let ACSEApdu::Aare(aare) = round_trip(&hex(OBSERVED_AARE)) else {
        panic!("not an AARE");
    };
    assert_eq!(aare.application_context_name.0, oid(MMS_CONTEXT));
    assert_eq!(aare.result, AssociateResult::ACCEPTED);
    assert_eq!(
        aare.result_source_diagnostic,
        AssociateSourceDiagnostic::AcseServiceUser(AssociateSourceDiagnosticAcseServiceUser::NULL)
    );
    assert_eq!(aare.responding_ap_title, None);
    let external = one_external(&aare.user_information);
    assert_eq!(external.indirect_reference, Some(3));
    let Encoding::SingleAsn1Type(value) = &external.encoding else {
        panic!("not a single ASN.1 type");
    };
    // An initiate-ResponsePDU of MMS: [9], constructed.
    assert_eq!(value.0[0], 0xA9);
}

// Pieces of hand-written vectors.
fn context_name() -> Vec<u8> {
    tlv(0x06, &[&[0x28, 0xCA, 0x22, 0x02, 0x03]])
}

/// A directory name with one relative name, commonName "igs" (X.501 §9, X.520).
fn rdn() -> Vec<u8> {
    let atav = tlv(
        0x30,
        &[&tlv(0x06, &[&[0x55, 0x04, 0x03]]), &tlv(0x13, &[b"igs"])],
    );
    tlv(0x31, &[&atav])
}

fn name() -> Vec<u8> {
    tlv(0x30, &[&rdn()])
}

fn external_bytes() -> Vec<u8> {
    let pdu = tlv(0xA8, &[&tlv(0x80, &[&[0x01]])]);
    tlv(0x28, &[&tlv(0x02, &[&[0x03]]), &tlv(0xA0, &[&pdu])])
}

fn full_aarq_parts() -> Vec<Vec<u8>> {
    vec![
        tlv(0x80, &[&[0x07, 0x80]]),
        tlv(0xA1, &[&context_name()]),
        tlv(0xA2, &[&name()]),
        tlv(0xA3, &[&rdn()]),
        tlv(0xA4, &[&tlv(0x02, &[&[0x07]])]),
        tlv(0xA5, &[&tlv(0x02, &[&[0x08]])]),
        tlv(0xA6, &[&tlv(0x06, &[&[0x29, 0x01, 0x87, 0x67]])]),
        tlv(0xA7, &[&tlv(0x02, &[&[0x0C]])]),
        tlv(0x8A, &[&[0x07, 0x80]]),
        tlv(0x8B, &[&[0x52, 0x03, 0x01]]),
        tlv(0xAC, &[&tlv(0x80, &[b"secret"])]),
        tlv(0xAD, &[&context_name()]),
        tlv(0x9D, &[b"igs"]),
        tlv(0xBE, &[&external_bytes()]),
    ]
}

fn aarq_of(parts: &[Vec<u8>]) -> Vec<u8> {
    let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    tlv(0x60, &parts)
}

#[test]
fn aarq_with_every_field() {
    let bytes = aarq_of(&full_aarq_parts());
    let ACSEApdu::Aarq(aarq) = round_trip(&bytes) else {
        panic!("not an AARQ");
    };
    let expected = AARQApdu {
        protocol_version: Some(AARQApduProtocolVersion(acse::version1())),
        application_context_name: ApplicationContextName(oid(MMS_CONTEXT)),
        called_ap_title: Some(APTitle::ApTitleForm1(APTitleForm1(RawBer(name())))),
        called_ae_qualifier: Some(AEQualifier::AeQualifierForm1(AEQualifierForm1(RawBer(
            rdn(),
        )))),
        called_ap_invocation_identifier: Some(APInvocationIdentifier(7)),
        called_ae_invocation_identifier: Some(AEInvocationIdentifier(8)),
        calling_ap_title: Some(APTitle::ApTitleForm2(APTitleForm2(oid(&[1, 1, 1, 999])))),
        calling_ae_qualifier: Some(AEQualifier::AeQualifierForm2(AEQualifierForm2(12))),
        calling_ap_invocation_identifier: None,
        calling_ae_invocation_identifier: None,
        sender_acse_requirements: Some(ACSERequirements(BitString {
            unused: 7,
            bytes: vec![0x80],
        })),
        mechanism_name: Some(MechanismName(oid(&[2, 2, 3, 1]))),
        calling_authentication_value: Some(AuthenticationValue::Charstring("secret".into())),
        application_context_name_list: Some(ApplicationContextNameList(vec![
            ApplicationContextName(oid(MMS_CONTEXT)),
        ])),
        implementation_information: Some(ImplementationData("igs".into())),
        user_information: Some(AssociationInformation(vec![RawBer(external_bytes())])),
    };
    assert_eq!(aarq, expected);
    assert_eq!(
        acse::encode(&ACSEApdu::Aarq(expected)).unwrap(),
        bytes,
        "encoding from the value"
    );
}

#[test]
fn aarq_ignores_undefined_elements() {
    let mut parts = full_aarq_parts();
    let known = aarq_of(&parts);
    // An undefined primitive [20] after the context name, and [31] in the high-tag form last.
    parts.insert(2, tlv(0x94, &[&[0x00]]));
    parts.push(vec![0x9F, 0x1F, 0x01, 0x00]);
    let with_unknown = aarq_of(&parts);
    let decoded = acse::decode(&with_unknown).unwrap();
    assert_eq!(decoded, acse::decode(&known).unwrap());
    assert_eq!(acse::encode(&decoded).unwrap(), known);
}

#[test]
fn aarq_refuses_known_fields_out_of_order() {
    let mut parts = full_aarq_parts();
    parts.swap(2, 6);
    assert!(matches!(
        acse::decode(&aarq_of(&parts)),
        Err(Error::Unexpected {
            ty: "AARQ-apdu",
            ..
        })
    ));
}

fn aare_parts() -> Vec<Vec<u8>> {
    vec![
        tlv(0xA1, &[&context_name()]),
        tlv(0xA2, &[&tlv(0x02, &[&[0x01]])]),
        tlv(0xA3, &[&tlv(0xA2, &[&tlv(0x02, &[&[0x02]])])]),
        tlv(0xA4, &[&tlv(0x06, &[&[0x29, 0x01, 0x87, 0x67, 0x01]])]),
        tlv(0xA5, &[&tlv(0x02, &[&[0x0C]])]),
    ]
}

#[test]
fn aare_rejected_by_the_provider() {
    let parts = aare_parts();
    let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let bytes = tlv(0x61, &parts);
    let ACSEApdu::Aare(aare) = round_trip(&bytes) else {
        panic!("not an AARE");
    };
    assert_eq!(aare.result, AssociateResult::REJECTED_PERMANENT);
    assert_eq!(
        aare.result_source_diagnostic,
        AssociateSourceDiagnostic::AcseServiceProvider(
            AssociateSourceDiagnosticAcseServiceProvider::NO_COMMON_ACSE_VERSION
        )
    );
    assert_eq!(
        aare.responding_ap_title,
        Some(APTitle::ApTitleForm2(APTitleForm2(oid(&[1, 1, 1, 999, 1]))))
    );
    assert!(acse::offers_version1(None));
}

#[test]
fn aare_refuses_undefined_elements() {
    let with = |at: usize| {
        let mut parts = aare_parts();
        parts.insert(at, tlv(0x94, &[&[0x00]]));
        let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        acse::decode(&tlv(0x61, &parts))
    };
    // Before a required component, it hides it; after the last one, it is left over.
    assert_eq!(
        with(2),
        Err(Error::Missing {
            ty: "AARE-apdu",
            component: "result-source-diagnostic"
        })
    );
    assert!(matches!(
        with(5),
        Err(Error::Unexpected {
            ty: "AARE-apdu",
            ..
        })
    ));
}

#[test]
fn release_and_abort() {
    let reason = |value: u8| tlv(0x80, &[&[value]]);
    let ACSEApdu::Rlrq(rlrq) = round_trip(&tlv(0x62, &[&reason(0)])) else {
        panic!("not an RLRQ");
    };
    assert_eq!(rlrq.reason, Some(ReleaseRequestReason::NORMAL));
    let ACSEApdu::Rlrq(empty) = round_trip(&[0x62, 0x00]) else {
        panic!("not an RLRQ");
    };
    assert_eq!(
        empty,
        RLRQApdu {
            reason: None,
            user_information: None
        }
    );
    let rlre = tlv(0x63, &[&reason(1), &tlv(0xBE, &[&external_bytes()])]);
    let ACSEApdu::Rlre(rlre) = round_trip(&rlre) else {
        panic!("not an RLRE");
    };
    assert_eq!(rlre.reason, Some(ReleaseResponseReason::NOT_FINISHED));
    assert_eq!(
        one_external(&rlre.user_information).indirect_reference,
        Some(3)
    );

    let abrt = tlv(0x64, &[&tlv(0x80, &[&[0x01]]), &tlv(0x81, &[&[0x02]])]);
    let ACSEApdu::Abrt(abrt) = round_trip(&abrt) else {
        panic!("not an ABRT");
    };
    assert_eq!(
        abrt,
        ABRTApdu {
            abort_source: ABRTSource::ACSE_SERVICE_PROVIDER,
            abort_diagnostic: Some(ABRTDiagnostic::PROTOCOL_ERROR),
            user_information: None,
        }
    );
    assert_eq!(
        acse::decode(&[0x64, 0x00]),
        Err(Error::Missing {
            ty: "ABRT-apdu",
            component: "abort-source"
        })
    );
    // An undefined element is refused outside the AARQ (X.227 §7.4).
    assert!(acse::decode(&tlv(0x62, &[&reason(0), &tlv(0x94, &[&[0]])])).is_err());
}

#[test]
fn extensible_values_outside_the_root_are_accepted() {
    // Each of these constraints has an extension marker.
    let ACSEApdu::Rlrq(rlrq) = round_trip(&tlv(0x62, &[&tlv(0x80, &[&[0x05]])])) else {
        panic!("not an RLRQ");
    };
    assert_eq!(rlrq.reason, Some(ReleaseRequestReason(5)));
    let ACSEApdu::Abrt(abrt) = round_trip(&tlv(0x64, &[&tlv(0x80, &[&[0x07]])])) else {
        panic!("not an ABRT");
    };
    assert_eq!(abrt.abort_source, ABRTSource(7));
    let diagnostic = tlv(0xA3, &[&tlv(0xA1, &[&tlv(0x02, &[&[0x0F]])])]);
    let mut parts = aare_parts();
    parts[2] = diagnostic;
    let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let ACSEApdu::Aare(aare) = round_trip(&tlv(0x61, &parts)) else {
        panic!("not an AARE");
    };
    assert_eq!(
        aare.result_source_diagnostic,
        AssociateSourceDiagnostic::AcseServiceUser(AssociateSourceDiagnosticAcseServiceUser(15))
    );
}

#[test]
fn protocol_version() {
    let bits = |unused, byte| BitString {
        unused,
        bytes: vec![byte],
    };
    assert!(acse::offers_version1(None));
    assert!(acse::offers_version1(Some(&acse::version1())));
    assert!(acse::offers_version1(Some(&bits(6, 0xC0))));
    assert!(!acse::offers_version1(Some(&bits(6, 0x40))));
    assert!(!acse::offers_version1(Some(&BitString::default())));
}

#[test]
fn malformed_apdus_are_refused() {
    let context = tlv(0xA1, &[&context_name()]);
    assert_eq!(
        acse::decode(&[0x60, 0x00]),
        Err(Error::Missing {
            ty: "AARQ-apdu",
            component: "application-context-name"
        })
    );
    // An AP title that is neither a name nor an object identifier.
    let title = tlv(0xA2, &[&tlv(0x02, &[&[0x05]])]);
    assert!(matches!(
        acse::decode(&tlv(0x60, &[&context, &title])),
        Err(Error::Unexpected { ty: "AP-title", .. })
    ));
    // Two values inside an explicit tag.
    let two = tlv(0xA1, &[&context_name(), &context_name()]);
    assert_eq!(
        acse::decode(&tlv(0x60, &[&two])),
        Err(Error::Ber(ber::Error::TrailingData))
    );
    // An explicit tag in the primitive form.
    let primitive = tlv(0x81, &[&context_name()]);
    assert_eq!(
        acse::decode(&tlv(0x60, &[&primitive])),
        Err(Error::Ber(ber::Error::WrongForm))
    );
    // An APDU of no known type, and octets after the APDU.
    assert!(matches!(
        acse::decode(&[0x65, 0x00]),
        Err(Error::Unexpected { .. })
    ));
    assert_eq!(
        acse::decode(&[0x62, 0x00, 0x00]),
        Err(Error::Ber(ber::Error::TrailingData))
    );
    // Truncated everywhere.
    let bytes = hex(OBSERVED_AARQ);
    for end in 0..bytes.len() {
        assert!(acse::decode(&bytes[..end]).is_err(), "cut at {end}");
    }
}

#[test]
fn indefinite_lengths_are_read() {
    // The observed AARE with its outer length in the indefinite form.
    let definite = hex(OBSERVED_AARE);
    let mut indefinite = vec![0x61, 0x80];
    indefinite.extend_from_slice(&definite[2..]);
    indefinite.extend_from_slice(&[0x00, 0x00]);
    assert_eq!(
        acse::decode(&indefinite).unwrap(),
        acse::decode(&definite).unwrap()
    );
}

#[test]
fn external_encodings() {
    let cases = [
        External {
            direct_reference: None,
            indirect_reference: Some(3),
            data_value_descriptor: None,
            encoding: Encoding::SingleAsn1Type(RawBer(vec![0x05, 0x00])),
        },
        External {
            direct_reference: Some(oid(&[1, 0, 9506, 2, 1])),
            indirect_reference: Some(3),
            data_value_descriptor: Some("mms".into()),
            encoding: Encoding::OctetAligned(vec![0x05, 0x00]),
        },
        External {
            direct_reference: Some(oid(&[2, 1, 1])),
            indirect_reference: None,
            data_value_descriptor: None,
            encoding: Encoding::Arbitrary(BitString {
                unused: 4,
                bytes: vec![0xF0],
            }),
        },
    ];
    let expected = [
        tlv(
            0x28,
            &[&tlv(0x02, &[&[0x03]]), &tlv(0xA0, &[&[0x05, 0x00]])],
        ),
        tlv(
            0x28,
            &[
                &tlv(0x06, &[&[0x28, 0xCA, 0x22, 0x02, 0x01]]),
                &tlv(0x02, &[&[0x03]]),
                &tlv(0x07, &[b"mms"]),
                &tlv(0x81, &[&[0x05, 0x00]]),
            ],
        ),
        tlv(
            0x28,
            &[&tlv(0x06, &[&[0x51, 0x01]]), &tlv(0x82, &[&[0x04, 0xF0]])],
        ),
    ];
    for (external, bytes) in cases.iter().zip(expected) {
        let raw = external.encode().unwrap();
        assert_eq!(raw.0, bytes);
        assert_eq!(&External::decode(&raw).unwrap(), external);
    }
}

#[test]
fn malformed_externals_are_refused() {
    let reference = tlv(0x02, &[&[0x03]]);
    let missing = RawBer(tlv(0x28, &[&reference]));
    assert_eq!(
        External::decode(&missing),
        Err(Error::Missing {
            ty: "EXTERNAL",
            component: "encoding"
        })
    );
    let extra = RawBer(tlv(
        0x28,
        &[&reference, &tlv(0x81, &[&[0x00]]), &tlv(0x81, &[&[0x00]])],
    ));
    assert!(matches!(
        External::decode(&extra),
        Err(Error::Unexpected { ty: "EXTERNAL", .. })
    ));
    let two_values = RawBer(tlv(0x28, &[&tlv(0xA0, &[&[0x05, 0x00, 0x05, 0x00]])]));
    assert!(External::decode(&two_values).is_err());
    assert!(External::decode(&RawBer(vec![0x30, 0x00])).is_err());
}

#[test]
fn external_under_an_implicit_tag() {
    // calling-authentication-value [12] EXPLICIT, then external [2] IMPLICIT EXTERNAL.
    let external = external_bytes();
    let mut retagged = external.clone();
    retagged[0] = 0xA2;
    let bytes = tlv(
        0x60,
        &[&tlv(0xA1, &[&context_name()]), &tlv(0xAC, &[&retagged])],
    );
    let ACSEApdu::Aarq(aarq) = round_trip(&bytes) else {
        panic!("not an AARQ");
    };
    assert_eq!(
        aarq.calling_authentication_value,
        Some(AuthenticationValue::External(RawBer(external)))
    );
}

#[test]
fn raw_values_are_checked_before_encoding() {
    let with = |raw: Vec<u8>| {
        ACSEApdu::Rlrq(RLRQApdu {
            reason: None,
            user_information: Some(AssociationInformation(vec![RawBer(raw)])),
        })
    };
    assert_eq!(
        acse::encode(&with(vec![0x30, 0x00])),
        Err(Error::InvalidRaw)
    );
    assert_eq!(
        acse::encode(&with(vec![0x28, 0x00, 0x28, 0x00])),
        Err(Error::InvalidRaw)
    );
    assert_eq!(
        acse::encode(&with(vec![0x28, 0x05])),
        Err(Error::InvalidRaw)
    );
    assert_eq!(
        acse::encode(&with(vec![0x28, 0x00])).unwrap(),
        tlv(0x62, &[&tlv(0xBE, &[&[0x28, 0x00]])])
    );
    let release = ACSEApdu::Rlre(RLREApdu {
        reason: Some(ReleaseResponseReason::NORMAL),
        user_information: None,
    });
    assert_eq!(
        acse::encode(&release).unwrap(),
        tlv(0x63, &[&tlv(0x80, &[&[0x00]])])
    );
}
