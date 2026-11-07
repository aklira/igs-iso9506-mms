// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Property tests, task C8: what the encoder accepts decodes back unchanged, and no input makes a
//! decoder panic. 10 000 cases per property. Needs the `proptest` feature, which brings the
//! strategies of the generated types.

#![cfg(feature = "proptest")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::cell::Cell;
use std::fmt::Debug;

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::strategy::BoxedStrategy;
use proptest::test_runner::{Config, TestRunner};

use igs_iso9506_mms_codec::acse::{self, ACSEApdu, External};
use igs_iso9506_mms_codec::asn;
use igs_iso9506_mms_codec::ber::Reader;
use igs_iso9506_mms_codec::generated::types::*;
use igs_iso9506_mms_codec::mms::{self, validate_cbb, Negotiated};
use igs_iso9506_mms_codec::presentation::{
    self, Abort, AbortProvider, AbortUser, AcceptNormal, Connect, ConnectAccept, ConnectNormal,
    ConnectRefuse, ContextDefinition, ContextResult, DefaultContextName, Mode, Pdv, PdvValues,
    UserData,
};
use igs_iso9506_mms_codec::schema::{BitString, ObjectIdentifier};
use igs_iso9506_mms_codec::session::{self, Spdu};
use igs_iso9506_mms_codec::strategy::{values, Values};
use igs_iso9506_mms_codec::transport::{
    self, ConnectionTpdu, DataTpdu, DisconnectRequest, ErrorTpdu, FrameDecoder, Parameters, Tpdu,
    TpduSize,
};

const CASES: u32 = 10_000;

fn runner() -> TestRunner {
    TestRunner::new(Config {
        cases: CASES,
        failure_persistence: None,
        ..Config::default()
    })
}

/// Runs `check` on 10 000 values; `check` returns whether the encoder accepted the value. At
/// least `share` of them must be accepted, so that the property is not empty.
fn run<T: Debug>(
    strategy: impl Strategy<Value = T>,
    share: f64,
    check: impl Fn(T) -> Result<bool, TestCaseError>,
) {
    let accepted = Cell::new(0u32);
    runner()
        .run(&strategy, |value| {
            if check(value)? {
                accepted.set(accepted.get() + 1);
            }
            Ok(())
        })
        .unwrap();
    let ratio = f64::from(accepted.get()) / f64::from(CASES);
    assert!(ratio >= share, "only {ratio} of the values were encodable");
}

/// The generated values always encode, and decode back to themselves.
fn generated<K: Values>(depth: u32)
where
    K::Value: PartialEq,
{
    run(values::<K>(depth), 1.0, |value| {
        let bytes =
            asn::encode_value::<K>(&value).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let back = asn::decode_value::<K>(&bytes)
            .map_err(|e| TestCaseError::fail(format!("{e}: {bytes:02x?}")))?;
        prop_assert_eq!(back, value);
        Ok(true)
    });
}

#[test]
fn mms_pdus_round_trip() {
    generated::<MMSpdu>(3);
}

#[test]
fn confirmed_pdus_round_trip() {
    generated::<ConfirmedRequestPDU>(3);
    generated::<ConfirmedResponsePDU>(3);
    generated::<ConfirmedErrorPDU>(2);
}

#[test]
fn environment_pdus_round_trip() {
    generated::<InitiateRequestPDU>(1);
    generated::<InitiateResponsePDU>(1);
    generated::<UnconfirmedPDU>(3);
    generated::<RejectPDU>(1);
}

#[test]
fn common_types_round_trip() {
    generated::<Data>(4);
    generated::<TypeSpecification>(4);
    generated::<VariableAccessSpecification>(3);
    generated::<AlternateAccess>(3);
}

#[test]
fn acse_apdus_round_trip() {
    generated::<ACSEApdu>(2);
}

fn all_negotiated() -> Negotiated {
    Negotiated {
        parameters: BitString {
            unused: 6,
            bytes: vec![0xFF, 0xFF, 0xC0],
        },
        services: BitString {
            unused: 3,
            bytes: vec![0xFF; 12],
        },
        nesting_level: Some(2),
    }
}

/// The check never panics, and a PDU that passes with nothing negotiated passes with everything.
#[test]
fn the_cbb_check_is_total() {
    let none = Negotiated {
        parameters: BitString::default(),
        services: BitString::default(),
        nesting_level: Some(0),
    };
    let all = all_negotiated();
    run(values::<MMSpdu>(3), 1.0, |pdu| {
        if validate_cbb(&pdu, &none).is_ok() {
            let mut everything = all.clone();
            everything.nesting_level = None;
            prop_assert_eq!(validate_cbb(&pdu, &everything), Ok(()));
        }
        let _ = validate_cbb(&pdu, &all);
        Ok(true)
    });
}

// Hand-written layers: their strategies cover the natural domain of each field, mostly valid.

fn small_bytes() -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..6)
}

fn oid() -> impl Strategy<Value = ObjectIdentifier> {
    (0u64..=2, 0u64..40, vec(0u64..100_000, 0..3)).prop_map(|(a, b, rest)| {
        let mut arcs = vec![a, b];
        arcs.extend(rest);
        ObjectIdentifier(arcs)
    })
}

fn bits(max_bits: usize) -> impl Strategy<Value = BitString> {
    (0..=max_bits).prop_flat_map(|n| {
        let octets = n.div_ceil(8);
        let unused = (octets * 8 - n) as u8;
        vec(any::<u8>(), octets).prop_map(move |mut bytes| {
            if let Some(last) = bytes.last_mut() {
                *last &= 0xFFu8 << unused;
            }
            BitString { unused, bytes }
        })
    })
}

/// Mostly in `valid`, sometimes anything.
fn mostly(valid: std::ops::RangeInclusive<u8>) -> impl Strategy<Value = u8> {
    prop_oneof![19 => valid, 1 => any::<u8>()]
}

fn parameters() -> impl Strategy<Value = Parameters> {
    (
        proptest::option::of(small_bytes()),
        proptest::option::of(small_bytes()),
        proptest::option::of((7u8..=13).prop_map(|c| TpduSize::from_code(c).unwrap())),
        proptest::option::of(prop_oneof![1u32..=0xFFFF, any::<u32>()]),
        proptest::option::of(any::<u8>()),
    )
        .prop_map(|(calling, called, size, preferred, options)| Parameters {
            calling_selector: calling,
            called_selector: called,
            tpdu_size: size,
            preferred_max_tpdu_size: preferred,
            additional_options: options,
            other: Vec::new(),
        })
}

fn tpdus() -> impl Strategy<Value = Tpdu> {
    let connection = (
        mostly(0..=15),
        any::<u16>(),
        any::<u16>(),
        mostly(0..=4),
        mostly(0..=15),
        parameters(),
        small_bytes(),
    )
        .prop_map(
            |(credit, dst_ref, src_ref, class, options, parameters, user_data)| ConnectionTpdu {
                credit,
                dst_ref,
                src_ref,
                class,
                options,
                parameters,
                user_data,
            },
        )
        .boxed();
    prop_oneof![
        connection.clone().prop_map(Tpdu::ConnectionRequest),
        connection.prop_map(Tpdu::ConnectionConfirm),
        (
            any::<u16>(),
            any::<u16>(),
            any::<u8>(),
            proptest::option::of(small_bytes()),
            small_bytes()
        )
            .prop_map(
                |(dst_ref, src_ref, reason, additional_information, user_data)| {
                    Tpdu::DisconnectRequest(DisconnectRequest {
                        dst_ref,
                        src_ref,
                        reason,
                        additional_information,
                        user_data,
                    })
                }
            ),
        (any::<bool>(), mostly(0..=127), vec(any::<u8>(), 0..64)).prop_map(
            |(end_of_tsdu, number, user_data)| Tpdu::Data(DataTpdu {
                end_of_tsdu,
                number,
                user_data,
            })
        ),
        (
            any::<u16>(),
            any::<u8>(),
            proptest::option::of(small_bytes())
        )
            .prop_map(|(dst_ref, cause, invalid_tpdu)| Tpdu::Error(ErrorTpdu {
                dst_ref,
                cause,
                invalid_tpdu,
            })),
    ]
}

#[test]
fn tpdus_round_trip() {
    run(tpdus(), 0.6, |tpdu| {
        let Ok(bytes) = tpdu.encode() else {
            return Ok(false);
        };
        prop_assert_eq!(
            Tpdu::decode(&bytes).map_err(|e| TestCaseError::fail(e.to_string()))?,
            tpdu
        );
        // Framed, then cut at an arbitrary point, the frame comes back whole.
        let frame = transport::encode_frame(&bytes).unwrap();
        let mut decoder = FrameDecoder::new();
        let cut = frame.len() / 2;
        decoder.push(&frame[..cut]);
        prop_assert_eq!(decoder.next_tpdu().unwrap(), None);
        decoder.push(&frame[cut..]);
        prop_assert_eq!(decoder.next_tpdu().unwrap(), Some(bytes));
        Ok(true)
    });
}

fn others() -> impl Strategy<Value = Vec<(u8, Vec<u8>)>> {
    Just(Vec::new())
}

fn spdus() -> BoxedStrategy<Spdu> {
    use session::{
        Abort as SAbort, Accept, Connect as SConnect, ConnectAcceptItem, ConnectionIdentifier,
        DataTransfer, Disconnect, Finish, GiveTokens, Refuse,
    };
    let ui = || proptest::option::of(vec(any::<u8>(), 0..40)).boxed();
    let byte = || proptest::option::of(any::<u8>()).boxed();
    let selector = || proptest::option::of(small_bytes()).boxed();
    let requirements = || proptest::option::of(any::<u16>()).boxed();
    let id = proptest::option::of(
        (
            selector(),
            selector(),
            proptest::option::of(vec(any::<u8>(), 0..=4)),
        )
            .prop_map(|(a, b, c)| ConnectionIdentifier {
                ss_user_reference: a,
                common_reference: b,
                additional_reference: c,
            }),
    )
    .boxed();
    let item = proptest::option::of(
        (
            any::<u8>(),
            proptest::option::of((any::<u16>(), any::<u16>())),
            any::<u8>(),
            byte(),
            others(),
        )
            .prop_map(
                |(protocol_options, tsdu_maximum_size, version_number, token_setting, other)| {
                    ConnectAcceptItem {
                        protocol_options,
                        tsdu_maximum_size,
                        version_number,
                        token_setting,
                        other,
                    }
                },
            ),
    )
    .boxed();
    let connect = (
        id.clone(),
        item.clone(),
        requirements(),
        selector(),
        selector(),
        byte(),
        ui(),
    )
        .prop_map(
            |(
                connection_identifier,
                item,
                session_user_requirements,
                calling_selector,
                called_selector,
                data_overflow,
                user_data,
            )| {
                Spdu::Connect(SConnect {
                    connection_identifier,
                    item,
                    session_user_requirements,
                    calling_selector,
                    called_selector,
                    data_overflow,
                    user_data,
                    other: Vec::new(),
                })
            },
        )
        .boxed();
    let accept = (
        (id.clone(), item, byte(), requirements()),
        (byte(), selector(), selector(), ui()),
    )
        .prop_map(
            |(
                (connection_identifier, item, token_item, session_user_requirements),
                (enclosure, calling_selector, responding_selector, user_data),
            )| {
                Spdu::Accept(Accept {
                    connection_identifier,
                    item,
                    token_item,
                    session_user_requirements,
                    enclosure,
                    calling_selector,
                    responding_selector,
                    user_data,
                    other: Vec::new(),
                })
            },
        )
        .boxed();
    let refuse = (id, byte(), requirements(), byte(), byte(), selector())
        .prop_map(
            |(
                connection_identifier,
                transport_disconnect,
                session_user_requirements,
                version_number,
                enclosure,
                reason,
            )| {
                Spdu::Refuse(Refuse {
                    connection_identifier,
                    transport_disconnect,
                    session_user_requirements,
                    version_number,
                    enclosure,
                    reason,
                    other: Vec::new(),
                })
            },
        )
        .boxed();
    let finish = (byte(), byte(), ui())
        .prop_map(|(transport_disconnect, enclosure, user_data)| {
            Spdu::Finish(Finish {
                transport_disconnect,
                enclosure,
                user_data,
                other: Vec::new(),
            })
        })
        .boxed();
    let disconnect = (byte(), ui())
        .prop_map(|(enclosure, user_data)| {
            Spdu::Disconnect(Disconnect {
                enclosure,
                user_data,
                other: Vec::new(),
            })
        })
        .boxed();
    let abort = (any::<u8>(), byte(), selector(), ui())
        .prop_map(|(transport_disconnect, enclosure, reflect, user_data)| {
            Spdu::Abort(SAbort {
                transport_disconnect,
                enclosure,
                reflect,
                user_data,
                other: Vec::new(),
            })
        })
        .boxed();
    let tokens = (byte(), byte(), ui())
        .prop_map(|(token_item, enclosure, user_data)| {
            Spdu::GiveTokens(GiveTokens {
                token_item,
                enclosure,
                user_data,
                other: Vec::new(),
            })
        })
        .boxed();
    let data = (byte(), vec(any::<u8>(), 0..40))
        .prop_map(|(enclosure, user_information)| {
            Spdu::DataTransfer(DataTransfer {
                enclosure,
                user_information,
                other: Vec::new(),
            })
        })
        .boxed();
    proptest::strategy::Union::new([
        connect,
        accept,
        refuse,
        finish,
        disconnect,
        abort,
        Just(Spdu::AbortAccept).boxed(),
        tokens,
        data,
    ])
    .boxed()
}

#[test]
fn spdus_round_trip() {
    // One SPDU, or GIVE TOKENS then DATA TRANSFER (basic concatenation).
    let pair = (proptest::option::of(any::<u8>()), vec(any::<u8>(), 0..20)).prop_map(
        |(token_item, data)| {
            vec![
                Spdu::GiveTokens(session::GiveTokens {
                    token_item,
                    enclosure: None,
                    user_data: None,
                    other: Vec::new(),
                }),
                Spdu::DataTransfer(session::DataTransfer {
                    enclosure: None,
                    user_information: data,
                    other: Vec::new(),
                }),
            ]
        },
    );
    let tsdu = prop_oneof![4 => spdus().prop_map(|s| vec![s]), 1 => pair];
    run(tsdu, 0.5, |spdus| {
        let Ok(bytes) = session::encode_tsdu(&spdus) else {
            return Ok(false);
        };
        let back = session::decode_tsdu(&bytes)
            .map_err(|e| TestCaseError::fail(format!("{e}: {bytes:02x?}")))?;
        prop_assert_eq!(back, spdus);
        Ok(true)
    });
}

fn user_data() -> impl Strategy<Value = UserData> {
    let values = prop_oneof![
        vec(any::<u8>(), 0..4).prop_map(|c| {
            let mut v = vec![0x04, c.len() as u8];
            v.extend(c);
            PdvValues::SingleAsn1Type(v)
        }),
        small_bytes().prop_map(PdvValues::OctetAligned),
        bits(20).prop_map(PdvValues::Arbitrary),
    ];
    let pdv = (
        proptest::option::of(oid()),
        prop_oneof![1i64..=127, any::<i64>()],
        values,
    )
        .prop_map(|(transfer_syntax, context_id, values)| Pdv {
            transfer_syntax,
            context_id,
            values,
        });
    prop_oneof![
        small_bytes().prop_map(UserData::Simple),
        vec(pdv, 0..3).prop_map(UserData::Full),
    ]
}

fn named(max: usize) -> impl Strategy<Value = BitString> {
    prop_oneof![19 => bits(max), 1 => bits(24)]
}

fn number(max: i64) -> impl Strategy<Value = i64> {
    prop_oneof![19 => 0..=max, 1 => any::<i64>()]
}

fn connect() -> impl Strategy<Value = Connect> {
    let definition = (
        prop_oneof![1i64..=127, any::<i64>()],
        oid(),
        vec(oid(), 0..3),
    )
        .prop_map(
            |(id, abstract_syntax, transfer_syntaxes)| ContextDefinition {
                id,
                abstract_syntax,
                transfer_syntaxes,
            },
        );
    let normal = (
        proptest::option::of(named(1)),
        proptest::option::of(small_bytes()),
        proptest::option::of(small_bytes()),
        proptest::option::of(vec(definition, 0..3)),
        proptest::option::of((oid(), oid()).prop_map(|(a, t)| DefaultContextName {
            abstract_syntax: a,
            transfer_syntax: t,
        })),
        proptest::option::of(named(2)),
        proptest::option::of(named(13)),
        proptest::option::of(user_data()),
    )
        .prop_map(
            |(
                protocol_version,
                calling_selector,
                called_selector,
                context_definitions,
                default_context,
                presentation_requirements,
                user_session_requirements,
                user_data,
            )| {
                ConnectNormal {
                    protocol_version,
                    calling_selector,
                    called_selector,
                    context_definitions,
                    default_context,
                    presentation_requirements,
                    user_session_requirements,
                    user_data,
                }
            },
        );
    proptest::option::of(normal).prop_map(|normal| Connect {
        mode: Mode::Normal,
        x410_parameters: None,
        normal,
    })
}

fn results() -> impl Strategy<Value = Vec<ContextResult>> {
    vec(
        (
            number(2),
            proptest::option::of(oid()),
            proptest::option::of(number(2)),
        )
            .prop_map(|(result, transfer_syntax, provider_reason)| ContextResult {
                result,
                transfer_syntax,
                provider_reason,
            }),
        0..3,
    )
}

#[test]
fn presentation_ppdus_round_trip() {
    run((connect(), vec(user_data(), 0..2)), 0.4, |(cp, cpc)| {
        let Ok(bytes) = presentation::encode_connect(&cp, &cpc) else {
            return Ok(false);
        };
        let back = presentation::decode_connect(&bytes)
            .map_err(|e| TestCaseError::fail(format!("{e}: {bytes:02x?}")))?;
        prop_assert_eq!(back, (cp, cpc));
        Ok(true)
    });
    let accept = (
        proptest::option::of(named(1)),
        proptest::option::of(small_bytes()),
        proptest::option::of(results()),
        proptest::option::of(named(2)),
        proptest::option::of(named(13)),
        proptest::option::of(user_data()),
    )
        .prop_map(
            |(
                protocol_version,
                responding_selector,
                context_results,
                presentation_requirements,
                user_session_requirements,
                user_data,
            )| ConnectAccept {
                mode: Mode::Normal,
                x410_parameters: None,
                normal: Some(AcceptNormal {
                    protocol_version,
                    responding_selector,
                    context_results,
                    presentation_requirements,
                    user_session_requirements,
                    user_data,
                }),
            },
        );
    run(accept, 0.4, |cpa| {
        let Ok(bytes) = cpa.encode() else {
            return Ok(false);
        };
        let back = ConnectAccept::decode(&bytes)
            .map_err(|e| TestCaseError::fail(format!("{e}: {bytes:02x?}")))?;
        prop_assert_eq!(back, cpa);
        Ok(true)
    });
    let refuse = (
        proptest::option::of(named(1)),
        proptest::option::of(small_bytes()),
        proptest::option::of(results()),
        proptest::option::of(number(2)),
        proptest::option::of(number(7)),
        proptest::option::of(user_data()),
    )
        .prop_map(
            |(
                protocol_version,
                responding_selector,
                context_results,
                default_context_result,
                provider_reason,
                user_data,
            )| ConnectRefuse {
                protocol_version,
                responding_selector,
                context_results,
                default_context_result,
                provider_reason,
                user_data,
            },
        );
    run(refuse, 0.4, |cpr| {
        let Ok(bytes) = cpr.encode() else {
            return Ok(false);
        };
        let back = ConnectRefuse::decode(&bytes)
            .map_err(|e| TestCaseError::fail(format!("{e}: {bytes:02x?}")))?;
        prop_assert_eq!(back, cpr);
        Ok(true)
    });
    let abort = prop_oneof![
        (
            proptest::option::of(vec((prop_oneof![1i64..=127, any::<i64>()], oid()), 0..3)),
            proptest::option::of(user_data())
        )
            .prop_map(|(context_list, user_data)| Abort::User(AbortUser {
                context_list,
                user_data
            })),
        (
            proptest::option::of(number(6)),
            proptest::option::of(number(32))
        )
            .prop_map(|(reason, event)| Abort::Provider(AbortProvider { reason, event })),
    ];
    run(abort, 0.4, |abort| {
        let Ok(bytes) = abort.encode() else {
            return Ok(false);
        };
        let back = presentation::decode_abort(&bytes)
            .map_err(|e| TestCaseError::fail(format!("{e}: {bytes:02x?}")))?;
        prop_assert_eq!(back, abort);
        Ok(true)
    });
}

#[test]
fn externals_round_trip() {
    let encoding = prop_oneof![
        Just(acse::Encoding::SingleAsn1Type(
            igs_iso9506_mms_codec::schema::RawBer(vec![0x05, 0x00])
        )),
        small_bytes().prop_map(acse::Encoding::OctetAligned),
        bits(20).prop_map(acse::Encoding::Arbitrary),
    ];
    let external = (
        proptest::option::of(oid()),
        proptest::option::of(any::<i64>()),
        proptest::option::of("[ -~]{0,6}"),
        encoding,
    )
        .prop_map(
            |(direct_reference, indirect_reference, data_value_descriptor, encoding)| External {
                direct_reference,
                indirect_reference,
                data_value_descriptor,
                encoding,
            },
        );
    run(external, 1.0, |external| {
        let raw = external
            .encode()
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(
            External::decode(&raw).map_err(|e| TestCaseError::fail(e.to_string()))?,
            external
        );
        Ok(true)
    });
}

// No input makes a decoder panic.

fn any_bytes() -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..300)
}

fn every_decoder(bytes: &[u8]) {
    let mut reader = Reader::new(bytes);
    while let Ok(element) = reader.read() {
        let _ = element.children();
    }
    let mut frames = FrameDecoder::new();
    frames.push(bytes);
    while let Ok(Some(_)) = frames.next_tpdu() {}
    let _ = Tpdu::decode(bytes);
    let _ = session::decode_tsdu(bytes);
    let _ = presentation::decode_connect(bytes);
    let _ = ConnectAccept::decode(bytes);
    let _ = ConnectRefuse::decode(bytes);
    let _ = presentation::decode_abort(bytes);
    let _ = UserData::decode_data(bytes, presentation::Encoding::Full);
    let _ = acse::decode(bytes);
    let _ = External::decode(&igs_iso9506_mms_codec::schema::RawBer(bytes.to_vec()));
    if let Ok(pdu) = mms::decode(bytes) {
        let _ = validate_cbb(&pdu, &all_negotiated());
    }
}

#[test]
fn random_bytes_never_panic() {
    run(any_bytes(), 1.0, |bytes| {
        every_decoder(&bytes);
        Ok(true)
    });
}

/// Valid encodings with one octet changed, inserted or removed: decoded or refused, never a
/// panic, and stable when decoded.
#[test]
fn mutated_encodings_never_panic() {
    let mutated = (
        values::<MMSpdu>(3),
        any::<prop::sample::Index>(),
        any::<u8>(),
        0u8..3,
    )
        .prop_map(|(pdu, at, octet, how)| {
            let mut bytes = mms::encode(&pdu).unwrap();
            let i = at.index(bytes.len() + 1);
            match how {
                0 if i < bytes.len() => bytes[i] = octet,
                1 if i < bytes.len() => {
                    bytes.remove(i);
                }
                _ => bytes.insert(i, octet),
            }
            bytes
        });
    run(mutated, 1.0, |bytes| {
        every_decoder(&bytes);
        if let Ok(pdu) = mms::decode(&bytes) {
            let again = mms::encode(&pdu).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(mms::decode(&again).unwrap(), pdu);
        }
        Ok(true)
    });
}
