// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The session and presentation connection (tasks L3 and L4): CONNECT, ACCEPT and REFUSE, FINISH
//! and DISCONNECT, ABORT, and the data transfer, over a transport connection of class 0 (ITU-T
//! X.225 §6.3.7, §7, §8; X.226 §6, §8).
//!
//! The connection performs no I/O, as the transport connection of task L2 does. It takes
//! [`Event`]s and returns [`Action`]s; the TSDUs it sends go to the transport connection, and the
//! TSDUs that the transport connection delivers come in as [`Event::Received`]. The user data of
//! the CP, CPA and CPR, and of the data transfer, is a [`UserData`] of the presentation layer; the
//! ACSE APDUs and the MMS PDUs of task L4 are its values. Decisions are recorded as D-017 and D-018
//! in `PROVENANCE.md`.

use igs_iso9506_mms_codec::acse;
use igs_iso9506_mms_codec::presentation::{
    self, AcceptNormal, ConnectAccept, ConnectNormal, ConnectRefuse, ContextDefinition,
    ContextResult, Encoding, Mode, UserData,
};
use igs_iso9506_mms_codec::schema::ObjectIdentifier;
use igs_iso9506_mms_codec::session::{
    decode_tsdu, encode_tsdu, Abort, Accept, Connect, ConnectAcceptItem, DataTransfer, Disconnect,
    Finish, GiveTokens, Refuse, Spdu, ABORT_PROTOCOL_ERROR, ABORT_TRANSPORT_RELEASED, ABORT_USER,
    FU_DUPLEX, PROTOCOL_VERSION_2,
};

use crate::config::{ConfigError, LinkConfig};
use crate::transport::{Cause as TransportCause, Role};

/// The abstract syntax of MMS: `mms-abstract-syntax-version1` of ISO 9506-2, module ISO-9506-MMS-1.
pub const MMS_ABSTRACT_SYNTAX: [u64; 5] = [1, 0, 9506, 2, 1];

/// The basic encoding of ASN.1, the transfer syntax of both abstract syntaxes (X.690,
/// basic-encoding).
pub const BASIC_ENCODING: [u64; 3] = [2, 1, 1];

/// Presentation context identifier of ACSE. Identifiers are odd integers (X.226 §6.2.2.7).
pub const ACSE_CONTEXT: i64 = 1;

/// Presentation context identifier of MMS (decision D-017).
pub const MMS_CONTEXT: i64 = 3;

/// Session reason code of a refusal by the called SS-user, whose user data is the CPR (X.225
/// §8.3.5.10, code 2).
pub const REFUSED_BY_USER: u8 = 2;

/// Session reason code 128 + 1: the session selector is unknown (X.225 §8.3.5.10).
const SESSION_SELECTOR_UNKNOWN: u8 = 129;

/// Presentation provider reason 3: the called presentation address is unknown (X.226 §6.2.4.9).
const PRESENTATION_ADDRESS_UNKNOWN: i64 = 3;

/// Presentation provider reason 0: not specified (X.226 §6.2.4.9).
const REASON_NOT_SPECIFIED: i64 = 0;

/// The origin of an abort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The user of the other end aborted.
    User,
    /// The provider aborted, or a protocol error was found.
    Provider,
    /// The transport connection was lost.
    Transport,
}

/// An input of the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Initiator: request the connection, with the user data of the CP.
    Connect(Option<UserData>),
    /// Responder: accept the connection that was indicated, with the user data of the CPA.
    Accept(Option<UserData>),
    /// Responder: refuse the connection that was indicated, with the user data of the CPR.
    Refuse(Option<UserData>),
    /// Send user data in the data transfer; its PDVs name the presentation contexts.
    Data(UserData),
    /// Release the connection in an orderly way (FINISH, then DISCONNECT).
    Release,
    /// Abort the connection, with the user (the MMS abort has no PDU of its own).
    Abort,
    /// Abort the connection with a protocol error found above: an ABORT that names the provider.
    ProviderAbort,
    /// A TSDU delivered by the transport connection.
    Received(Vec<u8>),
    /// The transport connection is closed, for the cause given.
    TransportClosed(TransportCause),
}

/// An output of the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// A TSDU for the transport connection.
    Send(Vec<u8>),
    /// Responder: a connection request is indicated, with the user data of its CP. Answer with
    /// [`Event::Accept`] or [`Event::Refuse`].
    ConnectIndication(Option<UserData>),
    /// The session and presentation connection is established, with the user data of the CPA.
    Connected(Option<UserData>),
    /// The connection request is refused, with this session reason code, and the user data of the
    /// CPR when it carries some.
    Refused(u8, Option<UserData>),
    /// User data received in the data transfer.
    Data(UserData),
    /// The orderly release is complete.
    Released,
    /// The connection is aborted.
    Aborted(Origin),
    /// The transport connection is no longer needed: release it.
    ReleaseTransport,
    /// The event is refused and the state is unchanged, because the caller misused the connection.
    Misuse(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
    Idle,
    /// Initiator: CONNECT sent.
    Connecting,
    /// Responder: CONNECT received; the contexts proposed are kept until the answer.
    Indicated(Vec<ContextDefinition>),
    Open,
    /// FINISH sent; DISCONNECT awaited.
    Releasing,
    Closed,
}

/// One session and presentation connection, as a state machine.
#[derive(Debug, Clone)]
pub struct Connection {
    role: Role,
    config: LinkConfig,
    state: State,
}

impl Connection {
    /// A connection in the idle state, for a configuration that passes [`LinkConfig::validate`].
    pub fn new(role: Role, config: LinkConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            role,
            config,
            state: State::Idle,
        })
    }

    /// Whether the connection is open.
    pub fn is_open(&self) -> bool {
        self.state == State::Open
    }

    /// Whether the connection is closed, for good.
    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// Takes an event, and returns the actions it causes.
    pub fn handle(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::Connect(user_data) => self.connect(user_data),
            Event::Accept(user_data) => self.answer(true, user_data),
            Event::Refuse(user_data) => self.answer(false, user_data),
            Event::Data(user_data) => self.data_out(&user_data),
            Event::Release => self.release(),
            Event::Abort => self.abort(),
            Event::ProviderAbort => self.protocol_error(),
            Event::Received(bytes) => self.received(&bytes),
            Event::TransportClosed(cause) => self.transport_closed(cause),
        }
    }

    fn connect(&mut self, user_data: Option<UserData>) -> Vec<Action> {
        if self.role != Role::Initiator || self.state != State::Idle {
            return vec![Action::Misuse("connect needs an idle initiator")];
        }
        let connect = presentation::Connect {
            mode: Mode::Normal,
            x410_parameters: None,
            normal: Some(ConnectNormal {
                protocol_version: Some(acse::version1()),
                calling_selector: self.config.calling_psap.clone(),
                called_selector: self.config.called_psap.clone(),
                context_definitions: Some(proposed_contexts()),
                user_data,
                ..ConnectNormal::default()
            }),
        };
        let Ok(cp) = presentation::encode_connect(&connect, &[]) else {
            return vec![Action::Misuse("the CP PPDU does not encode")];
        };
        let spdu = Spdu::Connect(Connect {
            item: Some(item()),
            session_user_requirements: Some(FU_DUPLEX),
            calling_selector: self.config.calling_ssap.clone(),
            called_selector: self.config.called_ssap.clone(),
            user_data: Some(cp),
            ..Connect::default()
        });
        match send(&[spdu]) {
            Ok(tsdu) => {
                self.state = State::Connecting;
                vec![Action::Send(tsdu)]
            }
            Err(message) => vec![Action::Misuse(message)],
        }
    }

    /// Responder: ACCEPT with the user data of the CPA, or REFUSE with a CPR that gives each
    /// context a user rejection and carries the user data.
    fn answer(&mut self, accepted: bool, user_data: Option<UserData>) -> Vec<Action> {
        let State::Indicated(contexts) = self.state.clone() else {
            return vec![Action::Misuse(
                "accept or refuse needs an indicated connection",
            )];
        };
        if accepted {
            let cpa = ConnectAccept {
                mode: Mode::Normal,
                x410_parameters: None,
                normal: Some(AcceptNormal {
                    responding_selector: self.config.called_psap.clone(),
                    context_results: Some(contexts.iter().map(judge).collect()),
                    user_data: user_data.clone(),
                    ..AcceptNormal::default()
                }),
            };
            let Ok(cpa_bytes) = cpa.encode() else {
                return vec![Action::Misuse("the CPA does not encode")];
            };
            let spdu = Spdu::Accept(Accept {
                item: Some(item()),
                session_user_requirements: Some(FU_DUPLEX),
                responding_selector: self.config.called_ssap.clone(),
                user_data: Some(cpa_bytes),
                ..Accept::default()
            });
            match send(&[spdu]) {
                Ok(tsdu) => {
                    self.state = State::Open;
                    vec![Action::Send(tsdu), Action::Connected(user_data)]
                }
                Err(message) => vec![Action::Misuse(message)],
            }
        } else {
            let results = contexts
                .iter()
                .map(|_| ContextResult {
                    result: 1,
                    transfer_syntax: None,
                    provider_reason: None,
                })
                .collect();
            let cpr = ConnectRefuse {
                responding_selector: self.config.called_psap.clone(),
                context_results: Some(results),
                user_data: user_data.clone(),
                ..ConnectRefuse::default()
            };
            match self.refusal_by_user(&cpr) {
                Ok(spdu) => self.refuse_with(&spdu, REFUSED_BY_USER, user_data),
                Err(message) => vec![Action::Misuse(message)],
            }
        }
    }

    /// The REFUSE that carries a CPR: reason 2, then the CPR.
    fn refusal_by_user(&self, cpr: &ConnectRefuse) -> Result<Spdu, &'static str> {
        let cpr_bytes = cpr.encode().map_err(|_| "the CPR does not encode")?;
        let mut reason = vec![REFUSED_BY_USER];
        reason.extend(cpr_bytes);
        Ok(Spdu::Refuse(Refuse {
            transport_disconnect: Some(TRANSPORT_RELEASED),
            reason: Some(reason),
            ..Refuse::default()
        }))
    }

    /// Sends a REFUSE and closes: the transport connection is released with it.
    fn refuse_with(&mut self, spdu: &Spdu, code: u8, user_data: Option<UserData>) -> Vec<Action> {
        match send(std::slice::from_ref(spdu)) {
            Ok(tsdu) => {
                self.state = State::Closed;
                vec![
                    Action::Send(tsdu),
                    Action::Refused(code, user_data),
                    Action::ReleaseTransport,
                ]
            }
            Err(message) => vec![Action::Misuse(message)],
        }
    }

    fn data_out(&mut self, user_data: &UserData) -> Vec<Action> {
        if self.state != State::Open {
            return vec![Action::Misuse("data needs an open connection")];
        }
        let Ok(bytes) = user_data.encode_data() else {
            return vec![Action::Misuse("the user data does not encode")];
        };
        // A DATA TRANSFER follows a GIVE TOKENS in one TSDU (X.225 §6.3.7, basic concatenation).
        let spdus = [
            Spdu::GiveTokens(GiveTokens::default()),
            Spdu::DataTransfer(DataTransfer {
                user_information: bytes,
                ..DataTransfer::default()
            }),
        ];
        match send(&spdus) {
            Ok(tsdu) => vec![Action::Send(tsdu)],
            Err(message) => vec![Action::Misuse(message)],
        }
    }

    fn release(&mut self) -> Vec<Action> {
        if self.state != State::Open {
            return vec![Action::Misuse("release needs an open connection")];
        }
        // The transport stays open for the DISCONNECT that answers (transport disconnect 0).
        let finish = Spdu::Finish(Finish {
            transport_disconnect: Some(0),
            ..Finish::default()
        });
        match send(&[finish]) {
            Ok(tsdu) => {
                self.state = State::Releasing;
                vec![Action::Send(tsdu)]
            }
            Err(message) => vec![Action::Misuse(message)],
        }
    }

    fn abort(&mut self) -> Vec<Action> {
        if self.is_closed() || self.state == State::Idle {
            return vec![Action::Misuse("abort needs a connection in progress")];
        }
        let spdu = Spdu::Abort(Abort {
            transport_disconnect: ABORT_USER | ABORT_TRANSPORT_RELEASED,
            // The MMS abort has no PDU of its own (ISO 9506-2 §24.4), so no user data follows the
            // user bit (X.225 §8.3.9.6 makes the User Data parameter optional).
            user_data: None,
            ..Abort::default()
        });
        match send(&[spdu]) {
            Ok(tsdu) => {
                self.state = State::Closed;
                vec![
                    Action::Send(tsdu),
                    Action::Aborted(Origin::User),
                    Action::ReleaseTransport,
                ]
            }
            Err(message) => vec![Action::Misuse(message)],
        }
    }

    fn received(&mut self, bytes: &[u8]) -> Vec<Action> {
        if self.is_closed() {
            return Vec::new();
        }
        let spdus = match decode_tsdu(bytes) {
            Ok(spdus) => spdus,
            Err(_) => return self.protocol_error(),
        };
        match spdus.as_slice() {
            [Spdu::GiveTokens(_), Spdu::DataTransfer(data)] => self.data_in(&data.user_information),
            [spdu] => self.single(spdu.clone()),
            _ => self.protocol_error(),
        }
    }

    fn data_in(&mut self, bytes: &[u8]) -> Vec<Action> {
        if !matches!(self.state, State::Open | State::Releasing) {
            return self.protocol_error();
        }
        match UserData::decode_data(bytes, Encoding::Full) {
            Ok(user_data) => vec![Action::Data(user_data)],
            Err(_) => self.protocol_error(),
        }
    }

    /// One SPDU of a TSDU, dispatched on the state.
    fn single(&mut self, spdu: Spdu) -> Vec<Action> {
        let state = self.state.clone();
        match (state, self.role, spdu) {
            (State::Idle, Role::Responder, Spdu::Connect(connect)) => self.indicate(&connect),
            (State::Connecting, Role::Initiator, Spdu::Accept(accept)) => self.confirmed(&accept),
            (State::Connecting, Role::Initiator, Spdu::Refuse(refuse)) => self.refused(&refuse),
            (
                State::Open | State::Releasing | State::Connecting | State::Indicated(_),
                _,
                Spdu::Abort(abort),
            ) => {
                let origin = if abort.transport_disconnect & ABORT_USER != 0 {
                    Origin::User
                } else {
                    Origin::Provider
                };
                self.state = State::Closed;
                vec![Action::Aborted(origin), Action::ReleaseTransport]
            }
            (State::Open | State::Releasing, _, Spdu::Finish(_)) => {
                // The DISCONNECT answers the FINISH at once: no user is waiting at this layer.
                let disconnect = Spdu::Disconnect(Disconnect::default());
                self.state = State::Closed;
                match send(&[disconnect]) {
                    Ok(tsdu) => vec![
                        Action::Send(tsdu),
                        Action::Released,
                        Action::ReleaseTransport,
                    ],
                    Err(message) => vec![Action::Misuse(message)],
                }
            }
            (State::Releasing, _, Spdu::Disconnect(_)) => {
                self.state = State::Closed;
                vec![Action::Released, Action::ReleaseTransport]
            }
            (State::Open, _, Spdu::GiveTokens(_)) => Vec::new(),
            _ => self.protocol_error(),
        }
    }

    /// Initiator: the ACCEPT carries the CPA; the connection is open, with its user data.
    fn confirmed(&mut self, accept: &Accept) -> Vec<Action> {
        let Some(bytes) = accept.user_data.as_deref() else {
            return self.protocol_error();
        };
        let normal = match ConnectAccept::decode(bytes) {
            Ok(ConnectAccept {
                mode: Mode::Normal,
                normal: Some(normal),
                ..
            }) => normal,
            _ => return self.protocol_error(),
        };
        // The results follow the order of the CP: the ACSE context, then the MMS context. Without
        // both, the association cannot be carried (ISO 9506-2 §A.5).
        let results = normal.context_results.unwrap_or_default();
        let accepted = |index: usize| results.get(index).is_some_and(|result| result.result == 0);
        let required_accepted = accepted(0) && accepted(1);
        if !required_accepted {
            return self.protocol_error();
        }
        self.state = State::Open;
        vec![Action::Connected(normal.user_data)]
    }

    /// Initiator: a REFUSE; with reason 2 it carries a CPR, whose user data is passed up.
    fn refused(&mut self, refuse: &Refuse) -> Vec<Action> {
        let reason = refuse.reason.clone().unwrap_or_default();
        let (code, rest) = match reason.split_first() {
            Some((&code, rest)) => (code, rest),
            None => (REFUSED_BY_USER, &[][..]),
        };
        let user_data = if code == REFUSED_BY_USER && !rest.is_empty() {
            ConnectRefuse::decode(rest)
                .ok()
                .and_then(|cpr| cpr.user_data)
        } else {
            None
        };
        self.state = State::Closed;
        vec![Action::Refused(code, user_data), Action::ReleaseTransport]
    }

    /// Responder: checks the CONNECT against the configured addresses, then indicates it.
    fn indicate(&mut self, connect: &Connect) -> Vec<Action> {
        let Some(bytes) = connect.user_data.as_deref() else {
            return self.protocol_error();
        };
        let Ok((cp, _)) = presentation::decode_connect(bytes) else {
            return self.protocol_error();
        };
        let session_mismatch = self
            .config
            .called_ssap
            .as_ref()
            .is_some_and(|ours| connect.called_selector.as_ref() != Some(ours));
        if session_mismatch {
            let refusal = Spdu::Refuse(Refuse {
                transport_disconnect: Some(TRANSPORT_RELEASED),
                reason: Some(vec![SESSION_SELECTOR_UNKNOWN]),
                ..Refuse::default()
            });
            return self.refuse_with(&refusal, SESSION_SELECTOR_UNKNOWN, None);
        }
        let Some(normal) = cp.normal.as_ref().filter(|_| cp.mode == Mode::Normal) else {
            return self.refuse_by_presentation(REASON_NOT_SPECIFIED);
        };
        let presentation_mismatch = self
            .config
            .called_psap
            .as_ref()
            .is_some_and(|ours| normal.called_selector.as_ref() != Some(ours));
        if presentation_mismatch {
            return self.refuse_by_presentation(PRESENTATION_ADDRESS_UNKNOWN);
        }
        let contexts = normal.context_definitions.clone().unwrap_or_default();
        let user_data = normal.user_data.clone();
        self.state = State::Indicated(contexts);
        vec![Action::ConnectIndication(user_data)]
    }

    /// Responder: refuses by the presentation provider, with a CPR that gives its reason.
    fn refuse_by_presentation(&mut self, provider_reason: i64) -> Vec<Action> {
        let cpr = ConnectRefuse {
            responding_selector: self.config.called_psap.clone(),
            provider_reason: Some(provider_reason),
            ..ConnectRefuse::default()
        };
        match self.refusal_by_user(&cpr) {
            Ok(spdu) => self.refuse_with(&spdu, REFUSED_BY_USER, None),
            Err(message) => vec![Action::Misuse(message)],
        }
    }

    fn transport_closed(&mut self, _cause: TransportCause) -> Vec<Action> {
        match self.state {
            State::Idle | State::Closed => Vec::new(),
            _ => {
                self.state = State::Closed;
                vec![Action::Aborted(Origin::Transport)]
            }
        }
    }

    /// Sends an ABORT for a protocol error, and closes.
    fn protocol_error(&mut self) -> Vec<Action> {
        if self.is_closed() {
            return Vec::new();
        }
        self.state = State::Closed;
        let spdu = Spdu::Abort(Abort {
            transport_disconnect: ABORT_PROTOCOL_ERROR | ABORT_TRANSPORT_RELEASED,
            ..Abort::default()
        });
        match send(&[spdu]) {
            Ok(tsdu) => vec![
                Action::Send(tsdu),
                Action::Aborted(Origin::Provider),
                Action::ReleaseTransport,
            ],
            Err(message) => vec![Action::Misuse(message)],
        }
    }
}

/// Transport disconnect bit 1 of a REFUSE or FINISH: the transport connection is released.
const TRANSPORT_RELEASED: u8 = 1;

fn item() -> ConnectAcceptItem {
    ConnectAcceptItem {
        version_number: PROTOCOL_VERSION_2,
        ..ConnectAcceptItem::default()
    }
}

/// The contexts of MMS and ACSE, both in the basic encoding.
fn proposed_contexts() -> Vec<ContextDefinition> {
    vec![
        ContextDefinition {
            id: ACSE_CONTEXT,
            abstract_syntax: ObjectIdentifier(acse::ABSTRACT_SYNTAX.to_vec()),
            transfer_syntaxes: vec![ObjectIdentifier(BASIC_ENCODING.to_vec())],
        },
        ContextDefinition {
            id: MMS_CONTEXT,
            abstract_syntax: ObjectIdentifier(MMS_ABSTRACT_SYNTAX.to_vec()),
            transfer_syntaxes: vec![ObjectIdentifier(BASIC_ENCODING.to_vec())],
        },
    ]
}

/// The answer to a proposed context: accepted when this end supports its abstract syntax (ACSE or
/// MMS) and the basic encoding; otherwise a provider rejection with its reason (X.226 §6.2.4.9).
fn judge(context: &ContextDefinition) -> ContextResult {
    let supported = context.abstract_syntax.0 == acse::ABSTRACT_SYNTAX
        || context.abstract_syntax.0 == MMS_ABSTRACT_SYNTAX;
    let basic = context
        .transfer_syntaxes
        .iter()
        .any(|t| t.0 == BASIC_ENCODING);
    if !supported {
        rejected(1)
    } else if !basic {
        rejected(2)
    } else {
        ContextResult {
            result: 0,
            transfer_syntax: Some(ObjectIdentifier(BASIC_ENCODING.to_vec())),
            provider_reason: None,
        }
    }
}

fn rejected(reason: i64) -> ContextResult {
    ContextResult {
        result: 2,
        transfer_syntax: None,
        provider_reason: Some(reason),
    }
}

fn send(spdus: &[Spdu]) -> Result<Vec<u8>, &'static str> {
    encode_tsdu(spdus).map_err(|_| "the SPDU does not encode")
}
