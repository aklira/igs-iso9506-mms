// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The MMS application association (task L4): the ACSE association that carries the Initiate, the
//! negotiation of its parameters and conformance building blocks, the conclusion and the abort
//! (ISO 9506-1 §8.2; ISO 9506-2 §8.2, §8.3, §24, Annex A; ITU-T X.227).
//!
//! The connection performs no I/O. It owns the presentation connection of task L3 and takes the
//! TSDUs of the transport connection of task L2 as [`Event::Received`]. Decisions are recorded as
//! D-018 in `PROVENANCE.md`.

use igs_iso9506_mms_codec::acse::{
    self, AAREApdu, AAREApduProtocolVersion, AARQApdu, AARQApduProtocolVersion, ACSEApdu,
    ApplicationContextName, AssociateResult, AssociateSourceDiagnostic,
    AssociateSourceDiagnosticAcseServiceUser, AssociationInformation, RLREApdu, RLRQApdu,
    ReleaseRequestReason, ReleaseResponseReason,
};
use igs_iso9506_mms_codec::generated::types::{
    AEQualifier, AEQualifierForm2, APTitle, APTitleForm2, InitiateResponsePDUInitResponseDetail,
    ParameterSupportOptions, ServiceErrorErrorClass, ServiceErrorErrorClassInitiate,
    ServiceSupportOptions,
};
use igs_iso9506_mms_codec::mms::{
    self, CbbError, InitiateErrorPDU, InitiateRequestPDU, InitiateResponsePDU, Integer16, Integer8,
    MMSpdu, Negotiated, ServiceError,
};
use igs_iso9506_mms_codec::presentation::{Pdv, PdvValues, UserData};
use igs_iso9506_mms_codec::schema::{BitString, ObjectIdentifier, RawBer};

use crate::config::{ApplicationContext, ConfigError, LinkConfig};
use crate::transport::{Cause as TransportCause, Role};
use crate::upper::{self, Origin, ACSE_CONTEXT, MMS_ABSTRACT_SYNTAX, MMS_CONTEXT};

/// The application context of MMS: `mms-application-context-version1` (ISO 9506-2 §A.7).
pub const MMS_APPLICATION_CONTEXT: [u64; 5] = [1, 0, 9506, 2, 5];

/// The application context name `1.0.9506.2.3`: the arc of the MMS annex module, which the reference
/// peer of the bench proposes (`docs/capabilities.md`, G13). A responder accepts it, and answers with
/// the name it was proposed (decision D-027). The initiator proposes [`MMS_APPLICATION_CONTEXT`] only.
pub const LEGACY_MMS_APPLICATION_CONTEXT: [u64; 5] = [1, 0, 9506, 2, 3];

/// The minor version number of ISO 9506-1 and ISO 9506-2 (ISO 9506-2 §24.11).
pub const MMS_VERSION: i64 = 4;

/// The least nesting level of TASE.2 (IEC 60870-6-702, stack requirements); a negotiated level below
/// it refuses the association (D-018).
pub const MIN_NESTING_LEVEL: i64 = 2;

/// What this end supports: the parameter CBBs and the services it serves (ISO 9506-1 §8.2.1.1.6,
/// §8.2.1.1.8). The limits of the association come from the [`LinkConfig`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    /// The parameter conformance building blocks supported (ISO 9506-2 §8.1.3.15).
    pub parameter_cbb: BitString,
    /// The services supported (ISO 9506-2 §8.1.3.14).
    pub services: BitString,
}

/// Why an association or a connection request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The ACSE association was rejected, with the result and the diagnostic of the AARE and, when
    /// the MMS negotiation failed, the Initiate-ErrorPDU.
    Rejected {
        /// The AssociateResult.
        result: i64,
        /// The diagnostic of the ACSE service user.
        diagnostic: i64,
        /// The Initiate-ErrorPDU, when the negotiation failed.
        error: Option<ServiceError>,
    },
    /// The presentation or session connection was refused, with its reason code.
    Provider(u8),
}

/// The answer of the called MMS user to an Initiate request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Accept the association, if its parameters can be negotiated.
    Accept,
    /// Refuse the association.
    Reject,
}

/// An input of the association.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Initiator: request an association with this Initiate-RequestPDU.
    Associate(InitiateRequestPDU),
    /// Responder: answer the Initiate request that was indicated.
    Answer(Answer),
    /// Send an MMS PDU in the association.
    Send(MMSpdu),
    /// Conclude the association: the CONCLUDE request, then the release of ACSE.
    Conclude,
    /// Abort the association, with the user.
    Abort,
    /// A TSDU delivered by the transport connection.
    Received(Vec<u8>),
    /// The transport connection is closed, for the cause given.
    TransportClosed(TransportCause),
}

/// The identity of the calling side, as its AARQ states it (ISO 8650-1 §6.1): the AP-title and the AE qualifier.
/// The responder indicates it before the Initiate request, so that the model can admit or refuse the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Calling {
    /// The AP-title of the calling application process, if the AARQ gives one.
    pub ap_title: Option<APTitle>,
    /// The AE qualifier of the calling application entity, if the AARQ gives one.
    pub ae_qualifier: Option<AEQualifier>,
}

/// An output of the association.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Responder: the identity of the calling side, indicated before [`Action::Indication`].
    Calling(Calling),
    /// A TSDU for the transport connection.
    Send(Vec<u8>),
    /// The transport connection is no longer needed: release it.
    ReleaseTransport,
    /// Responder: an Initiate request is indicated; answer it with [`Event::Answer`].
    Indication(InitiateRequestPDU),
    /// The association is established, with the Initiate response that negotiated it.
    Established(InitiateResponsePDU),
    /// The association is refused.
    Refused(Refusal),
    /// An MMS PDU received, that the negotiation allows.
    Pdu(MMSpdu),
    /// An MMS PDU received, that the negotiation does not allow: the caller answers it with a
    /// Reject PDU (ISO 9506-1 §8.2.1.1.8).
    Unsupported(MMSpdu, CbbError),
    /// A CONCLUDE request is received; it is answered when the release of ACSE arrives.
    ConcludeIndication,
    /// The association is released in an orderly way.
    Concluded,
    /// The association is aborted.
    Aborted(Origin),
    /// The event is refused and the state is unchanged, because the caller misused the association.
    Misuse(&'static str),
}

/// The negotiated view of an established association: what each end serves.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Session {
    /// Served by this end.
    me: Negotiated,
    /// Served by the other end.
    peer: Negotiated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
    Idle,
    /// Initiator: the AARQ is sent, with its Initiate request.
    Associating(InitiateRequestPDU),
    /// Responder: the AARQ is indicated, with its Initiate request.
    Indicated(InitiateRequestPDU),
    Open(Session),
    /// The CONCLUDE request is sent and its ACSE release awaited.
    Concluding(Session),
    /// The ACSE release is answered, and the session release awaited.
    Answered(Session),
    Closed,
}

/// One MMS application association, as a state machine over the presentation connection.
#[derive(Debug, Clone)]
pub struct Association {
    role: Role,
    config: LinkConfig,
    capabilities: Capabilities,
    upper: upper::Connection,
    state: State,
    /// Whether the parameter CBBs proposed are taken as negotiated for the checks of outgoing PDUs,
    /// for a peer that answers services whose CBBs it did not negotiate (`docs/capabilities.md`, G8).
    lenient_parameter_cbbs: bool,
    /// The application context name of the association: the one proposed by the initiator, as the
    /// responder answers with it.
    context: ApplicationContextName,
}

impl Association {
    /// An association in the idle state, for valid limits (see [`LinkConfig::validate`]).
    pub fn new(
        role: Role,
        config: LinkConfig,
        capabilities: Capabilities,
    ) -> Result<Self, ConfigError> {
        let upper = upper::Connection::new(role, config.clone())?;
        Ok(Self {
            role,
            config,
            capabilities,
            upper,
            state: State::Idle,
            lenient_parameter_cbbs: false,
            context: mms_context_name(),
        })
    }

    /// Takes the parameter CBBs proposed as negotiated for the checks of outgoing PDUs. Off by default:
    /// the peer's answer is what the standard says is negotiated. See `docs/capabilities.md`, G8.
    pub fn set_lenient_parameter_cbbs(&mut self, on: bool) {
        self.lenient_parameter_cbbs = on;
    }

    /// Whether the association is established.
    pub fn is_open(&self) -> bool {
        matches!(self.state, State::Open(_))
    }

    /// Whether the association is closed, for good.
    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// Takes an event, and returns the actions it causes.
    pub fn handle(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::Associate(request) => self.associate(request),
            Event::Answer(answer) => self.answer(answer),
            Event::Send(pdu) => self.send(pdu),
            Event::Conclude => self.conclude(),
            Event::Abort => {
                let actions = self.upper.handle(upper::Event::Abort);
                self.lower(actions)
            }
            Event::Received(tsdu) => {
                let actions = self.upper.handle(upper::Event::Received(tsdu));
                self.lower(actions)
            }
            Event::TransportClosed(cause) => {
                let actions = self.upper.handle(upper::Event::TransportClosed(cause));
                self.lower(actions)
            }
        }
    }

    fn associate(&mut self, request: InitiateRequestPDU) -> Vec<Action> {
        if self.role != Role::Initiator || self.state != State::Idle {
            return vec![Action::Misuse("associate needs an idle initiator")];
        }
        let mms = match mms::encode(&MMSpdu::InitiateRequestPDU(request.clone())) {
            Ok(bytes) => bytes,
            Err(_) => return vec![Action::Misuse("the Initiate request does not encode")],
        };
        let aarq = ACSEApdu::Aarq(AARQApdu {
            protocol_version: Some(AARQApduProtocolVersion(acse::version1())),
            application_context_name: context_name(self.config.application_context),
            called_ap_title: self
                .config
                .called_ap_title
                .clone()
                .map(|oid| APTitle::ApTitleForm2(APTitleForm2(oid))),
            called_ae_qualifier: self.config.called_ae_qualifier.map(ae_qualifier),
            called_ap_invocation_identifier: None,
            called_ae_invocation_identifier: None,
            // The AP-title of this end, as its configuration gives it (ISO 8650-1 §6.1.2).
            calling_ap_title: self
                .config
                .ap_title
                .clone()
                .map(|oid| APTitle::ApTitleForm2(APTitleForm2(oid))),
            calling_ae_qualifier: self.config.calling_ae_qualifier.map(ae_qualifier),
            calling_ap_invocation_identifier: None,
            calling_ae_invocation_identifier: None,
            sender_acse_requirements: None,
            mechanism_name: None,
            calling_authentication_value: None,
            application_context_name_list: None,
            implementation_information: None,
            user_information: match information(&mms) {
                Ok(information) => Some(information),
                Err(message) => return vec![Action::Misuse(message)],
            },
        });
        let Ok(acse_bytes) = acse::encode(&aarq) else {
            return vec![Action::Misuse("the AARQ does not encode")];
        };
        let actions = self
            .upper
            .handle(upper::Event::Connect(Some(acse_user_data(acse_bytes))));
        if actions
            .iter()
            .any(|action| matches!(action, upper::Action::Misuse(_)))
        {
            return self.lower(actions);
        }
        self.state = State::Associating(request);
        self.lower(actions)
    }

    /// Responder: the answer to the Initiate request, which negotiates the parameters.
    fn answer(&mut self, answer: Answer) -> Vec<Action> {
        let State::Indicated(request) = self.state.clone() else {
            return vec![Action::Misuse("answer needs an indicated association")];
        };
        match answer {
            Answer::Reject => self.reject(1, None),
            Answer::Accept => match negotiate(&request, &self.capabilities, &self.config) {
                Ok(response) => self.accept(&request, response),
                Err(error) => self.reject(1, Some(error)),
            },
        }
    }

    /// Responder: accepts with an AARE that carries the Initiate response (ISO 9506-2 §24.2).
    fn accept(
        &mut self,
        request: &InitiateRequestPDU,
        response: InitiateResponsePDU,
    ) -> Vec<Action> {
        let mms = match mms::encode(&MMSpdu::InitiateResponsePDU(response.clone())) {
            Ok(bytes) => bytes,
            Err(_) => return vec![Action::Misuse("the Initiate response does not encode")],
        };
        let aare = ACSEApdu::Aare(aare(
            AssociateResult::ACCEPTED,
            AssociateSourceDiagnosticAcseServiceUser::NULL,
            match information(&mms) {
                Ok(information) => Some(information),
                Err(message) => return vec![Action::Misuse(message)],
            },
            self.context.clone(),
        ));
        let Ok(acse_bytes) = acse::encode(&aare) else {
            return vec![Action::Misuse("the AARE does not encode")];
        };
        let actions = self
            .upper
            .handle(upper::Event::Accept(Some(acse_user_data(acse_bytes))));
        let mut out = self.lower(actions);
        if self.upper.is_open() {
            self.state = State::Open(Session {
                me: Negotiated::served_by_called(&response),
                peer: Negotiated::served_by_calling(request, &response),
            });
            out.push(Action::Established(response));
        }
        out
    }

    /// Responder: refuses with an AARE rejected by the ACSE service user, carrying the
    /// Initiate-ErrorPDU of a failed negotiation.
    fn reject(&mut self, diagnostic: i64, error: Option<ServiceError>) -> Vec<Action> {
        let diagnostic = AssociateSourceDiagnosticAcseServiceUser(diagnostic);
        let user_information = match error {
            Some(error) => {
                let mms = match mms::encode(&MMSpdu::InitiateErrorPDU(InitiateErrorPDU(error))) {
                    Ok(bytes) => bytes,
                    Err(_) => return vec![Action::Misuse("the Initiate error does not encode")],
                };
                match information(&mms) {
                    Ok(information) => Some(information),
                    Err(message) => return vec![Action::Misuse(message)],
                }
            }
            None => None,
        };
        let aare = ACSEApdu::Aare(aare(
            AssociateResult::REJECTED_PERMANENT,
            diagnostic,
            user_information,
            self.context.clone(),
        ));
        let Ok(acse_bytes) = acse::encode(&aare) else {
            return vec![Action::Misuse("the AARE does not encode")];
        };
        let actions = self
            .upper
            .handle(upper::Event::Refuse(Some(acse_user_data(acse_bytes))));
        self.lower(actions)
    }

    /// Translates the actions of the presentation connection.
    fn lower(&mut self, actions: Vec<upper::Action>) -> Vec<Action> {
        let mut out = Vec::new();
        for action in actions {
            match action {
                upper::Action::Send(tsdu) => out.push(Action::Send(tsdu)),
                upper::Action::ReleaseTransport => out.push(Action::ReleaseTransport),
                upper::Action::Misuse(message) => out.push(Action::Misuse(message)),
                upper::Action::ConnectIndication(user_data) => {
                    out.extend(self.indicated(user_data))
                }
                // The responder's CPA is answered by `accept`; only the initiator confirms.
                upper::Action::Connected(user_data) => {
                    if self.role == Role::Initiator {
                        out.extend(self.confirmed(user_data));
                    }
                }
                upper::Action::Refused(code, user_data) => {
                    out.extend(self.refused(code, user_data))
                }
                upper::Action::Data(user_data) => out.extend(self.received_data(user_data)),
                upper::Action::Released => {
                    self.state = State::Closed;
                    out.push(Action::Concluded);
                }
                upper::Action::Aborted(origin) => {
                    self.state = State::Closed;
                    out.push(Action::Aborted(origin));
                }
            }
        }
        out
    }

    /// Responder: the AARQ carries the Initiate request in the MMS context. Anything else is
    /// refused with an AARE of the diagnostic that says why.
    fn indicated(&mut self, user_data: Option<UserData>) -> Vec<Action> {
        let Some(ACSEApdu::Aarq(aarq)) = user_data.as_ref().and_then(acse_of) else {
            return self.reject(1, None);
        };
        let proposed = aarq.application_context_name.clone();
        if proposed != mms_context_name() && proposed != legacy_context_name() {
            return self.reject(2, None);
        }
        self.context = proposed;
        let Some(request) = aarq
            .user_information
            .as_ref()
            .and_then(mms_initiate_request)
        else {
            return self.reject(1, None);
        };
        self.state = State::Indicated(request.clone());
        let calling = Calling {
            ap_title: aarq.calling_ap_title.clone(),
            ae_qualifier: aarq.calling_ae_qualifier.clone(),
        };
        vec![Action::Calling(calling), Action::Indication(request)]
    }

    /// Initiator: the CPA carries the AARE, whose Initiate response negotiates the association.
    fn confirmed(&mut self, user_data: Option<UserData>) -> Vec<Action> {
        let State::Associating(request) = self.state.clone() else {
            return vec![Action::Misuse("no association is being requested")];
        };
        let Some(ACSEApdu::Aare(aare)) = user_data.as_ref().and_then(acse_of) else {
            return self.provider_abort();
        };
        if aare.result != AssociateResult::ACCEPTED {
            return self.provider_abort();
        }
        let Some(response) = aare
            .user_information
            .as_ref()
            .and_then(mms_initiate_response)
        else {
            return self.provider_abort();
        };
        if !response_within_request(&request, &response) {
            return self.provider_abort();
        }
        self.state = State::Open(Session {
            me: Negotiated::served_by_calling(&request, &response),
            peer: self.peer_view(&request, &response),
        });
        vec![Action::Established(response)]
    }

    /// The refusal of the association: its AARE when the CPR carries one, else the provider reason.
    fn refused(&mut self, code: u8, user_data: Option<UserData>) -> Vec<Action> {
        self.state = State::Closed;
        let refusal = match user_data.as_ref().and_then(acse_of) {
            Some(ACSEApdu::Aare(aare)) => Refusal::Rejected {
                result: aare.result.0,
                diagnostic: diagnostic_of(&aare),
                error: aare.user_information.as_ref().and_then(mms_initiate_error),
            },
            _ => Refusal::Provider(code),
        };
        vec![Action::Refused(refusal)]
    }

    /// Sends user data in the data transfer.
    fn send_user_data(&mut self, user_data: UserData) -> Vec<Action> {
        let actions = self.upper.handle(upper::Event::Data(user_data));
        self.lower(actions)
    }

    fn provider_abort(&mut self) -> Vec<Action> {
        let actions = self.upper.handle(upper::Event::ProviderAbort);
        self.lower(actions)
    }

    /// An MMS PDU or an ACSE APDU received in the data transfer.
    fn received_data(&mut self, user_data: UserData) -> Vec<Action> {
        if let Some(acse_pdu) = acse_of(&user_data) {
            return self.release_apdu(acse_pdu);
        }
        let Some(pdu) = user_data_mms(&user_data) else {
            return self.provider_abort();
        };
        if matches!(pdu, MMSpdu::ConcludeRequestPDU(_)) {
            // Answered at once, as the CONCLUDE response of the MMS user (accepting every request).
            let response = match mms::encode(&MMSpdu::ConcludeResponsePDU(
                igs_iso9506_mms_codec::mms::ConcludeResponsePDU(()),
            )) {
                Ok(bytes) => mms_user_data(bytes),
                Err(_) => return vec![Action::Misuse("the CONCLUDE response does not encode")],
            };
            let mut out = vec![Action::ConcludeIndication];
            out.extend(self.send_user_data(response));
            return out;
        }
        if matches!(
            pdu,
            MMSpdu::InitiateRequestPDU(_)
                | MMSpdu::InitiateResponsePDU(_)
                | MMSpdu::InitiateErrorPDU(_)
        ) {
            // Initiate is not used within an established association (ISO 9506-1 §8.2.2).
            return self.provider_abort();
        }
        let (State::Open(session) | State::Concluding(session)) = self.state.clone() else {
            return self.provider_abort();
        };
        // The initiator's CONCLUDE response triggers its ACSE release (Annex A.1.2.1).
        if matches!(pdu, MMSpdu::ConcludeResponsePDU(_))
            && self.state == State::Concluding(session.clone())
        {
            let mut out = vec![Action::Pdu(pdu)];
            out.extend(self.release_request());
            return out;
        }
        let served = serving_view(&session, &pdu, true);
        match mms::validate_cbb(&pdu, served) {
            Ok(()) => vec![Action::Pdu(pdu)],
            Err(error) => vec![Action::Unsupported(pdu, error)],
        }
    }

    /// ACSE release: a RLRQ is answered at once with the CONCLUDE response and a RLRE; a RLRE
    /// releases the session.
    fn release_apdu(&mut self, apdu: ACSEApdu) -> Vec<Action> {
        match apdu {
            ACSEApdu::Rlrq(_) => {
                // The CONCLUDE response went out when the request arrived; the ACSE release is
                // answered now (ISO 9506-2 Annex A.1.2.2).
                let State::Open(session) = self.state.clone() else {
                    return self.provider_abort();
                };
                let rlre = match acse::encode(&ACSEApdu::Rlre(RLREApdu {
                    reason: Some(ReleaseResponseReason::NORMAL),
                    user_information: None,
                })) {
                    Ok(bytes) => acse_user_data(bytes),
                    Err(_) => return vec![Action::Misuse("the RLRE does not encode")],
                };
                self.state = State::Answered(session);
                self.send_user_data(rlre)
            }
            ACSEApdu::Rlre(_) => {
                let State::Concluding(_) = self.state.clone() else {
                    return self.provider_abort();
                };
                // The ACSE release is complete: the session release follows.
                let actions = self.upper.handle(upper::Event::Release);
                self.lower(actions)
            }
            _ => self.provider_abort(),
        }
    }

    /// Sends an MMS PDU. A request is checked against what the other end serves, a response
    /// against what this end serves.
    fn send(&mut self, pdu: MMSpdu) -> Vec<Action> {
        let State::Open(session) = self.state.clone() else {
            return vec![Action::Misuse("send needs an established association")];
        };
        if matches!(
            pdu,
            MMSpdu::InitiateRequestPDU(_)
                | MMSpdu::InitiateResponsePDU(_)
                | MMSpdu::InitiateErrorPDU(_)
        ) {
            return vec![Action::Misuse("Initiate is not sent within an association")];
        }
        let served = serving_view(&session, &pdu, false);
        if mms::validate_cbb(&pdu, served).is_err() {
            return vec![Action::Misuse("the PDU is not allowed by the negotiation")];
        }
        let Ok(bytes) = mms::encode(&pdu) else {
            return vec![Action::Misuse("the MMS PDU does not encode")];
        };
        let actions = self.upper.handle(upper::Event::Data(mms_user_data(bytes)));
        self.lower(actions)
    }

    /// Requests the CONCLUDE: the MMS request, then the ACSE release (ISO 9506-2 §24.3).
    fn conclude(&mut self) -> Vec<Action> {
        let State::Open(session) = self.state.clone() else {
            return vec![Action::Misuse("conclude needs an established association")];
        };
        let request = match mms::encode(&MMSpdu::ConcludeRequestPDU(
            igs_iso9506_mms_codec::mms::ConcludeRequestPDU(()),
        )) {
            Ok(bytes) => mms_user_data(bytes),
            Err(_) => return vec![Action::Misuse("the CONCLUDE request does not encode")],
        };
        // The ACSE release follows the CONCLUDE response, not the request (ISO 9506-2 Annex A.1.2.1).
        self.state = State::Concluding(session);
        self.send_user_data(request)
    }

    /// The initiator's ACSE release, sent once the CONCLUDE response is received (Annex A.1.2.1).
    fn release_request(&mut self) -> Vec<Action> {
        let rlrq = match acse::encode(&ACSEApdu::Rlrq(RLRQApdu {
            reason: Some(ReleaseRequestReason::NORMAL),
            user_information: None,
        })) {
            Ok(bytes) => acse_user_data(bytes),
            Err(_) => return vec![Action::Misuse("the RLRQ does not encode")],
        };
        self.send_user_data(rlrq)
    }
}

/// The Initiate negotiation of ISO 9506-1 §8.2.1: each value is reduced to what both ends allow,
/// and an association that would serve no service, or a nesting level below TASE.2's, is refused.
pub fn negotiate(
    request: &InitiateRequestPDU,
    capabilities: &Capabilities,
    config: &LinkConfig,
) -> Result<InitiateResponsePDU, ServiceError> {
    let detail = &request.init_request_detail;
    let proposed_version = detail.proposed_version_number.0;
    if proposed_version < 1 {
        return Err(refusal(ServiceErrorErrorClassInitiate::OTHER));
    }
    let version = proposed_version.min(MMS_VERSION);

    let calling = request.proposed_max_serv_outstanding_calling.0;
    let called = request.proposed_max_serv_outstanding_called.0;
    if calling < 0 || called < 0 {
        return Err(refusal(ServiceErrorErrorClassInitiate::OTHER));
    }
    let negotiated_calling = calling.min(i64::from(config.max_outstanding_calling));
    if negotiated_calling == 0 {
        return Err(refusal(
            ServiceErrorErrorClassInitiate::MAX_SERVICES_OUTSTANDING_CALLING_INSUFFICIENT,
        ));
    }
    let negotiated_called = called.min(i64::from(config.max_outstanding_called));
    if negotiated_called == 0 {
        return Err(refusal(
            ServiceErrorErrorClassInitiate::MAX_SERVICES_OUTSTANDING_CALLED_INSUFFICIENT,
        ));
    }

    let proposed_nesting = request.proposed_data_structure_nesting_level.as_ref();
    if proposed_nesting.is_some_and(|n| n.0 < 0) {
        return Err(refusal(ServiceErrorErrorClassInitiate::OTHER));
    }
    // An absent level is unlimited (ISO 9506-1 §8.2.1.1.4).
    let nesting = proposed_nesting
        .map_or(i64::from(config.nesting_level), |n| n.0)
        .min(i64::from(config.nesting_level));
    if nesting < MIN_NESTING_LEVEL {
        return Err(refusal(
            ServiceErrorErrorClassInitiate::NESTING_LEVEL_INSUFFICIENT,
        ));
    }

    let parameters = intersect(
        &detail.proposed_parameter_cbb.0,
        &capabilities.parameter_cbb,
    );
    let services = intersect(&detail.services_supported_calling.0, &capabilities.services);
    if !any(&services) {
        return Err(refusal(
            ServiceErrorErrorClassInitiate::SERVICE_CBB_INSUFFICIENT,
        ));
    }

    Ok(InitiateResponsePDU {
        local_detail_called: None,
        negotiated_max_serv_outstanding_calling: Integer16(negotiated_calling),
        negotiated_max_serv_outstanding_called: Integer16(negotiated_called),
        negotiated_data_structure_nesting_level: Some(Integer8(nesting)),
        init_response_detail: InitiateResponsePDUInitResponseDetail {
            negotiated_version_number: Integer16(version),
            negotiated_parameter_cbb: ParameterSupportOptions(parameters),
            services_supported_called: ServiceSupportOptions(services),
            additional_supported_called: None,
            additional_cbb_supported_called: None,
            privilege_class_identity_called: None,
        },
    })
}

/// Whether a response reduces the request, as the initiator checks it: no value is larger than
/// proposed, and the services and parameters are a subset of those proposed.
fn response_within_request(request: &InitiateRequestPDU, response: &InitiateResponsePDU) -> bool {
    let detail = &request.init_request_detail;
    let reply = &response.init_response_detail;
    let version = reply.negotiated_version_number.0;
    let nesting = response
        .negotiated_data_structure_nesting_level
        .as_ref()
        .map(|n| n.0);
    let nesting_ok = match (
        nesting,
        request.proposed_data_structure_nesting_level.as_ref(),
    ) {
        (Some(level), Some(proposed)) => (MIN_NESTING_LEVEL..=proposed.0).contains(&level),
        (Some(level), None) => level >= MIN_NESTING_LEVEL,
        (None, _) => true,
    };
    (1..=detail.proposed_version_number.0).contains(&version)
        && response.negotiated_max_serv_outstanding_calling.0 >= 0
        && response.negotiated_max_serv_outstanding_calling.0
            <= request.proposed_max_serv_outstanding_calling.0
        && response.negotiated_max_serv_outstanding_called.0 >= 0
        && response.negotiated_max_serv_outstanding_called.0
            <= request.proposed_max_serv_outstanding_called.0
        && nesting_ok
}

fn refusal(class: ServiceErrorErrorClassInitiate) -> ServiceError {
    ServiceError {
        error_class: ServiceErrorErrorClass::Initiate(class),
        additional_code: None,
        additional_description: None,
        service_specific_info: None,
    }
}

fn aare(
    result: AssociateResult,
    diagnostic: AssociateSourceDiagnosticAcseServiceUser,
    user_information: Option<AssociationInformation>,
    context: ApplicationContextName,
) -> AAREApdu {
    AAREApdu {
        protocol_version: Some(AAREApduProtocolVersion(acse::version1())),
        application_context_name: context,
        result,
        result_source_diagnostic: AssociateSourceDiagnostic::AcseServiceUser(diagnostic),
        responding_ap_title: None,
        responding_ae_qualifier: None,
        responding_ap_invocation_identifier: None,
        responding_ae_invocation_identifier: None,
        responder_acse_requirements: None,
        mechanism_name: None,
        responding_authentication_value: None,
        application_context_name_list: None,
        implementation_information: None,
        user_information,
    }
}

fn diagnostic_of(aare: &AAREApdu) -> i64 {
    match &aare.result_source_diagnostic {
        AssociateSourceDiagnostic::AcseServiceUser(diagnostic) => diagnostic.0,
        AssociateSourceDiagnostic::AcseServiceProvider(diagnostic) => diagnostic.0,
    }
}

fn mms_context_name() -> ApplicationContextName {
    ApplicationContextName(ObjectIdentifier(MMS_APPLICATION_CONTEXT.to_vec()))
}

fn legacy_context_name() -> ApplicationContextName {
    ApplicationContextName(ObjectIdentifier(LEGACY_MMS_APPLICATION_CONTEXT.to_vec()))
}

/// An AE-qualifier of form 2 (ISO 8650-1 §6.1.2).
fn ae_qualifier(value: i64) -> AEQualifier {
    AEQualifier::AeQualifierForm2(AEQualifierForm2(value))
}

/// The name that the initiator proposes, as its configuration selects it.
fn context_name(context: ApplicationContext) -> ApplicationContextName {
    match context {
        ApplicationContext::Current => mms_context_name(),
        ApplicationContext::Legacy => legacy_context_name(),
    }
}

/// The user information of an ACSE APDU: one EXTERNAL whose data is the MMS PDU, in the MMS
/// presentation context (ISO 9506-2 §A.1, §A.5).
fn information(mms: &[u8]) -> Result<AssociationInformation, &'static str> {
    let external = acse::External {
        direct_reference: None,
        indirect_reference: Some(MMS_CONTEXT),
        data_value_descriptor: None,
        encoding: acse::Encoding::SingleAsn1Type(RawBer(mms.to_vec())),
    };
    let raw = external
        .encode()
        .map_err(|_| "the EXTERNAL does not encode")?;
    Ok(AssociationInformation(vec![raw]))
}

/// The MMS PDU in the user information of an ACSE APDU, when it has the MMS context.
fn mms_in(information: &AssociationInformation) -> Option<MMSpdu> {
    information.0.iter().find_map(|raw| {
        let external = acse::External::decode(raw).ok()?;
        let is_mms = external.indirect_reference == Some(MMS_CONTEXT)
            || external
                .direct_reference
                .as_ref()
                .is_some_and(|d| d.0 == MMS_ABSTRACT_SYNTAX);
        match external.encoding {
            acse::Encoding::SingleAsn1Type(bytes) if is_mms => mms::decode(&bytes.0).ok(),
            _ => None,
        }
    })
}

fn mms_initiate_request(information: &AssociationInformation) -> Option<InitiateRequestPDU> {
    match mms_in(information)? {
        MMSpdu::InitiateRequestPDU(request) => Some(request),
        _ => None,
    }
}

fn mms_initiate_response(information: &AssociationInformation) -> Option<InitiateResponsePDU> {
    match mms_in(information)? {
        MMSpdu::InitiateResponsePDU(response) => Some(response),
        _ => None,
    }
}

fn mms_initiate_error(information: &AssociationInformation) -> Option<ServiceError> {
    match mms_in(information)? {
        MMSpdu::InitiateErrorPDU(InitiateErrorPDU(error)) => Some(error),
        _ => None,
    }
}

/// User data of the presentation connection: one PDV of the ACSE context.
fn acse_user_data(bytes: Vec<u8>) -> UserData {
    UserData::Full(vec![Pdv {
        transfer_syntax: None,
        context_id: ACSE_CONTEXT,
        values: PdvValues::SingleAsn1Type(bytes),
    }])
}

/// User data of the presentation connection: one PDV of the MMS context.
fn mms_user_data(bytes: Vec<u8>) -> UserData {
    UserData::Full(vec![Pdv {
        transfer_syntax: None,
        context_id: MMS_CONTEXT,
        values: PdvValues::SingleAsn1Type(bytes),
    }])
}

/// The first PDV of a context, as its encoding.
fn pdv_of(user_data: &UserData, context: i64) -> Option<&[u8]> {
    match user_data {
        UserData::Full(pdvs) => pdvs.iter().find_map(|pdv| match &pdv.values {
            PdvValues::SingleAsn1Type(bytes) if pdv.context_id == context => Some(bytes.as_slice()),
            _ => None,
        }),
        UserData::Simple(_) => None,
    }
}

fn acse_of(user_data: &UserData) -> Option<ACSEApdu> {
    acse::decode(pdv_of(user_data, ACSE_CONTEXT)?).ok()
}

fn user_data_mms(user_data: &UserData) -> Option<MMSpdu> {
    mms::decode(pdv_of(user_data, MMS_CONTEXT)?).ok()
}

/// A request is served by the end that receives it. A response, and an unconfirmed PDU such as the
/// information report, which the server sends, are served by the end that sends them: the sender's
/// services and parameter CBBs apply to them.
fn is_request(pdu: &MMSpdu) -> bool {
    matches!(
        pdu,
        MMSpdu::ConfirmedRequestPDU(_) | MMSpdu::CancelRequestPDU(_)
    )
}

/// The view of the server that checks a PDU: `incoming` PDUs come from the peer, the others are sent by
/// this end. The end that serves the PDU is the receiver for a request, the sender otherwise.
fn serving_view<'a>(session: &'a Session, pdu: &MMSpdu, incoming: bool) -> &'a Negotiated {
    if is_request(pdu) == incoming {
        &session.me
    } else {
        &session.peer
    }
}

/// Bits set in both, over the shorter of the two.
fn intersect(a: &BitString, b: &BitString) -> BitString {
    let bits = length(a).min(length(b));
    let bytes: Vec<u8> = (0..bits.div_ceil(8))
        .map(|octet| {
            (0..8).fold(0u8, |acc, k| {
                let index = octet.saturating_mul(8).saturating_add(k);
                if index < bits && a.bit(index) && b.bit(index) {
                    acc | 0x80u8
                        .checked_shr(u32::try_from(k).unwrap_or(0))
                        .unwrap_or(0)
                } else {
                    acc
                }
            })
        })
        .collect();
    let unused = bytes.len().saturating_mul(8).saturating_sub(bits);
    BitString {
        unused: u8::try_from(unused).unwrap_or(0),
        bytes,
    }
}

impl Association {
    /// The peer's view of the association; see [`reduced_to_proposal`], and the lenient option.
    fn peer_view(
        &self,
        request: &InitiateRequestPDU,
        response: &InitiateResponsePDU,
    ) -> Negotiated {
        let mut peer = reduced_to_proposal(request, response);
        if self.lenient_parameter_cbbs {
            peer.parameters = request.init_request_detail.proposed_parameter_cbb.0.clone();
        }
        peer
    }
}

/// The peer's view of the association, reduced to what was proposed. ISO 9506-1 §8.2.1.1.8: any
/// additional bits received are ignored, so a peer that sets a service it was not offered is not
/// refused, and that service is not used.
fn reduced_to_proposal(request: &InitiateRequestPDU, response: &InitiateResponsePDU) -> Negotiated {
    let mut peer = Negotiated::served_by_called(response);
    peer.services = intersect(
        &peer.services,
        &request.init_request_detail.services_supported_calling.0,
    );
    peer.parameters = intersect(
        &peer.parameters,
        &request.init_request_detail.proposed_parameter_cbb.0,
    );
    peer
}

fn any(a: &BitString) -> bool {
    (0..length(a)).any(|index| a.bit(index))
}

fn length(a: &BitString) -> usize {
    a.bytes
        .len()
        .saturating_mul(8)
        .saturating_sub(usize::from(a.unused))
}

#[cfg(test)]
mod tests {
    use super::*;
    use igs_iso9506_mms_codec::generated::tables::{
        PARAMETER_SUPPORT_OPTIONS, SERVICE_SUPPORT_OPTIONS,
    };
    use igs_iso9506_mms_codec::generated::types::{
        CancelRequestPDU, Identifier, InformationReport, InitiateRequestPDUInitRequestDetail,
        InitiateResponsePDUInitResponseDetail, ObjectName, UnconfirmedPDU, UnconfirmedService,
        VariableAccessSpecification,
    };

    /// A bit string with the bits at these positions set, 96 bits long.
    fn bits(positions: &[usize]) -> BitString {
        let mut bytes = vec![0u8; 12];
        for &position in positions {
            if let Some(byte) = bytes.get_mut(position / 8) {
                *byte |= 0x80 >> (position % 8);
            }
        }
        BitString { unused: 0, bytes }
    }

    fn request(services: &[usize], parameters: &[usize]) -> InitiateRequestPDU {
        InitiateRequestPDU {
            local_detail_calling: None,
            proposed_max_serv_outstanding_calling: Integer16(8),
            proposed_max_serv_outstanding_called: Integer16(8),
            proposed_data_structure_nesting_level: Some(Integer8(6)),
            init_request_detail: InitiateRequestPDUInitRequestDetail {
                proposed_version_number: Integer16(MMS_VERSION),
                proposed_parameter_cbb: ParameterSupportOptions(bits(parameters)),
                services_supported_calling: ServiceSupportOptions(bits(services)),
                additional_supported_calling: None,
                additional_cbb_supported_calling: None,
                privilege_class_identity_calling: None,
            },
        }
    }

    fn response(services: &[usize], parameters: &[usize]) -> InitiateResponsePDU {
        InitiateResponsePDU {
            local_detail_called: None,
            negotiated_max_serv_outstanding_calling: Integer16(5),
            negotiated_max_serv_outstanding_called: Integer16(5),
            negotiated_data_structure_nesting_level: Some(Integer8(2)),
            init_response_detail: InitiateResponsePDUInitResponseDetail {
                negotiated_version_number: Integer16(MMS_VERSION),
                negotiated_parameter_cbb: ParameterSupportOptions(bits(parameters)),
                services_supported_called: ServiceSupportOptions(bits(services)),
                additional_supported_called: None,
                additional_cbb_supported_called: None,
                privilege_class_identity_called: None,
            },
        }
    }

    #[test]
    fn the_peers_extra_bits_are_ignored_not_refused() {
        // The peer sets service 0 and parameter 5, which were not proposed (ISO 9506-1 §8.2.1.1.8).
        let proposal = request(&[1, 2], &[0, 1]);
        let answer = response(&[0, 1, 2], &[0, 5]);
        let peer = reduced_to_proposal(&proposal, &answer);
        assert_eq!(peer.services.bytes, bits(&[1, 2]).bytes);
        assert_eq!(peer.parameters.bytes, bits(&[0]).bytes);
        assert!(response_within_request(&proposal, &answer));
    }

    fn position(name: &str) -> usize {
        SERVICE_SUPPORT_OPTIONS
            .iter()
            .map(|named| (named.name, named.position as usize))
            .chain(
                PARAMETER_SUPPORT_OPTIONS
                    .iter()
                    .map(|named| (named.name, named.position as usize)),
            )
            .find(|(n, _)| *n == name)
            .map(|(_, position)| position)
            .unwrap()
    }

    /// This end serves everything; the peer serves the information report, with these parameter CBBs.
    fn session(peer_parameters: &[usize]) -> Session {
        let report = position("informationReport");
        Session {
            me: Negotiated {
                parameters: bits(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
                services: bits(&[report]),
                nesting_level: Some(6),
            },
            peer: Negotiated {
                parameters: bits(peer_parameters),
                services: bits(&[report]),
                nesting_level: Some(6),
            },
        }
    }

    fn information_report() -> MMSpdu {
        MMSpdu::UnconfirmedPDU(UnconfirmedPDU {
            service: UnconfirmedService::InformationReport(InformationReport {
                variable_access_specification: VariableAccessSpecification::VariableListName(
                    ObjectName::VmdSpecific(Identifier("RPT".to_string())),
                ),
                list_of_access_result: Vec::new(),
            }),
            service_ext: None,
        })
    }

    #[test]
    fn an_incoming_report_is_checked_against_the_servers_cbbs() {
        // The server sends the report: its CBBs apply, not ours. Without the variable list CBB that the
        // server did not negotiate (G8), the report is refused; with it, accepted.
        let pdu = information_report();
        let without = session(&[]);
        assert!(mms::validate_cbb(&pdu, serving_view(&without, &pdu, true)).is_err());
        let with = session(&[position("vlis")]);
        assert!(mms::validate_cbb(&pdu, serving_view(&with, &pdu, true)).is_ok());
    }

    #[test]
    fn a_request_is_checked_against_the_end_that_serves_it() {
        let session = session(&[]);
        let request = MMSpdu::CancelRequestPDU(CancelRequestPDU(
            igs_iso9506_mms_codec::generated::types::Unsigned32(1),
        ));
        // An incoming request is served by this end; an outgoing one by the peer.
        assert!(std::ptr::eq(
            serving_view(&session, &request, true),
            &session.me
        ));
        assert!(std::ptr::eq(
            serving_view(&session, &request, false),
            &session.peer
        ));
        // A report sent by this end is served by this end; an incoming one by the peer.
        let report = information_report();
        assert!(std::ptr::eq(
            serving_view(&session, &report, false),
            &session.me
        ));
        assert!(std::ptr::eq(
            serving_view(&session, &report, true),
            &session.peer
        ));
    }

    #[test]
    fn a_value_above_the_proposal_is_still_refused() {
        let proposal = request(&[1], &[0]);
        let mut answer = response(&[1], &[0]);
        answer.negotiated_max_serv_outstanding_calling = Integer16(9);
        assert!(!response_within_request(&proposal, &answer));
    }
}
