// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Confirmed and unconfirmed requests of an MMS association (task L5): invoke IDs, the outstanding
//! limits, the matching of responses, the timeouts, Cancel, and the Reject PDU (ISO 9506-1 §7;
//! ISO 9506-2 §6.3, §6.4, §6.5, §7.1, §7.3, §7.4, §8.5, §8.6).
//!
//! The connection performs no I/O. It owns the association of task L4 and takes the time as an
//! argument of [`Requests::handle`], so that a test runs on a fake clock. Decisions are recorded as
//! D-019 in `PROVENANCE.md`.

use std::collections::BTreeMap;
use std::time::Duration;

use igs_iso9506_mms_codec::generated::types::{
    CancelErrorPDU, CancelRequestPDU, RejectPDURejectReasonCancelErrorPDU,
    RejectPDURejectReasonCancelResponsePDU, RejectPDURejectReasonConfirmedErrorPDU,
    RejectPDURejectReasonConfirmedRequestPDU, RejectPDURejectReasonConfirmedResponsePDU,
    RejectPDURejectReasonUnconfirmedPDU, ServiceErrorErrorClass,
    ServiceErrorErrorClassServicePreempt, UnconfirmedPDU,
};
use igs_iso9506_mms_codec::mms::{
    ConfirmedErrorPDU, ConfirmedRequestPDU, ConfirmedResponsePDU, ConfirmedServiceRequest,
    ConfirmedServiceResponse, MMSpdu, RejectPDU, RejectPDURejectReason, ServiceError,
    UnconfirmedService, Unsigned32,
};

use crate::association::{self, Capabilities};
use crate::config::{ConfigError, LinkConfig};
use crate::transport::Role;

/// The state of one request this end issued.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Outgoing {
    /// The service: the tag of its choice, which the response must carry (ISO 9506-2 §6.3.1.1).
    tag: u32,
    /// When the request times out.
    deadline: Duration,
    timed_out: bool,
    /// A Cancel-RequestPDU is outstanding.
    cancelling: bool,
    /// The final response or error of the request has arrived.
    original_done: bool,
}

/// The state of one request the other end issued.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Incoming {
    /// The tag of the service, which the response must carry.
    tag: u32,
    /// A Cancel-RequestPDU is awaiting an answer.
    cancel_requested: bool,
}

/// The outstanding limits of this end, from the negotiated values (ISO 9506-1 §8.2.1.2.2, §8.2.1.2.3):
/// the calling user creates the transactions of its requests with the calling limit, the called
/// user with the called one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Limits {
    outgoing: usize,
    incoming: usize,
}

/// An input of the requests layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Issue a confirmed request.
    Request(ConfirmedServiceRequest),
    /// Cancel an outstanding request, by its invoke ID.
    Cancel(u32),
    /// Answer an indicated request: a response, or an error.
    Respond(u32, Result<ConfirmedServiceResponse, ServiceError>),
    /// Answer a cancel that was indicated: accepted or refused.
    CancelAnswer {
        /// The invoke ID of the request whose cancel is answered.
        invoke: u32,
        /// Whether the cancel is accepted.
        accepted: bool,
    },
    /// Issue an unconfirmed service.
    Unconfirmed(UnconfirmedService),
    /// Reject an indicated request that this end does not serve (unrecognized-service).
    RejectIndication(u32),
    /// A lower event of the association.
    Association(association::Event),
    /// Time has passed: the timeouts are checked.
    Tick,
}

/// An output of the requests layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// A TSDU for the transport connection.
    Send(Vec<u8>),
    /// The transport connection is no longer needed: release it.
    ReleaseTransport,
    /// A request was issued, with this invoke ID.
    Requested(u32),
    /// The response to a request of this end.
    Response {
        /// The invoke ID.
        invoke: u32,
        /// The response.
        response: ConfirmedServiceResponse,
    },
    /// The error to a request of this end.
    Error {
        /// The invoke ID.
        invoke: u32,
        /// The error.
        error: ServiceError,
    },
    /// The cancel of a request succeeded.
    Cancelled(u32),
    /// The cancel of a request failed, and the request continues.
    CancelFailed(u32),
    /// A request of this end has been outstanding for the request timeout. The request stays
    /// outstanding; the user decides (for example, to cancel it). Reported once per request.
    Timeout(u32),
    /// A Reject PDU was received: the request it names, if any, failed.
    Rejected {
        /// The invoke ID the reject names.
        invoke: Option<u32>,
        /// The reason.
        reason: RejectPDURejectReason,
    },
    /// A confirmed request of the other end is indicated; answer it with [`Event::Respond`].
    Indication {
        /// The invoke ID.
        invoke: u32,
        /// The service.
        service: ConfirmedServiceRequest,
    },
    /// The other end cancels an indicated request; answer with [`Event::CancelAnswer`].
    CancelIndication(u32),
    /// An unconfirmed service of the other end.
    Unconfirmed(UnconfirmedService),
    /// An MMS PDU that is none of the above, as received (for the layers above).
    Other(MMSpdu),
    /// An MMS PDU the negotiation does not allow, for which no Reject applies.
    Unsupported(MMSpdu),
    /// An event of the association, not handled here.
    Association(association::Action),
    /// The event is refused and the state is unchanged, because the caller misused the layer.
    Misuse(&'static str),
}

/// The requests of one MMS association, as a state machine over the association of task L4.
#[derive(Debug, Clone)]
pub struct Requests {
    role: Role,
    config: LinkConfig,
    association: association::Association,
    limits: Option<Limits>,
    next_invoke: u32,
    outgoing: BTreeMap<u32, Outgoing>,
    incoming: BTreeMap<u32, Incoming>,
}

impl Requests {
    /// Requests in the idle state, for valid configurations (see [`LinkConfig::validate`]).
    pub fn new(
        role: Role,
        config: LinkConfig,
        capabilities: Capabilities,
    ) -> Result<Self, ConfigError> {
        let association = association::Association::new(role, config.clone(), capabilities)?;
        Ok(Self {
            role,
            config,
            association,
            limits: None,
            next_invoke: 1,
            outgoing: BTreeMap::new(),
            incoming: BTreeMap::new(),
        })
    }

    /// The number of requests this end has outstanding.
    pub fn outstanding(&self) -> usize {
        self.outgoing.len()
    }

    /// Takes the parameter CBBs proposed as negotiated for the checks of outgoing PDUs (see
    /// [`association::Association::set_lenient_parameter_cbbs`]).
    pub fn set_lenient_parameter_cbbs(&mut self, on: bool) {
        self.association.set_lenient_parameter_cbbs(on);
    }

    /// Sets the application profile of the association (see
    /// [`association::Association::set_profile`], D-033).
    pub fn set_profile(
        &mut self,
        profile: igs_iso9506_mms_codec::mms::profile::Profile,
    ) -> Result<(), igs_iso9506_mms_codec::mms::profile::ProfileError> {
        self.association.set_profile(profile)
    }

    /// Sets the limits of the profile on identifiers and on the MMS string of `Data` (see
    /// [`association::Association::set_string_limits`]).
    pub fn set_string_limits(&mut self, limits: igs_iso9506_mms_codec::mms::StringLimits) {
        self.association.set_string_limits(limits);
    }

    /// Whether the association is established.
    pub fn is_open(&self) -> bool {
        self.association.is_open()
    }

    /// Whether a request may be issued now: the association is established and the outstanding limit
    /// of this end is not reached.
    pub fn can_request(&self) -> bool {
        self.limits
            .is_some_and(|limits| self.outgoing.len() < limits.outgoing)
    }

    /// Takes an event at time `now`, and returns the actions it causes.
    pub fn handle(&mut self, event: Event, now: Duration) -> Vec<Action> {
        match event {
            Event::Request(service) => self.request(service, now),
            Event::Cancel(invoke) => self.cancel(invoke),
            Event::Respond(invoke, result) => self.respond(invoke, result),
            Event::CancelAnswer { invoke, accepted } => self.cancel_answer(invoke, accepted),
            Event::Unconfirmed(service) => self.send(MMSpdu::UnconfirmedPDU(UnconfirmedPDU {
                service,
                service_ext: None,
            })),
            Event::Association(event) => {
                let actions = self.association.handle(event);
                self.lower(actions)
            }
            Event::Tick => self.tick(now),
            Event::RejectIndication(invoke) => {
                self.incoming.remove(&invoke);
                self.reject(
                    RejectPDURejectReason::ConfirmedRequestPDU(
                        RejectPDURejectReasonConfirmedRequestPDU::UNRECOGNIZED_SERVICE,
                    ),
                    Some(invoke),
                )
            }
        }
    }

    fn request(&mut self, service: ConfirmedServiceRequest, now: Duration) -> Vec<Action> {
        let Some(limits) = self.limits else {
            return vec![Action::Misuse("requests need an established association")];
        };
        if self.outgoing.len() >= limits.outgoing {
            return vec![Action::Misuse("the outstanding limit is reached")];
        }
        let invoke = self.allocate();
        let tag = service.tag();
        let pdu = MMSpdu::ConfirmedRequestPDU(ConfirmedRequestPDU {
            invoke_id: Unsigned32(i64::from(invoke)),
            list_of_modifiers: None,
            service,
            service_ext: None,
        });
        let mut actions = self.send(pdu);
        if actions
            .iter()
            .any(|action| matches!(action, Action::Misuse(_)))
        {
            return actions;
        }
        self.outgoing.insert(
            invoke,
            Outgoing {
                tag,
                deadline: now.saturating_add(self.config.request_timeout),
                timed_out: false,
                cancelling: false,
                original_done: false,
            },
        );
        actions.insert(0, Action::Requested(invoke));
        actions
    }

    /// The next invoke ID not used by an outstanding request (ISO 9506-2 §7.1).
    fn allocate(&mut self) -> u32 {
        while self.outgoing.contains_key(&self.next_invoke) {
            self.next_invoke = self.next_invoke.wrapping_add(1);
        }
        let invoke = self.next_invoke;
        self.next_invoke = self.next_invoke.wrapping_add(1);
        invoke
    }

    fn cancel(&mut self, invoke: u32) -> Vec<Action> {
        match self.outgoing.get(&invoke) {
            None => vec![Action::Misuse("no outstanding request has this invoke ID")],
            Some(entry) if entry.cancelling => {
                vec![Action::Misuse("the request is already cancelling")]
            }
            Some(_) => {
                let pdu = MMSpdu::CancelRequestPDU(CancelRequestPDU(Unsigned32(i64::from(invoke))));
                let actions = self.send(pdu);
                if actions
                    .iter()
                    .any(|action| matches!(action, Action::Misuse(_)))
                {
                    return actions;
                }
                if let Some(entry) = self.outgoing.get_mut(&invoke) {
                    entry.cancelling = true;
                }
                actions
            }
        }
    }

    fn respond(
        &mut self,
        invoke: u32,
        result: Result<ConfirmedServiceResponse, ServiceError>,
    ) -> Vec<Action> {
        let Some(entry) = self.incoming.get(&invoke) else {
            return vec![Action::Misuse("no indicated request has this invoke ID")];
        };
        let pdu = match result {
            Ok(service) => {
                if service.tag() != entry.tag {
                    return vec![Action::Misuse("the response is for another service")];
                }
                MMSpdu::ConfirmedResponsePDU(ConfirmedResponsePDU {
                    invoke_id: Unsigned32(i64::from(invoke)),
                    service,
                    service_ext: None,
                })
            }
            Err(service_error) => MMSpdu::ConfirmedErrorPDU(ConfirmedErrorPDU {
                invoke_id: Unsigned32(i64::from(invoke)),
                modifier_position: None,
                service_error,
            }),
        };
        let actions = self.send(pdu);
        if !actions
            .iter()
            .any(|action| matches!(action, Action::Misuse(_)))
        {
            self.incoming.remove(&invoke);
        }
        actions
    }

    /// Answers a Cancel-RequestPDU: accepted, the cancel response and the error of the request;
    /// refused, a Cancel-ErrorPDU (ISO 9506-2 §6.3.1.2, transition 6).
    fn cancel_answer(&mut self, invoke: u32, accepted: bool) -> Vec<Action> {
        match self.incoming.get(&invoke) {
            Some(entry) if entry.cancel_requested => {}
            _ => {
                return vec![Action::Misuse(
                    "no cancel is awaiting an answer for this invoke ID",
                )]
            }
        }
        if accepted {
            let response = self.send(MMSpdu::CancelResponsePDU(
                igs_iso9506_mms_codec::generated::types::CancelResponsePDU(Unsigned32(i64::from(
                    invoke,
                ))),
            ));
            let error = self.send(MMSpdu::ConfirmedErrorPDU(ConfirmedErrorPDU {
                invoke_id: Unsigned32(i64::from(invoke)),
                modifier_position: None,
                service_error: cancelled_error(),
            }));
            let mut actions = response;
            actions.extend(error);
            if !actions
                .iter()
                .any(|action| matches!(action, Action::Misuse(_)))
            {
                self.incoming.remove(&invoke);
            }
            actions
        } else {
            let refusal = self.send(MMSpdu::CancelErrorPDU(cancel_error(invoke)));
            if let Some(entry) = self.incoming.get_mut(&invoke) {
                entry.cancel_requested = false;
            }
            refusal
        }
    }

    fn tick(&mut self, now: Duration) -> Vec<Action> {
        self.outgoing
            .iter_mut()
            .filter(|(_, entry)| !entry.timed_out && !entry.original_done && now >= entry.deadline)
            .map(|(invoke, entry)| {
                entry.timed_out = true;
                Action::Timeout(*invoke)
            })
            .collect()
    }

    /// Sends an MMS PDU through the association.
    fn send(&mut self, pdu: MMSpdu) -> Vec<Action> {
        let actions = self.association.handle(association::Event::Send(pdu));
        self.lower(actions)
    }

    /// Answers a received PDU that the layer cannot take, with the Reject PDU of its category.
    fn reject(&mut self, reason: RejectPDURejectReason, original: Option<u32>) -> Vec<Action> {
        let pdu = MMSpdu::RejectPDU(RejectPDU {
            original_invoke_id: original.map(|invoke| Unsigned32(i64::from(invoke))),
            reject_reason: reason,
        });
        self.send(pdu)
    }

    /// Translates the actions of the association, and handles the PDUs it passes up.
    fn lower(&mut self, actions: Vec<association::Action>) -> Vec<Action> {
        let mut out = Vec::new();
        for action in actions {
            match action {
                association::Action::Send(tsdu) => out.push(Action::Send(tsdu)),
                association::Action::ReleaseTransport => out.push(Action::ReleaseTransport),
                association::Action::Pdu(pdu) => out.extend(self.received(pdu)),
                association::Action::Unsupported(pdu, _) => out.extend(self.unsupported(pdu)),
                association::Action::Established(response) => {
                    let (calling, called) = (
                        response.negotiated_max_serv_outstanding_calling.0,
                        response.negotiated_max_serv_outstanding_called.0,
                    );
                    // The calling user creates the transactions of its requests with the calling
                    // limit: this end's outgoing limit is its own role's, the other end's is the other.
                    let (outgoing, incoming) = match self.role {
                        Role::Initiator => (calling, called),
                        Role::Responder => (called, calling),
                    };
                    self.limits = Some(Limits {
                        outgoing: usize::try_from(outgoing).unwrap_or(0),
                        incoming: usize::try_from(incoming).unwrap_or(0),
                    });
                    out.push(Action::Association(association::Action::Established(
                        response,
                    )));
                }
                association::Action::Misuse(message) => out.push(Action::Misuse(message)),
                other => out.push(Action::Association(other)),
            }
        }
        out
    }

    fn unsupported(&mut self, pdu: MMSpdu) -> Vec<Action> {
        match pdu {
            MMSpdu::ConfirmedRequestPDU(request) => {
                let invoke = invoke_of(&request.invoke_id);
                self.reject(
                    RejectPDURejectReason::ConfirmedRequestPDU(
                        RejectPDURejectReasonConfirmedRequestPDU::UNRECOGNIZED_SERVICE,
                    ),
                    invoke,
                )
            }
            MMSpdu::UnconfirmedPDU(_) => self.reject(
                RejectPDURejectReason::UnconfirmedPDU(
                    RejectPDURejectReasonUnconfirmedPDU::UNRECOGNIZED_SERVICE,
                ),
                None,
            ),
            // An answer that breaks the negotiation ends the request of this end: it is rejected, and
            // reported to the caller as unsupported (ISO 9506-2 §6.4: a RejectPDU for an invalid PDU).
            MMSpdu::ConfirmedResponsePDU(response) => {
                let invoke = invoke_of(&response.invoke_id);
                self.finish_unsupported(invoke, MMSpdu::ConfirmedResponsePDU(response))
            }
            MMSpdu::ConfirmedErrorPDU(error) => {
                let invoke = invoke_of(&error.invoke_id);
                self.finish_unsupported(invoke, MMSpdu::ConfirmedErrorPDU(error))
            }
            other => vec![Action::Unsupported(other)],
        }
    }

    /// An answer to a request of this end that the negotiation does not allow: the request is over,
    /// the answer is rejected, and the answer is reported as unsupported.
    fn finish_unsupported(&mut self, invoke: Option<u32>, pdu: MMSpdu) -> Vec<Action> {
        let Some(id) = invoke.filter(|id| self.outgoing.contains_key(id)) else {
            return vec![Action::Unsupported(pdu)];
        };
        self.outgoing.remove(&id);
        let mut actions = self.reject(
            RejectPDURejectReason::ConfirmedResponsePDU(
                RejectPDURejectReasonConfirmedResponsePDU::OTHER,
            ),
            Some(id),
        );
        actions.push(Action::Unsupported(pdu));
        actions
    }

    /// One PDU of the other end, that the association allowed.
    fn received(&mut self, pdu: MMSpdu) -> Vec<Action> {
        match pdu {
            MMSpdu::ConfirmedResponsePDU(response) => {
                let invoke = invoke_of(&response.invoke_id);
                self.response(invoke, response.service)
            }
            MMSpdu::ConfirmedErrorPDU(error) => {
                let invoke = invoke_of(&error.invoke_id);
                self.error(invoke, error.service_error)
            }
            MMSpdu::CancelResponsePDU(answer) => self.cancel_response(invoke_of(&answer.0)),
            MMSpdu::CancelErrorPDU(error) => {
                self.cancel_failed(invoke_of(&error.original_invoke_id))
            }
            MMSpdu::RejectPDU(reject) => self.rejected(reject),
            MMSpdu::ConfirmedRequestPDU(request) => self.indicate(request),
            MMSpdu::CancelRequestPDU(cancel) => self.cancel_indicated(invoke_of(&cancel.0)),
            MMSpdu::UnconfirmedPDU(unconfirmed) => vec![Action::Unconfirmed(unconfirmed.service)],
            other => vec![Action::Other(other)],
        }
    }

    /// A response to a request of this end: it must name an outstanding one of the same service.
    fn response(&mut self, invoke: Option<u32>, service: ConfirmedServiceResponse) -> Vec<Action> {
        let Some(invoke) = invoke else {
            return self.reject(
                RejectPDURejectReason::ConfirmedResponsePDU(
                    RejectPDURejectReasonConfirmedResponsePDU::INVALID_INVOKE_ID,
                ),
                None,
            );
        };
        match self.outgoing.get(&invoke) {
            Some(entry) if !entry.original_done && entry.tag == service.tag() => {
                let cancelling = entry.cancelling;
                self.finish(invoke, cancelling);
                vec![Action::Response {
                    invoke,
                    response: service,
                }]
            }
            _ => self.reject(
                RejectPDURejectReason::ConfirmedResponsePDU(
                    RejectPDURejectReasonConfirmedResponsePDU::INVALID_INVOKE_ID,
                ),
                Some(invoke),
            ),
        }
    }

    fn error(&mut self, invoke: Option<u32>, error: ServiceError) -> Vec<Action> {
        let Some(invoke) = invoke else {
            return self.reject(
                RejectPDURejectReason::ConfirmedErrorPDU(
                    RejectPDURejectReasonConfirmedErrorPDU::INVALID_INVOKE_ID,
                ),
                None,
            );
        };
        match self.outgoing.get(&invoke) {
            Some(entry) if !entry.original_done => {
                let cancelling = entry.cancelling;
                self.finish(invoke, cancelling);
                vec![Action::Error { invoke, error }]
            }
            _ => self.reject(
                RejectPDURejectReason::ConfirmedErrorPDU(
                    RejectPDURejectReasonConfirmedErrorPDU::INVALID_INVOKE_ID,
                ),
                Some(invoke),
            ),
        }
    }

    /// The final PDU of a request: the entry goes unless a cancel is still awaiting its answer.
    fn finish(&mut self, invoke: u32, cancelling: bool) {
        if cancelling {
            if let Some(entry) = self.outgoing.get_mut(&invoke) {
                entry.original_done = true;
            }
        } else {
            self.outgoing.remove(&invoke);
        }
    }

    fn cancel_response(&mut self, invoke: Option<u32>) -> Vec<Action> {
        match invoke.and_then(|invoke| self.outgoing.get_mut(&invoke).map(|entry| (invoke, entry)))
        {
            Some((invoke, entry)) if entry.cancelling => {
                entry.cancelling = false;
                let done = entry.original_done;
                if done {
                    self.outgoing.remove(&invoke);
                }
                vec![Action::Cancelled(invoke)]
            }
            _ => self.reject(
                RejectPDURejectReason::CancelResponsePDU(
                    RejectPDURejectReasonCancelResponsePDU::INVALID_INVOKE_ID,
                ),
                invoke,
            ),
        }
    }

    fn cancel_failed(&mut self, invoke: Option<u32>) -> Vec<Action> {
        match invoke.and_then(|invoke| self.outgoing.get_mut(&invoke).map(|entry| (invoke, entry)))
        {
            Some((invoke, entry)) if entry.cancelling => {
                entry.cancelling = false;
                let done = entry.original_done;
                if done {
                    self.outgoing.remove(&invoke);
                }
                vec![Action::CancelFailed(invoke)]
            }
            _ => self.reject(
                RejectPDURejectReason::CancelErrorPDU(
                    RejectPDURejectReasonCancelErrorPDU::INVALID_INVOKE_ID,
                ),
                invoke,
            ),
        }
    }

    /// A Reject PDU. A rejected request goes; a rejected cancel is no longer outstanding.
    fn rejected(&mut self, reject: RejectPDU) -> Vec<Action> {
        let invoke = reject.original_invoke_id.as_ref().and_then(invoke_of);
        if let Some(id) = invoke {
            match reject.reject_reason {
                RejectPDURejectReason::ConfirmedRequestPDU(_) => {
                    self.outgoing.remove(&id);
                }
                RejectPDURejectReason::CancelRequestPDU(_) => {
                    if let Some(entry) = self.outgoing.get_mut(&id) {
                        entry.cancelling = false;
                    }
                }
                _ => {}
            }
        }
        vec![Action::Rejected {
            invoke,
            reason: reject.reject_reason,
        }]
    }

    /// A request of the other end: within its limit, with an invoke ID not in use.
    fn indicate(&mut self, request: ConfirmedRequestPDU) -> Vec<Action> {
        let Some(invoke) = invoke_of(&request.invoke_id) else {
            return self.reject(
                RejectPDURejectReason::ConfirmedRequestPDU(
                    RejectPDURejectReasonConfirmedRequestPDU::INVALID_INVOKE_ID,
                ),
                None,
            );
        };
        if self.incoming.contains_key(&invoke) {
            return self.reject(
                RejectPDURejectReason::ConfirmedRequestPDU(
                    RejectPDURejectReasonConfirmedRequestPDU::INVALID_INVOKE_ID,
                ),
                Some(invoke),
            );
        }
        let limit = self.limits.map_or(0, |limits| limits.incoming);
        if self.incoming.len() >= limit {
            return self.reject(
                RejectPDURejectReason::ConfirmedRequestPDU(
                    RejectPDURejectReasonConfirmedRequestPDU::MAX_SERV_OUTSTANDING_EXCEEDED,
                ),
                Some(invoke),
            );
        }
        self.incoming.insert(
            invoke,
            Incoming {
                tag: request.service.tag(),
                cancel_requested: false,
            },
        );
        vec![Action::Indication {
            invoke,
            service: request.service,
        }]
    }

    /// A cancel of an indicated request is indicated; a cancel of any other is refused at once, and
    /// the user is not told (ISO 9506-2 §6.4).
    fn cancel_indicated(&mut self, invoke: Option<u32>) -> Vec<Action> {
        let Some(invoke) = invoke else {
            return self.send(MMSpdu::CancelErrorPDU(cancel_error(0)));
        };
        match self.incoming.get_mut(&invoke) {
            Some(entry) if !entry.cancel_requested => {
                entry.cancel_requested = true;
                vec![Action::CancelIndication(invoke)]
            }
            _ => self.send(MMSpdu::CancelErrorPDU(cancel_error(invoke))),
        }
    }
}

fn invoke_of(id: &Unsigned32) -> Option<u32> {
    u32::try_from(id.0).ok()
}

/// The error of a request that was cancelled (ISO 9506-2 §6.3.1.2: service-preempt, cancel).
fn cancelled_error() -> ServiceError {
    ServiceError {
        error_class: ServiceErrorErrorClass::ServicePreempt(
            ServiceErrorErrorClassServicePreempt::CANCEL,
        ),
        additional_code: None,
        additional_description: None,
        service_specific_info: None,
    }
}

/// The Cancel-ErrorPDU of a cancel that is refused or unknown.
fn cancel_error(invoke: u32) -> CancelErrorPDU {
    CancelErrorPDU {
        original_invoke_id: Unsigned32(i64::from(invoke)),
        service_error: ServiceError {
            error_class: ServiceErrorErrorClass::ServicePreempt(
                ServiceErrorErrorClassServicePreempt::OTHER,
            ),
            additional_code: None,
            additional_description: None,
            service_specific_info: None,
        },
    }
}
