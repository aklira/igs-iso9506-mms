// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The transport connection of class 0 (task L2): establishment with the TPDU size negotiated,
//! data transfer with segmenting and reassembly, and release (ITU-T X.224 §6.3, §8.2, §13; RFC 1006
//! and RFC 2126 for the TCP environment).
//!
//! The connection performs no I/O. [`Connection::handle`] takes an event and the time, and returns
//! the actions for the caller: octets to write to the network connection, TSDUs to pass up, and
//! the change of state. Time is a duration from any origin the caller chooses, so that a test can
//! run on a fake clock. Decisions of this module are recorded as D-016 in `PROVENANCE.md`.

use std::time::Duration;

use igs_iso9506_mms_codec::transport::{
    encode_frame, reason, reject_cause, ConnectionTpdu, DataTpdu, DisconnectRequest, ErrorTpdu,
    FrameDecoder, Parameters, Tpdu, TpduSize,
};

use crate::config::{ConfigError, LinkConfig};

/// Largest TSDU reassembled from DT TPDUs, in octets. A longer sequence is a protocol error.
pub const MAX_TSDU: usize = 1_048_576;

/// Octets of a DT TPDU before its user data: the length indicator, the code and the EOT octet
/// (X.224 §13.7.1).
const DT_HEADER: usize = 3;

/// Reference of this end, in CR and CC. A class 0 connection has one transport connection per
/// network connection, so any non-zero value identifies it.
const REFERENCE: u16 = 1;

/// Octets of a rejected TPDU quoted in an ER TPDU: the length indicator is at most 254, and the
/// fixed part and the parameter header of the ER take six of them.
const QUOTE: usize = 248;

/// The role of this end. The initiator sends the CR; the responder answers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Sends the connection request.
    Initiator,
    /// Answers the connection request.
    Responder,
}

/// An input of the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Initiator: start the connection, by a CR TPDU.
    Connect,
    /// Octets received from the network connection, in any piece size.
    Received(Vec<u8>),
    /// A TSDU from the upper layer, to send once the connection is open.
    Send(Vec<u8>),
    /// Release the connection. Class 0 releases implicitly, with the network connection.
    Release,
    /// Time has passed: check the timer of the connection request.
    Tick,
}

/// An output of the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Octets to write to the network connection: one TPKT frame.
    Transmit(Vec<u8>),
    /// A complete TSDU, reassembled from its DT TPDUs.
    Deliver(Vec<u8>),
    /// The transport connection is open, at the TPDU size of [`Connection::agreed_tpdu_size`].
    Opened,
    /// The transport connection is closed; the caller closes the network connection.
    Closed(Cause),
    /// The event is refused and the state is unchanged, because the caller misused the connection.
    Misuse(&'static str),
}

/// Why the transport connection is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    /// The local side released the connection.
    Local,
    /// The connection request was not confirmed before the connect timeout.
    Timeout,
    /// This end refused the connection request, for the reason of the DR TPDU sent.
    Declined(u8),
    /// The peer refused the connection request, with this reason.
    Refused(u8),
    /// The peer released the open connection, with this reason.
    Released(u8),
    /// The peer sent an ER TPDU, with this reject cause.
    Rejected(u8),
    /// This end found a protocol error and sent an ER TPDU with this reject cause.
    Protocol(u8),
    /// The TPKT framing of the byte stream is broken. No TPDU can be sent on it.
    Framing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    /// Initiator: the CR is sent, the CC is awaited until `deadline`.
    Confirming {
        deadline: Duration,
    },
    Open,
    Closed,
}

/// One class 0 transport connection, as a state machine.
#[derive(Debug, Clone)]
pub struct Connection {
    role: Role,
    config: LinkConfig,
    state: State,
    /// The TPDU size agreed, valid when open.
    size: TpduSize,
    /// The reference of the peer, valid once the connection request is answered.
    remote: u16,
    frames: FrameDecoder,
    tsdu: Vec<u8>,
}

impl Connection {
    /// A connection in the idle state, for a configuration that passes [`LinkConfig::validate`].
    pub fn new(role: Role, config: LinkConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            role,
            config,
            state: State::Idle,
            size: TpduSize::S128,
            remote: 0,
            frames: FrameDecoder::new(),
            tsdu: Vec::new(),
        })
    }

    /// Whether the transport connection is open.
    pub fn is_open(&self) -> bool {
        self.state == State::Open
    }

    /// Whether the transport connection is closed, for good.
    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// The TPDU size agreed, valid when the connection is open (X.224 §13.3.4 b).
    pub fn agreed_tpdu_size(&self) -> TpduSize {
        self.size
    }

    /// Takes an event at time `now`, and returns the actions it causes.
    pub fn handle(&mut self, event: Event, now: Duration) -> Vec<Action> {
        match event {
            Event::Connect => self.connect(now),
            Event::Received(bytes) => self.receive(&bytes),
            Event::Send(tsdu) => self.send(&tsdu),
            Event::Release => self.close(Cause::Local),
            Event::Tick => self.tick(now),
        }
    }

    fn connect(&mut self, now: Duration) -> Vec<Action> {
        if self.role != Role::Initiator || self.state != State::Idle {
            return vec![Action::Misuse("connect needs an idle initiator")];
        }
        let request = Tpdu::ConnectionRequest(ConnectionTpdu {
            credit: 0,
            dst_ref: 0,
            src_ref: REFERENCE,
            class: 0,
            options: 0,
            parameters: Parameters {
                calling_selector: self.config.calling_tsap.clone(),
                called_selector: self.config.called_tsap.clone(),
                tpdu_size: Some(self.config.tpdu_size),
                ..Parameters::default()
            },
            user_data: Vec::new(),
        });
        match transmit(&request) {
            Ok(frame) => {
                self.state = State::Confirming {
                    deadline: now.saturating_add(self.config.connect_timeout),
                };
                vec![Action::Transmit(frame)]
            }
            Err(message) => vec![Action::Misuse(message)],
        }
    }

    fn receive(&mut self, bytes: &[u8]) -> Vec<Action> {
        if self.is_closed() {
            return Vec::new();
        }
        self.frames.push(bytes);
        let mut actions = Vec::new();
        loop {
            match self.frames.next_tpdu() {
                Ok(Some(tpdu)) => {
                    actions.extend(self.tpdu(&tpdu));
                    if self.is_closed() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    actions.extend(self.close(Cause::Framing));
                    break;
                }
            }
        }
        actions
    }

    /// One TPDU of the byte stream, decoded and dispatched on the state.
    fn tpdu(&mut self, bytes: &[u8]) -> Vec<Action> {
        let tpdu = match Tpdu::decode(bytes) {
            Ok(tpdu) => tpdu,
            Err(error) => {
                let cause = error.reject_cause().unwrap_or(reject_cause::NOT_SPECIFIED);
                return self.reject(cause, bytes, error.offset());
            }
        };
        let outcome = match (self.state, self.role, tpdu) {
            (State::Idle, Role::Responder, Tpdu::ConnectionRequest(request)) => {
                self.accept(request)
            }
            (State::Confirming { .. }, _, Tpdu::ConnectionConfirm(confirm)) => {
                self.confirmed(confirm)
            }
            (State::Confirming { .. }, _, Tpdu::DisconnectRequest(refusal)) => {
                Ok(self.close(Cause::Refused(refusal.reason)))
            }
            (State::Open, _, Tpdu::Data(data)) => self.data(data),
            (State::Open, _, Tpdu::DisconnectRequest(release)) => {
                Ok(self.close(Cause::Released(release.reason)))
            }
            (_, _, Tpdu::Error(error)) => Ok(self.close(Cause::Rejected(error.cause))),
            _ => Err(reject_cause::INVALID_TPDU_TYPE),
        };
        match outcome {
            Ok(actions) => actions,
            Err(cause) => {
                // An unexpected type is in fault at its code, the second octet (X.224 §13.12.4).
                let offset = (cause == reject_cause::INVALID_TPDU_TYPE).then_some(1);
                self.reject(cause, bytes, offset)
            }
        }
    }

    /// Responder: a CR is accepted at the smaller of the proposed size and this end's maximum, or
    /// declined with a DR TPDU.
    fn accept(&mut self, request: ConnectionTpdu) -> Result<Vec<Action>, u8> {
        let mismatched_selector = self
            .config
            .called_tsap
            .as_ref()
            .is_some_and(|ours| request.parameters.called_selector.as_ref() != Some(ours));
        if request.class != 0
            || request.options != 0
            || request.credit != 0
            || !request.user_data.is_empty()
        {
            return Ok(self.decline(request.src_ref, reason::NOT_SPECIFIED));
        }
        if mismatched_selector {
            return Ok(self.decline(request.src_ref, reason::ADDRESS_UNKNOWN));
        }
        let proposed = request.parameters.tpdu_size.unwrap_or(TpduSize::S128);
        self.size = proposed.min(self.config.tpdu_size);
        self.remote = request.src_ref;
        let confirm = Tpdu::ConnectionConfirm(ConnectionTpdu {
            credit: 0,
            dst_ref: request.src_ref,
            src_ref: REFERENCE,
            class: 0,
            options: 0,
            parameters: Parameters {
                called_selector: self.config.called_tsap.clone(),
                tpdu_size: Some(self.size),
                ..Parameters::default()
            },
            user_data: Vec::new(),
        });
        match transmit(&confirm) {
            Ok(frame) => {
                self.state = State::Open;
                Ok(vec![Action::Transmit(frame), Action::Opened])
            }
            Err(_) => Ok(self.decline(request.src_ref, reason::NOT_SPECIFIED)),
        }
    }

    /// Responder: refuses a CR with a DR TPDU, whose source reference is zero (X.224 §13.3).
    fn decline(&mut self, remote: u16, why: u8) -> Vec<Action> {
        let refusal = Tpdu::DisconnectRequest(DisconnectRequest {
            dst_ref: remote,
            src_ref: 0,
            reason: why,
            additional_information: None,
            user_data: Vec::new(),
        });
        let mut actions = Vec::new();
        if let Ok(frame) = transmit(&refusal) {
            actions.push(Action::Transmit(frame));
        }
        actions.extend(self.close(Cause::Declined(why)));
        actions
    }

    /// Initiator: the CC must answer our CR, with the same class and no more than the size we
    /// proposed. An absent size is the default of X.224 §13.3.4 b), 128 octets.
    fn confirmed(&mut self, confirm: ConnectionTpdu) -> Result<Vec<Action>, u8> {
        if confirm.class != 0
            || confirm.options != 0
            || confirm.credit != 0
            || !confirm.user_data.is_empty()
            || confirm.dst_ref != REFERENCE
        {
            return Err(reject_cause::NOT_SPECIFIED);
        }
        let agreed = confirm.parameters.tpdu_size.unwrap_or(TpduSize::S128);
        if agreed > self.config.tpdu_size {
            return Err(reject_cause::INVALID_PARAMETER_VALUE);
        }
        self.size = agreed;
        self.remote = confirm.src_ref;
        self.state = State::Open;
        Ok(vec![Action::Opened])
    }

    /// Open: a DT TPDU fills the TSDU being reassembled; a TSDU ends at its EOT.
    fn data(&mut self, data: DataTpdu) -> Result<Vec<Action>, u8> {
        let limit = self.size.octets().saturating_sub(DT_HEADER);
        if data.user_data.len() > limit {
            return Err(reject_cause::NOT_SPECIFIED);
        }
        // All but the last TPDU of a sequence carry data (X.224 §6.3.3).
        if data.user_data.is_empty() && !data.end_of_tsdu {
            return Err(reject_cause::NOT_SPECIFIED);
        }
        if self.tsdu.len().saturating_add(data.user_data.len()) > MAX_TSDU {
            return Err(reject_cause::NOT_SPECIFIED);
        }
        self.tsdu.extend_from_slice(&data.user_data);
        if data.end_of_tsdu {
            let tsdu = std::mem::take(&mut self.tsdu);
            Ok(vec![Action::Deliver(tsdu)])
        } else {
            Ok(Vec::new())
        }
    }

    /// Sends an ER TPDU quoting the rejected TPDU up to the octet in fault, then closes.
    fn reject(&mut self, cause: u8, bytes: &[u8], offset: Option<usize>) -> Vec<Action> {
        let end = offset
            .and_then(|octet| octet.checked_add(1))
            .unwrap_or(bytes.len())
            .min(bytes.len())
            .min(QUOTE);
        let quoted = bytes.get(..end).unwrap_or(bytes).to_vec();
        let error = Tpdu::Error(ErrorTpdu {
            dst_ref: self.remote,
            cause,
            invalid_tpdu: Some(quoted),
        });
        let mut actions = Vec::new();
        if let Ok(frame) = transmit(&error) {
            actions.push(Action::Transmit(frame));
        }
        actions.extend(self.close(Cause::Protocol(cause)));
        actions
    }

    fn send(&mut self, tsdu: &[u8]) -> Vec<Action> {
        if self.state != State::Open {
            return vec![Action::Misuse("send needs an open connection")];
        }
        let Some(limit) = self
            .size
            .octets()
            .checked_sub(DT_HEADER)
            .filter(|octets| *octets > 0)
        else {
            return vec![Action::Misuse("the TPDU size leaves no room for data")];
        };
        // An empty TSDU is one DT TPDU with no data and the EOT set (X.224 §6.3.3).
        let parts: Vec<&[u8]> = if tsdu.is_empty() {
            vec![tsdu]
        } else {
            tsdu.chunks(limit).collect()
        };
        let last = parts.len().saturating_sub(1);
        let mut actions = Vec::with_capacity(parts.len());
        for (index, part) in parts.into_iter().enumerate() {
            let data = Tpdu::Data(DataTpdu {
                end_of_tsdu: index == last,
                number: 0,
                user_data: part.to_vec(),
            });
            match transmit(&data) {
                Ok(frame) => actions.push(Action::Transmit(frame)),
                Err(message) => return vec![Action::Misuse(message)],
            }
        }
        actions
    }

    fn tick(&mut self, now: Duration) -> Vec<Action> {
        match self.state {
            State::Confirming { deadline } if now >= deadline => self.close(Cause::Timeout),
            _ => Vec::new(),
        }
    }

    fn close(&mut self, cause: Cause) -> Vec<Action> {
        if self.is_closed() {
            return Vec::new();
        }
        self.state = State::Closed;
        self.tsdu = Vec::new();
        vec![Action::Closed(cause)]
    }
}

/// A TPDU as one TPKT frame, ready for the network connection.
fn transmit(tpdu: &Tpdu) -> Result<Vec<u8>, &'static str> {
    let bytes = tpdu.encode().map_err(|_| "the TPDU does not encode")?;
    encode_frame(&bytes).map_err(|_| "the frame does not encode")
}
