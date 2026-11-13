// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The MMS client (task T2): connect, the services in scope, the events of the connection, and the
//! reconnection policy.
//!
//! A [`Client`] is a handle on a background task that owns the connection (see `actor.rs`). Calls
//! are queued on a bounded channel, and each returns when its answer, or its error, is known.
//!
//! Back-pressure, documented: a call waits while the command channel is full, which holds at most
//! `command_capacity` calls, and the requests queued behind it, which are at most as many; the
//! events channel holds `event_capacity` events, and the task waits on it when the consumer is slow,
//! so that reports are never dropped.

use std::time::Duration;

use igs_iso9506_mms_codec::generated::types::{
    ConfirmedServiceRequest, ConfirmedServiceResponse, DefineNamedVariableListRequest,
    DefineNamedVariableListResponse, DeleteNamedVariableListRequest,
    DeleteNamedVariableListResponse, GetNameListRequest, GetNameListResponse,
    GetNamedVariableListAttributesRequest, GetNamedVariableListAttributesResponse,
    GetVariableAccessAttributesRequest, GetVariableAccessAttributesResponse, IdentifyRequest,
    IdentifyResponse, ReadJournalRequest, ReadJournalResponse, ReadRequest, ReadResponse,
    UnconfirmedService, WriteRequest, WriteResponse,
};
use igs_iso9506_mms_codec::mms::profile::Profile;
use igs_iso9506_mms_link::association::Capabilities;
use igs_iso9506_mms_link::config::LinkConfig;
use tokio::sync::{mpsc, oneshot};

use crate::actor;
use crate::connector::{Connector, TcpConnector};
use crate::error::Error;

/// Calls and events that the client may hold before their senders wait.
pub const DEFAULT_CAPACITY: usize = 32;

/// How the client reconnects after its connection ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconnect {
    /// Never: the client closes when its connection ends.
    Never,
    /// With exponential backoff from `initial` up to `max`; `attempts` bounds the tries, `None`
    /// keeps trying.
    Backoff {
        /// The first delay.
        initial: Duration,
        /// The longest delay.
        max: Duration,
        /// The number of attempts, or unlimited.
        attempts: Option<u32>,
    },
}

impl Default for Reconnect {
    fn default() -> Self {
        Self::Backoff {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(30),
            attempts: None,
        }
    }
}

/// The configuration of a client.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// The link parameters: selectors, timeouts, the limits proposed.
    pub link: LinkConfig,
    /// The parameter CBBs and the services this end supports.
    pub capabilities: Capabilities,
    /// The reconnection policy.
    pub reconnect: Reconnect,
    /// The capacity of the command channel, in calls.
    pub command_capacity: usize,
    /// The capacity of the event channel.
    pub event_capacity: usize,
    /// Whether the decoded actions of the connection and the calls are reported as [`Event::Trace`].
    pub trace: bool,
    /// Whether the parameter CBBs proposed are taken as negotiated for the outgoing checks, for a peer
    /// that answers services without having negotiated their CBBs (`docs/capabilities.md`, G8). Off
    /// by default: the standard's negotiation is the rule.
    pub lenient_parameter_cbbs: bool,
    /// The application profile of the associations: TASE.2 by default, or the IEC 61850 profile of
    /// IEC 61850-8-1 clause 24 (D-033).
    pub profile: Profile,
}

impl ClientConfig {
    /// A configuration with the default reconnection policy and capacities.
    pub fn new(link: LinkConfig, capabilities: Capabilities) -> Self {
        Self {
            link,
            capabilities,
            reconnect: Reconnect::default(),
            command_capacity: DEFAULT_CAPACITY,
            event_capacity: DEFAULT_CAPACITY,
            trace: false,
            lenient_parameter_cbbs: false,
            profile: Profile::TASE2,
        }
    }
}

/// The state of the connection, reported as an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// The association is established.
    Connected,
    /// The connection ended.
    Disconnected,
    /// A new connection is being made; `attempt` counts from 1.
    Reconnecting {
        /// The attempt number.
        attempt: u32,
    },
    /// The client is closed; no more events follow.
    Closed,
}

/// An event of the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The state of the connection changed.
    State(ConnectionState),
    /// An unconfirmed report of the peer (an information report).
    Report(UnconfirmedService),
    /// A decoded action of the connection, or a call, when tracing is on.
    Trace(String),
}

/// The events of a client, in order.
#[derive(Debug)]
pub struct Events {
    receiver: mpsc::Receiver<Event>,
}

impl Events {
    /// The next event; `None` once the client is closed and every event was taken.
    pub async fn next(&mut self) -> Option<Event> {
        self.receiver.recv().await
    }
}

/// A call to the background task.
pub(crate) enum Command {
    /// A confirmed request, answered on `reply`.
    Request {
        service: ConfirmedServiceRequest,
        reply: oneshot::Sender<Result<ConfirmedServiceResponse, Error>>,
    },
    /// Close the association in an orderly way, answered on `reply`.
    Close {
        reply: oneshot::Sender<Result<(), Error>>,
    },
    /// Abort the association at once, answered on `reply`.
    Abort {
        reply: oneshot::Sender<Result<(), Error>>,
    },
}

/// The parameter CBBs and the services in scope of the profile: every parameter CBB of the table, and
/// every service whose `in_scope` flag is set, with the unconfirmed information report.
pub fn in_scope_capabilities() -> Capabilities {
    use igs_iso9506_mms_codec::generated::tables::{PARAMETER_SUPPORT_OPTIONS, SERVICES};
    Capabilities {
        parameter_cbb: bit_string(
            PARAMETER_SUPPORT_OPTIONS
                .iter()
                .filter_map(|named| usize::try_from(named.position).ok()),
        ),
        services: bit_string(
            SERVICES
                .iter()
                .filter(|service| service.in_scope)
                .filter_map(|service| usize::try_from(service.bit.position).ok()),
        ),
    }
}

/// A bit string with the bits at these positions set, at least 96 bits long (ISO 9506-2 §8.1.3).
pub(crate) fn bit_string(
    positions: impl Iterator<Item = usize>,
) -> igs_iso9506_mms_codec::schema::BitString {
    let positions: Vec<usize> = positions.collect();
    let length = positions
        .iter()
        .map(|position| position.saturating_add(1))
        .max()
        .unwrap_or(0)
        .max(96);
    let octets = length.div_ceil(8);
    let mut bytes = vec![0u8; octets];
    for position in positions {
        let mask = 0x80u8
            .checked_shr(u32::try_from(position & 7).unwrap_or(0))
            .unwrap_or(0);
        if let Some(byte) = bytes.get_mut(position >> 3) {
            *byte |= mask;
        }
    }
    let unused = octets.saturating_mul(8).saturating_sub(length);
    igs_iso9506_mms_codec::schema::BitString {
        unused: u8::try_from(unused).unwrap_or(0),
        bytes,
    }
}

/// A handle on an MMS client. Cloning it shares the connection.
#[derive(Debug, Clone)]
pub struct Client {
    commands: mpsc::Sender<Command>,
}

impl Client {
    /// Connects over TCP to `address` and establishes the association.
    pub async fn connect(address: &str, config: ClientConfig) -> Result<(Self, Events), Error> {
        let connector = TcpConnector::new(address, config.link.connect_timeout);
        Self::connect_with(connector, config).await
    }

    /// Connects through `connector`, and establishes the association.
    pub async fn connect_with<C: Connector>(
        mut connector: C,
        config: ClientConfig,
    ) -> Result<(Self, Events), Error> {
        let (commands_tx, commands_rx) = mpsc::channel(config.command_capacity.max(1));
        let (events_tx, events_rx) = mpsc::channel(config.event_capacity.max(1));
        let link = actor::establish(&mut connector, &config).await?;
        // The first event: the association is established. The channel holds at least one event.
        let _ = events_tx
            .send(Event::State(ConnectionState::Connected))
            .await;
        let actor = actor::Actor::new(connector, config, commands_rx, events_tx, link);
        tokio::spawn(actor.run());
        Ok((
            Self {
                commands: commands_tx,
            },
            Events {
                receiver: events_rx,
            },
        ))
    }

    /// Sends a confirmed request and waits for its answer.
    pub async fn request(
        &self,
        service: ConfirmedServiceRequest,
    ) -> Result<ConfirmedServiceResponse, Error> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Request { service, reply })
            .await
            .map_err(|_| Error::ClientClosed)?;
        answer.await.map_err(|_| Error::ClientClosed)?
    }

    /// Closes the association in an orderly way. If the peer does not confirm the release within the
    /// request timeout, the association is aborted: the fallback of `docs/capabilities.md` (G1).
    pub async fn close(&self) -> Result<(), Error> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Close { reply })
            .await
            .map_err(|_| Error::ClientClosed)?;
        answer.await.map_err(|_| Error::ClientClosed)?
    }

    /// Aborts the association at once, without the release. For a client that has an error to leave
    /// with, where the orderly close would wait for a release the peer may not confirm.
    pub async fn abort(&self) -> Result<(), Error> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Abort { reply })
            .await
            .map_err(|_| Error::ClientClosed)?;
        answer.await.map_err(|_| Error::ClientClosed)?
    }

    /// Identify: the vendor, model and revision of the peer.
    pub async fn identify(&self) -> Result<IdentifyResponse, Error> {
        match self
            .request(ConfirmedServiceRequest::Identify(IdentifyRequest(())))
            .await?
        {
            ConfirmedServiceResponse::Identify(response) => Ok(response),
            _ => Err(Error::Unexpected),
        }
    }
}

macro_rules! typed_service {
    ($(#[$doc:meta])* $name:ident, $variant:ident, $request:ty, $response:ty) => {
        impl Client {
            $(#[$doc])*
            pub async fn $name(&self, request: $request) -> Result<$response, Error> {
                match self
                    .request(ConfirmedServiceRequest::$variant(request))
                    .await?
                {
                    ConfirmedServiceResponse::$variant(response) => Ok(response),
                    _ => Err(Error::Unexpected),
                }
            }
        }
    };
}

typed_service!(
    /// GetNameList: the names of the objects of a class and scope.
    get_name_list,
    GetNameList,
    GetNameListRequest,
    GetNameListResponse
);
typed_service!(
    /// Read: the values of the variables named.
    read,
    Read,
    ReadRequest,
    ReadResponse
);
typed_service!(
    /// Write: the values of the variables named.
    write,
    Write,
    WriteRequest,
    WriteResponse
);
typed_service!(
    /// GetVariableAccessAttributes: the type and the address of a variable.
    get_variable_access_attributes,
    GetVariableAccessAttributes,
    GetVariableAccessAttributesRequest,
    GetVariableAccessAttributesResponse
);
typed_service!(
    /// DefineNamedVariableList: defines a list of variables.
    define_named_variable_list,
    DefineNamedVariableList,
    DefineNamedVariableListRequest,
    DefineNamedVariableListResponse
);
typed_service!(
    /// GetNamedVariableListAttributes: the variables of a list.
    get_named_variable_list_attributes,
    GetNamedVariableListAttributes,
    GetNamedVariableListAttributesRequest,
    GetNamedVariableListAttributesResponse
);
typed_service!(
    /// DeleteNamedVariableList: deletes lists of variables.
    delete_named_variable_list,
    DeleteNamedVariableList,
    DeleteNamedVariableListRequest,
    DeleteNamedVariableListResponse
);
typed_service!(
    /// ReadJournal: the entries of a journal that the filters select (ISO 9506-2 clause 23.2); needs the `readJournal` service.
    read_journal,
    ReadJournal,
    ReadJournalRequest,
    ReadJournalResponse
);
