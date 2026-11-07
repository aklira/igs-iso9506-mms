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
    IdentifyResponse, ReadRequest, ReadResponse, UnconfirmedService, WriteRequest, WriteResponse,
};
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
    get_name_list, GetNameList, GetNameListRequest, GetNameListResponse
);
typed_service!(
    /// Read: the values of the variables named.
    read, Read, ReadRequest, ReadResponse
);
typed_service!(
    /// Write: the values of the variables named.
    write, Write, WriteRequest, WriteResponse
);
typed_service!(
    /// GetVariableAccessAttributes: the type and the address of a variable.
    get_variable_access_attributes, GetVariableAccessAttributes,
    GetVariableAccessAttributesRequest, GetVariableAccessAttributesResponse
);
typed_service!(
    /// DefineNamedVariableList: defines a list of variables.
    define_named_variable_list, DefineNamedVariableList,
    DefineNamedVariableListRequest, DefineNamedVariableListResponse
);
typed_service!(
    /// GetNamedVariableListAttributes: the variables of a list.
    get_named_variable_list_attributes, GetNamedVariableListAttributes,
    GetNamedVariableListAttributesRequest, GetNamedVariableListAttributesResponse
);
typed_service!(
    /// DeleteNamedVariableList: deletes lists of variables.
    delete_named_variable_list, DeleteNamedVariableList,
    DeleteNamedVariableListRequest, DeleteNamedVariableListResponse
);
