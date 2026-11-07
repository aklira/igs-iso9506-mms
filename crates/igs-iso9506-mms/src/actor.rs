// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The background task of a client: it owns the connection, the association and the requests, and
//! serves the calls of the handles (task T2).
//!
//! One task runs everything, so that no state is shared. It waits on three things at once: the
//! calls, the TSDUs of the connection, and a one-second tick that checks the request timeouts and the
//! close.

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use igs_iso9506_mms_codec::generated::types::{
    ConfirmedServiceRequest, ConfirmedServiceResponse, InitiateRequestPDUInitRequestDetail,
    ParameterSupportOptions, ServiceSupportOptions,
};
use igs_iso9506_mms_codec::mms::{InitiateRequestPDU, Integer16, Integer8};
use igs_iso9506_mms_link::association::{self, MMS_VERSION};
use igs_iso9506_mms_link::requests::{Action as RequestAction, Event as RequestEvent, Requests};
use igs_iso9506_mms_link::transport::Role;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{interval, sleep, timeout, Instant, MissedTickBehavior};

use crate::client::{ClientConfig, Command, ConnectionState, Event, Reconnect};
use crate::connector::Connector;
use crate::error::Error;
use crate::transport::{self, Transport};

/// How often the timeouts are checked.
const TICK: Duration = Duration::from_secs(1);

/// The answer to one call.
type Reply = oneshot::Sender<Result<ConfirmedServiceResponse, Error>>;

/// One connection: the transport and the requests over it.
pub(crate) struct Link {
    transport: Transport,
    requests: Requests,
}

/// A close in progress: its answer, and the instant after which the association is aborted.
struct Closing {
    reply: oneshot::Sender<Result<(), Error>>,
    deadline: Instant,
}

/// The end of the association, as reported by the requests layer.
enum Ending {
    Concluded,
    Aborted,
}

/// The task of one client.
pub(crate) struct Actor<C: Connector> {
    connector: C,
    config: ClientConfig,
    commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
    link: Option<Link>,
    started: Instant,
    /// The requests issued, by invoke ID, waiting for their answer.
    pending: BTreeMap<u32, Reply>,
    /// The calls not yet issued, waiting for an outstanding slot.
    queue: VecDeque<(ConfirmedServiceRequest, Reply)>,
    closing: Option<Closing>,
    done: bool,
}

/// The Initiate proposed for the configuration (ISO 9506-1 §8.2.1).
fn proposal(config: &ClientConfig) -> InitiateRequestPDU {
    InitiateRequestPDU {
        local_detail_calling: None,
        proposed_max_serv_outstanding_calling: Integer16(i64::from(
            config.link.max_outstanding_calling,
        )),
        proposed_max_serv_outstanding_called: Integer16(i64::from(
            config.link.max_outstanding_called,
        )),
        proposed_data_structure_nesting_level: Some(Integer8(i64::from(config.link.nesting_level))),
        init_request_detail: InitiateRequestPDUInitRequestDetail {
            proposed_version_number: Integer16(MMS_VERSION),
            proposed_parameter_cbb: ParameterSupportOptions(
                config.capabilities.parameter_cbb.clone(),
            ),
            services_supported_calling: ServiceSupportOptions(config.capabilities.services.clone()),
            additional_supported_calling: None,
            additional_cbb_supported_calling: None,
            privilege_class_identity_calling: None,
        },
    }
}

/// Writes the TSDUs of the actions, and returns the others.
async fn write(
    transport: &mut Transport,
    actions: Vec<RequestAction>,
) -> Result<Vec<RequestAction>, Error> {
    let mut rest = Vec::new();
    for action in actions {
        match action {
            RequestAction::Send(tsdu) => transport.send(tsdu).await?,
            other => rest.push(other),
        }
    }
    Ok(rest)
}

/// Opens one connection and establishes its association: the Initiate is proposed, and the answer
/// awaited within the request timeout.
pub(crate) async fn establish<C: Connector>(
    connector: &mut C,
    config: &ClientConfig,
) -> Result<Link, Error> {
    let stream = connector.connect().await?;
    let mut transport = transport::connect(stream, config.link.clone()).await?;
    let mut requests = Requests::new(
        Role::Initiator,
        config.link.clone(),
        config.capabilities.clone(),
    )?;
    let first = requests.handle(
        RequestEvent::Association(association::Event::Associate(proposal(config))),
        Duration::ZERO,
    );
    let mut reported = write(&mut transport, first).await?;
    loop {
        let outcome = reported.iter().find_map(|action| match action {
            RequestAction::Association(association::Action::Established(_)) => Some(Ok(())),
            RequestAction::Association(association::Action::Refused(refusal)) => {
                Some(Err(Error::Refused(refusal.clone())))
            }
            RequestAction::Association(association::Action::Aborted(_)) => {
                Some(Err(Error::ConnectionLost))
            }
            _ => None,
        });
        if let Some(outcome) = outcome {
            outcome?;
            return Ok(Link {
                transport,
                requests,
            });
        }
        let tsdu = timeout(config.link.request_timeout, transport.recv())
            .await
            .map_err(|_| Error::Timeout)?
            .ok_or(Error::ConnectionLost)?;
        let actions = requests.handle(
            RequestEvent::Association(association::Event::Received(tsdu)),
            Duration::ZERO,
        );
        reported = write(&mut transport, actions).await?;
    }
}

/// The receive side of the connection; pending forever while there is none.
async fn receive(link: &mut Option<Link>) -> Option<Vec<u8>> {
    match link.as_mut() {
        Some(link) => link.transport.recv().await,
        None => std::future::pending().await,
    }
}

/// The instant `after` from now, or now when it cannot be represented.
fn after(delay: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(delay).unwrap_or(now)
}

impl<C: Connector> Actor<C> {
    /// The task of a client that is connected through `link`.
    pub(crate) fn new(
        connector: C,
        config: ClientConfig,
        commands: mpsc::Receiver<Command>,
        events: mpsc::Sender<Event>,
        link: Link,
    ) -> Self {
        Self {
            connector,
            config,
            commands,
            events,
            link: Some(link),
            started: Instant::now(),
            pending: BTreeMap::new(),
            queue: VecDeque::new(),
            closing: None,
            done: false,
        }
    }

    /// Serves the calls and the connection until the client is closed.
    pub(crate) async fn run(mut self) {
        let mut ticker = interval(TICK);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        while !self.done {
            // While the queue is full, or a close is in progress, calls wait in the channel.
            let accepting =
                self.closing.is_none() && self.queue.len() < self.config.command_capacity.max(1);
            tokio::select! {
                command = self.commands.recv(), if accepting => match command {
                    Some(command) => self.command(command).await,
                    // Every handle is gone: close as an orderly close would.
                    None => self.shut().await,
                },
                tsdu = receive(&mut self.link) => match tsdu {
                    Some(tsdu) => self.received(tsdu).await,
                    None => self.lost().await,
                },
                _ = ticker.tick() => self.tick().await,
            }
            self.pump().await;
        }
        let _ = self
            .events
            .send(Event::State(ConnectionState::Closed))
            .await;
    }

    fn now(&self) -> Duration {
        self.started.elapsed()
    }

    /// Hands an event to the requests layer, when there is a connection.
    fn requests_handle(&mut self, event: RequestEvent) -> Vec<RequestAction> {
        let now = self.now();
        match self.link.as_mut() {
            Some(link) => link.requests.handle(event, now),
            None => Vec::new(),
        }
    }

    async fn command(&mut self, command: Command) {
        match command {
            Command::Request { service, reply } => self.queue.push_back((service, reply)),
            Command::Close { reply } => self.start_close(reply).await,
        }
    }

    /// The close of a handle that went away: the same as an orderly close, with no one to answer.
    async fn shut(&mut self) {
        if self.link.is_none() {
            self.done = true;
            return;
        }
        let (reply, _) = oneshot::channel();
        self.start_close(reply).await;
    }

    async fn start_close(&mut self, reply: oneshot::Sender<Result<(), Error>>) {
        if self.link.is_none() {
            let _ = reply.send(Ok(()));
            self.done = true;
            return;
        }
        self.fail_queue(|| Error::ClientClosed);
        self.closing = Some(Closing {
            reply,
            deadline: after(self.config.link.request_timeout),
        });
        let actions = self.requests_handle(RequestEvent::Association(association::Event::Conclude));
        self.dispatch(actions).await;
    }

    /// Issues the queued calls while the outstanding limit allows.
    async fn pump(&mut self) {
        loop {
            let can_issue = self
                .link
                .as_ref()
                .is_some_and(|link| link.requests.can_request());
            if !can_issue {
                break;
            }
            let Some((service, reply)) = self.queue.pop_front() else {
                break;
            };
            let actions = self.requests_handle(RequestEvent::Request(service));
            let issued = actions.iter().find_map(|action| match action {
                RequestAction::Requested(invoke) => Some(*invoke),
                _ => None,
            });
            match issued {
                Some(invoke) => {
                    self.pending.insert(invoke, reply);
                }
                None => {
                    let message = actions
                        .iter()
                        .find_map(|action| match action {
                            RequestAction::Misuse(message) => Some(*message),
                            _ => None,
                        })
                        .unwrap_or("the request is refused");
                    let _ = reply.send(Err(Error::Misuse(message)));
                }
            }
            self.dispatch(actions).await;
        }
    }

    /// Carries out the actions of the requests layer, in order; a request that the layer rejects is
    /// answered with a rejection of its own.
    async fn dispatch(&mut self, actions: Vec<RequestAction>) {
        let mut work: VecDeque<RequestAction> = actions.into();
        let mut ending = None;
        while let Some(action) = work.pop_front() {
            match action {
                RequestAction::Send(tsdu) => {
                    if let Some(link) = self.link.as_mut() {
                        // A failed write ends the connection: the receive side sees its end.
                        let _ = link.transport.send(tsdu).await;
                    }
                }
                RequestAction::Response { invoke, response } => {
                    self.answer(invoke, Ok(response));
                }
                RequestAction::Error { invoke, error } => {
                    self.answer(invoke, Err(Error::Service(error)));
                }
                RequestAction::Timeout(invoke) => self.answer(invoke, Err(Error::Timeout)),
                RequestAction::Rejected {
                    invoke: Some(invoke),
                    reason,
                } => self.answer(invoke, Err(Error::Rejected(reason))),
                RequestAction::Indication { invoke, .. } => {
                    // This client serves no service: an indicated request is rejected as unrecognized.
                    work.extend(self.requests_handle(RequestEvent::RejectIndication(invoke)));
                }
                RequestAction::Unconfirmed(service) => {
                    let _ = self.events.send(Event::Report(service)).await;
                }
                RequestAction::Association(association::Action::Concluded) => {
                    ending = Some(Ending::Concluded);
                }
                RequestAction::Association(association::Action::Aborted(_)) => {
                    ending = Some(Ending::Aborted);
                }
                _ => {}
            }
        }
        if let Some(ending) = ending {
            self.end(ending).await;
        }
    }

    fn answer(&mut self, invoke: u32, result: Result<ConfirmedServiceResponse, Error>) {
        if let Some(reply) = self.pending.remove(&invoke) {
            let _ = reply.send(result);
        }
    }

    async fn end(&mut self, ending: Ending) {
        match ending {
            Ending::Concluded => self.finish_close().await,
            Ending::Aborted if self.closing.is_some() => self.finish_close().await,
            Ending::Aborted => self.lost().await,
        }
    }

    async fn received(&mut self, tsdu: Vec<u8>) {
        let actions = self.requests_handle(RequestEvent::Association(
            association::Event::Received(tsdu),
        ));
        self.dispatch(actions).await;
    }

    async fn tick(&mut self) {
        // The release was not confirmed in time: the association is aborted (docs/capabilities.md, G1).
        let expired = self
            .closing
            .as_ref()
            .is_some_and(|closing| Instant::now() >= closing.deadline);
        if expired {
            let actions =
                self.requests_handle(RequestEvent::Association(association::Event::Abort));
            self.dispatch(actions).await;
            if self.closing.is_some() {
                self.finish_close().await;
            }
            return;
        }
        let actions = self.requests_handle(RequestEvent::Tick);
        self.dispatch(actions).await;
    }

    /// The connection ended without a close: the calls in flight fail, then the client reconnects if
    /// its policy allows.
    async fn lost(&mut self) {
        if let Some(link) = self.link.take() {
            let _ = link.transport.shutdown().await;
        }
        self.fail_all(|| Error::ConnectionLost);
        let _ = self
            .events
            .send(Event::State(ConnectionState::Disconnected))
            .await;
        if self.closing.is_some() {
            self.finish_close().await;
            return;
        }
        match self.reconnect().await {
            Some(link) => {
                self.link = Some(link);
                let _ = self
                    .events
                    .send(Event::State(ConnectionState::Connected))
                    .await;
            }
            None => self.done = true,
        }
    }

    /// Makes new connections, with backoff, until one is established, or the policy gives up.
    async fn reconnect(&mut self) -> Option<Link> {
        let Reconnect::Backoff {
            initial,
            max,
            attempts,
        } = self.config.reconnect.clone()
        else {
            return None;
        };
        let mut delay = initial;
        let mut attempt: u32 = 0;
        loop {
            attempt = attempt.saturating_add(1);
            if attempts.is_some_and(|limit| attempt > limit) {
                return None;
            }
            let _ = self
                .events
                .send(Event::State(ConnectionState::Reconnecting { attempt }))
                .await;
            if !self.wait_rejecting(delay).await {
                return None;
            }
            match establish(&mut self.connector, &self.config).await {
                Ok(link) => return Some(link),
                Err(_) => delay = delay.saturating_mul(2).min(max),
            }
        }
    }

    /// Waits for `delay`, answering the calls meanwhile: a request fails, a close ends the client.
    /// Returns false when the client was closed.
    async fn wait_rejecting(&mut self, delay: Duration) -> bool {
        let wait = sleep(delay);
        tokio::pin!(wait);
        loop {
            tokio::select! {
                _ = &mut wait => return true,
                command = self.commands.recv() => match command {
                    Some(Command::Request { reply, .. }) => {
                        let _ = reply.send(Err(Error::ConnectionLost));
                    }
                    Some(Command::Close { reply }) => {
                        let _ = reply.send(Ok(()));
                        return false;
                    }
                    None => return false,
                },
            }
        }
    }

    /// The close is complete, or the connection ended during it: the stream is shut and the caller
    /// answered.
    async fn finish_close(&mut self) {
        if let Some(link) = self.link.take() {
            let _ = link.transport.shutdown().await;
        }
        self.fail_all(|| Error::ClientClosed);
        if let Some(closing) = self.closing.take() {
            let _ = closing.reply.send(Ok(()));
        }
        self.done = true;
    }

    fn fail_all(&mut self, make: fn() -> Error) {
        for (_, reply) in std::mem::take(&mut self.pending) {
            let _ = reply.send(Err(make()));
        }
        self.fail_queue(make);
    }

    fn fail_queue(&mut self, make: fn() -> Error) {
        for (_, reply) in self.queue.drain(..) {
            let _ = reply.send(Err(make()));
        }
    }
}
