// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The MMS server (task S2): listens on TCP, runs one association per connection, and answers the
//! services in scope on one model of the VMD ([`crate::vmd::Vmd`]).
//!
//! The model is owned by one task. Each association sends its indicated requests to that task and waits
//! for the answer, so the services run one at a time, in the order they arrive. Each association checks
//! the PDUs against the CBBs it negotiated (the link layer, ISO 9506-2 §8), refuses those it does not
//! serve with a Reject PDU, and reports the unconfirmed PDUs that [`Server::publish`] sends.

pub mod access;
mod delivery;
mod service;

pub use delivery::{Delivery, Discard, MessageId, Publication, Refusal};
use delivery::{Hub, Outgoing, Queued};

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use igs_iso9506_mms_codec::generated::types::{
    ConfirmedServiceRequest, ConfirmedServiceResponse, ServiceError, ServiceErrorErrorClass,
    ServiceErrorErrorClassResource, UnconfirmedService,
};
use igs_iso9506_mms_link::association::{
    self, Action as AssocAction, Answer, Calling, Capabilities,
};
use igs_iso9506_mms_link::config::LinkConfig;
use igs_iso9506_mms_link::requests::{Action, Event, Requests};
use igs_iso9506_mms_link::transport::Role;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};

use crate::client::in_scope_capabilities;
use crate::error::Error;
use crate::tls::Secure;
use crate::transport::{accept, ByteStream};
use crate::vmd::Vmd;
use igs_iso9506_mms_codec::mms::profile::Profile;

/// The associations a server holds at once; a connection beyond it is closed at once.
pub const DEFAULT_MAX_ASSOCIATIONS: usize = 64;

/// How often the model is polled, by default.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// The calls waiting for the model.
const CALL_CAPACITY: usize = 64;

/// The reports waiting for an association by default. An association that falls further behind refuses the
/// reports, and each refusal is an outcome ([`Delivery::Refused`]).
pub const DEFAULT_REPORT_QUEUE: usize = 16;

/// The outcomes waiting for the application. An outcome that the application does not take in time is counted
/// ([`Server::dropped_deliveries`]).
const DELIVERY_CAPACITY: usize = 1024;

/// How long the listener waits after an accept error (for example, too many open files).
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

/// The configuration of a server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// The link parameters: selectors, the limits of outstanding requests, the nesting proposed.
    pub link: LinkConfig,
    /// The parameter CBBs and the services this server supports.
    pub capabilities: Capabilities,
    /// The associations at once; further connections are closed.
    pub max_associations: usize,
    /// The TLS backend: when set, every connection runs its handshake before its association (task X1).
    pub tls: Option<Secure>,
    /// How often the model is polled for its time-driven outputs ([`Model::poll`]).
    pub poll_interval: Duration,
    /// The application profile of the associations: TASE.2 by default, or the IEC 61850 profile (D-033).
    pub profile: Profile,
    /// The reports queued for each association, at least one (N5).
    pub report_queue: usize,
}

impl ServerConfig {
    /// The configuration with [`server_capabilities`] and the default limit of associations.
    pub fn new(link: LinkConfig) -> Self {
        Self {
            link,
            capabilities: server_capabilities(),
            max_associations: DEFAULT_MAX_ASSOCIATIONS,
            tls: None,
            poll_interval: DEFAULT_POLL_INTERVAL,
            profile: Profile::TASE2,
            report_queue: DEFAULT_REPORT_QUEUE,
        }
    }

    /// Queues this many reports for each association (N5): an association that holds this many refuses the next.
    pub fn with_report_queue(mut self, reports: usize) -> Self {
        self.report_queue = reports;
        self
    }

    /// Secures every connection with this TLS backend (task X1).
    pub fn with_tls(mut self, backend: Secure) -> Self {
        self.tls = Some(backend);
        self
    }

    /// Serves alternate access (task N4): the `valt` CBB is negotiated, so the requests that carry an
    /// alternate access reach the model, which reads their paths with [`access::steps`]. The generic VMD
    /// still refuses them, item by item.
    pub fn with_alternate_access(mut self) -> Self {
        use igs_iso9506_mms_codec::generated::tables::PARAMETER_SUPPORT_OPTIONS;
        if let Some(named) = PARAMETER_SUPPORT_OPTIONS
            .iter()
            .find(|named| named.name == "valt")
        {
            set_bit(
                &mut self.capabilities.parameter_cbb,
                named.position as usize,
            );
        }
        self
    }
}

/// Sets one bit of a negotiation bit string, extending it when the bit lies past its end.
fn set_bit(bits: &mut igs_iso9506_mms_codec::schema::BitString, position: usize) {
    let length = bits
        .bytes
        .len()
        .saturating_mul(8)
        .saturating_sub(usize::from(bits.unused));
    let length = length.max(position.saturating_add(1));
    let octets = length.div_ceil(8);
    bits.bytes.resize(octets, 0);
    bits.unused = u8::try_from(octets.saturating_mul(8).saturating_sub(length)).unwrap_or(0);
    if let Some(byte) = bits.bytes.get_mut(position >> 3) {
        *byte |= 0x80u8
            .checked_shr(u32::try_from(position & 7).unwrap_or(0))
            .unwrap_or(0);
    }
}

/// The capabilities of this server: the services in scope, and the parameter CBBs that the model
/// supports: the structures (`str1`, `str2`), the named variables (`vnam`) and the named variable lists
/// (`vlis`). Addresses, alternate access and the other CBBs are not negotiated, so a request that uses
/// them is refused with a Reject PDU.
pub fn server_capabilities() -> Capabilities {
    use igs_iso9506_mms_codec::generated::tables::PARAMETER_SUPPORT_OPTIONS;
    let served = ["str1", "str2", "vnam", "vlis"];
    let positions = PARAMETER_SUPPORT_OPTIONS
        .iter()
        .filter(|named| served.contains(&named.name))
        .filter_map(|named| usize::try_from(named.position).ok());
    Capabilities {
        parameter_cbb: crate::client::bit_string(positions),
        services: in_scope_capabilities().services,
    }
}

/// The number of an association on a server, from 1 in the order of the associations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(pub u64);

/// The identity of an association, as the model sees it: its number, and what its AARQ states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// The number of the association.
    pub id: PeerId,
    /// The identity of the calling side, from its AARQ.
    pub calling: Calling,
}

/// An unconfirmed PDU to send: to every open association when `peer` is `None`, else to that association only.
#[derive(Debug, Clone, PartialEq)]
pub struct Outbound {
    /// The association that the PDU is for, or `None` for all of them.
    pub peer: Option<PeerId>,
    /// The PDU.
    pub report: UnconfirmedService,
}

/// The model that a server serves: the VMD, or an application on it (task S1).
///
/// The model is owned by one task, which runs its calls one at a time. The calls name the association that makes them:
/// its admission, its confirmed services, and its release. [`Model::poll`] runs every
/// [`ServerConfig::poll_interval`]; its outputs go to the associations they name.
pub trait Model: Send + 'static {
    /// Whether the association may be established: a refusal is answered to the Initiate request. Admits every
    /// association by default.
    fn admit(&mut self, _peer: &Peer) -> bool {
        true
    }

    /// The answer to a confirmed service of an association.
    fn dispatch(
        &mut self,
        peer: &Peer,
        service: ConfirmedServiceRequest,
    ) -> Result<ConfirmedServiceResponse, ServiceError>;

    /// The association has ended: it was concluded, aborted, or its transport closed.
    fn released(&mut self, _peer: &Peer) {}

    /// The time-driven outputs, at `now` (the time since the server started).
    fn poll(&mut self, _now: Duration) -> Vec<Outbound> {
        Vec::new()
    }
}

impl Model for Vmd {
    fn dispatch(
        &mut self,
        _peer: &Peer,
        service: ConfirmedServiceRequest,
    ) -> Result<ConfirmedServiceResponse, ServiceError> {
        service::dispatch(self, service)
    }
}

/// A running server. Dropping it stops the listener and the associations.
pub struct Server {
    local_address: SocketAddr,
    hub: Arc<Hub>,
    deliveries: mpsc::Receiver<Delivery>,
    stop: watch::Sender<bool>,
    listener: JoinHandle<()>,
}

impl Server {
    /// Listens on `address` (for example `127.0.0.1:102`, or port 0 for a free port), and serves `vmd`.
    pub async fn bind(address: &str, config: ServerConfig, vmd: Vmd) -> Result<Self, Error> {
        Self::bind_model(address, config, vmd).await
    }

    /// Listens on `address`, and serves `model` (task S1): the model sees each association and its services.
    pub async fn bind_model<M: Model>(
        address: &str,
        config: ServerConfig,
        model: M,
    ) -> Result<Self, Error> {
        let listener = TcpListener::bind(address).await.map_err(Error::Io)?;
        let local_address = listener.local_addr().map_err(Error::Io)?;
        if config.report_queue == 0 {
            return Err(Error::Config(
                igs_iso9506_mms_link::config::ConfigError::OutOfRange {
                    field: "report_queue",
                    min: 1,
                    max: u64::MAX,
                    value: 0,
                },
            ));
        }
        let (calls, received) = mpsc::channel(CALL_CAPACITY);
        let (events, deliveries) = mpsc::channel(DELIVERY_CAPACITY);
        let hub = Arc::new(Hub::new(config.report_queue, events));
        let (stop, stop_rx) = watch::channel(false);
        tokio::spawn(model_task(
            model,
            received,
            Arc::clone(&hub),
            config.poll_interval.max(Duration::from_millis(1)),
        ));
        // The profile must fit this server's configuration before it listens (D-033).
        Requests::new(
            Role::Responder,
            config.link.clone(),
            config.capabilities.clone(),
        )?
        .set_profile(config.profile)
        .map_err(Error::Profile)?;
        let shared = Shared {
            link: config.link,
            capabilities: config.capabilities,
            profile: config.profile,
            calls,
            hub: Arc::clone(&hub),
            tls: config.tls,
            next_peer: Arc::new(AtomicU64::new(1)),
        };
        let limit = Arc::new(Semaphore::new(config.max_associations));
        let listener = tokio::spawn(accept_loop(listener, shared, stop_rx, limit));
        Ok(Self {
            local_address,
            hub,
            deliveries,
            stop,
            listener,
        })
    }

    /// The address the server listens on, with the port it was given.
    pub fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    /// Publishes an unconfirmed PDU (an information report, for instance) to every association that is open, and
    /// returns how many queued it. The call never waits: each association queues it, or refuses it when its queue
    /// is full; the outcomes are [`Delivery`] events ([`Server::next_delivery`]); see [`Server::publish_report`].
    pub fn publish(&self, report: UnconfirmedService) -> usize {
        self.publish_report(report).queued
    }

    /// Publishes like [`Server::publish`], and returns the identifier of the report and the count of the
    /// associations that queued it and that refused it.
    pub fn publish_report(&self, report: UnconfirmedService) -> Publication {
        self.hub.publish(None, report)
    }

    /// The next outcome of a report, for any association, in order; `None` once the server has stopped.
    pub async fn next_delivery(&mut self) -> Option<Delivery> {
        self.deliveries.recv().await
    }

    /// The outcomes that were not sent, because the application did not take them in time (see [`Delivery`]).
    pub fn dropped_deliveries(&self) -> u64 {
        self.hub.dropped()
    }

    /// Stops listening and ends the associations. Returns when the listener has stopped.
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        let _ = self.listener.await;
    }
}

/// The state that every association shares.
#[derive(Clone)]
struct Shared {
    link: LinkConfig,
    capabilities: Capabilities,
    profile: Profile,
    calls: mpsc::Sender<Call>,
    hub: Arc<Hub>,
    tls: Option<Secure>,
    next_peer: Arc<AtomicU64>,
}

impl Shared {
    /// Asks the model whether the association may be established.
    async fn admit(&self, peer: &Peer) -> bool {
        let (reply, answer) = oneshot::channel();
        if self
            .calls
            .send(Call::Admit {
                peer: peer.clone(),
                reply,
            })
            .await
            .is_err()
        {
            return false;
        }
        answer.await.unwrap_or(false)
    }

    /// Runs a confirmed service of the association on the model, and waits for its answer.
    async fn call(
        &self,
        peer: &Peer,
        service: ConfirmedServiceRequest,
    ) -> Result<ConfirmedServiceResponse, ServiceError> {
        let (reply, answer) = oneshot::channel();
        let call = Call::Service {
            peer: peer.clone(),
            service,
            reply,
        };
        if self.calls.send(call).await.is_err() {
            return Err(stopping());
        }
        answer.await.unwrap_or_else(|_| Err(stopping()))
    }

    /// Tells the model that the association has ended.
    async fn released(&self, peer: &Peer) {
        let _ = self.calls.send(Call::Released { peer: peer.clone() }).await;
    }
}

/// The MMS error of a request that the stopping server cannot serve.
fn stopping() -> ServiceError {
    ServiceError {
        error_class: ServiceErrorErrorClass::Resource(ServiceErrorErrorClassResource::OTHER),
        additional_code: None,
        additional_description: None,
        service_specific_info: None,
    }
}

/// A call to the model, from an association.
enum Call {
    Admit {
        peer: Peer,
        reply: oneshot::Sender<bool>,
    },
    Service {
        peer: Peer,
        service: ConfirmedServiceRequest,
        reply: oneshot::Sender<Result<ConfirmedServiceResponse, ServiceError>>,
    },
    Released {
        peer: Peer,
    },
}

/// The one owner of the model: it runs the calls in turn, and polls it. It ends when no association holds a sender.
async fn model_task<M: Model>(
    mut model: M,
    mut calls: mpsc::Receiver<Call>,
    hub: Arc<Hub>,
    poll_interval: Duration,
) {
    let started = Instant::now();
    let mut ticker = tokio::time::interval(poll_interval);
    loop {
        tokio::select! {
            call = calls.recv() => match call {
                Some(Call::Admit { peer, reply }) => {
                    // The association may have ended: its answer is then not needed.
                    let _ = reply.send(model.admit(&peer));
                }
                Some(Call::Service { peer, service, reply }) => {
                    let _ = reply.send(model.dispatch(&peer, service));
                }
                Some(Call::Released { peer }) => model.released(&peer),
                None => return,
            },
            _ = ticker.tick() => {
                for outbound in model.poll(started.elapsed()) {
                    hub.publish(outbound.peer, outbound.report);
                }
            }
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    shared: Shared,
    mut stop: watch::Receiver<bool>,
    limit: Arc<Semaphore>,
) {
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => match Arc::clone(&limit).try_acquire_owned() {
                    Ok(permit) => {
                        let _ = stream.set_nodelay(true);
                        tokio::spawn(connection(stream, shared.clone(), stop.clone(), permit));
                    }
                    // The server holds as many associations as it allows: the connection is closed.
                    Err(_) => drop(stream),
                },
                Err(_) => tokio::time::sleep(ACCEPT_RETRY).await,
            },
            _ = stop.changed() => return,
        }
    }
}

/// One connection: its TLS handshake when the server is secured (within the connect timeout), then its
/// association. A handshake that fails closes the connection.
async fn connection(
    stream: TcpStream,
    shared: Shared,
    stop: watch::Receiver<bool>,
    permit: OwnedSemaphorePermit,
) {
    match shared.tls.clone() {
        None => association(stream, shared, stop, permit).await,
        Some(secure) => {
            let handshake = secure.backend().accept(stream);
            if let Ok(Ok(secured)) = timeout(shared.link.connect_timeout, handshake).await {
                association(secured, shared, stop, permit).await;
            }
        }
    }
}

/// One association: the transport connection, the requests of the responder, and the services. The model is told
/// when an admitted association ends, however it ends.
async fn association<S: ByteStream>(
    stream: S,
    shared: Shared,
    stop: watch::Receiver<bool>,
    _permit: OwnedSemaphorePermit,
) {
    let id = PeerId(shared.next_peer.fetch_add(1, Ordering::Relaxed));
    let mut admitted: Option<Peer> = None;
    conduct(stream, &shared, stop, id, &mut admitted).await;
    if let Some(peer) = admitted {
        shared.released(&peer).await;
    }
}

/// The actions of one event, untagged: no report is waiting on them.
fn untagged(actions: Vec<Action>) -> impl Iterator<Item = (Option<MessageId>, Action)> {
    actions.into_iter().map(|action| (None, action))
}

/// The next report queued for the association, once it is open; pending forever before that.
async fn next_queued(queue: &mut Option<mpsc::Receiver<Queued>>) -> Option<Queued> {
    match queue {
        Some(queue) => queue.recv().await,
        None => std::future::pending().await,
    }
}

/// The exchanges of one association, until it ends. `admitted` is set when the model admits the association.
async fn conduct<S: ByteStream>(
    stream: S,
    shared: &Shared,
    mut stop: watch::Receiver<bool>,
    id: PeerId,
    admitted: &mut Option<Peer>,
) {
    let Ok(mut transport) = accept(stream, shared.link.clone()).await else {
        return;
    };
    let Ok(mut requests) = Requests::new(
        Role::Responder,
        shared.link.clone(),
        shared.capabilities.clone(),
    ) else {
        return;
    };
    if requests.set_profile(shared.profile).is_err() {
        return;
    }
    // The reports of this association. Its drop, however the association ends, discards what it still holds.
    let mut outgoing = Outgoing::new(Arc::clone(&shared.hub), id);
    let started = Instant::now();
    // The identity that the AARQ states, indicated just before the Initiate request.
    let mut calling: Option<Calling> = None;
    // FIFO: the actions of one event are carried out in the order the layers give them. A send that carries a
    // report is tagged with the report's message identifier, until it is written.
    let mut work: VecDeque<(Option<MessageId>, Action)> = VecDeque::new();
    loop {
        tokio::select! {
            received = transport.recv() => {
                let Some(tsdu) = received else { return };
                work.extend(untagged(requests.handle(
                    Event::Association(association::Event::Received(tsdu)),
                    started.elapsed(),
                )));
            }
            queued = next_queued(&mut outgoing.queue), if requests.is_open() => {
                let Some(queued) = queued else { return };
                let actions = requests.handle(Event::Unconfirmed(queued.report), started.elapsed());
                // A report that the protocol layer does not send is discarded: the negotiation does not allow it.
                if !actions.iter().any(|action| matches!(action, Action::Send(_))) {
                    shared.hub.discarded(queued.id, id, Discard::NotSent);
                }
                for action in actions {
                    if matches!(action, Action::Send(_)) {
                        outgoing.pending.push_back(queued.id);
                        work.push_back((Some(queued.id), action));
                    } else {
                        work.push_back((None, action));
                    }
                }
            }
            _ = stop.changed() => return,
        }
        while let Some((tag, action)) = work.pop_front() {
            match action {
                Action::Send(tsdu) => {
                    if transport.send(tsdu).await.is_err() {
                        return;
                    }
                    if let Some(message) = tag {
                        outgoing.pending.pop_front();
                        shared.hub.written(message, id);
                    }
                }
                Action::ReleaseTransport => return,
                Action::Association(AssocAction::Established(_)) => outgoing.open(),
                Action::Association(AssocAction::Calling(identity)) => calling = Some(identity),
                Action::Association(AssocAction::Indication(_)) => {
                    let peer = Peer {
                        id,
                        calling: calling.take().unwrap_or(Calling {
                            ap_title: None,
                            ae_qualifier: None,
                        }),
                    };
                    let accepted = shared.admit(&peer).await;
                    let answer = if accepted {
                        Answer::Accept
                    } else {
                        Answer::Reject
                    };
                    if accepted {
                        *admitted = Some(peer);
                    }
                    work.extend(untagged(requests.handle(
                        Event::Association(association::Event::Answer(answer)),
                        started.elapsed(),
                    )));
                }
                Action::Indication { invoke, service } => {
                    let result = match admitted.as_ref() {
                        Some(peer) => shared.call(peer, service).await,
                        // A service is served only on an admitted association.
                        None => Err(stopping()),
                    };
                    work.extend(untagged(
                        requests.handle(Event::Respond(invoke, result), started.elapsed()),
                    ));
                }
                Action::Association(AssocAction::Concluded)
                | Action::Association(AssocAction::Aborted(_)) => return,
                _ => {}
            }
        }
    }
}
