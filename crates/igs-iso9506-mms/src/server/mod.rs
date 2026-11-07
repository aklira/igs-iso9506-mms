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

mod service;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use igs_iso9506_mms_codec::generated::types::{
    ConfirmedServiceRequest, ConfirmedServiceResponse, ServiceError, ServiceErrorErrorClass,
    ServiceErrorErrorClassResource, UnconfirmedService,
};
use igs_iso9506_mms_link::association::{self, Action as AssocAction, Answer, Capabilities};
use igs_iso9506_mms_link::config::LinkConfig;
use igs_iso9506_mms_link::requests::{Action, Event, Requests};
use igs_iso9506_mms_link::transport::Role;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, oneshot, watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::client::in_scope_capabilities;
use crate::error::Error;
use crate::transport::accept;
use crate::vmd::Vmd;

/// The associations a server holds at once; a connection beyond it is closed at once.
pub const DEFAULT_MAX_ASSOCIATIONS: usize = 64;

/// The calls waiting for the model.
const CALL_CAPACITY: usize = 64;

/// The unconfirmed PDUs waiting for an association. An association that falls behind misses the
/// reports it did not take in time (the broadcast of tokio drops the oldest).
const REPORT_CAPACITY: usize = 16;

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
}

impl ServerConfig {
    /// The configuration with [`server_capabilities`] and the default limit of associations.
    pub fn new(link: LinkConfig) -> Self {
        Self {
            link,
            capabilities: server_capabilities(),
            max_associations: DEFAULT_MAX_ASSOCIATIONS,
        }
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

/// A running server. Dropping it stops the listener and the associations.
pub struct Server {
    local_address: SocketAddr,
    reports: broadcast::Sender<UnconfirmedService>,
    stop: watch::Sender<bool>,
    listener: JoinHandle<()>,
}

impl Server {
    /// Listens on `address` (for example `127.0.0.1:102`, or port 0 for a free port), and serves
    /// `vmd`.
    pub async fn bind(address: &str, config: ServerConfig, vmd: Vmd) -> Result<Self, Error> {
        let listener = TcpListener::bind(address).await.map_err(Error::Io)?;
        let local_address = listener.local_addr().map_err(Error::Io)?;
        let (calls, received) = mpsc::channel(CALL_CAPACITY);
        let (reports, _) = broadcast::channel(REPORT_CAPACITY);
        let (stop, stop_rx) = watch::channel(false);
        tokio::spawn(model_task(vmd, received));
        let shared = Shared {
            link: config.link,
            capabilities: config.capabilities,
            calls,
            reports: reports.clone(),
        };
        let limit = Arc::new(Semaphore::new(config.max_associations));
        let listener = tokio::spawn(accept_loop(listener, shared, stop_rx, limit));
        Ok(Self {
            local_address,
            reports,
            stop,
            listener,
        })
    }

    /// The address the server listens on, with the port it was given.
    pub fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    /// Sends an unconfirmed PDU (an information report, for instance) to every association that is open.
    /// Returns the number of associations it was queued to. An association that does not take it in time
    /// misses it.
    pub fn publish(&self, report: UnconfirmedService) -> usize {
        self.reports.send(report).unwrap_or(0)
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
    calls: mpsc::Sender<Call>,
    reports: broadcast::Sender<UnconfirmedService>,
}

impl Shared {
    /// Runs a service on the model and waits for its answer.
    async fn call(
        &self,
        service: ConfirmedServiceRequest,
    ) -> Result<ConfirmedServiceResponse, ServiceError> {
        let (reply, answer) = oneshot::channel();
        if self.calls.send(Call { service, reply }).await.is_err() {
            return Err(stopping());
        }
        answer.await.unwrap_or_else(|_| Err(stopping()))
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

/// A service to run on the model.
struct Call {
    service: ConfirmedServiceRequest,
    reply: oneshot::Sender<Result<ConfirmedServiceResponse, ServiceError>>,
}

/// The one owner of the model: it runs the calls in turn, and ends when no association holds a sender.
async fn model_task(mut vmd: Vmd, mut calls: mpsc::Receiver<Call>) {
    while let Some(call) = calls.recv().await {
        let result = service::dispatch(&mut vmd, call.service);
        // The association may have ended: its answer is then not needed.
        let _ = call.reply.send(result);
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
                        tokio::spawn(association(stream, shared.clone(), stop.clone(), permit));
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

/// One association: the transport connection, the requests of the responder, and the services.
async fn association(
    stream: TcpStream,
    shared: Shared,
    mut stop: watch::Receiver<bool>,
    _permit: OwnedSemaphorePermit,
) {
    let _ = stream.set_nodelay(true);
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
    let mut reports = shared.reports.subscribe();
    let started = Instant::now();
    // FIFO: the actions of one event are carried out in the order the layers give them.
    let mut work: VecDeque<Action> = VecDeque::new();
    loop {
        tokio::select! {
            received = transport.recv() => {
                let Some(tsdu) = received else { return };
                work.extend(requests.handle(
                    Event::Association(association::Event::Received(tsdu)),
                    started.elapsed(),
                ));
            }
            report = reports.recv(), if requests.is_open() => {
                // A lagged receiver misses the reports it did not take in time.
                if let Ok(report) = report {
                    work.extend(requests.handle(Event::Unconfirmed(report), started.elapsed()));
                }
            }
            _ = stop.changed() => return,
        }
        while let Some(action) = work.pop_front() {
            match action {
                Action::Send(tsdu) => {
                    if transport.send(tsdu).await.is_err() {
                        return;
                    }
                }
                Action::ReleaseTransport => return,
                Action::Association(AssocAction::Indication(_)) => {
                    work.extend(requests.handle(
                        Event::Association(association::Event::Answer(Answer::Accept)),
                        started.elapsed(),
                    ));
                }
                Action::Indication { invoke, service } => {
                    let result = shared.call(service).await;
                    work.extend(requests.handle(Event::Respond(invoke, result), started.elapsed()));
                }
                Action::Association(AssocAction::Concluded)
                | Action::Association(AssocAction::Aborted(_)) => return,
                _ => {}
            }
        }
    }
}
