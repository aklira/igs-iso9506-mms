// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The delivery of the reports of a server (task N5 of igs-iec61850-mms; MMS-009 to MMS-011).
//!
//! Each association has a bounded queue of the reports it must send, in order. A report is published once,
//! with a local [`MessageId`], and each association gets an outcome for it: queued, refused (its queue is
//! full, or it is not open), written to the transport, or discarded (the association ended first, or the
//! protocol layer did not send it). The outcomes are events; events that the application does not read
//! are counted, never silently dropped without a count.
//!
//! What the outcomes state is local: a report that is written is not a receipt by the peer, since MMS has no
//! acknowledgement of an unconfirmed PDU (MMS-009). Publishing never waits for an association: a slow one
//! fills its own queue and is refused, and the others are not delayed.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use igs_iso9506_mms_codec::generated::types::UnconfirmedService;
use tokio::sync::mpsc;

use super::PeerId;

/// The local identifier of a published report. It is stable for the life of the server and increases in the
/// order of publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId(pub u64);

/// Why a report was not queued for an association.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The queue of the association is full: it is saturated, and the report was not queued.
    Saturated,
    /// The association is not open: it is not established yet, or it has ended.
    NotOpen,
}

/// Why a queued report did not leave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discard {
    /// The association ended before the report was written to its transport.
    AssociationEnded,
    /// The protocol layer did not send the report: the negotiation does not allow it.
    NotSent,
}

/// An outcome of a report for one association. The outcomes of a report come in this order: `Queued` or
/// `Refused`, then `Written` or `Discarded`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// The report was queued for the association, behind the reports queued before it.
    Queued {
        /// The report.
        message: MessageId,
        /// The association.
        peer: PeerId,
    },
    /// The report was not queued for the association.
    Refused {
        /// The report.
        message: MessageId,
        /// The association.
        peer: PeerId,
        /// Why.
        reason: Refusal,
    },
    /// The transport took the bytes of the report. Local only: the peer may not have processed it.
    Written {
        /// The report.
        message: MessageId,
        /// The association.
        peer: PeerId,
    },
    /// The report was queued and did not leave.
    Discarded {
        /// The report.
        message: MessageId,
        /// The association.
        peer: PeerId,
        /// Why.
        reason: Discard,
    },
}

/// What a publication did: how many associations queued the report, and how many refused it. The outcome per
/// association follows as [`Delivery`] events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Publication {
    /// The report.
    pub id: MessageId,
    /// Associations that queued it.
    pub queued: usize,
    /// Associations that refused it.
    pub refused: usize,
}

/// A report waiting in the queue of an association.
#[derive(Debug)]
pub(crate) struct Queued {
    pub(crate) id: MessageId,
    pub(crate) report: UnconfirmedService,
}

/// The shared side of the delivery: the queues of the open associations, the events, and the counts.
#[derive(Debug)]
pub(crate) struct Hub {
    next: AtomicU64,
    capacity: usize,
    queues: Mutex<BTreeMap<PeerId, mpsc::Sender<Queued>>>,
    events: mpsc::Sender<Delivery>,
    dropped: AtomicU64,
}

impl Hub {
    /// A hub whose associations queue at most `capacity` reports each (at least one), and whose outcomes go to
    /// `events`.
    pub(crate) fn new(capacity: usize, events: mpsc::Sender<Delivery>) -> Self {
        Self {
            next: AtomicU64::new(0),
            capacity: capacity.max(1),
            queues: Mutex::new(BTreeMap::new()),
            events,
            dropped: AtomicU64::new(0),
        }
    }

    /// The number of outcomes that were not sent, because the application did not take them in time.
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn queues(&self) -> MutexGuard<'_, BTreeMap<PeerId, mpsc::Sender<Queued>>> {
        // A poisoned lock still holds consistent queues: the critical sections do not panic.
        self.queues
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn event(&self, delivery: Delivery) {
        if self.events.try_send(delivery).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Opens the queue of an association: from now on it takes the reports published to it.
    pub(crate) fn open(&self, peer: PeerId) -> mpsc::Receiver<Queued> {
        let (sender, queue) = mpsc::channel(self.capacity);
        self.queues().insert(peer, sender);
        queue
    }

    fn close(&self, peer: PeerId) {
        self.queues().remove(&peer);
    }

    /// Publishes a report to the association `peer`, or to every open association when `None`. The outcomes are
    /// sent as events; the call never waits.
    pub(crate) fn publish(&self, peer: Option<PeerId>, report: UnconfirmedService) -> Publication {
        let id = MessageId(self.next.fetch_add(1, Ordering::Relaxed).wrapping_add(1));
        let mut queues = self.queues();
        let targets: Vec<PeerId> = match peer {
            Some(peer) => vec![peer],
            None => queues.keys().copied().collect(),
        };
        let mut outcomes = Vec::with_capacity(targets.len());
        let mut closed = Vec::new();
        for target in targets {
            let outcome = match queues.get(&target) {
                Some(sender) => match sender.try_send(Queued {
                    id,
                    report: report.clone(),
                }) {
                    Ok(()) => Delivery::Queued {
                        message: id,
                        peer: target,
                    },
                    Err(mpsc::error::TrySendError::Full(_)) => Delivery::Refused {
                        message: id,
                        peer: target,
                        reason: Refusal::Saturated,
                    },
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        closed.push(target);
                        Delivery::Refused {
                            message: id,
                            peer: target,
                            reason: Refusal::NotOpen,
                        }
                    }
                },
                None => Delivery::Refused {
                    message: id,
                    peer: target,
                    reason: Refusal::NotOpen,
                },
            };
            outcomes.push(outcome);
        }
        for target in closed {
            queues.remove(&target);
        }
        drop(queues);
        let mut queued: usize = 0;
        let mut refused: usize = 0;
        for outcome in outcomes {
            match outcome {
                Delivery::Queued { .. } => queued = queued.saturating_add(1),
                _ => refused = refused.saturating_add(1),
            }
            self.event(outcome);
        }
        Publication {
            id,
            queued,
            refused,
        }
    }

    /// The transport took the report `message` of `peer`.
    pub(crate) fn written(&self, message: MessageId, peer: PeerId) {
        self.event(Delivery::Written { message, peer });
    }

    /// The report `message` of `peer` did not leave.
    pub(crate) fn discarded(&self, message: MessageId, peer: PeerId, reason: Discard) {
        self.event(Delivery::Discarded {
            message,
            peer,
            reason,
        });
    }
}

/// The delivery state of one association. Its drop is the end of the association, however it ends: the queue is
/// closed, and each report that is still queued or handed to the protocol layer is discarded.
pub(crate) struct Outgoing {
    hub: Arc<Hub>,
    peer: PeerId,
    /// The queue, once the association is open.
    pub(crate) queue: Option<mpsc::Receiver<Queued>>,
    /// The reports handed to the protocol layer, in the order of their Send actions, not yet written.
    pub(crate) pending: VecDeque<MessageId>,
    open: bool,
}

impl Outgoing {
    pub(crate) fn new(hub: Arc<Hub>, peer: PeerId) -> Self {
        Self {
            hub,
            peer,
            queue: None,
            pending: VecDeque::new(),
            open: false,
        }
    }

    /// The association is established: it takes the reports published from now on.
    pub(crate) fn open(&mut self) {
        if !self.open {
            self.queue = Some(self.hub.open(self.peer));
            self.open = true;
        }
    }
}

impl Drop for Outgoing {
    fn drop(&mut self) {
        if self.open {
            self.hub.close(self.peer);
        }
        for message in self.pending.drain(..) {
            self.hub
                .discarded(message, self.peer, Discard::AssociationEnded);
        }
        if let Some(queue) = self.queue.as_mut() {
            while let Ok(queued) = queue.try_recv() {
                self.hub
                    .discarded(queued.id, self.peer, Discard::AssociationEnded);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use igs_iso9506_mms_codec::generated::types::{
        AccessResult, Data, Identifier, InformationReport, ObjectName, UnconfirmedService,
        VariableAccessSpecification,
    };

    fn report(value: i64) -> UnconfirmedService {
        UnconfirmedService::InformationReport(InformationReport {
            variable_access_specification: VariableAccessSpecification::VariableListName(
                ObjectName::VmdSpecific(Identifier("RPT".into())),
            ),
            list_of_access_result: vec![AccessResult::Success(Data::Integer(i128::from(value)))],
        })
    }

    fn drain(events: &mut mpsc::Receiver<Delivery>) -> Vec<Delivery> {
        let mut out = Vec::new();
        while let Ok(event) = events.try_recv() {
            out.push(event);
        }
        out
    }

    #[test]
    fn a_saturated_association_refuses_and_the_others_are_not_delayed() {
        let (events_tx, mut events) = mpsc::channel(64);
        let hub = Arc::new(Hub::new(1, events_tx));
        let (a, b) = (PeerId(1), PeerId(2));
        let mut queue_a = Outgoing::new(Arc::clone(&hub), a);
        let mut queue_b = Outgoing::new(Arc::clone(&hub), b);
        queue_a.open();
        queue_b.open();

        // Two reports to a, whose queue holds one: the second is refused, b takes both.
        let first = hub.publish(Some(a), report(1));
        let second = hub.publish(Some(a), report(2));
        let third = hub.publish(None, report(3));
        assert_eq!((first.queued, first.refused), (1, 0));
        assert_eq!((second.queued, second.refused), (0, 1));
        assert_eq!(
            (third.queued, third.refused),
            (1, 1),
            "b queues it, a is saturated"
        );

        let outcomes = drain(&mut events);
        // Broadcasts reach the associations in the order of their identifiers: a, then b.
        assert_eq!(
            outcomes,
            vec![
                Delivery::Queued {
                    message: first.id,
                    peer: a
                },
                Delivery::Refused {
                    message: second.id,
                    peer: a,
                    reason: Refusal::Saturated
                },
                Delivery::Refused {
                    message: third.id,
                    peer: a,
                    reason: Refusal::Saturated
                },
                Delivery::Queued {
                    message: third.id,
                    peer: b
                },
            ]
        );
        assert_eq!(hub.dropped(), 0);
    }

    #[test]
    fn reports_stay_in_order_per_association() {
        let (events_tx, _events) = mpsc::channel(64);
        let hub = Arc::new(Hub::new(8, events_tx));
        let mut outgoing = Outgoing::new(Arc::clone(&hub), PeerId(7));
        outgoing.open();
        let ids: Vec<MessageId> = (1..=3)
            .map(|value| hub.publish(None, report(value)).id)
            .collect();
        let queue = outgoing.queue.as_mut().unwrap();
        let received: Vec<MessageId> =
            std::iter::from_fn(|| queue.try_recv().ok().map(|q| q.id)).collect();
        assert_eq!(received, ids);
    }

    #[test]
    fn a_report_is_never_queued_for_an_association_that_is_not_open() {
        let (events_tx, mut events) = mpsc::channel(64);
        let hub = Arc::new(Hub::new(4, events_tx));
        let outgoing = Outgoing::new(Arc::clone(&hub), PeerId(3));
        // Not opened: a targeted publication is refused, a broadcast reaches nobody.
        let targeted = hub.publish(Some(PeerId(3)), report(1));
        let broadcast = hub.publish(None, report(2));
        assert_eq!((targeted.queued, targeted.refused), (0, 1));
        assert_eq!((broadcast.queued, broadcast.refused), (0, 0));
        assert_eq!(
            drain(&mut events),
            vec![Delivery::Refused {
                message: targeted.id,
                peer: PeerId(3),
                reason: Refusal::NotOpen
            }]
        );
        drop(outgoing);
    }

    #[test]
    fn the_end_of_an_association_discards_what_it_held() {
        let (events_tx, mut events) = mpsc::channel(64);
        let hub = Arc::new(Hub::new(4, events_tx));
        let peer = PeerId(9);
        let mut outgoing = Outgoing::new(Arc::clone(&hub), peer);
        outgoing.open();
        let queued = hub.publish(Some(peer), report(1));
        let second = hub.publish(Some(peer), report(2));
        // The first report leaves the queue for the protocol layer, and is not written yet.
        let taken = outgoing.queue.as_mut().unwrap().try_recv().unwrap();
        outgoing.pending.push_back(taken.id);
        drop(outgoing);

        let outcomes = drain(&mut events);
        assert_eq!(
            outcomes,
            vec![
                Delivery::Queued {
                    message: queued.id,
                    peer
                },
                Delivery::Queued {
                    message: second.id,
                    peer
                },
                Delivery::Discarded {
                    message: queued.id,
                    peer,
                    reason: Discard::AssociationEnded
                },
                Delivery::Discarded {
                    message: second.id,
                    peer,
                    reason: Discard::AssociationEnded
                },
            ]
        );
        // After the end, the association is no longer a target.
        let after = hub.publish(Some(peer), report(3));
        assert_eq!((after.queued, after.refused), (0, 1));
    }

    #[test]
    fn outcomes_that_the_application_does_not_take_are_counted() {
        let (events_tx, _events) = mpsc::channel(1);
        let hub = Arc::new(Hub::new(4, events_tx));
        let mut outgoing = Outgoing::new(Arc::clone(&hub), PeerId(1));
        outgoing.open();
        // The event channel holds one outcome: the next ones are counted.
        hub.publish(None, report(1));
        hub.publish(None, report(2));
        hub.publish(None, report(3));
        assert_eq!(hub.dropped(), 2);
    }
}
