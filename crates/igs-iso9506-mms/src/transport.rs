// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The transport connection over a byte stream (task T1): a driver that runs the sans-I/O connection
//! of task L2 on tokio. It reads and writes the TPKT frames, and carries TSDUs in both directions over
//! bounded channels: a sender waits while its channel is full.
//!
//! The stream is any [`ByteStream`]. TCP is one (see [`connect_tcp`]); TLS will be another (task
//! X1), and the tests use an in-memory duplex stream.

use std::time::Duration;

use igs_iso9506_mms_link::config::LinkConfig;
use igs_iso9506_mms_link::transport::{Action, Cause, Connection, Event, Role};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{sleep_until, timeout, Instant};

use crate::error::Error;

/// Capacity of each channel, in TSDUs. A sender waits while its channel is full: back-pressure.
pub const CHANNEL_CAPACITY: usize = 16;

/// Size of one read from the stream, in octets.
const READ_SIZE: usize = 8192;

/// A byte stream that the transport connection runs over.
pub trait ByteStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T> ByteStream for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// The connection request is being answered.
    Connecting,
    /// The connection is open: TSDUs flow.
    Open,
    /// The driver stops: released locally, or the receiver is gone.
    Released,
}

/// The driver: owns the stream and the sans-I/O connection, and runs them until the connection ends.
struct Driver<S> {
    stream: S,
    connection: Connection,
    origin: Instant,
    /// The connect timer of the initiator; the responder has none.
    deadline: Option<Instant>,
    phase: Phase,
    outbound: mpsc::Receiver<Vec<u8>>,
    inbound: mpsc::Sender<Vec<u8>>,
    buffer: Vec<u8>,
}

impl<S: ByteStream> Driver<S> {
    /// Time since the driver started, as the connection takes it.
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    /// Runs the connection request until it is confirmed or refused.
    async fn establish(&mut self) -> Result<(), Error> {
        while self.phase == Phase::Connecting {
            let timer = self.deadline;
            tokio::select! {
                read = self.stream.read(&mut self.buffer) => {
                    let count = read?;
                    self.received(count).await?;
                }
                _ = sleep_until(timer.unwrap_or(self.origin)), if timer.is_some() => {
                    self.deadline = None;
                    let actions = self.connection.handle(Event::Tick, self.now());
                    self.apply(actions).await?;
                }
            }
        }
        Ok(())
    }

    /// Runs the open connection until it is released, or the stream fails.
    async fn run(mut self) -> Result<(), Error> {
        while self.phase == Phase::Open {
            tokio::select! {
                read = self.stream.read(&mut self.buffer) => {
                    let count = read?;
                    self.received(count).await?;
                }
                message = self.outbound.recv() => match message {
                    Some(tsdu) => {
                        let actions = self.connection.handle(Event::Send(tsdu), self.now());
                        self.apply(actions).await?;
                    }
                    // Every sender is gone: release. Class 0 releases with the network connection
                    // (X.224 §5.4.4), so nothing is sent for it.
                    None => {
                        let actions = self.connection.handle(Event::Release, self.now());
                        self.apply(actions).await?;
                    }
                },
            }
        }
        self.stream.shutdown().await?;
        Ok(())
    }

    /// The octets read from the stream: the first `count` of the buffer. Zero is the end of stream.
    async fn received(&mut self, count: usize) -> Result<(), Error> {
        if count == 0 {
            return Err(Error::PeerClosed);
        }
        let bytes = self
            .buffer
            .get(..count)
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        let actions = self.connection.handle(Event::Received(bytes), self.now());
        self.apply(actions).await
    }

    /// Carries out the actions of the connection, in order.
    async fn apply(&mut self, actions: Vec<Action>) -> Result<(), Error> {
        for action in actions {
            match action {
                Action::Transmit(frame) => self.stream.write_all(&frame).await?,
                Action::Deliver(tsdu) => {
                    if self.inbound.send(tsdu).await.is_err() {
                        // The receiver is gone: nothing more is delivered, and the driver stops.
                        self.phase = Phase::Released;
                        break;
                    }
                }
                Action::Opened => self.phase = Phase::Open,
                Action::Closed(Cause::Local) => self.phase = Phase::Released,
                Action::Closed(Cause::Timeout) => return Err(Error::ConnectTimeout),
                Action::Closed(cause) => return Err(Error::Closed(cause)),
                Action::Misuse(message) => return Err(Error::Misuse(message)),
            }
        }
        self.stream.flush().await?;
        Ok(())
    }
}

/// An open transport connection, driven in the background.
///
/// TSDUs are sent with [`Transport::send`] and received with [`Transport::recv`]. Dropping the
/// value without [`Transport::shutdown`] also stops the driver, but the outcome is then lost.
#[derive(Debug)]
pub struct Transport {
    outbound: mpsc::Sender<Vec<u8>>,
    inbound: mpsc::Receiver<Vec<u8>>,
    task: JoinHandle<Result<(), Error>>,
}

impl Transport {
    /// Sends a TSDU. Waits while the channel is full. Fails once the driver has stopped; the reason
    /// is then given by [`Transport::shutdown`].
    pub async fn send(&self, tsdu: Vec<u8>) -> Result<(), Error> {
        self.outbound.send(tsdu).await.map_err(|_| Error::Stopped)
    }

    /// Receives the next TSDU. `None` once the driver has stopped and nothing is left to deliver.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.inbound.recv().await
    }

    /// Stops the connection cleanly: the TSDUs already sent are written, then the connection is
    /// released. Returns the reason the driver stopped, if it stopped with an error. TSDUs received
    /// but not yet taken with [`Transport::recv`] are discarded.
    pub async fn shutdown(self) -> Result<(), Error> {
        let Transport {
            outbound,
            inbound,
            task,
        } = self;
        drop(outbound);
        drop(inbound);
        task.await.map_err(|_| Error::Stopped)?
    }
}

async fn open<S: ByteStream>(
    stream: S,
    role: Role,
    config: LinkConfig,
) -> Result<Transport, Error> {
    let connection = Connection::new(role, config.clone())?;
    let (outbound_tx, outbound_rx) = mpsc::channel(CHANNEL_CAPACITY);
    let (inbound_tx, inbound_rx) = mpsc::channel(CHANNEL_CAPACITY);
    let origin = Instant::now();
    let mut driver = Driver {
        stream,
        connection,
        origin,
        deadline: None,
        phase: Phase::Connecting,
        outbound: outbound_rx,
        inbound: inbound_tx,
        buffer: vec![0; READ_SIZE],
    };
    if role == Role::Initiator {
        // An instant too far away to be represented never expires.
        driver.deadline = origin.checked_add(config.connect_timeout);
        let actions = driver.connection.handle(Event::Connect, Duration::ZERO);
        driver.apply(actions).await?;
    }
    driver.establish().await?;
    let task = tokio::spawn(driver.run());
    Ok(Transport {
        outbound: outbound_tx,
        inbound: inbound_rx,
        task,
    })
}

/// Opens a transport connection as the initiator: sends the connection request on `stream`, and waits
/// for the confirm within the connect timeout of `config`.
pub async fn connect<S: ByteStream>(stream: S, config: LinkConfig) -> Result<Transport, Error> {
    open(stream, Role::Initiator, config).await
}

/// Opens a transport connection as the responder: waits for a connection request on `stream`, and
/// answers it if it can be accepted.
pub async fn accept<S: ByteStream>(stream: S, config: LinkConfig) -> Result<Transport, Error> {
    open(stream, Role::Responder, config).await
}

/// Connects over TCP to `address` (RFC 1006: TCP port 102 is the usual one), then as the initiator.
///
/// Both the TCP connection and the connection request are within the connect timeout of `config`.
pub async fn connect_tcp<A: ToSocketAddrs>(
    address: A,
    config: LinkConfig,
) -> Result<Transport, Error> {
    let connect_timeout = config.connect_timeout;
    let stream = timeout(connect_timeout, TcpStream::connect(address))
        .await
        .map_err(|_| Error::ConnectTimeout)??;
    stream.set_nodelay(true)?;
    connect(stream, config).await
}
