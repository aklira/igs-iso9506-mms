// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Async MMS client and server over TCP and TLS.
//!
//! The crate drives the sans-I/O layers of `igs-iso9506-mms-link` on tokio. The transport driver is in
//! [`transport`]; the client is [`Client`], the server is [`Server`], the model of the device is [`vmd`],
//! and TLS is in [`tls`].
//!
//! # Quick start
//!
//! A server and a client in one process: `cargo run -p igs-iso9506-mms --example loopback` (the source is in
//! `examples/loopback.rs`). The examples `client`, `server` and `tls` run the same services over TCP and TLS.
//!
//! The services in scope and the known gaps are listed in `docs/capabilities.md`.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

mod actor;
pub mod client;
pub mod connector;
pub mod error;
pub mod server;
pub mod tls;
pub mod transport;
pub mod vmd;

pub use client::{Client, ClientConfig, ConnectionState, Event, Events, Reconnect};
pub use connector::{Connector, TcpConnector};
pub use error::Error;
pub use server::{Server, ServerConfig};
pub use transport::{accept, connect, connect_tcp, ByteStream, Transport, CHANNEL_CAPACITY};
