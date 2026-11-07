// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Async MMS client and server over TCP and TLS.
//!
//! See IMPLEMENTATION.md section 2. This crate drives the sans-I/O layers of the link crate on
//! tokio; the transport driver is in [`transport`].

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
pub mod transport;
pub mod vmd;

pub use client::{Client, ClientConfig, ConnectionState, Event, Events, Reconnect};
pub use connector::{Connector, TcpConnector};
pub use error::Error;
pub use server::{Server, ServerConfig};
pub use transport::{accept, connect, connect_tcp, ByteStream, Transport, CHANNEL_CAPACITY};
