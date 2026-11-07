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

pub mod error;
pub mod transport;

pub use error::Error;
pub use transport::{accept, connect, connect_tcp, ByteStream, Transport, CHANNEL_CAPACITY};
