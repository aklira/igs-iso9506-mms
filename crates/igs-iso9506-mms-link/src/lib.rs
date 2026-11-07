// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Sans-I/O state machines of the OSI upper layers and of the MMS association.
//!
//! This crate performs no I/O: it takes events and returns actions. See IMPLEMENTATION.md
//! section 2.

#![forbid(unsafe_code)]
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

pub mod config;

pub use config::{ConfigError, LinkConfig};
