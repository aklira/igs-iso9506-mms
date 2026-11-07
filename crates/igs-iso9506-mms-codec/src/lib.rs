// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! BER and the encoding of TPKT, COTP, session, presentation, ACSE and MMS PDUs.
//!
//! This crate performs no I/O. See IMPLEMENTATION.md section 2.

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

/// Code generated from the data files; see the banner of each file.
pub mod generated;

/// Vocabulary of the generated code.
pub mod schema;

/// Basic Encoding Rules (ITU-T X.690).
pub mod ber;
