// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Presentation PPDUs in normal mode (ITU-T X.226 §8), with presentation contexts.
//!
//! The PPDUs travel as user data of session SPDUs: CP and CPC in CONNECT, CPA in ACCEPT, CPR in
//! REFUSE, ARU and ARP in ABORT, and user data alone in DATA TRANSFER, FINISH and DISCONNECT.
//! X.410-1984 mode is outside the profile: its parameters are kept as raw BER.

mod error;
mod ppdu;
mod user_data;

pub use error::Error;
pub use ppdu::{
    decode_abort, decode_connect, encode_connect, Abort, AbortProvider, AbortUser, AcceptNormal,
    Connect, ConnectAccept, ConnectNormal, ConnectRefuse, ContextDefinition, ContextResult,
    DefaultContextName, Mode,
};
pub use user_data::{Encoding, Pdv, PdvValues, UserData};
