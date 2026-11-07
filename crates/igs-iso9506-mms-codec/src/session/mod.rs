// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Session SPDUs of the kernel and duplex functional units (ITU-T X.225 §8), protocol version 2.
//!
//! The SPDUs that the stack uses are decoded field by field: CONNECT, ACCEPT, REFUSE, FINISH,
//! DISCONNECT, ABORT, ABORT ACCEPT, GIVE TOKENS and DATA TRANSFER. Any other SPDU keeps its
//! parameter field as received. A TSDU holds one SPDU, or a category 0 SPDU followed by one
//! category 2 SPDU (basic concatenation, §6.3.7).

mod error;
mod spdu;
mod units;

pub use error::Error;
pub use spdu::{
    decode_tsdu, encode_tsdu, si, Abort, Accept, Connect, ConnectAcceptItem, ConnectionIdentifier,
    DataTransfer, Disconnect, Finish, GiveTokens, Refuse, Spdu, ABORT_PROTOCOL_ERROR,
    ABORT_TRANSPORT_RELEASED, ABORT_USER, FU_DUPLEX, FU_HALF_DUPLEX, PROTOCOL_VERSION_1,
    PROTOCOL_VERSION_2,
};
