// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! ISO transport over TCP: TPKT framing (RFC 1006) and the TPDUs of class 0 (ITU-T X.224 §13).

mod cotp;
mod error;
mod tpkt;

pub use cotp::{
    reason, reject_cause, ConnectionTpdu, DataTpdu, DisconnectRequest, ErrorTpdu, Parameters, Tpdu,
    TpduSize,
};
pub use error::Error;
pub use tpkt::{encode_frame, FrameDecoder, MAX_FRAME, MAX_TPDU, TPKT_HEADER, TPKT_VERSION};
