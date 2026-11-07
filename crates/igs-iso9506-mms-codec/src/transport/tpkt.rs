// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! TPKT framing of RFC 1006: version 3, a reserved octet, a 16-bit length including the header.

use super::Error;

/// TPKT version of RFC 1006.
pub const TPKT_VERSION: u8 = 3;
/// Size of the TPKT header.
pub const TPKT_HEADER: usize = 4;
/// Largest TPKT, header included.
pub const MAX_FRAME: usize = 65_535;
/// Largest TPDU that a TPKT carries.
pub const MAX_TPDU: usize = MAX_FRAME - TPKT_HEADER;
/// Smallest TPKT: a header and the three octets of a DT TPDU.
const MIN_FRAME: usize = 7;

/// A TPKT around `tpdu`.
pub fn encode_frame(tpdu: &[u8]) -> Result<Vec<u8>, Error> {
    let length = tpdu
        .len()
        .checked_add(TPKT_HEADER)
        .filter(|n| *n <= MAX_FRAME)
        .ok_or(Error::TpduTooLong(tpdu.len()))?;
    let length = u16::try_from(length).map_err(|_| Error::TpduTooLong(tpdu.len()))?;
    let mut frame = Vec::with_capacity(usize::from(length));
    frame.push(TPKT_VERSION);
    frame.push(0);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(tpdu);
    Ok(frame)
}

/// Cuts a byte stream into TPDUs, whatever the size of the pieces it receives.
///
/// An error leaves the stream unusable: the connection must be closed.
#[derive(Debug, Clone)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
    max_frame: usize,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameDecoder {
    /// A decoder that accepts TPKTs up to 65,535 octets.
    pub fn new() -> Self {
        Self::with_max_frame(MAX_FRAME)
    }

    /// A decoder that refuses TPKTs longer than `max_frame` octets, header included.
    pub fn with_max_frame(max_frame: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_frame: max_frame.min(MAX_FRAME),
        }
    }

    /// Append received octets.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Octets received and not yet returned in a TPDU.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// The next complete TPDU, without its TPKT header, or `None` until more octets arrive.
    pub fn next_tpdu(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let Some(header) = self.buffer.get(..TPKT_HEADER) else {
            if let Some(&version) = self.buffer.first() {
                if version != TPKT_VERSION {
                    return Err(Error::TpktVersion(version));
                }
            }
            return Ok(None);
        };
        let (version, high, low) = match header {
            [version, _reserved, high, low] => (*version, *high, *low),
            _ => return Ok(None),
        };
        if version != TPKT_VERSION {
            return Err(Error::TpktVersion(version));
        }
        let length = usize::from(u16::from_be_bytes([high, low]));
        if !(MIN_FRAME..=self.max_frame).contains(&length) {
            return Err(Error::TpktLength(length));
        }
        let Some(tpdu) = self.buffer.get(TPKT_HEADER..length) else {
            return Ok(None);
        };
        let tpdu = tpdu.to_vec();
        self.buffer.drain(..length);
        Ok(Some(tpdu))
    }
}
