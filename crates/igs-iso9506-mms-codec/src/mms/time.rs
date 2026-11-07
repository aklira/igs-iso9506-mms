// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! TimeOfDay (ISO 9506-2 §7.5.1): milliseconds since midnight in four octets, then optionally the
//! day since 1 January 1984 in two octets, both big-endian; the top four bits are zero.

use crate::asn::Error;
use crate::generated::types::TimeOfDay;

const TY: &str = "TimeOfDay";

/// The largest millisecond count that the 28 bits of the field hold.
pub const MAX_MILLISECONDS: u32 = 0x0FFF_FFFF;

/// The four reserved bits are zero; the size is checked by the generated code.
pub(crate) fn check_time_of_day(octets: &[u8]) -> Result<(), Error> {
    if octets.first().is_some_and(|b| b & 0xF0 != 0) {
        Err(Error::Invalid { ty: TY })
    } else {
        Ok(())
    }
}

impl TimeOfDay {
    /// The four-octet form: a time of day without a date.
    pub fn from_milliseconds(milliseconds: u32) -> Result<Self, Error> {
        Self::new(milliseconds.to_be_bytes().to_vec())
    }

    /// The six-octet form: a time of day and the day since 1 January 1984 (day 0).
    pub fn from_milliseconds_and_day(milliseconds: u32, day: u16) -> Result<Self, Error> {
        let mut octets = milliseconds.to_be_bytes().to_vec();
        octets.extend_from_slice(&day.to_be_bytes());
        Self::new(octets)
    }

    /// Milliseconds since midnight.
    pub fn milliseconds(&self) -> Result<u32, Error> {
        self.check()?;
        match self.0.get(..4) {
            Some(&[a, b, c, d]) => Ok(u32::from_be_bytes([a, b, c, d])),
            _ => Err(Error::WrongSize { ty: TY }),
        }
    }

    /// The day since 1 January 1984, in the six-octet form.
    pub fn day(&self) -> Result<Option<u16>, Error> {
        self.check()?;
        match self.0.get(4..) {
            Some(&[a, b]) => Ok(Some(u16::from_be_bytes([a, b]))),
            Some(&[]) => Ok(None),
            _ => Err(Error::WrongSize { ty: TY }),
        }
    }
}
