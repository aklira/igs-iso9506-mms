// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The IEC 61850 `UtcTime` (IEC 61850-8-1 Annex F.3.1) and its time quality (Table 36 of 8-1, from
//! IEC 61850-7-2 TimeQuality).
//!
//! An UtcTime is eight octets: the seconds since 1970-01-01 00:00:00 UTC on 32 bits, the fraction of the
//! second on 24 bits, and one octet of time quality. The codec keeps the octets; this module reads them as
//! a timestamp. The meaning of the quality belongs to the application, but its encoding is checked here:
//! a time accuracy between 25 and 30 bits is invalid, and 31 is unspecified (N3, D-034).

use crate::asn::Error;
use crate::generated::types::UtcTime;

/// Length of an UtcTime, in octets (Annex F.3.1).
pub const UTC_TIME_OCTETS: usize = 8;

/// The largest fraction, which the 24 bits of the octets hold.
pub const MAX_FRACTION: u32 = (1 << 24) - 1;

/// The accuracy of the time, in bits of the fraction (Table 36, bits 3 to 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeAccuracy {
    /// The time is accurate to this number of bits of the fraction, from 0 to 24.
    Bits(u8),
    /// The accuracy is not specified (`11111`).
    Unspecified,
}

/// The time quality of an UtcTime (Table 36 of IEC 61850-8-1, from IEC 61850-7-2 TimeQuality).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeQuality {
    /// The leap seconds are known (bit 0).
    pub leap_second_known: bool,
    /// The clock has failed (bit 1).
    pub clock_failure: bool,
    /// The clock is not synchronised (bit 2).
    pub clock_not_synchronized: bool,
    /// The accuracy of the time (bits 3 to 7).
    pub accuracy: TimeAccuracy,
}

impl TimeQuality {
    /// Reads the quality octet. The accuracies `11001` to `11110` are invalid (Table 36).
    pub fn from_octet(octet: u8) -> Result<Self, Error> {
        let accuracy = match octet & 0x1F {
            value @ 0..=24 => TimeAccuracy::Bits(value),
            31 => TimeAccuracy::Unspecified,
            _ => return Err(Error::Invalid { ty: "TimeQuality" }),
        };
        Ok(Self {
            leap_second_known: octet & 0x80 != 0,
            clock_failure: octet & 0x40 != 0,
            clock_not_synchronized: octet & 0x20 != 0,
            accuracy,
        })
    }

    /// The quality octet. The bits above the flags are zero.
    pub fn to_octet(self) -> u8 {
        let accuracy = match self.accuracy {
            TimeAccuracy::Bits(bits) => bits,
            TimeAccuracy::Unspecified => 31,
        };
        (u8::from(self.leap_second_known) << 7)
            | (u8::from(self.clock_failure) << 6)
            | (u8::from(self.clock_not_synchronized) << 5)
            | accuracy
    }
}

/// A time of the IEC 61850 UtcTime: seconds since the epoch, the fraction of the second, and its quality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcTimestamp {
    /// Seconds since 1970-01-01 00:00:00 UTC.
    pub seconds: u32,
    /// Fraction of the second, in units of 2^-24 s; at most [`MAX_FRACTION`].
    pub fraction: u32,
    /// The time quality.
    pub quality: TimeQuality,
}

impl UtcTimestamp {
    /// A timestamp; the fraction must fit in 24 bits.
    pub fn new(seconds: u32, fraction: u32, quality: TimeQuality) -> Result<Self, Error> {
        if fraction > MAX_FRACTION {
            return Err(Error::Invalid { ty: "UtcTime" });
        }
        Ok(Self {
            seconds,
            fraction,
            quality,
        })
    }

    /// Reads the eight octets of an UtcTime: seconds, fraction, quality, in that order, big-endian.
    pub fn from_octets(octets: [u8; UTC_TIME_OCTETS]) -> Result<Self, Error> {
        let [s0, s1, s2, s3, f0, f1, f2, quality] = octets;
        Self::new(
            u32::from_be_bytes([s0, s1, s2, s3]),
            u32::from_be_bytes([0, f0, f1, f2]),
            TimeQuality::from_octet(quality)?,
        )
    }

    /// The eight octets of the UtcTime.
    pub fn to_octets(self) -> [u8; UTC_TIME_OCTETS] {
        let [s0, s1, s2, s3] = self.seconds.to_be_bytes();
        let [_, f0, f1, f2] = self.fraction.to_be_bytes();
        [s0, s1, s2, s3, f0, f1, f2, self.quality.to_octet()]
    }
}

impl UtcTime {
    /// The timestamp of this UtcTime. The value is refused unless it has eight octets and a valid quality.
    pub fn timestamp(&self) -> Result<UtcTimestamp, Error> {
        let octets: [u8; UTC_TIME_OCTETS] = self
            .0
            .as_slice()
            .try_into()
            .map_err(|_| Error::WrongSize { ty: "UtcTime" })?;
        UtcTimestamp::from_octets(octets)
    }

    /// The UtcTime of a timestamp.
    pub fn from_timestamp(timestamp: UtcTimestamp) -> Self {
        Self(timestamp.to_octets().to_vec())
    }
}
