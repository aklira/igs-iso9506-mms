// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! FloatingPoint (ISO 9506-2 §14.4.2.2): one octet giving the exponent width N, then the sign
//! bit, N exponent bits and the fraction bits, most significant first.
//!
//! With N = 8 and four octets, or N = 11 and eight, the bits are those of IEEE 754 single and
//! double precision. Other widths are read by the general rule of the clause: an exponent all ones
//! is an infinity or NaN; an exponent all zeros has no implicit leading one. When a value does not
//! fit the target, the fraction is rounded up if the first bit that does not fit is one, else
//! truncated; a magnitude too large becomes an infinity, one too small a zero.

use crate::asn::Error;
use crate::generated::types::FloatingPoint;

const TY: &str = "FloatingPoint";

fn invalid() -> Error {
    Error::Invalid { ty: TY }
}

/// Bit `index` of the octets after the first; bit 0 is the most significant of the second octet.
fn bit(octets: &[u8], index: usize) -> bool {
    let mask = 0x80u8.checked_shr((index % 8) as u32).unwrap_or(0);
    octets.get(index / 8).is_some_and(|b| b & mask != 0)
}

/// The exponent width and the octets of sign, exponent and fraction.
fn layout(octets: &[u8]) -> Result<(usize, &[u8]), Error> {
    let (&width, rest) = octets.split_first().ok_or_else(invalid)?;
    let width = usize::from(width);
    let bits = rest.len().checked_mul(8).ok_or_else(invalid)?;
    // N > 0, and the sign and the exponent fit; the fraction may be empty.
    if width == 0 || width >= bits {
        return Err(invalid());
    }
    Ok((width, rest))
}

/// At least two octets, an exponent width above zero that fits (§14.4.2.2).
pub(crate) fn check_floating_point(octets: &[u8]) -> Result<(), Error> {
    layout(octets).map(|_| ())
}

/// A value read in the general rule: its class, and for a finite non-zero value, the power of two
/// of its leading one bit and the index of the bit that follows it.
enum Reading {
    Nan,
    Infinite,
    Zero,
    Finite { lead: i128, next: usize },
}

/// Bits `from..to` as an unsigned integer, saturating; `invert` reads them inverted.
fn value(octets: &[u8], from: usize, to: usize, invert: bool) -> u128 {
    (from..to).fold(0u128, |acc, i| {
        let one = u128::from(bit(octets, i) != invert);
        acc.checked_mul(2)
            .and_then(|v| v.checked_add(one))
            .unwrap_or(u128::MAX)
    })
}

fn saturate(v: u128) -> i128 {
    i128::try_from(v).unwrap_or(i128::MAX)
}

fn read(width: usize, octets: &[u8]) -> Reading {
    let bits = octets.len().saturating_mul(8);
    let exponent_end = width.saturating_add(1);
    let exponent = 1..exponent_end;
    let all_ones = exponent.clone().all(|i| bit(octets, i));
    let all_zeros = !exponent.clone().any(|i| bit(octets, i));
    let fraction_zero = !(exponent_end..bits).any(|i| bit(octets, i));
    if all_ones {
        return if fraction_zero {
            Reading::Infinite
        } else {
            Reading::Nan
        };
    }
    if all_zeros && fraction_zero {
        return Reading::Zero;
    }
    // Unbiased exponent E - (2^(N-1) - 1): with the top exponent bit set, the value of the other
    // bits plus one; else minus the value of the other bits inverted.
    let unbiased = if bit(octets, 1) {
        saturate(value(octets, 2, exponent_end, false)).saturating_add(1)
    } else {
        0i128.saturating_sub(saturate(value(octets, 2, exponent_end, true)))
    };
    if !all_zeros {
        return Reading::Finite {
            lead: unbiased,
            next: exponent_end,
        };
    }
    // Exponent zero: the weight of the first fraction bit is 2^(1 - bias - 1).
    let minimum = unbiased.saturating_add(1);
    let first = (exponent_end..bits)
        .find(|&i| bit(octets, i))
        .unwrap_or(bits);
    let offset = i128::try_from(first.saturating_sub(width)).unwrap_or(i128::MAX);
    Reading::Finite {
        lead: minimum.saturating_sub(offset),
        next: first.saturating_add(1),
    }
}

/// The value in an IEEE 754 binary format of `we` exponent and `wf` fraction bits, as its bit
/// pattern; `we` is at most 11 and `wf` at most 52.
fn to_ieee(octets: &[u8], we: u32, wf: u32) -> Result<u64, Error> {
    let (width, rest) = layout(octets)?;
    let shift = |v: u64, by: u32| v.checked_shl(by).unwrap_or(0);
    let sign = if bit(rest, 0) {
        shift(1, we.saturating_add(wf))
    } else {
        0
    };
    let exponent_ones = shift(1, we).saturating_sub(1);
    let infinite = sign | shift(exponent_ones, wf);
    let finite = match read(width, rest) {
        Reading::Nan => return Ok(infinite | shift(1, wf.saturating_sub(1))),
        Reading::Infinite => return Ok(infinite),
        Reading::Zero => return Ok(sign),
        Reading::Finite { lead, next } => (lead, next),
    };
    let (mut lead, next) = finite;
    let bias = i128::from(shift(1, we.saturating_sub(1)).saturating_sub(1));
    let (emax, emin) = (bias, 1i128.saturating_sub(bias));
    if lead > emax {
        return Ok(infinite);
    }
    let wf_i = i128::from(wf);
    // Bits kept after the leading one: all of the fraction for a normal result, fewer for a
    // subnormal one, whose leading one sits `position` bits below the smallest normal exponent.
    let kept = if lead >= emin {
        wf_i
    } else {
        let position = emin.saturating_sub(lead);
        if position > wf_i.saturating_add(1) {
            return Ok(sign);
        }
        wf_i.saturating_sub(position)
    };
    let mut significand: u64 = if kept < 0 { 0 } else { 1 };
    let kept = usize::try_from(kept.max(0)).unwrap_or(0);
    for i in 0..kept {
        significand = shift(significand, 1) | u64::from(bit(rest, next.saturating_add(i)));
    }
    // The leading one itself is the first bit that does not fit when nothing is kept of it.
    let round = if lead < emin && emin.saturating_sub(lead) == wf_i.saturating_add(1) {
        true
    } else {
        bit(rest, next.saturating_add(kept))
    };
    if round {
        significand = significand.saturating_add(1);
    }
    if lead < emin {
        // Subnormal: no exponent field; a carry into bit `wf` gives the smallest normal number.
        return Ok(sign | significand);
    }
    if significand == shift(1, wf.saturating_add(1)) {
        significand = shift(1, wf);
        lead = lead.saturating_add(1);
        if lead > emax {
            return Ok(infinite);
        }
    }
    let biased = u64::try_from(lead.saturating_add(bias)).map_err(|_| invalid())?;
    let fraction = significand & shift(1, wf).saturating_sub(1);
    Ok(sign | shift(biased, wf) | fraction)
}

impl FloatingPoint {
    /// The IEEE 754 single precision form: exponent width 8, four octets.
    pub fn from_f32(value: f32) -> Self {
        let mut octets = vec![8];
        octets.extend_from_slice(&value.to_be_bytes());
        Self(octets)
    }

    /// The IEEE 754 double precision form: exponent width 11, eight octets.
    pub fn from_f64(value: f64) -> Self {
        let mut octets = vec![11];
        octets.extend_from_slice(&value.to_be_bytes());
        Self(octets)
    }

    /// The exponent width N.
    pub fn exponent_width(&self) -> Result<u8, Error> {
        layout(&self.0).map(|(width, _)| width as u8)
    }

    /// The value as an `f64`, rounded as the clause asks; a NaN loses its payload.
    pub fn to_f64(&self) -> Result<f64, Error> {
        to_ieee(&self.0, 11, 52).map(f64::from_bits)
    }

    /// The value as an `f32`, rounded as the clause asks; a NaN loses its payload.
    pub fn to_f32(&self) -> Result<f32, Error> {
        to_ieee(&self.0, 8, 23).map(|bits| f32::from_bits(bits as u32))
    }
}
