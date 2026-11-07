// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Length indicators and PGI and PI units (X.225 §8.2).

use super::Error;

/// A PGI or PI unit, by code, with its parameter field as received.
pub(crate) type Unit<'a> = (u8, &'a [u8]);

/// A length indicator (§8.2.5): one octet up to 254, else 255 and two octets.
/// Returns the length and the octets used.
pub(crate) fn length(bytes: &[u8]) -> Result<(usize, usize), Error> {
    match bytes {
        [] => Err(Error::Truncated),
        [0xFF, high, low, ..] => Ok((usize::from(u16::from_be_bytes([*high, *low])), 3)),
        [0xFF, ..] => Err(Error::Truncated),
        [first, ..] => Ok((usize::from(*first), 1)),
    }
}

pub(crate) fn put_length(out: &mut Vec<u8>, length: usize) -> Result<(), Error> {
    if let Ok(short @ 0..=254) = u8::try_from(length) {
        out.push(short);
    } else {
        let long = u16::try_from(length).map_err(|_| Error::TooLong)?;
        out.push(0xFF);
        out.extend_from_slice(&long.to_be_bytes());
    }
    Ok(())
}

/// The units of a parameter field, in increasing order of their codes, as the sender should
/// have written them (§8.2.6). The sort is stable: of two units with the same code, the last
/// received stays last.
pub(crate) fn units(mut field: &[u8]) -> Result<Vec<Unit<'_>>, Error> {
    let mut out = Vec::new();
    while let Some((&code, rest)) = field.split_first() {
        let (size, used) = length(rest)?;
        let rest = rest.get(used..).ok_or(Error::Truncated)?;
        let value = rest.get(..size).ok_or(Error::Length)?;
        out.push((code, value));
        field = rest.get(size..).ok_or(Error::Length)?;
    }
    out.sort_by_key(|(code, _)| *code);
    Ok(out)
}

/// Writes units in increasing order of their codes, as §8.2.6 requires at each level.
pub(crate) fn put_units(out: &mut Vec<u8>, mut units: Vec<(u8, Vec<u8>)>) -> Result<(), Error> {
    units.sort_by_key(|(code, _)| *code);
    for (code, value) in units {
        out.push(code);
        put_length(out, value.len())?;
        out.extend_from_slice(&value);
    }
    Ok(())
}

/// The value of a one-octet parameter.
pub(crate) fn octet(code: u8, value: &[u8]) -> Result<u8, Error> {
    match value {
        [octet] => Ok(*octet),
        _ => Err(Error::InvalidParameter(code)),
    }
}

/// The value of a two-octet parameter.
pub(crate) fn word(code: u8, value: &[u8]) -> Result<u16, Error> {
    match value {
        [high, low] => Ok(u16::from_be_bytes([*high, *low])),
        _ => Err(Error::InvalidParameter(code)),
    }
}

/// Checks the maximum length of a parameter.
pub(crate) fn bounded(code: u8, value: &[u8], max: usize) -> Result<Vec<u8>, Error> {
    if value.len() > max {
        Err(Error::InvalidParameter(code))
    } else {
        Ok(value.to_vec())
    }
}
