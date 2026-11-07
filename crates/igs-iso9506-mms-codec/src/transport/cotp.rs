// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The TPDUs of transport class 0 (ITU-T X.224 §13): CR, CC, DR, DT and ER.
//!
//! Decoding checks the structure; what class 0 allows on a connection (TPDU size, user data on
//! connection, class) is checked by the connection in `igs-iso9506-mms-link`.

use super::Error;

const CR: u8 = 0xE0;
const CC: u8 = 0xD0;
const DR: u8 = 0x80;
const DT: u8 = 0xF0;
const ER: u8 = 0x70;

const P_TPDU_SIZE: u8 = 0xC0;
const P_CALLING_SELECTOR: u8 = 0xC1;
const P_CALLED_SELECTOR: u8 = 0xC2;
const P_ADDITIONAL_OPTIONS: u8 = 0xC6;
const P_PREFERRED_MAX_TPDU_SIZE: u8 = 0xF0;
const P_ADDITIONAL_INFORMATION: u8 = 0xE0;
const P_INVALID_TPDU: u8 = 0xC1;

/// Parameter codes defined by X.224 §13 for any TPDU; others are refused outside a CR TPDU.
const DEFINED: [u8; 18] = [
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0xF0,
    0xF2, 0xE0,
];

/// Reject causes of an ER TPDU (X.224 §13.12.3).
pub mod reject_cause {
    /// Reason not specified.
    pub const NOT_SPECIFIED: u8 = 0;
    /// Invalid parameter code.
    pub const INVALID_PARAMETER_CODE: u8 = 1;
    /// Invalid TPDU type.
    pub const INVALID_TPDU_TYPE: u8 = 2;
    /// Invalid parameter value.
    pub const INVALID_PARAMETER_VALUE: u8 = 3;
}

/// Disconnect reasons of a DR TPDU usable in class 0 (X.224 §13.5.3).
pub mod reason {
    /// Reason not specified.
    pub const NOT_SPECIFIED: u8 = 0;
    /// Congestion at TSAP.
    pub const CONGESTION: u8 = 1;
    /// Session entity not attached to TSAP.
    pub const NOT_ATTACHED: u8 = 2;
    /// Address unknown.
    pub const ADDRESS_UNKNOWN: u8 = 3;
}

/// The TPDU size parameter (X.224 §13.3.4 b): a power of two from 128 to 8192 octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TpduSize(u8);

impl TpduSize {
    /// 128 octets, the default.
    pub const S128: Self = Self(7);
    /// 256 octets.
    pub const S256: Self = Self(8);
    /// 512 octets.
    pub const S512: Self = Self(9);
    /// 1024 octets.
    pub const S1024: Self = Self(10);
    /// 2048 octets, the largest of class 0.
    pub const S2048: Self = Self(11);
    /// 4096 octets, not allowed in class 0.
    pub const S4096: Self = Self(12);
    /// 8192 octets, not allowed in class 0.
    pub const S8192: Self = Self(13);

    /// The size for a coded value, from 7 to 13.
    pub fn from_code(code: u8) -> Option<Self> {
        (7..=13).contains(&code).then_some(Self(code))
    }

    /// The coded value.
    pub fn code(self) -> u8 {
        self.0
    }

    /// The size in octets, header included.
    pub fn octets(self) -> usize {
        1usize << self.0
    }
}

/// Parameters of the variable part of a CR or CC TPDU (X.224 §13.3.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parameters {
    /// Calling Transport-Selector.
    pub calling_selector: Option<Vec<u8>>,
    /// Called Transport-Selector in a CR TPDU, responding one in a CC TPDU.
    pub called_selector: Option<Vec<u8>>,
    /// Proposed or selected TPDU size.
    pub tpdu_size: Option<TpduSize>,
    /// Preferred maximum TPDU size, in multiples of 128 octets.
    pub preferred_max_tpdu_size: Option<u32>,
    /// Additional option selection.
    pub additional_options: Option<u8>,
    /// Other parameters, by code, as received.
    pub other: Vec<(u8, Vec<u8>)>,
}

/// A CR or CC TPDU (X.224 §13.3, §13.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionTpdu {
    /// Initial credit, zero in class 0.
    pub credit: u8,
    /// Destination reference, zero in a CR TPDU.
    pub dst_ref: u16,
    /// Source reference.
    pub src_ref: u16,
    /// Class, in bits 8 to 5 of the class option octet.
    pub class: u8,
    /// Options, in bits 4 to 1 of the class option octet.
    pub options: u8,
    /// Variable part.
    pub parameters: Parameters,
    /// User data, none in class 0 (RFC 1006 allows it for testing).
    pub user_data: Vec<u8>,
}

/// A DR TPDU (X.224 §13.5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DisconnectRequest {
    /// Destination reference.
    pub dst_ref: u16,
    /// Source reference.
    pub src_ref: u16,
    /// Reason, see [`reason`].
    pub reason: u8,
    /// Additional information parameter.
    pub additional_information: Option<Vec<u8>>,
    /// User data, none in class 0.
    pub user_data: Vec<u8>,
}

/// A DT TPDU in the format of classes 0 and 1 (X.224 §13.7).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DataTpdu {
    /// End of TSDU.
    pub end_of_tsdu: bool,
    /// Send sequence number, zero in class 0.
    pub number: u8,
    /// User data.
    pub user_data: Vec<u8>,
}

/// An ER TPDU (X.224 §13.12).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ErrorTpdu {
    /// Destination reference.
    pub dst_ref: u16,
    /// Reject cause, see [`reject_cause`].
    pub cause: u8,
    /// Header of the rejected TPDU, up to the octet in fault.
    pub invalid_tpdu: Option<Vec<u8>>,
}

/// A TPDU of class 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tpdu {
    /// Connection request.
    ConnectionRequest(ConnectionTpdu),
    /// Connection confirm.
    ConnectionConfirm(ConnectionTpdu),
    /// Disconnect request.
    DisconnectRequest(DisconnectRequest),
    /// Data.
    Data(DataTpdu),
    /// TPDU error.
    Error(ErrorTpdu),
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, Error> {
    let end = at.checked_add(2).ok_or(Error::Truncated)?;
    match bytes.get(at..end) {
        Some([high, low]) => Ok(u16::from_be_bytes([*high, *low])),
        _ => Err(Error::Truncated),
    }
}

/// A parameter of the variable part: offset of its code, code, value.
type Parameter<'a> = (usize, u8, &'a [u8]);

/// The variable part, checked against the end of the header.
fn parameters(bytes: &[u8], start: usize, end: usize) -> Result<Vec<Parameter<'_>>, Error> {
    let mut out = Vec::new();
    let mut at = start;
    while at < end {
        let code = *bytes.get(at).ok_or(Error::Truncated)?;
        let length_at = at.checked_add(1).ok_or(Error::Truncated)?;
        let length = usize::from(
            *bytes
                .get(length_at)
                .ok_or(Error::HeaderLength { offset: at })?,
        );
        let value_at = length_at.checked_add(1).ok_or(Error::Truncated)?;
        let next = value_at.checked_add(length).ok_or(Error::Truncated)?;
        if next > end {
            return Err(Error::InvalidParameterValue { offset: length_at });
        }
        let value = bytes.get(value_at..next).ok_or(Error::Truncated)?;
        out.push((at, code, value));
        at = next;
    }
    Ok(out)
}

fn connection_parameters(
    list: Vec<(usize, u8, &[u8])>,
    is_request: bool,
) -> Result<Parameters, Error> {
    let mut p = Parameters::default();
    // X.224 §13.2.3: a duplicated parameter takes its last value.
    for (offset, code, value) in list {
        let value_offset = offset.saturating_add(2);
        match code {
            P_CALLING_SELECTOR => p.calling_selector = Some(value.to_vec()),
            P_CALLED_SELECTOR => p.called_selector = Some(value.to_vec()),
            P_TPDU_SIZE => {
                let size = match value {
                    [code] => TpduSize::from_code(*code),
                    _ => None,
                };
                p.tpdu_size = Some(size.ok_or(Error::InvalidParameterValue {
                    offset: value_offset,
                })?);
            }
            P_PREFERRED_MAX_TPDU_SIZE => {
                if value.is_empty() || value.len() > 4 {
                    return Err(Error::InvalidParameterValue {
                        offset: value_offset,
                    });
                }
                let size = value.iter().fold(0u32, |n, &b| (n << 8) | u32::from(b));
                if size == 0 {
                    return Err(Error::InvalidParameterValue {
                        offset: value_offset,
                    });
                }
                p.preferred_max_tpdu_size = Some(size);
            }
            P_ADDITIONAL_OPTIONS => match value {
                [options] => p.additional_options = Some(*options),
                _ => {
                    return Err(Error::InvalidParameterValue {
                        offset: value_offset,
                    })
                }
            },
            // §13.2.3: an undefined parameter is ignored in a CR TPDU, an error elsewhere.
            _ if !DEFINED.contains(&code) && is_request => {}
            _ if !DEFINED.contains(&code) => return Err(Error::InvalidParameterCode { offset }),
            _ => p.other.push((code, value.to_vec())),
        }
    }
    Ok(p)
}

impl Tpdu {
    /// Decode one TPDU, as a TPKT carries it.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (&li, rest) = bytes.split_first().ok_or(Error::Truncated)?;
        let li = usize::from(li);
        // §13.2.1: 255 is reserved, and the header must leave room in the TPDU.
        if li == 255 || li >= bytes.len() {
            return Err(Error::HeaderLength { offset: 0 });
        }
        let code = *rest.first().ok_or(Error::Truncated)?;
        let header_end = li.checked_add(1).ok_or(Error::Truncated)?;
        let user_data = bytes.get(header_end..).ok_or(Error::Truncated)?.to_vec();
        let fixed = |size: usize| {
            if li < size {
                Err(Error::HeaderLength { offset: 0 })
            } else {
                Ok(())
            }
        };
        match code & 0xF0 {
            CR | CC => {
                fixed(6)?;
                let is_request = code & 0xF0 == CR;
                let class_option = *bytes.get(6).ok_or(Error::Truncated)?;
                let tpdu = ConnectionTpdu {
                    credit: code & 0x0F,
                    dst_ref: u16_at(bytes, 2)?,
                    src_ref: u16_at(bytes, 4)?,
                    class: class_option >> 4,
                    options: class_option & 0x0F,
                    parameters: connection_parameters(
                        parameters(bytes, 7, header_end)?,
                        is_request,
                    )?,
                    user_data,
                };
                Ok(if is_request {
                    Self::ConnectionRequest(tpdu)
                } else {
                    Self::ConnectionConfirm(tpdu)
                })
            }
            _ if code == DR => {
                fixed(6)?;
                let mut additional_information = None;
                for (offset, code, value) in parameters(bytes, 7, header_end)? {
                    match code {
                        P_ADDITIONAL_INFORMATION => additional_information = Some(value.to_vec()),
                        0xC3 => {}
                        _ => return Err(Error::InvalidParameterCode { offset }),
                    }
                }
                Ok(Self::DisconnectRequest(DisconnectRequest {
                    dst_ref: u16_at(bytes, 2)?,
                    src_ref: u16_at(bytes, 4)?,
                    reason: *bytes.get(6).ok_or(Error::Truncated)?,
                    additional_information,
                    user_data,
                }))
            }
            _ if code == DT => {
                // Class 0 and 1 format: no variable part (§13.7.1 a, §13.7.4).
                if li != 2 {
                    return Err(Error::HeaderLength { offset: 0 });
                }
                let octet = *bytes.get(2).ok_or(Error::Truncated)?;
                Ok(Self::Data(DataTpdu {
                    end_of_tsdu: octet & 0x80 != 0,
                    number: octet & 0x7F,
                    user_data,
                }))
            }
            _ if code == ER => {
                fixed(4)?;
                let mut invalid_tpdu = None;
                for (offset, code, value) in parameters(bytes, 5, header_end)? {
                    match code {
                        P_INVALID_TPDU => invalid_tpdu = Some(value.to_vec()),
                        0xC3 => {}
                        _ => return Err(Error::InvalidParameterCode { offset }),
                    }
                }
                if !user_data.is_empty() {
                    return Err(Error::HeaderLength { offset: 0 });
                }
                Ok(Self::Error(ErrorTpdu {
                    dst_ref: u16_at(bytes, 2)?,
                    cause: *bytes.get(4).ok_or(Error::Truncated)?,
                    invalid_tpdu,
                }))
            }
            _ => Err(Error::InvalidTpduType { code }),
        }
    }

    /// Encode the TPDU, to be carried in one TPKT.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut header = Vec::new();
        let mut params = Vec::new();
        let user_data: &[u8] = match self {
            Self::ConnectionRequest(t) | Self::ConnectionConfirm(t) => {
                let code = if matches!(self, Self::ConnectionRequest(_)) {
                    CR
                } else {
                    CC
                };
                fits(t.credit, 0x0F, "credit")?;
                fits(t.class, 0x0F, "class")?;
                fits(t.options, 0x0F, "options")?;
                header.push(code | t.credit);
                header.extend_from_slice(&t.dst_ref.to_be_bytes());
                header.extend_from_slice(&t.src_ref.to_be_bytes());
                header.push((t.class << 4) | t.options);
                let p = &t.parameters;
                if let Some(size) = p.tpdu_size {
                    put(&mut params, P_TPDU_SIZE, &[size.code()])?;
                }
                if let Some(size) = p.preferred_max_tpdu_size {
                    let bytes = size.to_be_bytes();
                    let skip = bytes.iter().take_while(|b| **b == 0).count().min(3);
                    put(
                        &mut params,
                        P_PREFERRED_MAX_TPDU_SIZE,
                        bytes.get(skip..).unwrap_or(&bytes),
                    )?;
                }
                if let Some(selector) = &p.called_selector {
                    put(&mut params, P_CALLED_SELECTOR, selector)?;
                }
                if let Some(selector) = &p.calling_selector {
                    put(&mut params, P_CALLING_SELECTOR, selector)?;
                }
                if let Some(options) = p.additional_options {
                    put(&mut params, P_ADDITIONAL_OPTIONS, &[options])?;
                }
                for (code, value) in &p.other {
                    // Decoding puts there only the defined codes it has no field for.
                    let own = [
                        P_TPDU_SIZE,
                        P_CALLING_SELECTOR,
                        P_CALLED_SELECTOR,
                        P_ADDITIONAL_OPTIONS,
                        P_PREFERRED_MAX_TPDU_SIZE,
                    ];
                    if !DEFINED.contains(code) || own.contains(code) {
                        return Err(Error::FieldOutOfRange("other parameter"));
                    }
                    put(&mut params, *code, value)?;
                }
                &t.user_data
            }
            Self::DisconnectRequest(t) => {
                header.push(DR);
                header.extend_from_slice(&t.dst_ref.to_be_bytes());
                header.extend_from_slice(&t.src_ref.to_be_bytes());
                header.push(t.reason);
                if let Some(info) = &t.additional_information {
                    put(&mut params, P_ADDITIONAL_INFORMATION, info)?;
                }
                &t.user_data
            }
            Self::Data(t) => {
                header.push(DT);
                fits(t.number, 0x7F, "TPDU number")?;
                header.push(if t.end_of_tsdu { 0x80 } else { 0 } | t.number);
                &t.user_data
            }
            Self::Error(t) => {
                header.push(ER);
                header.extend_from_slice(&t.dst_ref.to_be_bytes());
                header.push(t.cause);
                if let Some(invalid) = &t.invalid_tpdu {
                    put(&mut params, P_INVALID_TPDU, invalid)?;
                }
                &[]
            }
        };
        let li = header.len().checked_add(params.len()).filter(|n| *n <= 254);
        let li = li
            .and_then(|n| u8::try_from(n).ok())
            .ok_or(Error::HeaderLength { offset: 0 })?;
        let mut out = Vec::with_capacity(
            usize::from(li)
                .saturating_add(1)
                .saturating_add(user_data.len()),
        );
        out.push(li);
        out.extend_from_slice(&header);
        out.extend_from_slice(&params);
        out.extend_from_slice(user_data);
        if out.len() > super::MAX_TPDU {
            return Err(Error::TpduTooLong(out.len()));
        }
        Ok(out)
    }
}

fn fits(value: u8, max: u8, field: &'static str) -> Result<(), Error> {
    if value <= max {
        Ok(())
    } else {
        Err(Error::FieldOutOfRange(field))
    }
}

fn put(out: &mut Vec<u8>, code: u8, value: &[u8]) -> Result<(), Error> {
    let length = u8::try_from(value.len()).map_err(|_| Error::HeaderLength { offset: 0 })?;
    out.push(code);
    out.push(length);
    out.extend_from_slice(value);
    Ok(())
}
