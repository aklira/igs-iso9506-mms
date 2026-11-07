// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The SPDUs and the TSDU (X.225 §8.1, §8.3).

use super::units::{bounded, length, octet, put_length, put_units, units, word, Unit};
use super::Error;

/// SPDU identifiers (SI) of X.225 §8.3.
pub mod si {
    /// GIVE TOKENS, category 0; DATA TRANSFER, category 2, has the same value.
    pub const GIVE_TOKENS: u8 = 1;
    /// DATA TRANSFER.
    pub const DATA_TRANSFER: u8 = 1;
    /// PLEASE TOKENS, category 0.
    pub const PLEASE_TOKENS: u8 = 2;
    /// FINISH.
    pub const FINISH: u8 = 9;
    /// DISCONNECT.
    pub const DISCONNECT: u8 = 10;
    /// REFUSE.
    pub const REFUSE: u8 = 12;
    /// CONNECT.
    pub const CONNECT: u8 = 13;
    /// ACCEPT.
    pub const ACCEPT: u8 = 14;
    /// ABORT.
    pub const ABORT: u8 = 25;
    /// ABORT ACCEPT.
    pub const ABORT_ACCEPT: u8 = 26;
}

/// Session User Requirements, bit 1: half-duplex functional unit (§8.3.1.16).
pub const FU_HALF_DUPLEX: u16 = 0x0001;
/// Session User Requirements, bit 2: duplex functional unit.
pub const FU_DUPLEX: u16 = 0x0002;
/// Version Number, bit 1: protocol version 1 (§8.3.1.9).
pub const PROTOCOL_VERSION_1: u8 = 0x01;
/// Version Number, bit 2: protocol version 2.
pub const PROTOCOL_VERSION_2: u8 = 0x02;
/// Transport Disconnect of ABORT, bit 1: transport connection released (§8.3.9.3).
pub const ABORT_TRANSPORT_RELEASED: u8 = 0x01;
/// Transport Disconnect of ABORT, bit 2: user abort.
pub const ABORT_USER: u8 = 0x02;
/// Transport Disconnect of ABORT, bit 3: protocol error.
pub const ABORT_PROTOCOL_ERROR: u8 = 0x04;

const PGI_CONNECTION_ID: u8 = 1;
const PGI_CONNECT_ACCEPT: u8 = 5;
const PGI_USER_DATA: u8 = 193;
const PGI_EXTENDED_USER_DATA: u8 = 194;
const PI_CALLED_REFERENCE: u8 = 9;
const PI_CALLING_REFERENCE: u8 = 10;
const PI_COMMON_REFERENCE: u8 = 11;
const PI_ADDITIONAL_REFERENCE: u8 = 12;
const PI_TOKEN_ITEM: u8 = 16;
const PI_TRANSPORT_DISCONNECT: u8 = 17;
const PI_PROTOCOL_OPTIONS: u8 = 19;
const PI_USER_REQUIREMENTS: u8 = 20;
const PI_TSDU_MAXIMUM_SIZE: u8 = 21;
const PI_VERSION: u8 = 22;
const PI_ENCLOSURE: u8 = 25;
const PI_TOKEN_SETTING: u8 = 26;
const PI_REFLECT: u8 = 49;
const PI_REASON: u8 = 50;
const PI_CALLING_SELECTOR: u8 = 51;
const PI_CALLED_SELECTOR: u8 = 52;
const PI_DATA_OVERFLOW: u8 = 60;

/// User data in a CONNECT SPDU: up to 512 octets in the User Data parameter, up to 10 240 in
/// the Extended User Data parameter (§8.3.1, table 11).
const USER_DATA_MAX: usize = 512;
const EXTENDED_USER_DATA_MAX: usize = 10_240;

/// Other parameters, by code, as received.
pub type Others = Vec<(u8, Vec<u8>)>;

/// An SPDU taken apart for encoding: SI, parameter units, user information.
type Parts<'a> = (u8, Others, &'a [u8]);

/// The Connection Identifier parameter group (PGI 1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionIdentifier {
    /// Calling SS-user reference in a CONNECT SPDU, called one in ACCEPT and REFUSE SPDUs.
    pub ss_user_reference: Option<Vec<u8>>,
    /// Common reference.
    pub common_reference: Option<Vec<u8>>,
    /// Additional reference information.
    pub additional_reference: Option<Vec<u8>>,
}

/// The Connect/Accept Item parameter group (PGI 5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectAcceptItem {
    /// Protocol options; bit 1 announces extended concatenation on receipt.
    pub protocol_options: u8,
    /// Proposed maximum TSDU sizes, initiator to responder then back; zero is unlimited.
    pub tsdu_maximum_size: Option<(u16, u16)>,
    /// Protocol versions, see [`PROTOCOL_VERSION_1`] and [`PROTOCOL_VERSION_2`].
    pub version_number: u8,
    /// Initial token positions.
    pub token_setting: Option<u8>,
    /// Other parameters of the group.
    pub other: Others,
}

/// CONNECT SPDU (§8.3.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Connect {
    /// Connection identifier.
    pub connection_identifier: Option<ConnectionIdentifier>,
    /// Connect/Accept item; absent means the defaults, version 1.
    pub item: Option<ConnectAcceptItem>,
    /// Proposed functional units, see [`FU_DUPLEX`].
    pub session_user_requirements: Option<u16>,
    /// Calling session selector.
    pub calling_selector: Option<Vec<u8>>,
    /// Called session selector.
    pub called_selector: Option<Vec<u8>>,
    /// Data overflow: more than 10 240 octets of user data follow.
    pub data_overflow: Option<u8>,
    /// User data, from the User Data or the Extended User Data parameter.
    pub user_data: Option<Vec<u8>>,
    /// Other parameters.
    pub other: Others,
}

/// ACCEPT SPDU (§8.3.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Accept {
    /// Connection identifier.
    pub connection_identifier: Option<ConnectionIdentifier>,
    /// Connect/Accept item.
    pub item: Option<ConnectAcceptItem>,
    /// Tokens requested by the called SS-user.
    pub token_item: Option<u8>,
    /// Selected functional units.
    pub session_user_requirements: Option<u16>,
    /// Enclosure item, for segmented user data.
    pub enclosure: Option<u8>,
    /// Calling session selector.
    pub calling_selector: Option<Vec<u8>>,
    /// Responding session selector.
    pub responding_selector: Option<Vec<u8>>,
    /// User data.
    pub user_data: Option<Vec<u8>>,
    /// Other parameters.
    pub other: Others,
}

/// REFUSE SPDU (§8.3.5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Refuse {
    /// Connection identifier.
    pub connection_identifier: Option<ConnectionIdentifier>,
    /// Bit 1 set: the transport connection is released (the default when absent).
    pub transport_disconnect: Option<u8>,
    /// Functional units, with reason code 2.
    pub session_user_requirements: Option<u16>,
    /// Protocol versions.
    pub version_number: Option<u8>,
    /// Enclosure item.
    pub enclosure: Option<u8>,
    /// Reason code: its first octet, then user data for reason 2.
    pub reason: Option<Vec<u8>>,
    /// Other parameters.
    pub other: Others,
}

/// FINISH SPDU (§8.3.6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Finish {
    /// Bit 1 set: the transport connection is released (the default when absent).
    pub transport_disconnect: Option<u8>,
    /// Enclosure item.
    pub enclosure: Option<u8>,
    /// User data.
    pub user_data: Option<Vec<u8>>,
    /// Other parameters.
    pub other: Others,
}

/// DISCONNECT SPDU (§8.3.7).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Disconnect {
    /// Enclosure item.
    pub enclosure: Option<u8>,
    /// User data.
    pub user_data: Option<Vec<u8>>,
    /// Other parameters.
    pub other: Others,
}

/// ABORT SPDU (§8.3.9).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Abort {
    /// Transport disconnect and reason, see [`ABORT_USER`]; mandatory.
    pub transport_disconnect: u8,
    /// Enclosure item.
    pub enclosure: Option<u8>,
    /// Reflect parameter values, with a protocol error.
    pub reflect: Option<Vec<u8>>,
    /// User data, with a user abort.
    pub user_data: Option<Vec<u8>>,
    /// Other parameters.
    pub other: Others,
}

/// GIVE TOKENS SPDU (§8.3.16); without parameters ahead of a DATA TRANSFER SPDU.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GiveTokens {
    /// Tokens given.
    pub token_item: Option<u8>,
    /// Enclosure item.
    pub enclosure: Option<u8>,
    /// User data.
    pub user_data: Option<Vec<u8>>,
    /// Other parameters.
    pub other: Others,
}

/// DATA TRANSFER SPDU (§8.3.11).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DataTransfer {
    /// Enclosure item, present only with segmenting.
    pub enclosure: Option<u8>,
    /// User information field: the SSDU.
    pub user_information: Vec<u8>,
    /// Other parameters.
    pub other: Others,
}

/// An SPDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spdu {
    /// CONNECT.
    Connect(Connect),
    /// ACCEPT.
    Accept(Accept),
    /// REFUSE.
    Refuse(Refuse),
    /// FINISH.
    Finish(Finish),
    /// DISCONNECT.
    Disconnect(Disconnect),
    /// ABORT.
    Abort(Abort),
    /// ABORT ACCEPT.
    AbortAccept,
    /// GIVE TOKENS.
    GiveTokens(GiveTokens),
    /// DATA TRANSFER.
    DataTransfer(DataTransfer),
    /// Any other SPDU, as received.
    Other {
        /// SPDU identifier.
        si: u8,
        /// Parameter field.
        parameters: Vec<u8>,
        /// User information field, for the SPDUs that have one.
        user_information: Vec<u8>,
    },
}

fn user_data(slot: &mut Option<Vec<u8>>, code: u8, value: &[u8]) -> Result<(), Error> {
    if slot.is_some() {
        // §7.1.1: User Data and Extended User Data are exclusive.
        return Err(Error::InvalidParameter(code));
    }
    *slot = Some(value.to_vec());
    Ok(())
}

fn connection_identifier(value: &[u8], reference: u8) -> Result<ConnectionIdentifier, Error> {
    let mut id = ConnectionIdentifier::default();
    for (code, value) in units(value)? {
        match code {
            c if c == reference => id.ss_user_reference = Some(bounded(c, value, 64)?),
            PI_COMMON_REFERENCE => id.common_reference = Some(bounded(code, value, 64)?),
            PI_ADDITIONAL_REFERENCE => id.additional_reference = Some(bounded(code, value, 4)?),
            _ => {}
        }
    }
    Ok(id)
}

fn connect_accept_item(value: &[u8]) -> Result<ConnectAcceptItem, Error> {
    let mut item = ConnectAcceptItem::default();
    let (mut options, mut version) = (None, None);
    for (code, value) in units(value)? {
        match code {
            PI_PROTOCOL_OPTIONS => options = Some(octet(code, value)?),
            PI_VERSION => version = Some(octet(code, value)?),
            PI_TOKEN_SETTING => item.token_setting = Some(octet(code, value)?),
            PI_TSDU_MAXIMUM_SIZE => match value {
                [a, b, c, d] => {
                    item.tsdu_maximum_size =
                        Some((u16::from_be_bytes([*a, *b]), u16::from_be_bytes([*c, *d])));
                }
                _ => return Err(Error::InvalidParameter(code)),
            },
            _ => item.other.push((code, value.to_vec())),
        }
    }
    // Table 11: Protocol Options and Version Number are mandatory within the group.
    item.protocol_options = options.ok_or(Error::MissingParameter(PI_PROTOCOL_OPTIONS))?;
    item.version_number = version.ok_or(Error::MissingParameter(PI_VERSION))?;
    Ok(item)
}

fn decode_connect(list: Vec<Unit<'_>>) -> Result<Connect, Error> {
    let mut s = Connect::default();
    for (code, value) in list {
        match code {
            PGI_CONNECTION_ID => {
                s.connection_identifier = Some(connection_identifier(value, PI_CALLING_REFERENCE)?);
            }
            PGI_CONNECT_ACCEPT => s.item = Some(connect_accept_item(value)?),
            PI_USER_REQUIREMENTS => s.session_user_requirements = Some(word(code, value)?),
            PI_CALLING_SELECTOR => s.calling_selector = Some(bounded(code, value, 16)?),
            PI_CALLED_SELECTOR => s.called_selector = Some(bounded(code, value, 16)?),
            PI_DATA_OVERFLOW => s.data_overflow = Some(octet(code, value)?),
            PGI_USER_DATA => user_data(
                &mut s.user_data,
                code,
                &bounded(code, value, USER_DATA_MAX)?,
            )?,
            PGI_EXTENDED_USER_DATA => {
                user_data(
                    &mut s.user_data,
                    code,
                    &bounded(code, value, EXTENDED_USER_DATA_MAX)?,
                )?;
            }
            _ => s.other.push((code, value.to_vec())),
        }
    }
    Ok(s)
}

fn decode_accept(list: Vec<Unit<'_>>) -> Result<Accept, Error> {
    let mut s = Accept::default();
    for (code, value) in list {
        match code {
            PGI_CONNECTION_ID => {
                s.connection_identifier = Some(connection_identifier(value, PI_CALLED_REFERENCE)?);
            }
            PGI_CONNECT_ACCEPT => s.item = Some(connect_accept_item(value)?),
            PI_TOKEN_ITEM => s.token_item = Some(octet(code, value)?),
            PI_USER_REQUIREMENTS => s.session_user_requirements = Some(word(code, value)?),
            PI_ENCLOSURE => s.enclosure = Some(octet(code, value)?),
            PI_CALLING_SELECTOR => s.calling_selector = Some(bounded(code, value, 16)?),
            PI_CALLED_SELECTOR => s.responding_selector = Some(bounded(code, value, 16)?),
            PGI_USER_DATA => user_data(&mut s.user_data, code, value)?,
            _ => s.other.push((code, value.to_vec())),
        }
    }
    Ok(s)
}

fn decode_refuse(list: Vec<Unit<'_>>) -> Result<Refuse, Error> {
    let mut s = Refuse::default();
    for (code, value) in list {
        match code {
            PGI_CONNECTION_ID => {
                s.connection_identifier = Some(connection_identifier(value, PI_CALLED_REFERENCE)?);
            }
            PI_TRANSPORT_DISCONNECT => s.transport_disconnect = Some(octet(code, value)?),
            PI_USER_REQUIREMENTS => s.session_user_requirements = Some(word(code, value)?),
            PI_VERSION => s.version_number = Some(octet(code, value)?),
            PI_ENCLOSURE => s.enclosure = Some(octet(code, value)?),
            PI_REASON if value.is_empty() => return Err(Error::InvalidParameter(code)),
            PI_REASON => s.reason = Some(value.to_vec()),
            _ => s.other.push((code, value.to_vec())),
        }
    }
    Ok(s)
}

fn decode_finish(list: Vec<Unit<'_>>) -> Result<Finish, Error> {
    let mut s = Finish::default();
    for (code, value) in list {
        match code {
            PI_TRANSPORT_DISCONNECT => s.transport_disconnect = Some(octet(code, value)?),
            PI_ENCLOSURE => s.enclosure = Some(octet(code, value)?),
            PGI_USER_DATA => user_data(&mut s.user_data, code, value)?,
            _ => s.other.push((code, value.to_vec())),
        }
    }
    Ok(s)
}

fn decode_disconnect(list: Vec<Unit<'_>>) -> Result<Disconnect, Error> {
    let mut s = Disconnect::default();
    for (code, value) in list {
        match code {
            PI_ENCLOSURE => s.enclosure = Some(octet(code, value)?),
            PGI_USER_DATA => user_data(&mut s.user_data, code, value)?,
            _ => s.other.push((code, value.to_vec())),
        }
    }
    Ok(s)
}

fn decode_abort(list: Vec<Unit<'_>>) -> Result<Abort, Error> {
    let mut s = Abort::default();
    let mut disconnect = None;
    for (code, value) in list {
        match code {
            PI_TRANSPORT_DISCONNECT => disconnect = Some(octet(code, value)?),
            PI_ENCLOSURE => s.enclosure = Some(octet(code, value)?),
            PI_REFLECT => s.reflect = Some(bounded(code, value, 9)?),
            PGI_USER_DATA => user_data(&mut s.user_data, code, value)?,
            _ => s.other.push((code, value.to_vec())),
        }
    }
    s.transport_disconnect = disconnect.ok_or(Error::MissingParameter(PI_TRANSPORT_DISCONNECT))?;
    Ok(s)
}

fn decode_give_tokens(list: Vec<Unit<'_>>) -> Result<GiveTokens, Error> {
    let mut s = GiveTokens::default();
    for (code, value) in list {
        match code {
            PI_TOKEN_ITEM => s.token_item = Some(octet(code, value)?),
            PI_ENCLOSURE => s.enclosure = Some(octet(code, value)?),
            PGI_USER_DATA => user_data(&mut s.user_data, code, value)?,
            _ => s.other.push((code, value.to_vec())),
        }
    }
    Ok(s)
}

/// One SPDU header: SI, parameter field, and the octets after it.
fn split(bytes: &[u8]) -> Result<(u8, &[u8], &[u8]), Error> {
    let (&si, rest) = bytes.split_first().ok_or(Error::Truncated)?;
    let (size, used) = length(rest)?;
    let rest = rest.get(used..).ok_or(Error::Truncated)?;
    let parameters = rest.get(..size).ok_or(Error::Length)?;
    let after = rest.get(size..).ok_or(Error::Length)?;
    Ok((si, parameters, after))
}

/// A category 1 SPDU, or a category 0 one alone; `after` must be empty, except for SPDUs
/// whose kind this decoder does not know.
fn decode_alone(si: u8, parameters: &[u8], after: &[u8]) -> Result<Spdu, Error> {
    let known = [
        si::GIVE_TOKENS,
        si::FINISH,
        si::DISCONNECT,
        si::REFUSE,
        si::CONNECT,
        si::ACCEPT,
        si::ABORT,
        si::ABORT_ACCEPT,
    ];
    if known.contains(&si) && !after.is_empty() {
        return Err(Error::TrailingData);
    }
    let list = units(parameters)?;
    Ok(match si {
        si::CONNECT => Spdu::Connect(decode_connect(list)?),
        si::ACCEPT => Spdu::Accept(decode_accept(list)?),
        si::REFUSE => Spdu::Refuse(decode_refuse(list)?),
        si::FINISH => Spdu::Finish(decode_finish(list)?),
        si::DISCONNECT => Spdu::Disconnect(decode_disconnect(list)?),
        si::ABORT => Spdu::Abort(decode_abort(list)?),
        si::ABORT_ACCEPT if parameters.is_empty() => Spdu::AbortAccept,
        si::ABORT_ACCEPT => return Err(Error::InvalidParameter(0)),
        si::GIVE_TOKENS => Spdu::GiveTokens(decode_give_tokens(list)?),
        _ => Spdu::Other {
            si,
            parameters: parameters.to_vec(),
            user_information: after.to_vec(),
        },
    })
}

/// The SPDUs of one TSDU (§8.1, §6.3.7).
pub fn decode_tsdu(bytes: &[u8]) -> Result<Vec<Spdu>, Error> {
    let (si, parameters, after) = split(bytes)?;
    let category_0 = si == si::GIVE_TOKENS || si == si::PLEASE_TOKENS;
    if !category_0 || after.is_empty() {
        return Ok(vec![decode_alone(si, parameters, after)?]);
    }
    // Basic concatenation: the category 0 SPDU, then one category 2 SPDU, whose user information
    // field runs to the end of the TSDU.
    let first = if si == si::GIVE_TOKENS {
        Spdu::GiveTokens(decode_give_tokens(units(parameters)?)?)
    } else {
        Spdu::Other {
            si,
            parameters: parameters.to_vec(),
            user_information: Vec::new(),
        }
    };
    let (second_si, second_parameters, user_information) = split(after)?;
    let second = if second_si == si::DATA_TRANSFER && si == si::GIVE_TOKENS {
        let mut dt = DataTransfer {
            user_information: user_information.to_vec(),
            ..DataTransfer::default()
        };
        for (code, value) in units(second_parameters)? {
            match code {
                PI_ENCLOSURE => dt.enclosure = Some(octet(code, value)?),
                _ => dt.other.push((code, value.to_vec())),
            }
        }
        Spdu::DataTransfer(dt)
    } else {
        Spdu::Other {
            si: second_si,
            parameters: second_parameters.to_vec(),
            user_information: user_information.to_vec(),
        }
    };
    Ok(vec![first, second])
}

/// A parameter group: its PGI and its units.
type Group = (u8, Others);

fn reference_group(id: &ConnectionIdentifier, reference: u8) -> Result<Group, Error> {
    // The same bounds as on decoding.
    let mut group = Vec::new();
    if let Some(v) = &id.ss_user_reference {
        group.push((reference, bounded(reference, v, 64)?));
    }
    if let Some(v) = &id.common_reference {
        group.push((PI_COMMON_REFERENCE, bounded(PI_COMMON_REFERENCE, v, 64)?));
    }
    if let Some(v) = &id.additional_reference {
        group.push((
            PI_ADDITIONAL_REFERENCE,
            bounded(PI_ADDITIONAL_REFERENCE, v, 4)?,
        ));
    }
    Ok((PGI_CONNECTION_ID, group))
}

fn nested(group: Vec<(u8, Vec<u8>)>) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    put_units(&mut out, group)?;
    Ok(out)
}

fn item_units(item: &ConnectAcceptItem) -> Result<Vec<u8>, Error> {
    let mut group = vec![
        (PI_PROTOCOL_OPTIONS, vec![item.protocol_options]),
        (PI_VERSION, vec![item.version_number]),
    ];
    if let Some((forward, backward)) = item.tsdu_maximum_size {
        let mut value = forward.to_be_bytes().to_vec();
        value.extend_from_slice(&backward.to_be_bytes());
        group.push((PI_TSDU_MAXIMUM_SIZE, value));
    }
    if let Some(v) = item.token_setting {
        group.push((PI_TOKEN_SETTING, vec![v]));
    }
    group.extend(item.other.iter().cloned());
    nested(group)
}

fn push<T: Clone>(
    units: &mut Vec<(u8, Vec<u8>)>,
    code: u8,
    value: Option<&T>,
    f: impl Fn(&T) -> Vec<u8>,
) {
    if let Some(v) = value {
        units.push((code, f(v)));
    }
}

impl Spdu {
    /// The SI, parameter units and user information of this SPDU.
    fn parts(&self) -> Result<Parts<'_>, Error> {
        let mut u: Vec<(u8, Vec<u8>)> = Vec::new();
        let byte = |v: &u8| vec![*v];
        let word = |v: &u16| v.to_be_bytes().to_vec();
        let bytes = |v: &Vec<u8>| v.clone();
        let si = match self {
            Self::Connect(s) => {
                if let Some(id) = &s.connection_identifier {
                    let (code, group) = reference_group(id, PI_CALLING_REFERENCE)?;
                    u.push((code, nested(group)?));
                }
                if let Some(item) = &s.item {
                    u.push((PGI_CONNECT_ACCEPT, item_units(item)?));
                }
                push(
                    &mut u,
                    PI_USER_REQUIREMENTS,
                    s.session_user_requirements.as_ref(),
                    word,
                );
                push(
                    &mut u,
                    PI_CALLING_SELECTOR,
                    s.calling_selector.as_ref(),
                    bytes,
                );
                push(
                    &mut u,
                    PI_CALLED_SELECTOR,
                    s.called_selector.as_ref(),
                    bytes,
                );
                push(&mut u, PI_DATA_OVERFLOW, s.data_overflow.as_ref(), byte);
                if let Some(data) = &s.user_data {
                    let code = match data.len() {
                        0..=USER_DATA_MAX => PGI_USER_DATA,
                        n if n <= EXTENDED_USER_DATA_MAX => PGI_EXTENDED_USER_DATA,
                        _ => return Err(Error::TooLong),
                    };
                    u.push((code, data.clone()));
                }
                u.extend(s.other.iter().cloned());
                si::CONNECT
            }
            Self::Accept(s) => {
                if let Some(id) = &s.connection_identifier {
                    let (code, group) = reference_group(id, PI_CALLED_REFERENCE)?;
                    u.push((code, nested(group)?));
                }
                if let Some(item) = &s.item {
                    u.push((PGI_CONNECT_ACCEPT, item_units(item)?));
                }
                push(&mut u, PI_TOKEN_ITEM, s.token_item.as_ref(), byte);
                push(
                    &mut u,
                    PI_USER_REQUIREMENTS,
                    s.session_user_requirements.as_ref(),
                    word,
                );
                push(&mut u, PI_ENCLOSURE, s.enclosure.as_ref(), byte);
                push(
                    &mut u,
                    PI_CALLING_SELECTOR,
                    s.calling_selector.as_ref(),
                    bytes,
                );
                push(
                    &mut u,
                    PI_CALLED_SELECTOR,
                    s.responding_selector.as_ref(),
                    bytes,
                );
                push(&mut u, PGI_USER_DATA, s.user_data.as_ref(), bytes);
                u.extend(s.other.iter().cloned());
                si::ACCEPT
            }
            Self::Refuse(s) => {
                if let Some(id) = &s.connection_identifier {
                    let (code, group) = reference_group(id, PI_CALLED_REFERENCE)?;
                    u.push((code, nested(group)?));
                }
                push(
                    &mut u,
                    PI_TRANSPORT_DISCONNECT,
                    s.transport_disconnect.as_ref(),
                    byte,
                );
                push(
                    &mut u,
                    PI_USER_REQUIREMENTS,
                    s.session_user_requirements.as_ref(),
                    word,
                );
                push(&mut u, PI_VERSION, s.version_number.as_ref(), byte);
                push(&mut u, PI_ENCLOSURE, s.enclosure.as_ref(), byte);
                // The reason code takes one octet at least, as decoding requires.
                if s.reason.as_ref().is_some_and(Vec::is_empty) {
                    return Err(Error::InvalidParameter(PI_REASON));
                }
                push(&mut u, PI_REASON, s.reason.as_ref(), bytes);
                u.extend(s.other.iter().cloned());
                si::REFUSE
            }
            Self::Finish(s) => {
                push(
                    &mut u,
                    PI_TRANSPORT_DISCONNECT,
                    s.transport_disconnect.as_ref(),
                    byte,
                );
                push(&mut u, PI_ENCLOSURE, s.enclosure.as_ref(), byte);
                push(&mut u, PGI_USER_DATA, s.user_data.as_ref(), bytes);
                u.extend(s.other.iter().cloned());
                si::FINISH
            }
            Self::Disconnect(s) => {
                push(&mut u, PI_ENCLOSURE, s.enclosure.as_ref(), byte);
                push(&mut u, PGI_USER_DATA, s.user_data.as_ref(), bytes);
                u.extend(s.other.iter().cloned());
                si::DISCONNECT
            }
            Self::Abort(s) => {
                u.push((PI_TRANSPORT_DISCONNECT, vec![s.transport_disconnect]));
                push(&mut u, PI_ENCLOSURE, s.enclosure.as_ref(), byte);
                push(&mut u, PI_REFLECT, s.reflect.as_ref(), bytes);
                push(&mut u, PGI_USER_DATA, s.user_data.as_ref(), bytes);
                u.extend(s.other.iter().cloned());
                si::ABORT
            }
            Self::AbortAccept => si::ABORT_ACCEPT,
            Self::GiveTokens(s) => {
                push(&mut u, PI_TOKEN_ITEM, s.token_item.as_ref(), byte);
                push(&mut u, PI_ENCLOSURE, s.enclosure.as_ref(), byte);
                push(&mut u, PGI_USER_DATA, s.user_data.as_ref(), bytes);
                u.extend(s.other.iter().cloned());
                si::GIVE_TOKENS
            }
            Self::DataTransfer(s) => {
                push(&mut u, PI_ENCLOSURE, s.enclosure.as_ref(), byte);
                u.extend(s.other.iter().cloned());
                return Ok((si::DATA_TRANSFER, u, &s.user_information));
            }
            Self::Other {
                si,
                parameters,
                user_information,
            } => {
                // Kept as received: written back without reordering.
                return Ok((*si, vec![(0, parameters.clone())], user_information));
            }
        };
        Ok((si, u, &[]))
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let (si, units, user_information) = self.parts()?;
        let field = if let Self::Other { parameters, .. } = self {
            parameters.clone()
        } else {
            // The same bounds as on decoding: selectors of 16 octets, Reflect of 9.
            for (code, value) in &units {
                match *code {
                    PI_CALLING_SELECTOR | PI_CALLED_SELECTOR => {
                        bounded(*code, value, 16)?;
                    }
                    PI_REFLECT => {
                        bounded(*code, value, 9)?;
                    }
                    _ => {}
                }
            }
            let mut field = Vec::new();
            put_units(&mut field, units)?;
            field
        };
        out.push(si);
        put_length(out, field.len())?;
        out.extend_from_slice(&field);
        out.extend_from_slice(user_information);
        Ok(())
    }
}

/// One TSDU from its SPDUs: one SPDU other than DATA TRANSFER, or GIVE TOKENS followed by
/// DATA TRANSFER (basic concatenation).
pub fn encode_tsdu(spdus: &[Spdu]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    match spdus {
        [Spdu::DataTransfer(_)] | [] => return Err(Error::Concatenation),
        [single] => single.write(&mut out)?,
        [first @ Spdu::GiveTokens(_), second @ Spdu::DataTransfer(_)] => {
            first.write(&mut out)?;
            second.write(&mut out)?;
        }
        _ => return Err(Error::Concatenation),
    }
    Ok(out)
}
