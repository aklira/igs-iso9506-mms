// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! CP, CPC, CPA, CPR, ARU and ARP PPDUs (X.226 §8.2).

use super::{Error, UserData};
use crate::ber::{self, Element, Identifier, Reader, Writer};
use crate::schema::{BitString, ObjectIdentifier, TagClass};

fn ctx(number: u32, constructed: bool) -> Identifier {
    Identifier::context(number, constructed)
}

/// Same tag, whatever the form: strings may arrive constructed.
fn is(element: &Element<'_>, number: u32) -> bool {
    element.identifier.class == TagClass::Context && element.identifier.number == number
}

fn is_user_data(element: &Element<'_>) -> bool {
    element.identifier.class == TagClass::Application && element.identifier.number <= 1
}

/// Only named bits set (§8.5.2): positions below `named`.
fn named_bits(bits: &BitString, named: usize, what: &'static str) -> Result<(), Error> {
    for (index, octet) in bits.bytes.iter().enumerate() {
        for bit in 0..8usize {
            let position = index.saturating_mul(8).saturating_add(bit);
            let last = index.saturating_add(1) == bits.bytes.len();
            let unused = last && bit >= 8usize.saturating_sub(usize::from(bits.unused));
            if !unused && position >= named && octet & (0x80u8 >> bit) != 0 {
                return Err(Error::InvalidValue(what));
            }
        }
    }
    Ok(())
}

fn named_number(value: i64, max: i64, what: &'static str) -> Result<i64, Error> {
    if (0..=max).contains(&value) {
        Ok(value)
    } else {
        Err(Error::InvalidValue(what))
    }
}

/// Mode-selector values (§8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// X.410-1984 mode, outside the profile.
    X410,
    /// Normal mode.
    Normal,
}

fn mode(element: &Element<'_>) -> Result<Mode, Error> {
    let mut set = element.children()?;
    let value = set.read()?;
    if !is(&value, 0) {
        return Err(Error::Unexpected(value.identifier));
    }
    set.finish()?;
    match ber::integer_i64(&value)? {
        0 => Ok(Mode::X410),
        1 => Ok(Mode::Normal),
        _ => Err(Error::InvalidValue("mode-value")),
    }
}

fn write_mode(w: &mut Writer, value: Mode) -> Result<(), Error> {
    w.constructed(ctx(0, true), |set| {
        set.integer(ctx(0, false), if value == Mode::Normal { 1 } else { 0 });
        Ok::<(), Error>(())
    })
}

/// An item of a presentation context definition list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextDefinition {
    /// Presentation context identifier.
    pub id: i64,
    /// Abstract syntax name.
    pub abstract_syntax: ObjectIdentifier,
    /// Proposed transfer syntax names.
    pub transfer_syntaxes: Vec<ObjectIdentifier>,
}

/// An item of a presentation context definition result list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextResult {
    /// 0 acceptance, 1 user rejection, 2 provider rejection.
    pub result: i64,
    /// Transfer syntax chosen.
    pub transfer_syntax: Option<ObjectIdentifier>,
    /// Provider reason, 0 to 3.
    pub provider_reason: Option<i64>,
}

/// The default context name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultContextName {
    /// Abstract syntax name.
    pub abstract_syntax: ObjectIdentifier,
    /// Transfer syntax name.
    pub transfer_syntax: ObjectIdentifier,
}

fn context_definitions(element: &Element<'_>) -> Result<Vec<ContextDefinition>, Error> {
    let mut list = element.children()?;
    let mut out = Vec::new();
    while !list.is_empty() {
        let mut item = list.read_expected(Identifier::SEQUENCE)?.children()?;
        let id = ber::integer_i64(&item.read_expected(Identifier::INTEGER)?)?;
        let abstract_syntax =
            ber::object_identifier(&item.read_expected(Identifier::OBJECT_IDENTIFIER)?)?;
        let mut names = item.read_expected(Identifier::SEQUENCE)?.children()?;
        let mut transfer_syntaxes = Vec::new();
        while !names.is_empty() {
            transfer_syntaxes.push(ber::object_identifier(
                &names.read_expected(Identifier::OBJECT_IDENTIFIER)?,
            )?);
        }
        item.finish()?;
        out.push(ContextDefinition {
            id,
            abstract_syntax,
            transfer_syntaxes,
        });
    }
    Ok(out)
}

fn write_context_definitions(
    w: &mut Writer,
    tag: Identifier,
    list: &[ContextDefinition],
) -> Result<(), Error> {
    w.constructed(tag, |seq| {
        for item in list {
            seq.constructed(Identifier::SEQUENCE, |s| {
                s.integer(Identifier::INTEGER, item.id);
                s.object_identifier(Identifier::OBJECT_IDENTIFIER, &item.abstract_syntax)?;
                s.constructed(Identifier::SEQUENCE, |names| {
                    for name in &item.transfer_syntaxes {
                        names.object_identifier(Identifier::OBJECT_IDENTIFIER, name)?;
                    }
                    Ok::<(), Error>(())
                })
            })?;
        }
        Ok(())
    })
}

fn context_results(element: &Element<'_>) -> Result<Vec<ContextResult>, Error> {
    let mut list = element.children()?;
    let mut out = Vec::new();
    while !list.is_empty() {
        let mut item = list.read_expected(Identifier::SEQUENCE)?.children()?;
        let first = item.read()?;
        if !is(&first, 0) {
            return Err(Error::Missing("result"));
        }
        let mut entry = ContextResult {
            result: named_number(ber::integer_i64(&first)?, 2, "result")?,
            transfer_syntax: None,
            provider_reason: None,
        };
        while !item.is_empty() {
            let field = item.read()?;
            match field.identifier.number {
                1 if is(&field, 1) => entry.transfer_syntax = Some(ber::object_identifier(&field)?),
                2 if is(&field, 2) => {
                    entry.provider_reason = Some(named_number(
                        ber::integer_i64(&field)?,
                        3,
                        "provider-reason",
                    )?);
                }
                _ => return Err(Error::Unexpected(field.identifier)),
            }
        }
        out.push(entry);
    }
    Ok(out)
}

fn write_context_results(
    w: &mut Writer,
    tag: Identifier,
    list: &[ContextResult],
) -> Result<(), Error> {
    w.constructed(tag, |seq| {
        for item in list {
            seq.constructed(Identifier::SEQUENCE, |s| {
                s.integer(ctx(0, false), item.result);
                if let Some(name) = &item.transfer_syntax {
                    s.object_identifier(ctx(1, false), name)?;
                }
                if let Some(reason) = item.provider_reason {
                    s.integer(ctx(2, false), reason);
                }
                Ok::<(), Error>(())
            })?;
        }
        Ok(())
    })
}

fn bits(w: &mut Writer, tag: Identifier, value: Option<&BitString>) -> Result<(), Error> {
    if let Some(value) = value {
        w.bit_string(tag, value)?;
    }
    Ok(())
}

/// The normal-mode parameters of a CP PPDU.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectNormal {
    /// Protocol version; absent means version 1.
    pub protocol_version: Option<BitString>,
    /// Calling presentation selector.
    pub calling_selector: Option<Vec<u8>>,
    /// Called presentation selector.
    pub called_selector: Option<Vec<u8>>,
    /// Presentation contexts proposed.
    pub context_definitions: Option<Vec<ContextDefinition>>,
    /// Default context proposed.
    pub default_context: Option<DefaultContextName>,
    /// Presentation functional units proposed.
    pub presentation_requirements: Option<BitString>,
    /// Session functional units, when they differ from the session ones.
    pub user_session_requirements: Option<BitString>,
    /// User data.
    pub user_data: Option<UserData>,
}

/// CP PPDU (CP-type).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connect {
    /// Mode.
    pub mode: Mode,
    /// X.410-1984 mode parameters, as received.
    pub x410_parameters: Option<Vec<u8>>,
    /// Normal-mode parameters.
    pub normal: Option<ConnectNormal>,
}

fn decode_connect_normal(element: &Element<'_>) -> Result<ConnectNormal, Error> {
    let mut seq = element.children()?;
    let mut p = ConnectNormal::default();
    while !seq.is_empty() {
        let field = seq.read()?;
        if is_user_data(&field) {
            p.user_data = Some(UserData::decode_element(&field)?);
            continue;
        }
        if field.identifier.class != TagClass::Context {
            continue;
        }
        // §8.5.1: a CP PPDU ignores undefined elements and unnamed bits.
        match field.identifier.number {
            0 => p.protocol_version = Some(ber::bit_string(&field)?),
            1 => p.calling_selector = Some(ber::octet_string(&field)?),
            2 => p.called_selector = Some(ber::octet_string(&field)?),
            4 => p.context_definitions = Some(context_definitions(&field)?),
            6 => {
                let mut name = field.children()?;
                let abstract_syntax = ber::object_identifier(&name.read()?)?;
                let transfer_syntax = ber::object_identifier(&name.read()?)?;
                name.finish()?;
                p.default_context = Some(DefaultContextName {
                    abstract_syntax,
                    transfer_syntax,
                });
            }
            8 => p.presentation_requirements = Some(ber::bit_string(&field)?),
            9 => p.user_session_requirements = Some(ber::bit_string(&field)?),
            _ => {}
        }
    }
    Ok(p)
}

/// The user data of a CONNECT SPDU: a CP PPDU and the CPC values that may follow it (§8.3.3).
pub fn decode_connect(bytes: &[u8]) -> Result<(Connect, Vec<UserData>), Error> {
    let mut reader = Reader::new(bytes);
    let set = reader.read_expected(Identifier::SET)?;
    let mut parts = set.children()?;
    let (mut mode_value, mut x410, mut normal) = (None, None, None);
    while !parts.is_empty() {
        let field = parts.read()?;
        match field.identifier {
            id if id == ctx(0, true) => mode_value = Some(mode(&field)?),
            id if id == ctx(1, true) => x410 = Some(field.contents.to_vec()),
            id if id == ctx(2, true) => normal = Some(decode_connect_normal(&field)?),
            _ => {}
        }
    }
    let cp = Connect {
        mode: mode_value.ok_or(Error::Missing("mode-selector"))?,
        x410_parameters: x410,
        normal,
    };
    let mut cpc = Vec::new();
    while !reader.is_empty() {
        cpc.push(UserData::decode_element(&reader.read()?)?);
    }
    Ok((cp, cpc))
}

/// The user data of a CONNECT SPDU from a CP PPDU and CPC values.
pub fn encode_connect(cp: &Connect, cpc: &[UserData]) -> Result<Vec<u8>, Error> {
    let mut w = Writer::new();
    w.constructed(Identifier::SET, |set| {
        write_mode(set, cp.mode)?;
        if let Some(raw) = &cp.x410_parameters {
            set.constructed(ctx(1, true), |x| {
                x.raw(raw);
                Ok::<(), Error>(())
            })?;
        }
        if let Some(p) = &cp.normal {
            set.constructed(ctx(2, true), |seq| {
                bits(seq, ctx(0, false), p.protocol_version.as_ref())?;
                if let Some(s) = &p.calling_selector {
                    seq.octet_string(ctx(1, false), s);
                }
                if let Some(s) = &p.called_selector {
                    seq.octet_string(ctx(2, false), s);
                }
                if let Some(list) = &p.context_definitions {
                    write_context_definitions(seq, ctx(4, true), list)?;
                }
                if let Some(name) = &p.default_context {
                    seq.constructed(ctx(6, true), |n| {
                        n.object_identifier(ctx(0, false), &name.abstract_syntax)?;
                        n.object_identifier(ctx(1, false), &name.transfer_syntax)?;
                        Ok::<(), Error>(())
                    })?;
                }
                bits(seq, ctx(8, false), p.presentation_requirements.as_ref())?;
                bits(seq, ctx(9, false), p.user_session_requirements.as_ref())?;
                if let Some(data) = &p.user_data {
                    data.write(seq)?;
                }
                Ok::<(), Error>(())
            })?;
        }
        Ok::<(), Error>(())
    })?;
    for value in cpc {
        value.write(&mut w)?;
    }
    Ok(w.into_bytes())
}

/// The normal-mode parameters of a CPA PPDU.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcceptNormal {
    /// Protocol version; absent means version 1.
    pub protocol_version: Option<BitString>,
    /// Responding presentation selector.
    pub responding_selector: Option<Vec<u8>>,
    /// Result for each proposed context.
    pub context_results: Option<Vec<ContextResult>>,
    /// Presentation functional units selected.
    pub presentation_requirements: Option<BitString>,
    /// Session functional units, when they differ from the session ones.
    pub user_session_requirements: Option<BitString>,
    /// User data.
    pub user_data: Option<UserData>,
}

/// CPA PPDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectAccept {
    /// Mode.
    pub mode: Mode,
    /// X.410-1984 mode parameters, as received.
    pub x410_parameters: Option<Vec<u8>>,
    /// Normal-mode parameters.
    pub normal: Option<AcceptNormal>,
}

fn check_versions(
    p: Option<&BitString>,
    presentation: Option<&BitString>,
    session: Option<&BitString>,
) -> Result<(), Error> {
    if let Some(v) = p {
        named_bits(v, 1, "protocol-version")?;
    }
    if let Some(v) = presentation {
        named_bits(v, 2, "presentation-requirements")?;
    }
    if let Some(v) = session {
        named_bits(v, 13, "user-session-requirements")?;
    }
    Ok(())
}

impl ConnectAccept {
    /// Decode the user data of an ACCEPT SPDU.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let set = reader.read_expected(Identifier::SET)?;
        reader.finish()?;
        let mut parts = set.children()?;
        let (mut mode_value, mut x410, mut normal) = (None, None, None);
        while !parts.is_empty() {
            let field = parts.read()?;
            match field.identifier {
                id if id == ctx(0, true) => mode_value = Some(mode(&field)?),
                id if id == ctx(1, true) => x410 = Some(field.contents.to_vec()),
                id if id == ctx(2, true) => {
                    let mut seq = field.children()?;
                    let mut p = AcceptNormal::default();
                    while !seq.is_empty() {
                        let f = seq.read()?;
                        if is_user_data(&f) {
                            p.user_data = Some(UserData::decode_element(&f)?);
                            continue;
                        }
                        match f.identifier.number {
                            0 if is(&f, 0) => p.protocol_version = Some(ber::bit_string(&f)?),
                            3 if is(&f, 3) => p.responding_selector = Some(ber::octet_string(&f)?),
                            5 if f.identifier == ctx(5, true) => {
                                p.context_results = Some(context_results(&f)?)
                            }
                            8 if is(&f, 8) => {
                                p.presentation_requirements = Some(ber::bit_string(&f)?)
                            }
                            9 if is(&f, 9) => {
                                p.user_session_requirements = Some(ber::bit_string(&f)?)
                            }
                            _ => return Err(Error::Unexpected(f.identifier)),
                        }
                    }
                    check_versions(
                        p.protocol_version.as_ref(),
                        p.presentation_requirements.as_ref(),
                        p.user_session_requirements.as_ref(),
                    )?;
                    normal = Some(p);
                }
                other => return Err(Error::Unexpected(other)),
            }
        }
        Ok(Self {
            mode: mode_value.ok_or(Error::Missing("mode-selector"))?,
            x410_parameters: x410,
            normal,
        })
    }

    /// The user data of an ACCEPT SPDU.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut w = Writer::new();
        w.constructed(Identifier::SET, |set| {
            write_mode(set, self.mode)?;
            if let Some(raw) = &self.x410_parameters {
                set.constructed(ctx(1, true), |x| {
                    x.raw(raw);
                    Ok::<(), Error>(())
                })?;
            }
            if let Some(p) = &self.normal {
                set.constructed(ctx(2, true), |seq| {
                    bits(seq, ctx(0, false), p.protocol_version.as_ref())?;
                    if let Some(s) = &p.responding_selector {
                        seq.octet_string(ctx(3, false), s);
                    }
                    if let Some(list) = &p.context_results {
                        write_context_results(seq, ctx(5, true), list)?;
                    }
                    bits(seq, ctx(8, false), p.presentation_requirements.as_ref())?;
                    bits(seq, ctx(9, false), p.user_session_requirements.as_ref())?;
                    if let Some(data) = &p.user_data {
                        data.write(seq)?;
                    }
                    Ok::<(), Error>(())
                })?;
            }
            Ok::<(), Error>(())
        })?;
        Ok(w.into_bytes())
    }
}

/// CPR PPDU in normal mode.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectRefuse {
    /// Protocol version; absent means version 1.
    pub protocol_version: Option<BitString>,
    /// Responding presentation selector.
    pub responding_selector: Option<Vec<u8>>,
    /// Result for each proposed context.
    pub context_results: Option<Vec<ContextResult>>,
    /// Result for the default context, 0 to 2.
    pub default_context_result: Option<i64>,
    /// Provider reason, 0 to 7.
    pub provider_reason: Option<i64>,
    /// User data.
    pub user_data: Option<UserData>,
}

impl ConnectRefuse {
    /// Decode the user data of a REFUSE SPDU, normal mode.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let seq = reader.read_expected(Identifier::SEQUENCE)?;
        reader.finish()?;
        let mut fields = seq.children()?;
        let mut p = Self::default();
        while !fields.is_empty() {
            let f = fields.read()?;
            if is_user_data(&f) {
                p.user_data = Some(UserData::decode_element(&f)?);
                continue;
            }
            match f.identifier.number {
                0 if is(&f, 0) => {
                    let version = ber::bit_string(&f)?;
                    named_bits(&version, 1, "protocol-version")?;
                    p.protocol_version = Some(version);
                }
                3 if is(&f, 3) => p.responding_selector = Some(ber::octet_string(&f)?),
                5 if f.identifier == ctx(5, true) => p.context_results = Some(context_results(&f)?),
                7 if is(&f, 7) => {
                    p.default_context_result = Some(named_number(
                        ber::integer_i64(&f)?,
                        2,
                        "default-context-result",
                    )?);
                }
                10 if is(&f, 10) => {
                    p.provider_reason =
                        Some(named_number(ber::integer_i64(&f)?, 7, "provider-reason")?);
                }
                _ => return Err(Error::Unexpected(f.identifier)),
            }
        }
        Ok(p)
    }

    /// The user data of a REFUSE SPDU.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut w = Writer::new();
        w.constructed(Identifier::SEQUENCE, |seq| {
            bits(seq, ctx(0, false), self.protocol_version.as_ref())?;
            if let Some(s) = &self.responding_selector {
                seq.octet_string(ctx(3, false), s);
            }
            if let Some(list) = &self.context_results {
                write_context_results(seq, ctx(5, true), list)?;
            }
            if let Some(v) = self.default_context_result {
                seq.integer(ctx(7, false), v);
            }
            if let Some(v) = self.provider_reason {
                seq.integer(ctx(10, false), v);
            }
            if let Some(data) = &self.user_data {
                data.write(seq)?;
            }
            Ok::<(), Error>(())
        })?;
        Ok(w.into_bytes())
    }
}

/// ARU PPDU in normal mode.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AbortUser {
    /// Presentation contexts of the user data, with their transfer syntax.
    pub context_list: Option<Vec<(i64, ObjectIdentifier)>>,
    /// User data.
    pub user_data: Option<UserData>,
}

/// ARP PPDU.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AbortProvider {
    /// Abort reason, 0 to 6.
    pub reason: Option<i64>,
    /// Event identifier, 0 to 32.
    pub event: Option<i64>,
}

/// The user data of an ABORT SPDU (Abort-type).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Abort {
    /// ARU PPDU, normal mode.
    User(AbortUser),
    /// ARU PPDU, X.410-1984 mode, as received.
    UserX410(Vec<u8>),
    /// ARP PPDU.
    Provider(AbortProvider),
}

/// Decode the user data of an ABORT SPDU.
pub fn decode_abort(bytes: &[u8]) -> Result<Abort, Error> {
    let mut reader = Reader::new(bytes);
    let element = reader.read()?;
    reader.finish()?;
    match element.identifier {
        Identifier::SET => Ok(Abort::UserX410(element.contents.to_vec())),
        Identifier::SEQUENCE => {
            let mut fields = element.children()?;
            let mut p = AbortProvider::default();
            while !fields.is_empty() {
                let f = fields.read()?;
                match f.identifier.number {
                    0 if is(&f, 0) => {
                        p.reason = Some(named_number(ber::integer_i64(&f)?, 6, "abort-reason")?)
                    }
                    1 if is(&f, 1) => {
                        p.event = Some(named_number(ber::integer_i64(&f)?, 32, "event-identifier")?)
                    }
                    _ => return Err(Error::Unexpected(f.identifier)),
                }
            }
            Ok(Abort::Provider(p))
        }
        id if id == ctx(0, true) => {
            let mut fields = element.children()?;
            let mut p = AbortUser::default();
            while !fields.is_empty() {
                let f = fields.read()?;
                if is_user_data(&f) {
                    p.user_data = Some(UserData::decode_element(&f)?);
                } else if f.identifier == ctx(0, true) {
                    let mut list = f.children()?;
                    let mut items = Vec::new();
                    while !list.is_empty() {
                        let mut item = list.read_expected(Identifier::SEQUENCE)?.children()?;
                        let id = ber::integer_i64(&item.read_expected(Identifier::INTEGER)?)?;
                        let name = ber::object_identifier(
                            &item.read_expected(Identifier::OBJECT_IDENTIFIER)?,
                        )?;
                        item.finish()?;
                        items.push((id, name));
                    }
                    p.context_list = Some(items);
                } else {
                    return Err(Error::Unexpected(f.identifier));
                }
            }
            Ok(Abort::User(p))
        }
        other => Err(Error::Unexpected(other)),
    }
}

impl Abort {
    /// The user data of an ABORT SPDU.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut w = Writer::new();
        match self {
            Self::UserX410(raw) => w.constructed(Identifier::SET, |x| {
                x.raw(raw);
                Ok::<(), Error>(())
            })?,
            Self::Provider(p) => w.constructed(Identifier::SEQUENCE, |seq| {
                if let Some(v) = p.reason {
                    seq.integer(ctx(0, false), v);
                }
                if let Some(v) = p.event {
                    seq.integer(ctx(1, false), v);
                }
                Ok::<(), Error>(())
            })?,
            Self::User(p) => w.constructed(ctx(0, true), |seq| {
                if let Some(items) = &p.context_list {
                    seq.constructed(ctx(0, true), |list| {
                        for (id, name) in items {
                            list.constructed(Identifier::SEQUENCE, |s| {
                                s.integer(Identifier::INTEGER, *id);
                                s.object_identifier(Identifier::OBJECT_IDENTIFIER, name)?;
                                Ok::<(), Error>(())
                            })?;
                        }
                        Ok::<(), Error>(())
                    })?;
                }
                if let Some(data) = &p.user_data {
                    data.write(seq)?;
                }
                Ok::<(), Error>(())
            })?,
        }
        Ok(w.into_bytes())
    }
}
