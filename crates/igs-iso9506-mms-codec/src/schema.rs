// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Vocabulary of the generated code: tags, components, primitive values and table rows.

/// Class of a BER tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagClass {
    /// Universal.
    Universal,
    /// Application.
    Application,
    /// Context-specific.
    Context,
    /// Private.
    Private,
}

/// Whether a tag replaces the tag of its type or wraps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tagging {
    /// Replaces the tag of the type.
    Implicit,
    /// Wraps the encoding of the type.
    Explicit,
}

/// A tag of an ASN.1 type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    /// Class.
    pub class: TagClass,
    /// Number.
    pub number: u32,
    /// Implicit or explicit, after the rule on CHOICE and open types.
    pub tagging: Tagging,
}

impl Tag {
    /// A tag.
    pub const fn new(class: TagClass, number: u32, tagging: Tagging) -> Self {
        Self {
            class,
            number,
            tagging,
        }
    }
}

/// Whether a component must appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// Always present.
    Required,
    /// May be absent.
    Optional,
    /// May be absent, then has this value, in ASN.1 notation.
    Default(&'static str),
}

/// A component of a SEQUENCE or an alternative of a CHOICE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member {
    /// ASN.1 name.
    pub name: &'static str,
    /// Tag written in the module, if any.
    pub tag: Option<Tag>,
    /// Presence.
    pub presence: Presence,
}

/// A BIT STRING value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BitString {
    /// Unused bits in the last octet.
    pub unused: u8,
    /// The octets.
    pub bytes: Vec<u8>,
}

impl BitString {
    /// Whether bit `index` is present and set; bit 0 is the leading bit (X.690 §8.6.2).
    pub fn bit(&self, index: usize) -> bool {
        let present = self
            .bytes
            .len()
            .saturating_mul(8)
            .saturating_sub(usize::from(self.unused))
            > index;
        let mask = 0x80u8.checked_shr((index % 8) as u32).unwrap_or(0);
        present && self.bytes.get(index / 8).is_some_and(|b| b & mask != 0)
    }
}

/// An OBJECT IDENTIFIER value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObjectIdentifier(pub Vec<u64>);

/// BER octets kept as received.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawBer(pub Vec<u8>);

/// The four bit strings of the Initiate negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportOption {
    /// `ServiceSupportOptions`.
    Service,
    /// `AdditionalSupportOptions`.
    AdditionalService,
    /// `ParameterSupportOptions`.
    Parameter,
    /// `AdditionalCBBOptions`.
    AdditionalCbb,
}

/// A position in a support option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bit {
    /// Bit string.
    pub option: SupportOption,
    /// Position of the bit.
    pub position: u32,
}

/// The CHOICE that carries a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// Confirmed services.
    Confirmed,
    /// Additional services.
    Additional,
    /// Unconfirmed services.
    Unconfirmed,
}

/// A PDU of MMS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pdu {
    /// ASN.1 name.
    pub name: &'static str,
    /// Tag in the PDU CHOICE.
    pub tag: u32,
}

/// A service with a tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Service {
    /// ASN.1 name of the alternative.
    pub name: &'static str,
    /// CHOICE that carries it.
    pub family: Family,
    /// Tag. It differs from the bit position for part of the services.
    pub tag: u32,
    /// Name of its conformance building block.
    pub cbb: &'static str,
    /// Its bit in the negotiation.
    pub bit: Bit,
    /// Other CBBs needed: every group must hold, through one of its names.
    pub requires: &'static [&'static [&'static str]],
    /// Whether the profile requires it.
    pub in_scope: bool,
    /// Status for a client, as printed in the profile.
    pub client: &'static str,
    /// Status for a server, as printed in the profile.
    pub server: &'static str,
}

/// A modifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Modifier {
    /// ASN.1 name.
    pub name: &'static str,
    /// Tag.
    pub tag: u32,
    /// Name of its conformance building block.
    pub cbb: &'static str,
    /// Its bit in the negotiation.
    pub bit: Bit,
}

/// A parameter CBB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parameter {
    /// Name.
    pub name: &'static str,
    /// Its bit in the negotiation.
    pub bit: Bit,
}

/// A named bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamedBit {
    /// Name.
    pub name: &'static str,
    /// Position.
    pub position: u32,
}

/// A class of error or reject codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeTable {
    /// Name.
    pub name: &'static str,
    /// Tag.
    pub tag: u32,
    /// Names and values.
    pub codes: &'static [(&'static str, u32)],
}

/// What the profile asks of an environment PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PduRequirement {
    /// Name in the profile.
    pub name: &'static str,
    /// Tag in the PDU CHOICE.
    pub tag: u32,
    /// Whether the profile requires it.
    pub in_scope: bool,
    /// Status for a client, sending then receiving.
    pub client: &'static str,
    /// Status for a server, sending then receiving.
    pub server: &'static str,
}
