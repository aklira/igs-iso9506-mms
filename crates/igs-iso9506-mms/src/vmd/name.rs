// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Names of the MMS objects (ISO 9506-2 §7.5): identifiers, and the targets of a reference, which
//! are VMD-specific or domain-specific.

use std::fmt;

use igs_iso9506_mms_codec::generated::types::{Identifier, ObjectName, ObjectNameDomainSpecific};
use igs_iso9506_mms_codec::mms::is_identifier_char;

/// The longest identifier. The codec refuses longer ones (`docs/capabilities.md`, G9).
pub const MAX_IDENTIFIER_LENGTH: usize = 32;

/// An identifier of an MMS object: between one and [`MAX_IDENTIFIER_LENGTH`] characters, each one
/// accepted by the codec.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

/// Why a text is not an identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameError {
    /// The identifier is empty.
    Empty,
    /// The identifier has more characters than [`MAX_IDENTIFIER_LENGTH`].
    TooLong {
        /// The number of characters.
        length: usize,
    },
    /// A character that the codec does not accept in an identifier.
    InvalidCharacter(char),
    /// An object with an application association-specific name, which this model does not hold.
    AaSpecific,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "the identifier is empty"),
            Self::TooLong { length } => write!(
                f,
                "the identifier has {length} characters, at most {MAX_IDENTIFIER_LENGTH} allowed"
            ),
            Self::InvalidCharacter(c) => write!(f, "the character {c:?} is not allowed"),
            Self::AaSpecific => write!(f, "application association-specific names are not held"),
        }
    }
}

impl std::error::Error for NameError {}

impl Name {
    /// Checks an identifier.
    pub fn new(text: &str) -> Result<Self, NameError> {
        if text.is_empty() {
            return Err(NameError::Empty);
        }
        let length = text.chars().count();
        if length > MAX_IDENTIFIER_LENGTH {
            return Err(NameError::TooLong { length });
        }
        if let Some(c) = text.chars().find(|c| !is_identifier_char(*c)) {
            return Err(NameError::InvalidCharacter(c));
        }
        Ok(Self(text.to_string()))
    }

    /// The identifier as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The scope in which a name is looked up: the VMD, or one of its domains (ISO 9506-2 §7.5.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// The VMD-specific scope.
    Vmd,
    /// The domain-specific scope of the named domain.
    Domain(Name),
}

/// A reference to an object of the VMD: a VMD-specific name, or a domain-specific one (ISO 9506-2
/// §7.5.3, §7.5.4).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Target {
    /// The domain, for a domain-specific name.
    pub domain: Option<Name>,
    /// The item identifier.
    pub item: Name,
}

impl Target {
    /// A VMD-specific reference.
    pub fn vmd(item: Name) -> Self {
        Self { domain: None, item }
    }

    /// A domain-specific reference.
    pub fn in_domain(domain: Name, item: Name) -> Self {
        Self {
            domain: Some(domain),
            item,
        }
    }

    /// The scope of the reference.
    pub fn scope(&self) -> Scope {
        match &self.domain {
            None => Scope::Vmd,
            Some(domain) => Scope::Domain(domain.clone()),
        }
    }
}

impl TryFrom<&ObjectName> for Target {
    type Error = NameError;

    fn try_from(name: &ObjectName) -> Result<Self, Self::Error> {
        match name {
            ObjectName::VmdSpecific(Identifier(item)) => Ok(Self::vmd(Name::new(item)?)),
            ObjectName::DomainSpecific(ObjectNameDomainSpecific {
                domain_id: Identifier(domain),
                item_id: Identifier(item),
            }) => Ok(Self::in_domain(Name::new(domain)?, Name::new(item)?)),
            ObjectName::AaSpecific(_) => Err(NameError::AaSpecific),
        }
    }
}

impl From<&Target> for ObjectName {
    fn from(target: &Target) -> Self {
        match &target.domain {
            None => ObjectName::VmdSpecific(Identifier(target.item.as_str().to_string())),
            Some(domain) => ObjectName::DomainSpecific(ObjectNameDomainSpecific {
                domain_id: Identifier(domain.as_str().to_string()),
                item_id: Identifier(target.item.as_str().to_string()),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identifier_has_between_one_and_32_characters() {
        assert_eq!(Name::new(""), Err(NameError::Empty));
        assert!(Name::new("a").is_ok());
        let longest = "x".repeat(MAX_IDENTIFIER_LENGTH);
        assert!(Name::new(&longest).is_ok());
        let too_long = "x".repeat(MAX_IDENTIFIER_LENGTH + 1);
        assert_eq!(Name::new(&too_long), Err(NameError::TooLong { length: 33 }));
    }

    #[test]
    fn the_iec_61850_separators_are_identifier_characters() {
        assert!(Name::new("GGIO1$MX$AnIn1$mag$f").is_ok());
        assert_eq!(Name::new("a b"), Err(NameError::InvalidCharacter(' ')));
    }

    #[test]
    fn a_reference_round_trips_through_the_codec_type() {
        let target = Target::in_domain(Name::new("D").unwrap(), Name::new("item").unwrap());
        let name = ObjectName::from(&target);
        assert_eq!(Target::try_from(&name), Ok(target));
        let vmd = Target::vmd(Name::new("list").unwrap());
        assert_eq!(Target::try_from(&ObjectName::from(&vmd)), Ok(vmd));
    }
}
