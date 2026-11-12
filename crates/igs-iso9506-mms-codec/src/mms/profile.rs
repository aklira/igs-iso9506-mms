// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Profiles of the MMS association: what an application profile adds to ISO 9506 (D-033).
//!
//! The TASE.2 profile (IEC 60870-6-702) keeps the ISO 9506 limits and checks nothing more here. The
//! IEC 61850 profile (IEC 61850-8-1 clause 24) widens the identifiers and the `Data` strings
//! (see [`StringLimits`]), requires a nesting level of six when the logical-node model is declared
//! (Tables 124 and 125, c2), and requires the parameter CBBs and the services of Tables 127 and 128
//! that the declared ACSI model implies. The rules are generated from clause 24 (`generated::profile_81`).

use crate::generated::profile_81::{Rule, PARAMETER_RULES, SERVICE_RULES};
use crate::schema::BitString;

pub use super::strings::StringLimits;

/// A feature of the ACSI model that a rule of clause 24 depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    /// Logical-node model support (7-2 clause 10).
    LogicalNodes,
    /// Data-set support (7-2 clause 11).
    DataSets,
    /// A data object with an array implemented (7-2 clause 11, arrays).
    Arrays,
}

/// What a rule requires of one side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// Not required by the profile.
    Never,
    /// Required in every association.
    Always,
    /// Required when one of these features is declared. A sufficient condition: the rule may require
    /// more, but never less than what the clause states for these features.
    Any(&'static [Feature]),
    /// Required by a condition that names no modelled feature: not checked.
    Unmodelled,
}

/// The side of the association, in the MMS terms of Tables 124 to 128: the client is the initiator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The initiator of the association.
    Client,
    /// The responder of the association.
    Server,
}

/// The ACSI model that an application declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Model {
    /// Logical-node model support.
    pub logical_nodes: bool,
    /// Data-set support.
    pub data_sets: bool,
    /// Arrays implemented in a data object.
    pub arrays: bool,
}

impl Model {
    fn declares(self, feature: Feature) -> bool {
        match feature {
            Feature::LogicalNodes => self.logical_nodes,
            Feature::DataSets => self.data_sets,
            Feature::Arrays => self.arrays,
        }
    }

    /// Whether a requirement applies to this model.
    pub fn applies(self, requirement: Requirement) -> bool {
        match requirement {
            Requirement::Always => true,
            Requirement::Any(features) => features.iter().any(|f| self.declares(*f)),
            Requirement::Never | Requirement::Unmodelled => false,
        }
    }
}

/// The limits and requirements of one application profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    /// Name, for the diagnostics.
    pub name: &'static str,
    /// The limits on identifiers and on the `Data` MMS string.
    pub string_limits: StringLimits,
    /// The smallest nesting level that either side may negotiate.
    pub min_nesting: i64,
    /// The ACSI model whose rules apply; `None` for a profile without rules.
    pub model: Option<Model>,
}

impl Profile {
    /// ISO 9506 as TASE.2 uses it (IEC 60870-6-702): the limits of ISO 9506, a nesting level of two (6-702
    /// §5), and no rule beyond the negotiation itself.
    pub const TASE2: Self = Self {
        name: "TASE.2 (ISO 9506)",
        string_limits: StringLimits::ISO_9506,
        min_nesting: 2,
        model: None,
    };

    /// The IEC 61850-8-1 profile for a declared ACSI model: the IEC limits, a nesting level of six when
    /// the logical-node model is declared (Table 124, c2) and two otherwise, and the rules of clause 24.
    pub fn iec61850(model: Model) -> Self {
        Self {
            name: "IEC 61850-8-1",
            string_limits: StringLimits::IEC_61850,
            min_nesting: if model.logical_nodes { 6 } else { 2 },
            model: Some(model),
        }
    }

    /// The parameter CBBs that a side must negotiate, by name.
    pub fn required_parameters(&self, side: Side) -> Vec<&'static str> {
        self.required(PARAMETER_RULES, side)
    }

    /// The services that a side must support, by name.
    pub fn required_services(&self, side: Side) -> Vec<&'static str> {
        self.required(SERVICE_RULES, side)
    }

    fn required(&self, rules: &'static [Rule], side: Side) -> Vec<&'static str> {
        let Some(model) = self.model else {
            return Vec::new();
        };
        rules
            .iter()
            .filter(|rule| {
                let requirement = match side {
                    Side::Client => rule.client,
                    Side::Server => rule.server,
                };
                model.applies(requirement)
            })
            .map(|rule| rule.name)
            .collect()
    }

    /// Checks the nesting level that a side proposes or negotiates.
    pub fn check_nesting(&self, level: i64) -> Result<(), ProfileError> {
        if level < self.min_nesting {
            return Err(ProfileError::NestingBelowProfile {
                level,
                required: self.min_nesting,
            });
        }
        Ok(())
    }

    /// Checks that the parameter CBBs negotiated for a side include the ones it must have.
    pub fn check_parameters(&self, side: Side, negotiated: &BitString) -> Result<(), ProfileError> {
        self.check(PARAMETER_RULES, side, negotiated, |cbb| {
            ProfileError::ParameterNotNegotiated { side, cbb }
        })
    }

    /// Checks that the services a side supports include the ones it must support.
    pub fn check_services(&self, side: Side, supported: &BitString) -> Result<(), ProfileError> {
        self.check(SERVICE_RULES, side, supported, |service| {
            ProfileError::ServiceNotSupported { side, service }
        })
    }

    fn check(
        &self,
        rules: &'static [Rule],
        side: Side,
        bits: &BitString,
        error: impl Fn(&'static str) -> ProfileError,
    ) -> Result<(), ProfileError> {
        let Some(model) = self.model else {
            return Ok(());
        };
        for rule in rules {
            let requirement = match side {
                Side::Client => rule.client,
                Side::Server => rule.server,
            };
            if model.applies(requirement) && !bit_set(bits, rule.position) {
                return Err(error(rule.name));
            }
        }
        Ok(())
    }
}

/// Whether a bit is set in a negotiation bit string; a position past its end is not set.
fn bit_set(bits: &BitString, position: u32) -> bool {
    usize::try_from(position).is_ok_and(|p| p < length(bits) && bits.bit(p))
}

fn length(bits: &BitString) -> usize {
    bits.bytes
        .len()
        .saturating_mul(8)
        .saturating_sub(usize::from(bits.unused))
}

/// Why a negotiation does not fit a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileError {
    /// A nesting level below the profile's minimum.
    NestingBelowProfile {
        /// The level given.
        level: i64,
        /// The smallest the profile allows.
        required: i64,
    },
    /// A parameter CBB that the profile requires of this side and that is not negotiated.
    ParameterNotNegotiated {
        /// The side.
        side: Side,
        /// The CBB.
        cbb: &'static str,
    },
    /// A service that the profile requires of this side and that is not supported.
    ServiceNotSupported {
        /// The side.
        side: Side,
        /// The service.
        service: &'static str,
    },
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NestingBelowProfile { level, required } => {
                write!(
                    f,
                    "nesting level {level}, below the {required} of the profile"
                )
            }
            Self::ParameterNotNegotiated { side, cbb } => {
                write!(
                    f,
                    "the {cbb} CBB, required of the {side:?} side, is not negotiated"
                )
            }
            Self::ServiceNotSupported { side, service } => {
                write!(
                    f,
                    "the {service} service, required of the {side:?} side, is not supported"
                )
            }
        }
    }
}

impl std::error::Error for ProfileError {}
