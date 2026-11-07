// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Common MMS types (ISO 9506-2 §7.5, §14.2, §14.4; ISO 9506-1 §14.2.1): what their prose adds
//! to the generated types.
//!
//! The types are generated (see [`crate::generated::types`]); this module adds the checks that
//! their constraint check calls, and the readings of [`TimeOfDay`](crate::mms::TimeOfDay) and
//! [`FloatingPoint`](crate::mms::FloatingPoint). The profile has no `char` CBB, so an
//! [`Identifier`](crate::mms::Identifier) and an [`MMSString`](crate::mms::MMSString) are
//! VisibleStrings. The integers of [`Data`](crate::mms::Data) hold up to 128 bits: a type
//! description gives them at most 127.

mod floating;
mod time;

pub use crate::generated::types::{
    AccessResult, Data, DataAccessError, FloatingPoint, Identifier, Integer16, Integer32, Integer8,
    MMSString, ObjectName, ObjectNameDomainSpecific, TimeOfDay, TypeDescription,
    TypeDescriptionArray, TypeDescriptionFloatingPoint, TypeDescriptionStructure,
    TypeDescriptionStructureComponentsItem, TypeSpecification, Unsigned32, Unsigned8,
};
pub use time::MAX_MILLISECONDS;

use crate::asn::Error;

/// Whether a character is allowed in an Identifier: letters, digits, `$` and `_` (ISO 9506-2
/// §7.5.2, the branch without the `char` CBB).
pub fn is_identifier_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '$' || c == '_'
}

/// The permitted alphabet of an Identifier; its size is checked by the generated code.
pub(crate) fn check_identifier(text: &str) -> Result<(), Error> {
    if text.chars().all(is_identifier_char) {
        Ok(())
    } else {
        Err(Error::Invalid { ty: "Identifier" })
    }
}

pub(crate) use floating::check_floating_point;
pub(crate) use time::check_time_of_day;
