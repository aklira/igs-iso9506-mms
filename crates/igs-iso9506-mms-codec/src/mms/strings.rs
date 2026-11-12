// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The strings that the IEC 61850 union of the MMS modules widens, checked against the profile of
//! the association apart from the codec, as the CBBs are (D-032).
//!
//! The codec decodes the union of ISO 9506-2 and of its IEC 61850-8-1 Annex F extensions:
//! identifiers of up to 64 characters (Annex F.3.2) and a `Data` MMS string that is a UTF8String
//! (Annex F.3.3). A profile then narrows them: ISO 9506 keeps identifiers of 32 characters and the
//! VisibleString of the branch without the `char` CBB (ISO 9506-2 §7.5.2, §14.4.2); IEC 61850 allows
//! 64 characters and a UTF-8 string of at most 255 characters.

use crate::ber::Charset;

use super::{CbbError, MMSpdu};

/// A string reached by the generated `walk_strings` of the MMS types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Walked<'a> {
    /// An `Identifier`.
    Identifier(&'a str),
    /// The `mMSString` alternative of `Data`.
    DataMmsString(&'a str),
}

/// What a profile allows in the `mMSString` alternative of `Data`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataStringForm {
    /// A VisibleString, any length (ISO 9506-2 §14.4.2, branch without the `char` CBB).
    Visible,
    /// A UTF-8 string of at most this many characters (IEC 61850-8-1 Annex F.3.3).
    Utf8 {
        /// Largest number of characters.
        max_chars: usize,
    },
}

/// The limits of a profile on the strings of the IEC 61850 union.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringLimits {
    /// Largest number of characters of an identifier.
    pub max_identifier: usize,
    /// The form of the `Data` MMS string.
    pub data_mms_string: DataStringForm,
}

impl StringLimits {
    /// ISO 9506 without the `char` CBB, the profile of TASE.2: identifiers of 1 to 32 characters
    /// (ISO 9506-2 §7.5.2), a `Data` MMS string that is a VisibleString.
    pub const ISO_9506: Self = Self {
        max_identifier: 32,
        data_mms_string: DataStringForm::Visible,
    };

    /// IEC 61850-8-1: identifiers of 1 to 64 characters (Annex F.3.2), a `Data` MMS string that is a
    /// UTF8String of 0 to 255 characters (Annex F.3.3).
    pub const IEC_61850: Self = Self {
        max_identifier: 64,
        data_mms_string: DataStringForm::Utf8 { max_chars: 255 },
    };
}

impl Default for StringLimits {
    fn default() -> Self {
        Self::ISO_9506
    }
}

/// Checks every identifier and `Data` MMS string of a PDU against the limits of a profile.
pub fn check_strings(pdu: &MMSpdu, limits: &StringLimits) -> Result<(), CbbError> {
    pdu.walk_strings(&mut |walked| check(walked, limits))
}

fn check(walked: Walked<'_>, limits: &StringLimits) -> Result<(), CbbError> {
    match walked {
        Walked::Identifier(text) => {
            let length = text.chars().count();
            if length > limits.max_identifier {
                return Err(CbbError::IdentifierLength {
                    length,
                    limit: limits.max_identifier,
                });
            }
        }
        Walked::DataMmsString(text) => match limits.data_mms_string {
            DataStringForm::Visible if !Charset::Visible.accepts(text) => {
                return Err(CbbError::DataString {
                    reason: "not a VisibleString",
                });
            }
            DataStringForm::Utf8 { max_chars } if text.chars().count() > max_chars => {
                return Err(CbbError::DataString {
                    reason: "longer than the profile allows",
                });
            }
            _ => {}
        },
    }
    Ok(())
}
