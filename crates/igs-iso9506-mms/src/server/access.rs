// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Alternate access (ISO 9506-2 §14.4, IEC 61850-8-1 MMS-007; task N4 of igs-iec61850-mms).
//!
//! A request with alternate access reaches the model of the server only when the server negotiated the
//! `valt` CBB ([`ServerConfig::with_alternate_access`](crate::server::ServerConfig::with_alternate_access)).
//! The generic VMD keeps refusing it. A model that serves it reads the selections of each item with
//! [`steps`]: they come as a path of [`AccessStep`]s from the variable, checked against the bounds of the
//! protocol. What the model does with the path (which components exist, which elements) is its own.

use igs_iso9506_mms_codec::generated::types::{
    AlternateAccess, AlternateAccessItemItem, AlternateAccessSelection,
    AlternateAccessSelectionSelectAccess,
    AlternateAccessSelectionSelectAlternateAccessAccessSelection, DataAccessError,
};

/// One step of an access path: a component of a structure, or elements of an array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessStep {
    /// A named component of a structure.
    Component(String),
    /// One element of an array, by its index.
    Index(u32),
    /// `count` elements of an array, from `low` on (`count` is at least one).
    Range {
        /// The index of the first element.
        low: u32,
        /// The number of elements.
        count: u32,
    },
    /// All the elements of an array.
    AllElements,
}

/// Why an alternate access is refused by its bounds, before the model sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathError {
    /// An index that is negative or does not fit in 32 bits.
    IndexOutOfRange,
    /// A range of no element (`numberOfElements` zero).
    EmptyRange,
    /// A range whose last element does not fit in 32 bits.
    RangeOverflow,
}

impl PathError {
    /// The error of the item that carries the refused access: an invalid value (ISO 9506-2 Table 26).
    pub fn data_access_error(self) -> DataAccessError {
        DataAccessError::OBJECT_VALUE_INVALID
    }
}

/// The path of an alternate access, from the variable: the items of the list in order. A named item
/// starts with its component name. A nested selection (`selectAlternateAccess`) applies its own access
/// selection and then its alternate access, to the component it selects.
pub fn steps(access: &AlternateAccess) -> Result<Vec<AccessStep>, PathError> {
    let mut out = Vec::new();
    for item in &access.0 {
        match item {
            AlternateAccessItemItem::Unnamed(selection) => selection_steps(selection, &mut out)?,
            AlternateAccessItemItem::Named(named) => {
                out.push(AccessStep::Component(named.component_name.0.clone()));
                selection_steps(&named.access, &mut out)?;
            }
        }
    }
    Ok(out)
}

fn selection_steps(
    selection: &AlternateAccessSelection,
    out: &mut Vec<AccessStep>,
) -> Result<(), PathError> {
    match selection {
        AlternateAccessSelection::SelectAccess(select) => out.push(select_access(select)?),
        AlternateAccessSelection::SelectAlternateAccess(nested) => {
            out.push(nested_access(&nested.access_selection)?);
            out.extend(steps(&nested.alternate_access)?);
        }
    }
    Ok(())
}

fn select_access(select: &AlternateAccessSelectionSelectAccess) -> Result<AccessStep, PathError> {
    match select {
        AlternateAccessSelectionSelectAccess::Component(name) => {
            Ok(AccessStep::Component(name.0.clone()))
        }
        AlternateAccessSelectionSelectAccess::Index(index) => {
            Ok(AccessStep::Index(index_of(index.0)?))
        }
        AlternateAccessSelectionSelectAccess::IndexRange(range) => {
            range_of(range.low_index.0, range.number_of_elements.0)
        }
        AlternateAccessSelectionSelectAccess::AllElements => Ok(AccessStep::AllElements),
    }
}

fn nested_access(
    select: &AlternateAccessSelectionSelectAlternateAccessAccessSelection,
) -> Result<AccessStep, PathError> {
    match select {
        AlternateAccessSelectionSelectAlternateAccessAccessSelection::Component(name) => {
            Ok(AccessStep::Component(name.0.clone()))
        }
        AlternateAccessSelectionSelectAlternateAccessAccessSelection::Index(index) => {
            Ok(AccessStep::Index(index_of(index.0)?))
        }
        AlternateAccessSelectionSelectAlternateAccessAccessSelection::IndexRange(range) => {
            range_of(range.low_index.0, range.number_of_elements.0)
        }
        AlternateAccessSelectionSelectAlternateAccessAccessSelection::AllElements => {
            Ok(AccessStep::AllElements)
        }
    }
}

fn index_of(value: i64) -> Result<u32, PathError> {
    u32::try_from(value).map_err(|_| PathError::IndexOutOfRange)
}

fn range_of(low: i64, count: i64) -> Result<AccessStep, PathError> {
    let low = index_of(low)?;
    let count = index_of(count)?;
    if count == 0 {
        return Err(PathError::EmptyRange);
    }
    // The last element is low + count - 1, which must fit in 32 bits.
    let last = u64::from(low)
        .saturating_add(u64::from(count))
        .saturating_sub(1);
    if last > u64::from(u32::MAX) {
        return Err(PathError::RangeOverflow);
    }
    Ok(AccessStep::Range { low, count })
}

#[cfg(test)]
mod tests {
    use super::*;
    use igs_iso9506_mms_codec::generated::types::{
        AlternateAccessItemItemNamed, AlternateAccessSelectionSelectAccessIndexRange,
        AlternateAccessSelectionSelectAlternateAccess, Identifier, Unsigned32,
    };

    fn id(text: &str) -> Identifier {
        Identifier(text.to_string())
    }

    fn unnamed(select: AlternateAccessSelectionSelectAccess) -> AlternateAccessItemItem {
        AlternateAccessItemItem::Unnamed(AlternateAccessSelection::SelectAccess(select))
    }

    #[test]
    fn a_component_and_an_index_are_steps() {
        let access = AlternateAccess(vec![
            AlternateAccessItemItem::Named(AlternateAccessItemItemNamed {
                component_name: id("Data"),
                access: AlternateAccessSelection::SelectAccess(
                    AlternateAccessSelectionSelectAccess::Component(id("stVal")),
                ),
            }),
            unnamed(AlternateAccessSelectionSelectAccess::Index(Unsigned32(3))),
        ]);
        assert_eq!(
            steps(&access),
            Ok(vec![
                AccessStep::Component("Data".into()),
                AccessStep::Component("stVal".into()),
                AccessStep::Index(3),
            ])
        );
    }

    #[test]
    fn an_index_range_and_all_elements_keep_their_bounds() {
        let range = AlternateAccess(vec![unnamed(
            AlternateAccessSelectionSelectAccess::IndexRange(
                AlternateAccessSelectionSelectAccessIndexRange {
                    low_index: Unsigned32(2),
                    number_of_elements: Unsigned32(4),
                },
            ),
        )]);
        assert_eq!(
            steps(&range),
            Ok(vec![AccessStep::Range { low: 2, count: 4 }])
        );
        let all = AlternateAccess(vec![unnamed(
            AlternateAccessSelectionSelectAccess::AllElements,
        )]);
        assert_eq!(steps(&all), Ok(vec![AccessStep::AllElements]));
    }

    #[test]
    fn a_nested_selection_is_its_selection_then_its_alternate_access() {
        let nested = AlternateAccess(vec![AlternateAccessItemItem::Unnamed(
            AlternateAccessSelection::SelectAlternateAccess(
                AlternateAccessSelectionSelectAlternateAccess {
                    access_selection:
                        AlternateAccessSelectionSelectAlternateAccessAccessSelection::Index(
                            Unsigned32(1),
                        ),
                    alternate_access: AlternateAccess(vec![AlternateAccessItemItem::Named(
                        AlternateAccessItemItemNamed {
                            component_name: id("x"),
                            access: AlternateAccessSelection::SelectAccess(
                                AlternateAccessSelectionSelectAccess::AllElements,
                            ),
                        },
                    )]),
                },
            ),
        )]);
        assert_eq!(
            steps(&nested),
            Ok(vec![
                AccessStep::Index(1),
                AccessStep::Component("x".into()),
                AccessStep::AllElements,
            ])
        );
    }

    #[test]
    fn the_bounds_are_checked_before_the_model_sees_them() {
        let empty = AlternateAccess(vec![unnamed(
            AlternateAccessSelectionSelectAccess::IndexRange(
                AlternateAccessSelectionSelectAccessIndexRange {
                    low_index: Unsigned32(0),
                    number_of_elements: Unsigned32(0),
                },
            ),
        )]);
        assert_eq!(steps(&empty), Err(PathError::EmptyRange));

        let last = i64::from(u32::MAX);
        let overflow = AlternateAccess(vec![unnamed(
            AlternateAccessSelectionSelectAccess::IndexRange(
                AlternateAccessSelectionSelectAccessIndexRange {
                    low_index: Unsigned32(last),
                    number_of_elements: Unsigned32(2),
                },
            ),
        )]);
        assert_eq!(steps(&overflow), Err(PathError::RangeOverflow));
        // The last element alone fits.
        let fits = AlternateAccess(vec![unnamed(
            AlternateAccessSelectionSelectAccess::IndexRange(
                AlternateAccessSelectionSelectAccessIndexRange {
                    low_index: Unsigned32(last),
                    number_of_elements: Unsigned32(1),
                },
            ),
        )]);
        assert_eq!(
            steps(&fits),
            Ok(vec![AccessStep::Range {
                low: u32::MAX,
                count: 1
            }])
        );

        let negative = AlternateAccess(vec![unnamed(AlternateAccessSelectionSelectAccess::Index(
            Unsigned32(-1),
        ))]);
        assert_eq!(steps(&negative), Err(PathError::IndexOutOfRange));
    }

    #[test]
    fn a_refused_path_is_an_invalid_value_for_the_item() {
        assert_eq!(
            PathError::EmptyRange.data_access_error(),
            DataAccessError::OBJECT_VALUE_INVALID
        );
    }
}
