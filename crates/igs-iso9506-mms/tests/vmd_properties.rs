// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Property tests of the VMD model (task S1): the names, the conformance of values to the simple
//! types, and the model itself, compared with a plain reference model over random sequences of
//! operations.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

use igs_iso9506_mms::vmd::{
    conforms, Class, Error, Identity, MemoryVariable, Name, NameError, Scope, Target, Vmd,
    MAX_IDENTIFIER_LENGTH,
};
use igs_iso9506_mms_codec::generated::types::{
    AccessResult, Data, DataAccessError, TypeDescription, Unsigned8,
};
use igs_iso9506_mms_codec::schema::BitString;
use proptest::prelude::*;

// Names

proptest! {
    #[test]
    fn an_identifier_of_legal_characters_is_accepted_up_to_32(
        text in "[A-Za-z0-9_$]{1,32}"
    ) {
        prop_assert!(Name::new(&text).is_ok());
    }

    #[test]
    fn a_longer_identifier_is_refused_with_its_length(
        text in "[A-Za-z0-9_$]{33,80}"
    ) {
        prop_assert_eq!(
            Name::new(&text),
            Err(NameError::TooLong {
                length: text.len(),
                limit: 32
            })
        );
    }

    #[test]
    fn a_space_is_never_part_of_an_identifier(
        head in "[A-Za-z]{0,10}",
        tail in "[A-Za-z]{0,10}",
    ) {
        let text = format!("{head} {tail}");
        prop_assert_eq!(Name::new(&text), Err(NameError::InvalidCharacter(' ')));
    }
}

// Conformance to the simple types (ISO 9506-2 §14.2.2.4)

proptest! {
    #[test]
    fn an_integer_conforms_exactly_within_its_bits(bits in 1i64..=64, value in any::<i64>()) {
        let half = 1i128 << (bits - 1);
        let expected = (value as i128) >= -half && (value as i128) < half;
        let conforms_now = conforms(
            &TypeDescription::Integer(Unsigned8(bits)),
            &Data::Integer(i128::from(value)),
        );
        prop_assert_eq!(conforms_now, expected);
    }

    #[test]
    fn the_bounds_of_an_integer_are_inclusive_and_exclusive(bits in 1i64..=63) {
        let half = 1i128 << (bits - 1);
        let ty = TypeDescription::Integer(Unsigned8(bits));
        prop_assert!(conforms(&ty, &Data::Integer(half - 1)));
        prop_assert!(conforms(&ty, &Data::Integer(-half)));
        prop_assert!(!conforms(&ty, &Data::Integer(half)));
        prop_assert!(!conforms(&ty, &Data::Integer(-half - 1)));
    }

    #[test]
    fn an_unsigned_conforms_exactly_within_its_bits(bits in 1i64..=64, value in any::<u64>()) {
        let limit = 1u128 << bits;
        let expected = u128::from(value) < limit;
        prop_assert_eq!(
            conforms(&TypeDescription::Unsigned(Unsigned8(bits)), &Data::Unsigned(u128::from(value))),
            expected
        );
    }

    #[test]
    fn a_fixed_visible_string_has_exactly_its_size(size in 0i64..=40, text in "[ -~]{0,50}") {
        let length = text.chars().count() as i64;
        let ty = igs_iso9506_mms_codec::generated::types::TypeDescription::VisibleString(
            igs_iso9506_mms_codec::generated::types::Integer32(size),
        );
        prop_assert_eq!(conforms(&ty, &Data::VisibleString(text)), length == size);
    }

    #[test]
    fn a_variable_visible_string_has_at_most_its_maximum(maximum in 1i64..=40, text in "[ -~]{0,50}") {
        let length = text.chars().count() as i64;
        let ty = TypeDescription::VisibleString(igs_iso9506_mms_codec::generated::types::Integer32(-maximum));
        prop_assert_eq!(conforms(&ty, &Data::VisibleString(text)), length <= maximum);
    }

    #[test]
    fn a_bit_string_counts_its_bits_without_the_unused_ones(
        bytes in proptest::collection::vec(any::<u8>(), 1..=8),
        unused in 0u8..8,
        size in 1i64..=64,
    ) {
        let bits = (bytes.len() * 8) as i64 - i64::from(unused);
        let value = BitString { unused, bytes };
        let ty = TypeDescription::BitString(igs_iso9506_mms_codec::generated::types::Integer32(size));
        prop_assert_eq!(conforms(&ty, &Data::BitString(value)), bits == size);
    }

    #[test]
    fn a_value_of_another_kind_never_conforms(value in any::<i64>()) {
        prop_assert!(!conforms(&TypeDescription::Boolean, &Data::Integer(i128::from(value))));
        prop_assert!(!conforms(
            &TypeDescription::Integer(Unsigned8(64)),
            &Data::Unsigned(u128::from(value.unsigned_abs()))
        ));
    }
}

// The model against a reference model

#[derive(Debug, Clone)]
enum Op {
    Add {
        scope: u8,
        item: u8,
        value: i64,
        writable: bool,
    },
    Remove {
        scope: u8,
        item: u8,
    },
    Write {
        scope: u8,
        item: u8,
        value: i64,
    },
    WriteBool {
        scope: u8,
        item: u8,
    },
    Read {
        scope: u8,
        item: u8,
    },
    Define {
        scope: u8,
        list: u8,
        members: Vec<(u8, u8)>,
    },
    Delete {
        scope: u8,
        list: u8,
    },
    ReadList {
        scope: u8,
        list: u8,
    },
    Page,
}

const ITEMS: [&str; 3] = ["a", "b", "c"];
const LISTS: [&str; 2] = ["l", "m"];

fn scope_of(index: u8) -> Scope {
    if index == 0 {
        Scope::Vmd
    } else {
        Scope::Domain(Name::new("D").unwrap())
    }
}

fn target(scope: u8, item: &str) -> Target {
    match scope_of(scope) {
        Scope::Vmd => Target::vmd(Name::new(item).unwrap()),
        Scope::Domain(domain) => Target::in_domain(domain, Name::new(item).unwrap()),
    }
}

fn op() -> impl Strategy<Value = Op> {
    let scope = 0u8..2;
    let item = 0u8..3;
    let list = 0u8..2;
    prop_oneof![
        (scope.clone(), item.clone(), any::<i64>(), any::<bool>()).prop_map(
            |(scope, item, value, writable)| Op::Add {
                scope,
                item,
                value,
                writable
            }
        ),
        (scope.clone(), item.clone()).prop_map(|(scope, item)| Op::Remove { scope, item }),
        (scope.clone(), item.clone(), any::<i64>()).prop_map(|(scope, item, value)| Op::Write {
            scope,
            item,
            value
        }),
        (scope.clone(), item.clone()).prop_map(|(scope, item)| Op::WriteBool { scope, item }),
        (scope.clone(), item.clone()).prop_map(|(scope, item)| Op::Read { scope, item }),
        (
            scope.clone(),
            list.clone(),
            proptest::collection::vec((0u8..2, item.clone()), 0..4),
        )
            .prop_map(|(scope, list, members)| Op::Define {
                scope,
                list,
                members
            }),
        (scope.clone(), list.clone()).prop_map(|(scope, list)| Op::Delete { scope, list }),
        (scope, list).prop_map(|(scope, list)| Op::ReadList { scope, list }),
        Just(Op::Page),
    ]
}

/// The reference model: the variables and the lists of each scope, as plain values.
#[derive(Default)]
struct Reference {
    /// Keyed by scope index and item name; the value and whether it is writable.
    variables: BTreeMap<(u8, &'static str), (i64, bool)>,
    /// Keyed by scope index and list name; the members, as (scope index, item name).
    lists: BTreeMap<(u8, &'static str), Vec<(u8, &'static str)>>,
}

fn item_name(index: u8) -> &'static str {
    ITEMS[usize::from(index)]
}

fn list_name(index: u8) -> &'static str {
    LISTS[usize::from(index)]
}

fn member_name(scope: u8, item: u8) -> (u8, &'static str) {
    (scope, item_name(item))
}

#[test]
fn the_model_agrees_with_the_reference_over_random_operations() {
    let config = ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    };
    let mut runner = proptest::test_runner::TestRunner::new(config);
    runner
        .run(&proptest::collection::vec(op(), 0..40), |ops| {
            let mut model = Vmd::new(Identity {
                vendor: "igs".to_string(),
                model: "test".to_string(),
                revision: "1".to_string(),
            });
            model.add_domain(Name::new("D").unwrap()).unwrap();
            let mut reference = Reference::default();
            for op in ops {
                apply(&mut model, &mut reference, op)?;
            }
            Ok(())
        })
        .unwrap();
}

fn apply(model: &mut Vmd, reference: &mut Reference, op: Op) -> Result<(), TestCaseError> {
    match op {
        Op::Add {
            scope,
            item,
            value,
            writable,
        } => {
            let key = (scope, item_name(item));
            let variable = MemoryVariable::new(
                TypeDescription::Integer(Unsigned8(64)),
                Data::Integer(i128::from(value)),
                writable,
            )
            .unwrap();
            let result = model.add_variable(&target(scope, item_name(item)), Box::new(variable));
            match reference.variables.entry(key) {
                Entry::Occupied(_) => prop_assert_eq!(result, Err(Error::Exists)),
                Entry::Vacant(slot) => {
                    prop_assert_eq!(result, Ok(()));
                    slot.insert((value, writable));
                }
            }
        }
        Op::Remove { scope, item } => {
            let key = (scope, item_name(item));
            let result = model.remove_variable(&target(scope, item_name(item)));
            prop_assert_eq!(result.is_ok(), reference.variables.remove(&key).is_some());
        }
        Op::Write { scope, item, value } => {
            let key = (scope, item_name(item));
            let result = model.write(
                &target(scope, item_name(item)),
                Data::Integer(i128::from(value)),
            );
            match reference.variables.get_mut(&key) {
                None => prop_assert_eq!(result, Err(DataAccessError::OBJECT_NON_EXISTENT)),
                Some((_, false)) => {
                    prop_assert_eq!(result, Err(DataAccessError::OBJECT_ACCESS_DENIED))
                }
                Some((stored, true)) => {
                    prop_assert_eq!(result, Ok(()));
                    *stored = value;
                }
            }
        }
        Op::WriteBool { scope, item } => {
            // A boolean does not conform to the integer type. The checks run in the order of the
            // model: the existence, then the write permission, then the type.
            let result = model.write(&target(scope, item_name(item)), Data::Boolean(true));
            let expected = match reference.variables.get(&(scope, item_name(item))) {
                None => DataAccessError::OBJECT_NON_EXISTENT,
                Some((_, false)) => DataAccessError::OBJECT_ACCESS_DENIED,
                Some((_, true)) => DataAccessError::TYPE_INCONSISTENT,
            };
            prop_assert_eq!(result, Err(expected));
        }
        Op::Read { scope, item } => {
            let result = model.read(&target(scope, item_name(item)));
            match reference.variables.get(&(scope, item_name(item))) {
                None => prop_assert_eq!(result, Err(DataAccessError::OBJECT_NON_EXISTENT)),
                Some((value, _)) => {
                    prop_assert_eq!(result, Ok(Data::Integer(i128::from(*value))))
                }
            }
        }
        Op::Define {
            scope,
            list,
            members,
        } => {
            let key = (scope, list_name(list));
            let target_list = target(scope, list_name(list));
            let refs: Vec<Target> = members
                .iter()
                .map(|(s, i)| target(*s, item_name(*i)))
                .collect();
            let wanted: Vec<(u8, &'static str)> =
                members.iter().map(|(s, i)| member_name(*s, *i)).collect();
            let result = model.define_list(&target_list, refs);
            if reference.lists.contains_key(&key) {
                prop_assert_eq!(result, Err(Error::Exists));
            } else if wanted.iter().any(|m| !reference.variables.contains_key(m)) {
                prop_assert_eq!(result, Err(Error::NonExistent));
            } else {
                prop_assert_eq!(result, Ok(()));
                reference.lists.insert(key, wanted);
            }
        }
        Op::Delete { scope, list } => {
            let key = (scope, list_name(list));
            let result = model.delete_list(&target(scope, list_name(list)));
            prop_assert_eq!(result.is_ok(), reference.lists.remove(&key).is_some());
        }
        Op::ReadList { scope, list } => {
            let key = (scope, list_name(list));
            let result = model.read_list(&target(scope, list_name(list)));
            match reference.lists.get(&key) {
                None => prop_assert_eq!(result, Err(Error::NonExistent)),
                Some(members) => {
                    let expected: Vec<AccessResult> = members
                        .iter()
                        .map(|m| match reference.variables.get(m) {
                            Some((value, _)) => {
                                AccessResult::Success(Data::Integer(i128::from(*value)))
                            }
                            None => AccessResult::Failure(DataAccessError::OBJECT_NON_EXISTENT),
                        })
                        .collect();
                    prop_assert_eq!(result, Ok(expected));
                }
            }
        }
        Op::Page => {
            for (scope, index) in [(0u8, Scope::Vmd), (1u8, scope_of(1))] {
                let names: Vec<String> = reference
                    .variables
                    .keys()
                    .filter(|(s, _)| *s == scope)
                    .map(|(_, item)| item.to_string())
                    .collect();
                let mut sorted = names.clone();
                sorted.sort();
                let page = model.page(Class::NamedVariable, &index, None, 64).unwrap();
                let listed: Vec<String> =
                    page.names.iter().map(|n| n.as_str().to_string()).collect();
                prop_assert_eq!(listed, sorted);
                prop_assert!(!page.more_follows);
            }
        }
    }
    Ok(())
}

#[test]
fn the_longest_identifier_is_the_codec_limit() {
    assert_eq!(MAX_IDENTIFIER_LENGTH, 32);
    let longest = "x".repeat(MAX_IDENTIFIER_LENGTH);
    assert!(Name::new(&longest).is_ok());
}
