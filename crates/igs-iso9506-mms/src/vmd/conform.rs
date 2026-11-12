// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Whether a value conforms to a type description (ISO 9506-2 §14.2, the simple classes of §14.2.2.4).
//!
//! A size that is negative is a maximum: the value may be shorter (§14.2.2.4.2). A type that names
//! another type, or a value that this model does not hold (a boolean array, a value of a later
//! edition), does not conform: the model refuses it rather than guess.

use igs_iso9506_mms_codec::generated::types::{
    Data, TypeDescription, TypeDescriptionArray, TypeDescriptionStructure, TypeSpecification,
};
use igs_iso9506_mms_codec::schema::BitString;

/// Whether `value` is a value of the type `ty`.
pub fn conforms(ty: &TypeDescription, value: &Data) -> bool {
    match (ty, value) {
        (TypeDescription::Array(array), Data::Array(items)) => array_conforms(array, items),
        (TypeDescription::Structure(structure), Data::Structure(items)) => {
            structure_conforms(structure, items)
        }
        (TypeDescription::Boolean, Data::Boolean(_)) => true,
        (TypeDescription::BitString(size), Data::BitString(bits)) => {
            sized_length(size.0, bit_length(bits))
        }
        (TypeDescription::Integer(bits), Data::Integer(value)) => fits_signed(*value, bits.0),
        (TypeDescription::Unsigned(bits), Data::Unsigned(value)) => fits_unsigned(*value, bits.0),
        (TypeDescription::FloatingPoint(format), Data::FloatingPoint(float)) => {
            floating_point_conforms(format.format_width.0, format.exponent_width.0, &float.0)
        }
        (TypeDescription::OctetString(size), Data::OctetString(octets)) => {
            sized_length(size.0, octets.len())
        }
        (TypeDescription::VisibleString(size), Data::VisibleString(text)) => {
            sized_length(size.0, text.chars().count())
        }
        (TypeDescription::GeneralizedTime, Data::GeneralizedTime(_)) => true,
        (TypeDescription::BinaryTime(with_date), Data::BinaryTime(time)) => {
            // The sizes of the codec's TimeOfDay: four octets without the date, six with it.
            time.0.len() == if *with_date { 6 } else { 4 }
        }
        (TypeDescription::Bcd(digits), Data::Bcd(value)) => bcd_fits(*value, digits.0),
        (TypeDescription::ObjId, Data::ObjId(_)) => true,
        (TypeDescription::MMSString(size), Data::MMSString(text)) => {
            sized_length(size.0, text.0.chars().count())
        }
        (TypeDescription::UtcTime, Data::UtcTime(time)) => {
            // IEC 61850-8-1 Annex F.3.1: eight octets, read as a timestamp (N3).
            time.timestamp().is_ok()
        }
        // Types and values that this model does not hold.
        _ => false,
    }
}

fn array_conforms(array: &TypeDescriptionArray, items: &[Data]) -> bool {
    let Ok(count) = usize::try_from(array.number_of_elements.0) else {
        return false;
    };
    count == items.len()
        && items
            .iter()
            .all(|item| element_conforms(&array.element_type, item))
}

fn structure_conforms(structure: &TypeDescriptionStructure, items: &[Data]) -> bool {
    structure.components.len() == items.len()
        && structure
            .components
            .iter()
            .zip(items)
            .all(|(component, item)| element_conforms(&component.component_type, item))
}

/// A component or an element: named types are not held by this model.
fn element_conforms(ty: &TypeSpecification, value: &Data) -> bool {
    match ty {
        TypeSpecification::TypeDescription(description) => conforms(description, value),
        TypeSpecification::TypeName(_) => false,
    }
}

/// The number of bits of a bit string.
fn bit_length(bits: &BitString) -> usize {
    bits.bytes
        .len()
        .saturating_mul(8)
        .saturating_sub(usize::from(bits.unused))
}

/// A fixed length when the size is not negative, a maximum when it is (§14.2.2.4.2).
fn sized_length(size: i64, length: usize) -> bool {
    let Ok(length) = i64::try_from(length) else {
        return false;
    };
    if size >= 0 {
        length == size
    } else {
        size.checked_neg().is_some_and(|maximum| length <= maximum)
    }
}

/// Whether the value fits in a signed integer of `bits` bits (§14.2.2.4.1, INTEGER).
fn fits_signed(value: i128, bits: i64) -> bool {
    let Ok(bits) = u32::try_from(bits) else {
        return false;
    };
    if bits == 0 {
        return false;
    }
    if bits >= 128 {
        return true;
    }
    let Some(half) = bits
        .checked_sub(1)
        .and_then(|shift| 1i128.checked_shl(shift))
    else {
        return false;
    };
    match half.checked_neg() {
        Some(low) => value >= low && value < half,
        None => false,
    }
}

/// Whether the value fits in an unsigned integer of `bits` bits (§14.2.2.4.1, UNSIGNED).
fn fits_unsigned(value: u128, bits: i64) -> bool {
    let Ok(bits) = u32::try_from(bits) else {
        return false;
    };
    if bits == 0 {
        return false;
    }
    match 1u128.checked_shl(bits) {
        Some(limit) => value < limit,
        None => true,
    }
}

/// Whether a value in the codec's form (the exponent width, then the octets of the format) has the
/// exponent width and the length of the type (§14.2.2.4.1, FLOATING POINT).
fn floating_point_conforms(format_width: i64, exponent_width: i64, octets: &[u8]) -> bool {
    let (Ok(format), Ok(exponent)) = (u64::try_from(format_width), u8::try_from(exponent_width))
    else {
        return false;
    };
    let Some((&width, rest)) = octets.split_first() else {
        return false;
    };
    let body = u64::try_from(rest.len()).unwrap_or(u64::MAX);
    width == exponent && body == format.div_ceil(8)
}

/// Whether a BCD value has at most `digits` digits (§14.2.2.4.1, BCD).
fn bcd_fits(value: u128, digits: i64) -> bool {
    let Ok(digits) = u32::try_from(digits) else {
        return false;
    };
    match 10u128.checked_pow(digits) {
        Some(limit) => value < limit,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use igs_iso9506_mms_codec::generated::types::{
        Integer32, TimeOfDay, TypeDescriptionArray, TypeDescriptionFloatingPoint,
        TypeDescriptionStructure, TypeDescriptionStructureComponentsItem, Unsigned32, Unsigned8,
    };

    use super::*;

    fn integer(bits: i64) -> TypeDescription {
        TypeDescription::Integer(Unsigned8(bits))
    }

    #[test]
    fn an_array_has_its_number_of_elements_each_of_its_type() {
        let ty = TypeDescription::Array(Box::new(TypeDescriptionArray {
            packed: None,
            number_of_elements: Unsigned32(2),
            element_type: Box::new(TypeSpecification::TypeDescription(Box::new(integer(8)))),
        }));
        assert!(conforms(
            &ty,
            &Data::Array(vec![Data::Integer(1), Data::Integer(-1)])
        ));
        assert!(!conforms(&ty, &Data::Array(vec![Data::Integer(1)])));
        assert!(!conforms(
            &ty,
            &Data::Array(vec![Data::Integer(1), Data::Integer(300)])
        ));
    }

    #[test]
    fn a_structure_has_its_components_in_order() {
        let component = |ty| TypeDescriptionStructureComponentsItem {
            component_name: None,
            component_type: TypeSpecification::TypeDescription(Box::new(ty)),
        };
        let ty = TypeDescription::Structure(TypeDescriptionStructure {
            packed: None,
            components: vec![component(TypeDescription::Boolean), component(integer(16))],
        });
        assert!(conforms(
            &ty,
            &Data::Structure(vec![Data::Boolean(false), Data::Integer(5)])
        ));
        assert!(!conforms(
            &ty,
            &Data::Structure(vec![Data::Integer(5), Data::Boolean(false)])
        ));
    }

    #[test]
    fn a_named_type_is_not_held_so_its_values_are_refused() {
        let ty = TypeDescription::Array(Box::new(TypeDescriptionArray {
            packed: None,
            number_of_elements: Unsigned32(1),
            element_type: Box::new(TypeSpecification::TypeName(
                igs_iso9506_mms_codec::generated::types::ObjectName::VmdSpecific(
                    igs_iso9506_mms_codec::generated::types::Identifier("t".to_string()),
                ),
            )),
        }));
        assert!(!conforms(&ty, &Data::Array(vec![Data::Boolean(true)])));
    }

    #[test]
    fn a_floating_point_has_its_exponent_width_and_its_octets() {
        // ISO 9506-2 §14.4.2.2: the first octet is the exponent width, then the format's octets.
        let single = TypeDescription::FloatingPoint(TypeDescriptionFloatingPoint {
            format_width: Unsigned8(32),
            exponent_width: Unsigned8(8),
        });
        assert!(conforms(
            &single,
            &Data::FloatingPoint(igs_iso9506_mms_codec::generated::types::FloatingPoint(
                vec![8, 0, 0, 0, 0]
            ))
        ));
        assert!(!conforms(
            &single,
            &Data::FloatingPoint(igs_iso9506_mms_codec::generated::types::FloatingPoint(
                vec![11, 0, 0, 0, 0]
            ))
        ));
        assert!(!conforms(
            &single,
            &Data::FloatingPoint(igs_iso9506_mms_codec::generated::types::FloatingPoint(
                vec![8, 0, 0]
            ))
        ));
    }

    #[test]
    fn a_binary_time_has_its_date_or_not() {
        let without = TypeDescription::BinaryTime(false);
        let with = TypeDescription::BinaryTime(true);
        assert!(conforms(&without, &Data::BinaryTime(TimeOfDay(vec![0; 4]))));
        assert!(!conforms(
            &without,
            &Data::BinaryTime(TimeOfDay(vec![0; 6]))
        ));
        assert!(conforms(&with, &Data::BinaryTime(TimeOfDay(vec![0; 6]))));
    }

    #[test]
    fn a_bcd_has_at_most_its_digits() {
        let ty = TypeDescription::Bcd(Unsigned8(3));
        assert!(conforms(&ty, &Data::Bcd(999)));
        assert!(!conforms(&ty, &Data::Bcd(1000)));
    }

    #[test]
    fn a_size_that_is_negative_is_a_maximum() {
        assert!(sized_length(-4, 0));
        assert!(sized_length(-4, 4));
        assert!(!sized_length(-4, 5));
        assert!(sized_length(4, 4));
        assert!(!sized_length(4, 3));
        // The octet string of the same size, in the simple class.
        let ty = TypeDescription::OctetString(Integer32(-2));
        assert!(conforms(&ty, &Data::OctetString(vec![1, 2])));
        assert!(!conforms(&ty, &Data::OctetString(vec![1, 2, 3])));
    }

    #[test]
    fn an_unsupported_alternative_never_conforms() {
        let ty = TypeDescription::Unsupported {
            tag: 99,
            raw: igs_iso9506_mms_codec::schema::RawBer(Vec::new()),
        };
        assert!(!conforms(&ty, &Data::Boolean(true)));
    }
}
