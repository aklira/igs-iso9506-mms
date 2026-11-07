// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The access of the model to a named variable (ISO 9506-2 §14.1.3): the trait that an application,
//! a TASE.2 or an IEC 61850 object implements, and a variable that holds its value.

use igs_iso9506_mms_codec::generated::types::{Data, DataAccessError, TypeDescription};

use super::conform::conforms;

/// A named variable, as the model reads and writes it.
///
/// The model checks the scope, the existence, the write permission and the type of a value before it
/// calls the variable: `write` receives a value that conforms to [`Variable::type_description`]. The
/// variable answers for its own state, so that a device object can read the real device (ISO 9506-2
/// §14.1.1.2: the V-Get and V-Put functions).
pub trait Variable: Send {
    /// The type description of the variable.
    fn type_description(&self) -> &TypeDescription;

    /// Whether the variable accepts writes. A read-only variable is refused with
    /// object-access-denied.
    fn is_writable(&self) -> bool;

    /// The value of the variable, or the reason for which the access fails.
    fn read(&self) -> Result<Data, DataAccessError>;

    /// Updates the value of the variable, or the reason for which the update fails.
    fn write(&mut self, value: Data) -> Result<(), DataAccessError>;
}

/// A variable whose value is held in memory: the simplest object, for tests and for demonstration
/// servers.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryVariable {
    ty: TypeDescription,
    value: Data,
    writable: bool,
}

impl MemoryVariable {
    /// A variable of the type `ty`, holding `value`. The value must conform to the type; a value that
    /// does not is refused with type-inconsistent.
    pub fn new(ty: TypeDescription, value: Data, writable: bool) -> Result<Self, DataAccessError> {
        if conforms(&ty, &value) {
            Ok(Self {
                ty,
                value,
                writable,
            })
        } else {
            Err(DataAccessError::TYPE_INCONSISTENT)
        }
    }
}

impl Variable for MemoryVariable {
    fn type_description(&self) -> &TypeDescription {
        &self.ty
    }

    fn is_writable(&self) -> bool {
        self.writable
    }

    fn read(&self) -> Result<Data, DataAccessError> {
        Ok(self.value.clone())
    }

    fn write(&mut self, value: Data) -> Result<(), DataAccessError> {
        self.value = value;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use igs_iso9506_mms_codec::generated::types::Unsigned8;

    use super::*;

    #[test]
    fn a_memory_variable_refuses_a_value_of_another_type() {
        let ty = TypeDescription::Boolean;
        assert!(MemoryVariable::new(ty.clone(), Data::Boolean(true), true).is_ok());
        assert_eq!(
            MemoryVariable::new(ty, Data::Integer(1), true),
            Err(DataAccessError::TYPE_INCONSISTENT)
        );
    }

    #[test]
    fn a_memory_variable_keeps_the_last_value_written() {
        let ty = TypeDescription::Unsigned(Unsigned8(8));
        let mut variable = MemoryVariable::new(ty, Data::Unsigned(1), true).unwrap();
        variable.write(Data::Unsigned(200)).unwrap();
        assert_eq!(variable.read(), Ok(Data::Unsigned(200)));
    }
}
