// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The model of the Virtual Manufacturing Device (ISO 9506-1 §7, ISO 9506-2 §7.4, §14.1): domains,
//! named variables and named variable lists, with the names and the scopes of MMS.
//!
//! The model holds the objects, answers the lookups and the checks that the services need, and calls
//! the variables through [`Variable`], so that a TASE.2 or an IEC 61850 object can supply its own
//! values. Nothing here is specific to either. The model is single-owner: the server gives it to one
//! task, and the services run in turn (task S2).
//!
//! Not modelled yet: named types, unnamed variables (the address scheme), application
//! association-specific names, access control lists, and the other classes of the VMD. Their
//! references are refused: the list is in `docs/capabilities.md`.

mod conform;
mod file;
mod journal;
mod name;
mod variable;

pub use file::{FileError, FileStore, StoredFile};
pub use journal::Journal;

use std::collections::BTreeMap;

use igs_iso9506_mms_codec::generated::types::{
    AccessResult, Data, DataAccessError, ServiceError, ServiceErrorErrorClass,
    ServiceErrorErrorClassAccess, ServiceErrorErrorClassDefinition, TypeDescription,
};

pub use conform::conforms;
pub use name::{Name, NameError, Scope, Target, LARGEST_IDENTIFIER_LENGTH, MAX_IDENTIFIER_LENGTH};
pub use variable::{MemoryVariable, Variable};

/// The classes of named objects that the model holds (ISO 9506-2 §7.4.2, Table 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Named variable objects.
    NamedVariable,
    /// Named variable list objects.
    NamedVariableList,
    /// Domain objects, which exist at the VMD scope only.
    Domain,
}

/// The answers of the Identify service (ISO 9506-2 §7.1): the vendor, the model and the revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The vendor name.
    pub vendor: String,
    /// The model name.
    pub model: String,
    /// The revision.
    pub revision: String,
}

/// One page of a name list: the names after the given one, and whether more follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// The names of the page, in the order of the model.
    pub names: Vec<Name>,
    /// Whether names follow this page (GetNameList, moreFollows).
    pub more_follows: bool,
}

/// Why the model refuses an operation. Each reason has its MMS error, see [`Error::service_error`]
/// and [`Error::data_access_error`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The name is not valid.
    Name(NameError),
    /// An object of this name exists in the scope.
    Exists,
    /// The object, or the domain that holds it, does not exist.
    NonExistent,
    /// The class of object is not held in this scope.
    Unsupported,
}

impl Error {
    /// The MMS error of a service that defines, reads or deletes objects (ISO 9506-2 §7.1, ServiceError).
    pub fn service_error(&self) -> ServiceError {
        let error_class = match self {
            Self::Exists => {
                ServiceErrorErrorClass::Definition(ServiceErrorErrorClassDefinition::OBJECT_EXISTS)
            }
            Self::NonExistent => {
                ServiceErrorErrorClass::Access(ServiceErrorErrorClassAccess::OBJECT_NON_EXISTENT)
            }
            Self::Unsupported => ServiceErrorErrorClass::Access(
                ServiceErrorErrorClassAccess::OBJECT_ACCESS_UNSUPPORTED,
            ),
            Self::Name(_) => {
                ServiceErrorErrorClass::Definition(ServiceErrorErrorClassDefinition::OTHER)
            }
        };
        ServiceError {
            error_class,
            additional_code: None,
            additional_description: None,
            service_specific_info: None,
        }
    }

    /// The Data Access Error of a read or a write (ISO 9506-2 §14.4).
    pub fn data_access_error(&self) -> DataAccessError {
        match self {
            Self::NonExistent => DataAccessError::OBJECT_NON_EXISTENT,
            Self::Unsupported => DataAccessError::OBJECT_ACCESS_UNSUPPORTED,
            Self::Exists => DataAccessError::OBJECT_ATTRIBUTE_INCONSISTENT,
            Self::Name(_) => DataAccessError::OBJECT_UNDEFINED,
        }
    }
}

impl From<NameError> for Error {
    fn from(error: NameError) -> Self {
        match error {
            NameError::AaSpecific => Self::Unsupported,
            other => Self::Name(other),
        }
    }
}

/// A named variable list: the references of its members, in order (ISO 9506-2 §14.12).
type List = Vec<Target>;

/// A domain: its named variables, its named variable lists, and its journals.
#[derive(Default)]
struct Domain {
    variables: BTreeMap<Name, Box<dyn Variable>>,
    lists: BTreeMap<Name, List>,
    journals: BTreeMap<Name, Journal>,
}

/// The model of a VMD.
pub struct Vmd {
    identity: Identity,
    identifier_limit: usize,
    variables: BTreeMap<Name, Box<dyn Variable>>,
    lists: BTreeMap<Name, List>,
    domains: BTreeMap<Name, Domain>,
    files: FileStore,
}

impl std::fmt::Debug for Vmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The objects are trait objects: the counts are shown, not the values.
        f.debug_struct("Vmd")
            .field("identity", &self.identity)
            .field("variables", &self.variables.len())
            .field("lists", &self.lists.len())
            .field("domains", &self.domains.len())
            .finish()
    }
}

impl Vmd {
    /// An empty VMD with this identity.
    pub fn new(identity: Identity) -> Self {
        Self {
            identity,
            identifier_limit: MAX_IDENTIFIER_LENGTH,
            variables: BTreeMap::new(),
            lists: BTreeMap::new(),
            domains: BTreeMap::new(),
            files: FileStore::default(),
        }
    }

    /// The identity of the VMD.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The longest identifier of the objects of the VMD: 32 under the ISO 9506 profile, which is the default.
    pub fn identifier_limit(&self) -> usize {
        self.identifier_limit
    }

    /// Sets the identifier limit of the VMD for the profile it serves, up to [`LARGEST_IDENTIFIER_LENGTH`] (the
    /// IEC 61850 profile; task N6). Set it before the objects are added, since their names are checked when they
    /// are made.
    pub fn with_identifier_limit(mut self, limit: usize) -> Result<Self, NameError> {
        if !(1..=LARGEST_IDENTIFIER_LENGTH).contains(&limit) {
            return Err(NameError::LimitOutOfRange(limit));
        }
        self.identifier_limit = limit;
        Ok(self)
    }

    /// The name of an object of this VMD, checked against its identifier limit.
    pub fn name(&self, text: &str) -> Result<Name, NameError> {
        Name::with_limit(text, self.identifier_limit)
    }

    /// Adds a domain, at the VMD scope.
    pub fn add_domain(&mut self, name: Name) -> Result<(), Error> {
        if self.domains.contains_key(&name) {
            return Err(Error::Exists);
        }
        self.domains.insert(name, Domain::default());
        Ok(())
    }

    /// Adds a named variable at the reference `target`. The domain of the reference must exist.
    pub fn add_variable(
        &mut self,
        target: &Target,
        variable: Box<dyn Variable>,
    ) -> Result<(), Error> {
        let map = self.variables_mut(&target.scope())?;
        if map.contains_key(&target.item) {
            return Err(Error::Exists);
        }
        map.insert(target.item.clone(), variable);
        Ok(())
    }

    /// Removes a named variable, by local action (ISO 9506-2 §7.4.6). The lists that name it keep
    /// their references, which then fail with object-non-existent.
    pub fn remove_variable(&mut self, target: &Target) -> Result<Box<dyn Variable>, Error> {
        self.variables_mut(&target.scope())?
            .remove(&target.item)
            .ok_or(Error::NonExistent)
    }

    /// DefineNamedVariableList: defines the list `name`, with these members (ISO 9506-2 §14.12).
    /// The name must be free in its scope, and each member must exist when the list is defined.
    pub fn define_list(&mut self, name: &Target, members: Vec<Target>) -> Result<(), Error> {
        if self.lists_of(&name.scope())?.contains_key(&name.item) {
            return Err(Error::Exists);
        }
        if members.iter().any(|member| !self.exists(member)) {
            return Err(Error::NonExistent);
        }
        self.lists_mut(&name.scope())?
            .insert(name.item.clone(), members);
        Ok(())
    }

    /// Adds a file to the virtual file store of the VMD, at this path of directory names and a file name. An existing file is replaced.
    pub fn add_file(&mut self, path: &[&str], content: Vec<u8>, last_modified: Option<&str>) {
        self.files.add(
            path.iter().map(|part| (*part).to_string()).collect(),
            content,
            last_modified.map(str::to_string),
        );
    }

    /// The virtual file store of the VMD.
    pub fn files(&self) -> &FileStore {
        &self.files
    }

    /// The virtual file store of the VMD, for the file services.
    pub fn files_mut(&mut self) -> &mut FileStore {
        &mut self.files
    }

    /// Defines a journal of a domain, which keeps at most `capacity` entries (ISO 9506-2 clause 23). The journal is domain-specific:
    /// the name must have a domain, which must exist, and the name must be free in it.
    pub fn define_journal(&mut self, name: &Target, capacity: usize) -> Result<(), Error> {
        let domain = name.domain.clone().ok_or(Error::Unsupported)?;
        let domain = self.domains.get_mut(&domain).ok_or(Error::NonExistent)?;
        if domain.journals.contains_key(&name.item) {
            return Err(Error::Exists);
        }
        domain
            .journals
            .insert(name.item.clone(), Journal::new(capacity));
        Ok(())
    }

    /// Enters an entry into a journal of a domain (the application's side of ISO 9506-2 clause 23).
    pub fn append_journal(
        &mut self,
        name: &Target,
        entry: igs_iso9506_mms_codec::generated::types::JournalEntry,
    ) -> Result<(), Error> {
        self.journal_mut(name)?.append(entry);
        Ok(())
    }

    /// The journal of this name.
    pub fn journal(&self, name: &Target) -> Result<&Journal, Error> {
        let domain = name.domain.as_ref().ok_or(Error::Unsupported)?;
        self.domains
            .get(domain)
            .and_then(|domain| domain.journals.get(&name.item))
            .ok_or(Error::NonExistent)
    }

    fn journal_mut(&mut self, name: &Target) -> Result<&mut Journal, Error> {
        let domain = name.domain.as_ref().ok_or(Error::Unsupported)?;
        self.domains
            .get_mut(domain)
            .and_then(|domain| domain.journals.get_mut(&name.item))
            .ok_or(Error::NonExistent)
    }

    /// DeleteNamedVariableList for one list (ISO 9506-2 §14.13). The caller counts the matched and the
    /// deleted lists of a request.
    pub fn delete_list(&mut self, name: &Target) -> Result<(), Error> {
        self.lists_mut(&name.scope())?
            .remove(&name.item)
            .map(|_| ())
            .ok_or(Error::NonExistent)
    }

    /// GetNamedVariableListAttributes: the members of a list, in order (ISO 9506-2 §14.14).
    pub fn list_members(&self, name: &Target) -> Result<&[Target], Error> {
        self.lists_of(&name.scope())?
            .get(&name.item)
            .map(Vec::as_slice)
            .ok_or(Error::NonExistent)
    }

    /// GetNameList: one page of the names of a class in a scope, after `after` in the order of the
    /// model, of at most `limit` names. A class of names that the scope does not hold is refused.
    pub fn page(
        &self,
        class: Class,
        scope: &Scope,
        after: Option<&Name>,
        limit: usize,
    ) -> Result<Page, Error> {
        let names: Vec<Name> = match (class, scope) {
            (Class::Domain, Scope::Vmd) => self.domains.keys().cloned().collect(),
            (Class::Domain, Scope::Domain(_)) => return Err(Error::Unsupported),
            (Class::NamedVariable, scope) => self.variables_of(scope)?.keys().cloned().collect(),
            (Class::NamedVariableList, scope) => self.lists_of(scope)?.keys().cloned().collect(),
        };
        let after_names = names.iter().filter(|name| after.is_none_or(|a| *name > a));
        let page: Vec<Name> = after_names.clone().take(limit).cloned().collect();
        let more_follows = after_names.count() > page.len();
        Ok(Page {
            names: page,
            more_follows,
        })
    }

    /// Read of a named variable (ISO 9506-2 §14.6), with the reason for which it fails.
    pub fn read(&self, target: &Target) -> Result<Data, DataAccessError> {
        match self.variable(target) {
            Ok(variable) => variable.read(),
            Err(error) => Err(error.data_access_error()),
        }
    }

    /// The result of a Read of the members of a list, one per member (ISO 9506-2 §14.6, §14.1.4).
    pub fn read_list(&self, name: &Target) -> Result<Vec<AccessResult>, Error> {
        Ok(self
            .list_members(name)?
            .iter()
            .map(|member| match self.read(member) {
                Ok(data) => AccessResult::Success(data),
                Err(error) => AccessResult::Failure(error),
            })
            .collect())
    }

    /// Write of a named variable (ISO 9506-2 §14.7). The value must conform to the type of the
    /// variable, which is refused with type-inconsistent otherwise.
    pub fn write(&mut self, target: &Target, value: Data) -> Result<(), DataAccessError> {
        let variable = self
            .variable_mut(target)
            .map_err(|error| error.data_access_error())?;
        if !variable.is_writable() {
            return Err(DataAccessError::OBJECT_ACCESS_DENIED);
        }
        if !conforms(variable.type_description(), &value) {
            return Err(DataAccessError::TYPE_INCONSISTENT);
        }
        variable.write(value)
    }

    /// The type description of a named variable, for GetVariableAccessAttributes (ISO 9506-2 §14.9).
    pub fn type_description(&self, target: &Target) -> Result<&TypeDescription, Error> {
        Ok(self.variable(target)?.type_description())
    }

    /// Whether a named variable exists, or a named variable list.
    fn exists(&self, target: &Target) -> bool {
        self.variable(target).is_ok() || self.list_members(target).is_ok()
    }

    fn variable(&self, target: &Target) -> Result<&dyn Variable, Error> {
        self.variables_of(&target.scope())?
            .get(&target.item)
            .map(|variable| variable.as_ref())
            .ok_or(Error::NonExistent)
    }

    fn variable_mut(&mut self, target: &Target) -> Result<&mut Box<dyn Variable>, Error> {
        self.variables_mut(&target.scope())?
            .get_mut(&target.item)
            .ok_or(Error::NonExistent)
    }

    fn variables_of(&self, scope: &Scope) -> Result<&BTreeMap<Name, Box<dyn Variable>>, Error> {
        match scope {
            Scope::Vmd => Ok(&self.variables),
            Scope::Domain(domain) => self
                .domains
                .get(domain)
                .map(|domain| &domain.variables)
                .ok_or(Error::NonExistent),
        }
    }

    fn variables_mut(
        &mut self,
        scope: &Scope,
    ) -> Result<&mut BTreeMap<Name, Box<dyn Variable>>, Error> {
        match scope {
            Scope::Vmd => Ok(&mut self.variables),
            Scope::Domain(domain) => self
                .domains
                .get_mut(domain)
                .map(|domain| &mut domain.variables)
                .ok_or(Error::NonExistent),
        }
    }

    fn lists_of(&self, scope: &Scope) -> Result<&BTreeMap<Name, List>, Error> {
        match scope {
            Scope::Vmd => Ok(&self.lists),
            Scope::Domain(domain) => self
                .domains
                .get(domain)
                .map(|domain| &domain.lists)
                .ok_or(Error::NonExistent),
        }
    }

    fn lists_mut(&mut self, scope: &Scope) -> Result<&mut BTreeMap<Name, List>, Error> {
        match scope {
            Scope::Vmd => Ok(&mut self.lists),
            Scope::Domain(domain) => self
                .domains
                .get_mut(domain)
                .map(|domain| &mut domain.lists)
                .ok_or(Error::NonExistent),
        }
    }
}

#[cfg(test)]
mod tests {
    use igs_iso9506_mms_codec::generated::types::{Identifier, Unsigned8};

    use super::*;

    fn name(text: &str) -> Name {
        Name::new(text).unwrap()
    }

    fn vmd() -> Vmd {
        Vmd::new(Identity {
            vendor: "igs".to_string(),
            model: "test".to_string(),
            revision: "1".to_string(),
        })
    }

    fn integer() -> TypeDescription {
        TypeDescription::Integer(Unsigned8(32))
    }

    fn variable(value: i128, writable: bool) -> Box<dyn Variable> {
        Box::new(MemoryVariable::new(integer(), Data::Integer(value), writable).unwrap())
    }

    #[test]
    fn a_name_is_unique_in_its_scope() {
        let mut model = vmd();
        model.add_domain(name("D")).unwrap();
        model
            .add_variable(&Target::vmd(name("x")), variable(1, true))
            .unwrap();
        assert_eq!(
            model.add_variable(&Target::vmd(name("x")), variable(2, true)),
            Err(Error::Exists)
        );
        // The same identifier in a domain is another object.
        model
            .add_variable(&Target::in_domain(name("D"), name("x")), variable(3, true))
            .unwrap();
        assert_eq!(model.add_domain(name("D")), Err(Error::Exists));
    }

    #[test]
    fn a_domain_must_exist_before_its_objects() {
        let mut model = vmd();
        assert_eq!(
            model.add_variable(&Target::in_domain(name("D"), name("x")), variable(1, true)),
            Err(Error::NonExistent)
        );
    }

    #[test]
    fn names_are_listed_in_order_and_paged() {
        let mut model = vmd();
        for item in ["c", "a", "b", "d"] {
            model
                .add_variable(&Target::vmd(name(item)), variable(0, true))
                .unwrap();
        }
        let first = model
            .page(Class::NamedVariable, &Scope::Vmd, None, 2)
            .unwrap();
        assert_eq!(first.names, vec![name("a"), name("b")]);
        assert!(first.more_follows);
        let second = model
            .page(Class::NamedVariable, &Scope::Vmd, Some(&name("b")), 2)
            .unwrap();
        assert_eq!(second.names, vec![name("c"), name("d")]);
        assert!(!second.more_follows);
    }

    #[test]
    fn the_domains_are_listed_at_the_vmd_scope_only() {
        let mut model = vmd();
        model.add_domain(name("simple")).unwrap();
        let page = model.page(Class::Domain, &Scope::Vmd, None, 10).unwrap();
        assert_eq!(page.names, vec![name("simple")]);
        assert_eq!(
            model.page(Class::Domain, &Scope::Domain(name("simple")), None, 10),
            Err(Error::Unsupported)
        );
        assert_eq!(
            model.page(
                Class::NamedVariable,
                &Scope::Domain(name("other")),
                None,
                10
            ),
            Err(Error::NonExistent)
        );
    }

    #[test]
    fn a_read_returns_the_value_and_a_write_replaces_it() {
        let mut model = vmd();
        let target = Target::vmd(name("x"));
        model.add_variable(&target, variable(7, true)).unwrap();
        assert_eq!(model.read(&target), Ok(Data::Integer(7)));
        model.write(&target, Data::Integer(-3)).unwrap();
        assert_eq!(model.read(&target), Ok(Data::Integer(-3)));
    }

    #[test]
    fn a_write_is_refused_for_a_read_only_variable_and_a_wrong_type() {
        let mut model = vmd();
        let fixed = Target::vmd(name("fixed"));
        let typed = Target::vmd(name("typed"));
        model.add_variable(&fixed, variable(1, false)).unwrap();
        model.add_variable(&typed, variable(1, true)).unwrap();
        assert_eq!(
            model.write(&fixed, Data::Integer(2)),
            Err(DataAccessError::OBJECT_ACCESS_DENIED)
        );
        assert_eq!(
            model.write(&typed, Data::Boolean(true)),
            Err(DataAccessError::TYPE_INCONSISTENT)
        );
        // Nothing changed.
        assert_eq!(model.read(&fixed), Ok(Data::Integer(1)));
    }

    #[test]
    fn an_unknown_variable_is_non_existent_for_every_service() {
        let mut model = vmd();
        let missing = Target::vmd(name("missing"));
        assert_eq!(
            model.read(&missing),
            Err(DataAccessError::OBJECT_NON_EXISTENT)
        );
        assert_eq!(
            model.write(&missing, Data::Integer(1)),
            Err(DataAccessError::OBJECT_NON_EXISTENT)
        );
        assert_eq!(model.type_description(&missing), Err(Error::NonExistent));
    }

    #[test]
    fn a_list_reads_each_member_and_reports_the_missing_ones() {
        let mut model = vmd();
        model.add_domain(name("D")).unwrap();
        let a = Target::in_domain(name("D"), name("a"));
        let b = Target::in_domain(name("D"), name("b"));
        model.add_variable(&a, variable(1, true)).unwrap();
        model.add_variable(&b, variable(2, true)).unwrap();
        let list = Target::in_domain(name("D"), name("list"));
        model
            .define_list(&list, vec![a.clone(), b.clone()])
            .unwrap();
        assert_eq!(
            model.read_list(&list),
            Ok(vec![
                AccessResult::Success(Data::Integer(1)),
                AccessResult::Success(Data::Integer(2)),
            ])
        );
        // A member removed by local action fails alone (ISO 9506-2 §14.1.4).
        model.remove_variable(&b).unwrap();
        assert_eq!(
            model.read_list(&list),
            Ok(vec![
                AccessResult::Success(Data::Integer(1)),
                AccessResult::Failure(DataAccessError::OBJECT_NON_EXISTENT),
            ])
        );
    }

    #[test]
    fn a_list_is_defined_once_with_existing_members() {
        let mut model = vmd();
        model
            .add_variable(&Target::vmd(name("a")), variable(1, true))
            .unwrap();
        let list = Target::vmd(name("list"));
        assert_eq!(
            model.define_list(&list, vec![Target::vmd(name("missing"))]),
            Err(Error::NonExistent)
        );
        model
            .define_list(&list, vec![Target::vmd(name("a"))])
            .unwrap();
        assert_eq!(
            model.define_list(&list, vec![Target::vmd(name("a"))]),
            Err(Error::Exists)
        );
        assert_eq!(model.list_members(&list), Ok(&[Target::vmd(name("a"))][..]));
        model.delete_list(&list).unwrap();
        assert_eq!(model.delete_list(&list), Err(Error::NonExistent));
    }

    #[test]
    fn a_list_may_be_empty() {
        // The grammar of DefineNamedVariableList allows zero members; the reference server refuses
        // one, which is recorded in docs/capabilities.md (G12).
        let mut model = vmd();
        let list = Target::vmd(name("empty"));
        model.define_list(&list, Vec::new()).unwrap();
        assert_eq!(model.read_list(&list), Ok(Vec::new()));
    }

    #[test]
    fn a_reference_to_aa_specific_names_is_unsupported() {
        use igs_iso9506_mms_codec::generated::types::ObjectName;
        let aa = ObjectName::AaSpecific(Identifier("x".to_string()));
        assert_eq!(Target::try_from(&aa), Err(NameError::AaSpecific));
        assert_eq!(Error::from(NameError::AaSpecific), Error::Unsupported);
    }

    #[test]
    fn the_errors_carry_their_mms_codes() {
        assert_eq!(
            Error::NonExistent.data_access_error(),
            DataAccessError::OBJECT_NON_EXISTENT
        );
        let error = Error::Exists.service_error();
        assert_eq!(
            error.error_class,
            ServiceErrorErrorClass::Definition(ServiceErrorErrorClassDefinition::OBJECT_EXISTS)
        );
    }
}
