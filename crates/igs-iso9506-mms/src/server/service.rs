// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The services of the server, run on the model of the VMD (ISO 9506-2 §7, §14): each confirmed request
//! in scope is answered here. Failures of the model become the MMS errors of their services.

use igs_iso9506_mms_codec::generated::types::{
    AccessResult, ConfirmedServiceRequest, ConfirmedServiceResponse, DataAccessError,
    DefineNamedVariableListResponse, DeleteNamedVariableListRequest,
    DeleteNamedVariableListRequestScopeOfDelete, DeleteNamedVariableListResponse, DirectoryEntry,
    EntryContentEntryForm, FileAttributes, FileCloseRequest, FileCloseResponse, FileDeleteRequest,
    FileDeleteResponse, FileDirectoryRequest, FileDirectoryResponse, FileName, FileOpenRequest,
    FileOpenResponse, FileReadRequest, FileReadResponse, GetNameListRequest,
    GetNameListRequestObjectScope, GetNameListResponse, GetNamedVariableListAttributesRequest,
    GetNamedVariableListAttributesResponse,
    GetNamedVariableListAttributesResponseListOfVariableItem, GetVariableAccessAttributesRequest,
    GetVariableAccessAttributesResponse, Identifier, IdentifyResponse, Integer32, JournalEntry,
    MMSString, ObjectClass, ObjectClassBasicObjectClass, ObjectName, ReadJournalRequest,
    ReadJournalRequestRangeStartSpecification, ReadJournalRequestRangeStopSpecification,
    ReadJournalResponse, ReadRequest, ReadResponse, ServiceError, ServiceErrorErrorClass,
    ServiceErrorErrorClassDefinition, ServiceErrorErrorClassFile, TimeOfDay, Unsigned32,
    VariableAccessSpecification, VariableSpecification, WriteRequest, WriteResponse,
    WriteResponseItemItem,
};

use crate::vmd::{Class, Error as ModelError, FileError, Name, Scope, Target, Vmd};

/// The most names of one GetNameList answer. A name takes at most 34 octets on the wire, so a page stays
/// small whatever the negotiated size of the transport.
pub(crate) const NAME_PAGE: usize = 64;

/// Answers a confirmed request on the model. The Err case is the MMS error of the service.
pub(crate) fn dispatch(
    vmd: &mut Vmd,
    service: ConfirmedServiceRequest,
) -> Result<ConfirmedServiceResponse, ServiceError> {
    match service {
        ConfirmedServiceRequest::Identify(_) => Ok(identify(vmd)),
        ConfirmedServiceRequest::GetNameList(request) => {
            get_name_list(vmd, &request).map(ConfirmedServiceResponse::GetNameList)
        }
        ConfirmedServiceRequest::Read(request) => {
            read(vmd, &request).map(ConfirmedServiceResponse::Read)
        }
        ConfirmedServiceRequest::Write(request) => {
            write(vmd, &request).map(ConfirmedServiceResponse::Write)
        }
        ConfirmedServiceRequest::GetVariableAccessAttributes(request) => {
            get_variable_access_attributes(vmd, &request)
                .map(ConfirmedServiceResponse::GetVariableAccessAttributes)
        }
        ConfirmedServiceRequest::DefineNamedVariableList(request) => {
            define_named_variable_list(vmd, &request).map(|()| {
                ConfirmedServiceResponse::DefineNamedVariableList(DefineNamedVariableListResponse(
                    (),
                ))
            })
        }
        ConfirmedServiceRequest::GetNamedVariableListAttributes(request) => {
            get_named_variable_list_attributes(vmd, &request)
                .map(ConfirmedServiceResponse::GetNamedVariableListAttributes)
        }
        ConfirmedServiceRequest::DeleteNamedVariableList(request) => {
            delete_named_variable_list(vmd, &request)
                .map(ConfirmedServiceResponse::DeleteNamedVariableList)
        }
        ConfirmedServiceRequest::ReadJournal(request) => {
            read_journal(vmd, &request).map(ConfirmedServiceResponse::ReadJournal)
        }
        ConfirmedServiceRequest::FileOpen(request) => {
            file_open(vmd, &request).map(ConfirmedServiceResponse::FileOpen)
        }
        ConfirmedServiceRequest::FileRead(request) => {
            file_read(vmd, &request).map(ConfirmedServiceResponse::FileRead)
        }
        ConfirmedServiceRequest::FileClose(request) => {
            file_close(vmd, &request).map(ConfirmedServiceResponse::FileClose)
        }
        ConfirmedServiceRequest::FileDelete(request) => {
            file_delete(vmd, &request).map(ConfirmedServiceResponse::FileDelete)
        }
        ConfirmedServiceRequest::FileDirectory(request) => {
            file_directory(vmd, &request).map(ConfirmedServiceResponse::FileDirectory)
        }
        // Not served: the negotiation refuses such a request before it reaches here.
        _ => Err(unsupported_service()),
    }
}

/// The MMS error of a service the server does not serve.
fn unsupported_service() -> ServiceError {
    ModelError::Unsupported.service_error()
}

/// A failure of the model, as the MMS error of the service.
fn service(error: ModelError) -> ServiceError {
    error.service_error()
}

/// A request whose parts do not agree with each other: the lists of its items differ in length.
fn inconsistent() -> ServiceError {
    ServiceError {
        error_class: ServiceErrorErrorClass::Definition(ServiceErrorErrorClassDefinition::OTHER),
        additional_code: None,
        additional_description: None,
        service_specific_info: None,
    }
}

fn identifier(name: &Name) -> Identifier {
    Identifier(name.as_str().to_string())
}

/// The name of an identifier, checked against the identifier limit `limit` of the VMD.
fn name(limit: usize, identifier: &Identifier) -> Result<Name, ModelError> {
    Name::with_limit(&identifier.0, limit).map_err(ModelError::from)
}

/// The target of an object name, checked against the identifier limit `limit` of the VMD.
fn target(limit: usize, object: &ObjectName) -> Result<Target, ModelError> {
    Target::from_object_name(object, limit).map_err(ModelError::from)
}

fn identify(vmd: &Vmd) -> ConfirmedServiceResponse {
    let identity = vmd.identity();
    ConfirmedServiceResponse::Identify(IdentifyResponse {
        vendor_name: MMSString(identity.vendor.clone()),
        model_name: MMSString(identity.model.clone()),
        revision: MMSString(identity.revision.clone()),
        list_of_abstract_syntaxes: None,
    })
}

fn class_of(class: &ObjectClass) -> Result<Class, ModelError> {
    let ObjectClass::BasicObjectClass(ObjectClassBasicObjectClass(number)) = class else {
        return Err(ModelError::Unsupported);
    };
    if *number == ObjectClassBasicObjectClass::NAMED_VARIABLE.0 {
        Ok(Class::NamedVariable)
    } else if *number == ObjectClassBasicObjectClass::NAMED_VARIABLE_LIST.0 {
        Ok(Class::NamedVariableList)
    } else if *number == ObjectClassBasicObjectClass::DOMAIN.0 {
        Ok(Class::Domain)
    } else {
        Err(ModelError::Unsupported)
    }
}

fn scope_of(limit: usize, scope: &GetNameListRequestObjectScope) -> Result<Scope, ModelError> {
    match scope {
        GetNameListRequestObjectScope::VmdSpecific => Ok(Scope::Vmd),
        GetNameListRequestObjectScope::DomainSpecific(domain) => {
            Ok(Scope::Domain(name(limit, domain)?))
        }
        GetNameListRequestObjectScope::AaSpecific => Err(ModelError::Unsupported),
    }
}

fn get_name_list(
    vmd: &Vmd,
    request: &GetNameListRequest,
) -> Result<GetNameListResponse, ServiceError> {
    let class = class_of(&request.object_class).map_err(service)?;
    let scope = scope_of(vmd.identifier_limit(), &request.object_scope).map_err(service)?;
    let after = request
        .continue_after
        .as_ref()
        .map(|identifier| name(vmd.identifier_limit(), identifier))
        .transpose()
        .map_err(service)?;
    let page = vmd
        .page(class, &scope, after.as_ref(), NAME_PAGE)
        .map_err(service)?;
    Ok(GetNameListResponse {
        list_of_identifier: page.names.iter().map(identifier).collect(),
        more_follows: Some(page.more_follows),
    })
}

fn read(vmd: &Vmd, request: &ReadRequest) -> Result<ReadResponse, ServiceError> {
    let results = match &request.variable_access_specification {
        VariableAccessSpecification::ListOfVariable(items) => items
            .iter()
            .map(
                |item| match (&item.variable_specification, &item.alternate_access) {
                    (VariableSpecification::Name(object), None) => {
                        match target(vmd.identifier_limit(), object) {
                            Ok(target) => match vmd.read(&target) {
                                Ok(data) => AccessResult::Success(data),
                                Err(error) => AccessResult::Failure(error),
                            },
                            Err(error) => AccessResult::Failure(error.data_access_error()),
                        }
                    }
                    // Addresses, descriptions and alternate access are not served (the CBBs are not
                    // negotiated for them).
                    _ => AccessResult::Failure(DataAccessError::OBJECT_ACCESS_UNSUPPORTED),
                },
            )
            .collect(),
        VariableAccessSpecification::VariableListName(object) => {
            let list = target(vmd.identifier_limit(), object).map_err(service)?;
            vmd.read_list(&list).map_err(service)?
        }
    };
    Ok(ReadResponse {
        variable_access_specification: None,
        list_of_access_result: results,
    })
}

fn write(vmd: &mut Vmd, request: &WriteRequest) -> Result<WriteResponse, ServiceError> {
    // Each target is resolved on its own: a bad reference fails its item only.
    let targets: Vec<Result<Target, DataAccessError>> = match &request.variable_access_specification
    {
        VariableAccessSpecification::ListOfVariable(items) => items
            .iter()
            .map(
                |item| match (&item.variable_specification, &item.alternate_access) {
                    (VariableSpecification::Name(object), None) => {
                        target(vmd.identifier_limit(), object)
                            .map_err(|error| error.data_access_error())
                    }
                    _ => Err(DataAccessError::OBJECT_ACCESS_UNSUPPORTED),
                },
            )
            .collect(),
        VariableAccessSpecification::VariableListName(object) => {
            let list = target(vmd.identifier_limit(), object).map_err(service)?;
            vmd.list_members(&list)
                .map_err(service)?
                .iter()
                .cloned()
                .map(Ok)
                .collect()
        }
    };
    if targets.len() != request.list_of_data.len() {
        return Err(inconsistent());
    }
    let results = targets
        .into_iter()
        .zip(request.list_of_data.iter().cloned())
        .map(|(target, data)| {
            let outcome = match target {
                Ok(target) => vmd.write(&target, data),
                Err(error) => Err(error),
            };
            match outcome {
                Ok(()) => WriteResponseItemItem::Success,
                Err(error) => WriteResponseItemItem::Failure(error),
            }
        })
        .collect();
    Ok(WriteResponse(results))
}

fn get_variable_access_attributes(
    vmd: &Vmd,
    request: &GetVariableAccessAttributesRequest,
) -> Result<GetVariableAccessAttributesResponse, ServiceError> {
    let GetVariableAccessAttributesRequest::Name(object) = request else {
        return Err(unsupported_service());
    };
    let target = target(vmd.identifier_limit(), object).map_err(service)?;
    let type_description = vmd.type_description(&target).map_err(service)?.clone();
    Ok(GetVariableAccessAttributesResponse {
        // Named variables of this model are static: they are not deletable by MMS services.
        mms_deletable: false,
        address: None,
        type_description,
        access_control_list: None,
        meaning: None,
    })
}

fn define_named_variable_list(
    vmd: &mut Vmd,
    request: &igs_iso9506_mms_codec::generated::types::DefineNamedVariableListRequest,
) -> Result<(), ServiceError> {
    let list = target(vmd.identifier_limit(), &request.variable_list_name).map_err(service)?;
    let members = request
        .list_of_variable
        .iter()
        .map(
            |item| match (&item.variable_specification, &item.alternate_access) {
                (VariableSpecification::Name(object), None) => {
                    target(vmd.identifier_limit(), object)
                }
                _ => Err(ModelError::Unsupported),
            },
        )
        .collect::<Result<Vec<Target>, ModelError>>()
        .map_err(service)?;
    vmd.define_list(&list, members).map_err(service)
}

fn get_named_variable_list_attributes(
    vmd: &Vmd,
    request: &GetNamedVariableListAttributesRequest,
) -> Result<GetNamedVariableListAttributesResponse, ServiceError> {
    let list = target(vmd.identifier_limit(), &request.0).map_err(service)?;
    let members = vmd.list_members(&list).map_err(service)?;
    Ok(GetNamedVariableListAttributesResponse {
        // A list is defined by the MMS client, so it may be deleted by MMS services.
        mms_deletable: true,
        list_of_variable: members
            .iter()
            .map(
                |member| GetNamedVariableListAttributesResponseListOfVariableItem {
                    variable_specification: VariableSpecification::Name(ObjectName::from(member)),
                    alternate_access: None,
                },
            )
            .collect(),
        access_control_list: None,
    })
}

/// DeleteNamedVariableList (ISO 9506-2 §14.13): the lists of the scope, or the named lists. The matched
/// lists are the existing ones; each of them is deleted.
fn delete_named_variable_list(
    vmd: &mut Vmd,
    request: &DeleteNamedVariableListRequest,
) -> Result<DeleteNamedVariableListResponse, ServiceError> {
    let scope = request.scope_of_delete.as_ref().map_or(
        DeleteNamedVariableListRequestScopeOfDelete::SPECIFIC.0,
        |scope| scope.0,
    );
    let targets: Vec<Target> = if scope == DeleteNamedVariableListRequestScopeOfDelete::SPECIFIC.0 {
        request
            .list_of_variable_list_name
            .iter()
            .flatten()
            .map(|object| target(vmd.identifier_limit(), object))
            .collect::<Result<Vec<Target>, ModelError>>()
            .map_err(service)?
    } else if scope == DeleteNamedVariableListRequestScopeOfDelete::DOMAIN.0 {
        let domain = request
            .domain_name
            .as_ref()
            .ok_or_else(inconsistent)
            .and_then(|domain| name(vmd.identifier_limit(), domain).map_err(service))?;
        let domain_scope = Scope::Domain(domain.clone());
        vmd.page(Class::NamedVariableList, &domain_scope, None, usize::MAX)
            .map_err(service)?
            .names
            .into_iter()
            .map(|item| Target::in_domain(domain.clone(), item))
            .collect()
    } else if scope == DeleteNamedVariableListRequestScopeOfDelete::VMD.0 {
        vmd.page(Class::NamedVariableList, &Scope::Vmd, None, usize::MAX)
            .map_err(service)?
            .names
            .into_iter()
            .map(Target::vmd)
            .collect()
    } else {
        // Application association-specific lists are not held.
        return Err(unsupported_service());
    };
    let mut matched = 0i64;
    for list in &targets {
        match vmd.delete_list(list) {
            Ok(()) => matched = matched.saturating_add(1),
            Err(ModelError::NonExistent) => {}
            Err(other) => return Err(service(other)),
        }
    }
    Ok(DeleteNamedVariableListResponse {
        number_matched: Unsigned32(matched),
        number_deleted: Unsigned32(matched),
    })
}

/// The time of day as a number that orders the times of different days: the day since 1 January 1984 and the milliseconds of the
/// day. `None` for a time that is not a time of day.
fn time_key(time: &TimeOfDay) -> Option<u64> {
    let day = time.day().ok()?.unwrap_or(0);
    let milliseconds = time.milliseconds().ok()?;
    Some(
        u64::from(day)
            .saturating_mul(86_400_000)
            .saturating_add(u64::from(milliseconds)),
    )
}

/// The time of an entry, as its key (see [`time_key`]).
fn entry_time(entry: &JournalEntry) -> Option<u64> {
    time_key(&entry.entry_content.occurrence_time)
}

/// The tags of the variables of an entry, when it has data.
fn variable_tags(entry: &JournalEntry) -> Vec<&str> {
    match &entry.entry_content.entry_form {
        EntryContentEntryForm::Data(data) => data
            .list_of_variables
            .iter()
            .flatten()
            .map(|variable| variable.variable_tag.0.as_str())
            .collect(),
        EntryContentEntryForm::Annotation(_) => Vec::new(),
    }
}

/// ReadJournal (ISO 9506-2 clause 23.2; ISO 9506-1 clause 23.2): the entries of a domain's journal that the filters select, in
/// the order they were entered, or the reverse when the number of entries is negative. The range start is a time (from it,
/// included) or the identifier of an entry (from it, included); the range stop is a time (up to it, included); the list of
/// variables keeps the entries that hold one of its tags; the entry to start after is skipped, or, when it is not held, the
/// entries from its time are kept. `more follows` tells that entries were left out by the number of entries.
fn read_journal(
    vmd: &Vmd,
    request: &ReadJournalRequest,
) -> Result<ReadJournalResponse, ServiceError> {
    let journal_name = target(vmd.identifier_limit(), &request.journal_name).map_err(service)?;
    if journal_name.domain.is_none() {
        // Journals are held in domains; the VMD and the application association scopes hold none.
        return Err(unsupported_service());
    }
    let journal = vmd.journal(&journal_name).map_err(service)?;
    let mut selected: Vec<&JournalEntry> = journal.entries().collect();
    match &request.range_start_specification {
        None => {}
        Some(ReadJournalRequestRangeStartSpecification::StartingTime(from)) => {
            let from = time_key(from).ok_or_else(inconsistent)?;
            selected.retain(|entry| entry_time(entry).is_some_and(|time| time >= from));
        }
        Some(ReadJournalRequestRangeStartSpecification::StartingEntry(identifier)) => {
            // An identifier that is not held selects nothing.
            let start = selected
                .iter()
                .position(|entry| entry.entry_identifier == *identifier)
                .unwrap_or(selected.len());
            selected = selected.split_off(start);
        }
    }
    if let Some(ReadJournalRequestRangeStopSpecification::EndingTime(to)) =
        &request.range_stop_specification
    {
        let to = time_key(to).ok_or_else(inconsistent)?;
        selected.retain(|entry| entry_time(entry).is_some_and(|time| time <= to));
    }
    if let Some(tags) = &request.list_of_variables {
        selected.retain(|entry| {
            variable_tags(entry)
                .iter()
                .any(|tag| tags.iter().any(|wanted| wanted == tag))
        });
    }
    if let Some(after) = &request.entry_to_start_after {
        match selected
            .iter()
            .position(|entry| entry.entry_identifier == after.entry_specification)
        {
            Some(index) => selected = selected.split_off(index.saturating_add(1)),
            None => {
                let from = time_key(&after.time_specification).ok_or_else(inconsistent)?;
                selected.retain(|entry| entry_time(entry).is_some_and(|time| time >= from));
            }
        }
    }
    let (chosen, more): (Vec<&JournalEntry>, bool) = match &request.range_stop_specification {
        Some(ReadJournalRequestRangeStopSpecification::NumberOfEntries(count)) => {
            let wanted = usize::try_from(count.0.unsigned_abs()).unwrap_or(usize::MAX);
            let more = selected.len() > wanted;
            let chosen = if count.0 >= 0 {
                selected.into_iter().take(wanted).collect()
            } else {
                selected.into_iter().rev().take(wanted).collect()
            };
            (chosen, more)
        }
        _ => (selected, false),
    };
    Ok(ReadJournalResponse {
        list_of_journal_entry: chosen.into_iter().cloned().collect(),
        more_follows: Some(more),
    })
}

/// The most octets that one FileRead answer carries (the size of an answer that the associations hold).
const FILE_READ_OCTETS: usize = 2048;

/// The MMS error of a file operation: the error class `file` (ISO 9506-2 clause 18; IEC 61850-8-1 table 116).
fn file_error(error: FileError) -> ServiceError {
    let code = match error {
        FileError::NonExistent => ServiceErrorErrorClassFile::FILE_NON_EXISTENT,
        FileError::PositionInvalid => ServiceErrorErrorClassFile::POSITION_INVALID,
        FileError::Busy => ServiceErrorErrorClassFile::FILE_BUSY,
    };
    ServiceError {
        error_class: ServiceErrorErrorClass::File(code),
        additional_code: None,
        additional_description: None,
        service_specific_info: None,
    }
}

/// The attributes of a stored file: its size, and its last modification.
fn file_attributes(size: usize, last_modified: Option<&String>) -> FileAttributes {
    FileAttributes {
        size_of_file: Unsigned32(i64::try_from(size).unwrap_or(i64::MAX)),
        last_modified: last_modified.cloned(),
    }
}

/// FileOpen (ISO 9506-2 clause 18): starts a read of the file at its initial position, and gives the FRSM identifier and the file
/// attributes.
fn file_open(vmd: &mut Vmd, request: &FileOpenRequest) -> Result<FileOpenResponse, ServiceError> {
    let name = &request.file_name.0;
    let (size, last_modified) = {
        let file = vmd
            .files()
            .file(name)
            .ok_or_else(|| file_error(FileError::NonExistent))?;
        (file.content.len(), file.last_modified.clone())
    };
    let position = u64::try_from(request.initial_position.0)
        .map_err(|_| file_error(FileError::PositionInvalid))?;
    let frsm = vmd.files_mut().open(name, position).map_err(file_error)?;
    Ok(FileOpenResponse {
        frsm_id: Integer32(frsm),
        file_attributes: file_attributes(size, last_modified.as_ref()),
    })
}

/// FileRead: the next part of the file that an FRSM reads, and whether more follows.
fn file_read(vmd: &mut Vmd, request: &FileReadRequest) -> Result<FileReadResponse, ServiceError> {
    let (data, more) = vmd
        .files_mut()
        .read(request.0 .0, FILE_READ_OCTETS)
        .map_err(file_error)?;
    Ok(FileReadResponse {
        file_data: data,
        more_follows: Some(more),
    })
}

/// FileClose: ends the read of an FRSM.
fn file_close(
    vmd: &mut Vmd,
    request: &FileCloseRequest,
) -> Result<FileCloseResponse, ServiceError> {
    vmd.files_mut().close(request.0 .0).map_err(file_error)?;
    Ok(FileCloseResponse(()))
}

/// FileDelete: removes a file that no FRSM reads.
fn file_delete(
    vmd: &mut Vmd,
    request: &FileDeleteRequest,
) -> Result<FileDeleteResponse, ServiceError> {
    vmd.files_mut().delete(&request.0 .0).map_err(file_error)?;
    Ok(FileDeleteResponse(()))
}

/// FileDirectory (ISO 9506-2 clause 18): the files whose path starts with the file specification, after the entry named by
/// `continueAfter`. The answer holds them all (`moreFollows` is false).
fn file_directory(
    vmd: &mut Vmd,
    request: &FileDirectoryRequest,
) -> Result<FileDirectoryResponse, ServiceError> {
    let specification: &[String] = request
        .file_specification
        .as_ref()
        .map_or(&[], |name| name.0.as_slice());
    let after: Option<&[String]> = request
        .continue_after
        .as_ref()
        .map(|name| name.0.as_slice());
    let entries = vmd
        .files()
        .list(specification, after)
        .into_iter()
        .map(|(name, file)| DirectoryEntry {
            file_name: FileName(name.clone()),
            file_attributes: file_attributes(file.content.len(), file.last_modified.as_ref()),
        })
        .collect();
    Ok(FileDirectoryResponse {
        list_of_directory_entry: entries,
        more_follows: Some(false),
    })
}

#[cfg(test)]
mod tests {
    use igs_iso9506_mms_codec::generated::types::{
        ConfirmedServiceRequest, ConfirmedServiceResponse, Data,
        GetVariableAccessAttributesRequest, Identifier, ObjectName, ObjectNameDomainSpecific,
        TypeDescription,
    };

    use super::dispatch;
    use crate::vmd::{Identity, MemoryVariable, Name, Target, Vmd};

    fn identity() -> Identity {
        Identity {
            vendor: "igs".to_string(),
            model: "service".to_string(),
            revision: "1".to_string(),
        }
    }

    /// A VMD with the domain `D`, and with a variable of the identifier `item` when the limit admits it.
    fn vmd(limit: usize, item: &str) -> Vmd {
        let mut vmd = Vmd::new(identity())
            .with_identifier_limit(limit)
            .expect("a limit of the profile");
        vmd.add_domain(Name::new("D").expect("a name"))
            .expect("a new domain");
        if let Ok(name) = vmd.name(item) {
            let target = Target::in_domain(Name::new("D").expect("a name"), name);
            let variable =
                MemoryVariable::new(TypeDescription::Boolean, Data::Boolean(false), false)
                    .expect("a value of its type");
            vmd.add_variable(&target, Box::new(variable))
                .expect("a new variable");
        }
        vmd
    }

    fn describe(item: &str) -> ConfirmedServiceRequest {
        ConfirmedServiceRequest::GetVariableAccessAttributes(
            GetVariableAccessAttributesRequest::Name(ObjectName::DomainSpecific(
                ObjectNameDomainSpecific {
                    domain_id: Identifier("D".to_string()),
                    item_id: Identifier(item.to_string()),
                },
            )),
        )
    }

    #[test]
    fn a_vmd_with_the_iec_limit_serves_a_name_of_40_characters() {
        let item = "a".repeat(40);
        let mut vmd = vmd(64, &item);
        let answer = dispatch(&mut vmd, describe(&item));
        assert!(
            matches!(
                answer,
                Ok(ConfirmedServiceResponse::GetVariableAccessAttributes(_))
            ),
            "found {answer:?}"
        );
    }

    #[test]
    fn the_iso_limit_refuses_the_same_name() {
        let item = "a".repeat(40);
        let mut vmd = vmd(32, &item);
        assert!(dispatch(&mut vmd, describe(&item)).is_err());
    }
}
