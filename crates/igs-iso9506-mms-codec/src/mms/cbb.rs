// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The check of a decoded PDU against the conformance building blocks of the association.
//!
//! Decoding reads every branch of the IF directives of ISO 9506-2; this check refuses what the
//! negotiation does not allow: a service or modifier the serving user does not support (ISO
//! 9506-1 §8.2.1.1.8, §8.2.1.2.8), a parameter whose CBB was not negotiated (§8.1.3.15, read with
//! the directives of ISO 9506-2), and data nested deeper than negotiated (§8.1.3.16).

use std::fmt;

use crate::ber::Reader;
use crate::generated::tables::{
    ENVIRONMENT_BITS, MODIFIERS, PARAMETER_SUPPORT_OPTIONS, SERVICES, SERVICE_SUPPORT_OPTIONS,
};
use crate::generated::types::{
    AccessResult, AlternateAccess, AlternateAccessItemItem, AlternateAccessSelection,
    AlternateAccessSelectionSelectAccess,
    AlternateAccessSelectionSelectAlternateAccessAccessSelection, ConfirmedServiceRequest,
    ConfirmedServiceResponse, Data, InitiateRequestPDU, InitiateResponsePDU, MMSpdu, ObjectClass,
    ObjectClassBasicObjectClass, TypeDescription, TypeSpecification, UnconfirmedService,
    VariableAccessSpecification, VariableSpecification,
};
use crate::schema::{BitString, Family, RawBer, SupportOption};

/// What the Initiate exchange allows, for the PDUs whose service one user serves.
///
/// A confirmed service is served by the user that receives its requests, and an unconfirmed
/// service by the user that receives it. One value covers the requests and unconfirmed PDUs sent
/// to that user, and the responses and errors it sends; an association needs one per user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    /// The negotiated parameter CBBs.
    pub parameters: BitString,
    /// The services supported by the serving user.
    pub services: BitString,
    /// The negotiated nesting level; `None` is unlimited.
    pub nesting_level: Option<i64>,
}

impl Negotiated {
    /// For the services that the called user serves.
    pub fn served_by_called(response: &InitiateResponsePDU) -> Self {
        let detail = &response.init_response_detail;
        Self {
            parameters: detail.negotiated_parameter_cbb.0.clone(),
            services: detail.services_supported_called.0.clone(),
            nesting_level: response
                .negotiated_data_structure_nesting_level
                .as_ref()
                .map(|n| n.0),
        }
    }

    /// For the services that the calling user serves.
    pub fn served_by_calling(request: &InitiateRequestPDU, response: &InitiateResponsePDU) -> Self {
        Self {
            services: request
                .init_request_detail
                .services_supported_calling
                .0
                .clone(),
            ..Self::served_by_called(response)
        }
    }

    fn parameter(&self, name: &str) -> bool {
        PARAMETER_SUPPORT_OPTIONS
            .iter()
            .find(|b| b.name == name)
            .and_then(|b| usize::try_from(b.position).ok())
            .is_some_and(|position| self.parameters.bit(position))
    }

    fn service_bit(&self, option: SupportOption, position: u32) -> bool {
        option == SupportOption::Service
            && usize::try_from(position).is_ok_and(|p| self.services.bit(p))
    }

    /// A parameter CBB, or a service named in a requirement of the tables.
    fn has(&self, name: &str) -> bool {
        self.parameter(name)
            || SERVICE_SUPPORT_OPTIONS
                .iter()
                .find(|b| b.name == name)
                .is_some_and(|b| self.service_bit(SupportOption::Service, b.position))
    }

    fn need(&self, cbb: &'static str) -> Result<(), CbbError> {
        if self.parameter(cbb) {
            Ok(())
        } else {
            Err(CbbError::NotNegotiated { cbb })
        }
    }

    fn need_any(&self, cbbs: &[&'static str]) -> Result<(), CbbError> {
        match cbbs.iter().find(|c| self.parameter(c)) {
            Some(_) => Ok(()),
            None => Err(CbbError::NotNegotiated {
                cbb: cbbs.first().copied().unwrap_or(""),
            }),
        }
    }
}

/// Why a PDU breaks the negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CbbError {
    /// A service or modifier that the serving user does not support.
    NotSupported {
        /// Name of the service or modifier.
        name: &'static str,
    },
    /// A service tag that no service of its family has.
    UnknownService {
        /// Tag number.
        tag: u32,
    },
    /// A parameter whose CBB was not negotiated; with several possible CBBs, the first.
    NotNegotiated {
        /// The CBB.
        cbb: &'static str,
    },
    /// Data or a type nested deeper than negotiated.
    Nesting {
        /// Non-leaf nodes on the deepest path.
        depth: usize,
        /// The negotiated level.
        limit: i64,
    },
    /// An identifier longer than the profile allows (D-031).
    IdentifierLength {
        /// Characters of the identifier.
        length: usize,
        /// Largest number the profile allows.
        limit: usize,
    },
    /// A `Data` MMS string that the profile does not allow (D-031).
    DataString {
        /// What is wrong.
        reason: &'static str,
    },
}

impl fmt::Display for CbbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSupported { name } => write!(f, "{name} is not supported by the peer"),
            Self::UnknownService { tag } => write!(f, "no service has tag {tag}"),
            Self::NotNegotiated { cbb } => write!(f, "the {cbb} CBB was not negotiated"),
            Self::Nesting { depth, limit } => {
                write!(f, "nesting of {depth} levels, above the negotiated {limit}")
            }
            Self::IdentifierLength { length, limit } => {
                write!(
                    f,
                    "identifier of {length} characters, above the {limit} of the profile"
                )
            }
            Self::DataString { reason } => write!(f, "MMS string of Data {reason}"),
        }
    }
}

impl std::error::Error for CbbError {}

/// Checks a PDU against the negotiation of its serving user (see [`Negotiated`]). Initiate and
/// Reject PDUs are not checked: the first make the negotiation, the second may answer anything.
pub fn validate_cbb(pdu: &MMSpdu, n: &Negotiated) -> Result<(), CbbError> {
    match pdu {
        MMSpdu::ConfirmedRequestPDU(request) => {
            for modifier in request.list_of_modifiers.iter().flatten() {
                check_modifier(n, modifier)?;
            }
            check_service(n, Family::Confirmed, request.service.tag())?;
            check_extension(n, request.service_ext.is_some(), &["csr", "cspi"])?;
            check_request(n, &request.service)
        }
        MMSpdu::ConfirmedResponsePDU(response) => {
            check_service(n, Family::Confirmed, response.service.tag())?;
            check_extension(n, response.service_ext.is_some(), &["csr", "cspi"])?;
            check_response(n, &response.service)
        }
        MMSpdu::ConfirmedErrorPDU(_) => Ok(()),
        MMSpdu::UnconfirmedPDU(unconfirmed) => {
            check_service(n, Family::Unconfirmed, unconfirmed.service.tag())?;
            check_extension(n, unconfirmed.service_ext.is_some(), &["cspi"])?;
            match &unconfirmed.service {
                UnconfirmedService::InformationReport(report) => {
                    access(n, &report.variable_access_specification)?;
                    report
                        .list_of_access_result
                        .iter()
                        .try_for_each(|r| result(n, r))
                }
                UnconfirmedService::Unsupported { .. } => Ok(()),
            }
        }
        MMSpdu::CancelRequestPDU(_) | MMSpdu::CancelResponsePDU(_) | MMSpdu::CancelErrorPDU(_) => {
            check_environment(n, "cancel")
        }
        MMSpdu::ConcludeRequestPDU(_)
        | MMSpdu::ConcludeResponsePDU(_)
        | MMSpdu::ConcludeErrorPDU(_) => check_environment(n, "conclude"),
        MMSpdu::RejectPDU(_)
        | MMSpdu::InitiateRequestPDU(_)
        | MMSpdu::InitiateResponsePDU(_)
        | MMSpdu::InitiateErrorPDU(_) => Ok(()),
    }
}

fn check_service(n: &Negotiated, family: Family, tag: u32) -> Result<(), CbbError> {
    let service = SERVICES
        .iter()
        .find(|s| s.family == family && s.tag == tag)
        .ok_or(CbbError::UnknownService { tag })?;
    if !n.service_bit(service.bit.option, service.bit.position) {
        return Err(CbbError::NotSupported { name: service.name });
    }
    // Each group needs one of its CBBs (the IF directives around the service).
    for group in service.requires {
        if !group.iter().any(|name| n.has(name)) {
            return Err(CbbError::NotNegotiated {
                cbb: group.first().copied().unwrap_or(""),
            });
        }
    }
    Ok(())
}

fn check_environment(n: &Negotiated, name: &'static str) -> Result<(), CbbError> {
    let supported = ENVIRONMENT_BITS
        .iter()
        .find(|(service, _)| *service == name)
        .is_some_and(|(_, bit)| n.service_bit(bit.option, bit.position));
    if supported {
        Ok(())
    } else {
        Err(CbbError::NotSupported { name })
    }
}

fn check_modifier(n: &Negotiated, modifier: &RawBer) -> Result<(), CbbError> {
    let tag = Reader::new(&modifier.0)
        .peek_identifier()
        .ok()
        .flatten()
        .map_or(u32::MAX, |id| id.number);
    let modifier = MODIFIERS
        .iter()
        .find(|m| m.tag == tag)
        .ok_or(CbbError::UnknownService { tag })?;
    if n.service_bit(modifier.bit.option, modifier.bit.position) {
        Ok(())
    } else {
        Err(CbbError::NotSupported { name: modifier.cbb })
    }
}

fn check_extension(n: &Negotiated, present: bool, cbbs: &[&'static str]) -> Result<(), CbbError> {
    if present {
        n.need_any(cbbs)
    } else {
        Ok(())
    }
}

fn check_request(n: &Negotiated, service: &ConfirmedServiceRequest) -> Result<(), CbbError> {
    match service {
        ConfirmedServiceRequest::GetNameList(request) => object_class(n, &request.object_class),
        ConfirmedServiceRequest::Read(request) => access(n, &request.variable_access_specification),
        ConfirmedServiceRequest::Write(request) => {
            access(n, &request.variable_access_specification)?;
            request.list_of_data.iter().try_for_each(|d| data(n, d))
        }
        ConfirmedServiceRequest::GetVariableAccessAttributes(request) => match request {
            crate::generated::types::GetVariableAccessAttributesRequest::Name(_) => n.need("vnam"),
            crate::generated::types::GetVariableAccessAttributesRequest::Address(_) => {
                n.need("vadr")
            }
        },
        ConfirmedServiceRequest::DefineNamedVariableList(request) => {
            request.list_of_variable.iter().try_for_each(|item| {
                variable(n, &item.variable_specification)?;
                alternate(n, item.alternate_access.as_ref())
            })
        }
        ConfirmedServiceRequest::Identify(_)
        | ConfirmedServiceRequest::GetNamedVariableListAttributes(_)
        | ConfirmedServiceRequest::DeleteNamedVariableList(_)
        | ConfirmedServiceRequest::Unsupported { .. } => Ok(()),
    }
}

fn check_response(n: &Negotiated, service: &ConfirmedServiceResponse) -> Result<(), CbbError> {
    match service {
        ConfirmedServiceResponse::Read(response) => {
            if let Some(spec) = &response.variable_access_specification {
                access(n, spec)?;
            }
            response
                .list_of_access_result
                .iter()
                .try_for_each(|r| result(n, r))
        }
        ConfirmedServiceResponse::GetVariableAccessAttributes(response) => {
            if response.address.is_some() {
                n.need("vadr")?;
            }
            if response.access_control_list.is_some() {
                n.need("aco")?;
            }
            if response.meaning.is_some() {
                n.need("sem")?;
            }
            type_description(n, &response.type_description)?;
            nesting(n, type_depth_of(&response.type_description))
        }
        ConfirmedServiceResponse::GetNamedVariableListAttributes(response) => {
            if response.access_control_list.is_some() {
                n.need("aco")?;
            }
            response.list_of_variable.iter().try_for_each(|item| {
                variable(n, &item.variable_specification)?;
                alternate(n, item.alternate_access.as_ref())
            })
        }
        ConfirmedServiceResponse::GetNameList(_)
        | ConfirmedServiceResponse::Identify(_)
        | ConfirmedServiceResponse::Write(_)
        | ConfirmedServiceResponse::DefineNamedVariableList(_)
        | ConfirmedServiceResponse::DeleteNamedVariableList(_)
        | ConfirmedServiceResponse::Unsupported { .. } => Ok(()),
    }
}

/// The values of the basic object classes under IF directives of ISO 9506-2 §7.5.4.
fn object_class(n: &Negotiated, class: &ObjectClass) -> Result<(), CbbError> {
    match class {
        ObjectClass::BasicObjectClass(value) => match *value {
            ObjectClassBasicObjectClass::NAMED_VARIABLE
            | ObjectClassBasicObjectClass::NAMED_TYPE => n.need("vnam"),
            ObjectClassBasicObjectClass::SCATTERED_ACCESS => n.need("vsca"),
            ObjectClassBasicObjectClass::NAMED_VARIABLE_LIST => n.need("vlis"),
            _ => Ok(()),
        },
        ObjectClass::CsObjectClass(_) => n.need("cspi"),
    }
}

fn access(n: &Negotiated, spec: &VariableAccessSpecification) -> Result<(), CbbError> {
    match spec {
        VariableAccessSpecification::ListOfVariable(items) => items.iter().try_for_each(|item| {
            variable(n, &item.variable_specification)?;
            alternate(n, item.alternate_access.as_ref())
        }),
        VariableAccessSpecification::VariableListName(_) => n.need("vlis"),
    }
}

fn variable(n: &Negotiated, spec: &VariableSpecification) -> Result<(), CbbError> {
    match spec {
        VariableSpecification::Name(_) => n.need("vnam"),
        VariableSpecification::Address(_) => n.need("vadr"),
        VariableSpecification::VariableDescription(description) => {
            n.need("vadr")?;
            type_specification(n, &description.type_specification)?;
            nesting(n, type_depth(&description.type_specification))
        }
        VariableSpecification::ScatteredAccessDescription(_) => n.need("vsca"),
        VariableSpecification::Invalidated => Ok(()),
    }
}

/// Alternate access and its component names need `valt` (§8.1.3.15.4); its selections need
/// `str2` for components and `str1` for indexes (§8.1.3.15.1, §8.1.3.15.2).
fn alternate(n: &Negotiated, access: Option<&AlternateAccess>) -> Result<(), CbbError> {
    let Some(access) = access else {
        return Ok(());
    };
    n.need("valt")?;
    access.0.iter().try_for_each(|item| match item {
        AlternateAccessItemItem::Unnamed(selection) => selection_of(n, selection),
        AlternateAccessItemItem::Named(named) => {
            n.need("str2")?;
            selection_of(n, &named.access)
        }
    })
}

fn selection_of(n: &Negotiated, selection: &AlternateAccessSelection) -> Result<(), CbbError> {
    match selection {
        AlternateAccessSelection::SelectAlternateAccess(select) => {
            use AlternateAccessSelectionSelectAlternateAccessAccessSelection as S;
            match &select.access_selection {
                S::Component(_) => n.need("str2")?,
                S::Index(_) | S::IndexRange(_) => n.need("str1")?,
                S::AllElements => {}
            }
            alternate(n, Some(&select.alternate_access))
        }
        AlternateAccessSelection::SelectAccess(select) => match select {
            AlternateAccessSelectionSelectAccess::Component(_) => n.need("str2"),
            AlternateAccessSelectionSelectAccess::Index(_)
            | AlternateAccessSelectionSelectAccess::IndexRange(_) => n.need("str1"),
            AlternateAccessSelectionSelectAccess::AllElements => Ok(()),
        },
    }
}

fn result(n: &Negotiated, result: &AccessResult) -> Result<(), CbbError> {
    match result {
        AccessResult::Success(value) => data(n, value),
        AccessResult::Failure(_) => Ok(()),
    }
}

/// Arrays need `str1`, structures `str2`, and the depth stays within the negotiated level.
fn data(n: &Negotiated, value: &Data) -> Result<(), CbbError> {
    data_kinds(n, value)?;
    nesting(n, data_depth(value))
}

fn data_kinds(n: &Negotiated, value: &Data) -> Result<(), CbbError> {
    match value {
        Data::Array(items) => {
            n.need("str1")?;
            items.iter().try_for_each(|d| data_kinds(n, d))
        }
        Data::Structure(items) => {
            n.need("str2")?;
            items.iter().try_for_each(|d| data_kinds(n, d))
        }
        _ => Ok(()),
    }
}

/// Non-leaf nodes on the deepest path (ISO 9506-1 §8.1.3.16).
fn data_depth(value: &Data) -> usize {
    match value {
        Data::Array(items) | Data::Structure(items) => items
            .iter()
            .map(data_depth)
            .max()
            .unwrap_or(0)
            .saturating_add(1),
        _ => 0,
    }
}

fn nesting(n: &Negotiated, depth: usize) -> Result<(), CbbError> {
    match n.nesting_level {
        Some(limit) if i64::try_from(depth).map_or(true, |d| d > limit) => {
            Err(CbbError::Nesting { depth, limit })
        }
        _ => Ok(()),
    }
}

fn type_specification(n: &Negotiated, spec: &TypeSpecification) -> Result<(), CbbError> {
    match spec {
        TypeSpecification::TypeName(_) => Ok(()),
        TypeSpecification::TypeDescription(description) => type_description(n, description),
    }
}

/// Arrays need `str1`, structures `str2`, packed ones `vadr`, component names `valt`.
fn type_description(n: &Negotiated, description: &TypeDescription) -> Result<(), CbbError> {
    match description {
        TypeDescription::Array(array) => {
            n.need("str1")?;
            if array.packed == Some(true) {
                n.need("vadr")?;
            }
            type_specification(n, &array.element_type)
        }
        TypeDescription::Structure(structure) => {
            n.need("str2")?;
            if structure.packed == Some(true) {
                n.need("vadr")?;
            }
            structure.components.iter().try_for_each(|component| {
                if component.component_name.is_some() {
                    n.need("valt")?;
                }
                type_specification(n, &component.component_type)
            })
        }
        _ => Ok(()),
    }
}

fn type_depth(spec: &TypeSpecification) -> usize {
    match spec {
        TypeSpecification::TypeName(_) => 0,
        TypeSpecification::TypeDescription(description) => type_depth_of(description),
    }
}

fn type_depth_of(description: &TypeDescription) -> usize {
    match description {
        TypeDescription::Array(array) => type_depth(&array.element_type).saturating_add(1),
        TypeDescription::Structure(structure) => structure
            .components
            .iter()
            .map(|c| type_depth(&c.component_type))
            .max()
            .unwrap_or(0)
            .saturating_add(1),
        _ => 0,
    }
}
