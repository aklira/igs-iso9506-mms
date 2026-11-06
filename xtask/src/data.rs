// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The data files of tasks P3 and P4, and the checks that their counts agree.

use serde::Deserialize;
use std::collections::BTreeMap;

use crate::asn::Fail;

#[derive(Deserialize)]
pub struct Bit {
    pub option: String,
    pub position: u32,
}

#[derive(Deserialize)]
pub struct Pdu {
    pub name: String,
    pub tag: u32,
}

#[derive(Deserialize)]
pub struct Service {
    pub name: String,
    pub family: String,
    pub tag: u32,
    pub cbb: String,
    pub bit: Bit,
    #[serde(default)]
    pub requires: Vec<Vec<String>>,
}

#[derive(Deserialize)]
pub struct Environment {
    pub name: String,
    pub bit: Bit,
}

#[derive(Deserialize)]
pub struct Modifier {
    pub name: String,
    pub tag: u32,
    pub cbb: String,
    pub bit: Bit,
}

#[derive(Deserialize)]
pub struct Parameter {
    pub name: String,
    pub option: String,
    pub position: u32,
}

#[derive(Deserialize)]
pub struct NamedBit {
    pub name: String,
    pub position: u32,
}

#[derive(Deserialize)]
pub struct Code {
    pub name: String,
    pub code: u32,
}

#[derive(Deserialize)]
pub struct CodeTable {
    pub name: String,
    pub tag: u32,
    pub codes: Vec<Code>,
}

#[derive(Deserialize)]
pub struct Profile {
    pub pdus: Vec<Pdu>,
    pub services: Vec<Service>,
    pub environment_services: Vec<Environment>,
    pub modifiers: Vec<Modifier>,
    pub parameters: Vec<Parameter>,
    pub bits: BTreeMap<String, Vec<NamedBit>>,
    pub error_classes: Vec<CodeTable>,
    pub reject_reasons: Vec<CodeTable>,
}

#[derive(Deserialize, Default)]
pub struct Status {
    #[serde(default)]
    pub fs: String,
    #[serde(default)]
    pub sending_fs: String,
    #[serde(default)]
    pub receiving_fs: String,
}

#[derive(Deserialize)]
pub struct ProfileService {
    pub name: String,
    pub scope: String,
    #[serde(default)]
    pub tag: Option<u32>,
    #[serde(default)]
    pub family: Option<String>,
    #[serde(default)]
    pub client: Status,
    #[serde(default)]
    pub server: Status,
}

#[derive(Deserialize)]
pub struct Conformance {
    pub mms_services: Vec<ProfileService>,
    pub mms_pdus: Vec<ProfileService>,
}

pub fn validate(profile: &Profile, conformance: &Conformance) -> Result<(), Fail> {
    for service in &profile.services {
        let bits = profile
            .bits
            .get(&service.bit.option)
            .ok_or("unknown support option")?;
        let found = bits
            .iter()
            .any(|b| b.name == service.cbb && b.position == service.bit.position);
        if !found {
            return Err(format!("{}: bit not in {}", service.name, service.bit.option).into());
        }
    }
    let required = conformance
        .mms_services
        .iter()
        .filter(|s| s.scope == "required");
    for service in required {
        if service.tag.is_none() || service.family.is_none() {
            return Err(format!("{}: required but not in the profile", service.name).into());
        }
    }
    Ok(())
}
