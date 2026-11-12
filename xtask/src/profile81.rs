// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The IEC 61850 profile rules of MMS: the parameter CBBs and the services that each side must
//! negotiate, given the ACSI model it declares (IEC 61850-8-1 clause 24, Tables 127 and 128; D-033).
//!
//! The rules come from `docs/spec/8-1/data/conformance_81.yaml`, read here. A condition is mapped to
//! the features of the declared model that it mentions. Only sufficient conditions are mapped: when
//! a condition also lists conditions that are not modelled (an alternative service, a service of the
//! ACSI model not declared here), the rule still holds, but it is not required when only those hold.
//! A condition that names no modelled feature is `Unmodelled`: no requirement is checked for it.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Deserialize;

use crate::asn::Fail;

/// The rows of clause 24 that the rules use.
#[derive(Deserialize)]
pub struct Conformance81 {
    parameter_cbbs: Vec<Row>,
    mms_services: Vec<Row>,
}

#[derive(Deserialize)]
struct Row {
    name: String,
    client: Status,
    server: Status,
    #[serde(default)]
    conditions: BTreeMap<String, String>,
    /// Parameter CBBs carry their position at the top level.
    position: Option<u32>,
    /// Services carry it in their support option.
    bit: Option<Bit>,
}

#[derive(Deserialize)]
struct Status {
    /// Absent where the cell carries a value instead of a status (conclude: "See 24.2.2.3.10").
    fs: Option<String>,
}

#[derive(Deserialize)]
struct Bit {
    position: u32,
}

/// The module of the rules, as Rust text (without the banner).
pub fn rules_txt(conformance: &Conformance81) -> Result<String, Fail> {
    let mut o = String::from(
        "use crate::mms::profile::{Feature, Requirement};\n\n\
         /// A parameter CBB or a service of the IEC 61850 profile, with what each side requires.\n\
         pub struct Rule {\n    /// Name, as in the MMS tables.\n    pub name: &'static str,\n    \
         /// Position of its bit.\n    pub position: u32,\n    /// Requirement of the client side.\n    \
         pub client: Requirement,\n    /// Requirement of the server side.\n    pub server: Requirement,\n}\n\n",
    );
    for (konst, rows, what) in [
        (
            "PARAMETER_RULES",
            &conformance.parameter_cbbs,
            "parameter CBBs (Table 128)",
        ),
        (
            "SERVICE_RULES",
            &conformance.mms_services,
            "services (Table 127)",
        ),
    ] {
        let _ = writeln!(
            o,
            "/// The {what} of IEC 61850-8-1 clause 24.\npub static {konst}: &[Rule] = &["
        );
        for row in rows {
            let position = match (row.position, &row.bit) {
                (Some(p), _) => p,
                (None, Some(bit)) => bit.position,
                (None, None) => return Err(format!("{}: no bit position", row.name).into()),
            };
            let _ = writeln!(
                o,
                "    Rule {{ name: {:?}, position: {position}, client: {}, server: {} }},",
                row.name,
                requirement(row.client.fs.as_deref(), &row.conditions, &row.name)?,
                requirement(row.server.fs.as_deref(), &row.conditions, &row.name)?,
            );
        }
        o.push_str("];\n\n");
    }
    Ok(o)
}

/// The requirement of a status cell: `m` is required; `c…` depends on its condition; `o`, `i`, `x`
/// and the dashes are not required.
fn requirement(
    status: Option<&str>,
    conditions: &BTreeMap<String, String>,
    name: &str,
) -> Result<String, Fail> {
    let Some(status) = status else {
        return Ok("Requirement::Never".into());
    };
    match status {
        "m" => Ok("Requirement::Always".into()),
        "o" | "i" | "x" | "–" | "-" => Ok("Requirement::Never".into()),
        s if s.len() > 1 && s.starts_with('c') && s[1..].bytes().all(|b| b.is_ascii_digit()) => {
            let text = conditions
                .get(s)
                .ok_or_else(|| format!("{name}: condition {s} is not in its notes"))?;
            let features = features(text);
            Ok(if features.is_empty() {
                "Requirement::Unmodelled".into()
            } else {
                format!(
                    "Requirement::Any(&[{}])",
                    features
                        .iter()
                        .map(|f| format!("Feature::{f}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
        }
        other => Err(format!("{name}: unknown status {other:?}").into()),
    }
}

/// The modelled features that a condition mentions. The phrases are those of the clause; a condition
/// naming `CreateDataSet` alone is not a data-set condition of the declared model.
fn features(text: &str) -> Vec<&'static str> {
    let lower = text.to_lowercase();
    let mut out = Vec::new();
    if lower.contains("logical node") || lower.contains("logical device") {
        out.push("LogicalNodes");
    }
    if lower.contains("data set") || lower.contains("datasets") || lower.contains("data-set") {
        out.push("DataSets");
    }
    if lower.contains("array") {
        out.push("Arrays");
    }
    out
}
