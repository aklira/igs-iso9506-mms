// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Turn the parsed modules and the data files into Rust text.
//!
//! Only the types reachable from [`ROOTS`] are generated. Service CHOICEs keep the services in
//! scope and gain an `Unsupported` variant; [`OPAQUE`] types stay raw BER. Decoding and encoding
//! are added to this generator by the codec tasks.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write;

use crate::asn::{Class, Constraint, Fail, Kind, Member, Module, Ranges, Tag, Tagging, Type};
use crate::data::{CodeTable, Conformance, Profile, Status};

const ROOTS: [&str; 2] = ["MMSpdu", "ACSE-apdu"];

/// Out of scope, or outside the MMS and ACSE modules: kept as raw BER.
const OPAQUE: [&str; 9] = [
    "Modifier",
    "Request-Detail",
    "Response-Detail",
    "Unconfirmed-Detail",
    "AdditionalService-Request",
    "AdditionalService-Response",
    "AdditionalService-Error",
    "Name",
    "RelativeDistinguishedName",
];

/// Members kept as raw BER: their alternatives belong to services out of scope.
const OPAQUE_MEMBERS: [(&str, &str); 1] = [("ServiceError", "serviceSpecificInfo")];

/// CHOICEs of services, with the family whose tags select their alternatives.
const SERVICE_CHOICES: [(&str, &str); 3] = [
    ("ConfirmedServiceRequest", "confirmed"),
    ("ConfirmedServiceResponse", "confirmed"),
    ("UnconfirmedService", "unconfirmed"),
];

const KEYWORDS: [&str; 16] = [
    "abstract", "box", "final", "fn", "in", "loop", "macro", "match", "mod", "override", "ref",
    "self", "try", "type", "use", "where",
];

pub fn camel(name: &str) -> String {
    name.split('-')
        .map(|part| {
            let mut chars = part.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_uppercase().chain(chars).collect()
            })
        })
        .collect()
}

pub fn snake(name: &str) -> String {
    let mut out = String::new();
    let mut previous_lower = false;
    for c in name.chars() {
        if c == '-' {
            out.push('_');
            previous_lower = false;
        } else if c.is_uppercase() {
            if previous_lower {
                out.push('_');
            }
            out.extend(c.to_lowercase());
            previous_lower = false;
        } else {
            out.push(c);
            previous_lower = true;
        }
    }
    if KEYWORDS.contains(&out.as_str()) {
        out.push('_');
    }
    out
}

fn shout(name: &str) -> String {
    snake(name).trim_end_matches('_').to_uppercase()
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Rust {
    Unit,
    Plain(&'static str),
    Named(String),
    List(Box<Rust>),
}

struct Field {
    asn: String,
    name: String,
    rust: Rust,
    tag: Option<Tag>,
    presence: String,
}

enum Body {
    Struct(Vec<Field>),
    Enum {
        alternatives: Vec<Field>,
        unsupported: bool,
    },
    Newtype {
        inner: Rust,
        named: Vec<(String, i64)>,
        bits: bool,
        constraint: Constraint,
    },
}

struct Item {
    asn: String,
    tag: Option<Tag>,
    body: Body,
}

pub struct Generator<'a> {
    modules: &'a [Module],
    scope: BTreeMap<&'static str, BTreeSet<u32>>,
    items: BTreeMap<String, Item>,
    queue: VecDeque<String>,
    seen: BTreeSet<String>,
}

impl<'a> Generator<'a> {
    pub fn new(modules: &'a [Module], conformance: &Conformance) -> Self {
        let tags = |family: &str| {
            conformance
                .mms_services
                .iter()
                .filter(|s| s.scope == "required" && s.family.as_deref() == Some(family))
                .filter_map(|s| s.tag)
                .collect::<BTreeSet<u32>>()
        };
        let scope = BTreeMap::from([
            ("confirmed", tags("confirmed")),
            ("unconfirmed", tags("unconfirmed")),
        ]);
        Self {
            modules,
            scope,
            items: BTreeMap::new(),
            queue: VecDeque::new(),
            seen: BTreeSet::new(),
        }
    }

    fn lookup(&self, name: &str) -> Result<Type, Fail> {
        let mut found = self
            .modules
            .iter()
            .filter(|m| m.assignments.contains_key(name));
        let module = found.next().ok_or_else(|| format!("{name}: not defined"))?;
        if let Some(other) = found.next() {
            return Err(format!("{name}: in {} and {}", module.name, other.name).into());
        }
        module.type_of(name)
    }

    /// X.680 §31.2.7: an implicit tag on a CHOICE or an open type is explicit.
    fn effective(&self, tag: Option<Tag>, ty: &Type) -> Result<Option<Tag>, Fail> {
        let Some(mut tag) = tag else { return Ok(None) };
        let mut kind = ty.kind.clone();
        while let Kind::Reference(name) = kind {
            let target = self.lookup(&name)?;
            if target.tag.is_some() {
                return Ok(Some(tag));
            }
            kind = target.kind;
        }
        if matches!(kind, Kind::Choice(_) | Kind::Raw) {
            tag.tagging = Tagging::Explicit;
        }
        Ok(Some(tag))
    }

    fn hoist(&mut self, name: String, ty: &Type) -> Result<Rust, Fail> {
        if self.items.contains_key(&name) {
            return Err(format!("{name}: two anonymous types").into());
        }
        let mut inner = ty.clone();
        inner.tag = None;
        let item = self.item(&name, &name, &inner)?;
        self.items.insert(name.clone(), item);
        Ok(Rust::Named(name))
    }

    fn rust(&mut self, ty: &Type, hint: &str) -> Result<Rust, Fail> {
        let plain = ty.constraint == Constraint::default();
        Ok(match &ty.kind {
            Kind::Boolean => Rust::Plain("bool"),
            Kind::Null => Rust::Unit,
            Kind::Integer(named) if named.is_empty() && plain => Rust::Plain("i64"),
            Kind::BitString(named) if named.is_empty() && plain => Rust::Plain("BitString"),
            Kind::OctetString if plain => Rust::Plain("Vec<u8>"),
            Kind::Text if plain => Rust::Plain("String"),
            Kind::ObjectIdentifier => Rust::Plain("ObjectIdentifier"),
            Kind::Raw => Rust::Plain("RawBer"),
            Kind::SequenceOf(inner) if plain => {
                Rust::List(Box::new(self.rust(inner, &format!("{hint}Item"))?))
            }
            Kind::Reference(name) if OPAQUE.contains(&name.as_str()) => Rust::Plain("RawBer"),
            Kind::Reference(name) => {
                if self.seen.insert(name.clone()) {
                    self.queue.push_back(name.clone());
                }
                Rust::Named(camel(name))
            }
            _ => self.hoist(hint.to_owned(), ty)?,
        })
    }

    fn field(&mut self, parent: &str, asn: &str, member: &Member) -> Result<Field, Fail> {
        let opaque = OPAQUE_MEMBERS.contains(&(asn, member.name.as_str()));
        let hint = format!("{parent}{}", camel(&member.name));
        let rust = if opaque {
            Rust::Plain("RawBer")
        } else {
            self.rust(&member.ty, &hint)?
        };
        let presence = match (&member.default, member.optional) {
            (Some(value), _) => format!("Presence::Default({value:?})"),
            (None, true) => "Presence::Optional".to_owned(),
            (None, false) => "Presence::Required".to_owned(),
        };
        Ok(Field {
            asn: member.name.clone(),
            name: snake(&member.name),
            rust,
            tag: self.effective(member.ty.tag, &member.ty)?,
            presence,
        })
    }

    fn item(&mut self, rust: &str, asn: &str, ty: &Type) -> Result<Item, Fail> {
        let body = match &ty.kind {
            Kind::Sequence(members) => Body::Struct(
                members
                    .iter()
                    .map(|m| self.field(rust, asn, m))
                    .collect::<Result<_, _>>()?,
            ),
            Kind::Choice(members) => {
                let family = SERVICE_CHOICES.iter().find(|(n, _)| *n == asn);
                let kept = |m: &&Member| {
                    family.is_none_or(|(_, f)| {
                        m.ty.tag.is_some_and(|t| self.scope[f].contains(&t.number))
                    })
                };
                let members: Vec<Member> = members.iter().filter(kept).cloned().collect();
                Body::Enum {
                    alternatives: members
                        .iter()
                        .map(|m| self.field(rust, asn, m))
                        .collect::<Result<_, _>>()?,
                    unsupported: family.is_some(),
                }
            }
            other => {
                let mut bare = ty.clone();
                bare.tag = None;
                bare.constraint = Constraint::default();
                let (named, bits) = match other {
                    Kind::Integer(n) | Kind::Enumerated(n) => {
                        bare.kind = Kind::Integer(Vec::new());
                        (n.clone(), false)
                    }
                    Kind::BitString(n) => {
                        bare.kind = Kind::BitString(Vec::new());
                        (n.clone(), true)
                    }
                    _ => (Vec::new(), false),
                };
                Body::Newtype {
                    inner: self.rust(&bare, &format!("{rust}Item"))?,
                    named,
                    bits,
                    constraint: ty.constraint.clone(),
                }
            }
        };
        Ok(Item {
            asn: asn.to_owned(),
            tag: ty.tag,
            body,
        })
    }

    pub fn run(&mut self) -> Result<(), Fail> {
        for root in ROOTS {
            self.seen.insert(root.to_owned());
            self.queue.push_back(root.to_owned());
        }
        while let Some(name) = self.queue.pop_front() {
            let ty = self.lookup(&name)?;
            let rust = camel(&name);
            let item = self.item(&rust, &name, &ty)?;
            if self.items.insert(rust.clone(), item).is_some() {
                return Err(format!("{rust}: two types of this name").into());
            }
        }
        Ok(())
    }

    fn by_value(&self, name: &str) -> Vec<String> {
        let fields = match self.items.get(name).map(|i| &i.body) {
            Some(Body::Struct(f)) => f.iter().map(|x| &x.rust).collect(),
            Some(Body::Enum { alternatives, .. }) => alternatives.iter().map(|x| &x.rust).collect(),
            Some(Body::Newtype { inner, .. }) => vec![inner],
            None => Vec::new(),
        };
        fields
            .into_iter()
            .filter_map(|r| match r {
                Rust::Named(n) => Some(n.clone()),
                _ => None,
            })
            .collect()
    }

    fn reaches(&self, from: &str, to: &str) -> bool {
        let mut stack = vec![from.to_owned()];
        let mut visited = BTreeSet::new();
        while let Some(name) = stack.pop() {
            if name == to {
                return true;
            }
            if visited.insert(name.clone()) {
                stack.extend(self.by_value(&name));
            }
        }
        false
    }

    fn text(&self, owner: &str, rust: &Rust) -> String {
        match rust {
            Rust::Unit => "()".to_owned(),
            Rust::Plain(p) => (*p).to_owned(),
            Rust::Named(n) if self.reaches(n, owner) => format!("Box<{n}>"),
            Rust::Named(n) => n.clone(),
            Rust::List(inner) => match inner.as_ref() {
                Rust::Named(n) => format!("Vec<{n}>"),
                other => format!("Vec<{}>", self.text(owner, other)),
            },
        }
    }

    pub fn types_txt(&self, banner: &str) -> Result<String, Fail> {
        let mut o = format!(
            "{banner}\n#![allow(clippy::large_enum_variant, clippy::enum_variant_names, \
             clippy::upper_case_acronyms)]\n\n\
             use crate::schema::{{BitString, Member, ObjectIdentifier, Presence, RawBer, Tag, \
             TagClass, Tagging}};\n\n\
             /// Number of generated types.\npub const TYPE_COUNT: usize = {};\n\n",
            self.items.len()
        );
        for (name, item) in &self.items {
            emit_item(self, &mut o, name, item)?;
        }
        Ok(o)
    }
}

fn tag_text(tag: Option<Tag>) -> String {
    let Some(tag) = tag else {
        return "None".to_owned();
    };
    format!("Some({})", tag_value(tag))
}

fn tag_value(tag: Tag) -> String {
    let class = match tag.class {
        Class::Universal => "Universal",
        Class::Application => "Application",
        Class::Context => "Context",
        Class::Private => "Private",
    };
    let tagging = match tag.tagging {
        Tagging::Implicit => "Implicit",
        Tagging::Explicit => "Explicit",
    };
    format!(
        "Tag {{ class: TagClass::{class}, number: {}, tagging: Tagging::{tagging} }}",
        tag.number
    )
}

fn members_const(o: &mut String, label: &str, fields: &[Field]) -> Result<(), Fail> {
    writeln!(o, "    /// Components with their tags.")?;
    writeln!(o, "    pub const {label}: &'static [Member] = &[")?;
    for f in fields {
        writeln!(
            o,
            "Member {{ name: {:?}, tag: {}, presence: {} }},",
            f.asn,
            tag_text(f.tag),
            f.presence
        )?;
    }
    writeln!(o, "];")?;
    Ok(())
}

fn ranges_text(ranges: &Ranges) -> String {
    let items: Vec<String> = ranges
        .iter()
        .map(|(low, high)| {
            let bound = |b: &Option<i64>, open: &str| b.map_or(open.to_owned(), |v| v.to_string());
            format!("({}, {})", bound(low, "i64::MIN"), bound(high, "i64::MAX"))
        })
        .collect();
    format!("&[{}]", items.join(", "))
}

fn emit_item(g: &Generator, o: &mut String, name: &str, item: &Item) -> Result<(), Fail> {
    writeln!(o, "/// ASN.1 type `{}`.", item.asn)?;
    writeln!(o, "#[derive(Debug, Clone, PartialEq, Eq)]")?;
    match &item.body {
        Body::Struct(fields) => {
            writeln!(o, "pub struct {name} {{")?;
            for f in fields {
                let text = g.text(name, &f.rust);
                let text = if f.presence == "Presence::Required" {
                    text
                } else {
                    format!("Option<{text}>")
                };
                writeln!(o, "    /// Component `{}`.", f.asn)?;
                writeln!(o, "    pub {}: {text},", f.name)?;
            }
            writeln!(o, "}}\n\nimpl {name} {{")?;
            members_const(o, "COMPONENTS", fields)?;
        }
        Body::Enum {
            alternatives,
            unsupported,
        } => {
            writeln!(o, "pub enum {name} {{")?;
            for f in alternatives {
                writeln!(o, "    /// Alternative `{}`.", f.asn)?;
                if f.rust == Rust::Unit {
                    writeln!(o, "    {},", camel(&f.asn))?;
                } else {
                    writeln!(o, "    {}({}),", camel(&f.asn), g.text(name, &f.rust))?;
                }
            }
            if *unsupported {
                writeln!(o, "    /// An alternative out of scope, kept as received.")?;
                writeln!(o, "    Unsupported {{ /// Tag number.\n tag: u32, /// Contents.\n raw: RawBer }},")?;
            }
            writeln!(o, "}}\n\nimpl {name} {{")?;
            members_const(o, "ALTERNATIVES", alternatives)?;
        }
        Body::Newtype {
            inner,
            named,
            bits,
            constraint,
        } => {
            writeln!(
                o,
                "pub struct {name}(pub {});\n\nimpl {name} {{",
                g.text(name, inner)
            )?;
            for (asn, value) in named {
                writeln!(o, "    /// Named value `{asn}`.")?;
                if *bits {
                    writeln!(o, "    pub const {}: u32 = {value};", shout(asn))?;
                } else {
                    writeln!(o, "    pub const {}: Self = Self({value});", shout(asn))?;
                }
            }
            if !constraint.values.is_empty() {
                writeln!(o, "    /// Allowed values, as inclusive ranges.")?;
                writeln!(
                    o,
                    "    pub const VALUES: &'static [(i64, i64)] = {};",
                    ranges_text(&constraint.values)
                )?;
            }
            if !constraint.sizes.is_empty() {
                writeln!(o, "    /// Allowed sizes, as inclusive ranges.")?;
                writeln!(
                    o,
                    "    pub const SIZES: &'static [(i64, i64)] = {};",
                    ranges_text(&constraint.sizes)
                )?;
            }
        }
    }
    if let Some(tag) = item.tag {
        writeln!(o, "    /// Tag of the type.")?;
        writeln!(o, "    pub const TAG: Tag = {};", tag_value(tag))?;
    }
    writeln!(o, "}}\n")?;
    Ok(())
}

fn status(s: &Status) -> String {
    let parts = [&s.fs, &s.sending_fs, &s.receiving_fs];
    let text: Vec<&str> = parts
        .iter()
        .filter(|p| !p.is_empty())
        .map(|p| p.as_str())
        .collect();
    text.join("/")
}

fn code_tables(o: &mut String, label: &str, doc: &str, tables: &[CodeTable]) -> Result<(), Fail> {
    writeln!(o, "/// {doc}\npub const {label}: &[CodeTable] = &[")?;
    for t in tables {
        let codes: Vec<String> = t
            .codes
            .iter()
            .map(|c| format!("({:?}, {})", c.name, c.code))
            .collect();
        writeln!(
            o,
            "CodeTable {{ name: {:?}, tag: {}, codes: &[{}] }},",
            t.name,
            t.tag,
            codes.join(", ")
        )?;
    }
    writeln!(o, "];\n")?;
    Ok(())
}

pub fn tables_txt(
    banner: &str,
    profile: &Profile,
    conformance: &Conformance,
) -> Result<String, Fail> {
    let mut o = format!(
        "{banner}\nuse crate::schema::{{Bit, CodeTable, Family, Modifier, NamedBit, Parameter, \
         Pdu, PduRequirement, Service, SupportOption}};\n\n"
    );
    let option = |name: &str| match name {
        "ServiceSupportOptions" => "SupportOption::Service",
        "AdditionalSupportOptions" => "SupportOption::AdditionalService",
        "ParameterSupportOptions" => "SupportOption::Parameter",
        _ => "SupportOption::AdditionalCbb",
    };
    writeln!(o, "/// The PDUs of MMS.\npub const PDUS: &[Pdu] = &[")?;
    for p in &profile.pdus {
        writeln!(o, "Pdu {{ name: {:?}, tag: {} }},", p.name, p.tag)?;
    }
    writeln!(
        o,
        "];\n\n/// The services with a tag, in each family.\npub const SERVICES: &[Service] = &["
    )?;
    for s in &profile.services {
        let family = match s.family.as_str() {
            "confirmed" => "Family::Confirmed",
            "additional" => "Family::Additional",
            _ => "Family::Unconfirmed",
        };
        let row = conformance
            .mms_services
            .iter()
            .find(|c| c.tag == Some(s.tag) && c.family.as_deref() == Some(s.family.as_str()));
        let in_scope = row.is_some_and(|r| r.scope == "required");
        let (client, server) = row.map_or((String::new(), String::new()), |r| {
            (status(&r.client), status(&r.server))
        });
        let groups: Vec<String> = s.requires.iter().map(|g| format!("&{g:?}")).collect();
        writeln!(
            o,
            "Service {{ name: {:?}, family: {family}, tag: {}, cbb: {:?}, bit: Bit {{ option: {}, position: {} }}, requires: &[{}], in_scope: {in_scope}, client: {client:?}, server: {server:?} }},",
            s.name, s.tag, s.cbb, option(&s.bit.option), s.bit.position, groups.join(", ")
        )?;
    }
    writeln!(o, "];\n\n/// Services carried by their own PDUs, with their bit.\npub const ENVIRONMENT_BITS: &[(&str, Bit)] = &[")?;
    for e in &profile.environment_services {
        writeln!(
            o,
            "({:?}, Bit {{ option: {}, position: {} }}),",
            e.name,
            option(&e.bit.option),
            e.bit.position
        )?;
    }
    writeln!(
        o,
        "];\n\n/// The modifiers, with their tag and bit.\npub const MODIFIERS: &[Modifier] = &["
    )?;
    for m in &profile.modifiers {
        writeln!(o, "Modifier {{ name: {:?}, tag: {}, cbb: {:?}, bit: Bit {{ option: {}, position: {} }} }},", m.name, m.tag, m.cbb, option(&m.bit.option), m.bit.position)?;
    }
    writeln!(
        o,
        "];\n\n/// The parameter CBBs.\npub const PARAMETERS: &[Parameter] = &["
    )?;
    for p in &profile.parameters {
        writeln!(
            o,
            "Parameter {{ name: {:?}, bit: Bit {{ option: {}, position: {} }} }},",
            p.name,
            option(&p.option),
            p.position
        )?;
    }
    writeln!(o, "];\n")?;
    for (label, key) in [
        ("SERVICE_SUPPORT_OPTIONS", "ServiceSupportOptions"),
        ("ADDITIONAL_SUPPORT_OPTIONS", "AdditionalSupportOptions"),
        ("PARAMETER_SUPPORT_OPTIONS", "ParameterSupportOptions"),
        ("ADDITIONAL_CBB_OPTIONS", "AdditionalCBBOptions"),
    ] {
        let bits = profile.bits.get(key).ok_or("missing bit string")?;
        writeln!(
            o,
            "/// The named bits of `{key}`.\npub const {label}: &[NamedBit] = &["
        )?;
        for b in bits {
            writeln!(
                o,
                "NamedBit {{ name: {:?}, position: {} }},",
                b.name, b.position
            )?;
        }
        writeln!(o, "];\n")?;
    }
    code_tables(
        &mut o,
        "ERROR_CLASSES",
        "The classes of `ServiceError`, with their codes.",
        &profile.error_classes,
    )?;
    code_tables(
        &mut o,
        "REJECT_REASONS",
        "The families of reject reasons, with their codes.",
        &profile.reject_reasons,
    )?;
    writeln!(o, "/// What the profile asks of the environment PDUs.\npub const PDU_REQUIREMENTS: &[PduRequirement] = &[")?;
    for p in &conformance.mms_pdus {
        writeln!(
            o,
            "PduRequirement {{ name: {:?}, tag: {}, in_scope: {}, client: {:?}, server: {:?} }},",
            p.name,
            p.tag.ok_or("PDU without tag")?,
            p.scope == "required",
            status(&p.client),
            status(&p.server)
        )?;
    }
    writeln!(o, "];")?;
    Ok(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODULE: &str = "Test DEFINITIONS ::= BEGIN
        Pick ::= CHOICE { a [0] BOOLEAN, ..., b [1] NULL, ..., c [2] NULL } -- note
        Alias ::= Pick
        Number ::= [APPLICATION 3] IMPLICIT INTEGER
        low Number ::= 1
        Record ::= SEQUENCE {
            x [1] IMPLICIT Pick,
            y [2] IMPLICIT Alias,
            z [3] IMPLICIT INTEGER (0..7, ...) OPTIONAL,
            w [4] IMPLICIT Number
        }
        END";

    fn fixture() -> (Module, Conformance) {
        let conformance = Conformance {
            mms_services: Vec::new(),
            mms_pdus: Vec::new(),
        };
        (Module::parse(MODULE).unwrap(), conformance)
    }

    #[test]
    fn implicit_tag_on_a_choice_is_explicit() {
        let (module, conformance) = fixture();
        let modules = [module];
        let generator = Generator::new(&modules, &conformance);
        let Kind::Sequence(members) = modules[0].type_of("Record").unwrap().kind else {
            panic!("not a sequence");
        };
        let tagging = |i: usize| {
            let member: &Member = &members[i];
            generator
                .effective(member.ty.tag, &member.ty)
                .unwrap()
                .unwrap()
                .tagging
        };
        assert_eq!(tagging(0), Tagging::Explicit);
        assert_eq!(tagging(1), Tagging::Explicit);
        assert_eq!(tagging(2), Tagging::Implicit);
        assert_eq!(tagging(3), Tagging::Implicit);
    }

    #[test]
    fn extension_markers_keep_all_alternatives() {
        let (module, _) = fixture();
        let Kind::Choice(members) = module.type_of("Pick").unwrap().kind else {
            panic!("not a choice");
        };
        assert_eq!(members.len(), 3);
    }

    #[test]
    fn value_assignments_are_not_types() {
        let (module, _) = fixture();
        assert_eq!(module.assignments.len(), 4);
        assert!(!module.assignments.contains_key("low"));
    }
}
