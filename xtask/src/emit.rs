// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Turn the parsed modules and the data files into Rust text.
//!
//! Only the types reachable from [`ROOTS`] are generated. Service CHOICEs keep the services in
//! scope and gain an `Unsupported` variant; [`OPAQUE`] types stay raw BER. Every type implements
//! the `Codec` trait of the runtime module `asn` of the codec crate.

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

/// Types defined outside the modules read, with their universal tag: X.501 §9.2 defines `Name` as a
/// CHOICE whose only alternative is a SEQUENCE OF, and §9.3 `RelativeDistinguishedName` as a SET OF.
const FOREIGN: [(&str, u32); 2] = [("Name", 16), ("RelativeDistinguishedName", 17)];

/// SEQUENCEs that skip the encodings they do not know: X.227 §7.4 asks it of an incoming AARQ.
const LENIENT: [&str; 1] = ["AARQ-apdu"];

/// Types whose constraint is not checked: the edition read fixes the size of the CBB bit
/// strings, while a peer of an earlier version sends fewer bits (85 and 11 on the bench, task F5).
/// Task C7 settles their reading.
const UNCHECKED: [&str; 4] = [
    "ServiceSupportOptions",
    "ParameterSupportOptions",
    "AdditionalSupportOptions",
    "AdditionalCBBOptions",
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

/// The Rust type of a use of an ASN.1 type. `Plain` carries the Rust type and its codec kind.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Rust {
    Unit,
    Plain(&'static str, String),
    Named(String),
    List(Box<Rust>),
}

fn plain(rust: &'static str, kind: &str) -> Rust {
    Rust::Plain(rust, format!("asn::{kind}"))
}

/// The identifiers that can start a value: tags as (class, number), any context tag (the
/// `Unsupported` variant), or any tag at all (open types).
#[derive(Clone, Debug, Default)]
struct Idents {
    any: bool,
    any_context: bool,
    tags: BTreeSet<(u8, u32)>,
}

fn class_index(class: Class) -> u8 {
    match class {
        Class::Universal => 0,
        Class::Application => 1,
        Class::Context => 2,
        Class::Private => 3,
    }
}

impl Idents {
    fn one(class: Class, number: u32) -> Self {
        Self {
            tags: BTreeSet::from([(class_index(class), number)]),
            ..Self::default()
        }
    }

    fn universal(number: u32) -> Self {
        Self::one(Class::Universal, number)
    }

    fn join(&mut self, other: &Idents) {
        self.any |= other.any;
        self.any_context |= other.any_context;
        self.tags.extend(other.tags.iter().copied());
    }

    fn overlaps(&self, other: &Idents) -> bool {
        let context = |i: &Idents| i.any_context || i.tags.iter().any(|t| t.0 == 2);
        (self.any && (other.any || other.any_context || !other.tags.is_empty()))
            || (other.any && (self.any_context || !self.tags.is_empty()))
            || (self.any_context && context(other))
            || (other.any_context && context(self))
            || !self.tags.is_disjoint(&other.tags)
    }
}

struct Field {
    asn: String,
    name: String,
    rust: Rust,
    tag: Option<Tag>,
    presence: String,
    idents: Idents,
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
    /// Codec kinds of the opaque types, with the identifiers they accept.
    opaque: BTreeMap<String, Idents>,
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
            opaque: BTreeMap::new(),
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
        if matches!(kind, Kind::Choice(_) | Kind::Raw(None)) {
            tag.tagging = Tagging::Explicit;
        }
        Ok(Some(tag))
    }

    /// The identifiers that can start a value of `ty`, its own tag included.
    fn idents(&self, ty: &Type) -> Result<Idents, Fail> {
        if let Some(tag) = ty.tag {
            return Ok(Idents::one(tag.class, tag.number));
        }
        Ok(match &ty.kind {
            Kind::Boolean => Idents::universal(1),
            Kind::Integer(_) => Idents::universal(2),
            Kind::BitString(_) => Idents::universal(3),
            Kind::OctetString => Idents::universal(4),
            Kind::Null => Idents::universal(5),
            Kind::ObjectIdentifier => Idents::universal(6),
            Kind::Enumerated(_) => Idents::universal(10),
            Kind::Text(n) | Kind::Raw(Some(n)) => Idents::universal(*n),
            Kind::Raw(None) => Idents {
                any: true,
                ..Idents::default()
            },
            Kind::Sequence(_) | Kind::SequenceOf(_) => Idents::universal(16),
            Kind::Choice(members) => {
                let mut out = Idents::default();
                for m in members {
                    out.join(&self.idents(&m.ty)?);
                }
                out
            }
            Kind::Reference(name) if SERVICE_CHOICES.iter().any(|(n, _)| n == name) => Idents {
                any_context: true,
                ..Idents::default()
            },
            Kind::Reference(name) => match FOREIGN.iter().find(|(n, _)| n == name) {
                Some((_, number)) => Idents::universal(*number),
                None => self.idents(&self.lookup(name)?)?,
            },
        })
    }

    fn opaque_kind(&mut self, name: String, ty: &Type) -> Result<Rust, Fail> {
        let mut bare = ty.clone();
        bare.tag = None;
        let idents = self.idents(&bare)?;
        self.opaque.insert(name.clone(), idents);
        Ok(Rust::Plain("RawBer", name))
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
        let bare = ty.constraint == Constraint::default();
        Ok(match &ty.kind {
            Kind::Boolean => plain("bool", "Boolean"),
            Kind::Null => Rust::Unit,
            Kind::Integer(named) if named.is_empty() && bare => plain("i64", "Integer"),
            Kind::Enumerated(named) if named.is_empty() && bare => plain("i64", "Enumerated"),
            Kind::BitString(named) if named.is_empty() && bare => plain("BitString", "BitStr"),
            Kind::OctetString if bare => plain("Vec<u8>", "Octets"),
            Kind::Text(number) if bare => {
                let kind = match number {
                    12 => "Utf8",
                    23 => "UtcTime",
                    24 => "GeneralizedTime",
                    25 => "Graphic",
                    _ => "Visible",
                };
                plain("String", kind)
            }
            Kind::ObjectIdentifier => plain("ObjectIdentifier", "Oid"),
            Kind::Raw(Some(8)) => plain("RawBer", "External"),
            Kind::Raw(Some(_)) => plain("RawBer", "EmbeddedPdv"),
            Kind::Raw(None) => plain("RawBer", "Open"),
            Kind::SequenceOf(inner) if bare => {
                Rust::List(Box::new(self.rust(inner, &format!("{hint}Item"))?))
            }
            Kind::Reference(name) if OPAQUE.contains(&name.as_str()) => {
                self.opaque_kind(format!("Opaque{}", camel(name)), ty)?
            }
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
            self.opaque_kind(format!("Opaque{hint}"), &member.ty)?
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
            idents: self.idents(&member.ty)?,
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
                    Kind::Integer(n) => {
                        bare.kind = Kind::Integer(Vec::new());
                        (n.clone(), false)
                    }
                    Kind::Enumerated(n) => {
                        bare.kind = Kind::Enumerated(Vec::new());
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
        check_body(asn, &body)?;
        Ok(Item {
            asn: asn.to_owned(),
            tag: self.effective(ty.tag, ty)?,
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

    /// The codec kind of a use of a type, a type implementing `asn::Codec`.
    fn kind(&self, owner: &str, rust: &Rust) -> String {
        match rust {
            Rust::Unit => "asn::Null".to_owned(),
            Rust::Plain(_, kind) => kind.clone(),
            Rust::Named(n) if self.reaches(n, owner) => format!("asn::Boxed<{n}>"),
            Rust::Named(n) => n.clone(),
            Rust::List(inner) => match inner.as_ref() {
                Rust::Named(n) => format!("asn::ListOf<{n}>"),
                other => format!("asn::ListOf<{}>", self.kind(owner, other)),
            },
        }
    }

    fn text(&self, owner: &str, rust: &Rust) -> String {
        match rust {
            Rust::Unit => "()".to_owned(),
            Rust::Plain(p, _) => (*p).to_owned(),
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
             use crate::asn;\n\
             use crate::ber::{{self, Element, Writer}};\n\
             use crate::schema::{{BitString, Member, ObjectIdentifier, Presence, RawBer, Tag, \
             TagClass, Tagging}};\n\n\
             /// Number of generated types.\npub const TYPE_COUNT: usize = {};\n\n",
            self.items.len()
        );
        for (name, item) in &self.items {
            emit_item(self, &mut o, name, item)?;
            emit_codec(self, &mut o, name, item)?;
        }
        for (name, idents) in &self.opaque {
            emit_opaque(&mut o, name, idents)?;
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
        "Tag::new(TagClass::{class}, {}, Tagging::{tagging})",
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

/// X.680 §29.3 and §25.6: the tags of the alternatives differ, and so do the tags of an optional
/// component and of the components that may follow it.
fn check_body(asn: &str, body: &Body) -> Result<(), Fail> {
    match body {
        Body::Enum { alternatives, .. } => {
            for (i, a) in alternatives.iter().enumerate() {
                for b in alternatives.iter().skip(i + 1) {
                    if a.idents.overlaps(&b.idents) {
                        return Err(format!("{asn}: {} and {} share a tag", a.asn, b.asn).into());
                    }
                }
            }
        }
        Body::Struct(fields) => {
            for (i, a) in fields.iter().enumerate() {
                if a.presence == "Presence::Required" {
                    continue;
                }
                for b in fields.iter().skip(i + 1) {
                    if a.idents.overlaps(&b.idents) {
                        return Err(format!("{asn}: {} and {} share a tag", a.asn, b.asn).into());
                    }
                    if b.presence == "Presence::Required" {
                        break;
                    }
                }
            }
        }
        Body::Newtype { .. } => {}
    }
    Ok(())
}

fn emit_codec(g: &Generator, o: &mut String, name: &str, item: &Item) -> Result<(), Fail> {
    let ty = &item.asn;
    // The own tag replaces the base identifiers when it is implicit.
    let base_accepts = item.tag.is_none_or(|t| t.tagging == Tagging::Explicit);
    writeln!(o, "impl {name} {{")?;
    match &item.body {
        Body::Struct(fields) => {
            if base_accepts {
                writeln!(
                    o,
                    "fn base_accepts(id: ber::Identifier) -> bool {{ asn::is_universal(id, 16) }}"
                )?;
            }
            let known = if LENIENT.contains(&ty.as_str()) {
                let tests: Vec<String> = fields
                    .iter()
                    .map(|f| {
                        format!(
                            "asn::accepts::<{}>({}, id)",
                            g.kind(name, &f.rust),
                            tag_text(f.tag)
                        )
                    })
                    .collect();
                format!("Some(|id: ber::Identifier| {})", tests.join(" || "))
            } else {
                "None".to_owned()
            };
            writeln!(
                o,
                "fn base_decode(e: &Element<'_>) -> Result<Self, asn::Error> {{"
            )?;
            writeln!(o, "let mut c = asn::Components::new(e, {ty:?}, {known})?;")?;
            for f in fields {
                let kind = g.kind(name, &f.rust);
                if f.presence == "Presence::Required" {
                    writeln!(
                        o,
                        "let {} = c.required::<{kind}>({}, {:?})?;",
                        f.name,
                        tag_text(f.tag),
                        f.asn
                    )?;
                } else {
                    writeln!(
                        o,
                        "let {} = c.optional::<{kind}>({})?;",
                        f.name,
                        tag_text(f.tag)
                    )?;
                }
            }
            let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
            writeln!(o, "c.finish()?;\nOk(Self {{ {} }})\n}}", names.join(", "))?;
            writeln!(
                o,
                "fn base_encode(&self, w: &mut Writer, implicit: Option<ber::Identifier>) -> Result<(), asn::Error> {{"
            )?;
            if fields.is_empty() {
                writeln!(
                    o,
                    "w.constructed(implicit.unwrap_or(ber::Identifier::SEQUENCE), |_| Ok(()))"
                )?;
            } else {
                writeln!(
                    o,
                    "w.constructed(implicit.unwrap_or(ber::Identifier::SEQUENCE), |w| {{"
                )?;
                for f in fields {
                    let kind = g.kind(name, &f.rust);
                    let call = if f.presence == "Presence::Required" {
                        "encode"
                    } else {
                        "encode_optional"
                    };
                    writeln!(
                        o,
                        "asn::{call}::<{kind}>({}, &self.{}, w)?;",
                        tag_text(f.tag),
                        f.name
                    )?;
                }
                writeln!(o, "Ok(())\n}})")?;
            }
            writeln!(o, "}}")?;
        }
        Body::Enum {
            alternatives,
            unsupported,
        } => {
            let mut tests: Vec<String> = alternatives
                .iter()
                .map(|f| {
                    format!(
                        "asn::accepts::<{}>({}, id)",
                        g.kind(name, &f.rust),
                        tag_text(f.tag)
                    )
                })
                .collect();
            if *unsupported {
                tests.push("id.class == TagClass::Context".to_owned());
            }
            if tests.is_empty() {
                tests.push("false".to_owned());
            }
            if base_accepts {
                writeln!(
                    o,
                    "fn base_accepts(id: ber::Identifier) -> bool {{ {} }}",
                    tests.join(" || ")
                )?;
            }
            writeln!(
                o,
                "fn base_decode(e: &Element<'_>) -> Result<Self, asn::Error> {{\nlet id = e.identifier;"
            )?;
            for f in alternatives {
                let kind = g.kind(name, &f.rust);
                let tag = tag_text(f.tag);
                let variant = camel(&f.asn);
                if f.rust == Rust::Unit {
                    writeln!(
                        o,
                        "if asn::accepts::<{kind}>({tag}, id) {{ asn::decode::<{kind}>({tag}, e)?; return Ok(Self::{variant}); }}"
                    )?;
                } else {
                    writeln!(
                        o,
                        "if asn::accepts::<{kind}>({tag}, id) {{ return Ok(Self::{variant}(asn::decode::<{kind}>({tag}, e)?)); }}"
                    )?;
                }
            }
            if *unsupported {
                writeln!(
                    o,
                    "if id.class == TagClass::Context {{ return Ok(Self::Unsupported {{ tag: id.number, raw: asn::raw(e, None) }}); }}"
                )?;
            }
            writeln!(
                o,
                "Err(asn::Error::NoAlternative {{ ty: {ty:?}, found: id }})\n}}"
            )?;
            writeln!(
                o,
                "fn base_encode(&self, w: &mut Writer, implicit: Option<ber::Identifier>) -> Result<(), asn::Error> {{"
            )?;
            writeln!(o, "asn::no_implicit(implicit, {ty:?})?;\nmatch self {{")?;
            for f in alternatives {
                let kind = g.kind(name, &f.rust);
                let tag = tag_text(f.tag);
                let variant = camel(&f.asn);
                if f.rust == Rust::Unit {
                    writeln!(
                        o,
                        "Self::{variant} => asn::encode::<{kind}>({tag}, &(), w),"
                    )?;
                } else {
                    writeln!(
                        o,
                        "Self::{variant}(v) => asn::encode::<{kind}>({tag}, v, w),"
                    )?;
                }
            }
            if *unsupported {
                writeln!(
                    o,
                    "Self::Unsupported {{ tag, raw }} => asn::write_unsupported(w, *tag, raw),"
                )?;
            }
            writeln!(o, "}}\n}}")?;
        }
        Body::Newtype {
            inner, constraint, ..
        } => {
            let kind = g.kind(name, inner);
            let checked = !UNCHECKED.contains(&ty.as_str());
            let values = checked && !constraint.values.is_empty() && !constraint.values_extensible;
            let sizes = checked && !constraint.sizes.is_empty() && !constraint.sizes_extensible;
            if values && !matches!(inner, Rust::Plain("i64", _)) {
                return Err(
                    format!("{ty}: value constraint on a type that is not an integer").into(),
                );
            }
            let checked = values || sizes;
            if base_accepts {
                writeln!(
                    o,
                    "fn base_accepts(id: ber::Identifier) -> bool {{ <{kind} as asn::Codec>::accepts(id) }}"
                )?;
            }
            writeln!(
                o,
                "fn base_decode(e: &Element<'_>) -> Result<Self, asn::Error> {{"
            )?;
            if checked {
                writeln!(
                    o,
                    "let value = Self(<{kind} as asn::Codec>::decode(e)?);\nvalue.check()?;\nOk(value)\n}}"
                )?;
            } else {
                writeln!(o, "Ok(Self(<{kind} as asn::Codec>::decode(e)?))\n}}")?;
            }
            writeln!(
                o,
                "fn base_encode(&self, w: &mut Writer, implicit: Option<ber::Identifier>) -> Result<(), asn::Error> {{"
            )?;
            if checked {
                writeln!(o, "self.check()?;")?;
            }
            writeln!(
                o,
                "<{kind} as asn::Codec>::encode(&self.0, w, implicit)\n}}"
            )?;
            if checked {
                let text = g.text(name, inner);
                writeln!(
                    o,
                    "/// The value, if it meets the constraint of the type.\npub fn new(value: {text}) -> Result<Self, asn::Error> {{ let value = Self(value); value.check()?; Ok(value) }}"
                )?;
                writeln!(
                    o,
                    "/// Checks the value against the constraint of the type.\npub fn check(&self) -> Result<(), asn::Error> {{"
                )?;
                if values {
                    writeln!(o, "asn::check_values({ty:?}, Self::VALUES, self.0)?;")?;
                }
                if sizes {
                    writeln!(o, "asn::check_sizes({ty:?}, Self::SIZES, &self.0)?;")?;
                }
                writeln!(o, "Ok(())\n}}")?;
            }
        }
    }
    writeln!(o, "}}\n")?;

    writeln!(
        o,
        "impl asn::Codec for {name} {{\ntype Value = Self;\nconst NAME: &'static str = {ty:?};"
    )?;
    let (accepts, decode, encode) = match item.tag {
        None => (
            "Self::base_accepts(id)".to_owned(),
            "Self::base_decode(e)".to_owned(),
            "value.base_encode(w, implicit)".to_owned(),
        ),
        Some(tag) if tag.tagging == Tagging::Implicit => (
            "asn::is_tag(Self::TAG, id)".to_owned(),
            "Self::base_decode(e)".to_owned(),
            "value.base_encode(w, Some(implicit.unwrap_or(asn::identifier(Self::TAG))))".to_owned(),
        ),
        Some(_) => (
            "asn::is_tag(Self::TAG, id)".to_owned(),
            "asn::explicit(e, Self::NAME, Self::base_accepts, Self::base_decode)".to_owned(),
            "w.constructed(implicit.unwrap_or(asn::identifier(Self::TAG)), |w| value.base_encode(w, None))".to_owned(),
        ),
    };
    writeln!(
        o,
        "fn accepts(id: ber::Identifier) -> bool {{ {accepts} }}\n\
         fn decode(e: &Element<'_>) -> Result<Self, asn::Error> {{ {decode} }}\n\
         fn encode(value: &Self, w: &mut Writer, implicit: Option<ber::Identifier>) -> Result<(), asn::Error> {{ {encode} }}\n}}\n"
    )?;
    Ok(())
}

fn emit_opaque(o: &mut String, name: &str, idents: &Idents) -> Result<(), Fail> {
    let asn = name.trim_start_matches("Opaque");
    let classes = ["Universal", "Application", "Context", "Private"];
    let mut tests: Vec<String> = idents
        .tags
        .iter()
        .map(|(class, number)| {
            format!(
                "id.class == TagClass::{} && id.number == {number}",
                classes[usize::from(*class)]
            )
        })
        .collect();
    if tests.len() > 1 {
        tests = tests.into_iter().map(|t| format!("({t})")).collect();
    }
    if idents.any_context {
        tests.push("id.class == TagClass::Context".to_owned());
    }
    if idents.any {
        tests = vec!["true".to_owned()];
    }
    if tests.is_empty() {
        return Err(format!("{name}: no tag known").into());
    }
    let fixed = match (idents.any || idents.any_context, idents.tags.iter().next()) {
        (false, Some((class, number))) if idents.tags.len() == 1 => format!(
            "Some(ber::Identifier::new(TagClass::{}, true, {number}))",
            classes[usize::from(*class)]
        ),
        _ => "None".to_owned(),
    };
    let accepts = if idents.any {
        "fn accepts(_: ber::Identifier) -> bool { true }".to_owned()
    } else {
        format!(
            "fn accepts(id: ber::Identifier) -> bool {{ {} }}",
            tests.join(" || ")
        )
    };
    writeln!(
        o,
        "/// Codec of a type kept as raw BER.\n#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub struct {name};\n\n\
         impl asn::Codec for {name} {{\ntype Value = RawBer;\nconst NAME: &'static str = {asn:?};\n{accepts}\n\
         fn decode(e: &Element<'_>) -> Result<RawBer, asn::Error> {{ Ok(asn::raw(e, {fixed})) }}\n\
         fn encode(value: &RawBer, w: &mut Writer, implicit: Option<ber::Identifier>) -> Result<(), asn::Error> {{ asn::write_raw(w, value, Self::accepts, implicit) }}\n}}\n"
    )?;
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

    const CHECKS: &str = "Checks DEFINITIONS ::= BEGIN
        Twice ::= CHOICE { a INTEGER, b INTEGER }
        Hidden ::= SEQUENCE { a INTEGER OPTIONAL, b INTEGER }
        Fine ::= SEQUENCE { a [0] INTEGER OPTIONAL, b INTEGER, c INTEGER OPTIONAL }
        Open ::= CHOICE { a INTEGER, b ANY }
        Colour ::= ENUMERATED { red (0), green (1) }
        Shade ::= ENUMERATED { red (0), ..., green (1) }
        Small ::= INTEGER (0..7, ...)
        Name ::= VisibleString (SIZE (1..32))
        END";

    fn checked(name: &str) -> Result<Item, Fail> {
        let modules = [Module::parse(CHECKS).unwrap()];
        let conformance = Conformance {
            mms_services: Vec::new(),
            mms_pdus: Vec::new(),
        };
        let mut generator = Generator::new(&modules, &conformance);
        let ty = modules[0].type_of(name).unwrap();
        generator.item(name, name, &ty)
    }

    #[test]
    fn ambiguous_tags_are_refused() {
        for name in ["Twice", "Hidden", "Open"] {
            let error = checked(name).err().map(|e| e.to_string());
            assert!(error.is_some_and(|e| e.contains("share a tag")), "{name}");
        }
        assert!(checked("Fine").is_ok());
    }

    #[test]
    fn constraints_record_extension_markers() {
        let module = Module::parse(CHECKS).unwrap();
        let constraint = |name: &str| module.type_of(name).unwrap().constraint;
        let colour = constraint("Colour");
        assert_eq!(colour.values, vec![(Some(0), Some(0)), (Some(1), Some(1))]);
        assert!(!colour.values_extensible);
        assert!(constraint("Shade").values.is_empty());
        let small = constraint("Small");
        assert_eq!(small.values, vec![(Some(0), Some(7))]);
        assert!(small.values_extensible);
        let name = constraint("Name");
        assert_eq!(name.sizes, vec![(Some(1), Some(32))]);
        assert!(!name.sizes_extensible);
    }
}
