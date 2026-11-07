// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Reader for the subset of ASN.1 (X.680) that the modules of this stack use.
//!
//! Assignments are found by their `::=` and parsed on demand, so information object classes and
//! objects, which no generated type needs, are left aside. Comments are dropped by the tokenizer:
//! nothing of them reaches the generated code.

use std::collections::BTreeMap;

pub type Fail = Box<dyn std::error::Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tagging {
    Implicit,
    Explicit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Universal,
    Application,
    Context,
    Private,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    pub class: Class,
    pub number: u32,
    pub tagging: Tagging,
}

/// Allowed values or sizes, as inclusive ranges; `None` is an open end (`MIN`, `MAX`).
pub type Ranges = Vec<(Option<i64>, Option<i64>)>;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Constraint {
    pub values: Ranges,
    pub sizes: Ranges,
    /// An extension marker in the value constraint: other values are valid too.
    pub values_extensible: bool,
    /// An extension marker in the size constraint.
    pub sizes_extensible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Boolean,
    Null,
    Integer(Vec<(String, i64)>),
    Enumerated(Vec<(String, i64)>),
    BitString(Vec<(String, i64)>),
    OctetString,
    /// A character string or time type, with its universal tag number.
    Text(u32),
    ObjectIdentifier,
    /// EXTERNAL, EMBEDDED PDV (with their universal tag number), ANY and open types (none):
    /// left to the hand-written code as raw BER.
    Raw(Option<u32>),
    Sequence(Vec<Member>),
    SequenceOf(Box<Type>),
    Choice(Vec<Member>),
    Reference(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Type {
    pub tag: Option<Tag>,
    pub kind: Kind,
    pub constraint: Constraint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub name: String,
    pub ty: Type,
    pub optional: bool,
    pub default: Option<String>,
}

#[derive(Debug)]
pub struct Module {
    pub name: String,
    pub tagging: Tagging,
    tokens: Vec<String>,
    /// Type name -> index of the first token after `::=`.
    pub assignments: BTreeMap<String, usize>,
    values: BTreeMap<String, i64>,
}

fn tokenize(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c.is_whitespace() {
            i += 1;
        } else if c == '-' && next == Some('-') {
            // A comment ends at the end of the line or at the next `--`.
            i += 2;
            while i < chars.len() && chars[i] != '\n' {
                if chars[i] == '-' && chars.get(i + 1) == Some(&'-') {
                    i += 2;
                    break;
                }
                i += 1;
            }
        } else if c.is_ascii_alphabetic() || c == '&' {
            let start = i;
            i += 1;
            while i < chars.len()
                && (chars[i].is_ascii_alphanumeric()
                    || (chars[i] == '-' && chars.get(i + 1) != Some(&'-')))
            {
                i += 1;
            }
            out.push(chars[start..i].iter().collect());
        } else if c.is_ascii_digit() || (c == '-' && next.is_some_and(|n| n.is_ascii_digit())) {
            let start = i;
            i += 1;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            out.push(chars[start..i].iter().collect());
        } else if c == '"' {
            let start = i;
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                i += 1;
            }
            i += 1;
            out.push(chars[start..i.min(chars.len())].iter().collect());
        } else {
            let rest: String = chars[i..chars.len().min(i + 3)].iter().collect();
            let token = ["::=", "...", ".."]
                .into_iter()
                .find(|t| rest.starts_with(t))
                .map_or_else(|| c.to_string(), str::to_owned);
            i += token.chars().count();
            out.push(token);
        }
    }
    out
}

fn is_type_name(token: &str) -> bool {
    token.chars().next().is_some_and(char::is_uppercase)
        // All capitals: an information object class.
        && token.chars().any(char::is_lowercase)
}

impl Module {
    pub fn parse(text: &str) -> Result<Self, Fail> {
        let tokens = tokenize(text);
        let definitions = tokens
            .iter()
            .position(|t| t == "DEFINITIONS")
            .ok_or("no DEFINITIONS")?;
        let begin = tokens.iter().position(|t| t == "BEGIN").ok_or("no BEGIN")?;
        let name = tokens.first().ok_or("empty module")?.clone();
        let tagging = if tokens[definitions..begin].iter().any(|t| t == "IMPLICIT") {
            Tagging::Implicit
        } else {
            Tagging::Explicit
        };
        let mut assignments = BTreeMap::new();
        let mut values = BTreeMap::new();
        for i in begin..tokens.len() {
            if tokens[i] != "::=" {
                continue;
            }
            let left = &tokens[i - 1];
            // `name Type ::= value` assigns a value, not a type.
            let before = &tokens[i - 2];
            if before.chars().next().is_some_and(char::is_lowercase) {
                if let Ok(value) = tokens[i + 1].parse() {
                    values.insert(before.clone(), value);
                }
            } else if is_type_name(left) {
                assignments.insert(left.clone(), i + 1);
            }
        }
        Ok(Self {
            name,
            tagging,
            tokens,
            assignments,
            values,
        })
    }

    pub fn type_of(&self, name: &str) -> Result<Type, Fail> {
        let start = *self.assignments.get(name).ok_or("no such type")?;
        let mut parser = Parser {
            module: self,
            at: start,
        };
        parser
            .ty()
            .map_err(|e| format!("{}.{name}: {e}", self.name).into())
    }
}

struct Parser<'a> {
    module: &'a Module,
    at: usize,
}

impl Parser<'_> {
    fn peek(&self) -> &str {
        self.module.tokens.get(self.at).map_or("", String::as_str)
    }

    fn bump(&mut self) -> String {
        let token = self.peek().to_owned();
        self.at += 1;
        token
    }

    fn eat(&mut self, token: &str) -> bool {
        let found = self.peek() == token;
        if found {
            self.at += 1;
        }
        found
    }

    fn expect(&mut self, token: &str) -> Result<(), Fail> {
        if self.eat(token) {
            Ok(())
        } else {
            Err(format!("expected {token}, found {}", self.peek()).into())
        }
    }

    fn tag(&mut self) -> Result<Option<Tag>, Fail> {
        if !self.eat("[") {
            return Ok(None);
        }
        let class = match self.peek() {
            "APPLICATION" => Class::Application,
            "UNIVERSAL" => Class::Universal,
            "PRIVATE" => Class::Private,
            _ => Class::Context,
        };
        if class != Class::Context {
            self.bump();
        }
        let number = self.bump().parse()?;
        self.expect("]")?;
        let tagging = if self.eat("IMPLICIT") {
            Tagging::Implicit
        } else if self.eat("EXPLICIT") {
            Tagging::Explicit
        } else {
            self.module.tagging
        };
        Ok(Some(Tag {
            class,
            number,
            tagging,
        }))
    }

    fn ty(&mut self) -> Result<Type, Fail> {
        let tag = self.tag()?;
        let mut constraint = Constraint::default();
        let word = self.bump();
        let kind = match word.as_str() {
            "BOOLEAN" => Kind::Boolean,
            "NULL" => Kind::Null,
            "INTEGER" => Kind::Integer(self.named()?.0),
            "ENUMERATED" => {
                let (named, extensible) = self.named()?;
                // X.680 §20: without an extension marker, only the named values are values.
                if !extensible {
                    constraint.values = named.iter().map(|(_, v)| (Some(*v), Some(*v))).collect();
                }
                Kind::Enumerated(named)
            }
            "BIT" => {
                self.expect("STRING")?;
                Kind::BitString(self.named()?.0)
            }
            "OCTET" => {
                self.expect("STRING")?;
                Kind::OctetString
            }
            "OBJECT" => {
                self.expect("IDENTIFIER")?;
                Kind::ObjectIdentifier
            }
            // X.680 §8.4, table 1.
            "UTF8String" => Kind::Text(12),
            "UTCTime" => Kind::Text(23),
            "GeneralizedTime" => Kind::Text(24),
            "GraphicString" => Kind::Text(25),
            "VisibleString" => Kind::Text(26),
            "EXTERNAL" => Kind::Raw(Some(8)),
            "ANY" => Kind::Raw(None),
            "EMBEDDED" => {
                self.expect("PDV")?;
                Kind::Raw(Some(11))
            }
            "CHOICE" => Kind::Choice(self.members()?),
            "SEQUENCE" | "SET" => {
                if self.eat("SIZE") {
                    self.constraint_body(&mut constraint, true)?;
                }
                if self.eat("OF") {
                    Kind::SequenceOf(Box::new(self.ty()?))
                } else {
                    Kind::Sequence(self.members()?)
                }
            }
            name if name.chars().next().is_some_and(char::is_alphabetic) => {
                if self.eat(".") {
                    // `Module.Type` is a reference; `CLASS.&field` is an open type.
                    let field = self.bump();
                    if field.starts_with('&') {
                        Kind::Raw(None)
                    } else {
                        Kind::Reference(field)
                    }
                } else {
                    Kind::Reference(name.to_owned())
                }
            }
            other => return Err(format!("unexpected {other}").into()),
        };
        while self.peek() == "(" {
            self.constraint_body(&mut constraint, false)?;
        }
        Ok(Type {
            tag,
            kind,
            constraint,
        })
    }

    /// Named numbers or enumerations, and whether an extension marker is among them.
    fn named(&mut self) -> Result<(Vec<(String, i64)>, bool), Fail> {
        let mut out = Vec::new();
        let mut extensible = false;
        if !self.eat("{") {
            return Ok((out, extensible));
        }
        while !self.eat("}") {
            if self.eat("...") {
                extensible = true;
                continue;
            }
            if self.eat(",") {
                continue;
            }
            let name = self.bump();
            self.expect("(")?;
            let value = self.bump().parse()?;
            self.expect(")")?;
            out.push((name, value));
        }
        Ok((out, extensible))
    }

    fn members(&mut self) -> Result<Vec<Member>, Fail> {
        self.expect("{")?;
        let mut out = Vec::new();
        while !self.eat("}") {
            if self.eat(",") || self.eat("...") {
                continue;
            }
            let name = self.bump();
            let ty = self.ty()?;
            let optional = self.eat("OPTIONAL");
            let default = if self.eat("DEFAULT") {
                Some(self.default_value())
            } else {
                None
            };
            out.push(Member {
                name,
                ty,
                optional,
                default,
            });
        }
        Ok(out)
    }

    fn default_value(&mut self) -> String {
        let mut depth = 0;
        let mut words = Vec::new();
        loop {
            let token = self.peek();
            if depth == 0 && (token == "," || token == "}") {
                break;
            }
            depth += i32::from(token == "{") - i32::from(token == "}");
            words.push(self.bump());
        }
        words.join(" ")
    }

    fn bound(&self, token: &str) -> Result<Option<i64>, Fail> {
        if token == "MIN" || token == "MAX" {
            return Ok(None);
        }
        if let Ok(value) = token.parse() {
            return Ok(Some(value));
        }
        self.module
            .values
            .get(token)
            .map(|v| Some(*v))
            .ok_or_else(|| format!("unknown bound {token}").into())
    }

    /// One parenthesis group: `(a..b | c, ...)`, `(SIZE(...))`, `(FROM(...))`.
    fn constraint_body(&mut self, out: &mut Constraint, size: bool) -> Result<(), Fail> {
        self.expect("(")?;
        let mut ranges = Ranges::new();
        let mut extensible = false;
        loop {
            match self.peek() {
                ")" => {
                    self.bump();
                    break;
                }
                "..." => {
                    self.bump();
                    extensible = true;
                }
                "|" | "," | "^" => {
                    self.bump();
                }
                "SIZE" => {
                    self.bump();
                    self.constraint_body(out, true)?;
                }
                "FROM" => {
                    self.bump();
                    self.skip_group()?;
                }
                "{" | "@" | "&" => self.skip_group()?,
                "" => return Err("unterminated constraint".into()),
                _ => {
                    let low = self.bump();
                    let low = self.bound(&low)?;
                    let high = if self.eat("..") {
                        let high = self.bump();
                        self.bound(&high)?
                    } else {
                        low
                    };
                    ranges.push((low, high));
                }
            }
        }
        if size {
            out.sizes.extend(ranges);
            out.sizes_extensible |= extensible;
        } else {
            out.values.extend(ranges);
            out.values_extensible |= extensible;
        }
        Ok(())
    }

    /// Skip a balanced group of `(...)` or `{...}`, or a stray token.
    fn skip_group(&mut self) -> Result<(), Fail> {
        let mut depth = 0;
        loop {
            let token = self.bump();
            match token.as_str() {
                "(" | "{" => depth += 1,
                ")" | "}" => depth -= 1,
                "" => return Err("unterminated group".into()),
                _ => {}
            }
            if depth <= 0 {
                return Ok(());
            }
        }
    }
}
