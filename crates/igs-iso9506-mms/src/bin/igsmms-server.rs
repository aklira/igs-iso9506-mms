// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! `igsmms-server`: a demonstration MMS server (task S3). It serves the VMD of a TOML file: its domains,
//! its named variables and its named variable lists. It is the device under test of the bench (`bench/`).
//! Its services are those of the server library (`igs_iso9506_mms::Server`).

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use igs_iso9506_mms::vmd::{Identity, MemoryVariable, Name, Target, Vmd};
use igs_iso9506_mms::{Server, ServerConfig};
use igs_iso9506_mms_codec::generated::types::{
    Data, DataAccessError, FloatingPoint, TypeDescription, TypeDescriptionFloatingPoint, Unsigned8,
};
use igs_iso9506_mms_link::config::LinkConfig;
use serde::Deserialize;

/// The command line of `igsmms-server`.
#[derive(Debug, Parser)]
#[command(
    name = "igsmms-server",
    version,
    about = "Demonstration MMS server: serves the domains, variables and lists of a TOML file.",
    long_about = "MMS server over TCP (RFC 1006). It serves the VMD described by the configuration file: \
                  the identity, the domains, the named variables and the named variable lists. Each connection \
                  is one association. The server runs until it is stopped (Ctrl-C). The format of the file is \
                  in docs/igsmms-server.md."
)]
struct Cli {
    /// The address to listen on, as host:port. RFC 1006 uses TCP port 102.
    #[arg(short, long, value_name = "ADDRESS", default_value = "127.0.0.1:102")]
    listen: String,

    /// The configuration file: the VMD to serve. Without it, the server serves an empty VMD.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// The associations held at once; a connection beyond them is closed.
    #[arg(
        long,
        value_name = "COUNT",
        default_value_t = 64,
        value_parser = clap::value_parser!(u32).range(1..=10_000)
    )]
    max_associations: u32,

    /// The deepest nesting of data structures the server proposes (ISO 9506-1 §8.2.1.1.4). The server
    /// negotiates the nesting with the client, which may propose less.
    #[arg(
        long,
        value_name = "LEVEL",
        default_value_t = 2,
        value_parser = clap::value_parser!(u8).range(2..=127)
    )]
    nesting: u8,
}

/// The configuration file. Unknown keys are refused, so that a misspelt key is not silently ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    identity: IdentityConfig,
    #[serde(default)]
    domain: Vec<DomainConfig>,
    #[serde(default)]
    variable: Vec<VariableConfig>,
    #[serde(default)]
    list: Vec<ListConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityConfig {
    vendor: String,
    model: String,
    revision: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DomainConfig {
    name: String,
}

/// The types a variable of the file can have: the simple types of the model, with their sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Kind {
    Boolean,
    Integer,
    Unsigned,
    Float,
    VisibleString,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariableConfig {
    name: String,
    /// The domain of the variable; absent for a VMD-specific variable.
    domain: Option<String>,
    #[serde(rename = "type")]
    kind: Kind,
    /// The width in bits of an integer or an unsigned variable.
    bits: Option<i64>,
    /// The number of characters of a visible string.
    size: Option<i64>,
    value: toml::Value,
    writable: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListConfig {
    name: String,
    /// The domain of the list; absent for a VMD-specific list.
    domain: Option<String>,
    /// The members: `name` for a VMD-specific variable, `domain/name` for a domain-specific one.
    members: Vec<String>,
}

/// Why the configuration file is refused, with the object it concerns.
#[derive(Debug)]
struct ConfigError(String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn invalid(context: &str, message: impl std::fmt::Display) -> ConfigError {
    ConfigError(format!("{context}: {message}"))
}

fn name(context: &str, text: &str) -> Result<Name, ConfigError> {
    Name::new(text).map_err(|error| invalid(context, error))
}

/// The type description and the value of a variable of the file.
fn typed(variable: &VariableConfig) -> Result<(TypeDescription, Data), ConfigError> {
    let context = format!("variable {}", variable.name);
    match variable.kind {
        Kind::Boolean => {
            let value = variable
                .value
                .as_bool()
                .ok_or_else(|| invalid(&context, "a boolean value is expected"))?;
            Ok((TypeDescription::Boolean, Data::Boolean(value)))
        }
        Kind::Integer => {
            let bits = variable
                .bits
                .ok_or_else(|| invalid(&context, "an integer needs `bits`"))?;
            let value = variable
                .value
                .as_integer()
                .ok_or_else(|| invalid(&context, "an integer value is expected"))?;
            Ok((
                TypeDescription::Integer(Unsigned8(bits)),
                Data::Integer(i128::from(value)),
            ))
        }
        Kind::Unsigned => {
            let bits = variable
                .bits
                .ok_or_else(|| invalid(&context, "an unsigned needs `bits`"))?;
            let value = variable
                .value
                .as_integer()
                .and_then(|value| u128::try_from(value).ok())
                .ok_or_else(|| invalid(&context, "a value of zero or more is expected"))?;
            Ok((
                TypeDescription::Unsigned(Unsigned8(bits)),
                Data::Unsigned(value),
            ))
        }
        Kind::Float => {
            // The single precision format: the exponent width 8, then the four octets of the IEEE value.
            let value = variable
                .value
                .as_float()
                .ok_or_else(|| invalid(&context, "a floating-point value is expected"))?;
            let mut octets = vec![8u8];
            octets.extend_from_slice(&(value as f32).to_be_bytes());
            Ok((
                TypeDescription::FloatingPoint(TypeDescriptionFloatingPoint {
                    format_width: Unsigned8(32),
                    exponent_width: Unsigned8(8),
                }),
                Data::FloatingPoint(FloatingPoint(octets)),
            ))
        }
        Kind::VisibleString => {
            let size = variable
                .size
                .ok_or_else(|| invalid(&context, "a visible string needs `size`"))?;
            let text = variable
                .value
                .as_str()
                .ok_or_else(|| invalid(&context, "a string value is expected"))?;
            Ok((
                TypeDescription::VisibleString(igs_iso9506_mms_codec::generated::types::Integer32(
                    size,
                )),
                Data::VisibleString(text.to_string()),
            ))
        }
    }
}

/// The target of a member of a list: `name`, or `domain/name`.
fn member_target(context: &str, text: &str) -> Result<Target, ConfigError> {
    match text.split_once('/') {
        Some((domain, item)) => Ok(Target::in_domain(
            name(context, domain)?,
            name(context, item)?,
        )),
        None => Ok(Target::vmd(name(context, text)?)),
    }
}

/// Builds the VMD of the file. Each object is checked as the model checks it.
fn build(config: Config) -> Result<Vmd, ConfigError> {
    let identity = Identity {
        vendor: config.identity.vendor,
        model: config.identity.model,
        revision: config.identity.revision,
    };
    let mut vmd = Vmd::new(identity);
    for domain in &config.domain {
        let context = format!("domain {}", domain.name);
        vmd.add_domain(name(&context, &domain.name)?)
            .map_err(|error| invalid(&context, format!("{error:?}")))?;
    }
    for variable in &config.variable {
        let context = format!("variable {}", variable.name);
        let item = name(&context, &variable.name)?;
        let target = match &variable.domain {
            Some(domain) => Target::in_domain(name(&context, domain)?, item),
            None => Target::vmd(item),
        };
        let (ty, value) = typed(variable)?;
        let object = MemoryVariable::new(ty, value, variable.writable)
            .map_err(|error: DataAccessError| invalid(&context, format!("the value {error:?}")))?;
        vmd.add_variable(&target, Box::new(object))
            .map_err(|error| invalid(&context, format!("{error:?}")))?;
    }
    for list in &config.list {
        let context = format!("list {}", list.name);
        let item = name(&context, &list.name)?;
        let target = match &list.domain {
            Some(domain) => Target::in_domain(name(&context, domain)?, item),
            None => Target::vmd(item),
        };
        let members = list
            .members
            .iter()
            .map(|member| member_target(&context, member))
            .collect::<Result<Vec<Target>, ConfigError>>()?;
        vmd.define_list(&target, members)
            .map_err(|error| invalid(&context, format!("{error:?}")))?;
    }
    Ok(vmd)
}

/// Reads and builds the VMD of a configuration file, or an empty VMD without one.
fn load(path: Option<&PathBuf>) -> Result<Vmd, Box<dyn std::error::Error>> {
    let Some(path) = path else {
        return Ok(Vmd::new(Identity {
            vendor: "igs".to_string(),
            model: "igsmms-server".to_string(),
            revision: env!("CARGO_PKG_VERSION").to_string(),
        }));
    };
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let config: Config =
        toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(build(config)?)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let vmd = match load(cli.config.as_ref()) {
        Ok(vmd) => vmd,
        Err(error) => {
            eprintln!("igsmms-server: {error}");
            return ExitCode::FAILURE;
        }
    };
    let link = LinkConfig {
        nesting_level: cli.nesting,
        ..LinkConfig::default()
    };
    let config = ServerConfig {
        max_associations: usize::try_from(cli.max_associations).unwrap_or(usize::MAX),
        ..ServerConfig::new(link)
    };
    let server = match Server::bind(&cli.listen, config, vmd).await {
        Ok(server) => server,
        Err(error) => {
            eprintln!("igsmms-server: cannot listen on {}: {error}", cli.listen);
            return ExitCode::FAILURE;
        }
    };
    println!("igsmms-server: listening on {}", server.local_address());
    // The server runs until the process is stopped (Ctrl-C ends the process).
    std::future::pending::<()>().await;
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEMO: &str = r#"
        [identity]
        vendor = "igs"
        model = "demo"
        revision = "0.1"

        [[domain]]
        name = "demo"

        [[variable]]
        name = "speed"
        type = "integer"
        bits = 32
        value = 5
        writable = true

        [[variable]]
        domain = "demo"
        name = "temperature"
        type = "float"
        value = 21.5
        writable = false

        [[variable]]
        domain = "demo"
        name = "label"
        type = "visible-string"
        size = 3
        value = "igs"
        writable = true

        [[list]]
        name = "snapshot"
        domain = "demo"
        members = ["speed", "demo/temperature"]
    "#;

    fn parse(text: &str) -> Result<Vmd, String> {
        let config: Config = toml::from_str(text).map_err(|error| error.to_string())?;
        build(config).map_err(|error| error.to_string())
    }

    #[test]
    fn the_demo_file_builds_the_vmd_it_describes() {
        let vmd = parse(DEMO).unwrap();
        assert_eq!(vmd.identity().model, "demo");
        let speed = Target::vmd(Name::new("speed").unwrap());
        assert_eq!(vmd.read(&speed), Ok(Data::Integer(5)));
        let temperature = Target::in_domain(
            Name::new("demo").unwrap(),
            Name::new("temperature").unwrap(),
        );
        assert!(matches!(vmd.read(&temperature), Ok(Data::FloatingPoint(_))));
        let list = Target::in_domain(Name::new("demo").unwrap(), Name::new("snapshot").unwrap());
        assert_eq!(vmd.list_members(&list).unwrap().len(), 2);
    }

    #[test]
    fn a_value_out_of_its_type_is_refused_with_the_variable_named() {
        let text = DEMO.replace("value = 5", "value = 5000000000");
        let error = parse(&text).unwrap_err();
        assert!(error.contains("variable speed"), "{error}");
        let text = DEMO.replace("value = \"igs\"", "value = \"igsmms\"");
        assert!(parse(&text).unwrap_err().contains("variable label"));
    }

    #[test]
    fn the_default_limit_is_the_library_one() {
        let cli = Cli::parse_from(["igsmms-server"]);
        assert_eq!(
            usize::try_from(cli.max_associations).unwrap(),
            igs_iso9506_mms::server::DEFAULT_MAX_ASSOCIATIONS
        );
    }

    #[test]
    fn an_unknown_key_is_refused() {
        let text = DEMO.replace("writable = true", "writable = true\nwritabel = true");
        assert!(parse(&text).is_err());
    }

    #[test]
    fn a_list_names_a_member_that_exists() {
        let text = DEMO.replace(
            "members = [\"speed\", \"demo/temperature\"]",
            "members = [\"missing\"]",
        );
        assert!(parse(&text).unwrap_err().contains("list snapshot"));
    }

    #[test]
    fn an_unsigned_needs_a_value_of_zero_or_more() {
        let text = r#"
            [identity]
            vendor = "igs"
            model = "m"
            revision = "1"
            [[variable]]
            name = "count"
            type = "unsigned"
            bits = 8
            value = -1
            writable = false
        "#;
        assert!(parse(text).unwrap_err().contains("zero or more"));
    }

    #[test]
    fn a_variable_without_its_size_is_refused() {
        let text = DEMO.replace("size = 3", "");
        assert!(parse(&text).unwrap_err().contains("needs `size`"));
    }
}
