// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! `igsmms-client`: a command line client of the MMS stack (task T3). It connects to a server,
//! identifies it, lists the names of its objects, reads and writes variables, and shows their types.
//! With `--trace`, the decoded PDUs and the connection events are printed on standard error.

use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use igs_iso9506_mms::client::in_scope_capabilities;
use igs_iso9506_mms::{Client, ClientConfig, ConnectionState, Event, Events, Reconnect};
use igs_iso9506_mms_codec::generated::types::{
    AccessResult, GetNameListRequest, GetNameListRequestObjectScope,
    GetVariableAccessAttributesRequest, ObjectClass, ObjectClassBasicObjectClass, ReadRequest,
    VariableAccessSpecification, VariableAccessSpecificationListOfVariableItem,
    VariableSpecification, WriteRequest, WriteResponseItemItem,
};
use igs_iso9506_mms_codec::mms::profile::{Model, Profile};
use igs_iso9506_mms_codec::mms::{Data, Identifier, ObjectName, ObjectNameDomainSpecific};
use igs_iso9506_mms_link::config::LinkConfig;

/// The command line of `igsmms-client`.
#[derive(Debug, Parser)]
#[command(
    name = "igsmms-client",
    version,
    about = "MMS client: identify a server, list names, read and write variables.",
    long_about = "MMS client over TCP (RFC 1006). Each command opens one association with the server, \
                  runs the command, and closes the association. Results are printed on standard output; \
                  with --trace, the decoded PDUs and the connection events are printed on standard error."
)]
struct Cli {
    /// The server, as host:port. RFC 1006 uses TCP port 102.
    #[arg(short, long, global = true, default_value = "127.0.0.1:102")]
    server: String,

    /// Print the decoded PDUs and the connection events on standard error.
    #[arg(short, long, global = true)]
    trace: bool,

    /// Take the parameter CBBs proposed as negotiated, for a server that answers services without
    /// negotiating their CBBs (not conformant: see docs/capabilities.md, G8).
    #[arg(long, global = true)]
    lenient_parameter_cbbs: bool,

    /// The deepest nesting of data structures proposed (ISO 9506-1 §8.2.1.1.4). The TASE.2 minimum is
    /// 2; the reference server answers with deeper data, so the default is deeper.
    #[arg(
        long,
        global = true,
        value_name = "LEVEL",
        default_value_t = 6,
        value_parser = clap::value_parser!(u8).range(2..=127)
    )]
    nesting: u8,

    /// The application profile: TASE.2 (ISO 9506 limits) or IEC 61850-8-1 (clause 24; D-033). The
    /// IEC 61850 profile needs a nesting of six or more when logical nodes are declared.
    #[arg(long, global = true, value_name = "PROFILE", value_enum, default_value_t = ProfileChoice::Tase2)]
    profile: ProfileChoice,

    /// For the IEC 61850 profile: the logical-node model is declared (Table 127 and 128, c1 and c2).
    #[arg(long, global = true)]
    logical_nodes: bool,

    /// For the IEC 61850 profile: data sets are declared.
    #[arg(long, global = true)]
    data_sets: bool,

    /// For the IEC 61850 profile: arrays are declared in the data objects.
    #[arg(long, global = true)]
    arrays: bool,

    /// For the IEC 61850 profile: log services are declared (QueryLogByTime, QueryLogAfter), so ReadJournal is required.
    #[arg(long, global = true)]
    logs: bool,

    /// Seconds to wait for each answer before a request times out.
    #[arg(long, global = true, value_name = "SECONDS", default_value_t = 30)]
    timeout: u64,

    #[command(subcommand)]
    command: Command,
}

/// The commands of `igsmms-client`.
#[derive(Debug, Subcommand)]
enum Command {
    /// Identify the server: its vendor, model and revision.
    Identify,

    /// List the names of the objects of a class, following every page of the answer.
    Names {
        /// The class of the objects.
        #[arg(long, value_enum, default_value_t = Class::NamedVariable)]
        class: Class,

        /// The domain whose names are listed; the server's own names when absent.
        #[arg(long, value_name = "DOMAIN")]
        domain: Option<String>,
    },

    /// Read the value of a variable.
    Read {
        /// The name of the variable.
        name: String,

        /// The domain of the variable; the server's own variables when absent.
        #[arg(long, value_name = "DOMAIN")]
        domain: Option<String>,
    },

    /// Write a value to a variable.
    Write {
        /// The name of the variable.
        name: String,

        /// The value: true or false, an integer, or a string.
        value: String,

        /// The domain of the variable; the server's own variables when absent.
        #[arg(long, value_name = "DOMAIN")]
        domain: Option<String>,

        /// The kind of the value, read from it when absent.
        #[arg(long, value_enum)]
        kind: Option<Kind>,
    },

    /// Show the type, the address and whether the variable is deletable.
    Attributes {
        /// The name of the variable.
        name: String,

        /// The domain of the variable; the server's own variables when absent.
        #[arg(long, value_name = "DOMAIN")]
        domain: Option<String>,
    },
}

/// The classes of objects that `names` lists.
/// The application profile of the command line.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProfileChoice {
    /// ISO 9506 as TASE.2 uses it.
    Tase2,
    /// IEC 61850-8-1 clause 24, with the declared model of the command line.
    Iec61850,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Class {
    /// Named variables.
    NamedVariable,
    /// Named variable lists.
    NamedVariableList,
    /// Named types.
    NamedType,
    /// Domains: the first level of the server's objects.
    Domain,
}

impl Class {
    fn object_class(self) -> ObjectClass {
        let code = match self {
            Self::NamedVariable => ObjectClassBasicObjectClass::NAMED_VARIABLE,
            Self::NamedVariableList => ObjectClassBasicObjectClass::NAMED_VARIABLE_LIST,
            Self::NamedType => ObjectClassBasicObjectClass::NAMED_TYPE,
            Self::Domain => ObjectClassBasicObjectClass::DOMAIN,
        };
        ObjectClass::BasicObjectClass(code)
    }
}

/// The kinds of value that `write` takes.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum Kind {
    /// A boolean: true or false.
    Bool,
    /// An integer.
    Int,
    /// A string.
    Str,
}

/// The name of a variable, in its domain or in the server.
fn object_name(name: &str, domain: Option<&str>) -> ObjectName {
    match domain {
        Some(domain) => ObjectName::DomainSpecific(ObjectNameDomainSpecific {
            domain_id: Identifier(domain.to_string()),
            item_id: Identifier(name.to_string()),
        }),
        None => ObjectName::VmdSpecific(Identifier(name.to_string())),
    }
}

/// The access specification of one variable, by its name.
fn one_variable(name: &str, domain: Option<&str>) -> VariableAccessSpecification {
    VariableAccessSpecification::ListOfVariable(vec![
        VariableAccessSpecificationListOfVariableItem {
            variable_specification: VariableSpecification::Name(object_name(name, domain)),
            alternate_access: None,
        },
    ])
}

/// The scope of a name list: the domain's names, or the server's own.
fn scope(domain: Option<&str>) -> GetNameListRequestObjectScope {
    match domain {
        Some(domain) => {
            GetNameListRequestObjectScope::DomainSpecific(Identifier(domain.to_string()))
        }
        None => GetNameListRequestObjectScope::VmdSpecific,
    }
}

/// The value of a write, of the kind given, or of the kind its text suggests.
fn parse_value(kind: Option<Kind>, text: &str) -> Result<Data, String> {
    let invalid = |what: &str| format!("{text:?} is not {what}");
    match kind {
        Some(Kind::Bool) => text
            .parse::<bool>()
            .map(Data::Boolean)
            .map_err(|_| invalid("a boolean")),
        Some(Kind::Int) => text
            .parse::<i128>()
            .map(Data::Integer)
            .map_err(|_| invalid("an integer")),
        Some(Kind::Str) => Ok(Data::VisibleString(text.to_string())),
        None => Ok(match (text.parse::<bool>(), text.parse::<i128>()) {
            (Ok(value), _) => Data::Boolean(value),
            (_, Ok(value)) => Data::Integer(value),
            _ => Data::VisibleString(text.to_string()),
        }),
    }
}

/// A value of the data model, for display.
fn format_data(data: &Data) -> String {
    match data {
        Data::Boolean(value) => value.to_string(),
        Data::Integer(value) => value.to_string(),
        Data::Unsigned(value) => value.to_string(),
        Data::VisibleString(value) => format!("{value:?}"),
        Data::MMSString(value) => format!("{:?}", value.0),
        Data::OctetString(bytes) => bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
        Data::Array(items) => format!(
            "[{}]",
            items.iter().map(format_data).collect::<Vec<_>>().join(", ")
        ),
        Data::Structure(items) => format!(
            "{{{}}}",
            items.iter().map(format_data).collect::<Vec<_>>().join(", ")
        ),
        other => format!("{other:?}"),
    }
}

/// Runs one command against an open client.
async fn execute(client: &Client, command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::Identify => {
            let identity = client.identify().await?;
            println!("vendor: {}", identity.vendor_name.0);
            println!("model: {}", identity.model_name.0);
            println!("revision: {}", identity.revision.0);
        }
        Command::Names { class, domain } => {
            let mut after: Option<Identifier> = None;
            loop {
                let page = client
                    .get_name_list(GetNameListRequest {
                        object_class: class.object_class(),
                        object_scope: scope(domain.as_deref()),
                        continue_after: after.clone(),
                    })
                    .await?;
                for name in &page.list_of_identifier {
                    println!("{}", name.0);
                }
                // moreFollows is TRUE when absent (ISO 9506-2, GetNameList-Response).
                let more = page.more_follows.unwrap_or(true);
                match page.list_of_identifier.last() {
                    Some(last) if more => after = Some(last.clone()),
                    _ => break,
                }
            }
        }
        Command::Read { name, domain } => {
            let response = client
                .read(ReadRequest {
                    specification_with_result: None,
                    variable_access_specification: one_variable(&name, domain.as_deref()),
                })
                .await?;
            for result in &response.list_of_access_result {
                match result {
                    AccessResult::Success(data) => println!("{}", format_data(data)),
                    AccessResult::Failure(error) => println!("failure: {error:?}"),
                }
            }
        }
        Command::Write {
            name,
            value,
            domain,
            kind,
        } => {
            let data = parse_value(kind, &value)?;
            let response = client
                .write(WriteRequest {
                    variable_access_specification: one_variable(&name, domain.as_deref()),
                    list_of_data: vec![data],
                })
                .await?;
            for item in &response.0 {
                match item {
                    WriteResponseItemItem::Success => println!("written"),
                    WriteResponseItemItem::Failure(error) => println!("failure: {error:?}"),
                }
            }
        }
        Command::Attributes { name, domain } => {
            let response = client
                .get_variable_access_attributes(GetVariableAccessAttributesRequest::Name(
                    object_name(&name, domain.as_deref()),
                ))
                .await?;
            println!("deletable: {}", response.mms_deletable);
            println!("address: {:?}", response.address);
            println!("type: {:?}", response.type_description);
        }
    }
    Ok(())
}

/// Prints the events of the connection: the reports always, the states and the traces with `--trace`.
async fn print_events(mut events: Events, trace: bool) {
    while let Some(event) = events.next().await {
        let closed = matches!(event, Event::State(ConnectionState::Closed));
        match event {
            Event::Report(report) => println!("report: {report:?}"),
            Event::State(state) if trace => eprintln!("[state] {state:?}"),
            Event::Trace(text) if trace => eprintln!("[trace] {text}"),
            _ => {}
        }
        if closed {
            break;
        }
    }
}

/// Connects, runs the command, and closes the association.
async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let link = LinkConfig {
        nesting_level: cli.nesting,
        request_timeout: Duration::from_secs(cli.timeout),
        ..LinkConfig::default()
    };
    let profile = match cli.profile {
        ProfileChoice::Tase2 => Profile::TASE2,
        ProfileChoice::Iec61850 => Profile::iec61850(Model {
            logical_nodes: cli.logical_nodes,
            data_sets: cli.data_sets,
            arrays: cli.arrays,
            logs: cli.logs,
        }),
    };
    let config = ClientConfig {
        reconnect: Reconnect::Never,
        trace: cli.trace,
        lenient_parameter_cbbs: cli.lenient_parameter_cbbs,
        profile,
        ..ClientConfig::new(link, in_scope_capabilities())
    };
    let (client, events) = Client::connect(&cli.server, config).await?;
    let printer = tokio::spawn(print_events(events, cli.trace));
    let outcome = execute(&client, cli.command).await;
    // After an error the association is aborted: the orderly close would wait for a release.
    let closed = match outcome {
        Ok(()) => client.close().await,
        Err(_) => client.abort().await,
    };
    let _ = printer.await;
    outcome?;
    Ok(closed?)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("igsmms-client: {error}");
            if error.to_string().contains("negotiation") {
                eprintln!(
                    "hint: the negotiated CBBs do not allow this request; a server that answers it \
                     anyway can be used with --lenient-parameter-cbbs (docs/capabilities.md, G8)"
                );
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_line_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn a_value_takes_the_kind_its_text_suggests() {
        assert!(matches!(parse_value(None, "true"), Ok(Data::Boolean(true))));
        assert!(matches!(parse_value(None, "-42"), Ok(Data::Integer(-42))));
        assert!(matches!(
            parse_value(None, "hello"),
            Ok(Data::VisibleString(_))
        ));
        assert!(parse_value(Some(Kind::Int), "x").is_err());
    }

    #[test]
    fn data_is_shown_with_its_structure() {
        let data = Data::Structure(vec![Data::Integer(1), Data::VisibleString("a".to_string())]);
        assert_eq!(format_data(&data), "{1, \"a\"}");
    }

    #[test]
    fn a_domain_gives_a_domain_specific_name() {
        assert!(matches!(
            object_name("item", Some("dom")),
            ObjectName::DomainSpecific(_)
        ));
        assert!(matches!(
            object_name("item", None),
            ObjectName::VmdSpecific(_)
        ));
    }
}
