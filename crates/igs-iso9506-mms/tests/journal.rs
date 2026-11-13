// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! ReadJournal (ISO 9506-2 clause 23.2; IEC 61850-8-1 clause 17.3, for the log services of task Q5): a server that holds a
//! domain's journal answers the filters of the request, and a client reads them through its typed service. Phase N of the plan
//! (journals), decision D-048.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::Duration;

use igs_iso9506_mms::client::{in_scope_capabilities, Client, ClientConfig, Reconnect};
use igs_iso9506_mms::server::{Server, ServerConfig};
use igs_iso9506_mms::vmd::{Identity, Name, Target, Vmd};
use igs_iso9506_mms_codec::generated::types::{
    ApplicationReference, Data, EntryContent, EntryContentEntryForm, EntryContentEntryFormData,
    Identifier, JournalEntry, JournalVariable, MMS255String, ObjectName, ObjectNameDomainSpecific,
    ReadJournalRequest, ReadJournalRequestEntryToStartAfter,
    ReadJournalRequestRangeStartSpecification, ReadJournalRequestRangeStopSpecification, TimeOfDay,
};
use igs_iso9506_mms_codec::mms::profile::{Model, Profile};
use igs_iso9506_mms_link::config::LinkConfig;
use tokio::time::timeout;

const ANSWER: Duration = Duration::from_secs(10);

fn name(text: &str) -> Name {
    Name::new(text).expect("a valid name")
}

fn journal_name(item: &str) -> ObjectName {
    ObjectName::DomainSpecific(ObjectNameDomainSpecific {
        domain_id: Identifier(String::from("LD1")),
        item_id: Identifier(item.to_string()),
    })
}

/// An entry with its identifier, its time of day in seconds of day 0, and one variable of the tag and value.
fn entry(id: u8, seconds: u32, tag: &str, value: i128) -> JournalEntry {
    JournalEntry {
        entry_identifier: vec![0, 0, 0, 0, 0, 0, 0, id],
        originating_application: ApplicationReference {
            ap_title: None,
            ap_invocation_id: None,
            ae_qualifier: None,
            ae_invocation_id: None,
        },
        entry_content: EntryContent {
            occurrence_time: TimeOfDay::from_milliseconds_and_day(seconds * 1000, 0)
                .expect("a time of day"),
            entry_form: EntryContentEntryForm::Data(EntryContentEntryFormData {
                event: None,
                list_of_variables: Some(vec![JournalVariable {
                    variable_tag: MMS255String(tag.to_string()),
                    value_specification: Data::Integer(value),
                }]),
            }),
        },
    }
}

/// A domain LD1 with the journal LOG1, holding four entries at 10, 20, 30 and 40 seconds.
fn vmd() -> Vmd {
    let mut vmd = Vmd::new(Identity {
        vendor: "igs".to_string(),
        model: "journal".to_string(),
        revision: "1".to_string(),
    });
    vmd.add_domain(name("LD1")).expect("the domain is added");
    let target = Target::in_domain(name("LD1"), name("LOG1"));
    vmd.define_journal(&target, 8)
        .expect("the journal is defined");
    vmd.append_journal(&target, entry(1, 10, "V", 1)).unwrap();
    vmd.append_journal(&target, entry(2, 20, "A", 2)).unwrap();
    vmd.append_journal(&target, entry(3, 30, "V", 3)).unwrap();
    vmd.append_journal(&target, entry(4, 40, "A", 4)).unwrap();
    vmd
}

/// The IEC 61850 profile of an application that declares its log services (ReadJournal is then required, 8-1 table 128, c13).
fn logs_profile() -> Profile {
    Profile::iec61850(Model {
        logs: true,
        ..Model::default()
    })
}

async fn connected() -> (Server, Client) {
    let server_config = ServerConfig {
        profile: logs_profile(),
        ..ServerConfig::new(LinkConfig::default())
    };
    let server = Server::bind("127.0.0.1:0", server_config, vmd())
        .await
        .expect("the server binds");
    let address = server.local_address().to_string();
    let config = ClientConfig {
        reconnect: Reconnect::Never,
        profile: logs_profile(),
        ..ClientConfig::new(LinkConfig::default(), in_scope_capabilities())
    };
    let (client, _events) = timeout(ANSWER, Client::connect(&address, config))
        .await
        .expect("the association is in time")
        .expect("the association is accepted");
    (server, client)
}

fn request(item: &str) -> ReadJournalRequest {
    ReadJournalRequest {
        journal_name: journal_name(item),
        range_start_specification: None,
        range_stop_specification: None,
        list_of_variables: None,
        entry_to_start_after: None,
    }
}

fn identifiers(entries: &[JournalEntry]) -> Vec<u8> {
    entries
        .iter()
        .map(|entry| *entry.entry_identifier.last().expect("an identifier"))
        .collect()
}

#[tokio::test]
async fn the_entries_of_a_journal_are_read_in_the_order_they_were_entered() {
    let (_server, client) = connected().await;
    let answer = timeout(ANSWER, client.read_journal(request("LOG1")))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(identifiers(&answer.list_of_journal_entry), [1, 2, 3, 4]);
    assert_eq!(answer.more_follows, Some(false));
}

#[tokio::test]
async fn a_time_range_selects_the_entries_from_its_start_to_its_stop_included() {
    let (_server, client) = connected().await;
    let mut asked = request("LOG1");
    asked.range_start_specification =
        Some(ReadJournalRequestRangeStartSpecification::StartingTime(
            TimeOfDay::from_milliseconds_and_day(20_000, 0).unwrap(),
        ));
    asked.range_stop_specification = Some(ReadJournalRequestRangeStopSpecification::EndingTime(
        TimeOfDay::from_milliseconds_and_day(30_000, 0).unwrap(),
    ));
    let answer = timeout(ANSWER, client.read_journal(asked))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(identifiers(&answer.list_of_journal_entry), [2, 3]);
}

#[tokio::test]
async fn the_number_of_entries_limits_the_answer_and_its_sign_gives_the_order() {
    let (_server, client) = connected().await;
    let mut first = request("LOG1");
    first.range_stop_specification =
        Some(ReadJournalRequestRangeStopSpecification::NumberOfEntries(
            igs_iso9506_mms_codec::generated::types::Integer32(2),
        ));
    let answer = timeout(ANSWER, client.read_journal(first))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(identifiers(&answer.list_of_journal_entry), [1, 2]);
    assert_eq!(answer.more_follows, Some(true), "two entries are left out");

    let mut last = request("LOG1");
    last.range_stop_specification =
        Some(ReadJournalRequestRangeStopSpecification::NumberOfEntries(
            igs_iso9506_mms_codec::generated::types::Integer32(-2),
        ));
    let answer = timeout(ANSWER, client.read_journal(last))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        identifiers(&answer.list_of_journal_entry),
        [4, 3],
        "the newest first"
    );
}

#[tokio::test]
async fn the_list_of_variables_keeps_the_entries_that_hold_one_of_its_tags() {
    let (_server, client) = connected().await;
    let mut asked = request("LOG1");
    asked.list_of_variables = Some(vec!["A".to_string()]);
    let answer = timeout(ANSWER, client.read_journal(asked))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(identifiers(&answer.list_of_journal_entry), [2, 4]);
}

#[tokio::test]
async fn the_entry_to_start_after_is_skipped_and_an_entry_not_held_starts_at_its_time() {
    let (_server, client) = connected().await;
    let mut after = request("LOG1");
    after.entry_to_start_after = Some(ReadJournalRequestEntryToStartAfter {
        time_specification: TimeOfDay::from_milliseconds_and_day(20_000, 0).unwrap(),
        entry_specification: vec![0, 0, 0, 0, 0, 0, 0, 2],
    });
    let answer = timeout(ANSWER, client.read_journal(after))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(identifiers(&answer.list_of_journal_entry), [3, 4]);

    // An entry that is not held: the entries from its time are returned, including those with the same time.
    let mut unknown = request("LOG1");
    unknown.entry_to_start_after = Some(ReadJournalRequestEntryToStartAfter {
        time_specification: TimeOfDay::from_milliseconds_and_day(25_000, 0).unwrap(),
        entry_specification: vec![9],
    });
    let answer = timeout(ANSWER, client.read_journal(unknown))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(identifiers(&answer.list_of_journal_entry), [3, 4]);
}

#[tokio::test]
async fn a_journal_that_is_not_held_is_refused() {
    let (_server, client) = connected().await;
    let answer = timeout(ANSWER, client.read_journal(request("LOG9")))
        .await
        .unwrap();
    assert!(answer.is_err(), "the journal does not exist: {answer:?}");
}

#[test]
fn a_journal_keeps_its_capacity_and_overwrites_its_oldest_entry() {
    let mut vmd = vmd();
    let target = Target::in_domain(name("LD1"), name("LOG1"));
    vmd.define_journal(&Target::in_domain(name("LD1"), name("LOG2")), 2)
        .unwrap();
    let small = Target::in_domain(name("LD1"), name("LOG2"));
    vmd.append_journal(&small, entry(1, 1, "V", 1)).unwrap();
    vmd.append_journal(&small, entry(2, 2, "V", 2)).unwrap();
    vmd.append_journal(&small, entry(3, 3, "V", 3)).unwrap();
    let held: Vec<u8> = vmd
        .journal(&small)
        .unwrap()
        .entries()
        .map(|e| *e.entry_identifier.last().unwrap())
        .collect();
    assert_eq!(held, [2, 3]);
    assert_eq!(vmd.journal(&target).unwrap().len(), 4);
}
