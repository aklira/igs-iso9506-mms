// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The MMS file services of IEC 61850-8-1 clause 23 (task N8, decision D-049): GetFile through FileOpen, FileRead and FileClose;
//! GetFileAttributeValues and the listing through FileDirectory; DeleteFile through FileDelete. The server holds a virtual file store.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::Duration;

use igs_iso9506_mms::client::{in_scope_capabilities, Client, ClientConfig, Reconnect};
use igs_iso9506_mms::server::{Server, ServerConfig};
use igs_iso9506_mms::vmd::{Identity, Vmd};
use igs_iso9506_mms_codec::generated::types::{FileDirectoryRequest, FileName};
use igs_iso9506_mms_codec::mms::profile::{Model, Profile};
use igs_iso9506_mms_link::config::LinkConfig;
use tokio::time::timeout;

const ANSWER: Duration = Duration::from_secs(10);

/// A file of 5000 octets, which one FileRead answer (2048 octets) does not carry: three reads.
fn large_content() -> Vec<u8> {
    (0..5000u32).map(|i| (i % 251) as u8).collect()
}

fn vmd() -> Vmd {
    let mut vmd = Vmd::new(Identity {
        vendor: "igs".to_string(),
        model: "files".to_string(),
        revision: "1".to_string(),
    });
    vmd.add_file(
        &["LD", "LD1", "COMTRADE", "fault.cfg"],
        large_content(),
        Some("20261113120000Z"),
    );
    vmd.add_file(
        &["LD", "LD1", "COMTRADE", "fault.dat"],
        b"sample".to_vec(),
        None,
    );
    vmd.add_file(&["LD", "LD2", "readme.txt"], b"other device".to_vec(), None);
    vmd
}

/// The IEC 61850 profile of an application that declares the file services (GetFile and GetFileAttributeValues).
fn files_profile() -> Profile {
    Profile::iec61850(Model {
        files: true,
        ..Model::default()
    })
}

async fn connected() -> (Server, Client) {
    let server_config = ServerConfig {
        profile: files_profile(),
        ..ServerConfig::new(LinkConfig::default())
    };
    let server = Server::bind("127.0.0.1:0", server_config, vmd())
        .await
        .expect("the server binds");
    let address = server.local_address().to_string();
    let config = ClientConfig {
        reconnect: Reconnect::Never,
        profile: files_profile(),
        ..ClientConfig::new(LinkConfig::default(), in_scope_capabilities())
    };
    let (client, _events) = timeout(ANSWER, Client::connect(&address, config))
        .await
        .expect("the association is in time")
        .expect("the association is accepted");
    (server, client)
}

fn name(parts: &[&str]) -> FileName {
    FileName(parts.iter().map(|part| (*part).to_string()).collect())
}

#[tokio::test]
async fn get_file_reads_a_file_in_parts_and_returns_its_content() {
    let (_server, client) = connected().await;
    let content = timeout(
        ANSWER,
        client.get_file(&["LD", "LD1", "COMTRADE", "fault.cfg"]),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(content, large_content());
}

#[tokio::test]
async fn file_directory_lists_the_files_under_a_specification_in_order_and_continues_after_a_name()
{
    let (_server, client) = connected().await;
    let listed = timeout(
        ANSWER,
        client.file_directory(FileDirectoryRequest {
            file_specification: Some(name(&["LD", "LD1"])),
            continue_after: None,
        }),
    )
    .await
    .unwrap()
    .unwrap();
    let names: Vec<Vec<String>> = listed
        .list_of_directory_entry
        .iter()
        .map(|entry| entry.file_name.0.clone())
        .collect();
    assert_eq!(
        names,
        vec![
            vec!["LD", "LD1", "COMTRADE", "fault.cfg"],
            vec!["LD", "LD1", "COMTRADE", "fault.dat"],
        ]
    );
    assert_eq!(listed.more_follows, Some(false));

    let after = timeout(
        ANSWER,
        client.file_directory(FileDirectoryRequest {
            file_specification: Some(name(&["LD", "LD1"])),
            continue_after: Some(name(&["LD", "LD1", "COMTRADE", "fault.cfg"])),
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(after.list_of_directory_entry.len(), 1);
}

#[tokio::test]
async fn the_attributes_of_a_file_are_its_size_and_its_last_modification() {
    let (_server, client) = connected().await;
    let listed = timeout(
        ANSWER,
        client.file_directory(FileDirectoryRequest {
            file_specification: Some(name(&["LD", "LD1", "COMTRADE", "fault.cfg"])),
            continue_after: None,
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(listed.list_of_directory_entry.len(), 1);
    let attributes = &listed.list_of_directory_entry[0].file_attributes;
    assert_eq!(attributes.size_of_file.0, 5000);
    assert_eq!(attributes.last_modified.as_deref(), Some("20261113120000Z"));
}

#[tokio::test]
async fn a_file_that_does_not_exist_is_refused_and_a_deleted_file_is_gone() {
    let (_server, client) = connected().await;
    let missing = timeout(ANSWER, client.get_file(&["LD", "LD9", "none.cfg"]))
        .await
        .unwrap();
    assert!(missing.is_err(), "the file does not exist: {missing:?}");

    timeout(
        ANSWER,
        client.file_delete(igs_iso9506_mms_codec::generated::types::FileDeleteRequest(
            name(&["LD", "LD2", "readme.txt"]),
        )),
    )
    .await
    .unwrap()
    .unwrap();
    let gone = timeout(ANSWER, client.get_file(&["LD", "LD2", "readme.txt"]))
        .await
        .unwrap();
    assert!(gone.is_err(), "the deleted file is refused: {gone:?}");
}

#[test]
fn a_file_that_is_being_read_cannot_be_deleted_and_a_position_beyond_its_end_is_refused() {
    use igs_iso9506_mms::vmd::FileError;
    let mut vmd = vmd();
    let store = vmd.files_mut();
    let path = name(&["LD", "LD2", "readme.txt"]).0;
    let frsm = store.open(&path, 0).unwrap();
    assert_eq!(store.delete(&path), Err(FileError::Busy));
    store.close(frsm).unwrap();
    assert_eq!(store.open(&path, 999), Err(FileError::PositionInvalid));
    assert_eq!(store.close(frsm), Err(FileError::NonExistent));
    store.delete(&path).unwrap();
    assert!(store.file(&path).is_none());
}
