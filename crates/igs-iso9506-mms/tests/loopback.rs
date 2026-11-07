// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The transport driver over an in-process loopback (task T1): a duplex stream stands for the network.
//! The connect timeout is tested on a paused clock.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::Duration;

use igs_iso9506_mms::{accept, connect, Error, Transport, CHANNEL_CAPACITY};
use igs_iso9506_mms_codec::transport::reason;
use igs_iso9506_mms_link::config::LinkConfig;
use igs_iso9506_mms_link::transport::Cause;
use tokio::io::duplex;
use tokio::time::{timeout, Instant};

/// Opens a connection over a loopback, with the given configurations for each end.
async fn open_with(
    initiator: LinkConfig,
    responder: LinkConfig,
) -> (Result<Transport, Error>, Result<Transport, Error>) {
    let (a, b) = duplex(1024);
    tokio::join!(connect(a, initiator), accept(b, responder))
}

async fn open() -> (Transport, Transport) {
    let (client, server) = open_with(LinkConfig::default(), LinkConfig::default()).await;
    (client.unwrap(), server.unwrap())
}

#[tokio::test]
async fn tsdus_flow_in_both_directions() {
    let (mut client, mut server) = open().await;
    client.send(b"hello".to_vec()).await.unwrap();
    assert_eq!(server.recv().await, Some(b"hello".to_vec()));
    server.send(b"world".to_vec()).await.unwrap();
    assert_eq!(client.recv().await, Some(b"world".to_vec()));
    client.shutdown().await.unwrap();
    server.shutdown().await.unwrap_err();
}

#[tokio::test]
async fn many_tsdus_of_every_size_arrive_in_order() {
    let (client, mut server) = open().await;
    let sizes: Vec<usize> = (0..60).map(|i| (i * 977) % 3000).collect();
    // The sends run beside the receives: a sender that does not receive waits, by design (back-pressure).
    let sent = sizes.clone();
    let sender = tokio::spawn(async move {
        for (index, size) in sent.iter().enumerate() {
            client.send(vec![index as u8; *size]).await.unwrap();
        }
        client
    });
    for (index, size) in sizes.iter().enumerate() {
        assert_eq!(server.recv().await, Some(vec![index as u8; *size]));
    }
    sender.await.unwrap().shutdown().await.unwrap();
}

#[tokio::test]
async fn a_tsdu_longer_than_the_tpdu_size_is_segmented_and_reassembled() {
    let (client, mut server) = open().await;
    let tsdu: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    client.send(tsdu.clone()).await.unwrap();
    assert_eq!(server.recv().await, Some(tsdu));
}

#[tokio::test]
async fn an_empty_tsdu_is_carried() {
    let (client, mut server) = open().await;
    client.send(Vec::new()).await.unwrap();
    assert_eq!(server.recv().await, Some(Vec::new()));
}

#[tokio::test]
async fn a_clean_shutdown_ends_the_peer_with_end_of_stream() {
    let (client, mut server) = open().await;
    client.shutdown().await.unwrap();
    assert_eq!(
        server.recv().await,
        None,
        "the peer sees the end of the stream"
    );
    assert!(matches!(server.shutdown().await, Err(Error::PeerClosed)));
}

#[tokio::test]
async fn shutdown_writes_the_tsdus_already_sent_before_releasing() {
    let (client, mut server) = open().await;
    for index in 0..5u8 {
        client.send(vec![index; 10]).await.unwrap();
    }
    client.shutdown().await.unwrap();
    for index in 0..5u8 {
        assert_eq!(server.recv().await, Some(vec![index; 10]));
    }
    assert_eq!(server.recv().await, None);
}

#[tokio::test]
async fn a_slow_receiver_holds_back_the_sender_without_losing_tsdus() {
    let (client, mut server) = open().await;
    let sender = tokio::spawn(async move {
        for index in 0..(CHANNEL_CAPACITY * 6) {
            client.send(vec![index as u8; 500]).await.unwrap();
        }
        client
    });
    // Nobody receives yet: the sender cannot finish while the channels are full.
    let finished = timeout(Duration::from_millis(300), async {
        while !sender.is_finished() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(finished.is_err(), "the sender waits for the receiver");
    for index in 0..(CHANNEL_CAPACITY * 6) {
        assert_eq!(server.recv().await, Some(vec![index as u8; 500]));
    }
    let client = sender.await.unwrap();
    client.shutdown().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn the_connect_timeout_is_checked_on_the_clock() {
    // The other end is kept, but never answers.
    let (a, _silent) = duplex(1024);
    let config = LinkConfig {
        connect_timeout: Duration::from_secs(10),
        ..LinkConfig::default()
    };
    let start = Instant::now();
    let result = connect(a, config).await;
    assert!(matches!(result, Err(Error::ConnectTimeout)), "{result:?}");
    assert!(start.elapsed() >= Duration::from_secs(10));
}

#[tokio::test]
async fn a_peer_that_closes_before_answering_is_reported() {
    let (a, b) = duplex(1024);
    drop(b);
    // The request is written first: the broken pipe may be seen before the end of stream.
    let result = connect(a, LinkConfig::default()).await;
    assert!(
        matches!(&result, Err(Error::PeerClosed) | Err(Error::Io(_))),
        "{result:?}"
    );
}

#[tokio::test]
async fn a_responder_that_declines_the_request_closes_both_ends() {
    let responder = LinkConfig {
        called_tsap: Some(vec![1]),
        ..LinkConfig::default()
    };
    let initiator = LinkConfig {
        called_tsap: Some(vec![2]),
        ..LinkConfig::default()
    };
    let (client, server) = open_with(initiator, responder).await;
    assert!(matches!(
        client,
        Err(Error::Closed(Cause::Refused(code))) if code == reason::ADDRESS_UNKNOWN
    ));
    assert!(matches!(
        server,
        Err(Error::Closed(Cause::Declined(code))) if code == reason::ADDRESS_UNKNOWN
    ));
}

#[tokio::test]
async fn an_invalid_configuration_is_refused_before_any_byte_is_sent() {
    let (a, _b) = duplex(1024);
    let config = LinkConfig {
        nesting_level: 1,
        ..LinkConfig::default()
    };
    assert!(matches!(connect(a, config).await, Err(Error::Config(_))));
}
