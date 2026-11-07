// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The load test of the server (task S4): fifty clients at once, each one association, each one a series
//! of requests in scope. The latencies are measured per service and reported.
//!
//! The scenario needs a running server, the device of the bench or a host server built from `igsmms-server`
//! with `bench/device/demo.toml`. It is ignored by default; run it, in release, with
//!
//! ```text
//! MMS_PEER=127.0.0.1:10104 cargo test --release -p igs-iso9506-mms --test load -- --ignored --nocapture
//! ```
//!
//! The latencies are those seen by the clients, on the machine of the run: they include the client's own
//! work. The server is one task for the model, so its services run one at a time (`docs/capabilities.md`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::{Duration, Instant};

use igs_iso9506_mms::client::in_scope_capabilities;
use igs_iso9506_mms::{Client, ClientConfig, Reconnect};
use igs_iso9506_mms_codec::generated::types::{
    AccessResult, Data, GetNameListRequest, GetNameListRequestObjectScope, Identifier, ObjectClass,
    ObjectClassBasicObjectClass, ObjectName, ReadRequest, VariableAccessSpecification,
    VariableAccessSpecificationListOfVariableItem, VariableSpecification,
};
use igs_iso9506_mms_link::config::LinkConfig;
use tokio::task::JoinHandle;

/// The clients of the load: the number of associations open at once.
const CLIENTS: usize = 50;

/// The requests of each client, cycling through the services.
const REQUESTS_PER_CLIENT: usize = 1000;

/// The services measured, in the order of the cycle.
const SERVICES: [&str; 3] = ["identify", "getNameList(domain)", "read(speed)"];

/// The answer of a request must come within this time; a longer one is an error of the run.
const ANSWER: Duration = Duration::from_secs(10);

/// What one client measured: the connection time, and the latency of each request, by service.
struct Outcome {
    connect: Duration,
    latencies: Vec<(usize, Duration)>,
    errors: usize,
}

fn read_speed() -> ReadRequest {
    ReadRequest {
        specification_with_result: None,
        variable_access_specification: VariableAccessSpecification::ListOfVariable(vec![
            VariableAccessSpecificationListOfVariableItem {
                variable_specification: VariableSpecification::Name(ObjectName::VmdSpecific(
                    Identifier("speed".to_string()),
                )),
                alternate_access: None,
            },
        ]),
    }
}

fn domains() -> GetNameListRequest {
    GetNameListRequest {
        object_class: ObjectClass::BasicObjectClass(ObjectClassBasicObjectClass::DOMAIN),
        object_scope: GetNameListRequestObjectScope::VmdSpecific,
        continue_after: None,
    }
}

async fn client(address: String) -> Outcome {
    let config = ClientConfig {
        reconnect: Reconnect::Never,
        ..ClientConfig::new(
            LinkConfig {
                request_timeout: ANSWER,
                ..LinkConfig::default()
            },
            in_scope_capabilities(),
        )
    };
    let started = Instant::now();
    let (client, _events) = match Client::connect(&address, config).await {
        Ok(connected) => connected,
        Err(_) => {
            return Outcome {
                connect: started.elapsed(),
                latencies: Vec::new(),
                errors: REQUESTS_PER_CLIENT,
            }
        }
    };
    let connect = started.elapsed();
    let mut latencies = Vec::with_capacity(REQUESTS_PER_CLIENT);
    let mut errors = 0usize;
    for index in 0..REQUESTS_PER_CLIENT {
        let service = index % SERVICES.len();
        let began = Instant::now();
        let answered = match service {
            0 => client.identify().await.map(|_| ()).map_err(|_| ()),
            1 => client
                .get_name_list(domains())
                .await
                .map(|_| ())
                .map_err(|_| ()),
            _ => match client.read(read_speed()).await {
                Ok(response)
                    if matches!(
                        response.list_of_access_result.first(),
                        Some(AccessResult::Success(Data::Integer(_)))
                    ) =>
                {
                    Ok(())
                }
                _ => Err(()),
            },
        };
        let elapsed = began.elapsed();
        match answered {
            Ok(()) => latencies.push((service, elapsed)),
            Err(()) => errors += 1,
        }
    }
    let _ = client.close().await;
    Outcome {
        connect,
        latencies,
        errors,
    }
}

/// The value at this fraction of the sorted durations (nearest rank).
fn percentile(sorted: &[Duration], fraction: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let rank = ((sorted.len() as f64) * fraction).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn report(label: &str, durations: &mut [Duration]) {
    durations.sort();
    println!(
        "LOAD | {label:<20} | {:>6} | {:>10?} | {:>10?} | {:>10?} | {:>10?}",
        durations.len(),
        percentile(durations, 0.50),
        percentile(durations, 0.95),
        percentile(durations, 0.99),
        durations.last().copied().unwrap_or(Duration::ZERO),
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs a running server: MMS_PEER=127.0.0.1:10104"]
async fn fifty_clients_run_their_services_and_the_latencies_are_recorded() {
    let Some(address) = std::env::var("MMS_PEER").ok() else {
        eprintln!("MMS_PEER is not set: the load test is skipped");
        return;
    };
    let started = Instant::now();
    let tasks: Vec<JoinHandle<Outcome>> = (0..CLIENTS)
        .map(|_| tokio::spawn(client(address.clone())))
        .collect();
    let mut outcomes = Vec::with_capacity(CLIENTS);
    for task in tasks {
        outcomes.push(task.await.unwrap());
    }
    let wall = started.elapsed();

    let connected = outcomes.iter().filter(|o| !o.latencies.is_empty()).count();
    let errors: usize = outcomes.iter().map(|o| o.errors).sum();
    let requests: usize = outcomes.iter().map(|o| o.latencies.len() + o.errors).sum();
    let mut connects: Vec<Duration> = outcomes.iter().map(|o| o.connect).collect();
    connects.sort();

    println!("LOAD | clients {CLIENTS}, requests per client {REQUESTS_PER_CLIENT}, wall {wall:?}");
    println!(
        "LOAD | requests {requests}, errors {errors}, throughput {:.0} requests/s",
        requests as f64 / wall.as_secs_f64()
    );
    println!(
        "LOAD | service              |  count |        p50 |        p95 |        p99 |        max"
    );
    report("connect", &mut connects);
    for (index, label) in SERVICES.iter().enumerate() {
        let mut durations: Vec<Duration> = outcomes
            .iter()
            .flat_map(|o| o.latencies.iter())
            .filter(|(service, _)| *service == index)
            .map(|(_, duration)| *duration)
            .collect();
        report(label, &mut durations);
    }

    assert_eq!(connected, CLIENTS, "every client is connected");
    assert_eq!(errors, 0, "no request fails");
}
