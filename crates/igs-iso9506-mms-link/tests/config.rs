// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Tests of the connection parameters (task L1): the defaults, and each refused value at its
//! bound.

use std::time::Duration;

use igs_iso9506_mms_codec::schema::ObjectIdentifier;
use igs_iso9506_mms_codec::transport::TpduSize;
use igs_iso9506_mms_link::config::{
    MAX_NESTING_LEVEL, MAX_OUTSTANDING, MAX_PRESENTATION_SELECTOR, MAX_SESSION_SELECTOR,
    MAX_TRANSPORT_SELECTOR,
};
use igs_iso9506_mms_link::{ConfigError, LinkConfig};

fn valid(config: LinkConfig) {
    assert_eq!(config.validate(), Ok(()), "{config:?}");
}

fn refused(config: LinkConfig) -> ConfigError {
    match config.validate() {
        Err(error) => error,
        Ok(()) => panic!("accepted: {config:?}"),
    }
}

#[test]
fn defaults_are_valid() {
    valid(LinkConfig::default());
}

#[test]
fn defaults_propose_the_tpdu_size_the_reference_peer_proposes() {
    let config = LinkConfig::default();
    assert_eq!(config.tpdu_size, TpduSize::S8192);
    assert_eq!(config.tpdu_size.octets(), 8192);
    assert_eq!(
        config.nesting_level, 2,
        "the TASE.2 minimum (6-702 stack requirements)"
    );
}

#[test]
fn defaults_omit_the_selectors_and_the_ap_title() {
    let config = LinkConfig::default();
    assert!(config.calling_tsap.is_none() && config.called_tsap.is_none());
    assert!(config.calling_ssap.is_none() && config.called_ssap.is_none());
    assert!(config.calling_psap.is_none() && config.called_psap.is_none());
    assert!(config.ap_title.is_none());
}

#[test]
fn defaults_time_out_after_their_stated_durations() {
    let config = LinkConfig::default();
    assert_eq!(config.connect_timeout, Duration::from_secs(10));
    assert_eq!(config.request_timeout, Duration::from_secs(30));
}

#[test]
fn selectors_at_their_bound_are_accepted() {
    let config = LinkConfig {
        calling_tsap: Some(vec![1; MAX_TRANSPORT_SELECTOR]),
        called_ssap: Some(vec![2; MAX_SESSION_SELECTOR]),
        called_psap: Some(vec![3; MAX_PRESENTATION_SELECTOR]),
        ..LinkConfig::default()
    };
    valid(config);
}

#[test]
fn two_transport_selectors_share_the_header_of_the_connection_request() {
    let pair = |calling: usize, called: usize| LinkConfig {
        calling_tsap: Some(vec![1; calling]),
        called_tsap: Some(vec![2; called]),
        ..LinkConfig::default()
    };
    valid(pair(120, 121));
    assert_eq!(
        refused(pair(120, 122)),
        ConfigError::ConnectionRequestTooLong { length: 255 }
    );
}

#[test]
fn an_empty_selector_is_refused() {
    let config = LinkConfig {
        calling_ssap: Some(Vec::new()),
        ..LinkConfig::default()
    };
    assert_eq!(
        refused(config),
        ConfigError::EmptySelector {
            field: "calling_ssap"
        }
    );
}

#[test]
fn a_session_selector_over_16_octets_is_refused() {
    let config = LinkConfig {
        called_ssap: Some(vec![0; MAX_SESSION_SELECTOR + 1]),
        ..LinkConfig::default()
    };
    assert_eq!(
        refused(config),
        ConfigError::SelectorTooLong {
            field: "called_ssap",
            max: 16,
            len: 17
        }
    );
}

#[test]
fn a_presentation_selector_over_its_bound_is_refused() {
    let config = LinkConfig {
        calling_psap: Some(vec![0; MAX_PRESENTATION_SELECTOR + 1]),
        ..LinkConfig::default()
    };
    assert!(matches!(
        refused(config),
        ConfigError::SelectorTooLong {
            field: "calling_psap",
            ..
        }
    ));
}

#[test]
fn a_transport_selector_over_its_bound_is_refused() {
    let config = LinkConfig {
        called_tsap: Some(vec![0; MAX_TRANSPORT_SELECTOR + 1]),
        ..LinkConfig::default()
    };
    assert_eq!(
        refused(config),
        ConfigError::SelectorTooLong {
            field: "called_tsap",
            max: 243,
            len: 244
        }
    );
}

#[test]
fn an_ap_title_must_have_two_arcs_that_x690_can_encode() {
    let title = |arcs: &[u64]| LinkConfig {
        ap_title: Some(ObjectIdentifier(arcs.to_vec())),
        ..LinkConfig::default()
    };
    valid(title(&[1, 1, 9]));
    valid(title(&[2, 999]));
    valid(title(&[1, 39]));
    assert_eq!(refused(title(&[1])), ConfigError::InvalidApTitle);
    assert_eq!(refused(title(&[])), ConfigError::InvalidApTitle);
    assert_eq!(refused(title(&[3, 0])), ConfigError::InvalidApTitle);
    assert_eq!(refused(title(&[0, 40])), ConfigError::InvalidApTitle);
    assert_eq!(refused(title(&[1, 40])), ConfigError::InvalidApTitle);
}

#[test]
fn a_zero_timeout_is_refused() {
    let connect = LinkConfig {
        connect_timeout: Duration::ZERO,
        ..LinkConfig::default()
    };
    assert_eq!(
        refused(connect),
        ConfigError::ZeroTimeout {
            field: "connect_timeout"
        }
    );
    let request = LinkConfig {
        request_timeout: Duration::ZERO,
        ..LinkConfig::default()
    };
    assert_eq!(
        refused(request),
        ConfigError::ZeroTimeout {
            field: "request_timeout"
        }
    );
}

fn set_calling(config: &mut LinkConfig, value: u16) {
    config.max_outstanding_calling = value;
}

fn set_called(config: &mut LinkConfig, value: u16) {
    config.max_outstanding_called = value;
}

#[test]
fn outstanding_requests_are_between_one_and_the_integer16_maximum() {
    type Setter = fn(&mut LinkConfig, u16);
    let cases: [(Setter, &str); 2] = [
        (set_calling, "max_outstanding_calling"),
        (set_called, "max_outstanding_called"),
    ];
    for (set, field) in cases {
        let with = |value: u16| {
            let mut config = LinkConfig::default();
            set(&mut config, value);
            config
        };
        valid(with(1));
        valid(with(MAX_OUTSTANDING));
        assert!(matches!(
            refused(with(0)),
            ConfigError::OutOfRange { field: f, min: 1, .. } if f == field
        ));
        assert!(matches!(
            refused(with(MAX_OUTSTANDING + 1)),
            ConfigError::OutOfRange { field: f, max: 32_767, .. } if f == field
        ));
    }
}

#[test]
fn the_nesting_level_is_between_the_tase2_minimum_and_the_integer8_maximum() {
    let with = |level: u8| LinkConfig {
        nesting_level: level,
        ..LinkConfig::default()
    };
    valid(with(2));
    valid(with(MAX_NESTING_LEVEL));
    assert!(matches!(
        refused(with(1)),
        ConfigError::OutOfRange {
            field: "nesting_level",
            min: 2,
            ..
        }
    ));
    assert!(matches!(
        refused(with(0)),
        ConfigError::OutOfRange {
            field: "nesting_level",
            ..
        }
    ));
    assert!(matches!(
        refused(with(MAX_NESTING_LEVEL + 1)),
        ConfigError::OutOfRange {
            field: "nesting_level",
            max: 127,
            ..
        }
    ));
}

#[test]
fn every_error_has_a_message_that_names_its_field() {
    let error = refused(LinkConfig {
        nesting_level: 1,
        ..LinkConfig::default()
    });
    assert!(error.to_string().contains("nesting_level"));
}
