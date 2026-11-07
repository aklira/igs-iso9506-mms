// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Connection parameters of the stack (task L1): the selectors, the AP-title, the TPDU size, the
//! timeouts and the limits proposed in the association.
//!
//! Each item cites the clause that bounds it. Where no clause gives a value, the default is a
//! recorded decision (D-015 of `PROVENANCE.md`); a value is then checked by [`LinkConfig::validate`].

use std::fmt;
use std::time::Duration;

use igs_iso9506_mms_codec::schema::ObjectIdentifier;
use igs_iso9506_mms_codec::transport::TpduSize;

/// Largest session selector, in octets (X.225, table of the CN parameters, selectors 8.3.1.17).
pub const MAX_SESSION_SELECTOR: usize = 16;

/// Largest presentation selector, in octets. X.226 §8.2 gives the type as an OCTET STRING with no
/// bound; the session bound is kept, see D-015.
pub const MAX_PRESENTATION_SELECTOR: usize = 16;

/// Largest transport selector, in octets. X.224 §13.3.4 a) leaves its length undefined; a
/// parameter has a one-octet length, so 255 is the bound of the wire format.
pub const MAX_TRANSPORT_SELECTOR: usize = 255;

/// Largest value of the proposed data structure nesting level: an INTEGER of 8 bits, positive
/// (9506-2 §8.2, `proposedDataStructureNestingLevel`).
pub const MAX_NESTING_LEVEL: u8 = 127;

/// Largest value of the proposed number of outstanding services: an INTEGER of 16 bits, positive
/// (9506-2 §8.2, `proposedMaxServOutstandingCalling`).
pub const MAX_OUTSTANDING: u16 = 32_767;

/// The parameters of one endpoint of the stack.
///
/// A selector left `None` is omitted from the connection: X.224 §13.3.4 a) makes the transport
/// selector optional, and the session and presentation selectors are optional in their own
/// connection requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkConfig {
    /// Transport selector sent by the initiator in the CR TPDU (X.224 §13.3.4 a).
    pub calling_tsap: Option<Vec<u8>>,
    /// Transport selector of the responder in the CR TPDU (X.224 §13.3.4 a).
    pub called_tsap: Option<Vec<u8>>,
    /// Session selector of the initiator (X.225 §7.1.1 d).
    pub calling_ssap: Option<Vec<u8>>,
    /// Session selector of the responder (X.225 §7.1.1 d).
    pub called_ssap: Option<Vec<u8>>,
    /// Presentation selector of the initiator (X.226 §6.2.2.3).
    pub calling_psap: Option<Vec<u8>>,
    /// Presentation selector of the responder (X.226 §6.2.2.5).
    pub called_psap: Option<Vec<u8>>,
    /// AP-title of the initiator, as an object identifier (X.227, AP-title in form 2).
    pub ap_title: Option<ObjectIdentifier>,
    /// Largest TPDU size proposed in the CR TPDU (X.224 §13.3.4 b).
    pub tpdu_size: TpduSize,
    /// Time allowed for the transport connection and the association to be established.
    pub connect_timeout: Duration,
    /// Time allowed for the response to a confirmed service request.
    pub request_timeout: Duration,
    /// Number of confirmed service requests the initiator may have outstanding, proposed in the
    /// Initiate request (9506-2 §8.2, `proposedMaxServOutstandingCalling`).
    pub max_outstanding_calling: u16,
    /// Number of confirmed service requests the responder may have outstanding, proposed in the
    /// Initiate request (9506-2 §8.2, `proposedMaxServOutstandingCalled`).
    pub max_outstanding_called: u16,
    /// Deepest data structure proposed in the Initiate request (9506-2 §8.2,
    /// `proposedDataStructureNestingLevel`); at least two for TASE.2 (6-702 §5, stack requirements).
    pub nesting_level: u8,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            calling_tsap: None,
            called_tsap: None,
            calling_ssap: None,
            called_ssap: None,
            calling_psap: None,
            called_psap: None,
            ap_title: None,
            tpdu_size: TpduSize::S8192,
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            max_outstanding_calling: 8,
            max_outstanding_called: 8,
            nesting_level: 2,
        }
    }
}

/// A parameter of [`LinkConfig`] that is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// A selector is present but empty: omit it instead.
    EmptySelector {
        /// The name of the field.
        field: &'static str,
    },
    /// A selector is longer than its bound.
    SelectorTooLong {
        /// The name of the field.
        field: &'static str,
        /// The bound, in octets.
        max: usize,
        /// The length given, in octets.
        len: usize,
    },
    /// The AP-title is not an object identifier of the form X.690 §8.19 can encode.
    InvalidApTitle,
    /// An integer is outside its range.
    OutOfRange {
        /// The name of the field.
        field: &'static str,
        /// The smallest value allowed.
        min: u64,
        /// The largest value allowed.
        max: u64,
        /// The value given.
        value: u64,
    },
    /// A timeout is zero: it would expire at once.
    ZeroTimeout {
        /// The name of the field.
        field: &'static str,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySelector { field } => write!(f, "{field} is empty; omit it instead"),
            Self::SelectorTooLong { field, max, len } => {
                write!(f, "{field} has {len} octets, at most {max} allowed")
            }
            Self::InvalidApTitle => write!(f, "the AP-title is not a valid object identifier"),
            Self::OutOfRange {
                field,
                min,
                max,
                value,
            } => write!(f, "{field} is {value}, must be between {min} and {max}"),
            Self::ZeroTimeout { field } => write!(f, "{field} is zero"),
        }
    }
}

impl std::error::Error for ConfigError {}

fn selector(field: &'static str, value: Option<&[u8]>, max: usize) -> Result<(), ConfigError> {
    match value {
        None => Ok(()),
        Some([]) => Err(ConfigError::EmptySelector { field }),
        Some(bytes) if bytes.len() > max => Err(ConfigError::SelectorTooLong {
            field,
            max,
            len: bytes.len(),
        }),
        Some(_) => Ok(()),
    }
}

fn range(field: &'static str, value: u64, min: u64, max: u64) -> Result<(), ConfigError> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(ConfigError::OutOfRange {
            field,
            min,
            max,
            value,
        })
    }
}

/// An object identifier of at least two arcs, the first at most 2, and the second below 40
/// when the first is below 2 (X.690 §8.19.4).
fn check_ap_title(oid: &ObjectIdentifier) -> Result<(), ConfigError> {
    match oid.0.as_slice() {
        [first, second, ..] if *first <= 2 && (*first == 2 || *second < 40) => Ok(()),
        _ => Err(ConfigError::InvalidApTitle),
    }
}

impl LinkConfig {
    /// Checks every parameter; the first refused one is returned.
    pub fn validate(&self) -> Result<(), ConfigError> {
        selector(
            "calling_tsap",
            self.calling_tsap.as_deref(),
            MAX_TRANSPORT_SELECTOR,
        )?;
        selector(
            "called_tsap",
            self.called_tsap.as_deref(),
            MAX_TRANSPORT_SELECTOR,
        )?;
        selector(
            "calling_ssap",
            self.calling_ssap.as_deref(),
            MAX_SESSION_SELECTOR,
        )?;
        selector(
            "called_ssap",
            self.called_ssap.as_deref(),
            MAX_SESSION_SELECTOR,
        )?;
        selector(
            "calling_psap",
            self.calling_psap.as_deref(),
            MAX_PRESENTATION_SELECTOR,
        )?;
        selector(
            "called_psap",
            self.called_psap.as_deref(),
            MAX_PRESENTATION_SELECTOR,
        )?;
        if let Some(title) = &self.ap_title {
            check_ap_title(title)?;
        }
        for (field, timeout) in [
            ("connect_timeout", self.connect_timeout),
            ("request_timeout", self.request_timeout),
        ] {
            if timeout.is_zero() {
                return Err(ConfigError::ZeroTimeout { field });
            }
        }
        range(
            "max_outstanding_calling",
            u64::from(self.max_outstanding_calling),
            1,
            u64::from(MAX_OUTSTANDING),
        )?;
        range(
            "max_outstanding_called",
            u64::from(self.max_outstanding_called),
            1,
            u64::from(MAX_OUTSTANDING),
        )?;
        range(
            "nesting_level",
            u64::from(self.nesting_level),
            2,
            u64::from(MAX_NESTING_LEVEL),
        )
    }
}
