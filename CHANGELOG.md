# Changelog

All notable changes to this project are recorded in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

The next release is **2.0.0**: the public types change (decision D-032).

### Added

- The codec reads the IEC 61850 union of the MMS types (IEC 61850-8-1 Annex F): `Data::UtcTime` and
  `TypeDescription::UtcTime` (tag [17]), identifiers of up to 64 characters, the `pdu-size` service error
  (`ServiceErrorErrorClassService::PDU_SIZE`).
- `mms::check_strings`, `mms::StringLimits` (`ISO_9506`, `IEC_61850`) and the generated `walk_strings`:
  the strings that the union widens are checked per profile. `Association::set_string_limits` and
  `Requests::set_string_limits` choose the limits; ISO 9506 by default, so the behaviour of the ISO 9506
  profile (TASE.2) is unchanged.
- `CbbError::IdentifierLength` and `CbbError::DataString`.
- `mms::profile`: `Profile` (`TASE2`, `iec61850(Model)`), with the IEC 61850-8-1 clause 24 rules of the declared
  ACSI model: the nesting of six, the parameter CBBs (Table 128) and the services (Table 127) of each side
  (`required_parameters`, `required_services`, `check_parameters`, `check_services`, `check_nesting`).
  `Association::set_profile` and `Requests::set_profile` apply it; `ClientConfig::profile` and
  `ServerConfig::profile` carry it; `igsmms-client --profile iec61850 --logical-nodes [--data-sets] [--arrays]`.
- `Refusal::Profile` and `Error::Profile`: a profile refusal, with the CBB or the nesting that is missing.
- `mms::utc`: `UtcTimestamp` (seconds, 24-bit fraction, `TimeQuality`) and `TimeQuality` / `TimeAccuracy`,
  with `UtcTime::timestamp` and `UtcTime::from_timestamp`. A quality with an invalid accuracy is refused.
- `mms::encode_for(pdu, profile)`: the PDU as the profile writes it. `Association` sends with its profile.
- `schema::Tagging::Either`: a component tagged either way, read in both forms and written as the writer asks.
  The `mMSString` of `TypeDescription` is the one such component. The decoder reads both forms under every
  profile (D-034).
- The VMD checks that a `UtcTime` value of a described type is eight octets and valid.

### Changed

- **Breaking**: `Data` and `TypeDescription` have a new alternative (`UtcTime`); exhaustive matches need an arm.
- **Breaking**: `Data::MMSString` carries a `DataMMSString` (UTF-8 in the union) instead of an `MMSString`.
- A `Data` value with tag [17] is decoded as `Data::UtcTime` instead of `Data::Unsupported`.
- **Breaking**: `Refusal` gains `Profile`; `Writer`, `Tagging` and `ServerConfig` / `ClientConfig` gain fields or
  variants (`ClientConfig::profile`, `ServerConfig::profile`, `Tagging::Either`). Exhaustive matches and struct
  literals need an update.
- A `TypeDescription` `mMSString` is read in its explicit or its implicit form (D-034).

## [1.1.0] - 2026-11-08

### Added

- `LinkConfig::called_ap_title`, `calling_ae_qualifier` and `called_ae_qualifier`: the initiator can send the called AP-title and
  the AE-qualifiers in its AARQ, by configuration. They are absent by default, as before.
- `LinkConfig::application_context`: the application context that the initiator proposes. The default is the current one
  (`1.0.9506.2.5`); `ApplicationContext::Legacy` proposes the arc `1.0.9506.2.3`, which the peers of the 2002 edition propose.
  The responder accepts both, as before (decision D-027).

## [1.0.0] - 2026-11-07

### Added

- `igs-iso9506-mms-codec`: BER, and the ASN.1 types of the ACSE, presentation, session, COTP and MMS
  PDUs, generated from the profile data; the conformance building blocks (`cbb`) that validate a PDU against
  the negotiated parameters.
- `igs-iso9506-mms-link`: sans-I/O state machines for the transport (class 0, RFC 1006), the session and
  presentation connection, the MMS association (Initiate, conclusion, abort), and the requests (invoke IDs,
  limits, cancel, reject, timeouts). The responder accepts the application context of the MMS annex arc as
  well as the standard one (decision D-027).
- `igs-iso9506-mms`: the async `Client`, with its queue, its events, its reconnection policy and its close.
  The services in scope: Identify, GetNameList, Read, Write, GetVariableAccessAttributes, DefineNamedVariableList,
  GetNamedVariableListAttributes, DeleteNamedVariableList, and the information report.
- `igs-iso9506-mms`: the async `Server`, multi-client, with one task for the model, the CBB check on every PDU,
  the Reject PDU, the association limit, and the reports published to the open associations.
- `igs-iso9506-mms::vmd`: the model of the VMD: domains, named variables and named variable lists, with the
  `Variable` trait that a device object implements.
- `igs-iso9506-mms::server::Model`: a model of the server, other than the VMD, that sees each association: its
  calling identity (the AP-title and the AE qualifier of its AARQ), its admission, its confirmed services, its
  release, and a polled output sent to one association (`Outbound`). `Server::bind_model` serves it (decision D-031).
- `igs-iso9506-mms-link`: `Action::Calling`, the identity of the calling side indicated before the Initiate request.
  The initiator sends the AP-title of its configuration in its AARQ.
- `igs-iso9506-mms::tls`: TLS with a `TlsBackend` trait and a rustls backend (TLS 1.2 and 1.3, mutual
  authentication, revocation lists), for the client and the server (IEC 62351-3, decision D-030).
- Binaries `igsmms-client` (command line client) and `igsmms-server` (demonstration server from a TOML file).
- Examples `loopback`, `client`, `server` and `tls`.
- Interoperability tests on the bench against the reference peer (libiec61850), with captures decoded by tshark.

### Known gaps

The gaps are listed in `docs/capabilities.md`. The main ones: the security events of IEC 62351-3 are not raised;
rustls does not offer two mandatory TLS 1.2 suites and the CCM suite of TLS 1.3; there is no TLS renegotiation;
the reference peer does not serve journals; the device does not send reports unless the application publishes
them; the reference client's domain listing ends with an error because of the journal query.
