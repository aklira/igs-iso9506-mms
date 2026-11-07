# Changelog

All notable changes to this project are recorded in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
