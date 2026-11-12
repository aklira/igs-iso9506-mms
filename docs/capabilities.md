# Capabilities and known gaps

What the stack does, and what it does not, as observed against the reference peer of the bench
(task L6, `bench/tests/test_l6_interop.py`) or as decided. Rule 10 of `IMPLEMENTATION.md`: a failing
criterion is fixed, or recorded here.

## Supported services and CBBs (task X3)

The services of the profile, with the test that covers each row: a test named in a row must exist. The
checker `crates/igs-iso9506-mms/tests/capabilities_matrix.rs` reads this section and fails if a name is
missing. "Client" and "server" are the two ends of this repository. "Bench" is the reference peer
(libiec61850) against this repository's end, run by the bench tests. A gap is recorded in the last column,
and in the sections below.

<!-- matrix:begin -->

| Service (tag) | Client | Server | Bench | Gaps |
| --- | --- | --- | --- | --- |
| Identify (2) | `identify_is_answered_with_the_identity_of_the_peer`, `a_confirmed_identify_is_answered_by_the_reference_server` | `identify_is_answered_with_the_identity_of_the_server` | `test_stack_identifies_and_aborts_with_the_reference_server`, `test_the_reference_client_runs_its_services_against_the_device` | none |
| GetNameList (1), domains | `get_name_list_returns_the_names` | `get_name_list_lists_the_domains` | `test_the_client_runs_every_service_in_scope_against_the_reference_server`, `test_the_reference_client_matrix_against_the_device` | none |
| GetNameList (1), named variables, paged | `get_name_list_returns_the_names` | `get_name_list_pages_through_the_named_variables`, `get_name_list_of_a_domain_lists_its_variables` | `test_reference_clients_run_the_services_in_scope` | G8 (refused by default), G9 (identifiers over 32 characters, peer side) |
| GetNameList (1), journals | none | none | `test_the_reference_client_matrix_against_the_device` | G14: the peer asks for journals; the server answers with an error |
| Read (4) | `read_returns_the_values` | `read_returns_the_value_and_fails_per_item` | `test_the_client_runs_every_service_in_scope_against_the_reference_server`, `test_the_reference_client_matrix_against_the_device` | G8 for the peer's default; addresses and alternate access not served |
| Write (5) | `write_returns_the_result_of_each_item` | `write_is_answered_and_the_value_read_back`, `write_is_refused_for_a_read_only_variable_and_a_wrong_type` | none: the reference tool has no write | G8 (peer side) |
| GetVariableAccessAttributes (6) | `get_variable_access_attributes_returns_the_type` | `get_variable_access_attributes_returns_the_type` | none: the reference tool does not use it | address form not served |
| DefineNamedVariableList (11) | `define_named_variable_list_is_acknowledged` | `define_get_and_delete_a_named_variable_list`, `a_definition_that_exists_or_names_a_missing_member_is_an_error` | none: the reference tool has no define | G12: the peer refuses a domain-scope list |
| GetNamedVariableListAttributes (12) | `get_named_variable_list_attributes_returns_the_list` | `define_get_and_delete_a_named_variable_list` | `test_the_reference_client_matrix_against_the_device` | none |
| DeleteNamedVariableList (13) | `delete_named_variable_list_returns_the_counts` | `a_list_of_a_domain_is_deleted_with_its_scope`, `define_get_and_delete_a_named_variable_list` | none: the reference tool has no delete | none |
| InformationReport (unconfirmed 0) | `an_unconfirmed_report_reaches_the_event_stream` | `an_unconfirmed_report_reaches_the_associations`, `an_unconfirmed_service_reaches_the_other_end_without_a_state` | none: the device sends no report | G15 (no reporting control block) |
| Initiate, negotiation, refusal | `a_refused_association_fails_the_connect` | `no_common_service_is_refused_with_service_cbb_insufficient`, `a_nesting_level_below_the_tase2_minimum_is_refused_with_its_error` | `test_reference_client_initiates_and_reads_the_server_identity` | none |
| Conclude and abort | `close_releases_the_association_and_later_calls_fail` | `conclude_releases_the_association_in_the_order_of_annex_a`, `an_abort_is_a_user_abort_at_both_ends` | `test_stack_negotiates_and_concludes_with_the_reference_server`, `an_abort_ends_the_association_on_both_ends` | G1: the peer does not confirm the release |
| Reject (both directions) | `a_request_beyond_the_limit_of_the_peer_is_rejected_with_max_serv_outstanding_exceeded` | `a_repeated_invoke_id_from_the_peer_is_rejected_as_invalid`, `a_response_with_an_unknown_invoke_id_is_rejected_and_changes_nothing` | none | the Reject of a server for an unserved request is covered by the codec only |
| Cancel | `an_accepted_cancel_is_a_cancel_response_then_the_error_of_the_request` | `a_refused_cancel_leaves_the_request_to_complete` | none | none |
| TLS (IEC 62351-3) | `the_client_and_the_server_negotiate_tls_13_and_run_mms_over_it` | `a_revoked_certificate_is_refused_by_the_revocation_list` | none | G16, G17, G18, G19 |

### Index of the gaps

Each gap is described in the section that found it; this index gives its status.

| Gap | Status | Where |
| --- | --- | --- |
| G1 | Open: the peer does not confirm the release (RLRQ) | Gaps; T2 (D-021) |
| G2 | Partly closed: the reference client now runs its services against this server (S3, S4); the reverse direction is tested | Gaps; S3 |
| G3 | Open: no scenario checks a refusal of the association by the peer (the loopback tests do) | Gaps |
| G4 | Closed for the nine services in scope (T4, S4) | Gaps; T4 |
| G5 | Open: the PDUs that minor versions 1 and 2 forbid are not refused | Gaps |
| G6 | Not a defect: Wireshark reads the release as a zero-byte MMS PDU | Gaps |
| G7 | Fixed (T3): the extra bits of the peer's Initiate response are ignored | Gaps; T3 |
| G8 | Open: the peer negotiates no parameter CBB yet serves the services that need them; conformant by default, option `lenient` | Gaps; T3, T4 |
| G9 | Decoded since D-031 (identifiers of up to 64 characters); refused by the ISO 9506 profile, accepted by the IEC 61850 profile (task N2 of igs-iec61850-mms) | Gaps; T3; D-031 |
| G10 | Open: data nested deeper than negotiated; the command line proposes 6, the library 2 | Gaps; T3 |
| G11 | Open: a data tag of a later edition, kept raw | Gaps; T3 |
| G12 | Open: the peer refuses a domain-scope named variable list | S4 matrix; Client matrix |
| G13 | Fixed (D-027): the peer proposes application context 1.0.9506.2.3, now accepted | S3 |
| G14 | Open: the server does not hold journals; the reference client's domain listing ends with error 82 | S3; S4 |
| G15 | Open: the device sends no report; no reporting control block | S4 |
| G16 | Open: the security events of IEC 62351-3 Annex A are not raised | X1 |
| G17 | Open: rustls lacks two mandatory TLS 1.2 suites and the CCM suite of TLS 1.3 | X1 |
| G18 | Open: no TLS 1.2 renegotiation | X1 |
| G19 | Open: the 8 192-octet certificate boundary is not tested | X1 |

### Parameter CBBs

The server advertises four parameter CBBs (`server_capabilities`); a request that uses another is refused by the
CBB check of the association (ISO 9506-2 §8). The client proposes all of them and takes the server's answer.

| CBB | Served | Test covering the row |
| --- | --- | --- |
| str1 (arrays) | yes | `data_needs_str1_str2_and_the_nesting_level` |
| str2 (structures) | yes | `write_is_answered_and_the_value_read_back` |
| vnam (named variables) | yes | `read_returns_the_value_and_fails_per_item` |
| vlis (named variable lists) | yes | `define_get_and_delete_a_named_variable_list` |
| vadr (addresses) | no | `variable_specifications` (refused without the CBB) |
| valt (alternate access) | no | `alternate_access` (refused without the CBB) |
| vsca (scattered access) | no | `variable_specifications` (refused without the CBB) |
| all others | no | `the_cbb_check_is_total` |

<!-- matrix:end -->

## Against the reference server (libiec61850 v1.6.2.1, `server_example_basic_io`)

| Scenario | Result |
| --- | --- |
| TCP, COTP connection with the 8192-octet TPDU size | Works |
| Association: Initiate, negotiation (version 1, outstanding 5, nesting 2) | Works |
| Confirmed Identify, answered with the vendor name | Works |
| Abort by the user | Works; the peer closes the stream |
| Conclude: CONCLUDE request, CONCLUDE response | Works |

## TLS (task X1)

`igs_iso9506_mms::tls` (decision D-030): a `TlsBackend` secures the TCP connections, and `RustlsBackend` is the
backend, on the ring provider, with TLS 1.2 and TLS 1.3. The client connects with `SecureConnector`; the server
takes `ServerConfig::with_tls`. Tests: `crates/igs-iso9506-mms/tests/tls.rs`, over real sockets, with the
material of `tests/fixtures/tls` (generated by its `generate.sh`; test material only).

| Scenario | Test | Result |
| --- | --- | --- |
| TLS 1.3, mutual authentication, MMS identify and read over it | `the_client_and_the_server_negotiate_tls_13_and_run_mms_over_it` | Works |
| TLS 1.2 only, the client's certificate accepted | `a_client_that_offers_only_tls_12_...` | Works |
| No client certificate (clause 6.4.3) | `a_client_without_a_certificate_is_refused` | Refused: CertificateRequired |
| Certificate of another root | `a_certificate_from_another_root_is_refused` | Refused: UnknownCA |
| Expired certificate (clause 6.4.4.5) | `an_expired_certificate_is_refused` | Refused: CertificateExpired |
| Revoked certificate (clause 6.4.4.4, the CRL) | `a_revoked_certificate_is_refused_by_the_revocation_list` | Refused: CertificateRevoked |
| Server name not in the certificate | `a_server_name_outside_the_certificate_...` | Refused by the client |
| Plain client to a TLS server | `a_plain_client_is_refused_by_the_tls_server` | Refused |
| A backend without a revocation list | `a_backend_without_a_revocation_list_is_refused` | Refused at build |
| A station without its own certificate, as server | `a_station_without_a_certificate_of_its_own_...` | Refused |

Gaps of the TLS layer:

- **G16, security events.** The events of IEC 62351-3 Annex A (the handshake notices and the alarms) are not
  raised: the refusals are returned as `TlsError`, not as events. The events of `igs-iec104` (36 of them, with
  their mnemonics) are the model; they are not in this step.
- **G17, cipher suites.** The ring provider offers the AES-GCM and ChaCha20 suites of TLS 1.2 (ECDHE) and TLS 1.3.
  The profile's mandatory TLS 1.2 suites TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 and
  TLS_RSA_WITH_AES_128_CBC_SHA256 are not offered (rustls has no finite-field DHE and no static RSA key
  exchange), and TLS_AES_128_CCM_SHA256 of TLS 1.3 is not offered. A station with this backend does not
  conform to the profile on these points (`igs-iec104` has the same gap with rustls, see its X1 log).
- **G18, renegotiation.** The profile requires the TLS 1.2 renegotiation of the certificates at intervals
  (clause 7.4.5), which rustls does not do. The backend does not renegotiate.
- **G19, certificate size.** The profile requires certificates of at least 8 192 octets (clause 6.4.2); rustls
  accepts certificates of any size, but the tests use certificates of about 1 KiB and do not check the 8 192
  octets boundary.

## Server interoperability and load (task S4)

The matrix of the reference client against the device (`bench/tests/test_s4_server_matrix.py`) passes: each
row shows its expected output and exit status, and the capture shows the services on the wire.

| Row | Reference client command | Result |
| --- | --- | --- |
| identify | `-i` | Pass |
| getNameList, domains | `-d` | Pass |
| getNameList, named variables of a domain | `-t demo` | Pass: the three variables are listed |
| getNameList, journals | `-t demo` (the query that follows) | Gap G14: error 82, exit 82 |
| read, floating point, boolean, visible string | `-a demo -r ...` | Pass |
| read, unknown name | `-a demo -r missing` | Pass: error 10 (object-non-existent) |
| read, named variable list | `-a demo -v snapshot` | Pass |
| getNamedVariableListAttributes | `-a demo -z snapshot` | Pass: both members |

Not exercised by the reference client, which has no command for them: write, getVariableAccessAttributes,
defineNamedVariableList, deleteNamedVariableList, and the reception of reports (G15). They are covered by the
Rust scenarios of `tests/server.rs` and by the runs of `igsmms-client` against the host server
(`docs/ai-log/S4.md`).

Load (`crates/igs-iso9506-mms/tests/load.rs`, release build, host server with `bench/device/demo.toml`): fifty
clients, one association each, a thousand requests each (identify, domain list, read), 50 000 requests in each
run. Three runs, no error: about 58 000 to 61 000 requests per second; the request latency p50 is about
0.8 ms, p99 about 1.3 ms; the connection p50 is about 4 to 5 ms. The latencies are seen by the clients, on one
machine; the server runs its services one at a time (D-026).

Gaps of the server, found by the matrix and the load:

- **G15, reports.** The device sends no report: the model has no reporting control block, and no bench
  scenario enables one. The reception of an unconfirmed PDU by the reference client is not tested against the
  device (the library's `Server::publish` is tested in `tests/server.rs`).
- **The reference client does not write.** Its tool has no write, define or delete command: those services are
  tested by this repository's client and its Rust scenarios only.

## Device under test (task S3)

`igsmms-server` (`docs/igsmms-server.md`) serves the file `bench/device/demo.toml`. The reference client
ran these commands against it, and this repository's client ran the commands of `igsmms-client`:

| Command | Reference client (`mms_utility`) | Result |
| --- | --- | --- |
| identify | `-i` | Works: vendor, model and revision |
| domain list | `-d` | Works |
| variable list of the domain | `-t demo` | The three variables are listed; then G14 |
| read of a float, a boolean, a visible string | `-a demo -r ...` | Works |

Checked by `bench/tests/test_s3_device.py`: the services 1, 2 and 4 are on the wire in both directions,
and the capture decodes with no malformed frame apart from the release artefact (G6).

## Server (task S2)

Served by `igs_iso9506_mms::Server` (D-026), checked by `crates/igs-iso9506-mms/tests/server.rs` with this
repository's client over TCP:

| Service in scope | Test |
| --- | --- |
| Identify | `identify_is_answered_with_the_identity_of_the_server` |
| GetNameList (domains; named variables, paged; a domain's variables) | `get_name_list_*` (three tests) |
| Read (named variables, a structure, a list, a missing name) | `read_returns_the_value_and_fails_per_item` |
| Write (accepted, read back; read-only and wrong type refused) | `write_*` (two tests) |
| GetVariableAccessAttributes | `get_variable_access_attributes_returns_the_type` |
| DefineNamedVariableList, GetNamedVariableListAttributes, DeleteNamedVariableList | `define_get_and_delete_*`, `a_list_of_a_domain_*` |
| Definition errors (object exists, missing member) | `a_definition_that_exists_*` |
| informationReport (unconfirmed, sent by the server) | `an_unconfirmed_report_reaches_the_associations` |
| Several associations; the association limit; shutdown | `several_clients_*`, `a_connection_beyond_*`, `shutdown_*` |

Not covered by an integration test: the Reject PDU that the server sends for a request it does not serve.
A conforming client refuses such a request before it sends it, so the path is reached only from a peer that
breaks the negotiation. The codec's CBB tests cover the refusal itself (`crates/igs-iso9506-mms-codec/tests`).

Gaps of the server:

- **Reports go to every open association.** There is no reporting control block in the model yet: a report
  is not addressed to the clients that enabled it.
- **One task serves all the associations.** The services run one at a time (D-026). The load test with 50
  clients is task S4.
- **No access control.** The model's read and write permissions are per variable only (ISO 9506-2 access
  control lists are not modelled).
- **Addresses and alternate access are refused**, with object-access-unsupported per item in reads and writes,
  and with a service error in attribute requests.

## Server model: the VMD (task S1)

The model of the VMD in `igs_iso9506_mms::vmd` (D-025). Held: domains, named variables at the VMD and
domain scopes, named variable lists. Not held, and refused as unsupported: named types, unnamed
variables, application association-specific names, access control lists, and the other classes of the
VMD (program invocations, event objects, journals, semaphores, data exchanges, operator stations, unit
controls). A reference to one of them is `object-non-existent` or `object-access-unsupported` in a
service, never a silent success.

## Client matrix against the reference server (task T4)

The scenarios are `crates/igs-iso9506-mms/tests/interop_matrix.rs`, run by
`bench/tests/test_t4_client_matrix.py`: one association per row, the capture decoded by tshark. The
conformant rows show the refusal that the standard requires; the lenient rows use
`--lenient-parameter-cbbs` (G8). The service tags are those of the capture.

| Service in scope | Mode | Result |
| --- | --- | --- |
| Identify (2) | conformant | Works: vendor `MZ` |
| GetNameList, domains | conformant | Works: `simpleIOGenericIO` |
| GetNameList, named variables | conformant | Refused locally (G8) |
| GetNameList, named variables | lenient | The connection ends (G9) |
| GetNameList, named variable lists | lenient | Works: `LLN0$Events`, `LLN0$Events2`, `LLN0$Measurements` |
| Read (4) | conformant | Refused locally (G8) |
| Read (4) | lenient | Works: a floating-point value |
| Write (5) | lenient | Works: written, and read back in the same association |
| GetVariableAccessAttributes (6) | lenient | Works: the type of a floating-point variable |
| DefineNamedVariableList (11) | lenient, VMD scope | Works |
| DefineNamedVariableList (11) | lenient, domain scope | Refused by the peer, `object-non-existent` (G12) |
| GetNamedVariableListAttributes (12) | lenient | Works: the two members of the list |
| DeleteNamedVariableList (13) | lenient | Works: one list deleted |
| informationReport (unconfirmed 0) | lenient | Works: after a general interrogation, the report arrives (fixed by D-023) |

Identifiers of the scenarios are at most 32 characters, so that G9 does not apply to them.

## Gaps found by the command line client (task T3)

The bench transcript of the client is in `docs/ai-log/T3.md`. The reference server, when the command
line is used with `--lenient-parameter-cbbs` for the variable services:

| Command | Result |
| --- | --- |
| `identify` | Works: vendor, model and revision |
| `names --class domain` | Works: the domain list |
| `names --domain D` (named variables) | Refused locally by default (G8); with the option, the association ends (G9) |
| `read`, `attributes`, `write` (with the option) | Works for a variable the server answers; data nested deeper than 2 is refused unless the client proposes more (G10) |

## Gaps

- **G7, extra bits in the Initiate response.** The reference server sets services it was not offered
  (`status`). ISO 9506-1 §8.2.1.1.8 says any additional bits received are ignored. The stack ignores
  them and uses the intersection with the proposal (since task T3, D-018 and D-022). It was refused
  before, which broke the connection.
- **G8, parameter CBBs not negotiated.** The reference server answers an Initiate with an empty
  parameter CBB (`str1`, `str2`, `vnam`, `valt`, `vlis` all False), yet it serves the services that
  need them (`getNameList` on named variables, `read`). The stack follows the standard: a request
  that needs an unnegotiated CBB is refused locally. The option `--lenient-parameter-cbbs` (CLI) and
  `ClientConfig::lenient_parameter_cbbs` take the proposed CBBs as negotiated, for such a server. The
  default is the standard.
- **G9, identifiers longer than 32 characters.** The reference server lists IEC 61850 names of up to
  39 characters (30 of them in one answer of a domain listing). ISO 9506-2 §7.5.2 limits an
  identifier to 32 characters, and the codec refuses such an answer: the association then ends. This
  is the gap recorded in C7 for the IEC 61850 phase.
- **G10, data nested deeper than negotiated.** With a proposed nesting level of 2, the server answers
  a `read` with data nested deeper than the level it negotiated, and the stack refuses the answer as
  unsupported. The command line proposes a nesting level of 6 by default (`--nesting`). The library
  default stays at the TASE.2 minimum of 2 (D-015).
- **G11, data of a later edition.** The server sends a data value with tag 17 (utc-time), which the
  Data choice of the profile's edition does not define. The stack keeps it raw, as an unsupported
  alternative (decision D-004).

- **G12, list scope.** The reference server refuses a named variable list whose name is in the domain
  (`DefineNamedVariableList` with a domain-specific list name), with `object-non-existent`; two members
  tried, a floating-point and a boolean variable, both refused. A list at the VMD scope is accepted. The stack sends what the standard describes; the
  refusal comes from the peer. Recorded by the matrix of task T4; the domain scope is not used by the
  scenarios.
- **Fixed in T4: unconfirmed PDUs checked against their sender (D-023).** The reference server's
  information report uses `variableListName`, which needs the `vlis` CBB it did not negotiate. It was
  refused as `unrecognized-service`, because the check used this end's view for every unconfirmed PDU.
  An incoming report is now checked against the peer's view, as the standard's negotiation requires: under
  the conformant default it stays refused (G8); with the lenient option it is delivered.

- **G1, release by ACSE not answered by the peer.** After the CONCLUDE response, the peer does not
  answer the ACSE release (RLRQ): no RLRE, with or without the normal reason, in 3 seconds. The stack
  waits for the RLRE, as ISO 9506-2 Annex A.1.2.1 requires. The scenario therefore ends the
  association with an abort after the CONCLUDE response. Decided in task T2 (D-021): the client
  closes by a CONCLUDE, and aborts when the release is not confirmed within the request timeout.
- **G2, direction.** Tested in both directions since task S3: the reference client runs its commands
  against this repository's server (`bench/tests/test_s3_device.py`, transcript in `docs/ai-log/S3.md`):
  identify, the domain list, the variable list and reads. The reference client's journal query is refused
  (G14).
- **G13, legacy application context.** The reference client proposes the application context
  `1.0.9506.2.3`, the arc of the MMS annex module, not the one of ISO 9506-2 Annex A.7 (`1.0.9506.2.5`).
  The responder accepts both, and answers with the name it was proposed (D-027). The initiator still
  proposes only `1.0.9506.2.5`. Before S3 the server refused the reference client with
  application-context-name-not-supported.
- **G14, journals.** The reference client, asked for the variables of a domain (`mms_utility -t`), then asks
  for its journals. The server does not hold the journal class: it answers with a service error, and the
  client reports `Failed to read domain journals (error=82)` and exits with status 82. The variables are
  listed before that error. The journal class is outside the model (`docs/capabilities.md`, S1).
- **G3, refused association.** No scenario checks a refusal by the peer. The refusal paths are
  covered by the loopback tests of task L4.
- **G4, services beyond Identify.** Closed by the matrix of task T4 (above) for the nine services in scope,
  with the lenient option where G8 applies.
- **G5, version-dependent PDUs.** The peer negotiates version 1. The PDUs that ISO 9506-2 forbids in
  minor versions 1 and 2 are not refused by this stack yet (see D-018).
- **G6, Wireshark artefact (not a defect of the stack).** The RLRQ of the release, an ACSE APDU with
  no user information, makes tshark's MMS dissector run on zero bytes (`zero-byte MMS PDU`). The
  bench counts this expert message, and accepts it once per capture.
