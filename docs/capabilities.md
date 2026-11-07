# Capabilities and known gaps

What the stack does, and what it does not, as observed against the reference peer of the bench
(task L6, `bench/tests/test_l6_interop.py`) or as decided. Rule 10 of `IMPLEMENTATION.md`: a failing
criterion is fixed, or recorded here.

## Against the reference server (libiec61850 v1.6.2.1, `server_example_basic_io`)

| Scenario | Result |
| --- | --- |
| TCP, COTP connection with the 8192-octet TPDU size | Works |
| Association: Initiate, negotiation (version 1, outstanding 5, nesting 2) | Works |
| Confirmed Identify, answered with the vendor name | Works |
| Abort by the user | Works; the peer closes the stream |
| Conclude: CONCLUDE request, CONCLUDE response | Works |

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
