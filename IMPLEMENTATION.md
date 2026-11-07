# Implementation plan

This plan drives the implementation of `igs-iso9506-mms` up to a ready-to-use 1.0 release. It is
written for an AI coding agent working task by task. It follows the method of `igs-iec104`, with
one change: **the agent decides and records; it does not stop to ask** (rule 10).

Scope of 1.0: the OSI upper layers over TCP (TPKT, COTP, session, presentation, ACSE), the MMS
services that TASE.2 needs (the list comes from task P4), an MMS client and a multi-client MMS
server, TLS per IEC 62351-3. The design stays usable by IEC 61850 later. Other MMS services decode
to an unsupported variant that keeps the raw bytes.

---

## 1. Rules for the agent (read before every task)

1. **Clean room.** Never open, quote, reconstruct or describe the source code of libiec61850,
   rusty-iccp, or any other MMS or ICCP implementation; nor the `mms.asn` of Wireshark, nor the
   derived ASN.1 files published by NettedAutomation. Reference implementations are only ever run
   as separate processes in the interop bench.
2. **No standard text in this repository.** ISO and IEC standards are licensed. Never paste text
   from `docs/spec/` into code, comments, docs, tests or commit messages. Never commit an `.asn`
   file or a file of `docs/spec/`. Cite the clause (`// ISO 9506-2 §8.2`) and write in your own
   words. Facts such as tags, sizes, bit positions and service lists may be used as data.
3. **English only** for everything committed: code, comments, docs, commit messages.
4. **Every protocol behaviour needs a source.** Take values from the data files of section 3, not
   from memory. If the standard is silent or ambiguous, choose the reading best supported by the
   clauses, record it as a `D-nnn` entry of `PROVENANCE.md` with its confidence and a test, and go
   on. Do not wait for an answer.
5. **One task at a time.** Read only the inputs listed for the task. Keep each change small (aim for
   under 400 changed lines per commit). Do not start a task whose dependencies are not checked.
6. **Done means green.** A task is done only when all its done criteria pass, plus the standard gate:
   ```
   cargo fmt --all --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo test --workspace --all-features
   cargo deny check
   ```
7. **Commit per task, never push.** Nothing leaves this machine before task R1: code generated from
   the ISO modules mirrors their structure, and its publication needs a legal review. Message:
   `<crate or area>: <what>` then a blank line and `Task: <ID>`. Tick the task's box in section 6
   in the same commit.
8. **Safety.** `#![forbid(unsafe_code)]` in `igs-iso9506-mms-codec` and `igs-iso9506-mms-link`. No
   `unwrap`, `expect`, indexing that can panic, or unchecked arithmetic on data from the network:
   return `Result`. Bound every length and every nesting depth read from the wire.
9. **Dependencies** must be MIT, Apache-2.0, BSD or ISC and pass `cargo deny`. Prefer the ones
   already used by `igs-iec104`. A new dependency is recorded in `PROVENANCE.md` with its reason.
10. **Decide and record.** The only human gate is task R1 (⛔). Choices with written criteria (the
    codec approach, the reference peer, the exit of a phase) are made by the agent against those
    criteria and recorded in `PROVENANCE.md` and the ai-log. A failing criterion is fixed, or
    recorded as a known gap in `docs/capabilities.md`; it does not stop the plan.
11. **Log prompts.** Archive the prompt and a short summary of each task in
    `docs/ai-log/<task-id>.md` (no standard text).
12. **Reading the licensed text.** The agent may read `docs/spec/` and the PDFs, local or online,
    under the standing authorization recorded in `.claude/CONTEXT.md`. It reads only what the task
    needs (rule 5). Rule 2 still holds: nothing it reads goes into this repository.

---

## 2. Architecture (summary)

Cargo workspace:

| Crate | Role | I/O | async |
| --- | --- | --- | --- |
| `igs-iso9506-mms-codec` | BER (X.690 subset), TPKT, COTP TPDUs, session SPDUs, presentation PPDUs, ACSE APDUs, MMS PDUs and common types | none | no |
| `igs-iso9506-mms-link` | Sans-I/O connection state machines: COTP, session, presentation, ACSE, MMS association, invoke IDs | none | no |
| `igs-iso9506-mms` | Public API: `Client`, `Server`, VMD model, TLS, binaries `igsmms-client` and `igsmms-server` | TCP/TLS (tokio) | yes |
| `xtask` | Code generation and maintenance commands (not published) | files | no |

Design rules:

- **Sans-I/O stack**: the link takes events (bytes received, current instant, user requests) and
  returns actions (bytes to send, PDUs to deliver, next wake-up time, close).
- **Strong types**: one service = one enum variant; identifiers, invoke IDs and tags are newtypes;
  an invalid PDU cannot be built.
- **Two-level validation**: structural decoding in the codec; a separate check against the CBBs
  negotiated by Initiate, which the client and server call. This is the role that the 104 profile
  plays in `igs-iec104`.
- **All conditions true**: the generated types come from the `IF` variant of the modules (D-001).
- **Reusable by TASE.2 and IEC 61850**: nothing specific to either in this repository.

---

## 3. Sources of truth

`docs/spec/` is a local symlink to the private standards repository; it is ignored by git and not
available in CI. Read `docs/spec/<standard>/INDEX.md` first, then only the section you need. The
section files of 9506-1 and 9506-2 are found by clause number. The ASN.1 of `sections/` is not a
source: it was reformatted by a language model.

**Data files (use these for any value that becomes code):**

| File | Content |
| --- | --- |
| `docs/spec/9506-2/data/asn1/variante_if/*.asn` | MMS modules, directives resolved, decisions applied |
| `docs/spec/9506-1/data/asn1/variante_if/MMS-Object-Module-1.asn` | Object module |
| `docs/spec/X.227/data/asn1/variante_if/ACSE-1.asn` | ACSE (amendment 1) |
| `docs/spec/X.501/`, `docs/spec/X.520/` `data/asn1/` | `Name`, for the AP-title form 1 only |
| `docs/spec/9506-2/data/profile_mms.yaml` | Task P3: CBBs, services, tags |
| `docs/spec/6-702/data/conformance_702.yaml` | Task P4: services and stack requirements of TASE.2 |
| `PROVENANCE.md` | Decisions on ambiguities |

**Sections by topic:**

| Topic | Sections |
| --- | --- |
| PDU structure, common types | 9506-2 §7 |
| Directives, effective protocol | 9506-2 §5.14, §5.15 |
| Entering the MMS environment, errors, Reject | 9506-2 §6 |
| Initiate, Conclude, Abort, Cancel, Reject | 9506-2 §8, 9506-1 §8 |
| Status, GetNameList, Identify | 9506-2 §10, 9506-1 §10 |
| Variable access | 9506-2 §14, 9506-1 §14 |
| Mapping to the lower services, presentation contexts | 9506-2 §24, annex A |
| Service semantics and errors | 9506-1 §5, §24 |
| MMS on TCP/IP | 9506-1 annex F |
| Stack required by TASE.2 | 6-702 §5, §6 |
| BER | X.690 (free text) |
| TPKT | RFC 1006, RFC 2126 (free text) |
| COTP, session, presentation | X.224, X.225, X.226 (task P1) |
| ACSE | X.227 (free text) |
| TLS profile | 62351-3 |

Figures are missing from the prepared text (`[FIGURE ... MISSING]`). **The PDF is the authority**
when text and data disagree. When a task depends on a figure, read it in the PDF.

---

## 4. Phases and tasks

Each task lists: **Depends**, **Read**, **Produce**, **Done when**.

### Phase P — Inputs (done in `~/Dev/norm_preparation`, committed there)

**P1 — Free OSI texts**
- Produce: `prepare_norm.py` on X.224, X.225, X.226 and their amendments, X.690, and the same for
  RFC 1006 and RFC 2126 if useful; output in `docs/spec/X.224/` and so on.
- Done when: each `REPORT.md` is read and its points noted in `CONTEXT.md`.

**P2 — Presentation ASN.1**
- Produce: `extract_asn1.py` on X.226 and its amendments; modules in `docs/spec/X.226/data/asn1/`.
- Done when: the module parses, or its anomalies are settled in a decisions file.

**P3 — MMS profile data**
- Read: the `IF` variant, 9506-2 §5.14, §8.2, §25.
- Produce: `docs/spec/9506-2/data/profile_mms.yaml`, by a script: for each service its tag, PDU
  family and CBB; parameter CBBs and their bit positions; error classes.
- Done when: counts match the modules; every bit position is checked against the ASN.1.

**P4 — TASE.2 conformance data**
- Read: 6-702 PDF, tables of §6 and annex A.
- Produce: `docs/spec/6-702/data/conformance_702.yaml`, by a script from the PDF (not from
  `sections/`): MMS services, stack requirements, conformance blocks, each with its m/o/c/i status.
- Done when: the line-by-line comparison of TEMPLATE §6.1 matches the counts of short cells.

### Phase 0 — Foundations

**F1 — Workspace skeleton**
- Depends: none.
- Produce: root `Cargo.toml`, `rust-toolchain.toml`, the four crates, workspace lints as in
  `igs-iec104`, `deny.toml`, Apache-2.0 SPDX header in each source file.
- Done when: standard gate passes on the empty crates.

**F2 — Continuous integration and ai-log**
- Depends: F1.
- Produce: `.github/workflows/ci.yml` as in `igs-iec104` (the workflow must not need `docs/spec/`);
  `docs/ai-log/README.md`.
- Done when: the gate passes locally.

**F3 — Codec approach**
- Depends: F1.
- Produce: a short trial on `Data`, `ConfirmedServiceRequest` and one ACSE APDU, comparing a BER
  codec and generator of this project with `rasn` and `rasn-compiler`. Criteria, in order: all
  rule 8 guarantees can be held; the extension marker of the two service CHOICEs is handled; the
  generated code needs no hand edits; the dependency is justified. Default choice if no criterion
  separates them: the project's own codec.
- Done when: the choice is recorded in `PROVENANCE.md` and `docs/ai-log/F3.md`.

**F4 — Code generation**
- Depends: F3, P3.
- Produce: `cargo xtask codegen` reading the data files and writing
  `crates/igs-iso9506-mms-codec/src/generated/`: types with their tags, CBB and service tables,
  behind a "generated, do not edit" banner citing its sources by clause. No comment of a module is
  copied. Generated files are committed; `cargo xtask codegen --check` fails when they are stale.
- Done when: the generated code compiles and a test asserts the service and CBB counts.

**F5 — Interop bench skeleton**
- Depends: F1.
- Produce: `bench/` as in `igs-iec104`: `pyproject.toml` (pytest), `docker-compose.yml`, capture
  helper (`tcpdump`), assertion helper (`tshark -T json`). Reference peer: an MMS server and client
  built from the libiec61850 examples inside a container, as a black box; the Dockerfile fetches and
  builds them and nobody reads their source. Record licence and version in `PROVENANCE.md`.
- Done when: one scenario connects an existing MMS client to the peer and the capture decodes in
  `tshark` without errors.

### Phase 1 — Codec (`igs-iso9506-mms-codec`)

**C1 — BER**
- Depends: F3.
- Read: X.690.
- Produce: tag, length and value reader and writer: definite and indefinite lengths on decode as
  the standard allows, primitive types, bounded nesting.
- Done when: hand-written vectors for each type; malformed lengths are refused with a typed error.

**C2 — TPKT and COTP TPDUs**
- Depends: P1.
- Read: RFC 1006, X.224.
- Produce: TPKT framing; CR, CC, DT, DR, ER TPDUs of class 0; an incremental frame decoder.
- Done when: frames split at every byte boundary and concatenated frames decode.

**C3 — Session SPDUs**
- Depends: P1.
- Read: X.225.
- Produce: the SPDUs of the kernel functional unit that the stack needs, per task P4.
- Done when: round trips and hand-written vectors for each SPDU.

**C4 — Presentation PPDUs**
- Depends: C1, P2.
- Read: X.226.
- Produce: CP, CPA, CPR, ARU, ARP and user data, with presentation contexts.
- Done when: round trips; hand-written vectors.

**C5 — ACSE APDUs**
- Depends: C1, F4.
- Read: X.227.
- Produce: AARQ, AARE, RLRQ, RLRE, ABRT. AP-title form 2; form 1 decodes to raw bytes.
- Done when: round trips; hand-written vectors.

**C6 — MMS common types**
- Depends: C1, F4.
- Read: 9506-2 §7.5, §14.
- Produce: `Data`, `TypeSpecification`, `ObjectName`, `AccessResult`, `TimeOfDay`, `FloatingPoint`,
  with range-checked constructors; the alternatives and the formats of the prose (TimeOfDay octets,
  floating point fields) from the clauses.
- Done when: each type round-trips; min and max values tested.

**C7 — MMS PDUs**
- Depends: C6, P4.
- Read: 9506-2 §7, §8, §10, §14.
- Produce: the PDU CHOICE; requests and responses of the services in scope; other services decode
  to an unsupported variant with the raw bytes; a separate `validate_cbb(&Pdu, &Negotiated)`.
- Done when: a test vector per service in scope; each CBB refusal tested.

**C8 — Property tests**
- Depends: C2 to C7.
- Produce: `proptest` strategies; `decode(encode(x)) == x`; random bytes never panic.
- Done when: 10 000 cases per property pass.

**C9 — Fuzzing**
- Depends: C8.
- Produce: `fuzz/` (cargo-fuzz) targets for the frame decoder, BER and the PDU, seeded from the
  vectors. The agent runs a campaign of at least 8 hours in the background.
- Done when: no crash; result recorded in `docs/ai-log/C9.md`.

### Phase 2 — Link (`igs-iso9506-mms-link`)

**L1 — Parameters**
- Depends: C2.
- Produce: `LinkConfig` (TSAP, SSAP, PSAP selectors, AP-title, TPDU size, timeouts, maximum
  outstanding requests), defaults and validation from the clauses and P4.
- Done when: tests for defaults and invalid configurations.

**L2 — COTP connection**
- Depends: L1.
- Read: X.224, RFC 1006.
- Produce: sans-I/O class 0 connection: `handle(event, now) -> Vec<Action>`, TPDU size negotiation,
  segmentation and reassembly with a bounded size.
- Done when: deterministic fake-clock tests, both roles.

**L3 — Session and presentation connection**
- Depends: L2, C3, C4.
- Produce: connect, accept, refuse, release, abort, on both roles.
- Done when: fake-clock tests for each path.

**L4 — Association and Initiate**
- Depends: L3, C5, C7.
- Read: 9506-2 §8, §24, annex A.
- Produce: ACSE association carrying Initiate; negotiation of parameters and CBBs; Conclude, Abort.
- Done when: tests for each negotiation result, and for a refused association.

**L5 — Requests**
- Depends: L4.
- Read: 9506-2 §6, §8.5, §8.6.
- Produce: invoke IDs, outstanding limit, response matching, timeouts, Cancel, Reject, unconfirmed
  PDUs.
- Done when: fake-clock tests, including a response with an unknown invoke ID.

**L6 — Interop of the stack**
- Depends: L5, T1, F5.
- Produce: bench scenarios: association, Initiate, Conclude, Abort, in both directions as the peer
  allows.
- Done when: the scenarios pass, or the gap is recorded (rule 10).

### Phase 3 — Client (`igs-iso9506-mms`)

**T1 — Transport**
- Depends: L3.
- Produce: async driver over `tokio::net::TcpStream`, generic over a stream trait so that TLS plugs
  in later; clean shutdown; error types.
- Done when: tests against an in-process loopback using `tokio::time::pause`.

**T2 — Client API**
- Depends: T1, L5.
- Produce: `Client`: connect and reconnect policy, the services in scope, an event stream of
  unconfirmed reports and connection state, bounded channels with documented back-pressure.
- Done when: integration tests against the loopback for each service.

**T3 — `igsmms-client` binary**
- Depends: T2.
- Produce: CLI (clap) to connect, browse names, read, write, print decoded PDUs.
- Done when: `--help` documented; a run against the bench peer recorded in the ai-log.

**T4 — Client interop matrix**
- Depends: T2, F5.
- Produce: bench scenarios against the reference server, for each service in scope.
- Done when: the matrix passes; gaps recorded (rule 10).

### Phase 4 — Server

**S1 — VMD model**
- Depends: C6.
- Read: 9506-1 §7, §14.
- Produce: typed model of the VMD: domains, named variables, named variable lists, with access
  through a trait so that TASE.2 and IEC 61850 can supply their own objects.
- Done when: unit and property tests.

**S2 — Server**
- Depends: S1, T1, L5.
- Produce: multi-client `Server`: Initiate, the services in scope, unsolicited reports, CBB check on
  every PDU, Reject and error responses.
- Done when: integration tests per service with the `Client`.

**S3 — `igsmms-server` binary**
- Depends: S2.
- Produce: demo server with variables from a TOML file; usable as the bench device under test.
- Done when: documented; a run against the bench peer recorded.

**S4 — Server interop and load**
- Depends: S3, F5.
- Produce: bench scenarios with the reference client; load test with 50 clients.
- Done when: the matrix passes; latency measured and recorded; gaps recorded (rule 10).

### Phase 5 — TLS, documentation, release

**X1 — TLS**
- Depends: T1.
- Read: 62351-3, 6-702 §5.
- Produce: `TlsBackend` trait and `rustls` backend, reusing the design of `igs-iec104`. Application
  security of IEC 62351-4 is out of scope: that standard is not available.
- Done when: loopback TLS tests for client and server.

**X2 — Documentation and examples**
- Depends: T2, S2.
- Produce: rustdoc on every public item, `examples/`, README quick start, `CHANGELOG.md`.
- Done when: `cargo doc --no-deps` has no warnings; examples compile in CI.

**X3 — Supported service matrix**
- Depends: T4, S4.
- Produce: `docs/capabilities.md`: services, CBBs, the test covering each row, known gaps.
- Done when: every row names a test that exists.

**R1 — Legal review and release** ⛔
- Depends: all previous tasks.
- Gate (the only human gate): legal review of publishing code generated from the ISO modules,
  similarity check against libiec61850, crates.io names, git push and tag.
- Done when: a maintainer approves and publishes 1.0.0.

---

## 5. Definition of "ready to use" (1.0)

- Client and multi-client server interoperate with the reference peer on the bench matrix.
- Every service in scope encodes and decodes; CBB violations are refused; no panic on any input.
- `igs-iec-tase2` builds on this library without any change to it.
- Public API documented with examples; binaries usable.
- Every non-trivial behaviour traceable to a clause or an entry of `PROVENANCE.md`.

---

## 6. Progress

| Task | Status |
| --- | --- |
| P1 Free OSI texts | [x] |
| P2 Presentation ASN.1 | [x] |
| P3 MMS profile data | [x] |
| P4 TASE.2 conformance data | [x] |
| F1 Workspace skeleton | [x] |
| F2 Continuous integration and ai-log | [x] |
| F3 Codec approach | [x] |
| F4 Code generation | [x] |
| F5 Interop bench skeleton | [x] |
| C1 BER | [x] |
| C2 TPKT and COTP TPDUs | [x] |
| C3 Session SPDUs | [x] |
| C4 Presentation PPDUs | [x] |
| C5 ACSE APDUs | [x] |
| C6 MMS common types | [x] |
| C7 MMS PDUs | [x] |
| C8 Property tests | [x] |
| C9 Fuzzing | [ ] |
| L1 Parameters | [x] |
| L2 COTP connection | [x] |
| L3 Session and presentation connection | [x] |
| L4 Association and Initiate | [x] |
| L5 Requests | [x] |
| L6 Interop of the stack | [x] |
| T1 Transport | [x] |
| T2 Client API | [x] |
| T3 `igsmms-client` binary | [x] |
| T4 Client interop matrix | [x] |
| S1 VMD model | [x] |
| S2 Server | [x] |
| S3 `igsmms-server` binary | [ ] |
| S4 Server interop and load | [ ] |
| X1 TLS | [ ] |
| X2 Documentation and examples | [ ] |
| X3 Supported service matrix | [ ] |
| R1 Legal review and release ⛔ | [ ] |

Suggested order: P1–P4, F1, F2, F3, F4, F5, C1–C8, L1–L3, T1, L4, L5, L6, T2–T4, S1–S4, X1–X3, C9
(in the background from C8 on), R1.
