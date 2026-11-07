# Provenance

This file links every non-trivial behaviour of `igs-iso9506-mms` to its source: a clause of a standard, an
observation test, or third-party code under a permissive licence. The project is a clean-room
implementation: no protocol behaviour without a source recorded here or in a
`// ISO 9506-2 §8.2` comment.

The ISO and IEC standards are licensed and are not distributed with this repository. The references
below point to clauses; they do not reproduce the text of the standards.

## Reference standards

| Standard | Edition | Use |
| --- | --- | --- |
| ISO 9506-1 | 2003 | MMS services |
| ISO 9506-2 | 2003 | MMS protocol, ASN.1 |
| ITU-T X.224, X.225, X.226, X.227 | Editions in force | Transport, session, presentation, ACSE (free texts) |
| ITU-T X.690 | 02/2021 | BER (free text) |
| ITU-T X.501, X.520 | 11/1993 | `Name`, for the AP-title form 1 (free texts) |
| RFC 1006, RFC 2126 | | TPKT over TCP |
| IEC 62351-3 | 2023 | TLS profile |
| IEC 60870-6-702 | 2014 | Stack and services required by TASE.2 |

## Decisions on ambiguities in the standard

Confidence: **high** when the sources agree; **medium** when they contradict each other or are
silent, to be confirmed by an observation test against other implementations.

### D-001 — Generated types come from the variant with all conditions true

- **Decision**: the module of ISO 9506-2 is written with `IF`, `ELSE` and `ENDIF` directives
  (§5.14). The generated types use the `IF` branches. What a given association may use is checked
  separately, against the CBBs negotiated by Initiate.
- **Sources**: ISO 9506-2 §5.14, §5.15.
- **Confidence**: high.
- **Test**: to be written (task C7).

### D-002 — Defects of the published module

- **Decision**: the published module has unbalanced directives and misplaced punctuation, settled
  by 23 decisions in the private standards repository (pages 33, 35, 45, 52, 53, 60, 61, 94, 97,
  113, 119, 166). Lines of prose set in the code font (pages 60, 94) are not part of the module.
  `filename` on page 61 is read as the type `FileName`.
- **Sources**: ISO 9506-2, PDF, each page checked; parallel constructions of the same module.
- **Confidence**: high, except the place of the `ENDIF` of page 119: medium.
- **Test**: `cargo xtask codegen` parses every type of the corrected modules and fails otherwise;
  `crates/igs-iso9506-mms-codec/tests/generated.rs` checks the counts.

### D-003 — The project writes its own BER codec and generator

- **Decision**: the codec and `xtask codegen` are written in this project; `rasn` and
  `rasn-compiler` are not used. Task F3 compared the two on the criteria of the plan, in order.
- **Criterion 1, rule 8 guarantees**: does not separate them. `rasn` 0.30 returned an error on
  nesting up to 100,000 levels and on oversized lengths, on a 2 MiB stack, and did not panic on
  3 million noisy inputs. Its depth limit is fixed at 128, its decoding path is outside our lints,
  and it holds two `unsafe` blocks. The prototype of this project gave the same results with the
  lints of rule 8 active.
- **Criterion 2, extension markers**: `rasn-compiler` 0.16 refuses the end marker, in the two
  service CHOICEs and in five ACSE APDUs. The prototype reads them.
- **Criterion 3, no hand edits**: separates them. After three rewrites of the input (end markers,
  ACSE constraints, classes and information objects removed), `rasn-compiler` still produced code
  with 63 compile errors, 15 of them in the main MMS module. The prototype's output compiled
  unedited.
- **Criterion 4, dependency**: not justified, 35 crates for a function that the project can hold.
- **Also**: `rasn` rejects an unknown tag, whereas the scope asks for an unsupported variant that
  keeps the raw bytes. A hand-written wrapper would be needed.
- **Limits of the trial**: the prototype covers three productions and leaves service and ACSE
  field contents raw. The noise run is not a fuzzing campaign. `rasn-compiler` was tried at one
  version, with quick rewrites of the input.
- **Sources**: `docs/ai-log/F3.md`.
- **Confidence**: high for criteria 2 and 3.
- **Test**: the fuzz and property tests of the codec tasks.

### D-004 — Scope of the generated types

- **Decision**: the generator emits the types reachable from the MMS PDU and the ACSE APDU. The
  service CHOICEs keep the services that the profile requires and gain an `Unsupported` variant.
  Modifiers, the `service-ext` details, additional services, service-specific error information
  and `Name` stay raw BER. Every service, CBB and code stays in the tables, in or out of scope.
- **Sources**: IEC 60870-6-702 annex A, tables A.17 to A.32; the scope of `IMPLEMENTATION.md`.
- **Confidence**: high.
- **Test**: `crates/igs-iso9506-mms-codec/tests/generated.rs`.

### D-005 — Integers and DEFAULT in the generated types, for now

- **Decision**: an INTEGER is an `i64` in a newtype that carries its named values and allowed
  ranges; a component with DEFAULT is an `Option`, and its value stays in the component table.
  Range-checked constructors and the default values on decoding come with tasks C5 to C7.
- **Sources**: rule of strong types in `IMPLEMENTATION.md` section 2; X.680.
- **Confidence**: medium: `Data` may carry an integer wider than 64 bits, to settle in task C6.
- **Test**: to be written (task C6).

### D-006 — Dependencies of `xtask`

- **Decision**: `xtask` reads YAML with `serde` and `serde-saphyr` (MIT or Apache-2.0). It requires
  Rust 1.89, while the library crates stay at 1.85; it is not published and runs on a development
  machine only, so the minimum-version job excludes it. `serde_yaml` would need an advisory
  exception. `Unicode-3.0` joins the accepted licences for `unicode-ident`, a permissive licence
  on data tables, reached through `serde_derive`; `igs-iec104` accepts it too.
- **Sources**: rule 9 of `IMPLEMENTATION.md`; `cargo deny check`.
- **Confidence**: high.
- **Test**: the workflow and `cargo deny check`.

### D-007 — What the BER layer accepts and writes

- **Decision**: decoding accepts every choice X.690 leaves to a BER sender: long or short length
  forms, extra length octets (§8.1.3.5, note 2), the indefinite form on constructed encodings,
  constructed BIT STRING, OCTET STRING and character strings, any non-zero octet as TRUE. It
  refuses what X.690 forbids to every sender: an INTEGER with a redundant leading octet (§8.3.2),
  a tag number in a needless high-tag form (§8.1.2.4), the reserved length octet. Encoding writes
  definite lengths in the fewest octets, primitive strings and TRUE as `FF`, as DER does.
  GraphicString is read without escape sequences, so as printable ASCII. Nesting stops at 64
  constructed levels by default, a value the caller can change.
- **Sources**: ITU-T X.690 §8.1 to §8.8, §8.19, §8.23, §10, §11.1.
- **Confidence**: medium for the refusal of redundant INTEGER octets and for GraphicString:
  some peers might send them. To check on the bench (tasks L6, T4, S4).
- **Test**: `crates/igs-iso9506-mms-codec/tests/ber.rs`.

### D-008 — The TPDU decoder checks structure, the connection checks class 0

- **Decision**: decoding accepts in a CR or CC TPDU what class 0 does not allow but a peer sends:
  TPDU sizes of 4096 and 8192 octets, other classes, user data (RFC 1006 allows it for testing),
  a CR TPDU over 128 octets. The connection of task L2 decides what to accept. Decoding refuses
  what breaks the structure: a reserved length indicator, a header that does not fit, a parameter
  running past the header, a TPDU type outside class 0, a DT TPDU with a variable part. Each
  refusal carries the ER reject cause and the offset of the octet in fault (X.224 §13.12). The
  reserved octet of the TPKT header is ignored on receipt and written as zero.
- **Sources**: ITU-T X.224 §13.2 to §13.5, §13.7, §13.12; RFC 1006 §6. Observation: the reference
  client of the bench proposes 8192 octets and the reference server confirms it (task F5).
- **Confidence**: high.
- **Test**: `crates/igs-iso9506-mms-codec/tests/transport.rs`.

### D-009 — Session SPDUs: what is decoded, and what is kept

- **Decision**: the SPDUs of the kernel and duplex functional units are decoded field by field:
  CONNECT, ACCEPT, REFUSE, FINISH, DISCONNECT, ABORT, ABORT ACCEPT, GIVE TOKENS and DATA TRANSFER.
  Other SPDUs and unknown parameter codes, which §8.2.6 declares valid, are kept as received.
  A TSDU holds one SPDU, or GIVE TOKENS or PLEASE TOKENS followed by one category 2 SPDU (basic
  concatenation); extended concatenation, segmenting, OVERFLOW ACCEPT and CONNECT DATA OVERFLOW are
  out of the profile. Units are written in increasing code order (§8.2.6) and read in any order.
  A three-octet length indicator is read for short lengths too, and written only from 255. User
  data of a CONNECT SPDU goes in the User Data parameter up to 512 octets, else in the Extended User
  Data parameter up to 10 240.
- **Sources**: ITU-T X.225 §6.3.7, §8.2, §8.3.1 to §8.3.11, §8.3.16; IEC 60870-6-702 table A.61
  (version 2, duplex, extended concatenation and overflow out of scope). Observation: the CONNECT,
  ACCEPT and GIVE TOKENS with DATA TRANSFER of the bench peers decode and re-encode octet for octet.
- **Confidence**: high.
- **Test**: `crates/igs-iso9506-mms-codec/tests/session.rs`.

### D-010 — Presentation PPDUs, written by hand on the BER layer

- **Decision**: CP, CPC, CPA, CPR, ARU and ARP are coded by hand on the BER layer of task C1, not
  generated: one small module, needed before the generator has decoding (tasks C5 to C7). Normal
  mode is decoded; X.410-1984 mode, outside the profile, is kept as raw BER. As §8.5 requires, a
  CP PPDU ignores undefined elements and unnamed bits, while the other PPDUs refuse them, as they
  refuse numbers with no name. The components of a SET are read in any order and written in tag
  order. User data is decoded in both encodings: simple, which the profile requires (IEC
  60870-6-702 §6.4), and full, which the bench peers use. The contents of a single-ASN1-type PDV
  must be exactly one encoding; they are kept as octets for ACSE and MMS to decode.
- **Sources**: ITU-T X.226 §8.2 to §8.5; IEC 60870-6-702 §6.4, table A.60. Observation: the CP,
  CPA and data user data of the bench peers decode and re-encode octet for octet.
- **Confidence**: high.
- **Test**: `crates/igs-iso9506-mms-codec/tests/presentation.rs`.

## Third-party code and sources

| Source | Licence | Use | Provenance |
| --- | --- | --- | --- |
| libiec61850 | GPL-3.0 (`COPYING`, GitHub licence metadata) | Reference peer of the bench, tag `v1.6.2.1`, commit `c28c27c`, black box only; image built locally, not distributed | Source never read |
