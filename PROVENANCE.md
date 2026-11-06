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
- **Test**: to be written (task F4).

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

## Third-party code and sources

| Source | Licence | Use | Provenance |
| --- | --- | --- | --- |
| libiec61850 | GNU GPL v3, to be confirmed at task F5 | Reference peer of the bench, black box only | Source never read |
