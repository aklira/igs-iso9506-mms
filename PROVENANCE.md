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

## Third-party code and sources

| Source | Licence | Use | Provenance |
| --- | --- | --- | --- |
| libiec61850 | GNU GPL v3, to be confirmed at task F5 | Reference peer of the bench, black box only | Source never read |
