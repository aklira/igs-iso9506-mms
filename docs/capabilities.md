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

- **G1, release by ACSE not answered by the peer.** After the CONCLUDE response, the peer does not
  answer the ACSE release (RLRQ): no RLRE, with or without the normal reason, in 3 seconds. The stack
  waits for the RLRE, as ISO 9506-2 Annex A.1.2.1 requires. The scenario therefore ends the
  association with an abort after the CONCLUDE response. Decided in task T2 (D-021): the client
  closes by a CONCLUDE, and aborts when the release is not confirmed within the request timeout.
- **G2, direction.** Only the stack as client was tested against the peer. The reference client
  connecting to this stack as server needs the server (phase S).
- **G3, refused association.** No scenario checks a refusal by the peer. The refusal paths are
  covered by the loopback tests of task L4.
- **G4, services beyond Identify.** The bench scenario runs Identify only. The reads, writes and
  name lists are for the client tasks (T2, T4).
- **G5, version-dependent PDUs.** The peer negotiates version 1. The PDUs that ISO 9506-2 forbids in
  minor versions 1 and 2 are not refused by this stack yet (see D-018).
- **G6, Wireshark artefact (not a defect of the stack).** The RLRQ of the release, an ACSE APDU with
  no user information, makes tshark's MMS dissector run on zero bytes (`zero-byte MMS PDU`). The
  bench counts this expert message, and accepts it once per capture.
