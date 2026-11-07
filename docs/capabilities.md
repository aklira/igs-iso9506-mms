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

## Gaps

- **G1, release by ACSE not answered by the peer.** After the CONCLUDE response, the peer does not
  answer the ACSE release (RLRQ): no RLRE, with or without the normal reason, in 3 seconds. The stack
  waits for the RLRE, as ISO 9506-2 Annex A.1.2.1 requires. The scenario therefore ends the
  association with an abort after the CONCLUDE response. Decision for task T2: whether the client
  treats the CONCLUDE response as the end of the association after a timeout. Not decided here, since
  Annex A makes the RLRE a requirement.
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
