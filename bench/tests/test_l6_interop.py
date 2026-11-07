# SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
#
# SPDX-License-Identifier: Apache-2.0
"""L6: this repository's MMS stack, run on the host, against the reference server of the bench.

The Rust scenarios (crates/igs-iso9506-mms/tests/interop.rs) drive the stack; this file starts the
reference server with a capture, runs them, and checks the capture decodes cleanly in tshark.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from igs_bench import capture, tshark

REPO = Path(__file__).resolve().parents[2]
PEER = "127.0.0.1:10102"


# Known artefact of Wireshark, not a defect of the stack: an ACSE APDU without user information (the
# RLRQ of the release) makes its MMS dissector run on zero bytes. The release is standard (ISO 9506-2
# Annex A.1.2.1, ITU-T X.227). The expert message is filtered here, and counted.
KNOWN_ARTEFACT = '_ws.expert.message == "Internal error, zero-byte MMS PDU"'
ERRORS = "_ws.malformed || _ws.expert.severity == error"


def _lines(bench, display_filter: str) -> list[str]:
    out = bench.exec("capture", "tshark", "-r", f"/captures/{bench.capture_name}", "-Y", display_filter)
    return [line for line in out.stdout.splitlines() if line.strip()]


def _unexpected_errors(bench) -> list[str]:
    return _lines(bench, f"({ERRORS}) && !({KNOWN_ARTEFACT})")


def _known_artefacts(bench) -> int:
    return len(_lines(bench, KNOWN_ARTEFACT))


def _run_scenarios(name: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "MMS_PEER": PEER}
    return subprocess.run(
        ["cargo", "test", "-p", "igs-iso9506-mms", "--test", "interop", "--", "--ignored", "--test-threads=1", name],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        timeout=900,
    )


def test_stack_negotiates_and_concludes_with_the_reference_server(bench):
    bench.up("ref-server", "capture")
    capture.wait_live(bench)

    result = _run_scenarios("the_association_is_negotiated_and_concluded_with_the_reference_server")
    pcap = capture.stop(bench)
    assert pcap.is_file()

    frames = tshark.decode(bench)
    for frame in frames:
        print(frame.number, frame.src, ":".join(frame.protocols), frame.info)
    assert _unexpected_errors(bench) == []
    assert _known_artefacts(bench) <= 1, "only the release frame may carry the artefact"
    assert result.returncode == 0, result.stdout + result.stderr


def test_stack_identifies_and_aborts_with_the_reference_server(bench):
    bench.up("ref-server", "capture")
    capture.wait_live(bench)

    result = _run_scenarios("a_confirmed_identify_is_answered_by_the_reference_server")
    result_abort = _run_scenarios("an_abort_ends_the_association_on_both_ends")
    capture.stop(bench)
    frames = tshark.decode(bench)
    for frame in frames:
        print(frame.number, frame.src, ":".join(frame.protocols), frame.info)
    assert _unexpected_errors(bench) == []
    assert _known_artefacts(bench) <= 1, "only the release frame may carry the artefact"
    assert result.returncode == 0, result.stdout + result.stderr
    assert result_abort.returncode == 0, result_abort.stdout + result_abort.stderr
