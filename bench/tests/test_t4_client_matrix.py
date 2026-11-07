# SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
#
# SPDX-License-Identifier: Apache-2.0
"""T4: the client matrix. This stack, run on the host, runs one scenario per service in scope against the
reference server; the capture must show every service on the wire, and decode cleanly in tshark.

The scenarios are Rust tests (crates/igs-iso9506-mms/tests/interop_matrix.rs): each asserts its row of the
matrix, and this file checks the capture. The gaps of the matrix are recorded in docs/capabilities.md.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from igs_bench import capture, tshark

REPO = Path(__file__).resolve().parents[2]
PEER = "127.0.0.1:10102"

# Confirmed services in scope, by context tag (ISO 9506-2 §7): getNameList, identify, read, write,
# getVariableAccessAttributes, defineNamedVariableList, getNamedVariableListAttributes,
# deleteNamedVariableList.
CONFIRMED = {"1", "2", "4", "5", "6", "11", "12", "13"}
# informationReport is unconfirmed service 0.
UNCONFIRMED = {"0"}

# The release (RLRQ) carries no user information: Wireshark reads it as a zero-byte MMS PDU (G6). One
# per association; the matrix opens one association per scenario.
KNOWN_ARTEFACT = '_ws.expert.message == "Internal error, zero-byte MMS PDU"'
ERRORS = "_ws.malformed || _ws.expert.severity == error"


def _lines(bench, display_filter: str) -> list[str]:
    out = bench.exec("capture", "tshark", "-r", f"/captures/{bench.capture_name}", "-Y", display_filter)
    return [line for line in out.stdout.splitlines() if line.strip()]


def test_the_client_runs_every_service_in_scope_against_the_reference_server(bench):
    bench.up("ref-server", "capture")
    capture.wait_live(bench)

    env = {**os.environ, "MMS_PEER": PEER}
    result = subprocess.run(
        [
            "cargo",
            "test",
            "-p",
            "igs-iso9506-mms",
            "--test",
            "interop_matrix",
            "--",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        timeout=1200,
    )
    capture.stop(bench)

    # libtest may print its progress dot on the same line as the first row: match the marker anywhere.
    rows = [
        line[line.index("T4-MATRIX |") :]
        for line in result.stdout.splitlines()
        if "T4-MATRIX |" in line
    ]
    for row in rows:
        print(row)
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(rows) >= 13, rows

    assert _lines(bench, f"({ERRORS}) && !({KNOWN_ARTEFACT})") == []
    assert len(_lines(bench, KNOWN_ARTEFACT)) <= len(rows)

    assert CONFIRMED <= set(tshark.values(bench, "mms.confirmedServiceRequest"))
    assert CONFIRMED <= set(tshark.values(bench, "mms.confirmedServiceResponse"))
    assert UNCONFIRMED <= set(tshark.values(bench, "mms.unconfirmedService"))
