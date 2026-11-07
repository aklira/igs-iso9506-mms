# SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
#
# SPDX-License-Identifier: Apache-2.0
"""S4: the matrix of the reference client against `igsmms-server`, the device under test.

Each row is one command of the reference client (libiec61850's mms_utility, a black box), with the output it
must show and the exit status it must have. A row whose behaviour is a known gap says so: its expected output
is the gap (docs/capabilities.md). The capture of the device's network namespace must show the services of
the rows on the wire, and decode cleanly in tshark.

The rows the reference client has no command for (write, define and delete of lists, the reports) are not in
the matrix: they are tested by the Rust scenarios of the server (crates/igs-iso9506-mms/tests/server.rs).
"""

from __future__ import annotations

from igs_bench import capture, tshark

DEVICE = "172.31.102.30"

# (row, arguments of mms_utility, exit status, outputs that must appear)
ROWS = [
    ("identify", ["-i"], 0, ["vendor:\tigs", "model:\tigsmms demo"]),
    ("getNameList, domains", ["-d"], 0, ["demo"]),
    (
        "getNameList, named variables of the domain",
        ["-t", "demo"],
        82,  # the journal query that follows is the gap G14: the listing itself is correct
        ["label", "status", "temperature"],
    ),
    (
        "getNameList, journals (gap G14)",
        ["-t", "demo"],
        82,
        ["Failed to read domain journals (error=82)"],
    ),
    ("read, floating point", ["-a", "demo", "-r", "temperature"], 0, ["Read SUCCESS", "21.500000"]),
    ("read, boolean", ["-a", "demo", "-r", "status"], 0, ["Read SUCCESS", "true"]),
    ("read, visible string", ["-a", "demo", "-r", "label"], 0, ["Read SUCCESS", "igs"]),
    ("read, unknown name", ["-a", "demo", "-r", "missing"], 0, ["Read SUCCESS", "error 10"]),
    ("read, named variable list", ["-a", "demo", "-v", "snapshot"], 0, ["Read SUCCESS"]),
    (
        "getNamedVariableListAttributes",
        ["-a", "demo", "-z", "snapshot"],
        0,
        ["speed", "demo/temperature"],
    ),
]

# The services of the rows on the wire, by context tag: getNameList (1), identify (2), read (4),
# getNamedVariableListAttributes (12), as the confirmed services of this matrix.
SERVED = {"1", "2", "4", "12"}

KNOWN_ARTEFACT = '_ws.expert.message == "Internal error, zero-byte MMS PDU"'
ERRORS = "_ws.malformed || _ws.expert.severity == error"


def _lines(bench, display_filter: str) -> list[str]:
    out = bench.exec(
        "device-capture", "tshark", "-r", f"/captures/{bench.capture_name}", "-Y", display_filter
    )
    return [line for line in out.stdout.splitlines() if line.strip()]


def test_the_reference_client_matrix_against_the_device(bench):
    bench.up("device", "device-capture", "ref-client")
    capture.wait_live(bench, service="device-capture")

    results = []
    for row, arguments, status, outputs in ROWS:
        run = bench.exec(
            "ref-client", "mms_utility", "-h", DEVICE, *arguments, check=False
        )
        ok = run.returncode == status and all(text in run.stdout for text in outputs)
        results.append((row, run.returncode, ok))
        print(f"MATRIX | {row:<44} | exit {run.returncode:>3} | {'pass' if ok else 'FAIL'}")
        assert ok, (row, run.returncode, run.stdout)

    capture.stop(bench, service="device-capture")
    frames = tshark.decode(bench, service="device-capture")
    assert _lines(bench, f"({ERRORS}) && !({KNOWN_ARTEFACT})") == []
    assert SERVED <= set(tshark.values(bench, "mms.confirmedServiceRequest", service="device-capture"))
    assert SERVED <= set(tshark.values(bench, "mms.confirmedServiceResponse", service="device-capture"))
    assert all(ok for _, _, ok in results)
    assert len(frames) > 0
