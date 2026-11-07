# SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
#
# SPDX-License-Identifier: Apache-2.0
"""S3: the reference client runs its services against `igsmms-server`, the device under test.

The device is this repository's server, built as a static binary (bench/README.md) and run from
bench/device/demo.toml. The reference client (libiec61850's mms_utility, a black box) connects to it; the
capture of the device's network namespace must decode cleanly in tshark, and show the services.
"""

from __future__ import annotations

from igs_bench import capture, tshark

DEVICE = "172.31.102.30"
CLIENT = "172.31.102.21"

# The confirmed services that these commands of the reference client use: getNameList (1), identify (2),
# read (4). getVariableAccessAttributes (6) is not used by them.
SERVED = {"1", "2", "4"}

# The release carries no user information: Wireshark reads it as a zero-byte MMS PDU (G6). One per
# association, and the reference client makes one association per command.
KNOWN_ARTEFACT = '_ws.expert.message == "Internal error, zero-byte MMS PDU"'
ERRORS = "_ws.malformed || _ws.expert.severity == error"


def _lines(bench, display_filter: str) -> list[str]:
    out = bench.exec(
        "device-capture", "tshark", "-r", f"/captures/{bench.capture_name}", "-Y", display_filter
    )
    return [line for line in out.stdout.splitlines() if line.strip()]


def test_the_reference_client_runs_its_services_against_the_device(bench):
    bench.up("device", "device-capture", "ref-client")
    capture.wait_live(bench, service="device-capture")

    identity = bench.exec("ref-client", "mms_utility", "-h", DEVICE, "-i")
    assert "MMS connected" in identity.stdout
    assert "igs" in identity.stdout and "igsmms demo" in identity.stdout

    domains = bench.exec("ref-client", "mms_utility", "-h", DEVICE, "-d")
    assert "demo" in domains.stdout

    # The directory of the domain is listed, then the reference client asks for the journals of the domain:
    # the device does not hold the journal class, so it answers with an error, and the client exits with
    # status 82. That is the recorded gap G14 (docs/capabilities.md), not a failure of the listing.
    directory = bench.exec(
        "ref-client", "mms_utility", "-h", DEVICE, "-t", "demo", check=False
    )
    for name in ("temperature", "status", "label"):
        assert name in directory.stdout, name
    assert "Failed to read domain journals" in directory.stdout

    read = bench.exec(
        "ref-client", "mms_utility", "-h", DEVICE, "-a", "demo", "-r", "temperature"
    )
    assert "Read SUCCESS" in read.stdout

    capture.stop(bench, service="device-capture")

    frames = tshark.decode(bench, service="device-capture")
    for frame in frames:
        print(frame.number, frame.src, ":".join(frame.protocols), frame.info)
    assert _lines(bench, f"({ERRORS}) && !({KNOWN_ARTEFACT})") == []
    assert SERVED <= set(tshark.values(bench, "mms.confirmedServiceRequest", service="device-capture"))
    assert SERVED <= set(tshark.values(bench, "mms.confirmedServiceResponse", service="device-capture"))
    assert tshark.find(frames, src=DEVICE, info="initiate-ResponsePDU")
    assert tshark.find(frames, src=CLIENT, info="initiate-RequestPDU")
