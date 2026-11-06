# SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
#
# SPDX-License-Identifier: Apache-2.0
"""F5: the reference client opens an MMS association with the reference server and runs two
confirmed services; the capture must decode cleanly in tshark.

This exercises the bench only: no code of this project takes part yet.
"""

from __future__ import annotations

from igs_bench import capture, tshark

SERVER = "172.31.102.10"
CLIENT = "172.31.102.21"


def test_reference_client_initiates_and_reads_the_server_identity(bench):
    bench.up("ref-server", "ref-client", "capture")
    capture.wait_live(bench)

    result = bench.exec("ref-client", "mms_utility", "-h", SERVER, "-i", "-d")
    assert "MMS connected" in result.stdout

    pcap = capture.stop(bench)
    assert pcap.is_file()

    assert tshark.errors(bench) == []
    frames = tshark.decode(bench)
    assert tshark.find(frames, src=CLIENT, protocol="cotp", info="CR TPDU")
    assert tshark.find(frames, src=SERVER, protocol="cotp", info="CC TPDU")
    assert tshark.find(frames, src=CLIENT, info="initiate-RequestPDU")
    assert tshark.find(frames, src=SERVER, info="initiate-ResponsePDU")
    assert len(tshark.find(frames, src=CLIENT, info="confirmed-RequestPDU")) == 2
    assert len(tshark.find(frames, src=SERVER, info="confirmed-ResponsePDU")) == 2
    for name in ("tpkt", "cotp", "ses", "pres", "acse", "mms"):
        assert any(name in f.protocols for f in frames), name
