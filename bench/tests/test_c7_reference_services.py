# SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
#
# SPDX-License-Identifier: Apache-2.0
"""C7: the reference clients run every MMS service in scope against the reference server.

The capture is the source of the observed vectors of `tests/mms_pdus.rs` in the codec crate.
No code of this project takes part.
"""

from __future__ import annotations

import time

from igs_bench import capture, tshark

SERVER = "172.31.102.10"

# Tags of the confirmed services in scope (ISO 9506-2 §7): getNameList, identify, read, write,
# getVariableAccessAttributes, defineNamedVariableList, getNamedVariableListAttributes,
# deleteNamedVariableList.
CONFIRMED = {"1", "2", "4", "5", "6", "11", "12", "13"}


def test_reference_clients_run_the_services_in_scope(bench):
    bench.up("ref-server", "ref-client", "capture")
    capture.wait_live(bench)

    bench.exec("ref-client", "mms_utility", "-h", SERVER, "-i", "-d")
    bench.exec("ref-client", "iec61850_client_example2", SERVER)
    bench.exec("ref-client", "iec61850_client_example4", SERVER)
    bench.exec("ref-client", "client_example_control", SERVER)
    # Enables a report control block, then waits for reports: stopped after a few.
    reporting = bench.exec_async("ref-client", "iec61850_client_example_reporting", SERVER)
    time.sleep(10)
    reporting.terminate()
    reporting.wait(timeout=30)

    capture.stop(bench)
    assert tshark.errors(bench) == []
    assert CONFIRMED <= set(tshark.values(bench, "mms.confirmedServiceRequest"))
    assert CONFIRMED <= set(tshark.values(bench, "mms.confirmedServiceResponse"))
    # informationReport is unconfirmed service 0.
    assert "0" in tshark.values(bench, "mms.unconfirmedService")
