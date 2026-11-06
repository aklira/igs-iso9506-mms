# SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import time

import pytest

from igs_bench import capture
from igs_bench.compose import Bench


@pytest.fixture
def bench(request):
    """A fresh bench per scenario; the capture is kept in bench/captures/."""
    capture.CAPTURE_DIR.mkdir(exist_ok=True)
    name = f"{request.node.name}-{time.strftime('%Y%m%dT%H%M%S')}.pcap"
    instance = Bench(name)
    instance.down()
    try:
        yield instance
    finally:
        instance.down()
