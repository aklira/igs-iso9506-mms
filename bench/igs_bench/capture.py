# SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Capture helper: tcpdump runs in the `capture` service, see docker-compose.yml."""

from __future__ import annotations

import time
from pathlib import Path

from .compose import BENCH_DIR, Bench

CAPTURE_DIR = BENCH_DIR / "captures"
PCAP_HEADER = 24


def wait_live(bench: Bench, service: str = "capture", port: int = 102, timeout: float = 60) -> None:
    """Wait until tcpdump records traffic: a file with more than its header proves it listens."""
    path = f"/captures/{bench.capture_name}"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        bench.exec(service, "nc", "-z", "127.0.0.1", str(port), check=False)
        size = bench.exec(service, "sh", "-c", f"wc -c < '{path}'", check=False).stdout.strip()
        if size.isdigit() and int(size) > PCAP_HEADER:
            return
        time.sleep(0.5)
    raise TimeoutError(f"no traffic recorded in {path} after {timeout}s")


def stop(bench: Bench, service: str = "capture") -> Path:
    """Stop tcpdump in `service` so that the capture file is complete; return its host path."""
    bench.exec(service, "pkill", "-INT", "tcpdump", check=False)
    for _ in range(20):
        if bench.exec(service, "pgrep", "tcpdump", check=False).returncode != 0:
            break
        time.sleep(0.5)
    return CAPTURE_DIR / bench.capture_name
