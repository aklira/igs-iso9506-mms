# SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Assertion helper: decodes captures with `tshark -T json` in the `capture` service.

The Wireshark dissector is an independent decoder: a capture that it parses without malformed
packets or error-level expert info is well formed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .compose import Bench

FIELDS = ("frame.number", "ip.src", "frame.protocols", "_ws.col.info")


@dataclass(frozen=True)
class Frame:
    number: int
    src: str
    protocols: tuple[str, ...]
    info: str


def _path(bench: Bench) -> str:
    return f"/captures/{bench.capture_name}"


def decode(bench: Bench, service: str = "capture") -> list[Frame]:
    """Every frame of the capture, with the protocols that tshark recognised in it."""
    out = bench.exec(service, "tshark", "-r", _path(bench), "-T", "json", *(a for f in FIELDS for a in ("-e", f)))
    frames = []
    for packet in json.loads(out.stdout or "[]"):
        layers = packet["_source"]["layers"]
        frames.append(
            Frame(
                number=int(layers["frame.number"][0]),
                src=layers.get("ip.src", [""])[0],
                protocols=tuple(layers.get("frame.protocols", [""])[0].split(":")),
                info=layers.get("_ws.col.info", [""])[0],
            )
        )
    return frames


def errors(bench: Bench, service: str = "capture") -> list[str]:
    """Frames that tshark flags as malformed or with error-level expert info."""
    out = bench.exec(service, "tshark", "-r", _path(bench), "-Y", "_ws.malformed || _ws.expert.severity == error")
    return [line for line in out.stdout.splitlines() if line.strip()]


def find(frames: list[Frame], *, src: str, protocol: str = "mms", info: str | None = None) -> list[Frame]:
    """Frames sent by `src` that carry `protocol` and match `info`."""
    return [f for f in frames if f.src == src and protocol in f.protocols and (info is None or info in f.info)]


def values(bench: Bench, field: str, service: str = "capture") -> list[str]:
    """The non-empty values of one field over the MMS frames of the capture."""
    out = bench.exec(service, "tshark", "-r", _path(bench), "-Y", "mms", "-T", "fields", "-e", field)
    return [v for line in out.stdout.splitlines() for v in line.split(",") if v.strip()]
