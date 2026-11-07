# Interop bench

Black-box tests of `igs-iso9506-mms` against a reference peer, with captures decoded by `tshark`.

## Reference peer

The example programs of libiec61850 (GPL-3.0), built from a fixed commit by `peer/Dockerfile`. They
run as separate processes only. **Nobody reads their source**: it stays in the build stage of the
image, and only executables reach the final image (rule 1 of `IMPLEMENTATION.md`). The image is
built locally and is not distributed.

## Needs

- Docker with the compose plugin, or Podman with `podman-compose`. Set `BENCH_COMPOSE` to force one,
  for example `BENCH_COMPOSE=podman-compose`.
- Python 3.10 or later with `pytest`. `tcpdump` and `tshark` run in the `capture` container.

## Run

```bash
cd bench
python3 -m venv .venv
.venv/bin/pip install pytest
podman-compose build ref-server
.venv/bin/pytest
```

Captures stay in `captures/`, which git ignores.

## Host access

The reference server publishes its port 102 on `127.0.0.1:10102`, so that the stack run on the host
can reach it (task L6). Run the scenarios with `MMS_PEER=127.0.0.1:10102`.

## Device under test (`igsmms-server`)

The server of this repository runs as the device under test (task S3): `bench/device/demo.toml`, served
by a static binary built on the host and mounted in a Debian container at `172.31.102.30`. The reference
client runs its commands against it: `bench/tests/test_s3_device.py`. Build the binary first, as
`docs/igsmms-server.md` says (the musl target, `rustup target add x86_64-unknown-linux-musl`). The
binary is built from this repository's code and is not part of the reference peer.

## Layout

| Path | Content |
| --- | --- |
| `docker-compose.yml` | Reference server, reference client, capture container, device under test and its capture |
| `peer/Dockerfile` | Build of the reference peer |
| `igs_bench/compose.py` | Wrapper over the compose engine |
| `igs_bench/capture.py` | Stops `tcpdump` and returns the capture |
| `igs_bench/tshark.py` | Decodes a capture and lists its errors |
| `tests/` | Scenarios, one file per task (`test_l6_interop.py` drives the stack of this repository) |
