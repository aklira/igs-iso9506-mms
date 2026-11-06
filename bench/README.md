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

## Layout

| Path | Content |
| --- | --- |
| `docker-compose.yml` | Reference server, reference client, capture container |
| `peer/Dockerfile` | Build of the reference peer |
| `igs_bench/compose.py` | Wrapper over the compose engine |
| `igs_bench/capture.py` | Stops `tcpdump` and returns the capture |
| `igs_bench/tshark.py` | Decodes a capture and lists its errors |
| `tests/` | Scenarios, one file per task |
