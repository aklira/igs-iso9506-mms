# igs-iso9506-mms

A Rust implementation of MMS (ISO 9506) over TCP (RFC 1006), with an async client, an async server, and
TLS as IEC 62351-3 profiles it. Built for the RTE interoperability project; the status and the known gaps
are in [`docs/capabilities.md`](docs/capabilities.md).

Written from the standards, with no code of other MMS implementations read (clean room). The licensed
standard texts are not in this repository.

## Quick start

Requires Rust 1.85 or later.

```bash
git clone <this repository>
cd igs-iso9506-mms
cargo run -p igs-iso9506-mms --example loopback
```

The loopback example starts a server and a client in one process, identifies the server, reads and writes a
variable, and closes the association. It needs no network setup.

Two processes, over TCP:

```bash
cargo run -p igs-iso9506-mms --example server -- 127.0.0.1:10102     # terminal 1
cargo run -p igs-iso9506-mms --example client -- 127.0.0.1:10102     # terminal 2
```

With TLS (IEC 62351-3, mutual authentication), the example needs the certificates of the two ends:

```bash
cargo run -p igs-iso9506-mms --example tls -- root.pem crl.pem server.pem server.key client.pem client.key
```

The test certificates are in `crates/igs-iso9506-mms/tests/fixtures/tls`.

## Command lines

| Binary | Purpose |
| --- | --- |
| `igsmms-client` | identify a server, list its names, read, write, show the attributes of a variable |
| `igsmms-server` | serve the VMD of a TOML file (see [`docs/igsmms-server.md`](docs/igsmms-server.md)) |

```bash
cargo run -p igs-iso9506-mms --bin igsmms-client -- -s 127.0.0.1:10103 identify
cargo run -p igs-iso9506-mms --bin igsmms-server -- --listen 127.0.0.1:10103 --config bench/device/demo.toml
```

## Crates

| Crate | Role |
| --- | --- |
| `igs-iso9506-mms-codec` | BER and the ASN.1 types of the ACSE, presentation, session, COTP and MMS PDUs |
| `igs-iso9506-mms-link` | sans-I/O state machines: transport, session and presentation, the association, the requests |
| `igs-iso9506-mms` | the public API: `Client`, `Server`, the VMD model (`vmd`), TLS (`tls`), the binaries |

The library is `igs_iso9506_mms`. Its items are documented; `cargo doc -p igs-iso9506-mms --no-deps --open`.

## Tests and the bench

```bash
cargo test --workspace --all-features
```

The interoperability tests need the reference peer of the bench (`bench/`), which runs in containers and
needs Docker or Podman. See [`bench/README.md`](bench/README.md).

## Documents

- [`IMPLEMENTATION.md`](IMPLEMENTATION.md): the plan, its rules and the status of each task.
- [`PROVENANCE.md`](PROVENANCE.md): the decisions (`D-nnn`), the sources of each one, and the licences.
- [`docs/capabilities.md`](docs/capabilities.md): what the stack does, what the interoperability tests
  observed, and the gaps.
- [`CHANGELOG.md`](CHANGELOG.md): the changes.

## Licence

Apache-2.0. See [`LICENSE`](LICENSE).
