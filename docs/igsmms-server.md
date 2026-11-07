# `igsmms-server`: the demonstration server

`igsmms-server` serves the VMD of a TOML file over TCP (RFC 1006, port 102 by default). It is the
device under test of the bench (`bench/`), and a way to try the stack by hand. It is built from the
library `igs_iso9506_mms::Server` (task S2), with the model of `igs_iso9506_mms::vmd` (task S1).

## Run

```bash
cargo run -p igs-iso9506-mms --bin igsmms-server -- --listen 127.0.0.1:10103 --config bench/device/demo.toml
```

Other client, in another terminal:

```bash
cargo run -p igs-iso9506-mms --bin igsmms-client -- -s 127.0.0.1:10103 names --class domain
```

`igsmms-server --help` gives the options: `--listen` (default `127.0.0.1:102`), `--config`
(without it, the server serves an empty VMD), `--max-associations` (default 64, the connections
beyond it are closed), `--nesting` (default 2). The server runs until it is stopped (Ctrl-C).

## The configuration file

The file is TOML. Unknown keys are refused, with the line of the error. Its sections:

| Section | Keys | Meaning |
| --- | --- | --- |
| `[identity]` | `vendor`, `model`, `revision` | The answer to Identify. |
| `[[domain]]` | `name` | A domain. |
| `[[variable]]` | `name`, `domain` (optional), `type`, `bits` or `size`, `value`, `writable` | A named variable. Without `domain`, the variable is VMD-specific. |
| `[[list]]` | `name`, `domain` (optional), `members` | A named variable list, defined at start. |

Types of a variable (`type`):

| `type` | Value | Size key |
| --- | --- | --- |
| `boolean` | `true` or `false` | none |
| `integer` | a signed integer that fits `bits` | `bits` (1 to 127) |
| `unsigned` | an integer of zero or more that fits `bits` | `bits` |
| `float` | a floating-point number, single precision (format 32, exponent 8) | none |
| `visible-string` | a string of exactly `size` characters | `size` |

A member of a list is `name` for a VMD-specific variable, and `domain/name` for a domain-specific one.
Names follow the rules of the codec: between one and 32 characters, letters, digits, `_` and `$`.
Each object is checked when the file is read: a value outside its type, a duplicate name, a missing
domain or a missing member is refused, with the object named in the message. The server does not
start on an invalid file.

Example: `bench/device/demo.toml`.

## Behaviour

- **Services**: Identify, GetNameList (VMD and domain scopes, paged), Read, Write,
  GetVariableAccessAttributes, DefineNamedVariableList, GetNamedVariableListAttributes and
  DeleteNamedVariableList. The other services are not served (`docs/capabilities.md`).
- **Writes persist in memory** for the life of the process. A read-only variable (`writable = false`)
  refuses a write with object-access-denied.
- **Lists defined by a client** are kept until they are deleted or the process stops.
- **Not served**: journals (the reference client asks for them: G14), addresses, alternate access,
  access control, reports from a control block (`Server::publish` is the library's call).

## Bench run

The bench runs the server as a static binary, built on the host, mounted in a Debian container:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl -p igs-iso9506-mms --bin igsmms-server
```

Then `bench/tests/test_s3_device.py` starts the device (`bench/docker-compose.yml`, service `device`,
`172.31.102.30`), and runs the reference client's commands against it. The transcript is in
`docs/ai-log/S3.md`.
