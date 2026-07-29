# profinet-rs

A PROFINET IO-controller in Rust: DCP discovery and configuration, DCE/RPC over
UDP (also over raw Layer 2), acyclic record read/write, cyclic RT_CLASS_1 IO,
I&M, diagnosis and alarms, and GSDML parsing.

It exists as bench and commissioning tooling — a controller you can script
against a real device from a laptop — not as a certified PROFINET master.

## Provenance

**This is a derivative work of [`f0rw4rd/profinet-py`](https://github.com/f0rw4rd/profinet-py),
received under its GPL-3.0 option and ported to Rust.** The wire-level behaviour, the packet layouts and
much of the structure follow that project directly; its test vectors are used as
a byte-level oracle (`tools/gen_*golden*.py` generate `tests/golden/*.json` with
profinet-py, and the Rust side asserts byte-for-byte equality).

Changes made in this port, relative to the Python original:

- Rewritten in Rust, with the wire handling split into pure functions so the
  error-prone byte work is unit-testable without hardware.
- A raw-Layer-2 UDP transport (`rawudp`), added because macOS Local Network
  Privacy blocks a fresh unsigned binary from receiving LAN UDP through the IP
  stack.
- Response matching hardened: RPC responses are matched to the request's
  activity UUID (DREP-normalised) and sequence number; DCP SET and Identify
  responses are matched to the request's xid. The Python original accepts the
  first response that arrives.
- Assorted robustness fixes around over-length decoding, buffer sizing and
  device-error classification.

Because this is a derivative of a GPL-3.0 work, **the whole project is
GPL-3.0-only**. It cannot be relicensed or offered under a proprietary licence.

## Safety

This tool can take over a device's cyclic IO as the IO-controller and **drive
its outputs**. Whatever those outputs are wired to, it will drive them.

- Taking over the cyclic AR displaces any controller currently owning the
  device. Do not point it at a machine in service.
- The command layer drives nothing unless a bit is explicitly armed via
  `--allow-mask`, probes the current output state before taking over, holds a
  dead-man while any level bit is held, and runs a commanded safe shutdown
  (drive the all-zero image, verify it, then release) on **every** exit path
  including signals and a lost cyclic link. If it cannot verify the safe image
  it says so and exits non-zero.
- Those guardrails are engineering care, not a safety certification. Treat this
  as bench equipment and keep an independent means of removing power.

## Requirements

- Rust (stable; see `rust-toolchain.toml`)
- libpcap, and permission to open a raw capture device
  - macOS: install Wireshark's ChmodBPF helper, or otherwise grant your user
    access to `/dev/bpf*`, then start a new login session
  - Linux: `CAP_NET_RAW` (or root)

## Build

```sh
cargo build --release
```

This builds `profinet`, the CLI.

## Usage

```sh
# Discover devices on an interface
profinet -i en0 discover

# Identification & maintenance
profinet -i en0 read-inm0 <station>

# Read/write an acyclic record
profinet -i en0 read  <station> --index 4660 --slot 1 --subslot 1 --length 8
profinet -i en0 write <station> --index 4661 --slot 1 --subslot 1 --data 01

# Assign a station address over DCP
profinet -i en0 set-ip <mac> 192.168.0.2 255.255.255.0 0.0.0.0

# Cyclic RT_CLASS_1 exchange, driven from a GSDML
profinet -i en0 cyclic <station> --gsdml device.xml
```

A station can be given by name or by IPv4 address.

`--help` on any subcommand lists its options.

## Tests

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

Most wire-level tests assert byte-for-byte equality against golden vectors
generated from profinet-py (`tools/gen_*golden*.py`). Tests that need real
hardware are marked `#[ignore]`.

## License

Copyright (C) 2026 Roman Passler

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License, version 3, as published by the
Free Software Foundation. This program is distributed WITHOUT ANY WARRANTY,
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See [LICENSE](LICENSE) for the full text.

That notice covers this port. The work it derives from is copyright its own
authors and was received under its GPL-3.0 option — see
[Provenance](#provenance).
