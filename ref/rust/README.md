# 9P2000.N Rust Reference Implementation

This crate provides a Rust reference implementation of the [9P2000.N protocol](../../spec/9P2000.N-protocol.md), feature-equivalent to the [C](../c/) and [Go](../go/) reference implementations.

## Requirements

- Rust 1.56+ (edition 2021)
- No external dependencies (std only)

## Build and Test

```bash
cd ref/rust
cargo test
```

## Crate Layout

```
src/
  lib.rs         Module root + 35 unit tests
  types.rs       MsgType enum, Msg enum, Fcall, constants
  buf.rs         Growable byte buffer with LE wire primitives
  caps.rs        CapSet with bitmask fast path, intersect()
  codec.rs       marshal() / unmarshal() for all 46 message type pairs
```

## Usage

```rust
use p9n::types::*;
use p9n::buf::Buf;
use p9n::caps::*;
use p9n::codec::*;

// Marshal a Tcaps message
let mut buf = Buf::new(256);
let fc = Fcall {
    size: 0,
    msg_type: MsgType::Tcaps,
    tag: 1,
    msg: Msg::Caps {
        caps: vec![CAP_COMPOUND.into(), CAP_WATCH.into(), CAP_SPIFFE.into()],
    },
};
marshal(&mut buf, &fc).unwrap();
// buf.as_bytes() is the wire-format message

// Unmarshal any message
let mut rbuf = Buf::from_bytes(wire_data);
let got = unmarshal(&mut rbuf).unwrap();
println!("{}", got.msg_type.name()); // "Tcaps"

// Capability negotiation
let mut client = CapSet::new();
client.add(CAP_COMPOUND);
client.add(CAP_WATCH);

let mut server = CapSet::new();
server.add(CAP_WATCH);

let result = intersect(&client, &server);
assert!(result.has(CAP_WATCH));
assert!(result.has_bit(CapBit::Watch));
```

## Design Notes

- `Msg` is a Rust enum with variants for all 46 message types -- exhaustive pattern matching at compile time
- `MsgType` is `#[repr(u8)]` for zero-cost conversion to wire format
- Zero external dependencies; only uses `std::io` and `std::collections`
- All tests verify wire-format round-trip correctness (marshal then unmarshal)
