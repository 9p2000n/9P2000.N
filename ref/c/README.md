# 9P2000.N C Reference Implementation

This directory contains the C reference implementation of the [9P2000.N protocol](../../spec/9P2000.N-protocol.md). It provides a static library (`lib9pN.a`) for message marshalling/unmarshalling, capability negotiation, and compound operation building.

This implementation is intended as a **reference** for protocol correctness, not as a production-grade server or client. It demonstrates the exact wire format for all 46 message type pairs.

## Requirements

- C11 compiler (GCC or Clang)
- GNU Make
- Linux (tested on 6.17)

No external dependencies.

## Build

```bash
cd ref/c
make          # builds build/lib9pN.a
make test     # builds and runs all 36 tests
make clean    # removes build artifacts
```

## Source Layout

```
include/
  9pN.h             Protocol header: message types, structures, API declarations
src/
  buf.c             Growable byte buffer with little-endian wire primitives
  caps.c            Capability set management, bitmask fast path, Tcaps marshalling
  protocol.c        Marshal/unmarshal for all 46 message type pairs
  compound.c        High-level builder for Tcompound sub-operations
tests/
  test_9pN.c        36 unit tests covering all modules
Makefile            Build system
```

## Usage

### Link against the library

```bash
cc -I ref/c/include your_app.c -Lref/c/build -l9pN -o your_app
```

### Example: Capability Negotiation

```c
#include "9pN.h"

// Build capability set
struct p9n_capset client_caps;
p9n_capset_init(&client_caps);
p9n_capset_add(&client_caps, P9N_CAP_COMPOUND);
p9n_capset_add(&client_caps, P9N_CAP_WATCH);
p9n_capset_add(&client_caps, P9N_CAP_SPIFFE);

// Check capabilities with bitmask fast path
if (p9n_capset_has_bit(&client_caps, P9N_CBIT_SPIFFE)) {
    // SPIFFE is available
}

// Marshal a Tcaps message
struct p9n_buf buf;
p9n_buf_init(&buf, 256);
struct p9n_caps msg = { .ncaps = client_caps.ncaps, .caps = client_caps.caps };
p9n_marshal_caps(&buf, /*tag=*/1, &msg);
// buf.data[0..buf.len] is now the wire-format message
```

### Example: Compound Operation

```c
#include "9pN.h"

// Build walk + open + read + clunk in one message
struct p9n_compound_builder bld;
p9n_compound_builder_init(&bld);

const char *path[] = {"data", "config.yaml"};
p9n_compound_add_walk(&bld, root_fid, P9N_PREVFID, 2, path);
p9n_compound_add_lopen(&bld, P9N_PREVFID, 0 /* RDONLY */);
p9n_compound_add_read(&bld, P9N_PREVFID, 0, 4096);
p9n_compound_add_clunk(&bld, P9N_PREVFID);

struct p9n_buf wire;
p9n_buf_init(&wire, 512);
p9n_compound_encode(&bld, &wire, /*tag=*/1);
```

### Example: Unmarshal Any Message

```c
#include "9pN.h"

struct p9n_buf buf = { .data = wire_data, .len = wire_len, .cap = wire_len, .pos = 0 };
struct p9n_fcall fc;

if (p9n_unmarshal(&buf, &fc) == 0) {
    printf("Message: %s (type=%d, tag=%d)\n",
           p9n_msg_name(fc.type), fc.type, fc.tag);

    switch (fc.type) {
    case P9N_RNOTIFY:
        printf("Watch %d: %s event on '%s'\n",
               fc.u.notify.watchid,
               fc.u.notify.event == P9N_WATCH_CREATE ? "CREATE" : "OTHER",
               fc.u.notify.name);
        break;
    // ... handle other types
    }

    p9n_fcall_free(&fc);
}
```

## Test Coverage

The test suite covers:

| Category | Tests | What is verified |
|----------|-------|------------------|
| Buffer primitives | 8 | LE encoding, string/data, auto-grow, underflow |
| Capability negotiation | 5 | Add/has, bitmask, intersection, dedup, string-to-bit |
| Message round-trips | 13 | Marshal then unmarshal for all P0 message types |
| SPIFFE integration | 8 | Capability, startls_spiffe, fetchbundle, spiffeverify, authneg |
| Wire format | 2 | Message names, 7-byte header |

## API Reference

See [`include/9pN.h`](include/9pN.h) for the complete API. Key functions:

| Function | Purpose |
|----------|---------|
| `p9n_buf_init/free/reset` | Buffer lifecycle |
| `p9n_buf_put_*` / `p9n_buf_get_*` | Wire-format read/write primitives |
| `p9n_capset_init/add/has/intersect` | Capability set management |
| `p9n_marshal_*` | Encode messages to wire format |
| `p9n_unmarshal` | Decode any message from wire format |
| `p9n_fcall_free` | Free decoded message resources |
| `p9n_msg_name` | Message type to human-readable name |
| `p9n_compound_builder_*` | High-level compound operation builder |
