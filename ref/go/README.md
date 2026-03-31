# 9P2000.N Go Reference Implementation

This directory contains the Go reference implementation of the [9P2000.N protocol](../../spec/9P2000.N-protocol.md). It provides a `p9n` package for message marshalling/unmarshalling and capability negotiation -- feature-equivalent to the [C reference implementation](../c/).

## Requirements

- Go 1.21+
- No external dependencies

## Build and Test

```bash
cd ref/go
go test ./p9n/ -v
```

```
=== RUN   TestBufU8
--- PASS: TestBufU8
...
=== RUN   TestSpiffeMsgNames
--- PASS: TestSpiffeMsgNames
PASS
ok  	github.com/9p2000n/ref-go/p9n	0.004s
```

## Package Layout

```
p9n/
  types.go       Constants, message types, structs, MsgName()
  buf.go         Growable byte buffer with LE wire primitives
  caps.go        Capability set management with bitmask fast path
  codec.go       Marshal/Unmarshal for all 46 message type pairs
  p9n_test.go    34 tests: buffer, capabilities, round-trips, SPIFFE
```

## Usage

```go
import "github.com/9p2000n/ref-go/p9n"

// Marshal a Tcaps message
buf := p9n.NewBuf(256)
fc := &p9n.Fcall{
    Type: p9n.Tcaps,
    Tag:  1,
    Msg: &p9n.MsgCaps{
        Caps: []string{p9n.CapCompound, p9n.CapWatch, p9n.CapSpiffe},
    },
}
p9n.Marshal(buf, fc)
// buf.Bytes() is the wire-format message

// Unmarshal any message
rbuf := p9n.BufFrom(wireData)
got, err := p9n.Unmarshal(rbuf)
fmt.Println(p9n.MsgName(got.Type)) // "Tcaps"

// Capability negotiation
client := p9n.NewCapSet()
client.Add(p9n.CapCompound)
client.Add(p9n.CapWatch)

server := p9n.NewCapSet()
server.Add(p9n.CapWatch)

result := p9n.Intersect(client, server)
result.Has(p9n.CapWatch)    // true
result.HasBit(p9n.CBitWatch) // true (fast path)
```
