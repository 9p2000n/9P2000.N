package p9n

import (
	"encoding/binary"
	"errors"
	"io"
)

// ErrShortBuffer is returned when there isn't enough data to decode.
var ErrShortBuffer = errors.New("p9n: short buffer")

// Buf is a growable byte buffer for 9P2000.N message marshalling.
// All multi-byte integers are written in little-endian order.
type Buf struct {
	data []byte
	pos  int // read cursor
}

// NewBuf creates a buffer with the given initial capacity.
func NewBuf(cap int) *Buf {
	if cap <= 0 {
		cap = 4096
	}
	return &Buf{data: make([]byte, 0, cap)}
}

// BufFrom wraps existing data for reading.
func BufFrom(data []byte) *Buf {
	return &Buf{data: data, pos: 0}
}

// Bytes returns the written data.
func (b *Buf) Bytes() []byte { return b.data }

// Len returns the number of written bytes.
func (b *Buf) Len() int { return len(b.data) }

// Reset clears the buffer.
func (b *Buf) Reset() {
	b.data = b.data[:0]
	b.pos = 0
}

// remaining returns unread bytes count.
func (b *Buf) remaining() int { return len(b.data) - b.pos }

// --- Write primitives ---

func (b *Buf) PutU8(v uint8) {
	b.data = append(b.data, v)
}

func (b *Buf) PutU16(v uint16) {
	b.data = append(b.data, byte(v), byte(v>>8))
}

func (b *Buf) PutU32(v uint32) {
	b.data = append(b.data, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func (b *Buf) PutU64(v uint64) {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], v)
	b.data = append(b.data, tmp[:]...)
}

func (b *Buf) PutStr(s string) {
	b.PutU16(uint16(len(s)))
	b.data = append(b.data, s...)
}

func (b *Buf) PutData(d []byte) {
	b.PutU32(uint32(len(d)))
	b.data = append(b.data, d...)
}

func (b *Buf) PutBytes(d []byte) {
	b.data = append(b.data, d...)
}

// PatchU32 writes a uint32 at a specific offset (for size patching).
func (b *Buf) PatchU32(off int, v uint32) {
	b.data[off] = byte(v)
	b.data[off+1] = byte(v >> 8)
	b.data[off+2] = byte(v >> 16)
	b.data[off+3] = byte(v >> 24)
}

// --- Read primitives ---

func (b *Buf) GetU8() (uint8, error) {
	if b.remaining() < 1 {
		return 0, io.ErrUnexpectedEOF
	}
	v := b.data[b.pos]
	b.pos++
	return v, nil
}

func (b *Buf) GetU16() (uint16, error) {
	if b.remaining() < 2 {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.LittleEndian.Uint16(b.data[b.pos:])
	b.pos += 2
	return v, nil
}

func (b *Buf) GetU32() (uint32, error) {
	if b.remaining() < 4 {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.LittleEndian.Uint32(b.data[b.pos:])
	b.pos += 4
	return v, nil
}

func (b *Buf) GetU64() (uint64, error) {
	if b.remaining() < 8 {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.LittleEndian.Uint64(b.data[b.pos:])
	b.pos += 8
	return v, nil
}

func (b *Buf) GetStr() (string, error) {
	slen, err := b.GetU16()
	if err != nil {
		return "", err
	}
	if b.remaining() < int(slen) {
		return "", io.ErrUnexpectedEOF
	}
	s := string(b.data[b.pos : b.pos+int(slen)])
	b.pos += int(slen)
	return s, nil
}

func (b *Buf) GetData() ([]byte, error) {
	n, err := b.GetU32()
	if err != nil {
		return nil, err
	}
	if b.remaining() < int(n) {
		return nil, io.ErrUnexpectedEOF
	}
	d := make([]byte, n)
	copy(d, b.data[b.pos:b.pos+int(n)])
	b.pos += int(n)
	return d, nil
}

func (b *Buf) GetFixedBytes(n int) ([]byte, error) {
	if b.remaining() < n {
		return nil, io.ErrUnexpectedEOF
	}
	d := make([]byte, n)
	copy(d, b.data[b.pos:b.pos+n])
	b.pos += n
	return d, nil
}

func (b *Buf) GetQID() (QID, error) {
	var q QID
	var err error
	q.Type, err = b.GetU8()
	if err != nil {
		return q, err
	}
	q.Version, err = b.GetU32()
	if err != nil {
		return q, err
	}
	q.Path, err = b.GetU64()
	return q, err
}

func (b *Buf) PutQID(q QID) {
	b.PutU8(q.Type)
	b.PutU32(q.Version)
	b.PutU64(q.Path)
}
