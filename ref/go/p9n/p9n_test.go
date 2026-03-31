package p9n

import (
	"testing"
)

// roundTrip marshals then unmarshals an Fcall and returns the decoded result.
func roundTrip(t *testing.T, fc *Fcall) *Fcall {
	t.Helper()
	buf := NewBuf(256)
	if err := Marshal(buf, fc); err != nil {
		t.Fatalf("marshal %s: %v", MsgName(fc.Type), err)
	}
	rbuf := BufFrom(buf.Bytes())
	got, err := Unmarshal(rbuf)
	if err != nil {
		t.Fatalf("unmarshal %s: %v", MsgName(fc.Type), err)
	}
	if got.Type != fc.Type {
		t.Fatalf("type: got %d, want %d", got.Type, fc.Type)
	}
	if got.Tag != fc.Tag {
		t.Fatalf("tag: got %d, want %d", got.Tag, fc.Tag)
	}
	return got
}

// ====== Buffer tests ======

func TestBufU8(t *testing.T) {
	b := NewBuf(16)
	b.PutU8(0x42)
	b.PutU8(0xFF)
	rb := BufFrom(b.Bytes())
	v1, _ := rb.GetU8()
	v2, _ := rb.GetU8()
	if v1 != 0x42 || v2 != 0xFF {
		t.Fatalf("got %x %x", v1, v2)
	}
}

func TestBufU16LE(t *testing.T) {
	b := NewBuf(16)
	b.PutU16(0x1234)
	if b.Bytes()[0] != 0x34 || b.Bytes()[1] != 0x12 {
		t.Fatal("not little-endian")
	}
	rb := BufFrom(b.Bytes())
	v, _ := rb.GetU16()
	if v != 0x1234 {
		t.Fatalf("got %x", v)
	}
}

func TestBufU32(t *testing.T) {
	b := NewBuf(16)
	b.PutU32(0xDEADBEEF)
	rb := BufFrom(b.Bytes())
	v, _ := rb.GetU32()
	if v != 0xDEADBEEF {
		t.Fatalf("got %x", v)
	}
}

func TestBufU64(t *testing.T) {
	b := NewBuf(16)
	b.PutU64(0x0102030405060708)
	rb := BufFrom(b.Bytes())
	v, _ := rb.GetU64()
	if v != 0x0102030405060708 {
		t.Fatalf("got %x", v)
	}
}

func TestBufStr(t *testing.T) {
	b := NewBuf(64)
	b.PutStr("hello")
	if b.Len() != 7 { // 2 + 5
		t.Fatalf("len: %d", b.Len())
	}
	rb := BufFrom(b.Bytes())
	s, _ := rb.GetStr()
	if s != "hello" {
		t.Fatalf("got %q", s)
	}
}

func TestBufEmptyStr(t *testing.T) {
	b := NewBuf(16)
	b.PutStr("")
	rb := BufFrom(b.Bytes())
	s, _ := rb.GetStr()
	if s != "" {
		t.Fatalf("got %q", s)
	}
}

func TestBufUnderflow(t *testing.T) {
	b := NewBuf(4)
	b.PutU8(0x42)
	rb := BufFrom(b.Bytes())
	_, err := rb.GetU16()
	if err == nil {
		t.Fatal("expected error on underflow")
	}
}

// ====== Capability tests ======

func TestCapSetBasic(t *testing.T) {
	cs := NewCapSet()
	cs.Add(CapTLS)
	cs.Add(CapCompound)
	cs.Add(CapWatch)
	if !cs.Has(CapTLS) {
		t.Fatal("missing TLS")
	}
	if !cs.Has(CapCompound) {
		t.Fatal("missing compound")
	}
	if cs.Has(CapLease) {
		t.Fatal("unexpected lease")
	}
}

func TestCapSetBitmask(t *testing.T) {
	cs := NewCapSet()
	cs.Add(CapHash)
	cs.Add(CapSession)
	if !cs.HasBit(CBitHash) {
		t.Fatal("bit hash not set")
	}
	if !cs.HasBit(CBitSession) {
		t.Fatal("bit session not set")
	}
	if cs.HasBit(CBitTLS) {
		t.Fatal("bit TLS should not be set")
	}
}

func TestCapSetIntersect(t *testing.T) {
	client := NewCapSet()
	client.Add(CapTLS)
	client.Add(CapCompound)
	client.Add(CapWatch)
	client.Add(CapLease)

	server := NewCapSet()
	server.Add(CapCompound)
	server.Add(CapWatch)
	server.Add(CapHealth)

	result := Intersect(client, server)
	if result.Count() != 2 {
		t.Fatalf("count: %d", result.Count())
	}
	if !result.Has(CapCompound) {
		t.Fatal("missing compound")
	}
	if !result.Has(CapWatch) {
		t.Fatal("missing watch")
	}
	if result.Has(CapTLS) {
		t.Fatal("unexpected TLS")
	}
}

func TestCapSetDedup(t *testing.T) {
	cs := NewCapSet()
	cs.Add(CapTLS)
	cs.Add(CapTLS)
	cs.Add(CapTLS)
	if cs.Count() != 1 {
		t.Fatalf("dedup failed: %d", cs.Count())
	}
}

func TestCapToBit(t *testing.T) {
	if CapToBit(CapTLS) != int(CBitTLS) {
		t.Fatal("TLS bit")
	}
	if CapToBit(CapHash) != int(CBitHash) {
		t.Fatal("hash bit")
	}
	if CapToBit("unknown.cap") != -1 {
		t.Fatal("unknown should be -1")
	}
}

// ====== Marshal/Unmarshal round-trip tests ======

func TestCapsRoundTrip(t *testing.T) {
	fc := &Fcall{Type: Tcaps, Tag: 1, Msg: &MsgCaps{
		Caps: []string{"security.tls", "perf.compound", "fs.watch"},
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgCaps)
	if len(m.Caps) != 3 {
		t.Fatalf("ncaps: %d", len(m.Caps))
	}
	if m.Caps[0] != "security.tls" {
		t.Fatalf("cap0: %s", m.Caps[0])
	}
}

func TestStartlsRoundTrip(t *testing.T) {
	fc := &Fcall{Type: Tstartls, Tag: 42, Msg: nil}
	buf := NewBuf(16)
	Marshal(buf, fc)
	if buf.Len() != HeaderSize {
		t.Fatalf("startls size: %d, want %d", buf.Len(), HeaderSize)
	}
	got := roundTrip(t, fc)
	if got.Tag != 42 {
		t.Fatalf("tag: %d", got.Tag)
	}
}

func TestWatchRoundTrip(t *testing.T) {
	fc := &Fcall{Type: Twatch, Tag: 7, Msg: &MsgWatch{
		Fid: 100, Mask: WatchCreate | WatchModify, Flags: WatchRecursive,
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgWatch)
	if m.Fid != 100 || m.Mask != WatchCreate|WatchModify || m.Flags != WatchRecursive {
		t.Fatalf("watch: %+v", m)
	}
}

func TestNotifyRoundTrip(t *testing.T) {
	fc := &Fcall{Type: Rnotify, Tag: NoTag, Msg: &MsgNotify{
		WatchID: 42, Event: WatchCreate, Name: "newfile.txt",
		Qid: QID{Type: 0, Version: 1, Path: 12345},
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgNotify)
	if got.Tag != NoTag {
		t.Fatalf("tag: %d", got.Tag)
	}
	if m.WatchID != 42 || m.Name != "newfile.txt" || m.Qid.Path != 12345 {
		t.Fatalf("notify: %+v", m)
	}
}

func TestLeaseRoundTrip(t *testing.T) {
	fc := &Fcall{Type: Tlease, Tag: 10, Msg: &MsgLease{
		Fid: 200, Type: LeaseWrite, Duration: 30,
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgLease)
	if m.Fid != 200 || m.Type != LeaseWrite || m.Duration != 30 {
		t.Fatalf("lease: %+v", m)
	}
}

func TestLeasebreakRoundTrip(t *testing.T) {
	fc := &Fcall{Type: Rleasebreak, Tag: NoTag, Msg: &MsgLeasebreak{
		LeaseID: 0x1234567890ABCDEF, NewType: LeaseRead,
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgLeasebreak)
	if got.Tag != NoTag {
		t.Fatal("not NOTAG")
	}
	if m.LeaseID != 0x1234567890ABCDEF || m.NewType != LeaseRead {
		t.Fatalf("leasebreak: %+v", m)
	}
}

func TestSessionRoundTrip(t *testing.T) {
	var key [16]byte
	for i := range key {
		key[i] = 0xAB
	}
	fc := &Fcall{Type: Tsession, Tag: 5, Msg: &MsgSession{
		Key: key, Flags: SessionFids | SessionLeases,
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgSession)
	if m.Key[0] != 0xAB || m.Key[15] != 0xAB {
		t.Fatal("key mismatch")
	}
	if m.Flags != SessionFids|SessionLeases {
		t.Fatalf("flags: %x", m.Flags)
	}
}

func TestCompoundRoundTrip(t *testing.T) {
	fc := &Fcall{Type: Tcompound, Tag: 99, Msg: &MsgCompound{
		Ops: []SubOp{
			{Type: 110, Payload: []byte{0x01, 0x02, 0x03}},
			{Type: 116, Payload: []byte{0x04, 0x05}},
		},
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgCompound)
	if len(m.Ops) != 2 {
		t.Fatalf("nops: %d", len(m.Ops))
	}
	if m.Ops[0].Type != 110 || len(m.Ops[0].Payload) != 3 {
		t.Fatalf("op0: %+v", m.Ops[0])
	}
}

func TestHashRoundTrip(t *testing.T) {
	fc := &Fcall{Type: Thash, Tag: 20, Msg: &MsgHash{
		Fid: 55, Algo: HashBLAKE3, Offset: 0, Length: 0,
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgHash)
	if m.Fid != 55 || m.Algo != HashBLAKE3 {
		t.Fatalf("hash: %+v", m)
	}
}

func TestCompressRoundTrip(t *testing.T) {
	fc := &Fcall{Type: Tcompress, Tag: 15, Msg: &MsgCompress{
		Algo: CompressZstd, Level: 3,
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgCompress)
	if m.Algo != CompressZstd || m.Level != 3 {
		t.Fatalf("compress: %+v", m)
	}
}

func TestCopyrangeRoundTrip(t *testing.T) {
	fc := &Fcall{Type: Tcopyrange, Tag: 30, Msg: &MsgCopyrange{
		SrcFid: 10, SrcOff: 1024, DstFid: 20, DstOff: 0, Count: 65536, Flags: CopyReflink,
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgCopyrange)
	if m.SrcFid != 10 || m.Count != 65536 || m.Flags != CopyReflink {
		t.Fatalf("copyrange: %+v", m)
	}
}

func TestAllocateRoundTrip(t *testing.T) {
	fc := &Fcall{Type: Tallocate, Tag: 40, Msg: &MsgAllocate{
		Fid: 77, Mode: 0x03, Offset: 4096, Length: 8192,
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgAllocate)
	if m.Fid != 77 || m.Mode != 0x03 || m.Offset != 4096 || m.Length != 8192 {
		t.Fatalf("allocate: %+v", m)
	}
}

func TestAuthnegRoundTrip(t *testing.T) {
	fc := &Fcall{Type: Tauthneg, Tag: 2, Msg: &MsgAuthneg{
		Mechs: []string{AuthScramSHA256, AuthMTLS, AuthP9any},
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgAuthneg)
	if len(m.Mechs) != 3 || m.Mechs[0] != AuthScramSHA256 {
		t.Fatalf("authneg: %+v", m)
	}
}

// ====== SPIFFE tests ======

func TestSpiffeCapability(t *testing.T) {
	client := NewCapSet()
	client.Add(CapSpiffe)
	client.Add(CapTLS)
	client.Add(CapAuth)

	server := NewCapSet()
	server.Add(CapSpiffe)
	server.Add(CapTLS)

	result := Intersect(client, server)
	if !result.Has(CapSpiffe) {
		t.Fatal("missing SPIFFE")
	}
	if !result.HasBit(CBitSpiffe) {
		t.Fatal("SPIFFE bit not set")
	}
	if result.Has(CapAuth) {
		t.Fatal("unexpected auth")
	}
}

func TestStartlsSpiffeRoundTrip(t *testing.T) {
	fc := &Fcall{Type: TstartlsSpiffe, Tag: 3, Msg: &MsgStartlsSpiffe{
		SpiffeID:    "spiffe://example.com/server/web-frontend",
		TrustDomain: "example.com",
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgStartlsSpiffe)
	if m.SpiffeID != "spiffe://example.com/server/web-frontend" {
		t.Fatalf("spiffe_id: %s", m.SpiffeID)
	}
	if m.TrustDomain != "example.com" {
		t.Fatalf("trust_domain: %s", m.TrustDomain)
	}
}

func TestFetchbundleRoundTrip(t *testing.T) {
	fc := &Fcall{Type: Tfetchbundle, Tag: 10, Msg: &MsgFetchbundle{
		TrustDomain: "prod.example.com", Format: BundleX509CAs,
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgFetchbundle)
	if m.TrustDomain != "prod.example.com" || m.Format != BundleX509CAs {
		t.Fatalf("fetchbundle: %+v", m)
	}
}

func TestRfetchbundleRoundTrip(t *testing.T) {
	pem := []byte("-----BEGIN CERTIFICATE-----\nMIIBxTCCA...\n-----END CERTIFICATE-----\n")
	fc := &Fcall{Type: Rfetchbundle, Tag: 10, Msg: &MsgRfetchbundle{
		TrustDomain: "prod.example.com", Format: BundleX509CAs, Bundle: pem,
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgRfetchbundle)
	if m.TrustDomain != "prod.example.com" || string(m.Bundle) != string(pem) {
		t.Fatalf("rfetchbundle: %+v", m)
	}
}

func TestSpiffeverifyRoundTrip(t *testing.T) {
	jwt := []byte("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLmNvbSJ9.sig")
	fc := &Fcall{Type: Tspiffeverify, Tag: 20, Msg: &MsgSpiffeverify{
		SVIDType: SVIDJWT, SpiffeID: "spiffe://example.com/workload", SVID: jwt,
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgSpiffeverify)
	if m.SVIDType != SVIDJWT || m.SpiffeID != "spiffe://example.com/workload" {
		t.Fatalf("spiffeverify: %+v", m)
	}
}

func TestRspiffeverifyRoundTrip(t *testing.T) {
	fc := &Fcall{Type: Rspiffeverify, Tag: 20, Msg: &MsgRspiffeverify{
		Status: SpiffeOK, SpiffeID: "spiffe://example.com/workload",
		Expiry: 1743400000000000000,
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgRspiffeverify)
	if m.Status != SpiffeOK || m.SpiffeID != "spiffe://example.com/workload" {
		t.Fatalf("rspiffeverify: %+v", m)
	}
	if m.Expiry != 1743400000000000000 {
		t.Fatalf("expiry: %d", m.Expiry)
	}
}

func TestSpiffeAuthneg(t *testing.T) {
	fc := &Fcall{Type: Tauthneg, Tag: 5, Msg: &MsgAuthneg{
		Mechs: []string{AuthSpiffeX509, AuthSpiffeJWT, AuthMTLS},
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgAuthneg)
	if m.Mechs[0] != "SPIFFE-X.509" || m.Mechs[1] != "SPIFFE-JWT" {
		t.Fatalf("mechs: %v", m.Mechs)
	}
}

func TestSpiffeMsgNames(t *testing.T) {
	if MsgName(TstartlsSpiffe) != "Tstartls_spiffe" {
		t.Fatal("name mismatch")
	}
	if MsgName(Tfetchbundle) != "Tfetchbundle" {
		t.Fatal("name mismatch")
	}
	if MsgName(Rspiffeverify) != "Rspiffeverify" {
		t.Fatal("name mismatch")
	}
}

// ====== Transport tests ======

func TestRdmatokenRoundTrip(t *testing.T) {
	fc := &Fcall{Type: Trdmatoken, Tag: 50, Msg: &MsgRdmatoken{
		Fid: 10, Direction: 1, Rkey: 0xAABBCCDD, Addr: 0x1000200030004000, Length: 65536,
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgRdmatoken)
	if m.Fid != 10 || m.Direction != 1 || m.Rkey != 0xAABBCCDD || m.Addr != 0x1000200030004000 || m.Length != 65536 {
		t.Fatalf("rdmatoken: %+v", m)
	}

	// Reply
	fcr := &Fcall{Type: Rrdmatoken, Tag: 50, Msg: &MsgRrdmatoken{
		Rkey: 0x11223344, Addr: 0x5000600070008000, Length: 32768,
	}}
	gotr := roundTrip(t, fcr)
	mr := gotr.Msg.(*MsgRrdmatoken)
	if mr.Rkey != 0x11223344 || mr.Addr != 0x5000600070008000 || mr.Length != 32768 {
		t.Fatalf("rrdmatoken: %+v", mr)
	}
}

func TestRdmanotifyRoundTrip(t *testing.T) {
	fc := &Fcall{Type: Trdmanotify, Tag: 51, Msg: &MsgRdmanotify{
		Rkey: 0xDEAD, Addr: 0xBEEF0000, Length: 4096, Slots: 128,
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgRdmanotify)
	if m.Rkey != 0xDEAD || m.Addr != 0xBEEF0000 || m.Length != 4096 || m.Slots != 128 {
		t.Fatalf("rdmanotify: %+v", m)
	}

	// Reply is empty
	fcr := &Fcall{Type: Rrdmanotify, Tag: 51, Msg: nil}
	gotr := roundTrip(t, fcr)
	if gotr.Msg != nil {
		t.Fatal("Rrdmanotify should have nil payload")
	}
}

func TestQuicstreamRoundTrip(t *testing.T) {
	fc := &Fcall{Type: Tquicstream, Tag: 52, Msg: &MsgQuicstream{
		StreamType: QStreamData, StreamID: 0x123456789ABCDEF0,
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgQuicstream)
	if m.StreamType != QStreamData || m.StreamID != 0x123456789ABCDEF0 {
		t.Fatalf("quicstream: %+v", m)
	}

	// Reply
	fcr := &Fcall{Type: Rquicstream, Tag: 52, Msg: &MsgRquicstream{
		StreamID: 0xFEDCBA9876543210,
	}}
	gotr := roundTrip(t, fcr)
	mr := gotr.Msg.(*MsgRquicstream)
	if mr.StreamID != 0xFEDCBA9876543210 {
		t.Fatalf("rquicstream: %+v", mr)
	}
}

func TestTransportCapability(t *testing.T) {
	client := NewCapSet()
	client.Add(CapQUIC)
	client.Add(CapQUICMulti)
	client.Add(CapRDMA)
	client.Add(CapTLS)

	server := NewCapSet()
	server.Add(CapQUIC)
	server.Add(CapRDMA)

	result := Intersect(client, server)
	if !result.Has(CapQUIC) {
		t.Fatal("missing QUIC")
	}
	if !result.HasBit(CBitQUIC) {
		t.Fatal("QUIC bit not set")
	}
	if !result.Has(CapRDMA) {
		t.Fatal("missing RDMA")
	}
	if !result.HasBit(CBitRDMA) {
		t.Fatal("RDMA bit not set")
	}
	if result.Has(CapQUICMulti) {
		t.Fatal("unexpected QUIC multistream")
	}
	if result.Has(CapTLS) {
		t.Fatal("unexpected TLS")
	}
}

func TestCxlmapRoundTrip(t *testing.T) {
	fc := &Fcall{Type: Tcxlmap, Tag: 60, Msg: &MsgCxlmap{
		Fid: 8, Offset: 0, Length: 0x100000, Prot: 3, Flags: 5,
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgCxlmap)
	if m.Fid != 8 || m.Offset != 0 || m.Length != 0x100000 || m.Prot != 3 || m.Flags != 5 {
		t.Fatalf("cxlmap: %+v", m)
	}

	// Reply
	fcr := &Fcall{Type: Rcxlmap, Tag: 60, Msg: &MsgRcxlmap{
		HPA: 0x800000000000, Length: 0x100000, Granularity: 4096, Coherence: CXLCoherenceHardware,
	}}
	gotr := roundTrip(t, fcr)
	mr := gotr.Msg.(*MsgRcxlmap)
	if mr.HPA != 0x800000000000 || mr.Length != 0x100000 || mr.Granularity != 4096 || mr.Coherence != CXLCoherenceHardware {
		t.Fatalf("rcxlmap: %+v", mr)
	}
}

func TestCxlcoherenceRoundTrip(t *testing.T) {
	fc := &Fcall{Type: Tcxlcoherence, Tag: 61, Msg: &MsgCxlcoherence{
		Fid: 8, Mode: 2,
	}}
	got := roundTrip(t, fc)
	m := got.Msg.(*MsgCxlcoherence)
	if m.Fid != 8 || m.Mode != 2 {
		t.Fatalf("cxlcoherence: %+v", m)
	}

	// Reply
	fcr := &Fcall{Type: Rcxlcoherence, Tag: 61, Msg: &MsgRcxlcoherence{
		Mode: 1, SnoopID: 42,
	}}
	gotr := roundTrip(t, fcr)
	mr := gotr.Msg.(*MsgRcxlcoherence)
	if mr.Mode != 1 || mr.SnoopID != 42 {
		t.Fatalf("rcxlcoherence: %+v", mr)
	}
}

func TestCxlCapability(t *testing.T) {
	client := NewCapSet()
	client.Add(CapCXL)
	client.Add(CapRDMA)

	server := NewCapSet()
	server.Add(CapCXL)

	result := Intersect(client, server)
	if !result.Has(CapCXL) {
		t.Fatal("missing CXL")
	}
	if !result.HasBit(CBitCXL) {
		t.Fatal("CXL bit not set")
	}
	if result.Has(CapRDMA) {
		t.Fatal("unexpected RDMA")
	}
}

func TestTransportMsgNames(t *testing.T) {
	if MsgName(Trdmatoken) != "Trdmatoken" {
		t.Fatal("Trdmatoken name mismatch")
	}
	if MsgName(Rrdmanotify) != "Rrdmanotify" {
		t.Fatal("Rrdmanotify name mismatch")
	}
	if MsgName(Tquicstream) != "Tquicstream" {
		t.Fatal("Tquicstream name mismatch")
	}
	if MsgName(Rquicstream) != "Rquicstream" {
		t.Fatal("Rquicstream name mismatch")
	}
}

// ====== Wire format tests ======

func TestMsgNames(t *testing.T) {
	if MsgName(Tcaps) != "Tcaps" {
		t.Fatal("Tcaps")
	}
	if MsgName(Rnotify) != "Rnotify" {
		t.Fatal("Rnotify")
	}
	if MsgName(0) != "unknown" {
		t.Fatal("unknown")
	}
}

func TestWireHeaderSize(t *testing.T) {
	fc := &Fcall{Type: Tstartls, Tag: 0, Msg: nil}
	buf := NewBuf(16)
	Marshal(buf, fc)
	if buf.Len() != HeaderSize {
		t.Fatalf("header size: %d, want %d", buf.Len(), HeaderSize)
	}
}
