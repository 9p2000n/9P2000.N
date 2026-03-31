package p9n

import (
	"fmt"
)

// msgBegin writes the header placeholder and returns the offset for size patching.
func msgBegin(b *Buf, t MsgType, tag uint16) int {
	off := b.Len()
	b.PutU32(0) // placeholder size
	b.PutU8(uint8(t))
	b.PutU16(tag)
	return off
}

func msgFinish(b *Buf, off int) {
	b.PatchU32(off, uint32(b.Len()-off))
}

// Marshal encodes an Fcall to wire format and appends to buf.
func Marshal(buf *Buf, fc *Fcall) error {
	off := msgBegin(buf, fc.Type, fc.Tag)

	switch m := fc.Msg.(type) {
	// -- Negotiation --
	case *MsgCaps:
		buf.PutU16(uint16(len(m.Caps)))
		for _, c := range m.Caps {
			buf.PutStr(c)
		}

	// -- Security --
	case nil: // empty payload (Tstartls, Rstartls, Rauditctl, Rallocate, etc.)
		// nothing

	case *MsgAuthneg:
		buf.PutU16(uint16(len(m.Mechs)))
		for _, mech := range m.Mechs {
			buf.PutStr(mech)
		}

	case *MsgRauthneg:
		buf.PutStr(m.Mech)
		buf.PutData(m.Challenge)

	case *MsgCapgrant:
		buf.PutU32(m.Fid)
		buf.PutU64(m.Rights)
		buf.PutU64(m.Expiry)
		buf.PutU16(m.Depth)

	case *MsgRcapgrant:
		buf.PutStr(m.Token)

	case *MsgCapuse:
		buf.PutU32(m.Fid)
		buf.PutStr(m.Token)

	case *MsgRcapuse:
		buf.PutQID(m.Qid)

	case *MsgAuditctl:
		buf.PutU32(m.Fid)
		buf.PutU32(m.Flags)

	// -- SPIFFE --
	case *MsgStartlsSpiffe:
		buf.PutStr(m.SpiffeID)
		buf.PutStr(m.TrustDomain)

	case *MsgFetchbundle:
		buf.PutStr(m.TrustDomain)
		buf.PutU8(m.Format)

	case *MsgRfetchbundle:
		buf.PutStr(m.TrustDomain)
		buf.PutU8(m.Format)
		buf.PutData(m.Bundle)

	case *MsgSpiffeverify:
		buf.PutU8(m.SVIDType)
		buf.PutStr(m.SpiffeID)
		buf.PutData(m.SVID)

	case *MsgRspiffeverify:
		buf.PutU8(m.Status)
		buf.PutStr(m.SpiffeID)
		buf.PutU64(m.Expiry)

	// -- Transport --
	case *MsgCxlmap:
		buf.PutU32(m.Fid)
		buf.PutU64(m.Offset)
		buf.PutU64(m.Length)
		buf.PutU32(m.Prot)
		buf.PutU32(m.Flags)

	case *MsgRcxlmap:
		buf.PutU64(m.HPA)
		buf.PutU64(m.Length)
		buf.PutU32(m.Granularity)
		buf.PutU8(m.Coherence)

	case *MsgCxlcoherence:
		buf.PutU32(m.Fid)
		buf.PutU8(m.Mode)

	case *MsgRcxlcoherence:
		buf.PutU8(m.Mode)
		buf.PutU32(m.SnoopID)

	case *MsgRdmatoken:
		buf.PutU32(m.Fid)
		buf.PutU8(m.Direction)
		buf.PutU32(m.Rkey)
		buf.PutU64(m.Addr)
		buf.PutU32(m.Length)

	case *MsgRrdmatoken:
		buf.PutU32(m.Rkey)
		buf.PutU64(m.Addr)
		buf.PutU32(m.Length)

	case *MsgRdmanotify:
		buf.PutU32(m.Rkey)
		buf.PutU64(m.Addr)
		buf.PutU32(m.Length)
		buf.PutU16(m.Slots)

	case *MsgQuicstream:
		buf.PutU8(m.StreamType)
		buf.PutU64(m.StreamID)

	case *MsgRquicstream:
		buf.PutU64(m.StreamID)

	// -- Performance --
	case *MsgCompound:
		buf.PutU16(uint16(len(m.Ops)))
		for _, op := range m.Ops {
			opsize := uint32(SubopHdrSz + len(op.Payload))
			buf.PutU32(opsize)
			buf.PutU8(uint8(op.Type))
			buf.PutBytes(op.Payload)
		}

	case *MsgRcompound:
		buf.PutU16(uint16(len(m.Results)))
		for _, r := range m.Results {
			opsize := uint32(SubopHdrSz + len(r.Payload))
			buf.PutU32(opsize)
			buf.PutU8(uint8(r.Type))
			buf.PutBytes(r.Payload)
		}

	case *MsgCompress:
		buf.PutU8(m.Algo)
		buf.PutU8(m.Level)

	case *MsgRcompress:
		buf.PutU8(m.Algo)

	case *MsgCopyrange:
		buf.PutU32(m.SrcFid)
		buf.PutU64(m.SrcOff)
		buf.PutU32(m.DstFid)
		buf.PutU64(m.DstOff)
		buf.PutU64(m.Count)
		buf.PutU32(m.Flags)

	case *MsgRcopyrange:
		buf.PutU64(m.Count)

	case *MsgAllocate:
		buf.PutU32(m.Fid)
		buf.PutU32(m.Mode)
		buf.PutU64(m.Offset)
		buf.PutU64(m.Length)

	case *MsgSeekhole:
		buf.PutU32(m.Fid)
		buf.PutU8(m.SeekType)
		buf.PutU64(m.Offset)

	case *MsgRseekhole:
		buf.PutU64(m.Offset)

	case *MsgMmaphint:
		buf.PutU32(m.Fid)
		buf.PutU64(m.Offset)
		buf.PutU64(m.Length)
		buf.PutU32(m.Prot)

	case *MsgRmmaphint:
		buf.PutU8(m.Granted)

	// -- Filesystem --
	case *MsgWatch:
		buf.PutU32(m.Fid)
		buf.PutU32(m.Mask)
		buf.PutU32(m.Flags)

	case *MsgRwatch:
		buf.PutU32(m.WatchID)

	case *MsgUnwatch:
		buf.PutU32(m.WatchID)

	case *MsgNotify:
		buf.PutU32(m.WatchID)
		buf.PutU32(m.Event)
		buf.PutStr(m.Name)
		buf.PutQID(m.Qid)

	case *MsgGetacl:
		buf.PutU32(m.Fid)
		buf.PutU8(m.ACLType)

	case *MsgRgetacl:
		buf.PutData(m.Data)

	case *MsgSetacl:
		buf.PutU32(m.Fid)
		buf.PutU8(m.ACLType)
		buf.PutData(m.Data)

	case *MsgSnapshot:
		buf.PutU32(m.Fid)
		buf.PutStr(m.Name)
		buf.PutU32(m.Flags)

	case *MsgRsnapshot:
		buf.PutQID(m.Qid)

	case *MsgClone:
		buf.PutU32(m.SrcFid)
		buf.PutU32(m.DstFid)
		buf.PutStr(m.Name)
		buf.PutU32(m.Flags)

	case *MsgRclone:
		buf.PutQID(m.Qid)

	case *MsgXattrget:
		buf.PutU32(m.Fid)
		buf.PutStr(m.Name)

	case *MsgRxattrget:
		buf.PutData(m.Data)

	case *MsgXattrset:
		buf.PutU32(m.Fid)
		buf.PutStr(m.Name)
		buf.PutData(m.Data)
		buf.PutU32(m.Flags)

	case *MsgXattrlist:
		buf.PutU32(m.Fid)
		buf.PutU64(m.Cookie)
		buf.PutU32(m.Count)

	case *MsgRxattrlist:
		buf.PutU64(m.Cookie)
		buf.PutU16(uint16(len(m.Names)))
		for _, n := range m.Names {
			buf.PutStr(n)
		}

	// -- Distributed --
	case *MsgLease:
		buf.PutU32(m.Fid)
		buf.PutU8(m.Type)
		buf.PutU32(m.Duration)

	case *MsgRlease:
		buf.PutU64(m.LeaseID)
		buf.PutU8(m.Type)
		buf.PutU32(m.Duration)

	case *MsgLeaserenew:
		buf.PutU64(m.LeaseID)
		buf.PutU32(m.Duration)

	case *MsgRleaserenew:
		buf.PutU32(m.Duration)

	case *MsgLeasebreak:
		buf.PutU64(m.LeaseID)
		buf.PutU8(m.NewType)

	case *MsgLeaseack:
		buf.PutU64(m.LeaseID)

	case *MsgSession:
		buf.PutBytes(m.Key[:])
		buf.PutU32(m.Flags)

	case *MsgRsession:
		buf.PutU32(m.Flags)

	case *MsgConsistency:
		buf.PutU32(m.Fid)
		buf.PutU8(m.Level)

	case *MsgRconsistency:
		buf.PutU8(m.Level)

	case *MsgTopology:
		buf.PutU32(m.Fid)

	case *MsgRtopology:
		buf.PutU16(uint16(len(m.Replicas)))
		for _, r := range m.Replicas {
			buf.PutStr(r.Addr)
			buf.PutU8(r.Role)
			buf.PutU32(r.LatencyUs)
		}

	// -- Observability --
	case *MsgTraceattr:
		buf.PutU16(uint16(len(m.Attrs)))
		for k, v := range m.Attrs {
			buf.PutStr(k)
			buf.PutStr(v)
		}

	case *MsgRhealth:
		buf.PutU8(m.Status)
		buf.PutU32(m.Load)
		buf.PutU16(uint16(len(m.Metrics)))
		for _, mt := range m.Metrics {
			buf.PutStr(mt.Name)
			buf.PutU64(mt.Value)
		}

	case *MsgServerstatsReq:
		buf.PutU64(m.Mask)

	case *MsgRserverstats:
		buf.PutU16(uint16(len(m.Stats)))
		for _, s := range m.Stats {
			buf.PutStr(s.Name)
			buf.PutU8(s.Type)
			buf.PutU64(s.Value)
		}

	// -- Resource management --
	case *MsgGetquota:
		buf.PutU32(m.Fid)
		buf.PutU8(m.Type)

	case *MsgRgetquota:
		buf.PutU64(m.BytesUsed)
		buf.PutU64(m.BytesLimit)
		buf.PutU64(m.FilesUsed)
		buf.PutU64(m.FilesLimit)
		buf.PutU32(m.GracePeriod)

	case *MsgSetquota:
		buf.PutU32(m.Fid)
		buf.PutU8(m.Type)
		buf.PutU64(m.BytesLimit)
		buf.PutU64(m.FilesLimit)
		buf.PutU32(m.GracePeriod)

	case *MsgRatelimit:
		buf.PutU32(m.Fid)
		buf.PutU32(m.IOPS)
		buf.PutU64(m.BPS)

	case *MsgRratelimit:
		buf.PutU32(m.IOPS)
		buf.PutU64(m.BPS)

	// -- Streaming/Async --
	case *MsgAsync:
		buf.PutU8(uint8(m.InnerType))
		buf.PutBytes(m.Payload)

	case *MsgRasync:
		buf.PutU64(m.OpID)
		buf.PutU8(m.Status)

	case *MsgPoll:
		buf.PutU64(m.OpID)

	case *MsgRpoll:
		buf.PutU8(m.Status)
		buf.PutU32(m.Progress)
		buf.PutBytes(m.Payload)

	case *MsgStreamopen:
		buf.PutU32(m.Fid)
		buf.PutU8(m.Direction)
		buf.PutU64(m.Offset)
		buf.PutU64(m.Count)

	case *MsgRstreamopen:
		buf.PutU32(m.StreamID)

	case *MsgStreamdata:
		buf.PutU32(m.StreamID)
		buf.PutU32(m.Seq)
		buf.PutData(m.Data)

	case *MsgStreamclose:
		buf.PutU32(m.StreamID)

	// -- Content --
	case *MsgSearch:
		buf.PutU32(m.Fid)
		buf.PutStr(m.Query)
		buf.PutU32(m.Flags)
		buf.PutU32(m.MaxResults)
		buf.PutU64(m.Cookie)

	case *MsgRsearch:
		buf.PutU64(m.Cookie)
		buf.PutU16(uint16(len(m.Entries)))
		for _, e := range m.Entries {
			buf.PutQID(e.Qid)
			buf.PutStr(e.Name)
			buf.PutU32(e.Score)
		}

	case *MsgHash:
		buf.PutU32(m.Fid)
		buf.PutU8(m.Algo)
		buf.PutU64(m.Offset)
		buf.PutU64(m.Length)

	case *MsgRhash:
		buf.PutU8(m.Algo)
		buf.PutU16(uint16(len(m.Hash)))
		buf.PutBytes(m.Hash)

	default:
		return fmt.Errorf("p9n: unknown message type for marshal: %T", fc.Msg)
	}

	msgFinish(buf, off)
	return nil
}

// Unmarshal decodes a single Fcall from buf.
func Unmarshal(buf *Buf) (*Fcall, error) {
	fc := &Fcall{}
	var err error

	fc.Size, err = buf.GetU32()
	if err != nil {
		return nil, err
	}
	t, err := buf.GetU8()
	if err != nil {
		return nil, err
	}
	fc.Type = MsgType(t)
	fc.Tag, err = buf.GetU16()
	if err != nil {
		return nil, err
	}

	switch fc.Type {
	// -- Negotiation --
	case Tcaps, Rcaps:
		m := &MsgCaps{}
		n, err := buf.GetU16()
		if err != nil {
			return nil, err
		}
		m.Caps = make([]string, n)
		for i := range m.Caps {
			m.Caps[i], err = buf.GetStr()
			if err != nil {
				return nil, err
			}
		}
		fc.Msg = m

	// -- Security --
	case Tstartls, Rstartls, Rauditctl, Runwatch, Rsetacl, Rxattrset,
		Rallocate, Rleaseack, Rtraceattr, Thealth, Rsetquota,
		Rstreamclose, Rrdmanotify:
		fc.Msg = nil // empty payload

	case Tauthneg:
		m := &MsgAuthneg{}
		n, err := buf.GetU16()
		if err != nil {
			return nil, err
		}
		m.Mechs = make([]string, n)
		for i := range m.Mechs {
			m.Mechs[i], err = buf.GetStr()
			if err != nil {
				return nil, err
			}
		}
		fc.Msg = m

	case Rauthneg:
		m := &MsgRauthneg{}
		m.Mech, err = buf.GetStr()
		if err != nil {
			return nil, err
		}
		m.Challenge, err = buf.GetData()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tcapgrant:
		m := &MsgCapgrant{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Rights, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.Expiry, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.Depth, err = buf.GetU16()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rcapgrant:
		m := &MsgRcapgrant{}
		m.Token, err = buf.GetStr()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tcapuse:
		m := &MsgCapuse{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Token, err = buf.GetStr()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rcapuse:
		m := &MsgRcapuse{}
		m.Qid, err = buf.GetQID()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tauditctl:
		m := &MsgAuditctl{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Flags, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	// -- SPIFFE --
	case TstartlsSpiffe, RstartlsSpiffe:
		m := &MsgStartlsSpiffe{}
		m.SpiffeID, err = buf.GetStr()
		if err != nil {
			return nil, err
		}
		m.TrustDomain, err = buf.GetStr()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tfetchbundle:
		m := &MsgFetchbundle{}
		m.TrustDomain, err = buf.GetStr()
		if err != nil {
			return nil, err
		}
		m.Format, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rfetchbundle:
		m := &MsgRfetchbundle{}
		m.TrustDomain, err = buf.GetStr()
		if err != nil {
			return nil, err
		}
		m.Format, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		m.Bundle, err = buf.GetData()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tspiffeverify:
		m := &MsgSpiffeverify{}
		m.SVIDType, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		m.SpiffeID, err = buf.GetStr()
		if err != nil {
			return nil, err
		}
		m.SVID, err = buf.GetData()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rspiffeverify:
		m := &MsgRspiffeverify{}
		m.Status, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		m.SpiffeID, err = buf.GetStr()
		if err != nil {
			return nil, err
		}
		m.Expiry, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	// -- Transport --
	case Tcxlmap:
		m := &MsgCxlmap{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Offset, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.Length, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.Prot, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Flags, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rcxlmap:
		m := &MsgRcxlmap{}
		m.HPA, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.Length, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.Granularity, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Coherence, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tcxlcoherence:
		m := &MsgCxlcoherence{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Mode, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rcxlcoherence:
		m := &MsgRcxlcoherence{}
		m.Mode, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		m.SnoopID, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Trdmatoken:
		m := &MsgRdmatoken{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Direction, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		m.Rkey, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Addr, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.Length, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rrdmatoken:
		m := &MsgRrdmatoken{}
		m.Rkey, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Addr, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.Length, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Trdmanotify:
		m := &MsgRdmanotify{}
		m.Rkey, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Addr, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.Length, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Slots, err = buf.GetU16()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tquicstream:
		m := &MsgQuicstream{}
		m.StreamType, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		m.StreamID, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rquicstream:
		m := &MsgRquicstream{}
		m.StreamID, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	// -- Performance --
	case Tcompound:
		m := &MsgCompound{}
		m.Ops, err = unmarshalSubops(buf)
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rcompound:
		m := &MsgRcompound{}
		m.Results, err = unmarshalSubops(buf)
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tcompress:
		m := &MsgCompress{}
		m.Algo, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		m.Level, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rcompress:
		m := &MsgRcompress{}
		m.Algo, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tcopyrange:
		m := &MsgCopyrange{}
		m.SrcFid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.SrcOff, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.DstFid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.DstOff, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.Count, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.Flags, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rcopyrange:
		m := &MsgRcopyrange{}
		m.Count, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tallocate:
		m := &MsgAllocate{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Mode, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Offset, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.Length, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tseekhole:
		m := &MsgSeekhole{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.SeekType, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		m.Offset, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rseekhole:
		m := &MsgRseekhole{}
		m.Offset, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tmmaphint:
		m := &MsgMmaphint{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Offset, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.Length, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.Prot, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rmmaphint:
		m := &MsgRmmaphint{}
		m.Granted, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	// -- Filesystem --
	case Twatch:
		m := &MsgWatch{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Mask, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Flags, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rwatch:
		m := &MsgRwatch{}
		m.WatchID, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tunwatch:
		m := &MsgUnwatch{}
		m.WatchID, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rnotify:
		m := &MsgNotify{}
		m.WatchID, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Event, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Name, err = buf.GetStr()
		if err != nil {
			return nil, err
		}
		m.Qid, err = buf.GetQID()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tgetacl:
		m := &MsgGetacl{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.ACLType, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rgetacl:
		m := &MsgRgetacl{}
		m.Data, err = buf.GetData()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tsetacl:
		m := &MsgSetacl{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.ACLType, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		m.Data, err = buf.GetData()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tsnapshot:
		m := &MsgSnapshot{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Name, err = buf.GetStr()
		if err != nil {
			return nil, err
		}
		m.Flags, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rsnapshot:
		m := &MsgRsnapshot{}
		m.Qid, err = buf.GetQID()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tclone:
		m := &MsgClone{}
		m.SrcFid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.DstFid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Name, err = buf.GetStr()
		if err != nil {
			return nil, err
		}
		m.Flags, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rclone:
		m := &MsgRclone{}
		m.Qid, err = buf.GetQID()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Txattrget:
		m := &MsgXattrget{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Name, err = buf.GetStr()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rxattrget:
		m := &MsgRxattrget{}
		m.Data, err = buf.GetData()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Txattrset:
		m := &MsgXattrset{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Name, err = buf.GetStr()
		if err != nil {
			return nil, err
		}
		m.Data, err = buf.GetData()
		if err != nil {
			return nil, err
		}
		m.Flags, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Txattrlist:
		m := &MsgXattrlist{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Cookie, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.Count, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rxattrlist:
		m := &MsgRxattrlist{}
		m.Cookie, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		n, err := buf.GetU16()
		if err != nil {
			return nil, err
		}
		m.Names = make([]string, n)
		for i := range m.Names {
			m.Names[i], err = buf.GetStr()
			if err != nil {
				return nil, err
			}
		}
		fc.Msg = m

	// -- Distributed --
	case Tlease:
		m := &MsgLease{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Type, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		m.Duration, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rlease:
		m := &MsgRlease{}
		m.LeaseID, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.Type, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		m.Duration, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tleaserenew:
		m := &MsgLeaserenew{}
		m.LeaseID, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.Duration, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rleaserenew:
		m := &MsgRleaserenew{}
		m.Duration, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rleasebreak:
		m := &MsgLeasebreak{}
		m.LeaseID, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.NewType, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tleaseack:
		m := &MsgLeaseack{}
		m.LeaseID, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tsession:
		m := &MsgSession{}
		key, err := buf.GetFixedBytes(16)
		if err != nil {
			return nil, err
		}
		copy(m.Key[:], key)
		m.Flags, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rsession:
		m := &MsgRsession{}
		m.Flags, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tconsistency:
		m := &MsgConsistency{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Level, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rconsistency:
		m := &MsgRconsistency{}
		m.Level, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Ttopology:
		m := &MsgTopology{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rtopology:
		m := &MsgRtopology{}
		n, err := buf.GetU16()
		if err != nil {
			return nil, err
		}
		m.Replicas = make([]Replica, n)
		for i := range m.Replicas {
			m.Replicas[i].Addr, err = buf.GetStr()
			if err != nil {
				return nil, err
			}
			m.Replicas[i].Role, err = buf.GetU8()
			if err != nil {
				return nil, err
			}
			m.Replicas[i].LatencyUs, err = buf.GetU32()
			if err != nil {
				return nil, err
			}
		}
		fc.Msg = m

	// -- Observability --
	case Ttraceattr:
		m := &MsgTraceattr{Attrs: make(map[string]string)}
		n, err := buf.GetU16()
		if err != nil {
			return nil, err
		}
		for i := 0; i < int(n); i++ {
			k, err := buf.GetStr()
			if err != nil {
				return nil, err
			}
			v, err := buf.GetStr()
			if err != nil {
				return nil, err
			}
			m.Attrs[k] = v
		}
		fc.Msg = m

	case Rhealth:
		m := &MsgRhealth{}
		m.Status, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		m.Load, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		n, err := buf.GetU16()
		if err != nil {
			return nil, err
		}
		m.Metrics = make([]Metric, n)
		for i := range m.Metrics {
			m.Metrics[i].Name, err = buf.GetStr()
			if err != nil {
				return nil, err
			}
			m.Metrics[i].Value, err = buf.GetU64()
			if err != nil {
				return nil, err
			}
		}
		fc.Msg = m

	case Tserverstats:
		m := &MsgServerstatsReq{}
		m.Mask, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rserverstats:
		m := &MsgRserverstats{}
		n, err := buf.GetU16()
		if err != nil {
			return nil, err
		}
		m.Stats = make([]ServerStat, n)
		for i := range m.Stats {
			m.Stats[i].Name, err = buf.GetStr()
			if err != nil {
				return nil, err
			}
			m.Stats[i].Type, err = buf.GetU8()
			if err != nil {
				return nil, err
			}
			m.Stats[i].Value, err = buf.GetU64()
			if err != nil {
				return nil, err
			}
		}
		fc.Msg = m

	// -- Resource management --
	case Tgetquota:
		m := &MsgGetquota{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Type, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rgetquota:
		m := &MsgRgetquota{}
		m.BytesUsed, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.BytesLimit, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.FilesUsed, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.FilesLimit, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.GracePeriod, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tsetquota:
		m := &MsgSetquota{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Type, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		m.BytesLimit, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.FilesLimit, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.GracePeriod, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tratelimit:
		m := &MsgRatelimit{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.IOPS, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.BPS, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rratelimit:
		m := &MsgRratelimit{}
		m.IOPS, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.BPS, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	// -- Streaming/Async --
	case Tasync:
		m := &MsgAsync{}
		it, err := buf.GetU8()
		if err != nil {
			return nil, err
		}
		m.InnerType = MsgType(it)
		remaining := int(fc.Size) - HeaderSize - 1
		if remaining > 0 {
			m.Payload, err = buf.GetFixedBytes(remaining)
			if err != nil {
				return nil, err
			}
		}
		fc.Msg = m

	case Rasync:
		m := &MsgRasync{}
		m.OpID, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.Status, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tpoll:
		m := &MsgPoll{}
		m.OpID, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rpoll:
		m := &MsgRpoll{}
		m.Status, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		m.Progress, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		remaining := int(fc.Size) - HeaderSize - 5
		if remaining > 0 {
			m.Payload, err = buf.GetFixedBytes(remaining)
			if err != nil {
				return nil, err
			}
		}
		fc.Msg = m

	case Tstreamopen:
		m := &MsgStreamopen{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Direction, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		m.Offset, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.Count, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rstreamopen:
		m := &MsgRstreamopen{}
		m.StreamID, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tstreamdata, Rstreamdata:
		m := &MsgStreamdata{}
		m.StreamID, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Seq, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Data, err = buf.GetData()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Tstreamclose:
		m := &MsgStreamclose{}
		m.StreamID, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	// -- Content --
	case Tsearch:
		m := &MsgSearch{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Query, err = buf.GetStr()
		if err != nil {
			return nil, err
		}
		m.Flags, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.MaxResults, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Cookie, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rsearch:
		m := &MsgRsearch{}
		m.Cookie, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		n, err := buf.GetU16()
		if err != nil {
			return nil, err
		}
		m.Entries = make([]SearchEntry, n)
		for i := range m.Entries {
			m.Entries[i].Qid, err = buf.GetQID()
			if err != nil {
				return nil, err
			}
			m.Entries[i].Name, err = buf.GetStr()
			if err != nil {
				return nil, err
			}
			m.Entries[i].Score, err = buf.GetU32()
			if err != nil {
				return nil, err
			}
		}
		fc.Msg = m

	case Thash:
		m := &MsgHash{}
		m.Fid, err = buf.GetU32()
		if err != nil {
			return nil, err
		}
		m.Algo, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		m.Offset, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		m.Length, err = buf.GetU64()
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	case Rhash:
		m := &MsgRhash{}
		m.Algo, err = buf.GetU8()
		if err != nil {
			return nil, err
		}
		hl, err := buf.GetU16()
		if err != nil {
			return nil, err
		}
		m.Hash, err = buf.GetFixedBytes(int(hl))
		if err != nil {
			return nil, err
		}
		fc.Msg = m

	default:
		return nil, fmt.Errorf("p9n: unknown message type: %d", fc.Type)
	}

	return fc, nil
}

func unmarshalSubops(buf *Buf) ([]SubOp, error) {
	n, err := buf.GetU16()
	if err != nil {
		return nil, err
	}
	ops := make([]SubOp, n)
	for i := range ops {
		opsize, err := buf.GetU32()
		if err != nil {
			return nil, err
		}
		t, err := buf.GetU8()
		if err != nil {
			return nil, err
		}
		ops[i].Type = MsgType(t)
		plen := int(opsize) - SubopHdrSz
		if plen > 0 {
			ops[i].Payload, err = buf.GetFixedBytes(plen)
			if err != nil {
				return nil, err
			}
		}
	}
	return ops, nil
}
