pub mod types;
pub mod buf;
pub mod caps;
pub mod codec;

#[cfg(test)]
mod tests {
    use crate::types::*;
    use crate::buf::Buf;
    use crate::caps::*;
    use crate::codec::*;

    fn round_trip(fc: &Fcall) -> Fcall {
        let mut buf = Buf::new(256);
        marshal(&mut buf, fc).unwrap();
        let mut rbuf = Buf::from_bytes(buf.as_bytes().to_vec());
        unmarshal(&mut rbuf).unwrap()
    }

    // ====== Buffer ======
    #[test] fn buf_u8() {
        let mut b = Buf::new(16); b.put_u8(0x42); b.put_u8(0xFF);
        let mut r = Buf::from_bytes(b.as_bytes().to_vec());
        assert_eq!(r.get_u8().unwrap(), 0x42);
        assert_eq!(r.get_u8().unwrap(), 0xFF);
    }
    #[test] fn buf_u16_le() {
        let mut b = Buf::new(16); b.put_u16(0x1234);
        assert_eq!(b.as_bytes()[0], 0x34); assert_eq!(b.as_bytes()[1], 0x12);
        let mut r = Buf::from_bytes(b.as_bytes().to_vec());
        assert_eq!(r.get_u16().unwrap(), 0x1234);
    }
    #[test] fn buf_u32() {
        let mut b = Buf::new(16); b.put_u32(0xDEADBEEF);
        let mut r = Buf::from_bytes(b.as_bytes().to_vec());
        assert_eq!(r.get_u32().unwrap(), 0xDEADBEEF);
    }
    #[test] fn buf_u64() {
        let mut b = Buf::new(16); b.put_u64(0x0102030405060708);
        let mut r = Buf::from_bytes(b.as_bytes().to_vec());
        assert_eq!(r.get_u64().unwrap(), 0x0102030405060708);
    }
    #[test] fn buf_str() {
        let mut b = Buf::new(64); b.put_str("hello");
        assert_eq!(b.len(), 7);
        let mut r = Buf::from_bytes(b.as_bytes().to_vec());
        assert_eq!(r.get_str().unwrap(), "hello");
    }
    #[test] fn buf_empty_str() {
        let mut b = Buf::new(16); b.put_str("");
        let mut r = Buf::from_bytes(b.as_bytes().to_vec());
        assert_eq!(r.get_str().unwrap(), "");
    }
    #[test] fn buf_underflow() {
        let mut b = Buf::new(4); b.put_u8(0x42);
        let mut r = Buf::from_bytes(b.as_bytes().to_vec());
        assert!(r.get_u16().is_err());
    }

    // ====== Caps ======
    #[test] fn capset_basic() {
        let mut cs = CapSet::new();
        cs.add(CAP_TLS); cs.add(CAP_COMPOUND); cs.add(CAP_WATCH);
        assert!(cs.has(CAP_TLS)); assert!(cs.has(CAP_COMPOUND));
        assert!(!cs.has(CAP_LEASE));
    }
    #[test] fn capset_bitmask() {
        let mut cs = CapSet::new();
        cs.add(CAP_HASH); cs.add(CAP_SESSION);
        assert!(cs.has_bit(CapBit::Hash)); assert!(cs.has_bit(CapBit::Session));
        assert!(!cs.has_bit(CapBit::Tls));
    }
    #[test] fn capset_intersect() {
        let mut c = CapSet::new(); c.add(CAP_TLS); c.add(CAP_COMPOUND); c.add(CAP_WATCH); c.add(CAP_LEASE);
        let mut s = CapSet::new(); s.add(CAP_COMPOUND); s.add(CAP_WATCH); s.add(CAP_HEALTH);
        let r = intersect(&c, &s);
        assert_eq!(r.count(), 2); assert!(r.has(CAP_COMPOUND)); assert!(r.has(CAP_WATCH));
        assert!(!r.has(CAP_TLS)); assert!(!r.has(CAP_HEALTH));
    }
    #[test] fn capset_dedup() {
        let mut cs = CapSet::new(); cs.add(CAP_TLS); cs.add(CAP_TLS); cs.add(CAP_TLS);
        assert_eq!(cs.count(), 1);
    }
    #[test] fn cap_to_bit_fn() {
        assert_eq!(cap_to_bit(CAP_TLS), Some(CapBit::Tls));
        assert_eq!(cap_to_bit(CAP_HASH), Some(CapBit::Hash));
        assert_eq!(cap_to_bit("unknown.cap"), None);
    }

    // ====== Round-trips ======
    #[test] fn caps_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Tcaps, tag: 1,
            msg: Msg::Caps { caps: vec!["security.tls".into(), "perf.compound".into(), "fs.watch".into()] } };
        let got = round_trip(&fc);
        match got.msg { Msg::Caps { ref caps } => { assert_eq!(caps.len(), 3); assert_eq!(caps[0], "security.tls"); } _ => panic!() }
    }
    #[test] fn startls_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Tstartls, tag: 42, msg: Msg::Empty };
        let mut buf = Buf::new(16); marshal(&mut buf, &fc).unwrap();
        assert_eq!(buf.len(), HEADER_SIZE);
        let got = round_trip(&fc); assert_eq!(got.tag, 42);
    }
    #[test] fn watch_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Twatch, tag: 7,
            msg: Msg::Watch { fid: 100, mask: WATCH_CREATE | WATCH_MODIFY, flags: WATCH_RECURSIVE } };
        let got = round_trip(&fc);
        match got.msg { Msg::Watch { fid, mask, flags } => { assert_eq!(fid, 100); assert_eq!(mask, WATCH_CREATE | WATCH_MODIFY); assert_eq!(flags, WATCH_RECURSIVE); } _ => panic!() }
    }
    #[test] fn notify_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Rnotify, tag: NO_TAG,
            msg: Msg::Notify { watch_id: 42, event: WATCH_CREATE, name: "newfile.txt".into(), qid: Qid { qtype: 0, version: 1, path: 12345 } } };
        let got = round_trip(&fc);
        assert_eq!(got.tag, NO_TAG);
        match got.msg { Msg::Notify { watch_id, ref name, ref qid, .. } => { assert_eq!(watch_id, 42); assert_eq!(name, "newfile.txt"); assert_eq!(qid.path, 12345); } _ => panic!() }
    }
    #[test] fn lease_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Tlease, tag: 10,
            msg: Msg::Lease { fid: 200, lease_type: LEASE_WRITE, duration: 30 } };
        let got = round_trip(&fc);
        match got.msg { Msg::Lease { fid, lease_type, duration } => { assert_eq!(fid, 200); assert_eq!(lease_type, LEASE_WRITE); assert_eq!(duration, 30); } _ => panic!() }
    }
    #[test] fn leasebreak_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Rleasebreak, tag: NO_TAG,
            msg: Msg::Leasebreak { lease_id: 0x1234567890ABCDEF, new_type: LEASE_READ } };
        let got = round_trip(&fc);
        assert_eq!(got.tag, NO_TAG);
        match got.msg { Msg::Leasebreak { lease_id, new_type } => { assert_eq!(lease_id, 0x1234567890ABCDEF); assert_eq!(new_type, LEASE_READ); } _ => panic!() }
    }
    #[test] fn session_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Tsession, tag: 5,
            msg: Msg::Session { key: [0xAB; 16], flags: SESSION_FIDS | SESSION_LEASES } };
        let got = round_trip(&fc);
        match got.msg { Msg::Session { key, flags } => { assert_eq!(key[0], 0xAB); assert_eq!(key[15], 0xAB); assert_eq!(flags, SESSION_FIDS | SESSION_LEASES); } _ => panic!() }
    }
    #[test] fn compound_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Tcompound, tag: 99,
            msg: Msg::Compound { ops: vec![
                SubOp { msg_type: MsgType::Twatch, payload: vec![0x01, 0x02, 0x03] },
                SubOp { msg_type: MsgType::Twatch, payload: vec![0x04, 0x05] },
            ] } };
        let got = round_trip(&fc);
        match got.msg { Msg::Compound { ref ops } => { assert_eq!(ops.len(), 2); assert_eq!(ops[0].payload, vec![0x01, 0x02, 0x03]); } _ => panic!() }
    }
    #[test] fn hash_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Thash, tag: 20,
            msg: Msg::Hash { fid: 55, algo: HASH_BLAKE3, offset: 0, length: 0 } };
        let got = round_trip(&fc);
        match got.msg { Msg::Hash { fid, algo, .. } => { assert_eq!(fid, 55); assert_eq!(algo, HASH_BLAKE3); } _ => panic!() }
    }
    #[test] fn compress_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Tcompress, tag: 15,
            msg: Msg::Compress { algo: COMPRESS_ZSTD, level: 3 } };
        let got = round_trip(&fc);
        match got.msg { Msg::Compress { algo, level } => { assert_eq!(algo, COMPRESS_ZSTD); assert_eq!(level, 3); } _ => panic!() }
    }
    #[test] fn copyrange_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Tcopyrange, tag: 30,
            msg: Msg::Copyrange { src_fid: 10, src_off: 1024, dst_fid: 20, dst_off: 0, count: 65536, flags: COPY_REFLINK } };
        let got = round_trip(&fc);
        match got.msg { Msg::Copyrange { src_fid, count, flags, .. } => { assert_eq!(src_fid, 10); assert_eq!(count, 65536); assert_eq!(flags, COPY_REFLINK); } _ => panic!() }
    }
    #[test] fn allocate_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Tallocate, tag: 40,
            msg: Msg::Allocate { fid: 77, mode: 0x03, offset: 4096, length: 8192 } };
        let got = round_trip(&fc);
        match got.msg { Msg::Allocate { fid, mode, offset, length } => { assert_eq!(fid, 77); assert_eq!(mode, 0x03); assert_eq!(offset, 4096); assert_eq!(length, 8192); } _ => panic!() }
    }
    #[test] fn authneg_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Tauthneg, tag: 2,
            msg: Msg::Authneg { mechs: vec![AUTH_SCRAM_SHA256.into(), AUTH_MTLS.into(), AUTH_P9ANY.into()] } };
        let got = round_trip(&fc);
        match got.msg { Msg::Authneg { ref mechs } => { assert_eq!(mechs.len(), 3); assert_eq!(mechs[0], AUTH_SCRAM_SHA256); } _ => panic!() }
    }

    // ====== SPIFFE ======
    #[test] fn spiffe_capability() {
        let mut c = CapSet::new(); c.add(CAP_SPIFFE); c.add(CAP_TLS); c.add(CAP_AUTH);
        let mut s = CapSet::new(); s.add(CAP_SPIFFE); s.add(CAP_TLS);
        let r = intersect(&c, &s);
        assert!(r.has(CAP_SPIFFE)); assert!(r.has_bit(CapBit::Spiffe));
        assert!(!r.has(CAP_AUTH));
    }
    #[test] fn startls_spiffe_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::TstartlsSpiffe, tag: 3,
            msg: Msg::StartlsSpiffe { spiffe_id: "spiffe://example.com/server/web".into(), trust_domain: "example.com".into() } };
        let got = round_trip(&fc);
        match got.msg { Msg::StartlsSpiffe { ref spiffe_id, ref trust_domain } => { assert_eq!(spiffe_id, "spiffe://example.com/server/web"); assert_eq!(trust_domain, "example.com"); } _ => panic!() }
    }
    #[test] fn fetchbundle_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Tfetchbundle, tag: 10,
            msg: Msg::Fetchbundle { trust_domain: "prod.example.com".into(), format: BUNDLE_X509_CAS } };
        let got = round_trip(&fc);
        match got.msg { Msg::Fetchbundle { ref trust_domain, format } => { assert_eq!(trust_domain, "prod.example.com"); assert_eq!(format, BUNDLE_X509_CAS); } _ => panic!() }
    }
    #[test] fn rfetchbundle_roundtrip() {
        let pem = b"-----BEGIN CERTIFICATE-----\nMIIBxTCCA...\n-----END CERTIFICATE-----\n";
        let fc = Fcall { size: 0, msg_type: MsgType::Rfetchbundle, tag: 10,
            msg: Msg::Rfetchbundle { trust_domain: "prod.example.com".into(), format: BUNDLE_X509_CAS, bundle: pem.to_vec() } };
        let got = round_trip(&fc);
        match got.msg { Msg::Rfetchbundle { ref bundle, .. } => assert_eq!(bundle, pem), _ => panic!() }
    }
    #[test] fn spiffeverify_roundtrip() {
        let jwt = b"eyJhbGciOiJSUzI1NiJ9.payload.sig";
        let fc = Fcall { size: 0, msg_type: MsgType::Tspiffeverify, tag: 20,
            msg: Msg::Spiffeverify { svid_type: SVID_JWT, spiffe_id: "spiffe://example.com/wl".into(), svid: jwt.to_vec() } };
        let got = round_trip(&fc);
        match got.msg { Msg::Spiffeverify { svid_type, ref spiffe_id, .. } => { assert_eq!(svid_type, SVID_JWT); assert_eq!(spiffe_id, "spiffe://example.com/wl"); } _ => panic!() }
    }
    #[test] fn rspiffeverify_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Rspiffeverify, tag: 20,
            msg: Msg::Rspiffeverify { status: SPIFFE_OK, spiffe_id: "spiffe://example.com/wl".into(), expiry: 1743400000000000000 } };
        let got = round_trip(&fc);
        match got.msg { Msg::Rspiffeverify { status, expiry, .. } => { assert_eq!(status, SPIFFE_OK); assert_eq!(expiry, 1743400000000000000); } _ => panic!() }
    }
    #[test] fn spiffe_authneg() {
        let fc = Fcall { size: 0, msg_type: MsgType::Tauthneg, tag: 5,
            msg: Msg::Authneg { mechs: vec![AUTH_SPIFFE_X509.into(), AUTH_SPIFFE_JWT.into(), AUTH_MTLS.into()] } };
        let got = round_trip(&fc);
        match got.msg { Msg::Authneg { ref mechs } => { assert_eq!(mechs[0], "SPIFFE-X.509"); assert_eq!(mechs[1], "SPIFFE-JWT"); } _ => panic!() }
    }
    #[test] fn spiffe_msg_names() {
        assert_eq!(MsgType::TstartlsSpiffe.name(), "Tstartls_spiffe");
        assert_eq!(MsgType::Tfetchbundle.name(), "Tfetchbundle");
        assert_eq!(MsgType::Rspiffeverify.name(), "Rspiffeverify");
    }

    // ====== Transport ======
    #[test] fn rdmatoken_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Trdmatoken, tag: 1,
            msg: Msg::Rdmatoken { fid: 5, direction: 0, rkey: 0x1234, addr: 0x7F0000000000, length: 4096 } };
        let got = round_trip(&fc);
        match got.msg { Msg::Rdmatoken { fid, rkey, addr, length, .. } => { assert_eq!(fid, 5); assert_eq!(rkey, 0x1234); assert_eq!(addr, 0x7F0000000000); assert_eq!(length, 4096); } _ => panic!() }
    }
    #[test] fn rdmanotify_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Trdmanotify, tag: 2,
            msg: Msg::Rdmanotify { rkey: 0x5678, addr: 0xFF0000000000, length: 65536, slots: 128 } };
        let got = round_trip(&fc);
        match got.msg { Msg::Rdmanotify { rkey, slots, .. } => { assert_eq!(rkey, 0x5678); assert_eq!(slots, 128); } _ => panic!() }
    }
    #[test] fn quicstream_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Tquicstream, tag: 3,
            msg: Msg::Quicstream { stream_type: QSTREAM_PUSH, stream_id: 0xF001 } };
        let got = round_trip(&fc);
        match got.msg { Msg::Quicstream { stream_type, stream_id } => { assert_eq!(stream_type, QSTREAM_PUSH); assert_eq!(stream_id, 0xF001); } _ => panic!() }
    }
    #[test] fn transport_capability() {
        let mut c = CapSet::new(); c.add(CAP_QUIC); c.add(CAP_QUIC_MULTI); c.add(CAP_RDMA);
        let mut s = CapSet::new(); s.add(CAP_QUIC); s.add(CAP_RDMA);
        let r = intersect(&c, &s);
        assert!(r.has(CAP_QUIC)); assert!(r.has(CAP_RDMA)); assert!(!r.has(CAP_QUIC_MULTI));
    }
    #[test] fn transport_msg_names() {
        assert_eq!(MsgType::Trdmatoken.name(), "Trdmatoken");
        assert_eq!(MsgType::Tquicstream.name(), "Tquicstream");
    }
    #[test] fn cxlmap_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Tcxlmap, tag: 1,
            msg: Msg::Cxlmap { fid: 8, offset: 0, length: 0x100000, prot: 3, flags: CXL_MAP_SHARED | CXL_MAP_DAX } };
        let got = round_trip(&fc);
        match got.msg { Msg::Cxlmap { fid, length, flags, .. } => { assert_eq!(fid, 8); assert_eq!(length, 0x100000); assert_eq!(flags, 5); } _ => panic!() }
    }
    #[test] fn rcxlmap_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Rcxlmap, tag: 1,
            msg: Msg::Rcxlmap { hpa: 0x800000000000, length: 0x100000, granularity: 4096, coherence: CXL_COHERENCE_HARDWARE } };
        let got = round_trip(&fc);
        match got.msg { Msg::Rcxlmap { hpa, granularity, coherence, .. } => { assert_eq!(hpa, 0x800000000000); assert_eq!(granularity, 4096); assert_eq!(coherence, CXL_COHERENCE_HARDWARE); } _ => panic!() }
    }
    #[test] fn cxlcoherence_roundtrip() {
        let fc = Fcall { size: 0, msg_type: MsgType::Tcxlcoherence, tag: 2,
            msg: Msg::Cxlcoherence { fid: 8, mode: CXL_COHERENCE_HYBRID } };
        let got = round_trip(&fc);
        match got.msg { Msg::Cxlcoherence { fid, mode } => { assert_eq!(fid, 8); assert_eq!(mode, CXL_COHERENCE_HYBRID); } _ => panic!() }
    }
    #[test] fn cxl_capability() {
        let mut c = CapSet::new(); c.add(CAP_CXL); c.add(CAP_RDMA);
        let mut s = CapSet::new(); s.add(CAP_CXL);
        let r = intersect(&c, &s);
        assert!(r.has(CAP_CXL)); assert!(!r.has(CAP_RDMA));
    }

    // ====== Wire format ======
    #[test] fn msg_names() {
        assert_eq!(MsgType::Tcaps.name(), "Tcaps");
        assert_eq!(MsgType::Rnotify.name(), "Rnotify");
    }
    #[test] fn wire_header_size() {
        let fc = Fcall { size: 0, msg_type: MsgType::Tstartls, tag: 0, msg: Msg::Empty };
        let mut buf = Buf::new(16); marshal(&mut buf, &fc).unwrap();
        assert_eq!(buf.len(), HEADER_SIZE);
    }
}
