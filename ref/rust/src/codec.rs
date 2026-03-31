//! Marshal/unmarshal for all 46 9P2000.N message type pairs.

use crate::buf::Buf;
use crate::types::*;
use std::io;

fn msg_begin(buf: &mut Buf, t: MsgType, tag: u16) -> usize {
    let off = buf.len();
    buf.put_u32(0); // placeholder
    buf.put_u8(t as u8);
    buf.put_u16(tag);
    off
}

fn msg_finish(buf: &mut Buf, off: usize) {
    let size = (buf.len() - off) as u32;
    buf.patch_u32(off, size);
}

/// Encode an Fcall to wire format.
pub fn marshal(buf: &mut Buf, fc: &Fcall) -> io::Result<()> {
    let off = msg_begin(buf, fc.msg_type, fc.tag);

    match &fc.msg {
        Msg::Empty => {}
        Msg::Caps { caps } => { buf.put_u16(caps.len() as u16); for c in caps { buf.put_str(c); } }
        Msg::Authneg { mechs } => { buf.put_u16(mechs.len() as u16); for m in mechs { buf.put_str(m); } }
        Msg::Rauthneg { mech, challenge } => { buf.put_str(mech); buf.put_data(challenge); }
        Msg::Capgrant { fid, rights, expiry, depth } => { buf.put_u32(*fid); buf.put_u64(*rights); buf.put_u64(*expiry); buf.put_u16(*depth); }
        Msg::Rcapgrant { token } => { buf.put_str(token); }
        Msg::Capuse { fid, token } => { buf.put_u32(*fid); buf.put_str(token); }
        Msg::Rcapuse { qid } => { buf.put_qid(qid); }
        Msg::Auditctl { fid, flags } => { buf.put_u32(*fid); buf.put_u32(*flags); }
        Msg::StartlsSpiffe { spiffe_id, trust_domain } => { buf.put_str(spiffe_id); buf.put_str(trust_domain); }
        Msg::Fetchbundle { trust_domain, format } => { buf.put_str(trust_domain); buf.put_u8(*format); }
        Msg::Rfetchbundle { trust_domain, format, bundle } => { buf.put_str(trust_domain); buf.put_u8(*format); buf.put_data(bundle); }
        Msg::Spiffeverify { svid_type, spiffe_id, svid } => { buf.put_u8(*svid_type); buf.put_str(spiffe_id); buf.put_data(svid); }
        Msg::Rspiffeverify { status, spiffe_id, expiry } => { buf.put_u8(*status); buf.put_str(spiffe_id); buf.put_u64(*expiry); }
        Msg::Rdmatoken { fid, direction, rkey, addr, length } => { buf.put_u32(*fid); buf.put_u8(*direction); buf.put_u32(*rkey); buf.put_u64(*addr); buf.put_u32(*length); }
        Msg::Rrdmatoken { rkey, addr, length } => { buf.put_u32(*rkey); buf.put_u64(*addr); buf.put_u32(*length); }
        Msg::Rdmanotify { rkey, addr, length, slots } => { buf.put_u32(*rkey); buf.put_u64(*addr); buf.put_u32(*length); buf.put_u16(*slots); }
        Msg::Quicstream { stream_type, stream_id } => { buf.put_u8(*stream_type); buf.put_u64(*stream_id); }
        Msg::Rquicstream { stream_id } => { buf.put_u64(*stream_id); }
        Msg::Cxlmap { fid, offset, length, prot, flags } => { buf.put_u32(*fid); buf.put_u64(*offset); buf.put_u64(*length); buf.put_u32(*prot); buf.put_u32(*flags); }
        Msg::Rcxlmap { hpa, length, granularity, coherence } => { buf.put_u64(*hpa); buf.put_u64(*length); buf.put_u32(*granularity); buf.put_u8(*coherence); }
        Msg::Cxlcoherence { fid, mode } => { buf.put_u32(*fid); buf.put_u8(*mode); }
        Msg::Rcxlcoherence { mode, snoop_id } => { buf.put_u8(*mode); buf.put_u32(*snoop_id); }
        Msg::Compound { ops } => { marshal_subops(buf, ops); }
        Msg::Rcompound { results } => { marshal_subops(buf, results); }
        Msg::Compress { algo, level } => { buf.put_u8(*algo); buf.put_u8(*level); }
        Msg::Rcompress { algo } => { buf.put_u8(*algo); }
        Msg::Copyrange { src_fid, src_off, dst_fid, dst_off, count, flags } => {
            buf.put_u32(*src_fid); buf.put_u64(*src_off); buf.put_u32(*dst_fid);
            buf.put_u64(*dst_off); buf.put_u64(*count); buf.put_u32(*flags);
        }
        Msg::Rcopyrange { count } => { buf.put_u64(*count); }
        Msg::Allocate { fid, mode, offset, length } => { buf.put_u32(*fid); buf.put_u32(*mode); buf.put_u64(*offset); buf.put_u64(*length); }
        Msg::Seekhole { fid, seek_type, offset } => { buf.put_u32(*fid); buf.put_u8(*seek_type); buf.put_u64(*offset); }
        Msg::Rseekhole { offset } => { buf.put_u64(*offset); }
        Msg::Mmaphint { fid, offset, length, prot } => { buf.put_u32(*fid); buf.put_u64(*offset); buf.put_u64(*length); buf.put_u32(*prot); }
        Msg::Rmmaphint { granted } => { buf.put_u8(*granted); }
        Msg::Watch { fid, mask, flags } => { buf.put_u32(*fid); buf.put_u32(*mask); buf.put_u32(*flags); }
        Msg::Rwatch { watch_id } => { buf.put_u32(*watch_id); }
        Msg::Unwatch { watch_id } => { buf.put_u32(*watch_id); }
        Msg::Notify { watch_id, event, name, qid } => { buf.put_u32(*watch_id); buf.put_u32(*event); buf.put_str(name); buf.put_qid(qid); }
        Msg::Getacl { fid, acl_type } => { buf.put_u32(*fid); buf.put_u8(*acl_type); }
        Msg::Rgetacl { data } => { buf.put_data(data); }
        Msg::Setacl { fid, acl_type, data } => { buf.put_u32(*fid); buf.put_u8(*acl_type); buf.put_data(data); }
        Msg::Snapshot { fid, name, flags } => { buf.put_u32(*fid); buf.put_str(name); buf.put_u32(*flags); }
        Msg::Rsnapshot { qid } => { buf.put_qid(qid); }
        Msg::Clone { src_fid, dst_fid, name, flags } => { buf.put_u32(*src_fid); buf.put_u32(*dst_fid); buf.put_str(name); buf.put_u32(*flags); }
        Msg::Rclone { qid } => { buf.put_qid(qid); }
        Msg::Xattrget { fid, name } => { buf.put_u32(*fid); buf.put_str(name); }
        Msg::Rxattrget { data } => { buf.put_data(data); }
        Msg::Xattrset { fid, name, data, flags } => { buf.put_u32(*fid); buf.put_str(name); buf.put_data(data); buf.put_u32(*flags); }
        Msg::Xattrlist { fid, cookie, count } => { buf.put_u32(*fid); buf.put_u64(*cookie); buf.put_u32(*count); }
        Msg::Rxattrlist { cookie, names } => { buf.put_u64(*cookie); buf.put_u16(names.len() as u16); for n in names { buf.put_str(n); } }
        Msg::Lease { fid, lease_type, duration } => { buf.put_u32(*fid); buf.put_u8(*lease_type); buf.put_u32(*duration); }
        Msg::Rlease { lease_id, lease_type, duration } => { buf.put_u64(*lease_id); buf.put_u8(*lease_type); buf.put_u32(*duration); }
        Msg::Leaserenew { lease_id, duration } => { buf.put_u64(*lease_id); buf.put_u32(*duration); }
        Msg::Rleaserenew { duration } => { buf.put_u32(*duration); }
        Msg::Leasebreak { lease_id, new_type } => { buf.put_u64(*lease_id); buf.put_u8(*new_type); }
        Msg::Leaseack { lease_id } => { buf.put_u64(*lease_id); }
        Msg::Session { key, flags } => { buf.put_bytes(key); buf.put_u32(*flags); }
        Msg::Rsession { flags } => { buf.put_u32(*flags); }
        Msg::Consistency { fid, level } => { buf.put_u32(*fid); buf.put_u8(*level); }
        Msg::Rconsistency { level } => { buf.put_u8(*level); }
        Msg::Topology { fid } => { buf.put_u32(*fid); }
        Msg::Rtopology { replicas } => { buf.put_u16(replicas.len() as u16); for r in replicas { buf.put_str(&r.addr); buf.put_u8(r.role); buf.put_u32(r.latency_us); } }
        Msg::Traceattr { attrs } => { buf.put_u16(attrs.len() as u16); for (k, v) in attrs { buf.put_str(k); buf.put_str(v); } }
        Msg::Rhealth { status, load, metrics } => { buf.put_u8(*status); buf.put_u32(*load); buf.put_u16(metrics.len() as u16); for m in metrics { buf.put_str(&m.name); buf.put_u64(m.value); } }
        Msg::ServerstatsReq { mask } => { buf.put_u64(*mask); }
        Msg::Rserverstats { stats } => { buf.put_u16(stats.len() as u16); for s in stats { buf.put_str(&s.name); buf.put_u8(s.stat_type); buf.put_u64(s.value); } }
        Msg::Getquota { fid, quota_type } => { buf.put_u32(*fid); buf.put_u8(*quota_type); }
        Msg::Rgetquota { bytes_used, bytes_limit, files_used, files_limit, grace } => { buf.put_u64(*bytes_used); buf.put_u64(*bytes_limit); buf.put_u64(*files_used); buf.put_u64(*files_limit); buf.put_u32(*grace); }
        Msg::Setquota { fid, quota_type, bytes_limit, files_limit, grace } => { buf.put_u32(*fid); buf.put_u8(*quota_type); buf.put_u64(*bytes_limit); buf.put_u64(*files_limit); buf.put_u32(*grace); }
        Msg::Ratelimit { fid, iops, bps } => { buf.put_u32(*fid); buf.put_u32(*iops); buf.put_u64(*bps); }
        Msg::Rratelimit { iops, bps } => { buf.put_u32(*iops); buf.put_u64(*bps); }
        Msg::Async { inner_type, payload } => { buf.put_u8(*inner_type as u8); buf.put_bytes(payload); }
        Msg::Rasync { op_id, status } => { buf.put_u64(*op_id); buf.put_u8(*status); }
        Msg::Poll { op_id } => { buf.put_u64(*op_id); }
        Msg::Rpoll { status, progress, payload } => { buf.put_u8(*status); buf.put_u32(*progress); buf.put_bytes(payload); }
        Msg::Streamopen { fid, direction, offset, count } => { buf.put_u32(*fid); buf.put_u8(*direction); buf.put_u64(*offset); buf.put_u64(*count); }
        Msg::Rstreamopen { stream_id } => { buf.put_u32(*stream_id); }
        Msg::Streamdata { stream_id, seq, data } => { buf.put_u32(*stream_id); buf.put_u32(*seq); buf.put_data(data); }
        Msg::Streamclose { stream_id } => { buf.put_u32(*stream_id); }
        Msg::Search { fid, query, flags, max_results, cookie } => { buf.put_u32(*fid); buf.put_str(query); buf.put_u32(*flags); buf.put_u32(*max_results); buf.put_u64(*cookie); }
        Msg::Rsearch { cookie, entries } => { buf.put_u64(*cookie); buf.put_u16(entries.len() as u16); for e in entries { buf.put_qid(&e.qid); buf.put_str(&e.name); buf.put_u32(e.score); } }
        Msg::Hash { fid, algo, offset, length } => { buf.put_u32(*fid); buf.put_u8(*algo); buf.put_u64(*offset); buf.put_u64(*length); }
        Msg::Rhash { algo, hash } => { buf.put_u8(*algo); buf.put_u16(hash.len() as u16); buf.put_bytes(hash); }
    }

    msg_finish(buf, off);
    Ok(())
}

fn marshal_subops(buf: &mut Buf, ops: &[SubOp]) {
    buf.put_u16(ops.len() as u16);
    for op in ops {
        let opsize = (SUBOP_HDR_SZ + op.payload.len()) as u32;
        buf.put_u32(opsize);
        buf.put_u8(op.msg_type as u8);
        buf.put_bytes(&op.payload);
    }
}

/// Decode a single Fcall from buf.
pub fn unmarshal(buf: &mut Buf) -> io::Result<Fcall> {
    let size = buf.get_u32()?;
    let t = buf.get_u8()?;
    let tag = buf.get_u16()?;
    let msg_type = MsgType::from_u8(t)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("unknown type: {t}")))?;

    let msg = match msg_type {
        // Empty payload types
        MsgType::Tstartls | MsgType::Rstartls | MsgType::Rauditctl |
        MsgType::Runwatch | MsgType::Rsetacl | MsgType::Rxattrset |
        MsgType::Rallocate | MsgType::Rleaseack | MsgType::Rrdmanotify | MsgType::Rtraceattr |
        MsgType::Thealth | MsgType::Rsetquota | MsgType::Rstreamclose => Msg::Empty,

        MsgType::Tcaps | MsgType::Rcaps => {
            let n = buf.get_u16()?;
            let mut caps = Vec::with_capacity(n as usize);
            for _ in 0..n { caps.push(buf.get_str()?); }
            Msg::Caps { caps }
        }
        MsgType::Tauthneg => {
            let n = buf.get_u16()?;
            let mut mechs = Vec::with_capacity(n as usize);
            for _ in 0..n { mechs.push(buf.get_str()?); }
            Msg::Authneg { mechs }
        }
        MsgType::Rauthneg => Msg::Rauthneg { mech: buf.get_str()?, challenge: buf.get_data()? },
        MsgType::Tcapgrant => Msg::Capgrant { fid: buf.get_u32()?, rights: buf.get_u64()?, expiry: buf.get_u64()?, depth: buf.get_u16()? },
        MsgType::Rcapgrant => Msg::Rcapgrant { token: buf.get_str()? },
        MsgType::Tcapuse => Msg::Capuse { fid: buf.get_u32()?, token: buf.get_str()? },
        MsgType::Rcapuse => Msg::Rcapuse { qid: buf.get_qid()? },
        MsgType::Tauditctl => Msg::Auditctl { fid: buf.get_u32()?, flags: buf.get_u32()? },

        MsgType::TstartlsSpiffe | MsgType::RstartlsSpiffe =>
            Msg::StartlsSpiffe { spiffe_id: buf.get_str()?, trust_domain: buf.get_str()? },
        MsgType::Tfetchbundle => Msg::Fetchbundle { trust_domain: buf.get_str()?, format: buf.get_u8()? },
        MsgType::Rfetchbundle => Msg::Rfetchbundle { trust_domain: buf.get_str()?, format: buf.get_u8()?, bundle: buf.get_data()? },
        MsgType::Tspiffeverify => Msg::Spiffeverify { svid_type: buf.get_u8()?, spiffe_id: buf.get_str()?, svid: buf.get_data()? },
        MsgType::Rspiffeverify => Msg::Rspiffeverify { status: buf.get_u8()?, spiffe_id: buf.get_str()?, expiry: buf.get_u64()? },

        MsgType::Tcxlmap => Msg::Cxlmap { fid: buf.get_u32()?, offset: buf.get_u64()?, length: buf.get_u64()?, prot: buf.get_u32()?, flags: buf.get_u32()? },
        MsgType::Rcxlmap => Msg::Rcxlmap { hpa: buf.get_u64()?, length: buf.get_u64()?, granularity: buf.get_u32()?, coherence: buf.get_u8()? },
        MsgType::Tcxlcoherence => Msg::Cxlcoherence { fid: buf.get_u32()?, mode: buf.get_u8()? },
        MsgType::Rcxlcoherence => Msg::Rcxlcoherence { mode: buf.get_u8()?, snoop_id: buf.get_u32()? },

        MsgType::Trdmatoken => Msg::Rdmatoken { fid: buf.get_u32()?, direction: buf.get_u8()?, rkey: buf.get_u32()?, addr: buf.get_u64()?, length: buf.get_u32()? },
        MsgType::Rrdmatoken => Msg::Rrdmatoken { rkey: buf.get_u32()?, addr: buf.get_u64()?, length: buf.get_u32()? },
        MsgType::Trdmanotify => Msg::Rdmanotify { rkey: buf.get_u32()?, addr: buf.get_u64()?, length: buf.get_u32()?, slots: buf.get_u16()? },
        MsgType::Tquicstream => Msg::Quicstream { stream_type: buf.get_u8()?, stream_id: buf.get_u64()? },
        MsgType::Rquicstream => Msg::Rquicstream { stream_id: buf.get_u64()? },

        MsgType::Tcompound => Msg::Compound { ops: unmarshal_subops(buf)? },
        MsgType::Rcompound => Msg::Rcompound { results: unmarshal_subops(buf)? },
        MsgType::Tcompress => Msg::Compress { algo: buf.get_u8()?, level: buf.get_u8()? },
        MsgType::Rcompress => Msg::Rcompress { algo: buf.get_u8()? },
        MsgType::Tcopyrange => Msg::Copyrange { src_fid: buf.get_u32()?, src_off: buf.get_u64()?, dst_fid: buf.get_u32()?, dst_off: buf.get_u64()?, count: buf.get_u64()?, flags: buf.get_u32()? },
        MsgType::Rcopyrange => Msg::Rcopyrange { count: buf.get_u64()? },
        MsgType::Tallocate => Msg::Allocate { fid: buf.get_u32()?, mode: buf.get_u32()?, offset: buf.get_u64()?, length: buf.get_u64()? },
        MsgType::Tseekhole => Msg::Seekhole { fid: buf.get_u32()?, seek_type: buf.get_u8()?, offset: buf.get_u64()? },
        MsgType::Rseekhole => Msg::Rseekhole { offset: buf.get_u64()? },
        MsgType::Tmmaphint => Msg::Mmaphint { fid: buf.get_u32()?, offset: buf.get_u64()?, length: buf.get_u64()?, prot: buf.get_u32()? },
        MsgType::Rmmaphint => Msg::Rmmaphint { granted: buf.get_u8()? },

        MsgType::Twatch => Msg::Watch { fid: buf.get_u32()?, mask: buf.get_u32()?, flags: buf.get_u32()? },
        MsgType::Rwatch => Msg::Rwatch { watch_id: buf.get_u32()? },
        MsgType::Tunwatch => Msg::Unwatch { watch_id: buf.get_u32()? },
        MsgType::Rnotify => Msg::Notify { watch_id: buf.get_u32()?, event: buf.get_u32()?, name: buf.get_str()?, qid: buf.get_qid()? },
        MsgType::Tgetacl => Msg::Getacl { fid: buf.get_u32()?, acl_type: buf.get_u8()? },
        MsgType::Rgetacl => Msg::Rgetacl { data: buf.get_data()? },
        MsgType::Tsetacl => Msg::Setacl { fid: buf.get_u32()?, acl_type: buf.get_u8()?, data: buf.get_data()? },
        MsgType::Tsnapshot => Msg::Snapshot { fid: buf.get_u32()?, name: buf.get_str()?, flags: buf.get_u32()? },
        MsgType::Rsnapshot => Msg::Rsnapshot { qid: buf.get_qid()? },
        MsgType::Tclone => Msg::Clone { src_fid: buf.get_u32()?, dst_fid: buf.get_u32()?, name: buf.get_str()?, flags: buf.get_u32()? },
        MsgType::Rclone => Msg::Rclone { qid: buf.get_qid()? },
        MsgType::Txattrget => Msg::Xattrget { fid: buf.get_u32()?, name: buf.get_str()? },
        MsgType::Rxattrget => Msg::Rxattrget { data: buf.get_data()? },
        MsgType::Txattrset => Msg::Xattrset { fid: buf.get_u32()?, name: buf.get_str()?, data: buf.get_data()?, flags: buf.get_u32()? },
        MsgType::Txattrlist => Msg::Xattrlist { fid: buf.get_u32()?, cookie: buf.get_u64()?, count: buf.get_u32()? },
        MsgType::Rxattrlist => {
            let cookie = buf.get_u64()?;
            let n = buf.get_u16()?;
            let mut names = Vec::with_capacity(n as usize);
            for _ in 0..n { names.push(buf.get_str()?); }
            Msg::Rxattrlist { cookie, names }
        }

        MsgType::Tlease => Msg::Lease { fid: buf.get_u32()?, lease_type: buf.get_u8()?, duration: buf.get_u32()? },
        MsgType::Rlease => Msg::Rlease { lease_id: buf.get_u64()?, lease_type: buf.get_u8()?, duration: buf.get_u32()? },
        MsgType::Tleaserenew => Msg::Leaserenew { lease_id: buf.get_u64()?, duration: buf.get_u32()? },
        MsgType::Rleaserenew => Msg::Rleaserenew { duration: buf.get_u32()? },
        MsgType::Rleasebreak => Msg::Leasebreak { lease_id: buf.get_u64()?, new_type: buf.get_u8()? },
        MsgType::Tleaseack => Msg::Leaseack { lease_id: buf.get_u64()? },
        MsgType::Tsession => { let key: [u8; 16] = buf.get_fixed(16)?.try_into().unwrap(); Msg::Session { key, flags: buf.get_u32()? } }
        MsgType::Rsession => Msg::Rsession { flags: buf.get_u32()? },
        MsgType::Tconsistency => Msg::Consistency { fid: buf.get_u32()?, level: buf.get_u8()? },
        MsgType::Rconsistency => Msg::Rconsistency { level: buf.get_u8()? },
        MsgType::Ttopology => Msg::Topology { fid: buf.get_u32()? },
        MsgType::Rtopology => {
            let n = buf.get_u16()?;
            let mut reps = Vec::with_capacity(n as usize);
            for _ in 0..n { reps.push(Replica { addr: buf.get_str()?, role: buf.get_u8()?, latency_us: buf.get_u32()? }); }
            Msg::Rtopology { replicas: reps }
        }

        MsgType::Ttraceattr => {
            let n = buf.get_u16()?;
            let mut attrs = Vec::with_capacity(n as usize);
            for _ in 0..n { attrs.push((buf.get_str()?, buf.get_str()?)); }
            Msg::Traceattr { attrs }
        }
        MsgType::Rhealth => {
            let status = buf.get_u8()?; let load = buf.get_u32()?; let n = buf.get_u16()?;
            let mut metrics = Vec::with_capacity(n as usize);
            for _ in 0..n { metrics.push(Metric { name: buf.get_str()?, value: buf.get_u64()? }); }
            Msg::Rhealth { status, load, metrics }
        }
        MsgType::Tserverstats => Msg::ServerstatsReq { mask: buf.get_u64()? },
        MsgType::Rserverstats => {
            let n = buf.get_u16()?;
            let mut stats = Vec::with_capacity(n as usize);
            for _ in 0..n { stats.push(ServerStat { name: buf.get_str()?, stat_type: buf.get_u8()?, value: buf.get_u64()? }); }
            Msg::Rserverstats { stats }
        }

        MsgType::Tgetquota => Msg::Getquota { fid: buf.get_u32()?, quota_type: buf.get_u8()? },
        MsgType::Rgetquota => Msg::Rgetquota { bytes_used: buf.get_u64()?, bytes_limit: buf.get_u64()?, files_used: buf.get_u64()?, files_limit: buf.get_u64()?, grace: buf.get_u32()? },
        MsgType::Tsetquota => Msg::Setquota { fid: buf.get_u32()?, quota_type: buf.get_u8()?, bytes_limit: buf.get_u64()?, files_limit: buf.get_u64()?, grace: buf.get_u32()? },
        MsgType::Tratelimit => Msg::Ratelimit { fid: buf.get_u32()?, iops: buf.get_u32()?, bps: buf.get_u64()? },
        MsgType::Rratelimit => Msg::Rratelimit { iops: buf.get_u32()?, bps: buf.get_u64()? },

        MsgType::Tasync => { let it = buf.get_u8()?; let rem = size as usize - HEADER_SIZE - 1; let p = if rem > 0 { buf.get_fixed(rem)? } else { vec![] }; Msg::Async { inner_type: MsgType::from_u8(it).unwrap_or(MsgType::Tcaps), payload: p } }
        MsgType::Rasync => Msg::Rasync { op_id: buf.get_u64()?, status: buf.get_u8()? },
        MsgType::Tpoll => Msg::Poll { op_id: buf.get_u64()? },
        MsgType::Rpoll => { let s = buf.get_u8()?; let p = buf.get_u32()?; let rem = size as usize - HEADER_SIZE - 5; let pl = if rem > 0 { buf.get_fixed(rem)? } else { vec![] }; Msg::Rpoll { status: s, progress: p, payload: pl } }
        MsgType::Tstreamopen => Msg::Streamopen { fid: buf.get_u32()?, direction: buf.get_u8()?, offset: buf.get_u64()?, count: buf.get_u64()? },
        MsgType::Rstreamopen => Msg::Rstreamopen { stream_id: buf.get_u32()? },
        MsgType::Tstreamdata | MsgType::Rstreamdata => Msg::Streamdata { stream_id: buf.get_u32()?, seq: buf.get_u32()?, data: buf.get_data()? },
        MsgType::Tstreamclose => Msg::Streamclose { stream_id: buf.get_u32()? },

        MsgType::Tsearch => Msg::Search { fid: buf.get_u32()?, query: buf.get_str()?, flags: buf.get_u32()?, max_results: buf.get_u32()?, cookie: buf.get_u64()? },
        MsgType::Rsearch => {
            let cookie = buf.get_u64()?; let n = buf.get_u16()?;
            let mut entries = Vec::with_capacity(n as usize);
            for _ in 0..n { entries.push(SearchEntry { qid: buf.get_qid()?, name: buf.get_str()?, score: buf.get_u32()? }); }
            Msg::Rsearch { cookie, entries }
        }
        MsgType::Thash => Msg::Hash { fid: buf.get_u32()?, algo: buf.get_u8()?, offset: buf.get_u64()?, length: buf.get_u64()? },
        MsgType::Rhash => { let algo = buf.get_u8()?; let hl = buf.get_u16()?; Msg::Rhash { algo, hash: buf.get_fixed(hl as usize)? } }

        MsgType::Tnotify | MsgType::Tleasebreak => Msg::Empty, // reserved, never sent
    };

    Ok(Fcall { size, msg_type, tag, msg })
}

fn unmarshal_subops(buf: &mut Buf) -> io::Result<Vec<SubOp>> {
    let n = buf.get_u16()?;
    let mut ops = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let opsize = buf.get_u32()? as usize;
        let t = buf.get_u8()?;
        let plen = opsize - SUBOP_HDR_SZ;
        let payload = if plen > 0 { buf.get_fixed(plen)? } else { vec![] };
        ops.push(SubOp {
            msg_type: MsgType::from_u8(t).unwrap_or(MsgType::Tcaps),
            payload,
        });
    }
    Ok(ops)
}
