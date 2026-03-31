//! 9P2000.N protocol constants and message types.

// Protocol versions
pub const VERSION: &str = "9P2000.N";
pub const VERSION_L: &str = "9P2000.L";

// Magic numbers
pub const NO_TAG: u16 = 0xFFFF;
pub const NO_FID: u32 = 0xFFFFFFFF;
pub const PREV_FID: u32 = 0xFFFFFFFE;

// Sizes
pub const HEADER_SIZE: usize = 7;
pub const SUBOP_HDR_SZ: usize = 5;

/// Message type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MsgType {
    // Negotiation
    Tcaps = 128, Rcaps = 129,
    // Security
    Tstartls = 130, Rstartls = 131,
    Tauthneg = 132, Rauthneg = 133,
    Tcapgrant = 134, Rcapgrant = 135,
    Tcapuse = 136, Rcapuse = 137,
    Tauditctl = 138, Rauditctl = 139,
    // SPIFFE
    TstartlsSpiffe = 140, RstartlsSpiffe = 141,
    Tfetchbundle = 142, Rfetchbundle = 143,
    Tspiffeverify = 144, Rspiffeverify = 145,
    // CXL
    Tcxlmap = 146, Rcxlmap = 147,
    Tcxlcoherence = 148, Rcxlcoherence = 149,
    // Transport
    Trdmatoken = 150, Rrdmatoken = 151,
    Trdmanotify = 152, Rrdmanotify = 153,
    Tquicstream = 154, Rquicstream = 155,
    // Performance
    Tcompound = 156, Rcompound = 157,
    Tcompress = 158, Rcompress = 159,
    Tcopyrange = 160, Rcopyrange = 161,
    Tallocate = 162, Rallocate = 163,
    Tseekhole = 164, Rseekhole = 165,
    Tmmaphint = 166, Rmmaphint = 167,
    // Filesystem
    Twatch = 180, Rwatch = 181,
    Tunwatch = 182, Runwatch = 183,
    Tnotify = 184, Rnotify = 185,
    Tgetacl = 186, Rgetacl = 187,
    Tsetacl = 188, Rsetacl = 189,
    Tsnapshot = 190, Rsnapshot = 191,
    Tclone = 192, Rclone = 193,
    Txattrget = 194, Rxattrget = 195,
    Txattrset = 196, Rxattrset = 197,
    Txattrlist = 198, Rxattrlist = 199,
    // Distributed
    Tlease = 200, Rlease = 201,
    Tleaserenew = 202, Rleaserenew = 203,
    Tleasebreak = 204, Rleasebreak = 205,
    Tleaseack = 206, Rleaseack = 207,
    Tsession = 208, Rsession = 209,
    Tconsistency = 210, Rconsistency = 211,
    Ttopology = 212, Rtopology = 213,
    // Observability
    Ttraceattr = 220, Rtraceattr = 221,
    Thealth = 222, Rhealth = 223,
    Tserverstats = 224, Rserverstats = 225,
    // Resource
    Tgetquota = 230, Rgetquota = 231,
    Tsetquota = 232, Rsetquota = 233,
    Tratelimit = 234, Rratelimit = 235,
    // Streaming
    Tasync = 240, Rasync = 241,
    Tpoll = 242, Rpoll = 243,
    Tstreamopen = 244, Rstreamopen = 245,
    Tstreamdata = 246, Rstreamdata = 247,
    Tstreamclose = 248, Rstreamclose = 249,
    // Content
    Tsearch = 250, Rsearch = 251,
    Thash = 252, Rhash = 253,
}

impl MsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        // Safety: we check all valid values
        match v {
            128..=155 | 156..=167 | 180..=199 | 200..=213 |
            220..=225 | 230..=235 | 240..=253 => {
                // SAFETY: repr(u8) and we've verified the range
                Some(unsafe { std::mem::transmute(v) })
            }
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Tcaps => "Tcaps", Self::Rcaps => "Rcaps",
            Self::Tstartls => "Tstartls", Self::Rstartls => "Rstartls",
            Self::Tauthneg => "Tauthneg", Self::Rauthneg => "Rauthneg",
            Self::Tcapgrant => "Tcapgrant", Self::Rcapgrant => "Rcapgrant",
            Self::Tcapuse => "Tcapuse", Self::Rcapuse => "Rcapuse",
            Self::Tauditctl => "Tauditctl", Self::Rauditctl => "Rauditctl",
            Self::TstartlsSpiffe => "Tstartls_spiffe", Self::RstartlsSpiffe => "Rstartls_spiffe",
            Self::Tfetchbundle => "Tfetchbundle", Self::Rfetchbundle => "Rfetchbundle",
            Self::Tspiffeverify => "Tspiffeverify", Self::Rspiffeverify => "Rspiffeverify",
            Self::Tcxlmap => "Tcxlmap", Self::Rcxlmap => "Rcxlmap",
            Self::Tcxlcoherence => "Tcxlcoherence", Self::Rcxlcoherence => "Rcxlcoherence",
            Self::Trdmatoken => "Trdmatoken", Self::Rrdmatoken => "Rrdmatoken",
            Self::Trdmanotify => "Trdmanotify", Self::Rrdmanotify => "Rrdmanotify",
            Self::Tquicstream => "Tquicstream", Self::Rquicstream => "Rquicstream",
            Self::Tcompound => "Tcompound", Self::Rcompound => "Rcompound",
            Self::Tcompress => "Tcompress", Self::Rcompress => "Rcompress",
            Self::Tcopyrange => "Tcopyrange", Self::Rcopyrange => "Rcopyrange",
            Self::Tallocate => "Tallocate", Self::Rallocate => "Rallocate",
            Self::Tseekhole => "Tseekhole", Self::Rseekhole => "Rseekhole",
            Self::Tmmaphint => "Tmmaphint", Self::Rmmaphint => "Rmmaphint",
            Self::Twatch => "Twatch", Self::Rwatch => "Rwatch",
            Self::Tunwatch => "Tunwatch", Self::Runwatch => "Runwatch",
            Self::Tnotify => "Tnotify", Self::Rnotify => "Rnotify",
            Self::Tgetacl => "Tgetacl", Self::Rgetacl => "Rgetacl",
            Self::Tsetacl => "Tsetacl", Self::Rsetacl => "Rsetacl",
            Self::Tsnapshot => "Tsnapshot", Self::Rsnapshot => "Rsnapshot",
            Self::Tclone => "Tclone", Self::Rclone => "Rclone",
            Self::Txattrget => "Txattrget", Self::Rxattrget => "Rxattrget",
            Self::Txattrset => "Txattrset", Self::Rxattrset => "Rxattrset",
            Self::Txattrlist => "Txattrlist", Self::Rxattrlist => "Rxattrlist",
            Self::Tlease => "Tlease", Self::Rlease => "Rlease",
            Self::Tleaserenew => "Tleaserenew", Self::Rleaserenew => "Rleaserenew",
            Self::Tleasebreak => "Tleasebreak", Self::Rleasebreak => "Rleasebreak",
            Self::Tleaseack => "Tleaseack", Self::Rleaseack => "Rleaseack",
            Self::Tsession => "Tsession", Self::Rsession => "Rsession",
            Self::Tconsistency => "Tconsistency", Self::Rconsistency => "Rconsistency",
            Self::Ttopology => "Ttopology", Self::Rtopology => "Rtopology",
            Self::Ttraceattr => "Ttraceattr", Self::Rtraceattr => "Rtraceattr",
            Self::Thealth => "Thealth", Self::Rhealth => "Rhealth",
            Self::Tserverstats => "Tserverstats", Self::Rserverstats => "Rserverstats",
            Self::Tgetquota => "Tgetquota", Self::Rgetquota => "Rgetquota",
            Self::Tsetquota => "Tsetquota", Self::Rsetquota => "Rsetquota",
            Self::Tratelimit => "Tratelimit", Self::Rratelimit => "Rratelimit",
            Self::Tasync => "Tasync", Self::Rasync => "Rasync",
            Self::Tpoll => "Tpoll", Self::Rpoll => "Rpoll",
            Self::Tstreamopen => "Tstreamopen", Self::Rstreamopen => "Rstreamopen",
            Self::Tstreamdata => "Tstreamdata", Self::Rstreamdata => "Rstreamdata",
            Self::Tstreamclose => "Tstreamclose", Self::Rstreamclose => "Rstreamclose",
            Self::Tsearch => "Tsearch", Self::Rsearch => "Rsearch",
            Self::Thash => "Thash", Self::Rhash => "Rhash",
        }
    }
}

// Capability strings
pub const CAP_TLS: &str = "security.tls";
pub const CAP_AUTH: &str = "security.auth";
pub const CAP_SPIFFE: &str = "security.spiffe";
pub const CAP_COMPOUND: &str = "perf.compound";
pub const CAP_LARGEMSG: &str = "perf.largemsg";
pub const CAP_COMPRESS: &str = "perf.compress";
pub const CAP_COPY: &str = "perf.copy";
pub const CAP_ALLOC: &str = "perf.alloc";
pub const CAP_WATCH: &str = "fs.watch";
pub const CAP_ACL: &str = "fs.acl";
pub const CAP_SNAPSHOT: &str = "fs.snapshot";
pub const CAP_XATTR2: &str = "fs.xattr2";
pub const CAP_LEASE: &str = "dist.lease";
pub const CAP_SESSION: &str = "dist.session";
pub const CAP_CONSISTENCY: &str = "dist.consistency";
pub const CAP_TOPOLOGY: &str = "dist.topology";
pub const CAP_TRACE: &str = "obs.trace";
pub const CAP_HEALTH: &str = "obs.health";
pub const CAP_STATS: &str = "obs.stats";
pub const CAP_QUOTA: &str = "res.quota";
pub const CAP_RATELIMIT: &str = "res.ratelimit";
pub const CAP_ASYNC: &str = "stream.async";
pub const CAP_PIPE: &str = "stream.pipe";
pub const CAP_SEARCH: &str = "content.search";
pub const CAP_HASH: &str = "content.hash";
pub const CAP_QUIC: &str = "transport.quic";
pub const CAP_QUIC_MULTI: &str = "transport.quic.multistream";
pub const CAP_RDMA: &str = "transport.rdma";
pub const CAP_CXL: &str = "transport.cxl";
pub const CXL_COHERENCE_SOFTWARE: u8 = 0;
pub const CXL_COHERENCE_HARDWARE: u8 = 1;
pub const CXL_COHERENCE_HYBRID: u8 = 2;
pub const CXL_COHERENCE_RELAXED: u8 = 3;
pub const CXL_MAP_SHARED: u32 = 0x01;
pub const CXL_MAP_PRIVATE: u32 = 0x02;
pub const CXL_MAP_DAX: u32 = 0x04;

// Watch masks & flags
pub const WATCH_CREATE: u32 = 0x01;
pub const WATCH_REMOVE: u32 = 0x02;
pub const WATCH_MODIFY: u32 = 0x04;
pub const WATCH_ATTRIB: u32 = 0x08;
pub const WATCH_RENAME: u32 = 0x10;
pub const WATCH_RECURSIVE: u32 = 0x01;

// Lease types
pub const LEASE_READ: u8 = 1;
pub const LEASE_WRITE: u8 = 2;

// Session flags
pub const SESSION_FIDS: u32 = 0x01;
pub const SESSION_LEASES: u32 = 0x02;

// Compression
pub const COMPRESS_ZSTD: u8 = 2;

// Hash
pub const HASH_BLAKE3: u8 = 2;

// Copy
pub const COPY_REFLINK: u32 = 0x01;

// SPIFFE
pub const SVID_JWT: u8 = 1;
pub const BUNDLE_X509_CAS: u8 = 0;
pub const SPIFFE_OK: u8 = 0;

// Auth mechanisms
pub const AUTH_SPIFFE_X509: &str = "SPIFFE-X.509";
pub const AUTH_SPIFFE_JWT: &str = "SPIFFE-JWT";
pub const AUTH_SCRAM_SHA256: &str = "SASL-SCRAM-SHA-256";
pub const AUTH_MTLS: &str = "mTLS";
pub const AUTH_P9ANY: &str = "P9any";

// QUIC stream types
pub const QSTREAM_CONTROL: u8 = 0;
pub const QSTREAM_DATA: u8 = 1;
pub const QSTREAM_PUSH: u8 = 2;
pub const QSTREAM_BULK: u8 = 3;

/// QID: 9P file system entity identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qid {
    pub qtype: u8,
    pub version: u32,
    pub path: u64,
}

/// Sub-operation within a Tcompound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubOp {
    pub msg_type: MsgType,
    pub payload: Vec<u8>,
}

/// Replica entry within Rtopology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replica {
    pub addr: String,
    pub role: u8,
    pub latency_us: u32,
}

/// Metric entry within Rhealth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metric {
    pub name: String,
    pub value: u64,
}

/// ServerStat entry within Rserverstats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerStat {
    pub name: String,
    pub stat_type: u8,
    pub value: u64,
}

/// Search result entry within Rsearch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchEntry {
    pub qid: Qid,
    pub name: String,
    pub score: u32,
}

/// All possible 9P2000.N message payloads.
#[derive(Debug, Clone, PartialEq)]
pub enum Msg {
    Empty,
    Caps { caps: Vec<String> },
    Authneg { mechs: Vec<String> },
    Rauthneg { mech: String, challenge: Vec<u8> },
    Capgrant { fid: u32, rights: u64, expiry: u64, depth: u16 },
    Rcapgrant { token: String },
    Capuse { fid: u32, token: String },
    Rcapuse { qid: Qid },
    Auditctl { fid: u32, flags: u32 },
    StartlsSpiffe { spiffe_id: String, trust_domain: String },
    Fetchbundle { trust_domain: String, format: u8 },
    Rfetchbundle { trust_domain: String, format: u8, bundle: Vec<u8> },
    Spiffeverify { svid_type: u8, spiffe_id: String, svid: Vec<u8> },
    Rspiffeverify { status: u8, spiffe_id: String, expiry: u64 },
    Rdmatoken { fid: u32, direction: u8, rkey: u32, addr: u64, length: u32 },
    Rrdmatoken { rkey: u32, addr: u64, length: u32 },
    Rdmanotify { rkey: u32, addr: u64, length: u32, slots: u16 },
    Quicstream { stream_type: u8, stream_id: u64 },
    Rquicstream { stream_id: u64 },
    Cxlmap { fid: u32, offset: u64, length: u64, prot: u32, flags: u32 },
    Rcxlmap { hpa: u64, length: u64, granularity: u32, coherence: u8 },
    Cxlcoherence { fid: u32, mode: u8 },
    Rcxlcoherence { mode: u8, snoop_id: u32 },
    Compound { ops: Vec<SubOp> },
    Rcompound { results: Vec<SubOp> },
    Compress { algo: u8, level: u8 },
    Rcompress { algo: u8 },
    Copyrange { src_fid: u32, src_off: u64, dst_fid: u32, dst_off: u64, count: u64, flags: u32 },
    Rcopyrange { count: u64 },
    Allocate { fid: u32, mode: u32, offset: u64, length: u64 },
    Seekhole { fid: u32, seek_type: u8, offset: u64 },
    Rseekhole { offset: u64 },
    Mmaphint { fid: u32, offset: u64, length: u64, prot: u32 },
    Rmmaphint { granted: u8 },
    Watch { fid: u32, mask: u32, flags: u32 },
    Rwatch { watch_id: u32 },
    Unwatch { watch_id: u32 },
    Notify { watch_id: u32, event: u32, name: String, qid: Qid },
    Getacl { fid: u32, acl_type: u8 },
    Rgetacl { data: Vec<u8> },
    Setacl { fid: u32, acl_type: u8, data: Vec<u8> },
    Snapshot { fid: u32, name: String, flags: u32 },
    Rsnapshot { qid: Qid },
    Clone { src_fid: u32, dst_fid: u32, name: String, flags: u32 },
    Rclone { qid: Qid },
    Xattrget { fid: u32, name: String },
    Rxattrget { data: Vec<u8> },
    Xattrset { fid: u32, name: String, data: Vec<u8>, flags: u32 },
    Xattrlist { fid: u32, cookie: u64, count: u32 },
    Rxattrlist { cookie: u64, names: Vec<String> },
    Lease { fid: u32, lease_type: u8, duration: u32 },
    Rlease { lease_id: u64, lease_type: u8, duration: u32 },
    Leaserenew { lease_id: u64, duration: u32 },
    Rleaserenew { duration: u32 },
    Leasebreak { lease_id: u64, new_type: u8 },
    Leaseack { lease_id: u64 },
    Session { key: [u8; 16], flags: u32 },
    Rsession { flags: u32 },
    Consistency { fid: u32, level: u8 },
    Rconsistency { level: u8 },
    Topology { fid: u32 },
    Rtopology { replicas: Vec<Replica> },
    Traceattr { attrs: Vec<(String, String)> },
    Rhealth { status: u8, load: u32, metrics: Vec<Metric> },
    ServerstatsReq { mask: u64 },
    Rserverstats { stats: Vec<ServerStat> },
    Getquota { fid: u32, quota_type: u8 },
    Rgetquota { bytes_used: u64, bytes_limit: u64, files_used: u64, files_limit: u64, grace: u32 },
    Setquota { fid: u32, quota_type: u8, bytes_limit: u64, files_limit: u64, grace: u32 },
    Ratelimit { fid: u32, iops: u32, bps: u64 },
    Rratelimit { iops: u32, bps: u64 },
    Async { inner_type: MsgType, payload: Vec<u8> },
    Rasync { op_id: u64, status: u8 },
    Poll { op_id: u64 },
    Rpoll { status: u8, progress: u32, payload: Vec<u8> },
    Streamopen { fid: u32, direction: u8, offset: u64, count: u64 },
    Rstreamopen { stream_id: u32 },
    Streamdata { stream_id: u32, seq: u32, data: Vec<u8> },
    Streamclose { stream_id: u32 },
    Search { fid: u32, query: String, flags: u32, max_results: u32, cookie: u64 },
    Rsearch { cookie: u64, entries: Vec<SearchEntry> },
    Hash { fid: u32, algo: u8, offset: u64, length: u64 },
    Rhash { algo: u8, hash: Vec<u8> },
}

/// Top-level 9P2000.N message.
#[derive(Debug, Clone, PartialEq)]
pub struct Fcall {
    pub size: u32,
    pub msg_type: MsgType,
    pub tag: u16,
    pub msg: Msg,
}
