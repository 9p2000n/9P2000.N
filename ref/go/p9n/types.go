// Package p9n implements the 9P2000.N protocol wire format.
//
// 9P2000.N is a modular, capability-negotiated extension framework for the 9P
// remote resource protocol. This package provides message marshalling,
// unmarshalling, and capability negotiation — matching the C reference
// implementation feature-for-feature.
//
// Wire format: size[4] type[1] tag[2] payload — all integers little-endian.
package p9n

// Protocol versions.
const (
	Version     = "9P2000.N"
	VersionBase = "9P2000"
	VersionU    = "9P2000.u"
	VersionL    = "9P2000.L"
)

// Magic numbers.
const (
	NoTag   uint16 = 0xFFFF
	NoFid   uint32 = 0xFFFFFFFF
	PrevFid uint32 = 0xFFFFFFFE // magic fid in Tcompound sub-ops
)

// Header sizes.
const (
	HeaderSize  = 7 // size[4] + type[1] + tag[2]
	SubopHdrSz  = 5 // opsize[4] + type[1]
	QIDSize     = 13
	MaxCaps     = 64
	MaxCapLen   = 64
	MaxSpiffeID = 2048
)

// MsgType is a 9P2000.N message type identifier.
type MsgType uint8

// Message types — negotiation.
const (
	Tcaps MsgType = 128
	Rcaps MsgType = 129
)

// Message types — security.
const (
	Tstartls       MsgType = 130
	Rstartls       MsgType = 131
	Tauthneg       MsgType = 132
	Rauthneg       MsgType = 133
	Tcapgrant      MsgType = 134
	Rcapgrant      MsgType = 135
	Tcapuse        MsgType = 136
	Rcapuse        MsgType = 137
	Tauditctl      MsgType = 138
	Rauditctl      MsgType = 139
	TstartlsSpiffe MsgType = 140
	RstartlsSpiffe MsgType = 141
	Tfetchbundle   MsgType = 142
	Rfetchbundle   MsgType = 143
	Tspiffeverify  MsgType = 144
	Rspiffeverify  MsgType = 145
)

// Message types — transport.
const (
	Tcxlmap       MsgType = 146
	Rcxlmap       MsgType = 147
	Tcxlcoherence MsgType = 148
	Rcxlcoherence MsgType = 149
	Trdmatoken    MsgType = 150
	Rrdmatoken    MsgType = 151
	Trdmanotify   MsgType = 152
	Rrdmanotify   MsgType = 153
	Tquicstream   MsgType = 154
	Rquicstream   MsgType = 155
)

// Message types — performance.
const (
	Tcompound MsgType = 156
	Rcompound MsgType = 157
	Tcompress MsgType = 158
	Rcompress MsgType = 159
	Tcopyrange MsgType = 160
	Rcopyrange MsgType = 161
	Tallocate  MsgType = 162
	Rallocate  MsgType = 163
	Tseekhole  MsgType = 164
	Rseekhole  MsgType = 165
	Tmmaphint  MsgType = 166
	Rmmaphint  MsgType = 167
)

// Message types — filesystem.
const (
	Twatch    MsgType = 180
	Rwatch    MsgType = 181
	Tunwatch  MsgType = 182
	Runwatch  MsgType = 183
	Tnotify   MsgType = 184 // reserved
	Rnotify   MsgType = 185 // server-push
	Tgetacl   MsgType = 186
	Rgetacl   MsgType = 187
	Tsetacl   MsgType = 188
	Rsetacl   MsgType = 189
	Tsnapshot MsgType = 190
	Rsnapshot MsgType = 191
	Tclone    MsgType = 192
	Rclone    MsgType = 193
	Txattrget  MsgType = 194
	Rxattrget  MsgType = 195
	Txattrset  MsgType = 196
	Rxattrset  MsgType = 197
	Txattrlist MsgType = 198
	Rxattrlist MsgType = 199
)

// Message types — distributed.
const (
	Tlease       MsgType = 200
	Rlease       MsgType = 201
	Tleaserenew  MsgType = 202
	Rleaserenew  MsgType = 203
	Tleasebreak  MsgType = 204 // reserved
	Rleasebreak  MsgType = 205 // server-push
	Tleaseack    MsgType = 206
	Rleaseack    MsgType = 207
	Tsession     MsgType = 208
	Rsession     MsgType = 209
	Tconsistency MsgType = 210
	Rconsistency MsgType = 211
	Ttopology    MsgType = 212
	Rtopology    MsgType = 213
)

// Message types — observability.
const (
	Ttraceattr   MsgType = 220
	Rtraceattr   MsgType = 221
	Thealth      MsgType = 222
	Rhealth      MsgType = 223
	Tserverstats MsgType = 224
	Rserverstats MsgType = 225
)

// Message types — resource management.
const (
	Tgetquota  MsgType = 230
	Rgetquota  MsgType = 231
	Tsetquota  MsgType = 232
	Rsetquota  MsgType = 233
	Tratelimit MsgType = 234
	Rratelimit MsgType = 235
)

// Message types — streaming/async.
const (
	Tasync       MsgType = 240
	Rasync       MsgType = 241
	Tpoll        MsgType = 242
	Rpoll        MsgType = 243
	Tstreamopen  MsgType = 244
	Rstreamopen  MsgType = 245
	Tstreamdata  MsgType = 246
	Rstreamdata  MsgType = 247 // also server-push
	Tstreamclose MsgType = 248
	Rstreamclose MsgType = 249
)

// Message types — content-awareness.
const (
	Tsearch MsgType = 250
	Rsearch MsgType = 251
	Thash   MsgType = 252
	Rhash   MsgType = 253
)

// Capability strings.
const (
	CapTLS         = "security.tls"
	CapAuth        = "security.auth"
	CapCaps        = "security.caps"
	CapAudit       = "security.audit"
	CapSpiffe      = "security.spiffe"
	CapCompound    = "perf.compound"
	CapLargemsg    = "perf.largemsg"
	CapCompress    = "perf.compress"
	CapZerocopy    = "perf.zerocopy"
	CapCopy        = "perf.copy"
	CapAlloc       = "perf.alloc"
	CapMmap        = "perf.mmap"
	CapWatch       = "fs.watch"
	CapACL         = "fs.acl"
	CapSnapshot    = "fs.snapshot"
	CapXattr2      = "fs.xattr2"
	CapLease       = "dist.lease"
	CapSession     = "dist.session"
	CapConsistency = "dist.consistency"
	CapTopology    = "dist.topology"
	CapTrace       = "obs.trace"
	CapHealth      = "obs.health"
	CapStats       = "obs.stats"
	CapQuota       = "res.quota"
	CapRatelimit   = "res.ratelimit"
	CapAsync       = "stream.async"
	CapPipe        = "stream.pipe"
	CapSearch      = "content.search"
	CapHash        = "content.hash"
	CapQUIC        = "transport.quic"
	CapQUICMulti   = "transport.quic.multistream"
	CapRDMA        = "transport.rdma"
	CapCXL         = "transport.cxl"
)

// CapBit is a bit index for fast capability lookup.
type CapBit uint

const (
	CBitTLS CapBit = iota
	CBitAuth
	CBitCaps
	CBitAudit
	CBitCompound
	CBitLargemsg
	CBitCompress
	CBitZerocopy
	CBitCopy
	CBitAlloc
	CBitMmap
	CBitWatch
	CBitACL
	CBitSnapshot
	CBitXattr2
	CBitLease
	CBitSession
	CBitConsistency
	CBitTopology
	CBitTrace
	CBitHealth
	CBitStats
	CBitQuota
	CBitRatelimit
	CBitAsync
	CBitPipe
	CBitSearch
	CBitHash
	CBitSpiffe
	CBitQUIC
	CBitQUICMulti
	CBitRDMA
	CBitCXL
	CBitCount
)

// Watch event masks.
const (
	WatchCreate uint32 = 0x00000001
	WatchRemove uint32 = 0x00000002
	WatchModify uint32 = 0x00000004
	WatchAttrib uint32 = 0x00000008
	WatchRename uint32 = 0x00000010
	WatchAll    uint32 = 0xFFFFFFFF
)

// Watch flags.
const (
	WatchRecursive uint32 = 0x00000001
	WatchOneshot   uint32 = 0x00000002
)

// Lease types.
const (
	LeaseNone   uint8 = 0
	LeaseRead   uint8 = 1
	LeaseWrite  uint8 = 2
	LeaseHandle uint8 = 3
)

// Session flags.
const (
	SessionFids    uint32 = 0x00000001
	SessionLeases  uint32 = 0x00000002
	SessionWatches uint32 = 0x00000004
)

// Compression algorithms.
const (
	CompressNone   uint8 = 0
	CompressLZ4    uint8 = 1
	CompressZstd   uint8 = 2
	CompressSnappy uint8 = 3
)

// Hash algorithms.
const (
	HashXXHash64 uint8 = 0
	HashSHA256   uint8 = 1
	HashBLAKE3   uint8 = 2
	HashCRC32C   uint8 = 3
)

// Copy range flags.
const (
	CopyReflink uint32 = 0x00000001
	CopyDedup   uint32 = 0x00000002
)

// SPIFFE SVID types.
const (
	SVIDX509 uint8 = 0
	SVIDJWT  uint8 = 1
)

// SPIFFE bundle formats.
const (
	BundleX509CAs uint8 = 0
	BundleJWTKeys uint8 = 1
)

// SPIFFE verification status.
const (
	SpiffeOK        uint8 = 0
	SpiffeUntrusted uint8 = 1
	SpiffeExpired   uint8 = 2
	SpiffeRevoked   uint8 = 3
	SpiffeMismatch  uint8 = 4
)

// QUIC stream types.
const (
	QStreamControl uint8 = 0
	QStreamData    uint8 = 1
	QStreamPush    uint8 = 2
	QStreamBulk    uint8 = 3
)

// CXL coherence modes.
const (
	CXLCoherenceSoftware uint8 = 0
	CXLCoherenceHardware uint8 = 1
	CXLCoherenceHybrid   uint8 = 2
	CXLCoherenceRelaxed  uint8 = 3
)

// Auth mechanism names.
const (
	AuthScramSHA256 = "SASL-SCRAM-SHA-256"
	AuthMTLS        = "mTLS"
	AuthOIDC        = "OIDC"
	AuthP9any       = "P9any"
	AuthSpiffeX509  = "SPIFFE-X.509"
	AuthSpiffeJWT   = "SPIFFE-JWT"
)

// QID represents a 9P file system entity identifier.
type QID struct {
	Type    uint8
	Version uint32
	Path    uint64
}

// Fcall is the top-level message container.
type Fcall struct {
	Size uint32
	Type MsgType
	Tag  uint16
	Msg  any // one of the message structs below
}

// --- Message structs ---

type MsgCaps struct {
	Caps []string
}

type MsgAuthneg struct {
	Mechs []string
}

type MsgRauthneg struct {
	Mech      string
	Challenge []byte
}

type MsgCapgrant struct {
	Fid    uint32
	Rights uint64
	Expiry uint64
	Depth  uint16
}

type MsgRcapgrant struct {
	Token string
}

type MsgCapuse struct {
	Fid   uint32
	Token string
}

type MsgRcapuse struct {
	Qid QID
}

type MsgAuditctl struct {
	Fid   uint32
	Flags uint32
}

type MsgStartlsSpiffe struct {
	SpiffeID    string
	TrustDomain string
}

type MsgFetchbundle struct {
	TrustDomain string
	Format      uint8
}

type MsgRfetchbundle struct {
	TrustDomain string
	Format      uint8
	Bundle      []byte
}

type MsgSpiffeverify struct {
	SVIDType uint8
	SpiffeID string
	SVID     []byte
}

type MsgRspiffeverify struct {
	Status   uint8
	SpiffeID string
	Expiry   uint64
}

type MsgCxlmap struct {
	Fid    uint32
	Offset uint64
	Length uint64
	Prot   uint32
	Flags  uint32
}

type MsgRcxlmap struct {
	HPA         uint64
	Length      uint64
	Granularity uint32
	Coherence   uint8
}

type MsgCxlcoherence struct {
	Fid  uint32
	Mode uint8
}

type MsgRcxlcoherence struct {
	Mode    uint8
	SnoopID uint32
}

type MsgRdmatoken struct {
	Fid       uint32
	Direction uint8
	Rkey      uint32
	Addr      uint64
	Length    uint32
}

type MsgRrdmatoken struct {
	Rkey   uint32
	Addr   uint64
	Length uint32
}

type MsgRdmanotify struct {
	Rkey   uint32
	Addr   uint64
	Length uint32
	Slots  uint16
}

type MsgQuicstream struct {
	StreamType uint8
	StreamID   uint64
}

type MsgRquicstream struct {
	StreamID uint64
}

type SubOp struct {
	Type    MsgType
	Payload []byte
}

type MsgCompound struct {
	Ops []SubOp
}

type MsgRcompound struct {
	Results []SubOp
}

type MsgCompress struct {
	Algo  uint8
	Level uint8
}

type MsgRcompress struct {
	Algo uint8
}

type MsgCopyrange struct {
	SrcFid uint32
	SrcOff uint64
	DstFid uint32
	DstOff uint64
	Count  uint64
	Flags  uint32
}

type MsgRcopyrange struct {
	Count uint64
}

type MsgAllocate struct {
	Fid    uint32
	Mode   uint32
	Offset uint64
	Length uint64
}

type MsgSeekhole struct {
	Fid      uint32
	SeekType uint8
	Offset   uint64
}

type MsgRseekhole struct {
	Offset uint64
}

type MsgMmaphint struct {
	Fid    uint32
	Offset uint64
	Length uint64
	Prot   uint32
}

type MsgRmmaphint struct {
	Granted uint8
}

type MsgWatch struct {
	Fid   uint32
	Mask  uint32
	Flags uint32
}

type MsgRwatch struct {
	WatchID uint32
}

type MsgUnwatch struct {
	WatchID uint32
}

type MsgNotify struct {
	WatchID uint32
	Event   uint32
	Name    string
	Qid     QID
}

type MsgGetacl struct {
	Fid     uint32
	ACLType uint8
}

type MsgRgetacl struct {
	Data []byte
}

type MsgSetacl struct {
	Fid     uint32
	ACLType uint8
	Data    []byte
}

type MsgSnapshot struct {
	Fid   uint32
	Name  string
	Flags uint32
}

type MsgRsnapshot struct {
	Qid QID
}

type MsgClone struct {
	SrcFid uint32
	DstFid uint32
	Name   string
	Flags  uint32
}

type MsgRclone struct {
	Qid QID
}

type MsgXattrget struct {
	Fid  uint32
	Name string
}

type MsgRxattrget struct {
	Data []byte
}

type MsgXattrset struct {
	Fid   uint32
	Name  string
	Data  []byte
	Flags uint32
}

type MsgXattrlist struct {
	Fid    uint32
	Cookie uint64
	Count  uint32
}

type MsgRxattrlist struct {
	Cookie uint64
	Names  []string
}

type MsgLease struct {
	Fid      uint32
	Type     uint8
	Duration uint32
}

type MsgRlease struct {
	LeaseID  uint64
	Type     uint8
	Duration uint32
}

type MsgLeaserenew struct {
	LeaseID  uint64
	Duration uint32
}

type MsgRleaserenew struct {
	Duration uint32
}

type MsgLeasebreak struct {
	LeaseID uint64
	NewType uint8
}

type MsgLeaseack struct {
	LeaseID uint64
}

type MsgSession struct {
	Key   [16]byte
	Flags uint32
}

type MsgRsession struct {
	Flags uint32
}

type MsgConsistency struct {
	Fid   uint32
	Level uint8
}

type MsgRconsistency struct {
	Level uint8
}

type MsgTopology struct {
	Fid uint32
}

type Replica struct {
	Addr      string
	Role      uint8
	LatencyUs uint32
}

type MsgRtopology struct {
	Replicas []Replica
}

type MsgTraceattr struct {
	Attrs map[string]string
}

type Metric struct {
	Name  string
	Value uint64
}

type MsgRhealth struct {
	Status  uint8
	Load    uint32
	Metrics []Metric
}

type MsgServerstatsReq struct {
	Mask uint64
}

type ServerStat struct {
	Name  string
	Type  uint8
	Value uint64
}

type MsgRserverstats struct {
	Stats []ServerStat
}

type MsgGetquota struct {
	Fid  uint32
	Type uint8
}

type MsgRgetquota struct {
	BytesUsed   uint64
	BytesLimit  uint64
	FilesUsed   uint64
	FilesLimit  uint64
	GracePeriod uint32
}

type MsgSetquota struct {
	Fid         uint32
	Type        uint8
	BytesLimit  uint64
	FilesLimit  uint64
	GracePeriod uint32
}

type MsgRatelimit struct {
	Fid  uint32
	IOPS uint32
	BPS  uint64
}

type MsgRratelimit struct {
	IOPS uint32
	BPS  uint64
}

type MsgAsync struct {
	InnerType MsgType
	Payload   []byte
}

type MsgRasync struct {
	OpID   uint64
	Status uint8
}

type MsgPoll struct {
	OpID uint64
}

type MsgRpoll struct {
	Status   uint8
	Progress uint32
	Payload  []byte
}

type MsgStreamopen struct {
	Fid       uint32
	Direction uint8
	Offset    uint64
	Count     uint64
}

type MsgRstreamopen struct {
	StreamID uint32
}

type MsgStreamdata struct {
	StreamID uint32
	Seq      uint32
	Data     []byte
}

type MsgStreamclose struct {
	StreamID uint32
}

type MsgSearch struct {
	Fid        uint32
	Query      string
	Flags      uint32
	MaxResults uint32
	Cookie     uint64
}

type SearchEntry struct {
	Qid   QID
	Name  string
	Score uint32
}

type MsgRsearch struct {
	Cookie  uint64
	Entries []SearchEntry
}

type MsgHash struct {
	Fid    uint32
	Algo   uint8
	Offset uint64
	Length uint64
}

type MsgRhash struct {
	Algo uint8
	Hash []byte
}

// msgNames maps type numbers to human-readable names.
var msgNames = map[MsgType]string{
	Tcaps: "Tcaps", Rcaps: "Rcaps",
	Tstartls: "Tstartls", Rstartls: "Rstartls",
	Tauthneg: "Tauthneg", Rauthneg: "Rauthneg",
	Tcapgrant: "Tcapgrant", Rcapgrant: "Rcapgrant",
	Tcapuse: "Tcapuse", Rcapuse: "Rcapuse",
	Tauditctl: "Tauditctl", Rauditctl: "Rauditctl",
	TstartlsSpiffe: "Tstartls_spiffe", RstartlsSpiffe: "Rstartls_spiffe",
	Tfetchbundle: "Tfetchbundle", Rfetchbundle: "Rfetchbundle",
	Tspiffeverify: "Tspiffeverify", Rspiffeverify: "Rspiffeverify",
	Tcxlmap: "Tcxlmap", Rcxlmap: "Rcxlmap",
	Tcxlcoherence: "Tcxlcoherence", Rcxlcoherence: "Rcxlcoherence",
	Trdmatoken: "Trdmatoken", Rrdmatoken: "Rrdmatoken",
	Trdmanotify: "Trdmanotify", Rrdmanotify: "Rrdmanotify",
	Tquicstream: "Tquicstream", Rquicstream: "Rquicstream",
	Tcompound: "Tcompound", Rcompound: "Rcompound",
	Tcompress: "Tcompress", Rcompress: "Rcompress",
	Tcopyrange: "Tcopyrange", Rcopyrange: "Rcopyrange",
	Tallocate: "Tallocate", Rallocate: "Rallocate",
	Tseekhole: "Tseekhole", Rseekhole: "Rseekhole",
	Tmmaphint: "Tmmaphint", Rmmaphint: "Rmmaphint",
	Twatch: "Twatch", Rwatch: "Rwatch",
	Tunwatch: "Tunwatch", Runwatch: "Runwatch",
	Tnotify: "Tnotify", Rnotify: "Rnotify",
	Tgetacl: "Tgetacl", Rgetacl: "Rgetacl",
	Tsetacl: "Tsetacl", Rsetacl: "Rsetacl",
	Tsnapshot: "Tsnapshot", Rsnapshot: "Rsnapshot",
	Tclone: "Tclone", Rclone: "Rclone",
	Txattrget: "Txattrget", Rxattrget: "Rxattrget",
	Txattrset: "Txattrset", Rxattrset: "Rxattrset",
	Txattrlist: "Txattrlist", Rxattrlist: "Rxattrlist",
	Tlease: "Tlease", Rlease: "Rlease",
	Tleaserenew: "Tleaserenew", Rleaserenew: "Rleaserenew",
	Tleasebreak: "Tleasebreak", Rleasebreak: "Rleasebreak",
	Tleaseack: "Tleaseack", Rleaseack: "Rleaseack",
	Tsession: "Tsession", Rsession: "Rsession",
	Tconsistency: "Tconsistency", Rconsistency: "Rconsistency",
	Ttopology: "Ttopology", Rtopology: "Rtopology",
	Ttraceattr: "Ttraceattr", Rtraceattr: "Rtraceattr",
	Thealth: "Thealth", Rhealth: "Rhealth",
	Tserverstats: "Tserverstats", Rserverstats: "Rserverstats",
	Tgetquota: "Tgetquota", Rgetquota: "Rgetquota",
	Tsetquota: "Tsetquota", Rsetquota: "Rsetquota",
	Tratelimit: "Tratelimit", Rratelimit: "Rratelimit",
	Tasync: "Tasync", Rasync: "Rasync",
	Tpoll: "Tpoll", Rpoll: "Rpoll",
	Tstreamopen: "Tstreamopen", Rstreamopen: "Rstreamopen",
	Tstreamdata: "Tstreamdata", Rstreamdata: "Rstreamdata",
	Tstreamclose: "Tstreamclose", Rstreamclose: "Rstreamclose",
	Tsearch: "Tsearch", Rsearch: "Rsearch",
	Thash: "Thash", Rhash: "Rhash",
}

// MsgName returns the human-readable name for a message type.
func MsgName(t MsgType) string {
	if n, ok := msgNames[t]; ok {
		return n
	}
	return "unknown"
}
