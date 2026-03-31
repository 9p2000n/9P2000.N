/* SPDX-License-Identifier: MIT */
/*
 * 9P2000.N protocol definitions -- Next-generation 9P extensions.
 *
 * This header extends the base 9P2000/9P2000.L protocol with modular,
 * capability-negotiated extensions across 8 domains: security, performance,
 * filesystem semantics, distributed systems, observability, resource
 * management, streaming/async, and content-awareness.
 *
 * Wire format is preserved: size[4] type[1] tag[2] payload
 * All integers are little-endian. Strings are length[2] + UTF-8 (no NUL).
 */

#ifndef P9N_H
#define P9N_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ======================================================================
 * Version and Magic Numbers
 * ====================================================================== */

#define P9N_VERSION         "9P2000.N"
#define P9N_VERSION_BASE    "9P2000"
#define P9N_VERSION_U       "9P2000.u"
#define P9N_VERSION_L       "9P2000.L"

/* Standard 9P magic numbers (duplicated for standalone use) */
#define P9_NOTAG            ((uint16_t)0xFFFF)
#define P9_NOFID            ((uint32_t)0xFFFFFFFF)

/* Magic fid: refers to the fid returned by the previous sub-op in Tcompound */
#define P9N_PREVFID         ((uint32_t)0xFFFFFFFE)

/* Header sizes */
#define P9_HDRSZ            7       /* size[4] + type[1] + tag[2] */
#define P9N_SUBOP_HDRSZ     5       /* opsize[4] + type[1] (no tag in sub-ops) */

/* ======================================================================
 * 9P2000.N Message Types
 *
 * Allocation strategy:
 *   128-129  Negotiation
 *   130-149  Security (security.*)
 *   150-155  Transport (transport.*)
 *   156-179  Performance (perf.*)
 *   180-199  Filesystem semantics (fs.*)
 *   200-219  Distributed systems (dist.*)
 *   220-229  Observability (obs.*)
 *   230-239  Resource management (res.*)
 *   240-249  Streaming/Async (stream.*)
 *   250-255  Content-awareness (content.*)
 * ====================================================================== */

enum p9n_msg_t {
	/* -- Negotiation framework ---------------------------------------- */
	P9N_TCAPS              = 128,
	P9N_RCAPS              = 129,

	/* -- Security (security.*) ---------------------------------------- */
	P9N_TSTARTLS           = 130,
	P9N_RSTARTLS           = 131,
	P9N_TAUTHNEG           = 132,
	P9N_RAUTHNEG           = 133,
	P9N_TCAPGRANT          = 134,
	P9N_RCAPGRANT          = 135,
	P9N_TCAPUSE            = 136,
	P9N_RCAPUSE            = 137,
	P9N_TAUDITCTL          = 138,
	P9N_RAUDITCTL          = 139,

	/* SPIFFE identity extensions (security.spiffe) */
	P9N_TSTARTLS_SPIFFE    = 140,   /* TLS with SPIFFE ID validation */
	P9N_RSTARTLS_SPIFFE    = 141,
	P9N_TFETCHBUNDLE       = 142,   /* fetch SPIFFE trust bundle */
	P9N_RFETCHBUNDLE       = 143,
	P9N_TSPIFFEVERIFY      = 144,   /* verify peer SPIFFE identity */
	P9N_RSPIFFEVERIFY      = 145,

	/* -- Transport (transport.*) -------------------------------------- */
	P9N_TCXLMAP            = 146,   /* map file into CXL shared memory */
	P9N_RCXLMAP            = 147,
	P9N_TCXLCOHERENCE      = 148,   /* negotiate CXL coherence mode */
	P9N_RCXLCOHERENCE      = 149,
	P9N_TRDMATOKEN         = 150,   /* exchange RDMA memory region token */
	P9N_RRDMATOKEN         = 151,
	P9N_TRDMANOTIFY        = 152,   /* register RDMA notification ring */
	P9N_RRDMANOTIFY        = 153,
	P9N_TQUICSTREAM        = 154,   /* bind 9P channel to QUIC stream */
	P9N_RQUICSTREAM        = 155,

	/* -- Performance (perf.*) ----------------------------------------- */
	P9N_TCOMPOUND          = 156,
	P9N_RCOMPOUND          = 157,
	P9N_TCOMPRESS          = 158,
	P9N_RCOMPRESS          = 159,
	P9N_TCOPYRANGE         = 160,
	P9N_RCOPYRANGE         = 161,
	P9N_TALLOCATE          = 162,
	P9N_RALLOCATE          = 163,
	P9N_TSEEKHOLE          = 164,
	P9N_RSEEKHOLE          = 165,
	P9N_TMMAPHINT          = 166,
	P9N_RMMAPHINT          = 167,

	/* -- Filesystem semantics (fs.*) ---------------------------------- */
	P9N_TWATCH             = 180,
	P9N_RWATCH             = 181,
	P9N_TUNWATCH           = 182,
	P9N_RUNWATCH           = 183,
	P9N_TNOTIFY            = 184,   /* reserved, never sent by client */
	P9N_RNOTIFY            = 185,   /* server-push, tag = P9_NOTAG */
	P9N_TGETACL            = 186,
	P9N_RGETACL            = 187,
	P9N_TSETACL            = 188,
	P9N_RSETACL            = 189,
	P9N_TSNAPSHOT          = 190,
	P9N_RSNAPSHOT          = 191,
	P9N_TCLONE             = 192,
	P9N_RCLONE             = 193,
	P9N_TXATTRGET          = 194,
	P9N_RXATTRGET          = 195,
	P9N_TXATTRSET          = 196,
	P9N_RXATTRSET          = 197,
	P9N_TXATTRLIST         = 198,
	P9N_RXATTRLIST         = 199,

	/* -- Distributed systems (dist.*) --------------------------------- */
	P9N_TLEASE             = 200,
	P9N_RLEASE             = 201,
	P9N_TLEASERENEW        = 202,
	P9N_RLEASERENEW        = 203,
	P9N_TLEASEBREAK        = 204,   /* reserved, never sent by client */
	P9N_RLEASEBREAK        = 205,   /* server-push, tag = P9_NOTAG */
	P9N_TLEASEACK          = 206,
	P9N_RLEASEACK          = 207,
	P9N_TSESSION           = 208,
	P9N_RSESSION           = 209,
	P9N_TCONSISTENCY       = 210,
	P9N_RCONSISTENCY       = 211,
	P9N_TTOPOLOGY          = 212,
	P9N_RTOPOLOGY          = 213,

	/* -- Observability (obs.*) ---------------------------------------- */
	P9N_TTRACEATTR         = 220,
	P9N_RTRACEATTR         = 221,
	P9N_THEALTH            = 222,
	P9N_RHEALTH            = 223,
	P9N_TSERVERSTATS       = 224,
	P9N_RSERVERSTATS       = 225,

	/* -- Resource management (res.*) ---------------------------------- */
	P9N_TGETQUOTA          = 230,
	P9N_RGETQUOTA          = 231,
	P9N_TSETQUOTA          = 232,
	P9N_RSETQUOTA          = 233,
	P9N_TRATELIMIT         = 234,
	P9N_RRATELIMIT         = 235,

	/* -- Streaming/Async (stream.*) ----------------------------------- */
	P9N_TASYNC             = 240,
	P9N_RASYNC             = 241,
	P9N_TPOLL              = 242,
	P9N_RPOLL              = 243,
	P9N_TSTREAMOPEN        = 244,
	P9N_RSTREAMOPEN        = 245,
	P9N_TSTREAMDATA        = 246,
	P9N_RSTREAMDATA        = 247,   /* also server-push for reads */
	P9N_TSTREAMCLOSE       = 248,
	P9N_RSTREAMCLOSE       = 249,

	/* -- Content-awareness (content.*) -------------------------------- */
	P9N_TSEARCH            = 250,
	P9N_RSEARCH            = 251,
	P9N_THASH              = 252,
	P9N_RHASH              = 253,
};

/* ======================================================================
 * Capability Domain Strings
 * ====================================================================== */

/* Negotiation (implicit with 9P2000.N) */
#define P9N_CAP_TLS            "security.tls"
#define P9N_CAP_AUTH           "security.auth"
#define P9N_CAP_CAPS           "security.caps"
#define P9N_CAP_AUDIT          "security.audit"
#define P9N_CAP_SPIFFE         "security.spiffe"

#define P9N_CAP_COMPOUND       "perf.compound"
#define P9N_CAP_LARGEMSG       "perf.largemsg"
#define P9N_CAP_COMPRESS       "perf.compress"
#define P9N_CAP_ZEROCOPY       "perf.zerocopy"
#define P9N_CAP_COPY           "perf.copy"
#define P9N_CAP_ALLOC          "perf.alloc"
#define P9N_CAP_MMAP           "perf.mmap"

#define P9N_CAP_WATCH          "fs.watch"
#define P9N_CAP_ACL            "fs.acl"
#define P9N_CAP_SNAPSHOT       "fs.snapshot"
#define P9N_CAP_XATTR2         "fs.xattr2"

#define P9N_CAP_LEASE          "dist.lease"
#define P9N_CAP_SESSION        "dist.session"
#define P9N_CAP_CONSISTENCY    "dist.consistency"
#define P9N_CAP_TOPOLOGY       "dist.topology"

#define P9N_CAP_TRACE          "obs.trace"
#define P9N_CAP_HEALTH         "obs.health"
#define P9N_CAP_STATS          "obs.stats"

#define P9N_CAP_QUOTA          "res.quota"
#define P9N_CAP_RATELIMIT      "res.ratelimit"

#define P9N_CAP_ASYNC          "stream.async"
#define P9N_CAP_PIPE           "stream.pipe"

#define P9N_CAP_SEARCH         "content.search"
#define P9N_CAP_HASH           "content.hash"

#define P9N_CAP_QUIC           "transport.quic"
#define P9N_CAP_QUIC_MULTI     "transport.quic.multistream"
#define P9N_CAP_RDMA           "transport.rdma"
#define P9N_CAP_CXL            "transport.cxl"

/* Maximum number of capabilities in a single Tcaps/Rcaps message */
#define P9N_MAX_CAPS           64

/* Maximum capability string length */
#define P9N_MAX_CAP_LEN        64

/* ======================================================================
 * Capability Bitmask (for efficient runtime checking)
 * ====================================================================== */

enum p9n_cap_bit {
	P9N_CBIT_TLS           = 0,
	P9N_CBIT_AUTH          = 1,
	P9N_CBIT_CAPS          = 2,
	P9N_CBIT_AUDIT         = 3,
	P9N_CBIT_COMPOUND      = 4,
	P9N_CBIT_LARGEMSG      = 5,
	P9N_CBIT_COMPRESS      = 6,
	P9N_CBIT_ZEROCOPY      = 7,
	P9N_CBIT_COPY          = 8,
	P9N_CBIT_ALLOC         = 9,
	P9N_CBIT_MMAP          = 10,
	P9N_CBIT_WATCH         = 11,
	P9N_CBIT_ACL           = 12,
	P9N_CBIT_SNAPSHOT      = 13,
	P9N_CBIT_XATTR2        = 14,
	P9N_CBIT_LEASE         = 15,
	P9N_CBIT_SESSION       = 16,
	P9N_CBIT_CONSISTENCY   = 17,
	P9N_CBIT_TOPOLOGY      = 18,
	P9N_CBIT_TRACE         = 19,
	P9N_CBIT_HEALTH        = 20,
	P9N_CBIT_STATS         = 21,
	P9N_CBIT_QUOTA         = 22,
	P9N_CBIT_RATELIMIT     = 23,
	P9N_CBIT_ASYNC         = 24,
	P9N_CBIT_PIPE          = 25,
	P9N_CBIT_SEARCH        = 26,
	P9N_CBIT_HASH          = 27,
	P9N_CBIT_SPIFFE        = 28,
	P9N_CBIT_QUIC          = 29,
	P9N_CBIT_QUIC_MULTI    = 30,
	P9N_CBIT_RDMA          = 31,
	P9N_CBIT_CXL           = 32,
	P9N_CBIT_COUNT         = 33,
};

/* Capability bitmask type */
typedef uint64_t p9n_capset_t;

#define P9N_CAP_SET(bit)       ((p9n_capset_t)1ULL << (bit))
#define P9N_CAP_HAS(set, bit)  (((set) & P9N_CAP_SET(bit)) != 0)

/* ======================================================================
 * Compression Algorithms
 * ====================================================================== */

enum p9n_compress_algo {
	P9N_COMPRESS_NONE      = 0,
	P9N_COMPRESS_LZ4       = 1,
	P9N_COMPRESS_ZSTD      = 2,
	P9N_COMPRESS_SNAPPY    = 3,
};

/* ======================================================================
 * Watch Event Masks
 * ====================================================================== */

#define P9N_WATCH_CREATE       0x00000001
#define P9N_WATCH_REMOVE       0x00000002
#define P9N_WATCH_MODIFY       0x00000004
#define P9N_WATCH_ATTRIB       0x00000008
#define P9N_WATCH_RENAME       0x00000010
#define P9N_WATCH_ALL          0xFFFFFFFF

/* Watch flags */
#define P9N_WATCH_RECURSIVE    0x00000001
#define P9N_WATCH_ONESHOT      0x00000002

/* ======================================================================
 * Lease Types
 * ====================================================================== */

enum p9n_lease_type {
	P9N_LEASE_NONE         = 0,
	P9N_LEASE_READ         = 1,    /* shared read delegation */
	P9N_LEASE_WRITE        = 2,    /* exclusive write delegation */
	P9N_LEASE_HANDLE       = 3,    /* open-handle caching */
};

/* ======================================================================
 * Consistency Levels
 * ====================================================================== */

enum p9n_consistency_level {
	P9N_CONSIST_EVENTUAL   = 0,
	P9N_CONSIST_READ_YOUR_WRITES = 1,
	P9N_CONSIST_SEQUENTIAL = 2,
	P9N_CONSIST_LINEARIZABLE = 3,
};

/* ======================================================================
 * Async Operation Status
 * ====================================================================== */

enum p9n_async_status {
	P9N_ASYNC_PENDING      = 0,
	P9N_ASYNC_RUNNING      = 1,
	P9N_ASYNC_COMPLETE     = 2,
	P9N_ASYNC_FAILED       = 3,
};

/* ======================================================================
 * Copy Range Flags
 * ====================================================================== */

#define P9N_COPY_REFLINK       0x00000001   /* CoW if possible */
#define P9N_COPY_DEDUP         0x00000002   /* dedup hint */

/* ======================================================================
 * Allocate Modes (match Linux fallocate flags)
 * ====================================================================== */

#define P9N_FALLOC_KEEP_SIZE       0x01
#define P9N_FALLOC_PUNCH_HOLE      0x02
#define P9N_FALLOC_COLLAPSE_RANGE  0x04
#define P9N_FALLOC_ZERO_RANGE      0x08
#define P9N_FALLOC_INSERT_RANGE    0x10

/* Seek hole/data types */
#define P9N_SEEK_DATA              0
#define P9N_SEEK_HOLE              1

/* ======================================================================
 * ACL Types
 * ====================================================================== */

enum p9n_acl_type {
	P9N_ACL_POSIX_ACCESS   = 0,
	P9N_ACL_POSIX_DEFAULT  = 1,
	P9N_ACL_NFSV4          = 2,
	P9N_ACL_RICHACL        = 3,
};

/* ======================================================================
 * Hash Algorithms
 * ====================================================================== */

enum p9n_hash_algo {
	P9N_HASH_XXHASH64      = 0,
	P9N_HASH_SHA256         = 1,
	P9N_HASH_BLAKE3         = 2,
	P9N_HASH_CRC32C         = 3,
};

/* ======================================================================
 * Health Status
 * ====================================================================== */

enum p9n_health_status {
	P9N_HEALTH_OK          = 0,
	P9N_HEALTH_DEGRADED    = 1,
	P9N_HEALTH_READONLY    = 2,
	P9N_HEALTH_DRAINING    = 3,
};

/* ======================================================================
 * Quota Types
 * ====================================================================== */

enum p9n_quota_type {
	P9N_QUOTA_USER         = 0,
	P9N_QUOTA_GROUP        = 1,
	P9N_QUOTA_PROJECT      = 2,
};

/* ======================================================================
 * Topology Replica Roles
 * ====================================================================== */

enum p9n_replica_role {
	P9N_ROLE_PRIMARY       = 0,
	P9N_ROLE_SECONDARY     = 1,
	P9N_ROLE_READONLY      = 2,
	P9N_ROLE_WITNESS       = 3,
};

/* ======================================================================
 * Stat type for server stats
 * ====================================================================== */

enum p9n_stat_type {
	P9N_STAT_UINT64        = 0,    /* counter */
	P9N_STAT_GAUGE64       = 1,    /* gauge */
	P9N_STAT_FLOAT64       = 2,    /* IEEE 754 double as uint64 bits */
};

/* Server stats request mask */
#define P9N_STATS_STORAGE      0x01
#define P9N_STATS_MEMORY       0x02
#define P9N_STATS_CONNECTIONS  0x04
#define P9N_STATS_IO           0x08

/* ======================================================================
 * Search flags
 * ====================================================================== */

#define P9N_SEARCH_RECURSIVE   0x00000001
#define P9N_SEARCH_NAME_ONLY   0x00000002
#define P9N_SEARCH_REGEX       0x00000004
#define P9N_SEARCH_ICASE       0x00000008

/* ======================================================================
 * Stream direction
 * ====================================================================== */

enum p9n_stream_dir {
	P9N_STREAM_READ        = 0,
	P9N_STREAM_WRITE       = 1,
};

/* ======================================================================
 * Session flags
 * ====================================================================== */

#define P9N_SESSION_FIDS       0x00000001   /* preserve fids */
#define P9N_SESSION_LEASES     0x00000002   /* preserve leases */
#define P9N_SESSION_WATCHES    0x00000004   /* preserve watches */

/* ======================================================================
 * Authentication mechanism names
 * ====================================================================== */

#define P9N_AUTH_SCRAM_SHA256  "SASL-SCRAM-SHA-256"
#define P9N_AUTH_MTLS          "mTLS"
#define P9N_AUTH_OIDC          "OIDC"
#define P9N_AUTH_P9ANY         "P9any"
#define P9N_AUTH_SPIFFE_X509   "SPIFFE-X.509"
#define P9N_AUTH_SPIFFE_JWT    "SPIFFE-JWT"

/* ======================================================================
 * SPIFFE Constants
 * ====================================================================== */

/* Maximum SPIFFE ID length (spiffe://trust-domain/path) */
#define P9N_SPIFFE_ID_MAX      2048

/* SPIFFE SVID types */
enum p9n_svid_type {
	P9N_SVID_X509          = 0,
	P9N_SVID_JWT           = 1,
};

/* SPIFFE trust bundle format */
enum p9n_bundle_format {
	P9N_BUNDLE_X509_CAS    = 0,    /* PEM-encoded CA certificates */
	P9N_BUNDLE_JWT_KEYS    = 1,    /* JWK Set (JSON) */
};

/* SPIFFE verification result */
enum p9n_spiffe_verify_status {
	P9N_SPIFFE_OK          = 0,    /* identity verified */
	P9N_SPIFFE_UNTRUSTED   = 1,    /* trust domain not recognized */
	P9N_SPIFFE_EXPIRED     = 2,    /* SVID expired */
	P9N_SPIFFE_REVOKED     = 3,    /* SVID revoked */
	P9N_SPIFFE_MISMATCH    = 4,    /* SPIFFE ID does not match expected */
};

/* ======================================================================
 * Capability token rights bitmask
 * ====================================================================== */

#define P9N_RIGHT_READ         0x0000000000000001ULL
#define P9N_RIGHT_WRITE        0x0000000000000002ULL
#define P9N_RIGHT_WALK         0x0000000000000004ULL
#define P9N_RIGHT_CREATE       0x0000000000000008ULL
#define P9N_RIGHT_REMOVE       0x0000000000000010ULL
#define P9N_RIGHT_SETATTR      0x0000000000000020ULL
#define P9N_RIGHT_LOCK         0x0000000000000040ULL
#define P9N_RIGHT_ADMIN        0x0000000000000080ULL
#define P9N_RIGHT_ALL          0xFFFFFFFFFFFFFFFFULL

/* ======================================================================
 * Audit flags
 * ====================================================================== */

#define P9N_AUDIT_READ         0x00000001
#define P9N_AUDIT_WRITE        0x00000002
#define P9N_AUDIT_WALK         0x00000004
#define P9N_AUDIT_CREATE       0x00000008
#define P9N_AUDIT_REMOVE       0x00000010
#define P9N_AUDIT_SETATTR      0x00000020
#define P9N_AUDIT_ALL          0xFFFFFFFF

/* ======================================================================
 * Wire Structure Definitions
 *
 * These mirror the on-wire layout but use host types for in-memory use.
 * Actual marshalling/unmarshalling handles endianness.
 * ====================================================================== */

/* QID: 13 bytes on wire -- type[1] version[4] path[8] */
struct p9n_qid {
	uint8_t  type;
	uint32_t version;
	uint64_t path;
};

/* ---- Negotiation ---------------------------------------------------- */

struct p9n_caps {
	uint16_t  ncaps;
	char    **caps;         /* array of capability strings */
};

/* ---- Security ------------------------------------------------------- */

/* Tauthneg: nmechs[2] mechs[s]... */
struct p9n_authneg {
	uint16_t  nmechs;
	char    **mechs;
};

/* Rauthneg: mech[s] challenge_len[4] challenge[...] */
struct p9n_rauthneg {
	char     *mech;
	uint32_t  challenge_len;
	uint8_t  *challenge;
};

/* Tcapgrant: fid[4] rights[8] expiry[8] depth[2] */
struct p9n_capgrant {
	uint32_t fid;
	uint64_t rights;
	uint64_t expiry;        /* nanosecond unix timestamp, 0=no expiry */
	uint16_t depth;         /* walk depth, 0xFFFF=unlimited */
};

/* Rcapgrant: token[s] */
struct p9n_rcapgrant {
	char    *token;
};

/* Tcapuse: fid[4] token[s] */
struct p9n_capuse {
	uint32_t        fid;
	char           *token;
};

/* Rcapuse: qid[13] */
struct p9n_rcapuse {
	struct p9n_qid  qid;
};

/* Tauditctl: fid[4] flags[4] */
struct p9n_auditctl {
	uint32_t fid;
	uint32_t flags;
};

/* ---- SPIFFE extensions ---------------------------------------------- */

/*
 * Tstartls_spiffe: spiffe_id[s] trust_domain[s]
 *   Client sends expected server SPIFFE ID and its own trust domain.
 *   After Rstartls_spiffe, both sides begin TLS handshake.
 *   Certificates MUST contain the SPIFFE X.509-SVID extension.
 *
 * Rstartls_spiffe: spiffe_id[s] trust_domain[s]
 *   Server responds with its own SPIFFE ID and trust domain.
 */
struct p9n_startls_spiffe {
	char    *spiffe_id;     /* e.g., "spiffe://example.com/server" */
	char    *trust_domain;  /* e.g., "example.com" */
};

/*
 * Tfetchbundle: trust_domain[s] format[1]
 *   Request trust bundle for a specific trust domain.
 *   format=0: X.509 CAs (PEM), format=1: JWT JWK Set (JSON)
 *
 * Rfetchbundle: trust_domain[s] format[1] bundle_len[4] bundle[bundle_len]
 *   Response with the trust bundle data.
 */
struct p9n_fetchbundle {
	char    *trust_domain;
	uint8_t  format;        /* p9n_bundle_format */
};

struct p9n_rfetchbundle {
	char     *trust_domain;
	uint8_t   format;
	uint32_t  bundle_len;
	uint8_t  *bundle;       /* PEM or JWK Set data */
};

/*
 * Tspiffeverify: svid_type[1] spiffe_id[s] svid_len[4] svid[svid_len]
 *   Client presents its SVID for server-side verification.
 *   svid_type=0: X.509 certificate chain (DER), svid_type=1: JWT token
 *
 * Rspiffeverify: status[1] spiffe_id[s] expiry[8]
 *   Server returns verification result.
 */
struct p9n_spiffeverify {
	uint8_t   svid_type;    /* p9n_svid_type */
	char     *spiffe_id;
	uint32_t  svid_len;
	uint8_t  *svid;         /* DER cert chain or JWT string */
};

struct p9n_rspiffeverify {
	uint8_t   status;       /* p9n_spiffe_verify_status */
	char     *spiffe_id;    /* verified SPIFFE ID */
	uint64_t  expiry;       /* SVID expiry, nanosecond unix timestamp */
};

/* ---- Transport ------------------------------------------------------ */

/*
 * Tcxlmap: fid[4] offset[8] length[8] prot[4] flags[4]
 * Rcxlmap: hpa[8] length[8] granularity[4] coherence[1]
 *   Map a file region into CXL shared memory for load/store access.
 */
struct p9n_cxlmap {
	uint32_t fid;
	uint64_t offset;
	uint64_t length;        /* 0=whole file */
	uint32_t prot;          /* PROT_READ=0x1, PROT_WRITE=0x2 */
	uint32_t flags;         /* MAP_SHARED=0x1, MAP_PRIVATE=0x2, MAP_DAX=0x4 */
};

struct p9n_rcxlmap {
	uint64_t hpa;           /* Host Physical Address on CXL device */
	uint64_t length;        /* actual mapped length */
	uint32_t granularity;   /* CXL interleave granularity (bytes) */
	uint8_t  coherence;     /* 0=software, 1=hardware, 2=hybrid */
};

/* CXL coherence modes */
#define P9N_CXL_COHERENCE_SOFTWARE  0
#define P9N_CXL_COHERENCE_HARDWARE  1
#define P9N_CXL_COHERENCE_HYBRID    2
#define P9N_CXL_COHERENCE_RELAXED   3

/* CXL map flags */
#define P9N_CXL_MAP_SHARED     0x00000001
#define P9N_CXL_MAP_PRIVATE    0x00000002
#define P9N_CXL_MAP_DAX        0x00000004

/*
 * Tcxlcoherence: fid[4] mode[1]
 * Rcxlcoherence: mode[1] snoop_id[4]
 *   Negotiate coherence mode for a CXL-mapped file.
 */
struct p9n_cxlcoherence {
	uint32_t fid;
	uint8_t  mode;
};

struct p9n_rcxlcoherence {
	uint8_t  mode;
	uint32_t snoop_id;      /* CXL snoop filter identifier, 0=N/A */
};

/*
 * Trdmatoken: fid[4] direction[1] rkey[4] addr[8] length[4]
 * Rrdmatoken: rkey[4] addr[8] length[4]
 *   Exchange RDMA memory region tokens for zero-copy data transfer.
 */
struct p9n_rdmatoken {
	uint32_t fid;
	uint8_t  direction;     /* 0=client-to-server, 1=server-to-client */
	uint32_t rkey;          /* RDMA remote key */
	uint64_t addr;          /* virtual address of memory region */
	uint32_t length;        /* region size in bytes */
};

struct p9n_rrdmatoken {
	uint32_t rkey;
	uint64_t addr;
	uint32_t length;
};

/*
 * Trdmanotify: rkey[4] addr[8] length[4] slots[2]
 * Rrdmanotify: (empty)
 *   Register a notification ring buffer for RDMA-based server push.
 */
struct p9n_rdmanotify {
	uint32_t rkey;
	uint64_t addr;
	uint32_t length;
	uint16_t slots;         /* number of slots in ring buffer */
};

/*
 * Tquicstream: stream_type[1] stream_id[8]
 * Rquicstream: stream_id[8]
 *   Bind a logical 9P channel to a specific QUIC stream.
 */
struct p9n_quicstream {
	uint8_t  stream_type;   /* 0=control, 1=data, 2=push, 3=bulk */
	uint64_t stream_id;
};

struct p9n_rquicstream {
	uint64_t stream_id;
};

/* QUIC stream types */
#define P9N_QSTREAM_CONTROL    0
#define P9N_QSTREAM_DATA       1
#define P9N_QSTREAM_PUSH       2
#define P9N_QSTREAM_BULK       3

/* ---- Performance ---------------------------------------------------- */

/* A single sub-operation inside Tcompound */
struct p9n_subop {
	uint32_t  opsize;       /* total size of this sub-op */
	uint8_t   type;         /* message type (p9_msg_t or p9n_msg_t) */
	uint8_t  *payload;      /* raw payload bytes */
	uint32_t  payload_len;
};

/* Tcompound: nops[2] ops[...] */
struct p9n_compound {
	uint16_t           nops;
	struct p9n_subop  *ops;
};

/* Rcompound: nresults[2] results[...] */
struct p9n_rcompound {
	uint16_t           nresults;
	struct p9n_subop  *results;
};

/* Tcompress: algo[1] level[1] */
struct p9n_compress {
	uint8_t algo;
	uint8_t level;
};

/* Rcompress: algo[1] */
struct p9n_rcompress {
	uint8_t algo;
};

/* Tcopyrange: srcfid[4] srcoff[8] dstfid[4] dstoff[8] count[8] flags[4] */
struct p9n_copyrange {
	uint32_t srcfid;
	uint64_t srcoff;
	uint32_t dstfid;
	uint64_t dstoff;
	uint64_t count;
	uint32_t flags;
};

/* Rcopyrange: count[8] */
struct p9n_rcopyrange {
	uint64_t count;
};

/* Tallocate: fid[4] mode[4] offset[8] length[8] */
struct p9n_allocate {
	uint32_t fid;
	uint32_t mode;
	uint64_t offset;
	uint64_t length;
};

/* Tseekhole: fid[4] type[1] offset[8] */
struct p9n_seekhole {
	uint32_t fid;
	uint8_t  type;          /* P9N_SEEK_DATA or P9N_SEEK_HOLE */
	uint64_t offset;
};

/* Rseekhole: offset[8] */
struct p9n_rseekhole {
	uint64_t offset;
};

/* Tmmaphint: fid[4] offset[8] length[8] prot[4] */
struct p9n_mmaphint {
	uint32_t fid;
	uint64_t offset;
	uint64_t length;
	uint32_t prot;
};

/* Rmmaphint: granted[1] */
struct p9n_rmmaphint {
	uint8_t granted;
};

/* ---- Filesystem semantics ------------------------------------------- */

/* Twatch: fid[4] mask[4] flags[4] */
struct p9n_watch {
	uint32_t fid;
	uint32_t mask;
	uint32_t flags;
};

/* Rwatch: watchid[4] */
struct p9n_rwatch {
	uint32_t watchid;
};

/* Tunwatch: watchid[4] */
struct p9n_unwatch {
	uint32_t watchid;
};

/* Rnotify (server-push): watchid[4] event[4] name[s] qid[13] */
struct p9n_notify {
	uint32_t        watchid;
	uint32_t        event;
	char           *name;
	struct p9n_qid  qid;
};

/* Tgetacl: fid[4] acltype[1] */
struct p9n_getacl {
	uint32_t fid;
	uint8_t  acltype;
};

/* Rgetacl: count[4] data[count] */
struct p9n_rgetacl {
	uint32_t  count;
	uint8_t  *data;
};

/* Tsetacl: fid[4] acltype[1] count[4] data[count] */
struct p9n_setacl {
	uint32_t  fid;
	uint8_t   acltype;
	uint32_t  count;
	uint8_t  *data;
};

/* Tsnapshot: fid[4] name[s] flags[4] */
struct p9n_snapshot {
	uint32_t  fid;
	char     *name;
	uint32_t  flags;
};

/* Rsnapshot: qid[13] */
struct p9n_rsnapshot {
	struct p9n_qid qid;
};

/* Tclone: srcfid[4] dstfid[4] name[s] flags[4] */
struct p9n_clone {
	uint32_t  srcfid;
	uint32_t  dstfid;
	char     *name;
	uint32_t  flags;
};

/* Rclone: qid[13] */
struct p9n_rclone {
	struct p9n_qid qid;
};

/* Txattrget: fid[4] name[s] */
struct p9n_xattrget {
	uint32_t  fid;
	char     *name;
};

/* Rxattrget: count[4] data[count] */
struct p9n_rxattrget {
	uint32_t  count;
	uint8_t  *data;
};

/* Txattrset: fid[4] name[s] count[4] data[count] flags[4] */
struct p9n_xattrset {
	uint32_t  fid;
	char     *name;
	uint32_t  count;
	uint8_t  *data;
	uint32_t  flags;
};

/* Txattrlist: fid[4] cookie[8] count[4] */
struct p9n_xattrlist {
	uint32_t  fid;
	uint64_t  cookie;
	uint32_t  count;
};

/* Rxattrlist: cookie[8] nattrs[2] names[s]... */
struct p9n_rxattrlist {
	uint64_t  cookie;
	uint16_t  nattrs;
	char    **names;
};

/* ---- Distributed systems -------------------------------------------- */

/* Tlease: fid[4] type[1] duration[4] */
struct p9n_lease {
	uint32_t fid;
	uint8_t  type;
	uint32_t duration;      /* seconds */
};

/* Rlease: leaseid[8] type[1] duration[4] */
struct p9n_rlease {
	uint64_t leaseid;
	uint8_t  type;
	uint32_t duration;
};

/* Tleaserenew: leaseid[8] duration[4] */
struct p9n_leaserenew {
	uint64_t leaseid;
	uint32_t duration;
};

/* Rleaserenew: duration[4] */
struct p9n_rleaserenew {
	uint32_t duration;
};

/* Rleasebreak (server-push): leaseid[8] newtype[1] */
struct p9n_leasebreak {
	uint64_t leaseid;
	uint8_t  newtype;
};

/* Tleaseack: leaseid[8] */
struct p9n_leaseack {
	uint64_t leaseid;
};

/* Tsession: key[16] flags[4] */
struct p9n_session {
	uint8_t  key[16];
	uint32_t flags;
};

/* Rsession: flags[4] */
struct p9n_rsession {
	uint32_t flags;
};

/* Tconsistency: fid[4] level[1] */
struct p9n_consistency {
	uint32_t fid;
	uint8_t  level;
};

/* Rconsistency: level[1] */
struct p9n_rconsistency {
	uint8_t  level;
};

/* Replica info within Rtopology */
struct p9n_replica {
	char    *addr;
	uint8_t  role;
	uint32_t latency_us;
};

/* Ttopology: fid[4] */
struct p9n_topology {
	uint32_t fid;
};

/* Rtopology: nreplicas[2] replicas[...] */
struct p9n_rtopology {
	uint16_t            nreplicas;
	struct p9n_replica *replicas;
};

/* ---- Observability -------------------------------------------------- */

/* Ttraceattr: nattrs[2] key[s] value[s] ... */
struct p9n_traceattr {
	uint16_t  nattrs;
	char    **keys;
	char    **values;
};

/* Thealth: (empty payload) */
/* Rhealth: status[1] load[4] nmetrics[2] name[s] value[8] ... */
struct p9n_metric {
	char    *name;
	uint64_t value;
};

struct p9n_rhealth {
	uint8_t             status;
	uint32_t            load;       /* 0-10000 = 0.00%-100.00% */
	uint16_t            nmetrics;
	struct p9n_metric  *metrics;
};

/* Tserverstats: mask[8] */
struct p9n_serverstats_req {
	uint64_t mask;
};

/* Rserverstats: nstats[2] name[s] type[1] value[8] ... */
struct p9n_server_stat {
	char    *name;
	uint8_t  type;
	uint64_t value;
};

struct p9n_rserverstats {
	uint16_t                nstats;
	struct p9n_server_stat *stats;
};

/* ---- Resource management -------------------------------------------- */

/* Tgetquota: fid[4] type[1] */
struct p9n_getquota {
	uint32_t fid;
	uint8_t  type;
};

/* Rgetquota: bytesused[8] byteslimit[8] filesused[8] fileslimit[8] grace[4] */
struct p9n_rgetquota {
	uint64_t bytes_used;
	uint64_t bytes_limit;
	uint64_t files_used;
	uint64_t files_limit;
	uint32_t grace_period;  /* seconds */
};

/* Tsetquota: fid[4] type[1] byteslimit[8] fileslimit[8] grace[4] */
struct p9n_setquota {
	uint32_t fid;
	uint8_t  type;
	uint64_t bytes_limit;
	uint64_t files_limit;
	uint32_t grace_period;
};

/* Tratelimit: fid[4] iops[4] bps[8] */
struct p9n_ratelimit {
	uint32_t fid;
	uint32_t iops;          /* 0=unlimited */
	uint64_t bps;           /* 0=unlimited */
};

/* Rratelimit: iops[4] bps[8] */
struct p9n_rratelimit {
	uint32_t iops;
	uint64_t bps;
};

/* ---- Streaming/Async ------------------------------------------------ */

/* Tasync wraps another T-message: innertype[1] payload[...] */
struct p9n_async {
	uint8_t   innertype;
	uint8_t  *payload;
	uint32_t  payload_len;
};

/* Rasync: opid[8] status[1] */
struct p9n_rasync {
	uint64_t opid;
	uint8_t  status;
};

/* Tpoll: opid[8] */
struct p9n_poll {
	uint64_t opid;
};

/* Rpoll: status[1] progress[4] payload[...] */
struct p9n_rpoll {
	uint8_t   status;
	uint32_t  progress;     /* 0-10000 */
	uint8_t  *payload;      /* R-message payload when complete */
	uint32_t  payload_len;
};

/* Tstreamopen: fid[4] direction[1] offset[8] count[8] */
struct p9n_streamopen {
	uint32_t fid;
	uint8_t  direction;
	uint64_t offset;
	uint64_t count;
};

/* Rstreamopen: streamid[4] */
struct p9n_rstreamopen {
	uint32_t streamid;
};

/* Tstreamdata / Rstreamdata: streamid[4] seq[4] count[4] data[count] */
struct p9n_streamdata {
	uint32_t  streamid;
	uint32_t  seq;
	uint32_t  count;
	uint8_t  *data;
};

/* Tstreamclose: streamid[4] */
struct p9n_streamclose {
	uint32_t streamid;
};

/* ---- Content-awareness ---------------------------------------------- */

/* Tsearch: fid[4] query[s] flags[4] maxresults[4] cookie[8] */
struct p9n_search {
	uint32_t  fid;
	char     *query;
	uint32_t  flags;
	uint32_t  maxresults;
	uint64_t  cookie;
};

/* Search result entry */
struct p9n_search_entry {
	struct p9n_qid qid;
	char          *name;
	uint32_t       score;   /* 0-10000 relevance */
};

/* Rsearch: cookie[8] nresults[2] entries[...] */
struct p9n_rsearch {
	uint64_t                  cookie;
	uint16_t                  nresults;
	struct p9n_search_entry  *entries;
};

/* Thash: fid[4] algo[1] offset[8] length[8] */
struct p9n_hash {
	uint32_t fid;
	uint8_t  algo;
	uint64_t offset;
	uint64_t length;        /* 0=whole file */
};

/* Rhash: algo[1] hashlen[2] hash[hashlen] */
struct p9n_rhash {
	uint8_t   algo;
	uint16_t  hashlen;
	uint8_t  *hash;
};

/* ======================================================================
 * Unified Message Container (fcall)
 * ====================================================================== */

struct p9n_fcall {
	uint32_t size;          /* total wire size including this field */
	uint8_t  type;          /* p9n_msg_t */
	uint16_t tag;

	union {
		/* Negotiation */
		struct p9n_caps         caps;

		/* Security */
		struct p9n_authneg      authneg;
		struct p9n_rauthneg     rauthneg;
		struct p9n_capgrant     capgrant;
		struct p9n_rcapgrant    rcapgrant;
		struct p9n_capuse       capuse;
		struct p9n_rcapuse      rcapuse;
		struct p9n_auditctl     auditctl;

		/* SPIFFE */
		struct p9n_startls_spiffe  startls_spiffe;
		struct p9n_fetchbundle     fetchbundle;
		struct p9n_rfetchbundle    rfetchbundle;
		struct p9n_spiffeverify    spiffeverify;
		struct p9n_rspiffeverify   rspiffeverify;

		/* Transport */
		struct p9n_cxlmap       cxlmap;
		struct p9n_rcxlmap      rcxlmap;
		struct p9n_cxlcoherence cxlcoherence;
		struct p9n_rcxlcoherence rcxlcoherence;
		struct p9n_rdmatoken    rdmatoken;
		struct p9n_rrdmatoken   rrdmatoken;
		struct p9n_rdmanotify   rdmanotify;
		struct p9n_quicstream   quicstream;
		struct p9n_rquicstream  rquicstream;

		/* Performance */
		struct p9n_compound     compound;
		struct p9n_rcompound    rcompound;
		struct p9n_compress     compress;
		struct p9n_rcompress    rcompress;
		struct p9n_copyrange    copyrange;
		struct p9n_rcopyrange   rcopyrange;
		struct p9n_allocate     allocate;
		struct p9n_seekhole     seekhole;
		struct p9n_rseekhole    rseekhole;
		struct p9n_mmaphint     mmaphint;
		struct p9n_rmmaphint    rmmaphint;

		/* Filesystem */
		struct p9n_watch        watch;
		struct p9n_rwatch       rwatch;
		struct p9n_unwatch      unwatch;
		struct p9n_notify       notify;
		struct p9n_getacl       getacl;
		struct p9n_rgetacl      rgetacl;
		struct p9n_setacl       setacl;
		struct p9n_snapshot     snapshot;
		struct p9n_rsnapshot    rsnapshot;
		struct p9n_clone        clone;
		struct p9n_rclone       rclone;
		struct p9n_xattrget     xattrget;
		struct p9n_rxattrget    rxattrget;
		struct p9n_xattrset     xattrset;
		struct p9n_xattrlist    xattrlist;
		struct p9n_rxattrlist   rxattrlist;

		/* Distributed */
		struct p9n_lease        lease;
		struct p9n_rlease       rlease;
		struct p9n_leaserenew   leaserenew;
		struct p9n_rleaserenew  rleaserenew;
		struct p9n_leasebreak   leasebreak;
		struct p9n_leaseack     leaseack;
		struct p9n_session      session;
		struct p9n_rsession     rsession;
		struct p9n_consistency  consist;
		struct p9n_rconsistency rconsist;
		struct p9n_topology     topology;
		struct p9n_rtopology    rtopology;

		/* Observability */
		struct p9n_traceattr    traceattr;
		struct p9n_rhealth      rhealth;
		struct p9n_serverstats_req serverstats_req;
		struct p9n_rserverstats rserverstats;

		/* Resource management */
		struct p9n_getquota     getquota;
		struct p9n_rgetquota    rgetquota;
		struct p9n_setquota     setquota;
		struct p9n_ratelimit    ratelimit;
		struct p9n_rratelimit   rratelimit;

		/* Streaming */
		struct p9n_async        async;
		struct p9n_rasync       rasync;
		struct p9n_poll         poll;
		struct p9n_rpoll        rpoll;
		struct p9n_streamopen   streamopen;
		struct p9n_rstreamopen  rstreamopen;
		struct p9n_streamdata   streamdata;
		struct p9n_streamclose  streamclose;

		/* Content */
		struct p9n_search       search;
		struct p9n_rsearch      rsearch;
		struct p9n_hash         hash;
		struct p9n_rhash        rhash;
	} u;
};

/* ======================================================================
 * Buffer: growable byte buffer for marshalling
 * ====================================================================== */

struct p9n_buf {
	uint8_t *data;
	size_t   len;
	size_t   cap;
	size_t   pos;           /* read cursor */
};

/* ======================================================================
 * Capability Set: tracks negotiated capabilities
 * ====================================================================== */

struct p9n_capset {
	p9n_capset_t  bits;     /* fast bitmask lookup */
	uint16_t      ncaps;    /* number of raw string caps */
	char        **caps;     /* original string caps (for extensions) */
};

/* ======================================================================
 * API: Buffer operations
 * ====================================================================== */

int  p9n_buf_init(struct p9n_buf *buf, size_t initial_cap);
void p9n_buf_free(struct p9n_buf *buf);
void p9n_buf_reset(struct p9n_buf *buf);
int  p9n_buf_ensure(struct p9n_buf *buf, size_t additional);

/* Write primitives */
int  p9n_buf_put_u8(struct p9n_buf *buf, uint8_t val);
int  p9n_buf_put_u16(struct p9n_buf *buf, uint16_t val);
int  p9n_buf_put_u32(struct p9n_buf *buf, uint32_t val);
int  p9n_buf_put_u64(struct p9n_buf *buf, uint64_t val);
int  p9n_buf_put_str(struct p9n_buf *buf, const char *s);
int  p9n_buf_put_data(struct p9n_buf *buf, const void *data, uint32_t len);

/* Read primitives */
int  p9n_buf_get_u8(struct p9n_buf *buf, uint8_t *val);
int  p9n_buf_get_u16(struct p9n_buf *buf, uint16_t *val);
int  p9n_buf_get_u32(struct p9n_buf *buf, uint32_t *val);
int  p9n_buf_get_u64(struct p9n_buf *buf, uint64_t *val);
int  p9n_buf_get_str(struct p9n_buf *buf, char **s);
int  p9n_buf_get_data(struct p9n_buf *buf, uint8_t **data, uint32_t *len);

/* ======================================================================
 * API: Capability negotiation
 * ====================================================================== */

void p9n_capset_init(struct p9n_capset *cs);
void p9n_capset_free(struct p9n_capset *cs);
int  p9n_capset_add(struct p9n_capset *cs, const char *cap);
int  p9n_capset_has(const struct p9n_capset *cs, const char *cap);
int  p9n_capset_has_bit(const struct p9n_capset *cs, enum p9n_cap_bit bit);

/* Resolve capability string to bit index, or -1 if unknown */
int  p9n_cap_to_bit(const char *cap);

/* Intersect client and server capabilities */
int  p9n_capset_intersect(struct p9n_capset *result,
                          const struct p9n_capset *client,
                          const struct p9n_capset *server);

/* ======================================================================
 * API: Message marshalling (encode to wire)
 * ====================================================================== */

int  p9n_marshal_caps(struct p9n_buf *buf, uint16_t tag,
                      const struct p9n_caps *caps);
int  p9n_marshal_startls(struct p9n_buf *buf, uint16_t tag);
int  p9n_marshal_authneg(struct p9n_buf *buf, uint16_t tag,
                         const struct p9n_authneg *an);
int  p9n_marshal_rauthneg(struct p9n_buf *buf, uint16_t tag,
                          const struct p9n_rauthneg *ran);

/* SPIFFE messages */
int  p9n_marshal_startls_spiffe(struct p9n_buf *buf, uint16_t tag,
                                const struct p9n_startls_spiffe *ss);
int  p9n_marshal_fetchbundle(struct p9n_buf *buf, uint16_t tag,
                             const struct p9n_fetchbundle *fb);
int  p9n_marshal_rfetchbundle(struct p9n_buf *buf, uint16_t tag,
                              const struct p9n_rfetchbundle *rfb);
int  p9n_marshal_spiffeverify(struct p9n_buf *buf, uint16_t tag,
                              const struct p9n_spiffeverify *sv);
int  p9n_marshal_rspiffeverify(struct p9n_buf *buf, uint16_t tag,
                               const struct p9n_rspiffeverify *rsv);

/* Transport messages */
int  p9n_marshal_cxlmap(struct p9n_buf *buf, uint16_t tag,
                        const struct p9n_cxlmap *cm);
int  p9n_marshal_rcxlmap(struct p9n_buf *buf, uint16_t tag,
                         const struct p9n_rcxlmap *rcm);
int  p9n_marshal_cxlcoherence(struct p9n_buf *buf, uint16_t tag,
                              const struct p9n_cxlcoherence *cc);
int  p9n_marshal_rdmatoken(struct p9n_buf *buf, uint16_t tag,
                           const struct p9n_rdmatoken *rt);
int  p9n_marshal_rrdmatoken(struct p9n_buf *buf, uint16_t tag,
                            const struct p9n_rrdmatoken *rrt);
int  p9n_marshal_rdmanotify(struct p9n_buf *buf, uint16_t tag,
                            const struct p9n_rdmanotify *rn);
int  p9n_marshal_quicstream(struct p9n_buf *buf, uint16_t tag,
                            const struct p9n_quicstream *qs);

int  p9n_marshal_compound(struct p9n_buf *buf, uint16_t tag,
                          const struct p9n_compound *comp);
int  p9n_marshal_rcompound(struct p9n_buf *buf, uint16_t tag,
                           const struct p9n_rcompound *rcomp);

int  p9n_marshal_compress(struct p9n_buf *buf, uint16_t tag,
                          const struct p9n_compress *comp);
int  p9n_marshal_copyrange(struct p9n_buf *buf, uint16_t tag,
                           const struct p9n_copyrange *cr);
int  p9n_marshal_allocate(struct p9n_buf *buf, uint16_t tag,
                          const struct p9n_allocate *alloc);
int  p9n_marshal_seekhole(struct p9n_buf *buf, uint16_t tag,
                          const struct p9n_seekhole *sh);

int  p9n_marshal_watch(struct p9n_buf *buf, uint16_t tag,
                       const struct p9n_watch *w);
int  p9n_marshal_unwatch(struct p9n_buf *buf, uint16_t tag,
                         const struct p9n_unwatch *uw);
int  p9n_marshal_notify(struct p9n_buf *buf,
                        const struct p9n_notify *n);

int  p9n_marshal_lease(struct p9n_buf *buf, uint16_t tag,
                       const struct p9n_lease *l);
int  p9n_marshal_leaserenew(struct p9n_buf *buf, uint16_t tag,
                            const struct p9n_leaserenew *lr);
int  p9n_marshal_leaseack(struct p9n_buf *buf, uint16_t tag,
                          const struct p9n_leaseack *la);
int  p9n_marshal_leasebreak(struct p9n_buf *buf,
                            const struct p9n_leasebreak *lb);

int  p9n_marshal_session(struct p9n_buf *buf, uint16_t tag,
                         const struct p9n_session *s);

int  p9n_marshal_hash(struct p9n_buf *buf, uint16_t tag,
                      const struct p9n_hash *h);

/* ======================================================================
 * API: Message unmarshalling (decode from wire)
 * ====================================================================== */

int  p9n_unmarshal(struct p9n_buf *buf, struct p9n_fcall *fc);

/* ======================================================================
 * API: Fcall lifecycle
 * ====================================================================== */

void p9n_fcall_free(struct p9n_fcall *fc);

/* ======================================================================
 * API: Message type name lookup (for debugging)
 * ====================================================================== */

const char *p9n_msg_name(uint8_t type);

#ifdef __cplusplus
}
#endif

#endif /* P9N_H */
