/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for 9P2000.N protocol implementation.
 *
 * Tests cover: buffer primitives, capability negotiation, message
 * marshal/unmarshal round-trip for all P0 message types, compound
 * operations, and server-push messages.
 */

#include "../include/9pN.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
	do { \
		tests_run++; \
		printf("  %-50s ", #name); \
		fflush(stdout); \
	} while (0)

#define PASS() \
	do { \
		tests_passed++; \
		printf("[OK]\n"); \
	} while (0)

#define FAIL(msg) \
	do { \
		printf("[FAIL] %s\n", msg); \
	} while (0)

#define ASSERT(cond, msg) \
	do { \
		if (!(cond)) { \
			FAIL(msg); \
			return; \
		} \
	} while (0)

/* ======================================================================
 * Buffer tests
 * ====================================================================== */

static void test_buf_u8(void)
{
	TEST(buf_put_get_u8);
	struct p9n_buf buf;
	assert(p9n_buf_init(&buf, 64) == 0);

	p9n_buf_put_u8(&buf, 0x42);
	p9n_buf_put_u8(&buf, 0xFF);

	uint8_t a, b;
	p9n_buf_get_u8(&buf, &a);
	p9n_buf_get_u8(&buf, &b);

	ASSERT(a == 0x42, "u8 first value");
	ASSERT(b == 0xFF, "u8 second value");

	p9n_buf_free(&buf);
	PASS();
}

static void test_buf_u16(void)
{
	TEST(buf_put_get_u16_le);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 64);

	p9n_buf_put_u16(&buf, 0x1234);

	/* Verify little-endian on wire */
	ASSERT(buf.data[0] == 0x34, "LE low byte");
	ASSERT(buf.data[1] == 0x12, "LE high byte");

	uint16_t val;
	p9n_buf_get_u16(&buf, &val);
	ASSERT(val == 0x1234, "u16 round-trip");

	p9n_buf_free(&buf);
	PASS();
}

static void test_buf_u32(void)
{
	TEST(buf_put_get_u32_le);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 64);

	p9n_buf_put_u32(&buf, 0xDEADBEEF);

	uint32_t val;
	p9n_buf_get_u32(&buf, &val);
	ASSERT(val == 0xDEADBEEF, "u32 round-trip");

	p9n_buf_free(&buf);
	PASS();
}

static void test_buf_u64(void)
{
	TEST(buf_put_get_u64_le);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 64);

	p9n_buf_put_u64(&buf, 0x0102030405060708ULL);

	uint64_t val;
	p9n_buf_get_u64(&buf, &val);
	ASSERT(val == 0x0102030405060708ULL, "u64 round-trip");

	p9n_buf_free(&buf);
	PASS();
}

static void test_buf_str(void)
{
	TEST(buf_put_get_str);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 64);

	p9n_buf_put_str(&buf, "hello");

	/* Wire: len[2]=5 + "hello" */
	ASSERT(buf.len == 7, "string wire size");

	char *s;
	p9n_buf_get_str(&buf, &s);
	ASSERT(strcmp(s, "hello") == 0, "string content");
	free(s);

	p9n_buf_free(&buf);
	PASS();
}

static void test_buf_empty_str(void)
{
	TEST(buf_put_get_empty_str);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 64);

	p9n_buf_put_str(&buf, "");

	char *s;
	p9n_buf_get_str(&buf, &s);
	ASSERT(strcmp(s, "") == 0, "empty string");
	free(s);

	p9n_buf_free(&buf);
	PASS();
}

static void test_buf_grow(void)
{
	TEST(buf_auto_grow);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 4);

	/* Write more than initial capacity */
	for (int i = 0; i < 100; i++)
		p9n_buf_put_u32(&buf, (uint32_t)i);

	ASSERT(buf.len == 400, "grow length");
	ASSERT(buf.cap >= 400, "grow capacity");

	/* Verify data integrity after grow */
	uint32_t val;
	p9n_buf_get_u32(&buf, &val);
	ASSERT(val == 0, "first value after grow");

	p9n_buf_free(&buf);
	PASS();
}

static void test_buf_underflow(void)
{
	TEST(buf_read_underflow);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 64);

	p9n_buf_put_u8(&buf, 0x42);

	uint16_t val;
	int rc = p9n_buf_get_u16(&buf, &val);
	ASSERT(rc == -5, "underflow returns -EIO");  /* EIO = 5 */

	p9n_buf_free(&buf);
	PASS();
}

/* ======================================================================
 * Capability tests
 * ====================================================================== */

static void test_capset_basic(void)
{
	TEST(capset_add_has);
	struct p9n_capset cs;
	p9n_capset_init(&cs);

	p9n_capset_add(&cs, P9N_CAP_TLS);
	p9n_capset_add(&cs, P9N_CAP_COMPOUND);
	p9n_capset_add(&cs, P9N_CAP_WATCH);

	ASSERT(p9n_capset_has(&cs, P9N_CAP_TLS), "has TLS");
	ASSERT(p9n_capset_has(&cs, P9N_CAP_COMPOUND), "has compound");
	ASSERT(p9n_capset_has(&cs, P9N_CAP_WATCH), "has watch");
	ASSERT(!p9n_capset_has(&cs, P9N_CAP_LEASE), "not has lease");

	p9n_capset_free(&cs);
	PASS();
}

static void test_capset_bitmask(void)
{
	TEST(capset_bitmask_fast_path);
	struct p9n_capset cs;
	p9n_capset_init(&cs);

	p9n_capset_add(&cs, P9N_CAP_HASH);
	p9n_capset_add(&cs, P9N_CAP_SESSION);

	ASSERT(p9n_capset_has_bit(&cs, P9N_CBIT_HASH), "bit HASH set");
	ASSERT(p9n_capset_has_bit(&cs, P9N_CBIT_SESSION), "bit SESSION set");
	ASSERT(!p9n_capset_has_bit(&cs, P9N_CBIT_TLS), "bit TLS not set");

	p9n_capset_free(&cs);
	PASS();
}

static void test_capset_intersect(void)
{
	TEST(capset_intersect);
	struct p9n_capset client, server, result;
	p9n_capset_init(&client);
	p9n_capset_init(&server);

	p9n_capset_add(&client, P9N_CAP_TLS);
	p9n_capset_add(&client, P9N_CAP_COMPOUND);
	p9n_capset_add(&client, P9N_CAP_WATCH);
	p9n_capset_add(&client, P9N_CAP_LEASE);

	p9n_capset_add(&server, P9N_CAP_COMPOUND);
	p9n_capset_add(&server, P9N_CAP_WATCH);
	p9n_capset_add(&server, P9N_CAP_HEALTH);

	p9n_capset_intersect(&result, &client, &server);

	ASSERT(result.ncaps == 2, "intersection count");
	ASSERT(p9n_capset_has(&result, P9N_CAP_COMPOUND), "has compound");
	ASSERT(p9n_capset_has(&result, P9N_CAP_WATCH), "has watch");
	ASSERT(!p9n_capset_has(&result, P9N_CAP_TLS), "not has TLS");
	ASSERT(!p9n_capset_has(&result, P9N_CAP_HEALTH), "not has health");

	p9n_capset_free(&client);
	p9n_capset_free(&server);
	p9n_capset_free(&result);
	PASS();
}

static void test_capset_dedup(void)
{
	TEST(capset_dedup);
	struct p9n_capset cs;
	p9n_capset_init(&cs);

	p9n_capset_add(&cs, P9N_CAP_TLS);
	p9n_capset_add(&cs, P9N_CAP_TLS);
	p9n_capset_add(&cs, P9N_CAP_TLS);

	ASSERT(cs.ncaps == 1, "dedup count");

	p9n_capset_free(&cs);
	PASS();
}

static void test_cap_to_bit(void)
{
	TEST(cap_string_to_bit);

	ASSERT(p9n_cap_to_bit(P9N_CAP_TLS) == P9N_CBIT_TLS, "TLS bit");
	ASSERT(p9n_cap_to_bit(P9N_CAP_HASH) == P9N_CBIT_HASH, "HASH bit");
	ASSERT(p9n_cap_to_bit("unknown.cap") == -1, "unknown returns -1");

	PASS();
}

/* ======================================================================
 * Marshal/Unmarshal round-trip tests
 * ====================================================================== */

static void test_caps_roundtrip(void)
{
	TEST(caps_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 256);

	/* Build Tcaps */
	char *cap_list[] = { "security.tls", "perf.compound", "fs.watch" };
	struct p9n_caps caps = { .ncaps = 3, .caps = cap_list };
	int rc = p9n_marshal_caps(&buf, 1, &caps);
	ASSERT(rc == 0, "marshal caps");

	/* Unmarshal */
	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal caps");
	ASSERT(fc.type == P9N_TCAPS, "type is Tcaps");
	ASSERT(fc.tag == 1, "tag preserved");
	ASSERT(fc.u.caps.ncaps == 3, "3 caps");
	ASSERT(strcmp(fc.u.caps.caps[0], "security.tls") == 0, "cap 0");
	ASSERT(strcmp(fc.u.caps.caps[1], "perf.compound") == 0, "cap 1");
	ASSERT(strcmp(fc.u.caps.caps[2], "fs.watch") == 0, "cap 2");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_startls_roundtrip(void)
{
	TEST(startls_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 64);

	int rc = p9n_marshal_startls(&buf, 42);
	ASSERT(rc == 0, "marshal startls");

	/* Verify minimal message: size[4]=7 type[1]=130 tag[2]=42 */
	ASSERT(buf.len == 7, "startls wire size");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal startls");
	ASSERT(fc.type == P9N_TSTARTLS, "type is Tstartls");
	ASSERT(fc.tag == 42, "tag");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_watch_roundtrip(void)
{
	TEST(watch_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 128);

	struct p9n_watch w = {
		.fid = 100,
		.mask = P9N_WATCH_CREATE | P9N_WATCH_MODIFY,
		.flags = P9N_WATCH_RECURSIVE,
	};
	int rc = p9n_marshal_watch(&buf, 7, &w);
	ASSERT(rc == 0, "marshal watch");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal watch");
	ASSERT(fc.type == P9N_TWATCH, "type");
	ASSERT(fc.tag == 7, "tag");
	ASSERT(fc.u.watch.fid == 100, "fid");
	ASSERT(fc.u.watch.mask == (P9N_WATCH_CREATE | P9N_WATCH_MODIFY), "mask");
	ASSERT(fc.u.watch.flags == P9N_WATCH_RECURSIVE, "flags");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_notify_roundtrip(void)
{
	TEST(notify_server_push_roundtrip);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 128);

	struct p9n_notify n = {
		.watchid = 42,
		.event = P9N_WATCH_CREATE,
		.name = "newfile.txt",
		.qid = { .type = 0, .version = 1, .path = 12345 },
	};
	int rc = p9n_marshal_notify(&buf, &n);
	ASSERT(rc == 0, "marshal notify");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal notify");
	ASSERT(fc.type == P9N_RNOTIFY, "type is Rnotify");
	ASSERT(fc.tag == P9_NOTAG, "tag is NOTAG (server-push)");
	ASSERT(fc.u.notify.watchid == 42, "watchid");
	ASSERT(fc.u.notify.event == P9N_WATCH_CREATE, "event");
	ASSERT(strcmp(fc.u.notify.name, "newfile.txt") == 0, "name");
	ASSERT(fc.u.notify.qid.path == 12345, "qid.path");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_lease_roundtrip(void)
{
	TEST(lease_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 128);

	struct p9n_lease l = {
		.fid = 200,
		.type = P9N_LEASE_WRITE,
		.duration = 30,
	};
	int rc = p9n_marshal_lease(&buf, 10, &l);
	ASSERT(rc == 0, "marshal lease");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal lease");
	ASSERT(fc.type == P9N_TLEASE, "type");
	ASSERT(fc.u.lease.fid == 200, "fid");
	ASSERT(fc.u.lease.type == P9N_LEASE_WRITE, "type write");
	ASSERT(fc.u.lease.duration == 30, "duration");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_leasebreak_roundtrip(void)
{
	TEST(leasebreak_server_push_roundtrip);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 64);

	struct p9n_leasebreak lb = {
		.leaseid = 0x1234567890ABCDEFULL,
		.newtype = P9N_LEASE_READ,
	};
	int rc = p9n_marshal_leasebreak(&buf, &lb);
	ASSERT(rc == 0, "marshal leasebreak");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal leasebreak");
	ASSERT(fc.type == P9N_RLEASEBREAK, "type");
	ASSERT(fc.tag == P9_NOTAG, "NOTAG");
	ASSERT(fc.u.leasebreak.leaseid == 0x1234567890ABCDEFULL, "leaseid");
	ASSERT(fc.u.leasebreak.newtype == P9N_LEASE_READ, "newtype");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_session_roundtrip(void)
{
	TEST(session_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 64);

	struct p9n_session s;
	memset(s.key, 0xAB, 16);
	s.flags = P9N_SESSION_FIDS | P9N_SESSION_LEASES;

	int rc = p9n_marshal_session(&buf, 5, &s);
	ASSERT(rc == 0, "marshal session");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal session");
	ASSERT(fc.type == P9N_TSESSION, "type");
	ASSERT(fc.u.session.key[0] == 0xAB, "key[0]");
	ASSERT(fc.u.session.key[15] == 0xAB, "key[15]");
	ASSERT(fc.u.session.flags == (P9N_SESSION_FIDS | P9N_SESSION_LEASES),
	       "flags");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_compound_roundtrip(void)
{
	TEST(compound_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 256);

	/* Build a simple compound with 2 sub-ops */
	uint8_t payload1[] = { 0x01, 0x02, 0x03 };
	uint8_t payload2[] = { 0x04, 0x05 };

	struct p9n_subop ops[2] = {
		{ .opsize = P9N_SUBOP_HDRSZ + 3, .type = 110, /* Twalk */
		  .payload = payload1, .payload_len = 3 },
		{ .opsize = P9N_SUBOP_HDRSZ + 2, .type = 116, /* Tread */
		  .payload = payload2, .payload_len = 2 },
	};

	struct p9n_compound comp = { .nops = 2, .ops = ops };
	int rc = p9n_marshal_compound(&buf, 99, &comp);
	ASSERT(rc == 0, "marshal compound");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal compound");
	ASSERT(fc.type == P9N_TCOMPOUND, "type");
	ASSERT(fc.tag == 99, "tag");
	ASSERT(fc.u.compound.nops == 2, "nops");
	ASSERT(fc.u.compound.ops[0].type == 110, "op0 type");
	ASSERT(fc.u.compound.ops[0].payload_len == 3, "op0 plen");
	ASSERT(fc.u.compound.ops[0].payload[0] == 0x01, "op0 data");
	ASSERT(fc.u.compound.ops[1].type == 116, "op1 type");
	ASSERT(fc.u.compound.ops[1].payload_len == 2, "op1 plen");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_hash_roundtrip(void)
{
	TEST(hash_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 64);

	struct p9n_hash h = {
		.fid = 55,
		.algo = P9N_HASH_BLAKE3,
		.offset = 0,
		.length = 0,  /* whole file */
	};
	int rc = p9n_marshal_hash(&buf, 20, &h);
	ASSERT(rc == 0, "marshal hash");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal hash");
	ASSERT(fc.type == P9N_THASH, "type");
	ASSERT(fc.u.hash.fid == 55, "fid");
	ASSERT(fc.u.hash.algo == P9N_HASH_BLAKE3, "algo");
	ASSERT(fc.u.hash.length == 0, "whole file");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_compress_roundtrip(void)
{
	TEST(compress_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 64);

	struct p9n_compress comp = {
		.algo = P9N_COMPRESS_ZSTD,
		.level = 3,
	};
	int rc = p9n_marshal_compress(&buf, 15, &comp);
	ASSERT(rc == 0, "marshal compress");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal compress");
	ASSERT(fc.type == P9N_TCOMPRESS, "type");
	ASSERT(fc.u.compress.algo == P9N_COMPRESS_ZSTD, "algo");
	ASSERT(fc.u.compress.level == 3, "level");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_copyrange_roundtrip(void)
{
	TEST(copyrange_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 128);

	struct p9n_copyrange cr = {
		.srcfid = 10,
		.srcoff = 1024,
		.dstfid = 20,
		.dstoff = 0,
		.count = 65536,
		.flags = P9N_COPY_REFLINK,
	};
	int rc = p9n_marshal_copyrange(&buf, 30, &cr);
	ASSERT(rc == 0, "marshal copyrange");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal copyrange");
	ASSERT(fc.u.copyrange.srcfid == 10, "srcfid");
	ASSERT(fc.u.copyrange.srcoff == 1024, "srcoff");
	ASSERT(fc.u.copyrange.dstfid == 20, "dstfid");
	ASSERT(fc.u.copyrange.count == 65536, "count");
	ASSERT(fc.u.copyrange.flags == P9N_COPY_REFLINK, "reflink flag");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_allocate_roundtrip(void)
{
	TEST(allocate_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 128);

	struct p9n_allocate alloc = {
		.fid = 77,
		.mode = P9N_FALLOC_PUNCH_HOLE | P9N_FALLOC_KEEP_SIZE,
		.offset = 4096,
		.length = 8192,
	};
	int rc = p9n_marshal_allocate(&buf, 40, &alloc);
	ASSERT(rc == 0, "marshal allocate");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal allocate");
	ASSERT(fc.u.allocate.fid == 77, "fid");
	ASSERT(fc.u.allocate.mode == (P9N_FALLOC_PUNCH_HOLE | P9N_FALLOC_KEEP_SIZE),
	       "mode");
	ASSERT(fc.u.allocate.offset == 4096, "offset");
	ASSERT(fc.u.allocate.length == 8192, "length");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_authneg_roundtrip(void)
{
	TEST(authneg_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 256);

	char *mechs[] = { "SASL-SCRAM-SHA-256", "mTLS", "P9any" };
	struct p9n_authneg an = { .nmechs = 3, .mechs = mechs };
	int rc = p9n_marshal_authneg(&buf, 2, &an);
	ASSERT(rc == 0, "marshal authneg");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal authneg");
	ASSERT(fc.type == P9N_TAUTHNEG, "type");
	ASSERT(fc.u.authneg.nmechs == 3, "nmechs");
	ASSERT(strcmp(fc.u.authneg.mechs[0], "SASL-SCRAM-SHA-256") == 0, "mech0");
	ASSERT(strcmp(fc.u.authneg.mechs[1], "mTLS") == 0, "mech1");
	ASSERT(strcmp(fc.u.authneg.mechs[2], "P9any") == 0, "mech2");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

/* ======================================================================
 * Message name lookup
 * ====================================================================== */

static void test_msg_names(void)
{
	TEST(msg_name_lookup);

	ASSERT(strcmp(p9n_msg_name(P9N_TCAPS), "Tcaps") == 0, "Tcaps");
	ASSERT(strcmp(p9n_msg_name(P9N_RNOTIFY), "Rnotify") == 0, "Rnotify");
	ASSERT(strcmp(p9n_msg_name(P9N_TCOMPOUND), "Tcompound") == 0, "Tcompound");
	ASSERT(strcmp(p9n_msg_name(P9N_RLEASEBREAK), "Rleasebreak") == 0,
	       "Rleasebreak");
	ASSERT(strcmp(p9n_msg_name(0), "unknown") == 0, "unknown type");

	PASS();
}

/* ======================================================================
 * Wire size verification
 * ====================================================================== */

static void test_wire_header_size(void)
{
	TEST(wire_header_7_bytes);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 64);

	/* Tstartls has empty payload, so total wire size should be exactly 7 */
	p9n_marshal_startls(&buf, 0);
	ASSERT(buf.len == P9_HDRSZ, "minimal message = 7 bytes");

	/* Verify size field in the message itself */
	uint32_t size = buf.data[0]
	              | (buf.data[1] << 8)
	              | (buf.data[2] << 16)
	              | (buf.data[3] << 24);
	ASSERT(size == 7, "size field = 7");

	p9n_buf_free(&buf);
	PASS();
}

/* ======================================================================
 * SPIFFE integration tests
 * ====================================================================== */

static void test_spiffe_capability(void)
{
	TEST(spiffe_capability_negotiation);
	struct p9n_capset client, server, result;
	p9n_capset_init(&client);
	p9n_capset_init(&server);

	p9n_capset_add(&client, P9N_CAP_SPIFFE);
	p9n_capset_add(&client, P9N_CAP_TLS);
	p9n_capset_add(&client, P9N_CAP_AUTH);

	p9n_capset_add(&server, P9N_CAP_SPIFFE);
	p9n_capset_add(&server, P9N_CAP_TLS);

	p9n_capset_intersect(&result, &client, &server);

	ASSERT(p9n_capset_has(&result, P9N_CAP_SPIFFE), "SPIFFE negotiated");
	ASSERT(p9n_capset_has(&result, P9N_CAP_TLS), "TLS negotiated");
	ASSERT(!p9n_capset_has(&result, P9N_CAP_AUTH), "AUTH not in server");
	ASSERT(p9n_capset_has_bit(&result, P9N_CBIT_SPIFFE), "SPIFFE bit set");

	p9n_capset_free(&client);
	p9n_capset_free(&server);
	p9n_capset_free(&result);
	PASS();
}

static void test_startls_spiffe_roundtrip(void)
{
	TEST(startls_spiffe_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 256);

	struct p9n_startls_spiffe ss = {
		.spiffe_id = "spiffe://example.com/server/web-frontend",
		.trust_domain = "example.com",
	};
	int rc = p9n_marshal_startls_spiffe(&buf, 3, &ss);
	ASSERT(rc == 0, "marshal startls_spiffe");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal startls_spiffe");
	ASSERT(fc.type == P9N_TSTARTLS_SPIFFE, "type");
	ASSERT(fc.tag == 3, "tag");
	ASSERT(strcmp(fc.u.startls_spiffe.spiffe_id,
	       "spiffe://example.com/server/web-frontend") == 0, "spiffe_id");
	ASSERT(strcmp(fc.u.startls_spiffe.trust_domain,
	       "example.com") == 0, "trust_domain");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_fetchbundle_roundtrip(void)
{
	TEST(fetchbundle_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 256);

	/* Request X.509 trust bundle */
	struct p9n_fetchbundle fb = {
		.trust_domain = "prod.example.com",
		.format = P9N_BUNDLE_X509_CAS,
	};
	int rc = p9n_marshal_fetchbundle(&buf, 10, &fb);
	ASSERT(rc == 0, "marshal fetchbundle");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal fetchbundle");
	ASSERT(fc.type == P9N_TFETCHBUNDLE, "type");
	ASSERT(strcmp(fc.u.fetchbundle.trust_domain, "prod.example.com") == 0,
	       "trust_domain");
	ASSERT(fc.u.fetchbundle.format == P9N_BUNDLE_X509_CAS, "format");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_rfetchbundle_roundtrip(void)
{
	TEST(rfetchbundle_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 512);

	/* Simulated PEM bundle */
	const char *pem = "-----BEGIN CERTIFICATE-----\nMIIBxTCCA...\n-----END CERTIFICATE-----\n";
	struct p9n_rfetchbundle rfb = {
		.trust_domain = "prod.example.com",
		.format = P9N_BUNDLE_X509_CAS,
		.bundle_len = (uint32_t)strlen(pem),
		.bundle = (uint8_t *)pem,
	};
	int rc = p9n_marshal_rfetchbundle(&buf, 10, &rfb);
	ASSERT(rc == 0, "marshal rfetchbundle");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal rfetchbundle");
	ASSERT(fc.type == P9N_RFETCHBUNDLE, "type");
	ASSERT(strcmp(fc.u.rfetchbundle.trust_domain, "prod.example.com") == 0,
	       "trust_domain");
	ASSERT(fc.u.rfetchbundle.format == P9N_BUNDLE_X509_CAS, "format");
	ASSERT(fc.u.rfetchbundle.bundle_len == strlen(pem), "bundle_len");
	ASSERT(memcmp(fc.u.rfetchbundle.bundle, pem, strlen(pem)) == 0,
	       "bundle content");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_spiffeverify_roundtrip(void)
{
	TEST(spiffeverify_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 512);

	/* Simulated JWT-SVID */
	const char *jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLmNvbS93b3JrbG9hZCJ9.signature";
	struct p9n_spiffeverify sv = {
		.svid_type = P9N_SVID_JWT,
		.spiffe_id = "spiffe://example.com/workload",
		.svid_len = (uint32_t)strlen(jwt),
		.svid = (uint8_t *)jwt,
	};
	int rc = p9n_marshal_spiffeverify(&buf, 20, &sv);
	ASSERT(rc == 0, "marshal spiffeverify");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal spiffeverify");
	ASSERT(fc.type == P9N_TSPIFFEVERIFY, "type");
	ASSERT(fc.u.spiffeverify.svid_type == P9N_SVID_JWT, "svid_type JWT");
	ASSERT(strcmp(fc.u.spiffeverify.spiffe_id,
	       "spiffe://example.com/workload") == 0, "spiffe_id");
	ASSERT(fc.u.spiffeverify.svid_len == strlen(jwt), "svid_len");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_rspiffeverify_roundtrip(void)
{
	TEST(rspiffeverify_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 256);

	struct p9n_rspiffeverify rsv = {
		.status = P9N_SPIFFE_OK,
		.spiffe_id = "spiffe://example.com/workload",
		.expiry = 1743400000000000000ULL,  /* some future timestamp */
	};
	int rc = p9n_marshal_rspiffeverify(&buf, 20, &rsv);
	ASSERT(rc == 0, "marshal rspiffeverify");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal rspiffeverify");
	ASSERT(fc.type == P9N_RSPIFFEVERIFY, "type");
	ASSERT(fc.u.rspiffeverify.status == P9N_SPIFFE_OK, "status OK");
	ASSERT(strcmp(fc.u.rspiffeverify.spiffe_id,
	       "spiffe://example.com/workload") == 0, "spiffe_id");
	ASSERT(fc.u.rspiffeverify.expiry == 1743400000000000000ULL, "expiry");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_spiffe_authneg(void)
{
	TEST(spiffe_auth_mechanism_negotiation);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 256);

	/* Client proposes SPIFFE mechanisms */
	char *mechs[] = { P9N_AUTH_SPIFFE_X509, P9N_AUTH_SPIFFE_JWT, P9N_AUTH_MTLS };
	struct p9n_authneg an = { .nmechs = 3, .mechs = mechs };
	int rc = p9n_marshal_authneg(&buf, 5, &an);
	ASSERT(rc == 0, "marshal authneg");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal authneg");
	ASSERT(fc.u.authneg.nmechs == 3, "3 mechs");
	ASSERT(strcmp(fc.u.authneg.mechs[0], "SPIFFE-X.509") == 0, "SPIFFE-X.509");
	ASSERT(strcmp(fc.u.authneg.mechs[1], "SPIFFE-JWT") == 0, "SPIFFE-JWT");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_spiffe_msg_names(void)
{
	TEST(spiffe_msg_name_lookup);
	ASSERT(strcmp(p9n_msg_name(P9N_TSTARTLS_SPIFFE), "Tstartls_spiffe") == 0,
	       "Tstartls_spiffe");
	ASSERT(strcmp(p9n_msg_name(P9N_TFETCHBUNDLE), "Tfetchbundle") == 0,
	       "Tfetchbundle");
	ASSERT(strcmp(p9n_msg_name(P9N_RSPIFFEVERIFY), "Rspiffeverify") == 0,
	       "Rspiffeverify");
	PASS();
}

/* ======================================================================
 * Transport extension tests
 * ====================================================================== */

static void test_rdmatoken_roundtrip(void)
{
	TEST(rdmatoken_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 128);

	struct p9n_rdmatoken rt = {
		.fid = 5,
		.direction = 0,
		.rkey = 0x1234,
		.addr = 0x7F0000000000ULL,
		.length = 4096,
	};
	int rc = p9n_marshal_rdmatoken(&buf, 50, &rt);
	ASSERT(rc == 0, "marshal rdmatoken");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal rdmatoken");
	ASSERT(fc.type == P9N_TRDMATOKEN, "type");
	ASSERT(fc.tag == 50, "tag");
	ASSERT(fc.u.rdmatoken.fid == 5, "fid");
	ASSERT(fc.u.rdmatoken.direction == 0, "direction");
	ASSERT(fc.u.rdmatoken.rkey == 0x1234, "rkey");
	ASSERT(fc.u.rdmatoken.addr == 0x7F0000000000ULL, "addr");
	ASSERT(fc.u.rdmatoken.length == 4096, "length");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_rdmanotify_roundtrip(void)
{
	TEST(rdmanotify_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 128);

	struct p9n_rdmanotify rn = {
		.rkey = 0x5678,
		.addr = 0xFF0000000000ULL,
		.length = 65536,
		.slots = 128,
	};
	int rc = p9n_marshal_rdmanotify(&buf, 51, &rn);
	ASSERT(rc == 0, "marshal rdmanotify");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal rdmanotify");
	ASSERT(fc.type == P9N_TRDMANOTIFY, "type");
	ASSERT(fc.tag == 51, "tag");
	ASSERT(fc.u.rdmanotify.rkey == 0x5678, "rkey");
	ASSERT(fc.u.rdmanotify.addr == 0xFF0000000000ULL, "addr");
	ASSERT(fc.u.rdmanotify.length == 65536, "length");
	ASSERT(fc.u.rdmanotify.slots == 128, "slots");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_quicstream_roundtrip(void)
{
	TEST(quicstream_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 64);

	struct p9n_quicstream qs = {
		.stream_type = P9N_QSTREAM_PUSH,
		.stream_id = 0xF001,
	};
	int rc = p9n_marshal_quicstream(&buf, 52, &qs);
	ASSERT(rc == 0, "marshal quicstream");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal quicstream");
	ASSERT(fc.type == P9N_TQUICSTREAM, "type");
	ASSERT(fc.tag == 52, "tag");
	ASSERT(fc.u.quicstream.stream_type == P9N_QSTREAM_PUSH, "stream_type push");
	ASSERT(fc.u.quicstream.stream_id == 0xF001, "stream_id");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_transport_capability(void)
{
	TEST(transport_capability_negotiation);
	struct p9n_capset client, server, result;
	p9n_capset_init(&client);
	p9n_capset_init(&server);

	p9n_capset_add(&client, P9N_CAP_QUIC);
	p9n_capset_add(&client, P9N_CAP_QUIC_MULTI);
	p9n_capset_add(&client, P9N_CAP_RDMA);

	p9n_capset_add(&server, P9N_CAP_QUIC);
	p9n_capset_add(&server, P9N_CAP_RDMA);

	p9n_capset_intersect(&result, &client, &server);

	ASSERT(p9n_capset_has(&result, P9N_CAP_QUIC), "QUIC negotiated");
	ASSERT(p9n_capset_has(&result, P9N_CAP_RDMA), "RDMA negotiated");
	ASSERT(!p9n_capset_has(&result, P9N_CAP_QUIC_MULTI), "QUIC_MULTI absent");
	ASSERT(p9n_capset_has_bit(&result, P9N_CBIT_QUIC), "QUIC bit set");
	ASSERT(p9n_capset_has_bit(&result, P9N_CBIT_RDMA), "RDMA bit set");
	ASSERT(!p9n_capset_has_bit(&result, P9N_CBIT_QUIC_MULTI),
	       "QUIC_MULTI bit not set");

	p9n_capset_free(&client);
	p9n_capset_free(&server);
	p9n_capset_free(&result);
	PASS();
}

static void test_transport_msg_names(void)
{
	TEST(transport_msg_name_lookup);
	ASSERT(strcmp(p9n_msg_name(P9N_TRDMATOKEN), "Trdmatoken") == 0,
	       "Trdmatoken");
	ASSERT(strcmp(p9n_msg_name(P9N_TQUICSTREAM), "Tquicstream") == 0,
	       "Tquicstream");
	ASSERT(strcmp(p9n_msg_name(P9N_RRDMANOTIFY), "Rrdmanotify") == 0,
	       "Rrdmanotify");
	PASS();
}

/* ======================================================================
 * CXL transport tests
 * ====================================================================== */

static void test_cxlmap_roundtrip(void)
{
	TEST(cxlmap_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 128);

	struct p9n_cxlmap cm = {
		.fid = 8,
		.offset = 0,
		.length = 0x100000,
		.prot = 0x3,           /* PROT_READ | PROT_WRITE */
		.flags = 0x5,          /* MAP_SHARED | MAP_DAX */
	};
	int rc = p9n_marshal_cxlmap(&buf, 60, &cm);
	ASSERT(rc == 0, "marshal cxlmap");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal cxlmap");
	ASSERT(fc.type == P9N_TCXLMAP, "type");
	ASSERT(fc.tag == 60, "tag");
	ASSERT(fc.u.cxlmap.fid == 8, "fid");
	ASSERT(fc.u.cxlmap.offset == 0, "offset");
	ASSERT(fc.u.cxlmap.length == 0x100000, "length");
	ASSERT(fc.u.cxlmap.prot == 0x3, "prot");
	ASSERT(fc.u.cxlmap.flags == 0x5, "flags");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_rcxlmap_roundtrip(void)
{
	TEST(rcxlmap_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 128);

	struct p9n_rcxlmap rcm = {
		.hpa = 0x800000000000ULL,
		.length = 0x100000,
		.granularity = 4096,
		.coherence = P9N_CXL_COHERENCE_HARDWARE,
	};
	int rc = p9n_marshal_rcxlmap(&buf, 60, &rcm);
	ASSERT(rc == 0, "marshal rcxlmap");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal rcxlmap");
	ASSERT(fc.type == P9N_RCXLMAP, "type");
	ASSERT(fc.tag == 60, "tag");
	ASSERT(fc.u.rcxlmap.hpa == 0x800000000000ULL, "hpa");
	ASSERT(fc.u.rcxlmap.length == 0x100000, "length");
	ASSERT(fc.u.rcxlmap.granularity == 4096, "granularity");
	ASSERT(fc.u.rcxlmap.coherence == P9N_CXL_COHERENCE_HARDWARE, "coherence");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);
	PASS();
}

static void test_cxlcoherence_roundtrip(void)
{
	TEST(cxlcoherence_marshal_unmarshal);
	struct p9n_buf buf;
	p9n_buf_init(&buf, 128);

	/* Tcxlcoherence: fid=8, mode=2 (HYBRID) */
	struct p9n_cxlcoherence cc = {
		.fid = 8,
		.mode = P9N_CXL_COHERENCE_HYBRID,
	};
	int rc = p9n_marshal_cxlcoherence(&buf, 61, &cc);
	ASSERT(rc == 0, "marshal cxlcoherence");

	struct p9n_fcall fc;
	rc = p9n_unmarshal(&buf, &fc);
	ASSERT(rc == 0, "unmarshal cxlcoherence");
	ASSERT(fc.type == P9N_TCXLCOHERENCE, "type");
	ASSERT(fc.tag == 61, "tag");
	ASSERT(fc.u.cxlcoherence.fid == 8, "fid");
	ASSERT(fc.u.cxlcoherence.mode == P9N_CXL_COHERENCE_HYBRID, "mode");

	p9n_fcall_free(&fc);
	p9n_buf_free(&buf);

	/* Rcxlcoherence: mode=1, snoop_id=42 */
	struct p9n_buf buf2;
	p9n_buf_init(&buf2, 128);

	/* Marshal Rcxlcoherence manually since there's no dedicated marshal fn */
	struct p9n_rcxlcoherence rcc = {
		.mode = P9N_CXL_COHERENCE_HARDWARE,
		.snoop_id = 42,
	};
	/* Build the message by hand: size[4] type[1] tag[2] mode[1] snoop_id[4] */
	p9n_buf_put_u32(&buf2, 7 + 1 + 4);  /* size = header + payload */
	p9n_buf_put_u8(&buf2, P9N_RCXLCOHERENCE);
	p9n_buf_put_u16(&buf2, 61);
	p9n_buf_put_u8(&buf2, rcc.mode);
	p9n_buf_put_u32(&buf2, rcc.snoop_id);

	struct p9n_fcall fc2;
	rc = p9n_unmarshal(&buf2, &fc2);
	ASSERT(rc == 0, "unmarshal rcxlcoherence");
	ASSERT(fc2.type == P9N_RCXLCOHERENCE, "rtype");
	ASSERT(fc2.u.rcxlcoherence.mode == P9N_CXL_COHERENCE_HARDWARE, "rmode");
	ASSERT(fc2.u.rcxlcoherence.snoop_id == 42, "snoop_id");

	p9n_fcall_free(&fc2);
	p9n_buf_free(&buf2);
	PASS();
}

static void test_cxl_capability(void)
{
	TEST(cxl_capability_negotiation);
	struct p9n_capset client, server, result;
	p9n_capset_init(&client);
	p9n_capset_init(&server);

	/* Client wants CXL + RDMA + QUIC */
	p9n_capset_add(&client, P9N_CAP_CXL);
	p9n_capset_add(&client, P9N_CAP_RDMA);
	p9n_capset_add(&client, P9N_CAP_QUIC);

	/* Server only has CXL */
	p9n_capset_add(&server, P9N_CAP_CXL);

	p9n_capset_intersect(&result, &client, &server);

	ASSERT(result.ncaps == 1, "intersection count");
	ASSERT(p9n_capset_has(&result, P9N_CAP_CXL), "CXL present");
	ASSERT(!p9n_capset_has(&result, P9N_CAP_RDMA), "RDMA absent");
	ASSERT(!p9n_capset_has(&result, P9N_CAP_QUIC), "QUIC absent");
	ASSERT(p9n_capset_has_bit(&result, P9N_CBIT_CXL), "CXL bit set");
	ASSERT(!p9n_capset_has_bit(&result, P9N_CBIT_RDMA), "RDMA bit not set");

	p9n_capset_free(&client);
	p9n_capset_free(&server);
	p9n_capset_free(&result);
	PASS();
}

/* ======================================================================
 * Main
 * ====================================================================== */

int main(void)
{
	printf("9P2000.N Protocol Tests\n");
	printf("=======================\n\n");

	printf("Buffer primitives:\n");
	test_buf_u8();
	test_buf_u16();
	test_buf_u32();
	test_buf_u64();
	test_buf_str();
	test_buf_empty_str();
	test_buf_grow();
	test_buf_underflow();

	printf("\nCapability negotiation:\n");
	test_capset_basic();
	test_capset_bitmask();
	test_capset_intersect();
	test_capset_dedup();
	test_cap_to_bit();

	printf("\nMarshal/Unmarshal round-trip:\n");
	test_caps_roundtrip();
	test_startls_roundtrip();
	test_watch_roundtrip();
	test_notify_roundtrip();
	test_lease_roundtrip();
	test_leasebreak_roundtrip();
	test_session_roundtrip();
	test_compound_roundtrip();
	test_hash_roundtrip();
	test_compress_roundtrip();
	test_copyrange_roundtrip();
	test_allocate_roundtrip();
	test_authneg_roundtrip();

	printf("\nSPIFFE integration:\n");
	test_spiffe_capability();
	test_startls_spiffe_roundtrip();
	test_fetchbundle_roundtrip();
	test_rfetchbundle_roundtrip();
	test_spiffeverify_roundtrip();
	test_rspiffeverify_roundtrip();
	test_spiffe_authneg();
	test_spiffe_msg_names();

	printf("\nTransport extensions:\n");
	test_rdmatoken_roundtrip();
	test_rdmanotify_roundtrip();
	test_quicstream_roundtrip();
	test_transport_capability();
	test_transport_msg_names();
	test_cxlmap_roundtrip();
	test_rcxlmap_roundtrip();
	test_cxlcoherence_roundtrip();
	test_cxl_capability();

	printf("\nWire format:\n");
	test_msg_names();
	test_wire_header_size();

	printf("\n=======================\n");
	printf("Results: %d/%d passed\n", tests_passed, tests_run);

	return tests_passed == tests_run ? 0 : 1;
}
