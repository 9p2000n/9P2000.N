/* SPDX-License-Identifier: MIT */
/*
 * Compound operation builder for 9P2000.N.
 *
 * Provides a convenient API to construct Tcompound messages by
 * appending individual sub-operations. Supports the magic fid
 * P9N_PREVFID (0xFFFFFFFE) which refers to the fid returned by
 * the most recent sub-op that created/walked a fid.
 *
 * Usage:
 *   struct p9n_compound_builder bld;
 *   p9n_compound_init(&bld);
 *   p9n_compound_add_walk(&bld, rootfid, P9N_PREVFID, "usr", "local");
 *   p9n_compound_add_lopen(&bld, P9N_PREVFID, P9_DOTL_RDONLY);
 *   p9n_compound_add_read(&bld, P9N_PREVFID, 0, 4096);
 *   p9n_compound_add_clunk(&bld, P9N_PREVFID);
 *
 *   struct p9n_buf wire;
 *   p9n_compound_encode(&bld, &wire, tag);
 *   p9n_compound_free(&bld);
 */

#include "../include/9pN.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

/* 9P2000 base message types we reference in sub-ops */
#define P9_TWALK    110
#define P9_TLOPEN   12
#define P9_TREAD    116
#define P9_TWRITE   118
#define P9_TCLUNK   120
#define P9_TLCREATE 14
#define P9_TREMOVE  122

#define COMPOUND_MAX_OPS  256

struct p9n_compound_builder {
	uint16_t          nops;
	struct p9n_subop  ops[COMPOUND_MAX_OPS];
};

void p9n_compound_builder_init(struct p9n_compound_builder *bld)
{
	memset(bld, 0, sizeof(*bld));
}

void p9n_compound_builder_free(struct p9n_compound_builder *bld)
{
	for (uint16_t i = 0; i < bld->nops; i++)
		free(bld->ops[i].payload);
	memset(bld, 0, sizeof(*bld));
}

static int add_subop(struct p9n_compound_builder *bld, uint8_t type,
                     const uint8_t *payload, uint32_t payload_len)
{
	if (bld->nops >= COMPOUND_MAX_OPS)
		return -ENOSPC;

	struct p9n_subop *op = &bld->ops[bld->nops];
	op->type = type;
	op->opsize = P9N_SUBOP_HDRSZ + payload_len;
	op->payload_len = payload_len;

	if (payload_len) {
		op->payload = malloc(payload_len);
		if (!op->payload)
			return -ENOMEM;
		memcpy(op->payload, payload, payload_len);
	} else {
		op->payload = NULL;
	}

	bld->nops++;
	return 0;
}

/*
 * Add a Twalk sub-op.
 * Wire payload (no size/type/tag): fid[4] newfid[4] nwname[2] wname[s]...
 */
int p9n_compound_add_walk(struct p9n_compound_builder *bld,
                          uint32_t fid, uint32_t newfid,
                          uint16_t nwname, const char **wnames)
{
	struct p9n_buf tmp;
	int rc = p9n_buf_init(&tmp, 256);
	if (rc) return rc;

	rc = p9n_buf_put_u32(&tmp, fid);
	if (!rc) rc = p9n_buf_put_u32(&tmp, newfid);
	if (!rc) rc = p9n_buf_put_u16(&tmp, nwname);
	for (uint16_t i = 0; i < nwname && !rc; i++)
		rc = p9n_buf_put_str(&tmp, wnames[i]);

	if (!rc)
		rc = add_subop(bld, P9_TWALK, tmp.data, (uint32_t)tmp.len);

	p9n_buf_free(&tmp);
	return rc;
}

/*
 * Add a Tlopen sub-op.
 * Wire payload: fid[4] flags[4]
 */
int p9n_compound_add_lopen(struct p9n_compound_builder *bld,
                           uint32_t fid, uint32_t flags)
{
	uint8_t payload[8];
	payload[0] = (uint8_t)(fid);
	payload[1] = (uint8_t)(fid >> 8);
	payload[2] = (uint8_t)(fid >> 16);
	payload[3] = (uint8_t)(fid >> 24);
	payload[4] = (uint8_t)(flags);
	payload[5] = (uint8_t)(flags >> 8);
	payload[6] = (uint8_t)(flags >> 16);
	payload[7] = (uint8_t)(flags >> 24);
	return add_subop(bld, P9_TLOPEN, payload, 8);
}

/*
 * Add a Tread sub-op.
 * Wire payload: fid[4] offset[8] count[4]
 */
int p9n_compound_add_read(struct p9n_compound_builder *bld,
                          uint32_t fid, uint64_t offset, uint32_t count)
{
	struct p9n_buf tmp;
	int rc = p9n_buf_init(&tmp, 16);
	if (rc) return rc;

	rc = p9n_buf_put_u32(&tmp, fid);
	if (!rc) rc = p9n_buf_put_u64(&tmp, offset);
	if (!rc) rc = p9n_buf_put_u32(&tmp, count);

	if (!rc)
		rc = add_subop(bld, P9_TREAD, tmp.data, (uint32_t)tmp.len);

	p9n_buf_free(&tmp);
	return rc;
}

/*
 * Add a Twrite sub-op.
 * Wire payload: fid[4] offset[8] count[4] data[count]
 */
int p9n_compound_add_write(struct p9n_compound_builder *bld,
                           uint32_t fid, uint64_t offset,
                           const void *data, uint32_t count)
{
	struct p9n_buf tmp;
	int rc = p9n_buf_init(&tmp, 16 + count);
	if (rc) return rc;

	rc = p9n_buf_put_u32(&tmp, fid);
	if (!rc) rc = p9n_buf_put_u64(&tmp, offset);
	if (!rc) rc = p9n_buf_put_u32(&tmp, count);
	if (!rc && count) {
		rc = p9n_buf_ensure(&tmp, count);
		if (!rc) {
			memcpy(tmp.data + tmp.len, data, count);
			tmp.len += count;
		}
	}

	if (!rc)
		rc = add_subop(bld, P9_TWRITE, tmp.data, (uint32_t)tmp.len);

	p9n_buf_free(&tmp);
	return rc;
}

/*
 * Add a Tclunk sub-op.
 * Wire payload: fid[4]
 */
int p9n_compound_add_clunk(struct p9n_compound_builder *bld, uint32_t fid)
{
	uint8_t payload[4];
	payload[0] = (uint8_t)(fid);
	payload[1] = (uint8_t)(fid >> 8);
	payload[2] = (uint8_t)(fid >> 16);
	payload[3] = (uint8_t)(fid >> 24);
	return add_subop(bld, P9_TCLUNK, payload, 4);
}

/*
 * Encode the builder into a wire-format Tcompound message.
 */
int p9n_compound_encode(const struct p9n_compound_builder *bld,
                        struct p9n_buf *buf, uint16_t tag)
{
	struct p9n_compound comp;
	comp.nops = bld->nops;
	/* Cast away const: marshal_compound only reads the ops */
	comp.ops = (struct p9n_subop *)bld->ops;
	return p9n_marshal_compound(buf, tag, &comp);
}
