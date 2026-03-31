/* SPDX-License-Identifier: MIT */
/*
 * 9P2000.N protocol marshalling and unmarshalling.
 *
 * Every message follows the wire format: size[4] type[1] tag[2] payload
 * All marshal functions write a complete message including the size prefix.
 * The unmarshal entry point reads the header and dispatches by type.
 */

#include "../include/9pN.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Suppress unused-function warnings for marshal functions that are defined
 * but not yet called from the public API. They will be exposed as the
 * public API surface grows. */
#pragma GCC diagnostic ignored "-Wunused-function"

/* ======================================================================
 * Internal helpers
 * ====================================================================== */

/*
 * Begin a message: write placeholder size[4], type[1], tag[2].
 * Returns the offset of the size field for later patching.
 */
static int msg_begin(struct p9n_buf *buf, uint8_t type, uint16_t tag,
                     size_t *size_off)
{
	*size_off = buf->len;
	int rc;
	rc = p9n_buf_put_u32(buf, 0);        /* placeholder */
	if (rc) return rc;
	rc = p9n_buf_put_u8(buf, type);
	if (rc) return rc;
	rc = p9n_buf_put_u16(buf, tag);
	return rc;
}

/* Patch the size field at size_off with the actual message length. */
static void msg_finish(struct p9n_buf *buf, size_t size_off)
{
	uint32_t total = (uint32_t)(buf->len - size_off);
	buf->data[size_off + 0] = (uint8_t)(total);
	buf->data[size_off + 1] = (uint8_t)(total >> 8);
	buf->data[size_off + 2] = (uint8_t)(total >> 16);
	buf->data[size_off + 3] = (uint8_t)(total >> 24);
}

static int put_qid(struct p9n_buf *buf, const struct p9n_qid *qid)
{
	int rc;
	rc = p9n_buf_put_u8(buf, qid->type);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, qid->version);
	if (rc) return rc;
	return p9n_buf_put_u64(buf, qid->path);
}

static int get_qid(struct p9n_buf *buf, struct p9n_qid *qid)
{
	int rc;
	rc = p9n_buf_get_u8(buf, &qid->type);
	if (rc) return rc;
	rc = p9n_buf_get_u32(buf, &qid->version);
	if (rc) return rc;
	return p9n_buf_get_u64(buf, &qid->path);
}

/* ======================================================================
 * Marshal: Security
 * ====================================================================== */

int p9n_marshal_startls(struct p9n_buf *buf, uint16_t tag)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TSTARTLS, tag, &off);
	if (rc) return rc;
	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_authneg(struct p9n_buf *buf, uint16_t tag,
                        const struct p9n_authneg *an)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TAUTHNEG, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u16(buf, an->nmechs);
	if (rc) return rc;
	for (uint16_t i = 0; i < an->nmechs; i++) {
		rc = p9n_buf_put_str(buf, an->mechs[i]);
		if (rc) return rc;
	}

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_rauthneg(struct p9n_buf *buf, uint16_t tag,
                         const struct p9n_rauthneg *ran)
{
	size_t off;
	int rc = msg_begin(buf, P9N_RAUTHNEG, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_str(buf, ran->mech);
	if (rc) return rc;
	rc = p9n_buf_put_data(buf, ran->challenge, ran->challenge_len);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

static int marshal_capgrant(struct p9n_buf *buf, uint16_t tag,
                            const struct p9n_capgrant *cg)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TCAPGRANT, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, cg->fid);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, cg->rights);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, cg->expiry);
	if (rc) return rc;
	rc = p9n_buf_put_u16(buf, cg->depth);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

static int marshal_capuse(struct p9n_buf *buf, uint16_t tag,
                          const struct p9n_capuse *cu)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TCAPUSE, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, cu->fid);
	if (rc) return rc;
	rc = p9n_buf_put_str(buf, cu->token);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

static int marshal_auditctl(struct p9n_buf *buf, uint16_t tag,
                            const struct p9n_auditctl *ac)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TAUDITCTL, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, ac->fid);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, ac->flags);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

/* ======================================================================
 * Marshal: SPIFFE
 * ====================================================================== */

int p9n_marshal_startls_spiffe(struct p9n_buf *buf, uint16_t tag,
                               const struct p9n_startls_spiffe *ss)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TSTARTLS_SPIFFE, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_str(buf, ss->spiffe_id);
	if (rc) return rc;
	rc = p9n_buf_put_str(buf, ss->trust_domain);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_fetchbundle(struct p9n_buf *buf, uint16_t tag,
                            const struct p9n_fetchbundle *fb)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TFETCHBUNDLE, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_str(buf, fb->trust_domain);
	if (rc) return rc;
	rc = p9n_buf_put_u8(buf, fb->format);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_rfetchbundle(struct p9n_buf *buf, uint16_t tag,
                             const struct p9n_rfetchbundle *rfb)
{
	size_t off;
	int rc = msg_begin(buf, P9N_RFETCHBUNDLE, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_str(buf, rfb->trust_domain);
	if (rc) return rc;
	rc = p9n_buf_put_u8(buf, rfb->format);
	if (rc) return rc;
	rc = p9n_buf_put_data(buf, rfb->bundle, rfb->bundle_len);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_spiffeverify(struct p9n_buf *buf, uint16_t tag,
                             const struct p9n_spiffeverify *sv)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TSPIFFEVERIFY, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u8(buf, sv->svid_type);
	if (rc) return rc;
	rc = p9n_buf_put_str(buf, sv->spiffe_id);
	if (rc) return rc;
	rc = p9n_buf_put_data(buf, sv->svid, sv->svid_len);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_rspiffeverify(struct p9n_buf *buf, uint16_t tag,
                              const struct p9n_rspiffeverify *rsv)
{
	size_t off;
	int rc = msg_begin(buf, P9N_RSPIFFEVERIFY, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u8(buf, rsv->status);
	if (rc) return rc;
	rc = p9n_buf_put_str(buf, rsv->spiffe_id);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, rsv->expiry);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

/* ======================================================================
 * Marshal: Transport
 * ====================================================================== */

int p9n_marshal_cxlmap(struct p9n_buf *buf, uint16_t tag,
                       const struct p9n_cxlmap *cm)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TCXLMAP, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, cm->fid);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, cm->offset);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, cm->length);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, cm->prot);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, cm->flags);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_rcxlmap(struct p9n_buf *buf, uint16_t tag,
                        const struct p9n_rcxlmap *rcm)
{
	size_t off;
	int rc = msg_begin(buf, P9N_RCXLMAP, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u64(buf, rcm->hpa);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, rcm->length);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, rcm->granularity);
	if (rc) return rc;
	rc = p9n_buf_put_u8(buf, rcm->coherence);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_cxlcoherence(struct p9n_buf *buf, uint16_t tag,
                             const struct p9n_cxlcoherence *cc)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TCXLCOHERENCE, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, cc->fid);
	if (rc) return rc;
	rc = p9n_buf_put_u8(buf, cc->mode);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_rdmatoken(struct p9n_buf *buf, uint16_t tag,
                          const struct p9n_rdmatoken *rt)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TRDMATOKEN, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, rt->fid);
	if (rc) return rc;
	rc = p9n_buf_put_u8(buf, rt->direction);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, rt->rkey);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, rt->addr);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, rt->length);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_rrdmatoken(struct p9n_buf *buf, uint16_t tag,
                           const struct p9n_rrdmatoken *rrt)
{
	size_t off;
	int rc = msg_begin(buf, P9N_RRDMATOKEN, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, rrt->rkey);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, rrt->addr);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, rrt->length);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_rdmanotify(struct p9n_buf *buf, uint16_t tag,
                           const struct p9n_rdmanotify *rn)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TRDMANOTIFY, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, rn->rkey);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, rn->addr);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, rn->length);
	if (rc) return rc;
	rc = p9n_buf_put_u16(buf, rn->slots);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_quicstream(struct p9n_buf *buf, uint16_t tag,
                           const struct p9n_quicstream *qs)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TQUICSTREAM, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u8(buf, qs->stream_type);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, qs->stream_id);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

/* ======================================================================
 * Marshal: Performance
 * ====================================================================== */

int p9n_marshal_compound(struct p9n_buf *buf, uint16_t tag,
                         const struct p9n_compound *comp)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TCOMPOUND, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u16(buf, comp->nops);
	if (rc) return rc;

	for (uint16_t i = 0; i < comp->nops; i++) {
		const struct p9n_subop *op = &comp->ops[i];
		/* Sub-op: opsize[4] type[1] payload[...] */
		uint32_t opsize = P9N_SUBOP_HDRSZ + op->payload_len;
		rc = p9n_buf_put_u32(buf, opsize);
		if (rc) return rc;
		rc = p9n_buf_put_u8(buf, op->type);
		if (rc) return rc;
		if (op->payload_len) {
			rc = p9n_buf_ensure(buf, op->payload_len);
			if (rc) return rc;
			memcpy(buf->data + buf->len, op->payload, op->payload_len);
			buf->len += op->payload_len;
		}
	}

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_rcompound(struct p9n_buf *buf, uint16_t tag,
                          const struct p9n_rcompound *rcomp)
{
	size_t off;
	int rc = msg_begin(buf, P9N_RCOMPOUND, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u16(buf, rcomp->nresults);
	if (rc) return rc;

	for (uint16_t i = 0; i < rcomp->nresults; i++) {
		const struct p9n_subop *res = &rcomp->results[i];
		uint32_t opsize = P9N_SUBOP_HDRSZ + res->payload_len;
		rc = p9n_buf_put_u32(buf, opsize);
		if (rc) return rc;
		rc = p9n_buf_put_u8(buf, res->type);
		if (rc) return rc;
		if (res->payload_len) {
			rc = p9n_buf_ensure(buf, res->payload_len);
			if (rc) return rc;
			memcpy(buf->data + buf->len, res->payload, res->payload_len);
			buf->len += res->payload_len;
		}
	}

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_compress(struct p9n_buf *buf, uint16_t tag,
                         const struct p9n_compress *comp)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TCOMPRESS, tag, &off);
	if (rc) return rc;
	rc = p9n_buf_put_u8(buf, comp->algo);
	if (rc) return rc;
	rc = p9n_buf_put_u8(buf, comp->level);
	if (rc) return rc;
	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_copyrange(struct p9n_buf *buf, uint16_t tag,
                          const struct p9n_copyrange *cr)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TCOPYRANGE, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, cr->srcfid);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, cr->srcoff);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, cr->dstfid);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, cr->dstoff);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, cr->count);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, cr->flags);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_allocate(struct p9n_buf *buf, uint16_t tag,
                         const struct p9n_allocate *alloc)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TALLOCATE, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, alloc->fid);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, alloc->mode);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, alloc->offset);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, alloc->length);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_seekhole(struct p9n_buf *buf, uint16_t tag,
                         const struct p9n_seekhole *sh)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TSEEKHOLE, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, sh->fid);
	if (rc) return rc;
	rc = p9n_buf_put_u8(buf, sh->type);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, sh->offset);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

static int marshal_mmaphint(struct p9n_buf *buf, uint16_t tag,
                            const struct p9n_mmaphint *mh)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TMMAPHINT, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, mh->fid);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, mh->offset);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, mh->length);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, mh->prot);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

/* ======================================================================
 * Marshal: Filesystem semantics
 * ====================================================================== */

int p9n_marshal_watch(struct p9n_buf *buf, uint16_t tag,
                      const struct p9n_watch *w)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TWATCH, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, w->fid);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, w->mask);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, w->flags);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_unwatch(struct p9n_buf *buf, uint16_t tag,
                        const struct p9n_unwatch *uw)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TUNWATCH, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, uw->watchid);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_notify(struct p9n_buf *buf, const struct p9n_notify *n)
{
	/* Server-push: uses P9_NOTAG */
	size_t off;
	int rc = msg_begin(buf, P9N_RNOTIFY, P9_NOTAG, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, n->watchid);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, n->event);
	if (rc) return rc;
	rc = p9n_buf_put_str(buf, n->name);
	if (rc) return rc;
	rc = put_qid(buf, &n->qid);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

static int marshal_getacl(struct p9n_buf *buf, uint16_t tag,
                          const struct p9n_getacl *ga)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TGETACL, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, ga->fid);
	if (rc) return rc;
	rc = p9n_buf_put_u8(buf, ga->acltype);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

static int marshal_setacl(struct p9n_buf *buf, uint16_t tag,
                          const struct p9n_setacl *sa)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TSETACL, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, sa->fid);
	if (rc) return rc;
	rc = p9n_buf_put_u8(buf, sa->acltype);
	if (rc) return rc;
	rc = p9n_buf_put_data(buf, sa->data, sa->count);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

static int marshal_snapshot(struct p9n_buf *buf, uint16_t tag,
                            const struct p9n_snapshot *snap)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TSNAPSHOT, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, snap->fid);
	if (rc) return rc;
	rc = p9n_buf_put_str(buf, snap->name);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, snap->flags);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

static int marshal_xattrget(struct p9n_buf *buf, uint16_t tag,
                            const struct p9n_xattrget *xg)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TXATTRGET, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, xg->fid);
	if (rc) return rc;
	rc = p9n_buf_put_str(buf, xg->name);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

static int marshal_xattrset(struct p9n_buf *buf, uint16_t tag,
                            const struct p9n_xattrset *xs)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TXATTRSET, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, xs->fid);
	if (rc) return rc;
	rc = p9n_buf_put_str(buf, xs->name);
	if (rc) return rc;
	rc = p9n_buf_put_data(buf, xs->data, xs->count);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, xs->flags);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

/* ======================================================================
 * Marshal: Distributed systems
 * ====================================================================== */

int p9n_marshal_lease(struct p9n_buf *buf, uint16_t tag,
                      const struct p9n_lease *l)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TLEASE, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, l->fid);
	if (rc) return rc;
	rc = p9n_buf_put_u8(buf, l->type);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, l->duration);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_leaserenew(struct p9n_buf *buf, uint16_t tag,
                           const struct p9n_leaserenew *lr)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TLEASERENEW, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u64(buf, lr->leaseid);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, lr->duration);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_leaseack(struct p9n_buf *buf, uint16_t tag,
                         const struct p9n_leaseack *la)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TLEASEACK, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u64(buf, la->leaseid);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_leasebreak(struct p9n_buf *buf,
                           const struct p9n_leasebreak *lb)
{
	/* Server-push: uses P9_NOTAG */
	size_t off;
	int rc = msg_begin(buf, P9N_RLEASEBREAK, P9_NOTAG, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u64(buf, lb->leaseid);
	if (rc) return rc;
	rc = p9n_buf_put_u8(buf, lb->newtype);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

int p9n_marshal_session(struct p9n_buf *buf, uint16_t tag,
                        const struct p9n_session *s)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TSESSION, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_ensure(buf, 16);
	if (rc) return rc;
	memcpy(buf->data + buf->len, s->key, 16);
	buf->len += 16;

	rc = p9n_buf_put_u32(buf, s->flags);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

static int marshal_consistency(struct p9n_buf *buf, uint16_t tag,
                               const struct p9n_consistency *c)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TCONSISTENCY, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, c->fid);
	if (rc) return rc;
	rc = p9n_buf_put_u8(buf, c->level);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

static int marshal_topology(struct p9n_buf *buf, uint16_t tag,
                            const struct p9n_topology *t)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TTOPOLOGY, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, t->fid);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

/* ======================================================================
 * Marshal: Observability
 * ====================================================================== */

static int marshal_traceattr(struct p9n_buf *buf, uint16_t tag,
                             const struct p9n_traceattr *ta)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TTRACEATTR, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u16(buf, ta->nattrs);
	if (rc) return rc;
	for (uint16_t i = 0; i < ta->nattrs; i++) {
		rc = p9n_buf_put_str(buf, ta->keys[i]);
		if (rc) return rc;
		rc = p9n_buf_put_str(buf, ta->values[i]);
		if (rc) return rc;
	}

	msg_finish(buf, off);
	return 0;
}

static int marshal_health(struct p9n_buf *buf, uint16_t tag)
{
	size_t off;
	int rc = msg_begin(buf, P9N_THEALTH, tag, &off);
	if (rc) return rc;
	msg_finish(buf, off);
	return 0;
}

/* ======================================================================
 * Marshal: Content-awareness
 * ====================================================================== */

int p9n_marshal_hash(struct p9n_buf *buf, uint16_t tag,
                     const struct p9n_hash *h)
{
	size_t off;
	int rc = msg_begin(buf, P9N_THASH, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, h->fid);
	if (rc) return rc;
	rc = p9n_buf_put_u8(buf, h->algo);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, h->offset);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, h->length);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

/* ======================================================================
 * Marshal: Streaming/Async
 * ====================================================================== */

static int marshal_async(struct p9n_buf *buf, uint16_t tag,
                         const struct p9n_async *a)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TASYNC, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u8(buf, a->innertype);
	if (rc) return rc;
	if (a->payload_len) {
		rc = p9n_buf_ensure(buf, a->payload_len);
		if (rc) return rc;
		memcpy(buf->data + buf->len, a->payload, a->payload_len);
		buf->len += a->payload_len;
	}

	msg_finish(buf, off);
	return 0;
}

static int marshal_poll(struct p9n_buf *buf, uint16_t tag,
                        const struct p9n_poll *p)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TPOLL, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u64(buf, p->opid);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

static int marshal_streamopen(struct p9n_buf *buf, uint16_t tag,
                              const struct p9n_streamopen *so)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TSTREAMOPEN, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, so->fid);
	if (rc) return rc;
	rc = p9n_buf_put_u8(buf, so->direction);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, so->offset);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, so->count);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

static int marshal_streamdata(struct p9n_buf *buf, uint16_t tag,
                              const struct p9n_streamdata *sd)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TSTREAMDATA, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, sd->streamid);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, sd->seq);
	if (rc) return rc;
	rc = p9n_buf_put_data(buf, sd->data, sd->count);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

static int marshal_streamclose(struct p9n_buf *buf, uint16_t tag,
                               const struct p9n_streamclose *sc)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TSTREAMCLOSE, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, sc->streamid);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

/* ======================================================================
 * Marshal: Resource management
 * ====================================================================== */

static int marshal_getquota(struct p9n_buf *buf, uint16_t tag,
                            const struct p9n_getquota *gq)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TGETQUOTA, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, gq->fid);
	if (rc) return rc;
	rc = p9n_buf_put_u8(buf, gq->type);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

static int marshal_setquota(struct p9n_buf *buf, uint16_t tag,
                            const struct p9n_setquota *sq)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TSETQUOTA, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, sq->fid);
	if (rc) return rc;
	rc = p9n_buf_put_u8(buf, sq->type);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, sq->bytes_limit);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, sq->files_limit);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, sq->grace_period);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

static int marshal_ratelimit(struct p9n_buf *buf, uint16_t tag,
                             const struct p9n_ratelimit *rl)
{
	size_t off;
	int rc = msg_begin(buf, P9N_TRATELIMIT, tag, &off);
	if (rc) return rc;

	rc = p9n_buf_put_u32(buf, rl->fid);
	if (rc) return rc;
	rc = p9n_buf_put_u32(buf, rl->iops);
	if (rc) return rc;
	rc = p9n_buf_put_u64(buf, rl->bps);
	if (rc) return rc;

	msg_finish(buf, off);
	return 0;
}

/* ======================================================================
 * Unmarshal: dispatch by message type
 * ====================================================================== */

static int unmarshal_subops(struct p9n_buf *buf, uint16_t *nops,
                            struct p9n_subop **ops)
{
	int rc = p9n_buf_get_u16(buf, nops);
	if (rc) return rc;

	if (*nops == 0) {
		*ops = NULL;
		return 0;
	}

	*ops = calloc(*nops, sizeof(struct p9n_subop));
	if (!*ops)
		return -ENOMEM;

	for (uint16_t i = 0; i < *nops; i++) {
		rc = p9n_buf_get_u32(buf, &(*ops)[i].opsize);
		if (rc) goto err;
		rc = p9n_buf_get_u8(buf, &(*ops)[i].type);
		if (rc) goto err;

		uint32_t plen = (*ops)[i].opsize - P9N_SUBOP_HDRSZ;
		(*ops)[i].payload_len = plen;
		if (plen > 0) {
			if (buf->pos + plen > buf->len) {
				rc = -EIO;
				goto err;
			}
			(*ops)[i].payload = malloc(plen);
			if (!(*ops)[i].payload) {
				rc = -ENOMEM;
				goto err;
			}
			memcpy((*ops)[i].payload, buf->data + buf->pos, plen);
			buf->pos += plen;
		}
	}
	return 0;

err:
	for (uint16_t j = 0; j < *nops; j++)
		free((*ops)[j].payload);
	free(*ops);
	*ops = NULL;
	*nops = 0;
	return rc;
}

int p9n_unmarshal(struct p9n_buf *buf, struct p9n_fcall *fc)
{
	int rc;

	memset(fc, 0, sizeof(*fc));

	/* Read header: size[4] type[1] tag[2] */
	rc = p9n_buf_get_u32(buf, &fc->size);
	if (rc) return rc;
	rc = p9n_buf_get_u8(buf, &fc->type);
	if (rc) return rc;
	rc = p9n_buf_get_u16(buf, &fc->tag);
	if (rc) return rc;

	switch (fc->type) {
	/* -- Negotiation -- */
	case P9N_TCAPS:
	case P9N_RCAPS:
		rc = p9n_buf_get_u16(buf, &fc->u.caps.ncaps);
		if (rc) return rc;
		if (fc->u.caps.ncaps > P9N_MAX_CAPS)
			return -EINVAL;
		if (fc->u.caps.ncaps) {
			fc->u.caps.caps = calloc(fc->u.caps.ncaps, sizeof(char *));
			if (!fc->u.caps.caps)
				return -ENOMEM;
			for (uint16_t i = 0; i < fc->u.caps.ncaps; i++) {
				rc = p9n_buf_get_str(buf, &fc->u.caps.caps[i]);
				if (rc) return rc;
			}
		}
		break;

	/* -- Security -- */
	case P9N_TSTARTLS:
	case P9N_RSTARTLS:
		/* empty payload */
		break;

	case P9N_TAUTHNEG:
		rc = p9n_buf_get_u16(buf, &fc->u.authneg.nmechs);
		if (rc) return rc;
		fc->u.authneg.mechs = calloc(fc->u.authneg.nmechs, sizeof(char *));
		if (!fc->u.authneg.mechs)
			return -ENOMEM;
		for (uint16_t i = 0; i < fc->u.authneg.nmechs; i++) {
			rc = p9n_buf_get_str(buf, &fc->u.authneg.mechs[i]);
			if (rc) return rc;
		}
		break;

	case P9N_RAUTHNEG:
		rc = p9n_buf_get_str(buf, &fc->u.rauthneg.mech);
		if (rc) return rc;
		rc = p9n_buf_get_data(buf, &fc->u.rauthneg.challenge,
		                      &fc->u.rauthneg.challenge_len);
		if (rc) return rc;
		break;

	case P9N_TCAPGRANT:
		rc = p9n_buf_get_u32(buf, &fc->u.capgrant.fid);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.capgrant.rights);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.capgrant.expiry);
		if (rc) return rc;
		rc = p9n_buf_get_u16(buf, &fc->u.capgrant.depth);
		break;

	case P9N_RCAPGRANT:
		rc = p9n_buf_get_str(buf, &fc->u.rcapgrant.token);
		break;

	case P9N_TCAPUSE:
		rc = p9n_buf_get_u32(buf, &fc->u.capuse.fid);
		if (rc) return rc;
		rc = p9n_buf_get_str(buf, &fc->u.capuse.token);
		break;

	case P9N_RCAPUSE:
		rc = get_qid(buf, &fc->u.rcapuse.qid);
		break;

	case P9N_TAUDITCTL:
	case P9N_RAUDITCTL:
		rc = p9n_buf_get_u32(buf, &fc->u.auditctl.fid);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.auditctl.flags);
		break;

	/* -- SPIFFE -- */
	case P9N_TSTARTLS_SPIFFE:
	case P9N_RSTARTLS_SPIFFE:
		rc = p9n_buf_get_str(buf, &fc->u.startls_spiffe.spiffe_id);
		if (rc) return rc;
		rc = p9n_buf_get_str(buf, &fc->u.startls_spiffe.trust_domain);
		break;

	case P9N_TFETCHBUNDLE:
		rc = p9n_buf_get_str(buf, &fc->u.fetchbundle.trust_domain);
		if (rc) return rc;
		rc = p9n_buf_get_u8(buf, &fc->u.fetchbundle.format);
		break;

	case P9N_RFETCHBUNDLE:
		rc = p9n_buf_get_str(buf, &fc->u.rfetchbundle.trust_domain);
		if (rc) return rc;
		rc = p9n_buf_get_u8(buf, &fc->u.rfetchbundle.format);
		if (rc) return rc;
		rc = p9n_buf_get_data(buf, &fc->u.rfetchbundle.bundle,
		                      &fc->u.rfetchbundle.bundle_len);
		break;

	case P9N_TSPIFFEVERIFY:
		rc = p9n_buf_get_u8(buf, &fc->u.spiffeverify.svid_type);
		if (rc) return rc;
		rc = p9n_buf_get_str(buf, &fc->u.spiffeverify.spiffe_id);
		if (rc) return rc;
		rc = p9n_buf_get_data(buf, &fc->u.spiffeverify.svid,
		                      &fc->u.spiffeverify.svid_len);
		break;

	case P9N_RSPIFFEVERIFY:
		rc = p9n_buf_get_u8(buf, &fc->u.rspiffeverify.status);
		if (rc) return rc;
		rc = p9n_buf_get_str(buf, &fc->u.rspiffeverify.spiffe_id);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.rspiffeverify.expiry);
		break;

	/* -- Transport -- */
	case P9N_TCXLMAP:
		rc = p9n_buf_get_u32(buf, &fc->u.cxlmap.fid);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.cxlmap.offset);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.cxlmap.length);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.cxlmap.prot);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.cxlmap.flags);
		break;

	case P9N_RCXLMAP:
		rc = p9n_buf_get_u64(buf, &fc->u.rcxlmap.hpa);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.rcxlmap.length);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.rcxlmap.granularity);
		if (rc) return rc;
		rc = p9n_buf_get_u8(buf, &fc->u.rcxlmap.coherence);
		break;

	case P9N_TCXLCOHERENCE:
		rc = p9n_buf_get_u32(buf, &fc->u.cxlcoherence.fid);
		if (rc) return rc;
		rc = p9n_buf_get_u8(buf, &fc->u.cxlcoherence.mode);
		break;

	case P9N_RCXLCOHERENCE:
		rc = p9n_buf_get_u8(buf, &fc->u.rcxlcoherence.mode);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.rcxlcoherence.snoop_id);
		break;

	case P9N_TRDMATOKEN:
		rc = p9n_buf_get_u32(buf, &fc->u.rdmatoken.fid);
		if (rc) return rc;
		rc = p9n_buf_get_u8(buf, &fc->u.rdmatoken.direction);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.rdmatoken.rkey);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.rdmatoken.addr);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.rdmatoken.length);
		break;

	case P9N_RRDMATOKEN:
		rc = p9n_buf_get_u32(buf, &fc->u.rrdmatoken.rkey);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.rrdmatoken.addr);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.rrdmatoken.length);
		break;

	case P9N_TRDMANOTIFY:
		rc = p9n_buf_get_u32(buf, &fc->u.rdmanotify.rkey);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.rdmanotify.addr);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.rdmanotify.length);
		if (rc) return rc;
		rc = p9n_buf_get_u16(buf, &fc->u.rdmanotify.slots);
		break;

	case P9N_RRDMANOTIFY:
		/* empty payload */
		break;

	case P9N_TQUICSTREAM:
		rc = p9n_buf_get_u8(buf, &fc->u.quicstream.stream_type);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.quicstream.stream_id);
		break;

	case P9N_RQUICSTREAM:
		rc = p9n_buf_get_u64(buf, &fc->u.rquicstream.stream_id);
		break;

	/* -- Performance -- */
	case P9N_TCOMPOUND:
		rc = unmarshal_subops(buf, &fc->u.compound.nops,
		                      &fc->u.compound.ops);
		break;

	case P9N_RCOMPOUND:
		rc = unmarshal_subops(buf, &fc->u.rcompound.nresults,
		                      &fc->u.rcompound.results);
		break;

	case P9N_TCOMPRESS:
		rc = p9n_buf_get_u8(buf, &fc->u.compress.algo);
		if (rc) return rc;
		rc = p9n_buf_get_u8(buf, &fc->u.compress.level);
		break;

	case P9N_RCOMPRESS:
		rc = p9n_buf_get_u8(buf, &fc->u.rcompress.algo);
		break;

	case P9N_TCOPYRANGE:
		rc = p9n_buf_get_u32(buf, &fc->u.copyrange.srcfid);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.copyrange.srcoff);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.copyrange.dstfid);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.copyrange.dstoff);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.copyrange.count);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.copyrange.flags);
		break;

	case P9N_RCOPYRANGE:
		rc = p9n_buf_get_u64(buf, &fc->u.rcopyrange.count);
		break;

	case P9N_TALLOCATE:
		rc = p9n_buf_get_u32(buf, &fc->u.allocate.fid);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.allocate.mode);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.allocate.offset);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.allocate.length);
		break;

	case P9N_RALLOCATE:
		/* empty */
		break;

	case P9N_TSEEKHOLE:
		rc = p9n_buf_get_u32(buf, &fc->u.seekhole.fid);
		if (rc) return rc;
		rc = p9n_buf_get_u8(buf, &fc->u.seekhole.type);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.seekhole.offset);
		break;

	case P9N_RSEEKHOLE:
		rc = p9n_buf_get_u64(buf, &fc->u.rseekhole.offset);
		break;

	case P9N_TMMAPHINT:
		rc = p9n_buf_get_u32(buf, &fc->u.mmaphint.fid);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.mmaphint.offset);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.mmaphint.length);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.mmaphint.prot);
		break;

	case P9N_RMMAPHINT:
		rc = p9n_buf_get_u8(buf, &fc->u.rmmaphint.granted);
		break;

	/* -- Filesystem -- */
	case P9N_TWATCH:
		rc = p9n_buf_get_u32(buf, &fc->u.watch.fid);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.watch.mask);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.watch.flags);
		break;

	case P9N_RWATCH:
		rc = p9n_buf_get_u32(buf, &fc->u.rwatch.watchid);
		break;

	case P9N_TUNWATCH:
		rc = p9n_buf_get_u32(buf, &fc->u.unwatch.watchid);
		break;

	case P9N_RUNWATCH:
		/* empty */
		break;

	case P9N_RNOTIFY:
		rc = p9n_buf_get_u32(buf, &fc->u.notify.watchid);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.notify.event);
		if (rc) return rc;
		rc = p9n_buf_get_str(buf, &fc->u.notify.name);
		if (rc) return rc;
		rc = get_qid(buf, &fc->u.notify.qid);
		break;

	case P9N_TGETACL:
		rc = p9n_buf_get_u32(buf, &fc->u.getacl.fid);
		if (rc) return rc;
		rc = p9n_buf_get_u8(buf, &fc->u.getacl.acltype);
		break;

	case P9N_RGETACL:
		rc = p9n_buf_get_data(buf, &fc->u.rgetacl.data,
		                      &fc->u.rgetacl.count);
		break;

	case P9N_TSETACL:
		rc = p9n_buf_get_u32(buf, &fc->u.setacl.fid);
		if (rc) return rc;
		rc = p9n_buf_get_u8(buf, &fc->u.setacl.acltype);
		if (rc) return rc;
		rc = p9n_buf_get_data(buf, &fc->u.setacl.data,
		                      &fc->u.setacl.count);
		break;

	case P9N_RSETACL:
		/* empty */
		break;

	case P9N_TSNAPSHOT:
		rc = p9n_buf_get_u32(buf, &fc->u.snapshot.fid);
		if (rc) return rc;
		rc = p9n_buf_get_str(buf, &fc->u.snapshot.name);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.snapshot.flags);
		break;

	case P9N_RSNAPSHOT:
		rc = get_qid(buf, &fc->u.rsnapshot.qid);
		break;

	case P9N_TCLONE:
		rc = p9n_buf_get_u32(buf, &fc->u.clone.srcfid);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.clone.dstfid);
		if (rc) return rc;
		rc = p9n_buf_get_str(buf, &fc->u.clone.name);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.clone.flags);
		break;

	case P9N_RCLONE:
		rc = get_qid(buf, &fc->u.rclone.qid);
		break;

	case P9N_TXATTRGET:
		rc = p9n_buf_get_u32(buf, &fc->u.xattrget.fid);
		if (rc) return rc;
		rc = p9n_buf_get_str(buf, &fc->u.xattrget.name);
		break;

	case P9N_RXATTRGET:
		rc = p9n_buf_get_data(buf, &fc->u.rxattrget.data,
		                      &fc->u.rxattrget.count);
		break;

	case P9N_TXATTRSET:
		rc = p9n_buf_get_u32(buf, &fc->u.xattrset.fid);
		if (rc) return rc;
		rc = p9n_buf_get_str(buf, &fc->u.xattrset.name);
		if (rc) return rc;
		rc = p9n_buf_get_data(buf, &fc->u.xattrset.data,
		                      &fc->u.xattrset.count);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.xattrset.flags);
		break;

	case P9N_RXATTRSET:
		/* empty */
		break;

	case P9N_TXATTRLIST:
		rc = p9n_buf_get_u32(buf, &fc->u.xattrlist.fid);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.xattrlist.cookie);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.xattrlist.count);
		break;

	case P9N_RXATTRLIST:
		rc = p9n_buf_get_u64(buf, &fc->u.rxattrlist.cookie);
		if (rc) return rc;
		rc = p9n_buf_get_u16(buf, &fc->u.rxattrlist.nattrs);
		if (rc) return rc;
		if (fc->u.rxattrlist.nattrs) {
			fc->u.rxattrlist.names = calloc(fc->u.rxattrlist.nattrs,
			                                sizeof(char *));
			if (!fc->u.rxattrlist.names)
				return -ENOMEM;
			for (uint16_t i = 0; i < fc->u.rxattrlist.nattrs; i++) {
				rc = p9n_buf_get_str(buf, &fc->u.rxattrlist.names[i]);
				if (rc) return rc;
			}
		}
		break;

	/* -- Distributed -- */
	case P9N_TLEASE:
		rc = p9n_buf_get_u32(buf, &fc->u.lease.fid);
		if (rc) return rc;
		rc = p9n_buf_get_u8(buf, &fc->u.lease.type);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.lease.duration);
		break;

	case P9N_RLEASE:
		rc = p9n_buf_get_u64(buf, &fc->u.rlease.leaseid);
		if (rc) return rc;
		rc = p9n_buf_get_u8(buf, &fc->u.rlease.type);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.rlease.duration);
		break;

	case P9N_TLEASERENEW:
		rc = p9n_buf_get_u64(buf, &fc->u.leaserenew.leaseid);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.leaserenew.duration);
		break;

	case P9N_RLEASERENEW:
		rc = p9n_buf_get_u32(buf, &fc->u.rleaserenew.duration);
		break;

	case P9N_RLEASEBREAK:
		rc = p9n_buf_get_u64(buf, &fc->u.leasebreak.leaseid);
		if (rc) return rc;
		rc = p9n_buf_get_u8(buf, &fc->u.leasebreak.newtype);
		break;

	case P9N_TLEASEACK:
		rc = p9n_buf_get_u64(buf, &fc->u.leaseack.leaseid);
		break;

	case P9N_RLEASEACK:
		/* empty */
		break;

	case P9N_TSESSION:
		if (buf->pos + 16 > buf->len)
			return -EIO;
		memcpy(fc->u.session.key, buf->data + buf->pos, 16);
		buf->pos += 16;
		rc = p9n_buf_get_u32(buf, &fc->u.session.flags);
		break;

	case P9N_RSESSION:
		rc = p9n_buf_get_u32(buf, &fc->u.rsession.flags);
		break;

	case P9N_TCONSISTENCY:
		rc = p9n_buf_get_u32(buf, &fc->u.consist.fid);
		if (rc) return rc;
		rc = p9n_buf_get_u8(buf, &fc->u.consist.level);
		break;

	case P9N_RCONSISTENCY:
		rc = p9n_buf_get_u8(buf, &fc->u.rconsist.level);
		break;

	case P9N_TTOPOLOGY:
		rc = p9n_buf_get_u32(buf, &fc->u.topology.fid);
		break;

	case P9N_RTOPOLOGY:
		rc = p9n_buf_get_u16(buf, &fc->u.rtopology.nreplicas);
		if (rc) return rc;
		if (fc->u.rtopology.nreplicas) {
			fc->u.rtopology.replicas = calloc(fc->u.rtopology.nreplicas,
			                                  sizeof(struct p9n_replica));
			if (!fc->u.rtopology.replicas)
				return -ENOMEM;
			for (uint16_t i = 0; i < fc->u.rtopology.nreplicas; i++) {
				rc = p9n_buf_get_str(buf, &fc->u.rtopology.replicas[i].addr);
				if (rc) return rc;
				rc = p9n_buf_get_u8(buf, &fc->u.rtopology.replicas[i].role);
				if (rc) return rc;
				rc = p9n_buf_get_u32(buf, &fc->u.rtopology.replicas[i].latency_us);
				if (rc) return rc;
			}
		}
		break;

	/* -- Observability -- */
	case P9N_TTRACEATTR:
		rc = p9n_buf_get_u16(buf, &fc->u.traceattr.nattrs);
		if (rc) return rc;
		if (fc->u.traceattr.nattrs) {
			fc->u.traceattr.keys = calloc(fc->u.traceattr.nattrs,
			                              sizeof(char *));
			fc->u.traceattr.values = calloc(fc->u.traceattr.nattrs,
			                                sizeof(char *));
			if (!fc->u.traceattr.keys || !fc->u.traceattr.values)
				return -ENOMEM;
			for (uint16_t i = 0; i < fc->u.traceattr.nattrs; i++) {
				rc = p9n_buf_get_str(buf, &fc->u.traceattr.keys[i]);
				if (rc) return rc;
				rc = p9n_buf_get_str(buf, &fc->u.traceattr.values[i]);
				if (rc) return rc;
			}
		}
		break;

	case P9N_RTRACEATTR:
		/* empty */
		break;

	case P9N_THEALTH:
		/* empty */
		break;

	case P9N_RHEALTH:
		rc = p9n_buf_get_u8(buf, &fc->u.rhealth.status);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.rhealth.load);
		if (rc) return rc;
		rc = p9n_buf_get_u16(buf, &fc->u.rhealth.nmetrics);
		if (rc) return rc;
		if (fc->u.rhealth.nmetrics) {
			fc->u.rhealth.metrics = calloc(fc->u.rhealth.nmetrics,
			                               sizeof(struct p9n_metric));
			if (!fc->u.rhealth.metrics)
				return -ENOMEM;
			for (uint16_t i = 0; i < fc->u.rhealth.nmetrics; i++) {
				rc = p9n_buf_get_str(buf, &fc->u.rhealth.metrics[i].name);
				if (rc) return rc;
				rc = p9n_buf_get_u64(buf, &fc->u.rhealth.metrics[i].value);
				if (rc) return rc;
			}
		}
		break;

	case P9N_TSERVERSTATS:
		rc = p9n_buf_get_u64(buf, &fc->u.serverstats_req.mask);
		break;

	case P9N_RSERVERSTATS:
		rc = p9n_buf_get_u16(buf, &fc->u.rserverstats.nstats);
		if (rc) return rc;
		if (fc->u.rserverstats.nstats) {
			fc->u.rserverstats.stats = calloc(fc->u.rserverstats.nstats,
			                                  sizeof(struct p9n_server_stat));
			if (!fc->u.rserverstats.stats)
				return -ENOMEM;
			for (uint16_t i = 0; i < fc->u.rserverstats.nstats; i++) {
				rc = p9n_buf_get_str(buf, &fc->u.rserverstats.stats[i].name);
				if (rc) return rc;
				rc = p9n_buf_get_u8(buf, &fc->u.rserverstats.stats[i].type);
				if (rc) return rc;
				rc = p9n_buf_get_u64(buf, &fc->u.rserverstats.stats[i].value);
				if (rc) return rc;
			}
		}
		break;

	/* -- Resource management -- */
	case P9N_TGETQUOTA:
		rc = p9n_buf_get_u32(buf, &fc->u.getquota.fid);
		if (rc) return rc;
		rc = p9n_buf_get_u8(buf, &fc->u.getquota.type);
		break;

	case P9N_RGETQUOTA:
		rc = p9n_buf_get_u64(buf, &fc->u.rgetquota.bytes_used);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.rgetquota.bytes_limit);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.rgetquota.files_used);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.rgetquota.files_limit);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.rgetquota.grace_period);
		break;

	case P9N_TSETQUOTA:
		rc = p9n_buf_get_u32(buf, &fc->u.setquota.fid);
		if (rc) return rc;
		rc = p9n_buf_get_u8(buf, &fc->u.setquota.type);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.setquota.bytes_limit);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.setquota.files_limit);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.setquota.grace_period);
		break;

	case P9N_RSETQUOTA:
		/* empty */
		break;

	case P9N_TRATELIMIT:
		rc = p9n_buf_get_u32(buf, &fc->u.ratelimit.fid);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.ratelimit.iops);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.ratelimit.bps);
		break;

	case P9N_RRATELIMIT:
		rc = p9n_buf_get_u32(buf, &fc->u.rratelimit.iops);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.rratelimit.bps);
		break;

	/* -- Streaming/Async -- */
	case P9N_TASYNC: {
		rc = p9n_buf_get_u8(buf, &fc->u.async.innertype);
		if (rc) return rc;
		/* remaining bytes are the inner payload */
		uint32_t remaining = fc->size - P9_HDRSZ - 1;
		if (remaining > 0) {
			if (buf->pos + remaining > buf->len)
				return -EIO;
			fc->u.async.payload = malloc(remaining);
			if (!fc->u.async.payload)
				return -ENOMEM;
			memcpy(fc->u.async.payload, buf->data + buf->pos, remaining);
			buf->pos += remaining;
			fc->u.async.payload_len = remaining;
		}
		break;
	}

	case P9N_RASYNC:
		rc = p9n_buf_get_u64(buf, &fc->u.rasync.opid);
		if (rc) return rc;
		rc = p9n_buf_get_u8(buf, &fc->u.rasync.status);
		break;

	case P9N_TPOLL:
		rc = p9n_buf_get_u64(buf, &fc->u.poll.opid);
		break;

	case P9N_RPOLL: {
		rc = p9n_buf_get_u8(buf, &fc->u.rpoll.status);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.rpoll.progress);
		if (rc) return rc;
		uint32_t remaining = fc->size - P9_HDRSZ - 5;
		if (remaining > 0) {
			if (buf->pos + remaining > buf->len)
				return -EIO;
			fc->u.rpoll.payload = malloc(remaining);
			if (!fc->u.rpoll.payload)
				return -ENOMEM;
			memcpy(fc->u.rpoll.payload, buf->data + buf->pos, remaining);
			buf->pos += remaining;
			fc->u.rpoll.payload_len = remaining;
		}
		break;
	}

	case P9N_TSTREAMOPEN:
		rc = p9n_buf_get_u32(buf, &fc->u.streamopen.fid);
		if (rc) return rc;
		rc = p9n_buf_get_u8(buf, &fc->u.streamopen.direction);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.streamopen.offset);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.streamopen.count);
		break;

	case P9N_RSTREAMOPEN:
		rc = p9n_buf_get_u32(buf, &fc->u.rstreamopen.streamid);
		break;

	case P9N_TSTREAMDATA:
	case P9N_RSTREAMDATA:
		rc = p9n_buf_get_u32(buf, &fc->u.streamdata.streamid);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.streamdata.seq);
		if (rc) return rc;
		rc = p9n_buf_get_data(buf, &fc->u.streamdata.data,
		                      &fc->u.streamdata.count);
		break;

	case P9N_TSTREAMCLOSE:
		rc = p9n_buf_get_u32(buf, &fc->u.streamclose.streamid);
		break;

	case P9N_RSTREAMCLOSE:
		/* empty */
		break;

	/* -- Content-awareness -- */
	case P9N_TSEARCH:
		rc = p9n_buf_get_u32(buf, &fc->u.search.fid);
		if (rc) return rc;
		rc = p9n_buf_get_str(buf, &fc->u.search.query);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.search.flags);
		if (rc) return rc;
		rc = p9n_buf_get_u32(buf, &fc->u.search.maxresults);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.search.cookie);
		break;

	case P9N_RSEARCH:
		rc = p9n_buf_get_u64(buf, &fc->u.rsearch.cookie);
		if (rc) return rc;
		rc = p9n_buf_get_u16(buf, &fc->u.rsearch.nresults);
		if (rc) return rc;
		if (fc->u.rsearch.nresults) {
			fc->u.rsearch.entries = calloc(fc->u.rsearch.nresults,
			                               sizeof(struct p9n_search_entry));
			if (!fc->u.rsearch.entries)
				return -ENOMEM;
			for (uint16_t i = 0; i < fc->u.rsearch.nresults; i++) {
				rc = get_qid(buf, &fc->u.rsearch.entries[i].qid);
				if (rc) return rc;
				rc = p9n_buf_get_str(buf, &fc->u.rsearch.entries[i].name);
				if (rc) return rc;
				rc = p9n_buf_get_u32(buf, &fc->u.rsearch.entries[i].score);
				if (rc) return rc;
			}
		}
		break;

	case P9N_THASH:
		rc = p9n_buf_get_u32(buf, &fc->u.hash.fid);
		if (rc) return rc;
		rc = p9n_buf_get_u8(buf, &fc->u.hash.algo);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.hash.offset);
		if (rc) return rc;
		rc = p9n_buf_get_u64(buf, &fc->u.hash.length);
		break;

	case P9N_RHASH:
		rc = p9n_buf_get_u8(buf, &fc->u.rhash.algo);
		if (rc) return rc;
		rc = p9n_buf_get_u16(buf, &fc->u.rhash.hashlen);
		if (rc) return rc;
		if (fc->u.rhash.hashlen) {
			if (buf->pos + fc->u.rhash.hashlen > buf->len)
				return -EIO;
			fc->u.rhash.hash = malloc(fc->u.rhash.hashlen);
			if (!fc->u.rhash.hash)
				return -ENOMEM;
			memcpy(fc->u.rhash.hash, buf->data + buf->pos,
			       fc->u.rhash.hashlen);
			buf->pos += fc->u.rhash.hashlen;
		}
		break;

	default:
		return -ENOSYS;
	}

	return rc;
}

/* ======================================================================
 * Message type name lookup
 * ====================================================================== */

static const struct {
	uint8_t     type;
	const char *name;
} msg_names[] = {
	{ P9N_TCAPS,        "Tcaps"        },
	{ P9N_RCAPS,        "Rcaps"        },
	{ P9N_TSTARTLS,     "Tstartls"     },
	{ P9N_RSTARTLS,     "Rstartls"     },
	{ P9N_TAUTHNEG,     "Tauthneg"     },
	{ P9N_RAUTHNEG,     "Rauthneg"     },
	{ P9N_TCAPGRANT,    "Tcapgrant"    },
	{ P9N_RCAPGRANT,    "Rcapgrant"    },
	{ P9N_TCAPUSE,      "Tcapuse"      },
	{ P9N_RCAPUSE,      "Rcapuse"      },
	{ P9N_TAUDITCTL,    "Tauditctl"    },
	{ P9N_RAUDITCTL,    "Rauditctl"    },
	{ P9N_TSTARTLS_SPIFFE, "Tstartls_spiffe" },
	{ P9N_RSTARTLS_SPIFFE, "Rstartls_spiffe" },
	{ P9N_TFETCHBUNDLE,    "Tfetchbundle"    },
	{ P9N_RFETCHBUNDLE,    "Rfetchbundle"    },
	{ P9N_TSPIFFEVERIFY,   "Tspiffeverify"   },
	{ P9N_RSPIFFEVERIFY,   "Rspiffeverify"   },
	{ P9N_TCXLMAP,        "Tcxlmap"         },
	{ P9N_RCXLMAP,        "Rcxlmap"         },
	{ P9N_TCXLCOHERENCE,  "Tcxlcoherence"   },
	{ P9N_RCXLCOHERENCE,  "Rcxlcoherence"   },
	{ P9N_TRDMATOKEN,     "Trdmatoken"      },
	{ P9N_RRDMATOKEN,     "Rrdmatoken"      },
	{ P9N_TRDMANOTIFY,    "Trdmanotify"     },
	{ P9N_RRDMANOTIFY,    "Rrdmanotify"     },
	{ P9N_TQUICSTREAM,    "Tquicstream"     },
	{ P9N_RQUICSTREAM,    "Rquicstream"     },
	{ P9N_TCOMPOUND,    "Tcompound"    },
	{ P9N_RCOMPOUND,    "Rcompound"    },
	{ P9N_TCOMPRESS,    "Tcompress"    },
	{ P9N_RCOMPRESS,    "Rcompress"    },
	{ P9N_TCOPYRANGE,   "Tcopyrange"   },
	{ P9N_RCOPYRANGE,   "Rcopyrange"   },
	{ P9N_TALLOCATE,    "Tallocate"    },
	{ P9N_RALLOCATE,    "Rallocate"    },
	{ P9N_TSEEKHOLE,    "Tseekhole"    },
	{ P9N_RSEEKHOLE,    "Rseekhole"    },
	{ P9N_TMMAPHINT,    "Tmmaphint"    },
	{ P9N_RMMAPHINT,    "Rmmaphint"    },
	{ P9N_TWATCH,       "Twatch"       },
	{ P9N_RWATCH,       "Rwatch"       },
	{ P9N_TUNWATCH,     "Tunwatch"     },
	{ P9N_RUNWATCH,     "Runwatch"     },
	{ P9N_TNOTIFY,      "Tnotify"      },
	{ P9N_RNOTIFY,      "Rnotify"      },
	{ P9N_TGETACL,      "Tgetacl"      },
	{ P9N_RGETACL,      "Rgetacl"      },
	{ P9N_TSETACL,      "Tsetacl"      },
	{ P9N_RSETACL,      "Rsetacl"      },
	{ P9N_TSNAPSHOT,    "Tsnapshot"    },
	{ P9N_RSNAPSHOT,    "Rsnapshot"    },
	{ P9N_TCLONE,       "Tclone"       },
	{ P9N_RCLONE,       "Rclone"       },
	{ P9N_TXATTRGET,    "Txattrget"    },
	{ P9N_RXATTRGET,    "Rxattrget"    },
	{ P9N_TXATTRSET,    "Txattrset"    },
	{ P9N_RXATTRSET,    "Rxattrset"    },
	{ P9N_TXATTRLIST,   "Txattrlist"   },
	{ P9N_RXATTRLIST,   "Rxattrlist"   },
	{ P9N_TLEASE,       "Tlease"       },
	{ P9N_RLEASE,       "Rlease"       },
	{ P9N_TLEASERENEW,  "Tleaserenew"  },
	{ P9N_RLEASERENEW,  "Rleaserenew"  },
	{ P9N_TLEASEBREAK,  "Tleasebreak"  },
	{ P9N_RLEASEBREAK,  "Rleasebreak"  },
	{ P9N_TLEASEACK,    "Tleaseack"    },
	{ P9N_RLEASEACK,    "Rleaseack"    },
	{ P9N_TSESSION,     "Tsession"     },
	{ P9N_RSESSION,     "Rsession"     },
	{ P9N_TCONSISTENCY, "Tconsistency" },
	{ P9N_RCONSISTENCY, "Rconsistency" },
	{ P9N_TTOPOLOGY,    "Ttopology"    },
	{ P9N_RTOPOLOGY,    "Rtopology"    },
	{ P9N_TTRACEATTR,   "Ttraceattr"   },
	{ P9N_RTRACEATTR,   "Rtraceattr"   },
	{ P9N_THEALTH,      "Thealth"      },
	{ P9N_RHEALTH,      "Rhealth"      },
	{ P9N_TSERVERSTATS, "Tserverstats" },
	{ P9N_RSERVERSTATS, "Rserverstats" },
	{ P9N_TGETQUOTA,    "Tgetquota"    },
	{ P9N_RGETQUOTA,    "Rgetquota"    },
	{ P9N_TSETQUOTA,    "Tsetquota"    },
	{ P9N_RSETQUOTA,    "Rsetquota"    },
	{ P9N_TRATELIMIT,   "Tratelimit"   },
	{ P9N_RRATELIMIT,   "Rratelimit"   },
	{ P9N_TASYNC,       "Tasync"       },
	{ P9N_RASYNC,       "Rasync"       },
	{ P9N_TPOLL,        "Tpoll"        },
	{ P9N_RPOLL,        "Rpoll"        },
	{ P9N_TSTREAMOPEN,  "Tstreamopen"  },
	{ P9N_RSTREAMOPEN,  "Rstreamopen"  },
	{ P9N_TSTREAMDATA,  "Tstreamdata"  },
	{ P9N_RSTREAMDATA,  "Rstreamdata"  },
	{ P9N_TSTREAMCLOSE, "Tstreamclose" },
	{ P9N_RSTREAMCLOSE, "Rstreamclose" },
	{ P9N_TSEARCH,      "Tsearch"      },
	{ P9N_RSEARCH,      "Rsearch"      },
	{ P9N_THASH,        "Thash"        },
	{ P9N_RHASH,        "Rhash"        },
	{ 0, NULL }
};

const char *p9n_msg_name(uint8_t type)
{
	for (int i = 0; msg_names[i].name; i++) {
		if (msg_names[i].type == type)
			return msg_names[i].name;
	}
	return "unknown";
}

/* ======================================================================
 * Fcall free
 * ====================================================================== */

void p9n_fcall_free(struct p9n_fcall *fc)
{
	switch (fc->type) {
	case P9N_TCAPS:
	case P9N_RCAPS:
		for (uint16_t i = 0; i < fc->u.caps.ncaps; i++)
			free(fc->u.caps.caps[i]);
		free(fc->u.caps.caps);
		break;

	case P9N_TAUTHNEG:
		for (uint16_t i = 0; i < fc->u.authneg.nmechs; i++)
			free(fc->u.authneg.mechs[i]);
		free(fc->u.authneg.mechs);
		break;

	case P9N_RAUTHNEG:
		free(fc->u.rauthneg.mech);
		free(fc->u.rauthneg.challenge);
		break;

	case P9N_RCAPGRANT:
		free(fc->u.rcapgrant.token);
		break;

	case P9N_TCAPUSE:
		free(fc->u.capuse.token);
		break;

	case P9N_TSTARTLS_SPIFFE:
	case P9N_RSTARTLS_SPIFFE:
		free(fc->u.startls_spiffe.spiffe_id);
		free(fc->u.startls_spiffe.trust_domain);
		break;

	case P9N_TFETCHBUNDLE:
		free(fc->u.fetchbundle.trust_domain);
		break;

	case P9N_RFETCHBUNDLE:
		free(fc->u.rfetchbundle.trust_domain);
		free(fc->u.rfetchbundle.bundle);
		break;

	case P9N_TSPIFFEVERIFY:
		free(fc->u.spiffeverify.spiffe_id);
		free(fc->u.spiffeverify.svid);
		break;

	case P9N_RSPIFFEVERIFY:
		free(fc->u.rspiffeverify.spiffe_id);
		break;

	case P9N_TCOMPOUND:
		for (uint16_t i = 0; i < fc->u.compound.nops; i++)
			free(fc->u.compound.ops[i].payload);
		free(fc->u.compound.ops);
		break;

	case P9N_RCOMPOUND:
		for (uint16_t i = 0; i < fc->u.rcompound.nresults; i++)
			free(fc->u.rcompound.results[i].payload);
		free(fc->u.rcompound.results);
		break;

	case P9N_RNOTIFY:
		free(fc->u.notify.name);
		break;

	case P9N_RGETACL:
		free(fc->u.rgetacl.data);
		break;

	case P9N_TSETACL:
		free(fc->u.setacl.data);
		break;

	case P9N_TSNAPSHOT:
		free(fc->u.snapshot.name);
		break;

	case P9N_TCLONE:
		free(fc->u.clone.name);
		break;

	case P9N_TXATTRGET:
		free(fc->u.xattrget.name);
		break;

	case P9N_RXATTRGET:
		free(fc->u.rxattrget.data);
		break;

	case P9N_TXATTRSET:
		free(fc->u.xattrset.name);
		free(fc->u.xattrset.data);
		break;

	case P9N_RXATTRLIST:
		for (uint16_t i = 0; i < fc->u.rxattrlist.nattrs; i++)
			free(fc->u.rxattrlist.names[i]);
		free(fc->u.rxattrlist.names);
		break;

	case P9N_RTOPOLOGY:
		for (uint16_t i = 0; i < fc->u.rtopology.nreplicas; i++)
			free(fc->u.rtopology.replicas[i].addr);
		free(fc->u.rtopology.replicas);
		break;

	case P9N_TTRACEATTR:
		for (uint16_t i = 0; i < fc->u.traceattr.nattrs; i++) {
			free(fc->u.traceattr.keys[i]);
			free(fc->u.traceattr.values[i]);
		}
		free(fc->u.traceattr.keys);
		free(fc->u.traceattr.values);
		break;

	case P9N_RHEALTH:
		for (uint16_t i = 0; i < fc->u.rhealth.nmetrics; i++)
			free(fc->u.rhealth.metrics[i].name);
		free(fc->u.rhealth.metrics);
		break;

	case P9N_RSERVERSTATS:
		for (uint16_t i = 0; i < fc->u.rserverstats.nstats; i++)
			free(fc->u.rserverstats.stats[i].name);
		free(fc->u.rserverstats.stats);
		break;

	case P9N_TASYNC:
		free(fc->u.async.payload);
		break;

	case P9N_RPOLL:
		free(fc->u.rpoll.payload);
		break;

	case P9N_TSTREAMDATA:
	case P9N_RSTREAMDATA:
		free(fc->u.streamdata.data);
		break;

	case P9N_TSEARCH:
		free(fc->u.search.query);
		break;

	case P9N_RSEARCH:
		for (uint16_t i = 0; i < fc->u.rsearch.nresults; i++)
			free(fc->u.rsearch.entries[i].name);
		free(fc->u.rsearch.entries);
		break;

	case P9N_RHASH:
		free(fc->u.rhash.hash);
		break;

	default:
		break;
	}

	memset(fc, 0, sizeof(*fc));
}
