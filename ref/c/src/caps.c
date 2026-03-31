/* SPDX-License-Identifier: MIT */
/*
 * Capability negotiation for 9P2000.N.
 *
 * After Tversion/Rversion agrees on "9P2000.N", the client sends Tcaps
 * with the list of capabilities it desires. The server responds Rcaps
 * with the subset it supports. Both sides then store the intersection.
 */

#define _POSIX_C_SOURCE 200809L
#include "../include/9pN.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Mapping from capability string to bit index */
static const struct {
	const char    *name;
	enum p9n_cap_bit bit;
} cap_table[] = {
	{ P9N_CAP_TLS,         P9N_CBIT_TLS         },
	{ P9N_CAP_AUTH,        P9N_CBIT_AUTH         },
	{ P9N_CAP_CAPS,        P9N_CBIT_CAPS         },
	{ P9N_CAP_AUDIT,       P9N_CBIT_AUDIT        },
	{ P9N_CAP_COMPOUND,    P9N_CBIT_COMPOUND     },
	{ P9N_CAP_LARGEMSG,    P9N_CBIT_LARGEMSG     },
	{ P9N_CAP_COMPRESS,    P9N_CBIT_COMPRESS     },
	{ P9N_CAP_ZEROCOPY,    P9N_CBIT_ZEROCOPY     },
	{ P9N_CAP_COPY,        P9N_CBIT_COPY         },
	{ P9N_CAP_ALLOC,       P9N_CBIT_ALLOC        },
	{ P9N_CAP_MMAP,        P9N_CBIT_MMAP         },
	{ P9N_CAP_WATCH,       P9N_CBIT_WATCH        },
	{ P9N_CAP_ACL,         P9N_CBIT_ACL          },
	{ P9N_CAP_SNAPSHOT,    P9N_CBIT_SNAPSHOT      },
	{ P9N_CAP_XATTR2,     P9N_CBIT_XATTR2       },
	{ P9N_CAP_LEASE,       P9N_CBIT_LEASE        },
	{ P9N_CAP_SESSION,     P9N_CBIT_SESSION       },
	{ P9N_CAP_CONSISTENCY, P9N_CBIT_CONSISTENCY   },
	{ P9N_CAP_TOPOLOGY,    P9N_CBIT_TOPOLOGY      },
	{ P9N_CAP_TRACE,       P9N_CBIT_TRACE        },
	{ P9N_CAP_HEALTH,      P9N_CBIT_HEALTH       },
	{ P9N_CAP_STATS,       P9N_CBIT_STATS        },
	{ P9N_CAP_QUOTA,       P9N_CBIT_QUOTA        },
	{ P9N_CAP_RATELIMIT,   P9N_CBIT_RATELIMIT    },
	{ P9N_CAP_ASYNC,       P9N_CBIT_ASYNC        },
	{ P9N_CAP_PIPE,        P9N_CBIT_PIPE         },
	{ P9N_CAP_SEARCH,      P9N_CBIT_SEARCH       },
	{ P9N_CAP_HASH,        P9N_CBIT_HASH         },
	{ P9N_CAP_SPIFFE,      P9N_CBIT_SPIFFE       },
	{ P9N_CAP_QUIC,        P9N_CBIT_QUIC         },
	{ P9N_CAP_QUIC_MULTI,  P9N_CBIT_QUIC_MULTI   },
	{ P9N_CAP_RDMA,        P9N_CBIT_RDMA         },
	{ P9N_CAP_CXL,         P9N_CBIT_CXL          },
	{ NULL, 0 }
};

int p9n_cap_to_bit(const char *cap)
{
	for (int i = 0; cap_table[i].name; i++) {
		if (strcmp(cap_table[i].name, cap) == 0)
			return (int)cap_table[i].bit;
	}
	return -1;
}

void p9n_capset_init(struct p9n_capset *cs)
{
	cs->bits = 0;
	cs->ncaps = 0;
	cs->caps = NULL;
}

void p9n_capset_free(struct p9n_capset *cs)
{
	for (uint16_t i = 0; i < cs->ncaps; i++)
		free(cs->caps[i]);
	free(cs->caps);
	cs->caps = NULL;
	cs->ncaps = 0;
	cs->bits = 0;
}

int p9n_capset_add(struct p9n_capset *cs, const char *cap)
{
	/* Check for duplicates */
	for (uint16_t i = 0; i < cs->ncaps; i++) {
		if (strcmp(cs->caps[i], cap) == 0)
			return 0;
	}

	if (cs->ncaps >= P9N_MAX_CAPS)
		return -ENOSPC;

	char *dup = strdup(cap);
	if (!dup)
		return -ENOMEM;

	char **newcaps = realloc(cs->caps, (cs->ncaps + 1) * sizeof(char *));
	if (!newcaps) {
		free(dup);
		return -ENOMEM;
	}

	cs->caps = newcaps;
	cs->caps[cs->ncaps++] = dup;

	/* Update bitmask */
	int bit = p9n_cap_to_bit(cap);
	if (bit >= 0)
		cs->bits |= P9N_CAP_SET(bit);

	return 0;
}

int p9n_capset_has(const struct p9n_capset *cs, const char *cap)
{
	/* Fast path: check bitmask for known capabilities */
	int bit = p9n_cap_to_bit(cap);
	if (bit >= 0)
		return P9N_CAP_HAS(cs->bits, bit) ? 1 : 0;

	/* Slow path: linear search for unknown/extension capabilities */
	for (uint16_t i = 0; i < cs->ncaps; i++) {
		if (strcmp(cs->caps[i], cap) == 0)
			return 1;
	}
	return 0;
}

int p9n_capset_has_bit(const struct p9n_capset *cs, enum p9n_cap_bit bit)
{
	return P9N_CAP_HAS(cs->bits, bit) ? 1 : 0;
}

int p9n_capset_intersect(struct p9n_capset *result,
                         const struct p9n_capset *client,
                         const struct p9n_capset *server)
{
	p9n_capset_init(result);

	for (uint16_t i = 0; i < client->ncaps; i++) {
		if (p9n_capset_has(server, client->caps[i])) {
			int rc = p9n_capset_add(result, client->caps[i]);
			if (rc)
				return rc;
		}
	}
	return 0;
}

/* ======================================================================
 * Marshal / Unmarshal Tcaps and Rcaps
 * ====================================================================== */

int p9n_marshal_caps(struct p9n_buf *buf, uint16_t tag,
                     const struct p9n_caps *caps)
{
	/* Reserve space for size[4], fill later */
	size_t size_offset = buf->len;
	int rc;

	rc = p9n_buf_put_u32(buf, 0);           /* placeholder size */
	if (rc) return rc;
	rc = p9n_buf_put_u8(buf, P9N_TCAPS);
	if (rc) return rc;
	rc = p9n_buf_put_u16(buf, tag);
	if (rc) return rc;
	rc = p9n_buf_put_u16(buf, caps->ncaps);
	if (rc) return rc;

	for (uint16_t i = 0; i < caps->ncaps; i++) {
		rc = p9n_buf_put_str(buf, caps->caps[i]);
		if (rc) return rc;
	}

	/* Patch size field */
	uint32_t total = (uint32_t)(buf->len - size_offset);
	buf->data[size_offset + 0] = (uint8_t)(total);
	buf->data[size_offset + 1] = (uint8_t)(total >> 8);
	buf->data[size_offset + 2] = (uint8_t)(total >> 16);
	buf->data[size_offset + 3] = (uint8_t)(total >> 24);
	return 0;
}

/* ======================================================================
 * Populate a capset from a Tcaps/Rcaps message
 * ====================================================================== */

int p9n_capset_from_caps(struct p9n_capset *cs, const struct p9n_caps *caps)
{
	p9n_capset_init(cs);
	for (uint16_t i = 0; i < caps->ncaps; i++) {
		int rc = p9n_capset_add(cs, caps->caps[i]);
		if (rc)
			return rc;
	}
	return 0;
}

/* ======================================================================
 * Build a caps message from a capset
 * ====================================================================== */

int p9n_caps_from_capset(struct p9n_caps *caps, const struct p9n_capset *cs)
{
	caps->ncaps = cs->ncaps;
	caps->caps = cs->caps;  /* borrows pointers, caller must not free */
	return 0;
}
