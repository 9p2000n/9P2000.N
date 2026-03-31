/* SPDX-License-Identifier: MIT */
/*
 * p9n_buf -- growable byte buffer for 9P2000.N message marshalling.
 *
 * All multi-byte integers are written/read in little-endian order per the
 * 9P wire format specification.
 */

#include "../include/9pN.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define P9N_BUF_INITIAL_CAP  4096
#define P9N_BUF_MAX_CAP      (1U << 31)  /* 2 GB -- matches perf.largemsg */

int p9n_buf_init(struct p9n_buf *buf, size_t initial_cap)
{
	if (!initial_cap)
		initial_cap = P9N_BUF_INITIAL_CAP;

	buf->data = malloc(initial_cap);
	if (!buf->data)
		return -ENOMEM;

	buf->len = 0;
	buf->cap = initial_cap;
	buf->pos = 0;
	return 0;
}

void p9n_buf_free(struct p9n_buf *buf)
{
	free(buf->data);
	buf->data = NULL;
	buf->len = 0;
	buf->cap = 0;
	buf->pos = 0;
}

void p9n_buf_reset(struct p9n_buf *buf)
{
	buf->len = 0;
	buf->pos = 0;
}

int p9n_buf_ensure(struct p9n_buf *buf, size_t additional)
{
	size_t needed = buf->len + additional;
	if (needed <= buf->cap)
		return 0;

	size_t newcap = buf->cap;
	while (newcap < needed) {
		if (newcap >= P9N_BUF_MAX_CAP)
			return -ENOMEM;
		newcap *= 2;
		if (newcap > P9N_BUF_MAX_CAP)
			newcap = P9N_BUF_MAX_CAP;
	}

	uint8_t *newdata = realloc(buf->data, newcap);
	if (!newdata)
		return -ENOMEM;

	buf->data = newdata;
	buf->cap = newcap;
	return 0;
}

/* ---- Write primitives (little-endian) -------------------------------- */

int p9n_buf_put_u8(struct p9n_buf *buf, uint8_t val)
{
	int rc = p9n_buf_ensure(buf, 1);
	if (rc)
		return rc;
	buf->data[buf->len++] = val;
	return 0;
}

int p9n_buf_put_u16(struct p9n_buf *buf, uint16_t val)
{
	int rc = p9n_buf_ensure(buf, 2);
	if (rc)
		return rc;
	buf->data[buf->len++] = (uint8_t)(val);
	buf->data[buf->len++] = (uint8_t)(val >> 8);
	return 0;
}

int p9n_buf_put_u32(struct p9n_buf *buf, uint32_t val)
{
	int rc = p9n_buf_ensure(buf, 4);
	if (rc)
		return rc;
	buf->data[buf->len++] = (uint8_t)(val);
	buf->data[buf->len++] = (uint8_t)(val >> 8);
	buf->data[buf->len++] = (uint8_t)(val >> 16);
	buf->data[buf->len++] = (uint8_t)(val >> 24);
	return 0;
}

int p9n_buf_put_u64(struct p9n_buf *buf, uint64_t val)
{
	int rc = p9n_buf_ensure(buf, 8);
	if (rc)
		return rc;
	for (int i = 0; i < 8; i++)
		buf->data[buf->len++] = (uint8_t)(val >> (i * 8));
	return 0;
}

int p9n_buf_put_str(struct p9n_buf *buf, const char *s)
{
	uint16_t slen = s ? (uint16_t)strlen(s) : 0;
	int rc = p9n_buf_put_u16(buf, slen);
	if (rc)
		return rc;
	if (slen) {
		rc = p9n_buf_ensure(buf, slen);
		if (rc)
			return rc;
		memcpy(buf->data + buf->len, s, slen);
		buf->len += slen;
	}
	return 0;
}

int p9n_buf_put_data(struct p9n_buf *buf, const void *data, uint32_t len)
{
	int rc = p9n_buf_put_u32(buf, len);
	if (rc)
		return rc;
	if (len) {
		rc = p9n_buf_ensure(buf, len);
		if (rc)
			return rc;
		memcpy(buf->data + buf->len, data, len);
		buf->len += len;
	}
	return 0;
}

/* ---- Read primitives (little-endian) --------------------------------- */

int p9n_buf_get_u8(struct p9n_buf *buf, uint8_t *val)
{
	if (buf->pos + 1 > buf->len)
		return -EIO;
	*val = buf->data[buf->pos++];
	return 0;
}

int p9n_buf_get_u16(struct p9n_buf *buf, uint16_t *val)
{
	if (buf->pos + 2 > buf->len)
		return -EIO;
	*val = (uint16_t)buf->data[buf->pos]
	     | ((uint16_t)buf->data[buf->pos + 1] << 8);
	buf->pos += 2;
	return 0;
}

int p9n_buf_get_u32(struct p9n_buf *buf, uint32_t *val)
{
	if (buf->pos + 4 > buf->len)
		return -EIO;
	*val = (uint32_t)buf->data[buf->pos]
	     | ((uint32_t)buf->data[buf->pos + 1] << 8)
	     | ((uint32_t)buf->data[buf->pos + 2] << 16)
	     | ((uint32_t)buf->data[buf->pos + 3] << 24);
	buf->pos += 4;
	return 0;
}

int p9n_buf_get_u64(struct p9n_buf *buf, uint64_t *val)
{
	if (buf->pos + 8 > buf->len)
		return -EIO;
	*val = 0;
	for (int i = 0; i < 8; i++)
		*val |= (uint64_t)buf->data[buf->pos + i] << (i * 8);
	buf->pos += 8;
	return 0;
}

int p9n_buf_get_str(struct p9n_buf *buf, char **s)
{
	uint16_t slen;
	int rc = p9n_buf_get_u16(buf, &slen);
	if (rc)
		return rc;
	if (buf->pos + slen > buf->len)
		return -EIO;

	*s = malloc(slen + 1);
	if (!*s)
		return -ENOMEM;

	memcpy(*s, buf->data + buf->pos, slen);
	(*s)[slen] = '\0';
	buf->pos += slen;
	return 0;
}

int p9n_buf_get_data(struct p9n_buf *buf, uint8_t **data, uint32_t *len)
{
	int rc = p9n_buf_get_u32(buf, len);
	if (rc)
		return rc;
	if (buf->pos + *len > buf->len)
		return -EIO;

	if (*len) {
		*data = malloc(*len);
		if (!*data)
			return -ENOMEM;
		memcpy(*data, buf->data + buf->pos, *len);
		buf->pos += *len;
	} else {
		*data = NULL;
	}
	return 0;
}
