/*
 * (C) 2006-2008 by Pablo Neira Ayuso <pablo@netfilter.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "filter.h"
#include "bitops.h"
#include "jhash.h"
#include "hash.h"
#include "conntrackd.h"
#include "log.h"

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

struct ct_filter {
	int logic[CT_FILTER_MAX];
	u_int32_t l4protomap[IPPROTO_MAX/32];
	u_int16_t statemap[IPPROTO_MAX];
	struct hashtable *h;
	struct hashtable *h6;
};

/* XXX: These should be configurable, better use a rb-tree */
#define FILTER_POOL_SIZE 128
#define FILTER_POOL_LIMIT INT_MAX

static uint32_t hash(const void *data, struct hashtable *table)
{
	const uint32_t *f = data;

	return jhash_1word(*f, 0) % table->hashsize;
}

static uint32_t hash6(const void *data, struct hashtable *table)
{
	return jhash2(data, 4, 0) % table->hashsize;
}

static int compare(const void *data1, const void *data2)
{
	const uint32_t *f1 = data1;
	const uint32_t *f2 = data2;

	return *f1 == *f2;
}

static int compare6(const void *data1, const void *data2)
{
	return memcmp(data1, data2, sizeof(uint32_t)*4) == 0;
}

struct ct_filter *ct_filter_create(void)
{
	int i;
	struct ct_filter *filter;

	filter = calloc(sizeof(struct ct_filter), 1);
	if (!filter)
		return NULL;

	filter->h = hashtable_create(FILTER_POOL_SIZE,
				     FILTER_POOL_LIMIT,
				     sizeof(uint32_t),
				     hash,
				     compare);
	if (!filter->h) {
		free(filter);
		return NULL;
	}

	filter->h6 = hashtable_create(FILTER_POOL_SIZE,
				      FILTER_POOL_LIMIT,
				      sizeof(uint32_t)*4,
				      hash6,
				      compare6);
	if (!filter->h6) {
		free(filter->h);
		free(filter);
		return NULL;
	}

	for (i=0; i<CT_FILTER_MAX; i++)
		filter->logic[i] = -1;

	return filter;
}

void ct_filter_destroy(struct ct_filter *filter)
{
	hashtable_destroy(filter->h);
	hashtable_destroy(filter->h6);
	free(filter);
}

/* this is ugly, but it simplifies read_config_yy.y */
static struct ct_filter *__filter_alloc(struct ct_filter *filter)
{
	if (!STATE(us_filter)) {
		STATE(us_filter) = ct_filter_create();
		if (!STATE(us_filter)) {
			fprintf(stderr, "Can't create ignore pool!\n");
			exit(EXIT_FAILURE);
		}
	}

	return STATE(us_filter);
}

void ct_filter_set_logic(struct ct_filter *filter,
			 enum ct_filter_type type,
			 enum ct_filter_logic logic)
{
	filter = __filter_alloc(filter);
	filter->logic[type] = logic;
}

int ct_filter_add_ip(struct ct_filter *filter, void *data, uint8_t family)
{
	filter = __filter_alloc(filter);

	switch(family) {
		case AF_INET:
			if (!hashtable_add(filter->h, data))
				return 0;
			break;
		case AF_INET6:
			if (!hashtable_add(filter->h6, data))
				return 0;
			break;
	}
	return 1;
}

void ct_filter_add_proto(struct ct_filter *f, int protonum)
{
	f = __filter_alloc(f);

	set_bit_u32(protonum, f->l4protomap);
}

void ct_filter_add_state(struct ct_filter *f, int protonum, int val)
{
	f = __filter_alloc(f);

	set_bit_u16(val, &f->statemap[protonum]);
}

static int
__ct_filter_test_ipv4(struct ct_filter *f, struct nf_conntrack *ct)
{
	if (!f->h)
		return 0;

	/* we only use the real source and destination address */
	return (hashtable_test(f->h, nfct_get_attr(ct, ATTR_ORIG_IPV4_SRC)) ||
		hashtable_test(f->h, nfct_get_attr(ct, ATTR_REPL_IPV4_SRC)));
}

static int
__ct_filter_test_ipv6(struct ct_filter *f, struct nf_conntrack *ct)
{
	if (!f->h6)
		return 0;

	return (hashtable_test(f->h6, nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC)) ||
	        hashtable_test(f->h6, nfct_get_attr(ct, ATTR_REPL_IPV6_SRC)));
}

static int __ct_filter_test_state(struct ct_filter *f, struct nf_conntrack *ct)
{
	uint16_t val = 0;
	uint8_t protonum = nfct_get_attr_u8(ct, ATTR_L4PROTO);

	switch(protonum) {
	case IPPROTO_TCP:
		if (!nfct_attr_is_set(ct, ATTR_TCP_STATE))
			return -1;

		val = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
		break;
	default:
		return -1;
	}

	return test_bit_u16(val, &f->statemap[protonum]);
}

int ct_filter_check(struct ct_filter *f, struct nf_conntrack *ct)
{
	int ret, protonum = nfct_get_attr_u8(ct, ATTR_L4PROTO);

	/* no event filtering at all */
	if (f == NULL)
		return 1;

	if (f->logic[CT_FILTER_L4PROTO] != -1) {
		ret = test_bit_u32(protonum, f->l4protomap);
		if (ret ^ f->logic[CT_FILTER_L4PROTO])
			return 0;
	}

	if (f->logic[CT_FILTER_ADDRESS] != -1) {
		switch(nfct_get_attr_u8(ct, ATTR_L3PROTO)) {
		case AF_INET:
			ret = __ct_filter_test_ipv4(f, ct);
			if (ret ^ f->logic[CT_FILTER_ADDRESS])
				return 0;
			break;
		case AF_INET6:
			ret = __ct_filter_test_ipv6(f, ct);
			if (ret ^ f->logic[CT_FILTER_ADDRESS])
				return 0;
			break;
		default:
			break;
		}
	}

	if (f->logic[CT_FILTER_STATE] != -1) {
		ret = __ct_filter_test_state(f, ct);
		if (ret ^ f->logic[CT_FILTER_STATE])
			return 0;
	}

	return 1;
}
