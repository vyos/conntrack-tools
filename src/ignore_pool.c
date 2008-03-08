/*
 * (C) 2006-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
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

#include "ignore.h"
#include "jhash.h"
#include "hash.h"
#include "conntrackd.h"
#include "log.h"

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <stdlib.h>
#include <string.h>

/* XXX: These should be configurable, better use a rb-tree */
#define IGNORE_POOL_SIZE 128
#define IGNORE_POOL_LIMIT INT_MAX

static uint32_t hash(const void *data, struct hashtable *table)
{
	const uint32_t *ip = data;

	return jhash_1word(*ip, 0) % table->hashsize;
}

static uint32_t hash6(const void *data, struct hashtable *table)
{
	return jhash(data, sizeof(uint32_t)*4, 0) % table->hashsize;
}

static int compare(const void *data1, const void *data2)
{
	const uint32_t *ip1 = data1;
	const uint32_t *ip2 = data2;

	return *ip1 == *ip2;
}

static int compare6(const void *data1, const void *data2)
{
	return memcmp(data1, data2, sizeof(uint32_t)*4) == 0;
}

struct ignore_pool *ignore_pool_create(void)
{
	struct ignore_pool *ip;

	ip = malloc(sizeof(struct ignore_pool));
	if (!ip)
		return NULL;
	memset(ip, 0, sizeof(struct ignore_pool));

	ip->h = hashtable_create(IGNORE_POOL_SIZE,
				 IGNORE_POOL_LIMIT,
				 sizeof(uint32_t),
				 hash,
				 compare);
	if (!ip->h) {
		free(ip);
		return NULL;
	}

	ip->h6 = hashtable_create(IGNORE_POOL_SIZE,
				  IGNORE_POOL_LIMIT,
				  sizeof(uint32_t)*4,
				  hash6,
				  compare6);
	if (!ip->h6) {
		free(ip->h);
		free(ip);
		return NULL;
	}

	return ip;
}

void ignore_pool_destroy(struct ignore_pool *ip)
{
	hashtable_destroy(ip->h);
	hashtable_destroy(ip->h6);
	free(ip);
}

int ignore_pool_add(struct ignore_pool *ip, void *data, uint8_t family)
{
	switch(family) {
		case AF_INET:
			if (!hashtable_add(ip->h, data))
				return 0;
			break;
		case AF_INET6:
			if (!hashtable_add(ip->h6, data))
				return 0;
			break;
	}
	return 1;
}

static int
__ignore_pool_test_ipv4(struct ignore_pool *ip, struct nf_conntrack *ct)
{
	if (!ip->h)
		return 0;

	return (hashtable_test(ip->h, nfct_get_attr(ct, ATTR_ORIG_IPV4_SRC)) ||
		hashtable_test(ip->h, nfct_get_attr(ct, ATTR_ORIG_IPV4_DST)) ||
		hashtable_test(ip->h, nfct_get_attr(ct, ATTR_REPL_IPV4_SRC)) ||
		hashtable_test(ip->h, nfct_get_attr(ct, ATTR_REPL_IPV4_DST)));
}

static int
__ignore_pool_test_ipv6(struct ignore_pool *ip, struct nf_conntrack *ct)
{
	if (!ip->h6)
		return 0;

	return (hashtable_test(ip->h6, nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC)) ||
	        hashtable_test(ip->h6, nfct_get_attr(ct, ATTR_ORIG_IPV6_DST)) ||
	        hashtable_test(ip->h6, nfct_get_attr(ct, ATTR_REPL_IPV6_SRC)) ||
	        hashtable_test(ip->h6, nfct_get_attr(ct, ATTR_REPL_IPV6_DST)));
}

int ignore_pool_test(struct ignore_pool *ip, struct nf_conntrack *ct)
{
	int ret = 0;

	switch(nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO)) {
	case AF_INET:
		ret = __ignore_pool_test_ipv4(ip, ct);
		break;
	case AF_INET6:
		ret = __ignore_pool_test_ipv6(ip, ct);
		break;
	default:
		dlog(LOG_WARNING, "unknown layer 3 protocol?");
		break;
	}

	return ret;
}
