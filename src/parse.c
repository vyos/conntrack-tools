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

#include "network.h"

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#ifndef ssizeof
#define ssizeof(x) (int)sizeof(x)
#endif

static void parse_u8(struct nf_conntrack *ct, int attr, void *data)
{
	uint8_t *value = (uint8_t *) data;
	nfct_set_attr_u8(ct, attr, *value);
}

static void parse_u16(struct nf_conntrack *ct, int attr, void *data)
{
	uint16_t *value = (uint16_t *) data;
	nfct_set_attr_u16(ct, attr, ntohs(*value));
}

static void parse_u32(struct nf_conntrack *ct, int attr, void *data)
{
	uint32_t *value = (uint32_t *) data;
	nfct_set_attr_u32(ct, attr, ntohl(*value));
}

static void parse_pointer_be(struct nf_conntrack *ct, int attr, void *data)
{
	nfct_set_attr(ct, attr, data);
}

typedef void (*parse)(struct nf_conntrack *ct, int attr, void *data);

static parse h[ATTR_MAX] = {
	[ATTR_IPV4_SRC]		= parse_pointer_be,
	[ATTR_IPV4_DST]		= parse_pointer_be,
	[ATTR_IPV6_SRC]		= parse_pointer_be,
	[ATTR_IPV6_DST]		= parse_pointer_be,
	[ATTR_L3PROTO]		= parse_u8,
	[ATTR_PORT_SRC]		= parse_u16,
	[ATTR_PORT_DST]		= parse_u16,
	[ATTR_L4PROTO]		= parse_u8,
	[ATTR_TCP_STATE]	= parse_u8,
	[ATTR_SNAT_IPV4]	= parse_u32,
	[ATTR_DNAT_IPV4]	= parse_u32,
	[ATTR_SNAT_PORT]	= parse_u16,
	[ATTR_DNAT_PORT]	= parse_u16,
	[ATTR_TIMEOUT]		= parse_u32,
	[ATTR_MARK]		= parse_u32,
	[ATTR_STATUS]		= parse_u32,
	[ATTR_MASTER_IPV4_SRC]  = parse_u32,
	[ATTR_MASTER_IPV4_DST]  = parse_u32,
	[ATTR_MASTER_L3PROTO]   = parse_u8,
	[ATTR_MASTER_PORT_SRC]  = parse_u16,
	[ATTR_MASTER_PORT_DST]  = parse_u16,
	[ATTR_MASTER_L4PROTO]   = parse_u8,
	[ATTR_ORIG_NAT_SEQ_CORRECTION_POS]	= parse_u32,
	[ATTR_ORIG_NAT_SEQ_OFFSET_BEFORE]	= parse_u32,
	[ATTR_ORIG_NAT_SEQ_OFFSET_AFTER]	= parse_u32,
	[ATTR_REPL_NAT_SEQ_CORRECTION_POS]	= parse_u32,
	[ATTR_REPL_NAT_SEQ_OFFSET_BEFORE]	= parse_u32,
	[ATTR_REPL_NAT_SEQ_OFFSET_AFTER]	= parse_u32,
};

int
parse_netpld(struct nf_conntrack *ct,
	     struct nethdr *net,
	     int *query,
	     size_t remain)
{
	int len;
	struct netattr *attr;
	struct netpld *pld;

	if (remain < NETHDR_SIZ + sizeof(struct netpld))
		return -1;

	pld = NETHDR_DATA(net);

	if (remain < NETHDR_SIZ + sizeof(struct netpld) + ntohs(pld->len))
		return -1;

	if (net->len < NETHDR_SIZ + sizeof(struct netpld) + ntohs(pld->len))
		return -1;

	PLD_NETWORK2HOST(pld);
	len = pld->len;
	attr = PLD_DATA(pld);

	while (len > ssizeof(struct netattr)) {
		ATTR_NETWORK2HOST(attr);
		if (attr->nta_len > len)
			return -1;
		if (h[attr->nta_attr])
			h[attr->nta_attr](ct, attr->nta_attr, NTA_DATA(attr));
		attr = NTA_NEXT(attr, len);
	}

	*query = pld->query;
	return 0;
}
