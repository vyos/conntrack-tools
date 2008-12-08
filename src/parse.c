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

static void parse_u8(struct nf_conntrack *ct, int attr, void *data);
static void parse_u16(struct nf_conntrack *ct, int attr, void *data);
static void parse_u32(struct nf_conntrack *ct, int attr, void *data);
static void parse_group(struct nf_conntrack *ct, int attr, void *data);
static void parse_nat_seq_adj(struct nf_conntrack *ct, int attr, void *data);

struct parser {
	void 	(*parse)(struct nf_conntrack *ct, int attr, void *data);
	int 	attr;
};

static struct parser h[NTA_MAX] = {
	[NTA_IPV4] = {
		.parse	= parse_group,
		.attr	= ATTR_GRP_ORIG_IPV4,
	},
	[NTA_IPV6] = {
		.parse	= parse_group,
		.attr	= ATTR_GRP_ORIG_IPV6,
	},
	[NTA_PORT] = {
		.parse	= parse_group,
		.attr	= ATTR_GRP_ORIG_PORT,
	},
	[NTA_L4PROTO] = {
		.parse	= parse_u8,
		.attr	= ATTR_L4PROTO,
	},
	[NTA_STATE] = {
		.parse	= parse_u8,
		.attr	= ATTR_TCP_STATE,
	},
	[NTA_STATUS] = {
		.parse	= parse_u32,
		.attr	= ATTR_STATUS,
	},
	[NTA_MARK] = {
		.parse	= parse_u32,
		.attr	= ATTR_MARK,
	},
	[NTA_TIMEOUT] = {
		.parse	= parse_u32,
		.attr	= ATTR_TIMEOUT,
	},
	[NTA_MASTER_IPV4] = {
		.parse	= parse_group,
		.attr	= ATTR_GRP_MASTER_IPV4,
	},
	[NTA_MASTER_IPV6] = {
		.parse	= parse_group,
		.attr	= ATTR_GRP_MASTER_IPV6,
	},
	[NTA_MASTER_L4PROTO] = {
		.parse	= parse_u8,
		.attr	= ATTR_MASTER_L4PROTO,
	},
	[NTA_MASTER_PORT] = {
		.parse	= parse_group,
		.attr	= ATTR_GRP_MASTER_PORT,
	},
	[NTA_SNAT_IPV4]	= {
		.parse	= parse_u32,
		.attr	= ATTR_SNAT_IPV4,
	},
	[NTA_DNAT_IPV4] = {
		.parse	= parse_u32,
		.attr	= ATTR_DNAT_IPV4,
	},
	[NTA_SPAT_PORT]	= {
		.parse	= parse_u16,
		.attr	= ATTR_SNAT_PORT,
	},
	[NTA_DPAT_PORT]	= {
		.parse	= parse_u16,
		.attr	= ATTR_SNAT_PORT,
	},
	[NTA_NAT_SEQ_ADJ] = {
		.parse	= parse_nat_seq_adj,
	},
};

static void
parse_u8(struct nf_conntrack *ct, int attr, void *data)
{
	uint8_t *value = (uint8_t *) data;
	nfct_set_attr_u8(ct, h[attr].attr, *value);
}

static void
parse_u16(struct nf_conntrack *ct, int attr, void *data)
{
	uint16_t *value = (uint16_t *) data;
	nfct_set_attr_u16(ct, h[attr].attr, ntohs(*value));
}

static void
parse_u32(struct nf_conntrack *ct, int attr, void *data)
{
	uint32_t *value = (uint32_t *) data;
	nfct_set_attr_u32(ct, h[attr].attr, ntohl(*value));
}

static void
parse_group(struct nf_conntrack *ct, int attr, void *data)
{
	nfct_set_attr_grp(ct, h[attr].attr, data);
}

static void
parse_nat_seq_adj(struct nf_conntrack *ct, int attr, void *data)
{
	struct nta_attr_natseqadj *this = data;
	nfct_set_attr_u32(ct, ATTR_ORIG_NAT_SEQ_CORRECTION_POS, 
			  ntohl(this->orig_seq_correction_pos));
	nfct_set_attr_u32(ct, ATTR_ORIG_NAT_SEQ_OFFSET_BEFORE, 
			  ntohl(this->orig_seq_correction_pos));
	nfct_set_attr_u32(ct, ATTR_ORIG_NAT_SEQ_OFFSET_AFTER, 
			  ntohl(this->orig_seq_correction_pos));
	nfct_set_attr_u32(ct, ATTR_REPL_NAT_SEQ_CORRECTION_POS, 
			  ntohl(this->orig_seq_correction_pos));
	nfct_set_attr_u32(ct, ATTR_REPL_NAT_SEQ_OFFSET_BEFORE, 
			  ntohl(this->orig_seq_correction_pos));
	nfct_set_attr_u32(ct, ATTR_REPL_NAT_SEQ_OFFSET_AFTER, 
			  ntohl(this->orig_seq_correction_pos));
}

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
		if (h[attr->nta_attr].parse == NULL) {
			attr = NTA_NEXT(attr, len);
			continue;
		}
		h[attr->nta_attr].parse(ct, attr->nta_attr, NTA_DATA(attr));
		attr = NTA_NEXT(attr, len);
	}

	*query = pld->query;
	return 0;
}
