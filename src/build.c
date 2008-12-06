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

#include <string.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include "network.h"

static inline void *
put_header(struct netpld *pld, int attr, size_t len)
{
	struct netattr *nta = PLD_TAIL(pld);
	int total_size = NTA_ALIGN(NTA_LENGTH(len));
	int attr_size = NTA_LENGTH(len);
	pld->len += total_size;
	nta->nta_attr = htons(attr);
	nta->nta_len = htons(attr_size);
	memset((unsigned char *)nta + attr_size, 0, total_size - attr_size);
	return NTA_DATA(nta);
}

static inline void
addattr(struct netpld *pld, int attr, const void *data, size_t len)
{
	void *ptr = put_header(pld, attr, len);
	memcpy(ptr, data, len);
}

static inline void
__build_u8(const struct nf_conntrack *ct, int a, struct netpld *pld, int b)
{
	void *ptr = put_header(pld, b, sizeof(uint8_t));
	memcpy(ptr, nfct_get_attr(ct, a), sizeof(uint8_t));
}

static inline void 
__build_u16(const struct nf_conntrack *ct, int a, struct netpld *pld, int b)
{
	uint32_t data = nfct_get_attr_u16(ct, a);
	data = htons(data);
	addattr(pld, b, &data, sizeof(uint16_t));
}

static inline void 
__build_u32(const struct nf_conntrack *ct, int a, struct netpld *pld, int b)
{
	uint32_t data = nfct_get_attr_u32(ct, a);
	data = htonl(data);
	addattr(pld, b, &data, sizeof(uint32_t));
}

static inline void 
__build_group(const struct nf_conntrack *ct, int a, struct netpld *pld, 
	      int b, int size)
{
	void *ptr = put_header(pld, b, size);
	nfct_get_attr_grp(ct, a, ptr);
}

static inline void 
__build_natseqadj(const struct nf_conntrack *ct, struct netpld *pld)
{
	struct nta_attr_natseqadj data = {
		.orig_seq_correction_pos =
		htonl(nfct_get_attr_u32(ct, ATTR_ORIG_NAT_SEQ_CORRECTION_POS)),
		.orig_seq_offset_before = 
		htonl(nfct_get_attr_u32(ct, ATTR_ORIG_NAT_SEQ_OFFSET_BEFORE)),
		.orig_seq_offset_after =
		htonl(nfct_get_attr_u32(ct, ATTR_ORIG_NAT_SEQ_OFFSET_AFTER)),
		.repl_seq_correction_pos = 
		htonl(nfct_get_attr_u32(ct, ATTR_REPL_NAT_SEQ_CORRECTION_POS)),
		.repl_seq_offset_before =
		htonl(nfct_get_attr_u32(ct, ATTR_REPL_NAT_SEQ_OFFSET_BEFORE)),
		.repl_seq_offset_after = 
		htonl(nfct_get_attr_u32(ct, ATTR_REPL_NAT_SEQ_OFFSET_AFTER))
	};
	addattr(pld, NTA_NAT_SEQ_ADJ, &data, sizeof(struct nta_attr_natseqadj));
}

static enum nf_conntrack_attr nat_type[] =
	{ ATTR_ORIG_NAT_SEQ_CORRECTION_POS, ATTR_ORIG_NAT_SEQ_OFFSET_BEFORE,
	  ATTR_ORIG_NAT_SEQ_OFFSET_AFTER, ATTR_REPL_NAT_SEQ_CORRECTION_POS,
	  ATTR_REPL_NAT_SEQ_OFFSET_BEFORE, ATTR_REPL_NAT_SEQ_OFFSET_AFTER };

/* XXX: ICMP not supported */
void build_netpld(struct nf_conntrack *ct, struct netpld *pld, int query)
{
	if (nfct_attr_grp_is_set(ct, ATTR_GRP_ORIG_IPV4)) {
		__build_group(ct, ATTR_GRP_ORIG_IPV4, pld, NTA_IPV4, 
			      sizeof(struct nfct_attr_grp_ipv4));
	} else if (nfct_attr_grp_is_set(ct, ATTR_GRP_ORIG_IPV6)) {
		__build_group(ct, ATTR_GRP_ORIG_IPV6, pld, NTA_IPV6, 
			      sizeof(struct nfct_attr_grp_ipv6));
	}

	__build_u8(ct, ATTR_L4PROTO, pld, NTA_L4PROTO);
	if (nfct_attr_grp_is_set(ct, ATTR_GRP_ORIG_PORT)) {
		__build_group(ct, ATTR_GRP_ORIG_PORT, pld, NTA_PORT,
			      sizeof(struct nfct_attr_grp_port));
	}

	__build_u32(ct, ATTR_STATUS, pld, NTA_STATUS); 

	if (nfct_attr_is_set(ct, ATTR_TCP_STATE))
		__build_u8(ct, ATTR_TCP_STATE, pld, NTA_STATE);
	if (nfct_attr_is_set(ct, ATTR_MARK))
		__build_u32(ct, ATTR_MARK, pld, NTA_MARK);

	/* setup the master conntrack */
	if (nfct_attr_grp_is_set(ct, ATTR_GRP_MASTER_IPV4)) {
		__build_group(ct, ATTR_GRP_MASTER_IPV4, pld, NTA_MASTER_IPV4,
			      sizeof(struct nfct_attr_grp_ipv4));
		__build_u8(ct, ATTR_MASTER_L4PROTO, pld, NTA_MASTER_L4PROTO);
		if (nfct_attr_grp_is_set(ct, ATTR_GRP_MASTER_PORT)) {
			__build_group(ct, ATTR_GRP_MASTER_PORT,
				      pld, NTA_MASTER_PORT, 
				      sizeof(struct nfct_attr_grp_port));
		}
	} else if (nfct_attr_grp_is_set(ct, ATTR_GRP_MASTER_IPV6)) {
		__build_group(ct, ATTR_GRP_MASTER_IPV6, pld, NTA_MASTER_IPV6,
			      sizeof(struct nfct_attr_grp_ipv6));
		__build_u8(ct, ATTR_MASTER_L4PROTO, pld, NTA_MASTER_L4PROTO);
		if (nfct_attr_grp_is_set(ct, ATTR_GRP_MASTER_PORT)) {
			__build_group(ct, ATTR_GRP_MASTER_PORT,
				      pld, NTA_MASTER_PORT,
				      sizeof(struct nfct_attr_grp_port));
		}
	}

	/*  NAT */
	if (nfct_getobjopt(ct, NFCT_GOPT_IS_SNAT))
		__build_u32(ct, ATTR_REPL_IPV4_DST, pld, NTA_SNAT_IPV4);
	if (nfct_getobjopt(ct, NFCT_GOPT_IS_DNAT))
		__build_u32(ct, ATTR_REPL_IPV4_SRC, pld, NTA_DNAT_IPV4);
	if (nfct_getobjopt(ct, NFCT_GOPT_IS_SPAT))
		__build_u16(ct, ATTR_REPL_PORT_DST, pld, NTA_SPAT_PORT);
	if (nfct_getobjopt(ct, NFCT_GOPT_IS_DPAT))
		__build_u16(ct, ATTR_REPL_PORT_SRC, pld, NTA_DPAT_PORT);

	/* NAT sequence adjustment */
	if (nfct_attr_is_set_array(ct, nat_type, 6))
		__build_natseqadj(ct, pld);

	pld->query = query;

	PLD_HOST2NETWORK(pld);
}
