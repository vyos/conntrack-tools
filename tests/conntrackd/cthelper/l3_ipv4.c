#include <stdlib.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>

#include "proto.h"

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#define PRINT_CMP(...)

static void
l3_ipv4_ct_build_tuple(const uint8_t *pkt, struct nf_conntrack *ct)
{
	const struct iphdr *iph = (const struct iphdr *)pkt;

	nfct_set_attr_u16(ct, ATTR_ORIG_L3PROTO, AF_INET);
	nfct_set_attr_u16(ct, ATTR_REPL_L3PROTO, AF_INET);
	nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_SRC, iph->saddr);
	nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_DST, iph->daddr);
	nfct_set_attr_u32(ct, ATTR_REPL_IPV4_SRC, iph->daddr);
	nfct_set_attr_u32(ct, ATTR_REPL_IPV4_DST, iph->saddr);
}

static int
l3_ipv4_ct_cmp_tuple_orig(const uint8_t *pkt, struct nf_conntrack *ct)
{
	const struct iphdr *iph = (const struct iphdr *)pkt;

	PRINT_CMP("cmp_orig iph->saddr: %x == %x\n",
		iph->saddr, nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC));
	PRINT_CMP("cmp_orig iph->daddr: %x == %x\n",
		iph->daddr, nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST));

	if (iph->saddr == nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC) &&
	    iph->daddr == nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST))
		return 1;

	return 0;
}

static int
l3_ipv4_ct_cmp_tuple_repl(const uint8_t *pkt, struct nf_conntrack *ct)
{
	const struct iphdr *iph = (const struct iphdr *)pkt;

	PRINT_CMP("cmp_repl iph->saddr: %x == %x\n",
		iph->saddr, nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC));
	PRINT_CMP("cmp_repl iph->daddr: %x == %x\n",
		iph->daddr, nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST));

	if (iph->saddr == nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC) &&
	    iph->daddr == nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST))
		return 1;

	return 0;
}

static int l3_ipv4_pkt_l4proto_num(const uint8_t *pkt)
{
	const struct iphdr *iph = (const struct iphdr *)pkt;

	return iph->protocol;
}

static int l3_ipv4_pkt_l3hdr_len(const uint8_t *pkt)
{
	const struct iphdr *iph = (const struct iphdr *)pkt;

	return iph->ihl << 2;
}

static struct cthelper_proto_l2l3_helper ipv4 = {
	.l2protonum	= ETH_P_IP,
	.l3protonum	= AF_INET,
	.l2hdr_len	= ETH_HLEN,
	.l3ct_build	= l3_ipv4_ct_build_tuple,
	.l3ct_cmp_orig	= l3_ipv4_ct_cmp_tuple_orig,
	.l3ct_cmp_repl	= l3_ipv4_ct_cmp_tuple_repl,
	.l3pkt_hdr_len	= l3_ipv4_pkt_l3hdr_len,
	.l4pkt_proto	= l3_ipv4_pkt_l4proto_num,
};

void l2l3_ipv4_init(void)
{
	cthelper_proto_l2l3_helper_register(&ipv4);
}
