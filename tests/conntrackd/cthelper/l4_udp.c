#include <netinet/ip.h>
#include <netinet/udp.h>

#include "proto.h"

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#define PRINT_CMP(...)

static void l4_udp_ct_build_tuple(const uint8_t *pkt, struct nf_conntrack *ct)
{
	const struct udphdr *udph = (const struct udphdr *)pkt;

	nfct_set_attr_u8(ct, ATTR_ORIG_L4PROTO, IPPROTO_UDP);
	nfct_set_attr_u8(ct, ATTR_REPL_L4PROTO, IPPROTO_UDP);
	nfct_set_attr_u16(ct, ATTR_ORIG_PORT_SRC, udph->source);
	nfct_set_attr_u16(ct, ATTR_ORIG_PORT_DST, udph->dest);
	nfct_set_attr_u16(ct, ATTR_REPL_PORT_SRC, udph->dest);
	nfct_set_attr_u16(ct, ATTR_REPL_PORT_DST, udph->source);
}

static int l4_udp_ct_cmp_tuple_orig(const uint8_t *pkt, struct nf_conntrack *ct)
{
	const struct udphdr *udph = (const struct udphdr *)pkt;

	PRINT_CMP("cmp_orig udph->source: %u == %u\n",
		udph->source, nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC));
	PRINT_CMP("cmp_orig udph->dest: %u == %u\n",
		udph->dest, nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST));

	if (udph->source == nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC) &&
	    udph->dest == nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST))
		return 1;

	return 0;
}

static int
l4_udp_ct_cmp_tuple_repl(const uint8_t *pkt, struct nf_conntrack *ct)
{
	const struct udphdr *udph = (const struct udphdr *)pkt;

	PRINT_CMP("cmp_repl udph->source: %u == %u\n",
		udph->source, nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC));
	PRINT_CMP("cmp_repl udph->dest: %u == %u\n",
		udph->dest, nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST));

	if (udph->source == nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC) &&
	    udph->dest == nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST))
		return 1;

	return 0;
}

static int
l4_udp_ct_cmp_port(struct nf_conntrack *ct, uint16_t port)
{
	PRINT_CMP("cmp_port src: %u == %u\n",
		port, nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC));
	PRINT_CMP("cmp_port dst: %u == %u\n",
		port, nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST));

	if (port == nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC) ||
	    port == nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST))
		return 1;

	return 0;
}

static int l4_udp_pkt_no_data(const uint8_t *pkt)
{
	/* UDP has no control packets. */
	return 1;
}

static struct cthelper_proto_l4_helper tcp = {
	.l4protonum	= IPPROTO_UDP,
	.l4ct_build	= l4_udp_ct_build_tuple,
	.l4ct_cmp_orig	= l4_udp_ct_cmp_tuple_orig,
	.l4ct_cmp_repl	= l4_udp_ct_cmp_tuple_repl,
	.l4ct_cmp_port	= l4_udp_ct_cmp_port,
	.l4pkt_no_data	= l4_udp_pkt_no_data,
};

void l4_udp_init(void)
{
	cthelper_proto_l4_helper_register(&tcp);
}
