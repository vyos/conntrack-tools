#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "proto.h"

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#define PRINT_CMP(...)

static void l4_tcp_ct_build_tuple(const uint8_t *pkt, struct nf_conntrack *ct)
{
	const struct tcphdr *tcph = (const struct tcphdr *)pkt;

	nfct_set_attr_u8(ct, ATTR_ORIG_L4PROTO, IPPROTO_TCP);
	nfct_set_attr_u8(ct, ATTR_REPL_L4PROTO, IPPROTO_TCP);
	nfct_set_attr_u16(ct, ATTR_ORIG_PORT_SRC, tcph->source);
	nfct_set_attr_u16(ct, ATTR_ORIG_PORT_DST, tcph->dest);
	nfct_set_attr_u16(ct, ATTR_REPL_PORT_SRC, tcph->dest);
	nfct_set_attr_u16(ct, ATTR_REPL_PORT_DST, tcph->source);
}

static int l4_tcp_ct_cmp_tuple_orig(const uint8_t *pkt, struct nf_conntrack *ct)
{
	const struct tcphdr *tcph = (const struct tcphdr *)pkt;

	PRINT_CMP("cmp_orig tcph->source: %u == %u\n",
		tcph->source, nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC));
	PRINT_CMP("cmp_orig tcph->dest: %u == %u\n",
		tcph->dest, nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST));

	if (tcph->source == nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC) &&
	    tcph->dest == nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST))
		return 1;

	return 0;
}

static int
l4_tcp_ct_cmp_tuple_repl(const uint8_t *pkt, struct nf_conntrack *ct)
{
	const struct tcphdr *tcph = (const struct tcphdr *)pkt;

	PRINT_CMP("cmp_repl tcph->source: %u == %u\n",
		tcph->source, nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC));
	PRINT_CMP("cmp_repl tcph->dest: %u == %u\n",
		tcph->dest, nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST));

	if (tcph->source == nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC) &&
	    tcph->dest == nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST))
		return 1;

	return 0;
}

static int
l4_tcp_ct_cmp_port(struct nf_conntrack *ct, uint16_t port)
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

static int l4_tcp_pkt_no_data(const uint8_t *pkt)
{
	const struct tcphdr *tcph = (const struct tcphdr *)pkt;
	return tcph->syn || tcph->fin || tcph->rst || !tcph->psh;
}

static struct cthelper_proto_l4_helper tcp = {
	.l4protonum	= IPPROTO_TCP,
	.l4ct_build	= l4_tcp_ct_build_tuple,
	.l4ct_cmp_orig	= l4_tcp_ct_cmp_tuple_orig,
	.l4ct_cmp_repl	= l4_tcp_ct_cmp_tuple_repl,
	.l4ct_cmp_port	= l4_tcp_ct_cmp_port,
	.l4pkt_no_data	= l4_tcp_pkt_no_data,
};

void l4_tcp_init(void)
{
	cthelper_proto_l4_helper_register(&tcp);
}
