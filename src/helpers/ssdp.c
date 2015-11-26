/*
 * SSDP connection tracking helper
 * (SSDP = Simple Service Discovery Protocol)
 * For documentation about SSDP see
 * http://en.wikipedia.org/wiki/Simple_Service_Discovery_Protocol
 *
 * Copyright (C) 2014 Ashley Hughes <ashley.hughes@blueyonder.co.uk>
 * Based on the SSDP conntrack helper (nf_conntrack_ssdp.c),
 * :http://marc.info/?t=132945775100001&r=1&w=2
 *  (C) 2012 Ian Pilcher <arequipeno@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "conntrackd.h"
#include "helper.h"
#include "myct.h"
#include "log.h"
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/pktbuff.h>
#include <linux/netfilter.h>

#define SSDP_MCAST_ADDR		"239.255.255.250"
#define UPNP_MCAST_LL_ADDR	"FF02::C" /* link-local */
#define UPNP_MCAST_SL_ADDR	"FF05::C" /* site-local */

#define SSDP_M_SEARCH		"M-SEARCH"
#define SSDP_M_SEARCH_SIZE	(sizeof SSDP_M_SEARCH - 1)

static int ssdp_helper_cb(struct pkt_buff *pkt, uint32_t protoff,
			  struct myct *myct, uint32_t ctinfo)
{
	int ret = NF_ACCEPT;
	union nfct_attr_grp_addr daddr, saddr, taddr;
	struct iphdr *net_hdr = (struct iphdr *)pktb_network_header(pkt);
	int good_packet = 0;
	struct nf_expect *exp;
	uint16_t port;
	unsigned int dataoff;
	void *sb_ptr;

	cthelper_get_addr_dst(myct->ct, MYCT_DIR_ORIG, &daddr);
	switch (nfct_get_attr_u8(myct->ct, ATTR_L3PROTO)) {
	case AF_INET:
		inet_pton(AF_INET, SSDP_MCAST_ADDR, &(taddr.ip));
		if (daddr.ip == taddr.ip)
			good_packet = 1;
		break;
	case AF_INET6:
		inet_pton(AF_INET6, UPNP_MCAST_LL_ADDR, &(taddr.ip6));
		if (daddr.ip6[0] == taddr.ip6[0] &&
		    daddr.ip6[1] == taddr.ip6[1] &&
		    daddr.ip6[2] == taddr.ip6[2] &&
		    daddr.ip6[3] == taddr.ip6[3]) {
			good_packet = 1;
			break;
		}
		inet_pton(AF_INET6, UPNP_MCAST_SL_ADDR, &(taddr.ip6));
		if (daddr.ip6[0] == taddr.ip6[0] &&
		    daddr.ip6[1] == taddr.ip6[1] &&
		    daddr.ip6[2] == taddr.ip6[2] &&
		    daddr.ip6[3] == taddr.ip6[3]) {
			good_packet = 1;
			break;
		}
		break;
	default:
		break;
	}

	if (!good_packet) {
		pr_debug("ssdp_help: destination address not multicast; ignoring\n");
		return NF_ACCEPT;
	}

	/* No data? Ignore */
	dataoff = net_hdr->ihl*4 + sizeof(struct udphdr);
	if (dataoff >= pktb_len(pkt)) {
		pr_debug("ssdp_help: UDP payload too small for M-SEARCH; ignoring\n");
		return NF_ACCEPT;
	}

	sb_ptr = pktb_network_header(pkt) + dataoff;

	if (memcmp(sb_ptr, SSDP_M_SEARCH, SSDP_M_SEARCH_SIZE) != 0) {
		pr_debug("ssdp_help: UDP payload does not begin with 'M-SEARCH'; ignoring\n");
		return NF_ACCEPT;
	}

	cthelper_get_addr_src(myct->ct, MYCT_DIR_ORIG, &saddr);
	cthelper_get_port_src(myct->ct, MYCT_DIR_ORIG, &port);

	exp = nfexp_new();
	if (exp == NULL)
		return NF_DROP;

	if (cthelper_expect_init(exp, myct->ct, 0, NULL, &saddr,
				 IPPROTO_UDP, NULL, &port,
				 NF_CT_EXPECT_PERMANENT)) {
		nfexp_destroy(exp);
		return NF_DROP;
	}
	myct->exp = exp;

	return ret;
}

static struct ctd_helper ssdp_helper = {
	.name		= "ssdp",
	.l4proto	= IPPROTO_UDP,
	.priv_data_len	= 0,
	.cb		= ssdp_helper_cb,
	.policy		= {
		[0] = {
			.name		= "ssdp",
			.expect_max	= 1,
			.expect_timeout	= 5 * 60,
		},
	},
};

static void __attribute__ ((constructor)) ssdp_init(void)
{
	helper_register(&ssdp_helper);
}
