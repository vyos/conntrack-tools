#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <dlfcn.h>

#include "ct.h"
#include "proto.h"
#include "../../../include/helper.h"
#include "test.h"

#include <libnetfilter_queue/pktbuff.h>

struct cthelper_test_stats cthelper_test_stats;

static int
cthelper_process_packet(const uint8_t *pkt, uint32_t pktlen,
			struct ctd_helper *h, int proto, uint16_t port)
{
	struct pkt_buff *pktb;
	struct cthelper_proto_l2l3_helper *l3h;
	struct cthelper_proto_l4_helper *l4h;
	unsigned int l3hdr_len, l4protonum;
	struct nf_ct_entry *ct;
	int ret, this_proto;
	uint32_t dataoff, ctinfo = 0;

	l3h = cthelper_proto_l2l3_helper_find(pkt, &l4protonum, &l3hdr_len);
	if (l3h == NULL) {
		fprintf(stderr, "Unsupported layer 3 protocol, skipping.\n");
		return -1;
	}

	l4h = cthelper_proto_l4_helper_find(pkt, l4protonum);
	if (l4h == NULL) {
		fprintf(stderr, "Unsupported layer 4 protocol, skipping.\n");
		return -1;
	}
	/* get layer 3 header. */
	pkt += l3h->l2hdr_len;
	pktlen -= l3h->l2hdr_len;

	/* skip packet with mismatching protocol */
	this_proto = l3h->l4pkt_proto(pkt);
	if (this_proto != proto) {
		cthelper_test_stats.pkt_mismatch_proto++;
		return 0;
	}

	/* Look for the fake conntrack. */
	ct = ct_find(pkt, l3hdr_len, l3h, l4h, &ctinfo);
	if (ct == NULL) {
		/* It doesn't exist any, create one. */
		ct = ct_alloc(pkt, l3hdr_len, l3h, l4h);
		if (ct == NULL) {
			fprintf(stderr, "Not enough memory\n");
			return -1;
		}
		ct_add(ct);
		ctinfo += IP_CT_NEW;
	} else
		ctinfo += IP_CT_ESTABLISHED;

	/* skip packets with mismatching ports */
	if (!l4h->l4ct_cmp_port(ct->myct->ct, ntohs(port))) {
		cthelper_test_stats.pkt_mismatch_port++;
		return -1;
	}

	/*
	 * FIXME: reminder, implement this below in the kernel for cthelper.
	 */

	/* This packet contains no data, skip it. */
/*	if (l4h->l4pkt_no_data && l4h->l4pkt_no_data(pkt + l3hdr_len)) {
		NFG_DEBUG("skipping packet with no data\n");
		continue;
	} */

	/* Create the fake network buffer. */
	pktb = pktb_alloc(AF_INET, pkt, pktlen, 128);
	if (pktb == NULL) {
		fprintf(stderr, "Not enough memory\n");
		return -1;
	}

	dataoff = l3h->l3pkt_hdr_len(pkt);
	if (dataoff > pktb_len(pktb)) {
		fprintf(stderr, "wrong layer 3 offset: %d > %d\n",
			dataoff, pktb_len(pktb));
		return -1;
	}

	ret = h->cb(pktb, dataoff, ct->myct, ctinfo);
	pktb_free(pktb);

	return ret;
}

static int
cthelper_test(const char *pcapfile, const char *helper_name,
	      int l4proto, uint16_t port)
{
	struct pcap_pkthdr pcaph;
	char errbuf[PCAP_ERRBUF_SIZE];
	const u_char *pkt;
	pcap_t *handle;
	struct ctd_helper *h;

	h = helper_find("/usr/lib/conntrack-tools",
			helper_name, l4proto, RTLD_NOW);
	if (h == NULL) {
		fprintf(stderr, "couldn't find helper: %s\n", helper_name);
		return -1;
	}

	handle = pcap_open_offline(pcapfile, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open pcap file %s: %s\n",
				pcapfile, errbuf);
		return -1;
	}
	while ((pkt = pcap_next(handle, &pcaph)) != NULL) {
		cthelper_test_stats.pkts++;
		cthelper_process_packet(pkt, pcaph.caplen, h, l4proto, port);
	}

	ct_flush();
	pcap_close(handle);
	return 0;
}

int main(int argc, char *argv[])
{
	int ret, l4proto;

	if (argc != 5) {
		fprintf(stderr, "Wrong usage:\n");
		fprintf(stderr, "%s [pcap_file] [helper-name] [proto] [port]\n",
				argv[0]);
		fprintf(stderr, "example: %s file.pcap ftp tcp 21\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	if (strncmp("tcp", argv[3], strlen("tcp")) == 0)
		l4proto = IPPROTO_TCP;
	else if (strncmp("udp", argv[3], strlen("udp")) == 0)
		l4proto = IPPROTO_UDP;
	else {
		fprintf(stderr, "%s not supported, send a patch to Pablo\n",
			argv[3]);
		exit(EXIT_FAILURE);
	}

	/* Initialization of supported layer 3 and 4 protocols here. */
	l2l3_ipv4_init();
	l4_tcp_init();
	l4_udp_init();

	if (cthelper_test(argv[1], argv[2], l4proto, atoi(argv[4])) < 0)
		ret = EXIT_FAILURE;
	else
		ret = EXIT_SUCCESS;

	printf("\e[1;34mTest results: expect_created=%d packets=%d "
	       "packets_skipped=%d\e[0m\n",
		cthelper_test_stats.ct_expect_created,
		cthelper_test_stats.pkts,
		cthelper_test_stats.pkt_mismatch_proto +
		cthelper_test_stats.pkt_mismatch_port);

	return ret;
}
