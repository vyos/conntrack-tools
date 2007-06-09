/*
 * (C) 2005-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 */
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h> /* For htons */
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_udp.h>

#include "conntrack.h"

static struct option opts[] = {
	{"orig-port-src", 1, 0, '1'},
	{"sport", 1, 0, '1'},
	{"orig-port-dst", 1, 0, '2'},
	{"dport", 1, 0, '2'},
	{"reply-port-src", 1, 0, '3'},
	{"reply-port-dst", 1, 0, '4'},
	{"mask-port-src", 1, 0, '5'},
	{"mask-port-dst", 1, 0, '6'},
	{"tuple-port-src", 1, 0, '7'},
	{"tuple-port-dst", 1, 0, '8'},
	{0, 0, 0, 0}
};

static void help()
{
	fprintf(stdout, "  --orig-port-src\t\toriginal source port\n");
	fprintf(stdout, "  --orig-port-dst\t\toriginal destination port\n");
	fprintf(stdout, "  --reply-port-src\t\treply source port\n");
	fprintf(stdout, "  --reply-port-dst\t\treply destination port\n");
	fprintf(stdout, "  --mask-port-src\t\tmask source port\n");
	fprintf(stdout, "  --mask-port-dst\t\tmask destination port\n");
	fprintf(stdout, "  --tuple-port-src\t\texpectation tuple src port\n");
	fprintf(stdout, "  --tuple-port-src\t\texpectation tuple dst port\n");
}

static int parse_options(char c, char *argv[],
			 struct nf_conntrack *ct,
			 struct nf_conntrack *exptuple,
			 struct nf_conntrack *mask,
			 unsigned int *flags)
{
	switch(c) {
		case '1':
			if (!optarg)
				break;

			nfct_set_attr_u16(ct, 
					  ATTR_ORIG_PORT_SRC, 
					  htons(atoi(optarg)));

			*flags |= UDP_ORIG_SPORT;
			break;
		case '2':
			if (!optarg)
				break;

			nfct_set_attr_u16(ct, 
					  ATTR_ORIG_PORT_DST, 
					  htons(atoi(optarg)));

			*flags |= UDP_ORIG_DPORT;
			break;
		case '3':
			if (!optarg)
				break;

			nfct_set_attr_u16(ct, 
					  ATTR_REPL_PORT_SRC, 
					  htons(atoi(optarg)));

			*flags |= UDP_REPL_SPORT;
			break;
		case '4':
			if (!optarg)
				break;

			nfct_set_attr_u16(ct, 
					  ATTR_REPL_PORT_DST, 
					  htons(atoi(optarg)));

			*flags |= UDP_REPL_DPORT;
			break;
		case '5':
			if (!optarg)
				break;

			nfct_set_attr_u16(mask,
					  ATTR_ORIG_PORT_SRC,
					  htons(atoi(optarg)));

			*flags |= UDP_MASK_SPORT;
			break;
		case '6':
			if (!optarg)
				break;

			nfct_set_attr_u16(mask, 
					  ATTR_ORIG_PORT_DST, 
					  htons(atoi(optarg)));

			*flags |= UDP_MASK_DPORT;
			break;
		case '7':
			if (!optarg)
				break;

			nfct_set_attr_u16(exptuple, 
					  ATTR_ORIG_PORT_SRC, 
					  htons(atoi(optarg)));

			*flags |= UDP_EXPTUPLE_SPORT;
			break;
		case '8':
			if (!optarg)
				break;

			nfct_set_attr_u16(exptuple, 
					  ATTR_ORIG_PORT_DST, 
					  htons(atoi(optarg)));

			*flags |= UDP_EXPTUPLE_DPORT;
			break;
	}
	return 1;
}

static int final_check(unsigned int flags,
		       unsigned int command,
		       struct nf_conntrack *ct)
{
	int ret = 0;
	
	if ((flags & (UDP_ORIG_SPORT|UDP_ORIG_DPORT)) 
	    && !(flags & (UDP_REPL_SPORT|UDP_REPL_DPORT))) {
	    	nfct_set_attr_u16(ct,
				  ATTR_REPL_PORT_SRC, 
				  nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST));
		nfct_set_attr_u16(ct,
				  ATTR_REPL_PORT_DST,
				  nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC));
		ret = 1;
	} else if (!(flags & (UDP_ORIG_SPORT|UDP_ORIG_DPORT))
	            && (flags & (UDP_REPL_SPORT|UDP_REPL_DPORT))) {
	    	nfct_set_attr_u16(ct,
				  ATTR_ORIG_PORT_SRC, 
				  nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST));
		nfct_set_attr_u16(ct,
				  ATTR_ORIG_PORT_DST,
				  nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC));
		ret = 1;
	}
	if ((flags & (UDP_ORIG_SPORT|UDP_ORIG_DPORT)) 
	    && ((flags & (UDP_REPL_SPORT|UDP_REPL_DPORT))))
		ret = 1;

	return ret;
}

static struct ctproto_handler udp = {
	.name 			= "udp",
	.protonum		= IPPROTO_UDP,
	.parse_opts		= parse_options,
	.final_check		= final_check,
	.help			= help,
	.opts			= opts,
	.version		= VERSION,
};

void register_udp(void)
{
	register_proto(&udp);
}
