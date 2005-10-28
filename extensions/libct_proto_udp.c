/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@eurodev.net>
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
#include <netinet/in.h> /* For htons */
#include "conntrack.h"
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

static struct option opts[] = {
	{"orig-port-src", 1, 0, '1'},
	{"orig-port-dst", 1, 0, '2'},
	{"reply-port-src", 1, 0, '3'},
	{"reply-port-dst", 1, 0, '4'},
	{"mask-port-src", 1, 0, '5'},
	{"mask-port-dst", 1, 0, '6'},
	{0, 0, 0, 0}
};

enum udp_param_flags {
	ORIG_SPORT_BIT = 0,
	ORIG_SPORT = (1 << ORIG_SPORT_BIT),

	ORIG_DPORT_BIT = 1,
	ORIG_DPORT = (1 << ORIG_DPORT_BIT),

	REPL_SPORT_BIT = 2,
	REPL_SPORT = (1 << REPL_SPORT_BIT),

	REPL_DPORT_BIT = 3,
	REPL_DPORT = (1 << REPL_DPORT_BIT),

	MASK_SPORT_BIT = 4,
	MASK_SPORT = (1 << MASK_SPORT_BIT),

	MASK_DPORT_BIT = 5,
	MASK_DPORT = (1 << MASK_DPORT_BIT),
};

void help()
{
	fprintf(stdout, "--orig-port-src        original source port\n");
	fprintf(stdout, "--orig-port-dst        original destination port\n");
	fprintf(stdout, "--reply-port-src       reply source port\n");
	fprintf(stdout, "--reply-port-dst       reply destination port\n");
	fprintf(stdout, "--mask-port-src	mask source port\n");
	fprintf(stdout, "--mask-port-dst	mask destination port\n");
}

int parse_options(char c, char *argv[], 
		  struct nfct_tuple *orig,
		  struct nfct_tuple *reply,
		  struct nfct_tuple *mask,
		  union nfct_protoinfo *proto,
		  unsigned int *flags)
{
	switch(c) {
		case '1':
			if (optarg) {
				orig->l4src.udp.port = htons(atoi(optarg));
				*flags |= ORIG_SPORT;
			}
			break;
		case '2':
			if (optarg) {
				orig->l4dst.udp.port = htons(atoi(optarg));
				*flags |= ORIG_DPORT;
			}
			break;
		case '3':
			if (optarg) {
				reply->l4src.udp.port = htons(atoi(optarg));
				*flags |= REPL_SPORT;
			}
			break;
		case '4':
			if (optarg) {
				reply->l4dst.udp.port = htons(atoi(optarg));
				*flags |= REPL_DPORT;
			}
			break;
		case '5':
			if (optarg) {
				mask->l4src.udp.port = htons(atoi(optarg));
				*flags |= MASK_SPORT;
			}
			break;
		case '6':
			if (optarg) {
				mask->l4dst.udp.port = htons(atoi(optarg));
				*flags |= MASK_DPORT;
			}
			break;
	}
	return 1;
}

int final_check(unsigned int flags,
		struct nfct_tuple *orig,
		struct nfct_tuple *reply)
{
	if ((flags & (ORIG_SPORT|ORIG_DPORT)) 
	    && !(flags & (REPL_SPORT|REPL_DPORT))) {
		reply->l4src.udp.port = orig->l4dst.udp.port;
		reply->l4dst.udp.port = orig->l4src.udp.port;
		return 1;
	} else if (!(flags & (ORIG_SPORT|ORIG_DPORT))
	            && (flags & (REPL_SPORT|REPL_DPORT))) {
		orig->l4src.udp.port = reply->l4dst.udp.port;
		orig->l4dst.udp.port = reply->l4src.udp.port;
		return 1;
	}
	if ((flags & (ORIG_SPORT|ORIG_DPORT)) 
	    && ((flags & (REPL_SPORT|REPL_DPORT))))
		return 1;

	return 0;
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

void __attribute__ ((constructor)) init(void);

void init(void)
{
	register_proto(&udp);
}
