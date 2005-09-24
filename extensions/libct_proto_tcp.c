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
#include <string.h>
#include <netinet/in.h> /* For htons */
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <libnfnetlink_conntrack/libnfnetlink_conntrack.h>

#include "libct_proto.h"

static struct option opts[] = {
	{"orig-port-src", 1, 0, '1'},
	{"orig-port-dst", 1, 0, '2'},
	{"reply-port-src", 1, 0, '3'},
	{"reply-port-dst", 1, 0, '4'},
	{"mask-port-src", 1, 0, '5'},
	{"mask-port-dst", 1, 0, '6'},
	{"state", 1, 0, '7'},
	{0, 0, 0, 0}
};

enum tcp_param_flags {
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

	STATE_BIT = 6,
	STATE = (1 << STATE_BIT)
};

static const char *states[] = {
	"NONE",
	"SYN_SENT",
	"SYN_RECV",
	"ESTABLISHED",
	"FIN_WAIT",
	"CLOSE_WAIT",
	"LAST_ACK",
	"TIME_WAIT",
	"CLOSE",
	"LISTEN"
};

void help()
{
	fprintf(stdout, "--orig-port-src        original source port\n");
	fprintf(stdout, "--orig-port-dst        original destination port\n");
	fprintf(stdout, "--reply-port-src       reply source port\n");
	fprintf(stdout, "--reply-port-dst       reply destination port\n");
	fprintf(stdout, "--mask-port-src	mask source port\n");
	fprintf(stdout, "--mask-port-dst	mask destination port\n");
	fprintf(stdout, "--state                TCP state, fe. ESTABLISHED\n");
}

int parse_options(char c, char *argv[], 
		  struct ctnl_tuple *orig,
		  struct ctnl_tuple *reply,
		  struct ctnl_tuple *mask,
		  union ctnl_protoinfo *proto,
		  unsigned int *flags)
{
	switch(c) {
		case '1':
			if (optarg) {
				orig->l4src.tcp.port = htons(atoi(optarg));
				*flags |= ORIG_SPORT;
			}
			break;
		case '2':
			if (optarg) {
				orig->l4dst.tcp.port = htons(atoi(optarg));
				*flags |= ORIG_DPORT;
			}
			break;
		case '3':
			if (optarg) {
				reply->l4src.tcp.port = htons(atoi(optarg));
				*flags |= REPL_SPORT;
			}
			break;
		case '4':
			if (optarg) {
				reply->l4dst.tcp.port = htons(atoi(optarg));
				*flags |= REPL_DPORT;
			}
			break;
		case '5':
			if (optarg) {
				mask->l4src.tcp.port = htons(atoi(optarg));
				*flags |= MASK_SPORT;
			}
			break;
		case '6':
			if (optarg) {
				mask->l4dst.tcp.port = htons(atoi(optarg));
				*flags |= MASK_DPORT;
			}
			break;
		case '7':
			if (optarg) {
				int i;
				for (i=0; i<10; i++) {
					if (strcmp(optarg, states[i]) == 0) {
						proto->tcp.state = i;
						break;
					}
				}
				if (i == 10) {
					printf("doh?\n");
					return 0;
				}
			}
			break;
	}
	return 1;
}

int final_check(unsigned int flags,
		struct ctnl_tuple *orig,
		struct ctnl_tuple *reply)
{
	if ((flags & (ORIG_SPORT|ORIG_DPORT)) 
	    && !(flags & (REPL_SPORT|REPL_DPORT))) {
		reply->l4src.tcp.port = orig->l4dst.tcp.port;
		reply->l4dst.tcp.port = orig->l4src.tcp.port;
		return 1;
	} else if (!(flags & (ORIG_SPORT|ORIG_DPORT))
	            && (flags & (REPL_SPORT|REPL_DPORT))) {
		orig->l4src.tcp.port = reply->l4dst.tcp.port;
		orig->l4dst.tcp.port = reply->l4src.tcp.port;
		return 1;
	}
	if ((flags & (ORIG_SPORT|ORIG_DPORT)) 
	    && ((flags & (REPL_SPORT|REPL_DPORT))))
		return 1;

	return 0;
}

void parse_proto(struct nfattr *cda[], struct ctnl_tuple *tuple)
{
	if (cda[CTA_PROTO_SRC_PORT-1])
		tuple->l4src.tcp.port =
			*(u_int16_t *)NFA_DATA(cda[CTA_PROTO_SRC_PORT-1]);
	if (cda[CTA_PROTO_DST_PORT-1])
		tuple->l4dst.tcp.port =
			*(u_int16_t *)NFA_DATA(cda[CTA_PROTO_DST_PORT-1]);
}

void parse_protoinfo(struct nfattr *cda[], struct ctnl_conntrack *ct)
{
	if (cda[CTA_PROTOINFO_TCP_STATE-1])
                ct->protoinfo.tcp.state =
                        *(u_int8_t *)NFA_DATA(cda[CTA_PROTOINFO_TCP_STATE-1]);
}

void print_protoinfo(union ctnl_protoinfo *protoinfo)
{
	fprintf(stdout, "%s ", states[protoinfo->tcp.state]);
}

void print_proto(struct ctnl_tuple *tuple)
{
	fprintf(stdout, "sport=%u dport=%u ", htons(tuple->l4src.tcp.port),
					      htons(tuple->l4dst.tcp.port));
}

static struct ctproto_handler tcp = {
	.name 			= "tcp",
	.protonum		= 6,
	.parse_opts		= parse_options,
	.parse_protoinfo	= parse_protoinfo,
	.parse_proto		= parse_proto,
	.print_proto		= print_proto,
	.print_protoinfo	= print_protoinfo,
	.final_check		= final_check,
	.help			= help,
	.opts			= opts,
	.version		= LIBCT_VERSION,
};

void __attribute__ ((constructor)) init(void);
void __attribute__ ((destructor)) fini(void);

void init(void)
{
	register_proto(&tcp);
}

void fini(void)
{
	unregister_proto(&tcp);
}
