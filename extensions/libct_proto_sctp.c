/*
 * (C) 2005 by Harald Welte <lafoorge@netfilter.org>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License Version 2 as
 *      published by the Free Software Foundation
 *
 */
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h> /* For htons */
#include <linux/netfilter_ipv4/ip_conntrack_tuple.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include "libct_proto.h"

static struct option opts[] = {
	{"orig-port-src", 1, 0, '1'},
	{"orig-port-dst", 1, 0, '2'},
	{"reply-port-src", 1, 0, '3'},
	{"reply-port-dst", 1, 0, '4'},
	{"state", 1, 0, '5'},
	{0, 0, 0, 0}
};

enum sctp_param_flags {
	ORIG_SPORT_BIT = 0,
	ORIG_SPORT = (1 << ORIG_SPORT_BIT),

	ORIG_DPORT_BIT = 1,
	ORIG_DPORT = (1 << ORIG_DPORT_BIT),

	REPL_SPORT_BIT = 2,
	REPL_SPORT = (1 << REPL_SPORT_BIT),

	REPL_DPORT_BIT = 3,
	REPL_DPORT = (1 << REPL_DPORT_BIT),

	STATE_BIT = 4,
	STATE = (1 << STATE_BIT)
};

static const char *states[] = {
	"NONE",
	"CLOSED",
	"COOKIE_WAIT",
	"COOKIE_ECHOED",
	"ESTABLISHED",
	"SHUTDOWN_SENT",
	"SHUTDOWN_RECV",
	"SHUTDOWN_ACK_SENT",
};

static void help()
{
	fprintf(stdout, "--orig-port-src        original source port\n");
	fprintf(stdout, "--orig-port-dst        original destination port\n");
	fprintf(stdout, "--reply-port-src       reply source port\n");
	fprintf(stdout, "--reply-port-dst       reply destination port\n");
	fprintf(stdout, "--state                SCTP state, eg. ESTABLISHED\n");
}

static int parse(char c, char *argv[], 
	   struct ip_conntrack_tuple *orig,
	   struct ip_conntrack_tuple *reply,
	   union ip_conntrack_proto *proto,
	   unsigned int *flags)
{
	switch(c) {
		case '1':
			if (optarg) {
				orig->src.u.sctp.port = htons(atoi(optarg));
				*flags |= ORIG_SPORT;
			}
			break;
		case '2':
			if (optarg) {
				orig->dst.u.sctp.port = htons(atoi(optarg));
				*flags |= ORIG_DPORT;
			}
			break;
		case '3':
			if (optarg) {
				reply->src.u.sctp.port = htons(atoi(optarg));
				*flags |= REPL_SPORT;
			}
			break;
		case '4':
			if (optarg) {
				reply->dst.u.sctp.port = htons(atoi(optarg));
				*flags |= REPL_DPORT;
			}
			break;
		case '5':
			if (optarg) {
				int i;
				for (i=0; i<10; i++) {
					if (strcmp(optarg, states[i]) == 0) {
						proto->sctp.state = i;
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

static int final_check(unsigned int flags)
{
	if ((flags & ORIG_SPORT) && (flags & ORIG_DPORT))
		return 1;
	else if ((flags & REPL_SPORT) && (flags & REPL_DPORT))
		return 1;

	return 0;
}

static void print_tuple(struct ip_conntrack_tuple *t)
{
	fprintf(stdout, "sport=%d dport=%d ", ntohs(t->src.u.sctp.port), 
				             ntohs(t->dst.u.sctp.port));
}

static void print_proto(union ip_conntrack_proto *proto)
{
	if (proto->sctp.state > sizeof(states)/sizeof(char *))
		fprintf(stdout, "[%u] ", proto->sctp.state);
	else
		fprintf(stdout, "[%s] ", states[proto->sctp.state]);
}

static struct ctproto_handler sctp = {
	.name 		= "sctp",
	.protonum	= 132,
	.parse		= parse,
	.print_tuple	= print_tuple,
	.print_proto	= print_proto,
	.final_check	= final_check,
	.help		= help,
	.opts		= opts,
};

void __attribute__ ((constructor)) init(void);
void __attribute__ ((destructor)) fini(void);

void init(void)
{
	register_proto(&sctp);
}

void fini(void)
{
	unregister_proto(&sctp);
}
