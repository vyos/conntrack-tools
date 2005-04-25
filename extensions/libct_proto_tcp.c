#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <netinet/in.h> /* For htons */
#include <linux/netfilter_ipv4/ip_conntrack_tuple.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include "../include/libct_proto.h"

static struct option opts[] = {
	{"orig-port-src", 1, 0, '1'},
	{"orig-port-dst", 1, 0, '2'},
	{"reply-port-src", 1, 0, '3'},
	{"reply-port-dst", 1, 0, '4'},
	{"state", 1, 0, '5'},
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

	STATE_BIT = 4,
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

int parse(char c, char *argv[], 
	   struct ip_conntrack_tuple *orig,
	   struct ip_conntrack_tuple *reply,
	   union ip_conntrack_proto *proto,
	   unsigned int *flags)
{
	switch(c) {
		case '1':
			if (optarg) {
				orig->src.u.tcp.port = htons(atoi(optarg));
				*flags |= ORIG_SPORT;
			}
			break;
		case '2':
			if (optarg) {
				orig->dst.u.tcp.port = htons(atoi(optarg));
				*flags |= ORIG_DPORT;
			}
			break;
		case '3':
			if (optarg) {
				reply->src.u.tcp.port = htons(atoi(optarg));
				*flags |= REPL_SPORT;
			}
			break;
		case '4':
			if (optarg) {
				reply->dst.u.tcp.port = htons(atoi(optarg));
				*flags |= REPL_DPORT;
			}
			break;
		case '5':
			if (optarg) {
				int i;
				for (i=0; i<10; i++) {
					if (strcmp(optarg, states[i]) == 0) {
						proto->tcp.state = i;
						break;
					}
				}
				if (i == 10)
					printf("doh?\n");
			}
			break;
	}
	return 1;
}

void print(struct ip_conntrack_tuple *t)
{
	printf("sport=%d dport=%d ", ntohs(t->src.u.tcp.port), 
				     ntohs(t->dst.u.tcp.port));
}

static struct ctproto_handler tcp = {
	.name 		= "tcp",
	.protonum	= 6,
	.parse		= parse,
	.print		= print,
	.opts		= opts
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
