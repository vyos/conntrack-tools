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
	{0, 0, 0, 0}
};

int parse(char c, char *argv[], 
	   struct ip_conntrack_tuple *orig,
	   struct ip_conntrack_tuple *reply)
{
	switch(c) {
		case '1':
			if (optarg)
				orig->src.u.tcp.port = htons(atoi(optarg));
			break;
		case '2':
			if (optarg)
				orig->dst.u.tcp.port = htons(atoi(optarg));
			break;
		case '3':
			if (optarg)
				reply->src.u.tcp.port = htons(atoi(optarg));
			break;
		case '4':
			if (optarg)
				reply->dst.u.tcp.port = htons(atoi(optarg));
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
