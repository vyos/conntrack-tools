/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@eurodev.net>
 *	       Harald Welte <laforge@netfilter.org>
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
#include <netinet/ip_icmp.h>
#include "libct_proto.h"

static struct option opts[] = {
	{"icmp-type", 1, 0, '1'},
	{"icmp-code", 1, 0, '2'},
	{"icmp-id", 1, 0, '3'},
	{0, 0, 0, 0}
};

enum icmp_param_flags {
	ICMP_TYPE_BIT = 0,
	ICMP_TYPE = (1 << ICMP_TYPE_BIT),

	ICMP_CODE_BIT = 1,
	ICMP_CODE = (1 << ICMP_CODE_BIT),

	ICMP_ID_BIT = 2,
	ICMP_ID = (1 << ICMP_ID_BIT)
};

void help()
{
	fprintf(stdout, "--icmp-type            icmp type\n");
	fprintf(stdout, "--icmp-code            icmp code\n");
	fprintf(stdout, "--icmp-id              icmp id\n");
}

/* Add 1; spaces filled with 0. */
static u_int8_t invmap[]
	= { [ICMP_ECHO] = ICMP_ECHOREPLY + 1,
	    [ICMP_ECHOREPLY] = ICMP_ECHO + 1,
	    [ICMP_TIMESTAMP] = ICMP_TIMESTAMPREPLY + 1,
	    [ICMP_TIMESTAMPREPLY] = ICMP_TIMESTAMP + 1,
	    [ICMP_INFO_REQUEST] = ICMP_INFO_REPLY + 1,
	    [ICMP_INFO_REPLY] = ICMP_INFO_REQUEST + 1,
	    [ICMP_ADDRESS] = ICMP_ADDRESSREPLY + 1,
	    [ICMP_ADDRESSREPLY] = ICMP_ADDRESS + 1};

int parse(char c, char *argv[], 
	   struct ctnl_tuple *orig,
	   struct ctnl_tuple *reply,
	   struct ctnl_tuple *mask,
	   union ctnl_protoinfo *proto,
	   unsigned int *flags)
{
	switch(c) {
		case '1':
			if (optarg) {
				orig->l4dst.icmp.type = atoi(optarg);
				reply->l4dst.icmp.type =
					invmap[orig->l4dst.icmp.type] - 1;
				*flags |= ICMP_TYPE;
			}
			break;
		case '2':
			if (optarg) {
				orig->l4dst.icmp.code = atoi(optarg);
				reply->l4dst.icmp.code = 0;
				*flags |= ICMP_CODE;
			}
			break;
		case '3':
			if (optarg) {
				orig->l4src.icmp.id = atoi(optarg);
				reply->l4dst.icmp.id = 0;
				*flags |= ICMP_ID;
			}
			break;
	}
	return 1;
}

void parse_proto(struct nfattr *cda[], struct ctnl_tuple *tuple)
{
	if (cda[CTA_PROTO_ICMP_TYPE-1])
		tuple->l4dst.icmp.type =
			*(u_int8_t *)NFA_DATA(cda[CTA_PROTO_ICMP_TYPE-1]);

	if (cda[CTA_PROTO_ICMP_CODE-1])
		tuple->l4dst.icmp.code =
			*(u_int8_t *)NFA_DATA(cda[CTA_PROTO_ICMP_CODE-1]);

	if (cda[CTA_PROTO_ICMP_ID-1])
		tuple->l4src.icmp.id =
			*(u_int16_t *)NFA_DATA(cda[CTA_PROTO_ICMP_ID-1]);
}

int final_check(unsigned int flags,
		struct ctnl_tuple *orig,
		struct ctnl_tuple *reply)
{
	if (!(flags & ICMP_TYPE))
		return 0;
	else if (!(flags & ICMP_CODE))
		return 0;

	return 1;
}

void print_proto(struct ctnl_tuple *t)
{
	fprintf(stdout, "type=%d code=%d ", t->l4dst.icmp.type,
					    t->l4dst.icmp.code);
	/* ID only makes sense with ECHO */
	if (t->l4dst.icmp.type == 8)
		fprintf(stdout, "id=%d ", t->l4src.icmp.id);
}

static struct ctproto_handler icmp = {
	.name 		= "icmp",
	.protonum	= 1,
	.parse_opts	= parse,
	.parse_proto	= parse_proto,
	.print_proto	= print_proto,
	.final_check	= final_check,
	.help		= help,
	.opts		= opts,
	.version	= LIBCT_VERSION,
};

void __attribute__ ((constructor)) init(void);
void __attribute__ ((destructor)) fini(void);

void init(void)
{
	register_proto(&icmp);
}

void fini(void)
{
	unregister_proto(&icmp);
}
