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
#include "libct_proto.h"

static struct option opts[] = {
	{"--icmp-type", 1, 0, '1'},
	{"--icmp-code", 1, 0, '2'},
	{"--icmp-id", 1, 0, '3'},
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
				*flags |= ICMP_TYPE;
			}
			break;
		case '2':
			if (optarg) {
				orig->l4dst.icmp.code = atoi(optarg);
				*flags |= ICMP_CODE;
			}
			break;
		case '3':
			if (optarg) {
				orig->l4src.icmp.id = atoi(optarg);
				*flags |= ICMP_ID;
			}
			break;
	}
	return 1;
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
	fprintf(stdout, "type=%d code=%d id=%d", t->l4dst.icmp.type, 
				             	 t->l4dst.icmp.code,
						 t->l4src.icmp.id);
}

static struct ctproto_handler icmp = {
	.name 		= "icmp",
	.protonum	= 1,
	.parse_opts	= parse,
	.print_proto	= print_proto,
	.final_check	= final_check,
	.help		= help,
	.opts		= opts
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
