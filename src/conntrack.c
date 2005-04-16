/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@eurodev.net>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Note:
 *	Yes, portions of this code has been stolen from iptables ;)
 *	Special thanks to the the Netfilter Core Team.
 *	Thanks to Javier de Miguel Rodriguez <jmiguel at talika.eii.us.es>
 *	for introducing me to advanced firewalling stuff.
 *
 *						--pablo 13/04/2005
 *
 * 2005-04-16 Harald Welte <laforge@netfilter.org>: 
 * 	Add support for conntrack accounting and conntrack mark
 *
 */
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <netinet/in.h>
#include <linux/netfilter_ipv4/ip_conntrack_tuple.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include "libctnetlink.h"
#include "libnfnetlink.h"
#include "linux_list.h"
#include "libct_proto.h"

#define PROGNAME "conntrack"
#define VERSION "0.13"

#if 0
#define DEBUGP printf
#else
#define DEBUGP
#endif

enum action {
	CT_LIST_BIT 	= 0,
	CT_LIST 	= (1 << CT_LIST_BIT),
	
	CT_CREATE_BIT	= 1,
	CT_CREATE	= (1 << CT_CREATE_BIT),
	
	CT_DELETE_BIT	= 2,
	CT_DELETE	= (1 << CT_DELETE_BIT),
	
	CT_GET_BIT	= 3,
	CT_GET		= (1 << CT_GET_BIT),

	CT_FLUSH_BIT	= 4,
	CT_FLUSH	= (1 << CT_FLUSH_BIT),

	CT_EVENT_BIT	= 5,
	CT_EVENT	= (1 << CT_EVENT_BIT)
};
#define NUMBER_OF_CMD   6

enum options {
	CT_OPT_ORIG_SRC_BIT	= 0,
	CT_OPT_ORIG_SRC 	= (1 << CT_OPT_ORIG_SRC_BIT),
	
	CT_OPT_ORIG_DST_BIT	= 1,
	CT_OPT_ORIG_DST		= (1 << CT_OPT_ORIG_DST_BIT),

	CT_OPT_ORIG		= (CT_OPT_ORIG_SRC | CT_OPT_ORIG_DST),
	
	CT_OPT_REPL_SRC_BIT	= 2,
	CT_OPT_REPL_SRC		= (1 << CT_OPT_REPL_SRC_BIT),
	
	CT_OPT_REPL_DST_BIT	= 3,
	CT_OPT_REPL_DST		= (1 << CT_OPT_REPL_DST_BIT),

	CT_OPT_REPL		= (CT_OPT_REPL_SRC | CT_OPT_REPL_DST),

	CT_OPT_PROTO_BIT	= 4,
	CT_OPT_PROTO		= (1 << CT_OPT_PROTO_BIT),

	CT_OPT_ID_BIT		= 5,
	CT_OPT_ID		= (1 << CT_OPT_ID_BIT),

	CT_OPT_TIMEOUT_BIT	= 6,
	CT_OPT_TIMEOUT		= (1 << CT_OPT_TIMEOUT_BIT),

	CT_OPT_STATUS_BIT	= 7,
	CT_OPT_STATUS		= (1 << CT_OPT_STATUS_BIT),

	CT_OPT_ZERO_BIT		= 8,
	CT_OPT_ZERO		= (1 << CT_OPT_ZERO_BIT),
};
#define NUMBER_OF_OPT   9

static const char optflags[NUMBER_OF_OPT]
= { 's', 'd', 'r', 'q', 'p', 'i', 't', 'u', 'z'};

static struct option original_opts[] = {
	{"dump", 1, 0, 'L'},
	{"create", 1, 0, 'I'},
	{"delete", 1, 0, 'D'},
	{"get", 1, 0, 'G'},
	{"flush", 1, 0, 'F'},
	{"event", 1, 0, 'E'},
	{"orig-src", 1, 0, 's'},
	{"orig-dst", 1, 0, 'd'},
	{"reply-src", 1, 0, 'r'},
	{"reply-dst", 1, 0, 'q'},
	{"protonum", 1, 0, 'p'},
	{"timeout", 1, 0, 't'},
	{"id", 1, 0, 'i'},
	{"status", 1, 0, 'u'},
	{"zero", 0, 0, 'z'},
	{0, 0, 0, 0}
};

#define OPTION_OFFSET 256

static struct option *opts = original_opts;
static unsigned int global_option_offset = 0;

/* Table of legal combinations of commands and options.  If any of the
 * given commands make an option legal, that option is legal (applies to
 * CMD_LIST and CMD_ZERO only).
 * Key:
 *  +  compulsory
 *  x  illegal
 *     optional
 */

static char commands_v_options[NUMBER_OF_CMD][NUMBER_OF_OPT] =
/* Well, it's better than "Re: Linux vs FreeBSD" */
{
          /*   -s  -d  -r  -q  -p  -i  -t  -u  -z */
/*LIST*/      {'x','x','x','x','x','x','x','x',' '},
/*CREATE*/    {'+','+','+','+','+','x','+','+','x'},
/*DELETE*/    {' ',' ',' ',' ',' ','+','x','x','x'},
/*GET*/       {' ',' ',' ',' ','+','+','x','x','x'},
/*FLUSH*/     {'x','x','x','x','x','x','x','x','x'},
/*EVENT*/     {'x','x','x','x','x','x','x','x','x'}
};

LIST_HEAD(proto_list);

char *proto2str[] = {
	[IPPROTO_TCP] = "tcp",
        [IPPROTO_UDP] = "udp",
        [IPPROTO_ICMP] = "icmp",
        [IPPROTO_SCTP] = "sctp"
};

enum exittype {
        OTHER_PROBLEM = 1,
        PARAMETER_PROBLEM,
        VERSION_PROBLEM
};

void
exit_tryhelp(int status)
{
	fprintf(stderr, "Try `%s -h' or '%s --help' for more information.\n",
			PROGNAME, PROGNAME);
	exit(status);
}

static void
exit_error(enum exittype status, char *msg, ...)
{
	va_list args;

	/* On error paths, make sure that we don't leak the memory
	 * reserved during options merging */
	if (opts != original_opts) {
		free(opts);
		opts = original_opts;
		global_option_offset = 0;
	}
	va_start(args, msg);
	fprintf(stderr, "%s v%s: ", PROGNAME, VERSION);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, "\n");
	if (status == PARAMETER_PROBLEM)
		exit_tryhelp(status);
	exit(status);
}

static void
generic_opt_check(int command, int options)
{
	int i, j, legal = 0;

	/* Check that commands are valid with options.  Complicated by the
	 * fact that if an option is legal with *any* command given, it is
	 * legal overall (ie. -z and -l).
	 */
	for (i = 0; i < NUMBER_OF_OPT; i++) {
		legal = 0; /* -1 => illegal, 1 => legal, 0 => undecided. */

		for (j = 0; j < NUMBER_OF_CMD; j++) {
			if (!(command & (1<<j)))
				continue;

			if (!(options & (1<<i))) {
				if (commands_v_options[j][i] == '+') 
					exit_error(PARAMETER_PROBLEM, 
						   "You need to supply the "
						   "`-%c' option for this "
						   "command\n", optflags[i]);
			} else {
				if (commands_v_options[j][i] != 'x')
					legal = 1;
				else if (legal == 0)
					legal = -1;
			}
		}
		if (legal == -1)
			exit_error(PARAMETER_PROBLEM, "Illegal option `-%c'"
				   "with this command\n", optflags[i]);
	}
}

static struct option *
merge_options(struct option *oldopts, const struct option *newopts,
	      unsigned int *option_offset)
{
	unsigned int num_old, num_new, i;
	struct option *merge;

	for (num_old = 0; oldopts[num_old].name; num_old++);
	for (num_new = 0; newopts[num_new].name; num_new++);

	global_option_offset += OPTION_OFFSET;
	*option_offset = global_option_offset;

	merge = malloc(sizeof(struct option) * (num_new + num_old + 1));
	memcpy(merge, oldopts, num_old * sizeof(struct option));
	for (i = 0; i < num_new; i++) {
		merge[num_old + i] = newopts[i];
		merge[num_old + i].val += *option_offset;
	}
	memset(merge + num_old + num_new, 0, sizeof(struct option));

	return merge;
}

void not_implemented_yet()
{
	exit_error(OTHER_PROBLEM, "Sorry, not implemented yet :(\n");
}

unsigned int check_type()
{
	unsigned int type = 0;

	if (!optarg)
		exit_error(PARAMETER_PROBLEM, "must specified `conntrack' or "
			   "`expect'\n");
	
	if (strncmp("conntrack", optarg, 9) == 0)
		type = 0;
	else if (strncmp("expect", optarg, 6) == 0)
		type = 1;
	else {
		exit_error(PARAMETER_PROBLEM, "unknown type `%s'\n", optarg);
	}

	return type;
}

void usage(char *prog) {
printf("Tool to manipulate conntrack and expectations. Version %s\n", VERSION);
printf("Usage: %s [commands] [options]\n", prog);
printf("\n");
printf("Commands:\n");
printf("-L table	    	List conntrack or expectation table\n");
printf("-G table [options]  	Get conntrack or expectation\n");
printf("-D table [options]	Delete conntrack or expectation\n");
printf("-I table [options]	Create a conntrack or expectation\n");
printf("-E table	    	Show events\n");
printf("-F table	     	Flush table\n");
printf("\n");
printf("Options:\n");
printf("--orig-src	     	Source address from original direction\n");
printf("--orig-dst	     	Destination address from original direction\n");
printf("--reply-src		Source addres from reply direction\n");
printf("--reply-dst		Destination address from reply direction\n");
printf("-p 			Layer 4 Protocol\n");
printf("-t			Timeout\n");
printf("-i			Conntrack ID\n");
printf("-u			Status\n");
printf("-z			Zero Counters\n");
}

int main(int argc, char *argv[])
{
	char c;
	unsigned int command = 0, options = 0;
	struct ip_conntrack_tuple orig, reply, *o = NULL, *r = NULL;
	struct ctproto_handler *h = NULL;
	union ip_conntrack_proto proto;
	unsigned long timeout = 0;
	unsigned int status = 0;
	unsigned long id = 0;
	unsigned int type = 0;
	
	memset(&proto, 0, sizeof(union ip_conntrack_proto));
	memset(&orig, 0, sizeof(struct ip_conntrack_tuple));
	memset(&reply, 0, sizeof(struct ip_conntrack_tuple));
	orig.dst.dir = IP_CT_DIR_ORIGINAL;
	reply.dst.dir = IP_CT_DIR_REPLY;
	
	while ((c = getopt_long(argc, argv, 
			"L:I:D:G:E:s:d:r:q:p:i:t:u:z", opts, NULL)) != -1) {
	switch(c) {
		case 'L':
			command |= CT_LIST;
			type = check_type();
			break;
		case 'I':
			command |= CT_CREATE;
			type = check_type();
			break;
		case 'D':
			command |= CT_DELETE;
			type = check_type();
			break;
		case 'G':
			command |= CT_GET;
			type = check_type();
			break;
		case 'F':
			command |= CT_FLUSH;
			type = check_type();
			break;
		case 'E':
			command |= CT_EVENT;
			type = check_type();
			break;
		case 's':
			options |= CT_OPT_ORIG_SRC;
			if (optarg)
				orig.src.ip = inet_addr(optarg);
			break;
		case 'd':
			options |= CT_OPT_ORIG_DST;
			if (optarg)
				orig.dst.ip = inet_addr(optarg);
			break;
		case 'r':
			options |= CT_OPT_REPL_SRC;
			if (optarg)
				reply.src.ip = inet_addr(optarg);
			break;
		case 'q':
			options |= CT_OPT_REPL_DST;
			if (optarg)
				reply.dst.ip = inet_addr(optarg);
			break;
		case 'p':
			options |= CT_OPT_PROTO;
			h = findproto(optarg);
			if (!h)
				exit_error(PARAMETER_PROBLEM, "proto needed\n");
			orig.dst.protonum = h->protonum;
			reply.dst.protonum = h->protonum;
			opts = merge_options(opts, h->opts, 
					     &h->option_offset);
			break;
		case 'i':
			options |= CT_OPT_ID;
			id = atoi(optarg);
			break;
		case 't':
			options |= CT_OPT_TIMEOUT;
			if (optarg)
				timeout = atol(optarg);
			break;
		case 'u': {
		 	/* FIXME: NAT stuff, later... */
			if (!optarg)
				continue;

			options |= CT_OPT_STATUS;
			/* Just insert confirmed conntracks */
			status |= IPS_CONFIRMED;
			if (strncmp("SEEN_REPLY", optarg, strlen("SEEN_REPLY")) == 0)
				status |= IPS_SEEN_REPLY;
			else if (strncmp("ASSURED", optarg, strlen("ASSURED")) == 0)
				status |= IPS_ASSURED;
			else
				exit_error(PARAMETER_PROBLEM, "Invalid status"
					   "flag: %s\n", optarg);
			break;
		}
		case 'z':
			options |= CT_OPT_ZERO;
			break;
		default:
			if (h && !h->parse(c - h->option_offset, argv, 
					   &orig, &reply))
				exit_error(PARAMETER_PROBLEM, "parse error\n");

			/* Unknown argument... */
			if (!h) {
				usage(argv[0]);
				exit_error(PARAMETER_PROBLEM, "Missing "
					   "arguments...\n");
			}
			break;
		}
	}

	generic_opt_check(command, options);

	switch(command) {
		case CT_LIST:
			printf("list\n");
			if (type == 0) {
				if (options & CT_OPT_ZERO)
					dump_conntrack_table(1);
				else
					dump_conntrack_table(0);
			} else
				dump_expect_list();
			break;
		case CT_CREATE:
			printf("create\n");
			if (type == 0)
				create_conntrack(&orig, &reply, timeout, 
						 &proto, status);
			else
				not_implemented_yet();
			break;
		case CT_DELETE:
			printf("delete\n");
			if (type == 0) {
				if (options & CT_OPT_ORIG)
					delete_conntrack(&orig, CTA_ORIG, id);
				else if (options & CT_OPT_REPL)
					delete_conntrack(&reply, CTA_RPLY, id);
			} else
				not_implemented_yet();
			break;
		case CT_GET:
			printf("get\n");
			if (type == 0) {
				if (options & CT_OPT_ORIG)
					get_conntrack(&orig, CTA_ORIG, id);
				else if (options & CT_OPT_REPL)
					get_conntrack(&reply, CTA_RPLY, id);
			} else
				not_implemented_yet();
			break;
		case CT_FLUSH:
			not_implemented_yet();
			break;
		case CT_EVENT:
			printf("event\n");
			if (type == 0)
				event_conntrack();
			else
				/* and surely it won't ever... */
				not_implemented_yet();
		default:
			usage(argv[0]);
			break;
	}

	if (opts != original_opts) {
		free(opts);
		opts = original_opts;
		global_option_offset = 0;
	}
}
