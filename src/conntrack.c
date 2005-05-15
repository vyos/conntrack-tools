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
#include <sys/wait.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/netfilter_ipv4/ip_conntrack_tuple.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include "libctnetlink.h"
#include "libnfnetlink.h"
#include "linux_list.h"
#include "libct_proto.h"

#define PROGNAME "conntrack"
#define VERSION "0.60"

#if 0
#define DEBUGP printf
#else
#define DEBUGP
#endif

#ifndef PROC_SYS_MODPROBE
#define PROC_SYS_MODPROBE "/proc/sys/kernel/modprobe"
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
	CT_EVENT	= (1 << CT_EVENT_BIT),

	CT_ACTION_BIT	= 6,
	CT_ACTION	= (1 << CT_ACTION_BIT),

	CT_VERSION_BIT	= 7,
	CT_VERSION	= (1 << CT_VERSION_BIT),

	CT_HELP_BIT	= 8,
	CT_HELP		= (1 << CT_HELP_BIT),
};
#define NUMBER_OF_CMD   9

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

	CT_OPT_TIMEOUT_BIT	= 5,
	CT_OPT_TIMEOUT		= (1 << CT_OPT_TIMEOUT_BIT),

	CT_OPT_STATUS_BIT	= 6,
	CT_OPT_STATUS		= (1 << CT_OPT_STATUS_BIT),

	CT_OPT_ZERO_BIT		= 7,
	CT_OPT_ZERO		= (1 << CT_OPT_ZERO_BIT),

	CT_OPT_DUMP_MASK_BIT	= 8,
	CT_OPT_DUMP_MASK	= (1 << CT_OPT_DUMP_MASK_BIT),

	CT_OPT_GROUP_MASK_BIT	= 9,
	CT_OPT_GROUP_MASK	= (1 << CT_OPT_GROUP_MASK_BIT),

	CT_OPT_EVENT_MASK_BIT	= 10,
	CT_OPT_EVENT_MASK	= (1 << CT_OPT_EVENT_MASK_BIT),

};
#define NUMBER_OF_OPT   11

static const char optflags[NUMBER_OF_OPT]
= { 's', 'd', 'r', 'q', 'p', 't', 'u', 'z','m','g','e'};

static struct option original_opts[] = {
	{"dump", 2, 0, 'L'},
	{"create", 1, 0, 'I'},
	{"delete", 1, 0, 'D'},
	{"get", 1, 0, 'G'},
	{"flush", 1, 0, 'F'},
	{"event", 1, 0, 'E'},
	{"action", 1, 0, 'A'},
	{"version", 0, 0, 'V'},
	{"help", 0, 0, 'h'},
	{"orig-src", 1, 0, 's'},
	{"orig-dst", 1, 0, 'd'},
	{"reply-src", 1, 0, 'r'},
	{"reply-dst", 1, 0, 'q'},
	{"protonum", 1, 0, 'p'},
	{"timeout", 1, 0, 't'},
	{"status", 1, 0, 'u'},
	{"zero", 0, 0, 'z'},
	{"dump-mask", 1, 0, 'm'},
	{"groups", 1, 0, 'g'},
	{"event-mask", 1, 0, 'e'},
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
          /*   -s  -d  -r  -q  -p  -t  -u  -z  -m  -g  -e */
/*LIST*/      {'x','x','x','x','x','x','x',' ','x','x','x'},
/*CREATE*/    {'+','+','+','+','+','+','+','x','x','x','x'},
/*DELETE*/    {' ',' ',' ',' ',' ','x','x','x','x','x','x'},
/*GET*/       {' ',' ',' ',' ','+','x','x','x','x','x','x'},
/*FLUSH*/     {'x','x','x','x','x','x','x','x','x','x','x'},
/*EVENT*/     {'x','x','x','x','x','x','x','x','x',' ','x'},
/*ACTION*/    {'x','x','x','x','x','x','x','x',' ','x',' '},
/*VERSION*/   {'x','x','x','x','x','x','x','x','x','x','x'},
/*HELP*/      {'x','x','x','x',' ','x','x','x','x','x','x'},
};

/* FIXME: hardcoded!, this must be defined during compilation time */
char *lib_dir = CONNTRACK_LIB_DIR;

LIST_HEAD(proto_list);

char *proto2str[IPPROTO_MAX] = {
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

void extension_help(struct ctproto_handler *h)
{
	fprintf(stdout, "\n");
	fprintf(stdout, "Proto `%s' help:\n", h->name);
	h->help();
}

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
	fprintf(stderr,"%s v%s: ", PROGNAME, VERSION);
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
			exit_error(PARAMETER_PROBLEM, "Illegal option `-%c' "
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

static void dump_tuple(struct ip_conntrack_tuple *tp)
{
	fprintf(stdout, "tuple %p: %u %u.%u.%u.%u:%hu -> %u.%u.%u.%u:%hu\n",
		tp, tp->dst.protonum,
		NIPQUAD(tp->src.ip), ntohs(tp->src.u.all),
		NIPQUAD(tp->dst.ip), ntohs(tp->dst.u.all));
}

void not_implemented_yet()
{
	exit_error(OTHER_PROBLEM, "Sorry, not implemented yet :(\n");
}


#define PARSE_STATUS 0
#define PARSE_GROUP 1
#define PARSE_EVENT 2
#define PARSE_DUMP 3
#define PARSE_MAX PARSE_DUMP+1

static struct parse_parameter {
	char 	*parameter[10];
	size_t  size;
	unsigned int value[10];
} parse_array[PARSE_MAX] = {
	{ {"ASSURED", "SEEN_REPLY", "UNSET"},
	  3,
	  { IPS_ASSURED, IPS_SEEN_REPLY, 0} },
	{ {"ALL", "TCP", "UDP", "ICMP"},
	  4,
	  {~0U, NFGRP_IPV4_CT_TCP, NFGRP_IPV4_CT_UDP, NFGRP_IPV4_CT_ICMP} },
	{ {"ALL", "NEW", "RELATED", "DESTROY", "REFRESH", "STATUS", 
	   "PROTOINFO", "HELPER", "HELPINFO", "NATINFO"},
	  10,
	  {~0U, IPCT_NEW, IPCT_RELATED, IPCT_DESTROY, IPCT_REFRESH, IPCT_STATUS,
	   IPCT_PROTOINFO, IPCT_HELPER, IPCT_HELPINFO, IPCT_NATINFO} },
	{ {"ALL", "TUPLE", "STATUS", "TIMEOUT", "PROTOINFO", "HELPINFO", 
	   "COUNTERS", "MARK"}, 8,
	  {~0U, DUMP_TUPLE, DUMP_STATUS, DUMP_TIMEOUT, DUMP_PROTOINFO,
	   DUMP_HELPINFO, DUMP_COUNTERS, DUMP_MARK} }
};

static int
do_parse_parameter(const char *str, size_t strlen, unsigned int *value, 
		   int parse_type)
{
	int i, ret = 0;
	struct parse_parameter *p = &parse_array[parse_type];
	
	for (i = 0; i < p->size; i++)
		if (strncasecmp(str, p->parameter[i], strlen) == 0) {
			*value |= p->value[i];
			ret = 1;
			break;
		}
	
	return ret;
}

static void
parse_parameter(const char *arg, unsigned int *status, int parse_type)
{
	const char *comma;

	while ((comma = strchr(arg, ',')) != NULL) {
		if (comma == arg 
		    || !do_parse_parameter(arg, comma-arg, status, parse_type))
			exit_error(PARAMETER_PROBLEM,"Bad parameter `%s'", arg);
		arg = comma+1;
	}

	if (strlen(arg) == 0
	    || !do_parse_parameter(arg, strlen(arg), status, parse_type))
		exit_error(PARAMETER_PROBLEM, "Bad parameter `%s'", arg);
}

unsigned int check_type(int argc, char *argv[])
{
	char *table = NULL;

	/* Nasty bug or feature in getopt_long ? 
	 * It seems that it behaves badly with optional arguments.
	 * Fortunately, I just stole the fix from iptables ;) */
	if (optarg)
		return 0;
	else if (optind < argc && argv[optind][0] != '-' 
			&& argv[optind][0] != '!')
		table = argv[optind++];
	
	if (!table)
		return 0;
		
	if (strncmp("expect", table, 6) == 0)
		return 1;
	else if (strncmp("conntrack", table, 9) == 0)
		return 0;
	else
		exit_error(PARAMETER_PROBLEM, "unknown type `%s'\n", table);

	return 0;
}

static char *get_modprobe(void)
{
	int procfile;
	char *ret;

#define PROCFILE_BUFSIZ	1024
	procfile = open(PROC_SYS_MODPROBE, O_RDONLY);
	if (procfile < 0)
		return NULL;

	ret = (char *) malloc(PROCFILE_BUFSIZ);
	if (ret) {
		memset(ret, 0, PROCFILE_BUFSIZ);
		switch (read(procfile, ret, PROCFILE_BUFSIZ)) {
		case -1: goto fail;
		case PROCFILE_BUFSIZ: goto fail; /* Partial read.  Weird */
		}
		if (ret[strlen(ret)-1]=='\n') 
			ret[strlen(ret)-1]=0;
		close(procfile);
		return ret;
	}
 fail:
	free(ret);
	close(procfile);
	return NULL;
}

int iptables_insmod(const char *modname, const char *modprobe)
{
	char *buf = NULL;
	char *argv[3];
	int status;

	/* If they don't explicitly set it, read out of kernel */
	if (!modprobe) {
		buf = get_modprobe();
		if (!buf)
			return -1;
		modprobe = buf;
	}

	switch (fork()) {
	case 0:
		argv[0] = (char *)modprobe;
		argv[1] = (char *)modname;
		argv[2] = NULL;
		execv(argv[0], argv);

		/* not usually reached */
		exit(1);
	case -1:
		return -1;

	default: /* parent */
		wait(&status);
	}

	free(buf);
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return 0;
	return -1;
}

void usage(char *prog) {
fprintf(stdout, "Tool to manipulate conntrack and expectations. Version %s\n", VERSION);
fprintf(stdout, "Usage: %s [commands] [options]\n", prog);
fprintf(stdout, "\n");
fprintf(stdout, "Commands:\n");
fprintf(stdout, "-L [table] [-z]   	List conntrack or expectation table\n");
fprintf(stdout, "-G [table] parameters  Get conntrack or expectation\n");
fprintf(stdout, "-D [table] parameters	Delete conntrack or expectation\n");
fprintf(stdout, "-I [table] parameters	Create a conntrack or expectation\n");
fprintf(stdout, "-E [table] [options]	Show events\n");
fprintf(stdout, "-F [table]	     	Flush table\n");
fprintf(stdout, "-A [table] [options]	Set action\n");
fprintf(stdout, "\n");
fprintf(stdout, "Options:\n");
fprintf(stdout, "--orig-src ip	     	Source address from original direction\n");
fprintf(stdout, "--orig-dst ip	     	Destination address from original direction\n");
fprintf(stdout, "--reply-src ip		Source addres from reply direction\n");
fprintf(stdout, "--reply-dst ip		Destination address from reply direction\n");
fprintf(stdout, "-p proto		Layer 4 Protocol\n");
fprintf(stdout, "-t timeout		Set timeout\n");
fprintf(stdout, "-u status		Set status\n");
fprintf(stdout, "-m dumpmask		Set dump mask\n");
fprintf(stdout, "-g groupmask		Set group mask\n");
fprintf(stdout, "-e eventmask		Set event mask\n");
fprintf(stdout, "-z 			Zero Counters\n");
}

int main(int argc, char *argv[])
{
	char c;
	unsigned int command = 0, options = 0;
	struct ip_conntrack_tuple orig, reply, *o = NULL, *r = NULL;
	struct ctproto_handler *h = NULL;
	union ip_conntrack_proto proto;
	unsigned long timeout = 0;
	unsigned int status = 0, group_mask = 0;
	unsigned long id = 0;
	unsigned int type = 0, dump_mask = 0, extra_flags = 0, event_mask = 0;
	int res = 0, retry = 2;

	memset(&proto, 0, sizeof(union ip_conntrack_proto));
	memset(&orig, 0, sizeof(struct ip_conntrack_tuple));
	memset(&reply, 0, sizeof(struct ip_conntrack_tuple));
	orig.dst.dir = IP_CT_DIR_ORIGINAL;
	reply.dst.dir = IP_CT_DIR_REPLY;
	
	while ((c = getopt_long(argc, argv, 
		"L::I::D::G::E::A::F::hVs:d:r:q:p:t:u:m:g:e:z", 
		opts, NULL)) != -1) {
	switch(c) {
		case 'L':
			command |= CT_LIST;
			type = check_type(argc, argv);
			break;
		case 'I':
			command |= CT_CREATE;
			type = check_type(argc, argv);
			break;
		case 'D':
			command |= CT_DELETE;
			type = check_type(argc, argv);
			break;
		case 'G':
			command |= CT_GET;
			type = check_type(argc, argv);
			break;
		case 'F':
			command |= CT_FLUSH;
			type = check_type(argc, argv);
			break;
		case 'E':
			command |= CT_EVENT;
			type = check_type(argc, argv);
			break;
		case 'A':
			command |= CT_ACTION;
			type = check_type(argc, argv);
			break;
		case 'V':
			command |= CT_VERSION;
			break;
		case 'h':
			command |= CT_HELP;
			break;
		case 'm':
			if (!optarg)
				continue;
			
			options |= CT_OPT_DUMP_MASK;
			parse_parameter(optarg, &dump_mask, PARSE_DUMP);
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
			parse_parameter(optarg, &status, PARSE_STATUS);
			/* Just insert confirmed conntracks */
			status |= IPS_CONFIRMED;
			break;
		}
		case 'g':
			options |= CT_OPT_GROUP_MASK;
			parse_parameter(optarg, &group_mask, PARSE_GROUP);
			break;
		case 'e':
			options |= CT_OPT_EVENT_MASK;
			parse_parameter(optarg, &event_mask, PARSE_EVENT);
			break;
		case 'z':
			options |= CT_OPT_ZERO;
			break;
		default:
			if (h && h->parse && !h->parse(c - h->option_offset, 
						       argv, &orig, &reply,
						       &proto, &extra_flags))
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

	if (!(command & CT_HELP)
	    && h && h->final_check && !h->final_check(extra_flags)) {
		usage(argv[0]);
		extension_help(h);
		exit_error(PARAMETER_PROBLEM, "Missing protocol arguments!\n");
	}

	while (retry > 0) {
		retry--;
		switch(command) {
		case CT_LIST:
			if (type == 0) {
				if (options & CT_OPT_ZERO)
					res = dump_conntrack_table(1);
				else
					res = dump_conntrack_table(0);
			} else 
				res = dump_expect_list();
			break;
			
		case CT_CREATE:
			if (type == 0)
				res = create_conntrack(&orig, &reply, timeout, 
						       &proto, status);
			else
				not_implemented_yet();
			break;
			
		case CT_DELETE:
			if (type == 0) {
				if (options & CT_OPT_ORIG)
					res =delete_conntrack(&orig, CTA_ORIG, 
							      id);
				else if (options & CT_OPT_REPL)
					res = delete_conntrack(&reply, CTA_RPLY,
							       id);
			} else
				not_implemented_yet();
			break;
			
		case CT_GET:
			if (type == 0) {
				if (options & CT_OPT_ORIG)
					res = get_conntrack(&orig, CTA_ORIG, 
							    id);
				else if (options & CT_OPT_REPL)
					res = get_conntrack(&reply, CTA_RPLY,
							    id);
			} else
				not_implemented_yet();
			break;
			
		case CT_FLUSH:
			if (type == 0)
				res = flush_conntrack();
			else
				not_implemented_yet();
			break;
			
		case CT_EVENT:
			if (type == 0) {
				if (options & CT_OPT_GROUP_MASK)
					res = event_conntrack(group_mask);
				else
					res = event_conntrack(~0U);
			} else
				not_implemented_yet();
			
		case CT_ACTION:
			if (type == 0)
				if (options & CT_OPT_DUMP_MASK)
					res = set_mask(dump_mask, 0);
				else if (options & CT_OPT_EVENT_MASK)
					res = set_mask(event_mask, 1);
			break;
		case CT_VERSION:
			fprintf(stdout, "%s v%s\n", PROGNAME, VERSION);
			break;
		case CT_HELP:
			usage(argv[0]);
			if (options & CT_OPT_PROTO)
				extension_help(h);
			break;
		default:
			usage(argv[0]);
			break;
		}
		/* Maybe ip_conntrack_netlink isn't insmod'ed */
		if (res == -1 && retry)
			/* Give it a try just once */
			iptables_insmod("ip_conntrack_netlink", NULL);
		else
			retry--;
	}

	if (opts != original_opts) {
		free(opts);
		opts = original_opts;
		global_option_offset = 0;
	}

	if (res == -1)
		fprintf(stderr, "Operation failed\n");
}
