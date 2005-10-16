/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@netfilter.org>
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
 * 2005-06-23 Harald Welte <laforge@netfilter.org>:
 * 	Add support for expect creation
 * 2005-09-24 Harald Welte <laforge@netfilter.org>:
 * 	Remove remaints of "-A"
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
#include <dlfcn.h>
#include <string.h>
#include "linux_list.h"
#include "conntrack.h"
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#define PROGNAME "conntrack"
#define VERSION "0.86"

#ifndef PROC_SYS_MODPROBE
#define PROC_SYS_MODPROBE "/proc/sys/kernel/modprobe"
#endif

enum action {
	CT_NONE		= 0,
	
	CT_LIST_BIT 	= 0,
	CT_LIST 	= (1 << CT_LIST_BIT),
	
	CT_CREATE_BIT	= 1,
	CT_CREATE	= (1 << CT_CREATE_BIT),

	CT_UPDATE_BIT	= 2,
	CT_UPDATE	= (1 << CT_UPDATE_BIT),
	
	CT_DELETE_BIT	= 3,
	CT_DELETE	= (1 << CT_DELETE_BIT),
	
	CT_GET_BIT	= 4,
	CT_GET		= (1 << CT_GET_BIT),

	CT_FLUSH_BIT	= 5,
	CT_FLUSH	= (1 << CT_FLUSH_BIT),

	CT_EVENT_BIT	= 6,
	CT_EVENT	= (1 << CT_EVENT_BIT),

	CT_VERSION_BIT	= 7,
	CT_VERSION	= (1 << CT_VERSION_BIT),

	CT_HELP_BIT	= 8,
	CT_HELP		= (1 << CT_HELP_BIT),

	EXP_LIST_BIT 	= 9,
	EXP_LIST 	= (1 << EXP_LIST_BIT),
	
	EXP_CREATE_BIT	= 10,
	EXP_CREATE	= (1 << EXP_CREATE_BIT),
	
	EXP_DELETE_BIT	= 11,
	EXP_DELETE	= (1 << EXP_DELETE_BIT),
	
	EXP_GET_BIT	= 12,
	EXP_GET		= (1 << EXP_GET_BIT),

	EXP_FLUSH_BIT	= 13,
	EXP_FLUSH	= (1 << EXP_FLUSH_BIT),

	EXP_EVENT_BIT	= 14,
	EXP_EVENT	= (1 << EXP_EVENT_BIT),
};
#define NUMBER_OF_CMD   15

static const char cmdflags[NUMBER_OF_CMD]
= {'L','I','U','D','G','F','E','V','h','L','I','D','G','F','E'};

static const char cmd_need_param[NUMBER_OF_CMD]
= {' ','x','x','x','x',' ',' ',' ',' ',' ','x','x','x',' ',' '};

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

	CT_OPT_EVENT_MASK_BIT	= 8,
	CT_OPT_EVENT_MASK	= (1 << CT_OPT_EVENT_MASK_BIT),

	CT_OPT_EXP_SRC_BIT	= 9,
	CT_OPT_EXP_SRC		= (1 << CT_OPT_EXP_SRC_BIT),

	CT_OPT_EXP_DST_BIT	= 10,
	CT_OPT_EXP_DST		= (1 << CT_OPT_EXP_DST_BIT),

	CT_OPT_MASK_SRC_BIT	= 11,
	CT_OPT_MASK_SRC		= (1 << CT_OPT_MASK_SRC_BIT),

	CT_OPT_MASK_DST_BIT	= 12,
	CT_OPT_MASK_DST		= (1 << CT_OPT_MASK_DST_BIT),

	CT_OPT_NATRANGE_BIT	= 13,
	CT_OPT_NATRANGE		= (1 << CT_OPT_NATRANGE_BIT),
};
#define NUMBER_OF_OPT   14

static const char optflags[NUMBER_OF_OPT]
= {'s','d','r','q','p','t','u','z','e','[',']','{','}','a'};

static struct option original_opts[] = {
	{"dump", 2, 0, 'L'},
	{"create", 1, 0, 'I'},
	{"delete", 1, 0, 'D'},
	{"update", 1, 0, 'U'},
	{"get", 1, 0, 'G'},
	{"flush", 1, 0, 'F'},
	{"event", 1, 0, 'E'},
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
	{"event-mask", 1, 0, 'e'},
	{"tuple-src", 1, 0, '['},
	{"tuple-dst", 1, 0, ']'},
	{"mask-src", 1, 0, '{'},
	{"mask-dst", 1, 0, '}'},
	{"nat-range", 1, 0, 'a'},
	{0, 0, 0, 0}
};

#define OPTION_OFFSET 256

struct nfct_handle *cth;
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

/* FIXME: I'd need something different than this table to catch up some 
 *        particular cases. Better later Pablo */
static char commands_v_options[NUMBER_OF_CMD][NUMBER_OF_OPT] =
/* Well, it's better than "Re: Linux vs FreeBSD" */
{
          /*   -s  -d  -r  -q  -p  -t  -u  -z  -e  -x  -y  -k  -l  -a */
/*CT_LIST*/   {'x','x','x','x','x','x','x',' ','x','x','x','x','x','x'},
/*CT_CREATE*/ {' ',' ',' ',' ','+','+','+','x','x','x','x','x','x',' '},
/*CT_UPDATE*/ {' ',' ',' ',' ','+','+','+','x','x','x','x','x','x','x'},
/*CT_DELETE*/ {' ',' ',' ',' ',' ','x','x','x','x','x','x','x','x','x'},
/*CT_GET*/    {' ',' ',' ',' ','+','x','x','x','x','x','x','x','x','x'},
/*CT_FLUSH*/  {'x','x','x','x','x','x','x','x','x','x','x','x','x','x'},
/*CT_EVENT*/  {'x','x','x','x','x','x','x','x',' ','x','x','x','x','x'},
/*VERSION*/   {'x','x','x','x','x','x','x','x','x','x','x','x','x','x'},
/*HELP*/      {'x','x','x','x',' ','x','x','x','x','x','x','x','x','x'},
/*EXP_LIST*/  {'x','x','x','x','x','x','x','x','x','x','x','x','x','x'},
/*EXP_CREATE*/{'+','+',' ',' ','+','+',' ','x','x','+','+','+','+','x'},
/*EXP_DELETE*/{'+','+',' ',' ','+','x','x','x','x','x','x','x','x','x'},
/*EXP_GET*/   {'+','+',' ',' ','+','x','x','x','x','x','x','x','x','x'},
/*EXP_FLUSH*/ {'x','x','x','x','x','x','x','x','x','x','x','x','x','x'},
/*EXP_EVENT*/ {'x','x','x','x','x','x','x','x','x','x','x','x','x','x'},
};

char *lib_dir = CONNTRACK_LIB_DIR;

LIST_HEAD(proto_list);

void register_proto(struct ctproto_handler *h)
{
	if (strcmp(h->version, LIBCT_VERSION) != 0) {
		fprintf(stderr, "plugin `%s': version %s (I'm %s)\n",
			h->name, h->version, LIBCT_VERSION);
		exit(1);
	}
	list_add(&h->head, &proto_list);
}

void unregister_proto(struct ctproto_handler *h)
{
	list_del(&h->head);
}

static struct nfct_proto *findproto(char *name)
{
	struct list_head *i;
	struct nfct_proto *cur = NULL, *handler = NULL;

	if (!name) 
		return handler;

	lib_dir = getenv("CONNTRACK_LIB_DIR");
	if (!lib_dir)
		lib_dir = CONNTRACK_LIB_DIR;

	list_for_each(i, &proto_list) {
		cur = (struct nfct_proto *) i;
		if (strcmp(cur->name, name) == 0) {
			handler = cur;
			break;
		}
	}

	if (!handler) {
		char path[sizeof("libct_proto_.so")
			 + strlen(name) + strlen(lib_dir)];
                sprintf(path, "%s/libct_proto_%s.so", lib_dir, name);
		if (dlopen(path, RTLD_NOW))
			handler = findproto(name);
		else
			fprintf(stderr, "%s\n", dlerror());
	}

	return handler;
}

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
generic_cmd_check(int command, int options)
{
	int i;
	
	for (i = 0; i < NUMBER_OF_CMD; i++) {
		if (!(command & (1<<i)))
			continue;

		if (cmd_need_param[i] == 'x' && !options)
			exit_error(PARAMETER_PROBLEM,
				   "You need to supply parameters to `-%c'\n",
				   cmdflags[i]);
	}
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

/* From linux/errno.h */
#define ENOTSUPP        524     /* Operation is not supported */

/* Translates errno numbers into more human-readable form than strerror. */
const char *
err2str(int err, enum action command)
{
	unsigned int i;
	struct table_struct {
		enum action act;
		int err;
		const char *message;
	} table [] =
	  { { CT_LIST, -ENOTSUPP, "function not implemented" },
	    { 0xFFFF, -EINVAL, "invalid parameters" },
	    { CT_CREATE, -EEXIST, "Such conntrack exists, try -U to update" },
	    { CT_CREATE|CT_GET|CT_DELETE, -ENOENT, 
		    "such conntrack doesn't exist" },
	    { CT_CREATE|CT_GET, -ENOMEM, "not enough memory" },
	    { CT_GET, -EAFNOSUPPORT, "protocol not supported" },
	    { CT_CREATE, -ETIME, "conntrack has expired" },
	    { EXP_CREATE, -ENOENT, "master conntrack not found" },
	    { EXP_CREATE, -EINVAL, "invalid parameters" },
	    { ~0UL, -EPERM, "sorry, you must be root or get "
		    	    "CAP_NET_ADMIN capability to do this"}
	  };

	for (i = 0; i < sizeof(table)/sizeof(struct table_struct); i++) {
		if ((table[i].act & command) && table[i].err == err)
			return table[i].message;
	}

	return strerror(err);
}

static void dump_tuple(struct nfct_tuple *tp)
{
	fprintf(stdout, "tuple %p: %u %u.%u.%u.%u:%hu -> %u.%u.%u.%u:%hu\n",
		tp, tp->protonum,
		NIPQUAD(tp->src.v4), ntohs(tp->l4src.all),
		NIPQUAD(tp->dst.v4), ntohs(tp->l4dst.all));
}

#define PARSE_STATUS 0
#define PARSE_EVENT 1
#define PARSE_MAX 2

static struct parse_parameter {
	char 	*parameter[5];
	size_t  size;
	unsigned int value[5];
} parse_array[PARSE_MAX] = {
	{ {"ASSURED", "SEEN_REPLY", "UNSET", "SRC_NAT", "DST_NAT"}, 5,
	  { IPS_ASSURED, IPS_SEEN_REPLY, 0, 
	    IPS_SRC_NAT_DONE, IPS_DST_NAT_DONE} },
	{ {"ALL", "NEW", "UPDATES", "DESTROY"}, 4,
	  {~0U, NF_NETLINK_CONNTRACK_NEW, NF_NETLINK_CONNTRACK_UPDATE, 
	   NF_NETLINK_CONNTRACK_DESTROY} },
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

static void
add_command(unsigned int *cmd, const int newcmd, const int othercmds)
{
	if (*cmd & (~othercmds))
		exit_error(PARAMETER_PROBLEM, "Invalid commands combination\n");
	*cmd |= newcmd;
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

/* Shamelessly stolen from libipt_DNAT ;). Ranges expected in network order. */
static void
nat_parse(char *arg, int portok, struct nfct_nat *range)
{
	char *colon, *dash, *error;
	unsigned long ip;

	memset(range, 0, sizeof(range));
	colon = strchr(arg, ':');

	if (colon) {
		int port;

		if (!portok)
			exit_error(PARAMETER_PROBLEM,
				   "Need TCP or UDP with port specification");

		port = atoi(colon+1);
		if (port == 0 || port > 65535)
			exit_error(PARAMETER_PROBLEM,
				   "Port `%s' not valid\n", colon+1);

		error = strchr(colon+1, ':');
		if (error)
			exit_error(PARAMETER_PROBLEM,
				   "Invalid port:port syntax - use dash\n");

		dash = strchr(colon, '-');
		if (!dash) {
			range->l4min.tcp.port
				= range->l4max.tcp.port
				= htons(port);
		} else {
			int maxport;

			maxport = atoi(dash + 1);
			if (maxport == 0 || maxport > 65535)
				exit_error(PARAMETER_PROBLEM,
					   "Port `%s' not valid\n", dash+1);
			if (maxport < port)
				/* People are stupid.  */
				exit_error(PARAMETER_PROBLEM,
					   "Port range `%s' funky\n", colon+1);
			range->l4min.tcp.port = htons(port);
			range->l4max.tcp.port = htons(maxport);
		}
		/* Starts with a colon? No IP info... */
		if (colon == arg)
			return;
		*colon = '\0';
	}

	dash = strchr(arg, '-');
	if (colon && dash && dash > colon)
		dash = NULL;

	if (dash)
		*dash = '\0';

	ip = inet_addr(arg);
	if (!ip)
		exit_error(PARAMETER_PROBLEM, "Bad IP address `%s'\n",
			   arg);
	range->min_ip = ip;
	if (dash) {
		ip = inet_addr(dash+1);
		if (!ip)
			exit_error(PARAMETER_PROBLEM, "Bad IP address `%s'\n",
				   dash+1);
		range->max_ip = ip;
	} else
		range->max_ip = range->min_ip;
}

static void event_sighandler(int s)
{
	fprintf(stdout, "Now closing conntrack event dumping...\n");
	nfct_close(cth);
	exit(0);
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
fprintf(stdout, "-U [table] parameters  Update a conntrack\n");
fprintf(stdout, "-E [table] [options]	Show events\n");
fprintf(stdout, "-F [table]	     	Flush table\n");
fprintf(stdout, "\n");
fprintf(stdout, "Options:\n");
fprintf(stdout, "--orig-src ip	     	Source address from original direction\n");
fprintf(stdout, "--orig-dst ip	     	Destination address from original direction\n");
fprintf(stdout, "--reply-src ip		Source addres from reply direction\n");
fprintf(stdout, "--reply-dst ip		Destination address from reply direction\n");
fprintf(stdout, "--tuple-src ip		Source address in expect tuple\n");
fprintf(stdout, "--tuple-dst ip		Destination address in expect tuple\n");
fprintf(stdout, "--mask-src ip		Source mask address for expectation\n");
fprintf(stdout, "--mask-dst ip		Destination mask address for expectations\n");
fprintf(stdout, "-p proto		Layer 4 Protocol\n");
fprintf(stdout, "-t timeout		Set timeout\n");
fprintf(stdout, "-u status		Set status\n");
fprintf(stdout, "-e eventmask		Set event mask\n");
fprintf(stdout, "-a min_ip[-max_ip]	NAT ip range\n");
fprintf(stdout, "-z 			Zero Counters\n");
}

int main(int argc, char *argv[])
{
	char c;
	unsigned int command = 0, options = 0;
	struct nfct_tuple orig, reply, mask, *o = NULL, *r = NULL;
	struct nfct_tuple exptuple;
	struct ctproto_handler *h = NULL;
	union nfct_protoinfo proto;
	struct nfct_nat range;
	unsigned long timeout = 0;
	unsigned int status = IPS_CONFIRMED;
	unsigned long id = 0;
	unsigned int type = 0, extra_flags = 0, event_mask = 0;
	int manip = -1;
	int res = 0, retry = 2;

	memset(&proto, 0, sizeof(union nfct_protoinfo));
	memset(&orig, 0, sizeof(struct nfct_tuple));
	memset(&reply, 0, sizeof(struct nfct_tuple));
	memset(&mask, 0, sizeof(struct nfct_tuple));
	memset(&exptuple, 0, sizeof(struct nfct_tuple));
	memset(&range, 0, sizeof(struct nfct_nat));

	while ((c = getopt_long(argc, argv, 
		"L::I::U::D::G::E::F::hVs:d:r:q:p:t:u:e:a:z[:]:{:}:", 
		opts, NULL)) != -1) {
	switch(c) {
		case 'L':
			type = check_type(argc, argv);
			if (type == 0)
				add_command(&command, CT_LIST, CT_NONE);
			else if (type == 1)
				add_command(&command, EXP_LIST, CT_NONE);
			break;
		case 'I':
			type = check_type(argc, argv);
			if (type == 0)
				add_command(&command, CT_CREATE, CT_NONE);
			else if (type == 1)
				add_command(&command, EXP_CREATE, CT_NONE);
			break;
		case 'U':
			type = check_type(argc, argv);
			if (type == 0)
				add_command(&command, CT_UPDATE, CT_NONE);
			else
				exit_error(PARAMETER_PROBLEM, "Can't update "
					   "expectations");
			break;
		case 'D':
			type = check_type(argc, argv);
			if (type == 0)
				add_command(&command, CT_DELETE, CT_NONE);
			else if (type == 1)
				add_command(&command, EXP_DELETE, CT_NONE);
			break;
		case 'G':
			type = check_type(argc, argv);
			if (type == 0)
				add_command(&command, CT_GET, CT_NONE);
			else if (type == 1)
				add_command(&command, EXP_GET, CT_NONE);
			break;
		case 'F':
			type = check_type(argc, argv);
			if (type == 0)
				add_command(&command, CT_FLUSH, CT_NONE);
			else if (type == 1)
				add_command(&command, EXP_FLUSH, CT_NONE);
			break;
		case 'E':
			type = check_type(argc, argv);
			if (type == 0)
				add_command(&command, CT_EVENT, CT_NONE);
			else if (type == 1)
				add_command(&command, EXP_EVENT, CT_NONE);
			break;
		case 'V':
			add_command(&command, CT_VERSION, CT_NONE);
			break;
		case 'h':
			add_command(&command, CT_HELP, CT_NONE);
			break;
		case 's':
			options |= CT_OPT_ORIG_SRC;
			if (optarg)
				orig.src.v4 = inet_addr(optarg);
			break;
		case 'd':
			options |= CT_OPT_ORIG_DST;
			if (optarg)
				orig.dst.v4 = inet_addr(optarg);
			break;
		case 'r':
			options |= CT_OPT_REPL_SRC;
			if (optarg)
				reply.src.v4 = inet_addr(optarg);
			break;
		case 'q':
			options |= CT_OPT_REPL_DST;
			if (optarg)
				reply.dst.v4 = inet_addr(optarg);
			break;
		case 'p':
			options |= CT_OPT_PROTO;
			h = findproto(optarg);
			if (!h)
				exit_error(PARAMETER_PROBLEM, "proto needed\n");
			orig.protonum = h->protonum;
			reply.protonum = h->protonum;
			exptuple.protonum = h->protonum;
			mask.protonum = h->protonum;
			opts = merge_options(opts, h->opts, 
					     &h->option_offset);
			break;
		case 't':
			options |= CT_OPT_TIMEOUT;
			if (optarg)
				timeout = atol(optarg);
			break;
		case 'u': {
			if (!optarg)
				continue;

			options |= CT_OPT_STATUS;
			parse_parameter(optarg, &status, PARSE_STATUS);
			break;
		}
		case 'e':
			options |= CT_OPT_EVENT_MASK;
			parse_parameter(optarg, &event_mask, PARSE_EVENT);
			break;
		case 'z':
			options |= CT_OPT_ZERO;
			break;
		case '{':
			options |= CT_OPT_MASK_SRC;
			if (optarg)
				mask.src.v4 = inet_addr(optarg);
			break;
		case '}':
			options |= CT_OPT_MASK_DST;
			if (optarg)
				mask.dst.v4 = inet_addr(optarg);
			break;
		case '[':
			options |= CT_OPT_EXP_SRC;
			if (optarg)
				exptuple.src.v4 = inet_addr(optarg);
			break;
		case ']':
			options |= CT_OPT_EXP_DST;
			if (optarg)
				exptuple.dst.v4 = inet_addr(optarg);
			break;
		case 'a':
			options |= CT_OPT_NATRANGE;
			nat_parse(optarg, 1, &range);
			break;
		default:
			if (h && h->parse_opts 
			    &&!h->parse_opts(c - h->option_offset, argv, &orig, 
				             &reply, &mask, &proto, 
					     &extra_flags))
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

	generic_cmd_check(command, options);
	generic_opt_check(command, options);

	if (!(command & CT_HELP)
	    && h && h->final_check 
	    && !h->final_check(extra_flags, &orig, &reply)) {
		usage(argv[0]);
		extension_help(h);
		exit_error(PARAMETER_PROBLEM, "Missing protocol arguments!\n");
	}

	while (retry > 0) {
		retry--;
		switch(command) {
		case CT_LIST:
			cth = nfct_open(CONNTRACK, 0);
			if (!cth)
				exit_error(OTHER_PROBLEM, "Not enough memory");
			nfct_set_callback(cth, nfct_default_conntrack_display);
			if (options & CT_OPT_ZERO)
				res = nfct_dump_conntrack_table_zero(cth);
			else
				res = nfct_dump_conntrack_table(cth);
			break;
			nfct_close(cth);

		case EXP_LIST:
			cth = nfct_open(EXPECT, 0);
			if (!cth)
				exit_error(OTHER_PROBLEM, "Not enough memory");
			nfct_set_callback(cth, nfct_default_expect_display);
			res = nfct_dump_expect_list(cth);
			nfct_close(cth);
			break;
			
		case CT_CREATE:
			if ((options & CT_OPT_ORIG) 
			    && !(options & CT_OPT_REPL)) {
				reply.src.v4 = orig.dst.v4;
				reply.dst.v4 = orig.src.v4;
			} else if (!(options & CT_OPT_ORIG)
				   && (options & CT_OPT_REPL)) {
				orig.src.v4 = reply.dst.v4;
				orig.dst.v4 = reply.src.v4;
			}
			cth = nfct_open(CONNTRACK, 0);
			if (!cth)
				exit_error(OTHER_PROBLEM, "Not enough memory");
			if (options & CT_OPT_NATRANGE)
				res = nfct_create_conntrack_nat(cth,
								    &orig, 
								    &reply, 
								    timeout, 
								    &proto, 
								    status, 
								    &range);
			else
				res = nfct_create_conntrack(cth, &orig,
								    &reply,
								    timeout,
								    &proto,
								    status);
			nfct_close(cth);
			break;

		case EXP_CREATE:
			cth = nfct_open(EXPECT, 0);
			if (!cth)
				exit_error(OTHER_PROBLEM, "Not enough memory");
			if (options & CT_OPT_ORIG)
				res = nfct_create_expectation(cth,
								      &orig,
								      &exptuple,
								      &mask,
								      timeout);
			else if (options & CT_OPT_REPL)
				res = nfct_create_expectation(cth,
								      &reply,
								      &exptuple,
								      &mask,
								      timeout);
			nfct_close(cth);
			break;

		case CT_UPDATE:
			if ((options & CT_OPT_ORIG) 
			    && !(options & CT_OPT_REPL)) {
				reply.src.v4 = orig.dst.v4;
				reply.dst.v4 = orig.src.v4;
			} else if (!(options & CT_OPT_ORIG)
				   && (options & CT_OPT_REPL)) {
				orig.src.v4 = reply.dst.v4;
				orig.dst.v4 = reply.src.v4;
			}
			cth = nfct_open(CONNTRACK, 0);
			if (!cth)
				exit_error(OTHER_PROBLEM, "Not enough memory");
			res = nfct_update_conntrack(cth, &orig, &reply, 
							    timeout, &proto, 
							    status);
			nfct_close(cth);
			break;
			
		case CT_DELETE:
			cth = nfct_open(CONNTRACK, 0);
			if (!cth)
				exit_error(OTHER_PROBLEM, "Not enough memory");
			if (options & CT_OPT_ORIG)
				res = nfct_delete_conntrack(cth,&orig, 
							    NFCT_DIR_ORIGINAL);
			else if (options & CT_OPT_REPL)
				res = nfct_delete_conntrack(cth,&reply, 
							    NFCT_DIR_REPLY);
			nfct_close(cth);
			break;

		case EXP_DELETE:
			cth = nfct_open(EXPECT, 0);
			if (!cth)
				exit_error(OTHER_PROBLEM, "Not enough memory");
			if (options & CT_OPT_ORIG)
				res = nfct_delete_expectation(cth,&orig);
			else if (options & CT_OPT_REPL)
				res = nfct_delete_expectation(cth,&reply);
			nfct_close(cth);
			break;

		case CT_GET:
			cth = nfct_open(CONNTRACK, 0);
			if (!cth)
				exit_error(OTHER_PROBLEM, "Not enough memory");
			if (options & CT_OPT_ORIG)
				res = nfct_get_conntrack(cth,&orig, id);
			else if (options & CT_OPT_REPL)
				res = nfct_get_conntrack(cth,&reply, id);
			nfct_close(cth);
			break;

		case EXP_GET:
			cth = nfct_open(EXPECT, 0);
			if (!cth)
				exit_error(OTHER_PROBLEM, "Not enough memory");
			if (options & CT_OPT_ORIG)
				res = nfct_get_expectation(cth,&orig);
			else if (options & CT_OPT_REPL)
				res = nfct_get_expectation(cth,&reply);
			nfct_close(cth);
			break;

		case CT_FLUSH:
			cth = nfct_open(CONNTRACK, 0);
			if (!cth)
				exit_error(OTHER_PROBLEM, "Not enough memory");
			res = nfct_flush_conntrack_table(cth);
			nfct_close(cth);
			break;

		case EXP_FLUSH:
			cth = nfct_open(EXPECT, 0);
			if (!cth)
				exit_error(OTHER_PROBLEM, "Not enough memory");
			res = nfct_flush_expectation_table(cth);
			nfct_close(cth);
			break;
			
		case CT_EVENT:
			if (options & CT_OPT_EVENT_MASK) {
				cth = nfct_open(CONNTRACK, event_mask);
				if (!cth)
					exit_error(OTHER_PROBLEM, 
						   "Not enough memory");
				signal(SIGINT, event_sighandler);
				nfct_set_callback(cth, nfct_default_conntrack_display);
				res = nfct_event_conntrack(cth);
			} else {
				cth = nfct_open(CONNTRACK, ~0U);
				if (!cth)
					exit_error(OTHER_PROBLEM, 
						   "Not enough memory");
				signal(SIGINT, event_sighandler);
				nfct_set_callback(cth, nfct_default_conntrack_display);
				res = nfct_event_conntrack(cth);
			}
			nfct_close(cth);
			break;

		case EXP_EVENT:
			if (options & CT_OPT_EVENT_MASK) {
				cth = nfct_open(EXPECT, event_mask);
				if (!cth)
					exit_error(OTHER_PROBLEM, 
						   "Not enough memory");
				signal(SIGINT, event_sighandler);
				nfct_set_callback(cth, nfct_default_expect_display);
				res = nfct_event_expectation(cth);
			} else {
				cth = nfct_open(EXPECT, ~0U);
				if (!cth)
					exit_error(OTHER_PROBLEM, 
						   "Not enough memory");
				signal(SIGINT, event_sighandler);
				nfct_set_callback(cth, nfct_default_expect_display);
				res = nfct_event_expectation(cth);
			}
			nfct_close(cth);
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
		if (res < 0 && retry)
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

	if (res < 0)
		fprintf(stderr, "Operation failed: %s\n", err2str(res, command));
}
