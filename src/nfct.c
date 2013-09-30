/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Vyatta Inc. <http://www.vyatta.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <netinet/in.h>
#include <errno.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink_cttimeout.h>
#include <libnetfilter_cttimeout/libnetfilter_cttimeout.h>

#include "linux_list.h"
#include "nfct.h"

static int nfct_cmd_version(int argc, char *argv[]);
static int nfct_cmd_help(int argc, char *argv[]);

static void usage(char *argv[])
{
	fprintf(stderr, "Usage: %s subsystem command [parameters]...\n",
		argv[0]);
}

void nfct_perror(const char *msg)
{
	if (errno == 0) {
		fprintf(stderr, "nfct v%s: %s\n", VERSION, msg);
	} else {
		fprintf(stderr, "nfct v%s: %s: %s\n",
			VERSION, msg, strerror(errno));
	}
}

static LIST_HEAD(nfct_extension_list);

void nfct_extension_register(struct nfct_extension *ext)
{
	list_add(&ext->head, &nfct_extension_list);
}

static struct nfct_extension *nfct_extension_lookup(int type)
{
	struct nfct_extension *ext;

	list_for_each_entry(ext, &nfct_extension_list, head) {
		if (ext->type == type)
			return ext;
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	int subsys = NFCT_SUBSYS_NONE, ret = 0;
	struct nfct_extension *ext;

	if (argc < 2) {
		usage(argv);
		exit(EXIT_FAILURE);
	}
	if (strncmp(argv[1], "timeout", strlen(argv[1])) == 0) {
		subsys = NFCT_SUBSYS_TIMEOUT;
	} else if (strncmp(argv[1], "helper", strlen(argv[1])) == 0) {
		subsys = NFCT_SUBSYS_HELPER;
	} else if (strncmp(argv[1], "version", strlen(argv[1])) == 0)
		subsys = NFCT_SUBSYS_VERSION;
	else if (strncmp(argv[1], "help", strlen(argv[1])) == 0)
		subsys = NFCT_SUBSYS_HELP;
	else {
		fprintf(stderr, "nfct v%s: Unknown subsystem: %s\n",
			VERSION, argv[1]);
		usage(argv);
		exit(EXIT_FAILURE);
	}

	switch(subsys) {
	case NFCT_SUBSYS_VERSION:
		ret = nfct_cmd_version(argc, argv);
		break;
	case NFCT_SUBSYS_HELP:
		ret = nfct_cmd_help(argc, argv);
		break;
	default:
		ext = nfct_extension_lookup(subsys);
		if (ext == NULL) {
			fprintf(stderr, "nfct v%s: subsystem %s not supported\n",
				VERSION, argv[1]);
			return EXIT_FAILURE;
		}
		ret = ext->parse_params(argc, argv);
		break;
	}
	return ret < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

static const char version_msg[] =
	"nfct v%s: utility for the Netfilter's Connection Tracking System\n"
	"Copyright (C) 2012 Pablo Neira Ayuso <pablo@netfilter.org>\n"
	"This program comes with ABSOLUTELY NO WARRANTY.\n"
	"This is free software, and you are welcome to redistribute it under "
	"certain \nconditions; see LICENSE file distributed in this package "
	"for details.\n";

static int nfct_cmd_version(int argc, char *argv[])
{
	printf(version_msg, VERSION);
	return 0;
}

static const char help_msg[] =
	"nfct v%s: utility for the Netfilter's Connection Tracking System\n"
	"Usage: %s command [parameters]...\n\n"
	"Subsystem:\n"
	"  helper\t\tAllows to configure user-space helper\n"
	"  timeout\t\tAllows definition of fine-grain timeout policies\n"
	"  version\t\tDisplay version and disclaimer\n"
	"  help\t\t\tDisplay this help message\n"
	"Commands:\n"
	"  list [reset]\t\tList the accounting object table (and reset)\n"
	"  add object-name\tAdd new accounting object to table\n"
	"  delete object-name\tDelete existing accounting object\n"
	"  get object-name\tGet existing accounting object\n"
	"  flush\t\t\tFlush accounting object table\n";

static int nfct_cmd_help(int argc, char *argv[])
{
	printf(help_msg, VERSION, argv[0]);
	return 0;
}

int nfct_mnl_talk(struct mnl_socket *nl, struct nlmsghdr *nlh,
		  uint32_t seq, uint32_t portid,
		  int (*cb)(const struct nlmsghdr *nlh, void *data),
		  void *data)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		return -1;

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, cb, data);
		if (ret <= 0)
			break;

		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}
	if (ret == -1)
		return -1;

	return 0;
}
