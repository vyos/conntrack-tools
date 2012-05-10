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

#include "nfct.h"

static void
nfct_cmd_timeout_usage(char *argv[])
{
	fprintf(stderr, "nfct v%s: Missing command\n"
			"%s timeout list|add|delete|get|flush "
			"[parameters...]\n", VERSION, argv[0]);
}

int nfct_cmd_timeout_parse_params(int argc, char *argv[])
{
	int cmd = NFCT_CMD_NONE, ret = 0;

	if (argc < 3) {
		nfct_cmd_timeout_usage(argv);
		return -1;
	}
	if (strncmp(argv[2], "list", strlen(argv[2])) == 0)
		cmd = NFCT_CMD_LIST;
	else if (strncmp(argv[2], "add", strlen(argv[2])) == 0)
		cmd = NFCT_CMD_ADD;
	else if (strncmp(argv[2], "delete", strlen(argv[2])) == 0)
		cmd = NFCT_CMD_DELETE;
	else if (strncmp(argv[2], "get", strlen(argv[2])) == 0)
		cmd = NFCT_CMD_GET;
	else if (strncmp(argv[2], "flush", strlen(argv[2])) == 0)
		cmd = NFCT_CMD_FLUSH;
	else {
		fprintf(stderr, "nfct v%s: Unknown command: %s\n",
			VERSION, argv[2]);
		nfct_cmd_timeout_usage(argv);
		return -1;
	}
	switch(cmd) {
	case NFCT_CMD_LIST:
		ret = nfct_cmd_timeout_list(argc, argv);
		break;
	case NFCT_CMD_ADD:
		ret = nfct_cmd_timeout_add(argc, argv);
		break;
	case NFCT_CMD_DELETE:
		ret = nfct_cmd_timeout_delete(argc, argv);
		break;
	case NFCT_CMD_GET:
		ret = nfct_cmd_timeout_get(argc, argv);
		break;
	case NFCT_CMD_FLUSH:
		ret = nfct_cmd_timeout_flush(argc, argv);
		break;
	}

	return 0;
}

static int nfct_timeout_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nfct_timeout *t;
	char buf[4096];

	t = nfct_timeout_alloc();
	if (t == NULL) {
		nfct_perror("OOM");
		goto err;
	}

	if (nfct_timeout_nlmsg_parse_payload(nlh, t) < 0) {
		nfct_perror("nfct_timeout_nlmsg_parse_payload");
		goto err_free;
	}

	nfct_timeout_snprintf(buf, sizeof(buf), t, 0);
	printf("%s\n", buf);

err_free:
	nfct_timeout_free(t);
err:
	return MNL_CB_OK;
}

int nfct_cmd_timeout_list(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	unsigned int seq, portid;
	int ret;

	if (argc > 3) {
		nfct_perror("too many arguments");
		return -1;
	}

	seq = time(NULL);
	nlh = nfct_timeout_nlmsg_build_hdr(buf, IPCTNL_MSG_TIMEOUT_GET,
						NLM_F_DUMP, seq);

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		nfct_perror("mnl_socket_open");
		return -1;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		nfct_perror("mnl_socket_bind");
		return -1;
	}
	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		nfct_perror("mnl_socket_send");
		return -1;
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, nfct_timeout_cb, NULL);
		if (ret <= 0)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}
	if (ret == -1) {
		nfct_perror("error");
		return -1;
	}
	mnl_socket_close(nl);

	return 0;
}

static uint32_t nfct_timeout_attr_max[IPPROTO_MAX] = {
	[IPPROTO_ICMP]		= NFCT_TIMEOUT_ATTR_ICMP_MAX,
	[IPPROTO_TCP]		= NFCT_TIMEOUT_ATTR_TCP_MAX,
	[IPPROTO_UDP]		= NFCT_TIMEOUT_ATTR_UDP_MAX,
	[IPPROTO_UDPLITE]	= NFCT_TIMEOUT_ATTR_UDPLITE_MAX,
	[IPPROTO_SCTP]		= NFCT_TIMEOUT_ATTR_SCTP_MAX,
	[IPPROTO_DCCP]		= NFCT_TIMEOUT_ATTR_DCCP_MAX,
	[IPPROTO_ICMPV6]	= NFCT_TIMEOUT_ATTR_ICMPV6_MAX,
	[IPPROTO_GRE]		= NFCT_TIMEOUT_ATTR_GRE_MAX,
	[IPPROTO_RAW]		= NFCT_TIMEOUT_ATTR_GENERIC_MAX,
};

int nfct_cmd_timeout_add(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t portid, seq;
	struct nfct_timeout *t;
	uint16_t l3proto;
	uint8_t l4proto;
	int ret, i;
	unsigned int j;

	if (argc < 6) {
		nfct_perror("missing parameters\n"
			    "syntax: nfct timeout add name "
			    "family protocol state1 "
			    "timeout1 state2 timeout2...");
		return -1;
	}

	t = nfct_timeout_alloc();
	if (t == NULL) {
		nfct_perror("OOM");
		return -1;
	}

	nfct_timeout_attr_set(t, NFCT_TIMEOUT_ATTR_NAME, argv[3]);

	if (strcmp(argv[4], "inet") == 0)
		l3proto = AF_INET;
	else if (strcmp(argv[4], "inet6") == 0)
		l3proto = AF_INET6;
	else {
		nfct_perror("unknown layer 3 protocol");
		return -1;
	}
	nfct_timeout_attr_set_u16(t, NFCT_TIMEOUT_ATTR_L3PROTO, l3proto);

	if (strcmp(argv[5], "tcp") == 0)
		l4proto = IPPROTO_TCP;
	else if (strcmp(argv[5], "udp") == 0)
		l4proto = IPPROTO_UDP;
	else if (strcmp(argv[5], "udplite") == 0)
		l4proto = IPPROTO_UDPLITE;
	else if (strcmp(argv[5], "sctp") == 0)
		l4proto = IPPROTO_SCTP;
	else if (strcmp(argv[5], "dccp") == 0)
		l4proto = IPPROTO_DCCP;
	else if (strcmp(argv[5], "icmp") == 0)
		l4proto = IPPROTO_ICMP;
	else if (strcmp(argv[5], "icmpv6") == 0)
		l4proto = IPPROTO_ICMPV6;
	else if (strcmp(argv[5], "gre") == 0)
		l4proto = IPPROTO_GRE;
	else if (strcmp(argv[5], "generic") == 0)
		l4proto = IPPROTO_RAW;
	else {
		nfct_perror("unknown layer 4 protocol");
		return -1;
	}
	nfct_timeout_attr_set_u8(t, NFCT_TIMEOUT_ATTR_L4PROTO, l4proto);

	for (i=6; i<argc; i+=2) {
		int matching = -1;

		for (j=0; j<nfct_timeout_attr_max[l4proto]; j++) {
			const char *state_name;

			state_name =
				nfct_timeout_policy_attr_to_name(l4proto, j);
			if (state_name == NULL) {
				nfct_perror("state name is NULL");
				return -1;
			}
			if (strcasecmp(argv[i], state_name) != 0)
				continue;

			matching = j;
			break;
		}
		if (matching != -1) {
			if (i+1 >= argc) {
				nfct_perror("missing value for this timeout");
				return -1;
			}
			nfct_timeout_policy_attr_set_u32(t, matching,
							 atoi(argv[i+1]));
			matching = -1;
		} else {
			fprintf(stderr, "nfct v%s: Wrong state name: `%s' "
					"for protocol `%s'\n",
					VERSION, argv[i], argv[5]);
			return -1;
		}
	}

	seq = time(NULL);
	nlh = nfct_timeout_nlmsg_build_hdr(buf, IPCTNL_MSG_TIMEOUT_NEW,
				     NLM_F_CREATE | NLM_F_ACK, seq);
	nfct_timeout_nlmsg_build_payload(nlh, t);

	nfct_timeout_free(t);

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		nfct_perror("mnl_socket_open");
		return -1;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		nfct_perror("mnl_socket_bind");
		return -1;
	}
	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		nfct_perror("mnl_socket_send");
		return -1;
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
		if (ret <= 0)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}
	if (ret == -1) {
		nfct_perror("error");
		return -1;
	}
	mnl_socket_close(nl);

	return 0;
}

int nfct_cmd_timeout_delete(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t portid, seq;
	struct nfct_timeout *t;
	int ret;

	if (argc < 4) {
		nfct_perror("missing timeout policy name");
		return -1;
	} else if (argc > 4) {
		nfct_perror("too many arguments");
		return -1;
	}

	t = nfct_timeout_alloc();
	if (t == NULL) {
		nfct_perror("OOM");
		return -1;
	}

	nfct_timeout_attr_set(t, NFCT_TIMEOUT_ATTR_NAME, argv[3]);

	seq = time(NULL);
	nlh = nfct_timeout_nlmsg_build_hdr(buf, IPCTNL_MSG_TIMEOUT_DELETE,
				     NLM_F_ACK, seq);
	nfct_timeout_nlmsg_build_payload(nlh, t);

	nfct_timeout_free(t);

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		nfct_perror("mnl_socket_open");
		return -1;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		nfct_perror("mnl_socket_bind");
		return -1;
	}
	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		nfct_perror("mnl_socket_send");
		return -1;
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
		if (ret <= 0)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}
	if (ret == -1) {
		nfct_perror("error");
		return -1;
	}

	mnl_socket_close(nl);

	return 0;
}

int nfct_cmd_timeout_get(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t portid, seq;
	struct nfct_timeout *t;
	int ret;

	if (argc < 4) {
		nfct_perror("missing timeout policy name");
		return -1;
	} else if (argc > 4) {
		nfct_perror("too many arguments");
		return -1;
	}

	t = nfct_timeout_alloc();
	if (t == NULL) {
		nfct_perror("OOM");
		return -1;
	}
	nfct_timeout_attr_set(t, NFCT_TIMEOUT_ATTR_NAME, argv[3]);

	seq = time(NULL);
	nlh = nfct_timeout_nlmsg_build_hdr(buf, IPCTNL_MSG_TIMEOUT_GET,
				     NLM_F_ACK, seq);

	nfct_timeout_nlmsg_build_payload(nlh, t);

	nfct_timeout_free(t);

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		nfct_perror("mnl_socket_open");
		return -1;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		nfct_perror("mnl_socket_bind");
		return -1;
	}
	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		nfct_perror("mnl_socket_send");
		return -1;
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, nfct_timeout_cb, NULL);
		if (ret <= 0)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}
	if (ret == -1) {
		nfct_perror("error");
		return -1;
	}
	mnl_socket_close(nl);

	return 0;
}

int nfct_cmd_timeout_flush(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t portid, seq;
	int ret;

	if (argc > 3) {
		nfct_perror("too many arguments");
		return -1;
	}

	seq = time(NULL);
	nlh = nfct_timeout_nlmsg_build_hdr(buf, IPCTNL_MSG_TIMEOUT_DELETE,
					   NLM_F_ACK, seq);

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		nfct_perror("mnl_socket_open");
		return -1;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		nfct_perror("mnl_socket_bind");
		return -1;
	}
	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		nfct_perror("mnl_socket_send");
		return -1;
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
		if (ret <= 0)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}
	if (ret == -1) {
		nfct_perror("error");
		return -1;
	}

	mnl_socket_close(nl);

	return 0;
}
