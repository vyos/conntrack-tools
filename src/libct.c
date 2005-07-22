/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@eurodev.net>
 *             Harald Welte <laforge@netfilter.org>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */
#include <stdio.h>
#include <getopt.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
/* From kernel.h */
#define INT_MAX         ((int)(~0U>>1))
#define INT_MIN         (-INT_MAX - 1)
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include "libctnetlink.h"
#include "libnfnetlink.h"
#include "linux_list.h"
#include "libct_proto.h"

#if 0
#define DEBUGP printf
#else
#define DEBUGP
#endif

static struct ctnl_handle cth;
extern char *lib_dir;
extern struct list_head proto_list;
extern char *proto2str[];

static void print_status(unsigned int status)
{
	if (status & IPS_ASSURED)
		fprintf(stdout, "[ASSURED] ");
	if (!(status & IPS_SEEN_REPLY))
		fprintf(stdout, "[UNREPLIED] ");
}

static void parse_ip(struct nfattr *attr, struct ctnl_tuple *tuple)
{
	struct nfattr *tb[CTA_IP_MAX];

	memset(tb, 0, CTA_IP_MAX * sizeof(struct nfattr *));

        nfnl_parse_nested(tb, CTA_IP_MAX, attr);
	if (tb[CTA_IP_V4_SRC-1])
		tuple->src.v4 = *(u_int32_t *)NFA_DATA(tb[CTA_IP_V4_SRC-1]);

	if (tb[CTA_IP_V4_DST-1])
		tuple->dst.v4 = *(u_int32_t *)NFA_DATA(tb[CTA_IP_V4_DST-1]);
}

static void parse_proto(struct nfattr *attr, struct ctnl_tuple *tuple)
{
	struct nfattr *tb[CTA_PROTO_MAX];
	struct ctproto_handler *h;
	int dir = CTNL_DIR_REPLY;

	memset(tb, 0, CTA_PROTO_MAX * sizeof(struct nfattr *));

	nfnl_parse_nested(tb, CTA_IP_MAX, attr);
	if (tb[CTA_PROTO_NUM-1])
		tuple->protonum = *(u_int8_t *)NFA_DATA(tb[CTA_PROTO_NUM-1]);
	
	h = findproto(proto2str[tuple->protonum]);
	if (h && h->parse_proto)
		h->parse_proto(tb, tuple);
}

static void parse_tuple(struct nfattr *attr, struct ctnl_tuple *tuple)
{
	struct nfattr *tb[CTA_TUPLE_MAX];

	memset(tb, 0, CTA_TUPLE_MAX*sizeof(struct nfattr *));

	nfnl_parse_nested(tb, CTA_TUPLE_MAX, attr);
	if (tb[CTA_TUPLE_IP-1])
		parse_ip(tb[CTA_TUPLE_IP-1], tuple);
	if (tb[CTA_TUPLE_PROTO-1])
		parse_proto(tb[CTA_TUPLE_PROTO-1], tuple);
}

static void parse_protoinfo(struct nfattr *attr, struct ctnl_conntrack *ct)
{
	struct nfattr *tb[CTA_PROTOINFO_MAX];
	struct ctproto_handler *h;

	memset(tb, 0, CTA_PROTOINFO_MAX*sizeof(struct nfattr *));

	nfnl_parse_nested(tb,CTA_PROTOINFO_MAX, attr);

	h = findproto(proto2str[ct->tuple[CTNL_DIR_ORIGINAL].protonum]);
        if (h && h->parse_protoinfo)
		h->parse_protoinfo(tb, ct);
}
	
static void parse_counters(struct nfattr *attr, struct ctnl_conntrack *ct,
			   enum ctattr_type parent)
{
	struct nfattr *tb[CTA_COUNTERS_MAX];

	memset(tb, 0, CTA_COUNTERS_MAX*sizeof(struct nfattr *));

	nfnl_parse_nested(tb, CTA_COUNTERS_MAX, attr);
	if (tb[CTA_COUNTERS_PACKETS-1])
		ct->counters[CTNL_DIR_ORIGINAL].packets
		      = *(u_int64_t *)NFA_DATA(tb[CTA_COUNTERS_PACKETS-1]);
	if (tb[CTA_COUNTERS_BYTES-1])
		ct->counters[CTNL_DIR_ORIGINAL].bytes
		      = *(u_int64_t *)NFA_DATA(tb[CTA_COUNTERS_BYTES-1]);
}

/* Some people seem to like counting in decimal... */
#define STATUS		1
#define PROTOINFO 	2
#define TIMEOUT		4
#define MARK		8
#define COUNTERS	16
#define USE		32
#define ID		64

static int handler(struct sockaddr_nl *sock, struct nlmsghdr *nlh, void *arg)
{
	struct nfgenmsg *nfmsg;
	struct nfattr *nfa;
	int min_len = sizeof(struct nfgenmsg);;
	struct ctproto_handler *h = NULL;
	struct nfattr *attr = NFM_NFA(NLMSG_DATA(nlh));
	int attrlen = nlh->nlmsg_len - NLMSG_ALIGN(min_len);
	struct ctnl_conntrack ct;
	unsigned int flags = 0;

	memset(&ct, 0, sizeof(struct ctnl_conntrack));

	nfmsg = NLMSG_DATA(nlh);
//	min_len = sizeof(struct nfgenmsg);

	if (nlh->nlmsg_len < min_len)
		return -EINVAL;

	while (NFA_OK(attr, attrlen)) {
		switch(attr->nfa_type) {
		case CTA_TUPLE_ORIG:
			parse_tuple(attr, &ct.tuple[CTNL_DIR_ORIGINAL]);
			break;
		case CTA_TUPLE_REPLY:
			parse_tuple(attr, &ct.tuple[CTNL_DIR_REPLY]);
			break;
		case CTA_STATUS:
			ct.status = *(unsigned int *)NFA_DATA(attr);
			flags |= STATUS;
			break;
		case CTA_PROTOINFO:
			parse_protoinfo(attr, &ct);
			flags |= PROTOINFO;
			break;
		case CTA_TIMEOUT:
			ct.timeout = *(unsigned long *)NFA_DATA(attr);
			flags |= TIMEOUT;
			break;
		case CTA_MARK:
			ct.mark = *(unsigned long *)NFA_DATA(attr);
			flags |= MARK;
			break;
		case CTA_COUNTERS_ORIG:
		case CTA_COUNTERS_REPLY:
			parse_counters(attr, &ct, attr->nfa_type-1);
			flags |= COUNTERS;
			break;
		case CTA_USE:
			ct.use = *(unsigned int *)NFA_DATA(attr);
			flags |= USE;
			break;
		case CTA_ID:
			ct.id = *(u_int32_t *)NFA_DATA(attr);
			flags |= ID;
			break;
		}
		attr = NFA_NEXT(attr, attrlen);
	}

	fprintf(stdout, "%-8s %u ", 
		proto2str[ct.tuple[CTNL_DIR_ORIGINAL].protonum] == NULL ?
		"unknown" : proto2str[ct.tuple[CTNL_DIR_ORIGINAL].protonum], 
		ct.tuple[CTNL_DIR_ORIGINAL].protonum);

	if (flags & TIMEOUT)
		fprintf(stdout, "%lu ", ct.timeout);

        h = findproto(proto2str[ct.tuple[CTNL_DIR_ORIGINAL].protonum]);
        if ((flags & PROTOINFO) && h && h->print_protoinfo)
                h->print_protoinfo(&ct.protoinfo);

	fprintf(stdout, "src=%u.%u.%u.%u dst=%u.%u.%u.%u ",
		NIPQUAD(ct.tuple[CTNL_DIR_ORIGINAL].src.v4),
		NIPQUAD(ct.tuple[CTNL_DIR_ORIGINAL].dst.v4));

	if (h && h->print_proto)
		h->print_proto(&ct.tuple[CTNL_DIR_ORIGINAL]);

	if (flags & COUNTERS)
		fprintf(stdout, "packets=%llu bytes=%llu ",
			ct.counters[CTNL_DIR_ORIGINAL].packets,
			ct.counters[CTNL_DIR_ORIGINAL].bytes);

        fprintf(stdout, "src=%u.%u.%u.%u dst=%u.%u.%u.%u ",
		NIPQUAD(ct.tuple[CTNL_DIR_REPLY].src.v4),
		NIPQUAD(ct.tuple[CTNL_DIR_REPLY].dst.v4));

        h = findproto(proto2str[ct.tuple[CTNL_DIR_ORIGINAL].protonum]);
	if (h && h->print_proto)
		h->print_proto(&ct.tuple[CTNL_DIR_REPLY]);

	if (flags & COUNTERS)
		fprintf(stdout, "packets=%llu bytes=%llu ",
			ct.counters[CTNL_DIR_REPLY].packets,
			ct.counters[CTNL_DIR_REPLY].bytes);
	
	print_status(ct.status);

	if (flags & MARK)
		fprintf(stdout, "mark=%lu ", ct.mark);
	if (flags & USE)
		fprintf(stdout, "use=%u ", ct.use);
	if (flags & ID)
		fprintf(stdout, "id=%u ", ct.id);

	fprintf(stdout, "\n");

	return 0;
}

static char *typemsg2str(type, flags)
{
	char *ret = "UNKNOWN";

	if (type == IPCTNL_MSG_CT_NEW) {
		if (flags & NLM_F_CREATE)
			ret = "NEW";
		else
			ret = "UPDATE";
	} else if (type == IPCTNL_MSG_CT_DELETE)
		ret = "DESTROY";

	return ret;
}

static int event_handler(struct sockaddr_nl *sock, struct nlmsghdr *nlh, 
			 void *arg)
{
	int type = NFNL_MSG_TYPE(nlh->nlmsg_type);
	fprintf(stdout, "[%s] ", typemsg2str(type, nlh->nlmsg_flags));
	return handler(sock, nlh, arg);
}

void parse_expect(struct nfattr *attr, struct ctnl_tuple *tuple, 
		  struct ctnl_tuple *mask, unsigned long *timeout,
		  u_int32_t *id)
{
	struct nfattr *tb[CTA_EXPECT_MAX];

	memset(tb, 0, CTA_EXPECT_MAX*sizeof(struct nfattr *));

	nfnl_parse_nested(tb, CTA_EXPECT_MAX, attr);
	if (tb[CTA_EXPECT_TUPLE-1])
		parse_tuple(tb[CTA_EXPECT_TUPLE-1], tuple);
	if (tb[CTA_EXPECT_MASK-1])
		parse_tuple(tb[CTA_EXPECT_MASK-1], mask);
	if (tb[CTA_EXPECT_TIMEOUT-1])
		*timeout = *(unsigned long *)NFA_DATA(tb[CTA_EXPECT_TIMEOUT-1]);
	if (tb[CTA_EXPECT_ID-1])
		*id = *(u_int32_t *)NFA_DATA(tb[CTA_EXPECT_ID-1]);
}

static int expect_handler(struct sockaddr_nl *sock, struct nlmsghdr *nlh, void *arg)
{
	struct nfgenmsg *nfmsg;
	struct nfattr *nfa;
	int min_len = sizeof(struct nfgenmsg);;
	struct ctproto_handler *h = NULL;
	struct nfattr *attr = NFM_NFA(NLMSG_DATA(nlh));
	int attrlen = nlh->nlmsg_len - NLMSG_ALIGN(min_len);
	struct ctnl_tuple tuple, mask;
	unsigned long timeout = 0;
	u_int32_t id = 0;
	unsigned int flags;

	memset(&tuple, 0, sizeof(struct ctnl_tuple));
	memset(&mask, 0, sizeof(struct ctnl_tuple));

	nfmsg = NLMSG_DATA(nlh);

	if (nlh->nlmsg_len < min_len)
		return -EINVAL;

	while (NFA_OK(attr, attrlen)) {
		switch(attr->nfa_type) {
			case CTA_EXPECT:
				parse_expect(attr, &tuple, &mask, &timeout,
					     &id);
				break;
		}
		attr = NFA_NEXT(attr, attrlen);
	}
	fprintf(stdout, "%ld proto=%d ", timeout, tuple.protonum);

        fprintf(stdout, "src=%u.%u.%u.%u dst=%u.%u.%u.%u ",
		NIPQUAD(tuple.src.v4),
		NIPQUAD(tuple.dst.v4));

	fprintf(stdout, "src=%u.%u.%u.%u dst=%u.%u.%u.%u ",
		NIPQUAD(mask.src.v4),
		NIPQUAD(mask.dst.v4));

	fprintf(stdout, "id=0x%x ", id);
	
	fputc('\n', stdout);

	return 0;
}

int create_conntrack(struct ctnl_tuple *orig,
		     struct ctnl_tuple *reply,
		     unsigned long timeout,
		     union ctnl_protoinfo *proto,
		     unsigned int status,
		     struct ctnl_nat *range)
{
	struct ctnl_conntrack ct;
	int ret;

	memset(&ct, 0, sizeof(struct ctnl_conntrack));
	ct.tuple[CTNL_DIR_ORIGINAL] = *orig;
	ct.tuple[CTNL_DIR_REPLY] = *reply;
	ct.timeout = timeout;
	ct.status = status;
	ct.protoinfo = *proto;
	if (range)
		ct.nat = *range;
	
	if ((ret = ctnl_open(&cth, 0)) < 0)
		return ret;

	ret = ctnl_new_conntrack(&cth, &ct);

	ctnl_close(&cth);
	
	return ret;
}

int update_conntrack(struct ctnl_tuple *orig,
		     struct ctnl_tuple *reply,
		     unsigned long timeout,
		     union ctnl_protoinfo *proto,
		     unsigned int status)
{
	struct ctnl_conntrack ct;
	int ret;

	memset(&ct, 0, sizeof(struct ctnl_conntrack));
	ct.tuple[CTNL_DIR_ORIGINAL] = *orig;
	ct.tuple[CTNL_DIR_REPLY] = *reply;
	ct.timeout = timeout;
	ct.status = status;
	ct.protoinfo = *proto;
	
	if ((ret = ctnl_open(&cth, 0)) < 0)
		return ret;

	ret = ctnl_upd_conntrack(&cth, &ct);

	ctnl_close(&cth);
	
	return ret;
}

int delete_conntrack(struct ctnl_tuple *tuple, int dir)
{
	int ret;

	if ((ret = ctnl_open(&cth, 0)) < 0)
		return ret;

	ret = ctnl_del_conntrack(&cth, tuple, dir);
	ctnl_close(&cth);

	return ret;
}

/* get_conntrack_handler */
int get_conntrack(struct ctnl_tuple *tuple, int dir)
{
	struct ctnl_msg_handler h = {
		.type = 0,
		.handler = handler
	};
	int ret;

	if ((ret = ctnl_open(&cth, 0)) < 0)
		return ret;

	ctnl_register_handler(&cth, &h);

	ret = ctnl_get_conntrack(&cth, tuple, dir);
	ctnl_close(&cth);

	return ret;
}

int dump_conntrack_table(int zero)
{
	int ret;
	struct ctnl_msg_handler h = {
		.type = IPCTNL_MSG_CT_NEW, /* Hm... really? */
		.handler = handler
	};
	
	if ((ret = ctnl_open(&cth, 0)) < 0) 
		return ret;

	ctnl_register_handler(&cth, &h);

	if (zero) {
		ret = ctnl_list_conntrack_zero_counters(&cth, AF_INET);
	} else
		ret = ctnl_list_conntrack(&cth, AF_INET);

	ctnl_close(&cth);

	return ret;
}

static void event_sighandler(int s)
{
	fprintf(stdout, "Now closing conntrack event dumping...\n");
	ctnl_close(&cth);
}

int event_conntrack(unsigned int event_mask)
{
	struct ctnl_msg_handler hnew = {
		.type = IPCTNL_MSG_CT_NEW,
		.handler = event_handler
	};
	struct ctnl_msg_handler hdestroy = {
		.type = IPCTNL_MSG_CT_DELETE,
		.handler = event_handler
	};
	int ret;

	if ((ret = ctnl_open(&cth, event_mask)) < 0)
		return ret;

	signal(SIGINT, event_sighandler);
	ctnl_register_handler(&cth, &hnew);
	ctnl_register_handler(&cth, &hdestroy);
	ret = ctnl_event_conntrack(&cth, AF_INET);
	ctnl_close(&cth);

	return 0;
}

struct ctproto_handler *findproto(char *name)
{
	void *h = NULL;
	struct list_head *i;
	struct ctproto_handler *cur = NULL, *handler = NULL;

	if (!name) 
		return handler;

	lib_dir = getenv("CONNTRACK_LIB_DIR");
	if (!lib_dir)
		lib_dir = CONNTRACK_LIB_DIR;

	list_for_each(i, &proto_list) {
		cur = (struct ctproto_handler *) i;
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
			DEBUGP(stderr, "%s\n", dlerror());
	}

	return handler;
}

void register_proto(struct ctproto_handler *h)
{
	list_add(&h->head, &proto_list);
}

void unregister_proto(struct ctproto_handler *h)
{
	list_del(&h->head);
}

int dump_expect_list()
{
	struct ctnl_msg_handler h = {
		.type = IPCTNL_MSG_EXP_NEW,
		.handler = expect_handler
	};
	int ret;
	
	if ((ret = ctnl_open(&cth, 0)) < 0)
		return ret;

	ctnl_register_handler(&cth, &h);

	ret = ctnl_list_expect(&cth, AF_INET);
	ctnl_close(&cth);
	
	return ret;
}

int flush_conntrack()
{
	int ret;
	
	if ((ret = ctnl_open(&cth, 0)) < 0)
		return ret;

	ret = ctnl_flush_conntrack(&cth);
	ctnl_close(&cth);

	return ret;
}

int get_expect(struct ctnl_tuple *tuple,
	       enum ctattr_type t)
{
	/*
	struct ctnl_msg_handler h = {
		.type = IPCTNL_MSG_EXP_NEW,
		.handler = expect_handler
	};
	int ret;

	if ((ret = ctnl_open(&cth, 0)) < 0)
		return 0;

	ctnl_register_handler(&cth, &h);

	ret = ctnl_get_expect(&cth, tuple, t);
	ctnl_close(&cth);

	return ret;
	*/
}

int create_expectation(struct ctnl_tuple *tuple,
		       enum ctattr_type t,
		       struct ctnl_tuple *exptuple,
		       struct ctnl_tuple *mask,
		       unsigned long timeout)
{
	/*
	int ret;
	
	if ((ret = ctnl_open(&cth, 0)) < 0)
		return ret;

	ret = ctnl_new_expect(&cth, tuple, t, exptuple, mask, timeout);
	ctnl_close(&cth);

	return ret;
	*/
}

int delete_expectation(struct ctnl_tuple *tuple, enum ctattr_type t)
{
	/*
	int ret;
	
	if ((ret = ctnl_open(&cth, 0)) < 0)
		return ret;

	ret = ctnl_del_expect(&cth, tuple, t);
	ctnl_close(&cth);

	return ret;
	*/
}

int event_expectation(unsigned int event_mask)
{
	struct ctnl_msg_handler hnew = {
		.type = IPCTNL_MSG_EXP_NEW,
		.handler = expect_handler
	};
	struct ctnl_msg_handler hdestroy = {
		.type = IPCTNL_MSG_EXP_DELETE,
		.handler = expect_handler
	};
	int ret;
	
	if ((ret = ctnl_open(&cth, event_mask)) < 0)
		return ret;

	ctnl_register_handler(&cth, &hnew);
	ctnl_register_handler(&cth, &hdestroy);
	ret = ctnl_event_expect(&cth, AF_INET);
	ctnl_close(&cth);

	return ret;
}

int flush_expectation()
{
	int ret;
	
	if ((ret = ctnl_open(&cth, 0)) < 0)
		return ret;

	ret = ctnl_flush_expect(&cth);
	ctnl_close(&cth);

	return ret;
}

