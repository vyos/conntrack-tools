/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@eurodev.net>,
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
#include <errno.h>
#include <linux/netfilter_ipv4/ip_conntrack_tuple.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include "libctnetlink.h"
#include "libnfnetlink.h"
#include "linux_list.h"
#include "libct_proto.h"

#if 0
#define DEBUGP printf
#else
#define DEBUGP
#endif

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

static int handler(struct sockaddr_nl *sock, struct nlmsghdr *nlh, void *arg)
{
	struct nfgenmsg *nfmsg;
	struct nfattr *nfa;
	int min_len = 0;
	struct ctproto_handler *h = NULL;
	struct nfattr *attr = NFM_NFA(NLMSG_DATA(nlh));
	int attrlen = nlh->nlmsg_len - NLMSG_ALIGN(min_len);

	struct ip_conntrack_tuple *orig, *reply;
	struct cta_counters *ctr;
	unsigned long *status, *timeout;
	struct cta_proto *proto;
	unsigned long *id, *mark;

	DEBUGP("netlink header\n");
	DEBUGP("len: %d type: %d flags: %d seq: %d pid: %d\n", 
		nlh->nlmsg_len, nlh->nlmsg_type, nlh->nlmsg_flags, 
		nlh->nlmsg_seq, nlh->nlmsg_pid);

	nfmsg = NLMSG_DATA(nlh);
	DEBUGP("nfmsg->nfgen_family: %d\n", nfmsg->nfgen_family);

	min_len = sizeof(struct nfgenmsg);
	if (nlh->nlmsg_len < min_len)
		return -EINVAL;

	DEBUGP("size:%d\n", nlh->nlmsg_len);

	while (NFA_OK(attr, attrlen)) {
		switch(attr->nfa_type) {
		case CTA_ORIG:
			orig = NFA_DATA(attr);
			fprintf(stdout, "src=%u.%u.%u.%u dst=%u.%u.%u.%u ", 
					NIPQUAD(orig->src.ip), 
					NIPQUAD(orig->dst.ip));
			h = findproto(proto2str[orig->dst.protonum]);
			if (h && h->print_tuple)
				h->print_tuple(orig);
			break;
		case CTA_RPLY:
			reply = NFA_DATA(attr);
			fprintf(stdout, "src=%u.%u.%u.%u dst=%u.%u.%u.%u ",
					NIPQUAD(reply->src.ip), 
					NIPQUAD(reply->dst.ip));
			h = findproto(proto2str[reply->dst.protonum]);
			if (h && h->print_tuple)
				h->print_tuple(reply);	
			break;
		case CTA_STATUS:
			status = NFA_DATA(attr);
			print_status(*status);
			break;
		case CTA_PROTOINFO:
			proto = NFA_DATA(attr);
			if (proto2str[proto->num_proto]) {
				fprintf(stdout, "%s %d ", proto2str[proto->num_proto], proto->num_proto);
				h = findproto(proto2str[proto->num_proto]);
				if (h && h->print_proto)
					h->print_proto(&proto->proto);
			} else
				fprintf(stdout, "unknown %d ", proto->num_proto);
			break;
		case CTA_TIMEOUT:
			timeout = NFA_DATA(attr);
			fprintf(stdout, "timeout=%lu ", *timeout);
			break;
		case CTA_MARK:
			mark = NFA_DATA(attr);
			fprintf(stdout, "mark=%lu ", *mark);
			break;
		case CTA_COUNTERS:
			ctr = NFA_DATA(attr);
			fprintf(stdout, "orig_packets=%llu orig_bytes=%llu, "
			       "reply_packets=%llu reply_bytes=%llu ",
			       ctr->orig.packets, ctr->orig.bytes,
			       ctr->reply.packets, ctr->reply.bytes);
			break;
		}
		DEBUGP("nfa->nfa_type: %d\n", attr->nfa_type);
		DEBUGP("nfa->nfa_len: %d\n", attr->nfa_len);
		attr = NFA_NEXT(attr, attrlen);
	}
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

static int expect_handler(struct sockaddr_nl *sock, struct nlmsghdr *nlh, void *arg)
{
	struct nfgenmsg *nfmsg;
	struct nfattr *nfa;
	int min_len = 0;
	struct ctproto_handler *h = NULL;
	struct nfattr *attr = NFM_NFA(NLMSG_DATA(nlh));
	int attrlen = nlh->nlmsg_len - NLMSG_ALIGN(min_len);

	struct ip_conntrack_tuple *exp, *mask;
	unsigned long *timeout;

	DEBUGP("netlink header\n");
	DEBUGP("len: %d type: %d flags: %d seq: %d pid: %d\n", 
		nlh->nlmsg_len, nlh->nlmsg_type, nlh->nlmsg_flags, 
		nlh->nlmsg_seq, nlh->nlmsg_pid);

	nfmsg = NLMSG_DATA(nlh);
	DEBUGP("nfmsg->nfgen_family: %d\n", nfmsg->nfgen_family);

	min_len = sizeof(struct nfgenmsg);
	if (nlh->nlmsg_len < min_len)
		return -EINVAL;

	DEBUGP("size:%d\n", nlh->nlmsg_len);

	while (NFA_OK(attr, attrlen)) {
		switch(attr->nfa_type) {
		case CTA_EXP_TUPLE:
			exp = NFA_DATA(attr);
			fprintf(stdout, "src=%u.%u.%u.%u dst=%u.%u.%u.%u ", 
					NIPQUAD(exp->src.ip), 
					NIPQUAD(exp->dst.ip));
			h = findproto(proto2str[exp->dst.protonum]);
			if (h && h->print_tuple)
				h->print_tuple(exp);
			break;
		case CTA_EXP_MASK:
			mask = NFA_DATA(attr);
			fprintf(stdout, "src=%u.%u.%u.%u dst=%u.%u.%u.%u ",
					NIPQUAD(mask->src.ip), 
					NIPQUAD(mask->dst.ip));
			h = findproto(proto2str[mask->dst.protonum]);
			if (h && h->print_tuple)
				h->print_tuple(mask);	
			break;
		case CTA_EXP_TIMEOUT:
			timeout = NFA_DATA(attr);
			fprintf(stdout, "timeout:%lu ", *timeout);
			break;
		}
		DEBUGP("nfa->nfa_type: %d\n", attr->nfa_type);
		DEBUGP("nfa->nfa_len: %d\n", attr->nfa_len);
		attr = NFA_NEXT(attr, attrlen);
	}
	fprintf(stdout, "\n");

	return 0;
}

int create_conntrack(struct ip_conntrack_tuple *orig,
		     struct ip_conntrack_tuple *reply,
		     unsigned long timeout,
		     union ip_conntrack_proto *proto,
		     unsigned int status)
{
	struct cta_proto cta;
	struct nfattr *cda[CTA_MAX];
	struct ctnl_handle cth;
	int ret;
	
	cta.num_proto = orig->dst.protonum;
	memcpy(&cta.proto, proto, sizeof(*proto));
	if ((ret = ctnl_open(&cth, 0)) < 0)
		return ret;

	if ((ret = ctnl_new_conntrack(&cth, orig, reply, timeout, &cta, 
					status)) < 0)
		return ret;

	if ((ret = ctnl_close(&cth)) < 0)
		return ret;
	
	return 0;
}

int create_expect(struct ip_conntrack_tuple *tuple,
		  struct ip_conntrack_tuple *mask,
		  struct ip_conntrack_tuple *master_tuple_orig,
		  struct ip_conntrack_tuple *master_tuple_reply,
		  unsigned long timeout)
{
	struct ctnl_handle cth;
	int ret;

	if ((ret = ctnl_open(&cth, 0)) < 0)
		return ret;

	if ((ret = ctnl_new_expect(&cth, tuple, mask, master_tuple_orig,
				   master_tuple_reply, timeout)) < 0)
		return ret;

	if ((ret = ctnl_close(&cth)) < 0)
		return ret;

	return -1;
}

int delete_conntrack(struct ip_conntrack_tuple *tuple,
		     enum ctattr_type_t t)
{
	struct nfattr *cda[CTA_MAX];
	struct ctnl_handle cth;
	int ret;

	if ((ret = ctnl_open(&cth, 0)) < 0)
		return ret;

	if ((ret = ctnl_del_conntrack(&cth, tuple, t)) < 0)
		return ret;

	if ((ret = ctnl_close(&cth)) < 0)
		return ret;

	return 0;
}

/* get_conntrack_handler */
int get_conntrack(struct ip_conntrack_tuple *tuple, 
		  enum ctattr_type_t t,
		  unsigned long id)
{
	struct nfattr *cda[CTA_MAX];
	struct ctnl_handle cth;
	struct ctnl_msg_handler h = {
		.type = 0,
		.handler = handler
	};
	int ret;

	if ((ret = ctnl_open(&cth, 0)) < 0)
		return ret;

	ctnl_register_handler(&cth, &h);

	/* FIXME!!!! get_conntrack_handler returns -100 */
	if ((ret = ctnl_get_conntrack(&cth, tuple, t)) != -100)
		return ret;

	if ((ret = ctnl_close(&cth)) < 0)
		return ret;

	return 0;
}

int dump_conntrack_table(int zero)
{
	int ret;
	struct ctnl_handle cth;
	struct ctnl_msg_handler h = {
		.type = 0, /* Hm... really? */
		.handler = handler
	};
	
	if ((ret = ctnl_open(&cth, 0)) < 0) 
		return ret;

	ctnl_register_handler(&cth, &h);

	if (zero) {
		ret = ctnl_list_conntrack_zero_counters(&cth, AF_INET);
	} else
		ret = ctnl_list_conntrack(&cth, AF_INET);

	if (ret != -100)
		return ret;

	if ((ret = ctnl_close(&cth)) < 0)
		return ret;

	return 0;
}

int event_conntrack(unsigned int event_mask)
{
	struct ctnl_handle cth;
	struct ctnl_msg_handler hnew = {
		.type = 0, /* new */
		.handler = event_handler
	};
	struct ctnl_msg_handler hdestroy = {
		.type = 2, /* destroy */
		.handler = event_handler
	};
	int ret;
	
	if ((ret = ctnl_open(&cth, event_mask)) < 0)
		return ret;

	ctnl_register_handler(&cth, &hnew);
	ctnl_register_handler(&cth, &hdestroy);
	if ((ret = ctnl_event_conntrack(&cth, AF_INET)) < 0)
		return ret;

	if ((ret = ctnl_close(&cth)) < 0)
		return ret;

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
	struct ctnl_handle cth;
	struct ctnl_msg_handler h = {
		.type = 5, /* Hm... really? */
		.handler = expect_handler
	};
	int ret;
	
	if ((ret = ctnl_open(&cth, 0)) < 0)
		return ret;

	ctnl_register_handler(&cth, &h);

	if ((ret = ctnl_list_expect(&cth, AF_INET)) != -100)
		return ret;

	if ((ret = ctnl_close(&cth)) < 0)
		return ret;

	return 0;
}

int set_mask(unsigned int mask, int type)
{
	struct ctnl_handle cth;
	enum ctattr_type_t cta_type;
	int ret;

	switch(type) {
		case 0:
			cta_type = CTA_DUMPMASK;
			break;
		case 1:
			cta_type = CTA_EVENTMASK;
			break;
		default:
			/* Shouldn't happen */
			return -1;
	}

	if ((ret = ctnl_open(&cth, 0)) < 0)
		return ret;
	
	if ((ret = ctnl_set_mask(&cth, mask, cta_type)) < 0)
		return ret;
	
	if ((ret = ctnl_close(&cth)) < 0)
		return ret;

	return 0;
}

int flush_conntrack()
{
	struct ctnl_handle cth;
	int ret;
	
	if ((ret = ctnl_open(&cth, 0)) < 0)
		return ret;

	if ((ret = ctnl_flush_conntrack(&cth)) < 0)
		return ret;

	if ((ret = ctnl_close(&cth)) < 0)
		return ret;

	return 0;
}
