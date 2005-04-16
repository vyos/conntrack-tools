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

extern struct list_head proto_list;
extern char *proto2str[];

/* Built-in generic proto handler */

/* FIXME: This should die... */
static int parse(char c, char *argv[], 
	   struct ip_conntrack_tuple *orig,
	   struct ip_conntrack_tuple *reply) {
	return 0;
}
/* FIXME: die die too... */
static void print(struct ip_conntrack_tuple *t) {}

static struct ctproto_handler generic_handler = {
	.name 		= "generic",
	.protonum	= 0,
	.parse		= parse,
	.print		= print,
	.opts		= NULL
};

static int handler(struct sockaddr_nl *sock, struct nlmsghdr *nlh, void *arg)
{
	struct nfgenmsg *nfmsg;
	struct nfattr *nfa;
	int min_len = 0;
	struct ctproto_handler *h = NULL;

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

	while (nlh->nlmsg_len > min_len) {
		struct nfattr *attr = NFM_NFA(NLMSG_DATA(nlh));
		int attrlen = nlh->nlmsg_len - NLMSG_ALIGN(min_len);

		struct ip_conntrack_tuple *orig, *reply;
		unsigned long *status, *timeout;
		struct cta_proto *proto;
		unsigned long *id;

		while (NFA_OK(attr, attrlen)) {
			switch(attr->nfa_type) {
			case CTA_ORIG:
				orig = NFA_DATA(attr);
				printf("src=%u.%u.%u.%u dst=%u.%u.%u.%u ", 
						NIPQUAD(orig->src.ip), 
						NIPQUAD(orig->dst.ip));
				h = findproto(proto2str[orig->dst.protonum]);
				if (h)
					h->print(orig);
				break;
			case CTA_RPLY:
				reply = NFA_DATA(attr);
				printf("src=%u.%u.%u.%u dst=%u.%u.%u.%u ",
						NIPQUAD(reply->src.ip), 
						NIPQUAD(reply->dst.ip));
				h = findproto(proto2str[reply->dst.protonum]);
				if (h)
					h->print(reply);	
				break;
			case CTA_STATUS:
				status = NFA_DATA(attr);
				printf("status:%u ", *status);
				break;
			case CTA_PROTOINFO:
				proto = NFA_DATA(attr);
				if (proto2str[proto->num_proto])
					printf("%s %d", proto2str[proto->num_proto], proto->num_proto);
				else
					printf("unknown %d ", proto->num_proto);
				break;
			case CTA_TIMEOUT:
				timeout = NFA_DATA(attr);
				printf("timeout:%lu ", *timeout);
				break;
/*			case CTA_ID:
				id = NFA_DATA(attr);
				printf(" id:%lu ", *id);
				break;*/
			}
			DEBUGP("nfa->nfa_type: %d\n", attr->nfa_type);
			DEBUGP("nfa->nfa_len: %d\n", attr->nfa_len);
			attr = NFA_NEXT(attr, attrlen);
		}
		min_len += nlh->nlmsg_len;
		nlh = (struct nlmsghdr *) attr;
		printf("\n");
	}
	DEBUGP("exit from handler\n");

	return 0;
}

/* FIXME: use event messages better */
static char *typemsg2str[] = {
	"NEW",
	"GET", 
	"DESTROY"
};

static int event_handler(struct sockaddr_nl *sock, struct nlmsghdr *nlh, 
			 void *arg)
{
	struct nfgenmsg *nfmsg;
	struct nfattr *nfa;
	int min_len = 0;
	struct ctproto_handler *h = NULL;
	int type = NFNL_MSG_TYPE(nlh->nlmsg_type);

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

	printf("type: [%s] ", typemsg2str[type]);

	while (nlh->nlmsg_len > min_len) {
		struct nfattr *attr = NFM_NFA(NLMSG_DATA(nlh));
		int attrlen = nlh->nlmsg_len - NLMSG_ALIGN(min_len);

		struct ip_conntrack_tuple *orig, *reply;
		unsigned long *status, *timeout;
		struct cta_proto *proto;
		unsigned long *id;

		while (NFA_OK(attr, attrlen)) {
			switch(attr->nfa_type) {
			case CTA_ORIG:
				orig = NFA_DATA(attr);
				printf("src=%u.%u.%u.%u dst=%u.%u.%u.%u ", 
						NIPQUAD(orig->src.ip), 
						NIPQUAD(orig->dst.ip));
				h = findproto(proto2str[orig->dst.protonum]);
				if (h)
					h->print(orig);
				break;
			case CTA_RPLY:
				reply = NFA_DATA(attr);
				printf("src=%u.%u.%u.%u dst=%u.%u.%u.%u ",
						NIPQUAD(reply->src.ip), 
						NIPQUAD(reply->dst.ip));
				h = findproto(proto2str[reply->dst.protonum]);
				if (h)
					h->print(reply);	
				break;
			case CTA_STATUS:
				status = NFA_DATA(attr);
				printf("status:%u ", *status);
				break;
			case CTA_PROTOINFO:
				proto = NFA_DATA(attr);
				if (proto2str[proto->num_proto])
					printf("%s %d", proto2str[proto->num_proto], proto->num_proto);
				else
					printf("unknown %d ", proto->num_proto);
				break;
			case CTA_TIMEOUT:
				timeout = NFA_DATA(attr);
				printf("timeout:%lu ", *timeout);
				break;
/*			case CTA_ID:
				id = NFA_DATA(attr);
				printf(" id:%lu ", *id);
				break;*/
			}
			DEBUGP("nfa->nfa_type: %d\n", attr->nfa_type);
			DEBUGP("nfa->nfa_len: %d\n", attr->nfa_len);
			attr = NFA_NEXT(attr, attrlen);
		}
		min_len += nlh->nlmsg_len;
		nlh = (struct nlmsghdr *) attr;
		printf("\n");
	}
	DEBUGP("exit from handler\n");

	return 0;
}

static int expect_handler(struct sockaddr_nl *sock, struct nlmsghdr *nlh, void *arg)
{
	struct nfgenmsg *nfmsg;
	struct nfattr *nfa;
	int min_len = 0;
	struct ctproto_handler *h = NULL;

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

	while (nlh->nlmsg_len > min_len) {
		struct nfattr *attr = NFM_NFA(NLMSG_DATA(nlh));
		int attrlen = nlh->nlmsg_len - NLMSG_ALIGN(min_len);

		struct ip_conntrack_tuple *exp, *mask;
		unsigned long *timeout;

		while (NFA_OK(attr, attrlen)) {
			switch(attr->nfa_type) {
			case CTA_EXP_TUPLE:
				exp = NFA_DATA(attr);
				printf("src=%u.%u.%u.%u dst=%u.%u.%u.%u ", 
						NIPQUAD(exp->src.ip), 
						NIPQUAD(exp->dst.ip));
				h = findproto(proto2str[exp->dst.protonum]);
				if (h)
					h->print(exp);
				break;
			case CTA_EXP_MASK:
				mask = NFA_DATA(attr);
				printf("src=%u.%u.%u.%u dst=%u.%u.%u.%u ",
						NIPQUAD(mask->src.ip), 
						NIPQUAD(mask->dst.ip));
				h = findproto(proto2str[mask->dst.protonum]);
				if (h)
					h->print(mask);	
				break;
			case CTA_EXP_TIMEOUT:
				timeout = NFA_DATA(attr);
				printf("timeout:%lu ", *timeout);
				break;
			}
			DEBUGP("nfa->nfa_type: %d\n", attr->nfa_type);
			DEBUGP("nfa->nfa_len: %d\n", attr->nfa_len);
			attr = NFA_NEXT(attr, attrlen);
		}
		min_len += nlh->nlmsg_len;
		nlh = (struct nlmsghdr *) attr;
		printf("\n");
	}
	DEBUGP("exit from handler\n");

	return 0;
}

void create_conntrack(struct ip_conntrack_tuple *orig,
		      struct ip_conntrack_tuple *reply,
		      unsigned long timeout,
		      union ip_conntrack_proto *proto,
		      unsigned int status)
{
	struct cta_proto cta;
	struct nfattr *cda[CTA_MAX];
	struct ctnl_handle cth;
	
	cta.num_proto = orig->dst.protonum;
	memcpy(&cta.proto, proto, sizeof(*proto));
	if (ctnl_open(&cth, 0) < 0) {
		printf("error\n");
		exit(0);
	}

	/* FIXME: please unify returns values... */
	if (ctnl_new_conntrack(&cth, orig, reply, timeout, proto, status) < 0) {
		printf("error new conntrack\n");
		exit(0);
	}

	if (ctnl_close(&cth) < 0) {
		printf("error2");
		exit(0);
	}
}

void delete_conntrack(struct ip_conntrack_tuple *tuple,
		      enum ctattr_type_t t,
		      unsigned long id)
{
	struct nfattr *cda[CTA_MAX];
	struct ctnl_handle cth;

	if (ctnl_open(&cth, 0) < 0) {
		printf("error\n");
		exit(0);
	}

	/* FIXME: please unify returns values... */
	if (ctnl_del_conntrack(&cth, tuple, t, id) < 0) {
		printf("error del conntrack\n");
		exit(0);
	}

	if (ctnl_close(&cth) < 0) {
		printf("error2");
		exit(0);
	}
}

/* get_conntrack_handler */
void get_conntrack(struct ip_conntrack_tuple *tuple, 
		   enum ctattr_type_t t,
		   unsigned long id)
{
	struct nfattr *cda[CTA_MAX];
	struct ctnl_handle cth;
	struct ctnl_msg_handler h = {
		.type = 0,
		.handler = handler
	};

	if (ctnl_open(&cth, 0) < 0) {
		printf("error\n");
		exit(0);
	}

	ctnl_register_handler(&cth, &h);

	/* FIXME!!!! get_conntrack_handler returns -100 */
	if (ctnl_get_conntrack(&cth, tuple, t, id) != -100) {
		printf("error get conntrack\n");
		exit(0);
	}

	if (ctnl_close(&cth) < 0) {
		printf("error2");
		exit(0);
	}
}

void dump_conntrack_table()
{
	struct ctnl_handle cth;
	struct ctnl_msg_handler h = {
		.type = 0, /* Hm... really? */
		.handler = handler
	};
	
	if (ctnl_open(&cth, 0) < 0) {
		printf("error\n");
		exit(0);
	}

	ctnl_register_handler(&cth, &h);

	if (ctnl_list_conntrack(&cth, AF_INET) != -100) {
		printf("error list\n");
		exit(0);
	}

	if (ctnl_close(&cth) < 0) {
		printf("error2\n");
		exit(0);
	}
}

void event_conntrack()
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
	
	if (ctnl_open(&cth, NFGRP_IPV4_CT_TCP) < 0) {
		printf("error\n");
		exit(0);
	}

	ctnl_register_handler(&cth, &hnew);
	ctnl_register_handler(&cth, &hdestroy);
	ctnl_event_conntrack(&cth, AF_INET);

	if (ctnl_close(&cth) < 0) {
		printf("error2\n");
		exit(0);
	}
}

struct ctproto_handler *findproto(char *name)
{
	void *h = NULL;
	struct list_head *i;
	struct ctproto_handler *cur = NULL, *handler = NULL;

	list_for_each(i, &proto_list) {
		cur = (struct ctproto_handler *) i;
		if (strcmp(cur->name, name) == 0) {
			handler = cur;
			break;
		}
	}

	if (!handler) {
		char path[sizeof("extensions/libct_proto_.so")
			 + strlen(name)];
                sprintf(path, "extensions/libct_proto_%s.so", name);
		if (dlopen(path, RTLD_NOW))
			handler = findproto(name);
/*		else
			fprintf (stderr, "%s\n", dlerror());*/
	}

	if (!handler)
		handler = &generic_handler;

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

void dump_expect_list()
{
	struct ctnl_handle cth;
	struct ctnl_msg_handler h = {
		.type = 0, /* Hm... really? */
		.handler = expect_handler
	};
	
	if (ctnl_open(&cth, 0) < 0) {
		printf("error\n");
		exit(0);
	}

	ctnl_register_handler(&cth, &h);

	if (ctnl_list_expect(&cth, AF_INET) != -100) {
		printf("error list\n");
		exit(0);
	}

	if (ctnl_close(&cth) < 0) {
		printf("error2\n");
		exit(0);
	}
}

