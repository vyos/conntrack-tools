/* libctnetlink.h: Header file for the Connection Tracking library.
 *
 * Jay Schulist <jschlst@samba.org>, Copyright (c) 2001.
 * (C) 2002 by Harald Welte <laforge@gnumonks.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#ifndef __LIBCTNETLINK_H
#define __LIBCTNETLINK_H

#include <netinet/in.h>
#include <asm/types.h>
#include <linux/if.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include <linux/netfilter_ipv4/ip_conntrack_netlink.h> 
#include "libnfnetlink.h"

#define CTNL_BUFFSIZE	8192

struct ctnl_msg_handler {
	int type;
	int (*handler)(struct sockaddr_nl *, struct nlmsghdr *, void *arg);
};

struct ctnl_handle {
	struct nfnl_handle nfnlh;
	struct ctnl_msg_handler *handler[IPCTNL_MSG_COUNT];
};

extern int ctnl_open(struct ctnl_handle *cth, unsigned subscriptions);
extern int ctnl_close(struct ctnl_handle *cth);
extern int ctnl_unregister_handler(struct ctnl_handle *cth, int type);
extern int ctnl_register_handler(struct ctnl_handle *cth, 
				 struct ctnl_msg_handler *hndlr);
extern int ctnl_get_conntrack(struct ctnl_handle *cth,
			      struct ip_conntrack_tuple *tuple,
			      enum ctattr_type_t t,
			      unsigned long id);
extern int ctnl_del_conntrack(struct ctnl_handle *cth,
			      struct ip_conntrack_tuple *tuple,
			      enum ctattr_type_t t,
			      unsigned long id);
extern int ctnl_list_conntrack(struct ctnl_handle *cth, int family);

extern int ctnl_list_expect(struct ctnl_handle *cth, int family);
extern int ctnl_del_expect(struct ctnl_handle *cth,
			   struct ip_conntrack_tuple *t);

#if 0
extern int ctnl_listen(struct ctnl_handle *ctnl,
        int (*handler)(struct sockaddr_nl *, struct nlmsghdr *n, void *),
        void *jarg);
extern int ctnl_talk(struct ctnl_handle *ctnl, struct nlmsghdr *n, pid_t peer,
        unsigned groups, struct nlmsghdr *answer,
        int (*junk)(struct sockaddr_nl *, struct nlmsghdr *n, void *),
	void *jarg);
extern int ctnl_dump_request(struct ctnl_handle *cth, int type, void *req, 
	int len);
extern int ctnl_dump_filter(struct ctnl_handle *cth,
        int (*filter)(struct sockaddr_nl *, struct nlmsghdr *n, void *),
        void *arg1,
        int (*junk)(struct sockaddr_nl *,struct nlmsghdr *n, void *),
        void *arg2);
#endif

extern int ctnl_send(struct ctnl_handle *cth, struct nlmsghdr *n);
extern int ctnl_wilddump_request(struct ctnl_handle *cth, int family, int type);

#endif	/* __LIBCTNETLINK_H */
