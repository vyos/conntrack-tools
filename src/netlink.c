/*
 * (C) 2006 by Pablo Neira Ayuso <pablo@netfilter.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "conntrackd.h"
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <errno.h>
#include "us-conntrack.h"
#include <signal.h>
#include <stdlib.h>
#include "network.h"

static int ignore_conntrack(struct nf_conntrack *ct)
{
	/* ignore a certain protocol */
	if (CONFIG(ignore_protocol)[nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO)])
		return 1;

	/* Accept DNAT'ed traffic: not really coming to the local machine */
	if ((CONFIG(flags) & STRIP_NAT) && 
	    nfct_getobjopt(ct, NFCT_GOPT_IS_DNAT)) {
		debug_ct(ct, "DNAT");
		return 0;
	}

        /* Accept SNAT'ed traffic: not really coming to the local machine */
	if ((CONFIG(flags) & STRIP_NAT) && 
	    nfct_getobjopt(ct, NFCT_GOPT_IS_SNAT)) {
		debug_ct(ct, "SNAT");
		return 0;
	}

	/* Ignore traffic */
	if (ignore_pool_test(STATE(ignore_pool), ct)) {
		debug_ct(ct, "ignore traffic");
		return 1;
	}

	return 0;
}

static int nl_event_handler(struct nlmsghdr *nlh,
			    struct nfattr *nfa[],
			    void *data)
{
	char tmp[1024];
	struct nf_conntrack *ct = (struct nf_conntrack *) tmp;
	int type;

	memset(tmp, 0, sizeof(tmp));

	if ((type = nfct_parse_conntrack(NFCT_T_ALL, nlh, ct)) == NFCT_T_ERROR)
		return NFCT_CB_STOP;

	/* 
	 * Ignore this conntrack: it talks about a
	 * connection that is not interesting for us.
	 */
	if (ignore_conntrack(ct))
		return NFCT_CB_STOP;

	switch(type) {
	case NFCT_T_NEW:
		STATE(mode)->event_new(ct, nlh);
		break;
	case NFCT_T_UPDATE:
		STATE(mode)->event_upd(ct, nlh);
		break;
	case NFCT_T_DESTROY:
		if (STATE(mode)->event_dst(ct, nlh))
			update_traffic_stats(ct);
		break;
	default:
		dlog(STATE(log), "received unknown msg from ctnetlink\n");
		break;
	}

	return NFCT_CB_STOP;
}

int nl_init_event_handler(void)
{
	struct nfnl_callback cb_events = {
		.call		= nl_event_handler,
		.attr_count	= CTA_MAX
	};

	/* open event netlink socket */
	STATE(event) = nfnl_open();
	if (!STATE(event))
		return -1;

	/* set up socket buffer size */
	if (CONFIG(netlink_buffer_size))
		nfnl_rcvbufsiz(STATE(event), CONFIG(netlink_buffer_size));
	else {
		socklen_t socklen = sizeof(unsigned int);
		unsigned int read_size;

		/* get current buffer size */
		getsockopt(nfnl_fd(STATE(event)), SOL_SOCKET,
			   SO_RCVBUF, &read_size, &socklen);

		CONFIG(netlink_buffer_size) = read_size;
	}

	/* ensure that maximum grown size is >= than maximum size */
	if (CONFIG(netlink_buffer_size_max_grown) < CONFIG(netlink_buffer_size))
		CONFIG(netlink_buffer_size_max_grown) = 
					CONFIG(netlink_buffer_size);

	/* open event subsystem */
	STATE(subsys_event) = nfnl_subsys_open(STATE(event),
					       NFNL_SUBSYS_CTNETLINK,
					       IPCTNL_MSG_MAX,
					       NFCT_ALL_CT_GROUPS);
	if (STATE(subsys_event) == NULL)
		return -1;

	/* register callback for new and update events */
	nfnl_callback_register(STATE(subsys_event),
			       IPCTNL_MSG_CT_NEW,
			       &cb_events);

	/* register callback for delete events */
	nfnl_callback_register(STATE(subsys_event),
			       IPCTNL_MSG_CT_DELETE,
			       &cb_events);

	return 0;
}

static int nl_dump_handler(struct nlmsghdr *nlh,
			   struct nfattr *nfa[],
			   void *data)
{
	char buf[1024];
	struct nf_conntrack *ct = (struct nf_conntrack *) buf;
	int type;

	memset(buf, 0, sizeof(buf));

	if ((type = nfct_parse_conntrack(NFCT_T_ALL, nlh, ct)) == NFCT_T_ERROR)
		return NFCT_CB_CONTINUE;

	/* 
	 * Ignore this conntrack: it talks about a
	 * connection that is not interesting for us.
	 */
	if (ignore_conntrack(ct))
		return NFCT_CB_CONTINUE;

	switch(type) {
	case NFCT_T_UPDATE:
		STATE(mode)->dump(ct, nlh);
		break;
	default:
		dlog(STATE(log), "received unknown msg from ctnetlink");
		break;
	}
	return NFCT_CB_CONTINUE;
}

int nl_init_dump_handler(void)
{
	struct nfnl_callback cb_dump = {
		.call		= nl_dump_handler,
		.attr_count	= CTA_MAX
	};

	/* open dump netlink socket */
	STATE(dump) = nfnl_open();
	if (!STATE(dump))
		return -1;

	/* open dump subsystem */
	STATE(subsys_dump) = nfnl_subsys_open(STATE(dump),
					      NFNL_SUBSYS_CTNETLINK,
					      IPCTNL_MSG_MAX,
					      0);
	if (STATE(subsys_dump) == NULL)
		return -1;

	/* register callback for dumped entries */
	nfnl_callback_register(STATE(subsys_dump),
			       IPCTNL_MSG_CT_NEW,
			       &cb_dump);

	if (nl_dump_conntrack_table(STATE(dump), STATE(subsys_dump)) == -1)
		return -1;

	return 0;
}

static int nl_overrun_handler(struct nlmsghdr *nlh,
			      struct nfattr *nfa[],
			      void *data)
{
	char buf[1024];
	struct nf_conntrack *ct = (struct nf_conntrack *) buf;
	int type;

	memset(buf, 0, sizeof(buf));

	if ((type = nfct_parse_conntrack(NFCT_T_ALL, nlh, ct)) == NFCT_T_ERROR)
		return NFCT_CB_CONTINUE;

	/* 
	 * Ignore this conntrack: it talks about a
	 * connection that is not interesting for us.
	 */
	if (ignore_conntrack(ct))
		return NFCT_CB_CONTINUE;

	switch(type) {
	case NFCT_T_UPDATE:
		if (STATE(mode)->overrun)
			STATE(mode)->overrun(ct, nlh);
		break;
	default:
		dlog(STATE(log), "received unknown msg from ctnetlink");
		break;
	}
	return NFCT_CB_CONTINUE;
}

int nl_init_overrun_handler(void)
{
	struct nfnl_callback cb_sync = {
		.call		= nl_overrun_handler,
		.attr_count	= CTA_MAX
	};

	/* open sync netlink socket */
	STATE(sync) = nfnl_open();
	if (!STATE(sync))
		return -1;

	/* open synchronizer subsystem */
	STATE(subsys_sync) = nfnl_subsys_open(STATE(sync),
					      NFNL_SUBSYS_CTNETLINK,
					      IPCTNL_MSG_MAX,
					      0);
	if (STATE(subsys_sync) == NULL)
		return -1;

	/* register callback for dumped entries */
	nfnl_callback_register(STATE(subsys_sync),
			       IPCTNL_MSG_CT_NEW,
			       &cb_sync);

	return 0;
}

static int warned = 0;

void nl_resize_socket_buffer(struct nfnl_handle *h)
{
	unsigned int s = CONFIG(netlink_buffer_size) * 2;

	/* already warned that we have reached the maximum buffer size */
	if (warned)
		return;

	if (s > CONFIG(netlink_buffer_size_max_grown)) {
		dlog(STATE(log), "maximum netlink socket buffer size reached");
		s = CONFIG(netlink_buffer_size_max_grown);
		warned = 1;
	}

	CONFIG(netlink_buffer_size) = nfnl_rcvbufsiz(h, s);

	/* notify the sysadmin */
	dlog(STATE(log), "netlink socket buffer size has been set to %u bytes", 
			  CONFIG(netlink_buffer_size));
}

int nl_dump_conntrack_table(struct nfnl_handle *h, 
			    struct nfnl_subsys_handle *subsys)
{
	struct nfnlhdr req;

	memset(&req, 0, sizeof(req));
	nfct_build_query(subsys, 
			 NFCT_Q_DUMP, 
			 &CONFIG(family), 
			 &req, 
			 sizeof(req));

	if (nfnl_query(h, &req.nlh) == -1)
		return -1;

	return 0;
}

int nl_flush_master_conntrack_table(void)
{
	struct nfnlhdr req;

	memset(&req, 0, sizeof(req));
	nfct_build_query(STATE(subsys_sync), 
			 NFCT_Q_FLUSH, 
			 &CONFIG(family), 
			 &req, 
			 sizeof(req));

	if (nfnl_query(STATE(sync), &req.nlh) == -1)
		return -1;

	return 0;
}
