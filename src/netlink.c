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

#include "netlink.h"
#include "conntrackd.h"
#include "traffic_stats.h"
#include "filter.h"
#include "log.h"
#include "debug.h"

#include <string.h>
#include <errno.h>

static int sanity_check(struct nf_conntrack *ct)
{
	if (!nfct_attr_is_set(ct, ATTR_L3PROTO)) {
		dlog(LOG_ERR, "missing layer 3 protocol");
		return 0;
	}

	switch(nfct_get_attr_u8(ct, ATTR_L3PROTO)) {
	case AF_INET:
		if (!nfct_attr_is_set(ct, ATTR_IPV4_SRC) ||
		    !nfct_attr_is_set(ct, ATTR_IPV4_DST) ||
		    !nfct_attr_is_set(ct, ATTR_REPL_IPV4_SRC) ||
		    !nfct_attr_is_set(ct, ATTR_REPL_IPV4_DST)) {
		    	dlog(LOG_ERR, "missing IPv4 address. "
				      "You forgot to load "
				      "nf_conntrack_ipv4?");
			return 0;
		}
		break;
	case AF_INET6:
		if (!nfct_attr_is_set(ct, ATTR_IPV6_SRC) ||
		    !nfct_attr_is_set(ct, ATTR_IPV6_DST) ||
		    !nfct_attr_is_set(ct, ATTR_REPL_IPV6_SRC) ||
		    !nfct_attr_is_set(ct, ATTR_REPL_IPV6_DST)) {
		    	dlog(LOG_ERR, "missing IPv6 address. "
				      "You forgot to load "
				      "nf_conntrack_ipv6?");
			return 0;
		}
		break;
	}
	return 1;
}

/* we do user-space filtering for dump and resyncs */
int ignore_conntrack(struct nf_conntrack *ct, int userspace)
{
	/* missing mandatory attributes in object */
	if (!sanity_check(ct))
		return 1;

	if (userspace && !ct_filter_check(STATE(us_filter), ct)) {
		debug_ct(ct, "ignore traffic");
		return 1;
	}

	return 0;
}

static int event_handler(enum nf_conntrack_msg_type type,
			 struct nf_conntrack *ct,
			 void *data)
{
	/* skip user-space filtering if already do it in the kernel */
	if (ignore_conntrack(ct, !CONFIG(filter_from_kernelspace)))
		return NFCT_CB_STOP;

	switch(type) {
	case NFCT_T_NEW:
		STATE(mode)->event_new(ct);
		break;
	case NFCT_T_UPDATE:
		STATE(mode)->event_upd(ct);
		break;
	case NFCT_T_DESTROY:
		if (STATE(mode)->event_dst(ct))
			update_traffic_stats(ct);
		break;
	default:
		dlog(LOG_WARNING, "unknown msg from ctnetlink\n");
		break;
	}

	return NFCT_CB_CONTINUE;
}

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/fcntl.h>

int nl_init_event_handler(void)
{
	STATE(event) = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
	if (!STATE(event))
		return -1;

	if (STATE(filter)) {
		if (CONFIG(filter_from_kernelspace)) {
			if (nfct_filter_attach(nfct_fd(STATE(event)),
					       STATE(filter)) == -1) {
				dlog(LOG_ERR, "cannot set event filtering: %s",
				     strerror(errno));
			}
			dlog(LOG_NOTICE, "using kernel-space event filtering");
		} else
			dlog(LOG_NOTICE, "using user-space event filtering");

		nfct_filter_destroy(STATE(filter));
	}

	fcntl(nfct_fd(STATE(event)), F_SETFL, O_NONBLOCK);

	/* set up socket buffer size */
	if (CONFIG(netlink_buffer_size))
		nfnl_rcvbufsiz(nfct_nfnlh(STATE(event)),
			       CONFIG(netlink_buffer_size));
	else {
		socklen_t socklen = sizeof(unsigned int);
		unsigned int read_size;

		/* get current buffer size */
		getsockopt(nfct_fd(STATE(event)), SOL_SOCKET,
			   SO_RCVBUF, &read_size, &socklen);

		CONFIG(netlink_buffer_size) = read_size;
	}

	/* ensure that maximum grown size is >= than maximum size */
	if (CONFIG(netlink_buffer_size_max_grown) < CONFIG(netlink_buffer_size))
		CONFIG(netlink_buffer_size_max_grown) =
					CONFIG(netlink_buffer_size);

	/* register callback for events */
	nfct_callback_register(STATE(event), NFCT_T_ALL, event_handler, NULL);

	return 0;
}

static int dump_handler(enum nf_conntrack_msg_type type,
			struct nf_conntrack *ct,
			void *data)
{
	if (ignore_conntrack(ct, 1))
		return NFCT_CB_CONTINUE;

	switch(type) {
	case NFCT_T_UPDATE:
		STATE(mode)->dump(ct);
		break;
	default:
		dlog(LOG_WARNING, "unknown msg from ctnetlink");
		break;
	}
	return NFCT_CB_CONTINUE;
}

int nl_init_dump_handler(void)
{
	/* open dump netlink socket */
	STATE(dump) = nfct_open(CONNTRACK, 0);
	if (!STATE(dump))
		return -1;

	/* register callback for dumped entries */
	nfct_callback_register(STATE(dump), NFCT_T_ALL, dump_handler, NULL);

	if (nl_dump_conntrack_table() == -1)
		return -1;

	return 0;
}

int nl_init_overrun_handler(void)
{
	STATE(overrun) = nfct_open(CONNTRACK, 0);
	if (!STATE(overrun))
		return -1;

	fcntl(nfct_fd(STATE(overrun)), F_SETFL, O_NONBLOCK);

	nfct_callback_register(STATE(overrun), 
			       NFCT_T_ALL, 
			       STATE(mode)->overrun, 
			       NULL);
	return 0;
}

/* no callback, it does not do anything with the output */
int nl_init_request_handler(void)
{
	STATE(request) = nfct_open(CONNTRACK, 0);
	if (!STATE(request))
		return -1;

	return 0;
}

static int warned = 0;

void nl_resize_socket_buffer(struct nfct_handle *h)
{
	unsigned int s = CONFIG(netlink_buffer_size) * 2;

	/* already warned that we have reached the maximum buffer size */
	if (warned)
		return;

	if (s > CONFIG(netlink_buffer_size_max_grown)) {
		dlog(LOG_WARNING,
		     "maximum netlink socket buffer "
		     "size has been reached. We are likely to "
		     "be losing events, this may lead to "
		     "unsynchronized replicas. Please, consider "
		     "increasing netlink socket buffer size via "
		     "SocketBufferSize and "
		     "SocketBufferSizeMaxGrown clauses in "
		     "conntrackd.conf");
		s = CONFIG(netlink_buffer_size_max_grown);
		warned = 1;
	}

	CONFIG(netlink_buffer_size) = nfnl_rcvbufsiz(nfct_nfnlh(h), s);

	/* notify the sysadmin */
	dlog(LOG_NOTICE, "netlink socket buffer size "
			 "has been set to %u bytes",
			 CONFIG(netlink_buffer_size));
}

int nl_dump_conntrack_table(void)
{
	return nfct_query(STATE(dump), NFCT_Q_DUMP, &CONFIG(family));
}

int nl_overrun_request_resync(void)
{
	int family = CONFIG(family);
	return nfct_send(STATE(overrun), NFCT_Q_DUMP, &family);
}

static int __nl_get_conntrack(struct nfct_handle *h, struct nf_conntrack *ct)
{
	int ret;
	char __tmp[nfct_maxsize()];
	struct nf_conntrack *tmp = (struct nf_conntrack *) (void *)__tmp;

	memset(__tmp, 0, sizeof(__tmp));

	/* use the original tuple to check if it is there */
	nfct_copy(tmp, ct, NFCT_CP_ORIG);

	ret = nfct_query(h, NFCT_Q_GET, tmp);
	if (ret == -1)
		return errno == ENOENT ? 0 : -1;

	return 1;
}

int nl_exist_conntrack(struct nf_conntrack *ct)
{
	return __nl_get_conntrack(STATE(request), ct);
}

/* get the conntrack and update the cache */
int nl_get_conntrack(struct nf_conntrack *ct)
{
	return __nl_get_conntrack(STATE(dump), ct);
}

/* This function modifies the conntrack passed as argument! */
int nl_create_conntrack(struct nf_conntrack *ct)
{
	uint8_t flags;

	/* we hit error if we try to change the expected bit */
	if (nfct_attr_is_set(ct, ATTR_STATUS)) {
		uint32_t status = nfct_get_attr_u32(ct, ATTR_STATUS);
		status &= ~IPS_EXPECTED;
		nfct_set_attr_u32(ct, ATTR_STATUS, status);
	}

	nfct_setobjopt(ct, NFCT_SOPT_SETUP_REPLY);

	/*
	 * TCP flags to overpass window tracking for recovered connections
	 */
	flags = IP_CT_TCP_FLAG_BE_LIBERAL | IP_CT_TCP_FLAG_SACK_PERM;
	nfct_set_attr_u8(ct, ATTR_TCP_FLAGS_ORIG, flags);
	nfct_set_attr_u8(ct, ATTR_TCP_MASK_ORIG, flags);
	nfct_set_attr_u8(ct, ATTR_TCP_FLAGS_REPL, flags);
	nfct_set_attr_u8(ct, ATTR_TCP_MASK_REPL, flags);

	return nfct_query(STATE(dump), NFCT_Q_CREATE_UPDATE, ct);
}

/* This function modifies the conntrack passed as argument! */
int nl_update_conntrack(struct nf_conntrack *ct)
{
	uint8_t flags;

	/* unset NAT info, otherwise we hit error */
	nfct_attr_unset(ct, ATTR_SNAT_IPV4);
	nfct_attr_unset(ct, ATTR_DNAT_IPV4);
	nfct_attr_unset(ct, ATTR_SNAT_PORT);
	nfct_attr_unset(ct, ATTR_DNAT_PORT);

	if (nfct_attr_is_set(ct, ATTR_STATUS)) {
		uint32_t status = nfct_get_attr_u32(ct, ATTR_STATUS);
		status &= ~IPS_NAT_MASK;
		nfct_set_attr_u32(ct, ATTR_STATUS, status);
	}

	/* we hit error if we try to update the master conntrack */
	if (ct_is_related(ct)) {
		nfct_attr_unset(ct, ATTR_MASTER_L3PROTO);
		nfct_attr_unset(ct, ATTR_MASTER_L4PROTO);
		nfct_attr_unset(ct, ATTR_MASTER_IPV4_SRC);
		nfct_attr_unset(ct, ATTR_MASTER_IPV4_DST);
		nfct_attr_unset(ct, ATTR_MASTER_IPV6_SRC);
		nfct_attr_unset(ct, ATTR_MASTER_IPV6_DST);
		nfct_attr_unset(ct, ATTR_MASTER_PORT_SRC);
		nfct_attr_unset(ct, ATTR_MASTER_PORT_DST);
	}

	nfct_setobjopt(ct, NFCT_SOPT_SETUP_REPLY);

	/*
	 * TCP flags to overpass window tracking for recovered connections
	 */
	flags = IP_CT_TCP_FLAG_BE_LIBERAL | IP_CT_TCP_FLAG_SACK_PERM;
	nfct_set_attr_u8(ct, ATTR_TCP_FLAGS_ORIG, flags);
	nfct_set_attr_u8(ct, ATTR_TCP_MASK_ORIG, flags);
	nfct_set_attr_u8(ct, ATTR_TCP_FLAGS_REPL, flags);
	nfct_set_attr_u8(ct, ATTR_TCP_MASK_REPL, flags);

	return nfct_query(STATE(dump), NFCT_Q_CREATE_UPDATE, ct);
}

int nl_destroy_conntrack(struct nf_conntrack *ct)
{
	return nfct_query(STATE(dump), NFCT_Q_DESTROY, ct);
}
