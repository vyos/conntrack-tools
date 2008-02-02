/*
 * (C) 2006-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
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

#include "sync.h"
#include "netlink.h"
#include "traffic_stats.h"
#include "log.h"
#include "state_helper.h"
#include "cache.h"
#include "conntrackd.h"
#include "us-conntrack.h"
#include "network.h"
#include "debug.h"

#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

static void do_mcast_handler_step(struct nethdr *net)
{
	int query;
	struct netpld *pld = NETHDR_DATA(net);
	char __ct[nfct_maxsize()];
	struct nf_conntrack *ct = (struct nf_conntrack *)(void*) __ct;
	struct us_conntrack *u;

	if (STATE_SYNC(sync)->recv(net))
		return;

	memset(ct, 0, sizeof(__ct));

	/* XXX: check for malformed */
	parse_netpld(ct, pld, &query);

	switch(query) {
	case NFCT_Q_CREATE:
retry:		
		if ((u = cache_add(STATE_SYNC(external), ct))) {
			debug_ct(u->ct, "external new");
		} else {
		        /*
			 * One certain connection A arrives to the cache but 
			 * another existing connection B in the cache has 
			 * the same configuration, therefore B clashes with A.
			 */
			if (errno == EEXIST) {
				cache_del(STATE_SYNC(external), ct);
				goto retry;
			}
			debug_ct(ct, "can't add");
		}
		break;
	case NFCT_Q_UPDATE:
		if ((u = cache_update_force(STATE_SYNC(external), ct))) {
			debug_ct(u->ct, "external update");
		} else
			debug_ct(ct, "can't update");
		break;
	case NFCT_Q_DESTROY:
		if (cache_del(STATE_SYNC(external), ct))
			debug_ct(ct, "external destroy");
		else
			debug_ct(ct, "can't destroy");
		break;
	default:
		dlog(LOG_ERR, "mcast unknown query %d\n", query);
		break;
	}
}

/* handler for multicast messages received */
static void mcast_handler(void)
{
	ssize_t numbytes;
	size_t remain;
	char __net[65536], *ptr = __net; /* XXX: maximum MTU for IPv4 */

	numbytes = mcast_recv(STATE_SYNC(mcast_server), __net, sizeof(__net));
	if (numbytes <= 0)
		return;

	remain = numbytes;
	while (remain > 0) {
		struct nethdr *net = (struct nethdr *) ptr;

		if (remain < NETHDR_SIZ) {
			STATE(malformed)++;
			break;
		}

		if (ntohs(net->len) > remain) {
			dlog(LOG_ERR, "fragmented messages");
			break;
		}

		debug("recv sq: %u fl:%u len:%u (rem:%d)\n", 
			ntohl(net->seq), ntohs(net->flags),
			ntohs(net->len), remain);

		/* sanity check and convert nethdr to host byte order */
		if (handle_netmsg(net) == -1) {
			STATE(malformed)++;
			return;
		}
		do_mcast_handler_step(net);
		ptr += net->len;
		remain -= net->len;
	}
}

static int init_sync(void)
{
	state.sync = malloc(sizeof(struct ct_sync_state));
	if (!state.sync) {
		dlog(LOG_ERR, "can't allocate memory for sync");
		return -1;
	}
	memset(state.sync, 0, sizeof(struct ct_sync_state));

	if (CONFIG(flags) & CTD_SYNC_FTFW)
		STATE_SYNC(sync) = &sync_ftfw;
	else if (CONFIG(flags) & CTD_SYNC_ALARM)
		STATE_SYNC(sync) = &sync_alarm;
	else {
		fprintf(stderr, "WARNING: No synchronization mode specified. "
				"Defaulting to FT-FW mode.\n");
		CONFIG(flags) |= CTD_SYNC_FTFW;
		STATE_SYNC(sync) = &sync_ftfw;
	}

	if (STATE_SYNC(sync)->init)
		STATE_SYNC(sync)->init();

	STATE_SYNC(internal) =
		cache_create("internal", 
			     STATE_SYNC(sync)->internal_cache_flags,
			     STATE_SYNC(sync)->internal_cache_extra);

	if (!STATE_SYNC(internal)) {
		dlog(LOG_ERR, "can't allocate memory for "
			      "the internal cache");
		return -1;
	}

	/* straight forward commit of conntrack to kernel space */
	if (CONFIG(cache_write_through))
		STATE_SYNC(sync)->external_cache_flags |= WRITE_THROUGH;

	STATE_SYNC(external) = 
		cache_create("external",
			     STATE_SYNC(sync)->external_cache_flags,
			     NULL);

	if (!STATE_SYNC(external)) {
		dlog(LOG_ERR, "can't allocate memory for the "
			      "external cache");
		return -1;
	}

	/* multicast server to receive events from the wire */
	STATE_SYNC(mcast_server) = mcast_server_create(&CONFIG(mcast));
	if (STATE_SYNC(mcast_server) == NULL) {
		dlog(LOG_ERR, "can't open multicast server!");
		return -1;
	}

	/* multicast client to send events on the wire */
	STATE_SYNC(mcast_client) = mcast_client_create(&CONFIG(mcast));
	if (STATE_SYNC(mcast_client) == NULL) {
		dlog(LOG_ERR, "can't open client multicast socket");
		mcast_server_destroy(STATE_SYNC(mcast_server));
		return -1;
	}

	if (mcast_buffered_init(&CONFIG(mcast)) == -1) {
		dlog(LOG_ERR, "can't init tx buffer!");
		mcast_server_destroy(STATE_SYNC(mcast_server));
		mcast_client_destroy(STATE_SYNC(mcast_client));
		return -1;
	}

	/* initialization of multicast sequence generation */
	STATE_SYNC(last_seq_sent) = time(NULL);

	return 0;
}

static int add_fds_to_set_sync(fd_set *readfds) 
{
	FD_SET(STATE_SYNC(mcast_server->fd), readfds);

	return STATE_SYNC(mcast_server->fd);
}

static void run_sync(fd_set *readfds)
{
	/* multicast packet has been received */
	if (FD_ISSET(STATE_SYNC(mcast_server->fd), readfds))
		mcast_handler();

	if (STATE_SYNC(sync)->run)
		STATE_SYNC(sync)->run();

	/* flush pending messages */
	mcast_buffered_pending_netmsg(STATE_SYNC(mcast_client));
}

static void kill_sync(void)
{
	cache_destroy(STATE_SYNC(internal));
	cache_destroy(STATE_SYNC(external));

	mcast_server_destroy(STATE_SYNC(mcast_server));
	mcast_client_destroy(STATE_SYNC(mcast_client));

	mcast_buffered_destroy();

	if (STATE_SYNC(sync)->kill)
		STATE_SYNC(sync)->kill();
}

static void dump_stats_sync(int fd)
{
	char buf[512];
	int size;

	size = sprintf(buf, "multicast sequence tracking:\n"
			    "%20llu Pckts mfrm "
			    "%20llu Pckts lost\n\n",
			(unsigned long long)STATE(malformed),
			(unsigned long long)STATE_SYNC(packets_lost));

	send(fd, buf, size, 0);
}

/* handler for requests coming via UNIX socket */
static int local_handler_sync(int fd, int type, void *data)
{
	int ret = 1;

	switch(type) {
	case DUMP_INTERNAL:
		ret = fork();
		if (ret == 0) {
			cache_dump(STATE_SYNC(internal), fd, NFCT_O_PLAIN);
			exit(EXIT_SUCCESS);
		}
		break;
	case DUMP_EXTERNAL:
		ret = fork();
		if (ret == 0) {
			cache_dump(STATE_SYNC(external), fd, NFCT_O_PLAIN);
			exit(EXIT_SUCCESS);
		} 
		break;
	case DUMP_INT_XML:
		ret = fork();
		if (ret == 0) {
			cache_dump(STATE_SYNC(internal), fd, NFCT_O_XML);
			exit(EXIT_SUCCESS);
		}
		break;
	case DUMP_EXT_XML:
		ret = fork();
		if (ret == 0) {
			cache_dump(STATE_SYNC(external), fd, NFCT_O_XML);
			exit(EXIT_SUCCESS);
		}
		break;
	case COMMIT:
		ret = fork();
		if (ret == 0) {
			dlog(LOG_NOTICE, 
			     "committing external cache");
			cache_commit(STATE_SYNC(external));
			exit(EXIT_SUCCESS);
		}
		break;
	case FLUSH_CACHE:
		dlog(LOG_NOTICE, "flushing caches");
		cache_flush(STATE_SYNC(internal));
		cache_flush(STATE_SYNC(external));
		break;
	case KILL:
		killer(0);
		break;
	case STATS:
		cache_stats(STATE_SYNC(internal), fd);
		cache_stats(STATE_SYNC(external), fd);
		dump_traffic_stats(fd);
		mcast_dump_stats(fd, STATE_SYNC(mcast_client), 
				     STATE_SYNC(mcast_server));
		dump_stats_sync(fd);
		break;
	default:
		if (STATE_SYNC(sync)->local)
			ret = STATE_SYNC(sync)->local(fd, type, data);
		break;
	}

	return ret;
}

static void dump_sync(struct nf_conntrack *ct)
{
	if (!CONFIG(cache_write_through))
		nfct_attr_unset(ct, ATTR_TIMEOUT);

	/* This is required by kernels < 2.6.20 */
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_USE);

	if (cache_update_force(STATE_SYNC(internal), ct))
		debug_ct(ct, "resync");
}

static void mcast_send_sync(struct us_conntrack *u,
			    struct nf_conntrack *ct,
			    int query)
{
	size_t len;
	struct nethdr *net;

	if (!state_helper_verdict(query, ct))
		return;

	net = BUILD_NETMSG(ct, query);
	len = prepare_send_netmsg(STATE_SYNC(mcast_client), net);
	mcast_buffered_send_netmsg(STATE_SYNC(mcast_client), net, len);
	if (STATE_SYNC(sync)->send)
		STATE_SYNC(sync)->send(net, u);
}

static int overrun_cb(enum nf_conntrack_msg_type type,
		      struct nf_conntrack *ct,
		      void *data)
{
	struct us_conntrack *u;

	if (ignore_conntrack(ct))
		return NFCT_CB_CONTINUE;

	if (!CONFIG(cache_write_through))
		nfct_attr_unset(ct, ATTR_TIMEOUT);

	/* This is required by kernels < 2.6.20 */
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_USE);

	if (!cache_test(STATE_SYNC(internal), ct)) {
		if ((u = cache_update_force(STATE_SYNC(internal), ct))) {
			size_t len;

			debug_ct(u->ct, "overrun resync");

			struct nethdr *net = BUILD_NETMSG(u->ct, NFCT_Q_UPDATE);
			len = prepare_send_netmsg(STATE_SYNC(mcast_client),net);
			mcast_buffered_send_netmsg(STATE_SYNC(mcast_client), 
						   net, len);
			if (STATE_SYNC(sync)->send)
				STATE_SYNC(sync)->send(net, u);
		}
	}

	return NFCT_CB_CONTINUE;
}

static int overrun_purge_step(void *data1, void *data2)
{
	int ret;
	struct nfct_handle *h = data1;
	struct us_conntrack *u = data2;

	ret = nfct_query(h, NFCT_Q_GET, u->ct);
	if (ret == -1 && errno == ENOENT) {
		size_t len;
		struct nethdr *net = BUILD_NETMSG(u->ct, NFCT_Q_DESTROY);

		debug_ct(u->ct, "overrun purge resync");

	        len = prepare_send_netmsg(STATE_SYNC(mcast_client), net);
	        mcast_buffered_send_netmsg(STATE_SYNC(mcast_client), net, len);
		if (STATE_SYNC(sync)->send)
			STATE_SYNC(sync)->send(net, u);

		cache_del(STATE_SYNC(internal), u->ct);
	}

	return 0;
}

/* it's likely that we're losing events, just try to do our best here */
static void overrun_sync(void)
{
	int ret;
	struct nfct_handle *h;
	int family = CONFIG(family);

	h = nfct_open(CONNTRACK, 0);
	if (!h) {
		dlog(LOG_ERR, "can't open overrun handler");
		return;
	}

	nfct_callback_register(h, NFCT_T_ALL, overrun_cb, NULL);

	ret = nfct_query(h, NFCT_Q_DUMP, &family);
	if (ret == -1)
		dlog(LOG_ERR, 
		     "overrun query error %s", strerror(errno));

	nfct_callback_unregister(h);

	cache_iterate(STATE_SYNC(internal), h, overrun_purge_step);

	nfct_close(h);
}

static void event_new_sync(struct nf_conntrack *ct)
{
	struct us_conntrack *u;

	if (!CONFIG(cache_write_through))
		nfct_attr_unset(ct, ATTR_TIMEOUT);

	/* required by linux kernel <= 2.6.20 */
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_PACKETS);
retry:
	if ((u = cache_add(STATE_SYNC(internal), ct))) {
		mcast_send_sync(u, ct, NFCT_Q_CREATE);
		debug_ct(u->ct, "internal new");
	} else {
		if (errno == EEXIST) {
			cache_del(STATE_SYNC(internal), ct);
			mcast_send_sync(NULL, ct, NFCT_Q_DESTROY);
			goto retry;
		}

		dlog(LOG_ERR, "can't add to internal cache: "
			      "%s\n", strerror(errno));
		debug_ct(ct, "can't add");
	}
}

static void event_update_sync(struct nf_conntrack *ct)
{
	struct us_conntrack *u;

	if (!CONFIG(cache_write_through))
		nfct_attr_unset(ct, ATTR_TIMEOUT);

	if ((u = cache_update_force(STATE_SYNC(internal), ct)) == NULL) {
		debug_ct(ct, "can't update");
		return;
	}
	debug_ct(u->ct, "internal update");
	mcast_send_sync(u, ct, NFCT_Q_UPDATE);
}

static int event_destroy_sync(struct nf_conntrack *ct)
{
	if (!CONFIG(cache_write_through))
		nfct_attr_unset(ct, ATTR_TIMEOUT);

	if (cache_del(STATE_SYNC(internal), ct)) {
		mcast_send_sync(NULL, ct, NFCT_Q_DESTROY);
		debug_ct(ct, "internal destroy");
		return 1;
	} else {
		debug_ct(ct, "can't destroy");
		return 0;
	}
}

struct ct_mode sync_mode = {
	.init 			= init_sync,
	.add_fds_to_set 	= add_fds_to_set_sync,
	.run			= run_sync,
	.local			= local_handler_sync,
	.kill			= kill_sync,
	.dump			= dump_sync,
	.overrun		= overrun_sync,
	.event_new		= event_new_sync,
	.event_upd		= event_update_sync,
	.event_dst		= event_destroy_sync
};
