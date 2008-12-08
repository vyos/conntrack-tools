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
#include "cache.h"
#include "conntrackd.h"
#include "us-conntrack.h"
#include "network.h"
#include "fds.h"
#include "event.h"
#include "debug.h"

#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

static void do_mcast_handler_step(struct nethdr *net, size_t remain)
{
	int query;
	char __ct[nfct_maxsize()];
	struct nf_conntrack *ct = (struct nf_conntrack *)(void*) __ct;
	struct us_conntrack *u;

	if (net->version != CONNTRACKD_PROTOCOL_VERSION) {
		STATE(malformed)++;
		dlog(LOG_WARNING, "wrong protocol version `%u'", net->version);
		return;
	}

	switch (STATE_SYNC(sync)->recv(net)) {
		case MSG_DATA:
			break;
		case MSG_DROP:
		case MSG_CTL:
			return;
		case MSG_BAD:
			STATE(malformed)++;
			return;
		default:
			break;
	}

	memset(ct, 0, sizeof(__ct));

	if (parse_netpld(ct, net, &query, remain) == -1) {
		STATE(malformed)++;
		dlog(LOG_ERR, "parsing failed: malformed message");
		return;
	}

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
		STATE(malformed)++;
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
			dlog(LOG_WARNING, "no room for header");
			break;
		}

		if (ntohs(net->len) > remain) {
			STATE(malformed)++;
			dlog(LOG_WARNING, "fragmented message");
			break;
		}

		if (IS_CTL(net)) {
			if (remain < NETHDR_ACK_SIZ) {
				STATE(malformed)++;
				dlog(LOG_WARNING, "no room for ctl message");
			}

			if (ntohs(net->len) < NETHDR_ACK_SIZ) {
				STATE(malformed)++;
				dlog(LOG_WARNING, "ctl header too small");
			}
		} else {
			if (ntohs(net->len) < NETHDR_SIZ) {
				STATE(malformed)++;
				dlog(LOG_WARNING, "header too small");
			}
		}

		debug("recv sq: %u fl:%u len:%u (rem:%d)\n", 
			ntohl(net->seq), net->flags,
			ntohs(net->len), remain);

		HDR_NETWORK2HOST(net);

		do_mcast_handler_step(net, remain);
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
	else if (CONFIG(flags) & CTD_SYNC_NOTRACK)
		STATE_SYNC(sync) = &sync_notrack;
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

	dlog(LOG_NOTICE, "multicast server socket receiver queue "
			 "has been set to %d bytes", CONFIG(mcast).rcvbuf);

	/* multicast client to send events on the wire */
	STATE_SYNC(mcast_client) = mcast_client_create(&CONFIG(mcast));
	if (STATE_SYNC(mcast_client) == NULL) {
		dlog(LOG_ERR, "can't open client multicast socket");
		mcast_server_destroy(STATE_SYNC(mcast_server));
		return -1;
	}

	dlog(LOG_NOTICE, "multicast client socket sender queue "
			 "has been set to %d bytes", CONFIG(mcast).sndbuf);

	if (mcast_buffered_init(CONFIG(mcast).mtu) == -1) {
		dlog(LOG_ERR, "can't init tx buffer!");
		mcast_server_destroy(STATE_SYNC(mcast_server));
		mcast_client_destroy(STATE_SYNC(mcast_client));
		return -1;
	}

	STATE_SYNC(evfd) = create_evfd();
	if (STATE_SYNC(evfd) == NULL) {
		dlog(LOG_ERR, "cannot open evfd");
		return -1;
	}

	/* initialization of multicast sequence generation */
	STATE_SYNC(last_seq_sent) = time(NULL);

	return 0;
}

static int register_fds_sync(struct fds *fds) 
{
	if (register_fd(STATE_SYNC(mcast_server->fd), fds) == -1)
		return -1;

	return register_fd(get_read_evfd(STATE_SYNC(evfd)), fds);
}

static void run_sync(fd_set *readfds)
{
	/* multicast packet has been received */
	if (FD_ISSET(STATE_SYNC(mcast_server->fd), readfds))
		mcast_handler();

	if (FD_ISSET(get_read_evfd(STATE_SYNC(evfd)), readfds) && 
	    STATE_SYNC(sync)->run) {
	    	read_evfd(STATE_SYNC(evfd));
		STATE_SYNC(sync)->run();
	}

	/* flush pending messages */
	mcast_buffered_pending_netmsg(STATE_SYNC(mcast_client));
}

static void kill_sync(void)
{
	cache_destroy(STATE_SYNC(internal));
	cache_destroy(STATE_SYNC(external));

	mcast_server_destroy(STATE_SYNC(mcast_server));
	mcast_client_destroy(STATE_SYNC(mcast_client));

	destroy_evfd(STATE_SYNC(evfd));

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
	case RESET_TIMERS:
		ret = fork();
		if (ret == 0) {
			dlog(LOG_NOTICE, "resetting timers");
			cache_reset_timers(STATE_SYNC(internal));
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
	/* This is required by kernels < 2.6.20 */
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_USE);

	if (cache_update_force(STATE_SYNC(internal), ct))
		debug_ct(ct, "resync");
}

static void mcast_send_sync(struct us_conntrack *u, int query)
{
	size_t len;
	struct nethdr *net;

	net = BUILD_NETMSG(u->ct, query);
	len = prepare_send_netmsg(STATE_SYNC(mcast_client), net);

	if (STATE_SYNC(sync)->send)
		STATE_SYNC(sync)->send(net, u);

	mcast_buffered_send_netmsg(STATE_SYNC(mcast_client), net);
}

static int purge_step(void *data1, void *data2)
{
	int ret;
	struct nfct_handle *h = STATE(dump);
	struct us_conntrack *u = data2;

	ret = nfct_query(h, NFCT_Q_GET, u->ct);
	if (ret == -1 && errno == ENOENT) {
		debug_ct(u->ct, "overrun purge resync");
		mcast_send_sync(u, NFCT_Q_DESTROY);
		__cache_del_timer(STATE_SYNC(internal), u, CONFIG(del_timeout));
	}

	return 0;
}

static int purge_sync(void)
{
	cache_iterate(STATE_SYNC(internal), NULL, purge_step);

	return 0;
}

static int overrun_sync(enum nf_conntrack_msg_type type,
			struct nf_conntrack *ct,
			void *data)
{
	struct us_conntrack *u;

	if (ct_filter_conntrack(ct, 1))
		return NFCT_CB_CONTINUE;

	/* This is required by kernels < 2.6.20 */
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_USE);

	if (!cache_test(STATE_SYNC(internal), ct)) {
		if ((u = cache_update_force(STATE_SYNC(internal), ct))) {
			debug_ct(u->ct, "overrun resync");
			mcast_send_sync(u, NFCT_Q_UPDATE);
		}
	}

	return NFCT_CB_CONTINUE;
}

static void event_new_sync(struct nf_conntrack *ct)
{
	struct us_conntrack *u;

	/* required by linux kernel <= 2.6.20 */
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_PACKETS);
retry:
	if ((u = cache_add(STATE_SYNC(internal), ct))) {
		mcast_send_sync(u, NFCT_Q_CREATE);
		debug_ct(u->ct, "internal new");
	} else {
		if (errno == EEXIST) {
			cache_del(STATE_SYNC(internal), ct);
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

	if ((u = cache_update_force(STATE_SYNC(internal), ct)) == NULL) {
		debug_ct(ct, "can't update");
		return;
	}
	debug_ct(u->ct, "internal update");
	mcast_send_sync(u, NFCT_Q_UPDATE);
}

static int event_destroy_sync(struct nf_conntrack *ct)
{
	struct us_conntrack *u;

	u = cache_find(STATE_SYNC(internal), ct);
	if (u == NULL) {
		debug_ct(ct, "can't destroy");
		return 0;
	}

	mcast_send_sync(u, NFCT_Q_DESTROY);
	__cache_del_timer(STATE_SYNC(internal), u, CONFIG(del_timeout));
	debug_ct(ct, "internal destroy");
	return 1;
}

struct ct_mode sync_mode = {
	.init 			= init_sync,
	.register_fds		= register_fds_sync,
	.run			= run_sync,
	.local			= local_handler_sync,
	.kill			= kill_sync,
	.dump			= dump_sync,
	.overrun		= overrun_sync,
	.purge			= purge_sync,
	.event_new		= event_new_sync,
	.event_upd		= event_update_sync,
	.event_dst		= event_destroy_sync
};
