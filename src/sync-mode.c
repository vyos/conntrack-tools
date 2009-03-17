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
#include "network.h"
#include "fds.h"
#include "event.h"
#include "queue.h"

#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <net/if.h>

static void
mcast_change_current_link(int if_idx)
{
	if (if_idx != multichannel_get_current_ifindex(STATE_SYNC(channel)))
		multichannel_set_current_channel(STATE_SYNC(channel), if_idx);
}

static void
do_channel_handler_step(int if_idx, struct nethdr *net, size_t remain)
{
	char __ct[nfct_maxsize()];
	struct nf_conntrack *ct = (struct nf_conntrack *)(void*) __ct;
	struct cache_object *obj;
	int id;

	if (net->version != CONNTRACKD_PROTOCOL_VERSION) {
		STATE_SYNC(error).msg_rcv_malformed++;
		STATE_SYNC(error).msg_rcv_bad_version++;
		return;
	}

	switch (STATE_SYNC(sync)->recv(net)) {
	case MSG_DATA:
		mcast_change_current_link(if_idx);
		break;
	case MSG_CTL:
		mcast_change_current_link(if_idx);
		return;
	case MSG_BAD:
		STATE_SYNC(error).msg_rcv_malformed++;
		STATE_SYNC(error).msg_rcv_bad_header++;
		return;
	case MSG_DROP:
		return;
	default:
		break;
	}

	if (net->type > NET_T_STATE_MAX) {
		STATE_SYNC(error).msg_rcv_malformed++;
		STATE_SYNC(error).msg_rcv_bad_type++;
		return;
	}
	memset(ct, 0, sizeof(__ct));

	if (parse_payload(ct, net, remain) == -1) {
		STATE_SYNC(error).msg_rcv_malformed++;
		STATE_SYNC(error).msg_rcv_bad_payload++;
		return;
	}

	switch(net->type) {
	case NET_T_STATE_NEW:
		obj = cache_find(STATE_SYNC(external), ct, &id);
		if (obj == NULL) {
retry:
			obj = cache_object_new(STATE_SYNC(external), ct);
			if (obj == NULL)
				return;

			if (cache_add(STATE_SYNC(external), obj, id) == -1) {
				cache_object_free(obj);
				return;
			}
		} else {
			cache_del(STATE_SYNC(external), obj);
			cache_object_free(obj);
			goto retry;
		}
		break;
	case NET_T_STATE_UPD:
		cache_update_force(STATE_SYNC(external), ct);
		break;
	case NET_T_STATE_DEL:
		obj = cache_find(STATE_SYNC(external), ct, &id);
		if (obj) {
			cache_del(STATE_SYNC(external), obj);
			cache_object_free(obj);
		}
		break;
	default:
		STATE_SYNC(error).msg_rcv_malformed++;
		STATE_SYNC(error).msg_rcv_bad_type++;
		break;
	}
}

/* handler for messages received */
static void channel_handler(struct channel *m, int if_idx)
{
	ssize_t numbytes;
	ssize_t remain;
	char __net[65536], *ptr = __net; /* XXX: maximum MTU for IPv4 */

	numbytes = channel_recv(m, __net, sizeof(__net));
	if (numbytes <= 0)
		return;

	remain = numbytes;
	while (remain > 0) {
		struct nethdr *net = (struct nethdr *) ptr;

		if (remain < NETHDR_SIZ) {
			STATE_SYNC(error).msg_rcv_malformed++;
			STATE_SYNC(error).msg_rcv_truncated++;
			break;
		}

		if (ntohs(net->len) > remain) {
			STATE_SYNC(error).msg_rcv_malformed++;
			STATE_SYNC(error).msg_rcv_bad_size++;
			break;
		}

		if (IS_ACK(net) || IS_NACK(net) || IS_RESYNC(net)) {
			if (remain < NETHDR_ACK_SIZ) {
				STATE_SYNC(error).msg_rcv_malformed++;
				STATE_SYNC(error).msg_rcv_truncated++;
			}

			if (ntohs(net->len) < NETHDR_ACK_SIZ) {
				STATE_SYNC(error).msg_rcv_malformed++;
				STATE_SYNC(error).msg_rcv_bad_size++;
			}
		} else {
			if (ntohs(net->len) < NETHDR_SIZ) {
				STATE_SYNC(error).msg_rcv_malformed++;
				STATE_SYNC(error).msg_rcv_bad_size++;
			}
		}

		HDR_NETWORK2HOST(net);

		do_channel_handler_step(if_idx, net, remain);
		ptr += net->len;
		remain -= net->len;
	}
}

/* select a new interface candidate in a round robin basis */
static void interface_candidate(void)
{
	int i, idx;
	unsigned int flags;
	char buf[IFNAMSIZ];

	for (i=0; i<STATE_SYNC(channel)->channel_num; i++) {
		idx = multichannel_get_ifindex(STATE_SYNC(channel), i);
		if (idx == multichannel_get_current_ifindex(STATE_SYNC(channel)))
			continue;
		nlif_get_ifflags(STATE_SYNC(interface), idx, &flags);
		if (flags & (IFF_RUNNING | IFF_UP)) {
			multichannel_set_current_channel(STATE_SYNC(channel), i);
			dlog(LOG_NOTICE, "device `%s' becomes "
					 "dedicated link", 
					 if_indextoname(idx, buf));
			return;
		}
	}
	dlog(LOG_ERR, "no dedicated links available!");
}

static void interface_handler(void)
{
	int idx = multichannel_get_current_ifindex(STATE_SYNC(channel));
	unsigned int flags;

	nlif_catch(STATE_SYNC(interface));
	nlif_get_ifflags(STATE_SYNC(interface), idx, &flags);
	if (!(flags & IFF_RUNNING) || !(flags & IFF_UP))
		interface_candidate();
}

static void do_reset_cache_alarm(struct alarm_block *a, void *data)
{
	STATE(stats).nl_kernel_table_flush++;
	dlog(LOG_NOTICE, "flushing kernel conntrack table (scheduled)");
	nl_flush_conntrack_table(STATE(request));
	cache_flush(STATE_SYNC(internal));
}

static int init_sync(void)
{
	int i;

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
		dlog(LOG_ERR, "can't allocate memory for the internal cache");
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
		dlog(LOG_ERR, "can't allocate memory for the external cache");
		return -1;
	}

	channel_init();

	/* channel to send events on the wire */
	STATE_SYNC(channel) =
		multichannel_open(CONFIG(channel), CONFIG(channel_num));
	if (STATE_SYNC(channel) == NULL) {
		dlog(LOG_ERR, "can't open channel socket");
		return -1;
	}
	for (i=0; i<STATE_SYNC(channel)->channel_num; i++) {
		int fd = channel_get_fd(STATE_SYNC(channel)->channel[i]);
		if (register_fd(fd, STATE(fds)) == -1)
			return -1;
	}

	STATE_SYNC(interface) = nl_init_interface_handler();
	if (!STATE_SYNC(interface)) {
		dlog(LOG_ERR, "can't open interface watcher");
		return -1;
	}
	if (register_fd(nlif_fd(STATE_SYNC(interface)), STATE(fds)) == -1)
		return -1;

	STATE_SYNC(tx_queue) = queue_create(INT_MAX, QUEUE_F_EVFD);
	if (STATE_SYNC(tx_queue) == NULL) {
		dlog(LOG_ERR, "cannot create tx queue");
		return -1;
	}
	if (register_fd(queue_get_eventfd(STATE_SYNC(tx_queue)), 
							STATE(fds)) == -1)
		return -1;

	init_alarm(&STATE_SYNC(reset_cache_alarm), NULL, do_reset_cache_alarm);

	/* initialization of message sequence generation */
	STATE_SYNC(last_seq_sent) = time(NULL);

	return 0;
}

static void run_sync(fd_set *readfds)
{
	int i;

	for (i=0; i<STATE_SYNC(channel)->channel_num; i++) {
		int fd = channel_get_fd(STATE_SYNC(channel)->channel[i]);
		if (FD_ISSET(fd, readfds))
			channel_handler(STATE_SYNC(channel)->channel[i], i);
	}

	if (FD_ISSET(queue_get_eventfd(STATE_SYNC(tx_queue)), readfds))
		STATE_SYNC(sync)->xmit();

	if (FD_ISSET(nlif_fd(STATE_SYNC(interface)), readfds))
		interface_handler();

	/* flush pending messages */
	multichannel_send_flush(STATE_SYNC(channel));
}

static void kill_sync(void)
{
	cache_destroy(STATE_SYNC(internal));
	cache_destroy(STATE_SYNC(external));

	multichannel_close(STATE_SYNC(channel));

	nlif_close(STATE_SYNC(interface));

	queue_destroy(STATE_SYNC(tx_queue));

	if (STATE_SYNC(sync)->kill)
		STATE_SYNC(sync)->kill();
}

static void dump_stats_sync(int fd)
{
	char buf[512];
	int size;

	size = sprintf(buf, "message sequence tracking:\n"
			    "%20llu Msgs mfrm "
			    "%20llu Msgs lost\n\n",
			(unsigned long long)STATE_SYNC(error).msg_rcv_malformed,
			(unsigned long long)STATE_SYNC(error).msg_rcv_lost);

	send(fd, buf, size, 0);
}

static void dump_stats_sync_extended(int fd)
{
	char buf[512];
	int size;

	size = snprintf(buf, sizeof(buf),
			"network statistics:\n"
			"\trecv:\n"
			"\t\tMalformed messages:\t%20llu\n"
			"\t\tWrong protocol version:\t%20u\n"
			"\t\tMalformed header:\t%20u\n"
			"\t\tMalformed payload:\t%20u\n"
			"\t\tBad message type:\t%20u\n"
			"\t\tTruncated message:\t%20u\n"
			"\t\tBad message size:\t%20u\n"
			"\tsend:\n"
			"\t\tMalformed messages:\t%20u\n\n"
			"sequence tracking statistics:\n"
			"\trecv:\n"
			"\t\tPackets lost:\t\t%20llu\n"
			"\t\tPackets before:\t\t%20llu\n\n",
			(unsigned long long)STATE_SYNC(error).msg_rcv_malformed,
			STATE_SYNC(error).msg_rcv_bad_version,
			STATE_SYNC(error).msg_rcv_bad_header,
			STATE_SYNC(error).msg_rcv_bad_payload,
			STATE_SYNC(error).msg_rcv_bad_type,
			STATE_SYNC(error).msg_rcv_truncated,
			STATE_SYNC(error).msg_rcv_bad_size,
			STATE_SYNC(error).msg_snd_malformed,
			(unsigned long long)STATE_SYNC(error).msg_rcv_lost,
			(unsigned long long)STATE_SYNC(error).msg_rcv_before);

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
		/* delete the reset alarm if any before committing */
		del_alarm(&STATE_SYNC(reset_cache_alarm));
		ret = fork();
		if (ret == 0) {
			dlog(LOG_NOTICE, "committing external cache");
			cache_commit(STATE_SYNC(external));
			exit(EXIT_SUCCESS);
		}
		break;
	case RESET_TIMERS:
		if (!alarm_pending(&STATE_SYNC(reset_cache_alarm))) {
			dlog(LOG_NOTICE, "flushing conntrack table in %d secs",
					 CONFIG(purge_timeout));
			add_alarm(&STATE_SYNC(reset_cache_alarm),
				  CONFIG(purge_timeout), 0);
		}
		break;
	case FLUSH_CACHE:
		/* inmediate flush, remove pending flush scheduled if any */
		del_alarm(&STATE_SYNC(reset_cache_alarm));
		dlog(LOG_NOTICE, "flushing caches");
		cache_flush(STATE_SYNC(internal));
		cache_flush(STATE_SYNC(external));
		break;
	case FLUSH_INT_CACHE:
		/* inmediate flush, remove pending flush scheduled if any */
		del_alarm(&STATE_SYNC(reset_cache_alarm));
		dlog(LOG_NOTICE, "flushing internal cache");
		cache_flush(STATE_SYNC(internal));
		break;
	case FLUSH_EXT_CACHE:
		dlog(LOG_NOTICE, "flushing external cache");
		cache_flush(STATE_SYNC(external));
		break;
	case KILL:
		killer(0);
		break;
	case STATS:
		cache_stats(STATE_SYNC(internal), fd);
		cache_stats(STATE_SYNC(external), fd);
		dump_traffic_stats(fd);
		multichannel_stats(STATE_SYNC(channel), fd);
		dump_stats_sync(fd);
		break;
	case STATS_NETWORK:
		dump_stats_sync_extended(fd);
		multichannel_stats(STATE_SYNC(channel), fd);
		break;
	case STATS_CACHE:
		cache_stats_extended(STATE_SYNC(internal), fd);
		cache_stats_extended(STATE_SYNC(external), fd);
		break;
	case STATS_MULTICAST:
		multichannel_stats_extended(STATE_SYNC(channel),
					    STATE_SYNC(interface), fd);
		break;
	default:
		if (STATE_SYNC(sync)->local)
			ret = STATE_SYNC(sync)->local(fd, type, data);
		break;
	}

	return ret;
}

static void sync_send(struct cache_object *obj, int query)
{
	STATE_SYNC(sync)->enqueue(obj, query);
}

static void dump_sync(struct nf_conntrack *ct)
{
	/* This is required by kernels < 2.6.20 */
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_USE);

	cache_update_force(STATE_SYNC(internal), ct);
}

static int purge_step(void *data1, void *data2)
{
	struct cache_object *obj = data2;

	STATE(get_retval) = 0;
	nl_get_conntrack(STATE(get), obj->ct);	/* modifies STATE(get_reval) */
	if (!STATE(get_retval)) {
		if (obj->status != C_OBJ_DEAD) {
			cache_object_set_status(obj, C_OBJ_DEAD);
			sync_send(obj, NET_T_STATE_DEL);
			cache_object_put(obj);
		}
	}

	return 0;
}

static int purge_sync(void)
{
	cache_iterate(STATE_SYNC(internal), NULL, purge_step);

	return 0;
}

static int resync_sync(enum nf_conntrack_msg_type type,
		       struct nf_conntrack *ct,
		       void *data)
{
	struct cache_object *obj;

	if (ct_filter_conntrack(ct, 1))
		return NFCT_CB_CONTINUE;

	/* This is required by kernels < 2.6.20 */
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_USE);

	obj = cache_update_force(STATE_SYNC(internal), ct);
	if (obj == NULL)
		return NFCT_CB_CONTINUE;

	switch (obj->status) {
	case C_OBJ_NEW:
		sync_send(obj, NET_T_STATE_NEW);
		break;
	case C_OBJ_ALIVE:
		sync_send(obj, NET_T_STATE_UPD);
		break;
	}
	return NFCT_CB_CONTINUE;
}

static void event_new_sync(struct nf_conntrack *ct)
{
	struct cache_object *obj;
	int id;

	/* required by linux kernel <= 2.6.20 */
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_PACKETS);

	obj = cache_find(STATE_SYNC(internal), ct, &id);
	if (obj == NULL) {
retry:
		obj = cache_object_new(STATE_SYNC(internal), ct);
		if (obj == NULL)
			return;
		if (cache_add(STATE_SYNC(internal), obj, id) == -1) {
			cache_object_free(obj);
			return;
		}
		sync_send(obj, NET_T_STATE_NEW);
	} else {
		cache_del(STATE_SYNC(internal), obj);
		cache_object_free(obj);
		goto retry;
	}
}

static void event_update_sync(struct nf_conntrack *ct)
{
	struct cache_object *obj;

	obj = cache_update_force(STATE_SYNC(internal), ct);
	if (obj == NULL)
		return;

	sync_send(obj, NET_T_STATE_UPD);
}

static int event_destroy_sync(struct nf_conntrack *ct)
{
	struct cache_object *obj;
	int id;

	obj = cache_find(STATE_SYNC(internal), ct, &id);
	if (obj == NULL)
		return 0;

	if (obj->status != C_OBJ_DEAD) {
		cache_object_set_status(obj, C_OBJ_DEAD);
		sync_send(obj, NET_T_STATE_DEL);
		cache_object_put(obj);
	}
	return 1;
}

struct ct_mode sync_mode = {
	.init 			= init_sync,
	.run			= run_sync,
	.local			= local_handler_sync,
	.kill			= kill_sync,
	.dump			= dump_sync,
	.resync			= resync_sync,
	.purge			= purge_sync,
	.event_new		= event_new_sync,
	.event_upd		= event_update_sync,
	.event_dst		= event_destroy_sync
};
