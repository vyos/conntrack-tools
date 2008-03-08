/*
 * (C) 2006-2008 by Pablo Neira Ayuso <pablo@netfilter.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
#include "sync.h"
#include "us-conntrack.h"
#include "queue.h"
#include "debug.h"
#include "network.h"
#include "alarm.h"
#include "log.h"
#include "cache.h"

#include <string.h>

#if 0 
#define dp printf
#else
#define dp(...)
#endif

static LIST_HEAD(rs_list);
static LIST_HEAD(tx_list);
static unsigned int tx_list_len;
static struct queue *rs_queue;
static struct queue *tx_queue;

struct cache_ftfw {
	struct list_head 	rs_list;
	struct list_head	tx_list;
	uint32_t 		seq;
};

static void cache_ftfw_add(struct us_conntrack *u, void *data)
{
	struct cache_ftfw *cn = data;
	/* These nodes are not inserted in the list */
	INIT_LIST_HEAD(&cn->rs_list);
	INIT_LIST_HEAD(&cn->tx_list);
}

static void cache_ftfw_del(struct us_conntrack *u, void *data)
{
	struct cache_ftfw *cn = data;

	/* this node is already out of the list */
	if (list_empty(&cn->rs_list))
	    	return;

	/* no need for list_del_init since the entry is destroyed */
	list_del(&cn->rs_list);
}

static struct cache_extra cache_ftfw_extra = {
	.size 		= sizeof(struct cache_ftfw),
	.add		= cache_ftfw_add,
	.destroy	= cache_ftfw_del
};

static void tx_queue_add_ctlmsg(uint32_t flags, uint32_t from, uint32_t to)
{
	struct nethdr_ack ack = {
		.flags = flags,
		.from  = from,
		.to    = to,
	};

	queue_add(tx_queue, &ack, NETHDR_ACK_SIZ);
}

static struct alarm_block alive_alarm;

static void do_alive_alarm(struct alarm_block *a, void *data)
{
	tx_queue_add_ctlmsg(NET_F_ALIVE, 0, 0);

	add_alarm(&alive_alarm, 1, 0);
}

static int ftfw_init(void)
{
	tx_queue = queue_create(CONFIG(resend_queue_size));
	if (tx_queue == NULL) {
		dlog(LOG_ERR, "cannot create tx queue");
		return -1;
	}

	rs_queue = queue_create(CONFIG(resend_queue_size));
	if (rs_queue == NULL) {
		dlog(LOG_ERR, "cannot create rs queue");
		return -1;
	}

	INIT_LIST_HEAD(&tx_list);
	INIT_LIST_HEAD(&rs_list);

	/* XXX: alive message expiration configurable */
	init_alarm(&alive_alarm, NULL, do_alive_alarm);
	add_alarm(&alive_alarm, 1, 0);

	return 0;
}

static void ftfw_kill(void)
{
	queue_destroy(rs_queue);
	queue_destroy(tx_queue);
}

static int do_cache_to_tx(void *data1, void *data2)
{
	struct us_conntrack *u = data2;
	struct cache_ftfw *cn = cache_get_extra(STATE_SYNC(internal), u);

	/* add to tx list */
	list_add(&cn->tx_list, &tx_list);
	tx_list_len++;

	return 0;
}

static int ftfw_local(int fd, int type, void *data)
{
	int ret = 1;

	switch(type) {
	case REQUEST_DUMP:
		dlog(LOG_NOTICE, "request resync");
		tx_queue_add_ctlmsg(NET_F_RESYNC, 0, 0);
		break;
	case SEND_BULK:
		dlog(LOG_NOTICE, "sending bulk update");
		cache_iterate(STATE_SYNC(internal), NULL, do_cache_to_tx);
		break;
	default:
		ret = 0;
		break;
	}

	return ret;
}

static int rs_queue_to_tx(void *data1, const void *data2)
{
	struct nethdr *net = data1;
	const struct nethdr_ack *nack = data2;

	if (between(net->seq, nack->from, nack->to)) {
		dp("rs_queue_to_tx sq: %u fl:%u len:%u\n",
			net->seq, net->flags, net->len);
		queue_add(tx_queue, net, net->len);
	}
	return 0;
}

static int rs_queue_empty(void *data1, const void *data2)
{
	struct nethdr *net = data1;
	const struct nethdr_ack *h = data2;

	if (between(net->seq, h->from, h->to)) {
		dp("remove from queue (seq=%u)\n", net->seq);
		queue_del(rs_queue, data1);
	}
	return 0;
}

static void rs_list_to_tx(struct cache *c, unsigned int from, unsigned int to)
{
	struct cache_ftfw *cn;

	list_for_each_entry(cn, &rs_list, rs_list) {
		struct us_conntrack *u;
		
		u = cache_get_conntrack(STATE_SYNC(internal), cn);
		if (between(cn->seq, from, to)) {
			dp("resending nack'ed (oldseq=%u)\n", cn->seq);
			list_add(&cn->tx_list, &tx_list);
			tx_list_len++;
		} 
	}
}

static void rs_list_empty(struct cache *c, unsigned int from, unsigned int to)
{
	struct cache_ftfw *cn, *tmp;

	list_for_each_entry_safe(cn, tmp, &rs_list, rs_list) {
		struct us_conntrack *u;

		u = cache_get_conntrack(STATE_SYNC(internal), cn);
		if (between(cn->seq, from, to)) {
			dp("queue: deleting from queue (seq=%u)\n", cn->seq);
			list_del_init(&cn->rs_list);
		} 
	}
}

static int ftfw_recv(const struct nethdr *net)
{
	static unsigned int window = 0;
	unsigned int exp_seq;

	if (window == 0)
		window = CONFIG(window_size);

	if (!mcast_track_seq(net->seq, &exp_seq)) {
		dp("OOS: sending nack (seq=%u)\n", exp_seq);
		tx_queue_add_ctlmsg(NET_F_NACK, exp_seq, net->seq-1);
		window = CONFIG(window_size);
	} else {
		/* received a window, send an acknowledgement */
		if (--window == 0) {
			dp("sending ack (seq=%u)\n", net->seq);
			tx_queue_add_ctlmsg(NET_F_ACK, 
					    net->seq - CONFIG(window_size), 
					    net->seq);
		}
	}

	if (IS_NACK(net)) {
		const struct nethdr_ack *nack = (const struct nethdr_ack *) net;

		dp("NACK: from seq=%u to seq=%u\n", nack->from, nack->to);
		rs_list_to_tx(STATE_SYNC(internal), nack->from, nack->to);
		queue_iterate(rs_queue, nack, rs_queue_to_tx);
		return 1;
	} else if (IS_RESYNC(net)) {
		dp("RESYNC ALL\n");
		cache_iterate(STATE_SYNC(internal), NULL, do_cache_to_tx);
		return 1;
	} else if (IS_ACK(net)) {
		const struct nethdr_ack *h = (const struct nethdr_ack *) net;

		dp("ACK: from seq=%u to seq=%u\n", h->from, h->to);
		rs_list_empty(STATE_SYNC(internal), h->from, h->to);
		queue_iterate(rs_queue, h, rs_queue_empty);
		return 1;
	} else if (IS_ALIVE(net))
		return 1;

	return 0;
}

static void ftfw_send(struct nethdr *net, struct us_conntrack *u)
{
	struct netpld *pld = NETHDR_DATA(net);
	struct cache_ftfw *cn;

	HDR_NETWORK2HOST(net);

	switch(ntohs(pld->query)) {
	case NFCT_Q_CREATE:
	case NFCT_Q_UPDATE:
		cn = (struct cache_ftfw *) 
			cache_get_extra(STATE_SYNC(internal), u);

		if (!list_empty(&cn->rs_list))
			list_del(&cn->rs_list);

		cn->seq = net->seq;
		list_add(&cn->rs_list, &rs_list);
		break;
	case NFCT_Q_DESTROY:
		queue_add(rs_queue, net, net->len);
		break;
	}
}

static int tx_queue_xmit(void *data1, const void *data2)
{
	struct nethdr *net = data1;
	size_t len = prepare_send_netmsg(STATE_SYNC(mcast_client), net);

	dp("tx_queue sq: %u fl:%u len:%u\n",
               ntohl(net->seq), ntohs(net->flags), ntohs(net->len));

	mcast_buffered_send_netmsg(STATE_SYNC(mcast_client), net, len);
	HDR_NETWORK2HOST(net);

	if (IS_DATA(net) || IS_ACK(net) || IS_NACK(net)) {
		dp("-> back_to_tx_queue sq: %u fl:%u len:%u\n",
        	       net->seq, net->flags, net->len);
		queue_add(rs_queue, net, net->len);
	}
	queue_del(tx_queue, net);

	return 0;
}

static int tx_list_xmit(struct list_head *i, struct us_conntrack *u)
{
	int ret;
	struct nethdr *net = BUILD_NETMSG(u->ct, NFCT_Q_UPDATE);
	size_t len = prepare_send_netmsg(STATE_SYNC(mcast_client), net);

	dp("tx_list sq: %u fl:%u len:%u\n",
                ntohl(net->seq), ntohs(net->flags),
                ntohs(net->len));

	list_del_init(i);
	tx_list_len--;

	ret = mcast_buffered_send_netmsg(STATE_SYNC(mcast_client), net, len);
	if (STATE_SYNC(sync)->send)
		STATE_SYNC(sync)->send(net, u);

	return ret;
}

static void ftfw_run(void)
{
	struct cache_ftfw *cn, *tmp;

	/* send messages in the tx_queue */
	queue_iterate(tx_queue, NULL, tx_queue_xmit);

	/* send conntracks in the tx_list */
	list_for_each_entry_safe(cn, tmp, &tx_list, tx_list) {
		struct us_conntrack *u;

		u = cache_get_conntrack(STATE_SYNC(internal), cn);
		tx_list_xmit(&cn->tx_list, u);
	}
}

struct sync_mode sync_ftfw = {
	.internal_cache_flags	= LIFETIME,
	.external_cache_flags	= LIFETIME,
	.internal_cache_extra	= &cache_ftfw_extra,
	.init			= ftfw_init,
	.kill			= ftfw_kill,
	.local			= ftfw_local,
	.recv			= ftfw_recv,
	.send			= ftfw_send,
	.run			= ftfw_run,
};
