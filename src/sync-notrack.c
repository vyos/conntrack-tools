/*
 * (C) 2008 by Pablo Neira Ayuso <pablo@netfilter.org>
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
#include "sync.h"
#include "us-conntrack.h"
#include "queue.h"
#include "debug.h"
#include "network.h"
#include "log.h"
#include "cache.h"
#include "event.h"

#include <string.h>

static LIST_HEAD(tx_list);
static unsigned int tx_list_len;
static struct queue *tx_queue;

struct cache_notrack {
	struct list_head	tx_list;
};

static struct cache_extra cache_notrack_extra = {
	.size 		= sizeof(struct cache_notrack),
};

static void tx_queue_add_ctlmsg(uint32_t flags, uint32_t from, uint32_t to)
{
	struct nethdr_ack ack = {
		.flags = flags,
		.from  = from,
		.to    = to,
	};

	queue_add(tx_queue, &ack, NETHDR_ACK_SIZ);
	write_evfd(STATE_SYNC(evfd));
}

static int notrack_init(void)
{
	tx_queue = queue_create(~0U);
	if (tx_queue == NULL) {
		dlog(LOG_ERR, "cannot create tx queue");
		return -1;
	}

	return 0;
}

static void notrack_kill(void)
{
	queue_destroy(tx_queue);
}

static int do_cache_to_tx(void *data1, void *data2)
{
	struct us_conntrack *u = data2;
	struct cache_notrack *cn = cache_get_extra(STATE_SYNC(internal), u);

	/* add to tx list */
	list_add_tail(&cn->tx_list, &tx_list);
	tx_list_len++;

	write_evfd(STATE_SYNC(evfd));

	return 0;
}

static int notrack_local(int fd, int type, void *data)
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

static int digest_msg(const struct nethdr *net)
{
	if (IS_DATA(net))
		return MSG_DATA;

	if (IS_RESYNC(net)) {
		cache_iterate(STATE_SYNC(internal), NULL, do_cache_to_tx);
		return MSG_CTL;
	}

	return MSG_BAD;
}

static int notrack_recv(const struct nethdr *net)
{
	int ret;
	unsigned int exp_seq;

	mcast_track_seq(net->seq, &exp_seq);

	ret = digest_msg(net);

	if (ret != MSG_BAD)
		mcast_track_update_seq(net->seq);

	return ret;
}

static int tx_queue_xmit(void *data1, const void *data2)
{
	struct nethdr *net = data1;
	size_t len = prepare_send_netmsg(STATE_SYNC(mcast_client), net);

	mcast_buffered_send_netmsg(STATE_SYNC(mcast_client), net, len);
	queue_del(tx_queue, net);

	return 0;
}

static int tx_list_xmit(struct list_head *i, struct us_conntrack *u, int type)
{
	int ret;
	struct nethdr *net = BUILD_NETMSG(u->ct, type);
	size_t len = prepare_send_netmsg(STATE_SYNC(mcast_client), net);

	list_del_init(i);
	tx_list_len--;

	ret = mcast_buffered_send_netmsg(STATE_SYNC(mcast_client), net, len);

	return ret;
}

static void notrack_run(void)
{
	struct cache_notrack *cn, *tmp;

	/* send messages in the tx_queue */
	queue_iterate(tx_queue, NULL, tx_queue_xmit);

	/* send conntracks in the tx_list */
	list_for_each_entry_safe(cn, tmp, &tx_list, tx_list) {
		struct us_conntrack *u;

		u = cache_get_conntrack(STATE_SYNC(internal), cn);
		tx_list_xmit(&cn->tx_list, u, NFCT_Q_UPDATE);
	}
}

struct sync_mode sync_notrack = {
	.internal_cache_flags	= LIFETIME,
	.external_cache_flags	= LIFETIME,
	.internal_cache_extra	= &cache_notrack_extra,
	.init			= notrack_init,
	.kill			= notrack_kill,
	.local			= notrack_local,
	.recv			= notrack_recv,
	.run			= notrack_run,
};
