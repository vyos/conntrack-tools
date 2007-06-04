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

#include <errno.h>
#include "conntrackd.h"
#include "sync.h"
#include "linux_list.h"
#include "us-conntrack.h"
#include "buffer.h"
#include "debug.h"
#include "network.h"
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#if 0 
#define dp printf
#else
#define dp
#endif

static LIST_HEAD(queue);

struct cache_nack {
	struct list_head 	head;
	u_int32_t 		seq;
};

static void cache_nack_add(struct us_conntrack *u, void *data)
{
	struct cache_nack *cn = data;
	INIT_LIST_HEAD(&cn->head);
}

static void cache_nack_del(struct us_conntrack *u, void *data)
{
	struct cache_nack *cn = data;

	if (cn->head.next == &cn->head &&
	    cn->head.prev == &cn->head)
	    	return;

	list_del(&cn->head);
}

static struct cache_extra cache_nack_extra = {
	.size 		= sizeof(struct cache_nack),
	.add		= cache_nack_add,
	.destroy	= cache_nack_del
};

static int nack_init()
{
	STATE_SYNC(buffer) = buffer_create(CONFIG(resend_buffer_size));
	if (STATE_SYNC(buffer) == NULL)
		return -1;

	return 0;
}

static void nack_kill()
{
	buffer_destroy(STATE_SYNC(buffer));
}

static void mcast_send_nack(u_int32_t expt_seq, u_int32_t recv_seq)
{
	struct nlnetwork_ack nack = {
		.flags = NET_NACK,
		.from  = expt_seq,
		.to    = recv_seq,
	};

	mcast_send_error(STATE_SYNC(mcast_client), &nack);
	buffer_add(STATE_SYNC(buffer), &nack, sizeof(struct nlnetwork_ack));
}

static void mcast_send_ack(u_int32_t from, u_int32_t to)
{
	struct nlnetwork_ack ack = {
		.flags = NET_ACK,
		.from   = from,
		.to	= to,
	};

	mcast_send_error(STATE_SYNC(mcast_client), &ack);
	buffer_add(STATE_SYNC(buffer), &ack, sizeof(struct nlnetwork_ack));
}

static void mcast_send_resync()
{
	struct nlnetwork net = {
		.flags = NET_RESYNC,
	};

	mcast_send_error(STATE_SYNC(mcast_client), &net);
	buffer_add(STATE_SYNC(buffer), &net, sizeof(struct nlnetwork));
}

int nack_local(int fd, int type, void *data)
{
	int ret = 1;

	switch(type) {
		case REQUEST_DUMP:
			mcast_send_resync();
			dlog(STATE(log), "[REQ] request resync");
			break;
		default:
			ret = 0;
			break;
	}

	return ret;
}

static int buffer_compare(void *data1, void *data2)
{
	struct nlnetwork *net = data1;
	struct nlnetwork_ack *nack = data2;
	struct nlmsghdr *nlh = data1 + sizeof(struct nlnetwork);

	unsigned old_seq = ntohl(net->seq);

	if (between(ntohl(net->seq), nack->from, nack->to)) {
		if (mcast_resend_netmsg(STATE_SYNC(mcast_client), net))
			dp("resend destroy (old seq=%u) (seq=%u)\n", 
			   old_seq, ntohl(net->seq));
	}
	return 0;
}

static int buffer_remove(void *data1, void *data2)
{
	struct nlnetwork *net = data1;
	struct nlnetwork_ack *h = data2;

	if (between(ntohl(net->seq), h->from, h->to)) {
		dp("remove from buffer (seq=%u)\n", ntohl(net->seq));
		__buffer_del(STATE_SYNC(buffer), data1);
	}
	return 0;
}

static void queue_resend(struct cache *c, unsigned int from, unsigned int to)
{
	struct list_head *n;
	struct us_conntrack *u;
	unsigned int *seq;

	lock();
	list_for_each(n, &queue) {
		struct cache_nack *cn = (struct cache_nack *) n;
		struct us_conntrack *u;
		
		u = cache_get_conntrack(STATE_SYNC(internal), cn);

		if (between(cn->seq, from, to)) {
			debug_ct(u->ct, "resend nack");
			dp("resending nack'ed (oldseq=%u) ", cn->seq);

			char buf[4096];
			struct nlnetwork *net = (struct nlnetwork *) buf;

			int ret = build_network_msg(NFCT_Q_UPDATE,
						    STATE(subsys_event),
						    u->ct,
						    buf,
						    sizeof(buf));
			if (ret == -1) {
				unlock();
				break;
			}

			mcast_send_netmsg(STATE_SYNC(mcast_client), buf);
			if (STATE_SYNC(sync)->send)
				STATE_SYNC(sync)->send(NFCT_T_UPDATE, net, u);
			dp("(newseq=%u)\n", *seq);
		} 
	}
	unlock();
}

static void queue_empty(struct cache *c, unsigned int from, unsigned int to)
{
	struct list_head *n, *tmp;
	struct us_conntrack *u;
	unsigned int *seq;

	lock();
	dp("ACK from %u to %u\n", from, to);
	list_for_each_safe(n, tmp, &queue) {
		struct cache_nack *cn = (struct cache_nack *) n;

		u = cache_get_conntrack(STATE_SYNC(internal), cn);
		if (between(cn->seq, from, to)) {
			dp("remove %u\n", cn->seq);
			debug_ct(u->ct, "ack received: empty queue");
			dp("queue: deleting from queue (seq=%u)\n", cn->seq);
			list_del(&cn->head);
			INIT_LIST_HEAD(&cn->head);
		} 
	}
	unlock();
}

static int nack_recv(const struct nlnetwork *net)
{
	static unsigned int window = 0;
	unsigned int exp_seq;

	if (window == 0)
		window = CONFIG(window_size);

	if (!mcast_track_seq(net->seq, &exp_seq)) {
		dp("OOS: sending nack (seq=%u)\n", exp_seq);
		mcast_send_nack(exp_seq, net->seq - 1);
		window = CONFIG(window_size);
	} else {
		/* received a window, send an acknowledgement */
		if (--window == 0) {
			dp("sending ack (seq=%u)\n", net->seq);
			mcast_send_ack(net->seq-CONFIG(window_size), net->seq);
		}
	}

	if (net->flags & NET_NACK) {
		struct nlnetwork_ack *nack = (struct nlnetwork_ack *) net;

		dp("NACK: from seq=%u to seq=%u\n", nack->from, nack->to);
		queue_resend(STATE_SYNC(internal), nack->from, nack->to);
		buffer_iterate(STATE_SYNC(buffer), nack, buffer_compare);
		return 1;
	} else if (net->flags & NET_RESYNC) {
		dp("RESYNC ALL\n");
		cache_bulk(STATE_SYNC(internal));
		return 1;
	} else if (net->flags & NET_ACK) {
		struct nlnetwork_ack *h = (struct nlnetwork_ack *) net;

		dp("ACK: from seq=%u to seq=%u\n", h->from, h->to);
		queue_empty(STATE_SYNC(internal), h->from, h->to);
		buffer_iterate(STATE_SYNC(buffer), h, buffer_remove);
		return 1;
	}

	return 0;
}

static void nack_send(int type, 
		      const struct nlnetwork *net,
		      struct us_conntrack *u)
{
	unsigned int size = sizeof(struct nlnetwork); 
 	struct nlmsghdr *nlh = (struct nlmsghdr *) ((void *) net + size);
	struct cache_nack *cn;
 
	size += ntohl(nlh->nlmsg_len);

	switch(type) {
	case NFCT_T_NEW:
	case NFCT_T_UPDATE:
		cn = (struct cache_nack *) 
			cache_get_extra(STATE_SYNC(internal), u);

		if (cn->head.next == &cn->head &&
		    cn->head.prev == &cn->head)
		    	goto insert;

		list_del(&cn->head);
		INIT_LIST_HEAD(&cn->head);
insert:
		cn->seq = ntohl(net->seq);
		list_add(&cn->head, &queue);
		break;
	case NFCT_T_DESTROY:
		buffer_add(STATE_SYNC(buffer), net, size);
		break;
	}
}

struct sync_mode nack = {
	.internal_cache_flags	= LIFETIME,
	.external_cache_flags	= LIFETIME,
	.internal_cache_extra	= &cache_nack_extra,
	.init			= nack_init,
	.kill			= nack_kill,
	.local			= nack_local,
	.recv			= nack_recv,
	.send			= nack_send,
};
