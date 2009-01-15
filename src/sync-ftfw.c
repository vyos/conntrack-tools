/*
 * (C) 2006-2008 by Pablo Neira Ayuso <pablo@netfilter.org>
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
#include "queue.h"
#include "debug.h"
#include "network.h"
#include "alarm.h"
#include "log.h"
#include "cache.h"
#include "fds.h"

#include <string.h>

#if 0 
#define dp printf
#else
#define dp(...)
#endif

struct queue *tx_queue;
struct queue *rs_queue;
static uint32_t exp_seq;
static uint32_t window;
static uint32_t ack_from;
static int ack_from_set = 0;
static struct alarm_block alive_alarm;

enum {
	HELLO_INIT,
	HELLO_SAY,
	HELLO_DONE,
};
static int hello_state = HELLO_INIT;
static int say_hello_back;

/* XXX: alive message expiration configurable */
#define ALIVE_INT 1

struct cache_ftfw {
	struct queue_node	qnode;
	uint32_t 		seq;
};

static void cache_ftfw_add(struct cache_object *obj, void *data)
{
	struct cache_ftfw *cn = data;
	/* These nodes are not inserted in the list */
	queue_node_init(&cn->qnode, Q_ELEM_OBJ);
}

static void cache_ftfw_del(struct cache_object *obj, void *data)
{
	struct cache_ftfw *cn = data;
	queue_del(&cn->qnode);
}

static struct cache_extra cache_ftfw_extra = {
	.size 		= sizeof(struct cache_ftfw),
	.add		= cache_ftfw_add,
	.destroy	= cache_ftfw_del
};

static void tx_queue_add_ctlmsg(uint32_t flags, uint32_t from, uint32_t to)
{
	struct queue_object *qobj;
	struct nethdr_ack *ack;

	qobj = queue_object_new(Q_ELEM_CTL, sizeof(struct nethdr_ack));
	if (qobj == NULL)
		return;

	ack		= (struct nethdr_ack *)qobj->data;
	ack->type 	= NET_T_CTL;
	ack->flags	= flags;
	ack->from	= from;
	ack->to		= to;

	switch(hello_state) {
	case HELLO_INIT:
		hello_state = HELLO_SAY;
		/* fall through */
	case HELLO_SAY:
		ack->flags |= NET_F_HELLO;
		break;
	}

	if (say_hello_back) {
		ack->flags |= NET_F_HELLO_BACK;
		say_hello_back = 0;
	}

	queue_add(tx_queue, &qobj->qnode);
}

static void tx_queue_add_ctlmsg2(uint32_t flags)
{
	struct queue_object *qobj;
	struct nethdr *ctl;

	qobj = queue_object_new(Q_ELEM_CTL, sizeof(struct nethdr_ack));
	if (qobj == NULL)
		return;

	ctl		= (struct nethdr *)qobj->data;
	ctl->type 	= NET_T_CTL;
	ctl->flags	= flags;

	switch(hello_state) {
	case HELLO_INIT:
		hello_state = HELLO_SAY;
		/* fall through */
	case HELLO_SAY:
		ctl->flags |= NET_F_HELLO;
		break;
	}

	if (say_hello_back) {
		ctl->flags |= NET_F_HELLO_BACK;
		say_hello_back = 0;
	}

	queue_add(tx_queue, &qobj->qnode);
}

/* this function is called from the alarm framework */
static void do_alive_alarm(struct alarm_block *a, void *data)
{
	if (ack_from_set && mcast_track_is_seq_set()) {
		/* exp_seq contains the last update received */
		tx_queue_add_ctlmsg(NET_F_ACK,
				    ack_from,
				    STATE_SYNC(last_seq_recv));
		ack_from_set = 0;
	} else
		tx_queue_add_ctlmsg2(NET_F_ALIVE);

	add_alarm(&alive_alarm, ALIVE_INT, 0);
}

static int ftfw_init(void)
{
	tx_queue = queue_create(INT_MAX, QUEUE_F_EVFD);
	if (tx_queue == NULL) {
		dlog(LOG_ERR, "cannot create tx queue");
		return -1;
	}
	rs_queue = queue_create(INT_MAX, 0);
	if (rs_queue == NULL) {
		dlog(LOG_ERR, "cannot create rs queue");
		return -1;
	}

	init_alarm(&alive_alarm, NULL, do_alive_alarm);
	add_alarm(&alive_alarm, ALIVE_INT, 0);

	/* set ack window size */
	window = CONFIG(window_size);

	return 0;
}

static void ftfw_kill(void)
{
	queue_destroy(rs_queue);
	queue_destroy(tx_queue);
}

static int do_cache_to_tx(void *data1, void *data2)
{
	struct cache_object *obj = data2;
	struct cache_ftfw *cn = cache_get_extra(STATE_SYNC(internal), obj);

	if (queue_in(rs_queue, &cn->qnode))
		queue_del(&cn->qnode);

	queue_add(tx_queue, &cn->qnode);

	return 0;
}

static int rs_queue_dump(struct queue_node *n, const void *data2)
{
	const int *fd = data2;
	char buf[512];
	int size;

	switch(n->type) {
		case Q_ELEM_CTL: {
			struct nethdr *net = queue_node_data(n);
			size = sprintf(buf, "control -> seq:%u flags:%u\n",
					    net->seq, net->flags);
			break;
		}
		case Q_ELEM_OBJ: {
			struct cache_ftfw *cn = (struct cache_ftfw *) n;
			size = sprintf(buf, "object -> seq:%u\n", cn->seq);
		break;
		}
		default:
			return 0;
	}
	send(*fd, buf, size, 0);
	return 0;
}

static void debug_rs_dump(int fd)
{
	char buf[512];
	int size;

	size = sprintf(buf, "resent queue (len=%u):\n", queue_len(rs_queue));
	send(fd, buf, size, 0);
	queue_iterate(rs_queue, &fd, rs_queue_dump);
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
	case DEBUG_INFO:
		debug_rs_dump(fd);
		break;
	default:
		ret = 0;
		break;
	}

	return ret;
}

static int rs_queue_to_tx(struct queue_node *n, const void *data)
{
	const struct nethdr_ack *nack = data;

	switch(n->type) {
	case Q_ELEM_CTL: {
		struct nethdr_ack *net = queue_node_data(n);

		if (before(net->seq, nack->from))
			return 0;	/* continue */
		else if (after(net->seq, nack->to))
			return 1;	/* break */

		dp("rs_queue_to_tx sq: %u fl:%u len:%u\n",
			net->seq, net->flags, net->len);

		queue_del(n);
		queue_add(tx_queue, n);
		break;
	}
	case Q_ELEM_OBJ: {
		struct cache_ftfw *cn;

		cn = (struct cache_ftfw *) n;
		if (before(cn->seq, nack->from))
			return 0;
		else if (after(cn->seq, nack->to))
			return 1;

		dp("resending nack'ed (oldseq=%u)\n", cn->seq);

		queue_del(n);
		queue_add(tx_queue, n);
		break;
	}
	}
	return 0;
}

static int rs_queue_empty(struct queue_node *n, const void *data)
{
	const struct nethdr_ack *h = data;

	if (h == NULL) {
		dp("inconditional remove from queue (seq=%u)\n", net->seq);
		queue_del(n);
		return 0;
	}

	switch(n->type) {
	case Q_ELEM_CTL: {
		struct nethdr_ack *net = queue_node_data(n);

		if (before(net->seq, h->from))
			return 0;	/* continue */
		else if (after(net->seq, h->to))
			return 1;	/* break */

		dp("remove from queue (seq=%u)\n", net->seq);
		queue_del(n);
		queue_object_free((struct queue_object *)n);
		break;
	}
	case Q_ELEM_OBJ: {
		struct cache_ftfw *cn;

		cn = (struct cache_ftfw *) n;
		if (before(cn->seq, h->from))
			return 0;
		else if (after(cn->seq, h->to))
			return 1;

		dp("queue: deleting from queue (seq=%u)\n", cn->seq);
		queue_del(n);
		break;
	}
	}
	return 0;
}

static int digest_msg(const struct nethdr *net)
{
	if (IS_DATA(net))
		return MSG_DATA;

	else if (IS_ACK(net)) {
		const struct nethdr_ack *h = (const struct nethdr_ack *) net;

		if (before(h->to, h->from))
			return MSG_BAD;

		queue_iterate(rs_queue, h, rs_queue_empty);
		return MSG_CTL;

	} else if (IS_NACK(net)) {
		const struct nethdr_ack *nack = (const struct nethdr_ack *) net;

		if (before(nack->to, nack->from))
			return MSG_BAD;

		queue_iterate(rs_queue, nack, rs_queue_to_tx);
		return MSG_CTL;

	} else if (IS_RESYNC(net)) {
		dp("RESYNC ALL\n");
		cache_iterate(STATE_SYNC(internal), NULL, do_cache_to_tx);
		return MSG_CTL;

	} else if (IS_ALIVE(net))
		return MSG_CTL;

	return MSG_BAD;
}

static int digest_hello(const struct nethdr *net)
{
	int ret = 0;

	if (IS_HELLO(net)) {
		say_hello_back = 1;
		ret = 1;
	}
	if (IS_HELLO_BACK(net)) {
		/* this is a hello back for a requested hello */
		if (hello_state == HELLO_SAY)
			hello_state = HELLO_DONE;
	}

	return ret;
}

static int ftfw_recv(const struct nethdr *net)
{
	int ret = MSG_DATA;

	if (digest_hello(net)) {
		/* we have received a hello while we had data to acknowledge.
		 * reset the window, the other doesn't know anthing about it. */
		if (ack_from_set && before(net->seq, ack_from)) {
			window = CONFIG(window_size) - 1;
			ack_from = net->seq;
		}

		/* XXX: flush the resend queues since the other does not 
		 * know anything about that data, we are unreliable until 
		 * the helloing finishes */
		queue_iterate(rs_queue, NULL, rs_queue_empty);

		goto bypass;
	}

	switch (mcast_track_seq(net->seq, &exp_seq)) {
	case SEQ_AFTER:
		ret = digest_msg(net);
		if (ret == MSG_BAD) {
			ret = MSG_BAD;
			goto out;
		}

		if (ack_from_set) {
			tx_queue_add_ctlmsg(NET_F_ACK, ack_from, exp_seq-1);
			ack_from_set = 0;
		}

		tx_queue_add_ctlmsg(NET_F_NACK, exp_seq, net->seq-1);

		/* count this message as part of the new window */
		window = CONFIG(window_size) - 1;
		ack_from = net->seq;
		ack_from_set = 1;
		break;

	case SEQ_BEFORE:
		/* we don't accept delayed packets */
		ret = MSG_DROP;
		break;

	case SEQ_UNSET:
	case SEQ_IN_SYNC:
bypass:
		ret = digest_msg(net);
		if (ret == MSG_BAD) {
			ret = MSG_BAD;
			goto out;
		}

		if (!ack_from_set) {
			ack_from_set = 1;
			ack_from = net->seq;
		}

		if (--window <= 0) {
			/* received a window, send an acknowledgement */
			tx_queue_add_ctlmsg(NET_F_ACK, ack_from, net->seq);
			window = CONFIG(window_size);
			ack_from_set = 0;
		}
	}

out:
	if ((ret == MSG_DATA || ret == MSG_CTL))
		mcast_track_update_seq(net->seq);

	return ret;
}

static void ftfw_send(struct nethdr *net, struct cache_object *obj)
{
	struct cache_ftfw *cn;

	switch(net->type) {
	case NET_T_STATE_NEW:
	case NET_T_STATE_UPD:
	case NET_T_STATE_DEL:
		cn = (struct cache_ftfw *) 
			cache_get_extra(STATE_SYNC(internal), obj);

		if (queue_in(rs_queue, &cn->qnode))
			queue_del(&cn->qnode);

		switch(hello_state) {
		case HELLO_INIT:
			hello_state = HELLO_SAY;
			/* fall through */
		case HELLO_SAY:
			net->flags |= NET_F_HELLO;
			break;
		}

		if (say_hello_back) {
			net->flags |= NET_F_HELLO_BACK;
			say_hello_back = 0;
		}

		cn->seq = ntohl(net->seq);
		queue_add(rs_queue, &cn->qnode);
		break;
	}
}

static int tx_queue_xmit(struct queue_node *n, const void *data)
{
	switch(n->type) {
	case Q_ELEM_CTL: {
		struct nethdr *net = queue_node_data(n);

		if (IS_ACK(net) || IS_NACK(net) || IS_RESYNC(net)) {
			nethdr_set_ack(net);
		} else if (IS_ALIVE(net)) {
			nethdr_set_ctl(net);
		} else {
			STATE_SYNC(error).msg_snd_malformed++;
			return 0;
		}
		HDR_HOST2NETWORK(net);

		dp("tx_queue sq: %u fl:%u len:%u\n",
	               ntohl(net->seq), net->flags, ntohs(net->len));

		mcast_buffered_send_netmsg(STATE_SYNC(mcast_client), net);
		HDR_NETWORK2HOST(net);

		queue_del(n);
		if (IS_ACK(net) || IS_NACK(net) || IS_RESYNC(net))
			queue_add(rs_queue, n);
		else
			queue_object_free((struct queue_object *)n);
		break;
	}
	case Q_ELEM_OBJ: {
		struct cache_ftfw *cn;
		struct cache_object *obj;
		int type;
		struct nethdr *net;

		cn = (struct cache_ftfw *)n;
		obj = cache_data_get_object(STATE_SYNC(internal), cn);
		type = object_status_to_network_type(obj->status);
		net = BUILD_NETMSG(obj->ct, type);

		dp("tx_list sq: %u fl:%u len:%u\n",
	                ntohl(net->seq), net->flags, ntohs(net->len));

		queue_del(n);
		mcast_buffered_send_netmsg(STATE_SYNC(mcast_client), net);
		ftfw_send(net, obj);
		break;
	}
	}

	return 0;
}

static void ftfw_run(fd_set *readfds)
{
	if (FD_ISSET(queue_get_eventfd(tx_queue), readfds)) {
		queue_iterate(tx_queue, NULL, tx_queue_xmit);
		add_alarm(&alive_alarm, 1, 0);
		dp("tx_queue_len:%u rs_queue_len:%u\n",
		   queue_len(tx_queue), queue_len(rs_queue));
	}
}

static int ftfw_register_fds(struct fds *fds)
{
	return register_fd(queue_get_eventfd(tx_queue), fds);
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
	.register_fds		= ftfw_register_fds,
};
