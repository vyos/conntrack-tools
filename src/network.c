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

#include "conntrackd.h"
#include "network.h"
#include "log.h"
#include "debug.h"

#include <stdlib.h>
#include <time.h>
#include <string.h>

static unsigned int seq_set, cur_seq;

static size_t __do_send(struct mcast_sock *m, void *data, size_t len)
{
	struct nethdr *net = data;

#undef _TEST_DROP
#ifdef _TEST_DROP

#define DROP_RATE .25

	/* simulate message omission with a certain probability */
	if ((random() & 0x7FFFFFFF) < 0x80000000 * DROP_RATE) {
		printf("drop sq: %u fl:%u len:%u\n",
			ntohl(net->seq), ntohs(net->flags),
			ntohs(net->len));
		return 0;
	}
#endif
	debug("send sq: %u fl:%u len:%u\n",
		ntohl(net->seq), ntohs(net->flags),
		ntohs(net->len));

	return mcast_send(m, net, len);
}

static size_t __do_prepare(struct mcast_sock *m, void *data, size_t len)
{
	struct nethdr *net = data;

	if (!seq_set) {
		seq_set = 1;
		cur_seq = time(NULL);
	}
	net->len = len;
	net->seq = cur_seq++;
	HDR_HOST2NETWORK(net);

	return len;
}

static size_t __prepare_ctl(struct mcast_sock *m, void *data)
{
	return __do_prepare(m, data, NETHDR_ACK_SIZ);
}

static size_t __prepare_data(struct mcast_sock *m, void *data)
{
	struct nethdr *net = (struct nethdr *) data;
	struct netpld *pld = NETHDR_DATA(net);

	return __do_prepare(m, data, ntohs(pld->len) + NETPLD_SIZ + NETHDR_SIZ);
}

size_t prepare_send_netmsg(struct mcast_sock *m, void *data)
{
	int ret = 0;
	struct nethdr *net = (struct nethdr *) data;

	if (IS_DATA(net))
		ret = __prepare_data(m, data);
	else if (IS_CTL(net))
		ret = __prepare_ctl(m, data);

	return ret;
}

static size_t tx_buflenmax;
static size_t tx_buflen = 0;
static char *tx_buf;

#define HEADERSIZ 28 /* IP header (20 bytes) + UDP header 8 (bytes) */

int mcast_buffered_init(struct mcast_conf *mconf)
{
	int mtu = mconf->mtu - HEADERSIZ;

	/* default to Ethernet MTU 1500 bytes */
	if (mconf->mtu == 0)
		mtu = 1500 - HEADERSIZ;

	tx_buf = malloc(mtu);
	if (tx_buf == NULL)
		return -1;

	tx_buflenmax = mtu;

	return 0;
}

void mcast_buffered_destroy(void)
{
	free(tx_buf);
}

/* return 0 if it is not sent, otherwise return 1 */
int mcast_buffered_send_netmsg(struct mcast_sock *m, void *data, size_t len)
{
	int ret = 0;
	struct nethdr *net = data;

retry:
	if (tx_buflen + len < tx_buflenmax) {
		memcpy(tx_buf + tx_buflen, net, len);
		tx_buflen += len;
	} else {
		__do_send(m, tx_buf, tx_buflen);
		ret = 1;
		tx_buflen = 0;
		goto retry;
	}

	return ret;
}

ssize_t mcast_buffered_pending_netmsg(struct mcast_sock *m)
{
	ssize_t ret;

	if (tx_buflen == 0)
		return 0;

	ret = __do_send(m, tx_buf, tx_buflen);
	tx_buflen = 0;

	return ret;
}

int mcast_send_netmsg(struct mcast_sock *m, void *data)
{
	int ret;
	size_t len = prepare_send_netmsg(m, data);

	ret = mcast_buffered_send_netmsg(m, data, len);
	mcast_buffered_pending_netmsg(m);

	return ret;
}

void build_netmsg(struct nf_conntrack *ct, int query, struct nethdr *net)
{
	struct netpld *pld = NETHDR_DATA(net);

	build_netpld(ct, pld, query);
}

int handle_netmsg(struct nethdr *net)
{
	struct netpld *pld = NETHDR_DATA(net);

	/* message too small: no room for the header */
	if (ntohs(net->len) < NETHDR_ACK_SIZ)
		return -1;

	HDR_NETWORK2HOST(net);

	if (IS_CTL(net))
		return 0;

	/* information received is too small */
	if (net->len < sizeof(struct netpld))
		return -1;

	/* size mismatch! */
	if (net->len < ntohs(pld->len) + NETHDR_SIZ)
		return -1;

	return 0;
}

static int local_seq_set = 0;

/* this function only tracks, it does not update the last sequence received */
int mcast_track_seq(uint32_t seq, uint32_t *exp_seq)
{
	int ret = SEQ_UNKNOWN;

	/* netlink sequence tracking initialization */
	if (!local_seq_set) {
		ret = SEQ_UNSET;
		goto out;
	}

	/* fast path: we received the correct sequence */
	if (seq == STATE_SYNC(last_seq_recv)+1) {
		ret = SEQ_IN_SYNC;
		goto out;
	}

	/* out of sequence: some messages got lost */
	if (after(seq, STATE_SYNC(last_seq_recv)+1)) {
		STATE_SYNC(packets_lost) += seq-STATE_SYNC(last_seq_recv)+1;
		ret = SEQ_AFTER;
		goto out;
	}

	/* out of sequence: replayed/delayed packet? */
	if (before(seq, STATE_SYNC(last_seq_recv)+1))
		ret = SEQ_BEFORE;

out:
	*exp_seq = STATE_SYNC(last_seq_recv)+1;

	return ret;
}

void mcast_track_update_seq(uint32_t seq)
{
	if (!local_seq_set)
		local_seq_set = 1;

	STATE_SYNC(last_seq_recv) = seq;
}

int mcast_track_is_seq_set()
{
	return local_seq_set;
}
