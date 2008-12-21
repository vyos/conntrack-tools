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

#define NETHDR_ALIGNTO	4

static unsigned int seq_set, cur_seq;

int nethdr_align(int value)
{
	return (value + NETHDR_ALIGNTO - 1) & ~(NETHDR_ALIGNTO - 1);
}

int nethdr_size(int len)
{
	return NETHDR_SIZ + len;
}
	
static inline void __nethdr_set(struct nethdr *net, int len, int type)
{
	if (!seq_set) {
		seq_set = 1;
		cur_seq = time(NULL);
	}
	net->version	= CONNTRACKD_PROTOCOL_VERSION;
	net->type	= type;
	net->len	= len;
	net->seq	= cur_seq++;
}

void nethdr_set(struct nethdr *net, int type)
{
	__nethdr_set(net, NETHDR_SIZ, type);
}

void nethdr_set_ack(struct nethdr *net)
{
	__nethdr_set(net, NETHDR_ACK_SIZ, NET_T_CTL);
}

void nethdr_set_ctl(struct nethdr *net)
{
	__nethdr_set(net, NETHDR_SIZ, NET_T_CTL);
}

static size_t tx_buflenmax;
static size_t tx_buflen = 0;
static char *tx_buf;

#define HEADERSIZ 28 /* IP header (20 bytes) + UDP header 8 (bytes) */

int mcast_buffered_init(int if_mtu)
{
	int mtu = if_mtu - HEADERSIZ;

	/* default to Ethernet MTU 1500 bytes */
	if (if_mtu == 0)
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
int mcast_buffered_send_netmsg(struct mcast_sock *m, const struct nethdr *net)
{
	int ret = 0, len = ntohs(net->len);

retry:
	if (tx_buflen + len < tx_buflenmax) {
		memcpy(tx_buf + tx_buflen, net, len);
		tx_buflen += len;
	} else {
		mcast_send(m, tx_buf, tx_buflen);
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

	ret = mcast_send(m, tx_buf, tx_buflen);
	tx_buflen = 0;

	return ret;
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
		STATE_SYNC(error).msg_rcv_lost +=
					seq - STATE_SYNC(last_seq_recv) + 1;
		ret = SEQ_AFTER;
		goto out;
	}

	/* out of sequence: replayed/delayed packet? */
	if (before(seq, STATE_SYNC(last_seq_recv)+1)) {
		STATE_SYNC(error).msg_rcv_before++;
		ret = SEQ_BEFORE;
	}

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
