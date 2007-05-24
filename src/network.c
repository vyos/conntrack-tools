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

#if 0 
#define _TEST_DROP
#else
#undef _TEST_DROP
#endif

static int drop = 0; /* debugging purposes */
static unsigned int seq_set, cur_seq;

static int send_netmsg(struct mcast_sock *m, void *data, unsigned int len)
{
	struct nlnetwork *net = data;

#ifdef _TEST_DROP
        if (++drop > 10) {
		drop = 0;
		printf("dropping resend (seq=%u)\n", ntohl(net->seq));
		return 0;
	}
#endif
	return mcast_send(m, net, len);
}

int mcast_send_netmsg(struct mcast_sock *m, void *data)
{
	struct nlmsghdr *nlh = data + sizeof(struct nlnetwork);
	unsigned int len = nlh->nlmsg_len + sizeof(struct nlnetwork);
	struct nlnetwork *net = data;

	if (!seq_set) {
		seq_set = 1;
		cur_seq = time(NULL);
		net->flags |= NET_HELLO;
	}

	net->flags = htons(net->flags);
	net->seq = htonl(cur_seq++);

	if (nlh_host2network(nlh) == -1)
		return -1;

	return send_netmsg(m, data, len);
}

int mcast_resend_netmsg(struct mcast_sock *m, void *data)
{
	struct nlnetwork *net = data;
	struct nlmsghdr *nlh = data + sizeof(struct nlnetwork);
	unsigned int len;

	net->flags = ntohs(net->flags);

	if (!seq_set) {
		seq_set = 1;
		cur_seq = time(NULL);
		net->flags |= NET_HELLO;
	}

	if (net->flags & NET_NACK || net->flags & NET_ACK)
		len = sizeof(struct nlnetwork_ack);
	else
		len = sizeof(struct nlnetwork) + ntohl(nlh->nlmsg_len);

	net->flags = htons(net->flags);
	net->seq = htonl(cur_seq++);

	return send_netmsg(m, data, len);
}

int mcast_send_error(struct mcast_sock *m, void *data)
{
	struct nlnetwork *net = data;
	unsigned int len = sizeof(struct nlnetwork);

	if (!seq_set) {
		seq_set = 1;
		cur_seq = time(NULL);
		net->flags |= NET_HELLO;
	}

	if (net->flags & NET_NACK || net->flags & NET_ACK) {
		struct nlnetwork_ack *nack = (struct nlnetwork_ack *) net;
		nack->from = htonl(nack->from);
		nack->to = htonl(nack->to);
		len = sizeof(struct nlnetwork_ack);
	}

	net->flags = htons(net->flags);
	net->seq = htonl(cur_seq++);

	return send_netmsg(m, data, len);
}

int mcast_recv_netmsg(struct mcast_sock *m, void *data, int len)
{
	int ret;
	struct nlnetwork *net = data;
	struct nlmsghdr *nlh = data + sizeof(struct nlnetwork);
	struct nfgenmsg *nfhdr;

	ret = mcast_recv(m, net, len);
	if (ret <= 0)
		return ret;

	/* message too small: no room for the header */
	if (ret < sizeof(struct nlnetwork))
		return -1;

	if (ntohs(net->flags) & NET_HELLO)
		STATE_SYNC(last_seq_recv) = ntohl(net->seq) - 1;

	if (ntohs(net->flags) & NET_NACK || ntohs(net->flags) & NET_ACK) {
		struct nlnetwork_ack *nack = (struct nlnetwork_ack *) net;

		/* message too small: no room for the header */
		if (ret < sizeof(struct nlnetwork_ack))
			return -1;

		/* host byte order conversion */
		net->flags = ntohs(net->flags);
		net->seq = ntohl(net->seq);

		/* acknowledgement conversion */
		nack->from = ntohl(nack->from);
		nack->to = ntohl(nack->to);

		return ret;
	}

	if (ntohs(net->flags) & NET_RESYNC) {
		/* host byte order conversion */
		net->flags = ntohs(net->flags);
		net->seq = ntohl(net->seq);

		return ret;
	}

	/* information received is too small */
	if (ret < NLMSG_SPACE(sizeof(struct nfgenmsg)))
		return -1;

	/* information received and message length does not match */
	if (ret != ntohl(nlh->nlmsg_len) + sizeof(struct nlnetwork))
		return -1;

	/* this message does not come from ctnetlink */
	if (NFNL_SUBSYS_ID(ntohs(nlh->nlmsg_type)) != NFNL_SUBSYS_CTNETLINK)
		return -1;

	nfhdr = NLMSG_DATA(nlh);

	/* only AF_INET and AF_INET6 are supported */
	if (nfhdr->nfgen_family != AF_INET &&
	    nfhdr->nfgen_family != AF_INET6)
		return -1;

	/* only process message coming from nfnetlink v0 */
	if (nfhdr->version != NFNETLINK_V0)
		return -1;

	/* host byte order conversion */
	net->flags = ntohs(net->flags);
	net->seq = ntohl(net->seq);

	if (nlh_network2host(nlh) == -1)
		return -1;

	return ret;
}

int mcast_track_seq(u_int32_t seq, u_int32_t *exp_seq)
{
	static int seq_set = 0;
	int ret = 1;

	/* netlink sequence tracking initialization */
	if (!seq_set) {
		seq_set = 1;
		goto out;
	}

	/* fast path: we received the correct sequence */
	if (seq == STATE_SYNC(last_seq_recv)+1)
		goto out;

	/* out of sequence: some messages got lost */
	if (seq > STATE_SYNC(last_seq_recv)+1) {
		STATE_SYNC(packets_lost) += seq-STATE_SYNC(last_seq_recv)+1;
		ret = 0;
		goto out;
	}

	/* out of sequence: replayed or sequence wrapped around issues */
	if (seq < STATE_SYNC(last_seq_recv)+1) {
		/* 
		 * Check if the sequence has wrapped around.
		 * Perhaps it can be a replayed packet.
		 */
		if (STATE_SYNC(last_seq_recv)+1-seq > ~0U/2) {
			/* 
			 * Indeed, it is a wrapped around
			 */
			STATE_SYNC(packets_lost) += 
				~0U-STATE_SYNC(last_seq_recv)+1+seq;
		} else {
			/*
			 * It is a delayed packet
			 */
			dlog(STATE(log), "delayed packet? exp=%u rcv=%u",
					 STATE_SYNC(last_seq_recv)+1, seq);
		}
		ret = 0;
	}

out:
	*exp_seq = STATE_SYNC(last_seq_recv)+1;
	/* update expected sequence */
	STATE_SYNC(last_seq_recv) = seq;

	return ret;
}

int build_network_msg(const int msg_type,
		      struct nfnl_subsys_handle *ssh, 
		      struct nf_conntrack *ct,
		      void *buffer,
		      unsigned int size)
{
	memset(buffer, 0, size);
	buffer += sizeof(struct nlnetwork);
	return nfct_build_query(ssh, msg_type, ct, buffer, size);
}

unsigned int parse_network_msg(struct nf_conntrack *ct, 
			       const struct nlmsghdr *nlh)
{
	/* 
	 * The parsing of netlink messages going through network is 
	 * similar to the one that is done for messages coming from
	 * kernel, therefore do not replicate more code and use the
	 * function provided in the libraries.
	 *
	 * Yup, this is a hack 8)
	 */
	return nfct_parse_conntrack(NFCT_T_ALL, nlh, ct);
}

