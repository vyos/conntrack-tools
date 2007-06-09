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
#include "sync.h"
#include "network.h"
#include "us-conntrack.h"
#include "alarm.h"

static void refresher(struct alarm_list *a, void *data)
{
	struct us_conntrack *u = data;
	char __net[4096];
	int size;

	debug_ct(u->ct, "persistence update");

	a->expires = random() % CONFIG(refresh) + 1;
	size = build_network_msg(NFCT_Q_UPDATE,
				 STATE(subsys_event),
				 u->ct,
				 __net, 
				 sizeof(__net));
	mcast_send_netmsg(STATE_SYNC(mcast_client), __net);
}

static void cache_notrack_add(struct us_conntrack *u, void *data)
{
	struct alarm_list *alarm = data;

	init_alarm(alarm);
	set_alarm_expiration(alarm, (random() % conf.refresh) + 1);
	set_alarm_data(alarm, u);
	set_alarm_function(alarm, refresher);
	add_alarm(alarm);
}

static void cache_notrack_update(struct us_conntrack *u, void *data)
{
	struct alarm_list *alarm = data;
	mod_alarm(alarm, (random() % conf.refresh) + 1);
}

static void cache_notrack_destroy(struct us_conntrack *u, void *data)
{
	struct alarm_list *alarm = data;
	del_alarm(alarm);
}

static struct cache_extra cache_notrack_extra = {
	.size 		= sizeof(struct alarm_list),
	.add		= cache_notrack_add,
	.update		= cache_notrack_update,
	.destroy	= cache_notrack_destroy
};

static int notrack_recv(const struct nlnetwork *net)
{
	unsigned int exp_seq;

	/* 
	 * Ignore error messages: Although this message type is not ever
	 * generated in notrack mode, we don't want to crash the daemon 
	 * if someone nuts mixes nack and notrack.
	 */
	if (net->flags & (NET_RESYNC | NET_NACK))
		return 1;

	/* 
	 * Multicast sequence tracking: we keep track of multicast messages
	 * although we don't do any explicit message recovery. So, why do
	 * we do sequence tracking? Just to let know the sysadmin.
	 *
	 * Let t be 1 < t < RefreshTime. To ensure consistency, conntrackd
	 * retransmit every t seconds a message with the state of a certain
	 * entry even if such entry did not change. This mechanism also
	 * provides passive resynchronization, in other words, there is
	 * no facility to request a full synchronization from new nodes that
	 * just joined the cluster, instead they just get resynchronized in
	 * RefreshTime seconds at worst case.
	 */
	mcast_track_seq(net->seq, &exp_seq);

	return 0;
}

struct sync_mode notrack = {
	.internal_cache_flags	= LIFETIME,
	.external_cache_flags	= TIMER | LIFETIME,
	.internal_cache_extra	= &cache_notrack_extra,
	.recv 			= notrack_recv,
};