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
#include "cache.h"
#include "debug.h"

#include <stdlib.h>
#include <string.h>

static void refresher(struct alarm_list *a, void *data)
{
	size_t len;
	struct nethdr *net;
	struct us_conntrack *u = data;

	debug_ct(u->ct, "persistence update");

	add_alarm(a, 
		  random() % CONFIG(refresh) + 1,
		  ((random() % 5 + 1)  * 200000) - 1);

	net = BUILD_NETMSG(u->ct, NFCT_Q_UPDATE);
	len = prepare_send_netmsg(STATE_SYNC(mcast_client), net);
	mcast_buffered_send_netmsg(STATE_SYNC(mcast_client), net, len);
}

static void cache_alarm_add(struct us_conntrack *u, void *data)
{
	struct alarm_list *alarm = data;

	init_alarm(alarm, u, refresher);
	add_alarm(alarm,
		  random() % CONFIG(refresh) + 1,
		  ((random() % 5 + 1)  * 200000) - 1);
}

static void cache_alarm_update(struct us_conntrack *u, void *data)
{
	struct alarm_list *alarm = data;
	add_alarm(alarm, 
		  random() % CONFIG(refresh) + 1,
		  ((random() % 5 + 1)  * 200000) - 1);
}

static void cache_alarm_destroy(struct us_conntrack *u, void *data)
{
	struct alarm_list *alarm = data;
	del_alarm(alarm);
}

static struct cache_extra cache_alarm_extra = {
	.size 		= sizeof(struct alarm_list),
	.add		= cache_alarm_add,
	.update		= cache_alarm_update,
	.destroy	= cache_alarm_destroy
};

static int alarm_recv(const struct nethdr *net)
{
	unsigned int exp_seq;

	/* 
	 * Ignore error messages: Although this message type is not ever
	 * generated in alarm mode, we don't want to crash the daemon 
	 * if someone nuts mixes ftfw and alarm.
	 */
	if (net->flags)
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

struct sync_mode sync_alarm = {
	.internal_cache_flags	= LIFETIME,
	.external_cache_flags	= TIMER | LIFETIME,
	.internal_cache_extra	= &cache_alarm_extra,
	.recv 			= alarm_recv,
};
