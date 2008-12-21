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

#include "netlink.h"
#include "traffic_stats.h"
#include "debug.h"
#include "cache.h"
#include "log.h"
#include "conntrackd.h"
#include "us-conntrack.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

static int init_stats(void)
{
	state.stats = malloc(sizeof(struct ct_stats_state));
	if (!state.stats) {
		dlog(LOG_ERR, "can't allocate memory for stats");
		return -1;
	}
	memset(state.stats, 0, sizeof(struct ct_stats_state));

	STATE_STATS(cache) = cache_create("stats",
					  LIFETIME, 
					  NULL); 
	if (!STATE_STATS(cache)) {
		dlog(LOG_ERR, "can't allocate memory for the "
			      "external cache");
		free(state.stats);
		return -1;
	}

	return 0;
}

static void kill_stats(void)
{
	cache_destroy(STATE_STATS(cache));
}

/* handler for requests coming via UNIX socket */
static int local_handler_stats(int fd, int type, void *data)
{
	int ret = 1;

	switch(type) {
	case DUMP_INTERNAL:
		cache_dump(STATE_STATS(cache), fd, NFCT_O_PLAIN);
		break;
	case DUMP_INT_XML:
		cache_dump(STATE_STATS(cache), fd, NFCT_O_XML);
		break;
	case FLUSH_CACHE:
		dlog(LOG_NOTICE, "flushing caches");
		cache_flush(STATE_STATS(cache));
		break;
	case KILL:
		killer(0);
		break;
	case STATS:
		cache_stats(STATE_STATS(cache), fd);
		dump_traffic_stats(fd);
		break;
	case STATS_CACHE:
		cache_stats_extended(STATE_STATS(cache), fd);
		break;
	default:
		ret = 0;
		break;
	}

	return ret;
}

static void dump_stats(struct nf_conntrack *ct)
{
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_TIMEOUT);
	nfct_attr_unset(ct, ATTR_USE);

	if (cache_update_force(STATE_STATS(cache), ct))
		debug_ct(ct, "resync entry");
}

static int overrun_stats(enum nf_conntrack_msg_type type,
			 struct nf_conntrack *ct,
			 void *data)
{
	if (ct_filter_conntrack(ct, 1))
		return NFCT_CB_CONTINUE;

	/* This is required by kernels < 2.6.20 */
	nfct_attr_unset(ct, ATTR_TIMEOUT);
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_USE);

	if (!cache_test(STATE_STATS(cache), ct))
		if (!cache_update_force(STATE_STATS(cache), ct))
			debug_ct(ct, "overrun stats resync");

	return NFCT_CB_CONTINUE;
}

static int purge_step(void *data1, void *data2)
{
	int ret;
	struct us_conntrack *u = data2;

	ret = nfct_query(STATE(dump), NFCT_Q_GET, u->ct);
	if (ret == -1 && errno == ENOENT) {
		debug_ct(u->ct, "overrun purge stats");
		cache_del(STATE_STATS(cache), u->ct);
	}

	return 0;
}

static int purge_stats(void)
{
	cache_iterate(STATE_STATS(cache), NULL, purge_step);

	return 0;
}

static void event_new_stats(struct nf_conntrack *ct)
{
	nfct_attr_unset(ct, ATTR_TIMEOUT);

	if (cache_add(STATE_STATS(cache), ct)) {
		debug_ct(ct, "cache new");
	} else {
		if (errno != EEXIST) {
			dlog(LOG_ERR, 
			     "can't add to cache cache: %s\n", strerror(errno));
			debug_ct(ct, "can't add");
		}
	}
}

static void event_update_stats(struct nf_conntrack *ct)
{
	nfct_attr_unset(ct, ATTR_TIMEOUT);

	if (!cache_update_force(STATE_STATS(cache), ct)) {
		debug_ct(ct, "can't update");
		return;
	}
	debug_ct(ct, "update");
}

static int event_destroy_stats(struct nf_conntrack *ct)
{
	nfct_attr_unset(ct, ATTR_TIMEOUT);

	if (cache_del(STATE_STATS(cache), ct)) {
		debug_ct(ct, "cache destroy");
		dlog_ct(STATE(stats_log), ct, NFCT_O_PLAIN);
		return 1;
	} else {
		debug_ct(ct, "can't destroy!");
		return 0;
	}
}

struct ct_mode stats_mode = {
	.init 			= init_stats,
	.register_fds 		= NULL,
	.run			= NULL,
	.local			= local_handler_stats,
	.kill			= kill_stats,
	.dump			= dump_stats,
	.overrun		= overrun_stats,
	.purge			= purge_stats,
	.event_new		= event_new_stats,
	.event_upd		= event_update_stats,
	.event_dst		= event_destroy_stats
};
