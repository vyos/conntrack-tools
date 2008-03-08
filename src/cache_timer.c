/*
 * (C) 2006 by Pablo Neira Ayuso <pablo@netfilter.org>
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

#include "cache.h"
#include "conntrackd.h"
#include "us-conntrack.h"
#include "alarm.h"
#include "debug.h"

#include <stdio.h>

static void timeout(struct alarm_block *a, void *data)
{
	struct us_conntrack *u = data;

	debug_ct(u->ct, "expired timeout");
	cache_del(u->cache, u->ct);
}

static void timer_add(struct us_conntrack *u, void *data)
{
	struct alarm_block *alarm = data;

	init_alarm(alarm, u, timeout);
	add_alarm(alarm, CONFIG(cache_timeout), 0);
}

static void timer_update(struct us_conntrack *u, void *data)
{
	struct alarm_block *alarm = data;
	add_alarm(alarm, CONFIG(cache_timeout), 0);
}

static void timer_destroy(struct us_conntrack *u, void *data)
{
	struct alarm_block *alarm = data;
	del_alarm(alarm);
}

static int timer_dump(struct us_conntrack *u, void *data, char *buf, int type)
{
	struct timeval tv, tmp;
 	struct alarm_block *alarm = data;

	if (type == NFCT_O_XML)
		return 0;

	if (!alarm_pending(alarm))
		return 0;

	gettimeofday(&tv, NULL);
	timersub(&tv, &alarm->tv, &tmp);
	return sprintf(buf, " [expires in %lds]", tmp.tv_sec);
}

struct cache_feature timer_feature = {
	.size		= sizeof(struct alarm_block),
	.add		= timer_add,
	.update		= timer_update,
	.destroy	= timer_destroy,
	.dump		= timer_dump
};
