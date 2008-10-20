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

#include "cache.h"
#include "hash.h"
#include "log.h"
#include "conntrackd.h"
#include "netlink.h"
#include "us-conntrack.h"

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <sched.h>
#include <errno.h>
#include <string.h>

struct __dump_container {
	int fd;
	int type;
};

static int do_dump(void *data1, void *data2)
{
	char buf[1024];
	int size;
	struct __dump_container *container = data1;
	struct us_conntrack *u = data2;
	char *data = u->data;
	unsigned i;

	/*
	 * XXX: Do not dump the entries that are scheduled to expire.
	 * 	These entries talk about already destroyed connections
	 * 	that we keep for some time just in case that we have to
	 * 	resent some lost messages. We do not show them to the
	 * 	user as he may think that the firewall replicas are not
	 * 	in sync. The branch below is a hack as it is quite
	 * 	specific and it breaks conntrackd modularity. Probably
	 * 	there's a nicer way to do this but until I come up with it...
	 */
	if (CONFIG(flags) & CTD_SYNC_FTFW && alarm_pending(&u->alarm))
		return 0;

	/* do not show cached timeout, this may confuse users */
	if (nfct_attr_is_set(u->ct, ATTR_TIMEOUT))
		nfct_attr_unset(u->ct, ATTR_TIMEOUT);

	memset(buf, 0, sizeof(buf));
	size = nfct_snprintf(buf, 
			     sizeof(buf), 
			     u->ct, 
			     NFCT_T_UNKNOWN, 
			     container->type,
			     0);

	for (i = 0; i < u->cache->num_features; i++) {
		if (u->cache->features[i]->dump) {
			size += u->cache->features[i]->dump(u, 
							    data, 
							    buf+size,
							    container->type);
			data += u->cache->features[i]->size;
		}
	}
	size += sprintf(buf+size, "\n");
	if (send(container->fd, buf, size, 0) == -1) {
		if (errno != EPIPE)
			return -1;
	}

	return 0;
}

void cache_dump(struct cache *c, int fd, int type)
{
	struct __dump_container tmp = {
		.fd	= fd,
		.type	= type
	};

	hashtable_iterate(c->h, (void *) &tmp, do_dump);
}

static void __do_commit_step(struct cache *c, struct us_conntrack *u)
{
	int ret, retry = 1;
	struct nf_conntrack *ct = u->ct;

        /* 
	 * Set a reduced timeout for candidate-to-be-committed
	 * conntracks that live in the external cache
	 */
	nfct_set_attr_u32(ct, ATTR_TIMEOUT, CONFIG(commit_timeout));

try_again:
	ret = nl_exist_conntrack(ct);
	switch (ret) {
	case -1:
		dlog(LOG_ERR, "commit-exist: %s", strerror(errno));
		dlog_ct(STATE(log), ct, NFCT_O_PLAIN);
		break;
	case 0:
		if (nl_create_conntrack(ct) == -1) {
			if (errno == ENOMEM) {
				if (retry) {
					retry = 0;
					sched_yield();
					goto try_again;
				}
			}
			dlog(LOG_ERR, "commit-create: %s", strerror(errno));
			dlog_ct(STATE(log), ct, NFCT_O_PLAIN);
			c->commit_fail++;
		} else
			c->commit_ok++;
		break;
	case 1:
		c->commit_exist++;
		if (nl_update_conntrack(ct) == -1) {
			if (errno == ENOMEM || errno == ETIME) {
				if (retry) {
					retry = 0;
					sched_yield();
					goto try_again;
				}
			}
			/* try harder, delete the entry and retry */
			if (retry) {
				ret = nl_destroy_conntrack(ct);
				if (ret == 0 || 
				    (ret == -1 && errno == ENOENT)) {
					retry = 0;
					goto try_again;
				}
				dlog(LOG_ERR, "commit-rm: %s", strerror(errno));
				dlog_ct(STATE(log), ct, NFCT_O_PLAIN);
				c->commit_fail++;
				break;
			} 
			dlog(LOG_ERR, "commit-update: %s", strerror(errno));
			dlog_ct(STATE(log), ct, NFCT_O_PLAIN);
			c->commit_fail++;
		} else
			c->commit_ok++;
		break;
	}
}

static int do_commit_related(void *data1, void *data2)
{
	struct us_conntrack *u = data2;

	if (ct_is_related(u->ct))
		__do_commit_step(data1, u);

	/* keep iterating even if we have found errors */
	return 0;
}

static int do_commit_master(void *data1, void *data2)
{
	struct us_conntrack *u = data2;

	if (ct_is_related(u->ct))
		return 0;

	__do_commit_step(data1, u);
	return 0;
}

/* no need to clone, called from child process */
void cache_commit(struct cache *c)
{
	unsigned int commit_ok = c->commit_ok;
	unsigned int commit_exist = c->commit_exist;
	unsigned int commit_fail = c->commit_fail;

	/* commit master conntrack first, then related ones */
	hashtable_iterate(c->h, c, do_commit_master);
	hashtable_iterate(c->h, c, do_commit_related);

	/* calculate new entries committed */
	commit_ok = c->commit_ok - commit_ok;
	commit_fail = c->commit_fail - commit_fail;
	commit_exist = c->commit_exist - commit_exist;

	/* log results */
	dlog(LOG_NOTICE, "Committed %u new entries", commit_ok);

	if (commit_exist)
		dlog(LOG_NOTICE, "%u entries updated, "
				 "already exist", commit_exist);
	if (commit_fail)
		dlog(LOG_NOTICE, "%u entries can't be "
				 "committed", commit_fail);
}

static int do_reset_timers(void *data1, void *data2)
{
	int ret;
	u_int32_t current_timeout;
	struct us_conntrack *u = data2;
	struct nf_conntrack *ct = u->ct;

	ret = nl_get_conntrack(ct);
	switch (ret) {
	case -1:
		/* the kernel table is not in sync with internal cache */
		dlog(LOG_ERR, "reset-timers: %s", strerror(errno));
		dlog_ct(STATE(log), ct, NFCT_O_PLAIN);
		break;
	case 1:
		current_timeout = nfct_get_attr_u32(ct, ATTR_TIMEOUT);
		/* already about to die, do not touch it */
		if (current_timeout < CONFIG(purge_timeout))
			break;

		nfct_set_attr_u32(ct, ATTR_TIMEOUT, CONFIG(purge_timeout));

		if (nl_update_conntrack(ct) == -1) {
			if (errno == ETIME || errno == ENOENT)
				break;
			dlog(LOG_ERR, "reset-timers-upd: %s", strerror(errno));
			dlog_ct(STATE(log), ct, NFCT_O_PLAIN);
		}
		break;
	}
	return 0;
}

void cache_reset_timers(struct cache *c)
{
	hashtable_iterate(c->h, NULL, do_reset_timers);
}

static int do_flush(void *data1, void *data2)
{
	struct cache *c = data1;
	struct us_conntrack *u = data2;

	cache_del(c, u->ct);

	return 0;
}

void cache_flush(struct cache *c)
{
	hashtable_iterate(c->h, c, do_flush);
	c->flush++;
}
