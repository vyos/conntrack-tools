/*
 * (C) 2007 by Pablo Neira Ayuso <pablo@netfilter.org>
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
#include "cache.h"
#include "netlink.h"
#include "log.h"

#include <string.h>
#include <errno.h>

static void add_wt(struct cache_object *obj)
{
	int ret;
	char __ct[nfct_maxsize()];
	struct nf_conntrack *ct = (struct nf_conntrack *)(void*) __ct;

	ret = nl_exist_conntrack(STATE(request), obj->ct);
	switch (ret) {
	case -1:
		dlog(LOG_ERR, "cache_wt problem: %s", strerror(errno));
		dlog_ct(STATE(log), obj->ct, NFCT_O_PLAIN);
		break;
	case 0:
		memcpy(ct, obj->ct, nfct_maxsize());
		if (nl_create_conntrack(STATE(dump), ct) == -1) {
			dlog(LOG_ERR, "cache_wt create: %s", strerror(errno));
			dlog_ct(STATE(log), obj->ct, NFCT_O_PLAIN);
		}
		break;
	case 1:
		memcpy(ct, obj->ct, nfct_maxsize());
		if (nl_update_conntrack(STATE(dump), ct) == -1) {
			dlog(LOG_ERR, "cache_wt crt-upd: %s", strerror(errno));
			dlog_ct(STATE(log), obj->ct, NFCT_O_PLAIN);
		}
		break;
	}
}

static void upd_wt(struct cache_object *obj)
{
	char __ct[nfct_maxsize()];
	struct nf_conntrack *ct = (struct nf_conntrack *)(void*) __ct;

	memcpy(ct, obj->ct, nfct_maxsize());

	if (nl_update_conntrack(STATE(dump), ct) == -1) {
		dlog(LOG_ERR, "cache_wt update:%s", strerror(errno));
		dlog_ct(STATE(log), obj->ct, NFCT_O_PLAIN);
	}
}

static void writethrough_add(struct cache_object *obj, void *data)
{
	add_wt(obj);
}

static void writethrough_update(struct cache_object *obj, void *data)
{
	upd_wt(obj);
}

static void writethrough_destroy(struct cache_object *obj, void *data)
{
	nl_destroy_conntrack(STATE(dump), obj->ct);
}

struct cache_feature writethrough_feature = {
	.add		= writethrough_add,
	.update		= writethrough_update,
	.destroy	= writethrough_destroy,
};
