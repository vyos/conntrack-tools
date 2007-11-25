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

#include <stdio.h>
#include "conntrackd.h"
#include "us-conntrack.h"
#include "cache.h"

static void add_update(struct us_conntrack *u)
{
	char __ct[nfct_maxsize()];
	struct nf_conntrack *ct = (struct nf_conntrack *) __ct;

	memcpy(ct, u->ct, nfct_maxsize());

	nl_create_conntrack(ct);
}

static void writethrough_add(struct us_conntrack *u, void *data)
{
	add_update(u);
}

static void writethrough_update(struct us_conntrack *u, void *data)
{
	add_update(u);
}

static void writethrough_destroy(struct us_conntrack *u, void *data)
{
	nl_destroy_conntrack(u->ct);
}

struct cache_feature writethrough_feature = {
	.add		= writethrough_add,
	.update		= writethrough_update,
	.destroy	= writethrough_destroy,
};
