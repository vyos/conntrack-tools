/*
 * (C) 2006-2008 by Pablo Neira Ayuso <pablo@netfilter.org>
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
#include <stdlib.h>
#include <string.h>
#include "fds.h"

struct fds *create_fds(void)
{
	struct fds *fds;

	fds = (struct fds *) calloc(sizeof(struct fds), 1);
	if (fds == NULL)
		return NULL;

	return fds;
}

void destroy_fds(struct fds *fds)
{
	free(fds);
}

int register_fd(int fd, struct fds *fds)
{
	FD_SET(fd, &fds->readfds);

	if (fd > fds->maxfd)
		fds->maxfd = fd;

	return 0;
}
