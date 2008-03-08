/*
 * (C) 2006-2008 by Pablo Neira Ayuso <pablo@netfilter.org>
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
#include <stdlib.h>
#include <string.h>
#include "fds.h"

/* we don't handle that many descriptors so eight is just fine */
#define FDS_ARRAY_LEN 8
#define FDS_ARRAY_SIZE (sizeof(int) * FDS_ARRAY_LEN)

struct fds *create_fds(void)
{
	struct fds *fds;

	fds = (struct fds *) malloc(sizeof(struct fds));
	if (fds == NULL)
		return NULL;

	memset(fds, 0, sizeof(struct fds));

	fds->fd_array = (int *) malloc(FDS_ARRAY_SIZE);
	if (fds->fd_array == NULL) {
		free(fds);
		return NULL;
	}

	memset(fds->fd_array, 0, FDS_ARRAY_SIZE);
	fds->fd_array_len = FDS_ARRAY_LEN;

	return fds;
}

void destroy_fds(struct fds *fds)
{
	free(fds->fd_array);
	free(fds);
}

int register_fd(int fd, struct fds *fds)
{
	FD_SET(fd, &fds->readfds);

	if (fd > fds->maxfd)
		fds->maxfd = fd;

	if (fds->fd_array_cur >= fds->fd_array_len) {
		fds->fd_array_len += FDS_ARRAY_LEN;
		fds->fd_array = realloc(fds->fd_array,
					fds->fd_array_len * sizeof(int));
		if (fds->fd_array == NULL) {
			fds->fd_array_len -= FDS_ARRAY_LEN;
			return -1;
		}
	}

	fds->fd_array[fds->fd_array_cur++] = fd;

	return 0;
}
