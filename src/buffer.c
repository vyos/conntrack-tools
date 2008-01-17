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

#include "buffer.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct buffer *buffer_create(size_t size)
{
	struct buffer *b;

	b = malloc(sizeof(struct buffer));
	if (b == NULL)
		return NULL;
	memset(b, 0, sizeof(struct buffer));

	b->size = size;

	b->data = malloc(size);
	if (b->data == NULL) {
		free(b);
		return NULL;
	}
	memset(b->data, 0, size);

	return b;
}

void buffer_destroy(struct buffer *b)
{
	free(b->data);
	free(b);
}

int buffer_add(struct buffer *b, void *data, size_t size)
{
	if (b->size - b->cur_size < size) {
		errno = ENOSPC;
		return -1;
	}

	memcpy(b->data + b->cur_size, data, size);
	b->cur_size += size;
	return 0;
}

void buffer_flush(struct buffer *b, 
		  void (*cb)(void *buffer_data, void *data), 
		  void *data)
{
	cb(b->data, data);
	b->cur_size = 0;
	memset(b->data, 0, b->size);
}

size_t buffer_size(const struct buffer *b)
{
	return b->size;
}
