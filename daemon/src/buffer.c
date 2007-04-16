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

#include "buffer.h"

struct buffer *buffer_create(size_t max_size)
{
	struct buffer *b;

	b = malloc(sizeof(struct buffer));
	if (b == NULL)
		return NULL;
	memset(b, 0, sizeof(struct buffer));

	b->max_size = max_size;
	INIT_LIST_HEAD(&b->head);
	pthread_mutex_init(&b->lock, NULL);

	return b;
}

void buffer_destroy(struct buffer *b)
{
	struct list_head *i, *tmp;
	struct buffer_node *node;

	pthread_mutex_lock(&b->lock);
	list_for_each_safe(i, tmp, &b->head) {
		node = (struct buffer_node *) i;
		list_del(i);
		free(node);
	}
	pthread_mutex_unlock(&b->lock);
	pthread_mutex_destroy(&b->lock);
	free(b);
}

static struct buffer_node *buffer_node_create(const void *data, size_t size)
{
	struct buffer_node *n;

	n = malloc(sizeof(struct buffer_node) + size);
	if (n == NULL)
		return NULL;

	INIT_LIST_HEAD(&n->head);
	n->size = size;
	memcpy(n->data, data, size);

	return n;
}

int buffer_add(struct buffer *b, const void *data, size_t size)
{
	int ret = 0;
	struct buffer_node *n;

	pthread_mutex_lock(&b->lock);

	/* does it fit this buffer? */
	if (size > b->max_size) {
		errno = ENOSPC;
		ret = -1;
		goto err;
	}

retry:
	/* buffer is full: kill the oldest entry */
	if (b->cur_size + size > b->max_size) {
		n = (struct buffer_node *) b->head.prev;
		list_del(b->head.prev);
		b->cur_size -= n->size;
		free(n);
		goto retry;
	}

	n = buffer_node_create(data, size);
	if (n == NULL) {
		ret = -1;
		goto err;
	}

	list_add(&n->head, &b->head);
	b->cur_size += size;

err:
	pthread_mutex_unlock(&b->lock);
	return ret;
}

void __buffer_del(struct buffer *b, void *data)
{
	struct buffer_node *n = container_of(data, struct buffer_node, data); 

	list_del(&n->head);
	b->cur_size -= n->size;
	free(n);
}

void buffer_del(struct buffer *b, void *data)
{
	pthread_mutex_lock(&b->lock);
	buffer_del(b, data);
	pthread_mutex_unlock(&b->lock);
}

void buffer_iterate(struct buffer *b, 
		    void *data, 
		    int (*iterate)(void *data1, void *data2))
{
	struct list_head *i, *tmp;
	struct buffer_node *n;

	pthread_mutex_lock(&b->lock);
	list_for_each_safe(i, tmp, &b->head) {
		n = (struct buffer_node *) i;
		if (iterate(n->data, data))
			break;
	}
	pthread_mutex_unlock(&b->lock);
}
