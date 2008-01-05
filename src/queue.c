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

#include "queue.h"

struct queue *queue_create(size_t max_size)
{
	struct queue *b;

	b = malloc(sizeof(struct queue));
	if (b == NULL)
		return NULL;
	memset(b, 0, sizeof(struct queue));

	b->max_size = max_size;
	INIT_LIST_HEAD(&b->head);

	return b;
}

void queue_destroy(struct queue *b)
{
	struct list_head *i, *tmp;
	struct queue_node *node;

	/* XXX: set cur_size and num_elems */
	list_for_each_safe(i, tmp, &b->head) {
		node = (struct queue_node *) i;
		list_del(i);
		free(node);
	}
	free(b);
}

static struct queue_node *queue_node_create(const void *data, size_t size)
{
	struct queue_node *n;

	n = malloc(sizeof(struct queue_node) + size);
	if (n == NULL)
		return NULL;

	INIT_LIST_HEAD(&n->head);
	n->size = size;
	memcpy(n->data, data, size);

	return n;
}

int queue_add(struct queue *b, const void *data, size_t size)
{
	int ret = 0;
	struct queue_node *n;

	/* does it fit this queue? */
	if (size > b->max_size) {
		errno = ENOSPC;
		ret = -1;
		goto err;
	}

retry:
	/* queue is full: kill the oldest entry */
	if (b->cur_size + size > b->max_size) {
		n = (struct queue_node *) b->head.prev;
		list_del(b->head.prev);
		b->cur_size -= n->size;
		free(n);
		goto retry;
	}

	n = queue_node_create(data, size);
	if (n == NULL) {
		ret = -1;
		goto err;
	}

	list_add(&n->head, &b->head);
	b->cur_size += size;
	b->num_elems++;

err:
	return ret;
}

void queue_del(struct queue *b, void *data)
{
	struct queue_node *n = container_of(data, struct queue_node, data); 

	list_del(&n->head);
	b->cur_size -= n->size;
	b->num_elems--;
	free(n);
}

void queue_iterate(struct queue *b, 
		   void *data, 
		   int (*iterate)(void *data1, void *data2))
{
	struct list_head *i, *tmp;
	struct queue_node *n;

	list_for_each_safe(i, tmp, &b->head) {
		n = (struct queue_node *) i;
		if (iterate(n->data, data))
			break;
	}
}

unsigned int queue_len(struct queue *b)
{
	return b->num_elems;
}
