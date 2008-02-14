#ifndef _QUEUE_H_
#define _QUEUE_H_

#include "linux_list.h"

struct queue {
	size_t max_size;
	size_t cur_size;
	unsigned int num_elems;
	struct list_head head;
};

struct queue_node {
	struct list_head head;
	size_t size;
	char data[0];
};

struct queue *queue_create(size_t max_size);
void queue_destroy(struct queue *b);
unsigned int queue_len(const struct queue *b);
int queue_add(struct queue *b, const void *data, size_t size);
void queue_del(struct queue *b, void *data);
void queue_iterate(struct queue *b,
		   const void *data,
		   int (*iterate)(void *data1, const void *data2));

#endif
