#ifndef _BUFFER_H_
#define _BUFFER_H_

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include "linux_list.h"

struct buffer {
	pthread_mutex_t lock;
	size_t max_size;
	size_t cur_size;
	struct list_head head;
};

struct buffer_node {
	struct list_head head;
	size_t size;
	char data[0];
};

struct buffer *buffer_create(size_t max_size);
void buffer_destroy(struct buffer *b);
int buffer_add(struct buffer *b, const void *data, size_t size);
void buffer_del(struct buffer *b, void *data);
void __buffer_del(struct buffer *b, void *data);
void buffer_iterate(struct buffer *b, 
		    void *data, 
		    int (*iterate)(void *data1, void *data2));

#endif
