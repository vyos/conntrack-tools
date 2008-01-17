#ifndef _BUFFER_H_
#define _BUFFER_H_

#include <stddef.h>

struct buffer {
	unsigned char *data;
	size_t size;
	size_t cur_size;
};

struct buffer *buffer_create(size_t size);
void buffer_destroy(struct buffer *b);

int buffer_add(struct buffer *b, void *data, size_t size);
void buffer_flush(struct buffer *b, 
		  void (*cb)(void *buffer_data, 
		  void *data),
		  void *data);
size_t buffer_size(const struct buffer *b);

#endif
