#ifndef _BUFFER_H_
#define _BUFFER_H_

struct buffer {
	unsigned char *data;
	unsigned int size;
	unsigned int cur_size;
};

struct buffer *buffer_create(unsigned int size);
int buffer_add(struct buffer *b, void *data, unsigned int size);
void buffer_flush(struct buffer *b, 
		  void (*cb)(void *buffer_data, 
		  void *data),
		  void *data);
unsigned int buffer_size(const struct buffer *b);

#endif
