#ifndef _NF_SET_HASH_H_
#define _NF_SET_HASH_H_

#include <unistd.h>
#include "slist.h"
#include "linux_list.h"

#include <stdint.h>

struct hashtable;
struct hashtable_node;

struct hashtable {
	uint32_t hashsize;
	uint32_t limit;
	uint32_t count;
	uint32_t initval;
	uint32_t datasize;
	
	uint32_t (*hash)(const void *data, const struct hashtable *table);
	int	 (*compare)(const void *data1, const void *data2);

	struct slist_head 	members[0];
};

struct hashtable_node {
	struct slist_head head;
	char data[0];
};

struct hashtable_node *hashtable_alloc_node(int datasize, void *data);
void hashtable_destroy_node(struct hashtable_node *h);

struct hashtable *
hashtable_create(int hashsize, int limit, int datasize,
		 uint32_t (*hash)(const void *data,
		 		  const struct hashtable *table),
		 int (*compare)(const void *data1, const void *data2));
void hashtable_destroy(struct hashtable *h);

void *hashtable_add(struct hashtable *table, void *data);
void *hashtable_find(struct hashtable *table, const void *data);
int hashtable_del(struct hashtable *table, void *data);
int hashtable_flush(struct hashtable *table);
int hashtable_iterate(struct hashtable *table, void *data,
		      int (*iterate)(void *data1, void *data2));
unsigned int hashtable_counter(const struct hashtable *table);

#endif
