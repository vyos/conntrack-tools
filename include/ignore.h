#ifndef _IGNORE_H_
#define _IGNORE_H_

#include <stdint.h>

struct nf_conntrack;

struct ignore_pool {
	struct hashtable *h;
	struct hashtable *h6;
};

struct ignore_pool *ignore_pool_create(void);
void ignore_pool_destroy(struct ignore_pool *ip);
int ignore_pool_add(struct ignore_pool *ip, void *data, uint8_t family);
int ignore_pool_test(struct ignore_pool *ip, struct nf_conntrack *ct);

#endif
