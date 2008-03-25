#ifndef _STATE_HELPER_H_
#define _STATE_HELPER_H_

#include <stdint.h>

enum {
	ST_H_SKIP,
	ST_H_REPLICATE
};

struct state_replication_helper {
	uint8_t 		proto;
	unsigned int		state;

	int (*verdict)(const struct state_replication_helper *h,
		       const struct nf_conntrack *ct); 
};

int state_helper_verdict(int type, struct nf_conntrack *ct);
void state_helper_register(struct state_replication_helper *h, int h_state);

#endif
