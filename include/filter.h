#ifndef _FILTER_H_
#define _FILTER_H_

#include <stdint.h>

enum ct_filter_type {
	CT_FILTER_L4PROTO,
	CT_FILTER_STATE,
	CT_FILTER_ADDRESS,
	CT_FILTER_MAX
};

enum ct_filter_logic {
	CT_FILTER_NEGATIVE = 0,
	CT_FILTER_POSITIVE = 1,
};

struct nf_conntrack;
struct ct_filter;

struct ct_filter *ct_filter_create(void);
void ct_filter_destroy(struct ct_filter *filter);
int ct_filter_add_ip(struct ct_filter *filter, void *data, uint8_t family);
void ct_filter_add_proto(struct ct_filter *filter, int protonum);
void ct_filter_add_state(struct ct_filter *f, int protonum, int state);
void ct_filter_set_logic(struct ct_filter *f,
			 enum ct_filter_type type,
			 enum ct_filter_logic logic);
int ct_filter_check(struct ct_filter *filter, struct nf_conntrack *ct);

#endif
