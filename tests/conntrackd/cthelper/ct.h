#ifndef _CT_H_
#define _CT_H_

#include "../../../include/linux_list.h"
#include "../../../include/myct.h"

struct nf_ct_entry {
	struct list_head	head;
	struct myct		*myct;
};

struct cthelper_proto_l2l3_helper;
struct cthelper_proto_l4_helper;

struct nf_ct_entry *ct_alloc(const uint8_t *pkt, unsigned int l3hdr_len, struct cthelper_proto_l2l3_helper *l3h, struct cthelper_proto_l4_helper *l4h);

struct nf_ct_entry *ct_find(const uint8_t *pkt, unsigned int l3hdr_len, struct cthelper_proto_l2l3_helper *l3h, struct cthelper_proto_l4_helper *l4h, unsigned int *ctinfo);

void ct_add(struct nf_ct_entry *ct);
void ct_flush(void);

#endif
