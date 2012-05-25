#include <stdlib.h>
#include <netinet/in.h>
#include <linux/if_ether.h>

#include "linux_list.h"
#include "proto.h"

static LIST_HEAD(l2l3_helper_list);
static LIST_HEAD(l4_helper_list);

struct cthelper_proto_l2l3_helper *
cthelper_proto_l2l3_helper_find(const uint8_t *pkt,
				unsigned int *l4protonum,
				unsigned int *l3hdr_len)
{
	const struct ethhdr *eh = (const struct ethhdr *)pkt;
	struct cthelper_proto_l2l3_helper *cur;

	list_for_each_entry(cur, &l2l3_helper_list, head) {
		if (ntohs(cur->l2protonum) == eh->h_proto) {
			*l4protonum = cur->l4pkt_proto(pkt + ETH_HLEN);
			*l3hdr_len = cur->l3pkt_hdr_len(pkt + ETH_HLEN);
			return cur;
		}
	}
	return NULL;
}

void cthelper_proto_l2l3_helper_register(struct cthelper_proto_l2l3_helper *h)
{
	list_add(&h->head, &l2l3_helper_list);
}

struct cthelper_proto_l4_helper *
cthelper_proto_l4_helper_find(const uint8_t *pkt, unsigned int l4protocol)
{
	struct cthelper_proto_l4_helper *cur;

	list_for_each_entry(cur, &l4_helper_list, head) {
		if (cur->l4protonum == l4protocol)
			return cur;
	}
	return NULL;
}

void cthelper_proto_l4_helper_register(struct cthelper_proto_l4_helper *h)
{
	list_add(&h->head, &l4_helper_list);
}
