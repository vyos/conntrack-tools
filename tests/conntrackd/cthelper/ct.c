#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <linux/if_ether.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "proto.h"
#include "helper.h"
#include "myct.h"
#include "ct.h"

static LIST_HEAD(ct_list);

struct nf_ct_entry *
ct_alloc(const uint8_t *pkt, unsigned int l3hdr_len,
	 struct cthelper_proto_l2l3_helper *l3h,
	 struct cthelper_proto_l4_helper *l4h)
{
	struct nf_ct_entry *ct;

	ct = calloc(1, sizeof(struct nf_ct_entry));
	if (ct == NULL)
		return NULL;

	ct->myct = calloc(1, sizeof(struct myct));
	if (ct->myct == NULL) {
		free(ct);
		return NULL;
	}
	ct->myct->ct = nfct_new();
	if (ct->myct->ct == NULL) {
		free(ct->myct);
		free(ct);
		return NULL;
	}
	/* FIXME: use good private helper size */
	ct->myct->priv_data = calloc(1, 128);
	if (ct->myct->priv_data == NULL) {
		nfct_destroy(ct->myct->ct);
		free(ct->myct);
		free(ct);
		return NULL;
	}

	l3h->l3ct_build(pkt, ct->myct->ct);
	l4h->l4ct_build(pkt + l3hdr_len, ct->myct->ct);

	return ct;
}

struct nf_ct_entry *
ct_find(const uint8_t *pkt, unsigned int l3hdr_len,
	struct cthelper_proto_l2l3_helper *l3h,
	struct cthelper_proto_l4_helper *l4h, unsigned int *ctinfo)
{
	struct nf_ct_entry *cur;

	list_for_each_entry(cur, &ct_list, head) {
		if (l3h->l3ct_cmp_orig(pkt, cur->myct->ct) &&
		    l4h->l4ct_cmp_orig(pkt + l3hdr_len, cur->myct->ct)) {
			*ctinfo = 0;
			return cur;
		}
		if (l3h->l3ct_cmp_repl(pkt, cur->myct->ct) &&
		     l4h->l4ct_cmp_repl(pkt + l3hdr_len, cur->myct->ct)) {
			*ctinfo = IP_CT_IS_REPLY;
			return cur;
		}
	}
	return NULL;
}

void ct_add(struct nf_ct_entry *ct)
{
	list_add(&ct->head, &ct_list);
}

void ct_flush(void)
{
	struct nf_ct_entry *cur, *tmp;

	list_for_each_entry_safe(cur, tmp, &ct_list, head) {
		list_del(&cur->head);
		free(cur->myct->priv_data);
		free(cur->myct->ct);
		free(cur->myct);
		free(cur);
	}
}
