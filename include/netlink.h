#ifndef _NETLINK_H_
#define _NETLINK_H_

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

struct nf_conntrack;
struct nfct_handle;

struct nfct_handle *nl_init_event_handler(void);

struct nfct_handle *nl_init_dump_handler(void);

struct nfct_handle *nl_init_request_handler(void);

struct nfct_handle *nl_init_overrun_handler(void);

int nl_overrun_request_resync(void);

void nl_resize_socket_buffer(struct nfct_handle *h);

int nl_dump_conntrack_table(void);

int nl_exist_conntrack(struct nf_conntrack *ct);

int nl_get_conntrack(struct nf_conntrack *ct);

int nl_create_conntrack(struct nf_conntrack *ct);

int nl_update_conntrack(struct nf_conntrack *ct);

int nl_destroy_conntrack(struct nf_conntrack *ct);

static inline int ct_is_related(const struct nf_conntrack *ct)
{
	return (nfct_attr_is_set(ct, ATTR_MASTER_L3PROTO) &&
		nfct_attr_is_set(ct, ATTR_MASTER_L4PROTO) &&
		((nfct_attr_is_set(ct, ATTR_MASTER_IPV4_SRC) &&
		  nfct_attr_is_set(ct, ATTR_MASTER_IPV4_DST)) ||
		 (nfct_attr_is_set(ct, ATTR_MASTER_IPV6_SRC) &&
		  nfct_attr_is_set(ct, ATTR_MASTER_IPV6_DST))) &&
		nfct_attr_is_set(ct, ATTR_MASTER_PORT_SRC) &&
		nfct_attr_is_set(ct, ATTR_MASTER_PORT_DST));
}

#endif
