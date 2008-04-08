#ifndef _NETLINK_H_
#define _NETLINK_H_

struct nf_conntrack;
struct nfct_handle;

int ignore_conntrack(struct nf_conntrack *ct);

int nl_init_event_handler(void);

int nl_init_dump_handler(void);

void nl_resize_socket_buffer(struct nfct_handle *h);

int nl_dump_conntrack_table(void);

int nl_exist_conntrack(struct nf_conntrack *ct);

int nl_create_conntrack(struct nf_conntrack *ct);

int nl_update_conntrack(struct nf_conntrack *ct);

int nl_destroy_conntrack(struct nf_conntrack *ct);

#endif
