#ifndef _HELPER_H_
#define _HELPER_H_

#include <stdint.h>

#include "../../../include/linux_list.h"

struct nf_conntrack;

struct cthelper_proto_l4_helper {
	struct list_head	head;

	unsigned int		l4protonum;

	void	(*l4ct_build)(const uint8_t *pkt, struct nf_conntrack *ct);
	int	(*l4ct_cmp_orig)(const uint8_t *pkt, struct nf_conntrack *ct);
	int	(*l4ct_cmp_repl)(const uint8_t *pkt, struct nf_conntrack *ct);
	int	(*l4ct_cmp_port)(struct nf_conntrack *ct, uint16_t port);

	int	(*l4pkt_no_data)(const uint8_t *pkt);
};

struct cthelper_proto_l2l3_helper {
	struct list_head	head;

	unsigned int		l2protonum;
	unsigned int		l2hdr_len;

	unsigned int		l3protonum;

	void	(*l3ct_build)(const uint8_t *pkt, struct nf_conntrack *ct);
	int 	(*l3ct_cmp_orig)(const uint8_t *pkt, struct nf_conntrack *ct);
	int 	(*l3ct_cmp_repl)(const uint8_t *pkt, struct nf_conntrack *ct);

	int	(*l3pkt_hdr_len)(const uint8_t *pkt);
	int	(*l4pkt_proto)(const uint8_t *pkt);
};

struct cthelper_proto_l2l3_helper *cthelper_proto_l2l3_helper_find(const uint8_t *pkt, unsigned int *l4protonum, unsigned int *l3hdr_len);
void cthelper_proto_l2l3_helper_register(struct cthelper_proto_l2l3_helper *h);

struct cthelper_proto_l4_helper *cthelper_proto_l4_helper_find(const uint8_t *pkt, unsigned int l4protonum);
void cthelper_proto_l4_helper_register(struct cthelper_proto_l4_helper *h);

/* Initialization of supported protocols here. */
void l2l3_ipv4_init(void);
void l4_tcp_init(void);
void l4_udp_init(void);

#endif
