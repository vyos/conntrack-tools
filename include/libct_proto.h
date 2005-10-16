#ifndef _LIBCT_PROTO_H
#define _LIBCT_PROTO_H

#include "linux_list.h"
#include <getopt.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#define LIBCT_VERSION	"0.1.0"

/* FIXME: These should be independent from kernel space */
#define IPS_ASSURED (1 << 2)
#define IPS_SEEN_REPLY (1 << 1)
#define IPS_SRC_NAT_DONE (1 << 7)
#define IPS_DST_NAT_DONE (1 << 8)
#define IPS_CONFIRMED (1 << 3)

struct ctproto_handler {
	struct list_head 	head;

	char 			*name;
	u_int16_t 		protonum;
	char			*version;

	enum ctattr_protoinfo	protoinfo_attr;
	
	int (*parse_opts)(char c, char *argv[], 
		     struct nfct_tuple *orig,
		     struct nfct_tuple *reply,
		     struct nfct_tuple *mask,
		     union nfct_protoinfo *proto,
		     unsigned int *flags);

	int (*final_check)(unsigned int flags,
			   struct nfct_tuple *orig,
			   struct nfct_tuple *reply);

	void (*help)();

	struct option 		*opts;

	unsigned int		option_offset;
};

extern void register_proto(struct ctproto_handler *h);
extern void unregister_proto(struct ctproto_handler *h);

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#endif
