#ifndef _LIBCT_PROTO_H
#define _LIBCT_PROTO_H

/* FIXME: Rename this file pablo... */

#include "linux_list.h"
#include <getopt.h>
#include <libnfnetlink_conntrack/libnfnetlink_conntrack.h>

#define LIBCT_VERSION	"0.1.0"

struct cta_proto;

struct ctproto_handler {
	struct list_head 	head;

	char 			*name;
	u_int16_t 		protonum;
	char			*version;

	enum ctattr_protoinfo	protoinfo_attr;
	
	int (*parse_opts)(char c, char *argv[], 
		     struct ctnl_tuple *orig,
		     struct ctnl_tuple *reply,
		     struct ctnl_tuple *mask,
		     union ctnl_protoinfo *proto,
		     unsigned int *flags);
	void (*parse_proto)(struct nfattr *cda[], struct ctnl_tuple *tuple);
	void (*parse_protoinfo)(struct nfattr *cda[], 
				struct ctnl_conntrack *ct);
	void (*print_proto)(struct ctnl_tuple *t);
	void (*print_protoinfo)(union ctnl_protoinfo *protoinfo);

	int (*final_check)(unsigned int flags,
			   struct ctnl_tuple *orig,
			   struct ctnl_tuple *reply);

	void (*help)();

	struct option 		*opts;

	unsigned int		option_offset;
};

extern void register_proto(struct ctproto_handler *h);
extern void unregister_proto(struct ctproto_handler *h);

extern struct ctproto_handler *findproto(char *name);

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#endif
