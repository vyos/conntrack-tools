#ifndef _LIBCT_PROTO_H
#define _LIBCT_PROTO_H

#include "linux_list.h"
#include <getopt.h>

struct ctproto_handler {
	struct list_head 	head;

	char 			*name;
	u_int16_t 		protonum;
	
	int (*parse)(char c, char *argv[], struct ip_conntrack_tuple *orig,
		     struct ip_conntrack_tuple *reply);
	void (*print)(struct ip_conntrack_tuple *t);

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
