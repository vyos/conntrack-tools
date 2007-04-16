#ifndef _NETWORK_H_
#define _NETWORK_H_

#include <sys/types.h>

struct nlnetwork {
	u_int16_t flags; 
	u_int16_t checksum;
	u_int32_t seq;
};

struct nlnetwork_ack {
	u_int16_t flags; 
	u_int16_t checksum;
	u_int32_t seq;
	u_int32_t from;
	u_int32_t to;
};

enum {
	NET_HELLO_BIT = 0,
	NET_HELLO = (1 << NET_HELLO_BIT),

	NET_RESYNC_BIT = 1,
	NET_RESYNC = (1 << NET_RESYNC_BIT),

	NET_NACK_BIT = 2,
	NET_NACK = (1 << NET_NACK_BIT),

	NET_ACK_BIT = 3,
	NET_ACK = (1 << NET_ACK_BIT),
};

#endif
