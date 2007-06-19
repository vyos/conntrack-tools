#ifndef _NETWORK_H_
#define _NETWORK_H_

#include <sys/types.h>

struct nethdr {
	u_int16_t flags;
	u_int16_t padding;
	u_int32_t seq;
};
#define NETHDR_SIZ sizeof(struct nethdr)

struct nethdr_ack {
	u_int16_t flags; 
	u_int16_t padding;
	u_int32_t seq;
	u_int32_t from;
	u_int32_t to;
};
#define NETHDR_ACK_SIZ sizeof(struct nethdr_ack)

enum {
	NET_F_HELLO_BIT = 0,
	NET_F_HELLO = (1 << NET_F_HELLO_BIT),

	NET_F_RESYNC_BIT = 1,
	NET_F_RESYNC = (1 << NET_F_RESYNC_BIT),

	NET_F_NACK_BIT = 2,
	NET_F_NACK = (1 << NET_F_NACK_BIT),

	NET_F_ACK_BIT = 3,
	NET_F_ACK = (1 << NET_F_ACK_BIT),
};

/* extracted from net/tcp.h */

/*
 * The next routines deal with comparing 32 bit unsigned ints
 * and worry about wraparound (automatic with unsigned arithmetic).
 */

static inline int before(__u32 seq1, __u32 seq2)
{
	return (__s32)(seq1-seq2) < 0;
}
#define after(seq2, seq1)       before(seq1, seq2)

/* is s2<=s1<=s3 ? */
static inline int between(__u32 seq1, __u32 seq2, __u32 seq3)
{
	return seq3 - seq2 >= seq1 - seq2;
}

#endif
