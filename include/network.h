#ifndef _NETWORK_H_
#define _NETWORK_H_

#include <stdint.h>
#include <sys/types.h>

#define CONNTRACKD_PROTOCOL_VERSION	0

struct nf_conntrack;

struct nethdr {
	uint8_t version;
	uint8_t flags;
	uint16_t len;
	uint32_t seq;
};
#define NETHDR_SIZ sizeof(struct nethdr)

#define NETHDR_DATA(x)							 \
	(struct netpld *)(((char *)x) + sizeof(struct nethdr))

struct nethdr_ack {
	uint8_t version;
	uint8_t flags; 
	uint16_t len;
	uint32_t seq;
	uint32_t from;
	uint32_t to;
};
#define NETHDR_ACK_SIZ sizeof(struct nethdr_ack)

enum {
	NET_F_UNUSED 	= (1 << 0),
	NET_F_RESYNC 	= (1 << 1),
	NET_F_NACK 	= (1 << 2),
	NET_F_ACK 	= (1 << 3),
	NET_F_ALIVE 	= (1 << 4),
	NET_F_HELLO	= (1 << 5),
	NET_F_HELLO_BACK= (1 << 6),
};

enum {
	MSG_DATA,
	MSG_CTL,
	MSG_DROP,
	MSG_BAD,
};

#define BUILD_NETMSG(ct, query)					\
({								\
	char __net[4096];					\
	memset(__net, 0, sizeof(__net));			\
	build_netmsg(ct, query, (struct nethdr *) __net);	\
	(struct nethdr *) __net;				\
})

struct us_conntrack;
struct mcast_sock;

void build_netmsg(struct nf_conntrack *ct, int query, struct nethdr *net);
size_t prepare_send_netmsg(struct mcast_sock *m, void *data);
int mcast_send_netmsg(struct mcast_sock *m, void *data);

enum {
	SEQ_UNKNOWN,
	SEQ_UNSET,
	SEQ_IN_SYNC,
	SEQ_AFTER,
	SEQ_BEFORE,
};

int mcast_track_seq(uint32_t seq, uint32_t *exp_seq);
void mcast_track_update_seq(uint32_t seq);
int mcast_track_is_seq_set(void);

struct mcast_conf;

int mcast_buffered_init(struct mcast_conf *mconf);
void mcast_buffered_destroy(void);
int mcast_buffered_send_netmsg(struct mcast_sock *m, void *data, size_t len);
ssize_t mcast_buffered_pending_netmsg(struct mcast_sock *m);

#define IS_DATA(x)	((x->flags & ~(NET_F_HELLO | NET_F_HELLO_BACK)) == 0)
#define IS_ACK(x)	(x->flags & NET_F_ACK)
#define IS_NACK(x)	(x->flags & NET_F_NACK)
#define IS_RESYNC(x)	(x->flags & NET_F_RESYNC)
#define IS_ALIVE(x)	(x->flags & NET_F_ALIVE)
#define IS_CTL(x)	IS_ACK(x) || IS_NACK(x) || IS_RESYNC(x) || IS_ALIVE(x)
#define IS_HELLO(x)	(x->flags & NET_F_HELLO)
#define IS_HELLO_BACK(x)(x->flags & NET_F_HELLO_BACK)

#define HDR_NETWORK2HOST(x)						\
({									\
	x->len   = ntohs(x->len);					\
	x->seq   = ntohl(x->seq);					\
	if (IS_CTL(x)) {						\
		struct nethdr_ack *__ack = (struct nethdr_ack *) x;	\
		__ack->from = ntohl(__ack->from);			\
		__ack->to = ntohl(__ack->to);				\
	}								\
})

#define HDR_HOST2NETWORK(x)						\
({									\
	if (IS_CTL(x)) {						\
		struct nethdr_ack *__ack = (struct nethdr_ack *) x;	\
		__ack->from = htonl(__ack->from);			\
		__ack->to = htonl(__ack->to);				\
	}								\
	x->len   = htons(x->len);					\
	x->seq   = htonl(x->seq);					\
})

/* extracted from net/tcp.h */

/*
 * The next routines deal with comparing 32 bit unsigned ints
 * and worry about wraparound (automatic with unsigned arithmetic).
 */

static inline int before(uint32_t seq1, uint32_t seq2)
{
	return (int32_t)(seq1-seq2) < 0;
}
#define after(seq2, seq1)       before(seq1, seq2)

/* is s2<=s1<=s3 ? */
static inline int between(uint32_t seq1, uint32_t seq2, uint32_t seq3)
{
	return seq3 - seq2 >= seq1 - seq2;
}

struct netpld {
	uint16_t       len;
	uint16_t       query;
};
#define NETPLD_SIZ		sizeof(struct netpld)

#define PLD_NETWORK2HOST(x)						 \
({									 \
	x->len = ntohs(x->len);						 \
	x->query = ntohs(x->query);					 \
})

#define PLD_HOST2NETWORK(x)						 \
({									 \
	x->len = htons(x->len);						 \
	x->query = htons(x->query);					 \
})

struct netattr {
	uint16_t nta_len;
	uint16_t nta_attr;
};

#define ATTR_NETWORK2HOST(x)						 \
({									 \
	x->nta_len = ntohs(x->nta_len);					 \
	x->nta_attr = ntohs(x->nta_attr);				 \
})

#define PLD_DATA(x)							 \
	(struct netattr *)(((char *)x) + sizeof(struct netpld))

#define PLD_TAIL(x)							 \
	(struct netattr *)(((char *)x) + sizeof(struct netpld) + x->len)

#define NTA_DATA(x)							 \
	(void *)(((char *)x) + sizeof(struct netattr))

#define NTA_NEXT(x, len)						      \
(									      \
	len -= NTA_ALIGN(NTA_LENGTH(x->nta_len)),			      \
	(struct netattr *)(((char *)x) + NTA_ALIGN(NTA_LENGTH(x->nta_len)))   \
)

#define NTA_ALIGNTO	4
#define NTA_ALIGN(len)	(((len) + NTA_ALIGNTO - 1) & ~(NTA_ALIGNTO - 1))
#define NTA_LENGTH(len)	(NTA_ALIGN(sizeof(struct netattr)) + (len))

void build_netpld(struct nf_conntrack *ct, struct netpld *pld, int query);

int parse_netpld(struct nf_conntrack *ct, struct nethdr *net, int *query, size_t remain);

#endif
