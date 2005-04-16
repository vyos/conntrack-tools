/* libnfnetlink.h: Header file for generic netfilter netlink interface
 *
 * (C) 2002 Harald Welte <laforge@gnumonks.org>
 */

#ifndef __LIBNFNETLINK_H
#define __LIBNFNETLINK_H

#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>

#define NFNL_BUFFSIZE		8192

struct nfnl_handle {
	int			fd;
	struct sockaddr_nl	local;
	struct sockaddr_nl	peer;
	u_int8_t		subsys_id;
	u_int32_t		seq;
	u_int32_t		dump;
};

/* get a new library handle */
extern int nfnl_open(struct nfnl_handle *, u_int8_t, unsigned int);
extern int nfnl_close(struct nfnl_handle *);
extern int nfnl_send(struct nfnl_handle *, struct nlmsghdr *);


extern void nfnl_fill_hdr(struct nfnl_handle *, struct nlmsghdr *, int,
                          u_int8_t, u_int16_t, u_int16_t);

extern int nfnl_listen(struct nfnl_handle *,
                      int (*)(struct sockaddr_nl *, struct nlmsghdr *, void *),
                      void *);

extern int nfnl_talk(struct nfnl_handle *, struct nlmsghdr *, pid_t,
                     unsigned, struct nlmsghdr *,
                     int (*)(struct sockaddr_nl *, struct nlmsghdr *, void *),
                     void *);

/* nfnl attribute handling functions */
extern int nfnl_addattr_l(struct nlmsghdr *, int, int, void *, int);
extern int nfnl_addattr32(struct nlmsghdr *, int, int, u_int32_t);
extern int nfnl_nfa_addattr_l(struct nfattr *, int, int, void *, int);
extern int nfnl_nfa_addattr32(struct nfattr *, int, int, u_int32_t);
extern int nfnl_parse_attr(struct nfattr **, int, struct nfattr *, int);

extern void nfnl_dump_packet(struct nlmsghdr *, int, char *);
#endif /* __LIBNFNETLINK_H */
