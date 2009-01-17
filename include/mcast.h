#ifndef _MCAST_H_
#define _MCAST_H_

#include <stdint.h>
#include <netinet/in.h>
#include <net/if.h>

struct mcast_conf {
	int ipproto;
	int reuseaddr;
	int checksum;
	unsigned short port;
	union {
		struct in_addr inet_addr;
		struct in6_addr inet_addr6;
	} in;
	union {
		struct in_addr interface_addr;
		unsigned int interface_index6;
	} ifa;
	int mtu;
	int interface_idx;
	int sndbuf;
	int rcvbuf;
	char iface[IFNAMSIZ];
};

struct mcast_stats {
	uint64_t bytes;
	uint64_t messages;
	uint64_t error;
};

struct mcast_sock {
	int fd;
	union {
		struct sockaddr_in ipv4;
		struct sockaddr_in6 ipv6;
	} addr;
	socklen_t sockaddr_len;
	int interface_idx;
	struct mcast_stats stats;
};

#define MCAST_LINKS_MAX	4

struct mcast_sock_multi {
	int num_links;
	int max_mtu;
	struct mcast_sock *current_link;
	struct mcast_sock *multi[MCAST_LINKS_MAX];
};

struct mcast_sock *mcast_server_create(struct mcast_conf *conf);
void mcast_server_destroy(struct mcast_sock *m);
struct mcast_sock_multi *mcast_server_create_multi(struct mcast_conf *conf, int conf_len);
void mcast_server_destroy_multi(struct mcast_sock_multi *m);

struct mcast_sock *mcast_client_create(struct mcast_conf *conf);
void mcast_client_destroy(struct mcast_sock *m);
struct mcast_sock_multi *mcast_client_create_multi(struct mcast_conf *conf, int conf_len);
void mcast_client_destroy_multi(struct mcast_sock_multi*m);

ssize_t mcast_send(struct mcast_sock *m, void *data, int size);
ssize_t mcast_recv(struct mcast_sock *m, void *data, int size);

int mcast_get_fd(struct mcast_sock *m);
int mcast_get_ifidx(struct mcast_sock_multi *m, int i);
int mcast_get_current_ifidx(struct mcast_sock_multi *m);

struct mcast_sock *mcast_get_current_link(struct mcast_sock_multi *m);
void mcast_set_current_link(struct mcast_sock_multi *m, int i);

void mcast_dump_stats(int fd, const struct mcast_sock_multi *s, const struct mcast_sock_multi *r);

struct nlif_handle;

void mcast_dump_stats_extended(int fd, const struct mcast_sock_multi *s, const struct mcast_sock_multi *r, const struct nlif_handle *h);
#endif
