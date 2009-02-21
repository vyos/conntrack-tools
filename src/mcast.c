/*
 * (C) 2006-2009 by Pablo Neira Ayuso <pablo@netfilter.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Description: multicast socket library
 */

#include "mcast.h"

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <libnfnetlink/libnfnetlink.h>

struct mcast_sock *mcast_server_create(struct mcast_conf *conf)
{
	int yes = 1;
	union {
		struct ip_mreq ipv4;
		struct ipv6_mreq ipv6;
	} mreq;
	struct mcast_sock *m;
	socklen_t socklen = sizeof(int);

	m = (struct mcast_sock *) malloc(sizeof(struct mcast_sock));
	if (!m)
		return NULL;
	memset(m, 0, sizeof(struct mcast_sock));

	m->interface_idx = conf->interface_idx;

	switch(conf->ipproto) {
	case AF_INET:
		mreq.ipv4.imr_multiaddr.s_addr = conf->in.inet_addr.s_addr;
		mreq.ipv4.imr_interface.s_addr =conf->ifa.interface_addr.s_addr;

	        m->addr.ipv4.sin_family = AF_INET;
	        m->addr.ipv4.sin_port = htons(conf->port);
	        m->addr.ipv4.sin_addr.s_addr = htonl(INADDR_ANY);

		m->sockaddr_len = sizeof(struct sockaddr_in); 
		break;

	case AF_INET6:
		memcpy(&mreq.ipv6.ipv6mr_multiaddr, &conf->in.inet_addr6,
		       sizeof(uint32_t) * 4);
		mreq.ipv6.ipv6mr_interface = conf->ifa.interface_index6;

		m->addr.ipv6.sin6_family = AF_INET6;
		m->addr.ipv6.sin6_port = htons(conf->port);
		m->addr.ipv6.sin6_addr = in6addr_any;

		m->sockaddr_len = sizeof(struct sockaddr_in6);
		break;
	}

	if ((m->fd = socket(conf->ipproto, SOCK_DGRAM, 0)) == -1) {
		free(m);
		return NULL;
	}

	if(conf->iface[0]) {
		struct ifreq ifr;

		strncpy(ifr.ifr_name, conf->iface, sizeof(ifr.ifr_name));

		if (ioctl(m->fd, SIOCGIFMTU, &ifr) == -1) {
			close(m->fd);
			free(m);
			return NULL;
		}
		conf->mtu = ifr.ifr_mtu;
	}

	if (setsockopt(m->fd, SOL_SOCKET, SO_REUSEADDR, &yes, 
				sizeof(int)) == -1) {
		close(m->fd);
		free(m);
		return NULL;
	}

#ifndef SO_RCVBUFFORCE
#define SO_RCVBUFFORCE 33
#endif

	if (conf->rcvbuf &&
	    setsockopt(m->fd, SOL_SOCKET, SO_RCVBUFFORCE, &conf->rcvbuf,
				sizeof(int)) == -1) {
		/* not supported in linux kernel < 2.6.14 */
		if (errno != ENOPROTOOPT) {
			close(m->fd);
			free(m);
			return NULL;
		}
	}

	getsockopt(m->fd, SOL_SOCKET, SO_RCVBUF, &conf->rcvbuf, &socklen);

	if (bind(m->fd, (struct sockaddr *) &m->addr, m->sockaddr_len) == -1) {
		close(m->fd);
		free(m);
		return NULL;
	}

	switch(conf->ipproto) {
	case AF_INET:
		if (setsockopt(m->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
			       &mreq.ipv4, sizeof(mreq.ipv4)) < 0) {
			close(m->fd);
			free(m);
			return NULL;
		}
		break;
	case AF_INET6:
		if (setsockopt(m->fd, IPPROTO_IPV6, IPV6_JOIN_GROUP,
			       &mreq.ipv6, sizeof(mreq.ipv6)) < 0) {
			close(m->fd);
			free(m);
			return NULL;
		}
		break;
	}

	return m;
}

struct mcast_sock_multi *
mcast_server_create_multi(struct mcast_conf *conf, int conf_len)
{
	struct mcast_sock_multi *m;
	int i, j;

	if (conf_len <= 0 || conf_len > MCAST_LINKS_MAX)
		return NULL;

	m = calloc(sizeof(struct mcast_sock_multi), 1);
	if (m == NULL)
		return NULL;

	m->max_mtu = INT_MAX;
	for (i=0; i<conf_len; i++) {
		m->multi[i] = mcast_server_create(&conf[i]);
		if (m->multi[i] == NULL) {
			for (j=0; j<i; j++) {
				mcast_server_destroy(m->multi[j]);
			}
			free(m);
			return NULL;
		}
		if (m->max_mtu > conf[i].mtu)
			m->max_mtu = conf[i].mtu;
	}
	m->num_links = conf_len;

	return m;
}

void mcast_server_destroy(struct mcast_sock *m)
{
	close(m->fd);
	free(m);
}

void mcast_server_destroy_multi(struct mcast_sock_multi *m)
{
	int i;

	for (i=0; i<m->num_links; i++)
		mcast_server_destroy(m->multi[i]);
	free(m);
}

static int 
__mcast_client_create_ipv4(struct mcast_sock *m, struct mcast_conf *conf)
{
	int no = 0;

	m->addr.ipv4.sin_family = AF_INET;
	m->addr.ipv4.sin_port = htons(conf->port);
	m->addr.ipv4.sin_addr = conf->in.inet_addr;
	m->sockaddr_len = sizeof(struct sockaddr_in); 

	if (setsockopt(m->fd, IPPROTO_IP, IP_MULTICAST_LOOP, &no,
		       sizeof(int)) < 0) {
		close(m->fd);
		return -1;
	}

	if (setsockopt(m->fd, IPPROTO_IP, IP_MULTICAST_IF,
		       &conf->ifa.interface_addr,
		       sizeof(struct in_addr)) == -1) {
		close(m->fd);
		return -1;
	}

	return 0;
}

static int 
__mcast_client_create_ipv6(struct mcast_sock *m, struct mcast_conf *conf)
{
	int no = 0;

	m->addr.ipv6.sin6_family = AF_INET6;
	m->addr.ipv6.sin6_port = htons(conf->port);
	memcpy(&m->addr.ipv6.sin6_addr,
	       &conf->in.inet_addr6,
	       sizeof(struct in6_addr));
	m->sockaddr_len = sizeof(struct sockaddr_in6); 

	if (setsockopt(m->fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &no,
		       sizeof(int)) < 0) {
		close(m->fd);
		return -1;
	}

	if (setsockopt(m->fd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
		       &conf->ifa.interface_index6,
		       sizeof(unsigned int)) == -1) {
		close(m->fd);
		return -1;
	}

	return 0;
}

struct mcast_sock *mcast_client_create(struct mcast_conf *conf)
{
	int ret;
	struct mcast_sock *m;
	socklen_t socklen = sizeof(int);

	m = (struct mcast_sock *) malloc(sizeof(struct mcast_sock));
	if (!m)
		return NULL;
	memset(m, 0, sizeof(struct mcast_sock));

	m->interface_idx = conf->interface_idx;

	if ((m->fd = socket(conf->ipproto, SOCK_DGRAM, 0)) == -1) {
		free(m);
		return NULL;
	}

	if (setsockopt(m->fd, SOL_SOCKET, SO_NO_CHECK, &conf->checksum, 
				sizeof(int)) == -1) {
		close(m->fd);
		free(m);
		return NULL;
	}

#ifndef SO_SNDBUFFORCE
#define SO_SNDBUFFORCE 32
#endif

	if (conf->sndbuf &&
	    setsockopt(m->fd, SOL_SOCKET, SO_SNDBUFFORCE, &conf->sndbuf,
				sizeof(int)) == -1) {
		/* not supported in linux kernel < 2.6.14 */
		if (errno != ENOPROTOOPT) {
			close(m->fd);
			free(m);
			return NULL;
		}
	}

	getsockopt(m->fd, SOL_SOCKET, SO_SNDBUF, &conf->sndbuf, &socklen);

	switch(conf->ipproto) {
		case AF_INET:
			ret = __mcast_client_create_ipv4(m, conf);
			break;
		case AF_INET6:
			ret = __mcast_client_create_ipv6(m, conf);
			break;
		default:
			ret = 0;
			break;
	}

	if (ret == -1) {
		close(m->fd);
		free(m);
		m = NULL;
	}

	return m;
}

struct mcast_sock_multi *
mcast_client_create_multi(struct mcast_conf *conf, int conf_len)
{
	struct mcast_sock_multi *m;
	int i, j;

	if (conf_len <= 0 || conf_len > MCAST_LINKS_MAX)
		return NULL;

	m = calloc(sizeof(struct mcast_sock_multi), 1);
	if (m == NULL)
		return NULL;

	m->max_mtu = INT_MAX;
	for (i=0; i<conf_len; i++) {
		m->multi[i] = mcast_client_create(&conf[i]);
		if (m->multi[i] == NULL) {
			for (j=0; j<i; j++) {
				mcast_client_destroy(m->multi[j]);
			}
			free(m);
			return NULL;
		}
		if (m->max_mtu > conf[i].mtu)
			m->max_mtu = conf[i].mtu;
	}
	m->num_links = conf_len;

	return m;
}

void mcast_client_destroy(struct mcast_sock *m)
{
	close(m->fd);
	free(m);
}

void mcast_client_destroy_multi(struct mcast_sock_multi *m)
{
	int i;

	for (i=0; i<m->num_links; i++)
		mcast_client_destroy(m->multi[i]);
	free(m);
}

ssize_t mcast_send(struct mcast_sock *m, void *data, int size)
{
	ssize_t ret;
	
	ret = sendto(m->fd, 
		     data,
		     size,
		     0,
		     (struct sockaddr *) &m->addr,
		     m->sockaddr_len);
	if (ret == -1) {
		m->stats.error++;
		return ret;
	}

	m->stats.bytes += ret;
	m->stats.messages++;  

	return ret;
}

ssize_t mcast_recv(struct mcast_sock *m, void *data, int size)
{
	ssize_t ret;
	socklen_t sin_size = sizeof(struct sockaddr_in);

        ret = recvfrom(m->fd,
		       data, 
		       size,
		       0,
		       (struct sockaddr *)&m->addr,
		       &sin_size);
	if (ret == -1) {
		m->stats.error++;
		return ret;
	}

	m->stats.bytes += ret;
	m->stats.messages++;

	return ret;
}

void mcast_set_current_link(struct mcast_sock_multi *m, int i)
{
	m->current_link = m->multi[i];
}

struct mcast_sock *mcast_get_current_link(struct mcast_sock_multi *m)
{
	return m->current_link;
}

int mcast_get_fd(struct mcast_sock *m)
{
	return m->fd;
}

int mcast_get_current_ifidx(struct mcast_sock_multi *m)
{
	return m->current_link->interface_idx;
}

int mcast_get_ifidx(struct mcast_sock_multi *m, int i)
{
	return m->multi[i]->interface_idx;
}

static int
mcast_snprintf_stats(char *buf, size_t buflen, char *ifname,
		     struct mcast_stats *s, struct mcast_stats *r)
{
	size_t size;

	size = snprintf(buf, buflen, "multicast traffic (active device=%s):\n"
				     "%20llu Bytes sent "
				     "%20llu Bytes recv\n"
				     "%20llu Pckts sent "
				     "%20llu Pckts recv\n"
				     "%20llu Error send "
				     "%20llu Error recv\n\n",
				     ifname,
				     (unsigned long long)s->bytes,
				     (unsigned long long)r->bytes,
				     (unsigned long long)s->messages,
				     (unsigned long long)r->messages,
				     (unsigned long long)s->error,
				     (unsigned long long)r->error);
	return size;
}

static int
mcast_snprintf_stats2(char *buf, size_t buflen, const char *ifname, 
		      const char *status, int active,
		      struct mcast_stats *s, struct mcast_stats *r)
{
	size_t size;

	size = snprintf(buf, buflen, 
			"multicast traffic device=%s status=%s role=%s:\n"
			"%20llu Bytes sent "
			"%20llu Bytes recv\n"
			"%20llu Pckts sent "
			"%20llu Pckts recv\n"
			"%20llu Error send "
			"%20llu Error recv\n\n",
			ifname, status, active ? "ACTIVE" : "BACKUP",
			(unsigned long long)s->bytes,
			(unsigned long long)r->bytes,
			(unsigned long long)s->messages,
			(unsigned long long)r->messages,
			(unsigned long long)s->error,
			(unsigned long long)r->error);
	return size;
}

void
mcast_dump_stats(int fd,
		 const struct mcast_sock_multi *s,
		 const struct mcast_sock_multi *r)
{
	int i;
	struct mcast_stats snd = { 0, 0, 0};
	struct mcast_stats rcv = { 0, 0, 0};
	char ifname[IFNAMSIZ], buf[512];
	int size;

	/* it is the same for the receiver, no need to do it twice */
	if_indextoname(s->current_link->interface_idx, ifname);

	for (i=0; i<s->num_links && i<r->num_links; i++) {
		snd.bytes	+= s->multi[i]->stats.bytes;
		snd.messages	+= s->multi[i]->stats.messages;
		snd.error	+= s->multi[i]->stats.error;
		rcv.bytes	+= r->multi[i]->stats.bytes;
		rcv.messages	+= r->multi[i]->stats.messages;
		rcv.error	+= r->multi[i]->stats.error;
	}
	size = mcast_snprintf_stats(buf, sizeof(buf), ifname, &snd, &rcv);
	send(fd, buf, size, 0);
}

void
mcast_dump_stats_extended(int fd,
			  const struct mcast_sock_multi *s,
			  const struct mcast_sock_multi *r,
			  const struct nlif_handle *h)
{
	int i;
	char buf[4096];
	int size = 0;

	for (i=0; i<s->num_links && i<r->num_links; i++) {
		int idx = s->multi[i]->interface_idx, active;
		unsigned int flags;
		char ifname[IFNAMSIZ];
		const char *status;

		if_indextoname(idx, ifname);
		nlif_get_ifflags(h, idx, &flags);
		active = (s->multi[i] == s->current_link);
		/* 
		 * IFF_UP shows administrative status
		 * IFF_RUNNING shows carrier status
		 */
		if (flags & IFF_UP) {
			if (!(flags & IFF_RUNNING))
				status = "NO-CARRIER";
			else
				status = "RUNNING";
		} else {
			status = "DOWN";
		}
		size += mcast_snprintf_stats2(buf+size, sizeof(buf),
					      ifname, status, active,
					      &s->multi[i]->stats,
					      &r->multi[i]->stats);
	}
	send(fd, buf, size, 0);
}
