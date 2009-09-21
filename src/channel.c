/*
 * (C) 2009 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

#include "channel.h"
#include "network.h"

static struct channel_ops *ops[CHANNEL_MAX];
extern struct channel_ops channel_mcast;
extern struct channel_ops channel_udp;
extern struct channel_ops channel_tcp;

void channel_init(void)
{
	ops[CHANNEL_MCAST] = &channel_mcast;
	ops[CHANNEL_UDP] = &channel_udp;
	ops[CHANNEL_TCP] = &channel_tcp;
}

struct channel_buffer {
	char	*data;
	int	size;
	int	len;
};

static struct channel_buffer *
channel_buffer_open(int mtu, int headersiz)
{
	struct channel_buffer *b;

	b = calloc(sizeof(struct channel_buffer), 1);
	if (b == NULL)
		return NULL;

	b->size = mtu - headersiz;

	b->data = malloc(b->size);
	if (b->data == NULL) {
		free(b);
		return NULL;
	}
	return b;
}

static void
channel_buffer_close(struct channel_buffer *b)
{
	if (b == NULL)
		return;

	free(b->data);
	free(b);
}

struct channel *
channel_open(struct channel_conf *cfg)
{
	struct channel *c;
	struct ifreq ifr;
	int fd;

	if (cfg->channel_type >= CHANNEL_MAX)
		return NULL;
	if (!cfg->channel_ifname[0])
		return NULL;
	if (cfg->channel_flags >= CHANNEL_F_MAX)
		return NULL;

	c = calloc(sizeof(struct channel), 1);
	if (c == NULL)
		return NULL;

	c->channel_type = cfg->channel_type;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		free(c);
		return NULL;
	}
	strncpy(ifr.ifr_name, cfg->channel_ifname, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFMTU, &ifr) == -1) {
		free(c);
		return NULL;
	}
	close(fd);
	c->channel_ifmtu = ifr.ifr_mtu;

	c->channel_ifindex = if_nametoindex(cfg->channel_ifname);
	if (c->channel_ifindex == 0) {
		free(c);
		return NULL;
	}
	c->ops = ops[cfg->channel_type];

	if (cfg->channel_flags & CHANNEL_F_BUFFERED) {
		c->buffer = channel_buffer_open(c->channel_ifmtu,
						c->ops->headersiz);
		if (c->buffer == NULL) {
			free(c);
			return NULL;
		}
	}
	c->channel_flags = cfg->channel_flags;

	c->data = c->ops->open(&cfg->u);
	if (c->data == NULL) {
		channel_buffer_close(c->buffer);
		free(c);
		return NULL;
	}
	return c;
}

void
channel_close(struct channel *c)
{
	c->ops->close(c->data);
	if (c->channel_flags & CHANNEL_F_BUFFERED)
		channel_buffer_close(c->buffer);
	free(c);
}

int channel_send(struct channel *c, const struct nethdr *net)
{
	int ret = 0, len = ntohs(net->len);

	if (!(c->channel_flags & CHANNEL_F_BUFFERED)) {
		c->ops->send(c->data, net, len);
		return 1;
	}
retry:
	if (c->buffer->len + len < c->buffer->size) {
		memcpy(c->buffer->data + c->buffer->len, net, len);
		c->buffer->len += len;
	} else {
		c->ops->send(c->data, c->buffer->data, c->buffer->len);
		ret = 1;
		c->buffer->len = 0;
		goto retry;
	}
	return ret;
}

int channel_send_flush(struct channel *c)
{
	if (!(c->channel_flags & CHANNEL_F_BUFFERED) || c->buffer->len == 0)
		return 0;

	c->ops->send(c->data, c->buffer->data, c->buffer->len);
	c->buffer->len = 0;
	return 1;
}

int channel_recv(struct channel *c, char *buf, int size)
{
	return c->ops->recv(c->data, buf, size);
}

int channel_get_fd(struct channel *c)
{
	return c->ops->get_fd(c->data);
}

void channel_stats(struct channel *c, int fd)
{
	return c->ops->stats(c, fd);
}

void channel_stats_extended(struct channel *c, int active,
			    struct nlif_handle *h, int fd)
{
	return c->ops->stats_extended(c, active, h, fd);
}

int channel_accept_isset(struct channel *c, fd_set *readfds)
{
	return c->ops->accept_isset(c, readfds);
}

int channel_isset(struct channel *c, fd_set *readfds)
{
	return c->ops->isset(c, readfds);
}

int channel_accept(struct channel *c)
{
	return c->ops->accept(c);
}
