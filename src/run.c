/*
 * (C) 2006-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
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
 * Description: run and init functions
 */

#include "conntrackd.h"
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <errno.h>
#include "us-conntrack.h"
#include <signal.h>
#include <stdlib.h>

void killer(int foo)
{
	/* no signals while handling signals */
	sigprocmask(SIG_BLOCK, &STATE(block), NULL);

	nfnl_subsys_close(STATE(subsys_event));
	nfnl_subsys_close(STATE(subsys_dump));
	nfnl_close(STATE(event));
	nfnl_close(STATE(dump));

	ignore_pool_destroy(STATE(ignore_pool));
	local_server_destroy(STATE(local));
	STATE(mode)->kill();
        unlink(CONFIG(lockfile));
	dlog(STATE(log), "------- shutdown received ----");
	close_log(STATE(log));

	sigprocmask(SIG_UNBLOCK, &STATE(block), NULL);

	exit(0);			
}

void local_handler(int fd, void *data)
{
	int ret;
	int type;

	ret = read(fd, &type, sizeof(type));
	if (ret == -1) {
		dlog(STATE(log), "can't read from unix socket\n");
		return;
	}
	if (ret == 0) {
		debug("nothing to process\n");
		return;
	}

	switch(type) {
	case FLUSH_MASTER:
		dlog(STATE(log), "[REQ] flushing master table");
		nl_flush_master_conntrack_table();
		return;
	case RESYNC_MASTER:
		dlog(STATE(log), "[REQ] resync with master table");
		nl_dump_conntrack_table(STATE(dump), STATE(subsys_dump));
		return;
	}

	if (!STATE(mode)->local(fd, type, data))
		dlog(STATE(log), "[FAIL] unknown local request %d", type);
}

int init(int mode)
{
	switch(mode) {
		case STATS_MODE:
			STATE(mode) = &stats_mode;
			break;
		case SYNC_MODE:
			STATE(mode) = &sync_mode;
			break;
		default:
			fprintf(stderr, "Unknown running mode! default "
					"to synchronization mode\n");
			STATE(mode) = &sync_mode;
			break;
	}

	/* Initialization */
	if (STATE(mode)->init() == -1) {
		dlog(STATE(log), "[FAIL] initialization failed");
		return -1;
	}

	/* local UNIX socket */
	STATE(local) = local_server_create(&CONFIG(local));
	if (!STATE(local)) {
		dlog(STATE(log), "[FAIL] can't open unix socket!");
		return -1;
	}

	if (nl_init_event_handler() == -1) {
		dlog(STATE(log), "[FAIL] can't open netlink handler! "
				 "no ctnetlink kernel support?");
		return -1;
	}

	if (nl_init_dump_handler() == -1) {
		dlog(STATE(log), "[FAIL] can't open netlink handler! "
				 "no ctnetlink kernel support?");
		return -1;
	}

        /* Signals handling */
	sigemptyset(&STATE(block));
	sigaddset(&STATE(block), SIGTERM);
	sigaddset(&STATE(block), SIGINT);

	if (signal(SIGINT, killer) == SIG_ERR)
		return -1;

	if (signal(SIGTERM, killer) == SIG_ERR)
		return -1;

	/* ignore connection reset by peer */
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		return -1;

	dlog(STATE(log), "[OK] initialization completed");

	return 0;
}

#define POLL_NSECS 1

static void __run(void)
{
	int max, ret;
	fd_set readfds;
	struct timeval tv = {
		.tv_sec         = POLL_NSECS,
		.tv_usec        = 0
	};

	FD_ZERO(&readfds);
	FD_SET(STATE(local), &readfds);
	FD_SET(nfnl_fd(STATE(event)), &readfds);

	max = MAX(STATE(local), nfnl_fd(STATE(event)));

	if (STATE(mode)->add_fds_to_set)
		max = MAX(max, STATE(mode)->add_fds_to_set(&readfds));

	ret = select(max+1, &readfds, NULL, NULL, &tv);
	if (ret == -1) {
		/* interrupted syscall, retry */
		if (errno == EINTR)
			return;

		dlog(STATE(log), "select() failed: %s", strerror(errno));
		return;
	}

	/* signals are racy */
	sigprocmask(SIG_BLOCK, &STATE(block), NULL);		

	/* order received via UNIX socket */
	if (FD_ISSET(STATE(local), &readfds))
		do_local_server_step(STATE(local), NULL, local_handler);

	/* conntrack event has happened */
	if (FD_ISSET(nfnl_fd(STATE(event)), &readfds)) {
		ret = nfnl_catch(STATE(event));
		if (ret == -1) {
			switch(errno) {
			case ENOBUFS:
                		/*
		 		 * It seems that ctnetlink can't back off,
				 * it's likely that we're losing events.
				 * Solution: duplicate the socket buffer
				 * size and resync with master conntrack table.
				 */
				nl_resize_socket_buffer(STATE(event));
				STATE(mode)->overrun();
				break;
			case ENOENT:
				/*
				 * We received a message from another
				 * netfilter subsystem that we are not
				 * interested in. Just ignore it.
				 */
				break;
			default:
				dlog(STATE(log), "event catch says: %s",
						  strerror(errno));
				break;
			}
		}
	}

	if (STATE(mode)->step)
		STATE(mode)->step(&readfds);

	sigprocmask(SIG_UNBLOCK, &STATE(block), NULL);
}

void run(void)
{
	while(1)
		__run();
}
