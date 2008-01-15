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
#include "netlink.h"
#include "ignore.h"
#include "log.h"
#include "alarm.h"
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <errno.h>
#include "us-conntrack.h"
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>

void killer(int foo)
{
	/* no signals while handling signals */
	sigprocmask(SIG_BLOCK, &STATE(block), NULL);

	nfct_close(STATE(event));
	nfct_close(STATE(dump));

	ignore_pool_destroy(STATE(ignore_pool));
	local_server_destroy(STATE(local), CONFIG(local).path);
	STATE(mode)->kill();
        unlink(CONFIG(lockfile));
	dlog(STATE(log), LOG_NOTICE, "---- shutdown received ----");
	close_log();

	sigprocmask(SIG_UNBLOCK, &STATE(block), NULL);

	exit(0);			
}

static void child(int foo)
{
	while(wait(NULL) > 0);
}

void local_handler(int fd, void *data)
{
	int ret;
	int type;

	ret = read(fd, &type, sizeof(type));
	if (ret == -1) {
		dlog(STATE(log), LOG_ERR, "can't read from unix socket");
		return;
	}
	if (ret == 0)
		return;

	switch(type) {
	case FLUSH_MASTER:
		dlog(STATE(log), LOG_WARNING, "`conntrackd -F' is deprecated. "
				 	      "Use conntrack -F instead.");
		if (fork() == 0) {
			execlp("conntrack", "conntrack", "-F", NULL);
			exit(EXIT_SUCCESS);
		}
		return;
	case RESYNC_MASTER:
		dlog(STATE(log), LOG_NOTICE, "resync with master table");
		nl_dump_conntrack_table();
		return;
	}

	if (!STATE(mode)->local(fd, type, data))
		dlog(STATE(log), LOG_WARNING, "unknown local request %d", type);
}

int
init(void)
{
	if (CONFIG(flags) & CTD_STATS_MODE)
		STATE(mode) = &stats_mode;
	else if (CONFIG(flags) & CTD_SYNC_MODE)
		STATE(mode) = &sync_mode;
	else {
		fprintf(stderr, "WARNING: No running mode specified. "
				"Defaulting to statistics mode.\n");
		CONFIG(flags) |= CTD_STATS_MODE;
		STATE(mode) = &stats_mode;
	}

	/* Initialization */
	if (STATE(mode)->init() == -1) {
		dlog(STATE(log), LOG_ERR, "initialization failed");
		return -1;
	}

	/* local UNIX socket */
	STATE(local) = local_server_create(&CONFIG(local));
	if (!STATE(local)) {
		dlog(STATE(log), LOG_ERR, "can't open unix socket!");
		return -1;
	}

	if (nl_init_event_handler() == -1) {
		dlog(STATE(log), LOG_ERR, "can't open netlink handler! "
				 	  "no ctnetlink kernel support?");
		return -1;
	}

	if (nl_init_dump_handler() == -1) {
		dlog(STATE(log), LOG_ERR, "can't open netlink handler! "
				 "no ctnetlink kernel support?");
		return -1;
	}

        /* Signals handling */
	sigemptyset(&STATE(block));
	sigaddset(&STATE(block), SIGTERM);
	sigaddset(&STATE(block), SIGINT);
	sigaddset(&STATE(block), SIGCHLD);

	if (signal(SIGINT, killer) == SIG_ERR)
		return -1;

	if (signal(SIGTERM, killer) == SIG_ERR)
		return -1;

	/* ignore connection reset by peer */
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		return -1;

	if (signal(SIGCHLD, child) == SIG_ERR)
		return -1;

	dlog(STATE(log), LOG_NOTICE, "initialization completed");

	return 0;
}

static int __run(struct timeval *next_alarm)
{
	int max, ret;
	fd_set readfds;

	FD_ZERO(&readfds);
	FD_SET(STATE(local), &readfds);
	FD_SET(nfct_fd(STATE(event)), &readfds);

	max = MAX(STATE(local), nfct_fd(STATE(event)));

	if (STATE(mode)->add_fds_to_set)
		max = MAX(max, STATE(mode)->add_fds_to_set(&readfds));

	ret = select(max+1, &readfds, NULL, NULL, next_alarm);
	if (ret == -1) {
		/* interrupted syscall, retry */
		if (errno == EINTR)
			return 0;

		dlog(STATE(log), LOG_WARNING, 
		     "select failed: %s", strerror(errno));
		return 0;
	}

	/* timeout expired, run the alarm list */
	if (ret == 0)
		return 1;

	/* signals are racy */
	sigprocmask(SIG_BLOCK, &STATE(block), NULL);		

	/* order received via UNIX socket */
	if (FD_ISSET(STATE(local), &readfds))
		do_local_server_step(STATE(local), NULL, local_handler);

	/* conntrack event has happened */
	if (FD_ISSET(nfct_fd(STATE(event)), &readfds)) {
		while ((ret = nfct_catch(STATE(event))) != -1);
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
				/* XXX: schedule overrun call via alarm */
				STATE(mode)->overrun();
				break;
			case ENOENT:
				/*
				 * We received a message from another
				 * netfilter subsystem that we are not
				 * interested in. Just ignore it.
				 */
				break;
			case EAGAIN:
				break;
			default:
				dlog(STATE(log), LOG_WARNING,
				     "event catch says: %s", strerror(errno));
				break;
			}
		}
	}

	if (STATE(mode)->run)
		STATE(mode)->run(&readfds);

	sigprocmask(SIG_UNBLOCK, &STATE(block), NULL);

	return 0;
}

void __attribute__((noreturn))
run(void)
{
	struct timeval next_alarm;
	struct timeval *next = &next_alarm;
	struct timeval tv;

	/* initialization: get the first alarm available */
	gettimeofday(&tv, NULL);
	if (!get_next_alarm(&tv, next))
		next = NULL;

	while(1) {
		if (__run(next)) {
			sigprocmask(SIG_BLOCK, &STATE(block), NULL);
			next = &next_alarm;
			if (!do_alarm_run(next))
				next = NULL; /* no next alarms */
			sigprocmask(SIG_UNBLOCK, &STATE(block), NULL);
		}
	}
}
