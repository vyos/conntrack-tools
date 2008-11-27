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
#include "filter.h"
#include "log.h"
#include "alarm.h"
#include "fds.h"
#include "traffic_stats.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>

void killer(int foo)
{
	/* no signals while handling signals */
	sigprocmask(SIG_BLOCK, &STATE(block), NULL);

	nfct_close(STATE(event));
	nfct_close(STATE(request));

	if (STATE(us_filter))
		ct_filter_destroy(STATE(us_filter));
	local_server_destroy(&STATE(local));
	STATE(mode)->kill();

	nfct_close(STATE(dump));	/* cache_wt needs this here */
	destroy_fds(STATE(fds)); 

	unlink(CONFIG(lockfile));
	dlog(LOG_NOTICE, "---- shutdown received ----");
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
		dlog(LOG_ERR, "can't read from unix socket");
		return;
	}
	if (ret == 0)
		return;

	switch(type) {
	case FLUSH_MASTER:
		dlog(LOG_WARNING, "`conntrackd -F' is deprecated. "
				  "Use conntrack -F instead.");
		if (fork() == 0) {
			execlp("conntrack", "conntrack", "-F", NULL);
			exit(EXIT_SUCCESS);
		}
		return;
	case RESYNC_MASTER:
		dlog(LOG_NOTICE, "resync with master table");
		nl_dump_conntrack_table();
		return;
	}

	if (!STATE(mode)->local(fd, type, data))
		dlog(LOG_WARNING, "unknown local request %d", type);
}

static void do_overrun_alarm(struct alarm_block *a, void *data)
{
	nl_overrun_request_resync();
	add_alarm(&STATE(overrun_alarm), 2, 0);
}

static int event_handler(enum nf_conntrack_msg_type type,
			 struct nf_conntrack *ct,
			 void *data)
{
	/* skip user-space filtering if already do it in the kernel */
	if (ct_filter_conntrack(ct, !CONFIG(filter_from_kernelspace)))
		return NFCT_CB_STOP;

	switch(type) {
	case NFCT_T_NEW:
		STATE(mode)->event_new(ct);
		break;
	case NFCT_T_UPDATE:
		STATE(mode)->event_upd(ct);
		break;
	case NFCT_T_DESTROY:
		if (STATE(mode)->event_dst(ct))
			update_traffic_stats(ct);
		break;
	default:
		dlog(LOG_WARNING, "unknown msg from ctnetlink\n");
		break;
	}

	return NFCT_CB_CONTINUE;
}

static int dump_handler(enum nf_conntrack_msg_type type,
			struct nf_conntrack *ct,
			void *data)
{
	if (ct_filter_conntrack(ct, 1))
		return NFCT_CB_CONTINUE;

	switch(type) {
	case NFCT_T_UPDATE:
		STATE(mode)->dump(ct);
		break;
	default:
		dlog(LOG_WARNING, "unknown msg from ctnetlink");
		break;
	}
	return NFCT_CB_CONTINUE;
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
		dlog(LOG_ERR, "initialization failed");
		return -1;
	}

	/* local UNIX socket */
	if (local_server_create(&STATE(local), &CONFIG(local)) == -1) {
		dlog(LOG_ERR, "can't open unix socket!");
		return -1;
	}

	STATE(event) = nl_init_event_handler();
	if (STATE(event) == NULL) {
		dlog(LOG_ERR, "can't open netlink handler: %s",
		     strerror(errno));
		dlog(LOG_ERR, "no ctnetlink kernel support?");
		return -1;
	}
	nfct_callback_register(STATE(event), NFCT_T_ALL, event_handler, NULL);

	STATE(dump) = nl_init_dump_handler();
	if (STATE(dump) == NULL) {
		dlog(LOG_ERR, "can't open netlink handler: %s",
		     strerror(errno));
		dlog(LOG_ERR, "no ctnetlink kernel support?");
		return -1;
	}
	nfct_callback_register(STATE(dump), NFCT_T_ALL, dump_handler, NULL);

	if (nl_dump_conntrack_table() == -1) {
		dlog(LOG_ERR, "can't get kernel conntrack table");
		return -1;
	}

	STATE(overrun) = nl_init_overrun_handler();
	if (STATE(overrun)== NULL) {
		dlog(LOG_ERR, "can't open netlink handler: %s",
		     strerror(errno));
		dlog(LOG_ERR, "no ctnetlink kernel support?");
		return -1;
	}
	nfct_callback_register(STATE(overrun),
			       NFCT_T_ALL,
			       STATE(mode)->overrun,
			       NULL);

	/* no callback, it does not do anything with the output */
	STATE(request) = nl_init_request_handler();
	if (STATE(request) == NULL) {
		dlog(LOG_ERR, "can't open netlink handler: %s",
		     strerror(errno));
		dlog(LOG_ERR, "no ctnetlink kernel support?");
		return -1;
	}

	init_alarm(&STATE(overrun_alarm), NULL, do_overrun_alarm);

	STATE(fds) = create_fds();
	if (STATE(fds) == NULL) {
		dlog(LOG_ERR, "can't create file descriptor pool");
		return -1;
	}

	register_fd(STATE(local).fd, STATE(fds));
	register_fd(nfct_fd(STATE(event)), STATE(fds));
	register_fd(nfct_fd(STATE(overrun)), STATE(fds));

	if (STATE(mode)->register_fds &&
	    STATE(mode)->register_fds(STATE(fds)) == -1) {
		dlog(LOG_ERR, "fds registration failed");
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

	dlog(LOG_NOTICE, "initialization completed");

	return 0;
}

static void __run(struct timeval *next_alarm)
{
	int ret;
	fd_set readfds = STATE(fds)->readfds;

	ret = select(STATE(fds)->maxfd + 1, &readfds, NULL, NULL, next_alarm);
	if (ret == -1) {
		/* interrupted syscall, retry */
		if (errno == EINTR)
			return;

		dlog(LOG_WARNING, "select failed: %s", strerror(errno));
		return;
	}

	/* signals are racy */
	sigprocmask(SIG_BLOCK, &STATE(block), NULL);

	/* order received via UNIX socket */
	if (FD_ISSET(STATE(local).fd, &readfds))
		do_local_server_step(&STATE(local), NULL, local_handler);

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
				nl_overrun_request_resync();
				add_alarm(&STATE(overrun_alarm), 2, 0);
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
				dlog(LOG_WARNING,
				     "event catch says: %s", strerror(errno));
				break;
			}
		}
	}

	if (FD_ISSET(nfct_fd(STATE(overrun)), &readfds)) {
		del_alarm(&STATE(overrun_alarm));
		nfct_catch(STATE(overrun));
		if (STATE(mode)->purge)
			STATE(mode)->purge();
	}

	if (STATE(mode)->run)
		STATE(mode)->run(&readfds);

	sigprocmask(SIG_UNBLOCK, &STATE(block), NULL);
}

void __attribute__((noreturn))
run(void)
{
	struct timeval next_alarm; 
	struct timeval *next = NULL;

	while(1) {
		sigprocmask(SIG_BLOCK, &STATE(block), NULL);
		if (next != NULL && !timerisset(next))
			next = do_alarm_run(&next_alarm);
		else
			next = get_next_alarm_run(&next_alarm);
		sigprocmask(SIG_UNBLOCK, &STATE(block), NULL);

		__run(next);
	}
}
