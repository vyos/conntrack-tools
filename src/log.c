/*
 * (C) 2006 by Pablo Neira Ayuso <pablo@netfilter.org>
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
 * Description: Logging support for the conntrack daemon
 */

#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>
#include "buffer.h"
#include "conntrackd.h"

int init_log(void)
{
	if (CONFIG(logfile)[0]) {
		STATE(log) = fopen(CONFIG(logfile), "a+");
		if (STATE(log) == NULL) {
			fprintf(stderr, "can't open log file `%s'\n", 
				CONFIG(logfile));
			return -1;
		}
	}

	if (CONFIG(stats).logfile[0]) {
		STATE(stats_log) = fopen(CONFIG(stats).logfile, "a+");
		if (STATE(stats_log) == NULL) {
			fprintf(stderr, "can't open log file `%s'\n", 
				CONFIG(stats).logfile);
			return -1;
		}
	}

	if (CONFIG(syslog_facility) != -1 || 
	    CONFIG(stats).syslog_facility != -1)
		openlog(PACKAGE, LOG_PID, CONFIG(syslog_facility));

	return 0;
}

void dlog(FILE *fd, int priority, char *format, ...)
 {
	time_t t;
	char *buf;
	char *prio;
 	va_list args;
 
	if (fd) {
		t = time(NULL);
		buf = ctime(&t);
		buf[strlen(buf)-1]='\0';
		switch (priority) {
		case LOG_INFO:
			prio = "info";
			break;
		case LOG_NOTICE:
			prio = "notice";
			break;
		case LOG_WARNING:
			prio = "warning";
			break;
		case LOG_ERR:
			prio = "ERROR";
			break;
		default:
			prio = "?";
			break;
		}
		va_start(args, format);
		fprintf(fd, "[%s] (pid=%d) [%s] ", buf, getpid(), prio);
		vfprintf(fd, format, args);
		va_end(args);
		fprintf(fd, "\n");
		fflush(fd);
	}

	if (CONFIG(syslog_facility) != -1) {
		va_start(args, format);
		vsyslog(priority, format, args);
		va_end(args);
	}
}

void dlog_buffered_ct_flush(void *buffer_data, void *data)
{
	FILE *fd = data;

	fprintf(fd, "%s", buffer_data);
	fflush(fd);
}

void dlog_buffered_ct(FILE *fd, struct buffer *b, struct nf_conntrack *ct)
{
	time_t t;
	char buf[1024];
	char *tmp;
		
	t = time(NULL);
	ctime_r(&t, buf);
	tmp = buf + strlen(buf);
	buf[strlen(buf)-1]='\t';
	nfct_snprintf(buf+strlen(buf), 1024-strlen(buf), ct, 0, 0, 0);

	if (fd) {
		snprintf(buf+strlen(buf), 1024-strlen(buf), "\n");
		/* zero size buffer: force fflush */
		if (buffer_size(b) == 0) {
			fprintf(fd, "%s", buf);
			fflush(fd);
		}

		if (buffer_add(b, buf, strlen(buf)) == -1) {
			buffer_flush(b, dlog_buffered_ct_flush, fd);
			if (buffer_add(b, buf, strlen(buf)) == -1) {
				/* buffer too small, catacrocket! */
				fprintf(fd, "%s", buf);
				fflush(fd);
			}
		}
	}

	if (CONFIG(stats).syslog_facility != -1)
		syslog(LOG_INFO, "%s", tmp);
}

void close_log(void)
{
	if (STATE(log) != NULL)
		fclose(STATE(log));

	if (STATE(stats_log) != NULL)
		fclose(STATE(stats_log));

	if (CONFIG(syslog_facility) != -1)
		closelog();
}
