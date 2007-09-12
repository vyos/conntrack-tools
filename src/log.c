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
#include "conntrackd.h"

FILE *init_log(char *filename)
{
	FILE *fd = NULL;

	if (filename[0]) {
		fd = fopen(filename, "a+");
		if (fd == NULL) {
			fprintf(stderr, "can't open log file `%s'\n", filename);
			return NULL;
		}
	}

	if (CONFIG(syslog_facility) != -1)
		openlog(PACKAGE, LOG_PID, CONFIG(syslog_facility));

	return fd;
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

void close_log(FILE *fd)
{
	if (fd != NULL)
		fclose(fd);

	if (CONFIG(syslog_facility) != -1)
		closelog();
}
