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
 */

#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include "linux_list.h"
#include "conntrackd.h"
#include "alarm.h"
#include "jhash.h"
#include <time.h>
#include <errno.h>

static LIST_HEAD(alarm_list);

void set_alarm_function(struct alarm_list *t,
			void (*fcn)(struct alarm_list *a, void *data))
{
	t->function = fcn;
}

void set_alarm_data(struct alarm_list *t, void *data)
{
	t->data = data;
}

void init_alarm(struct alarm_list *t)
{
	timerclear(&t->tv);
	t->data 	= 0;
	t->function 	= NULL;
}

void __add_alarm(struct alarm_list *alarm)
{
	struct alarm_list *t;

	list_for_each_entry(t, &alarm_list, head) {
		if (timercmp(&alarm->tv, &t->tv, <)) {
			list_add_tail(&alarm->head, &t->head);
			return;
		}
	}
	list_add_tail(&alarm->head, &alarm_list);
}

void add_alarm(struct alarm_list *alarm)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	alarm->tv.tv_sec += tv.tv_sec;
	__add_alarm(alarm);
}

void del_alarm(struct alarm_list *alarm)
{
	list_del(&alarm->head);
}

void mod_alarm(struct alarm_list *alarm, unsigned long sc, unsigned long usc)
{
	struct timeval tv;

	list_del(&alarm->head);
	gettimeofday(&tv, NULL);
	alarm->tv.tv_sec = tv.tv_sec + sc;
	alarm->tv.tv_usec = usc;
	__add_alarm(alarm);
}

int get_next_alarm(struct timeval *tv, struct timeval *next_alarm)
{
	struct alarm_list *t;

	list_for_each_entry(t, &alarm_list, head) {
		timersub(&t->tv, tv, next_alarm);
		return 1;
	}
	return 0;
}

int do_alarm_run(struct timeval *next_alarm)
{
	struct alarm_list *t, *tmp;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	list_for_each_entry_safe(t, tmp, &alarm_list, head) {
		if (timercmp(&t->tv, &tv, >)) {
			timersub(&t->tv, &tv, next_alarm);
			return 1;
		}

		del_alarm(t);
		t->function(t, t->data);
	}

	/* check for refreshed alarms to get the next one */
	return get_next_alarm(&tv, next_alarm);
}
