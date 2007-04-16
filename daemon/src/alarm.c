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
#include "linux_list.h"
#include "conntrackd.h"
#include "alarm.h"
#include "jhash.h"
#include <pthread.h>
#include <time.h>
#include <errno.h>

/* alarm cascade */
#define ALARM_CASCADE_SIZE     10
static struct list_head *alarm_cascade;

/* thread stuff */
static pthread_t alarm_thread;

struct alarm_list *create_alarm()
{	
	return (struct alarm_list *) malloc(sizeof(struct alarm_list));
}

void destroy_alarm(struct alarm_list *t)
{
	free(t);
}

void set_alarm_expiration(struct alarm_list *t, unsigned long expires)
{
	t->expires = expires;
}

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
	INIT_LIST_HEAD(&t->head);

	t->expires 	= 0;
	t->data 	= 0;
	t->function 	= NULL;
}

void add_alarm(struct alarm_list *alarm)
{
	unsigned int pos = jhash(alarm, sizeof(alarm), 0) % ALARM_CASCADE_SIZE;

	list_add(&alarm->head, &alarm_cascade[pos]);
}

void del_alarm(struct alarm_list *alarm)
{
	list_del(&alarm->head);
}

int mod_alarm(struct alarm_list *alarm, unsigned long expires)
{
	alarm->expires = expires;
	return 0;
}

void __run_alarms()
{
	struct list_head *i, *tmp;
	struct alarm_list *t;
	struct timespec req = {0, 1000000000 / ALARM_CASCADE_SIZE};
	struct timespec rem;
	static int step = 0;

retry:
	if (nanosleep(&req, &rem) == -1) {
		/* interrupted syscall: retry with remaining time */
		if (errno == EINTR) {
			memcpy(&req, &rem, sizeof(struct timespec));
			goto retry;
		}
	}

	lock();
	list_for_each_safe(i, tmp, &alarm_cascade[step]) {
		t = (struct alarm_list *) i;

		t->expires--;
		if (t->expires == 0)
			t->function(t, t->data);
	}
	step = (step + 1) < ALARM_CASCADE_SIZE ? step + 1 : 0;
	unlock();
}

void *run_alarms(void *foo)
{
	while(1)
		__run_alarms();
}

int create_alarm_thread()
{
	int i;

	alarm_cascade = malloc(sizeof(struct list_head) * ALARM_CASCADE_SIZE);
	if (alarm_cascade == NULL)
		return -1;

	for (i=0; i<ALARM_CASCADE_SIZE; i++)
		INIT_LIST_HEAD(&alarm_cascade[i]);

	return pthread_create(&alarm_thread, NULL, run_alarms, NULL);
}

int destroy_alarm_thread()
{
	return pthread_cancel(alarm_thread);
}
