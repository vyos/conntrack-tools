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

#include "alarm.h"
#include "jhash.h"
#include <stdlib.h>
#include <limits.h>

#define ALARM_HASH_SIZE		2048

static struct list_head *alarm_hash;
int alarm_counter;

void init_alarm(struct alarm_list *t,
		void *data,
		void (*fcn)(struct alarm_list *a, void *data))
{
	/* initialize the head to check whether a node is inserted */
	INIT_LIST_HEAD(&t->head);
	timerclear(&t->tv);
	t->data = data;
	t->function = fcn;
}

static void
__add_alarm(struct alarm_list *alarm)
{
	struct alarm_list *t;
	int i = jhash(alarm, sizeof(alarm), 0) % ALARM_HASH_SIZE;

	list_for_each_entry(t, &alarm_hash[i], head) {
		if (timercmp(&alarm->tv, &t->tv, <)) {
			list_add_tail(&alarm->head, &t->head);
			return;
		}
	}
	list_add_tail(&alarm->head, &alarm_hash[i]);
}

void add_alarm(struct alarm_list *alarm, unsigned long sc, unsigned long usc)
{
	struct timeval tv;

	del_alarm(alarm);
	alarm->tv.tv_sec = sc;
	alarm->tv.tv_usec = usc;
	gettimeofday(&tv, NULL);
	timeradd(&alarm->tv, &tv, &alarm->tv);
	__add_alarm(alarm);
	alarm_counter++;
}

void del_alarm(struct alarm_list *alarm)
{
	/* don't remove a non-inserted node */
	if (!list_empty(&alarm->head)) {
		list_del_init(&alarm->head);
		alarm_counter--;
	}
}

static int 
calculate_next_run(struct timeval *cand,
		   struct timeval *tv, 
		   struct timeval *next_run)
{
	if (cand->tv_sec != LONG_MAX) {
		if (timercmp(cand, tv, >))
			timersub(cand, tv, next_run);
		else {
			/* loop again inmediately */
			next_run->tv_sec = 0;
			next_run->tv_usec = 0;
		}
		return 1;
	}
	return 0;
}

int get_next_alarm_run(struct timeval *next_run)
{
	int i;
	struct alarm_list *t;
	struct timeval tv;
	struct timeval cand = {
		.tv_sec = LONG_MAX,
		.tv_usec = LONG_MAX
	};

	gettimeofday(&tv, NULL);

	for (i=0; i<ALARM_HASH_SIZE; i++) {
		if (!list_empty(&alarm_hash[i])) {
			t = list_entry(alarm_hash[i].next, 
				       struct alarm_list,
				       head);
			if (timercmp(&t->tv, &cand, <)) {
				cand.tv_sec = t->tv.tv_sec;
				cand.tv_usec = t->tv.tv_usec;
			}
		}
	}

	return calculate_next_run(&cand, &tv, next_run);
}

static inline int 
tv_compare(struct alarm_list *a, struct timeval *cur, struct timeval *cand)
{
	if (timercmp(&a->tv, cur, >)) {
		/* select the next alarm candidate */
		if (timercmp(&a->tv, cand, <)) {
			cand->tv_sec = a->tv.tv_sec;
			cand->tv_usec = a->tv.tv_usec;
		}
		return 1;
	}
	return 0;
}

int do_alarm_run(struct timeval *next_run)
{
	int i;
	struct alarm_list *t, *next, *prev;
	struct timeval tv;
	struct timeval cand = {
		.tv_sec = LONG_MAX,
		.tv_usec = LONG_MAX
	};

	gettimeofday(&tv, NULL);

	for (i=0; i<ALARM_HASH_SIZE; i++) {
		list_for_each_entry_safe(t, next, &alarm_hash[i], head) {
			if (tv_compare(t, &tv, &cand))
				break;

			/* annotate previous alarm */
			prev = list_entry(next->head.prev,
					  struct alarm_list,
					  head);

			del_alarm(t);
			t->function(t, t->data);

			/* Special case: One deleted node is inserted 
			 * again in the same place */
			if (next->head.prev == &prev->head) {
				t = list_entry(next->head.prev,
					       struct alarm_list,
					       head);
				if (tv_compare(t, &tv, &cand))
					break;
			}
		}
	}

	return calculate_next_run(&cand, &tv, next_run);
}

int init_alarm_hash(void)
{
	int i;

	alarm_hash = malloc(sizeof(struct list_head) * ALARM_HASH_SIZE);
	if (alarm_hash == NULL)
		return -1;

	for (i=0; i<ALARM_HASH_SIZE; i++)
		INIT_LIST_HEAD(&alarm_hash[i]);

	return 0;
}

void destroy_alarm_hash(void)
{
	free(alarm_hash);
}
