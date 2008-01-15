#ifndef _TIMER_H_
#define _TIMER_H_

#include "linux_list.h"

struct alarm_list {
	struct list_head	head;
	struct timeval		tv;
	void			*data;
	void			(*function)(struct alarm_list *a, void *data);
};

static inline void
set_alarm_expiration(struct alarm_list *t, long tv_sec, long tv_usec)
{
	t->tv.tv_sec = tv_sec;
	t->tv.tv_usec = tv_usec;
}

void init_alarm(struct alarm_list *t,
		void *data,
		void (*fcn)(struct alarm_list *a, void *data));

void add_alarm(struct alarm_list *alarm);

void del_alarm(struct alarm_list *alarm);

void mod_alarm(struct alarm_list *alarm, unsigned long sc, unsigned long usc);

int get_next_alarm(struct timeval *tv, struct timeval *next_alarm);

int do_alarm_run(struct timeval *next_alarm);

#endif
