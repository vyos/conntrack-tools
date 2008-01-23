#ifndef _TIMER_H_
#define _TIMER_H_

#include "linux_list.h"

#include <sys/time.h>

struct alarm_list {
	struct list_head	head;
	struct timeval		tv;
	void			*data;
	void			(*function)(struct alarm_list *a, void *data);
};

int init_alarm_hash(void);

void destroy_alarm_hash(void);

void init_alarm(struct alarm_list *t,
		void *data,
		void (*fcn)(struct alarm_list *a, void *data));

void add_alarm(struct alarm_list *alarm, unsigned long sc, unsigned long usc);

void del_alarm(struct alarm_list *alarm);

int alarm_pending(struct alarm_list *alarm);

struct timeval *
get_next_alarm_run(struct timeval *next_alarm);

struct timeval *
do_alarm_run(struct timeval *next_alarm);

#endif
