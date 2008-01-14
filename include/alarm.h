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

#endif
