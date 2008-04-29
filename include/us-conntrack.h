#ifndef _US_CONNTRACK_H_
#define _US_CONNTRACK_H_

#include "alarm.h"
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

struct us_conntrack {
	struct 	nf_conntrack *ct;
	struct  cache *cache; 
	struct	alarm_block alarm;
	char 	data[0];
};

#endif
