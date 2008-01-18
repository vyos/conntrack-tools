#ifndef _LOG_H_
#define _LOG_H_

#include <stdio.h>

struct nf_conntrack;

int init_log(void);
void dlog(int priority, const char *format, ...);
void dlog_ct(struct nf_conntrack *ct);
void close_log(void);

#endif
