#ifndef _LOG_H_
#define _LOG_H_

#include <stdio.h>

struct buffer;
struct nf_conntrack;

int init_log();
void dlog(FILE *fd, int priority, char *format, ...);
void dlog_buffered_ct(FILE *fd, struct buffer *b, struct nf_conntrack *ct);
void dlog_buffered_ct_flush(void *buffer_data, void *data);
void close_log();

#endif
