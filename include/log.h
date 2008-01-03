#ifndef _LOG_H_
#define _LOG_H_

int init_log();
void dlog(FILE *fd, int priority, char *format, ...);
void dlog_ct(FILE *fd, struct nf_conntrack *ct);
void close_log();

#endif
