#ifndef _LOG_H_
#define _LOG_H_

#include <stdio.h>

FILE *init_log(char *filename);
void dlog(FILE *fd, int priority, char *format, ...);
void close_log(FILE *fd);

#endif
