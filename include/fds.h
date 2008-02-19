#ifndef _FDS_H_
#define _FDS_H_

struct fds {
	int	maxfd;
	int	fd_array_len;
	int	fd_array_cur;
	int	*fd_array;
	fd_set	readfds;
};

struct fds *create_fds(void);
void destroy_fds(struct fds *);
int register_fd(int fd, struct fds *fds);

#endif
