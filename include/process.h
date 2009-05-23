#ifndef _PROCESS_H_
#define _PROCESS_H_

struct child_process {
	struct list_head	head;
	int			pid;
	void			(*cb)(void *data);
	void			*data;
};

int fork_process_new(void (*cb)(void *data), void *data);
int fork_process_delete(int pid);

#endif
