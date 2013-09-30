#ifndef _NFCT_H_
#define _NFCT_H_

#include "linux_list.h"

enum {
	NFCT_SUBSYS_NONE = 0,
	NFCT_SUBSYS_TIMEOUT,
	NFCT_SUBSYS_HELPER,
	NFCT_SUBSYS_VERSION,
	NFCT_SUBSYS_HELP,
};

enum {
	NFCT_CMD_NONE = 0,
	NFCT_CMD_LIST,
	NFCT_CMD_ADD,
	NFCT_CMD_DELETE,
	NFCT_CMD_GET,
	NFCT_CMD_FLUSH,
	NFCT_CMD_DISABLE,
};

#define __init __attribute__((constructor))

void nfct_perror(const char *msg);

struct nfct_extension {
	struct list_head	head;
	int			type;
	int (*parse_params)(int argc, char *argv[]);
};

void nfct_extension_register(struct nfct_extension *ext);

int nfct_mnl_talk(struct mnl_socket *nl, struct nlmsghdr *nlh,
		  uint32_t seq, uint32_t portid,
		  int (*cb)(const struct nlmsghdr *nlh, void *data),
		  void *data);

#endif
