#ifndef _NFCT_H_
#define _NFCT_H_

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

void nfct_perror(const char *msg);

int nfct_cmd_timeout_parse_params(int argc, char *argv[]);
int nfct_cmd_timeout_list(int argc, char *argv[]);
int nfct_cmd_timeout_add(int argc, char *argv[]);
int nfct_cmd_timeout_delete(int argc, char *argv[]);
int nfct_cmd_timeout_get(int argc, char *argv[]);
int nfct_cmd_timeout_flush(int argc, char *argv[]);

int nfct_cmd_helper_parse_params(int argc, char *argv[]);
int nfct_cmd_helper_list(int argc, char *argv[]);
int nfct_cmd_helper_add(int argc, char *argv[]);
int nfct_cmd_helper_delete(int argc, char *argv[]);
int nfct_cmd_helper_get(int argc, char *argv[]);
int nfct_cmd_helper_flush(int argc, char *argv[]);
int nfct_cmd_helper_disable(int argc, char *argv[]);

#endif
