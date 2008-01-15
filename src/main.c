/*
 * (C) 2006-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdlib.h>
#include "conntrackd.h"
#include "log.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <linux/capability.h>
#include <errno.h>
#include "hash.h"
#include "jhash.h"

#undef _POSIX_SOURCE
#include <sys/capability.h>

struct ct_general_state st;
union ct_state state;

static const char usage_daemon_commands[] =
	"Daemon mode commands:\n"
	"  -d [options]\t\tRun in daemon mode\n";

static const char usage_client_commands[] = 
	"Client mode commands:\n"
	"  -c, commit external cache to conntrack table\n"
	"  -f, flush internal and external cache\n"
	"  -F, flush kernel conntrack table\n"
	"  -i, display content of the internal cache\n"
	"  -e, display the content of the external cache\n"
	"  -k, kill conntrack daemon\n"
	"  -s, dump statistics\n"
	"  -R, resync with kernel conntrack table\n"
	"  -n, request resync with other node (only FT-FW mode)\n"
	"  -x, dump cache in XML format (requires -i or -e)";

static const char usage_options[] =
	"Options:\n"
	"  -C [configfile], configuration file path\n";

static void
show_usage(char *progname)
{
	fprintf(stdout, "Connection tracking userspace daemon v%s\n", VERSION);
	fprintf(stdout, "Usage: %s [commands] [options]\n\n", progname);
	fprintf(stdout, "%s\n", usage_daemon_commands);
	fprintf(stdout, "%s\n", usage_client_commands);
	fprintf(stdout, "%s\n", usage_options);
}

static void
set_operation_mode(int *current, int want, char *argv[])
{
	if (*current == NOT_SET) {
		*current = want;
		return;
	}
	if (*current != want) {
		show_usage(argv[0]);
		fprintf(stderr, "\nError: Invalid parameters\n");
		exit(EXIT_FAILURE);
	}
}

static int check_capabilities(void)
{
	int ret;
	cap_user_header_t hcap;
	cap_user_data_t dcap;

	hcap = malloc(sizeof(cap_user_header_t));
	if (!hcap)
		return -1;

	hcap->version = _LINUX_CAPABILITY_VERSION;
	hcap->pid = getpid();

	dcap = malloc(sizeof(cap_user_data_t));
	if (!dcap) {
		free(hcap);
		return -1;
	}

	if (capget(hcap, dcap) == -1) {
		free(hcap);
		free(dcap);
		return -1;
	}

	ret = dcap->permitted & (1 << CAP_NET_ADMIN);

	free(hcap);
	free(dcap);

	return ret;
}

int main(int argc, char *argv[])
{
	int ret, i, config_set = 0, action = -1;
	char config_file[PATH_MAX];
	int type = 0;
	struct utsname u;
	int version, major, minor;

	/* Check kernel version: it must be >= 2.6.18 */
	if (uname(&u) == -1) {
		fprintf(stderr, "Can't retrieve kernel version via uname()\n");
		exit(EXIT_FAILURE);
	}
	sscanf(u.release, "%d.%d.%d", &version, &major, &minor);
	if (version < 2 && major < 6) {
		fprintf(stderr, "Linux kernel version must be >= 2.6.18\n");
		exit(EXIT_FAILURE);
	}

	if (major == 6 && minor < 18) {
		fprintf(stderr, "Linux kernel version must be >= 2.6.18\n");
		exit(EXIT_FAILURE);
	}

	ret = check_capabilities();
	switch (ret) {
		case -1:
			fprintf(stderr, "Can't get capabilities\n");
			exit(EXIT_FAILURE);
			break;
		case 0:
			fprintf(stderr, "You require CAP_NET_ADMIN in order "
					"to run conntrackd\n");
			exit(EXIT_FAILURE);
			break;
		default:
			break;
	}

	for (i=1; i<argc; i++) {
		switch(argv[i][1]) {
		case 'd':
			set_operation_mode(&type, DAEMON, argv);
			break;
		case 'c':
			set_operation_mode(&type, REQUEST, argv);
			action = COMMIT;
			break;
		case 'i':
			set_operation_mode(&type, REQUEST, argv);
			action = DUMP_INTERNAL;
			break;
		case 'e':
			set_operation_mode(&type, REQUEST, argv);
			action = DUMP_EXTERNAL;
			break;
		case 'C':
			if (++i < argc) {
				strncpy(config_file, argv[i], PATH_MAX);
				if (strlen(argv[i]) >= PATH_MAX){
					config_file[PATH_MAX-1]='\0';
					fprintf(stderr, "Path to config file "
						        "to long. Cutting it "
							"down to %d characters",
							PATH_MAX);
				}
				config_set = 1;
				break;
			}
			show_usage(argv[0]);
			fprintf(stderr, "Missing config filename\n");
			break;
		case 'F':
			set_operation_mode(&type, REQUEST, argv);
			action = FLUSH_MASTER;
			break;
		case 'f':
			set_operation_mode(&type, REQUEST, argv);
			action = FLUSH_CACHE;
			break;
		case 'R':
			set_operation_mode(&type, REQUEST, argv);
			action = RESYNC_MASTER;
			break;
		case 'B':
			set_operation_mode(&type, REQUEST, argv);
			action = SEND_BULK;
			break;
		case 'k':
			set_operation_mode(&type, REQUEST, argv);
			action = KILL;
			break;
		case 's':
			set_operation_mode(&type, REQUEST, argv);
			action = STATS;
			break;
		case 'S':
			fprintf(stderr, "WARNING: -S option is obsolete. "
					"Ignoring.\n");
			break;
		case 'n':
			set_operation_mode(&type, REQUEST, argv);
			action = REQUEST_DUMP;
			break;
		case 'x':
			if (action == DUMP_INTERNAL)
				action = DUMP_INT_XML;
			else if (action == DUMP_EXTERNAL)
				action = DUMP_EXT_XML;
			else {
				show_usage(argv[0]);
				fprintf(stderr, "Error: Invalid parameters\n");
				exit(EXIT_FAILURE);

			}
			break;
		default:
			show_usage(argv[0]);
			fprintf(stderr, "Unknown option: %s\n", argv[i]);
			return 0;
			break;
		}
	}

	if (config_set == 0)
		strcpy(config_file, DEFAULT_CONFIGFILE);

	umask(0177);

	if ((ret = init_config(config_file)) == -1) {
		fprintf(stderr, "can't open config file `%s'\n", config_file);
		exit(EXIT_FAILURE);
	}

	/*
	 * Setting up logging
	 */
	if (init_log() == -1)
		exit(EXIT_FAILURE);

	if (type == REQUEST) {
		if (do_local_request(action, &conf.local, local_step) == -1) {
			fprintf(stderr, "can't connect: is conntrackd "
					"running? appropriate permissions?\n");
			exit(EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);
	}

	/*
	 * lock file
	 */
	ret = open(CONFIG(lockfile), O_CREAT | O_EXCL | O_TRUNC, 0600);
	if (ret == -1) {
		fprintf(stderr, "lockfile `%s' exists, perhaps conntrackd "
			        "already running?\n", CONFIG(lockfile));
		exit(EXIT_FAILURE);
	}
	close(ret);

	/*
	 * initialization process
	 */

	if (init() == -1) {
		close_log();
		fprintf(stderr, "ERROR: conntrackd cannot start, please "
				"check the logfile for more info\n");
		unlink(CONFIG(lockfile));
		exit(EXIT_FAILURE);
	}

	/* Daemonize conntrackd */
	if (type == DAEMON) {
		pid_t pid, sid;

		if ((pid = fork()) == -1) {
			perror("fork has failed: ");
			exit(EXIT_FAILURE);
		} else if (pid)
			exit(EXIT_SUCCESS);
		
		sid = setsid();

		if (sid < 0) {
			perror("setsid has failed: ");
			exit(EXIT_FAILURE);
		}

		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);

		dlog(STATE(log), LOG_NOTICE, "-- starting in daemon mode --");
	} else
		dlog(STATE(log), LOG_NOTICE, "-- starting in console mode --");

	/*
	 * run main process
	 */
	run();
	return 0;
}
