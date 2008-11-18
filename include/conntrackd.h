#ifndef _CONNTRACKD_H_
#define _CONNTRACKD_H_

#include "mcast.h"
#include "local.h"
#include "alarm.h"
#include "filter.h"

#include <stdint.h>
#include <stdio.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <syslog.h>

/* UNIX facilities */
#define FLUSH_MASTER	0	/* flush kernel conntrack table 	*/
#define RESYNC_MASTER	1	/* resync with kernel conntrack table 	*/
#define DUMP_INTERNAL 	16	/* dump internal cache 			*/
#define DUMP_EXTERNAL 	17	/* dump external cache 			*/
#define COMMIT		18	/* commit external cache		*/
#define FLUSH_CACHE	19	/* flush cache				*/
#define KILL		20	/* kill conntrackd			*/
#define STATS		21	/* dump statistics			*/
#define SEND_BULK	22	/* send a bulk				*/
#define REQUEST_DUMP	23	/* request dump 			*/
#define DUMP_INT_XML	24	/* dump internal cache in XML		*/
#define DUMP_EXT_XML	25	/* dump external cache in XML		*/
#define RESET_TIMERS	26	/* reset kernel timers			*/
#define DEBUG_INFO	27	/* show debug info (if any)		*/

#define DEFAULT_CONFIGFILE	"/etc/conntrackd/conntrackd.conf"
#define DEFAULT_LOCKFILE	"/var/lock/conntrackd.lock"
#define DEFAULT_LOGFILE		"/var/log/conntrackd.log"
#define DEFAULT_STATS_LOGFILE	"/var/log/conntrackd-stats.log"
#define DEFAULT_SYSLOG_FACILITY	LOG_DAEMON

enum {
	SYNC_MODE_ALARM_BIT = 0,
	SYNC_MODE_ALARM = (1 << SYNC_MODE_ALARM_BIT),

	SYNC_MODE_FTFW_BIT = 1,
	SYNC_MODE_FTFW = (1 << SYNC_MODE_FTFW_BIT),

	DONT_CHECKSUM_BIT = 2,
	DONT_CHECKSUM = (1 << DONT_CHECKSUM_BIT),
};

/* daemon/request modes */
#define NOT_SET         0
#define DAEMON		1
#define REQUEST		2

/* conntrackd modes */
#define CTD_SYNC_MODE		(1UL << 0)
#define CTD_STATS_MODE		(1UL << 1)
#define CTD_SYNC_FTFW		(1UL << 2)
#define CTD_SYNC_ALARM		(1UL << 3)
#define CTD_SYNC_NOTRACK	(1UL << 4)

/* FILENAME_MAX is 4096 on my system, perhaps too much? */
#ifndef FILENAME_MAXLEN
#define FILENAME_MAXLEN 256
#endif

union inet_address {
	uint32_t ipv4;
	uint32_t ipv6[4];
	uint32_t all[4];
};

#define CONFIG(x) conf.x

struct ct_conf {
	char logfile[FILENAME_MAXLEN];
	int syslog_facility;
	char lockfile[FILENAME_MAXLEN];
	int hashsize;			/* hashtable size */
	struct mcast_conf mcast;	/* multicast settings */
	struct local_conf local;	/* unix socket facilities */
	int limit;
	int refresh;
	int cache_timeout;		/* cache entries timeout */
	int commit_timeout;		/* committed entries timeout */
	unsigned int purge_timeout;	/* purge kernel entries timeout */
	int del_timeout;
	unsigned int netlink_buffer_size;
	unsigned int netlink_buffer_size_max_grown;
	union inet_address *listen_to;
	unsigned int listen_to_len;
	unsigned int flags;
	int family;			/* protocol family */
	unsigned int resend_queue_size; /* FTFW protocol */
	unsigned int window_size;
	int cache_write_through;
	int filter_from_kernelspace;
	struct {
		char logfile[FILENAME_MAXLEN];
		int syslog_facility;
		size_t buffer_size;
	} stats;
};

#define STATE(x) st.x

struct ct_general_state {
	sigset_t 			block;
	FILE 				*log;
	FILE				*stats_log;
	struct local_server		local;
	struct ct_mode 			*mode;
	struct ct_filter		*us_filter;

	struct nfct_handle		*event;         /* event handler */
	struct nfct_filter		*filter;	/* event filter */

	struct nfct_handle		*dump;		/* dump handler */
	struct nfct_handle		*request;	/* request handler */
	struct nfct_handle		*overrun;	/* overrun handler */
	struct alarm_block		overrun_alarm;

	struct fds			*fds;

	/* statistics */
	uint64_t			malformed;
	uint64_t 			bytes[NFCT_DIR_MAX];
	uint64_t 			packets[NFCT_DIR_MAX];
};

#define STATE_SYNC(x) state.sync->x

struct ct_sync_state {
	struct cache *internal; 	/* internal events cache (netlink) */
	struct cache *external; 	/* external events cache (mcast) */

	struct mcast_sock *mcast_server;  /* multicast socket: incoming */
	struct mcast_sock *mcast_client;  /* multicast socket: outgoing  */
	struct evfd *evfd;		  /* event fd */

	struct sync_mode *sync;		/* sync mode */

	uint32_t last_seq_sent;	/* last sequence number sent */
	uint32_t last_seq_recv;	/* last sequence number recv */
	uint64_t packets_replayed;	/* number of replayed packets */
	uint64_t packets_lost;         /* lost packets: sequence tracking */
};

#define STATE_STATS(x) state.stats->x

struct ct_stats_state {
	struct cache *cache;            /* internal events cache (netlink) */
};

union ct_state {
	struct ct_sync_state *sync;
	struct ct_stats_state *stats;
};

extern struct ct_conf conf;
extern union ct_state state;
extern struct ct_general_state st;

#ifndef IPPROTO_VRRP
#define IPPROTO_VRRP 112
#endif

#define STEPS_PER_SECONDS	5

struct ct_mode {
	int (*init)(void);
	int (*register_fds)(struct fds *fds);
	void (*run)(fd_set *readfds);
	int (*local)(int fd, int type, void *data);
	void (*kill)(void);
	void (*dump)(struct nf_conntrack *ct);
	int (*overrun)(enum nf_conntrack_msg_type type,
		       struct nf_conntrack *ct,
		       void *data);
	int (*purge)(void);
	void (*event_new)(struct nf_conntrack *ct);
	void (*event_upd)(struct nf_conntrack *ct);
	int (*event_dst)(struct nf_conntrack *ct);
};

/* conntrackd modes */
extern struct ct_mode sync_mode;
extern struct ct_mode stats_mode;

#define MAX(x, y) x > y ? x : y

/* These live in run.c */
void killer(int foo);
void local_handler(int fd, void *data);
int init(void);
void run(void);

/* from read_config_yy.c */
int
init_config(char *filename);

#endif
