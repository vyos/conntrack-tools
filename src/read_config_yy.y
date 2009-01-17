%{
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
 *
 * Description: configuration file abstract grammar
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include "conntrackd.h"
#include "bitops.h"
#include "cidr.h"
#include <syslog.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

extern char *yytext;
extern int   yylineno;

struct ct_conf conf;

static void __kernel_filter_start(void);
static void __kernel_filter_add_state(int value);
static void __max_mcast_dedicated_links_reached(void);
%}

%union {
	int		val;
	char		*string;
}

%token T_IPV4_ADDR T_IPV4_IFACE T_PORT T_HASHSIZE T_HASHLIMIT T_MULTICAST
%token T_PATH T_UNIX T_REFRESH T_IPV6_ADDR T_IPV6_IFACE
%token T_IGNORE_UDP T_IGNORE_ICMP T_IGNORE_TRAFFIC T_BACKLOG T_GROUP
%token T_LOG T_UDP T_ICMP T_IGMP T_VRRP T_IGNORE_PROTOCOL
%token T_LOCK T_STRIP_NAT T_BUFFER_SIZE_MAX_GROWN T_EXPIRE T_TIMEOUT
%token T_GENERAL T_SYNC T_STATS T_RELAX_TRANSITIONS T_BUFFER_SIZE T_DELAY
%token T_SYNC_MODE T_LISTEN_TO T_FAMILY T_RESEND_BUFFER_SIZE
%token T_ALARM T_FTFW T_CHECKSUM T_WINDOWSIZE T_ON T_OFF
%token T_REPLICATE T_FOR T_IFACE T_PURGE
%token T_ESTABLISHED T_SYN_SENT T_SYN_RECV T_FIN_WAIT 
%token T_CLOSE_WAIT T_LAST_ACK T_TIME_WAIT T_CLOSE T_LISTEN
%token T_SYSLOG T_WRITE_THROUGH T_STAT_BUFFER_SIZE T_DESTROY_TIMEOUT
%token T_MCAST_RCVBUFF T_MCAST_SNDBUFF T_NOTRACK
%token T_FILTER T_ADDRESS T_PROTOCOL T_STATE T_ACCEPT T_IGNORE
%token T_FROM T_USERSPACE T_KERNELSPACE T_EVENT_ITER_LIMIT T_DEFAULT

%token <string> T_IP T_PATH_VAL
%token <val> T_NUMBER
%token <string> T_STRING

%%

configfile :
	   | lines
	   ;

lines : line
      | lines line
      ;

line : ignore_protocol
     | ignore_traffic
     | strip_nat
     | general
     | sync
     | stats
     ;

logfile_bool : T_LOG T_ON
{
	strncpy(conf.logfile, DEFAULT_LOGFILE, FILENAME_MAXLEN);
};

logfile_bool : T_LOG T_OFF
{
};

logfile_path : T_LOG T_PATH_VAL
{
	strncpy(conf.logfile, $2, FILENAME_MAXLEN);
};

syslog_bool : T_SYSLOG T_ON
{
	conf.syslog_facility = DEFAULT_SYSLOG_FACILITY;
};

syslog_bool : T_SYSLOG T_OFF
{
	conf.syslog_facility = -1;
}

syslog_facility : T_SYSLOG T_STRING
{
	if (!strcmp($2, "daemon"))
		conf.syslog_facility = LOG_DAEMON;
	else if (!strcmp($2, "local0"))
		conf.syslog_facility = LOG_LOCAL0;
	else if (!strcmp($2, "local1"))
		conf.syslog_facility = LOG_LOCAL1;
	else if (!strcmp($2, "local2"))
		conf.syslog_facility = LOG_LOCAL2;
	else if (!strcmp($2, "local3"))
		conf.syslog_facility = LOG_LOCAL3;
	else if (!strcmp($2, "local4"))
		conf.syslog_facility = LOG_LOCAL4;
	else if (!strcmp($2, "local5"))
		conf.syslog_facility = LOG_LOCAL5;
	else if (!strcmp($2, "local6"))
		conf.syslog_facility = LOG_LOCAL6;
	else if (!strcmp($2, "local7"))
		conf.syslog_facility = LOG_LOCAL7;
	else {
		fprintf(stderr, "'%s' is not a known syslog facility, "
				"ignoring.\n", $2);
		break;
	}

	if (conf.stats.syslog_facility != -1 &&
	    conf.syslog_facility != conf.stats.syslog_facility)
	    	fprintf(stderr, "WARNING: Conflicting Syslog facility "
				"values, defaulting to General.\n");
};

lock : T_LOCK T_PATH_VAL
{
	strncpy(conf.lockfile, $2, FILENAME_MAXLEN);
};

strip_nat: T_STRIP_NAT
{
	fprintf(stderr, "Notice: StripNAT clause is obsolete. "
			"Please, remove it from conntrackd.conf\n");
};

refreshtime : T_REFRESH T_NUMBER
{
	conf.refresh = $2;
};

expiretime: T_EXPIRE T_NUMBER
{
	conf.cache_timeout = $2;
};

timeout: T_TIMEOUT T_NUMBER
{
	conf.commit_timeout = $2;
};

purge: T_PURGE T_NUMBER
{
	conf.purge_timeout = $2;
};

checksum: T_CHECKSUM T_ON 
{
	fprintf(stderr, "WARNING: The use of `Checksum' outside the "
			"`Multicast' clause is ambiguous.\n");
	/* 
	 * XXX: The use of Checksum outside of the Multicast clause is broken
	 *	if we have more than one dedicated links.
	 */
	conf.mcast[0].checksum = 0;
};

checksum: T_CHECKSUM T_OFF
{
	fprintf(stderr, "WARNING: The use of `Checksum' outside the "
			"`Multicast' clause is ambiguous.\n");
	/* 
	 * XXX: The use of Checksum outside of the Multicast clause is broken
	 *	if we have more than one dedicated links.
	 */
	conf.mcast[0].checksum = 1;
};

ignore_traffic : T_IGNORE_TRAFFIC '{' ignore_traffic_options '}'
{
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_ADDRESS,
			    CT_FILTER_NEGATIVE);

	fprintf(stderr, "WARNING: The clause `IgnoreTrafficFor' is obsolete. "
			"Use `Filter' instead.\n");
};

ignore_traffic_options :
		       | ignore_traffic_options ignore_traffic_option;

ignore_traffic_option : T_IPV4_ADDR T_IP
{
	union inet_address ip;

	memset(&ip, 0, sizeof(union inet_address));

	if (!inet_aton($2, &ip.ipv4)) {
		fprintf(stderr, "%s is not a valid IPv4, ignoring", $2);
		break;
	}

	if (!ct_filter_add_ip(STATE(us_filter), &ip, AF_INET)) {
		if (errno == EEXIST)
			fprintf(stderr, "IP %s is repeated "
					"in the ignore pool\n", $2);
		if (errno == ENOSPC)
			fprintf(stderr, "Too many IP in the ignore pool!\n");
	}
};

ignore_traffic_option : T_IPV6_ADDR T_IP
{
	union inet_address ip;

	memset(&ip, 0, sizeof(union inet_address));

#ifdef HAVE_INET_PTON_IPV6
	if (inet_pton(AF_INET6, $2, &ip.ipv6) <= 0) {
		fprintf(stderr, "%s is not a valid IPv6, ignoring", $2);
		break;
	}
#else
	fprintf(stderr, "Cannot find inet_pton(), IPv6 unsupported!");
	break;
#endif

	if (!ct_filter_add_ip(STATE(us_filter), &ip, AF_INET6)) {
		if (errno == EEXIST)
			fprintf(stderr, "IP %s is repeated "
					"in the ignore pool\n", $2);
		if (errno == ENOSPC)
			fprintf(stderr, "Too many IP in the ignore pool!\n");
	}

};

multicast_line : T_MULTICAST '{' multicast_options '}'
{
	conf.mcast_links++;
};

multicast_line : T_MULTICAST T_DEFAULT '{' multicast_options '}'
{
	conf.mcast_default_link = conf.mcast_links;
	conf.mcast_links++;
};

multicast_options :
		  | multicast_options multicast_option;

multicast_option : T_IPV4_ADDR T_IP
{
	__max_mcast_dedicated_links_reached();

	if (!inet_aton($2, &conf.mcast[conf.mcast_links].in)) {
		fprintf(stderr, "%s is not a valid IPv4 address\n", $2);
		break;
	}

        if (conf.mcast[conf.mcast_links].ipproto == AF_INET6) {
		fprintf(stderr, "Your multicast address is IPv4 but "
		                "is binded to an IPv6 interface? Surely "
				"this is not what you want\n");
		break;
	}

	conf.mcast[conf.mcast_links].ipproto = AF_INET;
};

multicast_option : T_IPV6_ADDR T_IP
{
	__max_mcast_dedicated_links_reached();

#ifdef HAVE_INET_PTON_IPV6
	if (inet_pton(AF_INET6, $2, &conf.mcast[conf.mcast_links].in) <= 0) {
		fprintf(stderr, "%s is not a valid IPv6 address\n", $2);
		break;
	}
#else
	fprintf(stderr, "Cannot find inet_pton(), IPv6 unsupported!");
	break;
#endif

	if (conf.mcast[conf.mcast_links].ipproto == AF_INET) {
		fprintf(stderr, "Your multicast address is IPv6 but "
				"is binded to an IPv4 interface? Surely "
				"this is not what you want\n");
		break;
	}

	conf.mcast[conf.mcast_links].ipproto = AF_INET6;

	if (conf.mcast[conf.mcast_links].iface[0] &&
	    !conf.mcast[conf.mcast_links].ifa.interface_index6) {
		unsigned int idx;

		idx = if_nametoindex($2);
		if (!idx) {
			fprintf(stderr, "%s is an invalid interface.\n", $2);
			break;
		}

		conf.mcast[conf.mcast_links].ifa.interface_index6 = idx;
		conf.mcast[conf.mcast_links].ipproto = AF_INET6;
	}
};

multicast_option : T_IPV4_IFACE T_IP
{
	__max_mcast_dedicated_links_reached();

	if (!inet_aton($2, &conf.mcast[conf.mcast_links].ifa)) {
		fprintf(stderr, "%s is not a valid IPv4 address\n", $2);
		break;
	}

        if (conf.mcast[conf.mcast_links].ipproto == AF_INET6) {
		fprintf(stderr, "Your multicast interface is IPv4 but "
		                "is binded to an IPv6 interface? Surely "
				"this is not what you want\n");
		break;
	}

	conf.mcast[conf.mcast_links].ipproto = AF_INET;
};

multicast_option : T_IPV6_IFACE T_IP
{
	fprintf(stderr, "IPv6_interface not required for IPv6, ignoring.\n");
}

multicast_option : T_IFACE T_STRING
{
	unsigned int idx;

	__max_mcast_dedicated_links_reached();

	strncpy(conf.mcast[conf.mcast_links].iface, $2, IFNAMSIZ);

	idx = if_nametoindex($2);
	if (!idx) {
		fprintf(stderr, "%s is an invalid interface.\n", $2);
		break;
	}
	conf.mcast[conf.mcast_links].interface_idx = idx;

	if (conf.mcast[conf.mcast_links].ipproto == AF_INET6) {
		conf.mcast[conf.mcast_links].ifa.interface_index6 = idx;
		conf.mcast[conf.mcast_links].ipproto = AF_INET6;
	}
};

multicast_option : T_BACKLOG T_NUMBER
{
	fprintf(stderr, "Notice: Backlog option inside Multicast clause is "
			"obsolete. Please, remove it from conntrackd.conf.\n");
};

multicast_option : T_GROUP T_NUMBER
{
	__max_mcast_dedicated_links_reached();
	conf.mcast[conf.mcast_links].port = $2;
};

multicast_option: T_MCAST_SNDBUFF T_NUMBER
{
	__max_mcast_dedicated_links_reached();
	conf.mcast[conf.mcast_links].sndbuf = $2;
};

multicast_option: T_MCAST_RCVBUFF T_NUMBER
{
	__max_mcast_dedicated_links_reached();
	conf.mcast[conf.mcast_links].rcvbuf = $2;
};

multicast_option: T_CHECKSUM T_ON 
{
	__max_mcast_dedicated_links_reached();
	conf.mcast[conf.mcast_links].checksum = 0;
};

multicast_option: T_CHECKSUM T_OFF
{
	__max_mcast_dedicated_links_reached();
	conf.mcast[conf.mcast_links].checksum = 1;
};

hashsize : T_HASHSIZE T_NUMBER
{
	conf.hashsize = $2;
};

hashlimit: T_HASHLIMIT T_NUMBER
{
	conf.limit = $2;
};

unix_line: T_UNIX '{' unix_options '}';

unix_options:
	    | unix_options unix_option
	    ;

unix_option : T_PATH T_PATH_VAL
{
	strcpy(conf.local.path, $2);
};

unix_option : T_BACKLOG T_NUMBER
{
	conf.local.backlog = $2;
};

ignore_protocol: T_IGNORE_PROTOCOL '{' ignore_proto_list '}'
{
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_L4PROTO,
			    CT_FILTER_NEGATIVE);

	fprintf(stderr, "WARNING: The clause `IgnoreProtocol' is obsolete. "
			"Use `Filter' instead.\n");
};

ignore_proto_list:
		 | ignore_proto_list ignore_proto
		 ;

ignore_proto: T_NUMBER
{
	if ($1 < IPPROTO_MAX)
		ct_filter_add_proto(STATE(us_filter), $1);
	else
		fprintf(stderr, "Protocol number `%d' is freak\n", $1);
};

ignore_proto: T_STRING
{
	struct protoent *pent;

	pent = getprotobyname($1);
	if (pent == NULL) {
		fprintf(stderr, "getprotobyname() cannot find "
				"protocol `%s' in /etc/protocols.\n", $1);
		break;
	}
	ct_filter_add_proto(STATE(us_filter), pent->p_proto);
};

sync: T_SYNC '{' sync_list '}'
{
	if (conf.flags & CTD_STATS_MODE) {
		fprintf(stderr, "ERROR: Cannot use both Stats and Sync "
				"clauses in conntrackd.conf.\n");
		exit(EXIT_FAILURE);
	}
	conf.flags |= CTD_SYNC_MODE;
};

sync_list:
	 | sync_list sync_line;

sync_line: refreshtime
	 | expiretime
	 | timeout
	 | purge
	 | checksum
	 | multicast_line
	 | relax_transitions
	 | delay_destroy_msgs
	 | sync_mode_alarm
	 | sync_mode_ftfw
	 | sync_mode_notrack
	 | listen_to
	 | state_replication
	 | cache_writethrough
	 | destroy_timeout
	 ;

sync_mode_alarm: T_SYNC_MODE T_ALARM '{' sync_mode_alarm_list '}'
{
	conf.flags |= CTD_SYNC_ALARM;
};

sync_mode_ftfw: T_SYNC_MODE T_FTFW '{' sync_mode_ftfw_list '}'
{
	conf.flags |= CTD_SYNC_FTFW;
};

sync_mode_notrack: T_SYNC_MODE T_NOTRACK '{' sync_mode_notrack_list '}'
{
	conf.flags |= CTD_SYNC_NOTRACK;
};

sync_mode_alarm_list:
	      | sync_mode_alarm_list sync_mode_alarm_line;

sync_mode_alarm_line: refreshtime
              		 | expiretime
	     		 | timeout
			 | purge
			 | relax_transitions
			 | delay_destroy_msgs
			 ;

sync_mode_ftfw_list:
	      | sync_mode_ftfw_list sync_mode_ftfw_line;

sync_mode_ftfw_line: resend_queue_size
		   | timeout
		   | purge
		   | window_size
		   ;

sync_mode_notrack_list:
	      | sync_mode_notrack_list sync_mode_notrack_line;

sync_mode_notrack_line: timeout
		      | purge
		      ;

resend_queue_size: T_RESEND_BUFFER_SIZE T_NUMBER
{
	conf.resend_queue_size = $2;
};

window_size: T_WINDOWSIZE T_NUMBER
{
	conf.window_size = $2;
};

destroy_timeout: T_DESTROY_TIMEOUT T_NUMBER
{
	conf.del_timeout = $2;
};

relax_transitions: T_RELAX_TRANSITIONS
{
	fprintf(stderr, "Notice: RelaxTransitions clause is obsolete. "
			"Please, remove it from conntrackd.conf\n");
};

delay_destroy_msgs: T_DELAY
{
	fprintf(stderr, "Notice: DelayDestroyMessages clause is obsolete. "
			"Please, remove it from conntrackd.conf\n");
};

listen_to: T_LISTEN_TO T_IP
{
	union inet_address addr;

#ifdef HAVE_INET_PTON_IPV6
	if (inet_pton(AF_INET6, $2, &addr.ipv6) <= 0)
#endif
		if (inet_aton($2, &addr.ipv4) <= 0) {
			fprintf(stderr, "%s is not a valid IP address\n", $2);
			exit(EXIT_FAILURE);
		}

	if (CONFIG(listen_to_len) == 0 || CONFIG(listen_to_len) % 16) {
		CONFIG(listen_to) = realloc(CONFIG(listen_to),
					    sizeof(union inet_address) *
					    (CONFIG(listen_to_len) + 16));
		if (CONFIG(listen_to) == NULL) {
			fprintf(stderr, "cannot init listen_to array\n");
			exit(EXIT_FAILURE);
		}

		memset(CONFIG(listen_to) + 
		       (CONFIG(listen_to_len) * sizeof(union inet_address)),
		       0, sizeof(union inet_address) * 16);

	}
};

state_replication: T_REPLICATE states T_FOR state_proto
{
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_STATE,
			    CT_FILTER_POSITIVE);

	fprintf(stderr, "WARNING: The clause `Replicate' is obsolete. "
			"Use `Filter' instead.\n");
};

states:
      | states state;

state_proto: T_STRING
{
	if (strncmp($1, "TCP", strlen("TCP")) != 0) {
		fprintf(stderr, "Unsupported protocol `%s' in line %d.\n",
				$1, yylineno);
	}
};
state: tcp_state;

tcp_state: T_SYN_SENT
{
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_SYN_SENT);

	__kernel_filter_add_state(TCP_CONNTRACK_SYN_SENT);
};
tcp_state: T_SYN_RECV
{
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_SYN_RECV);

	__kernel_filter_add_state(TCP_CONNTRACK_SYN_RECV);
};
tcp_state: T_ESTABLISHED
{
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_ESTABLISHED);

	__kernel_filter_add_state(TCP_CONNTRACK_ESTABLISHED);
};
tcp_state: T_FIN_WAIT
{
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_FIN_WAIT);

	__kernel_filter_add_state(TCP_CONNTRACK_FIN_WAIT);
};
tcp_state: T_CLOSE_WAIT
{
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_CLOSE_WAIT);

	__kernel_filter_add_state(TCP_CONNTRACK_CLOSE_WAIT);
};
tcp_state: T_LAST_ACK
{
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_LAST_ACK);

	__kernel_filter_add_state(TCP_CONNTRACK_LAST_ACK);
};
tcp_state: T_TIME_WAIT
{
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_TIME_WAIT);

	__kernel_filter_add_state(TCP_CONNTRACK_TIME_WAIT);
};
tcp_state: T_CLOSE
{
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_CLOSE);

	__kernel_filter_add_state(TCP_CONNTRACK_CLOSE);
};
tcp_state: T_LISTEN
{
	ct_filter_add_state(STATE(us_filter),
			    IPPROTO_TCP,
			    TCP_CONNTRACK_LISTEN);

	__kernel_filter_add_state(TCP_CONNTRACK_LISTEN);
};

cache_writethrough: T_WRITE_THROUGH T_ON
{
	conf.cache_write_through = 1;
};

cache_writethrough: T_WRITE_THROUGH T_OFF
{
	conf.cache_write_through = 0;
};

general: T_GENERAL '{' general_list '}';

general_list:
	    | general_list general_line
	    ;

general_line: hashsize
	    | hashlimit
	    | logfile_bool
	    | logfile_path
	    | syslog_facility
	    | syslog_bool
	    | lock
	    | unix_line
	    | netlink_buffer_size
	    | netlink_buffer_size_max_grown
	    | family
	    | event_iterations_limit
	    | filter
	    ;

netlink_buffer_size: T_BUFFER_SIZE T_NUMBER
{
	conf.netlink_buffer_size = $2;
};

netlink_buffer_size_max_grown : T_BUFFER_SIZE_MAX_GROWN T_NUMBER
{
	conf.netlink_buffer_size_max_grown = $2;
};

family : T_FAMILY T_STRING
{
	if (strncmp($2, "IPv6", strlen("IPv6")) == 0)
		conf.family = AF_INET6;
	else
		conf.family = AF_INET;
};

event_iterations_limit : T_EVENT_ITER_LIMIT T_NUMBER
{
	CONFIG(event_iterations_limit) = $2;
};

filter : T_FILTER '{' filter_list '}'
{
	CONFIG(filter_from_kernelspace) = 0;
};

filter : T_FILTER T_FROM T_USERSPACE '{' filter_list '}'
{
	CONFIG(filter_from_kernelspace) = 0;
};

filter : T_FILTER T_FROM T_KERNELSPACE '{' filter_list '}'
{
	CONFIG(filter_from_kernelspace) = 1;
};

filter_list : 
	    | filter_list filter_item;

filter_item : T_PROTOCOL T_ACCEPT '{' filter_protocol_list '}'
{
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_L4PROTO,
			    CT_FILTER_POSITIVE);

	__kernel_filter_start();
};

filter_item : T_PROTOCOL T_IGNORE '{' filter_protocol_list '}'
{
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_L4PROTO,
			    CT_FILTER_NEGATIVE);

	__kernel_filter_start();

	nfct_filter_set_logic(STATE(filter),
			      NFCT_FILTER_L4PROTO,
			      NFCT_FILTER_LOGIC_NEGATIVE);
};

filter_protocol_list :
		     | filter_protocol_list filter_protocol_item;

filter_protocol_item : T_STRING
{
	struct protoent *pent;

	pent = getprotobyname($1);
	if (pent == NULL) {
		fprintf(stderr, "getprotobyname() cannot find "
				"protocol `%s' in /etc/protocols.\n", $1);
		break;
	}
	ct_filter_add_proto(STATE(us_filter), pent->p_proto);

	__kernel_filter_start();

	nfct_filter_add_attr_u32(STATE(filter),
				 NFCT_FILTER_L4PROTO,
				 pent->p_proto);
};

filter_item : T_ADDRESS T_ACCEPT '{' filter_address_list '}'
{
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_ADDRESS,
			    CT_FILTER_POSITIVE);

	__kernel_filter_start();
};

filter_item : T_ADDRESS T_IGNORE '{' filter_address_list '}'
{
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_ADDRESS,
			    CT_FILTER_NEGATIVE);

	__kernel_filter_start();

	nfct_filter_set_logic(STATE(filter),
			      NFCT_FILTER_SRC_IPV4,
			      NFCT_FILTER_LOGIC_NEGATIVE);
	nfct_filter_set_logic(STATE(filter),
			      NFCT_FILTER_DST_IPV4,
			      NFCT_FILTER_LOGIC_NEGATIVE);
};

filter_address_list :
		    | filter_address_list filter_address_item;

filter_address_item : T_IPV4_ADDR T_IP
{
	union inet_address ip;
	char *slash;
	unsigned int cidr = 32;

	memset(&ip, 0, sizeof(union inet_address));

	slash = strchr($2, '/');
	if (slash) {
		*slash = '\0';
		cidr = atoi(slash+1);
		if (cidr > 32) {
			fprintf(stderr, "%s/%d is not a valid network, "
					"ignoring\n", $2, cidr);
			break;
		}
	}

	if (!inet_aton($2, &ip.ipv4)) {
		fprintf(stderr, "%s is not a valid IPv4, ignoring", $2);
		break;
	}

	if (slash && cidr < 32) {
		/* network byte order */
		struct ct_filter_netmask_ipv4 tmp = {
			.ip = ip.ipv4,
			.mask = ipv4_cidr2mask_net(cidr)
		};

		if (!ct_filter_add_netmask(STATE(us_filter), &tmp, AF_INET)) {
			if (errno == EEXIST)
				fprintf(stderr, "Netmask %s is repeated "
						"in the ignore pool\n", $2);
		}
	} else {
		if (!ct_filter_add_ip(STATE(us_filter), &ip, AF_INET)) {
			if (errno == EEXIST)
				fprintf(stderr, "IP %s is repeated "
						"in the ignore pool\n", $2);
			if (errno == ENOSPC)
				fprintf(stderr, "Too many IP in the "
						"ignore pool!\n");
		}
	}
	__kernel_filter_start();

	/* host byte order */
	struct nfct_filter_ipv4 filter_ipv4 = {
		.addr = ntohl(ip.ipv4),
		.mask = ipv4_cidr2mask_host(cidr),
	};

	nfct_filter_add_attr(STATE(filter), NFCT_FILTER_SRC_IPV4, &filter_ipv4);
	nfct_filter_add_attr(STATE(filter), NFCT_FILTER_DST_IPV4, &filter_ipv4);
};

filter_address_item : T_IPV6_ADDR T_IP
{
	union inet_address ip;
	char *slash;
	int cidr;

	memset(&ip, 0, sizeof(union inet_address));

	slash = strchr($2, '/');
	if (slash) {
		*slash = '\0';
		cidr = atoi(slash+1);
		if (cidr > 128) {
			fprintf(stderr, "%s/%d is not a valid network, "
					"ignoring\n", $2, cidr);
			break;
		}
	}

#ifdef HAVE_INET_PTON_IPV6
	if (inet_pton(AF_INET6, $2, &ip.ipv6) <= 0) {
		fprintf(stderr, "%s is not a valid IPv6, ignoring", $2);
		break;
	}
#else
	fprintf(stderr, "Cannot find inet_pton(), IPv6 unsupported!");
	break;
#endif
	if (slash && cidr < 128) {
		struct ct_filter_netmask_ipv6 tmp;

		memcpy(tmp.ip, ip.ipv6, sizeof(uint32_t)*4);
		ipv6_cidr2mask_net(cidr, tmp.mask);
		if (!ct_filter_add_netmask(STATE(us_filter), &tmp, AF_INET6)) {
			if (errno == EEXIST)
				fprintf(stderr, "Netmask %s is repeated "
						"in the ignore pool\n", $2);
		}
	} else {
		if (!ct_filter_add_ip(STATE(us_filter), &ip, AF_INET6)) {
			if (errno == EEXIST)
				fprintf(stderr, "IP %s is repeated "
						"in the ignore pool\n", $2);
			if (errno == ENOSPC)
				fprintf(stderr, "Too many IP in the "
						"ignore pool!\n");
		}
	}
};

filter_item : T_STATE T_ACCEPT '{' filter_state_list '}'
{
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_STATE,
			    CT_FILTER_POSITIVE);

	__kernel_filter_start();
};

filter_item : T_STATE T_IGNORE '{' filter_state_list '}'
{
	ct_filter_set_logic(STATE(us_filter),
			    CT_FILTER_STATE,
			    CT_FILTER_NEGATIVE);


	__kernel_filter_start();

	nfct_filter_set_logic(STATE(filter),
			      NFCT_FILTER_L4PROTO_STATE,
			      NFCT_FILTER_LOGIC_NEGATIVE);
};

filter_state_list :
		  | filter_state_list filter_state_item;

filter_state_item : states T_FOR state_proto ;

stats: T_STATS '{' stats_list '}'
{
	if (conf.flags & CTD_SYNC_MODE) {
		fprintf(stderr, "ERROR: Cannot use both Stats and Sync "
				"clauses in conntrackd.conf.\n");
		exit(EXIT_FAILURE);
	}
	conf.flags |= CTD_STATS_MODE;
};

stats_list:
	 | stats_list stat_line
	 ;

stat_line: stat_logfile_bool
	 | stat_logfile_path
	 | stat_syslog_bool
	 | stat_syslog_facility
	 | buffer_size
	 ;

stat_logfile_bool : T_LOG T_ON
{
	strncpy(conf.stats.logfile, DEFAULT_STATS_LOGFILE, FILENAME_MAXLEN);
};

stat_logfile_bool : T_LOG T_OFF
{
};

stat_logfile_path : T_LOG T_PATH_VAL
{
	strncpy(conf.stats.logfile, $2, FILENAME_MAXLEN);
};

stat_syslog_bool : T_SYSLOG T_ON
{
	conf.stats.syslog_facility = DEFAULT_SYSLOG_FACILITY;
};

stat_syslog_bool : T_SYSLOG T_OFF
{
	conf.stats.syslog_facility = -1;
}

stat_syslog_facility : T_SYSLOG T_STRING
{
	if (!strcmp($2, "daemon"))
		conf.stats.syslog_facility = LOG_DAEMON;
	else if (!strcmp($2, "local0"))
		conf.stats.syslog_facility = LOG_LOCAL0;
	else if (!strcmp($2, "local1"))
		conf.stats.syslog_facility = LOG_LOCAL1;
	else if (!strcmp($2, "local2"))
		conf.stats.syslog_facility = LOG_LOCAL2;
	else if (!strcmp($2, "local3"))
		conf.stats.syslog_facility = LOG_LOCAL3;
	else if (!strcmp($2, "local4"))
		conf.stats.syslog_facility = LOG_LOCAL4;
	else if (!strcmp($2, "local5"))
		conf.stats.syslog_facility = LOG_LOCAL5;
	else if (!strcmp($2, "local6"))
		conf.stats.syslog_facility = LOG_LOCAL6;
	else if (!strcmp($2, "local7"))
		conf.stats.syslog_facility = LOG_LOCAL7;
	else {
		fprintf(stderr, "'%s' is not a known syslog facility, "
				"ignoring.\n", $2);
		break;
	}

	if (conf.syslog_facility != -1 &&
	    conf.stats.syslog_facility != conf.syslog_facility)
		fprintf(stderr, "WARNING: Conflicting Syslog facility "
				"values, defaulting to General.\n");
};

buffer_size: T_STAT_BUFFER_SIZE T_NUMBER
{
	fprintf(stderr, "WARNING: LogFileBufferSize is deprecated.\n");
};

%%

int __attribute__((noreturn))
yyerror(char *msg)
{
	fprintf(stderr, "Error parsing config file: ");
	fprintf(stderr, "line (%d), symbol '%s': %s\n", yylineno, yytext, msg);
	exit(EXIT_FAILURE);
}

static void __kernel_filter_start(void)
{
	if (!STATE(filter)) {
		STATE(filter) = nfct_filter_create();
		if (!STATE(filter)) {
			fprintf(stderr, "Can't create ignore pool!\n");
			exit(EXIT_FAILURE);
		}
	}
}

static void __kernel_filter_add_state(int value)
{
	__kernel_filter_start();

	struct nfct_filter_proto filter_proto = {
		.proto = IPPROTO_TCP,
		.state = value
	};
	nfct_filter_add_attr(STATE(filter),
			     NFCT_FILTER_L4PROTO_STATE,
			     &filter_proto);
}

static void __max_mcast_dedicated_links_reached(void)
{
	if (conf.mcast_links >= MCAST_LINKS_MAX) {
		fprintf(stderr, "ERROR: too many dedicated links in "
				"the configuration file (Maximum: %d).\n",
				MCAST_LINKS_MAX);
		exit(EXIT_FAILURE);
	}
}

int
init_config(char *filename)
{
	FILE *fp;

	fp = fopen(filename, "r");
	if (!fp)
		return -1;

	/* Zero may be a valid facility */
	CONFIG(syslog_facility) = -1;
	CONFIG(stats).syslog_facility = -1;

	yyrestart(fp);
	yyparse();
	fclose(fp);

	/* default to IPv4 */
	if (CONFIG(family) == 0)
		CONFIG(family) = AF_INET;

	/* set to default is not specified */
	if (strcmp(CONFIG(lockfile), "") == 0)
		strncpy(CONFIG(lockfile), DEFAULT_LOCKFILE, FILENAME_MAXLEN);

	/* default to 180 seconds of expiration time: cache entries */
	if (CONFIG(cache_timeout) == 0)
		CONFIG(cache_timeout) = 180;

	/* default to 180 seconds: committed entries */
	if (CONFIG(commit_timeout) == 0)
		CONFIG(commit_timeout) = 180;

	/* default to 15 seconds: purge kernel entries */
	if (CONFIG(purge_timeout) == 0)
		CONFIG(purge_timeout) = 15;

	/* default to 60 seconds of refresh time */
	if (CONFIG(refresh) == 0)
		CONFIG(refresh) = 60;

	if (CONFIG(resend_queue_size) == 0)
		CONFIG(resend_queue_size) = 262144;

	/* default to a window size of 300 packets */
	if (CONFIG(window_size) == 0)
		CONFIG(window_size) = 300;

	/* double of 120 seconds which is common timeout of a final state */
	if (conf.flags & CTD_SYNC_FTFW && CONFIG(del_timeout) == 0)
		CONFIG(del_timeout) = 240;

	if (CONFIG(event_iterations_limit) == 0)
		CONFIG(event_iterations_limit) = 100;

	return 0;
}
