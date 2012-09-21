include $(top_srcdir)/Make_global.am

SUBDIRS = helpers

AM_YFLAGS = -d

CLEANFILES = read_config_yy.c read_config_lex.c

sbin_PROGRAMS = conntrack conntrackd nfct

conntrack_SOURCES = conntrack.c
conntrack_LDADD = ../extensions/libct_proto_tcp.la ../extensions/libct_proto_udp.la ../extensions/libct_proto_udplite.la ../extensions/libct_proto_icmp.la ../extensions/libct_proto_icmpv6.la ../extensions/libct_proto_sctp.la ../extensions/libct_proto_dccp.la ../extensions/libct_proto_gre.la ../extensions/libct_proto_unknown.la ${LIBNETFILTER_CONNTRACK_LIBS} ${LIBMNL_LIBS} ${LIBNFNETLINK_LIBS}

nfct_SOURCES = nfct.c			\
	       helpers.c			\
	       nfct-extensions/timeout.c	\
	       nfct-extensions/helper.c

nfct_LDADD = ${LIBMNL_LIBS} 			\
	     ${LIBNETFILTER_CONNTRACK_LIBS}	\
	     ${LIBNETFILTER_CTTIMEOUT_LIBS}	\
	     ${LIBNETFILTER_CTHELPER_LIBS}	\
	     ${libdl_LIBS}

nfct_LDFLAGS = -export-dynamic

conntrackd_SOURCES = alarm.c main.c run.c hash.c queue.c rbtree.c \
		    local.c log.c mcast.c udp.c netlink.c vector.c \
		    filter.c fds.c event.c process.c origin.c date.c \
		    cache.c cache-ct.c cache-exp.c \
		    cache_timer.c \
		    ctnl.c cthelper.c \
		    sync-mode.c sync-alarm.c sync-ftfw.c sync-notrack.c \
		    traffic_stats.c stats-mode.c \
		    network.c cidr.c \
		    build.c parse.c \
		    channel.c multichannel.c channel_mcast.c channel_udp.c \
		    tcp.c channel_tcp.c \
		    external_cache.c external_inject.c \
		    internal_cache.c internal_bypass.c \
		    read_config_yy.y read_config_lex.l \
		    stack.c helpers.c utils.c expect.c

# yacc and lex generate dirty code
read_config_yy.o read_config_lex.o: AM_CFLAGS += -Wno-missing-prototypes -Wno-missing-declarations -Wno-implicit-function-declaration -Wno-nested-externs -Wno-undef -Wno-redundant-decls

conntrackd_LDADD = ${LIBMNL_LIBS} ${LIBNETFILTER_CONNTRACK_LIBS} \
		   ${LIBNETFILTER_QUEUE_LIBS} ${LIBNETFILTER_CTHELPER_LIBS} \
		   ${libdl_LIBS} ${LIBNFNETLINK_LIBS}

conntrackd_LDFLAGS = -export-dynamic

EXTRA_DIST = read_config_yy.h
