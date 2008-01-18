include $(top_srcdir)/Make_global.am

YACC=@YACC@ -d

CLEANFILES = read_config_yy.c read_config_lex.c

sbin_PROGRAMS = conntrack conntrackd

conntrack_SOURCES = conntrack.c
conntrack_LDADD = ../extensions/libct_proto_tcp.la ../extensions/libct_proto_udp.la ../extensions/libct_proto_icmp.la
conntrack_LDFLAGS = $(all_libraries) @LIBNETFILTER_CONNTRACK_LIBS@

conntrackd_SOURCES = alarm.c main.c run.c hash.c queue.c \
		    local.c log.c mcast.c netlink.c \
		    ignore_pool.c \
		    cache.c cache_iterators.c \
		    cache_lifetime.c cache_timer.c cache_wt.c \
		    sync-mode.c sync-alarm.c sync-ftfw.c \
		    traffic_stats.c stats-mode.c \
		    network.c \
		    state_helper.c state_helper_tcp.c \
		    build.c parse.c \
		    read_config_yy.y read_config_lex.l

# yacc and lex generate dirty code
read_config_yy.o read_config_lex.o: AM_CFLAGS += -Wno-missing-prototypes -Wno-missing-declarations -Wno-implicit-function-declaration -Wno-nested-externs -Wno-undef -Wno-redundant-decls

conntrackd_LDFLAGS = $(all_libraries) @LIBNETFILTER_CONNTRACK_LIBS@

EXTRA_DIST = read_config_yy.h
