include $(top_srcdir)/Make_global.am

check_PROGRAMS = cthelper-test

cthelper_test_SOURCES = proto.c			\
			ct.c			\
			l3_ipv4.c		\
			l4_tcp.c		\
			l4_udp.c		\
			expect.c		\
			../../../src/helpers.c	\
			main.c

cthelper_test_LDFLAGS = -dynamic 		\
			-lpcap			\
			-ldl			\
			-lmnl			\
			-lnetfilter_queue	\
			-lnetfilter_conntrack	\
			-export-dynamic
