# AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES=-I../include -I${KERNELDIR}
CFLAGS=-fPIC -Wall
LIBS=

lib_LTLIBRARIES = libct_proto_tcp.la libct_proto_udp.la libct_proto_icmp.la \
		  libct_proto_sctp.la

libct_proto_tcp_la_SOURCES = libct_proto_tcp.c
libct_proto_udp_la_SOURCES = libct_proto_udp.c
libct_proto_icmp_la_SOURCES = libct_proto_icmp.c
libct_proto_sctp_la_SOURCES = libct_proto_sctp.c
