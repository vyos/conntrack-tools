# AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES=-I../include -I${KERNELDIR}
CFLAGS=-fPIC -Wall
LIBS=

pkglib_LTLIBRARIES = ct_proto_tcp.la ct_proto_udp.la		\
		     ct_proto_icmp.la ct_proto_sctp.la

ct_proto_tcp_la_SOURCES = libct_proto_tcp.c
ct_proto_tcp_la_LDFLAGS = -module
ct_proto_udp_la_SOURCES = libct_proto_udp.c
ct_proto_udp_la_LDFLAGS = -module
ct_proto_icmp_la_SOURCES = libct_proto_icmp.c
ct_proto_icmp_la_LDFLAGS = -module
ct_proto_sctp_la_SOURCES = libct_proto_sctp.c
ct_proto_sctp_la_LDFLAGS = -module
