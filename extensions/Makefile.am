AUTOMAKE_OPTIONS = no-dependencies foreign

EXTRA_DIST = $(man_MANS) acinclude.m4

man_MANS =

INCLUDES=-I../include -I/lib/modules/$(shell (uname -r))/build/include
CFLAGS=-fPIC -Wall
LIBS=

lib_LTLIBRARIES = libct_proto_tcp.la libct_proto_udp.la

libct_proto_tcp_la_SOURCES = libct_proto_tcp.c
libct_proto_udp_la_SOURCES = libct_proto_udp.c
