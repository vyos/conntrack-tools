sbin_PROGRAMS = conntrack
conntrack_SOURCES = conntrack.c

INCLUDES= $(all_includes) -I$(top_srcdir)/include -I${KERNELDIR}
conntrack_LDFLAGS = $(all_libraries) -rdynamic
 
#AM_CFLAGS = -g
#LINKOPTS=-ldl -lnfnetlink -lctnetlink -rdynamic
