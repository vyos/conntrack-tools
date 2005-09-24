# not a GNU package. You can remove this line, if
# have all needed files, that a GNU package needs
AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

INCLUDES  = $(all_includes) -I$(top_srcdir)/include -I${KERNELDIR}
SUBDIRS   = src extensions
DIST_SUBDIRS = include src extensions
LINKOPTS  = -ldl -lnfnetlink -lnfnetlink_conntrack
AM_CFLAGS = -g

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
