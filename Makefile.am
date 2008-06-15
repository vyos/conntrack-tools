include Make_global.am

# not a GNU package. You can remove this line, if
# have all needed files, that a GNU package needs
AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

man_MANS = conntrack.8 conntrackd.8
EXTRA_DIST = $(man_MANS) Make_global.am doc

SUBDIRS   = extensions src
DIST_SUBDIRS = include src extensions
LIBS = @LIBNETFILTER_CONNTRACK_LIBS@

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

dist-hook:
	rm -rf `find $(distdir)/debian -name .svn`
	rm -rf `find $(distdir)/doc -name .svn`
