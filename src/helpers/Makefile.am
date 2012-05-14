include $(top_srcdir)/Make_global.am

pkglib_LTLIBRARIES = ct_helper_ftp.la

ct_helper_ftp_la_SOURCES = ftp.c
ct_helper_ftp_la_LDFLAGS = -avoid-version -module $(LIBNETFILTER_CONNTRACK_LIBS)
ct_helper_ftp_la_CFLAGS = $(AM_CFLAGS) $(LIBNETFILTER_CONNTRACK_CFLAGS)


