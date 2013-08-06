include $(top_srcdir)/Make_global.am

pkglib_LTLIBRARIES = ct_helper_dhcpv6.la \
		     ct_helper_ftp.la	\
		     ct_helper_rpc.la	\
		     ct_helper_tns.la

ct_helper_dhcpv6_la_SOURCES = dhcpv6.c
ct_helper_dhcpv6_la_LDFLAGS = -avoid-version -module $(LIBNETFILTER_CONNTRACK_LIBS)
ct_helper_dhcpv6_la_CFLAGS = $(AM_CFLAGS) $(LIBNETFILTER_CONNTRACK_CFLAGS)

ct_helper_ftp_la_SOURCES = ftp.c
ct_helper_ftp_la_LDFLAGS = -avoid-version -module $(LIBNETFILTER_CONNTRACK_LIBS)
ct_helper_ftp_la_CFLAGS = $(AM_CFLAGS) $(LIBNETFILTER_CONNTRACK_CFLAGS)

ct_helper_rpc_la_SOURCES = rpc.c
ct_helper_rpc_la_LDFLAGS = -avoid-version -module $(LIBNETFILTER_CONNTRACK_LIBS)
ct_helper_rpc_la_CFLAGS = $(AM_CFLAGS) $(LIBNETFILTER_CONNTRACK_CFLAGS)

ct_helper_tns_la_SOURCES = tns.c
ct_helper_tns_la_LDFLAGS = -avoid-version -module $(LIBNETFILTER_CONNTRACK_LIBS)
ct_helper_tns_la_CFLAGS = $(AM_CFLAGS) $(LIBNETFILTER_CONNTRACK_CFLAGS)
