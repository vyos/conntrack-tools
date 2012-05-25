AC_INIT(cthelper-test, 0.0.1, pablo@netfilter.org)
AC_CONFIG_AUX_DIR([build-aux])

AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects
	tar-pax no-dist-gzip dist-bzip2 1.6])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_SEARCH_LIBS([dlopen], [dl], [libdl_LIBS="$LIBS"; LIBS=""])
AC_SUBST([libdl_LIBS])

AC_PROG_CC
AC_DISABLE_STATIC
AM_PROG_LIBTOOL
AC_PROG_INSTALL
AC_PROG_LN_S
AM_PROG_LEX
AC_PROG_YACC

case "$host" in
*-*-linux*) ;;
*) AC_MSG_ERROR([Linux only, dude!]);;
esac

PKG_CHECK_MODULES([LIBNETFILTER_CONNTRACK], [libnetfilter_conntrack >= 1.0.0])
PKG_CHECK_MODULES([LIBNETFILTER_QUEUE], [libnetfilter_queue >= 1.0.0])

AC_CHECK_HEADERS(arpa/inet.h)
dnl check for inet_pton
AC_CHECK_FUNCS(inet_pton)
dnl Some systems have it, but not IPv6
if test "$ac_cv_func_inet_pton" = "yes" ; then
AC_MSG_CHECKING(if inet_pton supports IPv6)
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
int main()
  {
     struct in6_addr addr6;
     if (inet_pton(AF_INET6, "::1", &addr6) < 1)
        exit(1);
     else
        exit(0);
  }
  ]])],[ AC_MSG_RESULT(yes)
       AC_DEFINE_UNQUOTED(HAVE_INET_PTON_IPV6, 1, [Define to 1 if inet_pton supports IPv6.])
  ],[AC_MSG_RESULT(no)],[AC_MSG_RESULT(no)])
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
