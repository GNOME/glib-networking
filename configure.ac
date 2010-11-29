AC_PREREQ(2.65)
AC_CONFIG_MACRO_DIR([m4])

AC_INIT([glib-networking],[2.26.0],[http://bugzilla.gnome.org/enter_bug.cgi?product=glib&component=network])

AC_CONFIG_SRCDIR([proxy/libproxy/glibproxyresolver.h])
AC_CONFIG_HEADERS([config.h])

dnl Other initialization
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],)
LT_INIT

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CPP

dnl Checks for libraries.

dnl ****************************
dnl *** Checks for intltool  ***
dnl ****************************

IT_PROG_INTLTOOL([0.35.0])
GETTEXT_PACKAGE=glib-networking

AC_SUBST([GETTEXT_PACKAGE])
AC_DEFINE_UNQUOTED([GETTEXT_PACKAGE],["$GETTEXT_PACKAGE"],[The gettext domain name])
AM_GLIB_GNU_GETTEXT

dnl *****************************
dnl *** Check GLib GIO        ***
dnl *****************************

PKG_CHECK_MODULES(GIO, [gio-2.0 >= 2.27.3])
AC_SUBST(GIO_CFLAGS)
AC_SUBST(GIO_LIBS)

GIO_MODULE_DIR=$($PKG_CONFIG --variable giomoduledir gio-2.0)
AS_IF([test "x$GIO_MODULE_DIR" = "x"],
      [AC_MSG_FAILURE(GIO_MODULE_DIR is missing from gio-2.0.pc)])
AC_SUBST(GIO_MODULE_DIR)

AC_PATH_PROG(GIO_QUERYMODULES, gio-querymodules)
AC_SUBST(GIO_QUERYMODULES)

proxy_support=no
tls_support=no

dnl *****************************
dnl *** Checks for LibProxy   ***
dnl *****************************

AC_ARG_WITH(libproxy,
    [AC_HELP_STRING([--with-libproxy],
                    [support for libproxy @<:@default=check@:>@])],
    [],
    [with_libproxy=check])
AS_IF([test "x$with_libproxy" != "xno"],
    [PKG_CHECK_MODULES(LIBPROXY, [libproxy-1.0 >= 0.3.1],
        [with_libproxy=yes; proxy_support=libproxy],
        [AS_IF([test "x$with_libproxy" = "xyes"],
               [AC_MSG_FAILURE("$LIBPROXY_PKG_ERRORS")])])])
AM_CONDITIONAL(HAVE_LIBPROXY, [test "x$with_libproxy" = "xyes"])
AC_SUBST(LIBPROXY_CFLAGS)
AC_SUBST(LIBPROXY_LIBS)

dnl *****************************
dnl *** Checks for GNUTLS     ***
dnl *****************************
AC_ARG_WITH(gnutls,
    [AC_HELP_STRING([--with-gnutls],
                    [support for GNUTLS @<:@default=yes@:>@])],
    [],
    [with_gnutls=yes])
AS_IF([test "x$with_gnutls" != "xno"],
    [PKG_CHECK_MODULES(GNUTLS, [gnutls >= 2.1.7],
        [with_gnutls=yes
	 tls_support=gnutls
	 AM_PATH_LIBGCRYPT([])],
        [AS_IF([test "x$with_gnutls" = "xyes"],
               [AC_MSG_FAILURE("$GNUTLS_PKG_ERRORS")])])])
AM_CONDITIONAL(HAVE_GNUTLS, [test "x$with_gnutls" = "xyes"])
AC_SUBST(GNUTLS_CFLAGS)
AC_SUBST(GNUTLS_LIBS)

if test "x$with_gnutls" = "xyes"; then
    AC_MSG_CHECKING([location of system Certificate Authority list])
    AC_ARG_WITH(ca-certificates,
		[AC_HELP_STRING([--with-ca-certificates=@<:@path@:>@],
				[path to system Certificate Authority list])])
    if test "$with_ca_certificates" = "no"; then
        AC_MSG_RESULT([disabled])
    else
        if test -z "$with_ca_certificates"; then
	    for f in /etc/pki/tls/certs/ca-bundle.crt \
	       	     /etc/ssl/certs/ca-certificates.crt; do
		if test -f "$f"; then
		    with_ca_certificates="$f"
		fi
	    done
	    if test -z "$with_ca_certificates"; then
		AC_MSG_ERROR([could not find. Use --with-ca-certificates=path to set, or --without-ca-certificates to disable])
	    fi
        fi

        AC_MSG_RESULT($with_ca_certificates)
        AC_DEFINE_UNQUOTED(GTLS_SYSTEM_CA_FILE, ["$with_ca_certificates"], [The system TLS CA list])
    fi
fi

dnl *****************************
dnl *** done                  ***
dnl *****************************
AC_CONFIG_FILES([Makefile
                 po/Makefile.in po/Makefile
                 proxy/libproxy/Makefile
		 tls/gnutls/Makefile
		])
AC_OUTPUT

echo ""
echo "  Proxy support: $proxy_support"
echo "  TLS support:   $tls_support"
if test "$tls_support" != "no"; then
    echo "  TLS CA file:   ${with_ca_certificates:-(none)}"
    if test -n "$with_ca_certificates"; then
	if ! test -f "$with_ca_certificates"; then
	    AC_MSG_WARN([Specified certificate authority file '$with_ca_certificates' does not exist])
	fi
    fi
fi
