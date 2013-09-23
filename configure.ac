AC_PREREQ(2.65)
AC_CONFIG_MACRO_DIR([m4])

AC_INIT([glib-networking],[2.38.0],[http://bugzilla.gnome.org/enter_bug.cgi?product=glib&component=network])

AC_CONFIG_SRCDIR([proxy/libproxy/glibproxyresolver.h])
AC_CONFIG_HEADERS([config.h])

dnl Other initialization
AM_INIT_AUTOMAKE([1.11 no-dist-gzip dist-xz -Wno-portability])
AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])
LT_INIT

dnl Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
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
AM_PATH_GLIB_2_0(2.38.0,,AC_MSG_ERROR(GLIB not found),gio)
GLIB_CFLAGS="$GLIB_CFLAGS -DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_36"

GIO_MODULE_DIR=$($PKG_CONFIG --variable giomoduledir gio-2.0)
AS_IF([test "x$GIO_MODULE_DIR" = "x"],
      [AC_MSG_FAILURE(GIO_MODULE_DIR is missing from gio-2.0.pc)])
AC_SUBST(GIO_MODULE_DIR)

AC_PATH_PROG(GIO_QUERYMODULES, gio-querymodules)
AC_SUBST(GIO_QUERYMODULES)

GLIB_TESTS

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

dnl **************************************
dnl *** Checks for GNOME proxy backend ***
dnl **************************************
AC_ARG_WITH(gnome-proxy,
    [AC_HELP_STRING([--with-gnome-proxy],
                    [support for GNOME proxy configuration @<:@default=check@:>@])],
    [],
    [with_gnome_proxy=check])
AS_IF([test "x$with_gnome_proxy" != "xno"],
    [PKG_CHECK_MODULES(GSETTINGS_DESKTOP_SCHEMAS, [gsettings-desktop-schemas],
        [with_gnome_proxy=yes; proxy_support="gnome $proxy_support"],
	[AS_IF([test "x$with_gnome_proxy" = "xyes"],
               [AC_MSG_FAILURE("$GSETTINGS_DESKTOP_SCHEMAS_PKG_ERRORS")])])])
AM_CONDITIONAL(HAVE_GNOME_PROXY, [test "x$with_gnome_proxy" = "xyes"])
AC_SUBST(GSETTINGS_DESKTOP_SCHEMAS_CFLAGS)

dnl *****************************
dnl *** Checks for GNUTLS     ***
dnl *****************************

GNUTLS_MIN_REQUIRED=2.12.8

AC_ARG_WITH(gnutls,
    [AC_HELP_STRING([--with-gnutls],
                    [support for GNUTLS @<:@default=yes@:>@])],
    [],
    [with_gnutls=yes])
if test "x$with_gnutls" != "xno"; then
	PKG_CHECK_MODULES(GNUTLS,
	                  [gnutls >= $GNUTLS_MIN_REQUIRED],
	                  [with_gnutls=yes
	                   tls_support="${tls_support}gnutls "],
	                  [AS_IF([test "x$with_gnutls" = "xyes"],
	                         [AC_MSG_FAILURE("$GNUTLS_PKG_ERRORS")])])
fi
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
	       	     /etc/ssl/certs/ca-certificates.crt \
		     /etc/ssl/ca-bundle.pem; do
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
dnl *** Checks for pkcs11    ***
dnl *****************************

P11_KIT_REQUIRED=0.8

AC_ARG_WITH(pkcs11,
	[AC_HELP_STRING([--with-pkcs11],
	                [support for pkcs11 @<:@default=check@:>@])],
	                [],
	                [with_pkcs11=check])
if test "x$with_pkcs11" != "xno"; then
	PKG_CHECK_MODULES(PKCS11,
	                  [p11-kit-1 >= $P11_KIT_REQUIRED],
	                  [with_pkcs11=yes
	                   pkcs11_support=p11-kit
	                   tls_support="${tls_support}gnutls-pkcs11 "
	                   AC_DEFINE_UNQUOTED([HAVE_PKCS11], [1], [Building with PKCS#11 support])],
	                  [AS_IF([test "x$with_pkcs11" = "xyes"],
	                         [AC_MSG_FAILURE("$PKCS11_PKG_ERRORS")])
	                   pkcs11_support=no])
else
	pkcs11_support=no
fi
AM_CONDITIONAL(HAVE_PKCS11, [test "x$with_pkcs11" = "xyes"])
AC_SUBST(PKCS11_CFLAGS)
AC_SUBST(PKCS11_LIBS)

dnl ************************************
dnl *** Enable lcov coverage reports ***
dnl ************************************

AC_ARG_ENABLE(gcov,
  AS_HELP_STRING([--enable-gcov],
		 [Enable gcov]),
  [use_gcov=$enableval], [use_gcov=no])

if test "x$use_gcov" = "xyes"; then
  dnl we need gcc:
  if test "$GCC" != "yes"; then
    AC_MSG_ERROR([GCC is required for --enable-gcov])
  fi

  ltp_version_list="1.6 1.7 1.8 1.9"
  AC_CHECK_PROG(LTP, lcov, lcov)
  AC_CHECK_PROG(LTP_GENHTML, genhtml, genhtml)

  if test "$LTP"; then
    AC_CACHE_CHECK([for ltp version], glib_cv_ltp_version, [
      glib_cv_ltp_version=invalid
      ltp_version=`$LTP -v 2>/dev/null | $SED -e 's/^.* //'`
      for ltp_check_version in $ltp_version_list; do
        if test "$ltp_version" = "$ltp_check_version"; then
          glib_cv_ltp_version="$ltp_check_version (ok)"
        fi
      done
    ])
  else
    ltp_msg="To enable code coverage reporting you must have one of the following LTP versions installed: $ltp_version_list"
    AC_MSG_ERROR([$ltp_msg])
  fi

  case $glib_cv_ltp_version in
    ""|invalid[)]
      ltp_msg="You must have one of the following versions of LTP: $ltp_version_list (found: $ltp_version)."
      AC_MSG_ERROR([$ltp_msg])
      LTP="exit 0;"
      ;;
  esac

  if test -z "$LTP_GENHTML"; then
    AC_MSG_ERROR([Could not find genhtml from the LTP package])
  fi

  AC_DEFINE(HAVE_GCOV, 1, [Whether you have gcov])

  dnl Remove all optimization flags from CFLAGS
  changequote({,})
  CFLAGS=`echo "$CFLAGS" | $SED -e 's/-O[0-9]*//g'`
  changequote([,])

  dnl Add the special gcc flags
  CFLAGS="$CFLAGS -O0 -fprofile-arcs -ftest-coverage"
  LDFLAGS="$LDFLAGS -lgcov"
fi

dnl ****************************************************
dnl *** Warnings to show if using GCC                ***
dnl *** (do this last so -Werror won't mess up tests ***
dnl ****************************************************

AC_ARG_ENABLE(more-warnings,
	      AS_HELP_STRING([--disable-more-warnings], [Inhibit compiler warnings]),
	      set_more_warnings=no)

if test "$GCC" = "yes" -a "$set_more_warnings" != "no"; then
	CFLAGS="$CFLAGS \
		-Wall -Wstrict-prototypes -Werror=missing-prototypes \
		-Werror=implicit-function-declaration \
		-Werror=pointer-arith -Werror=init-self -Werror=format=2 \
		-Werror=missing-include-dirs \
		-Werror=declaration-after-statement"
fi

dnl *****************************
dnl *** done                  ***
dnl *****************************
AC_CONFIG_FILES([Makefile
                 po/Makefile.in po/Makefile
                 proxy/libproxy/Makefile
                 proxy/gnome/Makefile
                 proxy/tests/Makefile
                 tls/gnutls/Makefile
                 tls/pkcs11/Makefile
                 tls/tests/Makefile
                ])
AC_OUTPUT

echo ""
echo     "  Proxy support:     ${proxy_support:-no}"
echo     "  TLS support:       ${tls_support:-no}"
if test "$tls_support" != "no"; then
    echo "  PKCS#11 Support:   $pkcs11_support"
    echo "  TLS CA file:       ${with_ca_certificates:-(none)}"
    if test -n "$with_ca_certificates"; then
	if ! test -f "$with_ca_certificates"; then
	    AC_MSG_WARN([Specified certificate authority file '$with_ca_certificates' does not exist])
	fi
    fi
fi
