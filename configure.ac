AC_PREREQ(2.65)
AC_CONFIG_MACRO_DIR([m4])

AC_INIT([glib-openssl],[2.50.8],[http://bugzilla.gnome.org/enter_bug.cgi?product=glib-openssl])

AC_CONFIG_SRCDIR([tls/openssl/gtlsbackend-openssl.h])
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
dnl *** Checks for gettext   ***
dnl ****************************
AM_GNU_GETTEXT_VERSION([0.19.4])
AM_GNU_GETTEXT([external])

GETTEXT_PACKAGE=glib-openssl
AC_SUBST([GETTEXT_PACKAGE])
AC_DEFINE_UNQUOTED([GETTEXT_PACKAGE],["$GETTEXT_PACKAGE"],[The gettext domain name])

dnl *****************************
dnl *** Check GLib GIO        ***
dnl *****************************
AM_PATH_GLIB_2_0(2.46.0,,AC_MSG_ERROR(GLIB not found),gio)
GLIB_CFLAGS="$GLIB_CFLAGS -DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_46"

GIO_MODULE_DIR=$($PKG_CONFIG --variable giomoduledir gio-2.0)
AS_IF([test "$GIO_MODULE_DIR" = ""],
      [AC_MSG_FAILURE(GIO_MODULE_DIR is missing from gio-2.0.pc)])
AC_SUBST(GIO_MODULE_DIR)

AC_PATH_PROG(GIO_QUERYMODULES, gio-querymodules)
AC_SUBST(GIO_QUERYMODULES)

GLIB_TESTS

dnl **************************
dnl *** Checks for OpenSSL ***
dnl **************************
with_openssl=no
PKG_CHECK_MODULES(OPENSSL, [openssl],
                  with_openssl=yes,
                  with_openssl=no)
AM_CONDITIONAL(HAVE_OPENSSL, [test "$with_openssl" = "yes"])
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)

if test "x$with_openssl" = "xyes"; then
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

dnl ************************************
dnl *** Enable lcov coverage reports ***
dnl ************************************

AC_ARG_ENABLE(gcov,
  AS_HELP_STRING([--enable-gcov],
		 [Enable gcov]),
  [use_gcov=$enableval], [use_gcov=no])

if test "$use_gcov" = "yes"; then
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

dnl ****************************************************
dnl *** Check whether MSVC toolset is explicitly set ***
dnl ****************************************************
AM_CONDITIONAL(MSVC_BASE_NO_TOOLSET_SET, [test x$MSVC_BASE_TOOLSET = x])
AM_CONDITIONAL(MSVC_NO_TOOLSET_SET, [test x$MSVC_TOOLSET = x])

dnl *****************************
dnl *** done                  ***
dnl *****************************
AC_CONFIG_FILES([Makefile
                 po/Makefile.in po/Makefile
                 tls/base/Makefile
                 tls/openssl/Makefile
                 tls/tests/Makefile
                ])
AC_OUTPUT

echo ""
echo     "  TLS support:       ${with_openssl:-no}"
