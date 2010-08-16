AC_PREREQ(2.65)
AC_CONFIG_MACRO_DIR([m4])

AC_INIT([glib-networking],[0.0.1],[http://bugzilla.gnome.org/enter_bug.cgi?product=glib-networking])

AC_CONFIG_SRCDIR([proxy/libproxy/glibproxyresolver.h])
AC_CONFIG_HEADERS([config.h])

dnl Other initialization
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
LT_INIT

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CPP

dnl We need to get variables using pkg-config
AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
AS_IF([test "x$PKG_CONFIG" = "xno"],
      [AC_MSG_FAILURE(Can't find pkg-config tool.)])

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

PKG_CHECK_MODULES(GIO, [gio-2.0 >= 2.25.13])
AC_SUBST(GIO_CFLAGS)
AC_SUBST(GIO_LIBS)

GIO_MODULE_DIR=$($PKG_CONFIG --variable giomoduledir gio-2.0)
AS_IF([test "x$GIO_MODULE_DIR" = "x"],
      [AC_MSG_FAILURE(GIO_MODULE_DIR is missing from gio-2.0.pc)])
AC_SUBST(GIO_MODULE_DIR)

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
        [with_libproxy=yes],
        [AS_IF([test "x$with_libproxy" = "xyes"],
               [AC_MSG_FAILURE("$LIBPROXY_PKG_ERRORS")])])])
AM_CONDITIONAL(HAVE_LIBPROXY, [test "x$with_libproxy" = "xyes"])
AC_SUBST(LIBPROXY_CFLAGS)
AC_SUBST(LIBPROXY_LIBS)

dnl Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h])

dnl Checks for typedefs, structures, and compiler characteristics.

dnl Checks for library functions.

AC_CONFIG_FILES([Makefile
                 po/Makefile.in po/Makefile
                 proxy/libproxy/Makefile])
AC_OUTPUT
