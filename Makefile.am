## Process this file with automake to produce Makefile.in
include $(top_srcdir)/glib-openssl.mk

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

SUBDIRS = po tls/base tls/openssl tls/tests build

install-exec-hook:
	if test -n "$(GIO_QUERYMODULES)" -a -z "$(DESTDIR)"; then \
		$(GIO_QUERYMODULES) $(GIO_MODULE_DIR) ;           \
	fi

uninstall-hook:
	if test -n "$(GIO_QUERYMODULES)" -a -z "$(DESTDIR)"; then \
		$(GIO_QUERYMODULES) $(GIO_MODULE_DIR) ;           \
	fi

EXTRA_DIST +=			\
	tap-driver.sh		\
	tap-test		\
	config.h.win32.in	\
	config.h.win32		\
	$(NULL)
