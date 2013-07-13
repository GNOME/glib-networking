## Process this file with automake to produce Makefile.in
include $(top_srcdir)/glib-networking.mk

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

SUBDIRS = po

if HAVE_LIBPROXY
SUBDIRS += proxy/libproxy
endif

if HAVE_GNOME_PROXY
SUBDIRS += proxy/gnome
endif

SUBDIRS += proxy/tests

if HAVE_PKCS11
SUBDIRS += tls/pkcs11
endif

if HAVE_GNUTLS
SUBDIRS += tls/gnutls
SUBDIRS += tls/tests
endif

install-exec-hook:
	if test -n "$(GIO_QUERYMODULES)" -a -z "$(DESTDIR)"; then \
		$(GIO_QUERYMODULES) $(GIO_MODULE_DIR) ;           \
	fi

uninstall-hook:
	if test -n "$(GIO_QUERYMODULES)" -a -z "$(DESTDIR)"; then \
		$(GIO_QUERYMODULES) $(GIO_MODULE_DIR) ;           \
	fi
