include $(top_srcdir)/glib-openssl.mk

giomodule_LTLIBRARIES = libgioopenssl.la

libgioopenssl_la_SOURCES = 		\
	openssl-module.c		\
	gtlsbackend-openssl.h		\
	gtlsbackend-openssl.c		\
	gtlscertificate-openssl.h	\
	gtlscertificate-openssl.c	\
	gtlsconnection-openssl.h	\
	gtlsconnection-openssl.c	\
	gtlsserverconnection-openssl.h	\
	gtlsserverconnection-openssl.c	\
	gtlsclientconnection-openssl.h	\
	gtlsclientconnection-openssl.c	\
	gtlsdatabase-openssl.h		\
	gtlsdatabase-openssl.c		\
	gtlsfiledatabase-openssl.h	\
	gtlsfiledatabase-openssl.c	\
	gtlsbio.h			\
	gtlsbio.c			\
	openssl-util.h			\
	openssl-util.c			\
	openssl-include.h			\
	$(NULL)

AM_CPPFLAGS +=				\
	-I$(top_srcdir)/tls/base	\
	$(OPENSSL_CFLAGS)		\
	$(NULL)

libgioopenssl_la_LDFLAGS = $(module_flags)
libgioopenssl_la_LIBADD =		\
	../base/libtlsbase.la		\
	$(GLIB_LIBS)			\
	$(OPENSSL_LIBS)			\
	$(NULL)

EXTRA_DIST += \
	meson.build

# MSVC Projects

MSVCPROJS = libgioopenssl

libgioopenssl_FILES = $(libgioopenssl_la_SOURCES)
libgioopenssl_EXCLUDES = dummy
