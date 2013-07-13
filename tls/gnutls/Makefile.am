include $(top_srcdir)/glib-networking.mk

giomodule_LTLIBRARIES = libgiognutls.la

if HAVE_PKCS11
P11_SRCS = \
	gtlsbackend-gnutls-pkcs11.c	\
	gtlsbackend-gnutls-pkcs11.h	\
	gtlscertificate-gnutls-pkcs11.c	\
	gtlscertificate-gnutls-pkcs11.h	\
	gtlsdatabase-gnutls-pkcs11.c	\
	gtlsdatabase-gnutls-pkcs11.h	\
	$(NULL)
P11_LIBADD =				\
	$(top_builddir)/tls/pkcs11/libgiopkcs11.la \
	$(PKCS11_LIBS)			\
	$(NULL)
P11_CFLAGS =				\
	-I$(top_srcdir)/tls/		\
	$(PKCS11_CFLAGS)
else
P11_SRCS =
P11_LIBADD =
P11_CFLAGS =
endif

libgiognutls_la_SOURCES = 		\
	gnutls-module.c			\
	gtlsbackend-gnutls.c		\
	gtlsbackend-gnutls.h		\
	gtlscertificate-gnutls.c	\
	gtlscertificate-gnutls.h	\
	gtlsclientconnection-gnutls.c	\
	gtlsclientconnection-gnutls.h	\
	gtlsconnection-gnutls.c		\
	gtlsconnection-gnutls.h		\
	gtlsdatabase-gnutls.c		\
	gtlsdatabase-gnutls.h		\
	gtlsfiledatabase-gnutls.c	\
	gtlsfiledatabase-gnutls.h	\
	gtlsinputstream-gnutls.c	\
	gtlsinputstream-gnutls.h	\
	gtlsoutputstream-gnutls.c	\
	gtlsoutputstream-gnutls.h	\
	gtlsserverconnection-gnutls.c	\
	gtlsserverconnection-gnutls.h	\
	$(P11_SRCS) 			\
	$(NULL)

AM_CPPFLAGS +=				\
	$(P11_CFLAGS)			\
	$(GNUTLS_CFLAGS)		\
	$(NULL)

libgiognutls_la_LDFLAGS = $(module_flags)
libgiognutls_la_LIBADD =		\
	$(P11_LIBADD)			\
	$(GLIB_LIBS)			\
	$(GNUTLS_LIBS)			\
	$(NULL)
