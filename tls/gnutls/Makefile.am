include $(top_srcdir)/Makefile.decl

giomodule_LTLIBRARIES = libgiognutls.la

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
	$(NULL)

INCLUDES +=				\
	$(LIBGNUTLS_CFLAGS)		\
	$(LIBGCRYPT_CFLAGS)		\
	$(NULL)

libgiognutls_la_LDFLAGS = $(module_flags)
libgiognutls_la_LIBADD =		\
	$(GLIB_LIBS)			\
	$(GNUTLS_LIBS)			\
	$(LIBGCRYPT_LIBS)		\
	$(NULL)
