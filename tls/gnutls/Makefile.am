include $(top_srcdir)/Makefile.decl

NULL =

module_flags = -export_dynamic -avoid-version -module -no-undefined -export-symbols-regex '^g_io_module_(load|unload|query)'

giomodule_LTLIBRARIES = libgiognutls.la
giomoduledir = $(GIO_MODULE_DIR)

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
	gtlsinputstream-gnutls.c	\
	gtlsinputstream-gnutls.h	\
	gtlsoutputstream-gnutls.c	\
	gtlsoutputstream-gnutls.h	\
	gtlsserverconnection-gnutls.c	\
	gtlsserverconnection-gnutls.h	\
	$(NULL)

libgiognutls_la_CFLAGS = \
	-DG_LOG_DOMAIN=\"GLib-Net\"	\
	$(GIO_CFLAGS)			\
	$(LIBGNUTLS_CFLAGS)		\
	$(LIBGCRYPT_CFLAGS)		\
	-DGIO_MODULE_DIR=\"$(GIO_MODULE_DIR)\"	\
	-DG_DISABLE_DEPRECATED

libgiognutls_la_LDFLAGS = $(module_flags)
libgiognutls_la_LIBADD =		\
	$(GIO_LIBS)			\
	$(GNUTLS_LIBS)			\
	$(LIBGCRYPT_LIBS)		\
	$(NULL)
