include $(top_srcdir)/Makefile.decl

giomodule_LTLIBRARIES = libgiognutls.la

gnutls-marshal.h: gnutls-marshal.list
	$(AM_V_GEN) $(GLIB_GENMARSHAL) --prefix=_gnutls_marshal $(srcdir)/gnutls-marshal.list --header --internal > $@.tmp && \
	  mv $@.tmp $@

gnutls-marshal.c: gnutls-marshal.h gnutls-marshal.list
	$(AM_V_GEN) (echo "#include \"gnutls-marshal.h\""; \
	$(GLIB_GENMARSHAL) --prefix=_gnutls_marshal $(srcdir)/gnutls-marshal.list --body --internal) > $@.tmp && \
	  mv $@.tmp $@

libgiognutls_la_SOURCES = 		\
	gnutls-module.c			\
	gnutls-marshal.c		\
	gnutls-marshal.h		\
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

$(libgiognutls_la_OBJECTS): gnutls-marshal.h

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

BUILT_SOURCES = 		\
	gnutls-marshal.h	\
	gnutls-marshal.c

EXTRA_DIST += 			\
	gnutls-marshal.list

CLEANFILES = 			\
	$(BUILT_SOURCES)
