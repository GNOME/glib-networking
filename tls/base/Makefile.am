include $(top_srcdir)/glib-openssl.mk

noinst_LTLIBRARIES += libtlsbase.la

libtlsbase_la_SOURCES = 		\
	gtlsconnection-base.c		\
	gtlsconnection-base.h		\
	gtlsinputstream-base.c		\
	gtlsinputstream-base.h		\
	gtlsoutputstream-base.c		\
	gtlsoutputstream-base.h		\
	$(NULL)

libtlsbase_la_LDFLAGS = $(module_flags)
libtlsbase_la_LIBADD = $(GLIB_LIBS)

EXTRA_DIST += \
	meson.build

# MSVC Projects

MSVCPROJS = tlsbase

tlsbase_FILES = $(libtlsbase_la_SOURCES)
tlsbase_EXCLUDES = dummy
