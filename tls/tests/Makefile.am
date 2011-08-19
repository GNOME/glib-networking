NULL =

include $(top_srcdir)/Makefile.decl

INCLUDES =              \
	-g                  \
	$(GLIB_CFLAGS)      \
	-I$(top_srcdir)/tls \
	-DSRCDIR=\""$(srcdir)"\"

noinst_PROGRAMS = $(TEST_PROGS)

LDADD  = \
	$(GLIB_LIBS)

TEST_ENVIRONMENT =   \
	GIO_EXTRA_MODULES=$(top_builddir)/tls/gnutls/.libs

TEST_PROGS +=         \
	tls           \
	$(NULL)

EXTRA_DIST += \
	files \
	$(NULL)

DISTCLEANFILES = \
	$(NULL)
