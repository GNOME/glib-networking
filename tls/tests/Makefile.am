NULL =

include $(top_srcdir)/Makefile.decl

INCLUDES =					\
	$(GLIB_CFLAGS)				\
	-I$(top_srcdir)/tls			\
	-DSRCDIR=\""$(srcdir)"\"		\
	-DGNUTLS_MODULE_DIR=\""$(top_builddir)/tls/gnutls/.libs"\"

noinst_PROGRAMS = $(TEST_PROGS)

LDADD  = \
	$(GLIB_LIBS)

TEST_PROGS +=         \
	tls           \
	$(NULL)

EXTRA_DIST += \
	files \
	$(NULL)

DISTCLEANFILES = \
	$(NULL)
