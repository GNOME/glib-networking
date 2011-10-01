include $(top_srcdir)/Makefile.decl

INCLUDES +=					\
	-I$(top_srcdir)/tls			\
	-DSRCDIR=\""$(abs_srcdir)"\"		\
	-DTOP_BUILDDIR=\""$(top_builddir)"\"

noinst_PROGRAMS = $(TEST_PROGS)

LDADD  = \
	$(GLIB_LIBS)

TEST_PROGS +=		\
	certificate	\
	connection	\
	$(NULL)

EXTRA_DIST += \
	files \
	$(NULL)

DISTCLEANFILES = \
	$(NULL)
