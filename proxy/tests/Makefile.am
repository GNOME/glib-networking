include $(top_srcdir)/Makefile.decl

INCLUDES +=					\
	$(GSETTINGS_DESKTOP_SCHEMAS_CFLAGS)	\
	-I$(top_srcdir)/proxy			\
	-DSRCDIR=\""$(srcdir)"\"		\
	-DTOP_BUILDDIR=\""$(top_builddir)"\"

noinst_PROGRAMS = $(TEST_PROGS)

LDADD  = \
	$(GLIB_LIBS)

if HAVE_GNOME_PROXY
TEST_PROGS += gnome
endif
