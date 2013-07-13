include $(top_srcdir)/glib-networking.mk

AM_CPPFLAGS +=					\
	$(GSETTINGS_DESKTOP_SCHEMAS_CFLAGS)	\
	-I$(top_srcdir)/proxy			\
	-DSRCDIR=\""$(srcdir)"\"		\
	-DTOP_BUILDDIR=\""$(top_builddir)"\"

LDADD  = \
	$(GLIB_LIBS)

test_programs =

if HAVE_GNOME_PROXY
test_programs += gnome
endif

if HAVE_LIBPROXY
test_programs += libproxy
endif

EXTRA_DIST += common.c
