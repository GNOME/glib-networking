include $(top_srcdir)/glib-networking.mk

AM_CPPFLAGS += $(LIBPROXY_CFLAGS)

giomodule_LTLIBRARIES = libgiolibproxy.la

libgiolibproxy_la_SOURCES = 		\
	glibproxyresolver.c		\
	glibproxyresolver.h		\
	libproxy-module.c		\
	$(NULL)

libgiolibproxy_la_CFLAGS = -DGLIBPROXY_MODULE
libgiolibproxy_la_LDFLAGS = $(module_flags)
libgiolibproxy_la_LIBADD =		\
	$(GLIB_LIBS)			\
	$(LIBPROXY_LIBS)		\
	$(NULL)

libexec_PROGRAMS = glib-pacrunner

glib_pacrunner_SOURCES =		\
	glibproxyresolver.c		\
	glibproxyresolver.h		\
	glibpacrunner.c			\
	$(NULL)

glib_pacrunner_CFLAGS = -DGLIBPROXY_PACRUNNER
glib_pacrunner_LDADD =			\
	$(GLIB_LIBS)			\
	$(LIBPROXY_LIBS)		\
	$(NULL)

servicedir = $(datadir)/dbus-1/services
service_in_files = org.gtk.GLib.PACRunner.service.in
service_DATA = $(service_in_files:.service.in=.service)

EXTRA_DIST += $(service_in_files)
CLEANFILES += $(service_DATA)

org.gtk.GLib.PACRunner.service: org.gtk.GLib.PACRunner.service.in Makefile
	$(AM_V_GEN) sed -e "s|\@libexecdir\@|$(libexecdir)|" $< > $@
