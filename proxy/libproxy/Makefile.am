include $(top_srcdir)/Makefile.decl

NULL =

INCLUDES = \
	-DG_LOG_DOMAIN=\"GLib-Net\"	\
	$(GLIB_CFLAGS)			\
	$(LIBPROXY_CFLAGS)		\
	-DG_DISABLE_DEPRECATED

module_flags = -export_dynamic -avoid-version -module -no-undefined -export-symbols-regex '^g_io_module_(load|unload|query)'

giomodule_LTLIBRARIES = libgiolibproxy.la
giomoduledir = $(GIO_MODULE_DIR)

libgiolibproxy_la_SOURCES = 		\
	glibproxyresolver.c		\
	glibproxyresolver.h		\
	libproxy-module.c		\
	$(NULL)

libgiolibproxy_la_CFLAGS = -DGLIBPROXY_MODULE
libgiolibproxy_la_LDFLAGS = $(module_flags)
libgiolibproxy_la_LIBADD = \
		$(GLIB_LIBS) \
		$(LIBPROXY_LIBS) \
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

EXTRA_DIST = $(service_in_files)
CLEANFILES = $(service_DATA)

org.gtk.GLib.PACRunner.service: org.gtk.GLib.PACRunner.service.in Makefile
	$(AM_V_GEN) sed -e "s|\@libexecdir\@|$(libexecdir)|" $< > $@
