include $(top_srcdir)/Makefile.decl

NULL =

module_flags = -export_dynamic -avoid-version -module -no-undefined -export-symbols-regex '^g_io_module_(load|unload|query)'

giomodule_LTLIBRARIES = libgiognomeproxy.la
giomoduledir = $(GIO_MODULE_DIR)

libgiognomeproxy_la_SOURCES = 		\
	gproxyresolvergnome.c		\
	gproxyresolvergnome.h		\
	gnome-proxy-module.c		\
	$(NULL)

libgiognomeproxy_la_CFLAGS =			\
	-DG_LOG_DOMAIN=\"GLib-Net\"		\
	$(GLIB_CFLAGS)				\
	$(GSETTINGS_DESKTOP_SCHEMAS_CFLAGS)	\
	-DGIO_MODULE_DIR=\"$(GIO_MODULE_DIR)\"	\
	-DG_DISABLE_DEPRECATED

libgiognomeproxy_la_LDFLAGS = $(module_flags)
libgiognomeproxy_la_LIBADD = \
		$(GLIB_LIBS) \
		$(NULL)
