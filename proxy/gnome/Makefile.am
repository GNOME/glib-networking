include $(top_srcdir)/glib-networking.mk

giomodule_LTLIBRARIES = libgiognomeproxy.la

libgiognomeproxy_la_SOURCES = 		\
	gproxyresolvergnome.c		\
	gproxyresolvergnome.h		\
	gnome-proxy-module.c		\
	$(NULL)

AM_CPPFLAGS += $(GSETTINGS_DESKTOP_SCHEMAS_CFLAGS)

libgiognomeproxy_la_LDFLAGS = $(module_flags)
libgiognomeproxy_la_LIBADD =		\
	$(GLIB_LIBS)			\
	$(NULL)
