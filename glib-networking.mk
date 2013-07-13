### glib-networking declarations

module_flags = -export_dynamic -avoid-version -module -no-undefined -export-symbols-regex '^g_io_module_(load|unload|query)'

giomoduledir = $(GIO_MODULE_DIR)

AM_CPPFLAGS =                          \
       -DG_LOG_DOMAIN=\"GLib-Net\"     \
       -DG_DISABLE_DEPRECATED          \
       $(GLIB_CFLAGS)                  \
       $(NULL)

include $(top_srcdir)/glib.mk
