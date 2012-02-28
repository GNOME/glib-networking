include $(top_srcdir)/Makefile.decl

noinst_LTLIBRARIES = \
	libgiopkcs11.la

libgiopkcs11_la_SOURCES =			\
	gpkcs11array.c				\
	gpkcs11array.h				\
	gpkcs11pin.c				\
	gpkcs11pin.h				\
	gpkcs11slot.c				\
	gpkcs11slot.h				\
	gpkcs11util.c				\
	gpkcs11util.h				\
	pkcs11-trust-assertions.h		\
	$(NULL)

libgiopkcs11_la_LIBADD =			\
	$(GLIB_LIBS)				\
	$(NULL)

INCLUDES +=					\
	$(PKCS11_CFLAGS)			\
	-DG_DISABLE_DEPRECATED
