include $(top_srcdir)/glib-networking.mk

AM_CPPFLAGS +=					\
	-I$(top_srcdir)/tls			\
	-I$(top_builddir)/tls			\
	-DSRCDIR=\""$(abs_srcdir)"\"		\
	-DTOP_BUILDDIR=\""$(top_builddir)"\"

LDADD  = \
	$(GLIB_LIBS)

test_programs =       \
	certificate   \
	file-database \
	connection    \
	$(NULL)

if HAVE_PKCS11

test_programs +=           \
	pkcs11-util        \
	pkcs11-array       \
	pkcs11-pin         \
	pkcs11-slot

AM_CPPFLAGS +=			\
	$(PKCS11_CFLAGS)	\
	$(GNUTLS_CFLAGS)

LDADD += $(top_builddir)/tls/pkcs11/libgiopkcs11.la $(PKCS11_LIBS)

pkcs11_slot_SOURCES = pkcs11-slot.c \
	mock-pkcs11.c mock-pkcs11.h \
	mock-interaction.c mock-interaction.h

endif

EXTRA_DIST += \
	files \
	$(NULL)
