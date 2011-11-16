include $(top_srcdir)/Makefile.decl

INCLUDES +=					\
	-I$(top_srcdir)/tls			\
	-DSRCDIR=\""$(abs_srcdir)"\"		\
	-DTOP_BUILDDIR=\""$(top_builddir)"\"

noinst_PROGRAMS = $(TEST_PROGS)

LDADD  = \
	$(GLIB_LIBS)

TEST_PROGS +=         \
	certificate   \
	connection    \
	$(NULL)

if HAVE_PKCS11

TEST_PROGS +=              \
	pkcs11-util        \
	pkcs11-array       \
	pkcs11-pin         \
	pkcs11-slot

INCLUDES += $(PKCS11_CFLAGS)
LDADD += $(top_builddir)/tls/pkcs11/libgiopkcs11.la $(PKCS11_LIBS)

pkcs11_slot_SOURCES = pkcs11-slot.c \
	mock-pkcs11.c mock-pkcs11.h \
	mock-interaction.c mock-interaction.h

endif

DISTCLEANFILES = \
	$(NULL)

EXTRA_DIST += \
	files \
	$(NULL)
