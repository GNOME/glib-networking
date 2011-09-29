include $(top_srcdir)/Makefile.decl

INCLUDES +=					\
	-I$(top_srcdir)/tls			\
	-I$(top_builddir)/tls			\
	-DSRCDIR=\""$(abs_srcdir)"\"		\
	-DTOP_BUILDDIR=\""$(top_builddir)"\"

noinst_PROGRAMS = $(TEST_PROGS)

LDADD  = \
	$(GLIB_LIBS)

if HAVE_GNUTLS
TEST_PROGS +=			\
	certificate-gnutls	\
	connection-gnutls	\
	file-database-gnutls	\
	$(NULL)
endif

if HAVE_NSS
TEST_PROGS +=			\
	certificate-nss		\
	connection-nss		\
	file-database-nss	\
	$(NULL)
endif

certificate_gnutls_SOURCES = certificate.c
certificate_gnutls_CPPFLAGS = -DBACKEND=\""gnutls"\"

connection_gnutls_SOURCES = connection.c
connection_gnutls_CPPFLAGS = -DBACKEND=\""gnutls"\"

file_database_gnutls_SOURCES = file-database.c
file_database_gnutls_CPPFLAGS = -DBACKEND=\""gnutls"\"

certificate_nss_SOURCES = certificate.c
certificate_nss_CPPFLAGS = -DBACKEND=\""nss"\"

connection_nss_SOURCES = connection.c
connection_nss_CPPFLAGS = -DBACKEND=\""nss"\"

file_database_nss_SOURCES = file-database.c
file_database_nss_CPPFLAGS = -DBACKEND=\""nss"\"

if HAVE_PKCS11

TEST_PROGS +=              \
	pkcs11-util        \
	pkcs11-array       \
	pkcs11-pin         \
	pkcs11-slot

INCLUDES +=			\
	$(PKCS11_CFLAGS)	\
	$(GNUTLS_CFLAGS)

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
