include $(top_srcdir)/glib-networking.mk

AM_CPPFLAGS +=					\
	$(GNUTLS_CFLAGS)			\
	-I$(top_srcdir)/tls			\
	-I$(top_builddir)/tls			\
	-DSRCDIR=\""$(abs_srcdir)"\"		\
	-DTOP_BUILDDIR=\""$(top_builddir)"\"

LDADD  = \
	$(GLIB_LIBS) \
	$(GNUTLS_LIBS)

test_programs =       \
	certificate   \
	file-database \
	connection    \
	$(NULL)

connection_SOURCES = connection.c \
	mock-interaction.c mock-interaction.h

if HAVE_PKCS11

test_programs +=           \
	pkcs11-util        \
	pkcs11-array       \
	pkcs11-pin         \
	pkcs11-slot

AM_CPPFLAGS +=			\
	$(PKCS11_CFLAGS)

LDADD += $(top_builddir)/tls/pkcs11/libgiopkcs11.la $(PKCS11_LIBS)

pkcs11_slot_SOURCES = pkcs11-slot.c \
	mock-pkcs11.c mock-pkcs11.h \
	mock-interaction.c mock-interaction.h

endif

testfiles_data =				\
	files/ca.pem				\
	files/ca-alternative.pem		\
	files/ca-key.pem			\
	files/ca-roots.pem			\
	files/ca-roots-bad.pem			\
	files/ca-verisign-sha1.pem		\
	files/chain.pem				\
	files/chain-with-verisign-md2.pem	\
	files/client-and-key.pem		\
	files/client-future.pem			\
	files/client-past.pem			\
	files/client.pem			\
	files/client2-and-key.pem		\
	files/client2-key.pem			\
	files/client2.pem			\
	files/intermediate-ca.pem		\
	files/non-ca.pem			\
	files/server-and-key.pem		\
	files/server.der			\
	files/server-intermediate.pem		\
	files/server-intermediate-key.pem	\
	files/server-key.der			\
	files/server-key.pem			\
	files/server.pem			\
	files/server-self.pem			\
	$(NULL)

if ENABLE_INSTALLED_TESTS
testfilesdir = $(installed_testdir)/files
testfiles_DATA = $(testfiles_data)
endif

EXTRA_DIST += $(testfiles_data)
