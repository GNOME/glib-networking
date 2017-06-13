include $(top_srcdir)/glib-openssl.mk

AM_CPPFLAGS +=					\
	-I$(top_srcdir)/tls			\
	-I$(top_builddir)/tls			\
	-DSRCDIR=\""$(abs_srcdir)"\"		\
	-DTOP_BUILDDIR=\""$(top_builddir)"\"

LDADD  = \
	$(GLIB_LIBS)

test_programs =             \
	certificate-openssl   \
	file-database-openssl \
	connection-openssl    \
	$(NULL)

certificate_openssl_SOURCES = certificate.c
certificate_openssl_CPPFLAGS = $(AM_CPPFLAGS) $(OPENSSL_CFLAGS) -DBACKEND=\""openssl"\" -DWITH_BACKEND_OPENSSL
certificate_openssl_LDADD = $(GLIB_LIBS) $(OPENSSL_LIBS)

connection_openssl_SOURCES = connection.c mock-interaction.c mock-interaction.h
connection_openssl_CPPFLAGS = $(AM_CPPFLAGS) $(OPENSSL_CFLAGS) -DBACKEND=\""openssl"\" -DWITH_BACKEND_OPENSSL
connection_openssl_LDADD = $(GLIB_LIBS) $(OPENSSL_LIBS)

file_database_openssl_SOURCES = file-database.c
file_database_openssl_CPPFLAGS = $(AM_CPPFLAGS) $(OPENSSL_CFLAGS) -DBACKEND=\""openssl"\" -DWITH_BACKEND_OPENSSL
file_database_openssl_LDADD = $(GLIB_LIBS) $(OPENSSL_LIBS)

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

EXTRA_DIST += \
	$(testfiles_data) \
	meson.build
