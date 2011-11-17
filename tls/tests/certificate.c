/* GIO TLS tests
 *
 * Copyright 2011 Collabora, Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include <gio/gio.h>

#include <sys/types.h>
#include <string.h>

#define TEST_FILE(name) (SRCDIR "/files/" name)

typedef struct {
  gchar *pem;
  gsize pem_length;
  GByteArray *der;
} TestCertificate;

static void
setup_certificate (TestCertificate *test, gconstpointer data)
{
  GError *error = NULL;
  gchar *contents;
  gsize length;

  g_file_get_contents (TEST_FILE ("server.pem"),
		       &test->pem, &test->pem_length, &error);
  g_assert_no_error (error);

  g_file_get_contents (TEST_FILE ("server.der"),
		       &contents, &length, &error);
  g_assert_no_error (error);

  test->der = g_byte_array_new ();
  g_byte_array_append (test->der, (guint8 *)contents, length);
  g_free (contents);
}

static void
teardown_certificate (TestCertificate *test, gconstpointer data)
{
  g_free (test->pem);
  g_byte_array_free (test->der, TRUE);
}

static void
test_create_destroy_certificate_pem (TestCertificate *test, gconstpointer data)
{
  GTlsCertificate *cert;
  gchar *pem = NULL;
  GError *error = NULL;

  cert = g_tls_certificate_new_from_pem (test->pem, test->pem_length, &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));

  g_object_get (cert, "certificate-pem", &pem, NULL);
  g_assert_cmpstr (pem, ==, test->pem);
  g_free (pem);

  g_object_add_weak_pointer (G_OBJECT (cert), (gpointer *)&cert);
  g_object_unref (cert);
  g_assert (cert == NULL);
}

static void
test_create_destroy_certificate_der (TestCertificate *test, gconstpointer data)
{
  GTlsCertificate *cert;
  GByteArray *der = NULL;
  GError *error = NULL;
  GTlsBackend *backend;

  backend = g_tls_backend_get_default ();
  cert = g_initable_new (g_tls_backend_get_certificate_type (backend),
                         NULL, &error,
                         "certificate", test->der,
                         NULL);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));

  g_object_get (cert, "certificate", &der, NULL);
  g_assert (der);
  g_assert_cmpuint (der->len, ==, test->der->len);
  g_assert (memcmp (der->data, test->der->data, der->len) == 0);
  g_byte_array_unref (der);

  g_object_add_weak_pointer (G_OBJECT (cert), (gpointer *)&cert);
  g_object_unref (cert);
  g_assert (cert == NULL);
}

static void
test_create_certificate_with_issuer (TestCertificate   *test,
                                     gconstpointer      data)
{
  GTlsCertificate *cert, *issuer, *check;
  GError *error = NULL;
  GTlsBackend *backend;

  issuer = g_tls_certificate_new_from_file (TEST_FILE ("ca.pem"), &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (issuer));

  backend = g_tls_backend_get_default ();
  cert = g_initable_new (g_tls_backend_get_certificate_type (backend),
                         NULL, &error,
                         "certificate-pem", test->pem,
                         "issuer", issuer,
                         NULL);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));

  g_object_add_weak_pointer (G_OBJECT (issuer), (gpointer *)&issuer);
  g_object_unref (issuer);
  g_assert (issuer != NULL);

  check = g_tls_certificate_get_issuer (cert);
  g_assert (check == issuer);

  g_object_add_weak_pointer (G_OBJECT (cert), (gpointer *)&cert);
  g_object_unref (cert);
  g_assert (cert == NULL);
  g_assert (issuer == NULL);
}

/* -----------------------------------------------------------------------------
 * CERTIFICATE VERIFY
 */

typedef struct {
  GTlsCertificate *cert;
  GTlsCertificate *anchor;
  GSocketConnectable *identity;
  GTlsDatabase *database;
} TestVerify;

static void
setup_verify (TestVerify     *test,
              gconstpointer   data)
{
  GError *error = NULL;

  test->cert = g_tls_certificate_new_from_file (TEST_FILE ("server.pem"), &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (test->cert));

  test->identity = g_network_address_new ("server.example.com", 80);

  test->anchor = g_tls_certificate_new_from_file (TEST_FILE ("ca.pem"), &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (test->anchor));
  test->database = g_tls_file_database_new (TEST_FILE ("ca.pem"), &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_DATABASE (test->database));
}

static void
teardown_verify (TestVerify      *test,
                 gconstpointer    data)
{
  g_assert (G_IS_TLS_CERTIFICATE (test->cert));
  g_object_add_weak_pointer (G_OBJECT (test->cert),
			     (gpointer *)&test->cert);
  g_object_unref (test->cert);
  g_assert (test->cert == NULL);

  g_assert (G_IS_TLS_CERTIFICATE (test->anchor));
  g_object_add_weak_pointer (G_OBJECT (test->anchor),
			     (gpointer *)&test->anchor);
  g_object_unref (test->anchor);
  g_assert (test->anchor == NULL);

  g_assert (G_IS_TLS_DATABASE (test->database));
  g_object_add_weak_pointer (G_OBJECT (test->database),
			     (gpointer *)&test->database);
  g_object_unref (test->database);
  g_assert (test->database == NULL);

  g_object_add_weak_pointer (G_OBJECT (test->identity),
			     (gpointer *)&test->identity);
  g_object_unref (test->identity);
  g_assert (test->identity == NULL);
}

static void
test_verify_certificate_good (TestVerify      *test,
                              gconstpointer    data)
{
  GTlsCertificateFlags errors;

  errors = g_tls_certificate_verify (test->cert, test->identity, test->anchor);
  g_assert_cmpuint (errors, ==, 0);

  errors = g_tls_certificate_verify (test->cert, NULL, test->anchor);
  g_assert_cmpuint (errors, ==, 0);
}

static void
test_verify_certificate_bad_identity (TestVerify      *test,
                                      gconstpointer    data)
{
  GSocketConnectable *identity;
  GTlsCertificateFlags errors;

  identity = g_network_address_new ("other.example.com", 80);

  errors = g_tls_certificate_verify (test->cert, identity, test->anchor);
  g_assert_cmpuint (errors, ==, G_TLS_CERTIFICATE_BAD_IDENTITY);

  g_object_unref (identity);
}

static void
test_verify_certificate_bad_ca (TestVerify      *test,
                                gconstpointer    data)
{
  GTlsCertificateFlags errors;
  GTlsCertificate *cert;
  GError *error = NULL;

  /* Use a client certificate as the CA, which is wrong */
  cert = g_tls_certificate_new_from_file (TEST_FILE ("client.pem"), &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));

  errors = g_tls_certificate_verify (test->cert, test->identity, cert);
  g_assert_cmpuint (errors, ==, G_TLS_CERTIFICATE_UNKNOWN_CA);

  g_object_unref (cert);
}

static void
test_verify_certificate_bad_before (TestVerify      *test,
                                    gconstpointer    data)
{
  GTlsCertificateFlags errors;
  GTlsCertificate *cert;
  GError *error = NULL;

  /* This is a certificate in the future */
  cert = g_tls_certificate_new_from_file (TEST_FILE ("client-future.pem"), &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));

  errors = g_tls_certificate_verify (cert, NULL, test->anchor);
  g_assert_cmpuint (errors, ==, G_TLS_CERTIFICATE_NOT_ACTIVATED);

  g_object_unref (cert);
}

static void
test_verify_certificate_bad_expired (TestVerify      *test,
                                     gconstpointer    data)
{
  GTlsCertificateFlags errors;
  GTlsCertificate *cert;
  GError *error = NULL;

  /* This is a certificate in the future */
  cert = g_tls_certificate_new_from_file (TEST_FILE ("client-past.pem"), &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));

  errors = g_tls_certificate_verify (cert, NULL, test->anchor);
  g_assert_cmpuint (errors, ==, G_TLS_CERTIFICATE_EXPIRED);

  g_object_unref (cert);
}

static void
test_verify_certificate_bad_combo (TestVerify      *test,
                                   gconstpointer    data)
{
  GTlsCertificate *cert;
  GTlsCertificate *cacert;
  GSocketConnectable *identity;
  GTlsCertificateFlags errors;
  GError *error = NULL;

  cert = g_tls_certificate_new_from_file (TEST_FILE ("client-past.pem"), &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));

  /* Unrelated cert used as certificate authority */
  cacert = g_tls_certificate_new_from_file (TEST_FILE ("server-self.pem"), &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cacert));

  /*
   * - Use unrelated cert as CA
   * - Use wrong identity.
   * - Use expired certificate.
   */

  identity = g_network_address_new ("other.example.com", 80);

  errors = g_tls_certificate_verify (cert, identity, cacert);
  g_assert_cmpuint (errors, ==, G_TLS_CERTIFICATE_UNKNOWN_CA |
                    G_TLS_CERTIFICATE_BAD_IDENTITY | G_TLS_CERTIFICATE_EXPIRED);

  g_object_unref (cert);
  g_object_unref (cacert);
  g_object_unref (identity);
}

static void
test_verify_database_good (TestVerify      *test,
                           gconstpointer    data)
{
  GTlsCertificateFlags errors;
  GError *error = NULL;

  errors = g_tls_database_verify_chain (test->database, test->cert,
                                        G_TLS_DATABASE_PURPOSE_AUTHENTICATE_SERVER,
                                        test->identity, NULL, 0, NULL, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (errors, ==, 0);

  errors = g_tls_database_verify_chain (test->database, test->cert,
                                        G_TLS_DATABASE_PURPOSE_AUTHENTICATE_SERVER,
                                        NULL, NULL, 0, NULL, &error);
  g_assert_cmpuint (errors, ==, 0);
}

static void
test_verify_database_bad_identity (TestVerify      *test,
                                   gconstpointer    data)
{
  GSocketConnectable *identity;
  GTlsCertificateFlags errors;
  GError *error = NULL;

  identity = g_network_address_new ("other.example.com", 80);

  errors = g_tls_database_verify_chain (test->database, test->cert,
                                        G_TLS_DATABASE_PURPOSE_AUTHENTICATE_SERVER,
                                        identity, NULL, 0, NULL, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (errors, ==, G_TLS_CERTIFICATE_BAD_IDENTITY);

  g_object_unref (identity);
}

static void
test_verify_database_bad_ca (TestVerify      *test,
                             gconstpointer    data)
{
  GTlsCertificateFlags errors;
  GTlsCertificate *cert;
  GError *error = NULL;

  /* Use another certificate which isn't in our CA list */
  cert = g_tls_certificate_new_from_file (TEST_FILE ("server-self.pem"), &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));

  errors = g_tls_database_verify_chain (test->database, cert,
                                        G_TLS_DATABASE_PURPOSE_AUTHENTICATE_SERVER,
                                        test->identity, NULL, 0, NULL, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (errors, ==, G_TLS_CERTIFICATE_UNKNOWN_CA);

  g_object_unref (cert);
}

static void
test_verify_database_bad_before (TestVerify      *test,
                                 gconstpointer    data)
{
  GTlsCertificateFlags errors;
  GTlsCertificate *cert;
  GError *error = NULL;

  /* This is a certificate in the future */
  cert = g_tls_certificate_new_from_file (TEST_FILE ("client-future.pem"), &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));

  errors = g_tls_database_verify_chain (test->database, cert,
                                        G_TLS_DATABASE_PURPOSE_AUTHENTICATE_SERVER,
                                        NULL, NULL, 0, NULL, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (errors, ==, G_TLS_CERTIFICATE_NOT_ACTIVATED);

  g_object_unref (cert);
}

static void
test_verify_database_bad_expired (TestVerify      *test,
                                  gconstpointer    data)
{
  GTlsCertificateFlags errors;
  GTlsCertificate *cert;
  GError *error = NULL;

  /* This is a certificate in the future */
  cert = g_tls_certificate_new_from_file (TEST_FILE ("client-past.pem"), &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));

  errors = g_tls_database_verify_chain (test->database, cert,
                                        G_TLS_DATABASE_PURPOSE_AUTHENTICATE_SERVER,
                                        NULL, NULL, 0, NULL, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (errors, ==, G_TLS_CERTIFICATE_EXPIRED);

  g_object_unref (cert);
}

static void
test_verify_database_bad_combo (TestVerify      *test,
                                gconstpointer    data)
{
  GTlsCertificate *cert;
  GSocketConnectable *identity;
  GTlsCertificateFlags errors;
  GError *error = NULL;

  cert = g_tls_certificate_new_from_file (TEST_FILE ("server-self.pem"), &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));

  /*
   * - Use is self signed
   * - Use wrong identity.
   */

  identity = g_network_address_new ("other.example.com", 80);

  errors = g_tls_database_verify_chain (test->database, cert,
                                        G_TLS_DATABASE_PURPOSE_AUTHENTICATE_SERVER,
                                        identity, NULL, 0, NULL, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (errors, ==, G_TLS_CERTIFICATE_UNKNOWN_CA |
                    G_TLS_CERTIFICATE_BAD_IDENTITY);

  g_object_unref (cert);
  g_object_unref (identity);
}

/* -----------------------------------------------------------------------------
 * FILE DATABASE
 */

typedef struct {
  GTlsDatabase *database;
  const gchar *path;
} TestFileDatabase;

static void
setup_file_database (TestFileDatabase *test,
                     gconstpointer     data)
{
  GError *error = NULL;

  test->path = TEST_FILE ("ca-roots.pem");
  test->database = g_tls_file_database_new (test->path, &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_DATABASE (test->database));
}

static void
teardown_file_database (TestFileDatabase *test,
                        gconstpointer     data)
{
  g_assert (G_IS_TLS_DATABASE (test->database));
  g_object_add_weak_pointer (G_OBJECT (test->database),
			     (gpointer *)&test->database);
  g_object_unref (test->database);
  g_assert (test->database == NULL);
}

static void
test_file_database_handle (TestFileDatabase *test,
                           gconstpointer     unused)
{
  GTlsCertificate *certificate;
  GTlsCertificate *check;
  GError *error = NULL;
  gchar *handle;

  /*
   * ca.pem is in the ca-roots.pem that the test->database represents.
   * So it should be able to create a handle for it and treat it as if it
   * is 'in' the database.
   */

  certificate = g_tls_certificate_new_from_file (TEST_FILE ("ca.pem"), &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (certificate));

  handle = g_tls_database_create_certificate_handle (test->database, certificate);
  g_assert (handle != NULL);
  g_assert (g_str_has_prefix (handle, "file:///"));

  check = g_tls_database_lookup_certificate_for_handle (test->database, handle,
                                                        NULL, G_TLS_DATABASE_LOOKUP_NONE,
                                                        NULL, &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (check));

  g_free (handle);
  g_object_unref (check);
  g_object_unref (certificate);
}

static void
test_file_database_handle_invalid (TestFileDatabase *test,
                                   gconstpointer     unused)
{
  GTlsCertificate *certificate;
  GError *error = NULL;

  certificate = g_tls_database_lookup_certificate_for_handle (test->database, "blah:blah",
                                                              NULL, G_TLS_DATABASE_LOOKUP_NONE,
                                                              NULL, &error);
  g_assert_no_error (error);
  g_assert (certificate == NULL);
}

/* -----------------------------------------------------------------------------
 * BACKEND
 */

static void
test_default_database_is_singleton (void)
{
  GTlsBackend *backend;
  GTlsDatabase *database;
  GTlsDatabase *check;

  backend = g_tls_backend_get_default ();
  g_assert (G_IS_TLS_BACKEND (backend));

  database = g_tls_backend_get_default_database (backend);
  g_assert (G_IS_TLS_DATABASE (database));

  check = g_tls_backend_get_default_database (backend);
  g_assert (database == check);

  g_object_unref (database);
  g_object_unref (check);
}

int
main (int   argc,
      char *argv[])
{
  g_type_init ();
  g_test_init (&argc, &argv, NULL);

  g_setenv ("GSETTINGS_BACKEND", "memory", TRUE);
  g_setenv ("GIO_EXTRA_MODULES", TOP_BUILDDIR "/tls/gnutls/.libs", TRUE);
  g_setenv ("GIO_USE_TLS", "gnutls", TRUE);

  g_test_add_func ("/tls/backend/default-database-is-singleton",
                   test_default_database_is_singleton);

  g_test_add ("/tls/certificate/create-destroy-pem", TestCertificate, NULL,
              setup_certificate, test_create_destroy_certificate_pem, teardown_certificate);
  g_test_add ("/tls/certificate/create-destroy-der", TestCertificate, NULL,
              setup_certificate, test_create_destroy_certificate_der, teardown_certificate);
  g_test_add ("/tls/certificate/create-with-issuer", TestCertificate, NULL,
              setup_certificate, test_create_certificate_with_issuer, teardown_certificate);

  g_test_add ("/tls/certificate/verify-good", TestVerify, NULL,
              setup_verify, test_verify_certificate_good, teardown_verify);
  g_test_add ("/tls/certificate/verify-bad-identity", TestVerify, NULL,
              setup_verify, test_verify_certificate_bad_identity, teardown_verify);
  g_test_add ("/tls/certificate/verify-bad-ca", TestVerify, NULL,
              setup_verify, test_verify_certificate_bad_ca, teardown_verify);
  g_test_add ("/tls/certificate/verify-bad-before", TestVerify, NULL,
              setup_verify, test_verify_certificate_bad_before, teardown_verify);
  g_test_add ("/tls/certificate/verify-bad-expired", TestVerify, NULL,
              setup_verify, test_verify_certificate_bad_expired, teardown_verify);
  g_test_add ("/tls/certificate/verify-bad-combo", TestVerify, NULL,
              setup_verify, test_verify_certificate_bad_combo, teardown_verify);
  g_test_add ("/tls/database/verify-good", TestVerify, NULL,
              setup_verify, test_verify_database_good, teardown_verify);
  g_test_add ("/tls/database/verify-bad-identity", TestVerify, NULL,
              setup_verify, test_verify_database_bad_identity, teardown_verify);
  g_test_add ("/tls/database/verify-bad-ca", TestVerify, NULL,
              setup_verify, test_verify_database_bad_ca, teardown_verify);
  g_test_add ("/tls/database/verify-bad-before", TestVerify, NULL,
              setup_verify, test_verify_database_bad_before, teardown_verify);
  g_test_add ("/tls/database/verify-bad-expired", TestVerify, NULL,
              setup_verify, test_verify_database_bad_expired, teardown_verify);
  g_test_add ("/tls/database/verify-bad-combo", TestVerify, NULL,
              setup_verify, test_verify_database_bad_combo, teardown_verify);

  g_test_add ("/tls/file-database/test-handle", TestFileDatabase, NULL,
              setup_file_database, test_file_database_handle, teardown_file_database);
  g_test_add ("/tls/file-database/test-handle-invalid", TestFileDatabase, NULL,
              setup_file_database, test_file_database_handle_invalid, teardown_file_database);

  return g_test_run();
}
