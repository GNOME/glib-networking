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
  GTlsBackend *backend;
  GType cert_gtype;
  gchar *cert_pem;
  gsize cert_pem_length;
  GByteArray *cert_der;
  gchar *key_pem;
  gsize key_pem_length;
  GByteArray *key_der;
} TestCertificate;

static void
setup_certificate (TestCertificate *test, gconstpointer data)
{
  GError *error = NULL;
  gchar *contents;
  gsize length;

  test->backend = g_tls_backend_get_default ();
  test->cert_gtype = g_tls_backend_get_certificate_type (test->backend);

  g_file_get_contents (TEST_FILE ("server.pem"), &test->cert_pem,
                       &test->cert_pem_length, &error);
  g_assert_no_error (error);

  g_file_get_contents (TEST_FILE ("server.der"),
		       &contents, &length, &error);
  g_assert_no_error (error);

  test->cert_der = g_byte_array_new ();
  g_byte_array_append (test->cert_der, (guint8 *)contents, length);
  g_free (contents);

  g_file_get_contents (TEST_FILE ("server-key.pem"), &test->key_pem,
                       &test->key_pem_length, &error);
  g_assert_no_error (error);

  g_file_get_contents (TEST_FILE ("server-key.der"),
                       &contents, &length, &error);
  g_assert_no_error (error);

  test->key_der = g_byte_array_new ();
  g_byte_array_append (test->key_der, (guint8 *)contents, length);
  g_free (contents);
}

static void
teardown_certificate (TestCertificate *test,
                      gconstpointer data)
{
  g_free (test->cert_pem);
  g_byte_array_free (test->cert_der, TRUE);

  g_free (test->key_pem);
  g_byte_array_free (test->key_der, TRUE);
}

static void
test_create_pem (TestCertificate *test,
                 gconstpointer data)
{
  GTlsCertificate *cert;
  gchar *pem = NULL;
  GError *error = NULL;

  cert = g_tls_certificate_new_from_pem (test->cert_pem, test->cert_pem_length, &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));

  g_object_get (cert, "certificate-pem", &pem, NULL);
  g_assert_cmpstr (pem, ==, test->cert_pem);
  g_free (pem);

  g_object_add_weak_pointer (G_OBJECT (cert), (gpointer *)&cert);
  g_object_unref (cert);
  g_assert (cert == NULL);
}

static void
test_create_with_key_pem (TestCertificate *test,
                          gconstpointer data)
{
  GTlsCertificate *cert;
  GError *error = NULL;

  cert = g_initable_new (test->cert_gtype, NULL, &error,
                         "certificate-pem", test->cert_pem,
                         "private-key-pem", test->key_pem,
                         NULL);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));

  g_object_add_weak_pointer (G_OBJECT (cert), (gpointer *)&cert);
  g_object_unref (cert);
  g_assert (cert == NULL);
}

static void
test_create_der (TestCertificate *test,
                 gconstpointer data)
{
  GTlsCertificate *cert;
  GByteArray *der = NULL;
  GError *error = NULL;

  cert = g_initable_new (test->cert_gtype, NULL, &error,
                         "certificate", test->cert_der,
                         NULL);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));

  g_object_get (cert, "certificate", &der, NULL);
  g_assert (der);
  g_assert_cmpuint (der->len, ==, test->cert_der->len);
  g_assert (memcmp (der->data, test->cert_der->data, der->len) == 0);

  g_byte_array_unref (der);

  g_object_add_weak_pointer (G_OBJECT (cert), (gpointer *)&cert);
  g_object_unref (cert);
  g_assert (cert == NULL);
}

static void
test_create_with_key_der (TestCertificate *test,
                          gconstpointer data)
{
  GTlsCertificate *cert;
  GError *error = NULL;

  cert = g_initable_new (test->cert_gtype, NULL, &error,
                         "certificate", test->cert_der,
                         "private-key", test->key_der,
                         NULL);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));

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

  issuer = g_tls_certificate_new_from_file (TEST_FILE ("ca.pem"), &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (issuer));

  cert = g_initable_new (test->cert_gtype, NULL, &error,
                         "certificate-pem", test->cert_pem,
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
test_certificate_is_same (void)
{
  GTlsCertificate *one;
  GTlsCertificate *two;
  GTlsCertificate *three;
  GError *error = NULL;

  one = g_tls_certificate_new_from_file (TEST_FILE ("client.pem"), &error);
  g_assert_no_error (error);

  two = g_tls_certificate_new_from_file (TEST_FILE ("client-and-key.pem"), &error);
  g_assert_no_error (error);

  three = g_tls_certificate_new_from_file (TEST_FILE ("server.pem"), &error);
  g_assert_no_error (error);

  g_assert (g_tls_certificate_is_same (one, two) == TRUE);
  g_assert (g_tls_certificate_is_same (two, one) == TRUE);
  g_assert (g_tls_certificate_is_same (three, one) == FALSE);
  g_assert (g_tls_certificate_is_same (one, three) == FALSE);
  g_assert (g_tls_certificate_is_same (two, three) == FALSE);
  g_assert (g_tls_certificate_is_same (three, two) == FALSE);

  g_object_unref (one);
  g_object_unref (two);
  g_object_unref (three);
}

int
main (int   argc,
      char *argv[])
{
  g_test_init (&argc, &argv, NULL);

  g_setenv ("GSETTINGS_BACKEND", "memory", TRUE);
  g_setenv ("GIO_EXTRA_MODULES", TOP_BUILDDIR "/tls/gnutls/.libs", TRUE);
  g_setenv ("GIO_USE_TLS", "gnutls", TRUE);

  g_test_add ("/tls/certificate/create-pem", TestCertificate, NULL,
              setup_certificate, test_create_pem, teardown_certificate);
  g_test_add ("/tls/certificate/create-der", TestCertificate, NULL,
              setup_certificate, test_create_der, teardown_certificate);
  g_test_add ("/tls/certificate/create-with-key-pem", TestCertificate, NULL,
              setup_certificate, test_create_with_key_pem, teardown_certificate);
  g_test_add ("/tls/certificate/create-with-key-der", TestCertificate, NULL,
              setup_certificate, test_create_with_key_der, teardown_certificate);
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

  g_test_add_func ("/tls/certificate/is-same", test_certificate_is_same);

  return g_test_run();
}
