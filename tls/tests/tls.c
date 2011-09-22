/* GIO TLS tests
 *
 * Copyright (C) 2011 Collabora, Ltd.
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
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include <gio/gio.h>

#include <sys/types.h>
#include <string.h>

static gchar *source_dir = NULL;

/* -----------------------------------------------------------------------------
 * CONNECTION AND DATABASE TESTS
 */

#define TEST_DATA "You win again, gravity!\n"
#define TEST_DATA_LENGTH 24

typedef struct {
  GMainLoop *loop;
  GSocketService *service;
  GTlsDatabase *database;
  GIOStream *server_connection;
  GIOStream *client_connection;
  GSocketConnectable *identity;
  GSocketAddress *address;
  GTlsAuthenticationMode auth_mode;
  gboolean rehandshake;
  GTlsCertificateFlags accept_flags;
} TestConnection;

static void
setup_connection (TestConnection *test, gconstpointer data)
{
  GInetAddress *inet;
  guint16 port;

  test->loop = g_main_loop_new (NULL, FALSE);

  test->auth_mode = G_TLS_AUTHENTICATION_NONE;

  /* This is where the server listens and the client connects */
  port = g_random_int_range (50000, 65000);
  inet = g_inet_address_new_from_string ("127.0.0.1");
  test->address = G_SOCKET_ADDRESS (g_inet_socket_address_new (inet, port));
  g_object_unref (inet);

  /* The identity matches the server certificate */
  test->identity = g_network_address_new ("server.example.com", port);
}

static void
teardown_connection (TestConnection *test, gconstpointer data)
{
  if (test->service)
    {
      g_socket_service_stop (test->service);
      /* The outstanding accept_async will hold a ref on test->service,
       * which we want to wait for it to release if we're valgrinding.
       */
      g_object_add_weak_pointer (G_OBJECT (test->service), (gpointer *)&test->service);
      g_object_unref (test->service);
      while (test->service)
	g_main_context_iteration (NULL, TRUE);
    }

  if (test->server_connection)
    {
      g_assert (G_IS_TLS_SERVER_CONNECTION (test->server_connection));
      g_object_add_weak_pointer (G_OBJECT (test->server_connection),
				 (gpointer *)&test->server_connection);
      g_object_unref (test->server_connection);
      g_assert (test->server_connection == NULL);
    }

  if (test->client_connection)
    {
      g_assert (G_IS_TLS_CLIENT_CONNECTION (test->client_connection));
      g_object_add_weak_pointer (G_OBJECT (test->client_connection),
				 (gpointer *)&test->client_connection);
      g_object_unref (test->client_connection);
      g_assert (test->client_connection == NULL);
    }

  if (test->database)
    {
      g_assert (G_IS_TLS_DATABASE (test->database));
      g_object_add_weak_pointer (G_OBJECT (test->database),
				 (gpointer *)&test->database);
      g_object_unref (test->database);
      g_assert (test->database == NULL);
    }

  g_object_unref (test->address);
  g_object_unref (test->identity);
  g_main_loop_unref (test->loop);
}

static gboolean
on_accept_certificate (GTlsClientConnection *conn, GTlsCertificate *cert,
                       GTlsCertificateFlags errors, gpointer user_data)
{
  TestConnection *test = user_data;
  return errors == test->accept_flags;
}

static void on_output_write_finish (GObject        *object,
				    GAsyncResult   *res,
				    gpointer        user_data);

static void
on_rehandshake_finish (GObject        *object,
		       GAsyncResult   *res,
		       gpointer        user_data)
{
  TestConnection *test = user_data;
  GError *error = NULL;
  GOutputStream *stream;

  g_tls_connection_handshake_finish (G_TLS_CONNECTION (object), res, &error);
  g_assert_no_error (error);

  stream = g_io_stream_get_output_stream (test->server_connection);
  g_output_stream_write_async (stream, TEST_DATA + TEST_DATA_LENGTH / 2,
			       TEST_DATA_LENGTH / 2,
                               G_PRIORITY_DEFAULT, NULL,
                               on_output_write_finish, test);
}

static void
on_output_close_finish (GObject        *object,
                        GAsyncResult   *res,
                        gpointer        user_data)
{
  GError *error = NULL;
  g_output_stream_close_finish (G_OUTPUT_STREAM (object), res, &error);
  g_assert_no_error (error);
}

static void
on_output_write_finish (GObject        *object,
                        GAsyncResult   *res,
                        gpointer        user_data)
{
  TestConnection *test = user_data;
  GError *error = NULL;

  g_output_stream_write_finish (G_OUTPUT_STREAM (object), res, &error);
  g_assert_no_error (error);

  if (test->rehandshake)
    {
      test->rehandshake = FALSE;
      g_tls_connection_handshake_async (G_TLS_CONNECTION (test->server_connection),
					G_PRIORITY_DEFAULT, NULL,
					on_rehandshake_finish, test);
      return;
    }

  g_output_stream_close_async (G_OUTPUT_STREAM (object), G_PRIORITY_DEFAULT, NULL,
                               on_output_close_finish, test);
}

static gboolean
on_incoming_connection (GSocketService     *service,
                        GSocketConnection  *connection,
                        GObject            *source_object,
                        gpointer            user_data)
{
  TestConnection *test = user_data;
  GOutputStream *stream;
  GTlsCertificate *cert;
  GError *error = NULL;
  gchar *path;

  path = g_build_filename (source_dir, "server-and-key.pem", NULL);
  cert = g_tls_certificate_new_from_file (path, &error);
  g_assert_no_error (error);
  g_free (path);

  test->server_connection = g_tls_server_connection_new (G_IO_STREAM (connection),
                                                         cert, &error);
  g_assert_no_error (error);
  g_object_unref (cert);

  g_object_set (test->server_connection, "authentication-mode", test->auth_mode, NULL);
  g_signal_connect (test->server_connection, "accept-certificate",
                    G_CALLBACK (on_accept_certificate), test);

  if (test->database)
    g_tls_connection_set_database (G_TLS_CONNECTION (test->server_connection), test->database);

  stream = g_io_stream_get_output_stream (test->server_connection);

  g_output_stream_write_async (stream, TEST_DATA,
			       test->rehandshake ? TEST_DATA_LENGTH / 2 : TEST_DATA_LENGTH,
                               G_PRIORITY_DEFAULT, NULL,
                               on_output_write_finish, test);
  return FALSE;
}

static void
start_server_service (TestConnection *test, GTlsAuthenticationMode auth_mode)
{
  GError *error = NULL;

  test->service = g_socket_service_new ();
  g_socket_listener_add_address (G_SOCKET_LISTENER (test->service),
                                 G_SOCKET_ADDRESS (test->address),
                                 G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP,
                                 NULL, NULL, &error);
  g_assert_no_error (error);

  test->auth_mode = auth_mode;
  g_signal_connect (test->service, "incoming", G_CALLBACK (on_incoming_connection), test);
}

static GIOStream*
start_server_and_connect_to_it (TestConnection *test, GTlsAuthenticationMode auth_mode)
{
  GSocketClient *client;
  GError *error = NULL;
  GSocketConnection *connection;

  start_server_service (test, auth_mode);

  client = g_socket_client_new ();
  connection = g_socket_client_connect (client, G_SOCKET_CONNECTABLE (test->address),
                                        NULL, &error);
  g_assert_no_error (error);
  g_object_unref (client);

  return G_IO_STREAM (connection);
}

static void
on_input_read_finish (GObject        *object,
                      GAsyncResult   *res,
                      gpointer        user_data)
{
  TestConnection *test = user_data;
  GError *error = NULL;
  gchar *line, *check;

  line = g_data_input_stream_read_line_finish (G_DATA_INPUT_STREAM (object), res,
                                               NULL, &error);
  g_assert_no_error (error);
  g_assert (line);

  check = g_strdup (TEST_DATA);
  g_strstrip (check);
  g_assert_cmpstr (line, ==, check);
  g_free (check);
  g_free (line);

  g_main_loop_quit (test->loop);
}

static void
read_test_data_async (TestConnection *test)
{
  GDataInputStream *stream;

  stream = g_data_input_stream_new (g_io_stream_get_input_stream (test->client_connection));
  g_assert (stream);

  g_data_input_stream_read_line_async (stream, G_PRIORITY_DEFAULT, NULL,
                                       on_input_read_finish, test);
  g_object_unref (stream);
}

static void
test_basic_connection (TestConnection *test,
                       gconstpointer   data)
{
  GIOStream *connection;
  GError *error = NULL;

  connection = start_server_and_connect_to_it (test, G_TLS_AUTHENTICATION_NONE);
  test->client_connection = g_tls_client_connection_new (connection, test->identity, &error);
  g_assert_no_error (error);
  g_object_unref (connection);

  /* No validation at all in this test */
  g_tls_client_connection_set_validation_flags (G_TLS_CLIENT_CONNECTION (test->client_connection),
                                                0);

  read_test_data_async (test);
  g_main_loop_run (test->loop);
}

static void
test_verified_connection (TestConnection *test,
                          gconstpointer   data)
{
  GIOStream *connection;
  GError *error = NULL;
  gchar *path;

  path = g_build_filename (source_dir, "ca-roots.pem", NULL);
  test->database = g_tls_file_database_new (path, &error);
  g_assert_no_error (error);
  g_assert (test->database);
  g_free (path);

  connection = start_server_and_connect_to_it (test, G_TLS_AUTHENTICATION_NONE);
  test->client_connection = g_tls_client_connection_new (connection, test->identity, &error);
  g_assert_no_error (error);
  g_assert (test->client_connection);
  g_object_unref (connection);

  g_tls_connection_set_database (G_TLS_CONNECTION (test->client_connection), test->database);

  /* All validation in this test */
  g_tls_client_connection_set_validation_flags (G_TLS_CLIENT_CONNECTION (test->client_connection),
                                                G_TLS_CERTIFICATE_VALIDATE_ALL);

  read_test_data_async (test);
  g_main_loop_run (test->loop);
}

static void
test_client_auth_connection (TestConnection *test,
                             gconstpointer   data)
{
  GIOStream *connection;
  GError *error = NULL;
  GTlsCertificate *cert;
  gchar *path;

  path = g_build_filename (source_dir, "ca-roots.pem", NULL);
  test->database = g_tls_file_database_new (path, &error);
  g_assert_no_error (error);
  g_assert (test->database);
  g_free (path);

  connection = start_server_and_connect_to_it (test, G_TLS_AUTHENTICATION_REQUIRED);
  test->client_connection = g_tls_client_connection_new (connection, test->identity, &error);
  g_assert_no_error (error);
  g_assert (test->client_connection);
  g_object_unref (connection);

  g_tls_connection_set_database (G_TLS_CONNECTION (test->client_connection), test->database);

  path = g_build_filename (source_dir, "client-and-key.pem", NULL);
  cert = g_tls_certificate_new_from_file (path, &error);
  g_assert_no_error (error);
  g_free (path);

  g_tls_connection_set_certificate (G_TLS_CONNECTION (test->client_connection), cert);
  g_object_unref (cert);

  /* All validation in this test */
  g_tls_client_connection_set_validation_flags (G_TLS_CLIENT_CONNECTION (test->client_connection),
                                                G_TLS_CERTIFICATE_VALIDATE_ALL);

  read_test_data_async (test);
  g_main_loop_run (test->loop);
}

static void
test_client_auth_rehandshake (TestConnection *test,
			      gconstpointer   data)
{
  test->rehandshake = TRUE;
  test_client_auth_connection (test, data);
}

static void
test_connection_no_database (TestConnection *test,
                             gconstpointer   data)
{
  GIOStream *connection;
  GError *error = NULL;

  connection = start_server_and_connect_to_it (test, G_TLS_AUTHENTICATION_NONE);
  test->client_connection = g_tls_client_connection_new (connection, test->identity, &error);
  g_assert_no_error (error);
  g_assert (test->client_connection);
  g_object_unref (connection);

  /* Overrides loading of the default database */
  g_tls_connection_set_database (G_TLS_CONNECTION (test->client_connection), NULL);

  /* All validation in this test */
  g_tls_client_connection_set_validation_flags (G_TLS_CLIENT_CONNECTION (test->client_connection),
                                                G_TLS_CERTIFICATE_VALIDATE_ALL);

  test->accept_flags = G_TLS_CERTIFICATE_UNKNOWN_CA;
  g_signal_connect (test->client_connection, "accept-certificate",
                    G_CALLBACK (on_accept_certificate), test);

  read_test_data_async (test);
  g_main_loop_run (test->loop);
}

static void
socket_client_connected (GObject      *source,
			 GAsyncResult *result,
			 gpointer      user_data)
{
  TestConnection *test = user_data;
  GSocketConnection *connection;
  GError *error = NULL;

  connection = g_socket_client_connect_finish (G_SOCKET_CLIENT (source),
					       result, &error);
  g_assert_no_error (error);
  test->client_connection = G_IO_STREAM (connection);

  g_main_loop_quit (test->loop);
}

static void
test_connection_socket_client (TestConnection *test,
			       gconstpointer   data)
{
  GSocketClient *client;
  GTlsCertificateFlags flags;
  GSocketConnection *connection;
  GIOStream *base;
  GError *error = NULL;

  start_server_service (test, G_TLS_AUTHENTICATION_NONE);
  client = g_socket_client_new ();
  g_socket_client_set_tls (client, TRUE);
  flags = G_TLS_CERTIFICATE_VALIDATE_ALL & ~G_TLS_CERTIFICATE_UNKNOWN_CA;
  /* test->address doesn't match the server's cert */
  flags = flags & ~G_TLS_CERTIFICATE_BAD_IDENTITY;
  g_socket_client_set_tls_validation_flags (client, flags);

  g_socket_client_connect_async (client, G_SOCKET_CONNECTABLE (test->address),
				 NULL, socket_client_connected, test);
  g_main_loop_run (test->loop);

  connection = (GSocketConnection *)test->client_connection;
  test->client_connection = NULL;

  g_assert (G_IS_TCP_WRAPPER_CONNECTION (connection));
  base = g_tcp_wrapper_connection_get_base_io_stream (G_TCP_WRAPPER_CONNECTION (connection));
  g_assert (G_IS_TLS_CONNECTION (base));

  g_io_stream_close (G_IO_STREAM (connection), NULL, &error);
  g_assert_no_error (error);
  g_object_unref (connection);

  g_object_unref (client);
}

static void
socket_client_failed (GObject      *source,
		      GAsyncResult *result,
		      gpointer      user_data)
{
  TestConnection *test = user_data;
  GError *error = NULL;

  g_socket_client_connect_finish (G_SOCKET_CLIENT (source),
				  result, &error);
  g_assert_error (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE);
  g_clear_error (&error);

  g_main_loop_quit (test->loop);
}

static void
test_connection_socket_client_failed (TestConnection *test,
				      gconstpointer   data)
{
  GSocketClient *client;

  start_server_service (test, G_TLS_AUTHENTICATION_NONE);
  client = g_socket_client_new ();
  g_socket_client_set_tls (client, TRUE);
  /* this time we don't adjust the validation flags */

  g_socket_client_connect_async (client, G_SOCKET_CONNECTABLE (test->address),
				 NULL, socket_client_failed, test);
  g_main_loop_run (test->loop);

  g_object_unref (client);
}

/* -----------------------------------------------------------------------------
 * CERTIFICATE TESTS
 */

typedef struct {
  gchar *pem;
  gsize pem_length;
  GByteArray *der;
} TestCertificate;

static void
setup_certificate (TestCertificate *test, gconstpointer data)
{
  GError *error = NULL;
  gchar *path;
  gchar *contents;
  gsize length;

  path = g_build_filename (source_dir, "server.pem", NULL);
  g_file_get_contents (path, &test->pem, &test->pem_length, &error);
  g_assert_no_error (error);
  g_free (path);

  path = g_build_filename (source_dir, "server.der", NULL);
  g_file_get_contents (path, &contents, &length, &error);
  g_assert_no_error (error);
  g_free (path);

  test->der = g_byte_array_new ();
  g_byte_array_append (test->der, (guint8*)contents, length);
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
  gchar *path;

  path = g_build_filename (source_dir, "ca.pem", NULL);
  issuer = g_tls_certificate_new_from_file (path, &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (issuer));
  g_free (path);

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
  gchar *path;

  path = g_build_filename (source_dir, "server.pem", NULL);
  test->cert = g_tls_certificate_new_from_file (path, &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (test->cert));
  g_free (path);

  test->identity = g_network_address_new ("server.example.com", 80);

  path = g_build_filename (source_dir, "ca.pem", NULL);
  test->anchor = g_tls_certificate_new_from_file (path, &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (test->anchor));
  test->database = g_tls_file_database_new (path, &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_DATABASE (test->database));
  g_free (path);
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
  gchar *path;

  /* Use a client certificate as the CA, which is wrong */
  path = g_build_filename (source_dir, "client.pem", NULL);
  cert = g_tls_certificate_new_from_file (path, &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));
  g_free (path);

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
  gchar *path;

  /* This is a certificate in the future */
  path = g_build_filename (source_dir, "client-future.pem", NULL);
  cert = g_tls_certificate_new_from_file (path, &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));
  g_free (path);

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
  gchar *path;

  /* This is a certificate in the future */
  path = g_build_filename (source_dir, "client-past.pem", NULL);
  cert = g_tls_certificate_new_from_file (path, &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));
  g_free (path);

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
  gchar *path;

  path = g_build_filename (source_dir, "client-past.pem", NULL);
  cert = g_tls_certificate_new_from_file (path, &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));
  g_free (path);

  /* Unrelated cert used as certificate authority */
  path = g_build_filename (source_dir, "server-self.pem", NULL);
  cacert = g_tls_certificate_new_from_file (path, &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cacert));
  g_free (path);

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
  gchar *path;

  /* Use another certificate which isn't in our CA list */
  path = g_build_filename (source_dir, "server-self.pem", NULL);
  cert = g_tls_certificate_new_from_file (path, &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));
  g_free (path);

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
  gchar *path;

  /* This is a certificate in the future */
  path = g_build_filename (source_dir, "client-future.pem", NULL);
  cert = g_tls_certificate_new_from_file (path, &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));
  g_free (path);

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
  gchar *path;

  /* This is a certificate in the future */
  path = g_build_filename (source_dir, "client-past.pem", NULL);
  cert = g_tls_certificate_new_from_file (path, &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));
  g_free (path);

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
  gchar *path;

  path = g_build_filename (source_dir, "server-self.pem", NULL);
  cert = g_tls_certificate_new_from_file (path, &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (cert));
  g_free (path);

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
  gchar *path;
} TestFileDatabase;

static void
setup_file_database (TestFileDatabase *test,
                     gconstpointer     data)
{
  GError *error = NULL;

  test->path = g_build_filename (source_dir, "ca-roots.pem", NULL);
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

  g_free (test->path);
}

static void
test_file_database_handle (TestFileDatabase *test,
                           gconstpointer     unused)
{
  GTlsCertificate *certificate;
  GTlsCertificate *check;
  GError *error = NULL;
  gchar *handle;
  gchar *path;

  /*
   * ca.pem is in the ca-roots.pem that the test->database represents.
   * So it should be able to create a handle for it and treat it as if it
   * is 'in' the database.
   */

  path = g_build_filename (source_dir, "ca.pem", NULL);
  certificate = g_tls_certificate_new_from_file (path, &error);
  g_assert_no_error (error);
  g_assert (G_IS_TLS_CERTIFICATE (certificate));
  g_free (path);

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
  gchar *dir;
  int ret;

  g_type_init ();
  g_test_init (&argc, &argv, NULL);

  g_setenv ("GIO_EXTRA_MODULES", GNUTLS_MODULE_DIR, TRUE);

  /* Use the gnutls database */
  if (!g_getenv ("GIO_USE_TLS"))
      g_setenv ("GIO_USE_TLS", "gnutls", TRUE);

  /* Create an absolute path for test files */
  if (g_path_is_absolute (SRCDIR))
    {
      source_dir = g_build_filename (SRCDIR, "files", NULL);
    }
  else
    {
      dir = g_get_current_dir ();
      source_dir = g_build_filename (dir, SRCDIR, "files", NULL);
      g_free (dir);
    }

  g_test_add ("/tls/connection/basic", TestConnection, NULL,
              setup_connection, test_basic_connection, teardown_connection);
  g_test_add ("/tls/connection/verified", TestConnection, NULL,
              setup_connection, test_verified_connection, teardown_connection);
  g_test_add ("/tls/connection/client-auth", TestConnection, NULL,
              setup_connection, test_client_auth_connection, teardown_connection);
  g_test_add ("/tls/connection/client-auth-rehandshake", TestConnection, NULL,
              setup_connection, test_client_auth_rehandshake, teardown_connection);
  g_test_add ("/tls/connection/no-database", TestConnection, NULL,
              setup_connection, test_connection_no_database, teardown_connection);
  g_test_add ("/tls/connection/socket-client", TestConnection, NULL,
              setup_connection, test_connection_socket_client, teardown_connection);
  g_test_add ("/tls/connection/socket-client-failed", TestConnection, NULL,
              setup_connection, test_connection_socket_client_failed, teardown_connection);

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

  ret = g_test_run();

  g_free (source_dir);

  /* for valgrinding */
  g_main_context_unref (g_main_context_default ());

  return ret;
}
