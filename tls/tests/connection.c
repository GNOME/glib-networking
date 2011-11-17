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

  cert = g_tls_certificate_new_from_file (TEST_FILE ("server-and-key.pem"), &error);
  g_assert_no_error (error);

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

  test->database = g_tls_file_database_new (TEST_FILE ("ca-roots.pem"), &error);
  g_assert_no_error (error);
  g_assert (test->database);

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

  test->database = g_tls_file_database_new (TEST_FILE ("ca-roots.pem"), &error);
  g_assert_no_error (error);
  g_assert (test->database);

  connection = start_server_and_connect_to_it (test, G_TLS_AUTHENTICATION_REQUIRED);
  test->client_connection = g_tls_client_connection_new (connection, test->identity, &error);
  g_assert_no_error (error);
  g_assert (test->client_connection);
  g_object_unref (connection);

  g_tls_connection_set_database (G_TLS_CONNECTION (test->client_connection), test->database);

  cert = g_tls_certificate_new_from_file (TEST_FILE ("client-and-key.pem"), &error);
  g_assert_no_error (error);

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

int
main (int   argc,
      char *argv[])
{
  int ret;

  g_type_init ();
  g_test_init (&argc, &argv, NULL);

  g_setenv ("GSETTINGS_BACKEND", "memory", TRUE);
  g_setenv ("GIO_EXTRA_MODULES", TOP_BUILDDIR "/tls/gnutls/.libs", TRUE);
  g_setenv ("GIO_USE_TLS", "gnutls", TRUE);

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

  ret = g_test_run();

  /* for valgrinding */
  g_main_context_unref (g_main_context_default ());

  return ret;
}
