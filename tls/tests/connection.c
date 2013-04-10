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
  GError *read_error;
  gboolean expect_server_error;
  GError *server_error;
  gboolean server_closed;

  char buf[128];
  gssize nread, nwrote;
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
	g_main_context_iteration (NULL, FALSE);
    }

  if (test->server_connection)
    {
      while (!test->server_closed)
	g_main_context_iteration (NULL, FALSE);

      g_assert (G_IS_TLS_SERVER_CONNECTION (test->server_connection));
      g_object_add_weak_pointer (G_OBJECT (test->server_connection),
				 (gpointer *)&test->server_connection);
      g_object_unref (test->server_connection);
      while (test->server_connection)
	g_main_context_iteration (NULL, FALSE);
    }

  if (test->client_connection)
    {
      g_assert (G_IS_TLS_CLIENT_CONNECTION (test->client_connection));
      g_object_add_weak_pointer (G_OBJECT (test->client_connection),
				 (gpointer *)&test->client_connection);
      g_object_unref (test->client_connection);
      while (test->client_connection)
	g_main_context_iteration (NULL, FALSE);
    }

  if (test->database)
    {
      g_assert (G_IS_TLS_DATABASE (test->database));
      g_object_add_weak_pointer (G_OBJECT (test->database),
				 (gpointer *)&test->database);
      g_object_unref (test->database);
      while (test->database)
	g_main_context_iteration (NULL, FALSE);
    }

  g_object_unref (test->address);
  g_object_unref (test->identity);
  g_main_loop_unref (test->loop);
  g_clear_error (&test->read_error);
  g_clear_error (&test->server_error);
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
on_server_close_finish (GObject        *object,
                        GAsyncResult   *res,
                        gpointer        user_data)
{
  TestConnection *test = user_data;
  GError *error = NULL;

  g_io_stream_close_finish (G_IO_STREAM (object), res, &error);
  if (test->expect_server_error)
    g_assert (error != NULL);
  else
    g_assert_no_error (error);
  test->server_closed = TRUE;
}

static void
on_output_write_finish (GObject        *object,
                        GAsyncResult   *res,
                        gpointer        user_data)
{
  TestConnection *test = user_data;

  g_assert (test->server_error == NULL);
  g_output_stream_write_finish (G_OUTPUT_STREAM (object), res, &test->server_error);

  if (!test->server_error && test->rehandshake)
    {
      test->rehandshake = FALSE;
      g_tls_connection_handshake_async (G_TLS_CONNECTION (test->server_connection),
					G_PRIORITY_DEFAULT, NULL,
					on_rehandshake_finish, test);
      return;
    }

  g_io_stream_close_async (test->server_connection, G_PRIORITY_DEFAULT, NULL,
                           on_server_close_finish, test);
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
start_async_server_service (TestConnection *test, GTlsAuthenticationMode auth_mode)
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

static GIOStream *
start_async_server_and_connect_to_it (TestConnection *test, GTlsAuthenticationMode auth_mode)
{
  GSocketClient *client;
  GError *error = NULL;
  GSocketConnection *connection;

  start_async_server_service (test, auth_mode);

  client = g_socket_client_new ();
  connection = g_socket_client_connect (client, G_SOCKET_CONNECTABLE (test->address),
                                        NULL, &error);
  g_assert_no_error (error);
  g_object_unref (client);

  return G_IO_STREAM (connection);
}

static void
run_echo_server (GThreadedSocketService *service,
		 GSocketConnection      *connection,
		 GObject                *source_object,
		 gpointer                user_data)
{
  TestConnection *test = user_data;
  GTlsConnection *tlsconn;
  GTlsCertificate *cert;
  GError *error = NULL;
  GInputStream *istream;
  GOutputStream *ostream;
  gssize nread, nwrote, total;
  gchar buf[128];

  cert = g_tls_certificate_new_from_file (TEST_FILE ("server-and-key.pem"), &error);
  g_assert_no_error (error);

  test->server_connection = g_tls_server_connection_new (G_IO_STREAM (connection),
                                                         cert, &error);
  g_assert_no_error (error);
  g_object_unref (cert);

  tlsconn = G_TLS_CONNECTION (test->server_connection);
  g_tls_connection_handshake (tlsconn, NULL, &error);
  g_assert_no_error (error);

  istream = g_io_stream_get_input_stream (test->server_connection);
  ostream = g_io_stream_get_output_stream (test->server_connection);

  while (TRUE)
    {
      nread = g_input_stream_read (istream, buf, sizeof (buf), NULL, &error);
      g_assert_no_error (error);
      g_assert_cmpint (nread, >=, 0);

      if (nread == 0)
	break;

      for (total = 0; total < nread; total += nwrote)
	{
	  nwrote = g_output_stream_write (ostream, buf + total, nread - total, NULL, &error);
	  g_assert_no_error (error);
	}

      if (test->rehandshake)
	{
	  test->rehandshake = FALSE;
	  g_tls_connection_handshake (tlsconn, NULL, &error);
	  g_assert_no_error (error);
	}
    }

  g_io_stream_close (test->server_connection, NULL, &error);
  g_assert_no_error (error);
  test->server_closed = TRUE;
}

static void
start_echo_server_service (TestConnection *test)
{
  GError *error = NULL;

  test->service = g_threaded_socket_service_new (5);
  g_socket_listener_add_address (G_SOCKET_LISTENER (test->service),
                                 G_SOCKET_ADDRESS (test->address),
                                 G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP,
                                 NULL, NULL, &error);
  g_assert_no_error (error);

  g_signal_connect (test->service, "run", G_CALLBACK (run_echo_server), test);
}

static GIOStream *
start_echo_server_and_connect_to_it (TestConnection *test)
{
  GSocketClient *client;
  GError *error = NULL;
  GSocketConnection *connection;

  start_echo_server_service (test);

  client = g_socket_client_new ();
  connection = g_socket_client_connect (client, G_SOCKET_CONNECTABLE (test->address),
                                        NULL, &error);
  g_assert_no_error (error);
  g_object_unref (client);

  return G_IO_STREAM (connection);
}

static void
on_client_connection_close_finish (GObject        *object,
				   GAsyncResult   *res,
				   gpointer        user_data)
{
  TestConnection *test = user_data;
  GError *error = NULL;

  g_io_stream_close_finish (G_IO_STREAM (object), res, &error);
  g_assert_no_error (error);

  g_main_loop_quit (test->loop);
}

static void
on_input_read_finish (GObject        *object,
                      GAsyncResult   *res,
                      gpointer        user_data)
{
  TestConnection *test = user_data;
  gchar *line, *check;

  line = g_data_input_stream_read_line_finish (G_DATA_INPUT_STREAM (object), res,
                                               NULL, &test->read_error);
  if (!test->read_error)
    {
      g_assert (line);

      check = g_strdup (TEST_DATA);
      g_strstrip (check);
      g_assert_cmpstr (line, ==, check);
      g_free (check);
      g_free (line);
    }

  g_io_stream_close_async (test->client_connection, G_PRIORITY_DEFAULT,
			   NULL, on_client_connection_close_finish, test);
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

  connection = start_async_server_and_connect_to_it (test, G_TLS_AUTHENTICATION_NONE);
  test->client_connection = g_tls_client_connection_new (connection, test->identity, &error);
  g_assert_no_error (error);
  g_object_unref (connection);

  /* No validation at all in this test */
  g_tls_client_connection_set_validation_flags (G_TLS_CLIENT_CONNECTION (test->client_connection),
                                                0);

  read_test_data_async (test);
  g_main_loop_run (test->loop);

  g_assert_no_error (test->read_error);
  g_assert_no_error (test->server_error);
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

  connection = start_async_server_and_connect_to_it (test, G_TLS_AUTHENTICATION_NONE);
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

  g_assert_no_error (test->read_error);
  g_assert_no_error (test->server_error);
}

static void
on_notify_accepted_cas (GObject *obj,
                        GParamSpec *spec,
                        gpointer user_data)
{
  gboolean *changed = user_data;
  g_assert (*changed == FALSE);
  *changed = TRUE;
}

static void
test_client_auth_connection (TestConnection *test,
                             gconstpointer   data)
{
  GIOStream *connection;
  GError *error = NULL;
  GTlsCertificate *cert;
  GTlsCertificate *peer;
  gboolean cas_changed;

  test->database = g_tls_file_database_new (TEST_FILE ("ca-roots.pem"), &error);
  g_assert_no_error (error);
  g_assert (test->database);

  connection = start_async_server_and_connect_to_it (test, G_TLS_AUTHENTICATION_REQUIRED);
  test->client_connection = g_tls_client_connection_new (connection, test->identity, &error);
  g_assert_no_error (error);
  g_assert (test->client_connection);
  g_object_unref (connection);

  g_tls_connection_set_database (G_TLS_CONNECTION (test->client_connection), test->database);

  cert = g_tls_certificate_new_from_file (TEST_FILE ("client-and-key.pem"), &error);
  g_assert_no_error (error);

  g_tls_connection_set_certificate (G_TLS_CONNECTION (test->client_connection), cert);

  /* All validation in this test */
  g_tls_client_connection_set_validation_flags (G_TLS_CLIENT_CONNECTION (test->client_connection),
                                                G_TLS_CERTIFICATE_VALIDATE_ALL);

  cas_changed = FALSE;
  g_signal_connect (test->client_connection, "notify::accepted-cas",
                    G_CALLBACK (on_notify_accepted_cas), &cas_changed);

  read_test_data_async (test);
  g_main_loop_run (test->loop);

  g_assert_no_error (test->read_error);
  g_assert_no_error (test->server_error);

  peer = g_tls_connection_get_peer_certificate (G_TLS_CONNECTION (test->server_connection));
  g_assert (peer != NULL);
  g_assert (g_tls_certificate_is_same (peer, cert));
  g_assert (cas_changed == TRUE);

  g_object_unref (cert);
}

static void
test_client_auth_rehandshake (TestConnection *test,
			      gconstpointer   data)
{
  test->rehandshake = TRUE;
  test_client_auth_connection (test, data);
}

static void
test_client_auth_failure (TestConnection *test,
                          gconstpointer   data)
{
  GIOStream *connection;
  GError *error = NULL;
  gboolean accepted_changed;

  test->database = g_tls_file_database_new (TEST_FILE ("ca-roots.pem"), &error);
  g_assert_no_error (error);
  g_assert (test->database);

  connection = start_async_server_and_connect_to_it (test, G_TLS_AUTHENTICATION_REQUIRED);
  test->client_connection = g_tls_client_connection_new (connection, test->identity, &error);
  g_assert_no_error (error);
  g_assert (test->client_connection);
  g_object_unref (connection);

  g_tls_connection_set_database (G_TLS_CONNECTION (test->client_connection), test->database);

  /* No Certificate set */

  /* All validation in this test */
  g_tls_client_connection_set_validation_flags (G_TLS_CLIENT_CONNECTION (test->client_connection),
                                                G_TLS_CERTIFICATE_VALIDATE_ALL);

  accepted_changed = FALSE;
  g_signal_connect (test->client_connection, "notify::accepted-cas",
                    G_CALLBACK (on_notify_accepted_cas), &accepted_changed);

  read_test_data_async (test);
  g_main_loop_run (test->loop);

  g_assert_error (test->read_error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED);
  g_assert_error (test->server_error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED);

  g_assert (accepted_changed == TRUE);
}

static void
test_connection_no_database (TestConnection *test,
                             gconstpointer   data)
{
  GIOStream *connection;
  GError *error = NULL;

  connection = start_async_server_and_connect_to_it (test, G_TLS_AUTHENTICATION_NONE);
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

  g_assert_no_error (test->read_error);
  g_assert_no_error (test->server_error);
}

static void
handshake_failed_cb (GObject      *source,
		     GAsyncResult *result,
		     gpointer      user_data)
{
  TestConnection *test = user_data;
  GError *error = NULL;

  g_tls_connection_handshake_finish (G_TLS_CONNECTION (test->client_connection),
				     result, &error);
  g_assert_error (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE);
  g_clear_error (&error);

  g_main_loop_quit (test->loop);
}

static void
test_failed_connection (TestConnection *test,
			gconstpointer   data)
{
  GIOStream *connection;
  GError *error = NULL;
  GSocketConnectable *bad_addr;

  connection = start_async_server_and_connect_to_it (test, G_TLS_AUTHENTICATION_NONE);

  bad_addr = g_network_address_new ("wrong.example.com", 80);
  test->client_connection = g_tls_client_connection_new (connection, bad_addr, &error);
  g_object_unref (bad_addr);
  g_assert_no_error (error);
  g_object_unref (connection);

  g_tls_connection_handshake_async (G_TLS_CONNECTION (test->client_connection),
				    G_PRIORITY_DEFAULT, NULL,
				    handshake_failed_cb, test);
  g_main_loop_run (test->loop);

  g_tls_client_connection_set_validation_flags (G_TLS_CLIENT_CONNECTION (test->client_connection),
                                                G_TLS_CERTIFICATE_VALIDATE_ALL);

  read_test_data_async (test);
  g_main_loop_run (test->loop);

  g_assert_error (test->read_error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE);
  g_assert_no_error (test->server_error);
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

  start_async_server_service (test, G_TLS_AUTHENTICATION_NONE);
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

  start_async_server_service (test, G_TLS_AUTHENTICATION_NONE);
  client = g_socket_client_new ();
  g_socket_client_set_tls (client, TRUE);
  /* this time we don't adjust the validation flags */

  g_socket_client_connect_async (client, G_SOCKET_CONNECTABLE (test->address),
				 NULL, socket_client_failed, test);
  g_main_loop_run (test->loop);

  g_object_unref (client);
}

static void
simul_async_read_complete (GObject      *object,
			   GAsyncResult *result,
			   gpointer      user_data)
{
  TestConnection *test = user_data;
  gssize nread;
  GError *error = NULL;

  nread = g_input_stream_read_finish (G_INPUT_STREAM (object),
				      result, &error);
  g_assert_no_error (error);

  test->nread += nread;
  g_assert_cmpint (test->nread, <=, TEST_DATA_LENGTH);

  if (test->nread == TEST_DATA_LENGTH)
    {
      g_io_stream_close (test->client_connection, NULL, &error);
      g_assert_no_error (error);
      g_main_loop_quit (test->loop);
    }
  else
    {
      g_input_stream_read_async (G_INPUT_STREAM (object),
				 test->buf + test->nread,
				 TEST_DATA_LENGTH / 2,
				 G_PRIORITY_DEFAULT, NULL,
				 simul_async_read_complete, test);
    }
}

static void
simul_async_write_complete (GObject      *object,
			    GAsyncResult *result,
			    gpointer      user_data)
{
  TestConnection *test = user_data;
  gssize nwrote;
  GError *error = NULL;

  nwrote = g_output_stream_write_finish (G_OUTPUT_STREAM (object),
					 result, &error);
  g_assert_no_error (error);

  test->nwrote += nwrote;
  if (test->nwrote < TEST_DATA_LENGTH)
    {
      g_output_stream_write_async (G_OUTPUT_STREAM (object),
				   TEST_DATA + test->nwrote,
				   TEST_DATA_LENGTH - test->nwrote,
				   G_PRIORITY_DEFAULT, NULL,
				   simul_async_write_complete, test);
    }
}

static void
test_simultaneous_async (TestConnection *test,
			 gconstpointer   data)
{
  GIOStream *connection;
  GTlsCertificateFlags flags;
  GError *error = NULL;

  connection = start_echo_server_and_connect_to_it (test);
  test->client_connection = g_tls_client_connection_new (connection, test->identity, &error);
  g_assert_no_error (error);
  g_object_unref (connection);

  flags = G_TLS_CERTIFICATE_VALIDATE_ALL &
    ~(G_TLS_CERTIFICATE_UNKNOWN_CA | G_TLS_CERTIFICATE_BAD_IDENTITY);
  g_tls_client_connection_set_validation_flags (G_TLS_CLIENT_CONNECTION (test->client_connection),
                                                flags);

  memset (test->buf, 0, sizeof (test->buf));
  test->nread = test->nwrote = 0;

  g_input_stream_read_async (g_io_stream_get_input_stream (test->client_connection),
			     test->buf, TEST_DATA_LENGTH / 2,
			     G_PRIORITY_DEFAULT, NULL,
			     simul_async_read_complete, test);
  g_output_stream_write_async (g_io_stream_get_output_stream (test->client_connection),
			       TEST_DATA, TEST_DATA_LENGTH / 2,
			       G_PRIORITY_DEFAULT, NULL,
			       simul_async_write_complete, test);

  g_main_loop_run (test->loop);

  g_assert_cmpint (test->nread, ==, TEST_DATA_LENGTH);
  g_assert_cmpint (test->nwrote, ==, TEST_DATA_LENGTH);
  g_assert_cmpstr (test->buf, ==, TEST_DATA);
}

static void
test_simultaneous_async_rehandshake (TestConnection *test,
				     gconstpointer   data)
{
  test->rehandshake = TRUE;
  test_simultaneous_async (test, data);
}

static gpointer
simul_read_thread (gpointer user_data)
{
  TestConnection *test = user_data;
  GInputStream *istream = g_io_stream_get_input_stream (test->client_connection);
  GError *error = NULL;
  gssize nread;

  while (test->nread < TEST_DATA_LENGTH)
    {
      nread = g_input_stream_read (istream,
				   test->buf + test->nread,
				   MIN (TEST_DATA_LENGTH / 2, TEST_DATA_LENGTH - test->nread),
				   NULL, &error);
      g_assert_no_error (error);

      test->nread += nread;
    }

  return NULL;
}

static gpointer
simul_write_thread (gpointer user_data)
{
  TestConnection *test = user_data;
  GOutputStream *ostream = g_io_stream_get_output_stream (test->client_connection);
  GError *error = NULL;
  gssize nwrote;

  while (test->nwrote < TEST_DATA_LENGTH)
    {
      nwrote = g_output_stream_write (ostream,
				      TEST_DATA + test->nwrote,
				      MIN (TEST_DATA_LENGTH / 2, TEST_DATA_LENGTH - test->nwrote),
				      NULL, &error);
      g_assert_no_error (error);

      test->nwrote += nwrote;
    }

  return NULL;
}

static void
test_simultaneous_sync (TestConnection *test,
			gconstpointer   data)
{
  GIOStream *connection;
  GTlsCertificateFlags flags;
  GError *error = NULL;
  GThread *read_thread, *write_thread;

  connection = start_echo_server_and_connect_to_it (test);
  test->client_connection = g_tls_client_connection_new (connection, test->identity, &error);
  g_assert_no_error (error);
  g_object_unref (connection);

  flags = G_TLS_CERTIFICATE_VALIDATE_ALL &
    ~(G_TLS_CERTIFICATE_UNKNOWN_CA | G_TLS_CERTIFICATE_BAD_IDENTITY);
  g_tls_client_connection_set_validation_flags (G_TLS_CLIENT_CONNECTION (test->client_connection),
                                                flags);

  memset (test->buf, 0, sizeof (test->buf));
  test->nread = test->nwrote = 0;

  read_thread = g_thread_new ("reader", simul_read_thread, test);
  write_thread = g_thread_new ("writer", simul_write_thread, test);

  /* We need to run the main loop to get the GThreadedSocketService to
   * receive the connection and spawn the server thread.
   */
  while (!test->server_connection)
    g_main_context_iteration (NULL, FALSE);

  g_thread_join (write_thread);
  g_thread_join (read_thread);

  g_assert_cmpint (test->nread, ==, TEST_DATA_LENGTH);
  g_assert_cmpint (test->nwrote, ==, TEST_DATA_LENGTH);
  g_assert_cmpstr (test->buf, ==, TEST_DATA);

  g_io_stream_close (test->client_connection, NULL, &error);
  g_assert_no_error (error);
}

static void
test_simultaneous_sync_rehandshake (TestConnection *test,
				    gconstpointer   data)
{
  test->rehandshake = TRUE;
  test_simultaneous_sync (test, data);
}

static void
test_close_immediately (TestConnection *test,
                        gconstpointer   data)
{
  GIOStream *connection;
  GError *error = NULL;

  connection = start_async_server_and_connect_to_it (test, G_TLS_AUTHENTICATION_NONE);
  test->client_connection = g_tls_client_connection_new (connection, test->identity, &error);
  g_assert_no_error (error);
  g_object_unref (connection);

  /*
   * At this point the server won't get a chance to run. But regardless
   * closing should not wait on the server, trying to handshake or something.
   */
  g_io_stream_close (test->client_connection, NULL, &error);
  g_assert_no_error (error);
}

static void
quit_loop_on_notify (GObject *obj,
		     GParamSpec *spec,
		     gpointer user_data)
{
  GMainLoop *loop = user_data;

  g_main_loop_quit (loop);
}

static void
test_close_during_handshake (TestConnection *test,
			     gconstpointer   data)
{
  GIOStream *connection;
  GError *error = NULL;
  GMainContext *context;
  GMainLoop *loop;

  g_test_bug ("688751");

  connection = start_async_server_and_connect_to_it (test, G_TLS_AUTHENTICATION_REQUESTED);
  test->expect_server_error = TRUE;
  test->client_connection = g_tls_client_connection_new (connection, test->identity, &error);
  g_assert_no_error (error);
  g_object_unref (connection);

  loop = g_main_loop_new (NULL, FALSE);
  g_signal_connect (test->client_connection, "notify::accepted-cas",
                    G_CALLBACK (quit_loop_on_notify), loop);

  context = g_main_context_new ();
  g_main_context_push_thread_default (context);
  g_tls_connection_handshake_async (G_TLS_CONNECTION (test->client_connection),
				    G_PRIORITY_DEFAULT,
				    NULL, NULL, NULL);
  g_main_context_pop_thread_default (context);

  /* Now run the (default GMainContext) loop, which is needed for
   * the server side of things. The client-side handshake will run in
   * a thread, but its callback will never be invoked because its
   * context isn't running.
   */
  g_main_loop_run (loop);
  g_main_loop_unref (loop);

  /* At this point handshake_thread() has started (and maybe
   * finished), but handshake_thread_completed() (and thus
   * finish_handshake()) has not yet run. Make sure close doesn't
   * block.
   */
  g_io_stream_close (test->client_connection, NULL, &error);
  g_assert_no_error (error);

  /* We have to let the handshake_async() call finish now, or
   * teardown_connection() will assert.
   */
  g_main_context_iteration (context, TRUE);
  g_main_context_unref (context);
}

static void
test_write_during_handshake (TestConnection *test,
			    gconstpointer   data)
{
  GIOStream *connection;
  GError *error = NULL;
  GMainContext *context;
  GMainLoop *loop;
  GOutputStream *ostream;

  g_test_bug ("697754");

  connection = start_async_server_and_connect_to_it (test, G_TLS_AUTHENTICATION_REQUESTED);
  test->client_connection = g_tls_client_connection_new (connection, test->identity, &error);
  g_assert_no_error (error);
  g_object_unref (connection);

  loop = g_main_loop_new (NULL, FALSE);
  g_signal_connect (test->client_connection, "notify::accepted-cas",
                    G_CALLBACK (quit_loop_on_notify), loop);

  context = g_main_context_new ();
  g_main_context_push_thread_default (context);
  g_tls_connection_handshake_async (G_TLS_CONNECTION (test->client_connection),
				    G_PRIORITY_DEFAULT,
				    NULL, NULL, NULL);
  g_main_context_pop_thread_default (context);

  /* Now run the (default GMainContext) loop, which is needed for
   * the server side of things. The client-side handshake will run in
   * a thread, but its callback will never be invoked because its
   * context isn't running.
   */
  g_main_loop_run (loop);
  g_main_loop_unref (loop);

  /* At this point handshake_thread() has started (and maybe
   * finished), but handshake_thread_completed() (and thus
   * finish_handshake()) has not yet run. Make sure close doesn't
   * block.
   */

  ostream = g_io_stream_get_output_stream (test->client_connection);
  g_output_stream_write (ostream, TEST_DATA, TEST_DATA_LENGTH,
			 G_PRIORITY_DEFAULT, &error);
  g_assert_no_error (error);

  /* We have to let the handshake_async() call finish now, or
   * teardown_connection() will assert.
   */
  g_main_context_iteration (context, TRUE);
  g_main_context_unref (context);
}

int
main (int   argc,
      char *argv[])
{
  int ret;

  g_test_init (&argc, &argv, NULL);
  g_test_bug_base ("http://bugzilla.gnome.org/");

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
  g_test_add ("/tls/connection/client-auth-failure", TestConnection, NULL,
              setup_connection, test_client_auth_failure, teardown_connection);
  g_test_add ("/tls/connection/no-database", TestConnection, NULL,
              setup_connection, test_connection_no_database, teardown_connection);
  g_test_add ("/tls/connection/failed", TestConnection, NULL,
              setup_connection, test_failed_connection, teardown_connection);
  g_test_add ("/tls/connection/socket-client", TestConnection, NULL,
              setup_connection, test_connection_socket_client, teardown_connection);
  g_test_add ("/tls/connection/socket-client-failed", TestConnection, NULL,
              setup_connection, test_connection_socket_client_failed, teardown_connection);
  g_test_add ("/tls/connection/simultaneous-async", TestConnection, NULL,
              setup_connection, test_simultaneous_async, teardown_connection);
  g_test_add ("/tls/connection/simultaneous-sync", TestConnection, NULL,
	      setup_connection, test_simultaneous_sync, teardown_connection);
  g_test_add ("/tls/connection/simultaneous-async-rehandshake", TestConnection, NULL,
              setup_connection, test_simultaneous_async_rehandshake, teardown_connection);
  g_test_add ("/tls/connection/simultaneous-sync-rehandshake", TestConnection, NULL,
	      setup_connection, test_simultaneous_sync_rehandshake, teardown_connection);
  g_test_add ("/tls/connection/close-immediately", TestConnection, NULL,
              setup_connection, test_close_immediately, teardown_connection);
  g_test_add ("/tls/connection/close-during-handshake", TestConnection, NULL,
              setup_connection, test_close_during_handshake, teardown_connection);
  g_test_add ("/tls/connection/write-during-handshake", TestConnection, NULL,
              setup_connection, test_write_during_handshake, teardown_connection);

  ret = g_test_run();

  /* for valgrinding */
  g_main_context_unref (g_main_context_default ());

  return ret;
}
