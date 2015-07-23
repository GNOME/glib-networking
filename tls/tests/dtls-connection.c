/* GIO TLS tests
 *
 * Copyright 2011, 2015 Collabora, Ltd.
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
 * In addition, when the library is used with OpenSSL, a special
 * exception applies. Refer to the LICENSE_EXCEPTION file for details.
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 *         Philip Withnall <philip.withnall@collabora.co.uk>
 */

#include "config.h"

#include "mock-interaction.h"

#include <gio/gio.h>
#include <gnutls/gnutls.h>

#include <sys/types.h>
#include <string.h>

static const gchar *
tls_test_file_path (const char *name)
{
  const gchar *const_path;
  gchar *path;

  path = g_test_build_filename (G_TEST_DIST, "files", name, NULL);
  if (!g_path_is_absolute (path))
    {
      gchar *cwd, *abs;

      cwd = g_get_current_dir ();
      abs = g_build_filename (cwd, path, NULL);
      g_free (cwd);
      g_free (path);
      path = abs;
    }

  const_path = g_intern_string (path);
  g_free (path);
  return const_path;
}

#define TEST_DATA "You win again, gravity!\n"
#define TEST_DATA_LENGTH 24

typedef struct {
  GMainContext *context;
  gboolean loop_finished;
  GSocket *server_socket;
  GSource *server_source;
  GTlsDatabase *database;
  GDatagramBased *server_connection;
  GDatagramBased *client_connection;
  GSocketConnectable *identity;
  GSocketAddress *address;
  GTlsAuthenticationMode auth_mode;
  gboolean rehandshake;
  GTlsCertificateFlags accept_flags;
  GError *read_error;
  gboolean expect_server_error;
  GError *server_error;
  gboolean server_should_close;
  gboolean server_running;

  char buf[128];
  gssize nread, nwrote;
} TestConnection;

static void
setup_connection (TestConnection *test, gconstpointer data)
{
  test->context = g_main_context_default ();
  test->loop_finished = FALSE;
  test->auth_mode = G_TLS_AUTHENTICATION_NONE;
}

/* Waits about 10 seconds for @var to be NULL/FALSE */
#define WAIT_UNTIL_UNSET(var)				\
  if (var)						\
    {							\
      int i;						\
							\
      for (i = 0; i < 13 && (var); i++)			\
	{						\
	  g_usleep (1000 * (1 << i));			\
	  g_main_context_iteration (NULL, FALSE);	\
	}						\
							\
      g_assert (!(var));				\
    }

static void
teardown_connection (TestConnection *test, gconstpointer data)
{
  GError *error = NULL;

  if (test->server_source)
    {
      g_source_destroy (test->server_source);
      g_source_unref (test->server_source);
      test->server_source = NULL;
    }

  if (test->server_connection)
    {
      WAIT_UNTIL_UNSET (test->server_running);

      g_object_add_weak_pointer (G_OBJECT (test->server_connection),
				 (gpointer *)&test->server_connection);
      g_object_unref (test->server_connection);
      WAIT_UNTIL_UNSET (test->server_connection);
    }

  if (test->server_socket)
    {
      g_socket_close (test->server_socket, &error);
      g_assert_no_error (error);

      /* The outstanding accept_async will hold a ref on test->server_socket,
       * which we want to wait for it to release if we're valgrinding.
       */
      g_object_add_weak_pointer (G_OBJECT (test->server_socket), (gpointer *)&test->server_socket);
      g_object_unref (test->server_socket);
      WAIT_UNTIL_UNSET (test->server_socket);
    }

  if (test->client_connection)
    {
      g_object_add_weak_pointer (G_OBJECT (test->client_connection),
				 (gpointer *)&test->client_connection);
      g_object_unref (test->client_connection);
      WAIT_UNTIL_UNSET (test->client_connection);
    }

  if (test->database)
    {
      g_object_add_weak_pointer (G_OBJECT (test->database),
				 (gpointer *)&test->database);
      g_object_unref (test->database);
      WAIT_UNTIL_UNSET (test->database);
    }

  g_clear_object (&test->address);
  g_clear_object (&test->identity);
  g_clear_error (&test->read_error);
  g_clear_error (&test->server_error);
}

static void
start_server (TestConnection *test)
{
  GInetAddress *inet;
  GSocketAddress *addr;
  GInetSocketAddress *iaddr;
  GSocket *socket = NULL;
  GError *error = NULL;

  inet = g_inet_address_new_from_string ("127.0.0.1");
  addr = g_inet_socket_address_new (inet, 0);
  g_object_unref (inet);

  socket = g_socket_new (G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_DATAGRAM,
                         G_SOCKET_PROTOCOL_UDP, &error);
  g_assert_no_error (error);

  g_socket_bind (socket, addr, FALSE, &error);
  g_assert_no_error (error);

  test->address = g_socket_get_local_address (socket, &error);
  g_assert_no_error (error);

  g_object_unref (addr);

  /* The hostname in test->identity matches the server certificate. */
  iaddr = G_INET_SOCKET_ADDRESS (test->address);
  test->identity = g_network_address_new ("server.example.com",
					  g_inet_socket_address_get_port (iaddr));

  test->server_socket = socket;
  test->server_running = TRUE;
}

static gboolean
on_accept_certificate (GTlsClientConnection *conn, GTlsCertificate *cert,
                       GTlsCertificateFlags errors, gpointer user_data)
{
  TestConnection *test = user_data;
  return errors == test->accept_flags;
}

static void
close_server_connection (TestConnection *test);

static void
on_rehandshake_finish (GObject        *object,
		       GAsyncResult   *res,
		       gpointer        user_data)
{
  TestConnection *test = user_data;
  GError *error = NULL;
  GOutputVector vectors[2] = {
    { TEST_DATA + TEST_DATA_LENGTH / 2, TEST_DATA_LENGTH / 4 },
    { TEST_DATA + 3 * TEST_DATA_LENGTH / 4, TEST_DATA_LENGTH / 4},
  };
  GOutputMessage message = { NULL, vectors, G_N_ELEMENTS (vectors), 0, NULL, 0 };
  gint n_sent;

  g_dtls_connection_handshake_finish (G_DTLS_CONNECTION (object), res, &error);
  g_assert_no_error (error);

  do
    {
      g_clear_error (&test->server_error);
      n_sent = g_datagram_based_send_messages (test->server_connection,
                                               &message, 1,
                                               G_SOCKET_MSG_NONE, 0, NULL,
                                               &test->server_error);
      g_main_context_iteration (NULL, FALSE);
    }
  while (g_error_matches (test->server_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK));

  if (!test->server_error)
    {
      g_assert_cmpint (n_sent, ==, 1);
      g_assert_cmpuint (message.bytes_sent, ==, TEST_DATA_LENGTH / 2);
    }

  if (!test->server_error && test->rehandshake)
    {
      test->rehandshake = FALSE;
      g_dtls_connection_handshake_async (G_DTLS_CONNECTION (test->server_connection),
                                         G_PRIORITY_DEFAULT, NULL,
                                         on_rehandshake_finish, test);
      return;
    }

  if (test->server_should_close)
    close_server_connection (test);
}

static void
close_server_connection (TestConnection *test)
{
  GError *error = NULL;

  g_dtls_connection_close (G_DTLS_CONNECTION (test->server_connection),
                           NULL, &error);

  if (test->expect_server_error)
    g_assert (error != NULL);
  else
    g_assert_no_error (error);
  test->server_running = FALSE;
}

static gboolean
on_incoming_connection (GSocket       *socket,
                        GIOCondition   condition,
                        gpointer       user_data)
{
  TestConnection *test = user_data;
  GTlsCertificate *cert;
  GError *error = NULL;
  GOutputVector vector = {
    TEST_DATA,
    test->rehandshake ? TEST_DATA_LENGTH / 2 : TEST_DATA_LENGTH
  };
  GOutputMessage message = { NULL, &vector, 1, 0, NULL, 0 };
  gint n_sent;
  GSocketAddress *addr = NULL;  /* owned */
  guint8 databuf[65536];
  GInputVector vec = {databuf, sizeof (databuf)};
  gint flags = G_SOCKET_MSG_PEEK;
  gssize ret;

  /* Ignore this if the source has already been destroyed. */
  if (g_source_is_destroyed (test->server_source))
    return G_SOURCE_REMOVE;

  /* Remove the source as the first thing. */
  g_source_destroy (test->server_source);
  g_source_unref (test->server_source);
  test->server_source = NULL;

  /* Peek at the incoming packet to get the peer’s address. */
  ret = g_socket_receive_message (socket, &addr, &vec, 1, NULL, NULL,
                                  &flags, NULL, NULL);

  if (ret <= 0)
    return G_SOURCE_REMOVE;

  if (!g_socket_connect (socket, addr, NULL, NULL))
    {
      g_object_unref (addr);
      return G_SOURCE_CONTINUE;
    }

  g_clear_object (&addr);

  /* Wrap the socket in a GDtlsServerConnection. */
  cert = g_tls_certificate_new_from_file (tls_test_file_path ("server-and-key.pem"), &error);
  g_assert_no_error (error);

  test->server_connection = g_dtls_server_connection_new (G_DATAGRAM_BASED (socket),
                                                          cert, &error);
  g_debug ("%s: Server connection %p on socket %p", G_STRFUNC, test->server_connection, socket);
  g_assert_no_error (error);
  g_object_unref (cert);

  g_object_set (test->server_connection, "authentication-mode", test->auth_mode, NULL);
  g_signal_connect (test->server_connection, "accept-certificate",
                    G_CALLBACK (on_accept_certificate), test);

  if (test->database)
    g_dtls_connection_set_database (G_DTLS_CONNECTION (test->server_connection), test->database);

  do
    {
      g_clear_error (&test->server_error);
      n_sent = g_datagram_based_send_messages (test->server_connection,
                                               &message, 1,
                                               G_SOCKET_MSG_NONE, 0, NULL,
                                               &test->server_error);
      g_main_context_iteration (NULL, FALSE);
    }
  while (g_error_matches (test->server_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK));

  if (!test->server_error)
    {
      g_assert_cmpint (n_sent, ==, 1);
      g_assert_cmpuint (message.bytes_sent, ==, vector.size);
    }

  if (!test->server_error && test->rehandshake)
    {
      test->rehandshake = FALSE;
      g_dtls_connection_handshake_async (G_DTLS_CONNECTION (test->server_connection),
                                         G_PRIORITY_DEFAULT, NULL,
                                         on_rehandshake_finish, test);
      return G_SOURCE_REMOVE;
    }

  if (test->server_should_close)
    close_server_connection (test);

  return G_SOURCE_REMOVE;
}

static void
start_async_server_service (TestConnection *test, GTlsAuthenticationMode auth_mode,
                            gboolean should_close)
{
  start_server (test);

  test->auth_mode = auth_mode;
  test->server_source = g_socket_create_source (test->server_socket, G_IO_IN,
                                                NULL);
  g_source_set_callback (test->server_source,
                         (GSourceFunc) on_incoming_connection, test, NULL);
  g_source_attach (test->server_source, NULL);

  test->server_should_close = should_close;
}

static GDatagramBased *
start_async_server_and_connect_to_it (TestConnection *test,
                                      GTlsAuthenticationMode auth_mode,
                                      gboolean should_close)
{
  GError *error = NULL;
  GSocket *socket;

  start_async_server_service (test, auth_mode, should_close);

  socket = g_socket_new (G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_DATAGRAM,
                         G_SOCKET_PROTOCOL_UDP, &error);
  g_assert_no_error (error);

  g_socket_connect (socket, test->address, NULL, &error);
  g_assert_no_error (error);

  return G_DATAGRAM_BASED (socket);
}

static void
read_test_data_async (TestConnection *test)
{
  gchar *check;
  GError *error = NULL;
  guint8 buf[TEST_DATA_LENGTH * 2];
  GInputVector vectors[2] = {
    { &buf, sizeof (buf) / 2 },
    { &buf + sizeof (buf) / 2, sizeof (buf) / 2 },
  };
  GInputMessage message = { NULL, vectors, G_N_ELEMENTS (vectors), 0, 0, NULL, NULL };
  gint n_read;

  do
    {
      g_clear_error (&test->read_error);
      n_read = g_datagram_based_receive_messages (test->client_connection,
                                                  &message, 1,
                                                  G_SOCKET_MSG_NONE, 0,
                                                  NULL, &test->read_error);
      g_main_context_iteration (NULL, FALSE);
    }
  while (g_error_matches (test->read_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK));

  if (!test->read_error)
    {
      g_assert_cmpint (n_read, ==, 1);

      check = g_strdup (TEST_DATA);
      g_assert_cmpuint (strlen (check), ==, message.bytes_received);
      g_assert (strncmp (check, (const char *) buf, message.bytes_received) == 0);
      g_free (check);
    }

  g_dtls_connection_close (G_DTLS_CONNECTION (test->client_connection),
                           NULL, &error);
  g_assert_no_error (error);

  test->loop_finished = TRUE;
}

static void
test_basic_connection (TestConnection *test,
                       gconstpointer   data)
{
  GDatagramBased *connection;
  GError *error = NULL;

  connection = start_async_server_and_connect_to_it (test, G_TLS_AUTHENTICATION_NONE, TRUE);
  test->client_connection = g_dtls_client_connection_new (connection, test->identity, &error);
  g_debug ("%s: Client connection %p on socket %p", G_STRFUNC, test->client_connection, connection);
  g_assert_no_error (error);
  g_object_unref (connection);

  /* No validation at all in this test */
  g_dtls_client_connection_set_validation_flags (G_DTLS_CLIENT_CONNECTION (test->client_connection),
                                                 0);

  read_test_data_async (test);
  while (!test->loop_finished)
    g_main_context_iteration (test->context, TRUE);

  g_assert_no_error (test->server_error);
  g_assert_no_error (test->read_error);
}

int
main (int   argc,
      char *argv[])
{
  int ret;
  int i;

  /* Check if this is a subprocess, and set G_TLS_GNUTLS_PRIORITY
   * appropriately if so.
   */
  for (i = 1; i < argc - 1; i++)
    {
      if (!strcmp (argv[i], "-p"))
	{
	  const char *priority = argv[i + 1];

	  priority = strrchr (priority, '/');
	  if (priority++ &&
	      (g_str_has_prefix (priority, "NORMAL:") ||
	       g_str_has_prefix (priority, "NONE:")))
	    g_setenv ("G_TLS_GNUTLS_PRIORITY", priority, TRUE);
	  break;
	}
    }

  g_test_init (&argc, &argv, NULL);
  g_test_bug_base ("http://bugzilla.gnome.org/");

  g_setenv ("GSETTINGS_BACKEND", "memory", TRUE);
  g_setenv ("GIO_EXTRA_MODULES", TOP_BUILDDIR "/tls/gnutls/.libs", TRUE);
  g_setenv ("GIO_USE_TLS", "gnutls", TRUE);

  g_test_add ("/dtls/connection/basic", TestConnection, NULL,
              setup_connection, test_basic_connection, teardown_connection);

  ret = g_test_run();

  /* for valgrinding */
  g_main_context_unref (g_main_context_default ());

  return ret;
}
