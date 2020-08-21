/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO TLS tests
 *
 * Copyright 2020 Red Hat, Inc
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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
 */

#if __unix__

#include "config.h"

#include <gio/gio.h>
#include <sys/socket.h>

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

static GIOStream *
create_io_stream_for_unix_socket (gint fd)
{
  GError *error = NULL;
  GSocket *socket;
  GSocketConnection *connection;

  socket = g_socket_new_from_fd (fd, &error);
  g_assert_no_error (error);

  connection = g_socket_connection_factory_create_connection (socket);
  g_object_unref (socket);

  return G_IO_STREAM (connection);
}

static gboolean
source_dispatch_func (GPollableInputStream *stream,
                      gpointer              user_data)
{
  gboolean *was_dispatched = user_data;

  *was_dispatched = TRUE;

  return G_SOURCE_CONTINUE;
}

static void
assert_state (GInputStream *stream,
              gboolean     *was_dispatched,
              gboolean      is_readable)
{
  GPollableInputStream *pollable = G_POLLABLE_INPUT_STREAM (stream);

  /* First, the trivial check. Note that g_pollable_input_stream_is_readable()
   * is allowed to spuriously return TRUE, so if we expect the stream
   * to be readable, it had better really be readable, but it's OK
   * for it to return readable even when not expected. If we improve our
   * implementation to avoid spurious results, then this could be
   * tightened to use ==. Currently the GnuTLS backend has no spurious
   * results here, but OpenSSL does.
   */
  g_assert_cmpint (g_pollable_input_stream_is_readable (pollable), >=, is_readable);

  /* Next, check that the source is being correctly dispatched. */
  *was_dispatched = FALSE;
  while (!*was_dispatched && g_main_context_iteration (NULL, FALSE))
    ;

  /* Here we again must allow spurious wakeups. Both GnuTLS and OpenSSL
   * backends suffer spurious wakeups here.
   */
  g_assert_cmpint (*was_dispatched, >=, is_readable);
}

static void
check_input_stream_source (GIOStream *sender,
                           GIOStream *receiver)
{
  GOutputStream *output = g_io_stream_get_output_stream (sender);
  GInputStream *input = g_io_stream_get_input_stream (receiver);
  gboolean was_dispatched;
  GSource *source;
  char b;
  GError *error = NULL;

  source = g_pollable_input_stream_create_source (G_POLLABLE_INPUT_STREAM (input), NULL);
  g_source_set_callback (source, G_SOURCE_FUNC (source_dispatch_func), &was_dispatched, NULL);
  g_source_attach (source, NULL);

  /* At the start, there should be nothing pending. */
  assert_state (input, &was_dispatched, FALSE);

  /* Send two bytes. */
  g_output_stream_write (output, "ab", 2, NULL, &error);
  g_assert_no_error (error);

  /* Read the first byte. */
  assert_state (input, &was_dispatched, TRUE);
  b = 0;
  g_input_stream_read (input, &b, 1, NULL, &error);
  g_assert_no_error (error);
  g_assert_cmpint (b, ==, 'a');

  /* Read the second byte. This ensures the stream is readable as
   * expected and the data is not stuck in internal TLS library buffers.
   */
  assert_state (input, &was_dispatched, TRUE);
  g_input_stream_read (input, &b, 1, NULL, &error);
  g_assert_no_error (error);
  g_assert_cmpint (b, ==, 'b');

  /* There should be nothing else left. */
  assert_state (input, &was_dispatched, FALSE);

  g_source_destroy (source);
  g_source_unref (source);
}

static void
decrement_count (GObject      *source,
                 GAsyncResult *result,
                 gpointer      user_data)
{
  int *value = user_data;
  GError *error = NULL;

  g_tls_connection_handshake_finish (G_TLS_CONNECTION (source), result, &error);
  g_assert_no_error (error);

  (*value)--;
}

static void
test_connection_source (void)
{
  int sv[2];
  int waiting = 2;
  GIOStream *base_streams[2];
  GIOStream *tls_streams[2];
  GTlsCertificate *cert;
  GError *error = NULL;

  socketpair (AF_UNIX, SOCK_STREAM, 0, sv);

  base_streams[0] = create_io_stream_for_unix_socket (sv[0]);
  base_streams[1] = create_io_stream_for_unix_socket (sv[1]);

  cert = g_tls_certificate_new_from_file (tls_test_file_path ("server-and-key.pem"), &error);
  g_assert_no_error (error);

  tls_streams[0] = g_tls_server_connection_new (base_streams[0], cert, &error);
  g_assert_no_error (error);
  tls_streams[1] = g_tls_client_connection_new (base_streams[1], NULL, &error);
  g_assert_no_error (error);

  /* We need to explicitly handshake to avoid deadlocking during the
   * implicit handshake.
   */
  g_tls_client_connection_set_validation_flags (G_TLS_CLIENT_CONNECTION (tls_streams[1]), 0);
  g_tls_connection_handshake_async (G_TLS_CONNECTION (tls_streams[0]), 0, NULL, decrement_count, &waiting);
  g_tls_connection_handshake_async (G_TLS_CONNECTION (tls_streams[1]), 0, NULL, decrement_count, &waiting);
  while (waiting)
    g_main_context_iteration (NULL, TRUE);

  check_input_stream_source (tls_streams[0], tls_streams[1]);
  check_input_stream_source (tls_streams[1], tls_streams[0]);
}

int
main (int   argc,
      char *argv[])
{
  int ret;

  g_test_init (&argc, &argv, NULL);

  g_setenv ("GSETTINGS_BACKEND", "memory", TRUE);
  g_setenv ("GIO_USE_TLS", BACKEND, TRUE);

  g_assert_true (g_ascii_strcasecmp (G_OBJECT_TYPE_NAME (g_tls_backend_get_default ()), "GTlsBackend" BACKEND) == 0);

  g_test_add_func ("/tls/" BACKEND "/connection-source", test_connection_source);

  ret = g_test_run ();

  /* for valgrinding */
  g_main_context_unref (g_main_context_default ());

  return ret;
}

#else

int
main (void)
{
  return 0;
}

#endif /* __unix__ */
