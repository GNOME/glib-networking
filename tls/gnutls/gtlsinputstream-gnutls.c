/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2010 Red Hat, Inc.
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

#include "config.h"
#include "gtlsinputstream-gnutls.h"

struct _GTlsInputStreamGnutls
{
  GInputStream parent_instance;

  GWeakRef weak_conn;
};

static void g_tls_input_stream_gnutls_pollable_iface_init (GPollableInputStreamInterface *iface);

G_DEFINE_TYPE_WITH_CODE (GTlsInputStreamGnutls, g_tls_input_stream_gnutls, G_TYPE_INPUT_STREAM,
                         G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_INPUT_STREAM, g_tls_input_stream_gnutls_pollable_iface_init)
                         )

static void
g_tls_input_stream_gnutls_dispose (GObject *object)
{
  GTlsInputStreamGnutls *stream = G_TLS_INPUT_STREAM_GNUTLS (object);

  g_weak_ref_set (&stream->weak_conn, NULL);

  G_OBJECT_CLASS (g_tls_input_stream_gnutls_parent_class)->dispose (object);
}

static void
g_tls_input_stream_gnutls_finalize (GObject *object)
{
  GTlsInputStreamGnutls *stream = G_TLS_INPUT_STREAM_GNUTLS (object);

  g_weak_ref_clear (&stream->weak_conn);

  G_OBJECT_CLASS (g_tls_input_stream_gnutls_parent_class)->finalize (object);
}

static gssize
g_tls_input_stream_gnutls_read (GInputStream  *stream,
                                void          *buffer,
                                gsize          count,
                                GCancellable  *cancellable,
                                GError       **error)
{
  GTlsInputStreamGnutls *tls_stream = G_TLS_INPUT_STREAM_GNUTLS (stream);
  GTlsConnectionGnutls *conn;
  gssize ret;

  conn = g_weak_ref_get (&tls_stream->weak_conn);
  g_return_val_if_fail (conn != NULL, -1);

  ret = g_tls_connection_gnutls_read (conn,
                                      buffer, count, -1  /* blocking */,
                                      cancellable, error);
  g_object_unref (conn);
  return ret;
}

static gboolean
g_tls_input_stream_gnutls_pollable_is_readable (GPollableInputStream *pollable)
{
  GTlsInputStreamGnutls *tls_stream = G_TLS_INPUT_STREAM_GNUTLS (pollable);
  GTlsConnectionGnutls *conn;
  gboolean ret;

  conn = g_weak_ref_get (&tls_stream->weak_conn);
  g_return_val_if_fail (conn != NULL, FALSE);

  ret = g_tls_connection_gnutls_check (conn, G_IO_IN);

  g_object_unref (conn);
  return ret;
}

static GSource *
g_tls_input_stream_gnutls_pollable_create_source (GPollableInputStream *pollable,
                                                  GCancellable         *cancellable)
{
  GTlsInputStreamGnutls *tls_stream = G_TLS_INPUT_STREAM_GNUTLS (pollable);
  GTlsConnectionGnutls *conn;
  GSource *ret;

  conn = g_weak_ref_get (&tls_stream->weak_conn);
  g_return_val_if_fail (conn != NULL, NULL);

  ret = g_tls_connection_gnutls_create_source (conn, G_IO_IN, cancellable);
  g_object_unref (conn);
  return ret;
}

static gssize
g_tls_input_stream_gnutls_pollable_read_nonblocking (GPollableInputStream  *pollable,
                                                     void                  *buffer,
                                                     gsize                  size,
                                                     GError               **error)
{
  GTlsInputStreamGnutls *tls_stream = G_TLS_INPUT_STREAM_GNUTLS (pollable);
  GTlsConnectionGnutls *conn;
  gssize ret;

  conn = g_weak_ref_get (&tls_stream->weak_conn);
  g_return_val_if_fail (conn != NULL, -1);

  ret = g_tls_connection_gnutls_read (conn, buffer, size,
                                      0  /* non-blocking */, NULL, error);

  g_object_unref (conn);
  return ret;
}

static gboolean
g_tls_input_stream_gnutls_close (GInputStream            *stream,
                                 GCancellable             *cancellable,
                                 GError                  **error)
{
  GTlsInputStreamGnutls *tls_stream = G_TLS_INPUT_STREAM_GNUTLS (stream);
  GIOStream *conn;
  gboolean ret;

  conn = g_weak_ref_get (&tls_stream->weak_conn);

  /* Special case here because this is called by the finalize
   * of the main GTlsConnection object.
   */
  if (conn == NULL)
    return TRUE;

  ret = g_tls_connection_gnutls_close_internal (conn, G_TLS_DIRECTION_READ,
                                                -1,  /* blocking */
                                                cancellable, error);

  g_object_unref (conn);
  return ret;
}

/* We do async close as synchronous-in-a-thread so we don't need to
 * implement G_IO_IN/G_IO_OUT flip-flopping just for this one case
 * (since handshakes are also done synchronously now).
 */
static void
close_thread (GTask        *task,
              gpointer      object,
              gpointer      task_data,
              GCancellable *cancellable)
{
  GTlsInputStreamGnutls *tls_stream = object;
  GError *error = NULL;
  GIOStream *conn;

  conn = g_weak_ref_get (&tls_stream->weak_conn);

  if (conn && !g_tls_connection_gnutls_close_internal (conn,
                                                       G_TLS_DIRECTION_READ,
                                                       -1,  /* blocking */
                                                       cancellable, &error))
    g_task_return_error (task, error);
  else
    g_task_return_boolean (task, TRUE);

  if (conn)
    g_object_unref (conn);
}


static void
g_tls_input_stream_gnutls_close_async (GInputStream            *stream,
                                       int                       io_priority,
                                       GCancellable             *cancellable,
                                       GAsyncReadyCallback       callback,
                                       gpointer                  user_data)
{
  GTask *task;

  task = g_task_new (stream, cancellable, callback, user_data);
  g_task_set_source_tag (task, g_tls_input_stream_gnutls_close_async);
  g_task_set_priority (task, io_priority);
  g_task_run_in_thread (task, close_thread);
  g_object_unref (task);
}

static gboolean
g_tls_input_stream_gnutls_close_finish (GInputStream            *stream,
                                        GAsyncResult             *result,
                                        GError                  **error)
{
  g_return_val_if_fail (g_task_is_valid (result, stream), FALSE);
  g_return_val_if_fail (g_task_get_source_tag (G_TASK (result)) ==
                        g_tls_input_stream_gnutls_close_async, FALSE);

  return g_task_propagate_boolean (G_TASK (result), error);
}

static void
g_tls_input_stream_gnutls_class_init (GTlsInputStreamGnutlsClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GInputStreamClass *input_stream_class = G_INPUT_STREAM_CLASS (klass);

  gobject_class->dispose = g_tls_input_stream_gnutls_dispose;
  gobject_class->finalize = g_tls_input_stream_gnutls_finalize;

  input_stream_class->read_fn = g_tls_input_stream_gnutls_read;
  input_stream_class->close_fn = g_tls_input_stream_gnutls_close;
  input_stream_class->close_async = g_tls_input_stream_gnutls_close_async;
  input_stream_class->close_finish = g_tls_input_stream_gnutls_close_finish;
}

static void
g_tls_input_stream_gnutls_pollable_iface_init (GPollableInputStreamInterface *iface)
{
  iface->is_readable = g_tls_input_stream_gnutls_pollable_is_readable;
  iface->create_source = g_tls_input_stream_gnutls_pollable_create_source;
  iface->read_nonblocking = g_tls_input_stream_gnutls_pollable_read_nonblocking;
}

static void
g_tls_input_stream_gnutls_init (GTlsInputStreamGnutls *stream)
{
}

GInputStream *
g_tls_input_stream_gnutls_new (GTlsConnectionGnutls *conn)
{
  GTlsInputStreamGnutls *tls_stream;

  tls_stream = g_object_new (G_TYPE_TLS_INPUT_STREAM_GNUTLS, NULL);
  g_weak_ref_init (&tls_stream->weak_conn, conn);

  return G_INPUT_STREAM (tls_stream);
}
