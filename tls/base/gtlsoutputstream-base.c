/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2010 Red Hat, Inc.
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
 */

#include "config.h"
#include "gtlsoutputstream-base.h"

#include <glib/gi18n.h>

static void g_tls_output_stream_base_pollable_iface_init (GPollableOutputStreamInterface *iface);

G_DEFINE_TYPE_WITH_CODE (GTlsOutputStreamBase, g_tls_output_stream_base, G_TYPE_OUTPUT_STREAM,
			 G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_OUTPUT_STREAM, g_tls_output_stream_base_pollable_iface_init)
			 )

struct _GTlsOutputStreamBasePrivate
{
  GWeakRef weak_conn;
};

static void
g_tls_output_stream_base_dispose (GObject *object)
{
  GTlsOutputStreamBase *stream = G_TLS_OUTPUT_STREAM_BASE (object);

  g_weak_ref_set (&stream->priv->weak_conn, NULL);

  G_OBJECT_CLASS (g_tls_output_stream_base_parent_class)->dispose (object);
}

static void
g_tls_output_stream_base_finalize (GObject *object)
{
  GTlsOutputStreamBase *stream = G_TLS_OUTPUT_STREAM_BASE (object);

  g_weak_ref_clear (&stream->priv->weak_conn);

  G_OBJECT_CLASS (g_tls_output_stream_base_parent_class)->finalize (object);
}

static gssize
g_tls_output_stream_base_write (GOutputStream  *stream,
				const void     *buffer,
				gsize           count,
				GCancellable   *cancellable,
				GError        **error)
{
  GTlsOutputStreamBase *tls_stream = G_TLS_OUTPUT_STREAM_BASE (stream);
  GTlsConnectionBase *conn;
  gssize ret;

  conn = g_weak_ref_get (&tls_stream->priv->weak_conn);
  if (conn == NULL)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CLOSED,
                           _("Connection is closed"));
      return -1;
    }

  ret = g_tls_connection_base_write (conn, buffer, count, TRUE,
                                     cancellable, error);
  g_object_unref (conn);
  return ret;
}

static gboolean
g_tls_output_stream_base_pollable_is_writable (GPollableOutputStream *pollable)
{
  GTlsOutputStreamBase *tls_stream = G_TLS_OUTPUT_STREAM_BASE (pollable);
  GTlsConnectionBase *conn;
  gboolean ret;

  conn = g_weak_ref_get (&tls_stream->priv->weak_conn);
  g_return_val_if_fail (conn != NULL, FALSE);

  ret = g_tls_connection_base_check (conn, G_IO_OUT);

  g_object_unref (conn);

  return ret;
}

static GSource *
g_tls_output_stream_base_pollable_create_source (GPollableOutputStream *pollable,
						 GCancellable         *cancellable)
{
  GTlsOutputStreamBase *tls_stream = G_TLS_OUTPUT_STREAM_BASE (pollable);
  GTlsConnectionBase *conn;
  GSource *ret;

  conn = g_weak_ref_get (&tls_stream->priv->weak_conn);
  g_return_val_if_fail (conn != NULL, NULL);

  ret = g_tls_connection_base_create_source (conn,
                                             G_IO_OUT,
                                             cancellable);
  g_object_unref (conn);
  return ret;
}

static gssize
g_tls_output_stream_base_pollable_write_nonblocking (GPollableOutputStream  *pollable,
						     const void             *buffer,
						     gsize                   size,
						     GError                **error)
{
  GTlsOutputStreamBase *tls_stream = G_TLS_OUTPUT_STREAM_BASE (pollable);
  GTlsConnectionBase *conn;
  gssize ret;

  conn = g_weak_ref_get (&tls_stream->priv->weak_conn);
  g_return_val_if_fail (conn != NULL, -1);

  ret = g_tls_connection_base_write (conn, buffer, size, FALSE, NULL, error);

  g_object_unref (conn);
  return ret;
}

static gboolean
g_tls_output_stream_base_close (GOutputStream            *stream,
                                  GCancellable             *cancellable,
                                  GError                  **error)
{
  GTlsOutputStreamBase *tls_stream = G_TLS_OUTPUT_STREAM_BASE (stream);
  GIOStream *conn;
  gboolean ret;

  conn = g_weak_ref_get (&tls_stream->priv->weak_conn);

  /* Special case here because this is called by the finalize
   * of the main GTlsConnection object.
   */
  if (conn == NULL)
    return TRUE;

  ret = g_tls_connection_base_close_internal (conn, G_TLS_DIRECTION_WRITE,
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
  GTlsOutputStreamBase *tls_stream = object;
  GError *error = NULL;
  GIOStream *conn;

  conn = g_weak_ref_get (&tls_stream->priv->weak_conn);

  if (conn && !g_tls_connection_base_close_internal (conn,
                                                     G_TLS_DIRECTION_WRITE,
                                                     cancellable, &error))
    g_task_return_error (task, error);
  else
    g_task_return_boolean (task, TRUE);

  if (conn)
    g_object_unref (conn);
}


static void
g_tls_output_stream_base_close_async (GOutputStream            *stream,
                                      int                       io_priority,
                                      GCancellable             *cancellable,
                                      GAsyncReadyCallback       callback,
                                      gpointer                  user_data)
{
  GTask *task;

  task = g_task_new (stream, cancellable, callback, user_data);
  g_task_set_source_tag (task, g_tls_output_stream_base_close_async);
  g_task_set_priority (task, io_priority);
  g_task_run_in_thread (task, close_thread);
  g_object_unref (task);
}

static gboolean
g_tls_output_stream_base_close_finish (GOutputStream            *stream,
                                         GAsyncResult             *result,
                                         GError                  **error)
{
  g_return_val_if_fail (g_task_is_valid (result, stream), FALSE);
  g_return_val_if_fail (g_task_get_source_tag (G_TASK (result)) ==
                        g_tls_output_stream_base_close_async, FALSE);

  return g_task_propagate_boolean (G_TASK (result), error);
}

static void
g_tls_output_stream_base_class_init (GTlsOutputStreamBaseClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GOutputStreamClass *output_stream_class = G_OUTPUT_STREAM_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GTlsOutputStreamBasePrivate));

  gobject_class->dispose = g_tls_output_stream_base_dispose;
  gobject_class->finalize = g_tls_output_stream_base_finalize;

  output_stream_class->write_fn = g_tls_output_stream_base_write;
  output_stream_class->close_fn = g_tls_output_stream_base_close;
  output_stream_class->close_async = g_tls_output_stream_base_close_async;
  output_stream_class->close_finish = g_tls_output_stream_base_close_finish;
}

static void
g_tls_output_stream_base_pollable_iface_init (GPollableOutputStreamInterface *iface)
{
  iface->is_writable = g_tls_output_stream_base_pollable_is_writable;
  iface->create_source = g_tls_output_stream_base_pollable_create_source;
  iface->write_nonblocking = g_tls_output_stream_base_pollable_write_nonblocking;
}

static void
g_tls_output_stream_base_init (GTlsOutputStreamBase *stream)
{
  stream->priv = G_TYPE_INSTANCE_GET_PRIVATE (stream, G_TYPE_TLS_OUTPUT_STREAM_BASE, GTlsOutputStreamBasePrivate);
}

GOutputStream *
g_tls_output_stream_base_new (GTlsConnectionBase *conn)
{
  GTlsOutputStreamBase *tls_stream;

  tls_stream = g_object_new (G_TYPE_TLS_OUTPUT_STREAM_BASE, NULL);
  g_weak_ref_init (&tls_stream->priv->weak_conn, conn);

  return G_OUTPUT_STREAM (tls_stream);
}
