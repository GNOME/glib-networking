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
#include "gtlsoutputstream-gnutls.h"

static void g_tls_output_stream_gnutls_pollable_iface_init (GPollableOutputStreamInterface *iface);

G_DEFINE_TYPE_WITH_CODE (GTlsOutputStreamGnutls, g_tls_output_stream_gnutls, G_TYPE_OUTPUT_STREAM,
			 G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_OUTPUT_STREAM, g_tls_output_stream_gnutls_pollable_iface_init)
			 )

struct _GTlsOutputStreamGnutlsPrivate
{
  GWeakRef weak_conn;
};

static void
g_tls_output_stream_gnutls_dispose (GObject *object)
{
  GTlsOutputStreamGnutls *stream = G_TLS_OUTPUT_STREAM_GNUTLS (object);

  g_weak_ref_set (&stream->priv->weak_conn, NULL);

  G_OBJECT_CLASS (g_tls_output_stream_gnutls_parent_class)->dispose (object);
}

static void
g_tls_output_stream_gnutls_finalize (GObject *object)
{
  GTlsOutputStreamGnutls *stream = G_TLS_OUTPUT_STREAM_GNUTLS (object);

  g_weak_ref_clear (&stream->priv->weak_conn);

  G_OBJECT_CLASS (g_tls_output_stream_gnutls_parent_class)->finalize (object);
}

static gssize
g_tls_output_stream_gnutls_write (GOutputStream  *stream,
				  const void     *buffer,
				  gsize           count,
				  GCancellable   *cancellable,
				  GError        **error)
{
  GTlsOutputStreamGnutls *tls_stream = G_TLS_OUTPUT_STREAM_GNUTLS (stream);
  GTlsConnectionGnutls *conn;
  gssize ret;

  conn = g_weak_ref_get (&tls_stream->priv->weak_conn);
  g_return_val_if_fail (conn != NULL, -1);

  ret = g_tls_connection_gnutls_write (conn, buffer, count, TRUE,
                                       cancellable, error);
  g_object_unref (conn);
  return ret;
}

static gboolean
g_tls_output_stream_gnutls_pollable_is_writable (GPollableOutputStream *pollable)
{
  GTlsOutputStreamGnutls *tls_stream = G_TLS_OUTPUT_STREAM_GNUTLS (pollable);
  GTlsConnectionGnutls *conn;
  gboolean ret;

  conn = g_weak_ref_get (&tls_stream->priv->weak_conn);
  g_return_val_if_fail (conn != NULL, FALSE);

  ret = g_tls_connection_gnutls_check (conn, G_IO_OUT);

  g_object_unref (conn);

  return ret;
}

static GSource *
g_tls_output_stream_gnutls_pollable_create_source (GPollableOutputStream *pollable,
						   GCancellable         *cancellable)
{
  GTlsOutputStreamGnutls *tls_stream = G_TLS_OUTPUT_STREAM_GNUTLS (pollable);
  GTlsConnectionGnutls *conn;
  GSource *ret;

  conn = g_weak_ref_get (&tls_stream->priv->weak_conn);
  g_return_val_if_fail (conn != NULL, NULL);

  ret = g_tls_connection_gnutls_create_source (conn,
                                               G_IO_OUT,
                                               cancellable);
  g_object_unref (conn);
  return ret;
}

static gssize
g_tls_output_stream_gnutls_pollable_write_nonblocking (GPollableOutputStream  *pollable,
						       const void             *buffer,
						       gsize                   size,
						       GError                **error)
{
  GTlsOutputStreamGnutls *tls_stream = G_TLS_OUTPUT_STREAM_GNUTLS (pollable);
  GTlsConnectionGnutls *conn;
  gssize ret;

  conn = g_weak_ref_get (&tls_stream->priv->weak_conn);
  g_return_val_if_fail (conn != NULL, -1);

  ret = g_tls_connection_gnutls_write (conn, buffer, size, FALSE, NULL, error);

  g_object_unref (conn);
  return ret;
}

static void
g_tls_output_stream_gnutls_class_init (GTlsOutputStreamGnutlsClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GOutputStreamClass *output_stream_class = G_OUTPUT_STREAM_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GTlsOutputStreamGnutlsPrivate));

  gobject_class->dispose = g_tls_output_stream_gnutls_dispose;
  gobject_class->finalize = g_tls_output_stream_gnutls_finalize;

  output_stream_class->write_fn = g_tls_output_stream_gnutls_write;
}

static void
g_tls_output_stream_gnutls_pollable_iface_init (GPollableOutputStreamInterface *iface)
{
  iface->is_writable = g_tls_output_stream_gnutls_pollable_is_writable;
  iface->create_source = g_tls_output_stream_gnutls_pollable_create_source;
  iface->write_nonblocking = g_tls_output_stream_gnutls_pollable_write_nonblocking;
}

static void
g_tls_output_stream_gnutls_init (GTlsOutputStreamGnutls *stream)
{
  stream->priv = G_TYPE_INSTANCE_GET_PRIVATE (stream, G_TYPE_TLS_OUTPUT_STREAM_GNUTLS, GTlsOutputStreamGnutlsPrivate);
}

GOutputStream *
g_tls_output_stream_gnutls_new (GTlsConnectionGnutls *conn)
{
  GTlsOutputStreamGnutls *tls_stream;

  tls_stream = g_object_new (G_TYPE_TLS_OUTPUT_STREAM_GNUTLS, NULL);
  g_weak_ref_init (&tls_stream->priv->weak_conn, conn);

  return G_OUTPUT_STREAM (tls_stream);
}
