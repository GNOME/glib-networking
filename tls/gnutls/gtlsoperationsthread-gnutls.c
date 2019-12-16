/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2009 Red Hat, Inc
 * Copyright 2015, 2016 Collabora, Ltd.
 * Copyright 2019 Igalia S.L.
 * Copyright 2019 Metrological Group B.V.
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
#include "gtlsoperationsthread-gnutls.h"

#include "gtlsconnection-gnutls.h"

#include <glib/gi18n-lib.h>
#include <gnutls/dtls.h>

struct _GTlsOperationsThreadGnutls {
  GTlsOperationsThreadBase parent_instance;

  gnutls_session_t         session;
};

static gnutls_priority_t priority;

G_DEFINE_TYPE (GTlsOperationsThreadGnutls, g_tls_operations_thread_gnutls, G_TYPE_TLS_OPERATIONS_THREAD_BASE)

static GTlsConnectionBaseStatus
end_gnutls_io (GTlsOperationsThreadGnutls  *self,
               GIOCondition                 direction,
               int                          ret,
               GError                     **error,
               const char                  *err_prefix)
{
  GTlsConnectionBase *tls;
  GTlsConnectionBaseStatus status;
  gboolean handshaking;
  gboolean ever_handshaked;
  GError *my_error = NULL;

  /* We intentionally do not check for GNUTLS_E_INTERRUPTED here
   * Instead, the caller may poll for the source to become ready again.
   * (Note that GTlsOutputStreamGnutls and GTlsInputStreamGnutls inherit
   * from GPollableOutputStream and GPollableInputStream, respectively.)
   * See also the comment in set_gnutls_error().
   */
  if (ret == GNUTLS_E_AGAIN ||
      ret == GNUTLS_E_WARNING_ALERT_RECEIVED)
    return G_TLS_CONNECTION_BASE_TRY_AGAIN;

  tls = g_tls_operations_thread_base_get_connection (G_TLS_OPERATIONS_THREAD_BASE (self));

  status = g_tls_connection_base_pop_io (tls, direction, ret >= 0, &my_error);
  if (status == G_TLS_CONNECTION_BASE_OK ||
      status == G_TLS_CONNECTION_BASE_WOULD_BLOCK ||
      status == G_TLS_CONNECTION_BASE_TIMED_OUT)
    {
      if (my_error)
        g_propagate_error (error, my_error);
      return status;
    }

  g_assert (status == G_TLS_CONNECTION_BASE_ERROR);

  handshaking = g_tls_connection_base_is_handshaking (tls);
  ever_handshaked = g_tls_connection_base_ever_handshaked (tls);

  if (handshaking && !ever_handshaked)
    {
      if (g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_FAILED) ||
          g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_BROKEN_PIPE))
        {
          g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_NOT_TLS,
                       _("Peer failed to perform TLS handshake: %s"), my_error->message);
          g_clear_error (&my_error);
          return G_TLS_CONNECTION_BASE_ERROR;
        }

      if (status == GNUTLS_E_UNEXPECTED_PACKET_LENGTH ||
          status == GNUTLS_E_DECRYPTION_FAILED ||
          status == GNUTLS_E_UNSUPPORTED_VERSION_PACKET)
        {
          g_clear_error (&my_error);
          g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_NOT_TLS,
                       _("Peer failed to perform TLS handshake: %s"), gnutls_strerror (ret));
          return G_TLS_CONNECTION_BASE_ERROR;
        }
    }

  if (ret == GNUTLS_E_REHANDSHAKE)
    return G_TLS_CONNECTION_BASE_REHANDSHAKE;

  if (ret == GNUTLS_E_PREMATURE_TERMINATION)
    {
      if (handshaking && !ever_handshaked)
        {
          g_clear_error (&my_error);
          g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_NOT_TLS,
                       _("Peer failed to perform TLS handshake: %s"), gnutls_strerror (ret));
          return G_TLS_CONNECTION_BASE_ERROR;
        }

      if (g_tls_connection_get_require_close_notify (G_TLS_CONNECTION (tls)))
        {
          g_clear_error (&my_error);
          g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_EOF,
                               _("TLS connection closed unexpectedly"));
          return G_TLS_CONNECTION_BASE_ERROR;
        }

      return G_TLS_CONNECTION_BASE_OK;
    }

  if (ret == GNUTLS_E_NO_CERTIFICATE_FOUND || ret == GNUTLS_E_CERTIFICATE_REQUIRED)
    {
      g_clear_error (&my_error);
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED,
                           _("TLS connection peer did not send a certificate"));
      return G_TLS_CONNECTION_BASE_ERROR;
    }

  if (ret == GNUTLS_E_CERTIFICATE_ERROR)
    {
      g_clear_error (&my_error);
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                           _("Unacceptable TLS certificate"));
      return G_TLS_CONNECTION_BASE_ERROR;
    }

  if (ret == GNUTLS_E_FATAL_ALERT_RECEIVED)
    {
      g_clear_error (&my_error);
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Peer sent fatal TLS alert: %s"),
                   gnutls_alert_get_name (gnutls_alert_get (self->session)));
      return G_TLS_CONNECTION_BASE_ERROR;
    }

  if (ret == GNUTLS_E_INAPPROPRIATE_FALLBACK)
    {
      g_clear_error (&my_error);
      g_set_error_literal (error, G_TLS_ERROR,
                           G_TLS_ERROR_INAPPROPRIATE_FALLBACK,
                           _("Protocol version downgrade attack detected"));
      return G_TLS_CONNECTION_BASE_ERROR;
    }

  if (ret == GNUTLS_E_LARGE_PACKET)
    {
      guint mtu = gnutls_dtls_get_data_mtu (self->session);
      g_clear_error (&my_error);
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_MESSAGE_TOO_LARGE,
                   ngettext ("Message is too large for DTLS connection; maximum is %u byte",
                             "Message is too large for DTLS connection; maximum is %u bytes", mtu), mtu);
      return G_TLS_CONNECTION_BASE_ERROR;
    }

  if (ret == GNUTLS_E_TIMEDOUT)
    {
      g_clear_error (&my_error);
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                           _("The operation timed out"));
      return G_TLS_CONNECTION_BASE_ERROR;
    }

  if (error && my_error)
    g_propagate_error (error, my_error);

  if (error && !*error)
    {
      *error = g_error_new (G_TLS_ERROR, G_TLS_ERROR_MISC, "%s: %s",
                            err_prefix, gnutls_strerror (ret));
    }

  return G_TLS_CONNECTION_BASE_ERROR;
}

#define BEGIN_GNUTLS_IO(self, direction, cancellable)          \
  g_tls_connection_base_push_io (g_tls_operations_thread_base_get_connection (G_TLS_OPERATIONS_THREAD_BASE (self)),        \
                                 direction, 0, cancellable);    \
  do {

#define END_GNUTLS_IO(self, direction, ret, status, errmsg, err)      \
    status = end_gnutls_io (self, direction, ret, err, errmsg);       \
  } while (status == G_TLS_CONNECTION_BASE_TRY_AGAIN);

static void
initialize_gnutls_priority (void)
{
  const gchar *priority_override;
  const gchar *error_pos = NULL;
  int ret;

  g_assert (!priority);

  priority_override = g_getenv ("G_TLS_GNUTLS_PRIORITY");
  if (priority_override)
    {
      ret = gnutls_priority_init2 (&priority, priority_override, &error_pos, 0);
      if (ret != GNUTLS_E_SUCCESS)
        g_warning ("Failed to set GnuTLS session priority with beginning at %s: %s", error_pos, gnutls_strerror (ret));
      return;
    }

  ret = gnutls_priority_init2 (&priority, "%COMPAT:-VERS-TLS1.1:-VERS-TLS1.0", &error_pos, GNUTLS_PRIORITY_INIT_DEF_APPEND);
  if (ret != GNUTLS_E_SUCCESS)
    g_warning ("Failed to set GnuTLS session priority with error beginning at %s: %s", error_pos, gnutls_strerror (ret));
}

static void
set_handshake_priority (GTlsOperationsThreadGnutls *self)
{
  int ret;

  g_assert (priority);

  ret = gnutls_priority_set (self->session, priority);
  if (ret != GNUTLS_E_SUCCESS)
    g_warning ("Failed to set GnuTLS session priority: %s", gnutls_strerror (ret));
}

static GTlsConnectionBaseStatus
g_tls_operations_thread_gnutls_handshake (GTlsOperationsThreadBase *base,
                                          gint64                    timeout,
                                          GCancellable             *cancellable,
                                          GError                  **error)
{
  GTlsOperationsThreadGnutls *self = G_TLS_OPERATIONS_THREAD_GNUTLS (base);
  GTlsConnectionBase *tls;
  GTlsConnectionBaseStatus status;
  int ret;

  tls = g_tls_operations_thread_base_get_connection (base);

  if (!g_tls_connection_base_ever_handshaked (tls))
    set_handshake_priority (self);

  if (timeout > 0)
    {
      unsigned int timeout_ms;

      /* Convert from microseconds to milliseconds, but ensure the timeout
       * remains positive. */
      timeout_ms = (timeout + 999) / 1000;

      gnutls_handshake_set_timeout (self->session, timeout_ms);
      gnutls_dtls_set_timeouts (self->session, 1000 /* default */, timeout_ms);
    }

  BEGIN_GNUTLS_IO (self, G_IO_IN | G_IO_OUT, cancellable);
  ret = gnutls_handshake (self->session);
  if (ret == GNUTLS_E_GOT_APPLICATION_DATA)
    {
      guint8 buf[1024];

      /* Got app data while waiting for rehandshake; buffer it and try again */
      ret = gnutls_record_recv (self->session, buf, sizeof (buf));
      if (ret > -1)
        {
          /* FIXME: no longer belongs in GTlsConnectionBase? */
          g_tls_connection_base_handshake_thread_buffer_application_data (tls, buf, ret);
          ret = GNUTLS_E_AGAIN;
        }
    }
  END_GNUTLS_IO (self, G_IO_IN | G_IO_OUT, ret, status,
                 _("Error performing TLS handshake"), error);

  return status;
}

static GTlsConnectionBaseStatus
g_tls_operations_thread_gnutls_read (GTlsOperationsThreadBase  *base,
                                     void                      *buffer,
                                     gsize                      size,
                                     gssize                    *nread,
                                     GCancellable              *cancellable,
                                     GError                   **error)
{
  GTlsOperationsThreadGnutls *self = G_TLS_OPERATIONS_THREAD_GNUTLS (base);
  GTlsConnectionBaseStatus status;
  gssize ret;

  BEGIN_GNUTLS_IO (self, G_IO_IN, cancellable);
  ret = gnutls_record_recv (self->session, buffer, size);
  END_GNUTLS_IO (self, G_IO_IN, ret, status, _("Error reading data from TLS socket"), error);

  *nread = MAX (ret, 0);
  return status;
}

static gsize
input_vectors_from_gnutls_datum_t (GInputVector         *vectors,
                                   guint                 num_vectors,
                                   const gnutls_datum_t *datum)
{
  guint i;
  gsize total = 0;

  /* Copy into the receive vectors. */
  for (i = 0; i < num_vectors && total < datum->size; i++)
    {
      gsize count;
      GInputVector *vec = &vectors[i];

      count = MIN (vec->size, datum->size - total);

      memcpy (vec->buffer, datum->data + total, count);
      total += count;
    }

  g_assert (total <= datum->size);

  return total;
}

static GTlsConnectionBaseStatus
g_tls_operations_thread_gnutls_read_message (GTlsOperationsThreadBase  *base,
                                             GInputVector              *vectors,
                                             guint                      num_vectors,
                                             gssize                    *nread,
                                             GCancellable              *cancellable,
                                             GError                   **error)
{
  GTlsOperationsThreadGnutls *self = G_TLS_OPERATIONS_THREAD_GNUTLS (base);
  GTlsConnectionBaseStatus status;
  gssize ret;
  gnutls_packet_t packet = { 0, };

  BEGIN_GNUTLS_IO (self, G_IO_IN, cancellable);

  /* Receive the entire datagram (zero-copy). */
  ret = gnutls_record_recv_packet (self->session, &packet);

  if (ret > 0)
    {
      gnutls_datum_t data = { 0, };

      gnutls_packet_get (packet, &data, NULL);
      ret = input_vectors_from_gnutls_datum_t (vectors, num_vectors, &data);
      gnutls_packet_deinit (packet);
    }

  END_GNUTLS_IO (self, G_IO_IN, ret, status, _("Error reading data from TLS socket"), error);

  *nread = MAX (ret, 0);
  return status;
}

static GTlsConnectionBaseStatus
g_tls_operations_thread_gnutls_write (GTlsOperationsThreadBase  *base,
                                      const void                *buffer,
                                      gsize                      size,
                                      gssize                    *nwrote,
                                      GCancellable              *cancellable,
                                      GError                   **error)
{
  GTlsOperationsThreadGnutls *self = G_TLS_OPERATIONS_THREAD_GNUTLS (base);
  GTlsConnectionBaseStatus status;
  gssize ret;

  BEGIN_GNUTLS_IO (self, G_IO_OUT, cancellable);
  ret = gnutls_record_send (self->session, buffer, size);
  END_GNUTLS_IO (self, G_IO_OUT, ret, status, _("Error writing data to TLS socket"), error);

  *nwrote = MAX (ret, 0);
  return status;
}

static GTlsConnectionBaseStatus
g_tls_operations_thread_gnutls_write_message (GTlsOperationsThreadBase  *base,
                                              GOutputVector             *vectors,
                                              guint                      num_vectors,
                                              gssize                    *nwrote,
                                              GCancellable              *cancellable,
                                              GError                   **error)
{
  GTlsOperationsThreadGnutls *self = G_TLS_OPERATIONS_THREAD_GNUTLS (base);
  GTlsConnectionBase *connection;
  GTlsConnectionBaseStatus status;
  gssize ret;
  guint i;
  gsize total_message_size;

  connection = g_tls_operations_thread_base_get_connection (base);

  /* Calculate the total message size and check it’s not too big. */
  for (i = 0, total_message_size = 0; i < num_vectors; i++)
    total_message_size += vectors[i].size;

  if (g_tls_connection_base_is_dtls (connection) &&
      gnutls_dtls_get_data_mtu (self->session) < total_message_size)
    {
      char *message;
      guint mtu = gnutls_dtls_get_data_mtu (self->session);

      ret = GNUTLS_E_LARGE_PACKET;
      message = g_strdup_printf("%s %s",
                                ngettext ("Message of size %lu byte is too large for DTLS connection",
                                          "Message of size %lu bytes is too large for DTLS connection", total_message_size),
                                ngettext ("(maximum is %u byte)", "(maximum is %u bytes)", mtu));
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_MESSAGE_TOO_LARGE,
                   message,
                   total_message_size,
                   mtu);
      g_free (message);

      return G_TLS_CONNECTION_BASE_ERROR;
    }

  /* Queue up the data from all the vectors. */
  gnutls_record_cork (self->session);

  for (i = 0; i < num_vectors; i++)
    {
      ret = gnutls_record_send (self->session,
                                vectors[i].buffer, vectors[i].size);

      if (ret < 0 || ret < vectors[i].size)
        {
          /* Uncork to restore state, then bail. The peer will receive a
           * truncated datagram. */
          break;
        }
    }

  BEGIN_GNUTLS_IO (self, G_IO_OUT, cancellable);
  ret = gnutls_record_uncork (self->session, 0  /* flags */);
  END_GNUTLS_IO (self, G_IO_OUT, ret, status, _("Error writing data to TLS socket"), error);

  *nwrote = MAX (ret, 0);
  return status;
}

static GTlsConnectionBaseStatus
g_tls_operations_thread_gnutls_close (GTlsOperationsThreadBase  *base,
                                      GCancellable              *cancellable,
                                      GError                   **error)
{
  GTlsOperationsThreadGnutls *self = G_TLS_OPERATIONS_THREAD_GNUTLS (base);
  GTlsConnectionBaseStatus status;
  int ret;

  BEGIN_GNUTLS_IO (self, G_IO_IN | G_IO_OUT, cancellable);
  ret = gnutls_bye (self->session, GNUTLS_SHUT_WR);
  END_GNUTLS_IO (self, G_IO_IN | G_IO_OUT, ret, status, _("Error performing TLS close: %s"), error);

  return status;
}

static void
g_tls_operations_thread_gnutls_constructed (GObject *object)
{
  GTlsOperationsThreadGnutls *self = G_TLS_OPERATIONS_THREAD_GNUTLS (object);
  GTlsConnectionBase *tls;

  G_OBJECT_CLASS (g_tls_operations_thread_gnutls_parent_class)->constructed (object);

  tls = g_tls_operations_thread_base_get_connection (G_TLS_OPERATIONS_THREAD_BASE (self));
  self->session = g_tls_connection_gnutls_get_session (G_TLS_CONNECTION_GNUTLS (tls));
}

static void
g_tls_operations_thread_gnutls_init (GTlsOperationsThreadGnutls *self)
{
}

static void
g_tls_operations_thread_gnutls_class_init (GTlsOperationsThreadGnutlsClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsOperationsThreadBaseClass *base_class = G_TLS_OPERATIONS_THREAD_BASE_CLASS (klass);

  gobject_class->constructed   = g_tls_operations_thread_gnutls_constructed;

  base_class->handshake_fn     = g_tls_operations_thread_gnutls_handshake;
  base_class->read_fn          = g_tls_operations_thread_gnutls_read;
  base_class->read_message_fn  = g_tls_operations_thread_gnutls_read_message;
  base_class->write_fn         = g_tls_operations_thread_gnutls_write;
  base_class->write_message_fn = g_tls_operations_thread_gnutls_write_message;
  base_class->close_fn         = g_tls_operations_thread_gnutls_close;

  initialize_gnutls_priority ();
}

GTlsOperationsThreadBase *
g_tls_operations_thread_gnutls_new (GTlsConnectionGnutls *tls)
{
  return G_TLS_OPERATIONS_THREAD_BASE (g_object_new (G_TYPE_TLS_OPERATIONS_THREAD_GNUTLS,
                                                     "tls-connection", tls,
                                                     NULL));
}
