/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2009 Red Hat, Inc
 * Copyright 2015, 2016 Collabora, Ltd.
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
#include "glib.h"

#include <errno.h>
#include <stdarg.h>
#include <gnutls/dtls.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "gtlsconnection-gnutls.h"
#include "gtlsbackend-gnutls.h"
#include "gtlscertificate-gnutls.h"
#include "gtlsclientconnection-gnutls.h"

#ifdef G_OS_WIN32
#include <winsock2.h>
#include <winerror.h>

/* It isn’t clear whether MinGW always defines EMSGSIZE. */
#ifndef EMSGSIZE
#define EMSGSIZE WSAEMSGSIZE
#endif
#endif

#include <glib/gi18n-lib.h>
#include <glib/gprintf.h>

static ssize_t g_tls_connection_gnutls_push_func (gnutls_transport_ptr_t  transport_data,
                                                  const void             *buf,
                                                  size_t                  buflen);
static ssize_t g_tls_connection_gnutls_vec_push_func (gnutls_transport_ptr_t  transport_data,
                                                      const giovec_t         *iov,
                                                      int                     iovcnt);
static ssize_t g_tls_connection_gnutls_pull_func (gnutls_transport_ptr_t  transport_data,
                                                  void                   *buf,
                                                  size_t                  buflen);

static int     g_tls_connection_gnutls_pull_timeout_func (gnutls_transport_ptr_t transport_data,
                                                          unsigned int           ms);

static void g_tls_connection_gnutls_initable_iface_init (GInitableIface *iface);

static int verify_certificate_cb (gnutls_session_t session);

static gnutls_priority_t priority;

typedef struct
{
  gnutls_certificate_credentials_t creds;
  gnutls_session_t session;
  gchar *interaction_id;
} GTlsConnectionGnutlsPrivate;

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (GTlsConnectionGnutls, g_tls_connection_gnutls, G_TYPE_TLS_CONNECTION_BASE,
                                  G_ADD_PRIVATE (GTlsConnectionGnutls);
                                  G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                         g_tls_connection_gnutls_initable_iface_init);
                                  );

static gint unique_interaction_id = 0;

static void
g_tls_connection_gnutls_init (GTlsConnectionGnutls *gnutls)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  int unique_id;

  unique_id = g_atomic_int_add (&unique_interaction_id, 1);
  priv->interaction_id = g_strdup_printf ("gtls:%d", unique_id);
}

static void
g_tls_connection_gnutls_set_handshake_priority (GTlsConnectionGnutls *gnutls)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  int ret;

  g_assert (priority);

  ret = gnutls_priority_set (priv->session, priority);
  if (ret != GNUTLS_E_SUCCESS)
    g_warning ("Failed to set GnuTLS session priority: %s", gnutls_strerror (ret));
}

static gboolean
g_tls_connection_gnutls_initable_init (GInitable     *initable,
                                       GCancellable  *cancellable,
                                       GError       **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (initable);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GIOStream *base_io_stream = NULL;
  GDatagramBased *base_socket = NULL;
  gboolean client = G_IS_TLS_CLIENT_CONNECTION (gnutls);
  guint flags = client ? GNUTLS_CLIENT : GNUTLS_SERVER;
  int status;
  int ret;

  g_object_get (gnutls,
                "base-io-stream", &base_io_stream,
                "base-socket", &base_socket,
                NULL);

  /* Ensure we are in TLS mode or DTLS mode. */
  g_return_val_if_fail (!!base_io_stream != !!base_socket, FALSE);

  if (base_socket)
    flags |= GNUTLS_DATAGRAM;

  ret = gnutls_certificate_allocate_credentials (&priv->creds);
  if (ret != GNUTLS_E_SUCCESS)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Could not create TLS connection: %s"),
                   gnutls_strerror (ret));
      g_clear_object (&base_io_stream);
      g_clear_object (&base_socket);
      return FALSE;
    }

  gnutls_init (&priv->session, flags);

  gnutls_session_set_ptr (priv->session, gnutls);
  gnutls_session_set_verify_function (priv->session, verify_certificate_cb);

  status = gnutls_credentials_set (priv->session,
                                   GNUTLS_CRD_CERTIFICATE,
                                   priv->creds);
  if (status != 0)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Could not create TLS connection: %s"),
                   gnutls_strerror (status));
      g_clear_object (&base_io_stream);
      g_clear_object (&base_socket);
      return FALSE;
    }

  gnutls_transport_set_push_function (priv->session,
                                      g_tls_connection_gnutls_push_func);
  gnutls_transport_set_pull_function (priv->session,
                                      g_tls_connection_gnutls_pull_func);
  gnutls_transport_set_pull_timeout_function (priv->session,
                                              g_tls_connection_gnutls_pull_timeout_func);
  gnutls_transport_set_ptr (priv->session, gnutls);

  /* GDatagramBased supports vectored I/O; GPollableOutputStream does not. */
  if (base_socket)
    {
      gnutls_transport_set_vec_push_function (priv->session,
                                              g_tls_connection_gnutls_vec_push_func);
    }

  /* Set reasonable MTU */
  if (flags & GNUTLS_DATAGRAM)
    gnutls_dtls_set_mtu (priv->session, 1400);

  g_clear_object (&base_io_stream);
  g_clear_object (&base_socket);

  return TRUE;
}

static void
g_tls_connection_gnutls_finalize (GObject *object)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (object);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  if (priv->session)
    gnutls_deinit (priv->session);
  if (priv->creds)
    gnutls_certificate_free_credentials (priv->creds);

  g_free (priv->interaction_id);

  G_OBJECT_CLASS (g_tls_connection_gnutls_parent_class)->finalize (object);
}

gnutls_certificate_credentials_t
g_tls_connection_gnutls_get_credentials (GTlsConnectionGnutls *gnutls)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  return priv->creds;
}

gnutls_session_t
g_tls_connection_gnutls_get_session (GTlsConnectionGnutls *gnutls)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  return priv->session;
}

void
g_tls_connection_gnutls_handshake_thread_get_certificate (GTlsConnectionGnutls  *gnutls,
                                                          gnutls_pcert_st      **pcert,
                                                          unsigned int          *pcert_length,
                                                          gnutls_privkey_t      *pkey)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GTlsCertificate *cert;

  cert = g_tls_connection_get_certificate (G_TLS_CONNECTION (gnutls));

  if (cert)
    {
      g_tls_certificate_gnutls_copy (G_TLS_CERTIFICATE_GNUTLS (cert),
                                     priv->interaction_id,
                                     pcert, pcert_length, pkey);
    }
  else
    {
      *pcert = NULL;
      *pcert_length = 0;
      *pkey = NULL;
    }
}

static GTlsConnectionBaseStatus
end_gnutls_io (GTlsConnectionGnutls  *gnutls,
               GIOCondition           direction,
               int                    ret,
               GError               **error,
               const char            *err_prefix)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (gnutls);
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

      if (g_tls_connection_get_require_close_notify (G_TLS_CONNECTION (gnutls)))
        {
          g_clear_error (&my_error);
          g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_EOF,
                               _("TLS connection closed unexpectedly"));
          return G_TLS_CONNECTION_BASE_ERROR;
        }

      return G_TLS_CONNECTION_BASE_OK;
    }

  if (ret == GNUTLS_E_NO_CERTIFICATE_FOUND
#ifdef GNUTLS_E_CERTIFICATE_REQUIRED
           || ret == GNUTLS_E_CERTIFICATE_REQUIRED /* Added in GnuTLS 3.6.7 */
#endif
          )
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
                   gnutls_alert_get_name (gnutls_alert_get (priv->session)));
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
      guint mtu = gnutls_dtls_get_data_mtu (priv->session);
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

#define BEGIN_GNUTLS_IO(gnutls, direction, timeout, cancellable)        \
  g_tls_connection_base_push_io (G_TLS_CONNECTION_BASE (gnutls),        \
                                 direction, timeout, cancellable);      \
  do {

#define END_GNUTLS_IO(gnutls, direction, ret, status, errmsg, err)      \
    status = end_gnutls_io (gnutls, direction, ret, err, errmsg);       \
  } while (status == G_TLS_CONNECTION_BASE_TRY_AGAIN);

static void
set_gnutls_error (GTlsConnectionGnutls *gnutls,
                  GError               *error)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (gnutls);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  /* We set EINTR rather than EAGAIN for G_IO_ERROR_WOULD_BLOCK so
   * that GNUTLS_E_AGAIN only gets returned for gnutls-internal
   * reasons, not for actual socket EAGAINs (and we have access
   * to @error at the higher levels, so we can distinguish them
   * that way later).
   */

  if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
    gnutls_transport_set_errno (priv->session, EINTR);
  else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
    {
      /* Return EAGAIN while handshaking so that GnuTLS handles retries for us
       * internally in its handshaking code. */
      if (g_tls_connection_base_is_dtls (tls) && g_tls_connection_base_is_handshaking (tls))
        gnutls_transport_set_errno (priv->session, EAGAIN);
      else
        gnutls_transport_set_errno (priv->session, EINTR);
    }
  else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT))
    gnutls_transport_set_errno (priv->session, EINTR);
  else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_MESSAGE_TOO_LARGE))
    gnutls_transport_set_errno (priv->session, EMSGSIZE);
  else
    gnutls_transport_set_errno (priv->session, EIO);
}

static ssize_t
g_tls_connection_gnutls_pull_func (gnutls_transport_ptr_t  transport_data,
                                   void                   *buf,
                                   size_t                  buflen)
{
  GTlsConnectionBase *tls = transport_data;
  GTlsConnectionGnutls *gnutls = transport_data;
  ssize_t ret;

  /* If read_error is nonnull when we're called, it means
   * that an error previously occurred, but GnuTLS decided not to
   * propagate it. So it's correct for us to just clear it. (Usually
   * this means it ignored an EAGAIN after a short read, and now
   * we'll return EAGAIN again, which it will obey this time.)
   */
  g_clear_error (g_tls_connection_base_get_read_error (tls));

  if (g_tls_connection_base_is_dtls (tls))
    {
      GInputVector vector = { buf, buflen };
      GInputMessage message = { NULL, &vector, 1, 0, 0, NULL, NULL };

      ret = g_datagram_based_receive_messages (g_tls_connection_base_get_base_socket (tls),
                                               &message, 1, 0,
                                               g_tls_connection_base_is_handshaking (tls) ? 0 : g_tls_connection_base_get_read_timeout (tls),
                                               g_tls_connection_base_get_read_cancellable (tls),
                                               g_tls_connection_base_get_read_error (tls));

      if (ret > 0)
        ret = message.bytes_received;
    }
  else
    {
      ret = g_pollable_stream_read (G_INPUT_STREAM (g_tls_connection_base_get_base_istream (tls)),
                                    buf, buflen,
                                    g_tls_connection_base_get_read_timeout (tls) != 0,
                                    g_tls_connection_base_get_read_cancellable (tls),
                                    g_tls_connection_base_get_read_error (tls));
    }

  if (ret < 0)
    set_gnutls_error (gnutls, *g_tls_connection_base_get_read_error (tls));

  return ret;
}

static ssize_t
g_tls_connection_gnutls_push_func (gnutls_transport_ptr_t  transport_data,
                                   const void             *buf,
                                   size_t                  buflen)
{
  GTlsConnectionBase *tls = transport_data;
  GTlsConnectionGnutls *gnutls = transport_data;
  ssize_t ret;

  /* See comment in pull_func. */
  g_clear_error (g_tls_connection_base_get_write_error (tls));

  if (g_tls_connection_base_is_dtls (tls))
    {
      GOutputVector vector = { buf, buflen };
      GOutputMessage message = { NULL, &vector, 1, 0, NULL, 0 };

      ret = g_datagram_based_send_messages (g_tls_connection_base_get_base_socket (tls),
                                            &message, 1, 0,
                                            g_tls_connection_base_get_write_timeout (tls),
                                            g_tls_connection_base_get_write_cancellable (tls),
                                            g_tls_connection_base_get_write_error (tls));

      if (ret > 0)
        ret = message.bytes_sent;
    }
  else
    {
      ret = g_pollable_stream_write (G_OUTPUT_STREAM (g_tls_connection_base_get_base_ostream (tls)),
                                     buf, buflen,
                                     g_tls_connection_base_get_write_timeout (tls) != 0,
                                     g_tls_connection_base_get_write_cancellable (tls),
                                     g_tls_connection_base_get_write_error (tls));
    }

  if (ret < 0)
    set_gnutls_error (gnutls, *g_tls_connection_base_get_write_error (tls));

  return ret;
}

static ssize_t
g_tls_connection_gnutls_vec_push_func (gnutls_transport_ptr_t  transport_data,
                                       const giovec_t         *iov,
                                       int                     iovcnt)
{
  GTlsConnectionBase *tls = transport_data;
  GTlsConnectionGnutls *gnutls = transport_data;
  ssize_t ret;
  GOutputMessage message = { NULL, };
  GOutputVector *vectors;

  g_assert (g_tls_connection_base_is_dtls (tls));

  /* See comment in pull_func. */
  g_clear_error (g_tls_connection_base_get_write_error (tls));

  /* this entire expression will be evaluated at compile time */
  if (sizeof *iov == sizeof *vectors &&
      sizeof iov->iov_base == sizeof vectors->buffer &&
      G_STRUCT_OFFSET (giovec_t, iov_base) ==
      G_STRUCT_OFFSET (GOutputVector, buffer) &&
      sizeof iov->iov_len == sizeof vectors->size &&
      G_STRUCT_OFFSET (giovec_t, iov_len) ==
      G_STRUCT_OFFSET (GOutputVector, size))
    /* ABI is compatible */
    {
      message.vectors = (GOutputVector *)iov;
      message.num_vectors = iovcnt;
    }
  else
    /* ABI is incompatible */
    {
      gint i;

      message.vectors = g_newa (GOutputVector, iovcnt);
      for (i = 0; i < iovcnt; i++)
        {
          message.vectors[i].buffer = (void *)iov[i].iov_base;
          message.vectors[i].size = iov[i].iov_len;
        }
      message.num_vectors = iovcnt;
    }

  ret = g_datagram_based_send_messages (g_tls_connection_base_get_base_socket (tls),
                                        &message, 1, 0,
                                        g_tls_connection_base_get_write_timeout (tls),
                                        g_tls_connection_base_get_write_cancellable (tls),
                                        g_tls_connection_base_get_write_error (tls));

  if (ret > 0)
    ret = message.bytes_sent;
  else if (ret < 0)
    set_gnutls_error (gnutls, *g_tls_connection_base_get_write_error (tls));

  return ret;
}

static gboolean
read_pollable_cb (GPollableInputStream *istream,
                  gpointer              user_data)
{
  gboolean *read_done = user_data;

  *read_done = TRUE;

  return G_SOURCE_CONTINUE;
}

static gboolean
read_datagram_based_cb (GDatagramBased *datagram_based,
                        GIOCondition    condition,
                        gpointer        user_data)
{
  gboolean *read_done = user_data;

  *read_done = TRUE;

  return G_SOURCE_CONTINUE;
}

static gboolean
read_timeout_cb (gpointer user_data)
{
  gboolean *timed_out = user_data;

  *timed_out = TRUE;

  return G_SOURCE_REMOVE;
}

static int
g_tls_connection_gnutls_pull_timeout_func (gnutls_transport_ptr_t transport_data,
                                           unsigned int           ms)
{
  GTlsConnectionBase *tls = transport_data;

  /* Fast path. */
  if (g_tls_connection_base_base_check (tls, G_IO_IN) ||
      g_cancellable_is_cancelled (g_tls_connection_base_get_read_cancellable (tls)))
    return 1;

  /* If @ms is 0, GnuTLS wants an instant response, so there’s no need to
   * construct and query a #GSource. */
  if (ms > 0)
    {
      GMainContext *ctx = NULL;
      GSource *read_source = NULL, *timeout_source = NULL;
      gboolean read_done = FALSE, timed_out = FALSE;

      ctx = g_main_context_new ();

      /* Create a timeout source. */
      timeout_source = g_timeout_source_new (ms);
      g_source_set_callback (timeout_source, (GSourceFunc)read_timeout_cb,
                             &timed_out, NULL);

      /* Create a read source. We cannot use g_source_set_ready_time() on this
       * to combine it with the @timeout_source, as that could mess with the
       * internals of the #GDatagramBased’s #GSource implementation. */
      if (g_tls_connection_base_is_dtls (tls))
        {
          read_source = g_datagram_based_create_source (g_tls_connection_base_get_base_socket (tls),
                                                        G_IO_IN, NULL);
          g_source_set_callback (read_source, (GSourceFunc)read_datagram_based_cb,
                                 &read_done, NULL);
        }
      else
        {
          read_source = g_pollable_input_stream_create_source (g_tls_connection_base_get_base_istream (tls),
                                                               NULL);
          g_source_set_callback (read_source, (GSourceFunc)read_pollable_cb,
                                 &read_done, NULL);
        }

      g_source_attach (read_source, ctx);
      g_source_attach (timeout_source, ctx);

      while (!read_done && !timed_out)
        g_main_context_iteration (ctx, TRUE);

      g_source_destroy (read_source);
      g_source_destroy (timeout_source);

      g_main_context_unref (ctx);
      g_source_unref (read_source);
      g_source_unref (timeout_source);

      /* If @read_source was dispatched due to cancellation, the resulting error
       * will be handled in g_tls_connection_gnutls_pull_func(). */
      if (g_tls_connection_base_base_check (tls, G_IO_IN) ||
          g_cancellable_is_cancelled (g_tls_connection_base_get_read_cancellable (tls)))
        return 1;
    }

  return 0;
}

static GTlsSafeRenegotiationStatus
g_tls_connection_gnutls_handshake_thread_safe_renegotiation_status (GTlsConnectionBase *tls)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  return gnutls_safe_renegotiation_status (priv->session) ? G_TLS_SAFE_RENEGOTIATION_SUPPORTED_BY_PEER
                                                          : G_TLS_SAFE_RENEGOTIATION_UNSUPPORTED;
}

static GTlsConnectionBaseStatus
g_tls_connection_gnutls_handshake_thread_request_rehandshake (GTlsConnectionBase  *tls,
                                                              gint64               timeout,
                                                              GCancellable        *cancellable,
                                                              GError             **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GTlsConnectionBaseStatus status;
  int ret;

  /* On a client-side connection, gnutls_handshake() itself will start
   * a rehandshake, so we only need to do something special here for
   * server-side connections.
   */
  if (!G_IS_TLS_SERVER_CONNECTION (tls))
    return G_TLS_CONNECTION_BASE_OK;

  BEGIN_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, timeout, cancellable);
  ret = gnutls_rehandshake (priv->session);
  END_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, ret, status, _("Error performing TLS handshake: %s"), error);

  return status;
}

static GTlsCertificate *
g_tls_connection_gnutls_retrieve_peer_certificate (GTlsConnectionBase *tls)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  const gnutls_datum_t *certs;
  GTlsCertificateGnutls *chain;
  unsigned int num_certs;

  if (gnutls_certificate_type_get (priv->session) != GNUTLS_CRT_X509)
    return NULL;

  certs = gnutls_certificate_get_peers (priv->session, &num_certs);
  if (!certs || !num_certs)
    return NULL;

  chain = g_tls_certificate_gnutls_build_chain (certs, num_certs, GNUTLS_X509_FMT_DER);
  if (!chain)
    return NULL;

  return G_TLS_CERTIFICATE (chain);
}

static int
verify_certificate_cb (gnutls_session_t session)
{
  GTlsConnectionBase *tls = gnutls_session_get_ptr (session);

  /* Return 0 for the handshake to continue, non-zero to terminate.
   * Complete opposite of what OpenSSL does. */
  return !g_tls_connection_base_handshake_thread_verify_certificate (tls);
}

static void
g_tls_connection_gnutls_prepare_handshake (GTlsConnectionBase  *tls,
                                           gchar              **advertised_protocols)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  if (advertised_protocols)
    {
      gnutls_datum_t *protocols;
      int n_protos, i;

      n_protos = g_strv_length (advertised_protocols);
      protocols = g_new (gnutls_datum_t, n_protos);
      for (i = 0; advertised_protocols[i]; i++)
        {
          protocols[i].size = strlen (advertised_protocols[i]);
          protocols[i].data = (guchar *)advertised_protocols[i];
        }
      gnutls_alpn_set_protocols (priv->session, protocols, n_protos, 0);
      g_free (protocols);
    }
}

static GTlsConnectionBaseStatus
g_tls_connection_gnutls_handshake_thread_handshake (GTlsConnectionBase  *tls,
                                                    gint64               timeout,
                                                    GCancellable        *cancellable,
                                                    GError             **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GTlsConnectionBaseStatus status;
  int ret;

  if (!g_tls_connection_base_ever_handshaked (tls))
    g_tls_connection_gnutls_set_handshake_priority (gnutls);

  if (timeout > 0)
    {
      unsigned int timeout_ms;

      /* Convert from microseconds to milliseconds, but ensure the timeout
       * remains positive. */
      timeout_ms = (timeout + 999) / 1000;

      gnutls_handshake_set_timeout (priv->session, timeout_ms);
      gnutls_dtls_set_timeouts (priv->session, 1000 /* default */, timeout_ms);
    }

  BEGIN_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, timeout, cancellable);
  ret = gnutls_handshake (priv->session);
  if (ret == GNUTLS_E_GOT_APPLICATION_DATA)
    {
      guint8 buf[1024];

      /* Got app data while waiting for rehandshake; buffer it and try again */
      ret = gnutls_record_recv (priv->session, buf, sizeof (buf));
      if (ret > -1)
        {
          g_tls_connection_base_handshake_thread_buffer_application_data (tls, buf, ret);
          ret = GNUTLS_E_AGAIN;
        }
    }
  END_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, ret, status,
                 _("Error performing TLS handshake"), error);

  return status;
}

static void
g_tls_connection_gnutls_complete_handshake (GTlsConnectionBase  *tls,
                                            gboolean             handshake_succeeded,
                                            gchar              **negotiated_protocol,
                                            GError             **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gnutls_datum_t protocol;

  if (handshake_succeeded &&
      gnutls_alpn_get_selected_protocol (priv->session, &protocol) == 0 &&
      protocol.size > 0)
    {
      g_assert (!*negotiated_protocol);
      *negotiated_protocol = g_strndup ((gchar *)protocol.data, protocol.size);
    }
}

static gboolean
g_tls_connection_gnutls_is_session_resumed (GTlsConnectionBase *tls)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  return gnutls_session_is_resumed (priv->session);
}

static GTlsConnectionBaseStatus
g_tls_connection_gnutls_read (GTlsConnectionBase  *tls,
                              void                *buffer,
                              gsize                count,
                              gint64               timeout,
                              gssize              *nread,
                              GCancellable        *cancellable,
                              GError             **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GTlsConnectionBaseStatus status;
  gssize ret;

  BEGIN_GNUTLS_IO (gnutls, G_IO_IN, timeout, cancellable);
  ret = gnutls_record_recv (priv->session, buffer, count);
  END_GNUTLS_IO (gnutls, G_IO_IN, ret, status, _("Error reading data from TLS socket"), error);

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
g_tls_connection_gnutls_read_message (GTlsConnectionBase  *tls,
                                      GInputVector        *vectors,
                                      guint                num_vectors,
                                      gint64               timeout,
                                      gssize              *nread,
                                      GCancellable        *cancellable,
                                      GError             **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GTlsConnectionBaseStatus status;
  gssize ret;
  gnutls_packet_t packet = { 0, };

  BEGIN_GNUTLS_IO (gnutls, G_IO_IN, timeout, cancellable);

  /* Receive the entire datagram (zero-copy). */
  ret = gnutls_record_recv_packet (priv->session, &packet);

  if (ret > 0)
    {
      gnutls_datum_t data = { 0, };

      gnutls_packet_get (packet, &data, NULL);
      ret = input_vectors_from_gnutls_datum_t (vectors, num_vectors, &data);
      gnutls_packet_deinit (packet);
    }

  END_GNUTLS_IO (gnutls, G_IO_IN, ret, status, _("Error reading data from TLS socket"), error);

  *nread = MAX (ret, 0);
  return status;
}

static GTlsConnectionBaseStatus
g_tls_connection_gnutls_write (GTlsConnectionBase  *tls,
                               const void          *buffer,
                               gsize                count,
                               gint64               timeout,
                               gssize              *nwrote,
                               GCancellable        *cancellable,
                               GError             **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GTlsConnectionBaseStatus status;
  gssize ret;

  BEGIN_GNUTLS_IO (gnutls, G_IO_OUT, timeout, cancellable);
  ret = gnutls_record_send (priv->session, buffer, count);
  END_GNUTLS_IO (gnutls, G_IO_OUT, ret, status, _("Error writing data to TLS socket"), error);

  *nwrote = MAX (ret, 0);
  return status;
}

static GTlsConnectionBaseStatus
g_tls_connection_gnutls_write_message (GTlsConnectionBase  *tls,
                                       GOutputVector       *vectors,
                                       guint                num_vectors,
                                       gint64               timeout,
                                       gssize              *nwrote,
                                       GCancellable        *cancellable,
                                       GError             **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GTlsConnectionBaseStatus status;
  gssize ret;
  guint i;
  gsize total_message_size;

  /* Calculate the total message size and check it’s not too big. */
  for (i = 0, total_message_size = 0; i < num_vectors; i++)
    total_message_size += vectors[i].size;

  if (g_tls_connection_base_is_dtls (tls) &&
      gnutls_dtls_get_data_mtu (priv->session) < total_message_size)
    {
      char *message;
      guint mtu = gnutls_dtls_get_data_mtu (priv->session);

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
  gnutls_record_cork (priv->session);

  for (i = 0; i < num_vectors; i++)
    {
      ret = gnutls_record_send (priv->session,
                                vectors[i].buffer, vectors[i].size);

      if (ret < 0 || ret < vectors[i].size)
        {
          /* Uncork to restore state, then bail. The peer will receive a
           * truncated datagram. */
          break;
        }
    }

  BEGIN_GNUTLS_IO (gnutls, G_IO_OUT, timeout, cancellable);
  ret = gnutls_record_uncork (priv->session, 0  /* flags */);
  END_GNUTLS_IO (gnutls, G_IO_OUT, ret, status, _("Error writing data to TLS socket"), error);

  *nwrote = MAX (ret, 0);
  return status;
}

static GTlsConnectionBaseStatus
g_tls_connection_gnutls_close (GTlsConnectionBase  *tls,
                               gint64               timeout,
                               GCancellable        *cancellable,
                               GError             **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GTlsConnectionBaseStatus status;
  int ret;

  BEGIN_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, timeout, cancellable);
  ret = gnutls_bye (priv->session, GNUTLS_SHUT_WR);
  END_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, ret, status, _("Error performing TLS close: %s"), error);

  return status;
}

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
g_tls_connection_gnutls_class_init (GTlsConnectionGnutlsClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsConnectionBaseClass *base_class = G_TLS_CONNECTION_BASE_CLASS (klass);

  gobject_class->finalize                                = g_tls_connection_gnutls_finalize;

  base_class->prepare_handshake                          = g_tls_connection_gnutls_prepare_handshake;
  base_class->handshake_thread_safe_renegotiation_status = g_tls_connection_gnutls_handshake_thread_safe_renegotiation_status;
  base_class->handshake_thread_request_rehandshake       = g_tls_connection_gnutls_handshake_thread_request_rehandshake;
  base_class->handshake_thread_handshake                 = g_tls_connection_gnutls_handshake_thread_handshake;
  base_class->retrieve_peer_certificate                  = g_tls_connection_gnutls_retrieve_peer_certificate;
  base_class->complete_handshake                         = g_tls_connection_gnutls_complete_handshake;
  base_class->is_session_resumed                         = g_tls_connection_gnutls_is_session_resumed;
  base_class->read_fn                                    = g_tls_connection_gnutls_read;
  base_class->read_message_fn                            = g_tls_connection_gnutls_read_message;
  base_class->write_fn                                   = g_tls_connection_gnutls_write;
  base_class->write_message_fn                           = g_tls_connection_gnutls_write_message;
  base_class->close_fn                                   = g_tls_connection_gnutls_close;

  initialize_gnutls_priority ();
}

static void
g_tls_connection_gnutls_initable_iface_init (GInitableIface *iface)
{
  iface->init = g_tls_connection_gnutls_initable_init;
}
