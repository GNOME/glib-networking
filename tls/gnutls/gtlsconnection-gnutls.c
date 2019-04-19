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

static void g_tls_connection_gnutls_init_priorities (void);

static int verify_certificate_cb (gnutls_session_t session);

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
                                  g_tls_connection_gnutls_init_priorities ();
                                  );

static gint unique_interaction_id = 0;

static void
g_tls_connection_gnutls_init (GTlsConnectionGnutls *gnutls)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gint unique_id;

  gnutls_certificate_allocate_credentials (&priv->creds);

  g_mutex_init (&priv->verify_certificate_mutex);
  g_cond_init (&priv->verify_certificate_condition);

  unique_id = g_atomic_int_add (&unique_interaction_id, 1);
  priv->interaction_id = g_strdup_printf ("gtls:%d", unique_id);
}

/* First field is "fallback", second is "allow unsafe rehandshaking" */
static gnutls_priority_t priorities[2][2];

/* TODO: Get rid of this in favor of gnutls_set_default_priority_append()
 * when upgrading to GnuTLS 3.6.3.
 */
#define DEFAULT_BASE_PRIORITY "NORMAL:%COMPAT"

static void
g_tls_connection_gnutls_init_priorities (void)
{
  const gchar *base_priority;
  gchar *fallback_priority, *unsafe_rehandshake_priority, *fallback_unsafe_rehandshake_priority;
  const guint *protos;
  int ret, i, nprotos, fallback_proto;

  base_priority = g_getenv ("G_TLS_GNUTLS_PRIORITY");
  if (!base_priority)
    base_priority = DEFAULT_BASE_PRIORITY;
  ret = gnutls_priority_init (&priorities[FALSE][FALSE], base_priority, NULL);
  if (ret == GNUTLS_E_INVALID_REQUEST)
    {
      g_warning ("G_TLS_GNUTLS_PRIORITY is invalid; ignoring!");
      base_priority = DEFAULT_BASE_PRIORITY;
      ret = gnutls_priority_init (&priorities[FALSE][FALSE], base_priority, NULL);
      g_warn_if_fail (ret == 0);
    }

  unsafe_rehandshake_priority = g_strdup_printf ("%s:%%UNSAFE_RENEGOTIATION", base_priority);
  ret = gnutls_priority_init (&priorities[FALSE][TRUE], unsafe_rehandshake_priority, NULL);
  g_warn_if_fail (ret == 0);
  g_free (unsafe_rehandshake_priority);

  /* Figure out the lowest SSl/TLS version supported by base_priority */
  nprotos = gnutls_priority_protocol_list (priorities[FALSE][FALSE], &protos);
  fallback_proto = G_MAXUINT;
  for (i = 0; i < nprotos; i++)
    {
      if (protos[i] < fallback_proto)
        fallback_proto = protos[i];
    }
  if (fallback_proto == G_MAXUINT)
    {
      g_warning ("All GNUTLS protocol versions disabled?");
      fallback_priority = g_strdup (base_priority);
    }
  else
    {
      /* %COMPAT is intentionally duplicated here, to ensure it gets added for
       * the fallback even if the default priority has been changed. */
      fallback_priority = g_strdup_printf ("%s:%%COMPAT:!VERS-TLS-ALL:+VERS-%s:%%FALLBACK_SCSV",
                                           DEFAULT_BASE_PRIORITY,
                                           gnutls_protocol_get_name (fallback_proto));
    }
  fallback_unsafe_rehandshake_priority = g_strdup_printf ("%s:%%UNSAFE_RENEGOTIATION",
                                                          fallback_priority);

  ret = gnutls_priority_init (&priorities[TRUE][FALSE], fallback_priority, NULL);
  g_warn_if_fail (ret == 0);
  ret = gnutls_priority_init (&priorities[TRUE][TRUE], fallback_unsafe_rehandshake_priority, NULL);
  g_warn_if_fail (ret == 0);
  g_free (fallback_priority);
  g_free (fallback_unsafe_rehandshake_priority);
}

static void
g_tls_connection_gnutls_set_handshake_priority (GTlsConnectionGnutls *gnutls)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gboolean fallback, unsafe_rehandshake;

  if (G_IS_TLS_CLIENT_CONNECTION (gnutls))
    {
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
      fallback = g_tls_client_connection_get_use_ssl3 (G_TLS_CLIENT_CONNECTION (gnutls));
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
    }
  else
    fallback = FALSE;
  unsafe_rehandshake = g_tls_connection_get_rehandshake_mode (G_TLS_CONNECTION (gnutls)) == G_TLS_REHANDSHAKE_UNSAFELY;
  gnutls_priority_set (priv->session,
                       priorities[fallback][unsafe_rehandshake]);
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

// FIXME: Avoid g_object_get?
  g_object_get (gnutls,
                "base-io-stream", &base_io_stream,
                "base-socket", &base_socket,
                NULL);

  /* Ensure we are in TLS mode or DTLS mode. */
  g_return_val_if_fail (!!base_io_stream != !!base_socket, FALSE);

  if (base_socket)
    flags |= GNUTLS_DATAGRAM;

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
  if (base_socket != NULL)
    {
      gnutls_transport_set_vec_push_function (priv->session,
                                              g_tls_connection_gnutls_vec_push_func);
    }

  /* Set reasonable MTU */
  if (flags & GNUTLS_DATAGRAM)
    gnutls_dtls_set_mtu (priv->session, 1400);

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
g_tls_connection_gnutls_get_certificate (GTlsConnectionGnutls  *gnutls,
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

// FIXME: Right place?
  G_TLS_CONNECTION_GNUTLS_GET_CLASS (gnutls)->failed (gnutls);

  handshaking = g_tls_connection_base_is_handshaking (tls);
  ever_handshaked = g_tls_connection_base_ever_handshaked (tls);

  if (handshaking && !ever_handshaked)
    {
      if (status == GNUTLS_E_UNEXPECTED_PACKET_LENGTH ||
          status == GNUTLS_E_DECRYPTION_FAILED ||
          status == GNUTLS_E_UNSUPPORTED_VERSION_PACKET)
        {
          g_clear_error (&my_error);
          g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_NOT_TLS,
                               _("Peer failed to perform TLS handshake"));
          return G_TLS_CONNECTION_BASE_ERROR;
        }
    }

  if (ret == GNUTLS_E_REHANDSHAKE)
    {
      if (g_tls_connection_get_rehandshake_mode (G_TLS_CONNECTION (gnutls)) == G_TLS_REHANDSHAKE_NEVER)
        {
          g_clear_error (&my_error);
          g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                               _("Peer requested illegal TLS rehandshake"));
          return G_TLS_CONNECTION_BASE_ERROR;
        }

      return G_TLS_CONNECTION_BASE_REHANDSHAKE;
    }

  if (ret == GNUTLS_E_PREMATURE_TERMINATION)
    {
      if (handshaking && !ever_handshaked)
        {
          g_clear_error (&my_error);
          g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_NOT_TLS,
                               _("Peer failed to perform TLS handshake"));
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
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
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
#if GLIB_CHECK_VERSION(2, 60, 0)
                           G_TLS_ERROR_INAPPROPRIATE_FALLBACK,
#else
                           G_TLS_ERROR_MISC,
#endif
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

  g_propagate_error (error, my_error);
  if (error && !*error)
    {
      *error = g_error_new (G_TLS_ERROR, G_TLS_ERROR_MISC, "%s: %s",
                            err_prefix, gnutls_strerror (status));
    }
  return G_TLS_CONNECTION_BASE_ERROR;
}

#define BEGIN_GNUTLS_IO(gnutls, direction, timeout, cancellable)        \
  g_tls_connection_base_push_io (G_TLS_CONNECTION_BASE (gnutls),        \
                                 direction, timeout, cancellable);      \
  do {

#define END_GNUTLS_IO(gnutls, direction, ret, status, errmsg, err)	\
    status = end_gnutls_io (gnutls, direction, ret, err, errmsg, gnutls_strerror (ret));	\
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
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
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
  GTlsConnectionbase *tls = transport_data;
  GTlsConnectionGnutls *gnutls = transport_data;
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
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
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
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
  GTlsConnectionGnutls *gnutls = transport_data;
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

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

static GTlsConnectionBaseStatus
g_tls_connection_gnutls_request_rehandshake (GTlsConnectionBase  *tls,
                                             gint64               timeout,
                                             GCancellable        *cancellable,
                                             GError             **error)
{
  GTlsConnectionGnutls *gnutls;
  GTlsConnectionBaseStatus status;
  int ret;

  /* On a client-side connection, gnutls_handshake() itself will start
   * a rehandshake, so we only need to do something special here for
   * server-side connections.
   */
  if (!G_IS_TLS_SERVER_CONNECTION (tls))
    return G_TLS_CONNECTION_BASE_OK;

  gnutls = G_TLS_CONNECTION_GNUTLS (tls);

  BEGIN_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, timeout, cancellable);
  ret = gnutls_rehandshake (gnutls->priv->session);
  END_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, ret, status, _("Error performing TLS handshake: %s"), error);

  return status;
}

static GTlsCertificate *
get_peer_certificate_from_session (GTlsConnectionGnutls *gnutls)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  const gnutls_datum_t *certs;
  GTlsCertificateGnutls *chain;
  unsigned int num_certs;

  certs = gnutls_certificate_get_peers (priv->session, &num_certs);
  if (!certs || !num_certs)
    return NULL;

  chain = g_tls_certificate_gnutls_build_chain (certs, num_certs, GNUTLS_X509_FMT_DER);
  if (!chain)
    return NULL;

  return G_TLS_CERTIFICATE (chain);
}

//MOVE
#if 0
static GTlsCertificateFlags
verify_peer_certificate (GTlsConnectionGnutls *gnutls,
                         GTlsCertificate      *peer_certificate)
{
  GTlsConnection *conn = G_TLS_CONNECTION (gnutls);
  GSocketConnectable *peer_identity;
  GTlsDatabase *database;
  GTlsCertificateFlags errors;
  gboolean is_client;

  is_client = G_IS_TLS_CLIENT_CONNECTION (gnutls);

  if (!is_client)
    peer_identity = NULL;
  else if (!g_tls_connection_gnutls_is_dtls (gnutls))
    peer_identity = g_tls_client_connection_get_server_identity (G_TLS_CLIENT_CONNECTION (gnutls));
  else
    peer_identity = g_dtls_client_connection_get_server_identity (G_DTLS_CLIENT_CONNECTION (gnutls));

  errors = 0;

  database = g_tls_connection_get_database (conn);
  if (database == NULL)
    {
      errors |= G_TLS_CERTIFICATE_UNKNOWN_CA;
      errors |= g_tls_certificate_verify (peer_certificate, peer_identity, NULL);
    }
  else
    {
      GError *error = NULL;

      errors |= g_tls_database_verify_chain (database, peer_certificate,
                                             is_client ?
                                             G_TLS_DATABASE_PURPOSE_AUTHENTICATE_SERVER :
                                             G_TLS_DATABASE_PURPOSE_AUTHENTICATE_CLIENT,
                                             peer_identity,
                                             g_tls_connection_get_interaction (conn),
                                             G_TLS_DATABASE_VERIFY_NONE,
                                             NULL, &error);
      if (error)
        {
          g_warning ("failure verifying certificate chain: %s",
                     error->message);
          g_assert (errors != 0);
          g_clear_error (&error);
        }
    }

  return errors;
}

static void
update_peer_certificate_and_compute_errors (GTlsConnectionGnutls *gnutls)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GTlsCertificate *peer_certificate = NULL;
  GTlsCertificateFlags peer_certificate_errors = 0;

  /* This function must be called from the handshake context thread
   * (probably the main thread, NOT the handshake thread) because
   * g_tls_connection_base_set_peer_certificate() emits notifies
   * that are application-visible.
   *
   * verify_certificate_mutex should be locked.
   */
  g_assert (priv->handshake_context);
  g_assert (g_main_context_is_owner (priv->handshake_context));

  if (gnutls_certificate_type_get (priv->session) == GNUTLS_CRT_X509)
    {
      peer_certificate = get_peer_certificate_from_session (gnutls);
      if (peer_certificate)
        peer_certificate_errors = verify_peer_certificate (gnutls, peer_certificate);
    }

  g_tls_connection_base_set_peer_certificate (G_TLS_CONNECTION_BASE (gnutls),
                                              peer_certificate, peer_certificate_errors);
}

static gboolean
accept_or_reject_peer_certificate (gpointer user_data)
{
  GTlsConnectionGnutls *gnutls = user_data;
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gboolean accepted = FALSE;

  g_assert (g_main_context_is_owner (priv->handshake_context));

  g_mutex_lock (&priv->verify_certificate_mutex);

  update_peer_certificate_and_compute_errors (gnutls);

  if (G_IS_TLS_CLIENT_CONNECTION (gnutls) && priv->peer_certificate != NULL)
    {
      GTlsCertificateFlags validation_flags;

      if (!g_tls_connection_gnutls_is_dtls (gnutls))
        validation_flags =
          g_tls_client_connection_get_validation_flags (G_TLS_CLIENT_CONNECTION (gnutls));
      else
        validation_flags =
          g_dtls_client_connection_get_validation_flags (G_DTLS_CLIENT_CONNECTION (gnutls));

      if ((priv->peer_certificate_errors & validation_flags) == 0)
        accepted = TRUE;
    }

  if (!accepted)
    {
      g_main_context_pop_thread_default (priv->handshake_context);
      accepted = g_tls_connection_emit_accept_certificate (G_TLS_CONNECTION (gnutls),
                                                           priv->peer_certificate,
                                                           priv->peer_certificate_errors);
      g_main_context_push_thread_default (priv->handshake_context);
    }

  priv->peer_certificate_accepted = accepted;

  /* This has to be the very last statement before signaling the
   * condition variable because otherwise the code could spuriously
   * wakeup and continue before we are done here.
   */
  priv->peer_certificate_examined = TRUE;

  g_cond_signal (&priv->verify_certificate_condition);
  g_mutex_unlock (&priv->verify_certificate_mutex);

  g_object_notify (G_OBJECT (gnutls), "peer-certificate");
  g_object_notify (G_OBJECT (gnutls), "peer-certificate-errors");

  return G_SOURCE_REMOVE;
}

static int
verify_certificate_cb (gnutls_session_t session)
{
  GTlsConnectionGnutls *gnutls = gnutls_session_get_ptr (session);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gboolean accepted;

  g_mutex_lock (&priv->verify_certificate_mutex);
  priv->peer_certificate_examined = FALSE;
  priv->peer_certificate_accepted = FALSE;
  g_mutex_unlock (&priv->verify_certificate_mutex);

  /* Invoke the callback on the handshake context's thread. This is
   * necessary because we need to ensure the accept-certificate signal
   * is emitted on the original thread.
   */
  g_assert (priv->handshake_context);
  g_main_context_invoke (priv->handshake_context, accept_or_reject_peer_certificate, gnutls);

  /* We'll block the handshake thread until the original thread has
   * decided whether to accept the certificate.
   */
  g_mutex_lock (&priv->verify_certificate_mutex);
  while (!priv->peer_certificate_examined)
    g_cond_wait (&priv->verify_certificate_condition, &priv->verify_certificate_mutex);
  accepted = priv->peer_certificate_accepted;
  g_mutex_unlock (&priv->verify_certificate_mutex);

  /* Return 0 for the handshake to continue, non-zero to terminate. */
  return !accepted;
}
#endif

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
          protocols[i].data = g_memdup (advertised_protocols[i], protocols[i].size);
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
  GTlsConnectionBaseStatus status;
  int ret;

  if (!priv->ever_handshaked)
    g_tls_connection_gnutls_set_handshake_priority (gnutls);

  /* Adjust the timeout for the next operation in the sequence. */
  if (timeout > 0)
    {
      unsigned int timeout_ms;

      timeout -= (g_get_monotonic_time () - start_time);
      if (timeout <= 0)
        timeout = 1;

      /* Convert from microseconds to milliseconds, but ensure the timeout
       * remains positive. */
      timeout_ms = (timeout + 999) / 1000;

      gnutls_handshake_set_timeout (priv->session, timeout_ms);
      gnutls_dtls_set_timeouts (priv->session, 1000 /* default */,
                                timeout_ms);
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
          g_tls_connection_base_buffer_application_data (tls, buf, ret);
          ret = GNUTLS_E_AGAIN;
        }
    }
  END_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, ret, status,
                 _("Error performing TLS handshake"), error);

  return status;
}

static void
g_tls_connection_gnutls_complete_handshake (GTlsConnectionBase  *tls,
                                            gchar              **negotiated_protocol,
                                            GError             **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  g_clear_pointer (&priv->handshake_context, g_main_context_unref);

  if (gnutls_session_is_resumed (priv->session))
    {
      /* Because this session was resumed, we skipped certificate
       * verification on this handshake, so we missed our earlier
       * chance to set peer_certificate and peer_certificate_errors.
       * Do so here instead.
       *
       * The certificate has already been accepted, so we don't do
       * anything with the result here.
       */
      g_mutex_lock (&priv->verify_certificate_mutex);
      update_peer_certificate_and_compute_errors (gnutls);
      priv->peer_certificate_examined = TRUE;
      priv->peer_certificate_accepted = TRUE;
      g_mutex_unlock (&priv->verify_certificate_mutex);
    }

  if (g_task_propagate_boolean (task, error) &&
      priv->peer_certificate && !priv->peer_certificate_accepted)
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                           _("Unacceptable TLS certificate"));
    }

// FIXME: this needs to remain in GnuTLS class
  if (!*error && priv->advertised_protocols)
    update_negotiated_protocol (gnutls);

  if (*error && priv->started_handshake)
    priv->handshake_error = g_error_copy (*error);

  return (*error == NULL);
}

static gboolean
g_tls_connection_gnutls_handshake (GTlsConnection   *conn,
                                   GCancellable     *cancellable,
                                   GError          **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (conn);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GTask *task;
  gboolean success;
  gint64 *timeout = NULL;
  GError *my_error = NULL;

  g_assert (priv->handshake_context == NULL);
  priv->handshake_context = g_main_context_new ();

  g_main_context_push_thread_default (priv->handshake_context);

  begin_handshake (gnutls);

  task = g_task_new (conn, cancellable, sync_handshake_thread_completed, NULL);
  g_task_set_source_tag (task, g_tls_connection_gnutls_handshake);
  g_task_set_return_on_cancel (task, TRUE);

  timeout = g_new0 (gint64, 1);
  *timeout = -1;  /* blocking */
  g_task_set_task_data (task, timeout, g_free);

  g_task_run_in_thread (task, handshake_thread);
  crank_sync_handshake_context (gnutls, cancellable);

  success = finish_handshake (gnutls, task, &my_error);

  g_main_context_pop_thread_default (priv->handshake_context);
  g_clear_pointer (&priv->handshake_context, g_main_context_unref);
  g_object_unref (task);

  yield_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_HANDSHAKE);

  if (my_error)
    g_propagate_error (error, my_error);
  return success;
}

static gboolean
g_tls_connection_gnutls_dtls_handshake (GDtlsConnection       *conn,
                                        GCancellable          *cancellable,
                                        GError               **error)
{
  return g_tls_connection_gnutls_handshake (G_TLS_CONNECTION (conn),
                                            cancellable, error);
}

/* In the async version we use two GTasks; one to run handshake_thread() and
 * then call handshake_thread_completed(), and a second to call the caller's
 * original callback after we call finish_handshake().
 */

static void
handshake_thread_completed (GObject      *object,
                            GAsyncResult *result,
                            gpointer      user_data)
{
  GTask *caller_task = user_data;
  GTlsConnectionGnutls *gnutls = g_task_get_source_object (caller_task);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GError *error = NULL;
  gboolean need_finish_handshake, success;

  g_mutex_lock (&priv->op_mutex);
  if (priv->need_finish_handshake)
    {
      need_finish_handshake = TRUE;
      priv->need_finish_handshake = FALSE;
    }
  else
    need_finish_handshake = FALSE;
  g_mutex_unlock (&priv->op_mutex);

  if (need_finish_handshake)
    {
      success = finish_handshake (gnutls, G_TASK (result), &error);
      if (success)
        g_task_return_boolean (caller_task, TRUE);
      else
        g_task_return_error (caller_task, error);
    }
  else if (priv->handshake_error)
    g_task_return_error (caller_task, g_error_copy (priv->handshake_error));
  else
    g_task_return_boolean (caller_task, TRUE);

  g_clear_pointer (&priv->handshake_context, g_main_context_unref);
  g_object_unref (caller_task);
}

static void
async_handshake_thread (GTask        *task,
                        gpointer      object,
                        gpointer      task_data,
                        GCancellable *cancellable)
{
  GTlsConnectionGnutls *gnutls = object;
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  handshake_thread (task, object, task_data, cancellable);

  g_mutex_lock (&priv->op_mutex);
  priv->need_finish_handshake = TRUE;
  /* yield_op will clear handshaking too, but we don't want the
   * connection to be briefly "handshaking && need_finish_handshake"
   * after we unlock the mutex.
   */
  priv->handshaking = FALSE;
  g_mutex_unlock (&priv->op_mutex);

  yield_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_HANDSHAKE);
}

static void
g_tls_connection_gnutls_handshake_async (GTlsConnection       *conn,
                                         int                   io_priority,
                                         GCancellable         *cancellable,
                                         GAsyncReadyCallback   callback,
                                         gpointer              user_data)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (G_TLS_CONNECTION_GNUTLS (conn));
  GTask *thread_task, *caller_task;
  gint64 *timeout = NULL;

  g_assert (!priv->handshake_context);
  priv->handshake_context = g_main_context_ref_thread_default ();

  caller_task = g_task_new (conn, cancellable, callback, user_data);
  g_task_set_source_tag (caller_task, g_tls_connection_gnutls_handshake_async);
  g_task_set_priority (caller_task, io_priority);

  begin_handshake (G_TLS_CONNECTION_GNUTLS (conn));

  thread_task = g_task_new (conn, cancellable,
                            handshake_thread_completed, caller_task);
  g_task_set_source_tag (thread_task, g_tls_connection_gnutls_handshake_async);
  g_task_set_priority (thread_task, io_priority);

  timeout = g_new0 (gint64, 1);
  *timeout = -1;  /* blocking */
  g_task_set_task_data (thread_task, timeout, g_free);

  g_task_run_in_thread (thread_task, async_handshake_thread);
  g_object_unref (thread_task);
}

static gboolean
g_tls_connection_gnutls_handshake_finish (GTlsConnection       *conn,
                                          GAsyncResult         *result,
                                          GError              **error)
{
  g_return_val_if_fail (g_task_is_valid (result, conn), FALSE);

  return g_task_propagate_boolean (G_TASK (result), error);
}

static void
g_tls_connection_gnutls_dtls_handshake_async (GDtlsConnection       *conn,
                                              int                    io_priority,
                                              GCancellable          *cancellable,
                                              GAsyncReadyCallback    callback,
                                              gpointer               user_data)
{
  g_tls_connection_gnutls_handshake_async (G_TLS_CONNECTION (conn), io_priority,
                                           cancellable, callback, user_data);
}

static gboolean
g_tls_connection_gnutls_dtls_handshake_finish (GDtlsConnection       *conn,
                                               GAsyncResult          *result,
                                               GError               **error)
{
  return g_tls_connection_gnutls_handshake_finish (G_TLS_CONNECTION (conn),
                                                   result, error);
}

static gboolean
do_implicit_handshake (GTlsConnectionGnutls  *gnutls,
                       gint64                 timeout,
                       GCancellable          *cancellable,
                       GError               **error)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gint64 *thread_timeout = NULL;

  /* We have op_mutex */

  g_assert (priv->handshake_context == NULL);
  if (timeout != 0)
    {
      priv->handshake_context = g_main_context_new ();
      g_main_context_push_thread_default (priv->handshake_context);
    }
  else
    {
      priv->handshake_context = g_main_context_ref_thread_default ();
    }

  g_assert (priv->implicit_handshake == NULL);
  priv->implicit_handshake = g_task_new (gnutls, cancellable,
                                         timeout ? sync_handshake_thread_completed : NULL,
                                         NULL);
  g_task_set_source_tag (priv->implicit_handshake,
                         do_implicit_handshake);

  thread_timeout = g_new0 (gint64, 1);
  g_task_set_task_data (priv->implicit_handshake,
                        thread_timeout, g_free);

  begin_handshake (gnutls);

  if (timeout != 0)
    {
      GError *my_error = NULL;
      gboolean success;

      /* In the blocking case, run the handshake operation synchronously in
       * another thread, and delegate handling the timeout to that thread; it
       * should return G_IO_ERROR_TIMED_OUT iff (timeout > 0) and the operation
       * times out. If (timeout < 0) it should block indefinitely until the
       * operation is complete or errors. */
      *thread_timeout = timeout;

      g_mutex_unlock (&priv->op_mutex);

      g_task_set_return_on_cancel (priv->implicit_handshake, TRUE);
      g_task_run_in_thread (priv->implicit_handshake, handshake_thread);

      crank_sync_handshake_context (gnutls, cancellable);

      success = finish_handshake (gnutls,
                                  priv->implicit_handshake,
                                  &my_error);

      g_main_context_pop_thread_default (priv->handshake_context);
      g_clear_pointer (&priv->handshake_context, g_main_context_unref);
      g_clear_object (&priv->implicit_handshake);

      yield_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_HANDSHAKE);

      g_mutex_lock (&priv->op_mutex);

      if (my_error)
        g_propagate_error (error, my_error);
      return success;
    }
  else
    {
      /* In the non-blocking case, start the asynchronous handshake operation
       * and return EWOULDBLOCK to the caller, who will handle polling for
       * completion of the handshake and whatever operation they actually cared
       * about. Run the actual operation as blocking in its thread. */
      *thread_timeout = -1;  /* blocking */

      g_task_run_in_thread (priv->implicit_handshake,
                            async_handshake_thread);

      /* Intentionally not translated because this is not a fatal error to be
       * presented to the user, and to avoid this showing up in profiling. */
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK, "Operation would block");
      return FALSE;
    }
}

gssize
g_tls_connection_gnutls_read (GTlsConnectionGnutls  *gnutls,
                              void                  *buffer,
                              gsize                  count,
                              gint64                 timeout,
                              GCancellable          *cancellable,
                              GError               **error)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gssize ret;

  if (priv->app_data_buf && !priv->handshaking)
    {
      ret = MIN (count, priv->app_data_buf->len);
      memcpy (buffer, priv->app_data_buf->data, ret);
      if (ret == priv->app_data_buf->len)
        g_clear_pointer (&priv->app_data_buf, g_byte_array_unref);
      else
        g_byte_array_remove_range (priv->app_data_buf, 0, ret);
      return ret;
    }

 again:
  if (!claim_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_READ,
                 timeout, cancellable, error))
    return -1;

  BEGIN_GNUTLS_IO (gnutls, G_IO_IN, timeout, cancellable);
  ret = gnutls_record_recv (priv->session, buffer, count);
  END_GNUTLS_IO (gnutls, G_IO_IN, ret, _("Error reading data from TLS socket"), error);

  yield_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_READ);

  if (ret >= 0)
    return ret;
  else if (ret == GNUTLS_E_REHANDSHAKE)
    goto again;
  else
    return -1;
}

static gsize
input_vectors_from_gnutls_datum_t (GInputVector          *vectors,
                                   guint                  num_vectors,
                                   const gnutls_datum_t  *datum)
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

static gssize
g_tls_connection_gnutls_read_message (GTlsConnectionGnutls  *gnutls,
                                      GInputVector          *vectors,
                                      guint                  num_vectors,
                                      gint64                 timeout,
                                      GCancellable          *cancellable,
                                      GError               **error)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  guint i;
  gssize ret;
  gnutls_packet_t packet = { 0, };

  /* Copy data out of the app data buffer first. */
  if (priv->app_data_buf && !priv->handshaking)
    {
      ret = 0;

      for (i = 0; i < num_vectors; i++)
        {
          gsize count;
          GInputVector *vec = &vectors[i];

          count = MIN (vec->size, priv->app_data_buf->len);
          ret += count;

          memcpy (vec->buffer, priv->app_data_buf->data, count);
          if (count == priv->app_data_buf->len)
            g_clear_pointer (&priv->app_data_buf, g_byte_array_unref);
          else
            g_byte_array_remove_range (priv->app_data_buf, 0, count);
        }

      return ret;
    }

 again:
  if (!claim_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_READ,
                 timeout, cancellable, error))
    return -1;

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

  END_GNUTLS_IO (gnutls, G_IO_IN, ret, _("Error reading data from TLS socket"), error);

  yield_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_READ);

  if (ret >= 0)
    return ret;
  else if (ret == GNUTLS_E_REHANDSHAKE)
    goto again;
  else
    return -1;
}

static gint
g_tls_connection_gnutls_receive_messages (GDatagramBased  *datagram_based,
                                          GInputMessage   *messages,
                                          guint            num_messages,
                                          gint             flags,
                                          gint64           timeout,
                                          GCancellable    *cancellable,
                                          GError         **error)
{
  GTlsConnectionGnutls *gnutls;
  guint i;
  GError *child_error = NULL;

  gnutls = G_TLS_CONNECTION_GNUTLS (datagram_based);

  if (flags != G_SOCKET_MSG_NONE)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                   _("Receive flags are not supported"));
      return -1;
    }

  for (i = 0; i < num_messages && child_error == NULL; i++)
    {
      GInputMessage *message = &messages[i];
      gssize n_bytes_read;

      n_bytes_read = g_tls_connection_gnutls_read_message (gnutls,
                                                           message->vectors,
                                                           message->num_vectors,
                                                           timeout,
                                                           cancellable,
                                                           &child_error);

      if (message->address != NULL)
        *message->address = NULL;
      message->flags = G_SOCKET_MSG_NONE;
      if (message->control_messages != NULL)
        *message->control_messages = NULL;
      message->num_control_messages = 0;

      if (n_bytes_read > 0)
        {
          message->bytes_received = n_bytes_read;
        }
      else if (n_bytes_read == 0)
        {
          /* EOS. */
          break;
        }
      else if (i > 0 &&
               (g_error_matches (child_error,
                                 G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK) ||
                g_error_matches (child_error,
                                 G_IO_ERROR, G_IO_ERROR_TIMED_OUT)))
        {
          /* Blocked or timed out after receiving some messages successfully. */
          g_clear_error (&child_error);
          break;
        }
      else
        {
          /* Error, including G_IO_ERROR_WOULD_BLOCK or G_IO_ERROR_TIMED_OUT on
           * the first message; or G_IO_ERROR_CANCELLED at any time. */
          break;
        }
    }

  if (child_error != NULL)
    {
      g_propagate_error (error, child_error);
      return -1;
    }

  return i;
}

gssize
g_tls_connection_gnutls_write (GTlsConnectionGnutls  *gnutls,
                               const void            *buffer,
                               gsize                  count,
                               gint64                 timeout,
                               GCancellable          *cancellable,
                               GError               **error)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gssize ret;

 again:
  if (!claim_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_WRITE,
                 timeout, cancellable, error))
    return -1;

  BEGIN_GNUTLS_IO (gnutls, G_IO_OUT, timeout, cancellable);
  ret = gnutls_record_send (priv->session, buffer, count);
  END_GNUTLS_IO (gnutls, G_IO_OUT, ret, _("Error writing data to TLS socket"), error);

  yield_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_WRITE);

  if (ret >= 0)
    return ret;
  else if (ret == GNUTLS_E_REHANDSHAKE)
    goto again;
  else
    return -1;
}

static gssize
g_tls_connection_gnutls_write_message (GTlsConnectionGnutls  *gnutls,
                                       GOutputVector         *vectors,
                                       guint                  num_vectors,
                                       gint64                 timeout,
                                       GCancellable          *cancellable,
                                       GError               **error)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gssize ret;
  guint i;
  gsize total_message_size;

 again:
  if (!claim_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_WRITE,
                 timeout, cancellable, error))
    return -1;

  /* Calculate the total message size and check it’s not too big. */
  for (i = 0, total_message_size = 0; i < num_vectors; i++)
    total_message_size += vectors[i].size;

  if (priv->base_socket != NULL &&
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

      goto done;
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
  END_GNUTLS_IO (gnutls, G_IO_OUT, ret, _("Error writing data to TLS socket"), error);

 done:
  yield_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_WRITE);

  if (ret >= 0)
    return ret;
  else if (ret == GNUTLS_E_REHANDSHAKE)
    goto again;
  else
    return -1;
}

static gint
g_tls_connection_gnutls_send_messages (GDatagramBased  *datagram_based,
                                       GOutputMessage  *messages,
                                       guint            num_messages,
                                       gint             flags,
                                       gint64           timeout,
                                       GCancellable    *cancellable,
                                       GError         **error)
{
  GTlsConnectionGnutls *gnutls;
  guint i;
  GError *child_error = NULL;

  gnutls = G_TLS_CONNECTION_GNUTLS (datagram_based);

  if (flags != G_SOCKET_MSG_NONE)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                   _("Send flags are not supported"));
      return -1;
    }

  for (i = 0; i < num_messages && child_error == NULL; i++)
    {
      GOutputMessage *message = &messages[i];
      gssize n_bytes_sent;

      n_bytes_sent = g_tls_connection_gnutls_write_message (gnutls,
                                                            message->vectors,
                                                            message->num_vectors,
                                                            timeout,
                                                            cancellable,
                                                            &child_error);

      if (n_bytes_sent >= 0)
        {
          message->bytes_sent = n_bytes_sent;
        }
      else if (i > 0 &&
               (g_error_matches (child_error,
                                 G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK) ||
                g_error_matches (child_error,
                                 G_IO_ERROR, G_IO_ERROR_TIMED_OUT)))
        {
          /* Blocked or timed out after sending some messages successfully. */
          g_clear_error (&child_error);
          break;
        }
      else
        {
          /* Error, including G_IO_ERROR_WOULD_BLOCK or G_IO_ERROR_TIMED_OUT
           * on the first message; or G_IO_ERROR_CANCELLED at any time. */
          break;
        }
    }

  if (child_error != NULL)
    {
      g_propagate_error (error, child_error);
      return -1;
    }

  return i;
}

static GInputStream  *
g_tls_connection_gnutls_get_input_stream (GIOStream *stream)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (stream);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  return priv->tls_istream;
}

static GOutputStream *
g_tls_connection_gnutls_get_output_stream (GIOStream *stream)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (stream);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  return priv->tls_ostream;
}

gboolean
g_tls_connection_gnutls_close_internal (GIOStream     *stream,
                                        GTlsDirection  direction,
                                        gint64         timeout,
                                        GCancellable  *cancellable,
                                        GError       **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (stream);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GTlsConnectionGnutlsOp op;
  gboolean success = TRUE;
  int ret = 0;
  GError *gnutls_error = NULL, *stream_error = NULL;

  /* This can be called from g_io_stream_close(), g_input_stream_close(),
   * g_output_stream_close() or g_tls_connection_close(). In all cases, we only
   * do the gnutls_bye() for writing. The difference is how we set the flags on
   * this class and how the underlying stream is closed.
   */

  g_return_val_if_fail (direction != G_TLS_DIRECTION_NONE, FALSE);

  if (direction == G_TLS_DIRECTION_BOTH)
    op = G_TLS_CONNECTION_GNUTLS_OP_CLOSE_BOTH;
  else if (direction == G_TLS_DIRECTION_READ)
    op = G_TLS_CONNECTION_GNUTLS_OP_CLOSE_READ;
  else
    op = G_TLS_CONNECTION_GNUTLS_OP_CLOSE_WRITE;

  if (!claim_op (gnutls, op, timeout, cancellable, error))
    return FALSE;

  if (priv->ever_handshaked && !priv->write_closed &&
      direction & G_TLS_DIRECTION_WRITE)
    {
      BEGIN_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, timeout, cancellable);
      ret = gnutls_bye (priv->session, GNUTLS_SHUT_WR);
      END_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, ret,
                     _("Error performing TLS close"), &gnutls_error);

      priv->write_closed = TRUE;
    }

  if (!priv->read_closed && direction & G_TLS_DIRECTION_READ)
    priv->read_closed = TRUE;

  /* Close the underlying streams. Do this even if the gnutls_bye() call failed,
   * as the parent GIOStream will have set its internal closed flag and hence
   * this implementation will never be called again. */
  if (priv->base_io_stream != NULL)
    {
      if (direction == G_TLS_DIRECTION_BOTH)
        success = g_io_stream_close (priv->base_io_stream,
                                     cancellable, &stream_error);
      else if (direction & G_TLS_DIRECTION_READ)
        success = g_input_stream_close (g_io_stream_get_input_stream (priv->base_io_stream),
                                        cancellable, &stream_error);
      else if (direction & G_TLS_DIRECTION_WRITE)
        success = g_output_stream_close (g_io_stream_get_output_stream (priv->base_io_stream),
                                         cancellable, &stream_error);
    }
  else if (g_tls_connection_gnutls_is_dtls (gnutls))
    {
      /* We do not close underlying #GDatagramBaseds. There is no
       * g_datagram_based_close() method since different datagram-based
       * protocols vary wildly in how they close. */
      success = TRUE;
    }
  else
    {
      g_assert_not_reached ();
    }

  yield_op (gnutls, op);

  /* Propagate errors. */
  if (ret != 0)
    {
      g_propagate_error (error, gnutls_error);
      g_clear_error (&stream_error);
    }
  else if (!success)
    {
      g_propagate_error (error, stream_error);
      g_clear_error (&gnutls_error);
    }

  return success && (ret == 0);
}

static gboolean
g_tls_connection_gnutls_close (GIOStream     *stream,
                               GCancellable  *cancellable,
                               GError       **error)
{
  return g_tls_connection_gnutls_close_internal (stream,
                                                 G_TLS_DIRECTION_BOTH,
                                                 -1,  /* blocking */
                                                 cancellable, error);
}

static gboolean
g_tls_connection_gnutls_dtls_shutdown (GDtlsConnection  *conn,
                                       gboolean          shutdown_read,
                                       gboolean          shutdown_write,
                                       GCancellable     *cancellable,
                                       GError          **error)
{
  GTlsDirection direction = G_TLS_DIRECTION_NONE;

  if (shutdown_read)
    direction |= G_TLS_DIRECTION_READ;
  if (shutdown_write)
    direction |= G_TLS_DIRECTION_WRITE;

  return g_tls_connection_gnutls_close_internal (G_IO_STREAM (conn),
                                                 direction,
                                                 -1,  /* blocking */
                                                 cancellable, error);
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
  GIOStream *stream = object;
  GTlsDirection direction;
  GError *error = NULL;

  direction = GPOINTER_TO_INT (g_task_get_task_data (task));

  if (!g_tls_connection_gnutls_close_internal (stream, direction,
                                               -1,  /* blocking */
                                               cancellable, &error))
    g_task_return_error (task, error);
  else
    g_task_return_boolean (task, TRUE);
}

static void
g_tls_connection_gnutls_close_internal_async (GIOStream           *stream,
                                              GTlsDirection        direction,
                                              int                  io_priority,
                                              GCancellable        *cancellable,
                                              GAsyncReadyCallback  callback,
                                              gpointer             user_data)
{
  GTask *task;

  task = g_task_new (stream, cancellable, callback, user_data);
  g_task_set_source_tag (task, g_tls_connection_gnutls_close_internal_async);
  g_task_set_priority (task, io_priority);
  g_task_set_task_data (task, GINT_TO_POINTER (direction), NULL);
  g_task_run_in_thread (task, close_thread);
  g_object_unref (task);
}

static void
g_tls_connection_gnutls_close_async (GIOStream           *stream,
                                     int                  io_priority,
                                     GCancellable        *cancellable,
                                     GAsyncReadyCallback  callback,
                                     gpointer             user_data)
{
  g_tls_connection_gnutls_close_internal_async (stream, G_TLS_DIRECTION_BOTH,
                                                io_priority, cancellable,
                                                callback, user_data);
}

static gboolean
g_tls_connection_gnutls_close_finish (GIOStream           *stream,
                                      GAsyncResult        *result,
                                      GError             **error)
{
  g_return_val_if_fail (g_task_is_valid (result, stream), FALSE);

  return g_task_propagate_boolean (G_TASK (result), error);
}

static void
g_tls_connection_gnutls_dtls_shutdown_async (GDtlsConnection     *conn,
                                             gboolean             shutdown_read,
                                             gboolean             shutdown_write,
                                             int                  io_priority,
                                             GCancellable        *cancellable,
                                             GAsyncReadyCallback  callback,
                                             gpointer             user_data)
{
  GTlsDirection direction = G_TLS_DIRECTION_NONE;

  if (shutdown_read)
    direction |= G_TLS_DIRECTION_READ;
  if (shutdown_write)
    direction |= G_TLS_DIRECTION_WRITE;

  g_tls_connection_gnutls_close_internal_async (G_IO_STREAM (conn), direction,
                                                io_priority, cancellable,
                                                callback, user_data);
}

static gboolean
g_tls_connection_gnutls_dtls_shutdown_finish (GDtlsConnection  *conn,
                                              GAsyncResult     *result,
                                              GError          **error)
{
  g_return_val_if_fail (g_task_is_valid (result, conn), FALSE);

  return g_task_propagate_boolean (G_TASK (result), error);
}

static void
g_tls_connection_gnutls_class_init (GTlsConnectionGnutlsClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsConnectionBaseClass *base_class = G_TLS_CONNECTION_BASE_CLASS (klass);

  gobject_class->finalize = g_tls_connection_gnutls_finalize;

  base_class->request_rehandshake        = g_tls_connection_gnutls_request_rehandshake;
  base_class->prepare_handshake          = g_tls_connection_gnutls_prepare_handshake;
  base_class->handshake_thread_handshake = g_tls_connection_gnutls_handshake_thread_handshake;
  base_class->complete_handshake         = g_tls_connection_gnutls_complete_handshake;
  base_class->read_fn                    = g_tls_connection_gnutls_read;
  base_class->read_message_fn            = g_tls_connection_gnutls_read_message;
  base_class->write_fn                   = g_tls_connection_gnutls_write;
  base_class->write_message_fn           = g_tls_connection_gnutls_write_message;
  base_class->close_fn                   = g_tls_connection_gnutls_close;
}

static void
g_tls_connection_gnutls_initable_iface_init (GInitableIface *iface)
{
  iface->init = g_tls_connection_gnutls_initable_init;
}
