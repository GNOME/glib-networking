/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlsconnection-openssl.c
 *
 * Copyright (C) 2015 NICE s.r.l.
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, when the library is used with OpenSSL, a special
 * exception applies. Refer to the LICENSE_EXCEPTION file for details.
 *
 * Authors: Ignacio Casal Quinteiro
 */

#include "config.h"
#include "glib.h"

#include <errno.h>
#include <stdarg.h>
#include "openssl-include.h"

#include "gtlsconnection-openssl.h"
#include "gtlsbackend-openssl.h"
#include "gtlscertificate-openssl.h"
#include "gtlsdatabase-openssl.h"
#include "gtlsbio.h"
#include "gtlslog.h"

#include <glib/gi18n-lib.h>

typedef struct _GTlsConnectionOpensslPrivate
{
  BIO *bio;
  GMutex ssl_mutex;

  gboolean shutting_down;
} GTlsConnectionOpensslPrivate;

static void g_tls_connection_openssl_initable_iface_init (GInitableIface *iface);

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (GTlsConnectionOpenssl, g_tls_connection_openssl, G_TYPE_TLS_CONNECTION_BASE,
                                  G_ADD_PRIVATE (GTlsConnectionOpenssl)
                                  G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                         g_tls_connection_openssl_initable_iface_init))

static void
g_tls_connection_openssl_finalize (GObject *object)
{
  GTlsConnectionOpenssl *openssl = G_TLS_CONNECTION_OPENSSL (object);
  GTlsConnectionOpensslPrivate *priv;

  priv = g_tls_connection_openssl_get_instance_private (openssl);

  g_mutex_clear (&priv->ssl_mutex);

  G_OBJECT_CLASS (g_tls_connection_openssl_parent_class)->finalize (object);
}

static GTlsSafeRenegotiationStatus
g_tls_connection_openssl_handshake_thread_safe_renegotiation_status (GTlsConnectionBase *tls)
{
  GTlsConnectionOpenssl *openssl = G_TLS_CONNECTION_OPENSSL (tls);
  SSL *ssl;

  ssl = g_tls_connection_openssl_get_ssl (openssl);

  return SSL_get_secure_renegotiation_support (ssl) ? G_TLS_SAFE_RENEGOTIATION_SUPPORTED_BY_PEER
                                                    : G_TLS_SAFE_RENEGOTIATION_UNSUPPORTED;
}

static GTlsConnectionBaseStatus
end_openssl_io (GTlsConnectionOpenssl  *openssl,
                GIOCondition            direction,
                int                     ret,
                gboolean                blocking,
                GError                **error,
                const char             *err_prefix,
                const char             *err_str)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (openssl);
  GTlsConnectionOpensslPrivate *priv;
  int err_code, err, err_lib, reason;
  GError *my_error = NULL;
  GTlsConnectionBaseStatus status;
  SSL *ssl;

  priv = g_tls_connection_openssl_get_instance_private (openssl);

  ssl = g_tls_connection_openssl_get_ssl (openssl);

  err_code = SSL_get_error (ssl, ret);

  status = g_tls_connection_base_pop_io (tls, direction, ret > 0, &my_error);

  if ((err_code == SSL_ERROR_WANT_READ ||
       err_code == SSL_ERROR_WANT_WRITE) &&
      blocking)
    {
      if (my_error)
        g_error_free (my_error);
      return G_TLS_CONNECTION_BASE_TRY_AGAIN;
    }

  if (err_code == SSL_ERROR_ZERO_RETURN)
    return G_TLS_CONNECTION_BASE_OK;

  if (status == G_TLS_CONNECTION_BASE_OK ||
      status == G_TLS_CONNECTION_BASE_WOULD_BLOCK ||
      status == G_TLS_CONNECTION_BASE_TIMED_OUT)
    {
      if (my_error)
        g_propagate_error (error, my_error);
      return status;
    }

  /* This case is documented that it may happen and that is perfectly fine */
  if (err_code == SSL_ERROR_SYSCALL &&
      (priv->shutting_down && (!my_error || g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_BROKEN_PIPE))))
    {
      g_clear_error (&my_error);
      return G_TLS_CONNECTION_BASE_OK;
    }

  err = ERR_get_error ();
  err_lib = ERR_GET_LIB (err);
  reason = ERR_GET_REASON (err);

  if (g_tls_connection_base_is_handshaking (tls) && !g_tls_connection_base_ever_handshaked (tls))
    {
      if (reason == SSL_R_BAD_PACKET_LENGTH ||
          reason == SSL_R_UNKNOWN_ALERT_TYPE ||
          reason == SSL_R_DECRYPTION_FAILED ||
          reason == SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC ||
          reason == SSL_R_BAD_PROTOCOL_VERSION_NUMBER ||
          reason == SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE ||
          reason == SSL_R_UNKNOWN_PROTOCOL)
        {
          g_clear_error (&my_error);
          g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_NOT_TLS,
                       _("Peer failed to perform TLS handshake: %s"), ERR_reason_error_string (err));
          return G_TLS_CONNECTION_BASE_ERROR;
        }
    }

#ifdef SSL_R_SHUTDOWN_WHILE_IN_INIT
  /* XXX: this error happens on ubuntu when shutting down the connection, it
   * seems to be a bug in a specific version of openssl, so let's handle it
   * gracefully
   */
  if (reason == SSL_R_SHUTDOWN_WHILE_IN_INIT)
    {
      g_clear_error (&my_error);
      return G_TLS_CONNECTION_BASE_OK;
    }
#endif

  if (reason == SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE
#ifdef SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED
      || reason == SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED
#endif
     )
    {
      g_clear_error (&my_error);
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED,
                           _("TLS connection peer did not send a certificate"));
      return status;
    }

  if (reason == SSL_R_CERTIFICATE_VERIFY_FAILED)
    {
      g_clear_error (&my_error);
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                   _("Unacceptable TLS certificate"));
      return G_TLS_CONNECTION_BASE_ERROR;
    }

  if (reason == SSL_R_TLSV1_ALERT_UNKNOWN_CA)
    {
      g_clear_error (&my_error);
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                   _("Unacceptable TLS certificate authority"));
      return G_TLS_CONNECTION_BASE_ERROR;
    }

  if (err_lib == ERR_LIB_RSA && reason == RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY)
    {
      g_clear_error (&my_error);
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                           _("Digest too big for RSA key"));
      return G_TLS_CONNECTION_BASE_ERROR;
    }

  if (reason == SSL_R_NO_RENEGOTIATION)
    {
      g_clear_error (&my_error);
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                           _("Secure renegotiation is disabled"));
      return G_TLS_CONNECTION_BASE_REHANDSHAKE;
    }

  if (my_error)
    g_propagate_error (error, my_error);
  else
    /* FIXME: this is just for debug */
    g_message ("end_openssl_io %s: %d, %d, %d", G_IS_TLS_CLIENT_CONNECTION (openssl) ? "client" : "server", err_code, err_lib, reason);

  if (ret == 0 && err == 0 && err_lib == 0 && err_code == SSL_ERROR_SYSCALL)
    {
      /* SSL_ERROR_SYSCALL usually means we have no bloody idea what has happened
       * but when ret is 0 and all others as well - this is normally Early EOF condition
       */
      if (!g_tls_connection_get_require_close_notify (G_TLS_CONNECTION (openssl)))
        return G_TLS_CONNECTION_BASE_OK;

      if (error && !*error)
        *error = g_error_new (G_TLS_ERROR, G_TLS_ERROR_EOF, _("%s: The connection is broken"), err_prefix);
    }
  else
  if (error && !*error)
    *error = g_error_new (G_TLS_ERROR, G_TLS_ERROR_MISC, "%s: %s", err_prefix, err_str);

  return G_TLS_CONNECTION_BASE_ERROR;
}

static int
_openssl_alpn_select_cb (SSL                  *ssl,
                         const unsigned char **out,
                         unsigned char        *outlen,
                         const unsigned char  *in,
                         unsigned int          inlen,
                         void                 *arg)
{
  GTlsConnectionBase *tls = arg;
  int ret = SSL_TLSEXT_ERR_NOACK;
  gchar **advertised_protocols = NULL;
  gchar *logbuf;

  logbuf = g_strndup ((const gchar *)in, inlen);
  g_tls_log_debug (tls, "ALPN their protocols: %s", logbuf);
  g_free (logbuf);

  g_object_get (G_OBJECT (tls),
                "advertised-protocols", &advertised_protocols,
                NULL);

  if (!advertised_protocols)
    return ret;

  if (g_strv_length (advertised_protocols) > 0)
    {
      GByteArray *protocols = g_byte_array_new ();
      int i;
      guint8 slen = 0;
      guint8 *spd = NULL;

      for (i = 0; advertised_protocols[i]; i++)
        {
          guint8 len = strlen (advertised_protocols[i]);
          g_byte_array_append (protocols, &len, 1);
          g_byte_array_append (protocols,
                               (guint8 *)advertised_protocols[i],
                               len);
        }
      logbuf = g_strndup ((const gchar *)protocols->data, protocols->len);
      g_tls_log_debug (tls, "ALPN our protocols: %s", logbuf);
      g_free (logbuf);

      /* pointer to memory inside in[0..inlen] is returned on success
       * pointer to protocols->data is returned on failure */
      ret = SSL_select_next_proto (&spd, &slen,
                                   in, inlen,
                                   protocols->data, protocols->len);
      if (ret == OPENSSL_NPN_NEGOTIATED)
        {
          logbuf = g_strndup ((const gchar *)spd, slen);
          g_tls_log_debug (tls, "ALPN selected protocol %s", logbuf);
          g_free (logbuf);

          ret = SSL_TLSEXT_ERR_OK;
          *out = spd;
          *outlen = slen;
        }
      else
        {
          g_tls_log_debug (tls, "ALPN no matching protocol");
          ret = SSL_TLSEXT_ERR_NOACK;
        }

      g_byte_array_unref (protocols);
    }

  g_strfreev (advertised_protocols);
  return ret;
}

static void
g_tls_connection_openssl_prepare_handshake (GTlsConnectionBase  *tls,
                                            gchar              **advertised_protocols)
{
  SSL *ssl;

  if (!advertised_protocols)
    return;

  ssl = g_tls_connection_openssl_get_ssl (G_TLS_CONNECTION_OPENSSL (tls));

  if (G_IS_TLS_SERVER_CONNECTION (tls))
    {
      SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);

      g_tls_log_debug (tls, "Setting ALPN Callback on %p", ctx);
      SSL_CTX_set_alpn_select_cb (ctx, _openssl_alpn_select_cb, tls);

      return;
    }

  if (g_strv_length (advertised_protocols) > 0)
    {
      GByteArray *protocols = g_byte_array_new ();
      int ret, i;

      for (i = 0; advertised_protocols[i]; i++)
        {
          guint8 len = strlen (advertised_protocols[i]);
          g_byte_array_append (protocols, &len, 1);
          g_byte_array_append (protocols, (guint8 *)advertised_protocols[i], len);
        }
      ret = SSL_set_alpn_protos (ssl, protocols->data, protocols->len);
      if (ret)
        g_tls_log_debug (tls, "Error setting ALPN protocols: %d", ret);
      else
        {
          gchar *logbuf = g_strndup ((const gchar *)protocols->data, protocols->len);

          g_tls_log_debug (tls, "Setting ALPN protocols to %s", logbuf);
          g_free (logbuf);
        }
      g_byte_array_unref (protocols);
    }
}

static void
g_tls_connection_openssl_complete_handshake (GTlsConnectionBase  *tls,
                                             gboolean             handshake_succeeded,
                                             gchar              **negotiated_protocol,
                                             GError             **error)
{
  SSL *ssl;
  unsigned int len = 0;
  const unsigned char *data = NULL;

  if (!handshake_succeeded)
    return;

  ssl = g_tls_connection_openssl_get_ssl (G_TLS_CONNECTION_OPENSSL (tls));

  SSL_get0_alpn_selected (ssl, &data, &len);

  g_tls_log_debug (tls, "negotiated ALPN protocols: [%d]%p", len, data);

  if (data && len > 0)
    {
      g_assert (!*negotiated_protocol);
      *negotiated_protocol = g_strndup ((gchar *)data, len);
    }
}

#define BEGIN_OPENSSL_IO(openssl, direction, timeout, cancellable)          \
  do {                                                                      \
    char error_str[256];                                                    \
    g_tls_connection_base_push_io (G_TLS_CONNECTION_BASE (openssl),         \
                                   direction, timeout, cancellable);

#define END_OPENSSL_IO(openssl, direction, ret, timeout, status, errmsg, err) \
    ERR_error_string_n (SSL_get_error (ssl, ret), error_str, sizeof(error_str)); \
    status = end_openssl_io (openssl, direction, ret, timeout == -1, err, errmsg, error_str); \
  } while (status == G_TLS_CONNECTION_BASE_TRY_AGAIN);

static GTlsConnectionBaseStatus
g_tls_connection_openssl_handshake_thread_request_rehandshake (GTlsConnectionBase  *tls,
                                                               gint64               timeout,
                                                               GCancellable        *cancellable,
                                                               GError             **error)
{
  GTlsConnectionOpenssl *openssl;
  GTlsConnectionBaseStatus status;
  SSL *ssl;
  int ret;

  /* On a client-side connection, SSL_renegotiate() itself will start
   * a rehandshake, so we only need to do something special here for
   * server-side connections.
   */
  if (!G_IS_TLS_SERVER_CONNECTION (tls))
    return G_TLS_CONNECTION_BASE_OK;

  openssl = G_TLS_CONNECTION_OPENSSL (tls);

  ssl = g_tls_connection_openssl_get_ssl (openssl);

  BEGIN_OPENSSL_IO (openssl, G_IO_IN | G_IO_OUT, timeout, cancellable);
  if (SSL_version(ssl) >= TLS1_3_VERSION)
    ret = SSL_key_update (ssl, SSL_KEY_UPDATE_REQUESTED);
  else if (SSL_get_secure_renegotiation_support (ssl) && !(SSL_get_options(ssl) & SSL_OP_NO_RENEGOTIATION))
    /* remote and local peers both can rehandshake */
    ret = SSL_renegotiate (ssl);
  else
    g_tls_log_debug (tls, "Secure renegotiation is not supported");
  END_OPENSSL_IO (openssl, G_IO_IN | G_IO_OUT, ret, timeout, status,
                  _("Error performing TLS handshake"), error);

  return status;
}

static GTlsCertificate *
g_tls_connection_openssl_retrieve_peer_certificate (GTlsConnectionBase *tls)
{
  X509 *peer;
  STACK_OF (X509) *certs;
  GTlsCertificateOpenssl *chain;
  SSL *ssl;

  ssl = g_tls_connection_openssl_get_ssl (G_TLS_CONNECTION_OPENSSL (tls));

  peer = SSL_get_peer_certificate (ssl);
  if (!peer)
    return NULL;

  certs = SSL_get_peer_cert_chain (ssl);
  if (!certs)
    {
      X509_free (peer);
      return NULL;
    }

  chain = g_tls_certificate_openssl_build_chain (peer, certs);
  X509_free (peer);
  if (!chain)
    return NULL;

  return G_TLS_CERTIFICATE (chain);
}

static GTlsConnectionBaseStatus
g_tls_connection_openssl_handshake_thread_handshake (GTlsConnectionBase  *tls,
                                                     gint64               timeout,
                                                     GCancellable        *cancellable,
                                                     GError             **error)
{
  GTlsConnectionOpenssl *openssl = G_TLS_CONNECTION_OPENSSL (tls);
  GTlsConnectionBaseStatus status;
  SSL *ssl;
  int ret;

  ssl = g_tls_connection_openssl_get_ssl (openssl);

  BEGIN_OPENSSL_IO (openssl, G_IO_IN | G_IO_OUT, timeout, cancellable);
  ret = SSL_do_handshake (ssl);
  END_OPENSSL_IO (openssl, G_IO_IN | G_IO_OUT, ret, timeout, status,
                  _("Error performing TLS handshake"), error);

  if (ret > 0)
    {
      if (!g_tls_connection_base_handshake_thread_verify_certificate (G_TLS_CONNECTION_BASE (openssl)))
        {
          g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                               _("Unacceptable TLS certificate"));
          return G_TLS_CONNECTION_BASE_ERROR;
        }
    }

  return status;
}

static void
g_tls_connection_openssl_push_io (GTlsConnectionBase *tls,
                                  GIOCondition        direction,
                                  gint64              timeout,
                                  GCancellable       *cancellable)
{
  GTlsConnectionOpenssl *openssl = G_TLS_CONNECTION_OPENSSL (tls);
  GTlsConnectionOpensslPrivate *priv;
  GError **error;

  priv = g_tls_connection_openssl_get_instance_private (openssl);

  G_TLS_CONNECTION_BASE_CLASS (g_tls_connection_openssl_parent_class)->push_io (tls, direction,
                                                                                timeout, cancellable);

  /* FIXME: need to support timeout > 0
   * This will require changes in GTlsBio */

  if (direction & G_IO_IN)
    {
      error = g_tls_connection_base_get_read_error (tls);
      g_tls_bio_set_read_cancellable (priv->bio, cancellable);
      g_tls_bio_set_read_blocking (priv->bio, timeout == -1);
      g_clear_error (error);
      g_tls_bio_set_read_error (priv->bio, error);
    }

  if (direction & G_IO_OUT)
    {
      error = g_tls_connection_base_get_write_error (tls);
      g_tls_bio_set_write_cancellable (priv->bio, cancellable);
      g_tls_bio_set_write_blocking (priv->bio, timeout == -1);
      g_clear_error (error);
      g_tls_bio_set_write_error (priv->bio, error);
    }

  g_mutex_lock (&priv->ssl_mutex);
}

static GTlsConnectionBaseStatus
g_tls_connection_openssl_pop_io (GTlsConnectionBase  *tls,
                                 GIOCondition         direction,
                                 gboolean             success,
                                 GError             **error)
{
  GTlsConnectionOpenssl *openssl = G_TLS_CONNECTION_OPENSSL (tls);
  GTlsConnectionOpensslPrivate *priv;

  priv = g_tls_connection_openssl_get_instance_private (openssl);

  g_mutex_unlock (&priv->ssl_mutex);

  if (direction & G_IO_IN)
    g_tls_bio_set_read_cancellable (priv->bio, NULL);

  if (direction & G_IO_OUT)
    g_tls_bio_set_write_cancellable (priv->bio, NULL);

  return G_TLS_CONNECTION_BASE_CLASS (g_tls_connection_openssl_parent_class)->pop_io (tls, direction,
                                                                                      success, error);
}

static GTlsConnectionBaseStatus
g_tls_connection_openssl_read (GTlsConnectionBase    *tls,
                               void                  *buffer,
                               gsize                  count,
                               gint64                 timeout,
                               gssize                *nread,
                               GCancellable          *cancellable,
                               GError               **error)
{
  GTlsConnectionOpenssl *openssl = G_TLS_CONNECTION_OPENSSL (tls);
  GTlsConnectionOpensslPrivate *priv;
  GTlsConnectionBaseStatus status;
  SSL *ssl;
  gssize ret;

  priv = g_tls_connection_openssl_get_instance_private (openssl);

  ssl = g_tls_connection_openssl_get_ssl (openssl);

  /* FIXME: revert back to use BEGIN/END_OPENSSL_IO once we move all the ssl
   * operations into a worker thread
   */
  while (TRUE)
    {
      char error_str[256];

      /* We want to always be non blocking here to avoid deadlocks */
      g_tls_connection_base_push_io (G_TLS_CONNECTION_BASE (openssl),
                                     G_IO_IN, 0, cancellable);

      ret = SSL_read (ssl, buffer, count);

      ERR_error_string_n (SSL_get_error (ssl, ret), error_str, sizeof (error_str));
      status = end_openssl_io (openssl, G_IO_IN, ret, timeout == -1, error,
                               _("Error reading data from TLS socket"), error_str);

      if (status != G_TLS_CONNECTION_BASE_TRY_AGAIN)
        break;

      /* Wait for the socket to be available again to avoid an infinite loop */
      g_tls_bio_wait_available (priv->bio, G_IO_IN, cancellable);
    }

  *nread = MAX (ret, 0);
  return status;
}

static GTlsConnectionBaseStatus
g_tls_connection_openssl_write (GTlsConnectionBase    *tls,
                                const void            *buffer,
                                gsize                  count,
                                gint64                 timeout,
                                gssize                *nwrote,
                                GCancellable          *cancellable,
                                GError               **error)
{
  GTlsConnectionOpenssl *openssl = G_TLS_CONNECTION_OPENSSL (tls);
  GTlsConnectionOpensslPrivate *priv;
  GTlsConnectionBaseStatus status;
  SSL *ssl;
  gssize ret;

  priv = g_tls_connection_openssl_get_instance_private (openssl);

  ssl = g_tls_connection_openssl_get_ssl (openssl);

  while (TRUE)
    {
      char error_str[256];

      /* We want to always be non blocking here to avoid deadlocks */
      g_tls_connection_base_push_io (G_TLS_CONNECTION_BASE (openssl),
                                     G_IO_OUT, 0, cancellable);

      ret = SSL_write (ssl, buffer, count);

      ERR_error_string_n (SSL_get_error (ssl, ret), error_str, sizeof (error_str));
      status = end_openssl_io (openssl, G_IO_OUT, ret, timeout == -1, error,
                               _("Error writing data to TLS socket"), error_str);

      if (status != G_TLS_CONNECTION_BASE_TRY_AGAIN)
        break;

      /* Wait for the socket to be available again to avoid an infinite loop */
      g_tls_bio_wait_available (priv->bio, G_IO_OUT, cancellable);
    }

  *nwrote = MAX (ret, 0);
  return status;
}

static GTlsConnectionBaseStatus
g_tls_connection_openssl_close (GTlsConnectionBase  *tls,
                                gint64               timeout,
                                GCancellable        *cancellable,
                                GError             **error)
{
  GTlsConnectionOpenssl *openssl = G_TLS_CONNECTION_OPENSSL (tls);
  GTlsConnectionOpensslPrivate *priv;
  GTlsConnectionBaseStatus status;
  SSL *ssl;
  int ret;

  ssl = g_tls_connection_openssl_get_ssl (openssl);
  priv = g_tls_connection_openssl_get_instance_private (openssl);

  priv->shutting_down = TRUE;

  BEGIN_OPENSSL_IO (openssl, G_IO_IN | G_IO_OUT, timeout, cancellable);
  ret = SSL_shutdown (ssl);
  /* Note it is documented that getting 0 is correct when shutting down since
   * it means it will close the write direction
   */
  ret = ret == 0 ? 1 : ret;
  END_OPENSSL_IO (openssl, G_IO_IN | G_IO_OUT, ret, timeout, status,
                  _("Error performing TLS close"), error);

  return status;
}

static void
g_tls_connection_openssl_class_init (GTlsConnectionOpensslClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  GTlsConnectionBaseClass *base_class = G_TLS_CONNECTION_BASE_CLASS (klass);

  object_class->finalize                                 = g_tls_connection_openssl_finalize;

  base_class->prepare_handshake                          = g_tls_connection_openssl_prepare_handshake;
  base_class->complete_handshake                         = g_tls_connection_openssl_complete_handshake;
  base_class->handshake_thread_safe_renegotiation_status = g_tls_connection_openssl_handshake_thread_safe_renegotiation_status;
  base_class->handshake_thread_request_rehandshake       = g_tls_connection_openssl_handshake_thread_request_rehandshake;
  base_class->handshake_thread_handshake                 = g_tls_connection_openssl_handshake_thread_handshake;
  base_class->retrieve_peer_certificate                  = g_tls_connection_openssl_retrieve_peer_certificate;
  base_class->push_io                                    = g_tls_connection_openssl_push_io;
  base_class->pop_io                                     = g_tls_connection_openssl_pop_io;
  base_class->read_fn                                    = g_tls_connection_openssl_read;
  base_class->write_fn                                   = g_tls_connection_openssl_write;
  base_class->close_fn                                   = g_tls_connection_openssl_close;
}

static int data_index = -1;

static gboolean
g_tls_connection_openssl_initable_init (GInitable     *initable,
                                        GCancellable  *cancellable,
                                        GError       **error)
{
  GTlsConnectionOpenssl *openssl = G_TLS_CONNECTION_OPENSSL (initable);
  GTlsConnectionOpensslPrivate *priv;
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (initable);
  GIOStream *base_io_stream;
  SSL *ssl;

  g_object_get (tls,
                "base-io-stream", &base_io_stream,
                NULL);
  g_return_val_if_fail (base_io_stream, FALSE);

  priv = g_tls_connection_openssl_get_instance_private (openssl);

  ssl = g_tls_connection_openssl_get_ssl (openssl);
  g_assert (ssl);

  if (data_index == -1) {
      data_index = SSL_get_ex_new_index (0, (void *)"gtlsconnection", NULL, NULL, NULL);
  }
  SSL_set_ex_data (ssl, data_index, openssl);

  priv->bio = g_tls_bio_new (base_io_stream);

  SSL_set_bio (ssl, priv->bio, priv->bio);

  g_object_unref (base_io_stream);

  return TRUE;
}

static void
g_tls_connection_openssl_initable_iface_init (GInitableIface *iface)
{
  iface->init = g_tls_connection_openssl_initable_init;
}

static void
g_tls_connection_openssl_init (GTlsConnectionOpenssl *openssl)
{
  GTlsConnectionOpensslPrivate *priv;

  priv = g_tls_connection_openssl_get_instance_private (openssl);

  g_mutex_init (&priv->ssl_mutex);
}

SSL *
g_tls_connection_openssl_get_ssl (GTlsConnectionOpenssl *openssl)
{
  g_return_val_if_fail (G_IS_TLS_CONNECTION_OPENSSL (openssl), NULL);

  return G_TLS_CONNECTION_OPENSSL_GET_CLASS (openssl)->get_ssl (openssl);
}

GTlsConnectionOpenssl *
g_tls_connection_openssl_get_connection_from_ssl (SSL *ssl)
{
  g_return_val_if_fail (ssl, NULL);

  return SSL_get_ex_data (ssl, data_index);
}
