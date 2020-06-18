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

  if (my_error)
    g_propagate_error (error, my_error);
  else
    /* FIXME: this is just for debug */
    g_message ("end_openssl_io %s: %d, %d, %d", G_IS_TLS_CLIENT_CONNECTION (openssl) ? "client" : "server", err_code, err_lib, reason);

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
  int n_protos;
  gchar **advertised_protocols;

  g_tls_log_debug (tls, "ALPN their protocols: %s", in);

  g_object_get (G_OBJECT (tls),
                "advertised-protocols", &advertised_protocols,
                NULL);

  if (!advertised_protocols)
    return SSL_TLSEXT_ERR_NOACK;

  n_protos = g_strv_length (advertised_protocols);
  if (n_protos)
    {
      GByteArray *protocols = g_byte_array_new ();
      int ret, i;
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
      g_tls_log_debug (tls, "ALPN our protocols: %s", protocols->data);
      ret = SSL_select_next_proto (&spd, &slen,
                                   protocols->data, protocols->len,
                                   in, inlen);
      if (ret == OPENSSL_NPN_NO_OVERLAP)
        {
          g_tls_log_debug (tls, "ALPN no matching protocol");
          ret = SSL_TLSEXT_ERR_NOACK;
        }
      else
        {
          g_tls_log_debug (tls, "ALPN selected protocol [%d]%s", slen, spd);
          ret = SSL_TLSEXT_ERR_OK;
          *out = spd;
          *outlen = slen;
        }

      g_byte_array_unref (protocols);
      return ret;
    }
  return SSL_TLSEXT_ERR_NOACK;
}

static void
g_tls_connection_openssl_prepare_handshake (GTlsConnectionBase  *tls,
                                            gchar              **advertised_protocols)
{
  SSL *ssl;
  int n_protos;

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

  n_protos = g_strv_length (advertised_protocols);

  if (n_protos)
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
        g_tls_log_debug (tls, "Setting ALPN protocols to [%d]%s", protocols->len, protocols->data);
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
  ret = SSL_renegotiate (ssl);
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

static gboolean
_openssl_get_binding_tls_unique (GTlsConnectionOpenssl *tls,
                                 GByteArray            *data,
                                 GError               **error)
{
  SSL *ssl = g_tls_connection_openssl_get_ssl (tls);
  gboolean is_client = G_IS_TLS_CLIENT_CONNECTION (tls);
  gboolean resumed = SSL_session_reused (ssl);
  size_t len = 64;

  /* This is a drill */
  if (!data)
    return TRUE;

  do {
    g_byte_array_set_size (data, len);
    if ((resumed && is_client) || (!resumed && !is_client))
      len = SSL_get_peer_finished (ssl, data->data, data->len);
    else
      len = SSL_get_finished (ssl, data->data, data->len);
  } while (len > data->len);

  if (len > 0)
    {
      g_byte_array_set_size (data, len);
      return TRUE;
    }
  g_set_error (error, G_TLS_CHANNEL_BINDING_ERROR, G_TLS_CHANNEL_BINDING_ERROR_NOT_AVAILABLE,
               _("Channel binding data tls-unique is not available"));
  return FALSE;
}

static gboolean
_openssl_get_binding_tls_server_end_point (GTlsConnectionOpenssl *tls,
                                 GByteArray            *data,
                                 GError               **error)
{
  SSL *ssl = g_tls_connection_openssl_get_ssl (tls);
  gboolean is_client = G_IS_TLS_CLIENT_CONNECTION (tls);
  int algo_nid;
  const EVP_MD *algo = NULL;
  X509 *crt;

  if (is_client)
    crt = SSL_get_peer_certificate (ssl);
  else
    crt = SSL_get_certificate (ssl);

  if (!crt)
    {
      g_set_error (error, G_TLS_CHANNEL_BINDING_ERROR, G_TLS_CHANNEL_BINDING_ERROR_NOT_AVAILABLE,
                   _("X.509 Certificate is not available on the connection"));
      return FALSE;
    }

  if (!OBJ_find_sigid_algs (X509_get_signature_nid (crt), &algo_nid, NULL))
    {
      X509_free (crt);
      g_set_error (error, G_TLS_CHANNEL_BINDING_ERROR, G_TLS_CHANNEL_BINDING_ERROR_GENERAL_ERROR,
                   _("Unable to obtain certificate signature algoritm"));
      return FALSE;
    }

  /* This is a drill */
  if (!data)
    {
      X509_free (crt);
      return TRUE;
    }

  switch (algo_nid)
    {
    case NID_md5:
    case NID_sha1:
      algo_nid = NID_sha256;
      break;
    case NID_md5_sha1:
      g_set_error (error, G_TLS_CHANNEL_BINDING_ERROR, G_TLS_CHANNEL_BINDING_ERROR_NOT_SUPPORTED,
                   _("Current X.509 certificate uses unknown or unsupported signature algorithm"));
      return FALSE;
    }

  g_byte_array_set_size (data, EVP_MAX_MD_SIZE);
  algo = EVP_get_digestbynid (algo_nid);
  if (X509_digest (crt, algo, data->data, &(data->len)))
    {
      X509_free (crt);
      return TRUE;
    }

  X509_free (crt);
  g_set_error (error, G_TLS_CHANNEL_BINDING_ERROR, G_TLS_CHANNEL_BINDING_ERROR_GENERAL_ERROR,
               _("Failed to generate X.509 certificate digest"));
  return FALSE;
}

#define RFC5705_LABEL_DATA "EXPORTER-Channel-Binding"
#define RFC5705_LABEL_LEN 24
static gboolean
_openssl_get_binding_tls_exporter (GTlsConnectionOpenssl *tls,
                                   GByteArray            *data,
                                   GError               **error)
{
  SSL *ssl = g_tls_connection_openssl_get_ssl (tls);
  size_t  ctx_len = 0;
  guint8 *context = (guint8 *)"";
  int ret;

  if (!data)
    return TRUE;

  g_byte_array_set_size (data, 32);
  ret = SSL_export_keying_material (ssl,
                                    data->data, data->len,
                                    RFC5705_LABEL_DATA, RFC5705_LABEL_LEN,
                                    context, ctx_len,
                                    1 /* use context */);

  if (ret > 0)
    return TRUE;
  else
  if (ret < 0)
    g_set_error (error, G_TLS_CHANNEL_BINDING_ERROR, G_TLS_CHANNEL_BINDING_ERROR_NOT_SUPPORTED,
                 _("TLS Connection does not support TLS-Exporter feature"));
  else
    g_set_error (error, G_TLS_CHANNEL_BINDING_ERROR, G_TLS_CHANNEL_BINDING_ERROR_GENERAL_ERROR,
                 _("Unexpected error while exporting keying data"));

  return FALSE;
}

static gboolean
g_tls_connection_openssl_get_channel_binding_data (GTlsConnectionBase      *tls,
                                                   GTlsChannelBindingType   type,
                                                   GByteArray              *data,
                                                   GError                 **error)
{
  GTlsConnectionOpenssl *openssl = G_TLS_CONNECTION_OPENSSL (tls);

  /* XXX: remove the cast once public enum supports exporter */
  switch ((int)type)
    {
    case G_TLS_CHANNEL_BINDING_TLS_UNIQUE:
      return _openssl_get_binding_tls_unique (openssl, data, error);
      /* fall through */
    case G_TLS_CHANNEL_BINDING_TLS_SERVER_END_POINT:
      return _openssl_get_binding_tls_server_end_point (openssl, data, error);
      /* fall through */
    case 100500:
      return _openssl_get_binding_tls_exporter (openssl, data, error);
      /* fall through */
    default:
      /* Anyone to implement tls-unique-for-telnet? */
      g_set_error (error, G_TLS_CHANNEL_BINDING_ERROR, G_TLS_CHANNEL_BINDING_ERROR_NOT_IMPLEMENTED,
                   _("Requested channel binding type is not implemented"));
    }
  return FALSE;
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
  base_class->get_channel_binding_data                   = g_tls_connection_openssl_get_channel_binding_data;
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
