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
#include "gtlsfiledatabase-openssl.h"
#include "gtlsbio.h"

#include <glib/gi18n-lib.h>

typedef struct _GTlsConnectionOpensslPrivate
{
  BIO *bio;

  GTlsCertificate *peer_certificate_tmp;
  GTlsCertificateFlags peer_certificate_errors_tmp;

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

  g_clear_object (&priv->peer_certificate_tmp);

  G_OBJECT_CLASS (g_tls_connection_openssl_parent_class)->finalize (object);
}

static GTlsConnectionBaseStatus
end_openssl_io (GTlsConnectionOpenssl  *openssl,
                GIOCondition           direction,
                int                    ret,
                GError               **error,
                const char            *err_fmt,
                ...) G_GNUC_PRINTF(5, 6);

static GTlsConnectionBaseStatus
end_openssl_io (GTlsConnectionOpenssl  *openssl,
                GIOCondition            direction,
                int                     ret,
                GError                **error,
                const char             *err_fmt,
                ...)
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

  /* NOTE: this is tricky! The tls bio will set to retry if the operation
   * would block, and we would get an error code with WANT_READ or WANT_WRITE,
   * though if in that case we try again we would end up in an infinite loop
   * since we will not let the glib main loop to do its stuff and we would
   * be getting a would block forever. Instead we need to also check the error
   * we get from the socket operation to understand whether to try again. See
   * that we propagate the WOULD_BLOCK error a bit more down.
   */
  if ((err_code == SSL_ERROR_WANT_READ ||
       err_code == SSL_ERROR_WANT_WRITE) &&
      status != G_TLS_CONNECTION_BASE_WOULD_BLOCK)
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
  if (err_code == SSL_ERROR_SYSCALL && priv->shutting_down && !my_error)
    return G_TLS_CONNECTION_BASE_OK;

  err = ERR_get_error ();
  err_lib = ERR_GET_LIB (err);
  reason = ERR_GET_REASON (err);

  if (tls->handshaking && !tls->ever_handshaked)
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
          g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_NOT_TLS,
                               _("Peer failed to perform TLS handshake"));
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

  if (reason == SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE)
    {
      g_clear_error (&my_error);
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED,
                           _("TLS connection peer did not send a certificate"));
      return status;
    }

  if (err_lib == ERR_LIB_RSA && reason == RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY)
    {
      g_clear_error (&my_error);
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                           _("Digest too big for RSA key"));
      return G_TLS_CONNECTION_BASE_ERROR;
    }

  if (my_error != NULL)
    g_propagate_error (error, my_error);
  else
    /* FIXME: this is just for debug */
    g_message ("end_openssl_io %s: %d, %d, %d", G_IS_TLS_CLIENT_CONNECTION (openssl) ? "client" : "server", err_code, err_lib, reason);

  if (error && !*error)
    {
      va_list ap;

      va_start (ap, err_fmt);
      *error = g_error_new_valist (G_TLS_ERROR, G_TLS_ERROR_MISC, err_fmt, ap);
      va_end (ap);
    }

  return G_TLS_CONNECTION_BASE_ERROR;
}

#define BEGIN_OPENSSL_IO(openssl, direction, blocking, cancellable)        \
  g_tls_connection_base_push_io (G_TLS_CONNECTION_BASE (openssl),        \
                                 direction, blocking, cancellable);        \
  do {                                                                      \
    char error_str[256];

#define END_OPENSSL_IO(openssl, direction, ret, status, errmsg, err)        \
    ERR_error_string_n (SSL_get_error (ssl, ret), error_str, sizeof(error_str)); \
    status = end_openssl_io (openssl, direction, ret, err, errmsg, error_str); \
  } while (status == G_TLS_CONNECTION_BASE_TRY_AGAIN);

static GTlsConnectionBaseStatus
g_tls_connection_openssl_request_rehandshake (GTlsConnectionBase  *tls,
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

  if (tls->rehandshake_mode == G_TLS_REHANDSHAKE_NEVER)
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                           _("Peer requested illegal TLS rehandshake"));
      return G_TLS_CONNECTION_BASE_ERROR;
    }

  ssl = g_tls_connection_openssl_get_ssl (openssl);

  BEGIN_OPENSSL_IO (openssl, G_IO_IN | G_IO_OUT, TRUE, cancellable);
  ret = SSL_renegotiate (ssl);
  END_OPENSSL_IO (openssl, G_IO_IN | G_IO_OUT, ret, status,
                  _("Error performing TLS handshake: %s"), error);

  return status;
}

static GTlsCertificate *
get_peer_certificate (GTlsConnectionOpenssl *openssl)
{
  X509 *peer;
  STACK_OF (X509) *certs;
  GTlsCertificateOpenssl *chain;
  SSL *ssl;

  ssl = g_tls_connection_openssl_get_ssl (openssl);

  peer = SSL_get_peer_certificate (ssl);
  if (peer == NULL)
    return NULL;

  certs = SSL_get_peer_cert_chain (ssl);
  if (certs == NULL)
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

static GTlsCertificateFlags
verify_ocsp_response (GTlsConnectionOpenssl *openssl,
                      GTlsDatabase          *database,
                      GTlsCertificate       *peer_certificate)
{
#if (OPENSSL_VERSION_NUMBER >= 0x0090808fL) && !defined(OPENSSL_NO_TLSEXT) && \
  !defined(OPENSSL_NO_OCSP)
  SSL *ssl = NULL;
  OCSP_RESPONSE *resp = NULL;
  long len = 0;
  const unsigned char *p = NULL;

  ssl = g_tls_connection_openssl_get_ssl (openssl);
  len = SSL_get_tlsext_status_ocsp_resp (ssl, &p);
  /* Soft fail in case of no response is the best we can do */
  if (p == NULL)
    return 0;

  resp = d2i_OCSP_RESPONSE (NULL, &p, len);
  if (resp == NULL)
    return G_TLS_CERTIFICATE_GENERIC_ERROR;

  return g_tls_file_database_openssl_verify_ocsp_response (database,
                                                           peer_certificate,
                                                           resp);
#else
  return 0;
#endif
}

static GTlsCertificateFlags
verify_peer_certificate (GTlsConnectionOpenssl *openssl,
                         GTlsCertificate       *peer_certificate)
{
  GTlsConnection *conn = G_TLS_CONNECTION (openssl);
  GSocketConnectable *peer_identity;
  GTlsDatabase *database;
  GTlsCertificateFlags errors;
  gboolean is_client;

  is_client = G_IS_TLS_CLIENT_CONNECTION (openssl);
  if (is_client)
    peer_identity = g_tls_client_connection_get_server_identity (G_TLS_CLIENT_CONNECTION (openssl));
  else
    peer_identity = NULL;

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

  if (is_client && (errors == 0))
    errors = verify_ocsp_response (openssl, database, peer_certificate);

  return errors;
}

static GTlsConnectionBaseStatus
g_tls_connection_openssl_handshake (GTlsConnectionBase  *tls,
                                    GCancellable        *cancellable,
                                    GError             **error)
{
  GTlsConnectionOpenssl *openssl = G_TLS_CONNECTION_OPENSSL (tls);
  GTlsConnectionOpensslPrivate *priv;
  GTlsConnectionBaseStatus status;
  SSL *ssl;
  int ret;

  priv = g_tls_connection_openssl_get_instance_private (openssl);

  ssl = g_tls_connection_openssl_get_ssl (openssl);

  BEGIN_OPENSSL_IO (openssl, G_IO_IN | G_IO_OUT, TRUE, cancellable);
  ret = SSL_do_handshake (ssl);
  END_OPENSSL_IO (openssl, G_IO_IN | G_IO_OUT, ret, status,
                  _("Error performing TLS handshake: %s"), error);

  if (ret > 0)
    {
      priv->peer_certificate_tmp = get_peer_certificate (openssl);
      if (priv->peer_certificate_tmp)
        priv->peer_certificate_errors_tmp = verify_peer_certificate (openssl, priv->peer_certificate_tmp);
      else if (G_IS_TLS_CLIENT_CONNECTION (openssl))
        {
          g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                               _("Server did not return a valid TLS certificate"));
        }
    }

  return status;
}

static GTlsConnectionBaseStatus
g_tls_connection_openssl_complete_handshake (GTlsConnectionBase  *tls,
                                             GError             **error)
{
  GTlsConnectionOpenssl *openssl = G_TLS_CONNECTION_OPENSSL (tls);
  GTlsConnectionOpensslPrivate *priv;
  GTlsCertificate *peer_certificate;
  GTlsCertificateFlags peer_certificate_errors = 0;
  GTlsConnectionBaseStatus status = G_TLS_CONNECTION_BASE_OK;

  priv = g_tls_connection_openssl_get_instance_private (openssl);

  peer_certificate = priv->peer_certificate_tmp;
  priv->peer_certificate_tmp = NULL;
  peer_certificate_errors = priv->peer_certificate_errors_tmp;
  priv->peer_certificate_errors_tmp = 0;

  if (peer_certificate)
    {
      if (!g_tls_connection_base_accept_peer_certificate (tls, peer_certificate,
                                                          peer_certificate_errors))
        {
          g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                               _("Unacceptable TLS certificate"));
          status = G_TLS_CONNECTION_BASE_ERROR;
        }

      g_tls_connection_base_set_peer_certificate (G_TLS_CONNECTION_BASE (openssl),
                                                  peer_certificate,
                                                  peer_certificate_errors);
      g_clear_object (&peer_certificate);
    }

  return status;
}

static void
g_tls_connection_openssl_push_io (GTlsConnectionBase *tls,
                                  GIOCondition        direction,
                                  gboolean            blocking,
                                  GCancellable       *cancellable)
{
  GTlsConnectionOpenssl *openssl = G_TLS_CONNECTION_OPENSSL (tls);
  GTlsConnectionOpensslPrivate *priv;

  priv = g_tls_connection_openssl_get_instance_private (openssl);

  G_TLS_CONNECTION_BASE_CLASS (g_tls_connection_openssl_parent_class)->push_io (tls, direction,
                                                                                blocking, cancellable);

  if (direction & G_IO_IN)
    {
      g_tls_bio_set_read_cancellable (priv->bio, cancellable);
      g_tls_bio_set_read_blocking (priv->bio, blocking);
      g_clear_error (&tls->read_error);
      g_tls_bio_set_read_error (priv->bio, &tls->read_error);
    }

  if (direction & G_IO_OUT)
    {
      g_tls_bio_set_write_cancellable (priv->bio, cancellable);
      g_tls_bio_set_write_blocking (priv->bio, blocking);
      g_clear_error (&tls->write_error);
      g_tls_bio_set_write_error (priv->bio, &tls->write_error);
    }
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
                               gboolean               blocking,
                               gssize                *nread,
                               GCancellable          *cancellable,
                               GError               **error)
{
  GTlsConnectionOpenssl *openssl = G_TLS_CONNECTION_OPENSSL (tls);
  GTlsConnectionBaseStatus status;
  SSL *ssl;
  gssize ret;

  ssl = g_tls_connection_openssl_get_ssl (openssl);

  BEGIN_OPENSSL_IO (openssl, G_IO_IN, blocking, cancellable);
  ret = SSL_read (ssl, buffer, count);
  END_OPENSSL_IO (openssl, G_IO_IN, ret, status,
                  _("Error reading data from TLS socket: %s"), error);

  if (ret >= 0)
    *nread = ret;
  return status;
}

static GTlsConnectionBaseStatus
g_tls_connection_openssl_write (GTlsConnectionBase    *tls,
                                const void            *buffer,
                                gsize                  count,
                                gboolean               blocking,
                                gssize                *nwrote,
                                GCancellable          *cancellable,
                                GError               **error)
{
  GTlsConnectionOpenssl *openssl = G_TLS_CONNECTION_OPENSSL (tls);
  GTlsConnectionBaseStatus status;
  SSL *ssl;
  gssize ret;

  ssl = g_tls_connection_openssl_get_ssl (openssl);

  BEGIN_OPENSSL_IO (openssl, G_IO_OUT, blocking, cancellable);
  ret = SSL_write (ssl, buffer, count);
  END_OPENSSL_IO (openssl, G_IO_OUT, ret, status,
                  _("Error writing data to TLS socket: %s"), error);

  if (ret >= 0)
    *nwrote = ret;
  return status;
}

static GTlsConnectionBaseStatus
g_tls_connection_openssl_close (GTlsConnectionBase  *tls,
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

  BEGIN_OPENSSL_IO (openssl, G_IO_IN | G_IO_OUT, TRUE, cancellable);
  ret = SSL_shutdown (ssl);
  END_OPENSSL_IO (openssl, G_IO_IN | G_IO_OUT, ret, status,
                  _("Error performing TLS close: %s"), error);

  return status;
}

static void
g_tls_connection_openssl_class_init (GTlsConnectionOpensslClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsConnectionBaseClass *base_class = G_TLS_CONNECTION_BASE_CLASS (klass);

  gobject_class->finalize     = g_tls_connection_openssl_finalize;

  base_class->request_rehandshake = g_tls_connection_openssl_request_rehandshake;
  base_class->handshake           = g_tls_connection_openssl_handshake;
  base_class->complete_handshake  = g_tls_connection_openssl_complete_handshake;
  base_class->push_io             = g_tls_connection_openssl_push_io;
  base_class->pop_io              = g_tls_connection_openssl_pop_io;
  base_class->read_fn             = g_tls_connection_openssl_read;
  base_class->write_fn            = g_tls_connection_openssl_write;
  base_class->close_fn            = g_tls_connection_openssl_close;
}

static gboolean
g_tls_connection_openssl_initable_init (GInitable     *initable,
                                        GCancellable  *cancellable,
                                        GError       **error)
{
  GTlsConnectionOpenssl *openssl = G_TLS_CONNECTION_OPENSSL (initable);
  GTlsConnectionOpensslPrivate *priv;
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (initable);
  SSL *ssl;

  g_return_val_if_fail (tls->base_istream != NULL &&
                        tls->base_ostream != NULL, FALSE);

  priv = g_tls_connection_openssl_get_instance_private (openssl);

  ssl = g_tls_connection_openssl_get_ssl (openssl);
  g_assert (ssl != NULL);

  priv->bio = g_tls_bio_new (tls->base_io_stream);

  SSL_set_bio (ssl, priv->bio, priv->bio);

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
}

SSL *
g_tls_connection_openssl_get_ssl (GTlsConnectionOpenssl *openssl)
{
  g_return_val_if_fail (G_IS_TLS_CONNECTION_OPENSSL (openssl), NULL);

  return G_TLS_CONNECTION_OPENSSL_GET_CLASS (openssl)->get_ssl (openssl);
}

SSL_CTX *
g_tls_connection_openssl_get_ssl_ctx (GTlsConnectionOpenssl *openssl)
{
  g_return_val_if_fail (G_IS_TLS_CONNECTION_OPENSSL (openssl), NULL);

  return G_TLS_CONNECTION_OPENSSL_GET_CLASS (openssl)->get_ssl_ctx (openssl);
}

gboolean
g_tls_connection_openssl_request_certificate (GTlsConnectionOpenssl  *openssl,
                                              GError                **error)
{
  GTlsInteractionResult res = G_TLS_INTERACTION_UNHANDLED;
  GTlsInteraction *interaction;
  GTlsConnection *conn;
  GTlsConnectionBase *tls;

  g_return_val_if_fail (G_IS_TLS_CONNECTION_OPENSSL (openssl), FALSE);

  conn = G_TLS_CONNECTION (openssl);
  tls = G_TLS_CONNECTION_BASE (openssl);

  interaction = g_tls_connection_get_interaction (conn);
  if (!interaction)
    return FALSE;

  res = g_tls_interaction_invoke_request_certificate (interaction, conn, 0,
						      tls->read_cancellable, error);
  return res != G_TLS_INTERACTION_FAILED;
}
