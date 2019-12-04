/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2015 NICE s.r.l.
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

#include <glib/gi18n-lib.h>

#include "gtlsconnection-openssl.h"
#include "gtlsoperationsthread-openssl.h"

struct _GTlsOperationsThreadOpenssl {
  GTlsOperationsThreadBase parent_instance;

  SSL *ssl;
};

G_DEFINE_TYPE (GTlsOperationsThreadOpenssl, g_tls_operations_thread_openssl, G_TYPE_TLS_OPERATIONS_THREAD_BASE)

static GTlsConnectionBaseStatus
end_openssl_io (GTlsOperationsThreadOpenssl  *self,
                GIOCondition                  direction,
                int                           ret,
                gboolean                      blocking,
                GError                      **error,
                const char                   *err_prefix,
                const char                   *err_str)
{
  GTlsConnectionBase *tls;
  int err_code, err, err_lib, reason;
  GError *my_error = NULL;
  GTlsConnectionBaseStatus status;

  tls = g_tls_operations_thread_base_get_connection (G_TLS_OPERATIONS_THREAD_BASE (self));

  err_code = SSL_get_error (self->ssl, ret);

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
      ((g_tls_connection_openssl_get_shutting_down (G_TLS_CONNECTION_OPENSSL (tls)) && !my_error) ||
       g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_BROKEN_PIPE)))
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
    g_message ("end_openssl_io %s: %d, %d, %d", G_IS_TLS_CLIENT_CONNECTION (tls) ? "client" : "server", err_code, err_lib, reason);

  if (error && !*error)
    *error = g_error_new (G_TLS_ERROR, G_TLS_ERROR_MISC, "%s: %s", err_prefix, err_str);

  return G_TLS_CONNECTION_BASE_ERROR;
}

#define BEGIN_OPENSSL_IO(self, direction, timeout, cancellable)          \
  do {                                                                   \
    char error_str[256];                                                 \
    g_tls_connection_base_push_io (g_tls_operations_thread_base_get_connection (G_TLS_OPERATIONS_THREAD_BASE (self)), \
                                   direction, timeout, cancellable);

#define END_OPENSSL_IO(self, direction, ret, timeout, status, errmsg, err) \
    ERR_error_string_n (SSL_get_error (self->ssl, ret), error_str, sizeof (error_str)); \
    status = end_openssl_io (self, direction, ret, timeout == -1, err, errmsg, error_str); \
  } while (status == G_TLS_CONNECTION_BASE_TRY_AGAIN);

static GTlsConnectionBaseStatus
g_tls_operations_thread_openssl_read (GTlsOperationsThreadBase   *base,
                                      void                       *buffer,
                                      gsize                       size,
                                      gssize                     *nread,
                                      GCancellable               *cancellable,
                                      GError                    **error)
{
  GTlsOperationsThreadOpenssl *self = G_TYPE_TLS_OPERATIONS_THREAD_OPENSSL (base);
  GTlsConnectionBaseStatus status;
  gssize ret;

  BEGIN_OPENSSL_IO (self, G_IO_OUT, timeout, cancellable);
  ret = SSL_write (self->ssl, buffer, count);
  END_OPENSSL_IO (self, G_IO_OUT, ret, status,
                  _("Error writing data to TLS socket"), error);


  *nread = MAX (ret, 0);
  return status;
}

static GTlsConnectionBaseStatus
g_tls_connection_openssl_write (GTlsConnectionBase    *tls,
                                const void            *buffer,
                                gsize                  size,
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

      ret = SSL_write (ssl, buffer, size);

      ERR_error_string_n (SSL_get_error (ssl, ret), error_str, sizeof (error_str));
      status = end_openssl_io (openssl, G_IO_OUT, ret, FALSE, error,
                               _("Error writing data to TLS socket"), error_str);

      if (status != G_TLS_CONNECTION_BASE_TRY_AGAIN)
        break;

      /* Wait for the socket to be available again to avoid an infinite loop */
      g_tls_bio_wait_available (priv->bio, G_IO_OUT, cancellable);
    }

  *nwrote = MAX (ret, 0);
  return status;
}

static void
g_tls_operations_thread_openssl_constructed (GObject *object)
{
  GTlsOperationsThreadOpenssl *self = G_TYPE_TLS_OPERATIONS_THREAD_OPENSSL (object);
  GTlsConnectionOpenssl *openssl;

  G_OBJECT_CLASS (g_tls_operations_thread_openssl_parent_class)->constructed (object);

  openssl = g_tls_operations_thread_base_get_connection (G_TLS_OPERATIONS_THREAD_BASE (self));
  self->ssl = g_tls_connection_openssl_get_ssl (openssl);
}

static void
g_tls_operations_thread_openssl_init (GTlsOperationsThreadOpenssl *self)
{
}

static void
g_tls_operations_thread_openssl_class_init (GTlsOperationsThreadOpensslClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsOperationsThreadBaseClass *base_class = G_TLS_OPERATIONS_THREAD_BASE_CLASS (klass);

  gobject_class->constructed = g_tls_operations_thread_openssl_constructed;

  base_class->read_fn        = g_tls_operations_thread_openssl_read;
  base_class->write_fn       = g_tls_operations_thread_openssl_write;
}

GTlsOperationsThreadBase *
g_tls_operations_thread_openssl_new (GTlsConnectionOpenssl *tls)
{
  return G_TLS_OPERATIONS_THREAD_BASE (g_object_new (G_TYPE_TLS_OPERATIONS_THREAD_OPENSSL,
                                       "tls-connection", tls,
                                       NULL));
}
