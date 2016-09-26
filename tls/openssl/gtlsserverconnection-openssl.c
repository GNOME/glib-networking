/*
 * gtlsserverconnection-openssl.c
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
#include "gtlsserverconnection-openssl.h"
#include "gtlscertificate-openssl.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <glib/gi18n-lib.h>

typedef struct _GTlsServerConnectionOpensslPrivate
{
  GTlsAuthenticationMode authentication_mode;
  SSL_SESSION *session;
  SSL *ssl;
  SSL_CTX *ssl_ctx;
} GTlsServerConnectionOpensslPrivate;

enum
{
  PROP_0,
  PROP_AUTHENTICATION_MODE
};

static void g_tls_server_connection_openssl_initable_interface_init (GInitableIface  *iface);

static void g_tls_server_connection_openssl_server_connection_interface_init (GTlsServerConnectionInterface *iface);

static GInitableIface *g_tls_server_connection_openssl_parent_initable_iface;

G_DEFINE_TYPE_WITH_CODE (GTlsServerConnectionOpenssl, g_tls_server_connection_openssl, G_TYPE_TLS_CONNECTION_OPENSSL,
                         G_ADD_PRIVATE (GTlsServerConnectionOpenssl)
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                g_tls_server_connection_openssl_initable_interface_init)
                         G_IMPLEMENT_INTERFACE (G_TYPE_TLS_SERVER_CONNECTION,
                                                g_tls_server_connection_openssl_server_connection_interface_init))

static void
g_tls_server_connection_openssl_finalize (GObject *object)
{
  GTlsServerConnectionOpenssl *openssl = G_TLS_SERVER_CONNECTION_OPENSSL (object);
  GTlsServerConnectionOpensslPrivate *priv;

  priv = g_tls_server_connection_openssl_get_instance_private (openssl);

  SSL_free (priv->ssl);
  SSL_CTX_free (priv->ssl_ctx);
  SSL_SESSION_free (priv->session);

  G_OBJECT_CLASS (g_tls_server_connection_openssl_parent_class)->finalize (object);
}

static void
g_tls_server_connection_openssl_get_property (GObject    *object,
                                              guint       prop_id,
                                              GValue     *value,
                                              GParamSpec *pspec)
{
  GTlsServerConnectionOpenssl *openssl = G_TLS_SERVER_CONNECTION_OPENSSL (object);
  GTlsServerConnectionOpensslPrivate *priv;

  priv = g_tls_server_connection_openssl_get_instance_private (openssl);

  switch (prop_id)
    {
    case PROP_AUTHENTICATION_MODE:
      g_value_set_enum (value, priv->authentication_mode);
      break;
      
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_server_connection_openssl_set_property (GObject      *object,
                                              guint         prop_id,
                                              const GValue *value,
                                              GParamSpec   *pspec)
{
  GTlsServerConnectionOpenssl *openssl = G_TLS_SERVER_CONNECTION_OPENSSL (object);
  GTlsServerConnectionOpensslPrivate *priv;

  priv = g_tls_server_connection_openssl_get_instance_private (openssl);

  switch (prop_id)
    {
    case PROP_AUTHENTICATION_MODE:
      priv->authentication_mode = g_value_get_enum (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static int
verify_callback (int             preverify_ok,
                 X509_STORE_CTX *ctx)
{
  return 1;
}

static GTlsConnectionBaseStatus
g_tls_server_connection_openssl_handshake (GTlsConnectionBase  *tls,
                                           GCancellable        *cancellable,
                                           GError             **error)
{
  GTlsServerConnectionOpenssl *openssl = G_TLS_SERVER_CONNECTION_OPENSSL (tls);
  GTlsServerConnectionOpensslPrivate *priv;
  int req_mode = 0;

  priv = g_tls_server_connection_openssl_get_instance_private (openssl);

  switch (priv->authentication_mode)
    {
    case G_TLS_AUTHENTICATION_REQUIRED:
      req_mode = SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    case G_TLS_AUTHENTICATION_REQUESTED:
      req_mode |= SSL_VERIFY_PEER;
      break;
    case G_TLS_AUTHENTICATION_NONE:
    default:
      req_mode = SSL_VERIFY_NONE;
      break;
    }

  SSL_set_verify (priv->ssl, req_mode, verify_callback);
  /* FIXME: is this ok? */
  SSL_set_verify_depth (priv->ssl, 0);

  return G_TLS_CONNECTION_BASE_CLASS (g_tls_server_connection_openssl_parent_class)->
    handshake (tls, cancellable, error);
}

static SSL *
g_tls_server_connection_openssl_get_ssl (GTlsConnectionOpenssl *connection)
{
  GTlsServerConnectionOpenssl *server = G_TLS_SERVER_CONNECTION_OPENSSL (connection);
  GTlsServerConnectionOpensslPrivate *priv;

  priv = g_tls_server_connection_openssl_get_instance_private (server);

  return priv->ssl;
}

static SSL_CTX *
g_tls_server_connection_openssl_get_ssl_ctx (GTlsConnectionOpenssl *connection)
{
  GTlsServerConnectionOpenssl *server = G_TLS_SERVER_CONNECTION_OPENSSL (connection);
  GTlsServerConnectionOpensslPrivate *priv;

  priv = g_tls_server_connection_openssl_get_instance_private (server);

  return priv->ssl_ctx;
}

static void
g_tls_server_connection_openssl_class_init (GTlsServerConnectionOpensslClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsConnectionBaseClass *base_class = G_TLS_CONNECTION_BASE_CLASS (klass);
  GTlsConnectionOpensslClass *connection_class = G_TLS_CONNECTION_OPENSSL_CLASS (klass);

  gobject_class->finalize = g_tls_server_connection_openssl_finalize;
  gobject_class->get_property = g_tls_server_connection_openssl_get_property;
  gobject_class->set_property = g_tls_server_connection_openssl_set_property;

  base_class->handshake = g_tls_server_connection_openssl_handshake;

  connection_class->get_ssl = g_tls_server_connection_openssl_get_ssl;
  connection_class->get_ssl_ctx = g_tls_server_connection_openssl_get_ssl_ctx;

  g_object_class_override_property (gobject_class, PROP_AUTHENTICATION_MODE, "authentication-mode");
}

static void
g_tls_server_connection_openssl_init (GTlsServerConnectionOpenssl *openssl)
{
}

static void
g_tls_server_connection_openssl_server_connection_interface_init (GTlsServerConnectionInterface *iface)
{
}

static gboolean
g_tls_server_connection_openssl_initable_init (GInitable       *initable,
                                               GCancellable    *cancellable,
                                               GError         **error)
{
  GTlsServerConnectionOpenssl *server = G_TLS_SERVER_CONNECTION_OPENSSL (initable);
  GTlsServerConnectionOpensslPrivate *priv;
  GTlsCertificate *cert;
  long options;

  priv = g_tls_server_connection_openssl_get_instance_private (server);

  priv->session = SSL_SESSION_new ();

  priv->ssl_ctx = SSL_CTX_new (SSLv23_server_method ());
  if (priv->ssl_ctx == NULL)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Could not create TLS context: %s"),
                   ERR_error_string (ERR_get_error (), NULL));
      return FALSE;
    }

  options = SSL_OP_NO_TICKET;

  /* Only TLS 1.2 or higher */
  SSL_CTX_set_options (priv->ssl_ctx, options);

  cert = g_tls_connection_get_certificate (G_TLS_CONNECTION (initable));
  if (cert != NULL)
    {
      EVP_PKEY *key;
      X509 *x;
      GTlsCertificate *issuer;

      key = g_tls_certificate_openssl_get_key (G_TLS_CERTIFICATE_OPENSSL (cert));

      if (key == NULL)
        {
          g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                               _("Certificate has no private key"));
          return FALSE;
        }

      if (SSL_CTX_use_PrivateKey (priv->ssl_ctx, key) <= 0)
        {
          g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                       _("There is a problem with the certificate private key: %s"),
                       ERR_error_string (ERR_get_error (), NULL));
          return FALSE;
        }

      x = g_tls_certificate_openssl_get_cert (G_TLS_CERTIFICATE_OPENSSL (cert));
      if (SSL_CTX_use_certificate (priv->ssl_ctx, x) <= 0)
        {
          g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                       _("There is a problem with the certificate: %s"),
                       ERR_error_string (ERR_get_error (), NULL));
          return FALSE;
        }

      /* Add all the issuers to create the full certificate chain */
      for (issuer = g_tls_certificate_get_issuer (G_TLS_CERTIFICATE (cert));
           issuer != NULL;
           issuer = g_tls_certificate_get_issuer (issuer))
        {
          X509 *issuer_x;

          /* Be careful here and duplicate the certificate since the context
           * will take the ownership
           */
          issuer_x = X509_dup (g_tls_certificate_openssl_get_cert (G_TLS_CERTIFICATE_OPENSSL (issuer)));
          if (!SSL_CTX_add_extra_chain_cert (priv->ssl_ctx, issuer_x))
            g_warning ("There was a problem adding the extra chain certificate: %s",
                       ERR_error_string (ERR_get_error (), NULL));
        }
    }

  SSL_CTX_add_session (priv->ssl_ctx, priv->session);

  SSL_CTX_set_cipher_list (priv->ssl_ctx, "HIGH:!DSS:!aNULL@STRENGTH");

  priv->ssl = SSL_new (priv->ssl_ctx);
  if (priv->ssl == NULL)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Could not create TLS connection: %s"),
                   ERR_error_string (ERR_get_error (), NULL));
      return FALSE;
    }

  SSL_set_accept_state (priv->ssl);

  if (!g_tls_server_connection_openssl_parent_initable_iface->
      init (initable, cancellable, error))
    return FALSE;

  return TRUE;
}

static void
g_tls_server_connection_openssl_initable_interface_init (GInitableIface  *iface)
{
  g_tls_server_connection_openssl_parent_initable_iface = g_type_interface_peek_parent (iface);

  iface->init = g_tls_server_connection_openssl_initable_init;
}
