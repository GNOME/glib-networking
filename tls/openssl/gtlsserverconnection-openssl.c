/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlsserverconnection-openssl.c
 *
 * Copyright (C) 2015 NICE s.r.l.
 * Copyright 2019 Igalia S.L.
 * Copyright 2019 Metrological Group B.V.
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

#include "openssl-include.h"
#include <glib/gi18n-lib.h>

struct _GTlsServerConnectionOpenssl
{
  GTlsConnectionOpenssl parent_instance;

  GTlsAuthenticationMode authentication_mode;
};

enum
{
  PROP_0,
  PROP_AUTHENTICATION_MODE
};

static void g_tls_server_connection_openssl_initable_interface_init (GInitableIface  *iface);

static void g_tls_server_connection_openssl_server_connection_interface_init (GTlsServerConnectionInterface *iface);

static GInitableIface *g_tls_server_connection_openssl_parent_initable_iface;

G_DEFINE_TYPE_WITH_CODE (GTlsServerConnectionOpenssl, g_tls_server_connection_openssl, G_TYPE_TLS_CONNECTION_OPENSSL,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                g_tls_server_connection_openssl_initable_interface_init)
                         G_IMPLEMENT_INTERFACE (G_TYPE_TLS_SERVER_CONNECTION,
                                                g_tls_server_connection_openssl_server_connection_interface_init))


static void
g_tls_server_connection_openssl_get_property (GObject    *object,
                                              guint       prop_id,
                                              GValue     *value,
                                              GParamSpec *pspec)
{
  GTlsServerConnectionOpenssl *openssl = G_TLS_SERVER_CONNECTION_OPENSSL (object);

  switch (prop_id)
    {
    case PROP_AUTHENTICATION_MODE:
      g_value_set_enum (value, openssl->authentication_mode);
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

  switch (prop_id)
    {
    case PROP_AUTHENTICATION_MODE:
      openssl->authentication_mode = g_value_get_enum (value);
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

static void
g_tls_server_connection_openssl_prepare_handshake (GTlsConnectionBase  *tls,
                                                   gchar              **advertised_protocols)
{
  GTlsServerConnectionOpenssl *openssl = G_TLS_SERVER_CONNECTION_OPENSSL (tls);
  GTlsConnectionBaseClass *base_class = G_TLS_CONNECTION_BASE_CLASS (g_tls_server_connection_openssl_parent_class);
  int req_mode = 0;

  switch (openssl->authentication_mode)
    {
    case G_TLS_AUTHENTICATION_REQUIRED:
      req_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
      break;
    case G_TLS_AUTHENTICATION_REQUESTED:
      req_mode = SSL_VERIFY_PEER;
      break;
    case G_TLS_AUTHENTICATION_NONE:
    default:
      req_mode = SSL_VERIFY_NONE;
      break;
    }

  SSL_set_verify (openssl->ssl, req_mode, verify_callback);
  /* FIXME: is this ok? */
  SSL_set_verify_depth (openssl->ssl, 0);

  if (base_class->prepare_handshake)
    base_class->prepare_handshake (tls, advertised_protocols);
}

static SSL *
g_tls_server_connection_openssl_get_ssl (GTlsConnectionOpenssl *connection)
{
  return G_TLS_SERVER_CONNECTION_OPENSSL (connection)->ssl;
}

#if OPENSSL_VERSION_NUMBER < 0x10002000L
static gboolean
ssl_ctx_set_certificate (SSL_CTX          *ssl_ctx,
                         GTlsCertificate  *cert,
                         GError          **error)
{
  EVP_PKEY *key;
  X509 *x;
  GTlsCertificate *issuer;

  key = g_tls_certificate_openssl_get_key (G_TLS_CERTIFICATE_OPENSSL (cert));

  if (!key)
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                           _("Certificate has no private key"));
      return FALSE;
    }

  if (SSL_CTX_use_PrivateKey (ssl_ctx, key) <= 0)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                   _("There is a problem with the certificate private key: %s"),
                   ERR_error_string (ERR_get_error (), NULL));
     return FALSE;
    }

  x = g_tls_certificate_openssl_get_cert (G_TLS_CERTIFICATE_OPENSSL (cert));
  if (SSL_CTX_use_certificate (ssl_ctx, x) <= 0)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                   _("There is a problem with the certificate: %s"),
                   ERR_error_string (ERR_get_error (), NULL));
      return FALSE;
    }

  /* Add all the issuers to create the full certificate chain */
  for (issuer = g_tls_certificate_get_issuer (G_TLS_CERTIFICATE (cert));
       issuer;
       issuer = g_tls_certificate_get_issuer (issuer))
    {
      X509 *issuer_x;

      /* Be careful here and duplicate the certificate since the context
      * will take the ownership
       */
      issuer_x = X509_dup (g_tls_certificate_openssl_get_cert (G_TLS_CERTIFICATE_OPENSSL (issuer)));
      if (!SSL_CTX_add_extra_chain_cert (ssl_ctx, issuer_x))
        g_warning ("There was a problem adding the extra chain certificate: %s",
                   ERR_error_string (ERR_get_error (), NULL));
    }
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10002000L || defined (LIBRESSL_VERSION_NUMBER)
static gboolean
ssl_set_certificate (SSL              *ssl,
                     GTlsCertificate  *cert,
                     GError          **error)
{
  EVP_PKEY *key;
  X509 *x;
  GTlsCertificate *issuer;

  key = g_tls_certificate_openssl_get_key (G_TLS_CERTIFICATE_OPENSSL (cert));

  if (!key)
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                           _("Certificate has no private key"));
      return FALSE;
    }

  /* Note, order is important. If a certificate has been set previously,
   * OpenSSL requires that the new certificate is set _before_ the new
   * private key is set. */
  x = g_tls_certificate_openssl_get_cert (G_TLS_CERTIFICATE_OPENSSL (cert));
  if (SSL_use_certificate (ssl, x) <= 0)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                   _("There is a problem with the certificate: %s"),
                   ERR_error_string (ERR_get_error (), NULL));
      return FALSE;
    }

  if (SSL_use_PrivateKey (ssl, key) <= 0)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                   _("There is a problem with the certificate private key: %s"),
                   ERR_error_string (ERR_get_error (), NULL));
      return FALSE;
    }

  if (SSL_clear_chain_certs (ssl) == 0)
    g_warning ("There was a problem clearing the chain certificates: %s",
               ERR_error_string (ERR_get_error (), NULL));

  /* Add all the issuers to create the full certificate chain */
  for (issuer = g_tls_certificate_get_issuer (G_TLS_CERTIFICATE (cert));
       issuer;
       issuer = g_tls_certificate_get_issuer (issuer))
    {
      X509 *issuer_x;

      issuer_x = g_tls_certificate_openssl_get_cert (G_TLS_CERTIFICATE_OPENSSL (issuer));

      /* Be careful here and duplicate the certificate since the ssl object
       * will take the ownership
       */
      if (SSL_add1_chain_cert (ssl, issuer_x) == 0)
        g_warning ("There was a problem adding the chain certificate: %s",
                   ERR_error_string (ERR_get_error (), NULL));
    }

  return TRUE;
}

static void
on_certificate_changed (GObject    *object,
                        GParamSpec *spec,
                        gpointer    user_data)
{
  SSL *ssl;
  GTlsCertificate *cert;

  ssl = g_tls_server_connection_openssl_get_ssl (G_TLS_CONNECTION_OPENSSL (object));
  cert = g_tls_connection_get_certificate (G_TLS_CONNECTION (object));

  if (ssl && cert)
    ssl_set_certificate (ssl, cert, NULL);
}
#endif

static void
g_tls_server_connection_openssl_class_init (GTlsServerConnectionOpensslClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsConnectionBaseClass *base_class = G_TLS_CONNECTION_BASE_CLASS (klass);
  GTlsConnectionOpensslClass *connection_class = G_TLS_CONNECTION_OPENSSL_CLASS (klass);

  gobject_class->get_property = g_tls_server_connection_openssl_get_property;
  gobject_class->set_property = g_tls_server_connection_openssl_set_property;

  base_class->prepare_handshake = g_tls_server_connection_openssl_prepare_handshake;

  connection_class->get_ssl = g_tls_server_connection_openssl_get_ssl;

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

  if (!g_tls_server_connection_openssl_parent_initable_iface->init (initable, cancellable, error))
    return FALSE;

// FIXME: remove this
#if OPENSSL_VERSION_NUMBER >= 0x10002000L || defined (LIBRESSL_VERSION_NUMBER)
  g_signal_connect (server, "notify::certificate", G_CALLBACK (on_certificate_changed), NULL);
#endif

  return TRUE;
}

static void
g_tls_server_connection_openssl_initable_interface_init (GInitableIface  *iface)
{
  g_tls_server_connection_openssl_parent_initable_iface = g_type_interface_peek_parent (iface);

  iface->init = g_tls_server_connection_openssl_initable_init;
}
