/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlsclientconnection-openssl.c
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
#include <string.h>

#include "openssl-include.h"
#include "gtlsconnection-base.h"
#include "gtlsclientconnection-openssl.h"
#include "gtlsbackend-openssl.h"
#include "gtlscertificate-openssl.h"
#include <glib/gi18n-lib.h>

struct _GTlsClientConnectionOpenssl
{
  GTlsConnectionOpenssl parent_instance;

  GTlsCertificateFlags validation_flags;
  GSocketConnectable *server_identity;
  gboolean use_ssl3;

  STACK_OF (X509_NAME) *ca_list;

  SSL_SESSION *session;
  SSL *ssl;
  SSL_CTX *ssl_ctx;
};

enum
{
  PROP_0,
  PROP_VALIDATION_FLAGS,
  PROP_SERVER_IDENTITY,
  PROP_USE_SSL3,
  PROP_ACCEPTED_CAS
};

static void g_tls_client_connection_openssl_initable_interface_init (GInitableIface  *iface);

static void g_tls_client_connection_openssl_client_connection_interface_init (GTlsClientConnectionInterface *iface);

static GInitableIface *g_tls_client_connection_openssl_parent_initable_iface;

G_DEFINE_TYPE_WITH_CODE (GTlsClientConnectionOpenssl, g_tls_client_connection_openssl, G_TYPE_TLS_CONNECTION_OPENSSL,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                g_tls_client_connection_openssl_initable_interface_init)
                         G_IMPLEMENT_INTERFACE (G_TYPE_TLS_CLIENT_CONNECTION,
                                                g_tls_client_connection_openssl_client_connection_interface_init))

static void
g_tls_client_connection_openssl_finalize (GObject *object)
{
  GTlsClientConnectionOpenssl *openssl = G_TLS_CLIENT_CONNECTION_OPENSSL (object);

  g_clear_object (&openssl->server_identity);

  SSL_free (openssl->ssl);
  SSL_CTX_free (openssl->ssl_ctx);
  SSL_SESSION_free (openssl->session);

  G_OBJECT_CLASS (g_tls_client_connection_openssl_parent_class)->finalize (object);
}

static const gchar *
get_server_identity (GTlsClientConnectionOpenssl *openssl)
{
  if (G_IS_NETWORK_ADDRESS (openssl->server_identity))
    return g_network_address_get_hostname (G_NETWORK_ADDRESS (openssl->server_identity));
  else if (G_IS_NETWORK_SERVICE (openssl->server_identity))
    return g_network_service_get_domain (G_NETWORK_SERVICE (openssl->server_identity));
  else
    return NULL;
}

static void
g_tls_client_connection_openssl_get_property (GObject    *object,
                                             guint       prop_id,
                                             GValue     *value,
                                             GParamSpec *pspec)
{
  GTlsClientConnectionOpenssl *openssl = G_TLS_CLIENT_CONNECTION_OPENSSL (object);
  GList *accepted_cas;
  gint i;

  switch (prop_id)
    {
    case PROP_VALIDATION_FLAGS:
      g_value_set_flags (value, openssl->validation_flags);
      break;

    case PROP_SERVER_IDENTITY:
      g_value_set_object (value, openssl->server_identity);
      break;

    case PROP_USE_SSL3:
      g_value_set_boolean (value, openssl->use_ssl3);
      break;

    case PROP_ACCEPTED_CAS:
      accepted_cas = NULL;
      if (openssl->ca_list)
        {
          for (i = 0; i < sk_X509_NAME_num (openssl->ca_list); ++i)
            {
              int size;

              size = i2d_X509_NAME (sk_X509_NAME_value (openssl->ca_list, i), NULL);
              if (size > 0)
                {
                  unsigned char *ca;

                  ca = g_malloc (size);
                  size = i2d_X509_NAME (sk_X509_NAME_value (openssl->ca_list, i), &ca);
                  if (size > 0)
                    accepted_cas = g_list_prepend (accepted_cas, g_byte_array_new_take (
                                                   ca, size));
                  else
                    g_free (ca);
                }
            }
          accepted_cas = g_list_reverse (accepted_cas);
        }
      g_value_set_pointer (value, accepted_cas);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_client_connection_openssl_set_property (GObject      *object,
                                             guint         prop_id,
                                             const GValue *value,
                                             GParamSpec   *pspec)
{
  GTlsClientConnectionOpenssl *openssl = G_TLS_CLIENT_CONNECTION_OPENSSL (object);

  switch (prop_id)
    {
    case PROP_VALIDATION_FLAGS:
      openssl->validation_flags = g_value_get_flags (value);
      break;

    case PROP_SERVER_IDENTITY:
      if (openssl->server_identity)
        g_object_unref (openssl->server_identity);
      openssl->server_identity = g_value_dup_object (value);
      break;

    case PROP_USE_SSL3:
      openssl->use_ssl3 = g_value_get_boolean (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_client_connection_openssl_complete_handshake (GTlsConnectionBase  *tls,
                                                    gboolean             handshake_succeeded,
                                                    gchar              **negotiated_protocol,
                                                    GError             **error)
{
  GTlsClientConnectionOpenssl *client = G_TLS_CLIENT_CONNECTION_OPENSSL (tls);

  if (G_TLS_CONNECTION_BASE_CLASS (g_tls_client_connection_openssl_parent_class)->complete_handshake)
    G_TLS_CONNECTION_BASE_CLASS (g_tls_client_connection_openssl_parent_class)->complete_handshake (tls, handshake_succeeded, negotiated_protocol, error);

  /* It may have changed during the handshake, but we have to wait until here
   * because we can't emit notifies on the handshake thread.
   */
  g_object_notify (G_OBJECT (client), "accepted-cas");
}

static SSL *
g_tls_client_connection_openssl_get_ssl (GTlsConnectionOpenssl *connection)
{
  return G_TLS_CLIENT_CONNECTION_OPENSSL (connection)->ssl;
}

static void
g_tls_client_connection_openssl_class_init (GTlsClientConnectionOpensslClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsConnectionBaseClass *base_class = G_TLS_CONNECTION_BASE_CLASS (klass);
  GTlsConnectionOpensslClass *openssl_class = G_TLS_CONNECTION_OPENSSL_CLASS (klass);

  gobject_class->finalize             = g_tls_client_connection_openssl_finalize;
  gobject_class->get_property         = g_tls_client_connection_openssl_get_property;
  gobject_class->set_property         = g_tls_client_connection_openssl_set_property;

  base_class->complete_handshake      = g_tls_client_connection_openssl_complete_handshake;

  openssl_class->get_ssl              = g_tls_client_connection_openssl_get_ssl;

  g_object_class_override_property (gobject_class, PROP_VALIDATION_FLAGS, "validation-flags");
  g_object_class_override_property (gobject_class, PROP_SERVER_IDENTITY, "server-identity");
  g_object_class_override_property (gobject_class, PROP_USE_SSL3, "use-ssl3");
  g_object_class_override_property (gobject_class, PROP_ACCEPTED_CAS, "accepted-cas");
}

static void
g_tls_client_connection_openssl_init (GTlsClientConnectionOpenssl *openssl)
{
}

static void
g_tls_client_connection_openssl_copy_session_state (GTlsClientConnection *conn,
                                                    GTlsClientConnection *source)
{
}

static void
g_tls_client_connection_openssl_client_connection_interface_init (GTlsClientConnectionInterface *iface)
{
  iface->copy_session_state = g_tls_client_connection_openssl_copy_session_state;
}

static int data_index = -1;

static int
handshake_thread_retrieve_certificate (SSL       *ssl,
                                       X509     **x509,
                                       EVP_PKEY **pkey)
{
  GTlsClientConnectionOpenssl *client;
  GTlsConnectionBase *tls;
  GTlsCertificate *cert;

  client = SSL_get_ex_data (ssl, data_index);
  tls = G_TLS_CONNECTION_BASE (client);

  client->ca_list = SSL_get_client_CA_list (client->ssl);

  cert = g_tls_connection_get_certificate (G_TLS_CONNECTION (client));
  if (!cert)
    {
      if (g_tls_connection_base_handshake_thread_request_certificate (tls))
        cert = g_tls_connection_get_certificate (G_TLS_CONNECTION (client));
    }

  if (cert)
    {
      EVP_PKEY *key;

      key = g_tls_certificate_openssl_get_key (G_TLS_CERTIFICATE_OPENSSL (cert));

      if (key != NULL)
        {
          /* increase ref count */
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined (LIBRESSL_VERSION_NUMBER)
          CRYPTO_add (&key->references, 1, CRYPTO_LOCK_EVP_PKEY);
#else
          EVP_PKEY_up_ref (key);
#endif
          *pkey = key;

          *x509 = X509_dup (g_tls_certificate_openssl_get_cert (G_TLS_CERTIFICATE_OPENSSL (cert)));

          return 1;
        }
    }

  g_tls_connection_base_handshake_thread_set_missing_requested_client_certificate (tls);

  return 0;
}

static gboolean
set_cipher_list (GTlsClientConnectionOpenssl  *client,
                 GError                      **error)
{
  const gchar *cipher_list, *proto;

  cipher_list = g_getenv ("G_TLS_OPENSSL_CIPHER_LIST");
  if (cipher_list)
    {
      if (!SSL_CTX_set_cipher_list (client->ssl_ctx, cipher_list))
        {
          g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                       _("Could not set TLS cipher list: %s"),
                       ERR_error_string (ERR_get_error (), NULL));
          return FALSE;
        }
    }

  proto = g_getenv ("G_TLS_OPENSSL_MAX_PROTO");
  if (proto)
    {
      gint64 version = g_ascii_strtoll (proto, NULL, 0);

      if (version > 0 && version < G_MAXINT64)
        {
          if (!SSL_CTX_set_max_proto_version (client->ssl_ctx, (int)version))
            {
              g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                           _("Could not set MAX protocol to %ld: %s"),
                           version, ERR_error_string (ERR_get_error (), NULL));
              return FALSE;
            }
        }
    }

  return TRUE;
}

#ifdef SSL_CTX_set1_sigalgs_list
static void
set_signature_algorithm_list (GTlsClientConnectionOpenssl *client)
{
  const gchar *signature_algorithm_list;

  signature_algorithm_list = g_getenv ("G_TLS_OPENSSL_SIGNATURE_ALGORITHM_LIST");
  if (!signature_algorithm_list)
    return;

  SSL_CTX_set1_sigalgs_list (client->ssl_ctx, signature_algorithm_list);
}
#endif

#ifdef SSL_CTX_set1_curves_list
static void
set_curve_list (GTlsClientConnectionOpenssl *client)
{
  const gchar *curve_list;

  curve_list = g_getenv ("G_TLS_OPENSSL_CURVE_LIST");
  if (!curve_list)
    return;

  SSL_CTX_set1_curves_list (client->ssl_ctx, curve_list);
}
#endif

static gboolean
g_tls_client_connection_openssl_initable_init (GInitable       *initable,
                                               GCancellable    *cancellable,
                                               GError         **error)
{
  GTlsClientConnectionOpenssl *client = G_TLS_CLIENT_CONNECTION_OPENSSL (initable);
  long options;
  const char *hostname;

  client->session = SSL_SESSION_new ();

  client->ssl_ctx = SSL_CTX_new (SSLv23_client_method ());
  if (!client->ssl_ctx)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Could not create TLS context: %s"),
                   ERR_error_string (ERR_get_error (), NULL));
      return FALSE;
    }

  if (!set_cipher_list (client, error))
    return FALSE;

  /* Only TLS 1.2 or higher */
  options = SSL_OP_NO_TICKET |
            SSL_OP_NO_COMPRESSION |
#ifdef SSL_OP_NO_TLSv1_1
            SSL_OP_NO_TLSv1_1 |
#endif
            SSL_OP_NO_SSLv2 |
            SSL_OP_NO_SSLv3 |
            SSL_OP_NO_TLSv1;
  SSL_CTX_set_options (client->ssl_ctx, options);

  SSL_CTX_clear_options (client->ssl_ctx, SSL_OP_LEGACY_SERVER_CONNECT);

  hostname = get_server_identity (client);

#if OPENSSL_VERSION_NUMBER >= 0x10002000L && !defined (LIBRESSL_VERSION_NUMBER)
  if (hostname)
    {
      X509_VERIFY_PARAM *param;

      param = X509_VERIFY_PARAM_new ();
      X509_VERIFY_PARAM_set1_host (param, hostname, 0);
      SSL_CTX_set1_param (client->ssl_ctx, param);
      X509_VERIFY_PARAM_free (param);
    }
#endif

  SSL_CTX_add_session (client->ssl_ctx, client->session);

  SSL_CTX_set_client_cert_cb (client->ssl_ctx, handshake_thread_retrieve_certificate);

#ifdef SSL_CTX_set1_sigalgs_list
  set_signature_algorithm_list (client);
#endif

#ifdef SSL_CTX_set1_curves_list
  set_curve_list (client);
#endif

  client->ssl = SSL_new (client->ssl_ctx);
  if (!client->ssl)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Could not create TLS connection: %s"),
                   ERR_error_string (ERR_get_error (), NULL));
      return FALSE;
    }

  if (data_index == -1) {
      data_index = SSL_get_ex_new_index (0, (void *)"gtlsclientconnection", NULL, NULL, NULL);
  }
  SSL_set_ex_data (client->ssl, data_index, client);

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
  if (hostname)
    SSL_set_tlsext_host_name (client->ssl, hostname);
#endif

  SSL_set_connect_state (client->ssl);

  if (!g_tls_client_connection_openssl_parent_initable_iface->
      init (initable, cancellable, error))
    return FALSE;

  return TRUE;
}

static void
g_tls_client_connection_openssl_initable_interface_init (GInitableIface  *iface)
{
  g_tls_client_connection_openssl_parent_initable_iface = g_type_interface_peek_parent (iface);

  iface->init = g_tls_client_connection_openssl_initable_init;
}
