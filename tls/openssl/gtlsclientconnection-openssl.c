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

#define DEFAULT_CIPHER_LIST "HIGH:!DSS:!aNULL@STRENGTH"

typedef struct _GTlsClientConnectionOpensslPrivate
{
  GTlsCertificateFlags validation_flags;
  GSocketConnectable *server_identity;
  gboolean use_ssl3;
  gboolean session_data_override;

  GBytes *session_id;
  GBytes *session_data;

  STACK_OF (X509_NAME) *ca_list;

  SSL_SESSION *session;
  SSL *ssl;
  SSL_CTX *ssl_ctx;
} GTlsClientConnectionOpensslPrivate;

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
                         G_ADD_PRIVATE (GTlsClientConnectionOpenssl)
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                g_tls_client_connection_openssl_initable_interface_init)
                         G_IMPLEMENT_INTERFACE (G_TYPE_TLS_CLIENT_CONNECTION,
                                                g_tls_client_connection_openssl_client_connection_interface_init))

static void
g_tls_client_connection_openssl_finalize (GObject *object)
{
  GTlsClientConnectionOpenssl *openssl = G_TLS_CLIENT_CONNECTION_OPENSSL (object);
  GTlsClientConnectionOpensslPrivate *priv;

  priv = g_tls_client_connection_openssl_get_instance_private (openssl);

  g_clear_object (&priv->server_identity);
  g_clear_pointer (&priv->session_id, g_bytes_unref);
  g_clear_pointer (&priv->session_data, g_bytes_unref);

  SSL_free (priv->ssl);
  SSL_CTX_free (priv->ssl_ctx);
  SSL_SESSION_free (priv->session);

  G_OBJECT_CLASS (g_tls_client_connection_openssl_parent_class)->finalize (object);
}

static const gchar *
get_server_identity (GTlsClientConnectionOpenssl *openssl)
{
  GTlsClientConnectionOpensslPrivate *priv;

  priv = g_tls_client_connection_openssl_get_instance_private (openssl);

  if (G_IS_NETWORK_ADDRESS (priv->server_identity))
    return g_network_address_get_hostname (G_NETWORK_ADDRESS (priv->server_identity));
  else if (G_IS_NETWORK_SERVICE (priv->server_identity))
    return g_network_service_get_domain (G_NETWORK_SERVICE (priv->server_identity));
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
  GTlsClientConnectionOpensslPrivate *priv;
  GList *accepted_cas;
  gint i;

  priv = g_tls_client_connection_openssl_get_instance_private (openssl);

  switch (prop_id)
    {
    case PROP_VALIDATION_FLAGS:
      g_value_set_flags (value, priv->validation_flags);
      break;

    case PROP_SERVER_IDENTITY:
      g_value_set_object (value, priv->server_identity);
      break;

    case PROP_USE_SSL3:
      g_value_set_boolean (value, priv->use_ssl3);
      break;

    case PROP_ACCEPTED_CAS:
      accepted_cas = NULL;
      if (priv->ca_list)
        {
          for (i = 0; i < sk_X509_NAME_num (priv->ca_list); ++i)
            {
              int size;

              size = i2d_X509_NAME (sk_X509_NAME_value (priv->ca_list, i), NULL);
              if (size > 0)
                {
                  unsigned char *ca;

                  ca = g_malloc (size);
                  size = i2d_X509_NAME (sk_X509_NAME_value (priv->ca_list, i), &ca);
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
  GTlsClientConnectionOpensslPrivate *priv;

  priv = g_tls_client_connection_openssl_get_instance_private (openssl);

  switch (prop_id)
    {
    case PROP_VALIDATION_FLAGS:
      priv->validation_flags = g_value_get_flags (value);
      break;

    case PROP_SERVER_IDENTITY:
      if (priv->server_identity)
        g_object_unref (priv->server_identity);
      priv->server_identity = g_value_dup_object (value);
      break;

    case PROP_USE_SSL3:
      priv->use_ssl3 = g_value_get_boolean (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_client_connection_openssl_constructed (GObject *object)
{
  GTlsClientConnectionOpenssl *openssl = G_TLS_CLIENT_CONNECTION_OPENSSL (object);
  GTlsClientConnectionOpensslPrivate *priv;
  GSocketConnection *base_conn;
  GSocketAddress *remote_addr;
  GInetAddress *iaddr;
  guint port;

  priv = g_tls_client_connection_openssl_get_instance_private (openssl);

  /* Create a TLS session ID. We base it on the IP address since
   * different hosts serving the same hostname/service will probably
   * not share the same session cache. We base it on the
   * server-identity because at least some servers will fail (rather
   * than just failing to resume the session) if we don't.
   * (https://bugs.launchpad.net/bugs/823325)
   */
  g_object_get (G_OBJECT (openssl), "base-io-stream", &base_conn, NULL);
  if (G_IS_SOCKET_CONNECTION (base_conn))
    {
      remote_addr = g_socket_connection_get_remote_address (base_conn, NULL);
      if (G_IS_INET_SOCKET_ADDRESS (remote_addr))
        {
          GInetSocketAddress *isaddr = G_INET_SOCKET_ADDRESS (remote_addr);
          const gchar *server_hostname;
          gchar *addrstr, *session_id;

          iaddr = g_inet_socket_address_get_address (isaddr);
          port = g_inet_socket_address_get_port (isaddr);

          addrstr = g_inet_address_to_string (iaddr);
          server_hostname = get_server_identity (openssl);
          session_id = g_strdup_printf ("%s/%s/%d", addrstr,
                                        server_hostname ? server_hostname : "",
                                        port);
          priv->session_id = g_bytes_new_take (session_id, strlen (session_id));
          g_free (addrstr);
        }
      g_object_unref (remote_addr);
    }
  g_object_unref (base_conn);

  G_OBJECT_CLASS (g_tls_client_connection_openssl_parent_class)->constructed (object);
}

static GTlsConnectionBaseStatus
g_tls_client_connection_openssl_handshake (GTlsConnectionBase  *tls,
                                           GCancellable        *cancellable,
                                           GError             **error)
{
  return G_TLS_CONNECTION_BASE_CLASS (g_tls_client_connection_openssl_parent_class)->
    handshake (tls, cancellable, error);
}

static GTlsConnectionBaseStatus
g_tls_client_connection_openssl_complete_handshake (GTlsConnectionBase  *tls,
                                                    GError             **error)
{
  GTlsConnectionBaseStatus status;

  status = G_TLS_CONNECTION_BASE_CLASS (g_tls_client_connection_openssl_parent_class)->
    complete_handshake (tls, error);

  return status;
}

static SSL *
g_tls_client_connection_openssl_get_ssl (GTlsConnectionOpenssl *connection)
{
  GTlsClientConnectionOpenssl *client = G_TLS_CLIENT_CONNECTION_OPENSSL (connection);
  GTlsClientConnectionOpensslPrivate *priv;

  priv = g_tls_client_connection_openssl_get_instance_private (client);

  return priv->ssl;
}

static SSL_CTX *
g_tls_client_connection_openssl_get_ssl_ctx (GTlsConnectionOpenssl *connection)
{
  GTlsClientConnectionOpenssl *client = G_TLS_CLIENT_CONNECTION_OPENSSL (connection);
  GTlsClientConnectionOpensslPrivate *priv;

  priv = g_tls_client_connection_openssl_get_instance_private (client);

  return priv->ssl_ctx;
}

static void
g_tls_client_connection_openssl_class_init (GTlsClientConnectionOpensslClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsConnectionBaseClass *base_class = G_TLS_CONNECTION_BASE_CLASS (klass);
  GTlsConnectionOpensslClass *connection_class = G_TLS_CONNECTION_OPENSSL_CLASS (klass);

  gobject_class->finalize     = g_tls_client_connection_openssl_finalize;
  gobject_class->get_property = g_tls_client_connection_openssl_get_property;
  gobject_class->set_property = g_tls_client_connection_openssl_set_property;
  gobject_class->constructed  = g_tls_client_connection_openssl_constructed;

  base_class->handshake          = g_tls_client_connection_openssl_handshake;
  base_class->complete_handshake = g_tls_client_connection_openssl_complete_handshake;

  connection_class->get_ssl = g_tls_client_connection_openssl_get_ssl;
  connection_class->get_ssl_ctx = g_tls_client_connection_openssl_get_ssl_ctx;

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
retrieve_certificate (SSL       *ssl,
                      X509     **x509,
                      EVP_PKEY **pkey)
{
  GTlsClientConnectionOpenssl *client;
  GTlsClientConnectionOpensslPrivate *priv;
  GTlsConnectionBase *tls;
  GTlsConnectionOpenssl *openssl;
  GTlsCertificate *cert;
  gboolean set_certificate = FALSE;

  client = SSL_get_ex_data (ssl, data_index);
  tls = G_TLS_CONNECTION_BASE (client);
  openssl = G_TLS_CONNECTION_OPENSSL (client);

  priv = g_tls_client_connection_openssl_get_instance_private (client);

  tls->certificate_requested = TRUE;

  priv->ca_list = SSL_get_client_CA_list (priv->ssl);
  g_object_notify (G_OBJECT (client), "accepted-cas");

  cert = g_tls_connection_get_certificate (G_TLS_CONNECTION (client));
  if (cert != NULL)
    set_certificate = TRUE;
  else
    {
      g_clear_error (&tls->certificate_error);
      if (g_tls_connection_openssl_request_certificate (openssl, &tls->certificate_error))
        {
          cert = g_tls_connection_get_certificate (G_TLS_CONNECTION (client));
          set_certificate = (cert != NULL);
        }
    }

  if (set_certificate)
    {
      EVP_PKEY *key;

      key = g_tls_certificate_openssl_get_key (G_TLS_CERTIFICATE_OPENSSL (cert));
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

  return 0;
}

static int
generate_session_id (const SSL     *ssl,
                     unsigned char *id,
                     unsigned int  *id_len)
{
  GTlsClientConnectionOpenssl *client;
  GTlsClientConnectionOpensslPrivate *priv;
  int len;

  client = SSL_get_ex_data (ssl, data_index);
  priv = g_tls_client_connection_openssl_get_instance_private (client);

  len = MIN (*id_len, g_bytes_get_size (priv->session_id));
  memcpy (id, g_bytes_get_data (priv->session_id, NULL), len);

  return 1;
}

static void
set_cipher_list (GTlsClientConnectionOpenssl *client)
{
  GTlsClientConnectionOpensslPrivate *priv;
  const gchar *cipher_list;

  priv = g_tls_client_connection_openssl_get_instance_private (client);

  cipher_list = g_getenv ("G_TLS_OPENSSL_CIPHER_LIST");
  if (cipher_list == NULL)
    cipher_list = DEFAULT_CIPHER_LIST;

  SSL_CTX_set_cipher_list (priv->ssl_ctx, cipher_list);
}

#ifdef SSL_CTX_set1_sigalgs_list
static void
set_signature_algorithm_list (GTlsClientConnectionOpenssl *client)
{
  GTlsClientConnectionOpensslPrivate *priv;
  const gchar *signature_algorithm_list;

  priv = g_tls_client_connection_openssl_get_instance_private (client);

  signature_algorithm_list = g_getenv ("G_TLS_OPENSSL_SIGNATURE_ALGORITHM_LIST");
  if (signature_algorithm_list == NULL)
    return;

  SSL_CTX_set1_sigalgs_list (priv->ssl_ctx, signature_algorithm_list);
}
#endif

#ifdef SSL_CTX_set1_curves_list
static void
set_curve_list (GTlsClientConnectionOpenssl *client)
{
  GTlsClientConnectionOpensslPrivate *priv;
  const gchar *curve_list;

  priv = g_tls_client_connection_openssl_get_instance_private (client);

  curve_list = g_getenv ("G_TLS_OPENSSL_CURVE_LIST");
  if (curve_list == NULL)
    return;

  SSL_CTX_set1_curves_list (priv->ssl_ctx, curve_list);
}
#endif

static gboolean
use_ocsp (void)
{
  return g_getenv ("G_TLS_OPENSSL_OCSP_ENABLED") != NULL;
}

static gboolean
g_tls_client_connection_openssl_initable_init (GInitable       *initable,
                                               GCancellable    *cancellable,
                                               GError         **error)
{
  GTlsClientConnectionOpenssl *client = G_TLS_CLIENT_CONNECTION_OPENSSL (initable);
  GTlsClientConnectionOpensslPrivate *priv;
  long options;
  const char *hostname;

  priv = g_tls_client_connection_openssl_get_instance_private (client);

  priv->session = SSL_SESSION_new ();

  priv->ssl_ctx = SSL_CTX_new (SSLv23_client_method ());
  if (priv->ssl_ctx == NULL)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Could not create TLS context: %s"),
                   ERR_error_string (ERR_get_error (), NULL));
      return FALSE;
    }

  /* Only TLS 1.2 or higher */
  options = SSL_OP_NO_TICKET |
            SSL_OP_NO_COMPRESSION |
#ifdef SSL_OP_NO_TLSv1_1
            SSL_OP_NO_TLSv1_1 |
#endif
            SSL_OP_NO_SSLv2 |
            SSL_OP_NO_SSLv3 |
            SSL_OP_NO_TLSv1;
  SSL_CTX_set_options (priv->ssl_ctx, options);

  SSL_CTX_clear_options (priv->ssl_ctx, SSL_OP_LEGACY_SERVER_CONNECT);

  hostname = get_server_identity (client);

#if OPENSSL_VERSION_NUMBER >= 0x10002000L && !defined (LIBRESSL_VERSION_NUMBER)
  if (hostname)
    {
      X509_VERIFY_PARAM *param;

      param = X509_VERIFY_PARAM_new ();
      X509_VERIFY_PARAM_set1_host (param, hostname, 0);
      SSL_CTX_set1_param (priv->ssl_ctx, param);
      X509_VERIFY_PARAM_free (param);
    }
#endif

  SSL_CTX_set_generate_session_id (priv->ssl_ctx, generate_session_id);
  SSL_CTX_add_session (priv->ssl_ctx, priv->session);

  SSL_CTX_set_client_cert_cb (priv->ssl_ctx, retrieve_certificate);

  set_cipher_list (client);

#ifdef SSL_CTX_set1_sigalgs_list
  set_signature_algorithm_list (client);
#endif

#ifdef SSL_CTX_set1_curves_list
  set_curve_list (client);
#endif

  priv->ssl = SSL_new (priv->ssl_ctx);
  if (priv->ssl == NULL)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Could not create TLS connection: %s"),
                   ERR_error_string (ERR_get_error (), NULL));
      return FALSE;
    }

  if (data_index == -1) {
      data_index = SSL_get_ex_new_index (0, (void *)"gtlsclientconnection", NULL, NULL, NULL);
  }
  SSL_set_ex_data (priv->ssl, data_index, client);

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
  if (hostname)
    SSL_set_tlsext_host_name (priv->ssl, hostname);
#endif

  SSL_set_connect_state (priv->ssl);

#if (OPENSSL_VERSION_NUMBER >= 0x0090808fL) && !defined(OPENSSL_NO_TLSEXT) && \
    !defined(OPENSSL_NO_OCSP)
  if (use_ocsp())
    SSL_set_tlsext_status_type (priv->ssl, TLSEXT_STATUSTYPE_ocsp);
#endif

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
