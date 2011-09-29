/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2011 Red Hat, Inc
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "config.h"
#include <glib.h>

#include "gtlsclientconnection-nss.h"
#include "gtlscertificate-nss.h"

#include <key.h>

#include <glib/gi18n-lib.h>

enum
{
  PROP_0,
  PROP_VALIDATION_FLAGS,
  PROP_SERVER_IDENTITY,
  PROP_USE_SSL3,
  PROP_ACCEPTED_CAS
};

SECStatus g_tls_client_connection_nss_certificate_requested (void              *arg,
							     PRFileDesc        *fd,
							     CERTDistNames     *caNames,
							     CERTCertificate  **pRetCert,
							     SECKEYPrivateKey **pRetKey);

static void g_tls_client_connection_nss_client_connection_interface_init (GTlsClientConnectionInterface *iface);

G_DEFINE_TYPE_WITH_CODE (GTlsClientConnectionNss, g_tls_client_connection_nss, G_TYPE_TLS_CONNECTION_NSS,
			 G_IMPLEMENT_INTERFACE (G_TYPE_TLS_CLIENT_CONNECTION,
						g_tls_client_connection_nss_client_connection_interface_init));

struct _GTlsClientConnectionNssPrivate
{
  GTlsCertificateFlags validation_flags;
  GSocketConnectable *server_identity;
  gboolean use_ssl3;
  GList *accepted_cas;
};

static void
g_tls_client_connection_nss_init (GTlsClientConnectionNss *nss)
{
  GTlsConnectionNss *conn_nss = G_TLS_CONNECTION_NSS (nss);

  nss->priv = G_TYPE_INSTANCE_GET_PRIVATE (nss, G_TYPE_TLS_CLIENT_CONNECTION_NSS, GTlsClientConnectionNssPrivate);

  SSL_ResetHandshake (conn_nss->prfd, PR_FALSE);
  SSL_GetClientAuthDataHook (conn_nss->prfd, g_tls_client_connection_nss_certificate_requested, nss);
}

static void
g_tls_client_connection_nss_finalize (GObject *object)
{
  GTlsClientConnectionNss *nss = G_TLS_CLIENT_CONNECTION_NSS (object);

  if (nss->priv->server_identity)
    g_object_unref (nss->priv->server_identity);
  if (nss->priv->accepted_cas)
    g_list_free_full (nss->priv->accepted_cas, (GDestroyNotify)g_byte_array_unref);

  G_OBJECT_CLASS (g_tls_client_connection_nss_parent_class)->finalize (object);
}

static void
g_tls_client_connection_nss_get_property (GObject    *object,
					  guint       prop_id,
					  GValue     *value,
					  GParamSpec *pspec)
{
  GTlsClientConnectionNss *nss = G_TLS_CLIENT_CONNECTION_NSS (object);
  GList *accepted_cas, *iter;

  switch (prop_id)
    {
    case PROP_VALIDATION_FLAGS:
      g_value_set_flags (value, nss->priv->validation_flags);
      break;

    case PROP_SERVER_IDENTITY:
      g_value_set_object (value, nss->priv->server_identity);
      break;

    case PROP_USE_SSL3:
      g_value_set_boolean (value, nss->priv->use_ssl3);
      break;

    case PROP_ACCEPTED_CAS:
      accepted_cas = NULL;
      for (iter = nss->priv->accepted_cas; iter; iter = iter->next)
	accepted_cas = g_list_prepend (accepted_cas, g_byte_array_ref (iter->data));
      g_value_set_pointer (value, accepted_cas);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_client_connection_nss_set_property (GObject      *object,
					  guint         prop_id,
					  const GValue *value,
					  GParamSpec   *pspec)
{
  GTlsClientConnectionNss *nss = G_TLS_CLIENT_CONNECTION_NSS (object);
  GTlsConnectionNss *conn_nss = G_TLS_CONNECTION_NSS (object);
  const char *identity_host;

  switch (prop_id)
    {
    case PROP_VALIDATION_FLAGS:
      nss->priv->validation_flags = g_value_get_flags (value);
      break;

    case PROP_SERVER_IDENTITY:
      if (nss->priv->server_identity)
	g_object_unref (nss->priv->server_identity);
      nss->priv->server_identity = g_value_dup_object (value);

      if (G_IS_NETWORK_ADDRESS (nss->priv->server_identity))
	identity_host = g_network_address_get_hostname (G_NETWORK_ADDRESS (nss->priv->server_identity));
      else if (G_IS_NETWORK_SERVICE (nss->priv->server_identity))
	identity_host = g_network_service_get_domain (G_NETWORK_SERVICE (nss->priv->server_identity));
      else
	identity_host = NULL;

      if (identity_host)
	{
	  SSL_SetURL (conn_nss->prfd, identity_host);
	  SSL_SetSockPeerID (conn_nss->prfd, identity_host);
	}
      break;

    case PROP_USE_SSL3:
      nss->priv->use_ssl3 = g_value_get_boolean (value);
      SSL_OptionSet (conn_nss->prfd, SSL_ENABLE_TLS, !nss->priv->use_ssl3);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_client_connection_nss_class_init (GTlsClientConnectionNssClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GTlsClientConnectionNssPrivate));

  gobject_class->get_property = g_tls_client_connection_nss_get_property;
  gobject_class->set_property = g_tls_client_connection_nss_set_property;
  gobject_class->finalize     = g_tls_client_connection_nss_finalize;

  g_object_class_override_property (gobject_class, PROP_VALIDATION_FLAGS, "validation-flags");
  g_object_class_override_property (gobject_class, PROP_SERVER_IDENTITY, "server-identity");
  g_object_class_override_property (gobject_class, PROP_USE_SSL3, "use-ssl3");
  g_object_class_override_property (gobject_class, PROP_ACCEPTED_CAS, "accepted-cas");
}

static void
g_tls_client_connection_nss_client_connection_interface_init (GTlsClientConnectionInterface *iface)
{
}

SECStatus
g_tls_client_connection_nss_certificate_requested (void              *arg,
						   PRFileDesc        *fd,
						   CERTDistNames     *caNames,
						   CERTCertificate  **pRetCert,
						   SECKEYPrivateKey **pRetKey)
{
  GTlsClientConnectionNss *nss = arg;
  GTlsConnectionBase *tls = arg;
  GTlsCertificateNss *gcert;
  GByteArray *name;
  GList *cas = NULL;
  int i;

  tls->certificate_requested = TRUE;

  for (i = 0; i < caNames->nnames; i++)
    {
      name = g_byte_array_new ();
      g_byte_array_append (name, caNames->names[i].data, caNames->names[i].len);
      cas = g_list_prepend (cas, name);
    }
  nss->priv->accepted_cas = cas;
  g_object_notify (G_OBJECT (nss), "accepted-cas");

  if (!tls->certificate)
    return SECFailure;

  gcert = G_TLS_CERTIFICATE_NSS (tls->certificate);
  *pRetCert = CERT_DupCertificate (g_tls_certificate_nss_get_cert (gcert));
  *pRetKey = SECKEY_CopyPrivateKey (g_tls_certificate_nss_get_key (gcert));
  return SECSuccess;
}
