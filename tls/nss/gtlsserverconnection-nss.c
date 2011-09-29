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

#include "gtlsserverconnection-nss.h"
#include "gtlscertificate-nss.h"

#include <ssl.h>

#include <glib/gi18n-lib.h>

enum
{
  PROP_0,
  PROP_AUTHENTICATION_MODE
};

static void g_tls_server_connection_nss_server_connection_interface_init (GTlsServerConnectionInterface *iface);

G_DEFINE_TYPE_WITH_CODE (GTlsServerConnectionNss, g_tls_server_connection_nss, G_TYPE_TLS_CONNECTION_NSS,
			 G_IMPLEMENT_INTERFACE (G_TYPE_TLS_SERVER_CONNECTION,
						g_tls_server_connection_nss_server_connection_interface_init))

struct _GTlsServerConnectionNssPrivate
{
  GTlsAuthenticationMode authentication_mode;
};

static void
certificate_set (GObject    *object,
		 GParamSpec *pspec,
		 gpointer    user_data)
{
  GTlsConnectionNss *conn_nss = G_TLS_CONNECTION_NSS (object);
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (object);

  SSL_ConfigSecureServer (conn_nss->prfd,
			  g_tls_certificate_nss_get_cert (G_TLS_CERTIFICATE_NSS (tls->certificate)),
			  g_tls_certificate_nss_get_key (G_TLS_CERTIFICATE_NSS (tls->certificate)),
			  kt_rsa);
}

static void
g_tls_server_connection_nss_init (GTlsServerConnectionNss *nss)
{
  GTlsConnectionNss *conn_nss = G_TLS_CONNECTION_NSS (nss);

  nss->priv = G_TYPE_INSTANCE_GET_PRIVATE (nss, G_TYPE_TLS_SERVER_CONNECTION_NSS, GTlsServerConnectionNssPrivate);

  SSL_ResetHandshake (conn_nss->prfd, PR_TRUE);

  g_signal_connect (nss, "notify::certificate",
		    G_CALLBACK (certificate_set), NULL);
}

static void
g_tls_server_connection_nss_get_property (GObject    *object,
					  guint       prop_id,
					  GValue     *value,
					  GParamSpec *pspec)
{
  GTlsServerConnectionNss *nss = G_TLS_SERVER_CONNECTION_NSS (object);

  switch (prop_id)
    {
    case PROP_AUTHENTICATION_MODE:
      g_value_set_enum (value, nss->priv->authentication_mode);
      break;
      
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_server_connection_nss_set_property (GObject      *object,
					  guint         prop_id,
					  const GValue *value,
					  GParamSpec   *pspec)
{
  GTlsServerConnectionNss *nss = G_TLS_SERVER_CONNECTION_NSS (object);
  GTlsConnectionNss *conn_nss = G_TLS_CONNECTION_NSS (object);

  switch (prop_id)
    {
    case PROP_AUTHENTICATION_MODE:
      nss->priv->authentication_mode = g_value_get_enum (value);
      SSL_OptionSet (conn_nss->prfd, SSL_REQUEST_CERTIFICATE,
		     nss->priv->authentication_mode != G_TLS_AUTHENTICATION_NONE);
      SSL_OptionSet (conn_nss->prfd, SSL_REQUIRE_CERTIFICATE,
		     nss->priv->authentication_mode == G_TLS_AUTHENTICATION_REQUIRED);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_server_connection_nss_class_init (GTlsServerConnectionNssClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GTlsServerConnectionNssPrivate));

  gobject_class->get_property = g_tls_server_connection_nss_get_property;
  gobject_class->set_property = g_tls_server_connection_nss_set_property;

  g_object_class_override_property (gobject_class, PROP_AUTHENTICATION_MODE, "authentication-mode");

  /* FIXME: global! (but if we don't call it, it will crash
   * if the client aborts a handshake).
   */
  SSL_ConfigServerSessionIDCache (0, 0, 0, NULL);
}

static void
g_tls_server_connection_nss_server_connection_interface_init (GTlsServerConnectionInterface *iface)
{
}

