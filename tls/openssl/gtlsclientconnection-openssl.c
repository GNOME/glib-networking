/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlsclientconnection-openssl.c
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
#include "gtlsclientconnection-openssl.h"

#include "openssl-include.h"
#include "gtlsconnection-base.h"
#include "gtlsbackend-openssl.h"
#include "gtlscertificate-openssl.h"
#include "gtlsoperationsthread-base.h"

#include <errno.h>
#include <glib.h>
#include <string.h>
#include <glib/gi18n-lib.h>

struct _GTlsClientConnectionOpenssl
{
  GTlsConnectionOpenssl parent_instance;

  GTlsCertificateFlags validation_flags;
  GSocketConnectable *server_identity;
  gboolean use_ssl3;

  GList *accepted_cas;
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
g_tls_client_connection_openssl_set_accepted_cas (GTlsConnectionBase *tls,
                                                  GList              *accepted_cas)
{
  GTlsClientConnectionOpenssl *openssl = G_TLS_CLIENT_CONNECTION_OPENSSL (tls);

  if (openssl->accepted_cas)
    g_list_free_full (openssl->accepted_cas, (GDestroyNotify)g_byte_array_unref);

  openssl->accepted_cas = g_steal_pointer (&accepted_cas);
}

static void
g_tls_client_connection_openssl_copy_session_state (GTlsClientConnection *conn,
                                                    GTlsClientConnection *source)
{
}

static void
g_tls_client_connection_openssl_get_property (GObject    *object,
                                              guint       prop_id,
                                              GValue     *value,
                                              GParamSpec *pspec)
{
  GTlsClientConnectionOpenssl *openssl = G_TLS_CLIENT_CONNECTION_OPENSSL (object);

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
      g_value_set_pointer (value, g_list_copy (openssl->accepted_cas));
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
  const gchar *hostname;

  switch (prop_id)
    {
    case PROP_VALIDATION_FLAGS:
      openssl->validation_flags = g_value_get_flags (value);
      break;

    case PROP_SERVER_IDENTITY:
      if (openssl->server_identity)
        g_object_unref (openssl->server_identity);
      openssl->server_identity = g_value_dup_object (value);

      // FIXME: this only sets the server identinty.
      // We must also allow unsetting server identity on op thread, and for GnuTLS too
      hostname = get_server_identity (openssl);
      if (hostname)
        {
          GTlsOperationsThreadBase *thread;

          thread = g_tls_connection_base_get_op_thread (G_TLS_CONNECTION_BASE (openssl));
          if (thread)
            g_tls_operations_thread_base_set_server_identity (thread, hostname);
        }
      break;

    case PROP_USE_SSL3:
      openssl->use_ssl3 = g_value_get_boolean (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_client_connection_openssl_finalize (GObject *object)
{
  GTlsClientConnectionOpenssl *openssl = G_TLS_CLIENT_CONNECTION_OPENSSL (object);

  g_clear_object (&openssl->server_identity);

  if (openssl->accepted_cas)
    {
      g_list_free_full (openssl->accepted_cas, (GDestroyNotify)g_byte_array_unref);
      openssl->accepted_cas = NULL;
    }

  G_OBJECT_CLASS (g_tls_client_connection_openssl_parent_class)->finalize (object);
}

static void
g_tls_client_connection_openssl_init (GTlsClientConnectionOpenssl *openssl)
{
}

static void
g_tls_client_connection_openssl_class_init (GTlsClientConnectionOpensslClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsConnectionBaseClass *base_class = G_TLS_CONNECTION_BASE_CLASS (klass);

  gobject_class->finalize             = g_tls_client_connection_openssl_finalize;
  gobject_class->get_property         = g_tls_client_connection_openssl_get_property;
  gobject_class->set_property         = g_tls_client_connection_openssl_set_property;

  base_class->set_accepted_cas        = g_tls_client_connection_openssl_set_accepted_cas;

  g_object_class_override_property (gobject_class, PROP_VALIDATION_FLAGS, "validation-flags");
  g_object_class_override_property (gobject_class, PROP_SERVER_IDENTITY, "server-identity");
  g_object_class_override_property (gobject_class, PROP_USE_SSL3, "use-ssl3");
  g_object_class_override_property (gobject_class, PROP_ACCEPTED_CAS, "accepted-cas");
}

static void
g_tls_client_connection_openssl_client_connection_interface_init (GTlsClientConnectionInterface *iface)
{
  iface->copy_session_state = g_tls_client_connection_openssl_copy_session_state;
}

static gboolean
g_tls_client_connection_openssl_initable_init (GInitable       *initable,
                                               GCancellable    *cancellable,
                                               GError         **error)
{
  GTlsClientConnectionOpenssl *client = G_TLS_CLIENT_CONNECTION_OPENSSL (initable);
  GTlsOperationsThreadBase *thread;
  const gchar *hostname;

  if (!g_tls_client_connection_openssl_parent_initable_iface->init (initable, cancellable, error))
    return FALSE;

  hostname = get_server_identity (client);
  if (hostname)
    {
      thread = g_tls_connection_base_get_op_thread (G_TLS_CONNECTION_BASE (client));
      g_tls_operations_thread_base_set_server_identity (thread, hostname);
    }

  return TRUE;
}

static void
g_tls_client_connection_openssl_initable_interface_init (GInitableIface  *iface)
{
  g_tls_client_connection_openssl_parent_initable_iface = g_type_interface_peek_parent (iface);

  iface->init = g_tls_client_connection_openssl_initable_init;
}
