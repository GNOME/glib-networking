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

static void
g_tls_server_connection_openssl_class_init (GTlsServerConnectionOpensslClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->get_property = g_tls_server_connection_openssl_get_property;
  gobject_class->set_property = g_tls_server_connection_openssl_set_property;

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
  return g_tls_server_connection_openssl_parent_initable_iface->init (initable, cancellable, error);
}

static void
g_tls_server_connection_openssl_initable_interface_init (GInitableIface  *iface)
{
  g_tls_server_connection_openssl_parent_initable_iface = g_type_interface_peek_parent (iface);

  iface->init = g_tls_server_connection_openssl_initable_init;
}
