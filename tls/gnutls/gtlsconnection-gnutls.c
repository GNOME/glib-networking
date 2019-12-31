/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2009 Red Hat, Inc
 * Copyright 2015, 2016 Collabora, Ltd.
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
#include "gtlsconnection-gnutls.h"

#include "gtlsoperationsthread-gnutls.h"

#include <glib.h>
#include <gnutls/gnutls.h>

static GInitableIface *g_tls_connection_gnutls_parent_initable_iface;

static void g_tls_connection_gnutls_initable_iface_init (GInitableIface *iface);

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (GTlsConnectionGnutls, g_tls_connection_gnutls, G_TYPE_TLS_CONNECTION_BASE,
                                  G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                         g_tls_connection_gnutls_initable_iface_init);
                                  );

static void
g_tls_connection_gnutls_init (GTlsConnectionGnutls *gnutls)
{
}

static gboolean
g_tls_connection_gnutls_initable_init (GInitable     *initable,
                                       GCancellable  *cancellable,
                                       GError       **error)
{
  return g_tls_connection_gnutls_parent_initable_iface->init (initable, cancellable, error);
}

static GTlsOperationsThreadBase *
g_tls_connection_gnutls_create_op_thread (GTlsConnectionBase *tls)
{
  GIOStream *base_io_stream = NULL;
  GDatagramBased *base_socket = NULL;
  gboolean client = G_IS_TLS_CLIENT_CONNECTION (tls);
  guint flags = client ? GNUTLS_CLIENT : GNUTLS_SERVER;
  GTlsOperationsThreadBase *thread;

  g_object_get (tls,
                "base-io-stream", &base_io_stream,
                "base-socket", &base_socket,
                NULL);

  /* Ensure we are in TLS mode or DTLS mode. */
  g_assert (!!base_io_stream != !!base_socket);

  if (base_socket)
    flags |= GNUTLS_DATAGRAM;

  thread = g_tls_operations_thread_gnutls_new (G_TLS_CONNECTION_GNUTLS (tls),
                                               base_io_stream,
                                               base_socket,
                                               flags);

  g_clear_object (&base_io_stream);
  g_clear_object (&base_socket);

  return thread;
}

static void
g_tls_connection_gnutls_class_init (GTlsConnectionGnutlsClass *klass)
{
  GTlsConnectionBaseClass *base_class = G_TLS_CONNECTION_BASE_CLASS (klass);

  base_class->create_op_thread = g_tls_connection_gnutls_create_op_thread;
}

static void
g_tls_connection_gnutls_initable_iface_init (GInitableIface *iface)
{
  g_tls_connection_gnutls_parent_initable_iface = g_type_interface_peek_parent (iface);

  iface->init = g_tls_connection_gnutls_initable_init;
}
