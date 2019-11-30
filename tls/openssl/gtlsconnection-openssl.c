/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlsconnection-openssl.c
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

/* FIXME: audit includes throughout the project */

#include <errno.h>
#include <stdarg.h>
#include "openssl-include.h"

#include "gtlsconnection-openssl.h"
#include "gtlsbackend-openssl.h"
#include "gtlscertificate-openssl.h"
#include "gtlsdatabase-openssl.h"
#include "gtlsoperationsthread-openssl.h"
#include "gtlsbio.h"

#include <glib/gi18n-lib.h>

typedef struct _GTlsConnectionOpensslPrivate
{
} GTlsConnectionOpensslPrivate;

static GInitableIface *g_tls_connection_openssl_parent_initable_iface;

static void g_tls_connection_openssl_initable_iface_init (GInitableIface *iface);

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (GTlsConnectionOpenssl, g_tls_connection_openssl, G_TYPE_TLS_CONNECTION_BASE,
                                  G_ADD_PRIVATE (GTlsConnectionOpenssl)
                                  G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                         g_tls_connection_openssl_initable_iface_init))

static GTlsOperationsThreadBase *
g_tls_connection_openssl_create_op_thread (GTlsConnectionBase *tls)
{
  GTlsOperationsThreadBase *thread;
  GTlsOperationsThreadType thread_type;
  GIOStream *base_iostream = NULL;

  g_object_get (tls,
                "base-io-stream", &base_iostream,
                NULL);

  if (G_IS_TLS_CLIENT_CONNECTION (tls))
    thread_type = G_TLS_OPERATIONS_THREAD_CLIENT;
  else
    thread_type = G_TLS_OPERATIONS_THREAD_SERVER;

  thread = g_tls_operations_thread_openssl_new (base_iostream,
                                                thread_type);
  g_object_unref (base_iostream);

  return thread;
}

static void
g_tls_connection_openssl_class_init (GTlsConnectionOpensslClass *klass)
{
  GTlsConnectionBaseClass *base_class = G_TLS_CONNECTION_BASE_CLASS (klass);

  base_class->create_op_thread = g_tls_connection_openssl_create_op_thread;
}

static gboolean
g_tls_connection_openssl_initable_init (GInitable     *initable,
                                        GCancellable  *cancellable,
                                        GError       **error)
{
  return g_tls_connection_openssl_parent_initable_iface->init (initable, cancellable, error);
}

static void
g_tls_connection_openssl_initable_iface_init (GInitableIface *iface)
{
  g_tls_connection_openssl_parent_initable_iface = g_type_interface_peek_parent (iface);

  iface->init = g_tls_connection_openssl_initable_init;
}

static void
g_tls_connection_openssl_init (GTlsConnectionOpenssl *openssl)
{
}
