/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
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

#include "gtlsconnection-openssl.h"
#include "gtlsoperationsthread-openssl.h"

struct _GTlsOperationsThreadOpenssl {
  GTlsOperationsThreadBase parent_instance;
};

G_DEFINE_TYPE (GTlsOperationsThreadOpenssl, g_tls_operations_thread_openssl, G_TYPE_TLS_OPERATIONS_THREAD_BASE)

static void
g_tls_operations_thread_openssl_init (GTlsOperationsThreadOpenssl *self)
{
}

static void
g_tls_operations_thread_openssl_class_init (GTlsOperationsThreadOpensslClass *klass)
{
}

GTlsOperationsThreadBase *
g_tls_operations_thread_openssl_new (GTlsConnectionOpenssl *tls)
{
  return G_TLS_OPERATIONS_THREAD_BASE (g_object_new (G_TYPE_TLS_OPERATIONS_THREAD_OPENSSL,
                                       "tls-connection", tls,
                                       NULL));
}
