/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2019 Igalia S.L.
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

#pragma once

#include <gio/gio.h>

#include "gtlsconnection-base.h"

G_BEGIN_DECLS

#define G_TYPE_TLS_THREAD            (g_tls_thread_get_type ())

G_DECLARE_FINAL_TYPE (GTlsThread, g_tls_thread, G, TLS_THREAD, GObject)

GTlsThread               *g_tls_thread_new  (GTlsConnectionBase *tls);

GTlsConnectionBaseStatus  g_tls_thread_read (GTlsThread         *self,
                                             void               *buffer,
                                             gsize               size,
                                             gint64              timeout,
                                             gssize             *nread,
                                             GCancellable       *cancellable,
                                             GError            **error);

G_END_DECLS
