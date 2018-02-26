/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2009 Red Hat, Inc.
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

#ifndef __G_TLS_CONNECTION_GNUTLS_H__
#define __G_TLS_CONNECTION_GNUTLS_H__

#include <gio/gio.h>
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>

G_BEGIN_DECLS

#define G_TYPE_TLS_CONNECTION_GNUTLS            (g_tls_connection_gnutls_get_type ())

G_DECLARE_DERIVABLE_TYPE (GTlsConnectionGnutls, g_tls_connection_gnutls, G, TLS_CONNECTION_GNUTLS, GTlsConnection)

struct _GTlsConnectionGnutlsClass
{
  GTlsConnectionClass parent_class;

  void     (*failed)           (GTlsConnectionGnutls  *gnutls);

  void     (*begin_handshake)  (GTlsConnectionGnutls  *gnutls);
  void     (*finish_handshake) (GTlsConnectionGnutls  *gnutls,
                                GError               **inout_error);
};

gnutls_certificate_credentials_t g_tls_connection_gnutls_get_credentials (GTlsConnectionGnutls *connection);
gnutls_session_t                 g_tls_connection_gnutls_get_session     (GTlsConnectionGnutls *connection);

void     g_tls_connection_gnutls_get_certificate     (GTlsConnectionGnutls  *gnutls,
                                                      gnutls_pcert_st      **pcert,
                                                      unsigned int          *pcert_length,
                                                      gnutls_privkey_t      *pkey);

gboolean g_tls_connection_gnutls_request_certificate (GTlsConnectionGnutls  *gnutls,
                                                      GError               **error);

gssize   g_tls_connection_gnutls_read          (GTlsConnectionGnutls  *gnutls,
                                                void                  *buffer,
                                                gsize                  size,
                                                gint64                 timeout,
                                                GCancellable          *cancellable,
                                                GError               **error);
gssize   g_tls_connection_gnutls_write         (GTlsConnectionGnutls  *gnutls,
                                                const void            *buffer,
                                                gsize                  size,
                                                gint64                 timeout,
                                                GCancellable          *cancellable,
                                                GError               **error);

gboolean g_tls_connection_gnutls_check         (GTlsConnectionGnutls  *gnutls,
                                                GIOCondition           condition);
GSource *g_tls_connection_gnutls_create_source (GTlsConnectionGnutls  *gnutls,
                                                GIOCondition           condition,
                                                GCancellable          *cancellable);

typedef enum {
        G_TLS_DIRECTION_NONE = 0,
        G_TLS_DIRECTION_READ = 1 << 0,
        G_TLS_DIRECTION_WRITE = 1 << 1,
} GTlsDirection;

#define G_TLS_DIRECTION_BOTH (G_TLS_DIRECTION_READ | G_TLS_DIRECTION_WRITE)

gboolean g_tls_connection_gnutls_close_internal (GIOStream            *stream,
                                                 GTlsDirection         direction,
                                                 gint64                timeout,
                                                 GCancellable         *cancellable,
                                                 GError              **error);

G_END_DECLS

#endif /* __G_TLS_CONNECTION_GNUTLS_H___ */
