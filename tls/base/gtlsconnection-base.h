/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2009-2011 Red Hat, Inc
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

#ifndef __G_TLS_CONNECTION_BASE_H__
#define __G_TLS_CONNECTION_BASE_H__

#include <gio/gio.h>

G_BEGIN_DECLS

#define G_TYPE_TLS_CONNECTION_BASE            (g_tls_connection_base_get_type ())

G_DECLARE_DERIVABLE_TYPE (GTlsConnectionBase, g_tls_connection_base, G, TLS_CONNECTION_BASE, GTlsConnection)

typedef enum {
  G_TLS_CONNECTION_BASE_OK,
  G_TLS_CONNECTION_BASE_WOULD_BLOCK,
  G_TLS_CONNECTION_BASE_TIMED_OUT,
  G_TLS_CONNECTION_BASE_REHANDSHAKE,
  G_TLS_CONNECTION_BASE_TRY_AGAIN,
  G_TLS_CONNECTION_BASE_ERROR,
} GTlsConnectionBaseStatus;

typedef enum {
        G_TLS_DIRECTION_NONE = 0,
        G_TLS_DIRECTION_READ = 1 << 0,
        G_TLS_DIRECTION_WRITE = 1 << 1,
} GTlsDirection;

#define G_TLS_DIRECTION_BOTH (G_TLS_DIRECTION_READ | G_TLS_DIRECTION_WRITE)

struct _GTlsConnectionBaseClass
{
  GTlsConnectionClass parent_class;

  GTlsConnectionBaseStatus (*request_rehandshake)  (GTlsConnectionBase  *tls,
                                                    gint64               timeout,
                                                    GCancellable        *cancellable,
                                                    GError             **error);
  GTlsConnectionBaseStatus (*handshake)            (GTlsConnectionBase  *tls,
                                                    gint64               timeout,
                                                    GCancellable        *cancellable,
                                                    GError             **error);
  GTlsConnectionBaseStatus (*complete_handshake)   (GTlsConnectionBase  *tls,
                                                    GError             **error);

  void                     (*push_io)              (GTlsConnectionBase  *tls,
                                                    GIOCondition         direction,
                                                    gint64               timeout,
                                                    GCancellable        *cancellable);
  GTlsConnectionBaseStatus (*pop_io)               (GTlsConnectionBase  *tls,
                                                    GIOCondition         direction,
                                                    gboolean             success,
                                                    GError             **error);

  GTlsConnectionBaseStatus (*read_fn)              (GTlsConnectionBase  *tls,
                                                    void                *buffer,
                                                    gsize                count,
                                                    gint64               timeout,
                                                    gssize              *nread,
                                                    GCancellable        *cancellable,
                                                    GError             **error);
  GTlsConnectionBaseStatus (*read_message_fn)      (GTlsConnectionBase  *tls,
                                                    GInputVector        *vectors,
                                                    guint                num_vectors,
                                                    gint64               timeout,
                                                    gssize              *nread,
                                                    GCancellable        *cancellable,
                                                    GError             **error);

  GTlsConnectionBaseStatus (*write_fn)             (GTlsConnectionBase  *tls,
                                                    const void          *buffer,
                                                    gsize                count,
                                                    gint64               timeout,
                                                    gssize              *nwrote,
                                                    GCancellable        *cancellable,
                                                    GError             **error);
  GTlsConnectionBaseStatus (*write_message_fn)     (GTlsConnectionBase  *tls,
                                                    GOutputVector       *vectors,
                                                    guint                num_vectors,
                                                    gint64               timeout,
                                                    gssize              *nwrote,
                                                    GCancellable        *cancellable,
                                                    GError             **error);

  GTlsConnectionBaseStatus (*close_fn)             (GTlsConnectionBase  *tls,
                                                    gint64               timeout,
                                                    GCancellable        *cancellable,
                                                    GError             **error);
};

gboolean g_tls_connection_base_accept_peer_certificate (GTlsConnectionBase   *tls,
                                                        GTlsCertificate      *peer_certificate,
                                                        GTlsCertificateFlags  peer_certificate_errors);

void g_tls_connection_base_set_peer_certificate (GTlsConnectionBase   *tls,
                                                 GTlsCertificate      *peer_certificate,
                                                 GTlsCertificateFlags  peer_certificate_errors);

void     g_tls_connection_base_push_io       (GTlsConnectionBase *tls,
                                              GIOCondition        direction,
                                              gint64              timeout,
                                              GCancellable       *cancellable);
GTlsConnectionBaseStatus
         g_tls_connection_base_pop_io        (GTlsConnectionBase  *tls,
                                              GIOCondition         direction,
                                              gboolean             success,
                                              GError             **error);

gssize   g_tls_connection_base_read          (GTlsConnectionBase  *tls,
                                              void                *buffer,
                                              gsize                size,
                                              gint64               timeout,
                                              GCancellable        *cancellable,
                                              GError             **error);
gssize   g_tls_connection_base_write         (GTlsConnectionBase  *tls,
                                              const void          *buffer,
                                              gsize                size,
                                              gint64               timeout,
                                              GCancellable        *cancellable,
                                              GError             **error);

gboolean g_tls_connection_base_check         (GTlsConnectionBase  *tls,
                                              GIOCondition         condition);
GSource *g_tls_connection_base_create_source (GTlsConnectionBase  *tls,
                                              GIOCondition         condition,
                                              GCancellable        *cancellable);

gboolean g_tls_connection_base_close_internal (GIOStream      *stream,
                                               GTlsDirection   direction,
                                               gint64          timeout,
                                               GCancellable   *cancellable,
                                               GError        **error);

void     g_tls_connection_base_set_certificate_requested (GTlsConnectionBase *tls);

GError **g_tls_connection_base_get_certificate_error     (GTlsConnectionBase *tls);
GError **g_tls_connection_base_get_read_error            (GTlsConnectionBase *tls);
GError **g_tls_connection_base_get_write_error           (GTlsConnectionBase *tls);

gboolean g_tls_connection_base_is_handshaking            (GTlsConnectionBase *tls);

gboolean g_tls_connection_base_ever_handshaked           (GTlsConnectionBase *tls);

gboolean g_tls_connection_base_request_certificate (GTlsConnectionBase  *tls,
                                                    GError             **error);

G_END_DECLS

#endif /* __G_TLS_CONNECTION_BASE_H___ */
