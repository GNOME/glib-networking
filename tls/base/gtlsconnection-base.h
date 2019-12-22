/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2009-2011 Red Hat, Inc
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
} GTlsConnectionBaseStatus; /* FIXME: move? rename? GTlsOperationsThreadBaseStatus */

typedef enum {
  G_TLS_DIRECTION_NONE = 0,
  G_TLS_DIRECTION_READ = 1 << 0,
  G_TLS_DIRECTION_WRITE = 1 << 1,
} GTlsDirection;

#define G_TLS_DIRECTION_BOTH (G_TLS_DIRECTION_READ | G_TLS_DIRECTION_WRITE)

typedef struct _GTlsOperationsThreadBase GTlsOperationsThreadBase;

struct _GTlsConnectionBaseClass
{
  GTlsConnectionClass parent_class;

  GTlsOperationsThreadBase   *(*create_op_thread)           (GTlsConnectionBase   *tls);

  gboolean                    (*is_session_resumed)         (GTlsConnectionBase   *tls);

  void                        (*push_io)                    (GTlsConnectionBase   *tls,
                                                             GIOCondition          direction,
                                                             gint64                timeout, /* FIXME: remove timeout */
                                                             GCancellable         *cancellable);
  GTlsConnectionBaseStatus    (*pop_io)                     (GTlsConnectionBase   *tls,
                                                             GIOCondition          direction,
                                                             gboolean              success,
                                                             GError              **error);

  void                        (*set_accepted_cas)           (GTlsConnectionBase    *tls,
                                                             GList                 *accepted_cas);
};

gboolean                  g_tls_connection_base_handshake_thread_verify_certificate
                                                                        (GTlsConnectionBase *tls);

void                      g_tls_connection_base_push_io                 (GTlsConnectionBase *tls,
                                                                         GIOCondition        direction,
                                                                         gint64              timeout, /* FIXME: remove timeout */
                                                                         GCancellable       *cancellable);
GTlsConnectionBaseStatus  g_tls_connection_base_pop_io                  (GTlsConnectionBase  *tls,
                                                                         GIOCondition         direction,
                                                                         gboolean             success,
                                                                         GError             **error);

gssize                    g_tls_connection_base_read                    (GTlsConnectionBase  *tls,
                                                                         void                *buffer,
                                                                         gsize                size,
                                                                         gint64               timeout,
                                                                         GCancellable        *cancellable,
                                                                         GError             **error);
gssize                    g_tls_connection_base_write                   (GTlsConnectionBase  *tls,
                                                                         const void          *buffer,
                                                                         gsize                size,
                                                                         gint64               timeout,
                                                                         GCancellable        *cancellable,
                                                                         GError             **error);

gboolean                  g_tls_connection_base_check                   (GTlsConnectionBase  *tls,
                                                                         GIOCondition         condition);
gboolean                  g_tls_connection_base_base_check              (GTlsConnectionBase  *tls,
                                                                         GIOCondition         condition);
GSource                  *g_tls_connection_base_create_source           (GTlsConnectionBase  *tls,
                                                                         GIOCondition         condition,
                                                                         GCancellable        *cancellable);
GSource                  *g_tls_connection_base_create_base_source      (GTlsConnectionBase  *tls,
                                                                         GIOCondition         condition,
                                                                         GCancellable        *cancellable);

gboolean                  g_tls_connection_base_close_internal          (GIOStream      *stream,
                                                                         GTlsDirection   direction,
                                                                         gint64          timeout,
                                                                         GCancellable   *cancellable,
                                                                         GError        **error);

/* FIXME: audit, which are still needed? */

gboolean                  g_tls_connection_base_is_dtls                 (GTlsConnectionBase *tls);

GDatagramBased           *g_tls_connection_base_get_base_socket         (GTlsConnectionBase *tls);

GIOStream                *g_tls_connection_base_get_base_iostream       (GTlsConnectionBase *tls);

void                      g_tls_connection_base_handshake_thread_set_missing_requested_client_certificate
                                                                        (GTlsConnectionBase *tls);

gboolean                  g_tls_connection_base_handshake_thread_request_certificate
                                                                        (GTlsConnectionBase  *tls);

void                      g_tls_connection_base_handshake_thread_buffer_application_data
                                                                        (GTlsConnectionBase *tls,
                                                                         guint8             *data,
                                                                         gsize               length);

/* FIXME: needed? */
GTlsOperationsThreadBase *g_tls_connection_base_get_op_thread           (GTlsConnectionBase *tls);

G_END_DECLS
