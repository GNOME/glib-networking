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

#include "gtlsconnection-base.h"

#include <gio/gio.h>

G_BEGIN_DECLS

#define G_TYPE_TLS_OPERATIONS_THREAD_BASE (g_tls_operations_thread_base_get_type ())

G_DECLARE_DERIVABLE_TYPE (GTlsOperationsThreadBase, g_tls_operations_thread_base, G, TLS_OPERATIONS_THREAD_BASE, GObject)

struct _GTlsOperationsThreadBaseClass
{
  GObjectClass parent_class;

  void                        (*copy_client_session_state)  (GTlsOperationsThreadBase  *self,
                                                             GTlsOperationsThreadBase  *source);
  void                        (*set_server_identity)        (GTlsOperationsThreadBase  *self,
                                                             const gchar               *server_identity);

  GTlsConnectionBaseStatus    (*handshake_fn)               (GTlsOperationsThreadBase  *self,
                                                             const gchar              **advertised_protocols,
                                                             gint64                     timeout,
                                                             GCancellable              *cancellable,
                                                             GError                   **error);

/* FIXME: working on these... */
#if 0
  GTlsCertificate            *(*retrieve_peer_certificate)  (GTlsOperationsThreadBase  *self);
  GTlsCertificateFlags        (*verify_peer_certificate)    (GTlsOperationsThreadBase  *self,
                                                             GTlsCertificate           *certificate,
                                                             GTlsCertificateFlags       flags);
  void                        (*complete_handshake)         (GTlsOperationsThreadBase  *self,
                                                             gchar                    **negotiated_protocol,
                                                             GError                   **error);
#endif

  GTlsConnectionBaseStatus    (*read_fn)                    (GTlsOperationsThreadBase  *self,
                                                             void                      *buffer,
                                                             gsize                      size,
                                                             gssize                    *nread,
                                                             GCancellable              *cancellable,
                                                             GError                   **error);
  GTlsConnectionBaseStatus    (*read_message_fn)            (GTlsOperationsThreadBase  *self,
                                                             GInputVector              *vectors,
                                                             guint                      num_vectors,
                                                             gssize                    *nread,
                                                             GCancellable              *cancellable,
                                                             GError                   **error);

  GTlsConnectionBaseStatus    (*write_fn)                   (GTlsOperationsThreadBase  *self,
                                                             const void                *buffer,
                                                             gsize                      size,
                                                             gssize                    *nwrote,
                                                             GCancellable              *cancellable,
                                                             GError                   **error);
  GTlsConnectionBaseStatus    (*write_message_fn)           (GTlsOperationsThreadBase  *self,
                                                             GOutputVector             *vectors,
                                                             guint                      num_vectors,
                                                             gssize                    *nwrote,
                                                             GCancellable              *cancellable,
                                                             GError                   **error);

  GTlsConnectionBaseStatus    (*close_fn)                   (GTlsOperationsThreadBase  *self,
                                                             GCancellable              *cancellable,
                                                             GError                   **error);
};

/* FIXME: remove!!! */
GTlsConnectionBase       *g_tls_operations_thread_base_get_connection            (GTlsOperationsThreadBase  *self);

void                      g_tls_operations_thread_base_copy_client_session_state (GTlsOperationsThreadBase  *self,
                                                                                  GTlsOperationsThreadBase  *source);

void                      g_tls_operations_thread_base_set_server_identity       (GTlsOperationsThreadBase  *self,
                                                                                  const gchar               *server_identity);

GTlsConnectionBaseStatus  g_tls_operations_thread_base_handshake                 (GTlsOperationsThreadBase  *self,
                                                                                  const gchar              **advertised_protocols,
                                                                                  gint64                     timeout,
                                                                                  GCancellable              *cancellable,
                                                                                  GError                   **error);

GTlsConnectionBaseStatus  g_tls_operations_thread_base_read                      (GTlsOperationsThreadBase  *self,
                                                                                  void                      *buffer,
                                                                                  gsize                      size,
                                                                                  gint64                     timeout,
                                                                                  gssize                    *nread,
                                                                                  GCancellable              *cancellable,
                                                                                  GError                   **error);

GTlsConnectionBaseStatus  g_tls_operations_thread_base_read_message              (GTlsOperationsThreadBase  *self,
                                                                                  GInputVector              *vectors,
                                                                                  guint                      num_vectors,
                                                                                  gint64                     timeout,
                                                                                  gssize                    *nread,
                                                                                  GCancellable              *cancellable,
                                                                                  GError                   **error);

GTlsConnectionBaseStatus  g_tls_operations_thread_base_write                     (GTlsOperationsThreadBase  *self,
                                                                                  const void                *buffer,
                                                                                  gsize                      size,
                                                                                  gint64                     timeout,
                                                                                  gssize                    *nwrote,
                                                                                  GCancellable              *cancellable,
                                                                                  GError                   **error);

GTlsConnectionBaseStatus  g_tls_operations_thread_base_write_message             (GTlsOperationsThreadBase  *self,
                                                                                  GOutputVector             *vectors,
                                                                                  guint                      num_vectors,
                                                                                  gint64                     timeout,
                                                                                  gssize                    *nwrote,
                                                                                  GCancellable              *cancellable,
                                                                                  GError                   **error);

GTlsConnectionBaseStatus  g_tls_operations_thread_base_close                     (GTlsOperationsThreadBase  *self,
                                                                                  GCancellable              *cancellable,
                                                                                  GError                   **error);

G_END_DECLS
