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

#include "GTlsConnectionBase.h"

G_BEGIN_DECLS

#define G_TYPE_TLS_THREAD_BASE            (g_tls_thread_base_get_type ())

G_DECLARE_DERIVABLE_TYPE (GTlsThreadBase, g_tls_thread_base, G, TLS_THREAD_BASE, GObject)

struct _GTlsThreadBaseClass
{
  GObjectClass parent_class;

#if 0
  void                        (*prepare_handshake)          (GTlsConnectionBase   *tls,
                                                             gchar               **advertised_protocols);
  GTlsSafeRenegotiationStatus (*handshake_thread_safe_renegotiation_status)
                                                            (GTlsConnectionBase    *tls);
  GTlsConnectionBaseStatus    (*handshake_thread_request_rehandshake)
                                                            (GTlsConnectionBase   *tls,
                                                             gint64                timeout,
                                                             GCancellable         *cancellable,
                                                             GError              **error);
  GTlsConnectionBaseStatus    (*handshake_thread_handshake) (GTlsConnectionBase   *tls,
                                                             gint64                timeout,
                                                             GCancellable         *cancellable,
                                                             GError              **error);
  GTlsCertificate            *(*retrieve_peer_certificate)  (GTlsConnectionBase   *tls);
  GTlsCertificateFlags        (*verify_peer_certificate)    (GTlsConnectionBase   *tls,
                                                             GTlsCertificate      *certificate,
                                                             GTlsCertificateFlags  flags);
  void                        (*complete_handshake)         (GTlsConnectionBase   *tls,
                                                             gchar               **negotiated_protocol,
                                                             GError              **error);

  gboolean                    (*is_session_resumed)         (GTlsConnectionBase   *tls);

  void                        (*push_io)                    (GTlsConnectionBase   *tls,
                                                             GIOCondition          direction,
                                                             gint64                timeout,
                                                             GCancellable         *cancellable);
  GTlsConnectionBaseStatus    (*pop_io)                     (GTlsConnectionBase   *tls,
                                                             GIOCondition          direction,
                                                             gboolean              success,
                                                             GError              **error);

  GTlsConnectionBaseStatus    (*read_fn)                    (GTlsConnectionBase   *tls,
                                                             void                 *buffer,
                                                             gsize                 count,
                                                             gint64                timeout,
                                                             gssize               *nread,
                                                             GCancellable         *cancellable,
                                                             GError              **error);
  GTlsConnectionBaseStatus    (*read_message_fn)            (GTlsConnectionBase   *tls,
                                                             GInputVector         *vectors,
                                                             guint                 num_vectors,
                                                             gint64                timeout,
                                                             gssize               *nread,
                                                             GCancellable         *cancellable,
                                                             GError              **error);

  GTlsConnectionBaseStatus    (*write_fn)                   (GTlsConnectionBase   *tls,
                                                             const void           *buffer,
                                                             gsize                 count,
                                                             gint64                timeout,
                                                             gssize               *nwrote,
                                                             GCancellable         *cancellable,
                                                             GError              **error);
  GTlsConnectionBaseStatus    (*write_message_fn)           (GTlsConnectionBase   *tls,
                                                             GOutputVector        *vectors,
                                                             guint                 num_vectors,
                                                             gint64                timeout,
                                                             gssize               *nwrote,
                                                             GCancellable         *cancellable,
                                                             GError              **error);

  GTlsConnectionBaseStatus    (*close_fn)                   (GTlsConnectionBase   *tls,
                                                             gint64                timeout,
                                                             GCancellable         *cancellable,
                                                             GError              **error);
#endif
};

gssize g_tls_thread_base_read (GTlsThreadBase  *tls,
                               void            *buffer,
                               gsize            size,
                               gint64           timeout,
                               GCancellable    *cancellable,
                               GError         **error);

G_END_DECLS
