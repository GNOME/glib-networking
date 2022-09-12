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

#pragma once

#include <gio/gio.h>
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>

#include "gtlsconnection-base.h"

G_BEGIN_DECLS

#define G_TYPE_TLS_CONNECTION_GNUTLS            (g_tls_connection_gnutls_get_type ())

G_DECLARE_DERIVABLE_TYPE (GTlsConnectionGnutls, g_tls_connection_gnutls, G, TLS_CONNECTION_GNUTLS, GTlsConnectionBase)

struct _GTlsConnectionGnutlsClass
{
  GTlsConnectionBaseClass parent_class;

  void (*update_credentials) (GTlsConnectionGnutls             *gnutls,
                              gnutls_certificate_credentials_t  credentials);
};

gnutls_certificate_credentials_t g_tls_connection_gnutls_get_credentials (GTlsConnectionGnutls *connection);

gnutls_session_t                 g_tls_connection_gnutls_get_session     (GTlsConnectionGnutls *connection);

void     g_tls_connection_gnutls_handshake_thread_get_certificate     (GTlsConnectionGnutls  *gnutls,
                                                                       gnutls_pcert_st      **pcert,
                                                                       unsigned int          *pcert_length,
                                                                       gnutls_privkey_t      *pkey);

GTlsProtocolVersion glib_protocol_version_from_gnutls (gnutls_protocol_t protocol_version);

G_END_DECLS
