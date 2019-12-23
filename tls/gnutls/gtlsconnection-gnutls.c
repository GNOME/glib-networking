/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2009 Red Hat, Inc
 * Copyright 2015, 2016 Collabora, Ltd.
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

#include "config.h"
#include "glib.h"

/* FIXME: audit includes to remove */

#include <errno.h>
#include <stdarg.h>
#include <gnutls/dtls.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "gtlsconnection-gnutls.h"
#include "gtlsbackend-gnutls.h"
#include "gtlscertificate-gnutls.h"
#include "gtlsclientconnection-gnutls.h"
#include "gtlsoperationsthread-gnutls.h"

#ifdef G_OS_WIN32
#include <winsock2.h>
#include <winerror.h>

/* It isn’t clear whether MinGW always defines EMSGSIZE. */
#ifndef EMSGSIZE
#define EMSGSIZE WSAEMSGSIZE
#endif
#endif

#include <glib/gi18n-lib.h>
#include <glib/gprintf.h>

static GInitableIface *g_tls_connection_gnutls_parent_initable_iface;

static void g_tls_connection_gnutls_initable_iface_init (GInitableIface *iface);

typedef struct
{
  gnutls_session_t session; /* FIXME: should be used only by GTlsOperationsThreadGnutls */

} GTlsConnectionGnutlsPrivate;

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (GTlsConnectionGnutls, g_tls_connection_gnutls, G_TYPE_TLS_CONNECTION_BASE,
                                  G_ADD_PRIVATE (GTlsConnectionGnutls);
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
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (initable);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  if (!g_tls_connection_gnutls_parent_initable_iface->init (initable, cancellable, error))
    return FALSE;

  /* FIXME bad */
  priv->session = g_tls_operations_thread_gnutls_get_session (G_TLS_OPERATIONS_THREAD_GNUTLS (g_tls_connection_base_get_op_thread (G_TLS_CONNECTION_BASE (gnutls))));

  return TRUE;
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
  g_return_val_if_fail (!!base_io_stream != !!base_socket, FALSE);

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

static GTlsCertificate *
g_tls_connection_gnutls_retrieve_peer_certificate (GTlsConnectionBase *tls)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  const gnutls_datum_t *certs;
  GTlsCertificateGnutls *chain;
  unsigned int num_certs;

  if (gnutls_certificate_type_get (priv->session) != GNUTLS_CRT_X509)
    return NULL;

  certs = gnutls_certificate_get_peers (priv->session, &num_certs);
  if (!certs || !num_certs)
    return NULL;

  chain = g_tls_certificate_gnutls_build_chain (certs, num_certs, GNUTLS_X509_FMT_DER);
  if (!chain)
    return NULL;

  return G_TLS_CERTIFICATE (chain);
}

static gboolean
g_tls_connection_gnutls_is_session_resumed (GTlsConnectionBase *tls)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  return gnutls_session_is_resumed (priv->session);
}

static void
g_tls_connection_gnutls_class_init (GTlsConnectionGnutlsClass *klass)
{
  GTlsConnectionBaseClass *base_class = G_TLS_CONNECTION_BASE_CLASS (klass);

  base_class->create_op_thread                           = g_tls_connection_gnutls_create_op_thread;
  base_class->retrieve_peer_certificate                  = g_tls_connection_gnutls_retrieve_peer_certificate;
  base_class->is_session_resumed                         = g_tls_connection_gnutls_is_session_resumed;
}

static void
g_tls_connection_gnutls_initable_iface_init (GInitableIface *iface)
{
  g_tls_connection_gnutls_parent_initable_iface = g_type_interface_peek_parent (iface);

  iface->init = g_tls_connection_gnutls_initable_init;
}
