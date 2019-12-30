/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlsconnection-openssl.c
 *
 * Copyright (C) 2015 NICE s.r.l.
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
  BIO *bio;
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
  return g_tls_operations_thread_openssl_new (G_TLS_CONNECTION_OPENSSL (tls));
}

static GTlsCertificate *
g_tls_connection_openssl_retrieve_peer_certificate (GTlsConnectionBase *tls)
{
  X509 *peer;
  STACK_OF (X509) *certs;
  GTlsCertificateOpenssl *chain;
  SSL *ssl;

  ssl = g_tls_connection_openssl_get_ssl (G_TLS_CONNECTION_OPENSSL (tls));

  peer = SSL_get_peer_certificate (ssl);
  if (!peer)
    return NULL;

  certs = SSL_get_peer_cert_chain (ssl);
  if (!certs)
    {
      X509_free (peer);
      return NULL;
    }

  chain = g_tls_certificate_openssl_build_chain (peer, certs);
  X509_free (peer);
  if (!chain)
    return NULL;

  return G_TLS_CERTIFICATE (chain);
}

/* FIXME: move to op thread? */
static void
g_tls_connection_openssl_push_io (GTlsConnectionBase *tls,
                                  GIOCondition        direction,
                                  gint64              timeout,
                                  GCancellable       *cancellable)
{
  GTlsConnectionOpenssl *openssl = G_TLS_CONNECTION_OPENSSL (tls);
  GTlsConnectionOpensslPrivate *priv;
  GError **error;

  priv = g_tls_connection_openssl_get_instance_private (openssl);;

  /* FIXME: need to support timeout > 0
   * This will require changes in GTlsBio
   */

  if (direction & G_IO_IN)
    {
      error = g_tls_connection_base_get_read_error (tls);
      g_tls_bio_set_read_cancellable (priv->bio, cancellable);
      g_tls_bio_set_read_blocking (priv->bio, timeout == -1);
      g_clear_error (error);
      g_tls_bio_set_read_error (priv->bio, error);
    }

  if (direction & G_IO_OUT)
    {
      error = g_tls_connection_base_get_write_error (tls);
      g_tls_bio_set_write_cancellable (priv->bio, cancellable);
      g_tls_bio_set_write_blocking (priv->bio, timeout == -1);
      g_clear_error (error);
      g_tls_bio_set_write_error (priv->bio, error);
    }
}

static GTlsOperationStatus
g_tls_connection_openssl_pop_io (GTlsConnectionBase  *tls,
                                 GIOCondition         direction,
                                 gboolean             success,
                                 GError             **error)
{
  GTlsConnectionOpenssl *openssl = G_TLS_CONNECTION_OPENSSL (tls);
  GTlsConnectionOpensslPrivate *priv;

  priv = g_tls_connection_openssl_get_instance_private (openssl);

  if (direction & G_IO_IN)
    g_tls_bio_set_read_cancellable (priv->bio, NULL);

  if (direction & G_IO_OUT)
    g_tls_bio_set_write_cancellable (priv->bio, NULL);

  return G_TLS_CONNECTION_BASE_CLASS (g_tls_connection_openssl_parent_class)->pop_io (tls, direction,
                                                                                      success, error);
}

static void
g_tls_connection_openssl_class_init (GTlsConnectionOpensslClass *klass)
{
  GTlsConnectionBaseClass *base_class = G_TLS_CONNECTION_BASE_CLASS (klass);

  base_class->create_op_thread                           = g_tls_connection_openssl_create_op_thread;
  /* FIXME: remove */
  base_class->retrieve_peer_certificate                  = g_tls_connection_openssl_retrieve_peer_certificate;
  base_class->push_io                                    = g_tls_connection_openssl_push_io; /* FIXME: move to op thread */
  base_class->pop_io                                     = g_tls_connection_openssl_pop_io;
}

static int data_index = -1;

static gboolean
g_tls_connection_openssl_initable_init (GInitable     *initable,
                                        GCancellable  *cancellable,
                                        GError       **error)
{
  GTlsConnectionOpenssl *openssl = G_TLS_CONNECTION_OPENSSL (initable);
  GTlsConnectionOpensslPrivate *priv;
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (initable);
  GIOStream *base_io_stream;
  SSL *ssl;

  g_object_get (tls,
                "base-io-stream", &base_io_stream,
                NULL);
  g_return_val_if_fail (base_io_stream, FALSE);

  priv = g_tls_connection_openssl_get_instance_private (openssl);

  ssl = g_tls_connection_openssl_get_ssl (openssl);
  g_assert (ssl);

  if (data_index == -1) {
      data_index = SSL_get_ex_new_index (0, (void *)"gtlsconnection", NULL, NULL, NULL);
  }
  SSL_set_ex_data (ssl, data_index, openssl);

  priv->bio = g_tls_bio_new (base_io_stream);

  SSL_set_bio (ssl, priv->bio, priv->bio);

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

SSL *
g_tls_connection_openssl_get_ssl (GTlsConnectionOpenssl *openssl)
{
  g_return_val_if_fail (G_IS_TLS_CONNECTION_OPENSSL (openssl), NULL);

  return G_TLS_CONNECTION_OPENSSL_GET_CLASS (openssl)->get_ssl (openssl);
}

GTlsConnectionOpenssl *
g_tls_connection_openssl_get_connection_from_ssl (SSL *ssl)
{
  g_return_val_if_fail (ssl, NULL);

  return SSL_get_ex_data (ssl, data_index);
}
