/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlsdatabase-openssl.c
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

#include "gtlsdatabase-openssl.h"

#include <gio/gio.h>
#include <glib/gi18n-lib.h>
#include "openssl-include.h"

typedef struct
{
  /*
   * This class is protected by mutex because the default GTlsDatabase
   * is a global singleton, accessible via the default GTlsBackend.
   */
  GMutex mutex;

  /* read-only after construct */
  X509_STORE *store;
} GTlsDatabaseOpensslPrivate;

static void g_tls_database_openssl_initable_interface_init (GInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (GTlsDatabaseOpenssl, g_tls_database_openssl, G_TYPE_TLS_DATABASE,
                         G_ADD_PRIVATE (GTlsDatabaseOpenssl)
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                g_tls_database_openssl_initable_interface_init))

static void
g_tls_database_openssl_finalize (GObject *object)
{
  GTlsDatabaseOpenssl *self = G_TLS_DATABASE_OPENSSL (object);
  GTlsDatabaseOpensslPrivate *priv;

  priv = g_tls_database_openssl_get_instance_private (self);

  if (priv->store)
    X509_STORE_free (priv->store);

  g_mutex_clear (&priv->mutex);

  G_OBJECT_CLASS (g_tls_database_openssl_parent_class)->finalize (object);
}

static void
g_tls_database_openssl_init (GTlsDatabaseOpenssl *self)
{
  GTlsDatabaseOpensslPrivate *priv;

  priv = g_tls_database_openssl_get_instance_private (self);

  g_mutex_init (&priv->mutex);
}

static GTlsCertificateFlags
double_check_before_after_dates (GTlsCertificateOpenssl *chain)
{
  GTlsCertificateFlags gtls_flags = 0;
  X509 *cert;

  while (chain)
    {
      ASN1_TIME *not_before;
      ASN1_TIME *not_after;

      cert = g_tls_certificate_openssl_get_cert (chain);
      not_before = X509_get_notBefore (cert);
      not_after = X509_get_notAfter (cert);

      if (X509_cmp_current_time (not_before) > 0)
        gtls_flags |= G_TLS_CERTIFICATE_NOT_ACTIVATED;

      if (X509_cmp_current_time (not_after) < 0)
        gtls_flags |= G_TLS_CERTIFICATE_EXPIRED;

      chain = G_TLS_CERTIFICATE_OPENSSL (g_tls_certificate_get_issuer
                                         (G_TLS_CERTIFICATE (chain)));
    }

  return gtls_flags;
}

static STACK_OF(X509) *
convert_certificate_chain_to_openssl (GTlsCertificateOpenssl *chain)
{
  GTlsCertificate *cert;
  STACK_OF(X509) *openssl_chain;

  openssl_chain = sk_X509_new_null ();

  for (cert = G_TLS_CERTIFICATE (chain); cert; cert = g_tls_certificate_get_issuer (cert))
    sk_X509_push (openssl_chain, g_tls_certificate_openssl_get_cert (G_TLS_CERTIFICATE_OPENSSL (cert)));

  return openssl_chain;
}

static GTlsCertificateFlags
g_tls_database_openssl_verify_chain (GTlsDatabase             *database,
                                     GTlsCertificate          *chain,
                                     const gchar              *purpose,
                                     GSocketConnectable       *identity,
                                     GTlsInteraction          *interaction,
                                     GTlsDatabaseVerifyFlags   flags,
                                     GCancellable             *cancellable,
                                     GError                  **error)
{
  GTlsDatabaseOpenssl *self = G_TLS_DATABASE_OPENSSL (database);
  GTlsDatabaseOpensslPrivate *priv;
  STACK_OF(X509) *certs;
  X509_STORE_CTX *csc;
  X509 *x;
  GTlsCertificateFlags result = 0;

  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_OPENSSL (chain),
                        G_TLS_CERTIFICATE_GENERIC_ERROR);

  priv = g_tls_database_openssl_get_instance_private (self);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return G_TLS_CERTIFICATE_GENERIC_ERROR;

  certs = convert_certificate_chain_to_openssl (G_TLS_CERTIFICATE_OPENSSL (chain));

  csc = X509_STORE_CTX_new ();

  x = g_tls_certificate_openssl_get_cert (G_TLS_CERTIFICATE_OPENSSL (chain));
  if (!X509_STORE_CTX_init (csc, priv->store, x, certs))
    {
      X509_STORE_CTX_free (csc);
      sk_X509_free (certs);
      return G_TLS_CERTIFICATE_GENERIC_ERROR;
    }

  if (X509_verify_cert (csc) <= 0)
    result = g_tls_certificate_openssl_convert_error (X509_STORE_CTX_get_error (csc));

  X509_STORE_CTX_free (csc);
  sk_X509_free (certs);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return G_TLS_CERTIFICATE_GENERIC_ERROR;

  /* We have to check these ourselves since openssl
   * does not give us flags and UNKNOWN_CA will take priority.
   */
  result |= double_check_before_after_dates (G_TLS_CERTIFICATE_OPENSSL (chain));

  if (identity)
    result |= g_tls_certificate_openssl_verify_identity (G_TLS_CERTIFICATE_OPENSSL (chain),
                                                         identity);

  return result;
}

static gboolean
g_tls_database_openssl_populate_trust_list (GTlsDatabaseOpenssl  *self,
                                            X509_STORE           *store,
                                            GError              **error)
{
  if (!X509_STORE_set_default_paths (store))
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Failed to load system trust store: %s"),
                   ERR_error_string (ERR_get_error (), NULL));
      return FALSE;
    }

  return TRUE;
}

static void
g_tls_database_openssl_class_init (GTlsDatabaseOpensslClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsDatabaseClass *database_class = G_TLS_DATABASE_CLASS (klass);

  gobject_class->finalize = g_tls_database_openssl_finalize;

  database_class->verify_chain = g_tls_database_openssl_verify_chain;

  klass->populate_trust_list = g_tls_database_openssl_populate_trust_list;
}

static gboolean
g_tls_database_openssl_initable_init (GInitable    *initable,
                                      GCancellable *cancellable,
                                      GError      **error)
{
  GTlsDatabaseOpenssl *self = G_TLS_DATABASE_OPENSSL (initable);
  GTlsDatabaseOpensslPrivate *priv;
  X509_STORE *store;
  gboolean result = TRUE;

  priv = g_tls_database_openssl_get_instance_private (self);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return FALSE;

  store = X509_STORE_new ();
  if (store == NULL)
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                           _("Could not create CA store"));
      result = FALSE;
      goto out;
    }

  g_assert (G_TLS_DATABASE_OPENSSL_GET_CLASS (self)->populate_trust_list);
  if (!G_TLS_DATABASE_OPENSSL_GET_CLASS (self)->populate_trust_list (self, store, error))
    {
      result = FALSE;
      goto out;
    }

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    result = FALSE;

  if (result)
    {
      g_mutex_lock (&priv->mutex);
      if (!priv->store)
        {
          priv->store = store;
          store = NULL;
        }
      g_mutex_unlock (&priv->mutex);
    }

out:
  if (store)
    X509_STORE_free (store);

  return result;
}

static void
g_tls_database_openssl_initable_interface_init (GInitableIface *iface)
{
  iface->init = g_tls_database_openssl_initable_init;
}

GTlsDatabaseOpenssl *
g_tls_database_openssl_new (GError **error)
{
  g_return_val_if_fail (!error || !*error, NULL);

  return g_initable_new (G_TYPE_TLS_DATABASE_OPENSSL, NULL, error, NULL);
}
