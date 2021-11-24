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

#ifdef __APPLE__
#include <Security/Security.h>
#endif

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
#ifdef __APPLE__
  CFArrayRef anchors;
  OSStatus ret;
  CFIndex i;

  ret = SecTrustCopyAnchorCertificates (&anchors);
  if (ret != errSecSuccess)
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                           _("Could not get trusted anchors from Keychain"));
      return FALSE;
    }

  for (i = 0; i < CFArrayGetCount (anchors); i++)
    {
      SecCertificateRef cert;
      CFDataRef data;

      cert = (SecCertificateRef)CFArrayGetValueAtIndex (anchors, i);
      data = SecCertificateCopyData (cert);
      if (data)
        {
          X509 *x;
          const unsigned char *pdata;

          pdata = (const unsigned char *)CFDataGetBytePtr (data);

          x = d2i_X509 (NULL, &pdata, CFDataGetLength (data));
          if (x)
            X509_STORE_add_cert (store, x);

          CFRelease (data);
        }
    }

  CFRelease (anchors);
#endif

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

GTlsCertificateFlags
g_tls_database_openssl_verify_ocsp_response (GTlsDatabaseOpenssl *self,
                                             GTlsCertificate     *chain,
                                             OCSP_RESPONSE       *resp)
{
  GTlsCertificateFlags errors = 0;
#if (OPENSSL_VERSION_NUMBER >= 0x0090808fL) && !defined(OPENSSL_NO_TLSEXT) && \
  !defined(OPENSSL_NO_OCSP)
  GTlsDatabaseOpensslPrivate *priv;
  STACK_OF(X509) *chain_openssl = NULL;
  OCSP_BASICRESP *basic_resp = NULL;
  int ocsp_status = 0;
  int i;

  ocsp_status = OCSP_response_status (resp);
  if (ocsp_status != OCSP_RESPONSE_STATUS_SUCCESSFUL)
    {
      errors = G_TLS_CERTIFICATE_GENERIC_ERROR;
      goto end;
    }

  basic_resp = OCSP_response_get1_basic (resp);
  if (basic_resp == NULL)
    {
      errors = G_TLS_CERTIFICATE_GENERIC_ERROR;
      goto end;
    }

  chain_openssl = convert_certificate_chain_to_openssl (G_TLS_CERTIFICATE_OPENSSL (chain));
  priv = g_tls_database_openssl_get_instance_private (self);
  if ((chain_openssl == NULL) ||
      (priv->store == NULL))
    {
      errors = G_TLS_CERTIFICATE_GENERIC_ERROR;
      goto end;
    }

  if (OCSP_basic_verify (basic_resp, chain_openssl, priv->store, 0) <= 0)
    {
      errors = G_TLS_CERTIFICATE_GENERIC_ERROR;
      goto end;
    }

  for (i = 0; i < OCSP_resp_count (basic_resp); i++)
    {
      OCSP_SINGLERESP *single_resp = OCSP_resp_get0 (basic_resp, i);
      ASN1_GENERALIZEDTIME *revocation_time = NULL;
      ASN1_GENERALIZEDTIME *this_update_time = NULL;
      ASN1_GENERALIZEDTIME *next_update_time = NULL;
      int crl_reason = 0;
      int cert_status = 0;

      if (single_resp == NULL)
        continue;

      cert_status = OCSP_single_get0_status (single_resp,
                                             &crl_reason,
                                             &revocation_time,
                                             &this_update_time,
                                             &next_update_time);
      if (!OCSP_check_validity (this_update_time,
                                next_update_time,
                                300L,
                                -1L))
        {
          errors = G_TLS_CERTIFICATE_GENERIC_ERROR;
          goto end;
        }

      switch (cert_status)
        {
        case V_OCSP_CERTSTATUS_GOOD:
          break;
        case V_OCSP_CERTSTATUS_REVOKED:
          errors = G_TLS_CERTIFICATE_REVOKED;
          goto end;
        case V_OCSP_CERTSTATUS_UNKNOWN:
          errors = G_TLS_CERTIFICATE_GENERIC_ERROR;
          goto end;
        }
    }

end:
  if (chain_openssl)
    sk_X509_free (chain_openssl);

  if (basic_resp)
    OCSP_BASICRESP_free (basic_resp);

  if (resp)
    OCSP_RESPONSE_free (resp);

#endif
  return errors;
}
