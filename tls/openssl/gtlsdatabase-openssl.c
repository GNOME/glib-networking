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

/*
 * SecTrustCopyAnchorCertificates is only available on macOS, so we check for
 * SEC_OS_OSX: https://github.com/Apple-FOSS-Mirror/Security/blob/master/base/SecBase.h
 */
#ifdef __APPLE__
#include <Security/Security.h>
#else
#define SEC_OS_OSX 0
#endif

#ifdef G_OS_WIN32
#include <wincrypt.h>
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

#if SEC_OS_OSX
static gboolean
is_certificate_trusted (SecCertificateRef       *cert,
                        SecTrustSettingsDomain   domain,
                        GError                 **error)
{
  CFArrayRef cert_trust_settings;
  OSStatus ret;
  CFIndex i;

  ret = SecTrustSettingsCopyTrustSettings (*cert, domain, &cert_trust_settings);
  if (ret != errSecSuccess)
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                           _("Could not get trust settings for certificate"));
      return FALSE;
    }

  for (i = 0; i < CFArrayGetCount (cert_trust_settings); i++)
    {
      CFDictionaryRef trust_settings;
      CFNumberRef trust_setting_number;
      CFStringRef policy_name;

      /* Ignore trust settings which are not SSL policies. */
      trust_settings = (CFDictionaryRef)CFArrayGetValueAtIndex (cert_trust_settings, i);
      if (CFDictionaryGetValueIfPresent (trust_settings, kSecTrustSettingsPolicyString, 
                                         (const void **)&policy_name) &&
          CFStringCompare (policy_name, CFSTR ("sslServer"), 0) != kCFCompareEqualTo)
        {
          continue;
        }

      if (CFDictionaryGetValueIfPresent (trust_settings, kSecTrustSettingsResult, 
                                         (const void **)&trust_setting_number))
        {
          SecTrustSettingsResult trustSettingResult;

          if (trust_setting_number == NULL)
            {
              CFRelease (cert_trust_settings);
              return TRUE;
            }

          CFNumberGetValue (trust_setting_number, kCFNumberIntType, &trustSettingResult);
          /* kSecTrustSettingsResultUnspecified means neither trusted nor distrusted.  
           * kSecTrustSettingsResultInvalid should not be a possible value for trustSettingResult.
           * 
           * Only for kSecTrustSettingsResultDeny should the certificate not be trusted.
           */
          if (trustSettingResult != kSecTrustSettingsResultUnspecified && 
              trustSettingResult != kSecTrustSettingsResultInvalid)
            {
              CFRelease (cert_trust_settings);
              return trustSettingResult != kSecTrustSettingsResultDeny;
            }
        }
     }

  CFRelease (cert_trust_settings);

  /* We only reach here if the trust settings array is empty or trust setting parameter for 
   * a certificate is NULL. The documentation state that we should trust these certificates
   * as kSecTrustSettingsResultTrustRoot as only root certificates can have have that value.
   * 
   * https://developer.apple.com/documentation/security/1400261-sectrustsettingscopytrustsetting?language=objc
   * 
   * If it is not a root certificate then we trust it as root because they are retrieved
   * from the trust domains.
   */
  return TRUE;
}

static gboolean
populate_store (X509_STORE  *store,
                GError     **error)
{
  SecTrustSettingsDomain domains[] = { kSecTrustSettingsDomainUser, 
                                       kSecTrustSettingsDomainAdmin, 
                                       kSecTrustSettingsDomainSystem };
  GHashTable *trusted_certs = g_hash_table_new_full (g_bytes_hash, g_bytes_equal, 
                                                     (GDestroyNotify)g_bytes_unref, NULL);
  gboolean result = FALSE;

  for (int i = 0; i < G_N_ELEMENTS (domains); i++)
   {
      SecTrustSettingsDomain domain = domains[i];
      CFArrayRef domain_certs;
      OSStatus ret;
      CFIndex j;

      ret = SecTrustSettingsCopyCertificates (domain, &domain_certs);
      if (ret == errSecNoTrustSettings)
        {
          g_debug ("Domain %d was skipped as no trust settings were found", domain);
          continue;
        }
        
      if (ret != errSecSuccess)
        {
          g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                               _("Could not retrieve certificates"));
          goto out;
        }

      for (j = 0; j < CFArrayGetCount (domain_certs); j++)
        {
          SecCertificateRef cert;
          CFDataRef data;
          X509 *cert_x509;
          GBytes *cert_bytes;
          const unsigned char *pdata;

          cert = (SecCertificateRef)CFArrayGetValueAtIndex (domain_certs, j);
          if (!is_certificate_trusted (&cert, domain, error))
            {
              continue;
            }

          data = SecCertificateCopyData (cert);
          if (data == NULL)
            {
              continue;
            }

          pdata = (const unsigned char *)CFDataGetBytePtr (data);
          cert_x509 = d2i_X509 (NULL, &pdata, CFDataGetLength (data));
          if (cert_x509 == NULL)
            {
              CFRelease (data);
              continue;
            }

          cert_bytes = g_bytes_new (CFDataGetBytePtr (data), CFDataGetLength (data));
          if (cert_bytes == NULL)
            {
              goto next;
            }

          if (!g_hash_table_contains (trusted_certs, cert_bytes))
            {
              g_hash_table_add (trusted_certs, g_bytes_ref (cert_bytes));
              X509_STORE_add_cert (store, cert_x509);
            }

          g_bytes_unref (cert_bytes);

        next:
          X509_free (cert_x509);
          CFRelease (data);
        }

      CFRelease (domain_certs);
    }

  result = TRUE;

out:  
  g_hash_table_unref (trusted_certs);

  return result;
}

#elif defined(G_OS_WIN32)
static gboolean
add_certs_from_store (const gunichar2 *source_cert_store_name,
                      X509_STORE      *store)
{
  HANDLE store_handle;
  PCCERT_CONTEXT cert_context = NULL;

  store_handle = CertOpenSystemStoreW (0, source_cert_store_name);
  if (store_handle == NULL)
    return FALSE;

  while (cert_context = CertEnumCertificatesInStore (store_handle, cert_context))
    {
      X509 *x;
      const unsigned char *pdata;

      pdata = (const unsigned char *)cert_context->pbCertEncoded;

      x = d2i_X509 (NULL, &pdata, cert_context->cbCertEncoded);
      if (x)
        X509_STORE_add_cert (store, x);
    }

  CertCloseStore (store_handle, 0);
  return TRUE;
}

static gboolean
populate_store (X509_STORE  *store,
                GError     **error)
{
  if (!add_certs_from_store (L"ROOT", store))
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                           _("Could not get root certificate store"));
      return FALSE;
    }

  if (!add_certs_from_store (L"CA", store))
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                           _("Could not get CA certificate store"));
      return FALSE;
    }

  return TRUE;
}
#else
static gboolean
populate_store (X509_STORE  *store,
                GError     **error)
{
  if (!X509_STORE_set_default_paths (store))
    {
      char error_buffer[256];
      ERR_error_string_n (ERR_get_error (), error_buffer, sizeof (error_buffer));
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Failed to load system trust store: %s"),
                   error_buffer);
      return FALSE;
    }

  return TRUE;
}
#endif

static gboolean
g_tls_database_openssl_populate_trust_list (GTlsDatabaseOpenssl  *self,
                                            X509_STORE           *store,
                                            GError              **error)
{
  return populate_store (store, error);
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
