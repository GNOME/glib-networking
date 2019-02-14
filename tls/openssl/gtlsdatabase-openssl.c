/*
 * gtlsfiledatabase-openssl.c
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

typedef struct _GTlsDatabaseOpensslPrivate
{
  /*
   * This class is protected by mutex because the default GTlsDatabase
   * is a global singleton, accessible via the default GTlsBackend.
   */
  GMutex mutex;

  /* read-only after construct */
  X509_STORE *store;
  X509_STORE_CTX *store_ctx;

  /*
   * These are hash tables of gulong -> GPtrArray<GBytes>. The values of
   * the ptr array are full DER encoded certificate values. The keys are byte
   * arrays containing either subject DNs, issuer DNs, or full DER encoded certs
   */
  GHashTable *subjects;
  GHashTable *issuers;

  /*
   * This is a table of GBytes -> GBytes. The values and keys are
   * DER encoded certificate values.
   */
  GHashTable *complete;

  /*
   * This is a table of gchar * -> GPtrArray<GBytes>. The values of
   * the ptr array are full DER encoded certificate values. The keys are the
   * string handles. This array is populated on demand.
   */
  GHashTable *handles;
} GTlsDatabaseOpensslPrivate;

static void g_tls_database_openssl_initable_interface_init (GInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (GTlsDatabaseOpenssl, g_tls_database_openssl, G_TYPE_TLS_DATABASE,
                         G_ADD_PRIVATE (GTlsDatabaseOpenssl)
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                g_tls_database_openssl_initable_interface_init))

static GHashTable *
bytes_multi_table_new (void)
{
  return g_hash_table_new_full (g_int_hash, g_int_equal,
                                (GDestroyNotify)g_free,
                                (GDestroyNotify)g_ptr_array_unref);
}

static void
bytes_multi_table_insert (GHashTable *table,
                          gulong      key,
                          GBytes     *value)
{
  GPtrArray *multi;

  multi = g_hash_table_lookup (table, &key);
  if (multi == NULL)
    {
      int *key_ptr;

      key_ptr = g_new (int, 1);
      *key_ptr = (int)key;
      multi = g_ptr_array_new_with_free_func ((GDestroyNotify)g_bytes_unref);
      g_hash_table_insert (table, key_ptr, multi);
    }
  g_ptr_array_add (multi, g_bytes_ref (value));
}

static GBytes *
bytes_multi_table_lookup_ref_one (GHashTable *table,
                                  gulong      key)
{
  GPtrArray *multi;

  multi = g_hash_table_lookup (table, &key);
  if (multi == NULL)
    return NULL;

  g_assert (multi->len > 0);
  return g_bytes_ref (multi->pdata[0]);
}

static GList *
bytes_multi_table_lookup_ref_all (GHashTable *table,
                                  gulong      key)
{
  GPtrArray *multi;
  GList *list = NULL;
  guint i;

  multi = g_hash_table_lookup (table, &key);
  if (multi == NULL)
    return NULL;

  for (i = 0; i < multi->len; i++)
    list = g_list_prepend (list, g_bytes_ref (multi->pdata[i]));

  return g_list_reverse (list);
}

static GHashTable *
create_handles_array_unlocked (GTlsDatabaseOpenssl *self,
                               GHashTable          *complete)
{
  GHashTable *handles;
  GHashTableIter iter;
  GBytes *der;
  gchar *handle;

  handles = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
                                   (GDestroyNotify)g_bytes_unref);

  g_hash_table_iter_init (&iter, complete);
  while (g_hash_table_iter_next (&iter, NULL, (gpointer *)&der))
    {
      g_assert (G_TLS_DATABASE_OPENSSL_GET_CLASS (self)->create_handle_for_certificate);
      handle = G_TLS_DATABASE_OPENSSL_GET_CLASS (self)->create_handle_for_certificate (self, der);
      if (handle != NULL)
        g_hash_table_insert (handles, handle, g_bytes_ref (der));
    }

  return handles;
}

static gboolean
initialize_tables (X509_STORE *store,
                   GHashTable *subjects,
                   GHashTable *issuers,
                   GHashTable *complete)
{
  X509_STORE_CTX *store_ctx;
  STACK_OF(X509) *chain = NULL;
  gboolean ret = FALSE;
  int i;

  store_ctx = X509_STORE_CTX_new ();
  if (store_ctx == NULL)
    return FALSE;

  if (!X509_STORE_CTX_init (store_ctx, store, NULL, NULL))
    goto out;

  chain = X509_STORE_CTX_get1_chain (store_ctx);
  g_message("chain: %d", sk_X509_num (chain));

  for (i = 0; i < sk_X509_num (chain); i++)
    {
      X509 *x;
      unsigned long subject;
      unsigned long issuer;
      guint8 *data;
      int size;
      GBytes *der;

      x = sk_X509_value (chain, i);
      subject = X509_subject_name_hash (x);
      issuer = X509_issuer_name_hash (x);

      size = i2d_X509 (x, &data);
      der = g_bytes_new_take (der, size);

      g_hash_table_insert (complete, g_bytes_ref (der),
                           g_bytes_ref (der));

      bytes_multi_table_insert (subjects, subject, der);
      g_message ("issuer: %d", issuer);
      bytes_multi_table_insert (issuers, issuer, der);

      g_bytes_unref (der);
    }

  ret = TRUE;

out:
  X509_STORE_CTX_free (store_ctx);

  if (chain)
    sk_X509_pop_free (chain, X509_free);

  return ret;
}

static void
g_tls_database_openssl_finalize (GObject *object)
{
  GTlsDatabaseOpenssl *self = G_TLS_DATABASE_OPENSSL (object);
  GTlsDatabaseOpensslPrivate *priv;

  priv = g_tls_database_openssl_get_instance_private (self);

  g_clear_pointer (&priv->subjects, g_hash_table_destroy);
  g_clear_pointer (&priv->issuers, g_hash_table_destroy);
  g_clear_pointer (&priv->complete, g_hash_table_destroy);
  g_clear_pointer (&priv->handles, g_hash_table_destroy);

  if (priv->store != NULL)
    X509_STORE_free (priv->store);

  if (priv->store_ctx != NULL)
    X509_STORE_CTX_free (priv->store_ctx);

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

static gchar *
g_tls_database_openssl_create_certificate_handle (GTlsDatabase    *database,
                                                  GTlsCertificate *certificate)
{
  GTlsDatabaseOpenssl *self = G_TLS_DATABASE_OPENSSL (database);
  GTlsDatabaseOpensslPrivate *priv;
  GBytes *der;
  gboolean contains;
  gchar *handle = NULL;

  priv = g_tls_database_openssl_get_instance_private (self);

  der = g_tls_certificate_openssl_get_bytes (G_TLS_CERTIFICATE_OPENSSL (certificate));
  g_return_val_if_fail (der != NULL, FALSE);

  g_mutex_lock (&priv->mutex);

  /* At the same time look up whether this certificate is in list */
  contains = g_hash_table_lookup (priv->complete, der) ? TRUE : FALSE;

  g_mutex_unlock (&priv->mutex);

  /* Certificate is in the database */
  if (contains)
    {
      g_assert (G_TLS_DATABASE_OPENSSL_GET_CLASS (self)->create_handle_for_certificate);
      handle = G_TLS_DATABASE_OPENSSL_GET_CLASS (self)->create_handle_for_certificate (self, der);
    }

  g_bytes_unref (der);
  return handle;
}

static GTlsCertificate *
g_tls_database_openssl_lookup_certificate_for_handle (GTlsDatabase            *database,
                                                      const gchar             *handle,
                                                      GTlsInteraction         *interaction,
                                                      GTlsDatabaseLookupFlags  flags,
                                                      GCancellable            *cancellable,
                                                      GError                 **error)
{
  GTlsDatabaseOpenssl *self = G_TLS_DATABASE_OPENSSL (database);
  GTlsDatabaseOpensslPrivate *priv;
  GTlsCertificate *cert;
  GBytes *der;

  priv = g_tls_database_openssl_get_instance_private (self);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return NULL;

  if (!handle)
    return NULL;


  /* Create the handles table if not already done */
  if (!priv->handles)
    priv->handles = create_handles_array_unlocked (self, priv->complete);

  der = g_hash_table_lookup (priv->handles, handle);
  if (der != NULL)
    g_bytes_ref (der);

  g_mutex_unlock (&priv->mutex);

  if (der == NULL)
    return NULL;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    cert = NULL;
  else
    cert = g_tls_certificate_openssl_new (der, NULL);

  g_bytes_unref (der);
  return cert;
}

static GTlsCertificate *
g_tls_database_openssl_lookup_certificate_issuer (GTlsDatabase             *database,
                                                  GTlsCertificate          *certificate,
                                                  GTlsInteraction          *interaction,
                                                  GTlsDatabaseLookupFlags   flags,
                                                  GCancellable             *cancellable,
                                                  GError                  **error)
{
  GTlsDatabaseOpenssl *self = G_TLS_DATABASE_OPENSSL (database);
  GTlsDatabaseOpensslPrivate *priv;
  X509 *x, *issuer_x;
  GTlsCertificate *issuer = NULL;

  priv = g_tls_database_openssl_get_instance_private (self);

  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_OPENSSL (certificate), NULL);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return NULL;

  if (flags & G_TLS_DATABASE_LOOKUP_KEYPAIR)
    return NULL;

  /* Dig out the issuer of this certificate */
  x = g_tls_certificate_openssl_get_cert (G_TLS_CERTIFICATE_OPENSSL (certificate));
  if (!X509_STORE_CTX_get1_issuer (&issuer_x, priv->store_ctx, x))
    return NULL;

  issuer = g_tls_certificate_openssl_new_from_x509 (issuer_x, NULL);
  X509_free (issuer_x);

  return issuer;
}

static GList *
g_tls_database_openssl_lookup_certificates_issued_by (GTlsDatabase             *database,
                                                      GByteArray               *issuer_raw_dn,
                                                      GTlsInteraction          *interaction,
                                                      GTlsDatabaseLookupFlags   flags,
                                                      GCancellable             *cancellable,
                                                      GError                  **error)
{
  GTlsDatabaseOpenssl *self = G_TLS_DATABASE_OPENSSL (database);
  GTlsDatabaseOpensslPrivate *priv;
  X509_NAME *x_name;
  const unsigned char *in;
  GList *issued = NULL;

  priv = g_tls_database_openssl_get_instance_private (self);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return NULL;

  /* We don't have any private keys here */
  if (flags & G_TLS_DATABASE_LOOKUP_KEYPAIR)
    return NULL;

  in = issuer_raw_dn->data;
  x_name = d2i_X509_NAME (NULL, &in, issuer_raw_dn->len);
  if (x_name != NULL)
    {
      STACK_OF(X509) *certs;
      int i;

      certs = X509_STORE_get1_certs (priv->store_ctx, x_name);
      g_message ("issued: %d", sk_X509_num (certs));
      for (i = 0; i < sk_X509_num (certs); i++)
        {
          X509 *x;

          x = sk_X509_value (certs, i);
          issued = g_list_prepend (issued, g_tls_certificate_openssl_new_from_x509 (x, NULL));
        }

      sk_X509_pop_free (certs, X509_free);
      X509_NAME_free (x_name);
    }

  return issued;
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

static gchar *
g_tls_database_openssl_create_handle_for_certificate (GTlsDatabaseOpenssl *self,
                                                      GBytes              *der)
{
  gchar *bookmark;
  gchar *uri;

  /*
   * Here we create a URI that looks like
   * system-trust:#11b2641821252596420e468c275771f5e51022c121a17bd7a89a2f37b6336c8f.
   *
   * system-trust is a meaningless URI scheme, and the handle does not
   * even need to be a URI; this is just a nice stable way to uniquely
   * identify a certificate.
   */

  bookmark = g_compute_checksum_for_bytes (G_CHECKSUM_SHA256, der);
  uri = g_strconcat ("system-trust:#", bookmark, NULL);

  g_free (bookmark);

  return uri;
}

static gboolean
g_tls_database_openssl_populate_trust_list (GTlsDatabaseOpenssl  *self,
                                            X509_STORE           *store,
                                            GError              **error)
{
  X509_LOOKUP *lookup;

  lookup = X509_STORE_add_lookup (store, X509_LOOKUP_file ());
  if (lookup == NULL)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Failed to load system trust store file: %s"),
                   ERR_error_string (ERR_get_error (), NULL));
      return FALSE;
    }

  X509_LOOKUP_load_file (lookup, NULL, X509_FILETYPE_DEFAULT);

  lookup = X509_STORE_add_lookup (store, X509_LOOKUP_hash_dir ());
  if (lookup == NULL)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Failed to load system trust store: %s"),
                   ERR_error_string (ERR_get_error (), NULL));
      return FALSE;
    }

  X509_LOOKUP_add_dir (lookup, NULL, X509_FILETYPE_DEFAULT);

  /* clear any errors */
  ERR_clear_error ();

  return TRUE;
}

static void
g_tls_database_openssl_class_init (GTlsDatabaseOpensslClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsDatabaseClass *database_class = G_TLS_DATABASE_CLASS (klass);

  gobject_class->finalize     = g_tls_database_openssl_finalize;

  database_class->create_certificate_handle = g_tls_database_openssl_create_certificate_handle;
  database_class->lookup_certificate_for_handle = g_tls_database_openssl_lookup_certificate_for_handle;
  database_class->lookup_certificate_issuer = g_tls_database_openssl_lookup_certificate_issuer;
  database_class->lookup_certificates_issued_by = g_tls_database_openssl_lookup_certificates_issued_by;
  database_class->verify_chain = g_tls_database_openssl_verify_chain;

  klass->create_handle_for_certificate = g_tls_database_openssl_create_handle_for_certificate;
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
  X509_STORE_CTX *store_ctx;
  GHashTable *subjects, *issuers, *complete;
  gboolean result;

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

  store_ctx = X509_STORE_CTX_new ();
  if (store_ctx == NULL)
    return FALSE;

  if (!X509_STORE_CTX_init (store_ctx, store, NULL, NULL))
    goto out;

  subjects = bytes_multi_table_new ();
  issuers = bytes_multi_table_new ();

  complete = g_hash_table_new_full (g_bytes_hash, g_bytes_equal,
                                    (GDestroyNotify)g_bytes_unref,
                                    (GDestroyNotify)g_bytes_unref);

  if (!initialize_tables (store, subjects, issuers, complete))
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                           _("Could not initialize certificate chain data"));
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

      if (!priv->store_ctx)
        {
          priv->store_ctx = store_ctx;
          store_ctx = NULL;
        }

      if (!priv->subjects)
        {
          priv->subjects = subjects;
          subjects = NULL;
        }

      if (!priv->issuers)
        {
          priv->issuers = issuers;
          issuers = NULL;
        }

      if (!priv->complete)
        {
          priv->complete = complete;
          complete = NULL;
        }

      g_mutex_unlock (&priv->mutex);
    }

out:
  if (store != NULL)
    X509_STORE_free (store);
  if (store_ctx != NULL)
    X509_STORE_CTX_free (store_ctx);
  if (subjects != NULL)
    g_hash_table_unref (subjects);
  if (issuers != NULL)
    g_hash_table_unref (issuers);
  if (complete != NULL)
    g_hash_table_unref (complete);

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
  if (basic_resp != NULL)
    OCSP_BASICRESP_free (basic_resp);

  if (resp != NULL)
    OCSP_RESPONSE_free (resp);

#endif
  return errors;
}
