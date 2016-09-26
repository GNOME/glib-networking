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

#include "gtlsfiledatabase-openssl.h"

#include <gio/gio.h>
#include <glib/gi18n-lib.h>
#include <openssl/ssl.h>

typedef struct _GTlsFileDatabaseOpensslPrivate
{
  /* read-only after construct */
  gchar *anchor_filename;

  /* protected by mutex */
  GMutex mutex;

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
   * This is a table of gchar * -> GTlsCertificate.
   */
  GHashTable *certs_by_handle;
} GTlsFileDatabaseOpensslPrivate;

enum {
  STATUS_FAILURE,
  STATUS_INCOMPLETE,
  STATUS_SELFSIGNED,
  STATUS_PINNED,
  STATUS_ANCHORED,
};

enum
{
  PROP_0,
  PROP_ANCHORS,
};

static void g_tls_file_database_openssl_file_database_interface_init (GTlsFileDatabaseInterface *iface);

static void g_tls_file_database_openssl_initable_interface_init (GInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (GTlsFileDatabaseOpenssl, g_tls_file_database_openssl, G_TYPE_TLS_DATABASE_OPENSSL,
                         G_ADD_PRIVATE (GTlsFileDatabaseOpenssl)
                         G_IMPLEMENT_INTERFACE (G_TYPE_TLS_FILE_DATABASE,
                                                g_tls_file_database_openssl_file_database_interface_init)
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                g_tls_file_database_openssl_initable_interface_init))

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

static gchar *
create_handle_for_certificate (const gchar *filename,
                               GBytes      *der)
{
  gchar *bookmark;
  gchar *uri_part;
  gchar *uri;

  /*
   * Here we create a URI that looks like:
   * file:///etc/ssl/certs/ca-certificates.crt#11b2641821252596420e468c275771f5e51022c121a17bd7a89a2f37b6336c8f
   */

  uri_part = g_filename_to_uri (filename, NULL, NULL);
  if (!uri_part)
    return NULL;

  bookmark = g_compute_checksum_for_bytes (G_CHECKSUM_SHA256, der);
  uri = g_strconcat (uri_part, "#", bookmark, NULL);

  g_free (bookmark);
  g_free (uri_part);

  return uri;
}

static gboolean
load_anchor_file (GTlsFileDatabaseOpenssl  *file_database,
                  const gchar              *filename,
                  GHashTable               *subjects,
                  GHashTable               *issuers,
                  GHashTable               *complete,
                  GHashTable               *certs_by_handle,
                  GError                  **error)
{
  GTlsFileDatabaseOpensslPrivate *priv;
  GList *list;
  GList *l;
  GBytes *der;
  gchar *handle;
  GError *my_error = NULL;

  priv = g_tls_file_database_openssl_get_instance_private (file_database);

  list = g_tls_certificate_list_new_from_file (filename, &my_error);
  if (my_error)
    {
      g_propagate_error (error, my_error);
      return FALSE;
    }

  for (l = list; l; l = l->next)
    {
      X509 *x;
      unsigned long subject;
      unsigned long issuer;

      x = g_tls_certificate_openssl_get_cert (l->data);
      subject = X509_subject_name_hash (x);
      issuer = X509_issuer_name_hash (x);

      der = g_tls_certificate_openssl_get_bytes (l->data);
      g_return_val_if_fail (der != NULL, FALSE);

      g_hash_table_insert (complete, g_bytes_ref (der),
                           g_bytes_ref (der));

      bytes_multi_table_insert (subjects, subject, der);
      bytes_multi_table_insert (issuers, issuer, der);

      handle = create_handle_for_certificate (priv->anchor_filename, der);
      g_hash_table_insert (certs_by_handle, handle, g_object_ref (l->data));

      g_bytes_unref (der);

      g_object_unref (l->data);
    }
  g_list_free (list);

  return TRUE;
}

static void
g_tls_file_database_openssl_finalize (GObject *object)
{
  GTlsFileDatabaseOpenssl *file_database = G_TLS_FILE_DATABASE_OPENSSL (object);
  GTlsFileDatabaseOpensslPrivate *priv;

  priv = g_tls_file_database_openssl_get_instance_private (file_database);

  g_clear_pointer (&priv->subjects, g_hash_table_destroy);
  g_clear_pointer (&priv->issuers, g_hash_table_destroy);
  g_clear_pointer (&priv->complete, g_hash_table_destroy);
  g_clear_pointer (&priv->certs_by_handle, g_hash_table_destroy);

  g_free (priv->anchor_filename);
  priv->anchor_filename = NULL;

  g_mutex_clear (&priv->mutex);

  G_OBJECT_CLASS (g_tls_file_database_openssl_parent_class)->finalize (object);
}

static void
g_tls_file_database_openssl_get_property (GObject    *object,
                                          guint       prop_id,
                                          GValue     *value,
                                          GParamSpec *pspec)
{
  GTlsFileDatabaseOpenssl *file_database = G_TLS_FILE_DATABASE_OPENSSL (object);
  GTlsFileDatabaseOpensslPrivate *priv;

  priv = g_tls_file_database_openssl_get_instance_private (file_database);

  switch (prop_id)
    {
    case PROP_ANCHORS:
      g_value_set_string (value, priv->anchor_filename);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_file_database_openssl_set_property (GObject      *object,
                                          guint         prop_id,
                                          const GValue *value,
                                          GParamSpec   *pspec)
{
  GTlsFileDatabaseOpenssl *file_database = G_TLS_FILE_DATABASE_OPENSSL (object);
  GTlsFileDatabaseOpensslPrivate *priv;
  gchar *anchor_path;

  priv = g_tls_file_database_openssl_get_instance_private (file_database);

  switch (prop_id)
    {
    case PROP_ANCHORS:
      anchor_path = g_value_dup_string (value);
      if (anchor_path && !g_path_is_absolute (anchor_path))
        {
          g_warning ("The anchor file name for used with a GTlsFileDatabase "
                     "must be an absolute path, and not relative: %s", anchor_path);
        }
      else
        {
          priv->anchor_filename = anchor_path;
        }
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_file_database_openssl_init (GTlsFileDatabaseOpenssl *file_database)
{
  GTlsFileDatabaseOpensslPrivate *priv;

  priv = g_tls_file_database_openssl_get_instance_private (file_database);

  g_mutex_init (&priv->mutex);
}

static gchar *
g_tls_file_database_openssl_create_certificate_handle (GTlsDatabase    *database,
                                                       GTlsCertificate *certificate)
{
  GTlsFileDatabaseOpenssl *file_database = G_TLS_FILE_DATABASE_OPENSSL (database);
  GTlsFileDatabaseOpensslPrivate *priv;
  GBytes *der;
  gboolean contains;
  gchar *handle = NULL;

  priv = g_tls_file_database_openssl_get_instance_private (file_database);

  der = g_tls_certificate_openssl_get_bytes (G_TLS_CERTIFICATE_OPENSSL (certificate));
  g_return_val_if_fail (der != NULL, FALSE);

  g_mutex_lock (&priv->mutex);

  /* At the same time look up whether this certificate is in list */
  contains = g_hash_table_lookup (priv->complete, der) ? TRUE : FALSE;

  g_mutex_unlock (&priv->mutex);

  /* Certificate is in the database */
  if (contains)
    handle = create_handle_for_certificate (priv->anchor_filename, der);

  g_bytes_unref (der);
  return handle;
}

static GTlsCertificate *
g_tls_file_database_openssl_lookup_certificate_for_handle (GTlsDatabase            *database,
                                                           const gchar             *handle,
                                                           GTlsInteraction         *interaction,
                                                           GTlsDatabaseLookupFlags  flags,
                                                           GCancellable            *cancellable,
                                                           GError                 **error)
{
  GTlsFileDatabaseOpenssl *file_database = G_TLS_FILE_DATABASE_OPENSSL (database);
  GTlsFileDatabaseOpensslPrivate *priv;
  GTlsCertificate *cert;

  priv = g_tls_file_database_openssl_get_instance_private (file_database);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return NULL;

  if (!handle)
    return NULL;

  g_mutex_lock (&priv->mutex);

  cert = g_hash_table_lookup (priv->certs_by_handle, handle);

  g_mutex_unlock (&priv->mutex);

  return cert ? g_object_ref (cert) : NULL;
}

static GTlsCertificate *
g_tls_file_database_openssl_lookup_certificate_issuer (GTlsDatabase             *database,
                                                       GTlsCertificate          *certificate,
                                                       GTlsInteraction          *interaction,
                                                       GTlsDatabaseLookupFlags   flags,
                                                       GCancellable             *cancellable,
                                                       GError                  **error)
{
  GTlsFileDatabaseOpenssl *file_database = G_TLS_FILE_DATABASE_OPENSSL (database);
  GTlsFileDatabaseOpensslPrivate *priv;
  X509 *x;
  unsigned long issuer_hash;
  GBytes *der;
  GTlsCertificate *issuer = NULL;

  priv = g_tls_file_database_openssl_get_instance_private (file_database);

  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_OPENSSL (certificate), NULL);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return NULL;

  if (flags & G_TLS_DATABASE_LOOKUP_KEYPAIR)
    return NULL;

  /* Dig out the issuer of this certificate */
  x = g_tls_certificate_openssl_get_cert (G_TLS_CERTIFICATE_OPENSSL (certificate));
  issuer_hash = X509_issuer_name_hash (x);

  g_mutex_lock (&priv->mutex);
  der = bytes_multi_table_lookup_ref_one (priv->subjects, issuer_hash);
  g_mutex_unlock (&priv->mutex);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    issuer = NULL;
  else if (der != NULL)
    issuer = g_tls_certificate_openssl_new (der, NULL);

  if (der != NULL)
    g_bytes_unref (der);
  return issuer;

  return NULL;
}

static GList *
g_tls_file_database_openssl_lookup_certificates_issued_by (GTlsDatabase             *database,
                                                           GByteArray               *issuer_raw_dn,
                                                           GTlsInteraction          *interaction,
                                                           GTlsDatabaseLookupFlags   flags,
                                                           GCancellable             *cancellable,
                                                           GError                  **error)
{
  GTlsFileDatabaseOpenssl *file_database = G_TLS_FILE_DATABASE_OPENSSL (database);
  GTlsFileDatabaseOpensslPrivate *priv;
  X509_NAME *x_name;
  const unsigned char *in;
  GList *issued = NULL;

  priv = g_tls_file_database_openssl_get_instance_private (file_database);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return NULL;

  /* We don't have any private keys here */
  if (flags & G_TLS_DATABASE_LOOKUP_KEYPAIR)
    return NULL;

  in = issuer_raw_dn->data;
  x_name = d2i_X509_NAME (NULL, &in, issuer_raw_dn->len);
  if (x_name != NULL)
    {
      unsigned long issuer_hash;
      GList *ders, *l;

      issuer_hash = X509_NAME_hash (x_name);

      /* Find the full DER value of the certificate */
      g_mutex_lock (&priv->mutex);
      ders = bytes_multi_table_lookup_ref_all (priv->issuers, issuer_hash);
      g_mutex_unlock (&priv->mutex);

      for (l = ders; l != NULL; l = g_list_next (l))
        {
          if (g_cancellable_set_error_if_cancelled (cancellable, error))
            {
              g_list_free_full (issued, g_object_unref);
              issued = NULL;
              break;
            }

          issued = g_list_prepend (issued, g_tls_certificate_openssl_new (l->data, NULL));
        }

      g_list_free_full (ders, (GDestroyNotify)g_bytes_unref);
      X509_NAME_free (x_name);
    }

  return issued;
}

static gboolean
lookup_assertion (GTlsDatabaseOpenssl           *database,
                  GTlsCertificateOpenssl        *certificate,
                  GTlsDatabaseOpensslAssertion   assertion,
                  const gchar                   *purpose,
                  GSocketConnectable            *identity,
                  GCancellable                  *cancellable,
                  GError                       **error)
{
  GTlsFileDatabaseOpenssl *file_database = G_TLS_FILE_DATABASE_OPENSSL (database);
  GTlsFileDatabaseOpensslPrivate *priv;
  GBytes *der = NULL;
  gboolean contains;

  priv = g_tls_file_database_openssl_get_instance_private (file_database);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return FALSE;

  /* We only have anchored certificate assertions here */
  if (assertion != G_TLS_DATABASE_OPENSSL_ANCHORED_CERTIFICATE)
    return FALSE;

  /*
   * TODO: We should be parsing any Extended Key Usage attributes and
   * comparing them to the purpose.
   */

  der = g_tls_certificate_openssl_get_bytes (certificate);

  g_mutex_lock (&priv->mutex);
  contains = g_hash_table_lookup (priv->complete, der) ? TRUE : FALSE;
  g_mutex_unlock (&priv->mutex);

  g_bytes_unref (der);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return FALSE;

  /* All certificates in our file are anchored certificates */
  return contains;
}

static gboolean
is_self_signed (GTlsCertificateOpenssl *certificate)
{
  X509 *cert;
  X509_STORE *store;
  X509_STORE_CTX csc;
  STACK_OF(X509) *trusted;
  gboolean ret = FALSE;

  store = X509_STORE_new ();
  cert = g_tls_certificate_openssl_get_cert (certificate);

  if (!X509_STORE_CTX_init(&csc, store, cert, NULL))
    goto end;

  trusted = sk_X509_new_null ();
  sk_X509_push (trusted, cert);

  X509_STORE_CTX_trusted_stack (&csc, trusted);
  X509_STORE_CTX_set_flags (&csc, X509_V_FLAG_CHECK_SS_SIGNATURE);

  ret = X509_verify_cert (&csc) > 0;
  sk_X509_free (trusted);

end:
  X509_STORE_CTX_cleanup (&csc);
  X509_STORE_free (store);

  return ret;
}

static gint
build_certificate_chain (GTlsDatabaseOpenssl     *openssl,
                         GTlsCertificateOpenssl  *chain,
                         const gchar             *purpose,
                         GSocketConnectable      *identity,
                         GTlsInteraction         *interaction,
                         GTlsDatabaseVerifyFlags  flags,
                         GCancellable            *cancellable,
                         GTlsCertificateOpenssl  **anchor,
                         GError                 **error)
{

  GTlsCertificateOpenssl *certificate;
  GTlsCertificateOpenssl *previous;
  GTlsCertificate *issuer;
  gboolean certificate_is_from_db;

  g_assert (anchor);
  g_assert (chain);
  g_assert (purpose);
  g_assert (error);
  g_assert (!*error);

  /*
   * Remember that the first certificate never changes in the chain.
   * When we find a self-signed, pinned or anchored certificate, all
   * issuers are truncated from the chain.
   */

  *anchor = NULL;
  previous = NULL;
  certificate = chain;
  certificate_is_from_db = FALSE;

  /* First check for pinned certificate */
  if (lookup_assertion (openssl, certificate,
                        G_TLS_DATABASE_OPENSSL_PINNED_CERTIFICATE,
                        purpose, identity, cancellable, error))
    {
      g_tls_certificate_openssl_set_issuer (certificate, NULL);
      return STATUS_PINNED;
    }
  else if (*error)
    {
      return STATUS_FAILURE;
    }

  for (;;)
    {
      if (g_cancellable_set_error_if_cancelled (cancellable, error))
        return STATUS_FAILURE;

      /* Look up whether this certificate is an anchor */
      if (lookup_assertion (openssl, certificate,
                            G_TLS_DATABASE_OPENSSL_ANCHORED_CERTIFICATE,
                            purpose, identity, cancellable, error))
        {
          g_tls_certificate_openssl_set_issuer (certificate, NULL);
          *anchor = certificate;
          return STATUS_ANCHORED;
        }
      else if (*error)
        {
          return STATUS_FAILURE;
        }

      /* Is it self-signed? */
      if (is_self_signed (certificate))
        {
          /*
           * Since at this point we would fail with 'self-signed', can we replace
           * this certificate with one from the database and do better?
           */
          if (previous && !certificate_is_from_db)
            {
              issuer = g_tls_database_lookup_certificate_issuer (G_TLS_DATABASE (openssl),
                                                                 G_TLS_CERTIFICATE (previous),
                                                                 interaction,
                                                                 G_TLS_DATABASE_LOOKUP_NONE,
                                                                 cancellable, error);
              if (*error)
                {
                  return STATUS_FAILURE;
                }
              else if (issuer)
                {
                  /* Replaced with certificate in the db, restart step again with this certificate */
                  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_OPENSSL (issuer), STATUS_FAILURE);
                  g_tls_certificate_openssl_set_issuer (previous, G_TLS_CERTIFICATE_OPENSSL (issuer));
                  certificate = G_TLS_CERTIFICATE_OPENSSL (issuer);
                  certificate_is_from_db = TRUE;
                  g_object_unref (issuer);
                  continue;
                }
            }

          g_tls_certificate_openssl_set_issuer (certificate, NULL);
          return STATUS_SELFSIGNED;
        }

      previous = certificate;

      /* Bring over the next certificate in the chain */
      issuer = g_tls_certificate_get_issuer (G_TLS_CERTIFICATE (certificate));
      if (issuer)
        {
          g_return_val_if_fail (G_IS_TLS_CERTIFICATE_OPENSSL (issuer), STATUS_FAILURE);
          certificate = G_TLS_CERTIFICATE_OPENSSL (issuer);
          certificate_is_from_db = FALSE;
        }

      /* Search for the next certificate in chain */
      else
        {
          issuer = g_tls_database_lookup_certificate_issuer (G_TLS_DATABASE (openssl),
                                                             G_TLS_CERTIFICATE (certificate),
                                                             interaction,
                                                             G_TLS_DATABASE_LOOKUP_NONE,
                                                             cancellable, error);
          if (*error)
            return STATUS_FAILURE;
          else if (!issuer)
            return STATUS_INCOMPLETE;

          /* Found a certificate in chain, use for next step */
          g_return_val_if_fail (G_IS_TLS_CERTIFICATE_OPENSSL (issuer), STATUS_FAILURE);
          g_tls_certificate_openssl_set_issuer (certificate, G_TLS_CERTIFICATE_OPENSSL (issuer));
          certificate = G_TLS_CERTIFICATE_OPENSSL (issuer);
          certificate_is_from_db = TRUE;
          g_object_unref (issuer);
        }
    }

  g_assert_not_reached ();
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
g_tls_file_database_openssl_verify_chain (GTlsDatabase             *database,
                                          GTlsCertificate          *chain,
                                          const gchar              *purpose,
                                          GSocketConnectable       *identity,
                                          GTlsInteraction          *interaction,
                                          GTlsDatabaseVerifyFlags   flags,
                                          GCancellable             *cancellable,
                                          GError                  **error)
{
  GTlsDatabaseOpenssl *openssl;
  GTlsCertificateOpenssl *anchor;
  STACK_OF(X509) *certs, *anchors;
  X509_STORE *store;
  X509_STORE_CTX csc;
  X509 *x;
  gint status;
  GTlsCertificateFlags result = 0;
  GError *err = NULL;

  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_OPENSSL (chain),
                        G_TLS_CERTIFICATE_GENERIC_ERROR);

  openssl = G_TLS_DATABASE_OPENSSL (database);
  anchor = NULL;

  status = build_certificate_chain (openssl, G_TLS_CERTIFICATE_OPENSSL (chain), purpose,
                                    identity, interaction, flags, cancellable, &anchor, &err);
  if (status == STATUS_FAILURE)
    {
      g_propagate_error (error, err);
      return G_TLS_CERTIFICATE_GENERIC_ERROR;
    }

  /*
   * A pinned certificate is verified on its own, without any further
   * verification.
   */
  if (status == STATUS_PINNED)
      return 0;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return G_TLS_CERTIFICATE_GENERIC_ERROR;

  certs = convert_certificate_chain_to_openssl (G_TLS_CERTIFICATE_OPENSSL (chain));

  store = X509_STORE_new ();

  x = g_tls_certificate_openssl_get_cert (G_TLS_CERTIFICATE_OPENSSL (chain));
  if (!X509_STORE_CTX_init(&csc, store, x, certs))
    {
      X509_STORE_CTX_cleanup (&csc);
      X509_STORE_free (store);
      sk_X509_free (certs);
      return G_TLS_CERTIFICATE_GENERIC_ERROR;
    }

  if (anchor)
    {
      g_assert (g_tls_certificate_get_issuer (G_TLS_CERTIFICATE (anchor)) == NULL);
      anchors = convert_certificate_chain_to_openssl (G_TLS_CERTIFICATE_OPENSSL (anchor));
      X509_STORE_CTX_trusted_stack (&csc, anchors);
    }
  else
    anchors = NULL;

  if (X509_verify_cert (&csc) <= 0)
    result = g_tls_certificate_openssl_convert_error (X509_STORE_CTX_get_error (&csc));

  X509_STORE_CTX_cleanup (&csc);
  X509_STORE_free (store);
  sk_X509_free (certs);
  if (anchors)
    sk_X509_free (anchors);

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

static void
g_tls_file_database_openssl_class_init (GTlsFileDatabaseOpensslClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsDatabaseClass *database_class = G_TLS_DATABASE_CLASS (klass);

  gobject_class->get_property = g_tls_file_database_openssl_get_property;
  gobject_class->set_property = g_tls_file_database_openssl_set_property;
  gobject_class->finalize     = g_tls_file_database_openssl_finalize;

  database_class->create_certificate_handle = g_tls_file_database_openssl_create_certificate_handle;
  database_class->lookup_certificate_for_handle = g_tls_file_database_openssl_lookup_certificate_for_handle;
  database_class->lookup_certificate_issuer = g_tls_file_database_openssl_lookup_certificate_issuer;
  database_class->lookup_certificates_issued_by = g_tls_file_database_openssl_lookup_certificates_issued_by;
  database_class->verify_chain = g_tls_file_database_openssl_verify_chain;

  g_object_class_override_property (gobject_class, PROP_ANCHORS, "anchors");
}

static void
g_tls_file_database_openssl_file_database_interface_init (GTlsFileDatabaseInterface *iface)
{
}

static gboolean
g_tls_file_database_openssl_initable_init (GInitable    *initable,
                                           GCancellable *cancellable,
                                           GError      **error)
{
  GTlsFileDatabaseOpenssl *file_database = G_TLS_FILE_DATABASE_OPENSSL (initable);
  GTlsFileDatabaseOpensslPrivate *priv;
  GHashTable *subjects, *issuers, *complete, *certs_by_handle;
  gboolean result;

  priv = g_tls_file_database_openssl_get_instance_private (file_database);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return FALSE;

  subjects = bytes_multi_table_new ();
  issuers = bytes_multi_table_new ();

  complete = g_hash_table_new_full (g_bytes_hash, g_bytes_equal,
                                    (GDestroyNotify)g_bytes_unref,
                                    (GDestroyNotify)g_bytes_unref);

  certs_by_handle = g_hash_table_new_full (g_str_hash, g_str_equal,
                                           (GDestroyNotify)g_free,
                                           (GDestroyNotify)g_object_unref);

  if (priv->anchor_filename)
    result = load_anchor_file (file_database,
                               priv->anchor_filename,
                               subjects, issuers, complete,
                               certs_by_handle,
                               error);
  else
    result = TRUE;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    result = FALSE;

  if (result)
    {
      g_mutex_lock (&priv->mutex);
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
      if (!priv->certs_by_handle)
        {
          priv->certs_by_handle = certs_by_handle;
          certs_by_handle = NULL;
        }
      g_mutex_unlock (&priv->mutex);
    }

  if (subjects != NULL)
    g_hash_table_unref (subjects);
  if (issuers != NULL)
    g_hash_table_unref (issuers);
  if (complete != NULL)
    g_hash_table_unref (complete);
  if (certs_by_handle != NULL)
    g_hash_table_unref (certs_by_handle);
  return result;
}

static void
g_tls_file_database_openssl_initable_interface_init (GInitableIface *iface)
{
  iface->init = g_tls_file_database_openssl_initable_init;
}
