/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2010 Collabora, Ltd
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
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
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "gtlsfiledatabase-gnutls.h"

#include <gio/gio.h>
#include <glib/gi18n-lib.h>
#include <gnutls/x509.h>

#include "gtlscertificate-gnutls.h"

static void g_tls_file_database_gnutls_file_database_interface_init (GTlsFileDatabaseInterface *iface);

static void g_tls_file_database_gnutls_initable_interface_init (GInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (GTlsFileDatabaseGnutls, g_tls_file_database_gnutls, G_TYPE_TLS_DATABASE_GNUTLS,
                         G_IMPLEMENT_INTERFACE (G_TYPE_TLS_FILE_DATABASE,
                                                g_tls_file_database_gnutls_file_database_interface_init);
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                g_tls_file_database_gnutls_initable_interface_init);
			 );

enum
{
  PROP_0,
  PROP_ANCHORS,
};

struct _GTlsFileDatabaseGnutlsPrivate
{
  /* read-only after construct */
  gchar *anchor_filename;

  /* protected by mutex */
  GMutex mutex;

  /*
   * These are hash tables of GBytes -> GPtrArray<GBytes>. The values of
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
};

static GHashTable *
bytes_multi_table_new (void)
{
  return g_hash_table_new_full (g_bytes_hash, g_bytes_equal,
                                (GDestroyNotify)g_bytes_unref,
                                (GDestroyNotify)g_ptr_array_unref);
}

static void
bytes_multi_table_insert (GHashTable *table,
                          GBytes     *key,
                          GBytes     *value)
{
  GPtrArray *multi;

  multi = g_hash_table_lookup (table, key);
  if (multi == NULL)
    {
      multi = g_ptr_array_new_with_free_func ((GDestroyNotify)g_bytes_unref);
      g_hash_table_insert (table, g_bytes_ref (key), multi);
    }
  g_ptr_array_add (multi, g_bytes_ref (value));
}

static GBytes *
bytes_multi_table_lookup_ref_one (GHashTable *table,
                                  GBytes     *key)
{
  GPtrArray *multi;

  multi = g_hash_table_lookup (table, key);
  if (multi == NULL)
    return NULL;

  g_assert (multi->len > 0);
  return g_bytes_ref (multi->pdata[0]);
}

static GList *
bytes_multi_table_lookup_ref_all (GHashTable *table,
                                  GBytes     *key)
{
  GPtrArray *multi;
  GList *list = NULL;
  guint i;

  multi = g_hash_table_lookup (table, key);
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

static GHashTable *
create_handles_array_unlocked (const gchar *filename,
                               GHashTable  *complete)
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
      handle = create_handle_for_certificate (filename, der);
      if (handle != NULL)
        g_hash_table_insert (handles, handle, g_bytes_ref (der));
    }

  return handles;
}

static gboolean
load_anchor_file (const gchar  *filename,
                  GHashTable   *subjects,
                  GHashTable   *issuers,
                  GHashTable   *complete,
                  GError      **error)
{
  GList *list, *l;
  gnutls_x509_crt_t cert;
  gnutls_datum_t dn;
  GBytes *der;
  GBytes *subject;
  GBytes *issuer;
  gint gerr;
  GError *my_error = NULL;

  list = g_tls_certificate_list_new_from_file (filename, &my_error);
  if (my_error)
    {
      g_propagate_error (error, my_error);
      return FALSE;
    }

  for (l = list; l; l = l->next)
    {
      cert = g_tls_certificate_gnutls_get_cert (l->data);
      gerr = gnutls_x509_crt_get_raw_dn (cert, &dn);
      if (gerr < 0)
        {
          g_warning ("failed to get subject of anchor certificate: %s",
                     gnutls_strerror (gerr));
          continue;
        }

      subject = g_bytes_new_with_free_func (dn.data, dn.size, gnutls_free, dn.data);

      gerr = gnutls_x509_crt_get_raw_issuer_dn (cert, &dn);
      if (gerr < 0)
        {
          g_warning ("failed to get subject of anchor certificate: %s",
                     gnutls_strerror (gerr));
          continue;
        }

      issuer = g_bytes_new_with_free_func (dn.data, dn.size, gnutls_free, dn.data);

      der = g_tls_certificate_gnutls_get_bytes (l->data);
      g_return_val_if_fail (der != NULL, FALSE);

      /* Three different ways of looking up same certificate */
      bytes_multi_table_insert (subjects, subject, der);
      bytes_multi_table_insert (issuers, issuer, der);

      g_hash_table_insert (complete, g_bytes_ref (der),
                           g_bytes_ref (der));

      g_bytes_unref (der);
      g_bytes_unref (subject);
      g_bytes_unref (issuer);

      g_object_unref (l->data);
    }
  g_list_free (list);

  return TRUE;
}



static void
g_tls_file_database_gnutls_finalize (GObject *object)
{
  GTlsFileDatabaseGnutls *self = G_TLS_FILE_DATABASE_GNUTLS (object);

  if (self->priv->subjects)
    g_hash_table_destroy (self->priv->subjects);
  self->priv->subjects = NULL;

  if (self->priv->issuers)
    g_hash_table_destroy (self->priv->issuers);
  self->priv->issuers = NULL;

  if (self->priv->complete)
    g_hash_table_destroy (self->priv->complete);
  self->priv->complete = NULL;

  if (self->priv->handles)
    g_hash_table_destroy (self->priv->handles);
  self->priv->handles = NULL;

  g_free (self->priv->anchor_filename);
  self->priv->anchor_filename = NULL;

  g_mutex_clear (&self->priv->mutex);

  G_OBJECT_CLASS (g_tls_file_database_gnutls_parent_class)->finalize (object);
}

static void
g_tls_file_database_gnutls_get_property (GObject    *object,
                                         guint       prop_id,
                                         GValue     *value,
                                         GParamSpec *pspec)
{
  GTlsFileDatabaseGnutls *self = G_TLS_FILE_DATABASE_GNUTLS (object);

  switch (prop_id)
    {
    case PROP_ANCHORS:
      g_value_set_string (value, self->priv->anchor_filename);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_file_database_gnutls_set_property (GObject      *object,
                                         guint         prop_id,
                                         const GValue *value,
                                         GParamSpec   *pspec)
{
  GTlsFileDatabaseGnutls *self = G_TLS_FILE_DATABASE_GNUTLS (object);
  gchar *anchor_path;

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
          self->priv->anchor_filename = anchor_path;
        }
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_file_database_gnutls_init (GTlsFileDatabaseGnutls *self)
{
  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
                                            G_TYPE_TLS_FILE_DATABASE_GNUTLS,
                                            GTlsFileDatabaseGnutlsPrivate);
  g_mutex_init (&self->priv->mutex);
}

static gchar *
g_tls_file_database_gnutls_create_certificate_handle (GTlsDatabase    *database,
                                                      GTlsCertificate *certificate)
{
  GTlsFileDatabaseGnutls *self = G_TLS_FILE_DATABASE_GNUTLS (database);
  GBytes *der;
  gboolean contains;
  gchar *handle = NULL;

  der = g_tls_certificate_gnutls_get_bytes (G_TLS_CERTIFICATE_GNUTLS (certificate));
  g_return_val_if_fail (der != NULL, FALSE);

  g_mutex_lock (&self->priv->mutex);

  /* At the same time look up whether this certificate is in list */
  contains = g_hash_table_lookup (self->priv->complete, der) ? TRUE : FALSE;

  g_mutex_unlock (&self->priv->mutex);

  /* Certificate is in the database */
  if (contains)
    handle = create_handle_for_certificate (self->priv->anchor_filename, der);

  g_bytes_unref (der);
  return handle;
}

static GTlsCertificate *
g_tls_file_database_gnutls_lookup_certificate_for_handle (GTlsDatabase             *database,
                                                          const gchar              *handle,
                                                          GTlsInteraction          *interaction,
                                                          GTlsDatabaseLookupFlags   flags,
                                                          GCancellable             *cancellable,
                                                          GError                  **error)
{
  GTlsFileDatabaseGnutls *self = G_TLS_FILE_DATABASE_GNUTLS (database);
  GTlsCertificate *cert;
  GBytes *der;
  gnutls_datum_t datum;
  gsize length;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return NULL;

  if (!handle)
    return NULL;

  g_mutex_lock (&self->priv->mutex);

  /* Create the handles table if not already done */
  if (!self->priv->handles)
    self->priv->handles = create_handles_array_unlocked (self->priv->anchor_filename,
                                                         self->priv->complete);

    der = g_hash_table_lookup (self->priv->handles, handle);
    if (der != NULL)
      g_bytes_ref (der);

  g_mutex_unlock (&self->priv->mutex);

  if (der == NULL)
    return NULL;

  datum.data = (unsigned char *)g_bytes_get_data (der, &length);
  datum.size = length;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    cert = NULL;
  else
    cert = g_tls_certificate_gnutls_new (&datum, NULL);

  g_bytes_unref (der);
  return cert;
}

static gboolean
g_tls_file_database_gnutls_lookup_assertion (GTlsFileDatabaseGnutls       *self,
                                             GTlsCertificateGnutls        *certificate,
                                             GTlsDatabaseGnutlsAssertion   assertion,
                                             const gchar                  *purpose,
                                             GSocketConnectable           *identity,
                                             GCancellable                 *cancellable,
                                             GError                      **error)
{
  GBytes *der = NULL;
  gboolean contains;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return FALSE;

  /* We only have anchored certificate assertions here */
  if (assertion != G_TLS_DATABASE_GNUTLS_ANCHORED_CERTIFICATE)
    return FALSE;

  /*
   * TODO: We should be parsing any Extended Key Usage attributes and
   * comparing them to the purpose.
   */

  der = g_tls_certificate_gnutls_get_bytes (certificate);

  g_mutex_lock (&self->priv->mutex);
  contains = g_hash_table_lookup (self->priv->complete, der) ? TRUE : FALSE;
  g_mutex_unlock (&self->priv->mutex);

  g_bytes_unref (der);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return FALSE;

  /* All certificates in our file are anchored certificates */
  return contains;
}

static GTlsCertificate *
g_tls_file_database_gnutls_lookup_certificate_issuer (GTlsDatabase             *database,
                                                      GTlsCertificate          *certificate,
                                                      GTlsInteraction          *interaction,
                                                      GTlsDatabaseLookupFlags   flags,
                                                      GCancellable             *cancellable,
                                                      GError                  **error)
{
  GTlsFileDatabaseGnutls *self = G_TLS_FILE_DATABASE_GNUTLS (database);
  gnutls_datum_t dn = { NULL, 0 };
  GBytes *subject, *der;
  gnutls_datum_t datum;
  GTlsCertificate *issuer = NULL;
  gnutls_x509_crt_t cert;
  gsize length;
  int gerr;

  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_GNUTLS (certificate), NULL);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return NULL;

  if (flags & G_TLS_DATABASE_LOOKUP_KEYPAIR)
    return NULL;

  /* Dig out the issuer of this certificate */
  cert = g_tls_certificate_gnutls_get_cert (G_TLS_CERTIFICATE_GNUTLS (certificate));
  gerr = gnutls_x509_crt_get_raw_issuer_dn (cert, &dn);
  if (gerr < 0)
    {
      g_warning ("failed to get issuer of certificate: %s", gnutls_strerror (gerr));
      return NULL;
    }

  subject = g_bytes_new_with_free_func (dn.data, dn.size, gnutls_free, dn.data);

  /* Find the full DER value of the certificate */
  g_mutex_lock (&self->priv->mutex);
  der = bytes_multi_table_lookup_ref_one (self->priv->subjects, subject);
  g_mutex_unlock (&self->priv->mutex);

  g_bytes_unref (subject);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    {
      issuer = NULL;
    }
  else if (der != NULL)
    {
      datum.data = (unsigned char *)g_bytes_get_data (der, &length);
      datum.size = length;
      issuer = g_tls_certificate_gnutls_new (&datum, NULL);
    }

  if (der != NULL)
    g_bytes_unref (der);
  return issuer;
}

static GList *
g_tls_file_database_gnutls_lookup_certificates_issued_by (GTlsDatabase             *database,
                                                          GByteArray               *issuer_raw_dn,
                                                          GTlsInteraction          *interaction,
                                                          GTlsDatabaseLookupFlags   flags,
                                                          GCancellable             *cancellable,
                                                          GError                  **error)
{
  GTlsFileDatabaseGnutls *self = G_TLS_FILE_DATABASE_GNUTLS (database);
  GBytes *issuer;
  gnutls_datum_t datum;
  GList *issued = NULL;
  GList *ders;
  gsize length;
  GList *l;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return NULL;

  /* We don't have any private keys here */
  if (flags & G_TLS_DATABASE_LOOKUP_KEYPAIR)
    return NULL;

  issuer = g_bytes_new_static (issuer_raw_dn->data, issuer_raw_dn->len);

  /* Find the full DER value of the certificate */
  g_mutex_lock (&self->priv->mutex);
  ders = bytes_multi_table_lookup_ref_all (self->priv->issuers, issuer);
  g_mutex_unlock (&self->priv->mutex);

  g_bytes_unref (issuer);

  for (l = ders; l != NULL; l = g_list_next (l))
    {
      if (g_cancellable_set_error_if_cancelled (cancellable, error))
        {
          g_list_free_full (issued, g_object_unref);
          issued = NULL;
          break;
        }

      datum.data = (unsigned char *)g_bytes_get_data (l->data, &length);
      datum.size = length;
      issued = g_list_prepend (issued, g_tls_certificate_gnutls_new (&datum, NULL));
    }

  g_list_free_full (ders, (GDestroyNotify)g_bytes_unref);
  return issued;
}

#define BUILD_CERTIFICATE_CHAIN_RECURSION_LIMIT 10

enum {
  STATUS_FAILURE,
  STATUS_INCOMPLETE,
  STATUS_SELFSIGNED,
  STATUS_ANCHORED,
  STATUS_RECURSION_LIMIT_REACHED
};

static gboolean
is_self_signed (GTlsCertificateGnutls *certificate)
{
  const gnutls_x509_crt_t cert = g_tls_certificate_gnutls_get_cert (certificate);
  return (gnutls_x509_crt_check_issuer (cert, cert) > 0);
}

static gint
build_certificate_chain (GTlsFileDatabaseGnutls  *self,
                         GTlsCertificateGnutls   *certificate,
                         GTlsCertificateGnutls   *previous,
                         gboolean                 certificate_is_from_db,
                         guint                    recursion_depth,
                         const gchar             *purpose,
                         GSocketConnectable      *identity,
                         GTlsInteraction         *interaction,
                         GCancellable            *cancellable,
                         GTlsCertificateGnutls  **anchor,
                         GError                 **error)
{
  GTlsCertificate *issuer;
  gint status;

  if (recursion_depth++ > BUILD_CERTIFICATE_CHAIN_RECURSION_LIMIT)
    return STATUS_RECURSION_LIMIT_REACHED;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return STATUS_FAILURE;

  /* Look up whether this certificate is an anchor */
  if (g_tls_file_database_gnutls_lookup_assertion (self, certificate,
						   G_TLS_DATABASE_GNUTLS_ANCHORED_CERTIFICATE,
						   purpose, identity, cancellable, error))
    {
      g_tls_certificate_gnutls_set_issuer (certificate, NULL);
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
          issuer = g_tls_database_lookup_certificate_issuer (G_TLS_DATABASE (self),
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
              g_return_val_if_fail (G_IS_TLS_CERTIFICATE_GNUTLS (issuer), STATUS_FAILURE);
              certificate = G_TLS_CERTIFICATE_GNUTLS (issuer);
              g_tls_certificate_gnutls_set_issuer (previous, certificate);
              g_object_unref (issuer);

              return build_certificate_chain (self, certificate, previous, TRUE, recursion_depth,
                                              purpose, identity, interaction, cancellable, anchor, error);
            }
        }

      g_tls_certificate_gnutls_set_issuer (certificate, NULL);
      return STATUS_SELFSIGNED;
    }

  previous = certificate;

  /* Bring over the next certificate in the chain */
  issuer = g_tls_certificate_get_issuer (G_TLS_CERTIFICATE (certificate));
  if (issuer)
    {
      g_return_val_if_fail (G_IS_TLS_CERTIFICATE_GNUTLS (issuer), STATUS_FAILURE);
      certificate = G_TLS_CERTIFICATE_GNUTLS (issuer);

      status = build_certificate_chain (self, certificate, previous, FALSE, recursion_depth,
                                        purpose, identity, interaction, cancellable, anchor, error);
      if (status != STATUS_INCOMPLETE)
        {
          return status;
        }
    }

  /* Search for the next certificate in chain */
  issuer = g_tls_database_lookup_certificate_issuer (G_TLS_DATABASE (self),
                                                     G_TLS_CERTIFICATE (certificate),
                                                     interaction,
                                                     G_TLS_DATABASE_LOOKUP_NONE,
                                                     cancellable, error);
  if (*error)
    return STATUS_FAILURE;

  if (!issuer)
    return STATUS_INCOMPLETE;

  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_GNUTLS (issuer), STATUS_FAILURE);
  g_tls_certificate_gnutls_set_issuer (certificate, G_TLS_CERTIFICATE_GNUTLS (issuer));
  certificate = G_TLS_CERTIFICATE_GNUTLS (issuer);
  g_object_unref (issuer);

  return build_certificate_chain (self, certificate, previous, TRUE, recursion_depth,
                                  purpose, identity, interaction, cancellable, anchor, error);
}

static GTlsCertificateFlags
double_check_before_after_dates (GTlsCertificateGnutls *chain)
{
  GTlsCertificateFlags gtls_flags = 0;
  gnutls_x509_crt_t cert;
  time_t t, now;

  now = time (NULL);
  while (chain)
    {
      cert = g_tls_certificate_gnutls_get_cert (chain);
      t = gnutls_x509_crt_get_activation_time (cert);
      if (t == (time_t) -1 || t > now)
        gtls_flags |= G_TLS_CERTIFICATE_NOT_ACTIVATED;

      t = gnutls_x509_crt_get_expiration_time (cert);
      if (t == (time_t) -1 || t < now)
        gtls_flags |= G_TLS_CERTIFICATE_EXPIRED;

      chain = G_TLS_CERTIFICATE_GNUTLS (g_tls_certificate_get_issuer
                                        (G_TLS_CERTIFICATE (chain)));
    }

  return gtls_flags;
}

static void
convert_certificate_chain_to_gnutls (GTlsCertificateGnutls  *chain,
                                     gnutls_x509_crt_t     **gnutls_chain,
                                     guint                  *gnutls_chain_length)
{
  GTlsCertificate *cert;
  guint i;

  g_assert (gnutls_chain);
  g_assert (gnutls_chain_length);

  for (*gnutls_chain_length = 0, cert = G_TLS_CERTIFICATE (chain);
       cert; cert = g_tls_certificate_get_issuer (cert))
    ++(*gnutls_chain_length);

  *gnutls_chain = g_new0 (gnutls_x509_crt_t, *gnutls_chain_length);

  for (i = 0, cert = G_TLS_CERTIFICATE (chain);
       cert; cert = g_tls_certificate_get_issuer (cert), ++i)
    (*gnutls_chain)[i] = g_tls_certificate_gnutls_get_cert (G_TLS_CERTIFICATE_GNUTLS (cert));

  g_assert (i == *gnutls_chain_length);
}

static GTlsCertificateFlags
g_tls_file_database_gnutls_verify_chain (GTlsDatabase             *database,
					 GTlsCertificate          *chain,
					 const gchar              *purpose,
					 GSocketConnectable       *identity,
					 GTlsInteraction          *interaction,
					 GTlsDatabaseVerifyFlags   flags,
					 GCancellable             *cancellable,
					 GError                  **error)
{
  GTlsFileDatabaseGnutls *self;
  GTlsCertificateFlags result;
  GTlsCertificateGnutls *certificate;
  GError *err = NULL;
  GTlsCertificateGnutls *anchor;
  guint gnutls_result;
  gnutls_x509_crt_t *certs, *anchors;
  guint certs_length, anchors_length;
  gint status, gerr;
  guint recursion_depth = 0;

  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_GNUTLS (chain),
                        G_TLS_CERTIFICATE_GENERIC_ERROR);
  g_assert (purpose);

  self = G_TLS_FILE_DATABASE_GNUTLS (database);
  certificate = G_TLS_CERTIFICATE_GNUTLS (chain);

  /* First check for pinned certificate */
  if (g_tls_file_database_gnutls_lookup_assertion (self, certificate,
						   G_TLS_DATABASE_GNUTLS_PINNED_CERTIFICATE,
						   purpose, identity, cancellable, &err))
    {
      /*
       * A pinned certificate is verified on its own, without any further
       * verification.
       */
      g_tls_certificate_gnutls_set_issuer (certificate, NULL);
      return 0;
    }

  if (err)
    {
      g_propagate_error (error, err);
      return G_TLS_CERTIFICATE_GENERIC_ERROR;
    }

  anchor = NULL;
  status = build_certificate_chain (self, certificate, NULL, FALSE, recursion_depth,
                                    purpose, identity, interaction, cancellable, &anchor, &err);
  if (status == STATUS_FAILURE)
    {
      g_propagate_error (error, err);
      return G_TLS_CERTIFICATE_GENERIC_ERROR;
    }

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return G_TLS_CERTIFICATE_GENERIC_ERROR;

  convert_certificate_chain_to_gnutls (G_TLS_CERTIFICATE_GNUTLS (chain),
                                       &certs, &certs_length);

  if (anchor)
    {
      g_assert (g_tls_certificate_get_issuer (G_TLS_CERTIFICATE (anchor)) == NULL);
      convert_certificate_chain_to_gnutls (G_TLS_CERTIFICATE_GNUTLS (anchor),
                                           &anchors, &anchors_length);
    }
  else
    {
      anchors = NULL;
      anchors_length = 0;
    }

  gerr = gnutls_x509_crt_list_verify (certs, certs_length,
                                      anchors, anchors_length,
                                      NULL, 0, GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT,
                                      &gnutls_result);

  g_free (certs);
  g_free (anchors);

  if (gerr != 0)
    return G_TLS_CERTIFICATE_GENERIC_ERROR;
  else if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return G_TLS_CERTIFICATE_GENERIC_ERROR;

  result = g_tls_certificate_gnutls_convert_flags (gnutls_result);

  /*
   * We have to check these ourselves since gnutls_x509_crt_list_verify
   * won't bother if it gets an UNKNOWN_CA.
   */
  result |= double_check_before_after_dates (G_TLS_CERTIFICATE_GNUTLS (chain));

  if (identity)
    result |= g_tls_certificate_gnutls_verify_identity (G_TLS_CERTIFICATE_GNUTLS (chain),
                                                        identity);

  return result;
}

static void
g_tls_file_database_gnutls_class_init (GTlsFileDatabaseGnutlsClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsDatabaseClass *database_class = G_TLS_DATABASE_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GTlsFileDatabaseGnutlsPrivate));

  gobject_class->get_property = g_tls_file_database_gnutls_get_property;
  gobject_class->set_property = g_tls_file_database_gnutls_set_property;
  gobject_class->finalize     = g_tls_file_database_gnutls_finalize;

  database_class->create_certificate_handle = g_tls_file_database_gnutls_create_certificate_handle;
  database_class->lookup_certificate_for_handle = g_tls_file_database_gnutls_lookup_certificate_for_handle;
  database_class->lookup_certificate_issuer = g_tls_file_database_gnutls_lookup_certificate_issuer;
  database_class->lookup_certificates_issued_by = g_tls_file_database_gnutls_lookup_certificates_issued_by;
  database_class->verify_chain = g_tls_file_database_gnutls_verify_chain;

  g_object_class_override_property (gobject_class, PROP_ANCHORS, "anchors");
}

static void
g_tls_file_database_gnutls_file_database_interface_init (GTlsFileDatabaseInterface *iface)
{

}

static gboolean
g_tls_file_database_gnutls_initable_init (GInitable     *initable,
                                          GCancellable  *cancellable,
                                          GError       **error)
{
  GTlsFileDatabaseGnutls *self = G_TLS_FILE_DATABASE_GNUTLS (initable);
  GHashTable *subjects, *issuers, *complete;
  gboolean result;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return FALSE;

  subjects = bytes_multi_table_new ();
  issuers = bytes_multi_table_new ();

  complete = g_hash_table_new_full (g_bytes_hash, g_bytes_equal,
                                    (GDestroyNotify)g_bytes_unref,
                                    (GDestroyNotify)g_bytes_unref);

  if (self->priv->anchor_filename)
    result = load_anchor_file (self->priv->anchor_filename, subjects, issuers,
        complete, error);
  else
    result = TRUE;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    result = FALSE;

  if (result)
    {
      g_mutex_lock (&self->priv->mutex);
      if (!self->priv->subjects)
        {
          self->priv->subjects = subjects;
          subjects = NULL;
        }
      if (!self->priv->issuers)
        {
          self->priv->issuers = issuers;
          issuers = NULL;
        }
      if (!self->priv->complete)
        {
          self->priv->complete = complete;
          complete = NULL;
        }
      g_mutex_unlock (&self->priv->mutex);
    }

  if (subjects != NULL)
    g_hash_table_unref (subjects);
  if (issuers != NULL)
    g_hash_table_unref (issuers);
  if (complete != NULL)
    g_hash_table_unref (complete);
  return result;
}

static void
g_tls_file_database_gnutls_initable_interface_init (GInitableIface *iface)
{
  iface->init = g_tls_file_database_gnutls_initable_init;
}
