/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2010 Collabora, Ltd
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
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "gtlsfiledatabase-gnutls.h"

#include <gio/gio.h>
#include <glib/gi18n-lib.h>
#include <gnutls/x509.h>

#include "gtlscertificate-gnutls.h"

enum
{
  PROP_0,
  PROP_ANCHORS,
};

struct _GTlsFileDatabaseGnutls
{
  GTlsDatabaseGnutls parent_instance;

  /* read-only after construct */
  gchar *anchor_filename;
  gnutls_x509_trust_list_t trust_list;

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

static void g_tls_file_database_gnutls_file_database_interface_init (GTlsFileDatabaseInterface *iface);

static void g_tls_file_database_gnutls_initable_interface_init (GInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (GTlsFileDatabaseGnutls, g_tls_file_database_gnutls, G_TYPE_TLS_DATABASE_GNUTLS,
                         G_IMPLEMENT_INTERFACE (G_TYPE_TLS_FILE_DATABASE,
                                                g_tls_file_database_gnutls_file_database_interface_init);
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                g_tls_file_database_gnutls_initable_interface_init);
                         );

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
          g_warning ("failed to get issuer of anchor certificate: %s",
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

  g_clear_pointer (&self->subjects, g_hash_table_destroy);
  g_clear_pointer (&self->issuers, g_hash_table_destroy);
  g_clear_pointer (&self->complete, g_hash_table_destroy);
  g_clear_pointer (&self->handles, g_hash_table_destroy);
  if (self->anchor_filename)
    {
      g_free (self->anchor_filename);
      gnutls_x509_trust_list_deinit (self->trust_list, 1);
    }
  g_mutex_clear (&self->mutex);

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
      g_value_set_string (value, self->anchor_filename);
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
  const char *anchor_path;

  switch (prop_id)
    {
    case PROP_ANCHORS:
      anchor_path = g_value_get_string (value);
      if (anchor_path && !g_path_is_absolute (anchor_path))
        {
          g_warning ("The anchor file name used with a GTlsFileDatabase "
                     "must be an absolute path, and not relative: %s", anchor_path);
          return;
        }

      if (self->anchor_filename)
        {
          g_free (self->anchor_filename);
          gnutls_x509_trust_list_deinit (self->trust_list, 1);
        }
      self->anchor_filename = g_strdup (anchor_path);
      gnutls_x509_trust_list_init (&self->trust_list, 0);
      gnutls_x509_trust_list_add_trust_file (self->trust_list,
                                             anchor_path, NULL,
                                             GNUTLS_X509_FMT_PEM, 0, 0);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_file_database_gnutls_init (GTlsFileDatabaseGnutls *self)
{
  g_mutex_init (&self->mutex);
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

  g_mutex_lock (&self->mutex);

  /* At the same time look up whether this certificate is in list */
  contains = g_hash_table_lookup (self->complete, der) ? TRUE : FALSE;

  g_mutex_unlock (&self->mutex);

  /* Certificate is in the database */
  if (contains)
    handle = create_handle_for_certificate (self->anchor_filename, der);

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

  g_mutex_lock (&self->mutex);

  /* Create the handles table if not already done */
  if (!self->handles)
    self->handles = create_handles_array_unlocked (self->anchor_filename,
                                                   self->complete);

  der = g_hash_table_lookup (self->handles, handle);
  if (der != NULL)
    g_bytes_ref (der);

  g_mutex_unlock (&self->mutex);

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
  g_mutex_lock (&self->mutex);
  der = bytes_multi_table_lookup_ref_one (self->subjects, subject);
  g_mutex_unlock (&self->mutex);

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
  g_mutex_lock (&self->mutex);
  ders = bytes_multi_table_lookup_ref_all (self->issuers, issuer);
  g_mutex_unlock (&self->mutex);

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
  guint gnutls_result;
  gnutls_x509_crt_t *certs;
  guint certs_length;
  const char *hostname = NULL;
  char *free_hostname = NULL;
  int gerr;

  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_GNUTLS (chain),
                        G_TLS_CERTIFICATE_GENERIC_ERROR);
  g_assert (purpose);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return G_TLS_CERTIFICATE_GENERIC_ERROR;

  self = G_TLS_FILE_DATABASE_GNUTLS (database);

  convert_certificate_chain_to_gnutls (G_TLS_CERTIFICATE_GNUTLS (chain),
                                       &certs, &certs_length);
  gerr = gnutls_x509_trust_list_verify_crt (self->trust_list,
                                            certs, certs_length,
                                            0, &gnutls_result, NULL);

  if (gerr != 0 || g_cancellable_set_error_if_cancelled (cancellable, error))
    {
      g_free (certs);
      return G_TLS_CERTIFICATE_GENERIC_ERROR;
    }

  result = g_tls_certificate_gnutls_convert_flags (gnutls_result);

  if (G_IS_NETWORK_ADDRESS (identity))
    hostname = g_network_address_get_hostname (G_NETWORK_ADDRESS (identity));
  else if (G_IS_NETWORK_SERVICE (identity))
    hostname = g_network_service_get_domain (G_NETWORK_SERVICE (identity));
  else if (G_IS_INET_SOCKET_ADDRESS (identity))
    {
      GInetAddress *addr;

      addr = g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS (identity));
      hostname = free_hostname = g_inet_address_to_string (addr);
    }
  if (hostname)
    {
      if (!gnutls_x509_crt_check_hostname (certs[0], hostname))
        result |= G_TLS_CERTIFICATE_BAD_IDENTITY;
      g_free (free_hostname);
    }

  g_free (certs);
  return result;
}

static void
g_tls_file_database_gnutls_class_init (GTlsFileDatabaseGnutlsClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsDatabaseClass *database_class = G_TLS_DATABASE_CLASS (klass);

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

  if (self->anchor_filename)
    result = load_anchor_file (self->anchor_filename, subjects, issuers,
        complete, error);
  else
    result = TRUE;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    result = FALSE;

  if (result)
    {
      g_mutex_lock (&self->mutex);
      if (!self->subjects)
        {
          self->subjects = subjects;
          subjects = NULL;
        }
      if (!self->issuers)
        {
          self->issuers = issuers;
          issuers = NULL;
        }
      if (!self->complete)
        {
          self->complete = complete;
          complete = NULL;
        }
      g_mutex_unlock (&self->mutex);
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
