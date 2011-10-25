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
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "gtlsfiledatabase-gnutls.h"

#include <gio/gio.h>
#include <glib/gi18n-lib.h>
#include <gnutls/x509.h>

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
   * These are hash tables of GByteArray -> GPtrArray<GByteArray>. The values of
   * the ptr array are full DER encoded certificate values. The keys are byte
   * arrays containing either subject DNs, issuer DNs, or full DER encoded certs
   */
  GHashTable *subjects;
  GHashTable *issuers;

  /*
   * This is a table of GByteArray -> GByteArray. The values and keys are
   * DER encoded certificate values.
   */
  GHashTable *complete;

  /*
   * This is a table of gchar * -> GPtrArray<GByteArray>. The values of
   * the ptr array are full DER encoded certificate values. The keys are the
   * string handles. This array is populated on demand.
   */
  GHashTable *handles;
};

static guint
byte_array_hash (gconstpointer v)
{
  const GByteArray *array = v;
  const signed char *p;
  guint32 h = 0;
  gsize i;

  g_assert (array);
  g_assert (array->data);
  p = (signed char*)array->data;

  /* 31 bit hash function */
  for (i = 0; i < array->len; ++i, ++p)
    h = (h << 5) - h + *p;

  return h;
}

static gboolean
byte_array_equal (gconstpointer v1, gconstpointer v2)
{
  const GByteArray *array1 = v1;
  const GByteArray *array2 = v2;

  if (array1 == array2)
    return TRUE;
  if (!array1 || !array2)
    return FALSE;

  if (array1->len != array2->len)
    return FALSE;

  if (array1->data == array2->data)
    return TRUE;
  if (!array1->data || !array2->data)
    return FALSE;

  return (memcmp (array1->data, array2->data, array1->len) == 0) ? TRUE : FALSE;
}

static GHashTable *
multi_byte_array_hash_new (void)
{
  return g_hash_table_new_full (byte_array_hash, byte_array_equal,
                                (GDestroyNotify)g_byte_array_unref,
                                (GDestroyNotify)g_ptr_array_unref);
}

static void
multi_byte_array_hash_insert (GHashTable *table, GByteArray *key, GByteArray *value)
{
  GPtrArray *multi;

  multi = g_hash_table_lookup (table, key);
  if (multi == NULL)
    {
      multi = g_ptr_array_new_with_free_func ((GDestroyNotify)g_byte_array_unref);
      g_hash_table_insert (table, g_byte_array_ref (key), multi);
    }
  g_ptr_array_add (multi, g_byte_array_ref (value));
}

static GByteArray *
multi_byte_array_hash_lookup_one (GHashTable *table, GByteArray *key)
{
  GPtrArray *multi;

  multi = g_hash_table_lookup (table, key);
  if (multi == NULL)
    return NULL;

  g_assert (multi->len > 0);
  return multi->pdata[0];
}

static GPtrArray *
multi_byte_array_hash_lookup_all (GHashTable *table, GByteArray *key)
{
  return g_hash_table_lookup (table, key);
}

static gchar *
create_handle_for_certificate (const gchar *filename,
                               GByteArray  *der)
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

  bookmark = g_compute_checksum_for_data (G_CHECKSUM_SHA256,
                                          der->data, der->len);
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
  GByteArray *der;
  gchar *handle;

  handles = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
                                   (GDestroyNotify)g_byte_array_unref);

  g_hash_table_iter_init (&iter, complete);
  while (g_hash_table_iter_next (&iter, NULL, (gpointer *)&der))
    {
      handle = create_handle_for_certificate (filename, der);
      if (handle != NULL)
        g_hash_table_insert (handles, handle, g_byte_array_ref (der));
    }

  return handles;
}

static gboolean
load_anchor_file (const gchar *filename,
                  GHashTable  *subjects,
                  GHashTable  *issuers,
                  GHashTable  *complete,
                  GError     **error)
{
  GList *list, *l;
  gnutls_x509_crt_t cert;
  gnutls_datum_t dn;
  GByteArray *der;
  GByteArray *subject;
  GByteArray *issuer;
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

      subject = g_byte_array_new ();
      g_byte_array_append (subject, dn.data, dn.size);
      gnutls_free (dn.data);

      gerr = gnutls_x509_crt_get_raw_issuer_dn (cert, &dn);
      if (gerr < 0)
        {
          g_warning ("failed to get subject of anchor certificate: %s",
                     gnutls_strerror (gerr));
          continue;
        }

      issuer = g_byte_array_new ();
      g_byte_array_append (issuer, dn.data, dn.size);
      gnutls_free (dn.data);

      /* Dig out the full value of this certificate's DER encoding */
      der = NULL;
      g_object_get (l->data, "certificate", &der, NULL);
      g_return_val_if_fail (der, FALSE);

      /* Three different ways of looking up same certificate */
      multi_byte_array_hash_insert (subjects, subject, der);
      multi_byte_array_hash_insert (issuers, issuer, der);

      g_hash_table_insert (complete, g_byte_array_ref (der),
                           g_byte_array_ref (der));

      g_byte_array_unref (der);
      g_byte_array_unref (subject);
      g_byte_array_unref (issuer);

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

static gchar*
g_tls_file_database_gnutls_create_certificate_handle (GTlsDatabase            *database,
                                                      GTlsCertificate         *certificate)
{
  GTlsFileDatabaseGnutls *self = G_TLS_FILE_DATABASE_GNUTLS (database);
  GByteArray *der;
  gboolean contains;
  gchar *handle = NULL;

  g_object_get (certificate, "certificate", &der, NULL);
  g_return_val_if_fail (der, FALSE);

  g_mutex_lock (&self->priv->mutex);

  /* At the same time look up whether this certificate is in list */
  contains = g_hash_table_lookup (self->priv->complete, der) ? TRUE : FALSE;

  g_mutex_unlock (&self->priv->mutex);

  /* Certificate is in the database */
  if (contains)
    handle = create_handle_for_certificate (self->priv->anchor_filename, der);

  g_byte_array_unref (der);
  return handle;
}

static GTlsCertificate*
g_tls_file_database_gnutls_lookup_certificate_for_handle (GTlsDatabase            *database,
                                                          const gchar             *handle,
                                                          GTlsInteraction         *interaction,
                                                          GTlsDatabaseLookupFlags  flags,
                                                          GCancellable            *cancellable,
                                                          GError                 **error)
{
  GTlsFileDatabaseGnutls *self = G_TLS_FILE_DATABASE_GNUTLS (database);
  GByteArray *der;
  gnutls_datum_t datum;

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

  g_mutex_unlock (&self->priv->mutex);

  if (der == NULL)
    return NULL;

  datum.data = der->data;
  datum.size = der->len;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return NULL;

  return g_tls_certificate_gnutls_new (&datum, NULL);
}

static gboolean
g_tls_file_database_gnutls_lookup_assertion (GTlsDatabaseGnutls          *database,
                                             GTlsCertificateGnutls       *certificate,
                                             GTlsDatabaseGnutlsAssertion  assertion,
                                             const gchar                 *purpose,
                                             GSocketConnectable          *identity,
                                             GCancellable                *cancellable,
                                             GError                     **error)
{
  GTlsFileDatabaseGnutls *self = G_TLS_FILE_DATABASE_GNUTLS (database);
  GByteArray *der = NULL;
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

  g_object_get (certificate, "certificate", &der, NULL);
  g_return_val_if_fail (der, FALSE);

  g_mutex_lock (&self->priv->mutex);
  contains = g_hash_table_lookup (self->priv->complete, der) ? TRUE : FALSE;
  g_mutex_unlock (&self->priv->mutex);

  g_byte_array_unref (der);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return FALSE;

  /* All certificates in our file are anchored certificates */
  return contains;
}

static GTlsCertificate*
g_tls_file_database_gnutls_lookup_certificate_issuer (GTlsDatabase           *database,
                                                      GTlsCertificate        *certificate,
                                                      GTlsInteraction        *interaction,
                                                      GTlsDatabaseLookupFlags flags,
                                                      GCancellable           *cancellable,
                                                      GError                **error)
{
  GTlsFileDatabaseGnutls *self = G_TLS_FILE_DATABASE_GNUTLS (database);
  gnutls_datum_t dn = { NULL, 0 };
  GByteArray *subject, *der;
  gnutls_datum_t datum;
  GTlsCertificate *issuer = NULL;
  gnutls_x509_crt_t cert;
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

  subject = g_byte_array_new ();
  g_byte_array_append (subject, dn.data, dn.size);
  gnutls_free (dn.data);

  /* Find the full DER value of the certificate */
  g_mutex_lock (&self->priv->mutex);
  der = multi_byte_array_hash_lookup_one (self->priv->subjects, subject);
  g_mutex_unlock (&self->priv->mutex);

  g_byte_array_unref (subject);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return NULL;

  if (der != NULL)
    {
      datum.data = der->data;
      datum.size = der->len;
      issuer = g_tls_certificate_gnutls_new (&datum, NULL);
    }

  return issuer;
}

static GList*
g_tls_file_database_gnutls_lookup_certificates_issued_by (GTlsDatabase           *database,
                                                          GByteArray             *issuer_raw_dn,
                                                          GTlsInteraction        *interaction,
                                                          GTlsDatabaseLookupFlags flags,
                                                          GCancellable           *cancellable,
                                                          GError                **error)
{
  GTlsFileDatabaseGnutls *self = G_TLS_FILE_DATABASE_GNUTLS (database);
  GByteArray *der;
  gnutls_datum_t datum;
  GList *issued = NULL;
  GPtrArray *ders;
  GList *l;
  guint i;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return NULL;

  /* We don't have any private keys here */
  if (flags & G_TLS_DATABASE_LOOKUP_KEYPAIR)
    return NULL;

  /* Find the full DER value of the certificate */
  g_mutex_lock (&self->priv->mutex);
  ders = multi_byte_array_hash_lookup_all (self->priv->issuers, issuer_raw_dn);
  g_mutex_unlock (&self->priv->mutex);

  for (i = 0; ders && i < ders->len; i++)
    {
      if (g_cancellable_set_error_if_cancelled (cancellable, error))
        {
          for (l = issued; l != NULL; l = l->next)
            g_object_unref (l->data);
          g_list_free (issued);
          issued = NULL;
          break;
        }

      der = ders->pdata[i];
      datum.data = der->data;
      datum.size = der->len;
      issued = g_list_prepend (issued, g_tls_certificate_gnutls_new (&datum, NULL));
    }

  return issued;
}

static void
g_tls_file_database_gnutls_class_init (GTlsFileDatabaseGnutlsClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsDatabaseClass *database_class = G_TLS_DATABASE_CLASS (klass);
  GTlsDatabaseGnutlsClass *gnutls_class = G_TLS_DATABASE_GNUTLS_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GTlsFileDatabaseGnutlsPrivate));

  gobject_class->get_property = g_tls_file_database_gnutls_get_property;
  gobject_class->set_property = g_tls_file_database_gnutls_set_property;
  gobject_class->finalize     = g_tls_file_database_gnutls_finalize;

  database_class->create_certificate_handle = g_tls_file_database_gnutls_create_certificate_handle;
  database_class->lookup_certificate_for_handle = g_tls_file_database_gnutls_lookup_certificate_for_handle;
  database_class->lookup_certificate_issuer = g_tls_file_database_gnutls_lookup_certificate_issuer;
  database_class->lookup_certificates_issued_by = g_tls_file_database_gnutls_lookup_certificates_issued_by;
  gnutls_class->lookup_assertion = g_tls_file_database_gnutls_lookup_assertion;

  g_object_class_override_property (gobject_class, PROP_ANCHORS, "anchors");
}

static void
g_tls_file_database_gnutls_file_database_interface_init (GTlsFileDatabaseInterface *iface)
{

}

static gboolean
g_tls_file_database_gnutls_initable_init (GInitable    *initable,
                                          GCancellable *cancellable,
                                          GError      **error)
{
  GTlsFileDatabaseGnutls *self = G_TLS_FILE_DATABASE_GNUTLS (initable);
  GHashTable *subjects, *issuers, *complete;
  gboolean result;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return FALSE;

  subjects = multi_byte_array_hash_new ();
  issuers = multi_byte_array_hash_new ();

  complete = g_hash_table_new_full (byte_array_hash, byte_array_equal,
                                    (GDestroyNotify)g_byte_array_unref,
                                    (GDestroyNotify)g_byte_array_unref);

  result = load_anchor_file (self->priv->anchor_filename, subjects, issuers,
                             complete, error);

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
