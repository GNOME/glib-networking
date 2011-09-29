/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2011 Red Hat, Inc.
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
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "config.h"

#include "gtlsfiledatabase-nss.h"
#include "gtlsbackend-nss.h"

#include <gio/gio.h>
#include <glib/gi18n-lib.h>

/* NSS only has a single global database. The strategy here then is to
 * remember which certificates we read out of this file, and then when
 * asked to do some operation, we have the default database do it, and
 * then filter the results to only the certs in this database.
 */

/* The handle format is the same as the GNUTLS backend, for no real
 * reason other than "that's what the regression tests test for". We
 * could just as easily chain up.
 */

static void g_tls_file_database_nss_file_database_interface_init (GTlsFileDatabaseInterface *iface);

static void g_tls_file_database_nss_initable_interface_init (GInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (GTlsFileDatabaseNss, g_tls_file_database_nss, G_TYPE_TLS_DATABASE_NSS,
                         G_IMPLEMENT_INTERFACE (G_TYPE_TLS_FILE_DATABASE,
                                                g_tls_file_database_nss_file_database_interface_init);
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                g_tls_file_database_nss_initable_interface_init);
);

enum
{
  PROP_0,
  PROP_ANCHORS,
};

struct _GTlsFileDatabaseNssPrivate
{
  /* read-only after construct */
  gchar *anchor_filename;
  GHashTable *certs;
  GTlsDatabase *default_db;

  GHashTable *hashes, *certs_by_hash;
};

static void
g_tls_file_database_nss_init (GTlsFileDatabaseNss *nss)
{
  nss->priv = G_TYPE_INSTANCE_GET_PRIVATE (nss,
					   G_TYPE_TLS_FILE_DATABASE_NSS,
					   GTlsFileDatabaseNssPrivate);
  nss->priv->certs = g_hash_table_new_full (NULL, NULL, g_object_unref, NULL);
  nss->priv->default_db = G_TLS_DATABASE (g_tls_backend_nss_default_database);

  nss->priv->hashes = g_hash_table_new (NULL, NULL);
  nss->priv->certs_by_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
						    g_free, NULL);
}

static void
g_tls_file_database_nss_finalize (GObject *object)
{
  GTlsFileDatabaseNss *nss = G_TLS_FILE_DATABASE_NSS (object);

  if (nss->priv->certs)
    g_hash_table_destroy (nss->priv->certs);
  if (nss->priv->hashes)
    g_hash_table_destroy (nss->priv->hashes);
  if (nss->priv->certs_by_hash)
    g_hash_table_destroy (nss->priv->certs_by_hash);
  g_free (nss->priv->anchor_filename);

  G_OBJECT_CLASS (g_tls_file_database_nss_parent_class)->finalize (object);
}

static void
g_tls_file_database_nss_get_property (GObject    *object,
				      guint       prop_id,
				      GValue     *value,
				      GParamSpec *pspec)
{
  GTlsFileDatabaseNss *nss = G_TLS_FILE_DATABASE_NSS (object);

  switch (prop_id)
    {
    case PROP_ANCHORS:
      g_value_set_string (value, nss->priv->anchor_filename);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_file_database_nss_set_property (GObject      *object,
				      guint         prop_id,
				      const GValue *value,
				      GParamSpec   *pspec)
{
  GTlsFileDatabaseNss *nss = G_TLS_FILE_DATABASE_NSS (object);
  const gchar *anchor_path;

  switch (prop_id)
    {
    case PROP_ANCHORS:
      anchor_path = g_value_get_string (value);
      if (anchor_path && !g_path_is_absolute (anchor_path))
        {
          g_warning ("The anchor file name for used with a GTlsFileDatabase "
                     "must be an absolute path, and not relative: %s", anchor_path);
        }
      else
        {
          nss->priv->anchor_filename = g_strdup (anchor_path);
        }
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static gchar *
g_tls_file_database_nss_create_certificate_handle (GTlsDatabase    *database,
						   GTlsCertificate *certificate)
{
  GTlsFileDatabaseNss *nss = G_TLS_FILE_DATABASE_NSS (database);
  const gchar *hash;

  hash = g_strdup (g_hash_table_lookup (nss->priv->hashes, certificate));
  if (!hash)
    return NULL;

  return g_strdup_printf ("file://%s#%s", nss->priv->anchor_filename, hash);
}

static GTlsCertificate *
g_tls_file_database_nss_lookup_certificate_for_handle (GTlsDatabase            *database,
						       const gchar             *handle,
						       GTlsInteraction         *interaction,
						       GTlsDatabaseLookupFlags  flags,
						       GCancellable            *cancellable,
						       GError                 **error)
{
  GTlsFileDatabaseNss *nss = G_TLS_FILE_DATABASE_NSS (database);
  GTlsCertificate *cert;

  if (!g_str_has_prefix (handle, "file://"))
    return NULL;
  handle += 7;
  if (!g_str_has_prefix (handle, nss->priv->anchor_filename))
    return NULL;
  handle += strlen (nss->priv->anchor_filename);
  if (*handle != '#')
    return NULL;
  handle++;

  cert = g_hash_table_lookup (nss->priv->certs_by_hash, handle);
  if (cert)
    g_object_ref (cert);
  return cert;
}

static GTlsCertificate *
g_tls_file_database_nss_lookup_certificate_issuer (GTlsDatabase             *database,
						   GTlsCertificate          *certificate,
						   GTlsInteraction          *interaction,
						   GTlsDatabaseLookupFlags   flags,
						   GCancellable             *cancellable,
						   GError                  **error)
{
  GTlsFileDatabaseNss *nss = G_TLS_FILE_DATABASE_NSS (database);
  GTlsCertificate *issuer;

  issuer = g_tls_database_lookup_certificate_issuer (nss->priv->default_db,
						     certificate, interaction,
						     flags, cancellable,
						     error);
  if (issuer && g_hash_table_lookup (nss->priv->certs, issuer))
    return issuer;
  else if (issuer)
    g_object_unref (issuer);
  return NULL;
}

static GList*
g_tls_file_database_nss_lookup_certificates_issued_by (GTlsDatabase           *database,
						       GByteArray             *issuer_raw_dn,
						       GTlsInteraction        *interaction,
						       GTlsDatabaseLookupFlags flags,
						       GCancellable           *cancellable,
						       GError                **error)
{
  GTlsFileDatabaseNss *nss = G_TLS_FILE_DATABASE_NSS (database);
  GList *certs, *l, *next;
  GTlsCertificate *cert;

  certs = g_tls_database_lookup_certificates_issued_by (nss->priv->default_db,
							issuer_raw_dn,
							interaction, flags,
							cancellable, error);
  if (!certs)
    return NULL;

  for (l = certs; l; l = next)
    {
      cert = l->data;
      next = l->next;
      if (!g_hash_table_lookup (nss->priv->certs, cert))
	{
	  g_object_unref (cert);
	  certs = g_list_delete_link (certs, l);
	}
    }

  return certs;
}

static void
g_tls_file_database_nss_class_init (GTlsFileDatabaseNssClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsDatabaseClass *database_class = G_TLS_DATABASE_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GTlsFileDatabaseNssPrivate));

  gobject_class->get_property = g_tls_file_database_nss_get_property;
  gobject_class->set_property = g_tls_file_database_nss_set_property;
  gobject_class->finalize     = g_tls_file_database_nss_finalize;

  database_class->create_certificate_handle = g_tls_file_database_nss_create_certificate_handle;
  database_class->lookup_certificate_for_handle = g_tls_file_database_nss_lookup_certificate_for_handle;
  database_class->lookup_certificate_issuer = g_tls_file_database_nss_lookup_certificate_issuer;
  database_class->lookup_certificates_issued_by = g_tls_file_database_nss_lookup_certificates_issued_by;

  g_object_class_override_property (gobject_class, PROP_ANCHORS, "anchors");
}

static void
g_tls_file_database_nss_file_database_interface_init (GTlsFileDatabaseInterface *iface)
{

}

static gboolean
g_tls_file_database_nss_initable_init (GInitable     *initable,
				       GCancellable  *cancellable,
				       GError       **error)
{
  GTlsFileDatabaseNss *nss = G_TLS_FILE_DATABASE_NSS (initable);
  GError *my_error = NULL;
  GList *certs, *c;

  if (!nss->priv->anchor_filename)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
		   _("No certificate database filename specified"));
      return FALSE;
    }

  certs = g_tls_certificate_list_new_from_file (nss->priv->anchor_filename,
						&my_error);
  if (my_error)
    {
      g_propagate_error (error, my_error);
      return FALSE;
    }

  for (c = certs; c; c = c->next)
    {
      GTlsCertificateNss *nss_cert = c->data;
      CERTCertificate *cert = g_tls_certificate_nss_get_cert (nss_cert);
      gchar *hash = g_compute_checksum_for_data (G_CHECKSUM_SHA256,
						 cert->derCert.data,
						 cert->derCert.len);

      g_hash_table_insert (nss->priv->certs, nss_cert, nss_cert);
      g_hash_table_insert (nss->priv->certs_by_hash, hash, nss_cert);
      g_hash_table_insert (nss->priv->hashes, nss_cert, hash);
    }
  g_list_free (certs);

  return TRUE;
}

static void
g_tls_file_database_nss_initable_interface_init (GInitableIface *iface)
{
  iface->init = g_tls_file_database_nss_initable_init;
}

gboolean
g_tls_file_database_nss_contains (GTlsFileDatabaseNss *nss,
				  GTlsCertificateNss  *nss_cert)
{
  return g_hash_table_lookup (nss->priv->certs, nss_cert) == nss_cert;
}
