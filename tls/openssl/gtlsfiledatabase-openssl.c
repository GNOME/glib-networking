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
#include "openssl-include.h"

struct _GTlsFileDatabaseOpenssl
{
  GTlsDatabaseOpenssl parent_instance;

  /* read-only after construct */
  gchar *anchor_filename;
};

enum
{
  PROP_0,
  PROP_ANCHORS,
};

static void g_tls_file_database_openssl_file_database_interface_init (GTlsFileDatabaseInterface *iface);

G_DEFINE_TYPE_WITH_CODE (GTlsFileDatabaseOpenssl, g_tls_file_database_openssl, G_TYPE_TLS_DATABASE_OPENSSL,
                         G_IMPLEMENT_INTERFACE (G_TYPE_TLS_FILE_DATABASE,
                                                g_tls_file_database_openssl_file_database_interface_init))

static void
g_tls_file_database_openssl_finalize (GObject *object)
{
  GTlsFileDatabaseOpenssl *self = G_TLS_FILE_DATABASE_OPENSSL (object);

  g_free (self->anchor_filename);

  G_OBJECT_CLASS (g_tls_file_database_openssl_parent_class)->finalize (object);
}

static void
g_tls_file_database_openssl_get_property (GObject    *object,
                                          guint       prop_id,
                                          GValue     *value,
                                          GParamSpec *pspec)
{
  GTlsFileDatabaseOpenssl *self = G_TLS_FILE_DATABASE_OPENSSL (object);

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
g_tls_file_database_openssl_set_property (GObject      *object,
                                          guint         prop_id,
                                          const GValue *value,
                                          GParamSpec   *pspec)
{
  GTlsFileDatabaseOpenssl *self = G_TLS_FILE_DATABASE_OPENSSL (object);
  const gchar *anchor_path;

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

      g_free (self->anchor_filename);
      self->anchor_filename = g_strdup (anchor_path);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static gchar *
g_tls_file_database_openssl_create_handle_for_certificate (GTlsDatabaseOpenssl *self,
                                                           GBytes              *der)
{
  gchar *bookmark;
  gchar *uri_part;
  gchar *uri;

  /*
   * Here we create a URI that looks like:
   * file:///etc/ssl/certs/ca-certificates.crt#11b2641821252596420e468c275771f5e51022c121a17bd7a89a2f37b6336c8f
   */

  uri_part = g_filename_to_uri (G_TLS_FILE_DATABASE_OPENSSL (self)->anchor_filename,
                                NULL, NULL);
  if (!uri_part)
    return NULL;

  bookmark = g_compute_checksum_for_bytes (G_CHECKSUM_SHA256, der);
  uri = g_strconcat (uri_part, "#", bookmark, NULL);

  g_free (bookmark);
  g_free (uri_part);

  return uri;
}

static gboolean
g_tls_file_database_openssl_populate_trust_list (GTlsDatabaseOpenssl  *database,
                                                 X509_STORE           *store,
                                                 GError              **error)
{
  GTlsFileDatabaseOpenssl *self = G_TLS_FILE_DATABASE_OPENSSL (database);
  X509_LOOKUP *lookup;

  lookup = X509_STORE_add_lookup (store, X509_LOOKUP_file ());
  if (lookup == NULL)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Failed to load system trust store file: %s"),
                   ERR_error_string (ERR_get_error (), NULL));
      return FALSE;
    }

  X509_LOOKUP_load_file (lookup, self->anchor_filename, X509_FILETYPE_PEM);

  return TRUE;
}

static void
g_tls_file_database_openssl_class_init (GTlsFileDatabaseOpensslClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsDatabaseOpensslClass *openssl_database_class = G_TLS_DATABASE_OPENSSL_CLASS (klass);

  gobject_class->get_property = g_tls_file_database_openssl_get_property;
  gobject_class->set_property = g_tls_file_database_openssl_set_property;
  gobject_class->finalize     = g_tls_file_database_openssl_finalize;

  openssl_database_class->create_handle_for_certificate = g_tls_file_database_openssl_create_handle_for_certificate;
  openssl_database_class->populate_trust_list           = g_tls_file_database_openssl_populate_trust_list;

  g_object_class_override_property (gobject_class, PROP_ANCHORS, "anchors");
}

static void
g_tls_file_database_openssl_file_database_interface_init (GTlsFileDatabaseInterface *iface)
{
}

static void
g_tls_file_database_openssl_init (GTlsFileDatabaseOpenssl *file_database)
{
}
