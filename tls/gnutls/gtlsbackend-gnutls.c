/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2010 Red Hat, Inc
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
 */

#include "config.h"
#include "glib.h"

#include <errno.h>
#include <string.h>

#include <gnutls/gnutls.h>

#include "gtlsbackend-gnutls.h"
#include "gtlscertificate-gnutls.h"
#include "gtlsclientconnection-gnutls.h"
#include "gtlsfiledatabase-gnutls.h"
#include "gtlsserverconnection-gnutls.h"

struct _GTlsBackendGnutlsPrivate
{
  GMutex mutex;
  GTlsDatabase *default_database;
};

static void gtls_gnutls_init (void);
static void g_tls_backend_gnutls_interface_init (GTlsBackendInterface *iface);

G_DEFINE_DYNAMIC_TYPE_EXTENDED (GTlsBackendGnutls, g_tls_backend_gnutls, G_TYPE_OBJECT, 0,
				G_IMPLEMENT_INTERFACE_DYNAMIC (G_TYPE_TLS_BACKEND,
							       g_tls_backend_gnutls_interface_init);
				gtls_gnutls_init ();
				)

#ifdef GTLS_GNUTLS_DEBUG
static void
gtls_log_func (int level, const char *msg)
{
  g_print ("GTLS: %s", msg);
}
#endif

static void
gtls_gnutls_init (void)
{
  gnutls_global_init ();

#ifdef GTLS_GNUTLS_DEBUG
  gnutls_global_set_log_function (gtls_log_func);
  gnutls_global_set_log_level (9);

  /* Leak the module to keep it from being unloaded and breaking
   * the pointer to gtls_log_func().
   */
  g_type_plugin_use (g_type_get_plugin (G_TYPE_TLS_BACKEND_GNUTLS));
#endif
}

static void
g_tls_backend_gnutls_init (GTlsBackendGnutls *backend)
{
  backend->priv = G_TYPE_INSTANCE_GET_PRIVATE (backend, G_TYPE_TLS_BACKEND_GNUTLS, GTlsBackendGnutlsPrivate);
  g_mutex_init (&backend->priv->mutex);
}

static void
g_tls_backend_gnutls_finalize (GObject *object)
{
  GTlsBackendGnutls *backend = G_TLS_BACKEND_GNUTLS (object);

  if (backend->priv->default_database)
    g_object_unref (backend->priv->default_database);
  g_mutex_clear (&backend->priv->mutex);

  G_OBJECT_CLASS (g_tls_backend_gnutls_parent_class)->finalize (object);
}

static GTlsDatabase*
g_tls_backend_gnutls_real_create_database (GTlsBackendGnutls  *self,
                                           GError            **error)
{
  const gchar *anchor_file = NULL;
#ifdef GTLS_SYSTEM_CA_FILE
  anchor_file = GTLS_SYSTEM_CA_FILE;
#endif
  return g_tls_file_database_new (anchor_file, error);
}

static void
g_tls_backend_gnutls_class_init (GTlsBackendGnutlsClass *backend_class)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (backend_class);
  gobject_class->finalize = g_tls_backend_gnutls_finalize;
  backend_class->create_database = g_tls_backend_gnutls_real_create_database;
  g_type_class_add_private (backend_class, sizeof (GTlsBackendGnutlsPrivate));
}

static void
g_tls_backend_gnutls_class_finalize (GTlsBackendGnutlsClass *backend_class)
{
}

static GTlsDatabase*
g_tls_backend_gnutls_get_default_database (GTlsBackend *backend)
{
  GTlsBackendGnutls *self = G_TLS_BACKEND_GNUTLS (backend);
  GTlsDatabase *result;
  GError *error = NULL;

  g_mutex_lock (&self->priv->mutex);

  if (self->priv->default_database)
    {
      result = g_object_ref (self->priv->default_database);
    }
  else
    {
      g_assert (G_TLS_BACKEND_GNUTLS_GET_CLASS (self)->create_database);
      result = G_TLS_BACKEND_GNUTLS_GET_CLASS (self)->create_database (self, &error);
      if (error)
        {
          g_warning ("couldn't load TLS file database: %s",
                     error->message);
          g_clear_error (&error);
        }
      else
        {
          g_assert (result);
          self->priv->default_database = g_object_ref (result);
        }
    }

  g_mutex_unlock (&self->priv->mutex);

  return result;
}

static void
g_tls_backend_gnutls_interface_init (GTlsBackendInterface *iface)
{
  iface->get_certificate_type       = g_tls_certificate_gnutls_get_type;
  iface->get_client_connection_type = g_tls_client_connection_gnutls_get_type;
  iface->get_server_connection_type = g_tls_server_connection_gnutls_get_type;
  iface->get_file_database_type =     g_tls_file_database_gnutls_get_type;
  iface->get_default_database =       g_tls_backend_gnutls_get_default_database;
}

/* Session cache support; all the details are sort of arbitrary. Note
 * that having session_cache_cleanup() be a little bit slow isn't the
 * end of the world, since it will still be faster than the network
 * is. (NSS uses a linked list for its cache...)
 */

G_LOCK_DEFINE_STATIC (session_cache_lock);
GHashTable *session_cache;

#define SESSION_CACHE_MAX_SIZE 50
#define SESSION_CACHE_MAX_AGE (60 * 60) /* one hour */

typedef struct {
  gchar      *session_id;
  GByteArray *session_data;
  time_t      last_used;
} GTlsBackendGnutlsCacheData;

static void
session_cache_cleanup (void)
{
  GHashTableIter iter;
  gpointer key, value;
  GTlsBackendGnutlsCacheData *cache_data;
  time_t expired = time (NULL) - SESSION_CACHE_MAX_AGE;

  g_hash_table_iter_init (&iter, session_cache);
  while (g_hash_table_iter_next (&iter, &key, &value))
    {
      cache_data = value;
      if (cache_data->last_used < expired)
	g_hash_table_iter_remove (&iter);
    }
}

static void
cache_data_free (gpointer data)
{
  GTlsBackendGnutlsCacheData *cache_data = data;

  g_free (cache_data->session_id);
  g_byte_array_unref (cache_data->session_data);
  g_slice_free (GTlsBackendGnutlsCacheData, cache_data);
}

void
g_tls_backend_gnutls_cache_session_data (const gchar *session_id,
					 guchar      *session_data,
					 gsize        session_data_length)
{
  GTlsBackendGnutlsCacheData *cache_data;

  G_LOCK (session_cache_lock);

  if (!session_cache)
    session_cache = g_hash_table_new_full (g_str_hash, g_str_equal,
					   NULL, cache_data_free);

  cache_data = g_hash_table_lookup (session_cache, session_id);
  if (cache_data)
    {
      if (cache_data->session_data->len == session_data_length &&
	  memcmp (cache_data->session_data->data,
		  session_data, session_data_length) == 0)
	{
	  cache_data->last_used = time (NULL);
	  G_UNLOCK (session_cache_lock);
	  return;
	}

      g_byte_array_set_size (cache_data->session_data, 0);
    }
  else
    {
      if (g_hash_table_size (session_cache) >= SESSION_CACHE_MAX_SIZE)
	session_cache_cleanup ();

      cache_data = g_slice_new (GTlsBackendGnutlsCacheData);
      cache_data->session_id = g_strdup (session_id);
      cache_data->session_data = g_byte_array_sized_new (session_data_length);

      g_hash_table_insert (session_cache, cache_data->session_id, cache_data);
    }

  g_byte_array_append (cache_data->session_data,
		       session_data, session_data_length);
  cache_data->last_used = time (NULL);
  G_UNLOCK (session_cache_lock);
}

void
g_tls_backend_gnutls_uncache_session_data (const gchar *session_id)
{
  G_LOCK (session_cache_lock);
  if (session_cache)
    g_hash_table_remove (session_cache, session_id);
  G_UNLOCK (session_cache_lock);
}

GByteArray *
g_tls_backend_gnutls_lookup_session_data (const gchar *session_id)
{
  GTlsBackendGnutlsCacheData *cache_data;
  GByteArray *session_data = NULL;

  G_LOCK (session_cache_lock);
  if (session_cache)
    {
      cache_data = g_hash_table_lookup (session_cache, session_id);
      if (cache_data)
	{
	  cache_data->last_used = time (NULL);
	  session_data = g_byte_array_ref (cache_data->session_data);
	}
    }
  G_UNLOCK (session_cache_lock);

  return session_data;
}

void
g_tls_backend_gnutls_register (GIOModule *module)
{
  g_tls_backend_gnutls_register_type (G_TYPE_MODULE (module));
  g_io_extension_point_implement (G_TLS_BACKEND_EXTENSION_POINT_NAME,
				  g_tls_backend_gnutls_get_type(),
				  "gnutls",
				  0);
}
