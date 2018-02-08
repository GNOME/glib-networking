/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2010 Red Hat, Inc
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

typedef struct
{
  GMutex mutex;
  GTlsDatabase *default_database;
} GTlsBackendGnutlsPrivate;

static void g_tls_backend_gnutls_interface_init (GTlsBackendInterface *iface);

G_DEFINE_DYNAMIC_TYPE_EXTENDED (GTlsBackendGnutls, g_tls_backend_gnutls, G_TYPE_OBJECT, 0,
                                G_ADD_PRIVATE_DYNAMIC (GTlsBackendGnutls);
                                G_IMPLEMENT_INTERFACE_DYNAMIC (G_TYPE_TLS_BACKEND,
                                                               g_tls_backend_gnutls_interface_init);)

#ifdef GTLS_GNUTLS_DEBUG
static void
gtls_log_func (int level, const char *msg)
{
  g_print ("GTLS: %s", msg);
}
#endif

static gpointer
gtls_gnutls_init (gpointer data)
{
  GTypePlugin *plugin;

  gnutls_global_init ();

#ifdef GTLS_GNUTLS_DEBUG
  gnutls_global_set_log_function (gtls_log_func);
  gnutls_global_set_log_level (9);
#endif

  /* Leak the module to keep it from being unloaded. */
  plugin = g_type_get_plugin (G_TYPE_TLS_BACKEND_GNUTLS);
  if (plugin != NULL)
    g_type_plugin_use (plugin);
  return NULL;
}

GNUTLS_SKIP_GLOBAL_INIT

static GOnce gnutls_inited = G_ONCE_INIT;

static void
g_tls_backend_gnutls_init (GTlsBackendGnutls *backend)
{
  GTlsBackendGnutlsPrivate *priv = g_tls_backend_gnutls_get_instance_private (backend);

  /* Once we call gtls_gnutls_init(), we can't allow the module to be
   * unloaded (since if gnutls gets unloaded but gcrypt doesn't, then
   * gcrypt will have dangling pointers to gnutls's mutex functions).
   * So we initialize it from here rather than at class init time so
   * that it doesn't happen unless the app is actually using TLS (as
   * opposed to just calling g_io_modules_scan_all_in_directory()).
   */
  g_once (&gnutls_inited, gtls_gnutls_init, NULL);

  g_mutex_init (&priv->mutex);
}

static void
g_tls_backend_gnutls_finalize (GObject *object)
{
  GTlsBackendGnutls *backend = G_TLS_BACKEND_GNUTLS (object);
  GTlsBackendGnutlsPrivate *priv = g_tls_backend_gnutls_get_instance_private (backend);

  if (priv->default_database)
    g_object_unref (priv->default_database);
  g_mutex_clear (&priv->mutex);

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
}

static void
g_tls_backend_gnutls_class_finalize (GTlsBackendGnutlsClass *backend_class)
{
}

static GTlsDatabase*
g_tls_backend_gnutls_get_default_database (GTlsBackend *backend)
{
  GTlsBackendGnutls *self = G_TLS_BACKEND_GNUTLS (backend);
  GTlsBackendGnutlsPrivate *priv = g_tls_backend_gnutls_get_instance_private (self);
  GTlsDatabase *result;
  GError *error = NULL;

  g_mutex_lock (&priv->mutex);

  if (priv->default_database)
    {
      result = g_object_ref (priv->default_database);
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
          priv->default_database = g_object_ref (result);
        }
    }

  g_mutex_unlock (&priv->mutex);

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
  iface->get_dtls_client_connection_type = g_tls_client_connection_gnutls_get_type;
  iface->get_dtls_server_connection_type = g_tls_server_connection_gnutls_get_type;
}

/* Session cache support; all the details are sort of arbitrary. Note
 * that having session_cache_cleanup() be a little bit slow isn't the
 * end of the world, since it will still be faster than the network
 * is. (NSS uses a linked list for its cache...)
 */

G_LOCK_DEFINE_STATIC (session_cache_lock);
GHashTable *client_session_cache, *server_session_cache;

#define SESSION_CACHE_MAX_SIZE 50
#define SESSION_CACHE_MAX_AGE (60 * 60) /* one hour */

typedef struct {
  GBytes *session_id;
  GBytes *session_data;
  time_t  last_used;
} GTlsBackendGnutlsCacheData;

static void
session_cache_cleanup (GHashTable *cache)
{
  GHashTableIter iter;
  gpointer key, value;
  GTlsBackendGnutlsCacheData *cache_data;
  time_t expired = time (NULL) - SESSION_CACHE_MAX_AGE;

  g_hash_table_iter_init (&iter, cache);
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

  g_bytes_unref (cache_data->session_id);
  g_bytes_unref (cache_data->session_data);
  g_slice_free (GTlsBackendGnutlsCacheData, cache_data);
}

static GHashTable *
get_session_cache (unsigned int            type,
                   gboolean                create)
{
  GHashTable **cache_p;

  cache_p = (type == GNUTLS_CLIENT) ? &client_session_cache : &server_session_cache;
  if (!*cache_p && create)
    {
      *cache_p = g_hash_table_new_full (g_bytes_hash, g_bytes_equal,
                                        NULL, cache_data_free);
    }
  return *cache_p;
}

void
g_tls_backend_gnutls_store_session (unsigned int             type,
                                    GBytes                  *session_id,
                                    GBytes                  *session_data)
{
  GTlsBackendGnutlsCacheData *cache_data;
  GHashTable *cache;

  G_LOCK (session_cache_lock);

  cache = get_session_cache (type, TRUE);
  cache_data = g_hash_table_lookup (cache, session_id);
  if (cache_data)
    {
      if (!g_bytes_equal (cache_data->session_data, session_data))
        {
          g_bytes_unref (cache_data->session_data);
          cache_data->session_data = g_bytes_ref (session_data);
        }
    }
  else
    {
      if (g_hash_table_size (cache) >= SESSION_CACHE_MAX_SIZE)
        session_cache_cleanup (cache);

      cache_data = g_slice_new (GTlsBackendGnutlsCacheData);
      cache_data->session_id = g_bytes_ref (session_id);
      cache_data->session_data = g_bytes_ref (session_data);

      g_hash_table_insert (cache, cache_data->session_id, cache_data);
    }
  cache_data->last_used = time (NULL);

  G_UNLOCK (session_cache_lock);
}

void
g_tls_backend_gnutls_remove_session (unsigned int             type,
                                     GBytes                  *session_id)
{
  GHashTable *cache;

  G_LOCK (session_cache_lock);

  cache = get_session_cache (type, FALSE);
  if (cache)
    g_hash_table_remove (cache, session_id);

  G_UNLOCK (session_cache_lock);
}

GBytes *
g_tls_backend_gnutls_lookup_session (unsigned int             type,
                                     GBytes                  *session_id)
{
  GTlsBackendGnutlsCacheData *cache_data;
  GBytes *session_data = NULL;
  GHashTable *cache;

  G_LOCK (session_cache_lock);

  cache = get_session_cache (type, FALSE);
  if (cache)
    {
      cache_data = g_hash_table_lookup (cache, session_id);
      if (cache_data)
        {
          cache_data->last_used = time (NULL);
          session_data = g_bytes_ref (cache_data->session_data);
        }
    }

  G_UNLOCK (session_cache_lock);

  return session_data;
}

void
g_tls_backend_gnutls_register (GIOModule *module)
{
  g_tls_backend_gnutls_register_type (G_TYPE_MODULE (module));
  if (module == NULL)
    g_io_extension_point_register (G_TLS_BACKEND_EXTENSION_POINT_NAME);
  g_io_extension_point_implement (G_TLS_BACKEND_EXTENSION_POINT_NAME,
                                  g_tls_backend_gnutls_get_type(),
                                  "gnutls",
                                  0);
}
