/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlsbackend-openssl.c
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
#include "glib.h"

#include <errno.h>
#include <string.h>

#include "openssl-include.h"

#include "gtlsbackend-openssl.h"
#include "gtlscertificate-openssl.h"
#include "gtlsserverconnection-openssl.h"
#include "gtlsclientconnection-openssl.h"
#include "gtlsfiledatabase-openssl.h"

struct _GTlsBackendOpenssl
{
  GObject parent_instance;

  GMutex mutex;
  GTlsDatabase *default_database;
};

static void g_tls_backend_openssl_interface_init (GTlsBackendInterface *iface);

G_DEFINE_DYNAMIC_TYPE_EXTENDED (GTlsBackendOpenssl, g_tls_backend_openssl, G_TYPE_OBJECT, 0,
                                G_IMPLEMENT_INTERFACE_DYNAMIC (G_TYPE_TLS_BACKEND,
                                                               g_tls_backend_openssl_interface_init))

static GMutex *mutex_array = NULL;

struct CRYPTO_dynlock_value {
  GMutex mutex;
};

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

static size_t
id_cb (void)
{
  return (size_t) g_thread_self ();
}

static void
locking_cb (int         mode,
            int         n,
            const char *file,
            int         line)
{
  if (mode & CRYPTO_LOCK)
    g_mutex_lock (&mutex_array[n]);
  else
    g_mutex_unlock (&mutex_array[n]);
}

static struct CRYPTO_dynlock_value *
dyn_create_cb (const char *file,
               int         line)
{
  struct CRYPTO_dynlock_value *value = g_try_new (struct CRYPTO_dynlock_value, 1);

  if (value)
    g_mutex_init (&value->mutex);

  return value;
}

static void
dyn_lock_cb (int                          mode,
             struct CRYPTO_dynlock_value *l,
             const char                  *file,
             int                          line)
{
  if (mode & CRYPTO_LOCK)
    g_mutex_lock (&l->mutex);
  else
    g_mutex_unlock (&l->mutex);
}

static void
dyn_destroy_cb (struct CRYPTO_dynlock_value *l,
                const char                  *file,
                int                          line)
{
  g_mutex_clear (&l->mutex);
  g_free (l);
}

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

static gpointer
gtls_openssl_init (gpointer data)
{
  int i;
  GTypePlugin *plugin;

  /* Initialize openssl threading */
  mutex_array = g_malloc_n (CRYPTO_num_locks(), sizeof (GMutex));
  for (i = 0; i < CRYPTO_num_locks (); ++i)
    g_mutex_init(&mutex_array[i]);

  CRYPTO_set_id_callback (id_cb);
  CRYPTO_set_locking_callback (locking_cb);
  CRYPTO_set_dynlock_create_callback (dyn_create_cb);
  CRYPTO_set_dynlock_lock_callback (dyn_lock_cb);
  CRYPTO_set_dynlock_destroy_callback (dyn_destroy_cb);

  SSL_library_init ();
  SSL_load_error_strings ();
  OpenSSL_add_all_algorithms ();

  /* Leak the module to keep it from being unloaded. */
  plugin = g_type_get_plugin (G_TYPE_TLS_BACKEND_OPENSSL);
  if (plugin)
    g_type_plugin_use (plugin);
  return NULL;
}

static GOnce openssl_inited = G_ONCE_INIT;

static void
g_tls_backend_openssl_init (GTlsBackendOpenssl *backend)
{
  /* Once we call gtls_openssl_init(), we can't allow the module to be
   * unloaded (since if openssl gets unloaded but gcrypt doesn't, then
   * gcrypt will have dangling pointers to openssl's mutex functions).
   * So we initialize it from here rather than at class init time so
   * that it doesn't happen unless the app is actually using TLS (as
   * opposed to just calling g_io_modules_scan_all_in_directory()).
   */
  g_once (&openssl_inited, gtls_openssl_init, NULL);

  g_mutex_init (&backend->mutex);
}

static void
g_tls_backend_openssl_finalize (GObject *object)
{
  int i;

  GTlsBackendOpenssl *backend = G_TLS_BACKEND_OPENSSL (object);

  g_clear_object (&backend->default_database);
  g_mutex_clear (&backend->mutex);

  CRYPTO_set_id_callback (NULL);
  CRYPTO_set_locking_callback (NULL);
  CRYPTO_set_dynlock_create_callback (NULL);
  CRYPTO_set_dynlock_lock_callback (NULL);
  CRYPTO_set_dynlock_destroy_callback (NULL);
  for (i = 0; i < CRYPTO_num_locks(); ++i)
    g_mutex_clear (&mutex_array[i]);
  g_free (mutex_array);

  G_OBJECT_CLASS (g_tls_backend_openssl_parent_class)->finalize (object);
}

static void
g_tls_backend_openssl_class_init (GTlsBackendOpensslClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = g_tls_backend_openssl_finalize;
}

static void
g_tls_backend_openssl_class_finalize (GTlsBackendOpensslClass *backend_class)
{
}

static GTlsDatabase *
g_tls_backend_openssl_get_default_database (GTlsBackend *backend)
{
  GTlsBackendOpenssl *openssl_backend = G_TLS_BACKEND_OPENSSL (backend);
  GTlsDatabase *result;
  GError *error = NULL;

  g_mutex_lock (&openssl_backend->mutex);

  if (openssl_backend->default_database)
    {
      result = g_object_ref (openssl_backend->default_database);
    }
  else
    {
      result = G_TLS_DATABASE (g_tls_database_openssl_new (&error));
      if (error)
        {
          g_warning ("Couldn't load TLS file database: %s",
                     error->message);
          g_clear_error (&error);
        }
      else
        {
          g_assert (result);
          openssl_backend->default_database = g_object_ref (result);
        }
    }

  g_mutex_unlock (&openssl_backend->mutex);

  return result;
}

static void
g_tls_backend_openssl_interface_init (GTlsBackendInterface *iface)
{
  iface->get_certificate_type = g_tls_certificate_openssl_get_type;
  iface->get_client_connection_type = g_tls_client_connection_openssl_get_type;
  iface->get_server_connection_type = g_tls_server_connection_openssl_get_type;
  iface->get_file_database_type = g_tls_file_database_openssl_get_type;
  iface->get_default_database = g_tls_backend_openssl_get_default_database;
  iface->get_dtls_client_connection_type = g_tls_client_connection_openssl_get_type;
  iface->get_dtls_server_connection_type = g_tls_server_connection_openssl_get_type;
}

/* Session cache support. We try to be careful of TLS session tracking
 * and so have adopted the recommendations of arXiv:1810.07304 section 6
 * in using a 10-minute cache lifetime and in never updating the
 * expiration time of cache entries when they are accessed to ensure a
 * new session gets used after 10 minutes even if the cached one was
 * resumed more recently.
 *
 * https://arxiv.org/abs/1810.07304
 */

G_LOCK_DEFINE_STATIC (session_cache_lock);
static GHashTable *client_session_cache; /* (owned) GString -> (owned) GTlsBackendOpensslCacheData */

#define SESSION_CACHE_MAX_SIZE 50
#define SESSION_CACHE_MAX_AGE (10ll * 60ll * G_USEC_PER_SEC) /* ten minutes */

typedef struct {
  SSL_SESSION *session_ticket;
  gint64 expiration_time;
} GTlsBackendOpensslCacheData;

static void
session_cache_cleanup (GHashTable *cache)
{
  gint64 time;
  GHashTableIter iter;
  gpointer key, value;
  GTlsBackendOpensslCacheData *cache_data;
  GString *session_id = NULL;
  gint64 expiration_time = 0;
  gboolean removed = FALSE;

  time = g_get_monotonic_time ();

  g_hash_table_iter_init (&iter, cache);
  while (g_hash_table_iter_next (&iter, &key, &value))
    {
      cache_data = value;
      if (cache_data->expiration_time > expiration_time)
        {
          expiration_time = cache_data->expiration_time;
          session_id = key;
        }

      if (time > cache_data->expiration_time)
        {
          removed = TRUE;
          g_hash_table_iter_remove (&iter);
        }
    }

  if (!removed && session_id)
    g_hash_table_remove (cache, session_id);
}

static void
cache_data_free (GTlsBackendOpensslCacheData *data)
{
  SSL_SESSION_free (data->session_ticket);
  g_free (data);
}

static void
string_free (GString *data)
{
  g_string_free (data, TRUE);
}

static GHashTable *
get_session_cache (gboolean create)
{
  if (!client_session_cache && create)
    {
      client_session_cache = g_hash_table_new_full ((GHashFunc)g_string_hash,
                                                    (GEqualFunc)g_string_equal,
                                                    (GDestroyNotify)string_free,
                                                    (GDestroyNotify)cache_data_free);
    }
  return client_session_cache;
}

void
g_tls_backend_openssl_store_session_data (GString *session_id,
                                         SSL_SESSION *session_data)
{
  GTlsBackendOpensslCacheData *cache_data;
  GHashTable *cache;

  if (!session_id || !session_data)
    return;

  G_LOCK (session_cache_lock);

  cache = get_session_cache (TRUE);
  cache_data = g_hash_table_lookup (cache, session_id);
  if (!cache_data)
    {
      if (g_hash_table_size (cache) >= SESSION_CACHE_MAX_SIZE)
        session_cache_cleanup (cache);

      if (g_hash_table_size (cache) < SESSION_CACHE_MAX_SIZE)
        {
          cache_data = g_new (GTlsBackendOpensslCacheData, 1);
          cache_data->session_ticket = NULL;
          g_hash_table_insert (cache, g_string_new (session_id->str), cache_data);
        }
  }

  if (cache_data)
    {
      if (SSL_SESSION_up_ref (session_data))
        {
          SSL_SESSION_free (cache_data->session_ticket);
          cache_data->session_ticket = session_data;
          cache_data->expiration_time = g_get_monotonic_time () + SESSION_CACHE_MAX_AGE;
        }
      else
        g_warning ("Failed to acquire TLS session, will not be resumeable");
    }

  G_UNLOCK (session_cache_lock);
}

SSL_SESSION *
g_tls_backend_openssl_lookup_session_data (GString *session_id)
{
  GTlsBackendOpensslCacheData *cache_data;
  SSL_SESSION *session_data = NULL;
  GHashTable *cache;

  if (!session_id)
    return NULL;

  G_LOCK (session_cache_lock);

  cache = get_session_cache (FALSE);
  if (cache)
    {
      cache_data = g_hash_table_lookup (cache, session_id);
      if (cache_data)
        {
          if (g_get_monotonic_time () > cache_data->expiration_time)
            {
              g_hash_table_remove (cache, session_id);
              G_UNLOCK (session_cache_lock);
              return NULL;
            }

          session_data = cache_data->session_ticket;
          if (!SSL_SESSION_up_ref (session_data))
            {
              g_debug ("Failed to acquire cached TLS session, will not try to resume session");
              session_data = NULL;
            }

          /* Note that session tickets should be used only once since TLS 1.3,
           * so we remove from the queue after retrieval. See RFC 8446 §C.4.
           */
          if (SSL_SESSION_get_protocol_version (cache_data->session_ticket) == TLS1_3_VERSION)
            g_hash_table_remove (cache, session_id);
        }
    }

  G_UNLOCK (session_cache_lock);

  return session_data;
}

void
g_tls_backend_openssl_register (GIOModule *module)
{
  g_tls_backend_openssl_register_type (G_TYPE_MODULE (module));
  if (!module)
    g_io_extension_point_register (G_TLS_BACKEND_EXTENSION_POINT_NAME);
  g_io_extension_point_implement (G_TLS_BACKEND_EXTENSION_POINT_NAME,
                                  g_tls_backend_openssl_get_type (),
                                  "openssl",
                                  -1);
}
