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

typedef struct _GTlsBackendOpensslPrivate
{
  GMutex mutex;
  GTlsDatabase *default_database;
} GTlsBackendOpensslPrivate;

static void g_tls_backend_openssl_interface_init (GTlsBackendInterface *iface);

G_DEFINE_DYNAMIC_TYPE_EXTENDED (GTlsBackendOpenssl, g_tls_backend_openssl, G_TYPE_OBJECT, 0,
                                G_ADD_PRIVATE_DYNAMIC (GTlsBackendOpenssl)
                                G_IMPLEMENT_INTERFACE_DYNAMIC (G_TYPE_TLS_BACKEND,
                                                               g_tls_backend_openssl_interface_init))

static GMutex *mutex_array = NULL;

struct CRYPTO_dynlock_value {
  GMutex mutex;
};

static unsigned long
id_cb (void)
{
  return (unsigned long) g_thread_self ();
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

static gpointer
gtls_openssl_init (gpointer data)
{
  int i;

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
  g_type_plugin_use (g_type_get_plugin (G_TYPE_TLS_BACKEND_OPENSSL));

  return NULL;
}

static GOnce openssl_inited = G_ONCE_INIT;

static void
g_tls_backend_openssl_init (GTlsBackendOpenssl *backend)
{
  GTlsBackendOpensslPrivate *priv;

  priv = g_tls_backend_openssl_get_instance_private (backend);

  /* Once we call gtls_openssl_init(), we can't allow the module to be
   * unloaded (since if openssl gets unloaded but gcrypt doesn't, then
   * gcrypt will have dangling pointers to openssl's mutex functions).
   * So we initialize it from here rather than at class init time so
   * that it doesn't happen unless the app is actually using TLS (as
   * opposed to just calling g_io_modules_scan_all_in_directory()).
   */
  g_once (&openssl_inited, gtls_openssl_init, NULL);

  g_mutex_init (&priv->mutex);
}

static void
g_tls_backend_openssl_finalize (GObject *object)
{
  int i;

  GTlsBackendOpenssl *backend = G_TLS_BACKEND_OPENSSL (object);
  GTlsBackendOpensslPrivate *priv;

  priv = g_tls_backend_openssl_get_instance_private (backend);

  g_clear_object (&priv->default_database);
  g_mutex_clear (&priv->mutex);

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

static GTlsDatabase *
g_tls_backend_openssl_real_create_database (GTlsBackendOpenssl  *self,
                                            GError             **error)
{
  gchar *anchor_file = NULL;
  GTlsDatabase *database;

#ifdef G_OS_WIN32
  if (g_getenv ("G_TLS_OPENSSL_HANDLE_CERT_RELOCATABLE") != NULL)
    {
      gchar *module_dir;

      module_dir = g_win32_get_package_installation_directory_of_module (NULL);
      anchor_file = g_build_filename (module_dir, "bin", "cert.pem", NULL);
      g_free (module_dir);
    }
#endif

#ifdef GTLS_SYSTEM_CA_FILE
  if (anchor_file == NULL)
    anchor_file = g_strdup (GTLS_SYSTEM_CA_FILE);
#endif

  if (anchor_file == NULL)
    {
      const gchar *openssl_cert_file;

      openssl_cert_file = g_getenv (X509_get_default_cert_file_env ());
      if (openssl_cert_file == NULL)
        openssl_cert_file = X509_get_default_cert_file ();

      anchor_file = g_strdup (openssl_cert_file);
    }

  database = g_tls_file_database_new (anchor_file, error);
  g_free (anchor_file);

  return database;
}

static void
g_tls_backend_openssl_class_init (GTlsBackendOpensslClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = g_tls_backend_openssl_finalize;

  klass->create_database = g_tls_backend_openssl_real_create_database;
}

static void
g_tls_backend_openssl_class_finalize (GTlsBackendOpensslClass *backend_class)
{
}

static GTlsDatabase*
g_tls_backend_openssl_get_default_database (GTlsBackend *backend)
{
  GTlsBackendOpenssl *openssl_backend = G_TLS_BACKEND_OPENSSL (backend);
  GTlsBackendOpensslPrivate *priv;
  GTlsDatabase *result;
  GError *error = NULL;

  priv = g_tls_backend_openssl_get_instance_private (openssl_backend);

  g_mutex_lock (&priv->mutex);

  if (priv->default_database)
    {
      result = g_object_ref (priv->default_database);
    }
  else
    {
      g_assert (G_TLS_BACKEND_OPENSSL_GET_CLASS (openssl_backend)->create_database);
      result = G_TLS_BACKEND_OPENSSL_GET_CLASS (openssl_backend)->create_database (openssl_backend, &error);
      if (error)
        {
          g_warning ("Couldn't load TLS file database: %s",
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
g_tls_backend_openssl_interface_init (GTlsBackendInterface *iface)
{
  iface->get_certificate_type = g_tls_certificate_openssl_get_type;
  iface->get_client_connection_type = g_tls_client_connection_openssl_get_type;
  iface->get_server_connection_type = g_tls_server_connection_openssl_get_type;
  iface->get_file_database_type = g_tls_file_database_openssl_get_type;
  iface->get_default_database = g_tls_backend_openssl_get_default_database;
}

void
g_tls_backend_openssl_register (GIOModule *module)
{
  g_tls_backend_openssl_register_type (G_TYPE_MODULE (module));
  g_io_extension_point_implement (G_TLS_BACKEND_EXTENSION_POINT_NAME,
                                  g_tls_backend_openssl_get_type(),
                                  "openssl",
                                  -1);
}
