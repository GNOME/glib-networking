/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright © 2011 Collabora, Ltd.
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
 *
 * Author: Stef Walter <stef@collabora.co.uk>
 */

#include "config.h"
#include "glib.h"

#include "gtlsbackend-gnutls-pkcs11.h"
#include "gtlsdatabase-gnutls-pkcs11.h"

G_DEFINE_DYNAMIC_TYPE (GTlsBackendGnutlsPkcs11, g_tls_backend_gnutls_pkcs11, G_TYPE_TLS_BACKEND_GNUTLS);

static void
g_tls_backend_gnutls_pkcs11_init (GTlsBackendGnutlsPkcs11 *backend)
{

}

static GTlsDatabase*
g_tls_backend_gnutls_pkcs11_create_database (GTlsBackendGnutls  *backend,
                                             GError            **error)
{
  return g_tls_database_gnutls_pkcs11_new (error);
}

static void
g_tls_backend_gnutls_pkcs11_class_init (GTlsBackendGnutlsPkcs11Class *backend_class)
{
  GTlsBackendGnutlsClass *gnutls_class = G_TLS_BACKEND_GNUTLS_CLASS (backend_class);
  gnutls_class->create_database = g_tls_backend_gnutls_pkcs11_create_database;
}

static void
g_tls_backend_gnutls_pkcs11_class_finalize (GTlsBackendGnutlsPkcs11Class *backend_class)
{

}

void
g_tls_backend_gnutls_pkcs11_register (GIOModule *module)
{
  g_tls_backend_gnutls_pkcs11_register_type (G_TYPE_MODULE (module));
  g_io_extension_point_implement (G_TLS_BACKEND_EXTENSION_POINT_NAME,
				  g_tls_backend_gnutls_pkcs11_get_type(),
				  "gnutls-pkcs11",
				  -5);
}
