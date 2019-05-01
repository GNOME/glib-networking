/*
 * Copyright 2019 Igalia S.L.
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
 * Author: Patrick Griffis <pgriffis@igalia.com>
 */

#include <gio/gio.h>

int
main (int argc, char const *argv[])
{
  g_autoptr(GTlsBackend) backend = g_tls_backend_get_default ();
  g_autoptr(GTlsDatabase) db = g_tls_backend_get_default_database (backend);
  g_autoptr(GTlsDatabase) pk_db = g_tls_backend_get_pkcs11_database (backend);
  g_autoptr(GError) error = NULL;

  g_autoptr(GByteArray) issuer = g_byte_array_new_take ((guint8*)g_strdup("DC = com, DC = pivkey, CN = PIVKey Device Certificate Authority"), strlen("DC = com, DC = pivkey, CN = PIVKey Device Certificate Authority"));

  GList *certs = g_tls_database_lookup_certificates_issued_by (pk_db, issuer, NULL, G_TLS_DATABASE_LOOKUP_NONE, NULL, &error);
  g_message ("%p %p %p", pk_db, certs, error);

  return 0;
}
