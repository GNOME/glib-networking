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

  const guchar issuer_str[] = "\x30\x7e\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x13\x30\x11\x06\x03\x55\x04\x08\x0c\x0a\x43\x61\x6c\x69\x66\x6f\x72\x6e\x69\x61\x31\x16\x30\x14\x06\x03\x55\x04\x07\x0c\x0d\x53\x61\x6e\x20\x46\x72\x61\x6e\x63\x69\x73\x63\x6f\x31\x0f\x30\x0d\x06\x03\x55\x04\x0a\x0c\x06\x42\x61\x64\x53\x53\x4c\x31\x31\x30\x2f\x06\x03\x55\x04\x03\x0c\x28\x42\x61\x64\x53\x53\x4c\x20\x43\x6c\x69\x65\x6e\x74\x20\x52\x6f\x6f\x74\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x41\x75\x74\x68\x6f\x72\x69\x74\x79";
  g_autoptr(GByteArray) issuer = g_byte_array_new ();
  g_byte_array_append (issuer, issuer_str, G_N_ELEMENTS (issuer_str) - 1);

  GList *certs = g_tls_database_lookup_certificates_issued_by (pk_db, issuer, NULL, G_TLS_DATABASE_LOOKUP_NONE, NULL, &error);
  g_message ("%p %p %p", pk_db, certs, error);

  return 0;
}
