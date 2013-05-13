/* GIO TLS tests
 *
 * Copyright (C) 2011 Collabora, Ltd.
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
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include <gio/gio.h>

#include <sys/types.h>
#include <string.h>

#include "pkcs11/gpkcs11pin.h"

typedef struct {
  GTlsPassword *pin;
} TestPin;

static void
setup_pin (TestPin          *test,
           gconstpointer     unused)
{
  test->pin = g_pkcs11_pin_new (G_TLS_PASSWORD_RETRY, "Test description");
  g_assert (G_IS_PKCS11_PIN (test->pin));
  g_assert (G_IS_TLS_PASSWORD (test->pin));
}

static void
teardown_pin (TestPin       *test,
              gconstpointer  unused)
{
  g_assert_cmpint (G_OBJECT (test->pin)->ref_count, ==, 1);
  g_object_unref (test->pin);
}

static void
test_attributes (TestPin        *test,
                 gconstpointer   data)
{
  GTlsPasswordFlags flags;
  const gchar *description;

  flags = g_tls_password_get_flags (test->pin);
  g_assert_cmpuint (flags, ==, G_TLS_PASSWORD_RETRY);

  description = g_tls_password_get_description (test->pin);
  g_assert_cmpstr (description, ==, "Test description");
}

static void
test_warnings (TestPin        *test,
               gconstpointer   data)
{
  const gchar *warning;

  g_tls_password_set_flags (test->pin, G_TLS_PASSWORD_RETRY);
  warning = g_tls_password_get_warning (test->pin);
  g_assert (warning != NULL);

  g_tls_password_set_flags (test->pin, G_TLS_PASSWORD_FINAL_TRY);
  warning = g_tls_password_get_warning (test->pin);
  g_assert (warning != NULL);

  g_tls_password_set_flags (test->pin, G_TLS_PASSWORD_MANY_TRIES);
  warning = g_tls_password_get_warning (test->pin);
  g_assert (warning != NULL);

  g_tls_password_set_flags (test->pin, (GTlsPasswordFlags)0x10000000);
  warning = g_tls_password_get_warning (test->pin);
  g_assert (warning == NULL);

}

static void
test_set_get_value (TestPin        *test,
                    gconstpointer   data)
{
  const guchar *value;
  gsize n_value = G_MAXSIZE;

  value = g_tls_password_get_value (test->pin, &n_value);
  g_assert_cmpuint (n_value, ==, 0);
  g_assert (value == NULL);

  g_tls_password_set_value (test->pin, (const guchar *)"secret", -1);

  value = g_tls_password_get_value (test->pin, &n_value);
  g_assert_cmpuint (n_value, ==, 6);
  g_assert (!strncmp ((const gchar *)value, "secret", n_value));

  g_tls_password_set_value (test->pin, (const guchar *)"other", 5);

  value = g_tls_password_get_value (test->pin, &n_value);
  g_assert_cmpuint (n_value, ==, 5);
  g_assert (!strncmp ((const gchar *)value, "other", n_value));
}

static void
test_internal_pin (TestPin        *test,
                   gconstpointer   data)
{
  P11KitPin *pin;
  const unsigned char *value;
  size_t n_value;

  g_tls_password_set_value (test->pin, (const guchar *)"secret", -1);

  pin = g_pkcs11_pin_steal_internal (G_PKCS11_PIN (test->pin));

  value = p11_kit_pin_get_value (pin, &n_value);
  g_assert_cmpuint (n_value, ==, 6);
  g_assert (!strncmp ((const gchar *)value, "secret", n_value));

  p11_kit_pin_unref (pin);
}

int
main (int   argc,
      char *argv[])
{
  g_test_init (&argc, &argv, NULL);

  g_test_add ("/pkcs11/pin/attributes", TestPin, NULL,
              setup_pin, test_attributes, teardown_pin);
  g_test_add ("/pkcs11/pin/warnings", TestPin, NULL,
              setup_pin, test_warnings, teardown_pin);
  g_test_add ("/pkcs11/pin/set-get-value", TestPin, NULL,
              setup_pin, test_set_get_value, teardown_pin);
  g_test_add ("/pkcs11/pin/internal-pin", TestPin, NULL,
              setup_pin, test_internal_pin, teardown_pin);

  return g_test_run();
}
