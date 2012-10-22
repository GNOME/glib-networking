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

#include "pkcs11/gpkcs11array.h"

typedef struct {
  GPkcs11Array *array;
} TestArray;

static void
setup_array (TestArray          *test,
             gconstpointer       unused)
{
  test->array = g_pkcs11_array_new ();
  g_assert (test->array);
}

static void
teardown_array (TestArray       *test,
                gconstpointer    unused)
{
  g_pkcs11_array_unref (test->array);
}

static void
test_add_find (TestArray      *test,
               gconstpointer   data)
{
  CK_ATTRIBUTE attr;
  const CK_ATTRIBUTE *check;
  const gchar *value = "test";

  attr.type = CKA_LABEL;
  attr.ulValueLen = strlen (value) + 1;
  attr.pValue = (gpointer)value;
  g_pkcs11_array_add (test->array, &attr);
  memset (&attr, 0, sizeof (attr));

  check = g_pkcs11_array_find (test->array, CKA_LABEL);
  g_assert (check != NULL);
  g_assert_cmpuint ((guint)check->ulValueLen, ==, strlen (value) + 1);
  g_assert_cmpstr (check->pValue, ==, value);
  g_assert (check->pValue != value);

  /* Should be copied properly, and be independent from stack value */
  g_assert (check != &attr);

  check = g_pkcs11_array_find (test->array, CKA_ID);
  g_assert (check == NULL);
  g_assert_cmpuint (test->array->count, ==, 1);

  /* Adding a second value of same type, should add a duplicate */
  attr.type = CKA_LABEL;
  attr.ulValueLen = 3;
  attr.pValue = "bye";
  g_pkcs11_array_add (test->array, &attr);
  g_assert_cmpuint (test->array->count, ==, 2);
}

static void
test_set_find (TestArray      *test,
               gconstpointer   data)
{
  CK_ATTRIBUTE attr;
  const CK_ATTRIBUTE *check;
  const gchar *value = "test";

  attr.type = CKA_LABEL;
  attr.ulValueLen = strlen (value) + 1;
  attr.pValue = (gpointer)value;
  g_pkcs11_array_set (test->array, &attr);
  memset (&attr, 0, sizeof (attr));

  check = g_pkcs11_array_find (test->array, CKA_LABEL);
  g_assert (check != NULL);
  g_assert_cmpuint ((guint)check->ulValueLen, ==, strlen (value) + 1);
  g_assert_cmpstr (check->pValue, ==, value);
  g_assert (check->pValue != value);

  /* Should be copied properly, and be independent from stack value */
  g_assert (check != &attr);

  /* Adding a second value of same type should override */
  attr.type = CKA_LABEL;
  attr.ulValueLen = 3;
  attr.pValue = "bye";
  g_pkcs11_array_set (test->array, &attr);
  g_assert_cmpuint (test->array->count, ==, 1);
}

static void
test_value (TestArray      *test,
            gconstpointer   data)
{
  const CK_ATTRIBUTE *check;
  const gchar *value = "test";

  /* Add with null termiator */
  g_pkcs11_array_add_value (test->array, CKA_LABEL, value, -1);
  check = g_pkcs11_array_find (test->array, CKA_LABEL);
  g_assert (check != NULL);
  g_assert_cmpuint ((guint)check->ulValueLen, ==, strlen (value));
  g_assert (memcmp (check->pValue, value, check->ulValueLen) == 0);
  g_assert (check->pValue != value);

  /* Add with value length */
  g_pkcs11_array_add_value (test->array, CKA_ID, value, 3);
  check = g_pkcs11_array_find (test->array, CKA_ID);
  g_assert (check != NULL);
  g_assert_cmpuint ((guint)check->ulValueLen, ==, 3);
  g_assert (memcmp (check->pValue, value, check->ulValueLen) == 0);
  g_assert (check->pValue != value);
  g_assert_cmpuint (test->array->count, ==, 2);

  /* Set should override */
  g_pkcs11_array_set_value (test->array, CKA_LABEL, "boring", 6);
  check = g_pkcs11_array_find (test->array, CKA_LABEL);
  g_assert (check != NULL);
  g_assert_cmpuint ((guint)check->ulValueLen, ==, 6);
  g_assert (memcmp (check->pValue, "boring", check->ulValueLen) == 0);
  g_assert_cmpuint (test->array->count, ==, 2);

  /* Override with calculated length */
  g_pkcs11_array_set_value (test->array, CKA_LABEL, "boring", -1);
  check = g_pkcs11_array_find (test->array, CKA_LABEL);
  g_assert (check != NULL);
  g_assert_cmpuint ((guint)check->ulValueLen, ==, 6);
  g_assert (memcmp (check->pValue, "boring", check->ulValueLen) == 0);
  g_assert_cmpuint (test->array->count, ==, 2);

}

static void
test_boolean (TestArray      *test,
              gconstpointer   data)
{
  const CK_ATTRIBUTE *check;
  gboolean bval = FALSE;

  g_pkcs11_array_add_boolean (test->array, CKA_TOKEN, TRUE);
  if (!g_pkcs11_array_find_boolean (test->array, CKA_TOKEN, &bval))
    g_assert_not_reached ();
  g_assert (bval == TRUE);

  /* Check that it's actually formatted right */
  check = g_pkcs11_array_find (test->array, CKA_TOKEN);
  g_assert (check != NULL);
  g_assert_cmpuint (check->ulValueLen, ==, sizeof (CK_BBOOL));
  g_assert (check->pValue != NULL);
  g_assert (*((CK_BBOOL*)check->pValue) == CK_TRUE);

  /* Check FALSE */
  g_pkcs11_array_add_boolean (test->array, CKA_ENCRYPT, FALSE);

  /* Check that it's actually formatted right */
  check = g_pkcs11_array_find (test->array, CKA_ENCRYPT);
  g_assert (check != NULL);
  g_assert_cmpuint (check->ulValueLen, ==, sizeof (CK_BBOOL));
  g_assert (check->pValue != NULL);
  g_assert (*((CK_BBOOL*)check->pValue) == CK_FALSE);
  g_assert_cmpuint (test->array->count, ==, 2);

  /* Add a non boolean value */
  g_pkcs11_array_add_value (test->array, CKA_LABEL, "label", -1);

  /* Shouldn't work to find boolean on that */
  if (g_pkcs11_array_find_boolean (test->array, CKA_LABEL, &bval))
    g_assert_not_reached ();
  g_assert_cmpuint (test->array->count, ==, 3);

  /* Set should override */
  g_pkcs11_array_set_boolean (test->array, CKA_TOKEN, FALSE);
  if (!g_pkcs11_array_find_boolean (test->array, CKA_TOKEN, &bval))
    g_assert_not_reached ();
  g_assert (bval == FALSE);
  g_assert_cmpuint (test->array->count, ==, 3);
}

static void
test_ulong (TestArray      *test,
            gconstpointer   data)
{
  const CK_ATTRIBUTE *check;
  gulong uval = FALSE;

  g_pkcs11_array_add_ulong (test->array, CKA_PIXEL_X, 38938);
  if (!g_pkcs11_array_find_ulong (test->array, CKA_PIXEL_X, &uval))
    g_assert_not_reached ();
  g_assert (uval == 38938UL);
  g_assert_cmpuint (test->array->count, ==, 1);

  /* Check that it's actually formatted right */
  check = g_pkcs11_array_find (test->array, CKA_PIXEL_X);
  g_assert (check != NULL);
  g_assert_cmpuint (check->ulValueLen, ==, sizeof (CK_ULONG));
  g_assert (check->pValue != NULL);
  g_assert (*((CK_ULONG*)check->pValue) == 38938UL);

  /* Check -1, since this is used regularly */
  g_pkcs11_array_add_ulong (test->array, CKA_MODULUS_BITS, (gulong)-1);

  /* Check that it's actually formatted right */
  check = g_pkcs11_array_find (test->array, CKA_MODULUS_BITS);
  g_assert (check != NULL);
  g_assert_cmpuint (check->ulValueLen, ==, sizeof (CK_ULONG));
  g_assert (check->pValue != NULL);
  g_assert (*((CK_ULONG*)check->pValue) == (CK_ULONG)-1);
  g_assert_cmpuint (test->array->count, ==, 2);

  /* Add a non ulong length value */
  g_pkcs11_array_add_value (test->array, CKA_LABEL, "label", -1);
  g_assert_cmpuint (test->array->count, ==, 3);

  /* Shouldn't work to find ulong on that */
  if (g_pkcs11_array_find_ulong (test->array, CKA_LABEL, &uval))
    g_assert_not_reached ();

  /* Set should override */
  g_pkcs11_array_set_ulong (test->array, CKA_PIXEL_X, 48);
  if (!g_pkcs11_array_find_ulong (test->array, CKA_PIXEL_X, &uval))
    g_assert_not_reached ();
  g_assert (uval == 48UL);
  g_assert_cmpuint (test->array->count, ==, 3);
}

static void
test_boxed (TestArray      *test,
            gconstpointer   data)
{
  GPkcs11Array *array;

  /* Should reference */
  array = g_boxed_copy (G_TYPE_PKCS11_ARRAY, test->array);
  g_assert (array == test->array);

  /* Should unreference */
  g_boxed_free (G_TYPE_PKCS11_ARRAY, array);
}

int
main (int   argc,
      char *argv[])
{
  g_test_init (&argc, &argv, NULL);

  g_test_add ("/pkcs11/array/add-find", TestArray, NULL,
              setup_array, test_add_find, teardown_array);
  g_test_add ("/pkcs11/array/set-find", TestArray, NULL,
              setup_array, test_set_find, teardown_array);
  g_test_add ("/pkcs11/array/value", TestArray, NULL,
              setup_array, test_value, teardown_array);
  g_test_add ("/pkcs11/array/boolean", TestArray, NULL,
              setup_array, test_boolean, teardown_array);
  g_test_add ("/pkcs11/array/ulong", TestArray, NULL,
              setup_array, test_ulong, teardown_array);
  g_test_add ("/pkcs11/array/boxed", TestArray, NULL,
              setup_array, test_boxed, teardown_array);

  return g_test_run();
}
