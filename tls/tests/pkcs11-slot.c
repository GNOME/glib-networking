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

#include "pkcs11/gpkcs11slot.h"
#include "pkcs11/gpkcs11util.h"

#include "mock-pkcs11.h"
#include "mock-interaction.h"

#include <p11-kit/p11-kit.h>

#include <stdlib.h>

typedef struct {
  CK_FUNCTION_LIST funcs;
  GPkcs11Slot *slot;
  GPkcs11Slot *not_present;
} TestSlot;

static void
setup_slot (TestSlot        *test,
            gconstpointer    unused)
{
  CK_RV rv;

  /* Copy this so we can replace certain functions in our tests */
  memcpy (&test->funcs, &mock_default_functions, sizeof (test->funcs));

  rv = p11_kit_initialize_module (&test->funcs);
  g_assert (rv == CKR_OK);

  test->slot = g_object_new (G_TYPE_PKCS11_SLOT,
                             "slot-id", MOCK_SLOT_ONE_ID,
                             "module", &test->funcs,
                             NULL);
  g_assert (G_IS_PKCS11_SLOT (test->slot));

  test->not_present = g_object_new (G_TYPE_PKCS11_SLOT,
                                    "slot-id", MOCK_SLOT_TWO_ID,
                                    "module", &test->funcs,
                                    NULL);
  g_assert (G_IS_PKCS11_SLOT (test->not_present));
}

static void
teardown_slot (TestSlot     *test,
               gconstpointer unused)
{
  CK_RV rv;

  g_assert_cmpint (G_OBJECT (test->slot)->ref_count, ==, 1);
  g_object_unref (test->slot);

  g_assert_cmpint (G_OBJECT (test->not_present)->ref_count, ==, 1);
  g_object_unref (test->not_present);

  rv = p11_kit_finalize_module (&test->funcs);
  g_assert (rv == CKR_OK);
}

static void
test_properties (TestSlot       *test,
                 gconstpointer   unused)
{
  CK_SLOT_ID id;
  CK_FUNCTION_LIST_PTR module;

  g_object_get (test->slot, "slot-id", &id, "module", &module, NULL);
  g_assert_cmpuint (id, ==, MOCK_SLOT_ONE_ID);
  g_assert (module == &test->funcs);
}

static void
test_token_info (TestSlot       *test,
                 gconstpointer   unused)
{
  CK_TOKEN_INFO token_info;
  char *label;

  if (!g_pkcs11_slot_get_token_info (test->slot, &token_info))
    g_assert_not_reached ();

  label = p11_kit_space_strdup (token_info.label, sizeof (token_info.label));
  g_assert_cmpstr (label, ==, "TEST LABEL");
  free (label);
}

static void
test_token_info_not_present (TestSlot       *test,
                             gconstpointer   unused)
{
  CK_TOKEN_INFO token_info;
  char *label;

  if (!g_pkcs11_slot_get_token_info (test->slot, &token_info))
    g_assert_not_reached ();

  label = p11_kit_space_strdup (token_info.label, sizeof (token_info.label));
  g_assert_cmpstr (label, ==, "TEST LABEL");
  free (label);
}

static void
test_matches_uri (TestSlot       *test,
                  gconstpointer   unused)
{
  P11KitUri *uri;

  uri = p11_kit_uri_new ();
  if (p11_kit_uri_parse (MOCK_SLOT_ONE_URI, P11_KIT_URI_FOR_TOKEN, uri) != 0)
    g_assert_not_reached ();
  g_assert (!p11_kit_uri_any_unrecognized (uri));

  if (!g_pkcs11_slot_matches_uri (test->slot, uri))
    g_assert_not_reached();

  if (g_pkcs11_slot_matches_uri (test->not_present, uri))
    g_assert_not_reached ();

  p11_kit_uri_free (uri);
}


static gboolean
accumulate_check_not_called (gpointer result,
                             gpointer user_data)
{
  g_assert_not_reached ();
  return FALSE;
}

static void
test_enumerate_no_match (TestSlot     *test,
                         gconstpointer unused)
{
  GPkcs11EnumerateState state;
  CK_ATTRIBUTE_TYPE types[] = { CKA_LABEL, CKA_ID };
  GError *error = NULL;
  GPkcs11Array *match;

  match = g_pkcs11_array_new ();
  g_pkcs11_array_add_value (match, CKA_LABEL, "Non existant", -1);
  g_pkcs11_array_add_value (match, CKA_ID, "Bad ID", -1);

  state = g_pkcs11_slot_enumerate (test->slot, NULL,
                                   match->attrs, match->count, FALSE,
                                   types, G_N_ELEMENTS (types),
                                   accumulate_check_not_called, NULL,
                                   NULL, &error);

  g_assert_cmpuint (state, ==, G_PKCS11_ENUMERATE_CONTINUE);
  g_assert_no_error (error);

  g_pkcs11_array_unref (match);
}

static void
test_enumerate_not_present (TestSlot      *test,
                            gconstpointer  unused)
{
  GPkcs11EnumerateState state;
  CK_ATTRIBUTE_TYPE types[] = { CKA_LABEL, CKA_ID };
  GError *error = NULL;
  GPkcs11Array *match;

  /* Empty match should match anything ... */
  match = g_pkcs11_array_new ();

  /* ... but token is not present, so nothing */
  state = g_pkcs11_slot_enumerate (test->not_present, NULL,
                                   match->attrs, match->count, FALSE,
                                   types, G_N_ELEMENTS (types),
                                   accumulate_check_not_called, NULL,
                                   NULL, &error);

  g_assert_cmpuint (state, ==, G_PKCS11_ENUMERATE_CONTINUE);
  g_assert_no_error (error);

  g_pkcs11_array_unref (match);
}

static gboolean
accumulate_results (gpointer result,
                    gpointer user_data)
{
  GPtrArray *results = user_data;
  GPkcs11Array *attrs = result;

  g_assert (results);
  g_assert (attrs);

  g_ptr_array_add (results, g_pkcs11_array_ref (attrs));
  return TRUE;
}

static void
test_enumerate_all (TestSlot     *test,
                    gconstpointer unused)
{
  GPkcs11EnumerateState state;
  CK_ATTRIBUTE_TYPE types[] = { CKA_LABEL, CKA_ID };
  GError *error = NULL;
  GPkcs11Array *match;
  GPkcs11Array *attrs;
  GPtrArray *results;
  const CK_ATTRIBUTE *attr;
  guint i;

  /* Match anything */
  match = g_pkcs11_array_new ();

  results = g_ptr_array_new_with_free_func ((GDestroyNotify)g_pkcs11_array_unref);

  state = g_pkcs11_slot_enumerate (test->slot, NULL,
                                   match->attrs, match->count, FALSE,
                                   types, G_N_ELEMENTS (types),
                                   accumulate_results, results,
                                   NULL, &error);

  g_pkcs11_array_unref (match);

  g_assert_cmpuint (state, ==, G_PKCS11_ENUMERATE_CONTINUE);
  g_assert_no_error (error);

  g_assert_cmpuint (results->len, >, 1);

  for (i = 0; i < results->len; i++)
    {
      attrs = results->pdata[i];
      attr = g_pkcs11_array_find (attrs, CKA_LABEL);
      g_assert (attr != NULL);
      g_assert (g_utf8_validate (attr->pValue, attr->ulValueLen, NULL));
    }

  g_ptr_array_free (results, TRUE);
}

static gboolean
accumulate_first (gpointer result,
                  gpointer user_data)
{
  GPtrArray *results = user_data;
  GPkcs11Array *attrs = result;

  g_assert (results);
  g_assert (attrs);
  g_assert_cmpuint (results->len, ==, 0);

  g_ptr_array_add (results, g_pkcs11_array_ref (attrs));
  return FALSE; /* Don't call again */
}

static void
test_enumerate_first (TestSlot     *test,
                      gconstpointer unused)
{
  GPkcs11EnumerateState state;
  CK_ATTRIBUTE_TYPE types[] = { CKA_LABEL, CKA_ID };
  GError *error = NULL;
  GPkcs11Array *match;
  GPkcs11Array *attrs;
  GPtrArray *results;
  const CK_ATTRIBUTE *attr;

  /* Match anything */
  match = g_pkcs11_array_new ();

  results = g_ptr_array_new_with_free_func ((GDestroyNotify)g_pkcs11_array_unref);

  state = g_pkcs11_slot_enumerate (test->slot, NULL,
                                   match->attrs, match->count, FALSE,
                                   types, G_N_ELEMENTS (types),
                                   accumulate_first, results,
                                   NULL, &error);

  g_pkcs11_array_unref (match);

  g_assert_cmpuint (state, ==, G_PKCS11_ENUMERATE_STOP);
  g_assert_no_error (error);

  g_assert_cmpuint (results->len, ==, 1);
  attrs = results->pdata[0];
  attr = g_pkcs11_array_find (attrs, CKA_LABEL);
  g_assert (attr != NULL);
  g_assert (g_utf8_validate (attr->pValue, attr->ulValueLen, NULL));

  g_ptr_array_free (results, TRUE);
}

static gboolean
accumulate_check_null_result (gpointer result,
                              gpointer user_data)
{
  GPkcs11Array *attrs = result;
  g_assert (attrs == NULL);
  return TRUE; /* call again */
}

static void
test_enumerate_no_attrs (TestSlot     *test,
                         gconstpointer unused)
{
  GPkcs11EnumerateState state;
  GError *error = NULL;
  GPkcs11Array *match;

  /* Match anything */
  match = g_pkcs11_array_new ();

  state = g_pkcs11_slot_enumerate (test->slot, NULL,
                                   match->attrs, match->count, FALSE,
                                   NULL, 0,
                                   accumulate_check_null_result, NULL,
                                   NULL, &error);

  g_pkcs11_array_unref (match);

  /* Didn't find anything, so continue */
  g_assert_cmpuint (state, ==, G_PKCS11_ENUMERATE_CONTINUE);
  g_assert_no_error (error);
}

static void
test_enumerate_fail_session (TestSlot     *test,
                             gconstpointer unused)
{
  GPkcs11EnumerateState state;
  GError *error = NULL;

  /* Make opening a session fail */
  test->funcs.C_OpenSession = mock_fail_C_OpenSession;

  state = g_pkcs11_slot_enumerate (test->slot, NULL,
                                   NULL, 0, FALSE,
                                   NULL, 0,
                                   accumulate_check_not_called, NULL,
                                   NULL, &error);

  g_assert_cmpuint (state, ==, G_PKCS11_ENUMERATE_FAILED);
  g_assert_error (error, G_PKCS11_ERROR, CKR_GENERAL_ERROR);
  g_error_free (error);
}

static void
test_enumerate_fail_attributes (TestSlot     *test,
                                gconstpointer unused)
{
  GPkcs11EnumerateState state;
  GError *error = NULL;
  CK_ATTRIBUTE_TYPE types[] = { CKA_LABEL, CKA_ID };

  /* Make retrieving object attrs fail */
  test->funcs.C_GetAttributeValue = mock_fail_C_GetAttributeValue;

  state = g_pkcs11_slot_enumerate (test->slot, NULL,
                                   NULL, 0, FALSE,
                                   types, G_N_ELEMENTS (types),
                                   accumulate_check_not_called, NULL,
                                   NULL, &error);

  g_assert_cmpuint (state, ==, G_PKCS11_ENUMERATE_FAILED);
  g_assert_error (error, G_PKCS11_ERROR, CKR_FUNCTION_FAILED);
  g_error_free (error);
}

static gboolean
accumulate_cancel_on_first (gpointer result,
                            gpointer user_data)
{
  GCancellable *cancellable = G_CANCELLABLE (user_data);
  g_assert (!g_cancellable_is_cancelled (cancellable));
  g_cancellable_cancel (cancellable);
  return TRUE; /* call again, except that above cancellation should stop */
}

static void
test_enumerate_cancel (TestSlot     *test,
                       gconstpointer unused)
{
  GPkcs11EnumerateState state;
  GError *error = NULL;
  GPkcs11Array *match;
  GCancellable *cancellable;

  cancellable = g_cancellable_new ();

  /* Match anything */
  match = g_pkcs11_array_new ();

  state = g_pkcs11_slot_enumerate (test->slot, NULL,
                                   match->attrs, match->count, FALSE,
                                   NULL, 0,
                                   accumulate_cancel_on_first, cancellable,
                                   cancellable, &error);

  g_pkcs11_array_unref (match);
  g_object_unref (cancellable);

  g_assert_cmpuint (state, ==, G_PKCS11_ENUMERATE_FAILED);
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
  g_error_free (error);
}

static void
test_enumerate_private (TestSlot     *test,
                        gconstpointer unused)
{
  CK_ATTRIBUTE_TYPE types[] = { CKA_LABEL, CKA_ID, CKA_PRIVATE };
  GPkcs11EnumerateState state;
  GError *error = NULL;
  GPkcs11Array *match;
  GPtrArray *results;
  gboolean bval;
  GTlsInteraction *interaction;

  /* Match label of private object, see mock*/
  match = g_pkcs11_array_new ();
  g_pkcs11_array_add_value (match, CKA_LABEL, "PRIVATE", -1);

  /* Shouldn't match anything, since not logged in */
  state = g_pkcs11_slot_enumerate (test->slot, NULL,
                                   match->attrs, match->count, FALSE,
                                   types, G_N_ELEMENTS (types),
                                   accumulate_check_not_called, NULL,
                                   NULL, &error);

  g_assert_cmpuint (state, ==, G_PKCS11_ENUMERATE_CONTINUE);
  g_assert_no_error (error);

  /* This time we try to log in but no interaction is set */
  state = g_pkcs11_slot_enumerate (test->slot, NULL,
                                   match->attrs, match->count, TRUE, /* match privates */
                                   types, G_N_ELEMENTS (types),
                                   accumulate_check_not_called, NULL,
                                   NULL, &error);

  g_assert_cmpuint (state, ==, G_PKCS11_ENUMERATE_CONTINUE);
  g_assert_no_error (error);

  /* This time we log in, and should have a match */
  results = g_ptr_array_new_with_free_func ((GDestroyNotify)g_pkcs11_array_unref);
  interaction = mock_interaction_new_static (MOCK_SLOT_ONE_PIN);

  state = g_pkcs11_slot_enumerate (test->slot, interaction,
                                   match->attrs, match->count, TRUE,
                                   types, G_N_ELEMENTS (types),
                                   accumulate_results, results,
                                   NULL, &error);

  g_assert_cmpuint (state, ==, G_PKCS11_ENUMERATE_CONTINUE);
  g_assert_no_error (error);

  /* One private object, with following info */
  g_assert_cmpuint (results->len, ==, 1);
  if (!g_pkcs11_array_find_boolean (results->pdata[0], CKA_PRIVATE, &bval))
    g_assert_not_reached ();
  g_assert (bval == TRUE);

  g_object_unref (interaction);
  g_pkcs11_array_unref (match);
  g_ptr_array_free (results, TRUE);
}

int
main (int   argc,
      char *argv[])
{
  g_test_init (&argc, &argv, NULL);

  g_test_add ("/pkcs11/slot/properties", TestSlot, NULL,
              setup_slot, test_properties, teardown_slot);
  g_test_add ("/pkcs11/slot/token-info", TestSlot, NULL,
              setup_slot, test_token_info, teardown_slot);
  g_test_add ("/pkcs11/slot/token-not-present", TestSlot, NULL,
              setup_slot, test_token_info_not_present, teardown_slot);
  g_test_add ("/pkcs11/slot/matches-uri", TestSlot, NULL,
              setup_slot, test_matches_uri, teardown_slot);
  g_test_add ("/pkcs11/slot/enumerate-no-match", TestSlot, NULL,
              setup_slot, test_enumerate_no_match, teardown_slot);
  g_test_add ("/pkcs11/slot/enumerate-not-present", TestSlot, NULL,
              setup_slot, test_enumerate_not_present, teardown_slot);
  g_test_add ("/pkcs11/slot/enumerate-all", TestSlot, NULL,
              setup_slot, test_enumerate_all, teardown_slot);
  g_test_add ("/pkcs11/slot/enumerate-first", TestSlot, NULL,
              setup_slot, test_enumerate_first, teardown_slot);
  g_test_add ("/pkcs11/slot/enumerate-no-attrs", TestSlot, NULL,
              setup_slot, test_enumerate_no_attrs, teardown_slot);
  g_test_add ("/pkcs11/slot/enumerate-fail-session", TestSlot, NULL,
              setup_slot, test_enumerate_fail_session, teardown_slot);
  g_test_add ("/pkcs11/slot/enumerate-fail-attributes", TestSlot, NULL,
              setup_slot, test_enumerate_fail_attributes, teardown_slot);
  g_test_add ("/pkcs11/slot/enumerate-cancel", TestSlot, NULL,
              setup_slot, test_enumerate_cancel, teardown_slot);
  g_test_add ("/pkcs11/slot/enumerate-private", TestSlot, NULL,
              setup_slot, test_enumerate_private, teardown_slot);

  return g_test_run();
}
