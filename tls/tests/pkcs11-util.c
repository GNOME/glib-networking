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

#include "pkcs11/gpkcs11util.h"

static void
test_propagate_error (void)
{
  GError *error = NULL;

  if (!g_pkcs11_propagate_error (&error, CKR_BUFFER_TOO_SMALL))
    g_assert_not_reached ();
  g_assert_error (error, G_PKCS11_ERROR, (gint)CKR_BUFFER_TOO_SMALL);
  g_clear_error (&error);

  if (g_pkcs11_propagate_error (&error, CKR_OK))
    g_assert_not_reached ();
  g_assert_no_error (error);

  if (!g_pkcs11_propagate_error (&error, CKR_CANCEL))
    g_assert_not_reached ();
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
  g_clear_error (&error);
}

int
main (int   argc,
      char *argv[])
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/pkcs11/util/propagate-error", test_propagate_error);

  return g_test_run();
}
