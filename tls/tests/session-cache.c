/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO TLS tests
 *
 * Copyright 2026 Red Hat, Inc.
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
 * Author: Nieves Montero <nmontero@redhat.com>
 */

#include <gio/gio.h>

#include "gtlssessioncache.h"

#define TEST_SESSION_ID "test-session"
#define TEST_TICKET_COUNT 40
#define TEST_EXPECTED_TICKETS 32

static gpointer
session_dup (gpointer session_data)
{
  return g_bytes_ref (session_data);
}

static gint
session_acquire (gpointer session_data)
{
  g_bytes_ref (session_data);
  return TRUE;
}

static void
session_release (gpointer session_data)
{
  g_bytes_unref (session_data);
}

static GBytes *
create_ticket (guint value)
{
  return g_bytes_new (&value, sizeof (value));
}

static guint
get_ticket_value (GBytes *ticket)
{
  gsize size;
  const guint *value;

  value = g_bytes_get_data (ticket, &size);

  g_assert_cmpuint (size, ==, sizeof (*value));

  return *value;
}

static void
test_tls13_session_ticket_limit (void)
{
  guint i;

  for (i = 0; i < TEST_TICKET_COUNT; i++)
    {
      GBytes *ticket;

      ticket = create_ticket (i);

      g_tls_store_session_data (TEST_SESSION_ID,
                                ticket,
                                session_dup,
                                session_acquire,
                                session_release,
                                G_TLS_PROTOCOL_VERSION_TLS_1_3);

      g_bytes_unref (ticket);
    }

  for (i = TEST_TICKET_COUNT - TEST_EXPECTED_TICKETS;
       i < TEST_TICKET_COUNT;
       i++)
    {
      GBytes *ticket;

      ticket = g_tls_lookup_session_data (TEST_SESSION_ID);

      g_assert_nonnull (ticket);
      g_assert_cmpuint (get_ticket_value (ticket), ==, i);

      g_bytes_unref (ticket);
    }

  g_assert_null (g_tls_lookup_session_data (TEST_SESSION_ID));
}

int
main (int   argc,
      char *argv[])
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/tls/session-cache/tls13-ticket-limit",
                   test_tls13_session_ticket_limit);

  return g_test_run ();
}
