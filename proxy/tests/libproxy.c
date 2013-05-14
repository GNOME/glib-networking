/* GLibProxyResolver tests
 *
 * Copyright 2011-2013 Red Hat, Inc.
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
 * Public License along with this library; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <gio/gio.h>

#include "common.c"

static void
reset_proxy_settings (gpointer      fixture,
		      gconstpointer user_data)
{
  g_unsetenv ("http_proxy");
  g_unsetenv ("HTTP_PROXY");
  g_unsetenv ("https_proxy");
  g_unsetenv ("HTTPS_PROXY");
  g_unsetenv ("ftp_proxy");
  g_unsetenv ("FTP_PROXY");
  g_unsetenv ("no_proxy");
  g_unsetenv ("NO_PROXY");
}

static void
test_proxy_uri (gpointer      fixture,
		gconstpointer user_data)
{
  g_setenv ("http_proxy", "http://proxy.example.com:8080", TRUE);
  g_setenv ("https_proxy", "http://proxy-s.example.com:7070", TRUE);
  g_setenv ("ftp_proxy", "ftp://proxy-f.example.com:6060", TRUE);

  test_proxy_uri_common ();
}

static void
test_proxy_socks (gpointer      fixture,
		  gconstpointer user_data)
{
  g_setenv ("http_proxy", "socks://proxy.example.com:1234", TRUE);
  g_setenv ("no_proxy", "127.0.0.1", TRUE);

  test_proxy_socks_common ();
}

static void
test_proxy_ignore (gpointer      fixture,
		   gconstpointer user_data)
{
  gchar *no_proxy = g_strjoinv (",", (gchar **) ignore_hosts);

  g_setenv ("http_proxy", "http://localhost:8080", TRUE);
  g_setenv ("no_proxy", no_proxy, TRUE);
  g_free (no_proxy);

  test_proxy_ignore_common (TRUE);
}

int
main (int   argc,
      char *argv[])
{
  g_test_init (&argc, &argv, NULL);

  /* Unset variables that would make libproxy try to use gconf or ksettings */
  g_unsetenv ("GNOME_DESKTOP_SESSION_ID");
  g_unsetenv ("DESKTOP_SESSION");
  g_unsetenv ("KDE_FULL_SESSION");

  /* Use the just-built libproxy module */
  g_setenv ("GIO_EXTRA_MODULES", TOP_BUILDDIR "/proxy/libproxy/.libs", TRUE);

  g_test_add_vtable ("/proxy/libproxy/uri", 0, NULL,
		     reset_proxy_settings, test_proxy_uri, NULL);
  g_test_add_vtable ("/proxy/libproxy/socks", 0, NULL,
		     reset_proxy_settings, test_proxy_socks, NULL);
  g_test_add_vtable ("/proxy/libproxy/ignore", 0, NULL,
		     reset_proxy_settings, test_proxy_ignore, NULL);

  return g_test_run();
}
