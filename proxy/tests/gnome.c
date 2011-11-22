/* GProxyResolverGnome tests
 *
 * Copyright 2011 Red Hat, Inc.
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
#include <gdesktop-enums.h>

#define GNOME_PROXY_SETTINGS_SCHEMA       "org.gnome.system.proxy"
#define GNOME_PROXY_MODE_KEY              "mode"
#define GNOME_PROXY_AUTOCONFIG_URL_KEY    "autoconfig-url"
#define GNOME_PROXY_IGNORE_HOSTS_KEY      "ignore-hosts"
#define GNOME_PROXY_USE_SAME_PROXY_KEY    "use-same-proxy"

#define GNOME_PROXY_HTTP_CHILD_SCHEMA     "http"
#define GNOME_PROXY_HTTP_HOST_KEY         "host"
#define GNOME_PROXY_HTTP_PORT_KEY         "port"
#define GNOME_PROXY_HTTP_USE_AUTH_KEY     "use-authentication"
#define GNOME_PROXY_HTTP_USER_KEY         "authentication-user"
#define GNOME_PROXY_HTTP_PASSWORD_KEY     "authentication-password"

#define GNOME_PROXY_HTTPS_CHILD_SCHEMA    "https"
#define GNOME_PROXY_HTTPS_HOST_KEY        "host"
#define GNOME_PROXY_HTTPS_PORT_KEY        "port"

#define GNOME_PROXY_FTP_CHILD_SCHEMA      "ftp"
#define GNOME_PROXY_FTP_HOST_KEY          "host"
#define GNOME_PROXY_FTP_PORT_KEY          "port"

#define GNOME_PROXY_SOCKS_CHILD_SCHEMA    "socks"
#define GNOME_PROXY_SOCKS_HOST_KEY        "host"
#define GNOME_PROXY_SOCKS_PORT_KEY        "port"

static const char *ignore_hosts[] = {
  ".bbb.xx",
  "*.ccc.xx",
  "ddd.xx",
  "*.eee.xx:8000",
  "127.0.0.0/24",
  "10.0.0.1:8000",
  "::1",
  "fe80::/10"
};
static const int n_ignore_hosts = G_N_ELEMENTS (ignore_hosts);

static const struct {
  const char *uri;
  const char *proxy;
} ignore_tests[] = {
  { "http://aaa.xx/",          	 "http://localhost:8080" },
  { "http://aaa.xx:8000/",     	 "http://localhost:8080" },
  { "http://www.aaa.xx/",      	 "http://localhost:8080" },
  { "http://www.aaa.xx:8000/", 	 "http://localhost:8080" },
  { "https://aaa.xx/",         	 "http://localhost:8080" },
  { "http://bbb.xx/",          	 "direct://" },
  { "http://www.bbb.xx/",      	 "direct://" },
  { "http://bbb.xx:8000/",     	 "direct://" },
  { "http://www.bbb.xx:8000/", 	 "direct://" },
  { "https://bbb.xx/",         	 "direct://" },
  { "http://nobbb.xx/",          "http://localhost:8080" },
  { "http://www.nobbb.xx/",      "http://localhost:8080" },
  { "http://nobbb.xx:8000/",     "http://localhost:8080" },
  { "http://www.nobbb.xx:8000/", "http://localhost:8080" },
  { "https://nobbb.xx/",         "http://localhost:8080" },
  { "http://ccc.xx/",          	 "direct://" },
  { "http://www.ccc.xx/",      	 "direct://" },
  { "http://ccc.xx:8000/",     	 "direct://" },
  { "http://www.ccc.xx:8000/", 	 "direct://" },
  { "https://ccc.xx/",         	 "direct://" },
  { "http://ddd.xx/",          	 "direct://" },
  { "http://ddd.xx:8000/",     	 "direct://" },
  { "http://www.ddd.xx/",      	 "direct://" },
  { "http://www.ddd.xx:8000/", 	 "direct://" },
  { "https://ddd.xx/",         	 "direct://" },
  { "http://eee.xx/",          	 "http://localhost:8080" },
  { "http://eee.xx:8000/",     	 "direct://" },
  { "http://www.eee.xx/",      	 "http://localhost:8080" },
  { "http://www.eee.xx:8000/", 	 "direct://" },
  { "https://eee.xx/",         	 "http://localhost:8080" },
  { "http://1.2.3.4/",         	 "http://localhost:8080" },
  { "http://127.0.0.1/",       	 "direct://" },
  { "http://127.0.0.2/",       	 "direct://" },
  { "http://127.0.0.255/",     	 "direct://" },
  { "http://127.0.1.0/",       	 "http://localhost:8080" },
  { "http://10.0.0.1/",        	 "http://localhost:8080" },
  { "http://10.0.0.1:8000/",   	 "direct://" },
  { "http://[::1]/",           	 "direct://" },
  { "http://[::1]:80/",        	 "direct://" },
  { "http://[::1:1]/",         	 "http://localhost:8080" },
  { "http://[::1:1]:80/",      	 "http://localhost:8080" },
  { "http://[fe80::1]/",       	 "direct://" },
  { "http://[fe80::1]:80/",    	 "direct://" },
  { "http://[fec0::1]/",       	 "http://localhost:8080" },
  { "http://[fec0::1]:80/",    	 "http://localhost:8080" }
};
static const int n_ignore_tests = G_N_ELEMENTS (ignore_tests);

static void
test_proxy_ignore (void)
{
  GSettings *settings, *http;
  GProxyResolver *resolver;
  GError *error = NULL;
  char **proxies;
  int i;

  settings = g_settings_new (GNOME_PROXY_SETTINGS_SCHEMA);
  g_settings_set_enum (settings, GNOME_PROXY_MODE_KEY, G_DESKTOP_PROXY_MODE_MANUAL);
  g_settings_set (settings, GNOME_PROXY_IGNORE_HOSTS_KEY,
		  "@as", g_variant_new_strv (ignore_hosts, n_ignore_hosts));

  http = g_settings_get_child (settings, GNOME_PROXY_HTTP_CHILD_SCHEMA);
  g_settings_set_string (http, GNOME_PROXY_HTTP_HOST_KEY, "localhost");
  g_settings_set_int (http, GNOME_PROXY_HTTP_PORT_KEY, 8080);

  resolver = g_proxy_resolver_get_default ();

  for (i = 0; i < n_ignore_tests; i++)
    {
      proxies = g_proxy_resolver_lookup (resolver, ignore_tests[i].uri,
					 NULL, &error);
      g_assert_no_error (error);

      g_assert_cmpstr (proxies[0], ==, ignore_tests[i].proxy);
      g_strfreev (proxies);
    }
}

int
main (int   argc,
      char *argv[])
{
  g_type_init ();
  g_test_init (&argc, &argv, NULL);

  g_setenv ("GIO_EXTRA_MODULES", TOP_BUILDDIR "/proxy/gnome/.libs", TRUE);
  g_setenv ("GIO_USE_PROXY_RESOLVER", "gnome", TRUE);
  g_setenv ("GSETTINGS_BACKEND", "memory", TRUE);

  g_test_add_func ("/proxy/gnome/ignore", test_proxy_ignore);

  return g_test_run();
}
