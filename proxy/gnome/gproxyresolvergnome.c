/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2010 Red Hat, Inc.
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

#include "config.h"

#include <stdlib.h>

#include "gproxyresolvergnome.h"

#include <glib/gi18n-lib.h>
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

typedef struct {
  gchar        *name;
  gint          length;
  gushort       port;
} GProxyResolverGnomeDomain;

struct _GProxyResolverGnome {
  GObject parent_instance;

  GSettings *proxy_settings;
  GSettings *http_settings;
  GSettings *https_settings;
  GSettings *ftp_settings;
  GSettings *socks_settings;
  gboolean need_update;

  GDesktopProxyMode mode;
  gchar *autoconfig_url;
  gboolean use_same_proxy;

  GPtrArray *ignore_ips;
  GProxyResolverGnomeDomain *ignore_domains;

  gchar *http_proxy, *https_proxy;
  gchar *ftp_proxy, *socks_authority;

  GDBusProxy *pacrunner;

  GMutex lock;
};

static void g_proxy_resolver_gnome_iface_init (GProxyResolverInterface *iface);

G_DEFINE_DYNAMIC_TYPE_EXTENDED (GProxyResolverGnome,
				g_proxy_resolver_gnome,
				G_TYPE_OBJECT, 0,
				G_IMPLEMENT_INTERFACE_DYNAMIC (G_TYPE_PROXY_RESOLVER,
							       g_proxy_resolver_gnome_iface_init))

static void
g_proxy_resolver_gnome_class_finalize (GProxyResolverGnomeClass *klass)
{
}

static void
free_settings (GProxyResolverGnome *resolver)
{
  int i;

  if (resolver->ignore_ips)
    g_ptr_array_free (resolver->ignore_ips, TRUE);
  if (resolver->ignore_domains)
    {
      for (i = 0; resolver->ignore_domains[i].name; i++)
	g_free (resolver->ignore_domains[i].name);
      g_free (resolver->ignore_domains);
    }

  g_free (resolver->http_proxy);
  g_free (resolver->https_proxy);
  g_free (resolver->ftp_proxy);
  g_free (resolver->socks_authority);
  g_free (resolver->autoconfig_url);
}

static void
gsettings_changed (GSettings   *settings,
		   const gchar *key,
		   gpointer     user_data)
{
  GProxyResolverGnome *resolver = user_data;

  g_mutex_lock (&resolver->lock);
  resolver->need_update = TRUE;
  g_mutex_unlock (&resolver->lock);
}

static void
g_proxy_resolver_gnome_finalize (GObject *object)
{
  GProxyResolverGnome *resolver = G_PROXY_RESOLVER_GNOME (object);

  if (resolver->proxy_settings)
    {
      g_signal_handlers_disconnect_by_func (resolver->proxy_settings,
					    (gpointer)gsettings_changed,
					    resolver);
      g_object_unref (resolver->proxy_settings);

      g_signal_handlers_disconnect_by_func (resolver->http_settings,
					    (gpointer)gsettings_changed,
					    resolver);
      g_object_unref (resolver->http_settings);

      g_signal_handlers_disconnect_by_func (resolver->https_settings,
					    (gpointer)gsettings_changed,
					    resolver);
      g_object_unref (resolver->https_settings);

      g_signal_handlers_disconnect_by_func (resolver->ftp_settings,
					    (gpointer)gsettings_changed,
					    resolver);
      g_object_unref (resolver->ftp_settings);

      g_signal_handlers_disconnect_by_func (resolver->socks_settings,
					    (gpointer)gsettings_changed,
					    resolver);
      g_object_unref (resolver->socks_settings);

      free_settings (resolver);
    }

  if (resolver->pacrunner)
    g_object_unref (resolver->pacrunner);

  g_mutex_clear (&resolver->lock);

  G_OBJECT_CLASS (g_proxy_resolver_gnome_parent_class)->finalize (object);
}

static void
g_proxy_resolver_gnome_init (GProxyResolverGnome *resolver)
{
  g_mutex_init (&resolver->lock);

  resolver->proxy_settings = g_settings_new (GNOME_PROXY_SETTINGS_SCHEMA);
  g_signal_connect (resolver->proxy_settings, "changed",
		    G_CALLBACK (gsettings_changed), resolver);
  resolver->http_settings = g_settings_get_child (resolver->proxy_settings,
                                                  GNOME_PROXY_HTTP_CHILD_SCHEMA);
  g_signal_connect (resolver->http_settings, "changed",
		    G_CALLBACK (gsettings_changed), resolver);
  resolver->https_settings = g_settings_get_child (resolver->proxy_settings,
                                                   GNOME_PROXY_HTTPS_CHILD_SCHEMA);
  g_signal_connect (resolver->https_settings, "changed",
		    G_CALLBACK (gsettings_changed), resolver);
  resolver->ftp_settings = g_settings_get_child (resolver->proxy_settings,
                                                 GNOME_PROXY_FTP_CHILD_SCHEMA);
  g_signal_connect (resolver->ftp_settings, "changed",
		    G_CALLBACK (gsettings_changed), resolver);
  resolver->socks_settings = g_settings_get_child (resolver->proxy_settings,
                                                   GNOME_PROXY_SOCKS_CHILD_SCHEMA);
  g_signal_connect (resolver->socks_settings, "changed",
		    G_CALLBACK (gsettings_changed), resolver);

  resolver->need_update = TRUE;
}

/* called with lock held */
static void
update_settings (GProxyResolverGnome *resolver)
{
  gchar **ignore_hosts;
  gchar *host;
  guint port;
  int i;

  resolver->need_update = FALSE;

  free_settings (resolver);

  resolver->mode =
    g_settings_get_enum (resolver->proxy_settings, GNOME_PROXY_MODE_KEY);
  resolver->autoconfig_url =
    g_settings_get_string (resolver->proxy_settings, GNOME_PROXY_AUTOCONFIG_URL_KEY);
  resolver->use_same_proxy =
    g_settings_get_boolean (resolver->proxy_settings, GNOME_PROXY_USE_SAME_PROXY_KEY);

  ignore_hosts =
    g_settings_get_strv (resolver->proxy_settings, GNOME_PROXY_IGNORE_HOSTS_KEY);
  if (ignore_hosts && ignore_hosts[0])
    {
      GPtrArray *ignore_ips;
      GArray *ignore_domains;
      gchar *host, *tmp, *colon, *bracket;
      GInetAddress *iaddr;
      GInetAddressMask *mask;
      GProxyResolverGnomeDomain domain;
      gushort port;

      ignore_ips = g_ptr_array_new_with_free_func (g_object_unref);
      ignore_domains = g_array_new (TRUE, FALSE, sizeof (GProxyResolverGnomeDomain));

      for (i = 0; ignore_hosts[i]; i++)
	{
	  host = g_strchomp (ignore_hosts[i]);

	  /* See if it's an IP address or IP/length mask */
	  mask = g_inet_address_mask_new_from_string (host, NULL);
	  if (mask)
	    {
	      g_ptr_array_add (ignore_ips, mask);
	      continue;
	    }

	  port = 0;

	  if (*host == '[')
	    {
	      /* [IPv6]:port */
	      host++;
	      bracket = strchr (host, ']');
	      if (!bracket || !bracket[1] || bracket[1] != ':')
		goto bad;

	      port = strtoul (bracket + 2, &tmp, 10);
	      if (*tmp)
		goto bad;

	      *bracket = '\0';
	    }
	  else
	    {
	      colon = strchr (host, ':');
	      if (colon && !strchr (colon + 1, ':'))
		{
		  /* hostname:port or IPv4:port */
		  port = strtoul (colon + 1, &tmp, 10);
		  if (*tmp)
		    goto bad;
		  *colon = '\0';
		}
	    }

	  iaddr = g_inet_address_new_from_string (host);
	  if (iaddr)
	    g_object_unref (iaddr);
	  else
	    {
	      if (g_str_has_prefix (host, "*."))
		host += 2;
	      else if (*host == '.')
		host++;
	    }

	  memset (&domain, 0, sizeof (domain));
	  domain.name = g_strdup (host);
	  domain.length = strlen (domain.name);
	  domain.port = port;
	  g_array_append_val (ignore_domains, domain);
	  continue;

	bad:
	  g_warning ("Ignoring invalid ignore_hosts value '%s'", host);
	}

      if (ignore_ips->len)
	resolver->ignore_ips = ignore_ips;
      else
	{
	  g_ptr_array_free (ignore_ips, TRUE);
	  resolver->ignore_ips = NULL;
	}

      resolver->ignore_domains = (GProxyResolverGnomeDomain *)
	g_array_free (ignore_domains, ignore_domains->len == 0);
    }
  else
    {
      resolver->ignore_ips = NULL;
      resolver->ignore_domains = NULL;
    }
  g_strfreev (ignore_hosts);

  host = g_settings_get_string (resolver->http_settings, GNOME_PROXY_HTTP_HOST_KEY);
  port = g_settings_get_int (resolver->http_settings, GNOME_PROXY_HTTP_PORT_KEY);

  if (host && *host)
    {
      if (g_settings_get_boolean (resolver->http_settings, GNOME_PROXY_HTTP_USE_AUTH_KEY))
	{
	  gchar *user, *password;
	  gchar *enc_user, *enc_password;

	  user = g_settings_get_string (resolver->http_settings, GNOME_PROXY_HTTP_USER_KEY);
	  enc_user = g_uri_escape_string (user, NULL, TRUE);
	  g_free (user);
	  password = g_settings_get_string (resolver->http_settings, GNOME_PROXY_HTTP_PASSWORD_KEY);
	  enc_password = g_uri_escape_string (password, NULL, TRUE);
	  g_free (password);

	  resolver->http_proxy = g_strdup_printf ("http://%s:%s@%s:%u",
						  enc_user, enc_password,
						  host, port);
	  g_free (enc_user);
	  g_free (enc_password);
	}
      else
	resolver->http_proxy = g_strdup_printf ("http://%s:%u", host, port);
    }
  g_free (host);

  host = g_settings_get_string (resolver->https_settings, GNOME_PROXY_HTTPS_HOST_KEY);
  port = g_settings_get_int (resolver->https_settings, GNOME_PROXY_HTTPS_PORT_KEY);
  if (host && *host)
    resolver->https_proxy = g_strdup_printf ("http://%s:%u", host, port);
  g_free (host);

  host = g_settings_get_string (resolver->ftp_settings, GNOME_PROXY_FTP_HOST_KEY);
  port = g_settings_get_int (resolver->ftp_settings, GNOME_PROXY_FTP_PORT_KEY);
  if (host && *host)
    resolver->ftp_proxy = g_strdup_printf ("ftp://%s:%u", host, port);
  g_free (host);

  host = g_settings_get_string (resolver->socks_settings, GNOME_PROXY_SOCKS_HOST_KEY);
  port = g_settings_get_int (resolver->socks_settings, GNOME_PROXY_SOCKS_PORT_KEY);
  if (host && *host)
    resolver->socks_authority = g_strdup_printf ("%s:%u", host, port);
  g_free (host);

  if (resolver->mode == G_DESKTOP_PROXY_MODE_AUTO && !resolver->pacrunner)
    {
      GError *error = NULL;
      resolver->pacrunner =
	g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SESSION,
				       G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
				       G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
				       NULL,
				       "org.gtk.GLib.PACRunner",
				       "/org/gtk/GLib/PACRunner",
				       "org.gtk.GLib.PACRunner",
				       NULL, &error);
      if (error)
	{
	  g_warning ("Could not start proxy autoconfiguration helper:"
		     "\n    %s\nProxy autoconfiguration will not work",
		     error->message);
	}
    }
  else if (resolver->mode != G_DESKTOP_PROXY_MODE_AUTO && resolver->pacrunner)
    {
      g_object_unref (resolver->pacrunner);
      resolver->pacrunner = NULL;
    }
}

static gboolean
g_proxy_resolver_gnome_is_supported (GProxyResolver *object)
{
  return !g_strcmp0 (g_getenv ("DESKTOP_SESSION"), "gnome");
}

static gboolean
ignore_host (GProxyResolverGnome *resolver,
	     const gchar         *host,
	     gushort              port)
{
  gchar *ascii_host = NULL;
  gboolean ignore = FALSE;
  gint i, length, offset;

  if (resolver->ignore_ips)
    {
      GInetAddress *iaddr;

      iaddr = g_inet_address_new_from_string (host);
      if (iaddr)
	{
	  for (i = 0; i < resolver->ignore_ips->len; i++)
	    {
	      GInetAddressMask *mask = resolver->ignore_ips->pdata[i];

	      if (g_inet_address_mask_matches (mask, iaddr))
		{
		  ignore = TRUE;
		  break;
		}
	    }

	  g_object_unref (iaddr);
	  if (ignore)
	    return TRUE;
	}
    }

  if (g_hostname_is_non_ascii (host))
    host = ascii_host = g_hostname_to_ascii (host);
  length = strlen (host);

  if (resolver->ignore_domains)
    {
      for (i = 0; resolver->ignore_domains[i].length; i++)
	{
	  GProxyResolverGnomeDomain *domain = &resolver->ignore_domains[i];

	  offset = length - domain->length;
	  if ((domain->port == 0 || domain->port == port) &&
	      (offset == 0 || (offset > 0 && host[offset - 1] == '.')) &&
	      (g_ascii_strcasecmp (domain->name, host + offset) == 0))
	    {
	      ignore = TRUE;
	      break;
	    }
	}
    }

  g_free (ascii_host);
  return ignore;
}

static inline gchar **
make_proxies (const gchar *proxy)
{
  gchar **proxies;

  proxies = g_new (gchar *, 2);
  proxies[0] = g_strdup (proxy);
  proxies[1] = NULL;

  return proxies;
}

/* Threadsafely determines what to do with @uri; returns %FALSE if an
 * error occurs, %TRUE and an array of proxies if the mode is NONE or
 * MANUAL, or if @uri is covered by ignore-hosts, or %TRUE and a
 * (transfer-full) pacrunner and autoconfig url if the mode is AUTOMATIC.
 */
static gboolean
g_proxy_resolver_gnome_lookup_internal (GProxyResolverGnome   *resolver,
					const gchar           *uri,
					gchar               ***out_proxies,
					GDBusProxy           **out_pacrunner,
					gchar                **out_autoconfig_url,
					GCancellable          *cancellable,
					GError               **error)
{
  GSocketConnectable *addr = NULL;
  const gchar *scheme = NULL, *host = NULL;
  gushort port;

  *out_proxies = NULL;
  *out_pacrunner = NULL;
  *out_autoconfig_url = NULL;

  g_mutex_lock (&resolver->lock);
  if (resolver->need_update)
    update_settings (resolver);

  if (resolver->mode == G_DESKTOP_PROXY_MODE_NONE)
    {
      *out_proxies = make_proxies ("direct://");
      goto done;
    }

  /* FIXME: use guri when it lands... */
  addr = g_network_address_parse_uri (uri, 0, error);
  if (!addr)
    goto done;
  scheme = g_network_address_get_scheme (G_NETWORK_ADDRESS (addr));
  host = g_network_address_get_hostname (G_NETWORK_ADDRESS (addr));
  port = g_network_address_get_port (G_NETWORK_ADDRESS (addr));

  if (ignore_host (resolver, host, port))
    {
      *out_proxies = make_proxies ("direct://");
      goto done;
    }

  if (resolver->pacrunner)
    {
      *out_pacrunner = g_object_ref (resolver->pacrunner);
      *out_autoconfig_url = g_strdup (resolver->autoconfig_url);
      goto done;
    }
  else if (resolver->ftp_proxy &&
	   (!strcmp (scheme, "ftp") || !strcmp (scheme, "ftps")))
    {
      *out_proxies = make_proxies (resolver->ftp_proxy);
    }
  else if (resolver->https_proxy && !strcmp (scheme, "https"))
    {
      *out_proxies = make_proxies (resolver->https_proxy);
    }
  else if (resolver->http_proxy &&
      (!strcmp (scheme, "http") || !strcmp (scheme, "https")))
    {
      *out_proxies = make_proxies (resolver->http_proxy);
    }
  else if (resolver->socks_authority)
    {
      *out_proxies = g_new (gchar *, 4);
      *out_proxies[0] = g_strdup_printf ("socks5://%s", resolver->socks_authority);
      *out_proxies[1] = g_strdup_printf ("socks4a://%s", resolver->socks_authority);
      *out_proxies[2] = g_strdup_printf ("socks4://%s", resolver->socks_authority);
      *out_proxies[3] = NULL;
    }
  else if (resolver->use_same_proxy && resolver->http_proxy)
    {
      *out_proxies = make_proxies (resolver->http_proxy);
    }
  else
    *out_proxies = make_proxies ("direct://");

done:
  if (addr)
    g_object_unref (addr);
  g_mutex_unlock (&resolver->lock);

  if (*out_proxies || *out_pacrunner)
    return TRUE;
  else
    return FALSE;
}

static gchar **
g_proxy_resolver_gnome_lookup (GProxyResolver  *proxy_resolver,
			       const gchar     *uri,
			       GCancellable    *cancellable,
			       GError         **error)
{
  GProxyResolverGnome *resolver = G_PROXY_RESOLVER_GNOME (proxy_resolver);
  GDBusProxy *pacrunner;
  gchar **proxies, *autoconfig_url;

  if (!g_proxy_resolver_gnome_lookup_internal (resolver, uri,
					       &proxies, &pacrunner, &autoconfig_url,
					       cancellable, error))
    return NULL;

  if (pacrunner)
    {
      GVariant *vproxies;

      vproxies = g_dbus_proxy_call_sync (pacrunner,
					 "Lookup",
					 g_variant_new ("(ss)",
							autoconfig_url,
							uri),
					 G_DBUS_CALL_FLAGS_NONE,
					 -1,
					 cancellable, error);
      if (vproxies)
	{
	  g_variant_get (vproxies, "(^as)", &proxies);
	  g_variant_unref (vproxies);
	}
      else
	proxies = NULL;

      g_object_unref (pacrunner);
      g_free (autoconfig_url);
    }

  return proxies;
}

static void
got_autoconfig_proxies (GObject      *source,
			GAsyncResult *result,
			gpointer      user_data)
{
  GTask *task = user_data;
  GVariant *vproxies;
  char **proxies;
  GError *error = NULL;

  vproxies = g_dbus_proxy_call_finish (G_DBUS_PROXY (source),
				       result, &error);
  if (vproxies)
    {
      g_variant_get (vproxies, "(^as)", &proxies);
      g_task_return_pointer (task, proxies, (GDestroyNotify)g_strfreev);
      g_variant_unref (vproxies);
    }
  else
    g_task_return_error (task, error);
  g_object_unref (task);
}

static void
g_proxy_resolver_gnome_lookup_async (GProxyResolver      *proxy_resolver,
				     const gchar         *uri,
				     GCancellable        *cancellable,
				     GAsyncReadyCallback  callback,
				     gpointer             user_data)
{
  GProxyResolverGnome *resolver = G_PROXY_RESOLVER_GNOME (proxy_resolver);
  GTask *task;
  char **proxies, *autoconfig_url;
  GDBusProxy *pacrunner;
  GError *error = NULL;

  task = g_task_new (resolver, cancellable, callback, user_data);

   if (!g_proxy_resolver_gnome_lookup_internal (resolver, uri,
						&proxies, &pacrunner, &autoconfig_url,
						cancellable, &error))
     {
       g_task_return_error (task, error);
       g_object_unref (task);
       return;
     }
   else if (proxies)
     {
       g_task_return_pointer (task, proxies, (GDestroyNotify)g_strfreev);
       g_object_unref (task);
       return;
     }

   g_dbus_proxy_call (pacrunner,
		      "Lookup",
		      g_variant_new ("(ss)",
				     autoconfig_url,
				     uri),
		      G_DBUS_CALL_FLAGS_NONE,
		      -1,
		      cancellable,
		      got_autoconfig_proxies,
		      task);
   g_object_unref (pacrunner);
   g_free (autoconfig_url);
}

static gchar **
g_proxy_resolver_gnome_lookup_finish (GProxyResolver  *resolver,
				      GAsyncResult    *result,
				      GError         **error)
{
  g_return_val_if_fail (g_task_is_valid (result, resolver), NULL);

  return g_task_propagate_pointer (G_TASK (result), error);
}

static void
g_proxy_resolver_gnome_class_init (GProxyResolverGnomeClass *resolver_class)
{
  GObjectClass *object_class;
  
  object_class = G_OBJECT_CLASS (resolver_class);
  object_class->finalize = g_proxy_resolver_gnome_finalize;
}

static void
g_proxy_resolver_gnome_iface_init (GProxyResolverInterface *iface)
{
  iface->is_supported = g_proxy_resolver_gnome_is_supported;
  iface->lookup = g_proxy_resolver_gnome_lookup;
  iface->lookup_async = g_proxy_resolver_gnome_lookup_async;
  iface->lookup_finish = g_proxy_resolver_gnome_lookup_finish;
}

void
g_proxy_resolver_gnome_register (GIOModule *module)
{
  g_proxy_resolver_gnome_register_type (G_TYPE_MODULE (module));
  g_io_extension_point_implement (G_PROXY_RESOLVER_EXTENSION_POINT_NAME,
				  g_proxy_resolver_gnome_get_type(),
				  "gnome",
				  80);
}
