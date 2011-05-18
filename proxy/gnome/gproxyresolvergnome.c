/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright (C) 2010 Red Hat, Inc.
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

#define GNOME_PROXY_HTTP_SETTINGS_SCHEMA  "org.gnome.system.proxy.http"
#define GNOME_PROXY_HTTP_ENABLED_KEY      "enabled"
#define GNOME_PROXY_HTTP_HOST_KEY         "host"
#define GNOME_PROXY_HTTP_PORT_KEY         "port"
#define GNOME_PROXY_HTTP_USE_AUTH_KEY     "use-authentication"
#define GNOME_PROXY_HTTP_USER_KEY         "authentication-user"
#define GNOME_PROXY_HTTP_PASSWORD_KEY     "authentication-password"

#define GNOME_PROXY_HTTPS_SETTINGS_SCHEMA "org.gnome.system.proxy.https"
#define GNOME_PROXY_HTTPS_HOST_KEY        "host"
#define GNOME_PROXY_HTTPS_PORT_KEY        "port"

#define GNOME_PROXY_FTP_SETTINGS_SCHEMA   "org.gnome.system.proxy.ftp"
#define GNOME_PROXY_FTP_HOST_KEY          "host"
#define GNOME_PROXY_FTP_PORT_KEY          "port"

#define GNOME_PROXY_SOCKS_SETTINGS_SCHEMA "org.gnome.system.proxy.socks"
#define GNOME_PROXY_SOCKS_HOST_KEY        "host"
#define GNOME_PROXY_SOCKS_PORT_KEY        "port"

typedef struct {
  GSocketFamily family;
  guint8        mask[16];
  gint          length;
} GProxyResolverGnomeIPMask;

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
  gchar **ignore_hosts;
  GProxyResolverGnomeIPMask *ignore_ips;

  gchar *http_proxy, *https_proxy;
  gchar *ftp_proxy, *socks_authority;

  GDBusProxy *pacrunner;

  GMutex *lock;
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
  g_free (resolver->autoconfig_url);
  g_strfreev (resolver->ignore_hosts);
  g_free (resolver->ignore_ips);

  g_free (resolver->http_proxy);
  g_free (resolver->https_proxy);
  g_free (resolver->ftp_proxy);
  g_free (resolver->socks_authority);
}

static void
gsettings_changed (GSettings   *settings,
		   const gchar *key,
		   gpointer     user_data)
{
  GProxyResolverGnome *resolver = user_data;

  g_mutex_lock (resolver->lock);
  resolver->need_update = TRUE;
  g_mutex_unlock (resolver->lock);
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

  g_mutex_free (resolver->lock);

  G_OBJECT_CLASS (g_proxy_resolver_gnome_parent_class)->finalize (object);
}

static void
g_proxy_resolver_gnome_init (GProxyResolverGnome *resolver)
{
  resolver->lock = g_mutex_new ();

  resolver->proxy_settings = g_settings_new (GNOME_PROXY_SETTINGS_SCHEMA);
  g_signal_connect (resolver->proxy_settings, "changed",
		    G_CALLBACK (gsettings_changed), resolver);
  resolver->http_settings = g_settings_new (GNOME_PROXY_HTTP_SETTINGS_SCHEMA);
  g_signal_connect (resolver->http_settings, "changed",
		    G_CALLBACK (gsettings_changed), resolver);
  resolver->https_settings = g_settings_new (GNOME_PROXY_HTTPS_SETTINGS_SCHEMA);
  g_signal_connect (resolver->https_settings, "changed",
		    G_CALLBACK (gsettings_changed), resolver);
  resolver->ftp_settings = g_settings_new (GNOME_PROXY_FTP_SETTINGS_SCHEMA);
  g_signal_connect (resolver->ftp_settings, "changed",
		    G_CALLBACK (gsettings_changed), resolver);
  resolver->socks_settings = g_settings_new (GNOME_PROXY_SOCKS_SETTINGS_SCHEMA);
  g_signal_connect (resolver->socks_settings, "changed",
		    G_CALLBACK (gsettings_changed), resolver);

  resolver->need_update = TRUE;
}

/* called with lock held */
static void
update_settings (GProxyResolverGnome *resolver)
{
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

  resolver->ignore_hosts =
    g_settings_get_strv (resolver->proxy_settings, GNOME_PROXY_IGNORE_HOSTS_KEY);

  if (resolver->ignore_hosts && resolver->ignore_hosts[0])
    {
      GArray *ignore_ips;
      gchar *slash;
      GInetAddress *iaddr;
      GProxyResolverGnomeIPMask mask;

      ignore_ips = g_array_new (TRUE, FALSE, sizeof (GProxyResolverGnomeIPMask));
      for (i = 0; resolver->ignore_hosts[i]; i++)
	{
	  host = resolver->ignore_hosts[i];
	  slash = strchr (host, '/');
	  if (slash)
	    host = g_strndup (host, slash - host);
	  iaddr = g_inet_address_new_from_string (host);
	  if (iaddr)
	    {
	      int addrlen = g_inet_address_get_native_size (iaddr);

	      memset (&mask, 0, sizeof (mask));
	      mask.family = g_inet_address_get_family (iaddr);
	      memcpy (mask.mask, g_inet_address_to_bytes (iaddr), addrlen);
	      if (slash)
		{
		  mask.length = atoi (slash + 1);
		  if (mask.length > addrlen * 8)
		    {
		      g_warning("ignore_host '%s' has invalid mask length",
				resolver->ignore_hosts[i]);
		      mask.length = addrlen;
		    }
		}
	      else
		mask.length = 0;

	      g_array_append_val (ignore_ips, mask);

	      g_object_unref (iaddr);
	    }
	  if (slash)
	    g_free (host);
	}

      if (ignore_ips->len)
	resolver->ignore_ips = (GProxyResolverGnomeIPMask *)g_array_free (ignore_ips, FALSE);
      else
	{
	  g_array_free (ignore_ips, TRUE);
	  resolver->ignore_ips = NULL;
	}
    }
  else
    resolver->ignore_ips = NULL;

  host = g_settings_get_string (resolver->http_settings, GNOME_PROXY_HTTP_HOST_KEY);
  port = g_settings_get_int (resolver->http_settings, GNOME_PROXY_HTTP_PORT_KEY);

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
  GProxyResolverGnome *resolver = G_PROXY_RESOLVER_GNOME (object);

  return resolver->proxy_settings != NULL;
}

static gboolean
parse_uri (const gchar  *uri,
	   gchar       **scheme,
	   gchar       **host)
{
  const gchar *authority, *hoststart, *hostend, *at, *colon, *slash;

  colon = strchr (uri, ':');
  if (!colon || strncmp (colon, "://", 3) != 0)
    return FALSE;

  *scheme = g_strndup (uri, colon - uri);

  authority = colon + 3;
  colon = strchr (authority, ':');
  slash = strchr (authority, '/');
  if (colon && (!slash || colon < slash))
    hostend = colon;
  else if (slash)
    hostend = slash;
  else
    hostend = authority + strlen (authority);

  at = strchr (authority, '@');
  if (at && at < hostend)
    hoststart = at + 1;
  else
    hoststart = authority;
  *host = g_strndup (hoststart, hostend - hoststart);

  return TRUE;
}

static gboolean
masked_compare (const guint8 *mask,
		const guint8 *addr,
		int           maskbits)
{
  int bytes, bits;

  if (maskbits == 0)
    return TRUE;

  bytes = maskbits / 8;
  if (bytes != 0 && memcmp (mask, addr, bytes) != 0)
    return FALSE;

  bits = maskbits % 8;
  return mask[bytes] == (addr[bytes] & (0xFF << (8 - bits)));
}

static gboolean
ignore_host (GProxyResolverGnome *resolver,
	     const gchar         *host)
{
  gboolean ignore = FALSE;
  gint i;

  if (resolver->ignore_ips)
    {
      GInetAddress *iaddr;

      iaddr = g_inet_address_new_from_string (host);
      if (iaddr)
	{
	  GSocketFamily family = g_inet_address_get_family (iaddr);
	  const guint8 *addr = g_inet_address_to_bytes (iaddr);

	  for (i = 0; resolver->ignore_ips[i].length; i++)
	    {
	      if (resolver->ignore_ips[i].family == family &&
		  masked_compare (resolver->ignore_ips[i].mask, addr,
				  resolver->ignore_ips[i].length))
		{
		  ignore = TRUE;
		  break;
		}
	    }

	  g_object_unref (iaddr);
	  return ignore;
	}
    }

  if (resolver->ignore_hosts && resolver->ignore_hosts[0])
    {
      gchar *ascii_host = NULL;

      if (g_hostname_is_non_ascii (host))
	host = ascii_host = g_hostname_to_ascii (host);

      for (i = 0; resolver->ignore_hosts[i]; i++)
	{
	  if (!g_ascii_strcasecmp (host, resolver->ignore_hosts[i]))
	    {
	      ignore = TRUE;
	      break;
	    }
	}

      g_free (ascii_host);
    }

  return ignore;
}

static gchar **
g_proxy_resolver_gnome_lookup (GProxyResolver  *proxy_resolver,
			       const gchar     *uri,
			       GCancellable    *cancellable,
			       GError         **error)
{
  GProxyResolverGnome *resolver = G_PROXY_RESOLVER_GNOME (proxy_resolver);
  gchar *scheme = NULL, *host = NULL;
  const gchar *proxy = "direct://";
  gchar **proxies = NULL;

  g_mutex_lock (resolver->lock);
  if (resolver->need_update)
    update_settings (resolver);
  g_mutex_unlock (resolver->lock);

  if (resolver->mode == G_DESKTOP_PROXY_MODE_NONE)
    goto done;

  /* FIXME: use guri when it lands... */
  if (!parse_uri (uri, &scheme, &host))
    goto done;
  if (ignore_host (resolver, host))
    goto done;

  if (resolver->pacrunner)
    {
      GVariant *vproxies;

      vproxies = g_dbus_proxy_call_sync (resolver->pacrunner,
					 "Lookup",
					 g_variant_new ("(ss)",
							resolver->autoconfig_url,
							uri),
					 G_DBUS_CALL_FLAGS_NONE,
					 -1,
					 cancellable, error);
      if (vproxies)
	{
	  g_variant_get (vproxies, "(^as)", &proxies);
	  g_variant_unref (vproxies);
	}
    }
  else if (resolver->ftp_proxy &&
	   (!strcmp (scheme, "ftp") || !strcmp (scheme, "ftps")))
    {
      proxy = resolver->ftp_proxy;
    }
  else if (resolver->https_proxy && !strcmp (scheme, "https"))
    {
      proxy = resolver->https_proxy;
    }
  else if (resolver->http_proxy &&
      (!strcmp (scheme, "http") || !strcmp (scheme, "https")))
    {
      proxy = resolver->http_proxy;
    }
  else if (resolver->socks_authority)
    {
      proxies = g_new0 (gchar *, 4);
      proxies[0] = g_strdup_printf ("socks5://%s", resolver->socks_authority);
      proxies[1] = g_strdup_printf ("socks4a://%s", resolver->socks_authority);
      proxies[2] = g_strdup_printf ("socks4://%s", resolver->socks_authority);
    }
  else if (resolver->use_same_proxy && resolver->http_proxy)
    {
      proxy = resolver->http_proxy;
    }

done:
  g_free (scheme);
  g_free (host);

  if (!proxies)
    {
      proxies = g_new0 (gchar *, 2);
      proxies[0] = g_strdup (proxy);
    }
  return proxies;
}

static void
got_autoconfig_proxies (GObject      *source,
			GAsyncResult *result,
			gpointer      user_data)
{
  GSimpleAsyncResult *simple = user_data;
  GVariant *vproxies;
  char **proxies;
  GError *error = NULL;

  vproxies = g_dbus_proxy_call_finish (G_DBUS_PROXY (source),
				       result, &error);
  if (vproxies)
    {
      g_variant_get (vproxies, "(^as)", &proxies);
      g_simple_async_result_set_op_res_gpointer (simple, proxies,
						 (GDestroyNotify)g_strfreev);
      g_variant_unref (vproxies);
    }
  else
    {
      g_simple_async_result_set_from_error (simple, error);
      g_error_free (error);
    }
  g_simple_async_result_complete (simple);
  g_object_unref (simple);
}

static void
g_proxy_resolver_gnome_lookup_async (GProxyResolver      *proxy_resolver,
				     const gchar         *uri,
				     GCancellable        *cancellable,
				     GAsyncReadyCallback  callback,
				     gpointer             user_data)
{
  GProxyResolverGnome *resolver = G_PROXY_RESOLVER_GNOME (proxy_resolver);
  GSimpleAsyncResult *simple;

  simple = g_simple_async_result_new (G_OBJECT (resolver),
				      callback, user_data,
				      g_proxy_resolver_gnome_lookup_async);

  if (resolver->pacrunner)
    {
      g_dbus_proxy_call (resolver->pacrunner,
			 "Lookup",
			 g_variant_new ("(ss)",
					resolver->autoconfig_url,
					uri),
			 G_DBUS_CALL_FLAGS_NONE,
			 -1,
			 cancellable,
			 got_autoconfig_proxies,
			 simple);
    }
  else
    {
      GError *error = NULL;
      char **proxies;

      proxies = g_proxy_resolver_gnome_lookup (proxy_resolver, uri,
					       cancellable, &error);
      if (proxies)
	{
	  g_simple_async_result_set_op_res_gpointer (simple, proxies,
						     (GDestroyNotify)g_strfreev);
	}
      else
	{
	  g_simple_async_result_set_from_error (simple, error);
	  g_error_free (error);
	}
      g_simple_async_result_complete_in_idle (simple);
      g_object_unref (simple);
    }
}

static gchar **
g_proxy_resolver_gnome_lookup_finish (GProxyResolver  *resolver,
				      GAsyncResult    *result,
				      GError         **error)
{
  GSimpleAsyncResult *simple;
  gchar **proxies;

  g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (resolver), g_proxy_resolver_gnome_lookup_async), NULL);

  simple = G_SIMPLE_ASYNC_RESULT (result);

  if (g_simple_async_result_propagate_error (simple, error))
    return NULL;

  proxies = g_simple_async_result_get_op_res_gpointer (simple);
  return g_strdupv (proxies);
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
