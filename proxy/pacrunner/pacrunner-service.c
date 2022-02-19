/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright © 2011, 2022 Red Hat, Inc.
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
 */
#include "config.h"

#include <gio/gio.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <stdlib.h>

static const gchar introspection_xml[] =
  "<node>"
  "  <interface name='org.gtk.GLib.PACRunner'>"
  "    <method name='Lookup'>"
  "      <arg type='s' name='pac_url' direction='in'/>"
  "      <arg type='s' name='lookup_url' direction='in'/>"
  "      <arg type='as' name='proxies' direction='out'/>"
  "    </method>"
  "  </interface>"
  "</node>";

static GMainLoop *loop;
static GCancellable *cancellable;

static void
add_to_results_if_valid (const char *scheme,
                         const char *server,
                         GPtrArray  *results)
{
  char *url_string;

  if (!server || !*server)
    return;

  url_string = g_strconcat (scheme, server, NULL);
  if (g_uri_is_valid (url_string, G_URI_FLAGS_NONE, NULL))
    g_ptr_array_add (results, g_steal_pointer (&url_string));

  g_free (url_string);
}

/* Loosely based on format_pac_response() in libproxy's proxy.cpp */
static char **
format_pac_response (char *response)
{
  char **directives;
  GPtrArray *results;

  if (response[0] == ';')
    response++;

  response = g_strstrip (response);
  directives = g_strsplit (response, ";", 0);
  results = g_ptr_array_sized_new (g_strv_length (directives));

  for (char **remaining_directives = directives;
       remaining_directives && *remaining_directives;
       remaining_directives++)
    {
      const char *directive = *remaining_directives;
      const char *method;
      const char *server;
      char **split_directive;
      
      directive = g_strstrip ((char *)directive);
      if (g_ascii_strcasecmp (directive, "direct") == 0)
       {
         g_ptr_array_add (results, g_strdup ("direct://"));
         continue;
       }

      split_directive = g_strsplit_set (directive, " \t", 2);
      method = split_directive[0];
      server = split_directive[1];

      if (g_ascii_strcasecmp (method, "proxy") == 0)
        add_to_results_if_valid ("http://", server, results);
      else if (g_ascii_strcasecmp (method, "socks") == 0)
        add_to_results_if_valid ("socks://", server, results);
      else if (g_ascii_strcasecmp (method, "socks4") == 0)
        add_to_results_if_valid ("socks4://", server, results);
      else if (g_ascii_strcasecmp (method, "socks4a") == 0)
        add_to_results_if_valid ("socks4a://", server, results);
      else if (g_ascii_strcasecmp (method, "socks5") == 0)
        add_to_results_if_valid ("socks5://", server, results);

      g_strfreev (split_directive);
    }

  g_ptr_array_add (results, NULL);
  g_strfreev (directives);
  return (char **)g_ptr_array_free (results, FALSE);
}

static void
subprocess_finished_cb (GObject      *source,
                        GAsyncResult *result,
                        gpointer      user_data)
{
  GSubprocess *subprocess = G_SUBPROCESS (source);
  GDBusMethodInvocation *invocation = user_data;
  char *stdout_buf = NULL;
  char *stderr_buf = NULL;
  char **proxies = NULL;
  GError *error = NULL;

  g_subprocess_communicate_utf8_finish (subprocess, result,
                                        &stdout_buf, &stderr_buf,
                                        &error);
  if (error)
    {
      g_dbus_method_invocation_take_error (g_steal_pointer (&invocation), error);
      goto out;
    }

  proxies = format_pac_response (stdout_buf);
  g_dbus_method_invocation_return_value (g_steal_pointer (&invocation),
                                         g_variant_new ("(^as)", proxies));

out:
  g_free (stdout_buf);
  g_free (stderr_buf);
  g_strfreev (proxies);
  g_object_unref (subprocess);
}

static void
handle_method_call (GDBusConnection       *connection,
                    const gchar           *sender,
                    const gchar           *object_path,
                    const gchar           *interface_name,
                    const gchar           *method_name,
                    GVariant              *parameters,
                    GDBusMethodInvocation *invocation,
                    gpointer               user_data)
{
  const char *pac_url, *lookup_url;
  GSubprocessLauncher *launcher;
  GSubprocess *subprocess;
  GError *error = NULL;

  g_variant_get (parameters, "(&s&s)", &pac_url, &lookup_url);

  if (g_ascii_strncasecmp (pac_url, "http:", 5) &&
      g_ascii_strncasecmp (pac_url, "https:", 6) &&
      g_ascii_strncasecmp (pac_url, "file:", 5))
    {
      g_dbus_method_invocation_return_error (g_steal_pointer (&invocation),
                                             G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                                             "PAC URL %s has unsupported protocol", pac_url);
      return;
    }

  launcher = g_subprocess_launcher_new (G_SUBPROCESS_FLAGS_STDOUT_PIPE);
  subprocess = g_subprocess_launcher_spawn (launcher, &error,
                                            LIBEXEC_DIR "/glib-pacrunner-worker",
                                            pac_url, lookup_url,
                                            NULL);
  g_object_unref (launcher);
  if (!subprocess)
    {
      g_prefix_error (&error, _("Failed to spawn pacrunner-worker"));
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation), error);
      g_error_free (error);
      return;                  
    }

  g_subprocess_communicate_utf8_async (g_steal_pointer (&subprocess),
                                       NULL,
                                       cancellable,
                                       subprocess_finished_cb,
                                       g_steal_pointer (&invocation));
}

static const GDBusInterfaceVTable interface_vtable =
  {
    handle_method_call,
    NULL,
    NULL
  };

static void
on_bus_acquired (GDBusConnection *connection,
                 const gchar     *name,
                 gpointer         user_data)
{
  GDBusNodeInfo *introspection_data;
  GError *error = NULL;

  introspection_data = g_dbus_node_info_new_for_xml (introspection_xml, NULL);
  g_dbus_connection_register_object (connection,
                                     "/org/gtk/GLib/PACRunner",
                                     introspection_data->interfaces[0],
                                     &interface_vtable,
                                     NULL,
                                     NULL,
                                     &error);
  if (error)
    g_error ("Could not register server: %s", error->message);
}

static void
on_name_acquired (GDBusConnection *connection,
                  const gchar     *name,
                  gpointer         user_data)
{
}

static void
on_name_lost (GDBusConnection *connection,
              const gchar     *name,
              gpointer         user_data)
{
  g_cancellable_cancel (cancellable);
  g_main_loop_quit (loop);
}

int
main (int argc, char *argv[])
{
  GOptionContext *context;
  int owner_id;
  GError *error = NULL;

  setlocale (LC_ALL, "");
  bindtextdomain (GETTEXT_PACKAGE, LOCALE_DIR);
  bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");

  context = g_option_context_new ("Start pacrunner service");
  g_option_context_parse (context, &argc, &argv, &error);
  g_option_context_free (context);
  if (error)
    {
      g_warning ("Failed to parse options: %s", error->message);
      g_error_free (error);
      return 1;
    }

  owner_id = g_bus_own_name (G_BUS_TYPE_SESSION,
                             "org.gtk.GLib.PACRunner",
                             G_BUS_NAME_OWNER_FLAGS_NONE,
                             on_bus_acquired,
                             on_name_acquired,
                             on_name_lost,
                             NULL,
                             NULL);

  cancellable = g_cancellable_new ();

  loop = g_main_loop_new (NULL, FALSE);
  g_main_loop_run (loop);

  g_bus_unown_name (owner_id);
  g_main_loop_unref (loop);
  g_object_unref (cancellable);

  return 0;
}
