/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright © 2022 Red Hat, Inc.
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

/* This file is (very loosely) based on libproxy's pacrunner_webkit.cpp. */

#include "config.h"

#include "ghttp.h"
#include "pacutils.h"
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <jsc/jsc.h>
#include <stdlib.h>
#include <unistd.h>

static char *
dns_resolve (const char *hostname)
{
  GResolver *resolver = g_resolver_get_default ();
  GList *addresses;
  char *first_address;
  GError *error = NULL;

  addresses = g_resolver_lookup_by_name (resolver,
                                         hostname,
                                         NULL,
                                         &error);
  if (error) {
    g_warning ("Failed to resolve %s: %s", hostname, error->message);
    g_error_free (error);
    return NULL;
  }

  first_address = g_inet_address_to_string (addresses->data);
  g_resolver_free_addresses (addresses);
  return first_address;
}

static char *
my_ip_address (void)
{
  char hostname[HOST_NAME_MAX + 1];

  if (gethostname (hostname, sizeof (hostname)) == -1)
    {
      g_warning ("Failed to get system hostname: %s", g_strerror (errno));
      return NULL;
    }

  return dns_resolve (hostname);
}

static char *
download_pac (const char  *pac_url,
              GError     **error)
{
  const char *http = g_intern_static_string ("http");
  const char *https = g_intern_static_string ("https");
  const char *file = g_intern_static_string ("file");
  const char *scheme;
  char *result = NULL;
  GInputStream *pac;
  GByteArray *bytes;
  guchar buffer[2048];
  gssize n_read;
  GFile *f;

  scheme = g_uri_peek_scheme (pac_url);
  if (scheme == http || scheme == https)
    {
      pac = g_request_uri (pac_url, NULL, error);
      if (!pac)
        return NULL;
    }
  else if (scheme == file)
    {
      f = g_file_new_for_uri (pac_url);
      pac = G_INPUT_STREAM (g_file_read (f, NULL, error));
      g_object_unref (f);
      if (!pac)
        return NULL;
    }
  else
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "PAC URL %s has unsupported scheme %s", pac_url, scheme);
      return NULL;
    }

  bytes = g_byte_array_sized_new (sizeof (buffer));
  do
    {
      n_read = g_input_stream_read (pac, buffer, sizeof (buffer),
                                    NULL, error);
      if (n_read == -1)
        {
          g_byte_array_free (bytes, TRUE);
          return NULL;
        }
      g_byte_array_append (bytes, buffer, n_read);
    } while (n_read > 0);

  result = (char *)g_byte_array_free (bytes, FALSE);

  g_object_unref (pac);
  return result;
}

static char *
evaluate_pac (const char  *pac,
              const char  *lookup_url,
              const char  *host,
              GError     **error)
{
  JSCContext *context;
  JSCValue *value = NULL;
  char *statement = NULL;
  char *result = NULL;
  JSCException *exception = NULL;

  context = jsc_context_new ();
  value = jsc_value_new_function (context,
                                  "dnsResolve",
                                  G_CALLBACK (dns_resolve), NULL, NULL,
                                  G_TYPE_STRING, 1,
                                  G_TYPE_STRING);
  jsc_context_set_value (context, "dnsResolve", value);
  g_clear_object (&value);

  value = jsc_value_new_function (context,
                                  "myIpAddress",
                                  G_CALLBACK (my_ip_address), NULL, NULL,
                                  G_TYPE_STRING, 0);
  jsc_context_set_value (context, "dnsResolve", value);
  g_clear_object (&value);

  jsc_context_check_syntax (context,
                            JAVASCRIPT_ROUTINES, -1,
                            JSC_CHECK_SYNTAX_MODE_SCRIPT,
                            NULL, 0, &exception);
  if (exception)
    g_error ("Fatal: pacrunner JS failed syntax sanity check: %s", jsc_exception_report (exception));
  value = jsc_context_evaluate (context, JAVASCRIPT_ROUTINES, -1);
  g_clear_object (&value);

  jsc_context_check_syntax (context,
                            pac, -1,
                            JSC_CHECK_SYNTAX_MODE_SCRIPT,
                            NULL, 0, &exception);
  if (exception)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Syntax error in proxy autoconfig script: %s", jsc_exception_report (exception));
      g_object_unref (exception);
      goto out;
    }
  value = jsc_context_evaluate (context, pac, -1);
  g_clear_object (&value);

  statement = g_strdup_printf ("FindProxyForURL('%s', '%s');", lookup_url, host);
  jsc_context_check_syntax (context,
                            statement, -1,
                            JSC_CHECK_SYNTAX_MODE_SCRIPT,
                            NULL, 0, &exception);
  if (exception)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Syntax error in script \"%s\": %s", statement, jsc_exception_report (exception));
      g_object_unref (exception);
      goto out;
    }
  value = jsc_context_evaluate (context, statement, -1);
  if (!jsc_value_is_string (value))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Proxy autoconfig script result '%s' is not a string", jsc_value_to_string (value));
      g_clear_object (&value);
    }

out:
  if (value)
    {
      result = jsc_value_to_string (value);
      g_object_unref (value);
    }
  g_free (statement);
  g_object_unref (context);
  return result;
}

/* Paranoia: prevent a malicious URL from executing script in the PAC context by
 * encoding any use of the quote character ' that it needs to use to break out
 * of its intended context. It's generally better to encode everything that's
 * not alphanumeric, but in this case that is not possible because the PAC
 * script will expect to operate on unencoded URLs, so we really cannot encode
 * anything more than necessary.
 */
static char *
encode_single_quotes (const char  *input,
                      GError     **error)
{
  GString *str;
  const char *c = input;

  if (!g_utf8_validate (input, -1, NULL))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Input is not valid UTF-8");
      return NULL;
    }

  str = g_string_new (NULL);
  do
    {
      gunichar u = g_utf8_get_char (c);
      if (u == '\'')
        g_string_append_printf (str, "\\u%04u", u);
      else
        g_string_append_unichar (str, u);
      c = g_utf8_next_char (c);
    } while (*c);

  return g_string_free (str, FALSE);
}

static void
process_lookup_url (const char  *lookup_url,
                    char       **out_sanitized_url,
                    char       **out_sanitized_host,
                    GError     **error)
{
  GUri *uri;
  GUri *tmp;
  char *url_string = NULL;
  char *encoded_url = NULL;
  char *encoded_host = NULL;

  uri = g_uri_parse (lookup_url, G_URI_FLAGS_NONE, error);
  if (!uri)
    return;

  /* In the future, we probably want to sanitize all URLs down to only
   * protocol://host:port, but for now browsers only do this for https
   * URLs, so let's remain compatible.
   */
  if (strcmp (g_uri_get_scheme (uri), "https") == 0)
    {
      tmp = g_uri_build (G_URI_FLAGS_NONE,
                         g_uri_get_scheme (uri),
                         NULL,
                         g_uri_get_host (uri),
                         g_uri_get_port (uri),
                         NULL, NULL, NULL);
      g_uri_unref (uri);
      uri = g_steal_pointer (&tmp);
    }

  url_string = g_uri_to_string (uri);
  encoded_url = encode_single_quotes (url_string, error);
  if (!encoded_url)
    goto out;

  encoded_host = encode_single_quotes (g_uri_get_host (uri), error);
  if (!encoded_url)
    goto out;

  *out_sanitized_url = g_steal_pointer (&encoded_url);
  *out_sanitized_host = g_steal_pointer (&encoded_host);

out:
  g_uri_unref (uri);
  g_free (url_string);
  g_free (encoded_url);
  g_free (encoded_host);
}

int
main (int argc, char *argv[])
{
  GOptionContext *context;
  const char *pac_url;
  const char *lookup_url;
  char *sanitized_url = NULL;
  char *sanitized_host = NULL;
  char *pac = NULL;
  char *result = NULL;
  int exit_status = 1;
  GError *error = NULL;

  context = g_option_context_new ("PAC_URL LOOKUP_URL");
  g_option_context_parse (context, &argc, &argv, &error);
  g_option_context_free (context);
  if (error)
    {
      g_warning ("Failed to parse options: %s", error->message);
      g_error_free (error);
      goto out;
    }

  if (argc != 3)
    {
      g_fprintf (stderr, "Usage: %s PAC_URL LOOKUP_URL\n", argv[0]);
      goto out;
    }

  pac_url = argv[1];
  lookup_url = argv[2];

  process_lookup_url (lookup_url, &sanitized_url, &sanitized_host, &error);
  if (error)
    {
      g_warning ("Failed to parse lookup URL %s: %s", lookup_url, error->message);
      g_error_free (error);
      goto out;
    }

  pac = download_pac (pac_url, &error);
  if (!pac)
    {
      g_warning ("Failed to download proxy autoconfig script %s: %s", pac_url, error->message);
      g_error_free (error);
      goto out;
    }

  result = evaluate_pac (pac, sanitized_url, sanitized_host, &error);
  if (!result)
    {
      g_warning ("Failed to resolve proxy for URL %s using proxy autoconfig script %s: %s",
                 lookup_url, pac_url, error->message);
      g_error_free (error);
      goto out;
    }

  g_printf ("%s\n", result);
  exit_status = 0;

out:
  g_free (pac);
  g_free (sanitized_url);
  g_free (sanitized_host);

  return exit_status;
}
