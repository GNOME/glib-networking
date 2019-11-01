/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2009 Red Hat, Inc
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
 */

#include "config.h"

#include <gio/gio.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <stdarg.h>
#if SYSTEMD_JOURNAL
#define SD_JOURNAL_SUPPRESS_LOCATION
#include <systemd/sd-journal.h>
#endif

#include "gtlslog.h"

#if SYSTEMD_JOURNAL
static int log_level_to_journal_priority(GLogLevelFlags level)
{
  int priority;
  switch(level) {
    case G_LOG_LEVEL_ERROR:         priority=LOG_ERR;          break;
    case G_LOG_LEVEL_WARNING:       priority=LOG_WARNING;      break;
    case G_LOG_LEVEL_INFO:          priority=LOG_INFO;         break;
    case G_LOG_LEVEL_DEBUG:         priority=LOG_DEBUG;        break;
    default:                        priority=LOG_DEBUG;        break;
  }
  return priority;
}
#endif

void g_tls_log (GLogLevelFlags level,
                gpointer       conn,
                const char    *format,
                ...)
{
  char *header = NULL;
  char *message = NULL;
  va_list args;
  int ret;

  va_start (args, format);
  ret = g_vasprintf (&message, format, args);
  va_end (args);

  if (ret <= 0)
      return;

  if (conn && G_IS_TLS_CONNECTION (conn)) {
    if (G_IS_TLS_CLIENT_CONNECTION (conn))
        header = g_strdup_printf("CLIENT[%p]: ", conn);
    else if (G_IS_TLS_SERVER_CONNECTION (conn))
        header = g_strdup_printf("SERVER[%p]: ", conn);
    else
        g_assert_not_reached();
  } else {
    header = g_strdup("");
  }

#if SYSTEMD_JOURNAL
  sd_journal_send ("MESSAGE=%s%s", header, message,
                   "SYSLOG_IDENTIFIER="G_LOG_DOMAIN,
                   "THREAD=%p", g_thread_self(),
                   "PRIORITY=%i", log_level_to_journal_priority(level),
                   NULL);
#else
  g_log (G_LOG_DOMAIN,
         level,
         "%s%s", header, message);
#endif

  g_free (message);
  g_free (header);
}
