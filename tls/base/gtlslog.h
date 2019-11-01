/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2010 Red Hat, Inc.
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

#ifndef __G_TLS_LOG_H__
#define __G_TLS_LOG_H__

#include <glib.h>

G_BEGIN_DECLS

void g_tls_log (GLogLevelFlags level,
                gpointer       conn,
                const char     *format,
                ...);

#define g_tls_log_debug(_conn, _format, _args...)   g_tls_log (G_LOG_LEVEL_DEBUG, _conn, _format, ## _args)
#define g_tls_log_info(_conn, _format, _args...)    g_tls_log (G_LOG_LEVEL_INFO, _conn, _format, ## _args)
#define g_tls_log_warning(_conn, _format, _args...) g_tls_log (G_LOG_LEVEL_WARNING, _conn, _format, ## _args)
#define g_tls_log_error(_conn, _format, _args...)   g_tls_log (G_LOG_LEVEL_ERROR, _conn, _format, ## _args)

G_END_DECLS

#endif /* __G_TLS_LOG_H__ */
