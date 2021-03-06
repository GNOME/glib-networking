/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlsfiledatabase-openssl.h
 *
 * Copyright (C) 2015 NICE s.r.l.
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, when the library is used with OpenSSL, a special
 * exception applies. Refer to the LICENSE_EXCEPTION file for details.
 *
 * Authors: Ignacio Casal Quinteiro
 */

#pragma once

#include <gio/gio.h>

#include "gtlsdatabase-openssl.h"

G_BEGIN_DECLS

#define G_TYPE_TLS_FILE_DATABASE_OPENSSL            (g_tls_file_database_openssl_get_type ())

G_DECLARE_FINAL_TYPE (GTlsFileDatabaseOpenssl, g_tls_file_database_openssl, G, TLS_FILE_DATABASE_OPENSSL, GTlsDatabaseOpenssl)

G_END_DECLS
