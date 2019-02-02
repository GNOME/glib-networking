/*
 * gtlsbio.h
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

#ifndef __G_TLS_BIO_H__
#define __G_TLS_BIO_H__

#include <gio/gio.h>
#include "openssl-include.h"

G_BEGIN_DECLS

BIO       *g_tls_bio_new                   (GIOStream    *io_stream);

void       g_tls_bio_set_read_cancellable  (BIO          *bio,
                                            GCancellable *cancellable);

void       g_tls_bio_set_read_blocking     (BIO          *bio,
                                            gboolean      blocking);

void       g_tls_bio_set_read_error        (BIO          *bio,
                                            GError      **error);

void       g_tls_bio_set_write_cancellable (BIO          *bio,
                                            GCancellable *cancellable);

void       g_tls_bio_set_write_blocking    (BIO          *bio,
                                            gboolean      blocking);

void       g_tls_bio_set_write_error       (BIO          *bio,
                                            GError      **error);

G_END_DECLS

#endif /* __G_TLS_BIO_H__ */
