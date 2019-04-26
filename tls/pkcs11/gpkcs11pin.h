/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Pin, Output and Pkcs11ing Library
 *
 * Copyright © 2011 Collabora Ltd.
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
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#ifndef __G_PKCS11_PIN_H__
#define __G_PKCS11_PIN_H__

#include <gio/gio.h>
#include <p11-kit/pin.h>

G_BEGIN_DECLS

#define G_TYPE_PKCS11_PIN            (g_pkcs11_pin_get_type ())

G_DECLARE_FINAL_TYPE (GPkcs11Pin, g_pkcs11_pin, G, PKCS11_PIN, GTlsPassword)

GTlsPassword *          g_pkcs11_pin_new             (GTlsPasswordFlags  flags,
                                                      const gchar       *description);

P11KitPin *             g_pkcs11_pin_steal_internal  (GPkcs11Pin  *self);

G_END_DECLS

#endif /* __G_PKCS11_PIN_H___ */
