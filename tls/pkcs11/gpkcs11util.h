/* GIO - Small GLib wrapper of PKCS#11 for use in GTls
 *
 * Copyright 2011 Collabora, Ltd.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#ifndef __G_PKCS11_UTIL_H__
#define __G_PKCS11_UTIL_H__

#include <glib.h>

#include <p11-kit/pkcs11.h>

G_BEGIN_DECLS

#define                G_PKCS11_VENDOR_CODE               0x47000000 /* G000 */

enum {
  G_PKCS11_ERROR_BAD_URI = (CKR_VENDOR_DEFINED | (G_PKCS11_VENDOR_CODE + 1)),
};

#define                G_PKCS11_ERROR                     (g_pkcs11_get_error_domain ())

GQuark                 g_pkcs11_get_error_domain          (void) G_GNUC_CONST;

gboolean               g_pkcs11_propagate_error           (GError **error,
                                                           CK_RV rv);

G_END_DECLS

#endif /* __G_PKCS11_UTIL_H___ */
