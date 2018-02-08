/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - Small GLib wrapper of PKCS#11 for use in GTls
 *
 * Copyright 2011 Collabora, Ltd
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

#include "config.h"

#include "gpkcs11util.h"

#include <glib/gi18n-lib.h>
#include <gio/gio.h>

#include <p11-kit/p11-kit.h>

GQuark
g_pkcs11_get_error_domain (void)
{
  static GQuark domain = 0;
  static volatile gsize quark_inited = 0;

  if (g_once_init_enter (&quark_inited))
    {
      domain = g_quark_from_static_string ("g-pkcs11-error");
      g_once_init_leave (&quark_inited, 1);
    }

  return domain;
}

gboolean
g_pkcs11_propagate_error (GError **error, CK_RV rv)
{
  if (rv == CKR_OK)
    return FALSE;
  if (rv == CKR_CANCEL)
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CANCELLED,
                           p11_kit_strerror (rv));
  else
    g_set_error_literal (error, G_PKCS11_ERROR, (gint)rv,
                         p11_kit_strerror (rv));
  return TRUE;
}
