/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - Small GLib wrapper of PKCS#11 for use in GTls
 *
 * Copyright 2011 Collabora, Ltd.
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

#ifndef __G_PKCS11_SLOT_H__
#define __G_PKCS11_SLOT_H__

#include <gio/gio.h>

#include "gpkcs11array.h"

#include <p11-kit/pkcs11.h>
#include <p11-kit/uri.h>

G_BEGIN_DECLS

typedef enum
{
  G_PKCS11_ENUMERATE_FAILED,
  G_PKCS11_ENUMERATE_STOP,
  G_PKCS11_ENUMERATE_CONTINUE
} GPkcs11EnumerateState;

#define G_TYPE_PKCS11_SLOT            (g_pkcs11_slot_get_type ())

G_DECLARE_FINAL_TYPE (GPkcs11Slot, g_pkcs11_slot, G, PKCS11_SLOT, GObject)

typedef gboolean             (*GPkcs11Accumulator)            (gpointer result,
                                                               gpointer user_data);

GPkcs11EnumerateState        g_pkcs11_slot_enumerate          (GPkcs11Slot             *self,
                                                               GTlsInteraction         *interaction,
                                                               CK_ATTRIBUTE_PTR         match,
                                                               CK_ULONG                 match_count,
                                                               gboolean                 match_private,
                                                               const CK_ATTRIBUTE_TYPE *attr_types,
                                                               guint                    attr_types_length,
                                                               GPkcs11Accumulator       accumulator,
                                                               gpointer                 user_data,
                                                               GCancellable            *cancellable,
                                                               GError                 **error);

gboolean                     g_pkcs11_slot_get_token_info     (GPkcs11Slot             *self,
                                                               CK_TOKEN_INFO_PTR        token_info);

gboolean                     g_pkcs11_slot_matches_uri        (GPkcs11Slot             *self,
                                                               P11KitUri               *uri);

G_END_DECLS

#endif /* __G_PKCS11_SLOT_H___ */
