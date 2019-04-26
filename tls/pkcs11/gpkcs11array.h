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

#ifndef __G_PKCS11_ARRAY_H__
#define __G_PKCS11_ARRAY_H__

#include <glib.h>
#include <glib-object.h>

#include <p11-kit/pkcs11.h>

#include <p11-kit/uri.h>

G_BEGIN_DECLS

typedef struct _GPkcs11Array       GPkcs11Array;

struct _GPkcs11Array
{
  CK_ATTRIBUTE *attrs;
  CK_ULONG      count;
};

#define             G_TYPE_PKCS11_ARRAY                     (g_pkcs11_array_get_type ())

GType               g_pkcs11_array_get_type                 (void) G_GNUC_CONST;

GPkcs11Array*       g_pkcs11_array_new                      (void);

#define             g_pkcs11_array_index(array,index_)      ((array)->attrs)[index_]

void                g_pkcs11_array_add                      (GPkcs11Array        *array,
                                                             CK_ATTRIBUTE        *attr);

void                g_pkcs11_array_add_value                (GPkcs11Array        *array,
                                                             CK_ATTRIBUTE_TYPE    type,
                                                             gconstpointer        value,
                                                             gssize               length);

void                g_pkcs11_array_add_boolean              (GPkcs11Array         *array,
                                                             CK_ATTRIBUTE_TYPE     type,
                                                             gboolean              value);

void                g_pkcs11_array_add_ulong                (GPkcs11Array         *array,
                                                             CK_ATTRIBUTE_TYPE     type,
                                                             gulong                value);

void                g_pkcs11_array_set                      (GPkcs11Array        *array,
                                                             CK_ATTRIBUTE        *attr);

void                g_pkcs11_array_set_value                (GPkcs11Array        *array,
                                                             CK_ATTRIBUTE_TYPE    type,
                                                             gconstpointer        value,
                                                             gssize               length);

void                g_pkcs11_array_set_boolean              (GPkcs11Array         *array,
                                                             CK_ATTRIBUTE_TYPE     type,
                                                             gboolean              value);

void                g_pkcs11_array_set_ulong                (GPkcs11Array         *array,
                                                             CK_ATTRIBUTE_TYPE     type,
                                                             gulong                value);

const CK_ATTRIBUTE* g_pkcs11_array_find                     (GPkcs11Array         *array,
                                                             CK_ATTRIBUTE_TYPE     type);

const CK_ATTRIBUTE* g_pkcs11_array_find_valid               (GPkcs11Array         *array,
                                                             CK_ATTRIBUTE_TYPE     type);

gboolean            g_pkcs11_array_find_boolean             (GPkcs11Array         *array,
                                                             CK_ATTRIBUTE_TYPE     type,
                                                             gboolean             *value);

gboolean            g_pkcs11_array_find_ulong               (GPkcs11Array         *array,
                                                             CK_ATTRIBUTE_TYPE     type,
                                                             gulong               *value);

GPkcs11Array*       g_pkcs11_array_ref                      (GPkcs11Array         *array);

void                g_pkcs11_array_unref                    (GPkcs11Array         *array);

G_END_DECLS

#endif /* __G_PKCS11_ARRAY_H___ */
