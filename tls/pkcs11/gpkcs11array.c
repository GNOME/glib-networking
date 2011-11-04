/* GIO - Small GLib wrapper of PKCS#11 for use in GTls
 *
 * Copyright 2011 Collabora, Ltd
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "gpkcs11array.h"

#include <string.h>

G_DEFINE_BOXED_TYPE (GPkcs11Array, g_pkcs11_array, g_pkcs11_array_ref, g_pkcs11_array_unref);

typedef struct _GRealPkcs11Array
{
  CK_ATTRIBUTE *attrs;
  CK_ULONG len;
  volatile gint ref_count;
} GRealPkcs11Array;

GPkcs11Array*
g_pkcs11_array_new (void)
{
  GRealPkcs11Array *array = g_slice_new (GRealPkcs11Array);

  array->attrs = NULL;
  array->len = 0;
  array->ref_count = 1;

  return (GPkcs11Array*) array;
}

void
g_pkcs11_array_add (GPkcs11Array *array,
                    CK_ATTRIBUTE *attr)
{
  GRealPkcs11Array *rarray = (GRealPkcs11Array*)array;

  g_return_if_fail (array);
  g_return_if_fail (attr);
  g_return_if_fail (attr->ulValueLen != (CK_ATTRIBUTE_TYPE)-1 || !attr->pValue);
  g_return_if_fail (attr->pValue || !attr->ulValueLen);

  rarray->attrs = g_renew (CK_ATTRIBUTE, rarray->attrs, rarray->len + 1);
  memcpy (rarray->attrs + rarray->len, attr, sizeof (CK_ATTRIBUTE));
  if (attr->pValue)
    rarray->attrs[rarray->len].pValue = g_memdup (attr->pValue, attr->ulValueLen);
  rarray->len++;
}

void
g_pkcs11_array_add_value (GPkcs11Array      *array,
                          CK_ATTRIBUTE_TYPE  type,
                          gconstpointer      value,
                          gssize              length)
{
  CK_ATTRIBUTE attr;

  g_return_if_fail (array);

  if (length < 0)
    length = strlen (value);

  attr.type = type;
  attr.pValue = (gpointer)value;
  attr.ulValueLen = length;
  g_pkcs11_array_add (array, &attr);
}

void
g_pkcs11_array_add_boolean (GPkcs11Array      *array,
                            CK_ATTRIBUTE_TYPE  attr_type,
                            gboolean           value)
{
  CK_ATTRIBUTE attr;
  CK_BBOOL bval;

  g_return_if_fail (array);

  bval = value ? CK_TRUE : CK_FALSE;
  attr.type = attr_type;
  attr.pValue = &bval;
  attr.ulValueLen = sizeof (bval);
  g_pkcs11_array_add (array, &attr);
}

void
g_pkcs11_array_add_ulong (GPkcs11Array      *array,
                          CK_ATTRIBUTE_TYPE  type,
                          gulong             value)
{
  CK_ATTRIBUTE attr;
  CK_ULONG uval;

  g_return_if_fail (array);

  uval = value;
  attr.type = type;
  attr.pValue = &uval;
  attr.ulValueLen = sizeof (uval);
  g_pkcs11_array_add (array, &attr);
}

void
g_pkcs11_array_set (GPkcs11Array *array,
                    CK_ATTRIBUTE *attr)
{
  CK_ATTRIBUTE *previous;

  g_return_if_fail (array);
  g_return_if_fail (attr);
  g_return_if_fail (attr->ulValueLen != (CK_ATTRIBUTE_TYPE)-1 || !attr->pValue);
  g_return_if_fail (attr->pValue || !attr->ulValueLen);

  previous = (CK_ATTRIBUTE*)g_pkcs11_array_find (array, attr->type);
  if (previous == NULL)
    {
      g_pkcs11_array_add (array, attr);
    }
  else
    {
      g_free (previous->pValue);
      previous->pValue = g_memdup (attr->pValue, attr->ulValueLen);
      previous->ulValueLen = attr->ulValueLen;
    }
}

void
g_pkcs11_array_set_value (GPkcs11Array      *array,
                          CK_ATTRIBUTE_TYPE  type,
                          gconstpointer      value,
                          gssize              length)
{
  CK_ATTRIBUTE attr;

  g_return_if_fail (array);

  if (length < 0)
    length = strlen (value);

  attr.type = type;
  attr.pValue = (gpointer)value;
  attr.ulValueLen = length;
  g_pkcs11_array_set (array, &attr);
}

void
g_pkcs11_array_set_boolean (GPkcs11Array      *array,
                            CK_ATTRIBUTE_TYPE  attr_type,
                            gboolean           value)
{
  CK_ATTRIBUTE attr;
  CK_BBOOL bval;

  g_return_if_fail (array);

  bval = value ? CK_TRUE : CK_FALSE;
  attr.type = attr_type;
  attr.pValue = &bval;
  attr.ulValueLen = sizeof (bval);
  g_pkcs11_array_set (array, &attr);
}

void
g_pkcs11_array_set_ulong (GPkcs11Array      *array,
                          CK_ATTRIBUTE_TYPE  type,
                          gulong             value)
{
  CK_ATTRIBUTE attr;
  CK_ULONG uval;

  g_return_if_fail (array);

  uval = value;
  attr.type = type;
  attr.pValue = &uval;
  attr.ulValueLen = sizeof (uval);
  g_pkcs11_array_set (array, &attr);
}


const CK_ATTRIBUTE*
g_pkcs11_array_find (GPkcs11Array         *array,
                     CK_ATTRIBUTE_TYPE     type)
{
    const CK_ATTRIBUTE* attr;
    guint i;

    g_return_val_if_fail (array, NULL);

    for (i = 0; i < array->count; ++i)
      {
        attr = &g_pkcs11_array_index (array, i);
        if (attr->type == type)
          return attr;
      }

    return NULL;
}

gboolean
g_pkcs11_array_find_boolean (GPkcs11Array         *array,
                             CK_ATTRIBUTE_TYPE     type,
                             gboolean             *value)
{
  const CK_ATTRIBUTE* attr;

  g_return_val_if_fail (array, FALSE);
  g_return_val_if_fail (value, FALSE);

  attr = g_pkcs11_array_find (array, type);
  if (!attr || !attr->pValue || attr->ulValueLen != sizeof (CK_BBOOL))
    return FALSE;
  *value = *((CK_BBOOL*)attr->pValue) ? TRUE : FALSE;
  return TRUE;
}

gboolean
g_pkcs11_array_find_ulong (GPkcs11Array         *array,
                           CK_ATTRIBUTE_TYPE     type,
                           gulong               *value)
{
  const CK_ATTRIBUTE* attr;

  g_return_val_if_fail (array, FALSE);
  g_return_val_if_fail (value, FALSE);

  attr = g_pkcs11_array_find (array, type);
  if (!attr || !attr->pValue || attr->ulValueLen != sizeof (CK_ULONG))
    return FALSE;
  *value = *((CK_ULONG*)attr->pValue);
  return TRUE;
}

GPkcs11Array*
g_pkcs11_array_ref (GPkcs11Array *array)
{
  GRealPkcs11Array *rarray = (GRealPkcs11Array*) array;

  g_return_val_if_fail (array, NULL);
  g_return_val_if_fail (g_atomic_int_get (&rarray->ref_count) > 0, array);
  g_atomic_int_inc (&rarray->ref_count);
  return array;
}

void
g_pkcs11_array_unref (GPkcs11Array *array)
{
  GRealPkcs11Array *rarray = (GRealPkcs11Array*) array;
  CK_ULONG i;

  g_return_if_fail (array);
  g_return_if_fail (g_atomic_int_get (&rarray->ref_count) > 0);
  if (g_atomic_int_dec_and_test (&rarray->ref_count))
    {
      for (i = 0; i < rarray->len; ++i)
        g_free (rarray->attrs[i].pValue);
      g_free (rarray->attrs);
      g_slice_free1 (sizeof (GRealPkcs11Array), array);
    }
}
