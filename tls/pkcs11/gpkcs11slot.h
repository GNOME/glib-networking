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
#define G_PKCS11_SLOT(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), G_TYPE_PKCS11_SLOT, GPkcs11Slot))
#define G_PKCS11_SLOT_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), G_TYPE_PKCS11_SLOT, GPkcs11SlotClass))
#define G_IS_PKCS11_SLOT(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), G_TYPE_PKCS11_SLOT))
#define G_IS_PKCS11_SLOT_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), G_TYPE_PKCS11_SLOT))
#define G_PKCS11_SLOT_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), G_TYPE_PKCS11_SLOT, GPkcs11SlotClass))

typedef struct _GPkcs11SlotPrivate                   GPkcs11SlotPrivate;
typedef struct _GPkcs11SlotClass                     GPkcs11SlotClass;
typedef struct _GPkcs11Slot                          GPkcs11Slot;

struct _GPkcs11SlotClass
{
  GObjectClass parent_class;
};

struct _GPkcs11Slot
{
  GObject parent_instance;
  GPkcs11SlotPrivate *priv;
};

typedef gboolean             (*GPkcs11Accumulator)            (gpointer result,
                                                               gpointer user_data);

GType                        g_pkcs11_slot_get_type           (void) G_GNUC_CONST;

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
