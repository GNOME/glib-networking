/* GIO - GLib Pin, Output and Pkcs11ing Library
 *
 * Copyright © 2011 Collabora Ltd.
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

#ifndef __G_PKCS11_PIN_H__
#define __G_PKCS11_PIN_H__

#include <gio/gio.h>
#include <p11-kit/pin.h>

G_BEGIN_DECLS

#define G_TYPE_PKCS11_PIN            (g_pkcs11_pin_get_type ())
#define G_PKCS11_PIN(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), G_TYPE_PKCS11_PIN, GPkcs11Pin))
#define G_PKCS11_PIN_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), G_TYPE_PKCS11_PIN, GPkcs11PinClass))
#define G_IS_PKCS11_PIN(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), G_TYPE_PKCS11_PIN))
#define G_IS_PKCS11_PIN_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), G_TYPE_PKCS11_PIN))
#define G_PKCS11_PIN_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), G_TYPE_PKCS11_PIN, GPkcs11PinClass))

typedef struct _GPkcs11PinPrivate                   GPkcs11PinPrivate;
typedef struct _GPkcs11PinClass                     GPkcs11PinClass;
typedef struct _GPkcs11Pin                          GPkcs11Pin;

struct _GPkcs11PinClass
{
  GTlsPasswordClass parent_class;
};

struct _GPkcs11Pin
{
  GTlsPassword parent_instance;
  GPkcs11PinPrivate *priv;
};

GType                   g_pkcs11_pin_get_type        (void) G_GNUC_CONST;

GTlsPassword *          g_pkcs11_pin_new             (GTlsPasswordFlags  flags,
                                                      const gchar       *description);

P11KitPin *             g_pkcs11_pin_steal_internal  (GPkcs11Pin  *self);

G_END_DECLS

#endif /* __G_PKCS11_PIN_H___ */
