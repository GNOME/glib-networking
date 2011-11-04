/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright © 2011 Collabora Ltd.
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

#include <string.h>

#include "gpkcs11pin.h"
#include <glib/gi18n-lib.h>

enum
{
  PROP_0,

  PROP_FLAGS,
  PROP_DESCRIPTION
};

G_DEFINE_TYPE (GPkcs11Pin, g_pkcs11_pin, G_TYPE_TLS_PASSWORD);

struct _GPkcs11PinPrivate
{
  P11KitPin *pin;
};

static void
g_pkcs11_pin_init (GPkcs11Pin *self)
{
  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
                                            G_TYPE_PKCS11_PIN,
                                            GPkcs11PinPrivate);
}

static void
g_pkcs11_pin_finalize (GObject *object)
{
  GPkcs11Pin *self = G_PKCS11_PIN (object);

  if (self->priv->pin)
    p11_kit_pin_unref (self->priv->pin);

  G_OBJECT_CLASS (g_pkcs11_pin_parent_class)->finalize (object);
}

static const guchar *
g_pkcs11_pin_get_value (GTlsPassword  *password,
                        gsize         *length)
{
  GPkcs11Pin *self = G_PKCS11_PIN (password);

  if (!self->priv->pin)
    {
      if (length)
        *length = 0;
      return NULL;
    }

  return p11_kit_pin_get_value (self->priv->pin, length);
}

static void
g_pkcs11_pin_set_value (GTlsPassword  *password,
                        guchar        *value,
                        gssize         length,
                        GDestroyNotify destroy)
{
  GPkcs11Pin *self = G_PKCS11_PIN (password);

  if (self->priv->pin)
    {
      p11_kit_pin_unref (self->priv->pin);
      self->priv->pin = NULL;
    }

  if (length < 0)
    length = strlen ((gchar *) value);

  self->priv->pin = p11_kit_pin_new_for_buffer (value, length, destroy);
}

static const gchar *
g_pkcs11_pin_get_default_warning (GTlsPassword  *password)
{
  GTlsPasswordFlags flags;

  flags = g_tls_password_get_flags (password);

  if (flags & G_TLS_PASSWORD_FINAL_TRY)
    return _("This is the last chance to enter the PIN correctly before the token is locked.");
  if (flags & G_TLS_PASSWORD_MANY_TRIES)
    return _("Several PIN attempts have been incorrect, and the token will be locked after further failures.");
  if (flags & G_TLS_PASSWORD_RETRY)
    return _("The PIN entered is incorrect.");

  return NULL;
}


static void
g_pkcs11_pin_class_init (GPkcs11PinClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsPasswordClass *password_class = G_TLS_PASSWORD_CLASS (klass);

  password_class->get_value = g_pkcs11_pin_get_value;
  password_class->set_value = g_pkcs11_pin_set_value;
  password_class->get_default_warning = g_pkcs11_pin_get_default_warning;

  gobject_class->finalize     = g_pkcs11_pin_finalize;

  g_type_class_add_private (klass, sizeof (GPkcs11PinPrivate));
}

GTlsPassword *
g_pkcs11_pin_new (GTlsPasswordFlags  flags,
                  const gchar       *description)
{
  GPkcs11Pin *self;

  self = g_object_new (G_TYPE_PKCS11_PIN,
                       "flags", flags,
                       "description", description,
                       NULL);

  return G_TLS_PASSWORD (self);
}


P11KitPin *
g_pkcs11_pin_steal_internal (GPkcs11Pin  *self)
{
  P11KitPin *pin;

  g_return_val_if_fail (G_IS_PKCS11_PIN (self), NULL);

  pin = self->priv->pin;
  self->priv->pin = NULL;
  return pin;
}
