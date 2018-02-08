/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
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

struct _GPkcs11Pin
{
  GTlsPassword parent_instance;

  P11KitPin *pin;
};

G_DEFINE_TYPE (GPkcs11Pin, g_pkcs11_pin, G_TYPE_TLS_PASSWORD);

static void
g_pkcs11_pin_init (GPkcs11Pin *self)
{
}

static void
g_pkcs11_pin_finalize (GObject *object)
{
  GPkcs11Pin *self = G_PKCS11_PIN (object);

  if (self->pin)
    p11_kit_pin_unref (self->pin);

  G_OBJECT_CLASS (g_pkcs11_pin_parent_class)->finalize (object);
}

static const guchar *
g_pkcs11_pin_get_value (GTlsPassword  *password,
                        gsize         *length)
{
  GPkcs11Pin *self = G_PKCS11_PIN (password);

  if (!self->pin)
    {
      if (length)
        *length = 0;
      return NULL;
    }

  return p11_kit_pin_get_value (self->pin, length);
}

static void
g_pkcs11_pin_set_value (GTlsPassword  *password,
                        guchar        *value,
                        gssize         length,
                        GDestroyNotify destroy)
{
  GPkcs11Pin *self = G_PKCS11_PIN (password);

  if (self->pin)
    {
      p11_kit_pin_unref (self->pin);
      self->pin = NULL;
    }

  if (length < 0)
    length = strlen ((gchar *) value);

  self->pin = p11_kit_pin_new_for_buffer (value, length, destroy);
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

  pin = self->pin;
  self->pin = NULL;
  return pin;
}
