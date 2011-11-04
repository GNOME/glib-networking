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

#include "gpkcs11slot.h"

#include "gpkcs11array.h"
#include "gpkcs11pin.h"
#include "gpkcs11util.h"

#include <glib/gi18n.h>

#include <p11-kit/p11-kit.h>
#include <p11-kit/pin.h>

#include <stdlib.h>

enum {
  PROP_0,
  PROP_MODULE,
  PROP_SLOT_ID
};

struct _GPkcs11SlotPrivate
{
  /* read-only after construct */
  CK_FUNCTION_LIST_PTR module;
  CK_SLOT_ID slot_id;

  /* protected by mutex */
  GMutex mutex;
  CK_SESSION_HANDLE last_session;
};

G_DEFINE_TYPE (GPkcs11Slot, g_pkcs11_slot, G_TYPE_OBJECT);

static gboolean
check_if_session_logged_in (GPkcs11Slot        *self,
                            CK_SESSION_HANDLE   session)
{
  CK_SESSION_INFO session_info;
  CK_RV rv;

  rv = (self->priv->module->C_GetSessionInfo) (session, &session_info);
  if (rv != CKR_OK)
    return FALSE;

  /* Already logged in */
  if (session_info.state == CKS_RO_USER_FUNCTIONS ||
      session_info.state == CKS_RW_USER_FUNCTIONS)
    return TRUE;

  return FALSE;
}

static gboolean
session_login_protected_auth_path (GPkcs11Slot       *self,
                                   CK_SESSION_HANDLE  session,
                                   GError           **error)
{
  CK_RV rv;

  rv = (self->priv->module->C_Login) (session, CKU_USER, NULL, 0);
  if (rv == CKR_USER_ALREADY_LOGGED_IN)
    rv = CKR_OK;
  if (g_pkcs11_propagate_error (error, rv))
    return FALSE;
  return TRUE;
}

static gboolean
session_login_with_pin (GPkcs11Slot          *self,
                        GTlsInteraction      *interaction,
                        CK_SESSION_HANDLE     session,
                        CK_TOKEN_INFO        *token_info,
                        GTlsPasswordFlags     flags,
                        GCancellable         *cancellable,
                        GError              **error)
{
  GTlsInteractionResult result = G_TLS_INTERACTION_UNHANDLED;
  GTlsPassword *password = NULL;
  const guchar *value;
  gsize length;
  CK_RV rv;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return FALSE;

  else if (interaction != NULL)
    {
      gchar *description = p11_kit_space_strdup (token_info->label,
                                                 sizeof (token_info->label));
      password = g_tls_password_new (flags, description);
      free (description);

      result = g_tls_interaction_ask_password (interaction, password, cancellable, error);
    }

  switch (result)
    {
    case G_TLS_INTERACTION_UNHANDLED:
      g_clear_object (&password);
      g_message ("no pin is available to log in, or the user cancelled pin entry");
      return TRUE;
    case G_TLS_INTERACTION_FAILED:
      g_clear_object (&password);
      return FALSE;
    case G_TLS_INTERACTION_HANDLED:
      break;
    }

  g_assert (interaction != NULL && password != NULL);
  value = g_tls_password_get_value (password, &length);
  rv = (self->priv->module->C_Login) (session, CKU_USER, (CK_UTF8CHAR_PTR)value, length);
  g_object_unref (password);

  if (rv == CKR_USER_ALREADY_LOGGED_IN)
    rv = CKR_OK;
  if (g_pkcs11_propagate_error (error, rv))
    return FALSE;
  return TRUE;
}

static gboolean
session_login_if_necessary (GPkcs11Slot        *self,
                            GTlsInteraction    *interaction,
                            CK_SESSION_HANDLE   session,
                            GCancellable       *cancellable,
                            GError            **error)
{
  CK_TOKEN_INFO token_info;
  GTlsPasswordFlags flags = 0;
  GError *err = NULL;
  CK_RV rv;

  for (;;)
    {
      if (g_cancellable_set_error_if_cancelled (cancellable, error))
        return FALSE;

      /* Do we actually need to login? */
      if (check_if_session_logged_in (self, session))
        return TRUE;

      /* Get the token information, this can change between login attempts */
      rv = (self->priv->module->C_GetTokenInfo) (self->priv->slot_id, &token_info);
      if (g_pkcs11_propagate_error (error, rv))
        return FALSE;

      if (!(token_info.flags & CKF_LOGIN_REQUIRED))
        return TRUE;

      /* Login is not initialized on token, don't try to login */
      if (!(token_info.flags & CKF_USER_PIN_INITIALIZED))
        return TRUE;

      /* Protected auth path, only call login once, and let token prompt user */
      if (token_info.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
        return session_login_protected_auth_path (self, session, error);

      /* Normal authentication path, ask p11-kit to call any callbacks */
      else
        {

          if (token_info.flags & CKF_SO_PIN_COUNT_LOW)
            flags |= G_TLS_PASSWORD_MANY_TRIES;
          if (token_info.flags & CKF_SO_PIN_FINAL_TRY)
            flags |= G_TLS_PASSWORD_FINAL_TRY;

          if (session_login_with_pin (self, interaction, session, &token_info,
                                      flags, cancellable, &err))
            return TRUE;

          /* User cancelled, don't try to log in */
          if (err == NULL)
            return TRUE;

          if (!g_error_matches (err, G_PKCS11_ERROR, CKR_PIN_INCORRECT))
            {
              g_propagate_error (error, err);
              return FALSE;
            }

          /* Try again */
          g_clear_error (&err);
          flags |= G_TLS_PASSWORD_RETRY;
        }
    }
}

static CK_SESSION_HANDLE
session_checkout_or_open (GPkcs11Slot     *self,
                          GTlsInteraction *interaction,
                          gboolean         login,
                          GCancellable    *cancellable,
                          GError         **error)
{
  CK_SESSION_HANDLE session = 0;
  CK_RV rv;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return 0;

  g_mutex_lock (&self->priv->mutex);

  if (self->priv->last_session)
    {
      session = self->priv->last_session;
      self->priv->last_session = 0;
    }

  g_mutex_unlock (&self->priv->mutex);

  if (!session)
    {
      rv = (self->priv->module->C_OpenSession) (self->priv->slot_id, CKF_SERIAL_SESSION,
                                                NULL, NULL, &session);
      if (g_pkcs11_propagate_error (error, rv))
        return 0;
    }

  if (login)
    {
      if (!session_login_if_necessary (self, interaction, session, cancellable, error))
        {
          (self->priv->module->C_CloseSession) (session);
          return 0;
        }
    }

  return session;
}

static void
session_close (GPkcs11Slot       *self,
               CK_SESSION_HANDLE   session)
{
  CK_RV rv;

  g_assert (session != 0);

  rv = (self->priv->module->C_CloseSession) (session);
  if (rv != CKR_OK)
    g_warning ("couldn't close pkcs11 session: %s",
               p11_kit_strerror (rv));
}

static void
session_checkin_or_close (GPkcs11Slot      *self,
                          CK_SESSION_HANDLE  session)
{
  g_assert (session != 0);

  g_mutex_lock (&self->priv->mutex);

  if (self->priv->last_session == 0)
    {
      self->priv->last_session = session;
      session = 0;
    }

  g_mutex_unlock (&self->priv->mutex);

  if (session != 0)
    session_close (self, session);
}

static GPkcs11Array*
retrieve_object_attributes (GPkcs11Slot              *self,
                            CK_SESSION_HANDLE         session,
                            CK_OBJECT_HANDLE          object,
                            const CK_ATTRIBUTE_TYPE  *attr_types,
                            guint                     attr_types_length,
                            GError                  **error)
{
  GPkcs11Array *result;
  CK_ATTRIBUTE_PTR attr;
  CK_ATTRIBUTE blank;
  CK_RV rv;
  guint i;

  result = g_pkcs11_array_new ();
  memset (&blank, 0, sizeof (blank));
  for (i = 0; i < attr_types_length; ++i)
    {
      blank.type = attr_types[i];
      g_pkcs11_array_add (result, &blank);
    }

  /* Get all the required buffer sizes */
  rv = (self->priv->module->C_GetAttributeValue) (session, object,
                                                  result->attrs, result->count);
  if (rv == CKR_ATTRIBUTE_SENSITIVE ||
      rv == CKR_ATTRIBUTE_TYPE_INVALID)
    rv = CKR_OK;
  if (g_pkcs11_propagate_error (error, rv))
    {
      g_pkcs11_array_unref (result);
      return NULL;
    }

  /* Now allocate memory for them all */
  for (i = 0; i < attr_types_length; ++i)
    {
      attr = &g_pkcs11_array_index (result, i);
      if (attr->ulValueLen != (CK_ULONG)-1 && attr->ulValueLen)
          attr->pValue = g_malloc0 (attr->ulValueLen);
    }

  /* And finally get all the values */
  rv = (self->priv->module->C_GetAttributeValue) (session, object,
                                                  result->attrs, result->count);
  if (rv == CKR_ATTRIBUTE_SENSITIVE ||
      rv == CKR_ATTRIBUTE_TYPE_INVALID ||
      rv == CKR_BUFFER_TOO_SMALL)
    rv = CKR_OK;
  if (g_pkcs11_propagate_error (error, rv))
    {
      g_pkcs11_array_unref (result);
      return NULL;
    }

  return result;
}

static void
g_pkcs11_slot_init (GPkcs11Slot *self)
{
  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
                                            G_TYPE_PKCS11_SLOT,
                                            GPkcs11SlotPrivate);
  g_mutex_init (&self->priv->mutex);
}

static void
g_pkcs11_slot_dispose (GObject *object)
{
  GPkcs11Slot *self = G_PKCS11_SLOT (object);
  CK_SESSION_HANDLE session = 0;

  g_mutex_lock (&self->priv->mutex);

  session = self->priv->last_session;
  self->priv->last_session = 0;

  g_mutex_unlock (&self->priv->mutex);

  if (session)
    session_close (self, session);

  G_OBJECT_CLASS (g_pkcs11_slot_parent_class)->dispose (object);
}

static void
g_pkcs11_slot_finalize (GObject *object)
{
  GPkcs11Slot *self = G_PKCS11_SLOT (object);

  g_assert (self->priv->last_session == 0);
  g_mutex_clear (&self->priv->mutex);

  G_OBJECT_CLASS (g_pkcs11_slot_parent_class)->finalize (object);
}

static void
g_pkcs11_slot_get_property (GObject    *object,
                             guint       prop_id,
                             GValue     *value,
                             GParamSpec *pspec)
{
  GPkcs11Slot *self = G_PKCS11_SLOT (object);

  switch (prop_id)
    {
    case PROP_MODULE:
      g_value_set_pointer (value, self->priv->module);
      break;

    case PROP_SLOT_ID:
      g_value_set_ulong (value, self->priv->slot_id);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_pkcs11_slot_set_property (GObject      *object,
                             guint         prop_id,
                             const GValue *value,
                             GParamSpec   *pspec)
{
  GPkcs11Slot *self = G_PKCS11_SLOT (object);

  switch (prop_id)
    {
    case PROP_MODULE:
      self->priv->module = g_value_get_pointer (value);
      g_assert (self->priv->module);
      break;

    case PROP_SLOT_ID:
      self->priv->slot_id = g_value_get_ulong (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_pkcs11_slot_class_init (GPkcs11SlotClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GPkcs11SlotPrivate));

  gobject_class->get_property = g_pkcs11_slot_get_property;
  gobject_class->set_property = g_pkcs11_slot_set_property;
  gobject_class->dispose      = g_pkcs11_slot_dispose;
  gobject_class->finalize     = g_pkcs11_slot_finalize;

  g_object_class_install_property (gobject_class, PROP_MODULE,
                                   g_param_spec_pointer ("module",
                                                         N_("Module"),
                                                         N_("PKCS#11 Module Pointer"),
                                                         G_PARAM_READWRITE |
                                                         G_PARAM_CONSTRUCT |
                                                         G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_SLOT_ID,
                                   g_param_spec_ulong ("slot-id",
                                                         N_("Slot ID"),
                                                         N_("PKCS#11 Slot Identifier"),
                                                         0,
                                                         G_MAXULONG,
                                                         G_MAXULONG,
                                                         G_PARAM_READWRITE |
                                                         G_PARAM_CONSTRUCT |
                                                         G_PARAM_STATIC_STRINGS));
}

GPkcs11EnumerateState
g_pkcs11_slot_enumerate (GPkcs11Slot             *self,
                         GTlsInteraction         *interaction,
                         CK_ATTRIBUTE_PTR         match,
                         CK_ULONG                 match_count,
                         gboolean                 match_private,
                         const CK_ATTRIBUTE_TYPE *attr_types,
                         guint                    attr_types_length,
                         GPkcs11Accumulator       accumulator,
                         gpointer                 user_data,
                         GCancellable            *cancellable,
                         GError                 **error)
{
  GPkcs11EnumerateState state = G_PKCS11_ENUMERATE_CONTINUE;
  CK_OBJECT_HANDLE objects[256];
  CK_SESSION_HANDLE session;
  GPkcs11Array *attrs;
  GError *err = NULL;
  CK_ULONG count, i;
  CK_RV rv;

  g_return_val_if_fail (G_IS_PKCS11_SLOT (self), FALSE);
  g_return_val_if_fail (accumulator, FALSE);
  g_return_val_if_fail (!error || !*error, FALSE);

  session = session_checkout_or_open (self, interaction, match_private,
                                      cancellable, &err);
  if (err != NULL)
    {
      /* If the slot isn't present, then nothing to match :) */
      if (g_error_matches (err, G_PKCS11_ERROR, CKR_TOKEN_NOT_PRESENT))
        {
          g_clear_error (&err);
          return G_PKCS11_ENUMERATE_CONTINUE;
        }

      g_propagate_error (error, err);
      return G_PKCS11_ENUMERATE_FAILED;
    }

  rv = (self->priv->module->C_FindObjectsInit) (session, match, match_count);

  while (state == G_PKCS11_ENUMERATE_CONTINUE && rv == CKR_OK &&
         !g_cancellable_is_cancelled (cancellable))
    {
      count = 0;
      rv = (self->priv->module->C_FindObjects) (session, objects,
                                                G_N_ELEMENTS (objects), &count);
      if (rv == CKR_OK)
        {
          if (count == 0)
            break;

          for (i = 0; state == G_PKCS11_ENUMERATE_CONTINUE && i < count; ++i)
            {
              if (attr_types_length)
                {
                  attrs = retrieve_object_attributes (self, session, objects[i],
                                                  attr_types, attr_types_length, error);
                  if (attrs == NULL)
                      state = G_PKCS11_ENUMERATE_FAILED;
                }
              else
                {
                  attrs = NULL;
                }

              if (state == G_PKCS11_ENUMERATE_CONTINUE)
                {
                  if (!(accumulator) (attrs, user_data))
                    state = G_PKCS11_ENUMERATE_STOP;
                }

              if (attrs)
                g_pkcs11_array_unref (attrs);

              if (g_cancellable_is_cancelled (cancellable))
                break;
            }
        }
    }

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    {
      state = G_PKCS11_ENUMERATE_FAILED;
    }
  else if (rv != CKR_OK && rv != CKR_TOKEN_NOT_PRESENT)
    {
      g_pkcs11_propagate_error (error, rv);
      state = G_PKCS11_ENUMERATE_FAILED;
    }

  rv = (self->priv->module->C_FindObjectsFinal) (session);
  if (rv == CKR_OK)
    session_checkin_or_close (self, session);
  else
    session_close (self, session);

  return state;
}

gboolean
g_pkcs11_slot_get_token_info (GPkcs11Slot       *self,
                              CK_TOKEN_INFO_PTR  token_info)
{
  CK_RV rv;

  g_return_val_if_fail (G_IS_PKCS11_SLOT (self), FALSE);
  g_return_val_if_fail (token_info, FALSE);

  memset (token_info, 0, sizeof (CK_TOKEN_INFO));
  rv = (self->priv->module->C_GetTokenInfo) (self->priv->slot_id, token_info);
  if (rv == CKR_TOKEN_NOT_PRESENT)
    return FALSE;

  if (rv != CKR_OK)
    {
      g_warning ("call to C_GetTokenInfo on PKCS#11 module failed: %s",
                 p11_kit_strerror (rv));
      return FALSE;
    }

  return TRUE;
}

gboolean
g_pkcs11_slot_matches_uri (GPkcs11Slot            *self,
                           P11KitUri              *uri)
{
  CK_INFO library;
  CK_TOKEN_INFO token;
  CK_RV rv;

  g_return_val_if_fail (G_IS_PKCS11_SLOT (self), FALSE);
  g_return_val_if_fail (uri, FALSE);

  memset (&library, 0, sizeof (library));
  rv = (self->priv->module->C_GetInfo) (&library);
  if (rv != CKR_OK)
    {
      g_warning ("call to C_GetInfo on PKCS#11 module failed: %s",
                 p11_kit_strerror (rv));
      return FALSE;
    }

  if (!p11_kit_uri_match_module_info (uri, &library))
    return FALSE;

  memset (&token, 0, sizeof (token));
  if (!g_pkcs11_slot_get_token_info (self, &token))
    return FALSE;

  return p11_kit_uri_match_token_info (uri, &token);
}
