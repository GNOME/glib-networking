/*
 * Copyright (C) 2011 Collabora Ltd.
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include <string.h>
#include <gio/gio.h>

#include "mock-interaction.h"

G_DEFINE_TYPE (MockInteraction, mock_interaction, G_TYPE_TLS_INTERACTION);

static void
on_cancellable_cancelled (GCancellable *cancellable,
                          gpointer user_data)
{
  GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
  GError *error = NULL;
  if (!g_cancellable_set_error_if_cancelled (cancellable, &error))
    g_assert_not_reached ();
  g_simple_async_result_take_error (res, error);
}

static void
mock_interaction_ask_password_async (GTlsInteraction    *interaction,
                                     GTlsPassword       *password,
                                     GCancellable       *cancellable,
                                     GAsyncReadyCallback callback,
                                     gpointer            user_data)
{
  MockInteraction *self = MOCK_INTERACTION (interaction);
  GSimpleAsyncResult *res;

  res = g_simple_async_result_new (G_OBJECT (interaction), callback, user_data,
                                   mock_interaction_ask_password_async);

  if (cancellable)
    g_cancellable_connect (cancellable,
                           G_CALLBACK (on_cancellable_cancelled),
                           g_object_ref (res),
                           g_object_unref);

  g_tls_password_set_value (password, (const guchar *)self->static_password, -1);
  g_simple_async_result_complete_in_idle (res);
}

static GTlsInteractionResult
mock_interaction_ask_password_finish (GTlsInteraction    *interaction,
                                      GAsyncResult       *result,
                                      GError            **error)
{
  g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (interaction),
                                                        mock_interaction_ask_password_async),
                                                        G_TLS_INTERACTION_UNHANDLED);

  if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
    return G_TLS_INTERACTION_FAILED;

  return G_TLS_INTERACTION_HANDLED;
}

static GTlsInteractionResult
mock_interaction_ask_password (GTlsInteraction    *interaction,
                               GTlsPassword       *password,
                               GCancellable       *cancellable,
                               GError            **error)
{
  MockInteraction *self = MOCK_INTERACTION (interaction);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return G_TLS_INTERACTION_FAILED;

  g_tls_password_set_value (password, (const guchar *)self->static_password, -1);
  return G_TLS_INTERACTION_HANDLED;
}

static void
mock_interaction_init (MockInteraction *self)
{

}

static void
mock_interaction_finalize (GObject *object)
{
  MockInteraction *self = MOCK_INTERACTION (object);

  g_free (self->static_password);

  G_OBJECT_CLASS (mock_interaction_parent_class)->finalize (object);
}

static void
mock_interaction_class_init (MockInteractionClass *klass)
{
  GObjectClass         *object_class = G_OBJECT_CLASS (klass);
  GTlsInteractionClass *interaction_class = G_TLS_INTERACTION_CLASS (klass);

  object_class->finalize     = mock_interaction_finalize;

  interaction_class->ask_password = mock_interaction_ask_password;
  interaction_class->ask_password_async = mock_interaction_ask_password_async;
  interaction_class->ask_password_finish = mock_interaction_ask_password_finish;

}

GTlsInteraction *
mock_interaction_new_static (const gchar *password)
{
  MockInteraction *self;

  self = g_object_new (MOCK_TYPE_INTERACTION, NULL);

  self->static_password = g_strdup (password);
  return G_TLS_INTERACTION (self);
}
