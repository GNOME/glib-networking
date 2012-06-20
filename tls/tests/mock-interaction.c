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
mock_interaction_ask_password_async (GTlsInteraction    *interaction,
                                     GTlsPassword       *password,
                                     GCancellable       *cancellable,
                                     GAsyncReadyCallback callback,
                                     gpointer            user_data)
{
  MockInteraction *self = MOCK_INTERACTION (interaction);
  GTask *task;

  task = g_task_new (interaction, cancellable, callback, user_data);

  g_tls_password_set_value (password, (const guchar *)self->static_password, -1);
  g_task_return_boolean (task, TRUE);
}

static GTlsInteractionResult
mock_interaction_ask_password_finish (GTlsInteraction    *interaction,
                                      GAsyncResult       *result,
                                      GError            **error)
{
  g_return_val_if_fail (g_task_is_valid (result, interaction),
			G_TLS_INTERACTION_UNHANDLED);

  if (g_task_had_error (G_TASK (result)))
    {
      g_task_propagate_boolean (G_TASK (result), error);
      return G_TLS_INTERACTION_FAILED;
    }
  else
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
