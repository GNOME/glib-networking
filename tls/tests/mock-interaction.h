/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
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

#include <gio/gio.h>

#ifndef __MOCK_INTERACTION_H__
#define __MOCK_INTERACTION_H__

G_BEGIN_DECLS

#define MOCK_TYPE_INTERACTION         (mock_interaction_get_type ())
#define MOCK_INTERACTION(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), MOCK_TYPE_INTERACTION, MockInteraction))
#define MOCK_INTERACTION_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST((k), MOCK_TYPE_INTERACTION, MockInteractionClass))
#define MOCK_IS_INTERACTION(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), MOCK_TYPE_INTERACTION))
#define MOCK_IS_INTERACTION_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), MOCK_TYPE_INTERACTION))
#define MOCK_INTERACTION_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), MOCK_TYPE_INTERACTION, MockInteractionClass))

typedef struct _MockInteraction         MockInteraction;
typedef struct _MockInteractionClass    MockInteractionClass;

struct _MockInteraction
{
  GTlsInteraction parent_instance;
  gchar *static_password;
};

struct _MockInteractionClass
{
  GTlsInteractionClass parent_class;
};


GType            mock_interaction_get_type   (void);
GTlsInteraction *mock_interaction_new_static       (const gchar *password);

G_END_DECLS

#endif /* __MOCK_INTERACTION_H__ */
