/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * Copyright (C) 2011 Collabora Ltd.
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

G_DECLARE_FINAL_TYPE (MockInteraction, mock_interaction, MOCK, INTERACTION, GTlsInteraction)

GTlsInteraction *mock_interaction_new_static_password       (const gchar *password);

GTlsInteraction *mock_interaction_new_static_certificate    (GTlsCertificate *cert);

GTlsInteraction *mock_interaction_new_static_error          (GQuark domain,
                                                             gint code,
                                                             const gchar *message);

G_END_DECLS

#endif /* __MOCK_INTERACTION_H__ */
