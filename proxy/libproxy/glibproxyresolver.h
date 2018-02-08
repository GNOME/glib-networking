/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2010 Collabora, Ltd.
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
 * Author: Nicolas Dufresne <nicolas.dufresne@collabora.co.uk>
 */

#ifndef __G_LIBPROXY_RESOLVER_H__
#define __G_LIBPROXY_RESOLVER_H__

#include <glib-object.h>
#include <gio/gio.h>

G_BEGIN_DECLS

#define G_TYPE_LIBPROXY_RESOLVER         (g_libproxy_resolver_get_type ())
#define G_LIBPROXY_RESOLVER(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), G_TYPE_LIBPROXY_RESOLVER, GLibProxyResolver))
#define G_LIBPROXY_RESOLVER_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST((k), G_TYPE_LIBPROXY_RESOLVER, GLibProxyResolverClass))
#define G_IS_LIBPROXY_RESOLVER(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), G_TYPE_LIBPROXY_RESOLVER))
#define G_IS_LIBPROXY_RESOLVER_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), G_TYPE_LIBPROXY_RESOLVER))
#define G_LIBPROXY_RESOLVER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), G_TYPE_LIBPROXY_RESOLVER, GLibProxyResolverClass))

typedef struct _GLibProxyResolver       GLibProxyResolver;
typedef struct _GLibProxyResolverClass  GLibProxyResolverClass;

struct _GLibProxyResolverClass {
  GObjectClass parent_class;
};

GType g_libproxy_resolver_get_type (void);
void  g_libproxy_resolver_register (GIOModule *module);

G_END_DECLS

#endif /* __G_LIBPROXY_RESOLVER_H__ */
