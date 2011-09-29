/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2011 Red Hat, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 */

#ifndef __G_TLS_BACKEND_NSS_H__
#define __G_TLS_BACKEND_NSS_H__

#include <gio/gio.h>

#include "gtlsdatabase-nss.h"

G_BEGIN_DECLS

#define G_TYPE_TLS_BACKEND_NSS            (g_tls_backend_nss_get_type ())
#define G_TLS_BACKEND_NSS(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), G_TYPE_TLS_BACKEND_NSS, GTlsBackendNss))
#define G_TLS_BACKEND_NSS_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), G_TYPE_TLS_BACKEND_NSS, GTlsBackendNssClass))
#define G_IS_TLS_BACKEND_NSS(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), G_TYPE_TLS_BACKEND_NSS))
#define G_IS_TLS_BACKEND_NSS_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), G_TYPE_TLS_BACKEND_NSS))
#define G_TLS_BACKEND_NSS_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), G_TYPE_TLS_BACKEND_NSS, GTlsBackendNssClass))

typedef struct _GTlsBackendNss        GTlsBackendNss;
typedef struct _GTlsBackendNssClass   GTlsBackendNssClass;
typedef struct _GTlsBackendNssPrivate GTlsBackendNssPrivate;

struct _GTlsBackendNssClass
{
  GObjectClass parent_class;
};

struct _GTlsBackendNss
{
  GObject parent_instance;
  GTlsBackendNssPrivate *priv;
};

GType g_tls_backend_nss_get_type (void) G_GNUC_CONST;
void  g_tls_backend_nss_register (GIOModule *module);

extern GTlsDatabaseNss *g_tls_backend_nss_default_database;
extern CERTCertDBHandle *g_tls_backend_nss_certdbhandle;
extern PK11SlotInfo *g_tls_backend_nss_pem_slot;

G_END_DECLS

#endif /* __G_TLS_BACKEND_NSS_H___ */
