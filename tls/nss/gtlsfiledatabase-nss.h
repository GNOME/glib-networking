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

#ifndef __G_TLS_FILE_DATABASE_NSS_H__
#define __G_TLS_FILE_DATABASE_NSS_H__

#include <gio/gio.h>

#include "gtlsdatabase-nss.h"

G_BEGIN_DECLS

#define G_TYPE_TLS_FILE_DATABASE_NSS            (g_tls_file_database_nss_get_type ())
#define G_TLS_FILE_DATABASE_NSS(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), G_TYPE_TLS_FILE_DATABASE_NSS, GTlsFileDatabaseNss))
#define G_TLS_FILE_DATABASE_NSS_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), G_TYPE_TLS_FILE_DATABASE_NSS, GTlsFileDatabaseNssClass))
#define G_IS_TLS_FILE_DATABASE_NSS(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), G_TYPE_TLS_FILE_DATABASE_NSS))
#define G_IS_TLS_FILE_DATABASE_NSS_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), G_TYPE_TLS_FILE_DATABASE_NSS))
#define G_TLS_FILE_DATABASE_NSS_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), G_TYPE_TLS_FILE_DATABASE_NSS, GTlsFileDatabaseNssClass))

typedef struct _GTlsFileDatabaseNssPrivate                   GTlsFileDatabaseNssPrivate;
typedef struct _GTlsFileDatabaseNssClass                     GTlsFileDatabaseNssClass;
typedef struct _GTlsFileDatabaseNss                          GTlsFileDatabaseNss;

struct _GTlsFileDatabaseNssClass
{
  GTlsDatabaseNssClass parent_class;
};

struct _GTlsFileDatabaseNss
{
  GTlsDatabaseNss parent_instance;
  GTlsFileDatabaseNssPrivate *priv;
};

GType g_tls_file_database_nss_get_type (void) G_GNUC_CONST;

gboolean g_tls_file_database_nss_contains (GTlsFileDatabaseNss *nss,
					   GTlsCertificateNss  *nss_cert);

G_END_DECLS

#endif /* __G_TLS_FILE_DATABASE_NSS_H___ */
