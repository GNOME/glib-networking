/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2011 Red Hat, Inc..
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 */

#ifndef __G_TLS_DATABASE_NSS_H__
#define __G_TLS_DATABASE_NSS_H__

#include <gio/gio.h>
#include <cert.h>

#include "gtlscertificate-nss.h"

G_BEGIN_DECLS

#define G_TYPE_TLS_DATABASE_NSS            (g_tls_database_nss_get_type ())
#define G_TLS_DATABASE_NSS(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), G_TYPE_TLS_DATABASE_NSS, GTlsDatabaseNss))
#define G_TLS_DATABASE_NSS_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), G_TYPE_TLS_DATABASE_NSS, GTlsDatabaseNssClass))
#define G_IS_TLS_DATABASE_NSS(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), G_TYPE_TLS_DATABASE_NSS))
#define G_IS_TLS_DATABASE_NSS_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), G_TYPE_TLS_DATABASE_NSS))
#define G_TLS_DATABASE_NSS_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), G_TYPE_TLS_DATABASE_NSS, GTlsDatabaseNssClass))

typedef struct _GTlsDatabaseNssPrivate                   GTlsDatabaseNssPrivate;
typedef struct _GTlsDatabaseNssClass                     GTlsDatabaseNssClass;
typedef struct _GTlsDatabaseNss                          GTlsDatabaseNss;

struct _GTlsDatabaseNssClass
{
  GTlsDatabaseClass parent_class;

};

struct _GTlsDatabaseNss
{
  GTlsDatabase parent_instance;
  GTlsDatabaseNssPrivate *priv;
};

GType g_tls_database_nss_get_type (void) G_GNUC_CONST;

GTlsCertificateNss *g_tls_database_nss_get_gcert       (GTlsDatabaseNss    *nss,
							CERTCertificate    *cert,
							gboolean            create);
void                g_tls_database_nss_gcert_created   (GTlsDatabaseNss    *nss,
							CERTCertificate    *cert,
							GTlsCertificateNss *gcert);

void                g_tls_database_nss_gcert_destroyed (GTlsDatabaseNss    *nss,
							CERTCertificate    *cert);

G_END_DECLS

#endif /* __G_TLS_DATABASE_NSS_H___ */
