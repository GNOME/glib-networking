/* GIO - GLib Certificate, Output and Gnutlsing Library
 *
 * Copyright 2011 Collabora, Ltd.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#ifndef __G_TLS_DATABASE_GNUTLS_PKCS11_H__
#define __G_TLS_DATABASE_GNUTLS_PKCS11_H__

#include <gio/gio.h>

#include "gtlsdatabase-gnutls.h"

G_BEGIN_DECLS

#define G_TYPE_TLS_DATABASE_GNUTLS_PKCS11            (g_tls_database_gnutls_pkcs11_get_type ())
#define G_TLS_DATABASE_GNUTLS_PKCS11(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), G_TYPE_TLS_DATABASE_GNUTLS_PKCS11, GTlsDatabaseGnutlsPkcs11))
#define G_TLS_DATABASE_GNUTLS_PKCS11_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), G_TYPE_TLS_DATABASE_GNUTLS_PKCS11, GTlsDatabaseGnutlsPkcs11Class))
#define G_IS_TLS_DATABASE_GNUTLS_PKCS11(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), G_TYPE_TLS_DATABASE_GNUTLS_PKCS11))
#define G_IS_TLS_DATABASE_GNUTLS_PKCS11_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), G_TYPE_TLS_DATABASE_GNUTLS_PKCS11))
#define G_TLS_DATABASE_GNUTLS_PKCS11_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), G_TYPE_TLS_DATABASE_GNUTLS_PKCS11, GTlsDatabaseGnutlsPkcs11Class))

typedef struct _GTlsDatabaseGnutlsPkcs11Private                   GTlsDatabaseGnutlsPkcs11Private;
typedef struct _GTlsDatabaseGnutlsPkcs11Class                     GTlsDatabaseGnutlsPkcs11Class;
typedef struct _GTlsDatabaseGnutlsPkcs11                          GTlsDatabaseGnutlsPkcs11;

struct _GTlsDatabaseGnutlsPkcs11Class
{
  GTlsDatabaseGnutlsClass parent_class;
};

struct _GTlsDatabaseGnutlsPkcs11
{
  GTlsDatabaseGnutls parent_instance;
  GTlsDatabaseGnutlsPkcs11Private *priv;
};

GType                        g_tls_database_gnutls_pkcs11_get_type              (void) G_GNUC_CONST;

GTlsDatabase*                g_tls_database_gnutls_pkcs11_new                   (GError **error);

G_END_DECLS

#endif /* __G_TLS_DATABASE_GNUTLS_PKCS11_H___ */
