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

#ifndef __G_TLS_CLIENT_CONNECTION_NSS_H__
#define __G_TLS_CLIENT_CONNECTION_NSS_H__

#include "gtlsconnection-nss.h"
#include <ssl.h>

G_BEGIN_DECLS

#define G_TYPE_TLS_CLIENT_CONNECTION_NSS            (g_tls_client_connection_nss_get_type ())
#define G_TLS_CLIENT_CONNECTION_NSS(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), G_TYPE_TLS_CLIENT_CONNECTION_NSS, GTlsClientConnectionNss))
#define G_TLS_CLIENT_CONNECTION_NSS_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), G_TYPE_TLS_CLIENT_CONNECTION_NSS, GTlsClientConnectionNssClass))
#define G_IS_TLS_CLIENT_CONNECTION_NSS(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), G_TYPE_TLS_CLIENT_CONNECTION_NSS))
#define G_IS_TLS_CLIENT_CONNECTION_NSS_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), G_TYPE_TLS_CLIENT_CONNECTION_NSS))
#define G_TLS_CLIENT_CONNECTION_NSS_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), G_TYPE_TLS_CLIENT_CONNECTION_NSS, GTlsClientConnectionNssClass))

typedef struct _GTlsClientConnectionNssPrivate GTlsClientConnectionNssPrivate;
typedef struct _GTlsClientConnectionNssClass   GTlsClientConnectionNssClass;
typedef struct _GTlsClientConnectionNss        GTlsClientConnectionNss;

struct _GTlsClientConnectionNssClass
{
  GTlsConnectionNssClass parent_class;
};

struct _GTlsClientConnectionNss
{
  GTlsConnectionNss parent_instance;
  GTlsClientConnectionNssPrivate *priv;
};

GType g_tls_client_connection_nss_get_type (void) G_GNUC_CONST;

G_END_DECLS

#endif /* __G_TLS_CLIENT_CONNECTION_NSS_H___ */
