/*
 * gtlsconnection-openssl.h
 *
 * Copyright (C) 2015 NICE s.r.l.
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, when the library is used with OpenSSL, a special
 * exception applies. Refer to the LICENSE_EXCEPTION file for details.
 *
 * Authors: Ignacio Casal Quinteiro
 */

#ifndef __G_TLS_CONNECTION_OPENSSL_H__
#define __G_TLS_CONNECTION_OPENSSL_H__

#include <gio/gio.h>

#include "gtlsconnection-base.h"
#include "openssl-include.h"

G_BEGIN_DECLS

#define G_TYPE_TLS_CONNECTION_OPENSSL            (g_tls_connection_openssl_get_type ())
#define G_TLS_CONNECTION_OPENSSL(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), G_TYPE_TLS_CONNECTION_OPENSSL, GTlsConnectionOpenssl))
#define G_TLS_CONNECTION_OPENSSL_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), G_TYPE_TLS_CONNECTION_OPENSSL, GTlsConnectionOpensslClass))
#define G_IS_TLS_CONNECTION_OPENSSL(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), G_TYPE_TLS_CONNECTION_OPENSSL))
#define G_IS_TLS_CONNECTION_OPENSSL_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), G_TYPE_TLS_CONNECTION_OPENSSL))
#define G_TLS_CONNECTION_OPENSSL_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), G_TYPE_TLS_CONNECTION_OPENSSL, GTlsConnectionOpensslClass))

typedef struct _GTlsConnectionOpensslClass GTlsConnectionOpensslClass;
typedef struct _GTlsConnectionOpenssl      GTlsConnectionOpenssl;

struct _GTlsConnectionOpensslClass
{
  GTlsConnectionBaseClass parent_class;

  SSL     *(*get_ssl)     (GTlsConnectionOpenssl *connection);
  SSL_CTX *(*get_ssl_ctx) (GTlsConnectionOpenssl *connection);
};

struct _GTlsConnectionOpenssl
{
  GTlsConnectionBase parent_instance;
};

GType g_tls_connection_openssl_get_type (void) G_GNUC_CONST;

SSL     *g_tls_connection_openssl_get_ssl     (GTlsConnectionOpenssl *connection);
SSL_CTX *g_tls_connection_openssl_get_ssl_ctx (GTlsConnectionOpenssl *connection);

gboolean g_tls_connection_openssl_request_certificate (GTlsConnectionOpenssl  *openssl,
                                                       GError                **error);

G_END_DECLS

#endif /* __G_TLS_CONNECTION_OPENSSL_H___ */
