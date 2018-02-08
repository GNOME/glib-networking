/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Backend, Output and Gnutlsing Library
 *
 * Copyright © 2011 Collabora, Ltd.
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
 * In addition, when the library is used with OpenSSL, a special
 * exception applies. Refer to the LICENSE_EXCEPTION file for details.
 *
 * Author: Stef Walter <stef@collabora.co.uk>
 */

#ifndef __G_TLS_BACKEND_GNUTLS_PKCS11_H__
#define __G_TLS_BACKEND_GNUTLS_PKCS11_H__

#include <gio/gio.h>
#include <gnutls/gnutls.h>

#include "gtlsbackend-gnutls.h"

G_BEGIN_DECLS

#define G_TYPE_TLS_BACKEND_GNUTLS_PKCS11            (g_tls_backend_gnutls_pkcs11get_type ())
#define G_TLS_BACKEND_GNUTLS_PKCS11(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), G_TYPE_TLS_BACKEND_GNUTLS_PKCS11, GTlsBackendGnutlsPkcs11))
#define G_TLS_BACKEND_GNUTLS_PKCS11_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), G_TYPE_TLS_BACKEND_GNUTLS_PKCS11, GTlsBackendGnutlsPkcs11Class))
#define G_IS_TLS_BACKEND_GNUTLS_PKCS11(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), G_TYPE_TLS_BACKEND_GNUTLS_PKCS11))
#define G_IS_TLS_BACKEND_GNUTLS_PKCS11_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), G_TYPE_TLS_BACKEND_GNUTLS_PKCS11))
#define G_TLS_BACKEND_GNUTLS_PKCS11_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), G_TYPE_TLS_BACKEND_GNUTLS_PKCS11, GTlsBackendGnutlsPkcs11Class))

typedef struct _GTlsBackendGnutlsPkcs11        GTlsBackendGnutlsPkcs11;
typedef struct _GTlsBackendGnutlsPkcs11Class   GTlsBackendGnutlsPkcs11Class;

struct _GTlsBackendGnutlsPkcs11Class
{
  GTlsBackendGnutlsClass parent_class;
};

struct _GTlsBackendGnutlsPkcs11
{
  GTlsBackendGnutls parent_instance;
};

GType        g_tls_backend_gnutls_pkcs11_get_type           (void) G_GNUC_CONST;

void         g_tls_backend_gnutls_pkcs11_register           (GIOModule *module);

G_END_DECLS

#endif /* __G_TLS_BACKEND_GNUTLS_H___ */
