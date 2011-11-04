/* GIO - GLib Certificate, Output and Gnutlsing Library
 *
 * Copyright © 2011 Collabora Ltd.
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

#ifndef __G_TLS_CERTIFICATE_GNUTLS_PKCS11_H__
#define __G_TLS_CERTIFICATE_GNUTLS_PKCS11_H__

#include <gio/gio.h>
#include <gnutls/gnutls.h>

G_BEGIN_DECLS

#define G_TYPE_TLS_CERTIFICATE_GNUTLS_PKCS11            (g_tls_certificate_gnutls_pkcs11_get_type ())
#define G_TLS_CERTIFICATE_GNUTLS_PKCS11(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), G_TYPE_TLS_CERTIFICATE_GNUTLS_PKCS11, GTlsCertificateGnutlsPkcs11))
#define G_TLS_CERTIFICATE_GNUTLS_PKCS11_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), G_TYPE_TLS_CERTIFICATE_GNUTLS_PKCS11, GTlsCertificateGnutlsPkcs11Class))
#define G_IS_TLS_CERTIFICATE_GNUTLS_PKCS11(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), G_TYPE_TLS_CERTIFICATE_GNUTLS_PKCS11))
#define G_IS_TLS_CERTIFICATE_GNUTLS_PKCS11_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), G_TYPE_TLS_CERTIFICATE_GNUTLS_PKCS11))
#define G_TLS_CERTIFICATE_GNUTLS_PKCS11_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), G_TYPE_TLS_CERTIFICATE_GNUTLS_PKCS11, GTlsCertificateGnutlsPkcs11Class))

typedef struct _GTlsCertificateGnutlsPkcs11Private                   GTlsCertificateGnutlsPkcs11Private;
typedef struct _GTlsCertificateGnutlsPkcs11Class                     GTlsCertificateGnutlsPkcs11Class;
typedef struct _GTlsCertificateGnutlsPkcs11                          GTlsCertificateGnutlsPkcs11;

struct _GTlsCertificateGnutlsPkcs11Class
{
  GTlsCertificateGnutlsClass parent_class;
};

struct _GTlsCertificateGnutlsPkcs11
{
  GTlsCertificateGnutls parent_instance;
  GTlsCertificateGnutlsPkcs11Private *priv;
};

GType              g_tls_certificate_gnutls_pkcs11_get_type              (void) G_GNUC_CONST;

GTlsCertificate *  g_tls_certificate_gnutls_pkcs11_new                   (gpointer        certificate_der,
                                                                          gsize           certificate_der_length,
                                                                          const gchar     *certificate_uri,
                                                                          const gchar     *private_key_uri,
                                                                          GTlsCertificate *issuer);

gchar *            g_tls_certificate_gnutls_pkcs11_build_certificate_uri (GTlsCertificateGnutlsPkcs11 *self,
                                                                          const gchar *interaction_id);

gchar *            g_tls_certificate_gnutls_pkcs11_build_private_key_uri (GTlsCertificateGnutlsPkcs11 *self,
                                                                          const gchar *interaction_id);

G_END_DECLS

#endif /* __G_TLS_CERTIFICATE_GNUTLS_PKCS11_H___ */
