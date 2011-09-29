/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2011 Red Hat, Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 */

#ifndef __G_TLS_CERTIFICATE_NSS_H__
#define __G_TLS_CERTIFICATE_NSS_H__

#include <gio/gio.h>
#include <cert.h>

G_BEGIN_DECLS

#define G_TYPE_TLS_CERTIFICATE_NSS            (g_tls_certificate_nss_get_type ())
#define G_TLS_CERTIFICATE_NSS(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), G_TYPE_TLS_CERTIFICATE_NSS, GTlsCertificateNss))
#define G_TLS_CERTIFICATE_NSS_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), G_TYPE_TLS_CERTIFICATE_NSS, GTlsCertificateNssClass))
#define G_IS_TLS_CERTIFICATE_NSS(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), G_TYPE_TLS_CERTIFICATE_NSS))
#define G_IS_TLS_CERTIFICATE_NSS_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), G_TYPE_TLS_CERTIFICATE_NSS))
#define G_TLS_CERTIFICATE_NSS_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), G_TYPE_TLS_CERTIFICATE_NSS, GTlsCertificateNssClass))

typedef struct _GTlsCertificateNssPrivate                   GTlsCertificateNssPrivate;
typedef struct _GTlsCertificateNssClass                     GTlsCertificateNssClass;
typedef struct _GTlsCertificateNss                          GTlsCertificateNss;

struct _GTlsCertificateNssClass
{
  GTlsCertificateClass parent_class;
};

struct _GTlsCertificateNss
{
  GTlsCertificate parent_instance;
  GTlsCertificateNssPrivate *priv;
};

GType g_tls_certificate_nss_get_type (void) G_GNUC_CONST;

GTlsCertificateNss   *g_tls_certificate_nss_new_for_cert (CERTCertificate          *cert);

CERTCertificate      *g_tls_certificate_nss_get_cert     (GTlsCertificateNss       *nss);
SECKEYPrivateKey     *g_tls_certificate_nss_get_key      (GTlsCertificateNss       *nss);

GTlsCertificateFlags  g_tls_certificate_nss_verify_full  (GTlsCertificate          *chain,
							  GTlsDatabase             *database,
							  GTlsCertificate          *trusted_ca,
							  const gchar              *purpose,
							  GSocketConnectable       *identity,
							  GTlsInteraction          *interaction,
							  GTlsDatabaseVerifyFlags   flags,
							  GCancellable             *cancellable,
							  GError                  **error);

G_END_DECLS

#endif /* __G_TLS_CERTIFICATE_NSS_H___ */
