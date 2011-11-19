/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2009 Red Hat, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 */

#ifndef __G_TLS_CERTIFICATE_GNUTLS_H__
#define __G_TLS_CERTIFICATE_GNUTLS_H__

#include <gio/gio.h>
#include <gnutls/gnutls.h>

G_BEGIN_DECLS

#define G_TYPE_TLS_CERTIFICATE_GNUTLS            (g_tls_certificate_gnutls_get_type ())
#define G_TLS_CERTIFICATE_GNUTLS(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), G_TYPE_TLS_CERTIFICATE_GNUTLS, GTlsCertificateGnutls))
#define G_TLS_CERTIFICATE_GNUTLS_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), G_TYPE_TLS_CERTIFICATE_GNUTLS, GTlsCertificateGnutlsClass))
#define G_IS_TLS_CERTIFICATE_GNUTLS(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), G_TYPE_TLS_CERTIFICATE_GNUTLS))
#define G_IS_TLS_CERTIFICATE_GNUTLS_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), G_TYPE_TLS_CERTIFICATE_GNUTLS))
#define G_TLS_CERTIFICATE_GNUTLS_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), G_TYPE_TLS_CERTIFICATE_GNUTLS, GTlsCertificateGnutlsClass))

typedef struct _GTlsCertificateGnutlsPrivate                   GTlsCertificateGnutlsPrivate;
typedef struct _GTlsCertificateGnutlsClass                     GTlsCertificateGnutlsClass;
typedef struct _GTlsCertificateGnutls                          GTlsCertificateGnutls;

struct _GTlsCertificateGnutlsClass
{
  GTlsCertificateClass parent_class;

  void              (*copy)               (GTlsCertificateGnutls    *gnutls,
                                           const gchar              *interaction_id,
                                           gnutls_retr2_st          *st);
};

struct _GTlsCertificateGnutls
{
  GTlsCertificate parent_instance;
  GTlsCertificateGnutlsPrivate *priv;
};

GType g_tls_certificate_gnutls_get_type (void) G_GNUC_CONST;

GTlsCertificate *            g_tls_certificate_gnutls_new             (const gnutls_datum    *datum,
                                                                       GTlsCertificate       *issuer);

void                         g_tls_certificate_gnutls_set_data        (GTlsCertificateGnutls *gnutls,
                                                                       const gnutls_datum *datum);

const gnutls_x509_crt_t      g_tls_certificate_gnutls_get_cert        (GTlsCertificateGnutls *gnutls);
gboolean                     g_tls_certificate_gnutls_has_key         (GTlsCertificateGnutls *gnutls);

void                         g_tls_certificate_gnutls_copy            (GTlsCertificateGnutls *gnutls,
                                                                       const gchar           *interaction_id,
                                                                       gnutls_retr2_st       *st);

GTlsCertificateFlags         g_tls_certificate_gnutls_verify_identity (GTlsCertificateGnutls *gnutls,
								       GSocketConnectable    *identity);

GTlsCertificateFlags         g_tls_certificate_gnutls_convert_flags   (guint                  gnutls_flags);

void                         g_tls_certificate_gnutls_set_issuer      (GTlsCertificateGnutls *gnutls,
                                                                       GTlsCertificateGnutls *issuer);

GTlsCertificateGnutls*       g_tls_certificate_gnutls_steal_issuer    (GTlsCertificateGnutls *gnutls);

G_END_DECLS

#endif /* __G_TLS_CERTIFICATE_GNUTLS_H___ */
