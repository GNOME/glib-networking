/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright © 2011 Collabora Ltd.
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
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include <gnutls/gnutls.h>
#include <gnutls/pkcs11.h>
#include <string.h>

#include "gtlscertificate-gnutls.h"
#include "gtlscertificate-gnutls-pkcs11.h"

enum
{
  PROP_0,

  PROP_CERTIFICATE_URI,
  PROP_PRIVATE_KEY_URI
};

struct _GTlsCertificateGnutlsPkcs11
{
  GTlsCertificateGnutls parent_instance;

  gchar *certificate_uri;
  gchar *private_key_uri;
};

G_DEFINE_TYPE (GTlsCertificateGnutlsPkcs11, g_tls_certificate_gnutls_pkcs11,
               G_TYPE_TLS_CERTIFICATE_GNUTLS);

static void
g_tls_certificate_gnutls_pkcs11_finalize (GObject *object)
{
  GTlsCertificateGnutlsPkcs11 *self = G_TLS_CERTIFICATE_GNUTLS_PKCS11 (object);

  g_free (self->certificate_uri);
  g_free (self->private_key_uri);

  G_OBJECT_CLASS (g_tls_certificate_gnutls_pkcs11_parent_class)->finalize (object);
}

static void
g_tls_certificate_gnutls_pkcs11_get_property (GObject    *object,
                                              guint       prop_id,
                                              GValue     *value,
                                              GParamSpec *pspec)
{
  GTlsCertificateGnutlsPkcs11 *self = G_TLS_CERTIFICATE_GNUTLS_PKCS11 (object);

  switch (prop_id)
    {
    case PROP_CERTIFICATE_URI:
      g_value_set_string (value, self->certificate_uri);
      break;
    case PROP_PRIVATE_KEY_URI:
      g_value_set_string (value, self->private_key_uri);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_certificate_gnutls_pkcs11_set_property (GObject      *object,
                                              guint         prop_id,
                                              const GValue *value,
                                              GParamSpec   *pspec)
{
  GTlsCertificateGnutlsPkcs11 *self = G_TLS_CERTIFICATE_GNUTLS_PKCS11 (object);

  switch (prop_id)
    {
    case PROP_CERTIFICATE_URI:
      g_free (self->certificate_uri);
      self->certificate_uri = g_value_dup_string (value);
      break;
    case PROP_PRIVATE_KEY_URI:
      g_free (self->private_key_uri);
      self->private_key_uri = g_value_dup_string (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_certificate_gnutls_pkcs11_init (GTlsCertificateGnutlsPkcs11 *self)
{
}

static void
g_tls_certificate_gnutls_pkcs11_copy (GTlsCertificateGnutls    *gnutls,
                                      const gchar              *interaction_id,
                                      gnutls_retr2_st          *st)
{
  GTlsCertificateGnutlsPkcs11 *self = G_TLS_CERTIFICATE_GNUTLS_PKCS11 (gnutls);
  gchar *uri;

  st->key.x509 = NULL;

  /* Let the base class copy certificate in */
  G_TLS_CERTIFICATE_GNUTLS_CLASS (g_tls_certificate_gnutls_pkcs11_parent_class)->copy (gnutls,
                                                                                       interaction_id,
                                                                                       st);

  /* This is the allocation behavior we expect from base class */
  g_assert (st->deinit_all);

  /* If the base class somehow put a key in, then respect that */
  if (st->key.x509 == NULL)
    {
      uri = g_tls_certificate_gnutls_pkcs11_build_private_key_uri (self, interaction_id);
      if (uri != NULL)
        {
          gnutls_pkcs11_privkey_init (&st->key.pkcs11);
          gnutls_pkcs11_privkey_import_url (st->key.pkcs11, uri, GNUTLS_PKCS11_URL_GENERIC);
          st->key_type = GNUTLS_PRIVKEY_PKCS11;
          g_free (uri);
        }
    }
}

static void
g_tls_certificate_gnutls_pkcs11_class_init (GTlsCertificateGnutlsPkcs11Class *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsCertificateGnutlsClass *gnutls_class = G_TLS_CERTIFICATE_GNUTLS_CLASS (klass);

  gobject_class->get_property = g_tls_certificate_gnutls_pkcs11_get_property;
  gobject_class->set_property = g_tls_certificate_gnutls_pkcs11_set_property;
  gobject_class->finalize     = g_tls_certificate_gnutls_pkcs11_finalize;

  gnutls_class->copy = g_tls_certificate_gnutls_pkcs11_copy;

  g_object_class_install_property (gobject_class, PROP_CERTIFICATE_URI,
                  g_param_spec_string ("certificate-uri", "Certificate URI",
                                       "PKCS#11 URI of Certificate", NULL,
                                       G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_PRIVATE_KEY_URI,
                  g_param_spec_string ("private-key-uri", "Private Key URI",
                                       "PKCS#11 URI of Private Key", NULL,
                                       G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
}

GTlsCertificate *
g_tls_certificate_gnutls_pkcs11_new (gpointer certificate_data,
                                     gsize certificate_data_length,
                                     const gchar *certificate_uri,
                                     const gchar *private_key_uri,
                                     GTlsCertificate    *issuer)
{
  GTlsCertificate *certificate;
  gnutls_datum_t datum;

  g_return_val_if_fail (certificate_data, NULL);
  g_return_val_if_fail (certificate_uri, NULL);

  datum.data = certificate_data;
  datum.size = certificate_data_length;

  certificate = g_object_new (G_TYPE_TLS_CERTIFICATE_GNUTLS_PKCS11,
                              "issuer", issuer,
                              "certificate-uri", certificate_uri,
                              "private-key-uri", private_key_uri,
                              NULL);

  g_tls_certificate_gnutls_set_data (G_TLS_CERTIFICATE_GNUTLS (certificate), &datum);

  return certificate;
}

gchar *
g_tls_certificate_gnutls_pkcs11_build_certificate_uri (GTlsCertificateGnutlsPkcs11 *self,
                                                       const gchar *interaction_id)
{
  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_GNUTLS_PKCS11 (self), NULL);
  if (self->certificate_uri == NULL)
    return NULL;
  else if (interaction_id)
    return g_strdup_printf ("%s;pinfile=%s", self->certificate_uri, interaction_id);
  else
    return g_strdup (self->certificate_uri);
}

gchar *
g_tls_certificate_gnutls_pkcs11_build_private_key_uri (GTlsCertificateGnutlsPkcs11 *self,
                                                       const gchar *interaction_id)
{
  if (self->private_key_uri == NULL)
    return NULL;
  else if (interaction_id)
    return g_strdup_printf ("%s;pinfile=%s", self->private_key_uri, interaction_id);
  else
    return g_strdup (self->private_key_uri);
}
