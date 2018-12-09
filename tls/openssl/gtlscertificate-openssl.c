/*
 * gtlscertificate-openssl.c
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

#include "config.h"

#include <string.h>
#include "openssl-include.h"

#include "gtlscertificate-openssl.h"
#include "openssl-util.h"
#include <glib/gi18n-lib.h>

typedef struct _GTlsCertificateOpensslPrivate
{
  X509 *cert;
  EVP_PKEY *key;

  GTlsCertificateOpenssl *issuer;

  GError *construct_error;

  guint have_cert : 1;
  guint have_key  : 1;
} GTlsCertificateOpensslPrivate;

enum
{
  PROP_0,

  PROP_CERTIFICATE,
  PROP_CERTIFICATE_PEM,
  PROP_PRIVATE_KEY,
  PROP_PRIVATE_KEY_PEM,
  PROP_ISSUER
};

static void     g_tls_certificate_openssl_initable_iface_init (GInitableIface  *iface);

G_DEFINE_TYPE_WITH_CODE (GTlsCertificateOpenssl, g_tls_certificate_openssl, G_TYPE_TLS_CERTIFICATE,
                         G_ADD_PRIVATE (GTlsCertificateOpenssl)
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                g_tls_certificate_openssl_initable_iface_init))

static void
g_tls_certificate_openssl_finalize (GObject *object)
{
  GTlsCertificateOpenssl *openssl = G_TLS_CERTIFICATE_OPENSSL (object);
  GTlsCertificateOpensslPrivate *priv;

  priv = g_tls_certificate_openssl_get_instance_private (openssl);

  if (priv->cert)
    X509_free (priv->cert);
  if (priv->key)
    EVP_PKEY_free (priv->key);

  g_clear_object (&priv->issuer);

  g_clear_error (&priv->construct_error);

  G_OBJECT_CLASS (g_tls_certificate_openssl_parent_class)->finalize (object);
}

static void
g_tls_certificate_openssl_get_property (GObject    *object,
                                        guint       prop_id,
                                        GValue     *value,
                                        GParamSpec *pspec)
{
  GTlsCertificateOpenssl *openssl = G_TLS_CERTIFICATE_OPENSSL (object);
  GTlsCertificateOpensslPrivate *priv;
  GByteArray *certificate;
  guint8 *data;
  BIO *bio;
  char *certificate_pem;
  int size;

  priv = g_tls_certificate_openssl_get_instance_private (openssl);

  switch (prop_id)
    {
    case PROP_CERTIFICATE:
      /* NOTE: we do the two calls to avoid openssl allocating the buffer for us */
      size = i2d_X509 (priv->cert, NULL);
      if (size < 0)
        certificate = NULL;
      else
        {
          certificate = g_byte_array_sized_new (size);
          certificate->len = size;
          data = certificate->data;
          size = i2d_X509 (priv->cert, &data);
          if (size < 0)
            {
              g_byte_array_free (certificate, TRUE);
              certificate = NULL;
            }
        }
      g_value_take_boxed (value, certificate);
      break;

    case PROP_CERTIFICATE_PEM:
      bio = BIO_new (BIO_s_mem ());

      if (!PEM_write_bio_X509 (bio, priv->cert) || !BIO_write (bio, "\0", 1))
        certificate_pem = NULL;
      else
        {
          BIO_get_mem_data (bio, &certificate_pem);
          g_value_set_string (value, certificate_pem);

          BIO_free_all (bio);
        }
      break;

    case PROP_ISSUER:
      g_value_set_object (value, priv->issuer);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_certificate_openssl_set_property (GObject      *object,
                                       guint         prop_id,
                                       const GValue *value,
                                       GParamSpec   *pspec)
{
  GTlsCertificateOpenssl *openssl = G_TLS_CERTIFICATE_OPENSSL (object);
  GTlsCertificateOpensslPrivate *priv;
  GByteArray *bytes;
  guint8 *data;
  BIO *bio;
  const char *string;

  priv = g_tls_certificate_openssl_get_instance_private (openssl);

  switch (prop_id)
    {
    case PROP_CERTIFICATE:
      bytes = g_value_get_boxed (value);
      if (!bytes)
        break;
      g_return_if_fail (priv->have_cert == FALSE);
      /* see that we cannot use bytes->data directly since it will move the pointer */
      data = bytes->data;
      priv->cert = d2i_X509 (NULL, (const unsigned char **)&data, bytes->len);
      if (priv->cert != NULL)
        priv->have_cert = TRUE;
      else if (!priv->construct_error)
        {
          priv->construct_error =
            g_error_new (G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                         _("Could not parse DER certificate: %s"),
                         ERR_error_string (ERR_get_error (), NULL));
        }

      break;

    case PROP_CERTIFICATE_PEM:
      string = g_value_get_string (value);
      if (!string)
        break;
      g_return_if_fail (priv->have_cert == FALSE);
      bio = BIO_new_mem_buf ((gpointer)string, -1);
      priv->cert = PEM_read_bio_X509 (bio, NULL, NULL, NULL);
      BIO_free (bio);
      if (priv->cert != NULL)
        priv->have_cert = TRUE;
      else if (!priv->construct_error)
        {
          priv->construct_error =
            g_error_new (G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                         _("Could not parse PEM certificate: %s"),
                         ERR_error_string (ERR_get_error (), NULL));
        }
      break;

    case PROP_PRIVATE_KEY:
      bytes = g_value_get_boxed (value);
      if (!bytes)
        break;
      g_return_if_fail (priv->have_key == FALSE);
      bio = BIO_new_mem_buf (bytes->data, bytes->len);
      priv->key = d2i_PrivateKey_bio (bio, NULL);
      BIO_free (bio);
      if (priv->key != NULL)
        priv->have_key = TRUE;
      else if (!priv->construct_error)
        {
          priv->construct_error =
            g_error_new (G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                         _("Could not parse DER private key: %s"),
                         ERR_error_string (ERR_get_error (), NULL));
        }
      break;

    case PROP_PRIVATE_KEY_PEM:
      string = g_value_get_string (value);
      if (!string)
        break;
      g_return_if_fail (priv->have_key == FALSE);
      bio = BIO_new_mem_buf ((gpointer)string, -1);
      priv->key = PEM_read_bio_PrivateKey (bio, NULL, NULL, NULL);
      BIO_free (bio);
      if (priv->key != NULL)
        priv->have_key = TRUE;
      else if (!priv->construct_error)
        {
          priv->construct_error =
            g_error_new (G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                         _("Could not parse PEM private key: %s"),
                         ERR_error_string (ERR_get_error (), NULL));
        }
      break;

    case PROP_ISSUER:
      priv->issuer = g_value_dup_object (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_certificate_openssl_init (GTlsCertificateOpenssl *openssl)
{
}

static gboolean
g_tls_certificate_openssl_initable_init (GInitable       *initable,
                                         GCancellable    *cancellable,
                                         GError         **error)
{
  GTlsCertificateOpenssl *openssl = G_TLS_CERTIFICATE_OPENSSL (initable);
  GTlsCertificateOpensslPrivate *priv;

  priv = g_tls_certificate_openssl_get_instance_private (openssl);

  if (priv->construct_error)
    {
      g_propagate_error (error, priv->construct_error);
      priv->construct_error = NULL;
      return FALSE;
    }
  else if (!priv->have_cert)
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                           _("No certificate data provided"));
      return FALSE;
    }
  else
    return TRUE;
}

static GTlsCertificateFlags
g_tls_certificate_openssl_verify (GTlsCertificate     *cert,
                                  GSocketConnectable  *identity,
                                  GTlsCertificate     *trusted_ca)
{
  GTlsCertificateOpenssl *cert_openssl;
  GTlsCertificateOpensslPrivate *priv;
  GTlsCertificateFlags gtls_flags;
  X509 *x;
  STACK_OF(X509) *untrusted;
  gint i;

  cert_openssl = G_TLS_CERTIFICATE_OPENSSL (cert);
  priv = g_tls_certificate_openssl_get_instance_private (cert_openssl);
  x = priv->cert;

  untrusted = sk_X509_new_null ();
  for (; cert_openssl; cert_openssl = priv->issuer)
    {
      priv = g_tls_certificate_openssl_get_instance_private (cert_openssl);
      sk_X509_push (untrusted, priv->cert);
    }

  gtls_flags = 0;

  if (trusted_ca)
    {
      X509_STORE *store;
      X509_STORE_CTX *csc;
      STACK_OF(X509) *trusted;

      store = X509_STORE_new ();
      csc = X509_STORE_CTX_new ();

      if (!X509_STORE_CTX_init (csc, store, x, untrusted))
        {
          sk_X509_free (untrusted);
          X509_STORE_CTX_free (csc);
          X509_STORE_free (store);
          return G_TLS_CERTIFICATE_GENERIC_ERROR;
        }

      trusted = sk_X509_new_null ();
      cert_openssl = G_TLS_CERTIFICATE_OPENSSL (trusted_ca);
      for (; cert_openssl; cert_openssl = priv->issuer)
        {
          priv = g_tls_certificate_openssl_get_instance_private (cert_openssl);
          sk_X509_push (trusted, priv->cert);
        }

      X509_STORE_CTX_trusted_stack (csc, trusted);
      if (X509_verify_cert (csc) <= 0)
        gtls_flags |= g_tls_certificate_openssl_convert_error (X509_STORE_CTX_get_error (csc));

      sk_X509_free (trusted);
      X509_STORE_CTX_free (csc);
      X509_STORE_free (store);
    }

  /* We have to check these ourselves since openssl
   * does not give us flags and UNKNOWN_CA will take priority.
   */
  for (i = 0; i < sk_X509_num (untrusted); i++)
    {
      X509 *c = sk_X509_value (untrusted, i);
      ASN1_TIME *not_before = X509_get_notBefore (c);
      ASN1_TIME *not_after = X509_get_notAfter (c);

      if (X509_cmp_current_time (not_before) > 0)
        gtls_flags |= G_TLS_CERTIFICATE_NOT_ACTIVATED;

      if (X509_cmp_current_time (not_after) < 0)
        gtls_flags |= G_TLS_CERTIFICATE_EXPIRED;
    }

  sk_X509_free (untrusted);

  if (identity)
    gtls_flags |= g_tls_certificate_openssl_verify_identity (G_TLS_CERTIFICATE_OPENSSL (cert), identity);

  return gtls_flags;
}

static void
g_tls_certificate_openssl_class_init (GTlsCertificateOpensslClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsCertificateClass *certificate_class = G_TLS_CERTIFICATE_CLASS (klass);

  gobject_class->get_property = g_tls_certificate_openssl_get_property;
  gobject_class->set_property = g_tls_certificate_openssl_set_property;
  gobject_class->finalize     = g_tls_certificate_openssl_finalize;

  certificate_class->verify = g_tls_certificate_openssl_verify;

  g_object_class_override_property (gobject_class, PROP_CERTIFICATE, "certificate");
  g_object_class_override_property (gobject_class, PROP_CERTIFICATE_PEM, "certificate-pem");
  g_object_class_override_property (gobject_class, PROP_PRIVATE_KEY, "private-key");
  g_object_class_override_property (gobject_class, PROP_PRIVATE_KEY_PEM, "private-key-pem");
  g_object_class_override_property (gobject_class, PROP_ISSUER, "issuer");
}

static void
g_tls_certificate_openssl_initable_iface_init (GInitableIface  *iface)
{
  iface->init = g_tls_certificate_openssl_initable_init;
}

GTlsCertificate *
g_tls_certificate_openssl_new (GBytes          *bytes,
                               GTlsCertificate *issuer)
{
  GTlsCertificateOpenssl *openssl;

  openssl = g_object_new (G_TYPE_TLS_CERTIFICATE_OPENSSL,
                          "issuer", issuer,
                          NULL);
  g_tls_certificate_openssl_set_data (openssl, bytes);

  return G_TLS_CERTIFICATE (openssl);
}

GTlsCertificate *
g_tls_certificate_openssl_new_from_x509 (X509            *x,
                                         GTlsCertificate *issuer)
{
  GTlsCertificateOpenssl *openssl;
  GTlsCertificateOpensslPrivate *priv;

  openssl = g_object_new (G_TYPE_TLS_CERTIFICATE_OPENSSL,
                          "issuer", issuer,
                          NULL);

  priv = g_tls_certificate_openssl_get_instance_private (openssl);

  priv->cert = X509_dup (x);
  priv->have_cert = TRUE;

  return G_TLS_CERTIFICATE (openssl);
}

void
g_tls_certificate_openssl_set_data (GTlsCertificateOpenssl *openssl,
                                    GBytes                 *bytes)
{
  GTlsCertificateOpensslPrivate *priv;
  const unsigned char *data;

  g_return_if_fail (G_IS_TLS_CERTIFICATE_OPENSSL (openssl));

  priv = g_tls_certificate_openssl_get_instance_private (openssl);

  g_return_if_fail (!priv->have_cert);

  data = (const unsigned char *)g_bytes_get_data (bytes, NULL);
  priv->cert = d2i_X509 (NULL, &data, g_bytes_get_size (bytes));

  if (priv->cert != NULL)
    priv->have_cert = TRUE;
}

GBytes *
g_tls_certificate_openssl_get_bytes (GTlsCertificateOpenssl *openssl)
{
  GByteArray *array;

  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_OPENSSL (openssl), NULL);

  g_object_get (openssl, "certificate", &array, NULL);
  return g_byte_array_free_to_bytes (array);
}

X509 *
g_tls_certificate_openssl_get_cert (GTlsCertificateOpenssl *openssl)
{
  GTlsCertificateOpensslPrivate *priv;

  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_OPENSSL (openssl), FALSE);

  priv = g_tls_certificate_openssl_get_instance_private (openssl);

  return priv->cert;
}

EVP_PKEY *
g_tls_certificate_openssl_get_key (GTlsCertificateOpenssl *openssl)
{
  GTlsCertificateOpensslPrivate *priv;

  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_OPENSSL (openssl), FALSE);

  priv = g_tls_certificate_openssl_get_instance_private (openssl);

  return priv->key;
}

void
g_tls_certificate_openssl_set_issuer (GTlsCertificateOpenssl *openssl,
                                      GTlsCertificateOpenssl *issuer)
{
  GTlsCertificateOpensslPrivate *priv;

  g_return_if_fail (G_IS_TLS_CERTIFICATE_OPENSSL (openssl));
  g_return_if_fail (!issuer || G_IS_TLS_CERTIFICATE_OPENSSL (issuer));

  priv = g_tls_certificate_openssl_get_instance_private (openssl);

  if (g_set_object (&priv->issuer, issuer))
    g_object_notify (G_OBJECT (openssl), "issuer");
}

static gboolean
verify_identity_hostname (GTlsCertificateOpenssl *openssl,
                          GSocketConnectable     *identity)
{
  GTlsCertificateOpensslPrivate *priv;
  const char *hostname;

  priv = g_tls_certificate_openssl_get_instance_private (openssl);

  if (G_IS_NETWORK_ADDRESS (identity))
    hostname = g_network_address_get_hostname (G_NETWORK_ADDRESS (identity));
  else if (G_IS_NETWORK_SERVICE (identity))
    hostname = g_network_service_get_domain (G_NETWORK_SERVICE (identity));
  else
    return FALSE;

  return g_tls_X509_check_host (priv->cert, hostname, strlen (hostname), 0, NULL) == 1;
}

static gboolean
verify_identity_ip (GTlsCertificateOpenssl *openssl,
                    GSocketConnectable     *identity)
{
  GTlsCertificateOpensslPrivate *priv;
  GInetAddress *addr;
  gsize addr_size;
  const guint8 *addr_bytes;
  gboolean ret;

  priv = g_tls_certificate_openssl_get_instance_private (openssl);

  if (G_IS_INET_SOCKET_ADDRESS (identity))
    addr = g_object_ref (g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS (identity)));
  else {
    const char *hostname;

    if (G_IS_NETWORK_ADDRESS (identity))
      hostname = g_network_address_get_hostname (G_NETWORK_ADDRESS (identity));
    else if (G_IS_NETWORK_SERVICE (identity))
      hostname = g_network_service_get_domain (G_NETWORK_SERVICE (identity));
    else
      return FALSE;

    addr = g_inet_address_new_from_string (hostname);
    if (!addr)
      return FALSE;
  }

  addr_bytes = g_inet_address_to_bytes (addr);
  addr_size = g_inet_address_get_native_size (addr);

  ret = g_tls_X509_check_ip (priv->cert, addr_bytes, addr_size, 0) == 1;

  g_object_unref (addr);
  return ret;
}

GTlsCertificateFlags
g_tls_certificate_openssl_verify_identity (GTlsCertificateOpenssl *openssl,
                                           GSocketConnectable     *identity)
{
  if (verify_identity_hostname (openssl, identity))
    return 0;
  else if (verify_identity_ip (openssl, identity))
    return 0;

  /* FIXME: check sRVName and uniformResourceIdentifier
   * subjectAltNames, if appropriate for @identity.
   */

  return G_TLS_CERTIFICATE_BAD_IDENTITY;
}

GTlsCertificateFlags
g_tls_certificate_openssl_convert_error (guint openssl_error)
{
  GTlsCertificateFlags gtls_flags;

  gtls_flags = 0;

  /* FIXME: should we add more ? */
  switch (openssl_error)
    {
    case X509_V_OK:
      break;
    case X509_V_ERR_CERT_NOT_YET_VALID:
      gtls_flags = G_TLS_CERTIFICATE_NOT_ACTIVATED;
      break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
      gtls_flags = G_TLS_CERTIFICATE_EXPIRED;
      break;
    case X509_V_ERR_CERT_REVOKED:
      gtls_flags = G_TLS_CERTIFICATE_REVOKED;
      break;
    case X509_V_ERR_AKID_SKID_MISMATCH:
      gtls_flags = G_TLS_CERTIFICATE_BAD_IDENTITY;
      break;
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
      gtls_flags = G_TLS_CERTIFICATE_UNKNOWN_CA;
      break;
    default:
      g_message ("certificate error: %s", X509_verify_cert_error_string (openssl_error));
      gtls_flags = G_TLS_CERTIFICATE_GENERIC_ERROR;
    }

  return gtls_flags;
}

static gboolean
is_issuer (GTlsCertificateOpenssl *cert,
           GTlsCertificateOpenssl *issuer)
{
  X509 *x;
  X509 *issuer_x;
  X509_STORE *store;
  X509_STORE_CTX *csc;
  STACK_OF(X509) *trusted;
  gboolean ret = FALSE;
  gint err;

  x = g_tls_certificate_openssl_get_cert (cert);
  issuer_x = g_tls_certificate_openssl_get_cert (issuer);

  store = X509_STORE_new ();
  csc = X509_STORE_CTX_new ();

  if (!X509_STORE_CTX_init (csc, store, x, NULL))
    goto end;

  trusted = sk_X509_new_null ();
  sk_X509_push (trusted, issuer_x);

  X509_STORE_CTX_trusted_stack (csc, trusted);
  X509_STORE_CTX_set_flags (csc, X509_V_FLAG_CB_ISSUER_CHECK);

  /* FIXME: is this the right way to do it? */
  if (X509_verify_cert (csc) <= 0)
    {
      err = X509_STORE_CTX_get_error (csc);
      if (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)
        ret = TRUE;
    }
  else
    ret = TRUE;

  sk_X509_free (trusted);

end:
  X509_STORE_CTX_free (csc);
  X509_STORE_free (store);

  return ret;
}

GTlsCertificateOpenssl *
g_tls_certificate_openssl_build_chain (X509            *x,
                                       STACK_OF (X509) *chain)
{
  GPtrArray *glib_certs;
  GTlsCertificateOpenssl *issuer;
  GTlsCertificateOpenssl *result;
  guint i, j;

  g_return_val_if_fail (x != NULL, NULL);
  g_return_val_if_fail (chain, NULL);

  glib_certs = g_ptr_array_new_full (sk_X509_num (chain), g_object_unref);
  g_ptr_array_add (glib_certs, g_tls_certificate_openssl_new_from_x509 (x, NULL));
  for (i = 1; i < sk_X509_num (chain); i++)
    g_ptr_array_add (glib_certs, g_tls_certificate_openssl_new_from_x509 (sk_X509_value (chain, i), NULL));

  /* Some servers send certs out of order, or will send duplicate
   * certs, so we need to be careful when assigning the issuer of
   * our new GTlsCertificateOpenssl.
   */
  for (i = 0; i < glib_certs->len; i++)
    {
      issuer = NULL;

      /* Check if the cert issued itself */
      if (is_issuer (glib_certs->pdata[i], glib_certs->pdata[i]))
        continue;

      if (i < glib_certs->len - 1 &&
          is_issuer (glib_certs->pdata[i], glib_certs->pdata[i + 1]))
        {
          issuer = glib_certs->pdata[i + 1];
        }
      else
        {
          for (j = 0; j < glib_certs->len; j++)
            {
              if (j != i &&
                  is_issuer (glib_certs->pdata[i], glib_certs->pdata[j]))
                {
                  issuer = glib_certs->pdata[j];
                  break;
                }
            }
        }

      if (issuer)
        g_tls_certificate_openssl_set_issuer (glib_certs->pdata[i], issuer);
    }

  result = g_object_ref (glib_certs->pdata[0]);
  g_ptr_array_unref (glib_certs);

  return result;
}
