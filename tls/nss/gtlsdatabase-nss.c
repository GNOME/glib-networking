/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2011 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "config.h"

#include <pk11pub.h>
#include <secerr.h>

#include "gtlsdatabase-nss.h"
#include "gtlsbackend-nss.h"
#include "gtlscertificate-nss.h"

#include <glib/gi18n-lib.h>

G_DEFINE_TYPE (GTlsDatabaseNss, g_tls_database_nss, G_TYPE_TLS_DATABASE);

struct _GTlsDatabaseNssPrivate
{
  GMutex mutex;
  GHashTable *gcerts;
};

static void
g_tls_database_nss_init (GTlsDatabaseNss *nss)
{
  nss->priv = G_TYPE_INSTANCE_GET_PRIVATE (nss,
					   G_TYPE_TLS_DATABASE_NSS,
					   GTlsDatabaseNssPrivate);

  g_mutex_init (&nss->priv->mutex);

  /* gcerts is a cache of CERTCertificate to GTlsCertificateNss
   * mappings, including every live GTlsCertificateNss. Note that both
   * types enforce uniqueness, so there should be a one-to-one
   * mapping.
   */
  nss->priv->gcerts = g_hash_table_new (NULL, NULL);
}

static void
g_tls_database_nss_finalize (GObject *object)
{
  GTlsDatabaseNss *nss = G_TLS_DATABASE_NSS (object);
  GHashTableIter iter;
  gpointer cert, gcert;

  g_mutex_clear (&nss->priv->mutex);

  g_hash_table_iter_init (&iter, nss->priv->gcerts);
  while (g_hash_table_iter_next (&iter, &cert, &gcert))
    CERT_DestroyCertificate (cert);
  g_hash_table_destroy (nss->priv->gcerts);

  G_OBJECT_CLASS (g_tls_database_nss_parent_class)->finalize (object);
}

GTlsCertificateNss *
g_tls_database_nss_get_gcert (GTlsDatabaseNss *nss,
			      CERTCertificate *cert,
			      gboolean         create)
{
  GTlsCertificateNss *gcert;

  g_mutex_lock (&nss->priv->mutex);

  gcert = g_hash_table_lookup (nss->priv->gcerts, cert);
  if (gcert)
    g_object_ref (gcert);
  else if (create)
    {
      gcert = g_tls_certificate_nss_new_for_cert (cert);
      /* The GTlsCertificate constructor will call
       * g_tls_database_nss_gcert_created() to add it to the hash.
       */
    }

  g_mutex_unlock (&nss->priv->mutex);
  return gcert;
}

void
g_tls_database_nss_gcert_created (GTlsDatabaseNss    *nss,
				  CERTCertificate    *cert,
				  GTlsCertificateNss *gcert)
{
  g_mutex_lock (&nss->priv->mutex);
  /* We keep a ref on the CERTCertificate, but not the GTlsCertificate */
  g_hash_table_insert (nss->priv->gcerts, CERT_DupCertificate (cert), gcert);
  g_mutex_unlock (&nss->priv->mutex);
}

void
g_tls_database_nss_gcert_destroyed (GTlsDatabaseNss *nss,
				    CERTCertificate *cert)
{
  g_mutex_lock (&nss->priv->mutex);
  g_hash_table_remove (nss->priv->gcerts, cert);
  CERT_DestroyCertificate (cert);
  g_mutex_unlock (&nss->priv->mutex);
}

static GTlsCertificateFlags
g_tls_database_nss_verify_chain (GTlsDatabase             *database,
				 GTlsCertificate          *chain,
				 const gchar              *purpose,
				 GSocketConnectable       *identity,
				 GTlsInteraction          *interaction,
				 GTlsDatabaseVerifyFlags   flags,
				 GCancellable             *cancellable,
				 GError                  **error)
{
  return g_tls_certificate_nss_verify_full (chain, database, NULL,
					    purpose, identity, interaction,
					    flags, cancellable, error);
}

static gchar *
g_tls_database_nss_create_certificate_handle (GTlsDatabase    *database,
					      GTlsCertificate *certificate)
{

  CERTCertificate *cert = g_tls_certificate_nss_get_cert (G_TLS_CERTIFICATE_NSS (certificate));
  gchar *issuer, *serial, *handle;

  issuer = g_base64_encode ((guchar *)cert->derIssuer.data,
			    cert->derIssuer.len);
  serial = g_base64_encode ((guchar *)cert->serialNumber.data,
			    cert->serialNumber.len);

  handle = g_strdup_printf ("nss:%s#%s", issuer, serial);
  g_free (issuer);
  g_free (serial);

  return handle;
}

static GTlsCertificate *
g_tls_database_nss_lookup_certificate_for_handle (GTlsDatabase             *database,
						  const gchar              *handle,
						  GTlsInteraction          *interaction,
						  GTlsDatabaseLookupFlags   flags,
						  GCancellable             *cancellable,
						  GError                  **error)
{
  GTlsDatabaseNss *nss = G_TLS_DATABASE_NSS (database);
  const gchar *split, *issuer, *serial;
  CERTIssuerAndSN issuerAndSN;
  CERTCertificate *cert;
  GTlsCertificateNss *ret;
  gsize length;

  if (!g_str_has_prefix (handle, "nss:"))
    return NULL;

  issuer = handle + 4;
  split = strchr (issuer, '#');
  if (!split)
    return NULL;
  serial = split + 1;

  issuerAndSN.derIssuer.data = g_base64_decode (issuer, &length);
  issuerAndSN.derIssuer.len = length;

  issuerAndSN.serialNumber.data = g_base64_decode (serial, &length);
  issuerAndSN.serialNumber.len = length;

  cert = CERT_FindCertByIssuerAndSN (g_tls_backend_nss_certdbhandle, &issuerAndSN);
  g_free (issuerAndSN.derIssuer.data);
  g_free (issuerAndSN.serialNumber.data);
  if (!cert)
    return NULL;

  ret = g_tls_database_nss_get_gcert (nss, cert, TRUE);
  CERT_DestroyCertificate (cert);
  return G_TLS_CERTIFICATE (ret);
}

static GTlsCertificate *
g_tls_database_nss_lookup_certificate_issuer (GTlsDatabase             *database,
					      GTlsCertificate          *certificate,
					      GTlsInteraction          *interaction,
					      GTlsDatabaseLookupFlags   flags,
					      GCancellable             *cancellable,
					      GError                  **error)
{
  GTlsDatabaseNss *nss = G_TLS_DATABASE_NSS (database);
  GTlsCertificateNss *cert_nss = G_TLS_CERTIFICATE_NSS (certificate);
  CERTCertificate *cert, *issuer_cert;
  GTlsCertificateNss *issuer;

  cert = g_tls_certificate_nss_get_cert (cert_nss);
  issuer_cert = CERT_FindCertIssuer(cert, PR_Now (),
				    /* FIXME? Though it seems to not actually
				     * matter if this is wrong.
				     */
				    certUsageSSLServer);
  if (issuer_cert)
    {
      issuer = g_tls_database_nss_get_gcert (nss, issuer_cert, TRUE);
      CERT_DestroyCertificate (issuer_cert);
      return G_TLS_CERTIFICATE (issuer);
    }
  else
    return NULL;
}

static GList *
g_tls_database_nss_lookup_certificates_issued_by (GTlsDatabase             *database,
						  GByteArray               *issuer_raw_dn,
						  GTlsInteraction          *interaction,
						  GTlsDatabaseLookupFlags   flags,
						  GCancellable             *cancellable,
						  GError                  **error)
{
  GTlsDatabaseNss *nss = G_TLS_DATABASE_NSS (database);
  GList *certs;
  CERTCertNicknames *nicknames;
  CERTCertificate *cert;
  SECItem issuerName;
  int i;

  nicknames = CERT_GetCertNicknames (g_tls_backend_nss_certdbhandle,
				     SEC_CERT_NICKNAMES_ALL, interaction);
  if (!nicknames)
    return NULL;

  certs = NULL;
  for (i = 0; i < nicknames->numnicknames; i++)
    {
      cert = PK11_FindCertFromNickname (nicknames->nicknames[i], interaction);
      if (!cert)
	continue;

      if (CERT_IssuerNameFromDERCert (&cert->derCert, &issuerName) == SECSuccess)
	{
	  if (issuer_raw_dn->len == issuerName.len &&
	      memcmp (issuer_raw_dn->data, issuerName.data, issuerName.len) == 0)
	    certs = g_list_prepend (certs, g_tls_database_nss_get_gcert (nss, cert, TRUE));

	  SECITEM_FreeItem (&issuerName, PR_FALSE);
	}

      CERT_DestroyCertificate (cert);
    }

  CERT_FreeNicknames (nicknames);
  return certs;
}

static void
g_tls_database_nss_class_init (GTlsDatabaseNssClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  GTlsDatabaseClass *database_class = G_TLS_DATABASE_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GTlsDatabaseNssPrivate));

  object_class->finalize = g_tls_database_nss_finalize;

  database_class->verify_chain = g_tls_database_nss_verify_chain;
  database_class->create_certificate_handle = g_tls_database_nss_create_certificate_handle;            
  database_class->lookup_certificate_for_handle = g_tls_database_nss_lookup_certificate_for_handle;        
  database_class->lookup_certificate_issuer = g_tls_database_nss_lookup_certificate_issuer;            
  database_class->lookup_certificates_issued_by = g_tls_database_nss_lookup_certificates_issued_by;        
}
