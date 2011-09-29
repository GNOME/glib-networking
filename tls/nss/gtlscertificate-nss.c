/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2011 Red Hat, Inc
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
#include "glib.h"

#include <errno.h>

#include <cert.h>
#include <keyhi.h>
#include <pk11pub.h>
#include <secerr.h>

#include "gtlscertificate-nss.h"
#include "gtlsbackend-nss.h"
#include "gtlsdatabase-nss.h"
#include "gtlsfiledatabase-nss.h"
#include <glib/gi18n-lib.h>

static void     g_tls_certificate_nss_initable_iface_init (GInitableIface  *iface);

G_DEFINE_TYPE_WITH_CODE (GTlsCertificateNss, g_tls_certificate_nss, G_TYPE_TLS_CERTIFICATE,
			 G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
						g_tls_certificate_nss_initable_iface_init);)

enum
{
  PROP_0,

  PROP_CERTIFICATE,
  PROP_CERTIFICATE_PEM,
  PROP_CERTIFICATE_FILE,
  PROP_PRIVATE_KEY,
  PROP_PRIVATE_KEY_PEM,
  PROP_PRIVATE_KEY_FILE,
  PROP_ISSUER
};

struct _GTlsCertificateNssPrivate
{
  CERTCertificate *cert;
  SECKEYPrivateKey *key;

  GTlsCertificateNss *issuer;
  gboolean expanded;

  GError *construct_error;
  char *cert_file, *key_file;
  gboolean delete_key_file;
};

static gboolean load_from_files (GTlsCertificateNss  *nss,
				 GError             **error);

static gboolean
idle_unref (gpointer obj)
{
  g_object_unref (obj);
  return FALSE;
}

static GObject *
g_tls_certificate_nss_constructor (GType                  type,
				   guint                  n_construct_properties,
				   GObjectConstructParam *construct_properties)
{
  GObject *obj;
  GTlsCertificateNss *nss, *existing;

  obj = G_OBJECT_CLASS (g_tls_certificate_nss_parent_class)->constructor (type, n_construct_properties, construct_properties);
  nss = G_TLS_CERTIFICATE_NSS (obj);

  if (nss->priv->construct_error)
    return obj;

  if (!nss->priv->cert && !nss->priv->cert_file)
    return obj;

  /* We can't do this in set_property() because cert_file and key_file
   * could be set in either order.
   */
  if (nss->priv->cert_file || nss->priv->key_file)
    load_from_files (nss, &nss->priv->construct_error);

  if (nss->priv->construct_error)
    return obj;

  /* If this is a duplicate of an existing certificate then NSS will
   * have returned a new reference to the same CERTCertificate it created
   * before. In order to be able to map CERTCertificates to
   * GTlsCertificates then, we need to uniquify GTlsCertificates too.
   * So check if we already have one for this cert.
   */
  existing = g_tls_database_nss_get_gcert (g_tls_backend_nss_default_database,
					   nss->priv->cert, FALSE);
  if (existing)
    {
      /* Return the existing one rather than the new one, but we can't
       * just unref the new one immediately.
       * (https://bugzilla.gnome.org/show_bug.cgi?id=661576).
       */
      g_idle_add (idle_unref, obj);
      obj = G_OBJECT (existing);
    }
  else
    {
      g_tls_database_nss_gcert_created (g_tls_backend_nss_default_database,
					nss->priv->cert, nss);
    }

  return obj;
}

static void
g_tls_certificate_nss_finalize (GObject *object)
{
  GTlsCertificateNss *nss = G_TLS_CERTIFICATE_NSS (object);

  if (nss->priv->cert)
    {
      g_tls_database_nss_gcert_destroyed (g_tls_backend_nss_default_database,
					  nss->priv->cert);
      CERT_DestroyCertificate (nss->priv->cert);
    }
  if (nss->priv->key)
    SECKEY_DestroyPrivateKey (nss->priv->key);

  g_clear_object (&nss->priv->issuer);

  g_clear_error (&nss->priv->construct_error);

  g_free (nss->priv->cert_file);
  if (nss->priv->delete_key_file)
    unlink (nss->priv->key_file);
  g_free (nss->priv->key_file);

  G_OBJECT_CLASS (g_tls_certificate_nss_parent_class)->finalize (object);
}

static PK11GenericObject *
create_pkcs11_object (const char      *filename,
		      CK_OBJECT_CLASS  obj_class)
{
  CK_BBOOL cktrue = CK_TRUE;
  CK_ATTRIBUTE attrs[3];

  attrs[0].type = CKA_CLASS;
  attrs[0].pValue = &obj_class;
  attrs[0].ulValueLen = sizeof (obj_class);

  attrs[1].type = CKA_TOKEN;
  attrs[1].pValue = &cktrue;
  attrs[1].ulValueLen = sizeof (CK_BBOOL);

  attrs[2].type = CKA_LABEL;
  attrs[2].pValue = (unsigned char *)filename;
  attrs[2].ulValueLen = strlen (filename) + 1;

  return PK11_CreateGenericObject (g_tls_backend_nss_pem_slot,
				   attrs, 3, PR_FALSE);
}

static gboolean
load_from_files (GTlsCertificateNss  *nss,
		 GError             **error)
{
  PK11GenericObject *cert_obj, *key_obj = NULL;
  SECItem cert_der, id;

  if (nss->priv->cert_file)
    {
      cert_obj = create_pkcs11_object (nss->priv->cert_file, CKO_CERTIFICATE);
      if (!cert_obj)
	{
	cert_fail:
	  g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
			       _("Could not read certificate data"));
	  return FALSE;
	}

      if (PK11_ReadRawAttribute (PK11_TypeGeneric, cert_obj,
				 CKA_VALUE, &cert_der) != SECSuccess)
	{
	  PK11_DestroyGenericObject (cert_obj);
	  goto cert_fail;
	}

      nss->priv->cert = PK11_FindCertFromDERCertItem (g_tls_backend_nss_pem_slot,
						      &cert_der, NULL);
      SECITEM_FreeItem (&cert_der, PR_FALSE);
      PK11_DestroyGenericObject (cert_obj);
      if (!nss->priv->cert)
	goto cert_fail;
    }

  /* Try to create a private key object from the cert file if a
   * separate key file was not specified, but don't consider failure
   * to be an error in that case.
   */
  key_obj = create_pkcs11_object (nss->priv->key_file ?
				  nss->priv->key_file :
				  nss->priv->cert_file,
				  CKO_PRIVATE_KEY);
  if (!key_obj)
    {
      if (!nss->priv->key_file)
	return TRUE;

    key_fail:
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
			   _("Could not read private key data"));
      return FALSE;
    }

  /* In theory we should be able to use PK11_FindKeyByDERCert here,
   * but it doesn't work right with the PEM module.
   */
  if (PK11_ReadRawAttribute (PK11_TypePrivKey, key_obj,
			     CKA_ID, &id) != SECSuccess)
    {
      PK11_DestroyGenericObject (key_obj);
      goto key_fail;
    }
  nss->priv->key = PK11_FindKeyByKeyID (g_tls_backend_nss_pem_slot,
					&id, NULL);
  SECITEM_FreeItem (&id, PR_FALSE);
  PK11_DestroyGenericObject (key_obj);
  if (!nss->priv->key)
    goto key_fail;

  if (nss->priv->delete_key_file)
    {
      unlink (nss->priv->key_file);
      nss->priv->delete_key_file = FALSE;
    }

  return TRUE;
}

#define PEM_CERTIFICATE_HEADER "-----BEGIN CERTIFICATE-----"
#define PEM_CERTIFICATE_FOOTER "-----END CERTIFICATE-----"
#define PEM_PRIVKEY_HEADER     "-----BEGIN RSA PRIVATE KEY-----"
#define PEM_PRIVKEY_FOOTER     "-----END RSA PRIVATE KEY-----"
#define PEM_PKCS8_HEADER     "-----BEGIN PRIVATE KEY-----"
#define PEM_PKCS8_FOOTER     "-----END PRIVATE KEY-----"

static char *
encode_pem (const char *header,
	    const char *footer,
	    guint8     *data,
	    gsize       length)
{
  GString *pem;
  char *out;
  int encoded_len, broken_len, full_len;
  int state = 0, save = 0;

  encoded_len = (length / 3 + 1) * 4;
  broken_len = encoded_len + (encoded_len / 72) + 1;
  full_len = strlen (header) + 1 + broken_len + strlen (footer) + 1;

  pem = g_string_sized_new (full_len + 1);
  g_string_append (pem, header);
  g_string_append_c (pem, '\n');
  out = pem->str + pem->len;
  out += g_base64_encode_step (data, length, TRUE, out, &state, &save);
  out += g_base64_encode_close (TRUE, out, &state, &save);
  pem->len = out - pem->str;
  g_string_append (pem, footer);
  g_string_append_c (pem, '\n');

  return g_string_free (pem, FALSE);
}

static void
g_tls_certificate_nss_get_property (GObject    *object,
				    guint       prop_id,
				    GValue     *value,
				    GParamSpec *pspec)
{
  GTlsCertificateNss *nss = G_TLS_CERTIFICATE_NSS (object);
  CERTCertificate *nss_cert = nss->priv->cert;

  switch (prop_id)
    {
    case PROP_CERTIFICATE:
      if (nss_cert)
	{
	  GByteArray *certificate;

	  certificate = g_byte_array_sized_new (nss_cert->derCert.len);
	  certificate->len = nss_cert->derCert.len;
	  memcpy (certificate->data, nss_cert->derCert.data,
		  nss_cert->derCert.len);
	  g_value_take_boxed (value, certificate);
	}
      else
	g_value_set_boxed (value, NULL);
      break;

    case PROP_CERTIFICATE_PEM:
      if (nss_cert)
	{
	  g_value_take_string (value, encode_pem (PEM_CERTIFICATE_HEADER,
						  PEM_CERTIFICATE_FOOTER,
						  nss_cert->derCert.data,
						  nss_cert->derCert.len));
	}
      else
	g_value_set_string (value, NULL);
      break;

    case PROP_ISSUER:
      g_value_set_object (value, nss->priv->issuer);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_certificate_nss_set_property (GObject      *object,
				    guint         prop_id,
				    const GValue *value,
				    GParamSpec   *pspec)
{
  GTlsCertificateNss *nss = G_TLS_CERTIFICATE_NSS (object);
  GByteArray *bytes;
  const gchar *string;
  gchar *free_string = NULL;
  gint fd, left, nwrote;

  if (nss->priv->construct_error)
    return;

  switch (prop_id)
    {
    case PROP_CERTIFICATE:
      bytes = g_value_get_boxed (value);
      if (!bytes)
	break;
      g_return_if_fail (nss->priv->cert == NULL);
      g_return_if_fail (nss->priv->cert_file == NULL);

      /* Make sure it's really DER */
      if (!g_strstr_len ((gchar *)bytes->data, bytes->len, PEM_CERTIFICATE_HEADER))
	nss->priv->cert = CERT_DecodeCertFromPackage ((gchar *)bytes->data, bytes->len);

      if (!nss->priv->cert)
	{
	  nss->priv->construct_error =
	    g_error_new (G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
			 _("Could not parse DER certificate"));
	}
      break;

    case PROP_CERTIFICATE_PEM:
      string = g_value_get_string (value);
      if (!string)
	break;
      g_return_if_fail (nss->priv->cert == NULL);
      g_return_if_fail (nss->priv->cert_file == NULL);

      /* Make sure it's really PEM */
      if (strstr (string, PEM_CERTIFICATE_HEADER))
	nss->priv->cert = CERT_DecodeCertFromPackage ((gchar *)string, strlen (string));

      if (!nss->priv->cert)
	{
	  nss->priv->construct_error =
	    g_error_new (G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
			 _("Could not parse PEM certificate"));
	}
      break;

    case PROP_CERTIFICATE_FILE:
      string = g_value_get_string (value);
      if (!string)
	break;
      g_return_if_fail (nss->priv->cert == NULL);
      g_return_if_fail (nss->priv->cert_file == NULL);

      nss->priv->cert_file = g_strdup (string);
      break;

    case PROP_PRIVATE_KEY:
      bytes = g_value_get_boxed (value);
      if (!bytes)
	break;
      g_return_if_fail (nss->priv->key_file == NULL);

      /* Make sure it's really DER */
      if (g_strstr_len ((gchar *)bytes->data, bytes->len, PEM_PRIVKEY_HEADER) ||
	  g_strstr_len ((gchar *)bytes->data, bytes->len, PEM_PKCS8_HEADER))
	{
	  nss->priv->construct_error =
	    g_error_new (G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
			 _("Could not parse DER private key"));
	  break;
	}
      string = free_string = encode_pem (PEM_PRIVKEY_HEADER,
					 PEM_PRIVKEY_FOOTER,
					 bytes->data, bytes->len);
      goto write_private_key_pem;      

    case PROP_PRIVATE_KEY_PEM:
      string = g_value_get_string (value);
      if (!string)
	break;
      g_return_if_fail (nss->priv->key_file == NULL);

      /* Make sure it's really PEM */
      if (!strstr (string, PEM_PRIVKEY_HEADER) &&
	  !strstr (string, PEM_PKCS8_HEADER))
	{
	  nss->priv->construct_error =
	    g_error_new (G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
			 _("Could not parse PEM certificate"));
	  break;
	}

    write_private_key_pem:
      /* There is no public NSS API to create a SECKEYPrivateKey from
       * raw DER data. So we have to have the PEM PKCS#11 module do it
       * for us, which means we have to write the data out to a
       * temporary file. Ugh.
       */
      nss->priv->key_file = g_build_filename (g_get_user_runtime_dir (),
					      "XXXXXX.key",
					      NULL);
      fd = g_mkstemp (nss->priv->key_file);
      if (fd == -1)
	{
	  int errsv = errno;

	  g_set_error (&nss->priv->construct_error,
		       G_IO_ERROR, g_io_error_from_errno (errsv),
		       _("Unable to create temporary private key file: %s"),
		       g_strerror (errsv));
	}
      else
	{
	  left = strlen (string);
	  while (left)
	    {
	      nwrote = write (fd, string, left);
	      if (nwrote == -1)
		{
		  int errsv = errno;

		  if (errno == EINTR)
		    continue;
		  g_set_error (&nss->priv->construct_error,
			       G_IO_ERROR, g_io_error_from_errno (errsv),
			       _("Unable to create temporary private key file: %s"),
			       g_strerror (errsv));
		  break;
		}

	      string += nwrote;
	      left -= nwrote;
	    }

	  close (fd);
	  nss->priv->delete_key_file = TRUE;
	}
      break;

    case PROP_PRIVATE_KEY_FILE:
      string = g_value_get_string (value);
      if (!string)
	break;
      g_return_if_fail (nss->priv->key_file == NULL);

      nss->priv->key_file = g_strdup (string);
      break;

    case PROP_ISSUER:
      nss->priv->issuer = g_value_dup_object (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }

  g_free (free_string);
}

static void
g_tls_certificate_nss_init (GTlsCertificateNss *nss)
{
  nss->priv = G_TYPE_INSTANCE_GET_PRIVATE (nss,
					   G_TYPE_TLS_CERTIFICATE_NSS,
					   GTlsCertificateNssPrivate);
}

static gboolean
g_tls_certificate_nss_initable_init (GInitable       *initable,
				     GCancellable    *cancellable,
				     GError         **error)
{
  GTlsCertificateNss *nss = G_TLS_CERTIFICATE_NSS (initable);

  if (nss->priv->construct_error)
    {
      g_propagate_error (error, nss->priv->construct_error);
      nss->priv->construct_error = NULL;
      return FALSE;
    }

  if (!nss->priv->cert)
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
			   _("No certificate data provided"));
      return FALSE;
    }

  return TRUE;
}

/* FIXME: mostly dup from gnutls */
static GTlsCertificateFlags
g_tls_certificate_nss_verify_identity (GTlsCertificateNss *nss,
				       GSocketConnectable *identity)
{
  const char *hostname;

  if (G_IS_NETWORK_ADDRESS (identity))
    hostname = g_network_address_get_hostname (G_NETWORK_ADDRESS (identity));
  else if (G_IS_NETWORK_SERVICE (identity))
    hostname = g_network_service_get_domain (G_NETWORK_SERVICE (identity));
  else
    hostname = NULL;

  if (hostname)
    {
      if (CERT_VerifyCertName (nss->priv->cert, hostname) == SECSuccess)
	return 0;
    }

  /* FIXME: check sRVName and uniformResourceIdentifier
   * subjectAltNames, if appropriate for @identity.
   */

  return G_TLS_CERTIFICATE_BAD_IDENTITY;
}

static void
g_tls_certificate_nss_expand_chain (GTlsCertificateNss *nss_cert)
{
  GTlsCertificateNss *c, *issuer = NULL;
  CERTCertificateList *list;
  CERTCertificate *cert;
  SECCertUsage usage;
  int i;

  g_return_if_fail (nss_cert->priv->cert->nsCertType != 0);

  if (nss_cert->priv->expanded)
    return;

  if (nss_cert->priv->cert->nsCertType & NS_CERT_TYPE_SSL_CLIENT)
    usage = certUsageSSLClient;
  else
    usage = certUsageSSLServer;

  list = CERT_CertChainFromCert (nss_cert->priv->cert, usage, PR_TRUE);
  /* list->certs[0] is nss_cert itself, so start from index 1 */
  for (i = 1, c = nss_cert; i < list->len; i++, c = c->priv->issuer)
    {
      cert = CERT_FindCertByDERCert (g_tls_backend_nss_certdbhandle,
				     &list->certs[i]);
      issuer = g_tls_database_nss_get_gcert (g_tls_backend_nss_default_database, cert, TRUE);
      CERT_DestroyCertificate (cert);

      if (c->priv->issuer == issuer)
	{
	  g_object_unref (issuer);
	  break;
	}

      if (c->priv->issuer)
	g_object_unref (c->priv->issuer);
      c->priv->issuer = issuer;
      c->priv->expanded = TRUE;
    }

  if (i == list->len && issuer)
    {
      issuer->priv->expanded = TRUE;
      g_clear_object (&issuer->priv->issuer);
    }

  CERT_DestroyCertificateList (list);
}

/* Our certificate verification routine... called by both
 * g_tls_certificate_nss_verify() and g_tls_database_nss_verify_chain().
 *
 * For our verification purposes, we have to treat the certificates in
 * @database or @trusted_ca as though they were trusted, but we can't
 * actually mark them trusted because we don't know why our caller is
 * currently considering them trusted, so we can't let that trust
 * "leak" into the rest of the program.
 *
 * Fortunately, NSS will tell us in excruciating detail exactly what it
 * doesn't like about a certificate, and so if the only problem with
 * the cert is that it's signed by a @database or @trusted_ca cert that
 * NSS doesn't like, then we can just ignore that error.
 */
GTlsCertificateFlags
g_tls_certificate_nss_verify_full (GTlsCertificate          *chain,
				   GTlsDatabase             *database,
				   GTlsCertificate          *trusted_ca,
				   const gchar              *purpose,
				   GSocketConnectable       *identity,
				   GTlsInteraction          *interaction,
				   GTlsDatabaseVerifyFlags   flags,
				   GCancellable             *cancellable,
				   GError                  **error)
{
  GTlsCertificateNss *nss_cert = G_TLS_CERTIFICATE_NSS (chain);
  GTlsCertificateFlags result;
  SECCertificateUsage usage;
  PLArenaPool *arena;
  CERTVerifyLog *log;
  CERTVerifyLogNode *node;
  PRTime now = PR_Now ();
  SECCertTimeValidity time_validity;
  int trusted_ca_index = -1;

  g_return_val_if_fail (database == NULL || trusted_ca == NULL, G_TLS_CERTIFICATE_GENERIC_ERROR);

  if (database == (GTlsDatabase *)g_tls_backend_nss_default_database)
    database = NULL;

  if (!strcmp (purpose, G_TLS_DATABASE_PURPOSE_AUTHENTICATE_SERVER))
    usage = certificateUsageSSLServer;
  else if (!strcmp (purpose, G_TLS_DATABASE_PURPOSE_AUTHENTICATE_CLIENT))
    usage = certificateUsageSSLClient;
  else
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
		   _("Unsupported key purpose OID '%s'"), purpose);
      return G_TLS_CERTIFICATE_GENERIC_ERROR;
    }

  result = 0;

  /* Verify the certificate and log all errors. As a side effect, this
   * will ensure that nss_cert->priv->cert->nsCertType is set.
   */
  arena = PORT_NewArena (512);
  log = PORT_ArenaZNew (arena, CERTVerifyLog);
  log->arena = arena;
  CERT_VerifyCert (g_tls_backend_nss_certdbhandle, nss_cert->priv->cert,
		   PR_TRUE, usage, now, interaction, log);

  /* Now expand the gtls-level chain, and see if it contains a cert
   * from @trusted_ca or @database, and if so, remember where in the
   * chain it is.
   */
  g_tls_certificate_nss_expand_chain (nss_cert);
  if (database || trusted_ca)
    {
      GTlsFileDatabaseNss *db_nss = database ? G_TLS_FILE_DATABASE_NSS (database) : NULL;
      GTlsCertificateNss *c;
      int n;

      for (c = nss_cert, n = 0; c; c = c->priv->issuer, n++)
	{
	  if (trusted_ca && c == (GTlsCertificateNss *)trusted_ca)
	    break;
	  if (db_nss && g_tls_file_database_nss_contains (db_nss, c))
	    break;
	}

      if (c)
	trusted_ca_index = n;
      else
	result |= G_TLS_CERTIFICATE_UNKNOWN_CA;
    }

  /* Now go through the verification log translating the errors */
  for (node = log->head; node; node = node->next)
    {
      if (trusted_ca_index != -1 && node->depth > trusted_ca_index)
	break;

      switch (node->error)
	{
	case SEC_ERROR_INADEQUATE_KEY_USAGE:
	  /* Cert is not appropriately tagged for signing. For
	   * historical/compatibility reasons, we ignore this when
	   * using PEM certificates.
	   */
	  if (database || trusted_ca)
	    break;
	  /* else fall through */

	case SEC_ERROR_UNKNOWN_ISSUER:
	  /* Cert was issued by an unknown CA */
	case SEC_ERROR_UNTRUSTED_ISSUER:
	  /* Cert is a CA that is not marked trusted */
	case SEC_ERROR_CA_CERT_INVALID:
	  /* Cert is not a CA */

	  /* These are all OK if they occur on the trusted CA, but not
	   * before it.
	   */
	  if (node->depth != trusted_ca_index)
	    result |= G_TLS_CERTIFICATE_UNKNOWN_CA;
	  break;

	case SEC_ERROR_CERT_NOT_IN_NAME_SPACE:
	  /* Cert is not authorized to sign the cert it signed */
	  result |= G_TLS_CERTIFICATE_UNKNOWN_CA;
	  break;

	case SEC_ERROR_EXPIRED_CERTIFICATE:
	case SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE:
	  /* Cert is either expired or not yet valid;
	   * CERT_VerifyCert() doesn't distinguish.
	   */
	  time_validity =  CERT_CheckCertValidTimes (node->cert, now, PR_FALSE);
	  if (time_validity == secCertTimeNotValidYet)
	    result |= G_TLS_CERTIFICATE_NOT_ACTIVATED;
	  else if (time_validity == secCertTimeExpired)
	    result |= G_TLS_CERTIFICATE_EXPIRED;
	  break;

	case SEC_ERROR_REVOKED_CERTIFICATE:
	  result |= G_TLS_CERTIFICATE_REVOKED;
	  break;

	default:
	  result |= G_TLS_CERTIFICATE_GENERIC_ERROR;
	  break;
	}

      CERT_DestroyCertificate (node->cert);
    }

  for (; node; node = node->next)
    CERT_DestroyCertificate (node->cert);
  PORT_FreeArena (log->arena, PR_FALSE);

  if (identity)
    result |= g_tls_certificate_nss_verify_identity (nss_cert, identity);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    result = G_TLS_CERTIFICATE_GENERIC_ERROR;

  return result;
}

static GTlsCertificateFlags
g_tls_certificate_nss_verify (GTlsCertificate     *cert,
			      GSocketConnectable  *identity,
			      GTlsCertificate     *trusted_ca)
{
  GTlsCertificateNss *nss_cert = G_TLS_CERTIFICATE_NSS (cert);
  GTlsCertificateFlags flags;

  /* nss_cert->priv->cert->nsCertType may not have been set yet, but
   * it will get set as a side effect of verifying the cert. If we
   * don't know yet what kind of key it is, we'll try server first.
   */

  if ((nss_cert->priv->cert->nsCertType & NS_CERT_TYPE_SSL_SERVER) ||
      (nss_cert->priv->cert->nsCertType == 0))
    {
      flags = g_tls_certificate_nss_verify_full (cert, NULL, trusted_ca,
						 G_TLS_DATABASE_PURPOSE_AUTHENTICATE_SERVER,
						 identity, NULL, 0, NULL, NULL);
    }

  if (!(nss_cert->priv->cert->nsCertType & NS_CERT_TYPE_SSL_SERVER))
    {
      flags = g_tls_certificate_nss_verify_full (cert, NULL, trusted_ca,
						 G_TLS_DATABASE_PURPOSE_AUTHENTICATE_CLIENT,
						 identity, NULL, 0, NULL, NULL);
    }

  return flags;
}

static void
g_tls_certificate_nss_class_init (GTlsCertificateNssClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsCertificateClass *certificate_class = G_TLS_CERTIFICATE_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GTlsCertificateNssPrivate));

  gobject_class->constructor  = g_tls_certificate_nss_constructor;
  gobject_class->get_property = g_tls_certificate_nss_get_property;
  gobject_class->set_property = g_tls_certificate_nss_set_property;
  gobject_class->finalize     = g_tls_certificate_nss_finalize;

  certificate_class->verify = g_tls_certificate_nss_verify;

  g_object_class_override_property (gobject_class, PROP_CERTIFICATE, "certificate");
  g_object_class_override_property (gobject_class, PROP_CERTIFICATE_PEM, "certificate-pem");
  g_object_class_override_property (gobject_class, PROP_PRIVATE_KEY, "private-key");
  g_object_class_override_property (gobject_class, PROP_PRIVATE_KEY_PEM, "private-key-pem");
  g_object_class_override_property (gobject_class, PROP_ISSUER, "issuer");

  g_object_class_install_property (gobject_class, PROP_CERTIFICATE_FILE,
				   g_param_spec_string ("certificate-file",
							"Certificate file",
							"File containing the certificate",
							NULL,
							G_PARAM_WRITABLE |
							G_PARAM_CONSTRUCT_ONLY |
							G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (gobject_class, PROP_PRIVATE_KEY_FILE,
				   g_param_spec_string ("private-key-file",
							"Private key file",
							"File containing the private key",
							NULL,
							G_PARAM_WRITABLE |
							G_PARAM_CONSTRUCT_ONLY |
							G_PARAM_STATIC_STRINGS));
}

static void
g_tls_certificate_nss_initable_iface_init (GInitableIface  *iface)
{
  iface->init = g_tls_certificate_nss_initable_init;
}

GTlsCertificateNss *
g_tls_certificate_nss_new_for_cert (CERTCertificate *cert)
{
  GTlsCertificateNss *nss;

  nss = g_object_new (G_TYPE_TLS_CERTIFICATE_NSS, NULL);
  nss->priv->cert = CERT_DupCertificate (cert);

  return nss;
}

CERTCertificate *
g_tls_certificate_nss_get_cert (GTlsCertificateNss *nss)
{
  return nss->priv->cert;
}

SECKEYPrivateKey *
g_tls_certificate_nss_get_key (GTlsCertificateNss *nss)
{
  return nss->priv->key;
}
