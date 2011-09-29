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
#include <glib.h>

#include "gtlsconnection-nss.h"
#include "gtlsbackend-nss.h"
#include "gtlscertificate-nss.h"
#include "gtlsclientconnection-nss.h"
#include "gtlsdatabase-nss.h"
#include "gtlsprfiledesc-nss.h"
#include <glib/gi18n-lib.h>

#include <secerr.h>
#include <ssl.h>
#include <sslerr.h>
#include <nspr.h>

static SECStatus g_tls_connection_nss_auth_certificate (void       *arg,
							PRFileDesc *fd, 
							PRBool      checkSig,
							PRBool      isServer);
static SECStatus g_tls_connection_nss_bad_cert         (void       *arg,
							PRFileDesc *fd);
static void      g_tls_connection_nss_handshaked       (PRFileDesc *fd,
							void       *arg);

static void g_tls_connection_nss_initable_iface_init (GInitableIface *iface);

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (GTlsConnectionNss, g_tls_connection_nss, G_TYPE_TLS_CONNECTION_BASE,
				  G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
							 g_tls_connection_nss_initable_iface_init););

struct _GTlsConnectionNssPrivate
{
  gboolean handshake_completed;
};

static void
g_tls_connection_nss_init (GTlsConnectionNss *nss)
{
  PRFileDesc *prfd;

  nss->priv = G_TYPE_INSTANCE_GET_PRIVATE (nss, G_TYPE_TLS_CONNECTION_NSS, GTlsConnectionNssPrivate);

  prfd = g_tls_prfiledesc_new (nss);
  nss->prfd = SSL_ImportFD (NULL, prfd);

  SSL_OptionSet (nss->prfd, SSL_SECURITY, PR_TRUE);
  SSL_OptionSet (nss->prfd, SSL_ENABLE_FDX, PR_TRUE);
  SSL_OptionSet (nss->prfd, SSL_ENABLE_SSL2, PR_FALSE);
  SSL_OptionSet (nss->prfd, SSL_V2_COMPATIBLE_HELLO, PR_FALSE);
  SSL_OptionSet (nss->prfd, SSL_ENABLE_SSL3, PR_TRUE);
  SSL_OptionSet (nss->prfd, SSL_ENABLE_TLS, PR_TRUE);
}

static gboolean
g_tls_connection_nss_initable_init (GInitable     *initable,
				    GCancellable  *cancellable,
				    GError       **error)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (initable);
  GTlsConnectionNss *nss = G_TLS_CONNECTION_NSS (initable);

  g_return_val_if_fail (tls->base_istream != NULL &&
			tls->base_ostream != NULL, FALSE);

  SSL_AuthCertificateHook (nss->prfd, g_tls_connection_nss_auth_certificate, nss);
  SSL_BadCertHook (nss->prfd, g_tls_connection_nss_bad_cert, nss);
  SSL_SetPKCS11PinArg (nss->prfd, nss);
  SSL_HandshakeCallback (nss->prfd, g_tls_connection_nss_handshaked, nss);

  return TRUE;
}

static void
g_tls_connection_nss_finalize (GObject *object)
{
  GTlsConnectionNss *nss = G_TLS_CONNECTION_NSS (object);

  if (nss->prfd)
    PR_Close (nss->prfd);

  G_OBJECT_CLASS (g_tls_connection_nss_parent_class)->finalize (object);
}

static SECStatus
g_tls_connection_nss_auth_certificate (void       *arg,
				       PRFileDesc *fd, 
				       PRBool      checkSig,
				       PRBool      isServer)
{
  GTlsConnectionBase *tls = arg;
  CERTCertificate *cert;
  GTlsCertificateNss *gcert;
  GSocketConnectable *identity;
  gboolean accepted;

  if (isServer)
    identity = NULL;
  else
    identity = g_tls_client_connection_get_server_identity (G_TLS_CLIENT_CONNECTION (tls));

  cert = SSL_RevealCert (fd);
  gcert = g_tls_database_nss_get_gcert (g_tls_backend_nss_default_database,
					cert, TRUE);
  CERT_DestroyCertificate (cert);

  tls->peer_certificate = G_TLS_CERTIFICATE (gcert);
  tls->peer_certificate_errors =
    g_tls_database_verify_chain (tls->database ? tls->database :
				 G_TLS_DATABASE (g_tls_backend_nss_default_database),
				 tls->peer_certificate,
				 isServer ? G_TLS_DATABASE_PURPOSE_AUTHENTICATE_CLIENT : G_TLS_DATABASE_PURPOSE_AUTHENTICATE_SERVER,
				 identity,
				 tls->interaction,
				 G_TLS_DATABASE_VERIFY_NONE,
				 tls->read_cancellable,
				 &tls->read_error);

  if (tls->read_error)
    {
      PR_SetError (SSL_ERROR_BAD_CERTIFICATE, 0);
      return SECFailure;
    }
  
  if (isServer)
    {
      accepted = g_tls_connection_emit_accept_certificate (G_TLS_CONNECTION (tls),
							   tls->peer_certificate,
							   tls->peer_certificate_errors);
    }
  else
    {
      GTlsCertificateFlags validation_flags = g_tls_client_connection_get_validation_flags (G_TLS_CLIENT_CONNECTION (tls));

      if (tls->peer_certificate_errors & validation_flags)
	{
	  accepted = g_tls_connection_emit_accept_certificate (G_TLS_CONNECTION (tls),
							       tls->peer_certificate,
							       tls->peer_certificate_errors);
	}
      else
	accepted = TRUE;
    }

  if (accepted)
    return SECSuccess;
  else
    {
      PR_SetError (SSL_ERROR_BAD_CERTIFICATE, 0);
      return SECFailure;
    }
}

static SECStatus
g_tls_connection_nss_bad_cert (void       *arg,
			       PRFileDesc *fd)
{
  g_print ("BAD CERT\n");

  /* FIXME */

  return SECFailure;
}

static GTlsConnectionBaseStatus
end_nss_io (GTlsConnectionNss  *nss,
	    GIOCondition        direction,
	    gboolean            success,
	    GError            **error)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (nss);
  GError *my_error = NULL;
  GTlsConnectionBaseStatus status;

  status = g_tls_connection_base_pop_io (tls, direction, success, &my_error);
  if (status == G_TLS_CONNECTION_BASE_OK ||
      status == G_TLS_CONNECTION_BASE_WOULD_BLOCK)
    {
      if (my_error)
	g_propagate_error (error, my_error);
      return status;
    }

  if (my_error)
    g_propagate_error (error, my_error);
  if (error && !*error)
    {
      int errnum = PR_GetError ();

      /* FIXME: need real error descriptions */

      if (errnum == SSL_ERROR_BAD_CERTIFICATE)
	{
	  g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
			       _("Unacceptable TLS certificate"));

	}
      else if (errnum == SSL_ERROR_BAD_CERT_ALERT)
	{
	  if (tls->certificate_requested)
	    {
	      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED,
				   _("TLS connection peer did not send a certificate"));
	    }
	  else
	    {
	      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_HANDSHAKE,
				   _("Peer rejected the provided TLS certificate"));
	    }
	}
      else if (errnum == SSL_ERROR_NO_CERTIFICATE)
	{
	  g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED,
			       _("TLS connection peer did not send a certificate"));
	}
      else if (IS_SSL_ERROR (errnum))
	{
	  g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
		       "SSL error %d", errnum);
	}
      else if (IS_SEC_ERROR (errnum))
	{
	  g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
		       "SEC error %d", errnum);
	}
      else
	{
	  g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
			       PR_ErrorToString (PR_GetError (), 1));
	}
    }

  return G_TLS_CONNECTION_BASE_ERROR;
}

#define BEGIN_NSS_IO(nss, direction, blocking, cancellable)		\
  g_tls_connection_base_push_io (G_TLS_CONNECTION_BASE (nss),		\
				 direction, blocking, cancellable);

#define END_NSS_IO(nss, direction, status, success, error)		\
  status = end_nss_io (nss, direction, success, error);

static GTlsConnectionBaseStatus
g_tls_connection_nss_read (GTlsConnectionBase    *tls,
			   void                  *buffer,
			   gsize                  count,
			   gboolean               blocking,
			   gssize                *nread,
			   GCancellable          *cancellable,
			   GError               **error)
{
  GTlsConnectionNss *nss = G_TLS_CONNECTION_NSS (tls);
  GTlsConnectionBaseStatus status;
  PRInt32 ret;

  BEGIN_NSS_IO (nss, G_IO_IN, blocking, cancellable);
  ret = PR_Recv (nss->prfd, buffer, count, 0, PR_INTERVAL_NO_TIMEOUT);
  END_NSS_IO (nss, G_IO_IN, status, ret >= 0, error);

  if (ret >= 0)
    *nread = ret;
  else
    g_prefix_error (error, _("Error reading data from TLS socket: "));

  return status;
}

static GTlsConnectionBaseStatus
g_tls_connection_nss_write (GTlsConnectionBase    *tls,
			    const void            *buffer,
			    gsize                  count,
			    gboolean               blocking,
			    gssize                *nwrote,
			    GCancellable          *cancellable,
			    GError               **error)
{
  GTlsConnectionNss *nss = G_TLS_CONNECTION_NSS (tls);
  GTlsConnectionBaseStatus status;
  PRInt32 ret;

  BEGIN_NSS_IO (nss, G_IO_OUT, blocking, cancellable);
  ret = PR_Send (nss->prfd, buffer, count, 0, PR_INTERVAL_NO_TIMEOUT);
  END_NSS_IO (nss, G_IO_OUT, status, ret >= 0, error);

  if (ret >= 0)
    *nwrote = ret;
  else
    g_prefix_error (error, _("Error writing data to TLS socket: "));

  return status;
}

static void
g_tls_connection_nss_handshaked (PRFileDesc *fd,
				 void       *arg)
{
  GTlsConnectionNss *nss = arg;

  nss->priv->handshake_completed = TRUE;
}

static GTlsConnectionBaseStatus
g_tls_connection_nss_request_rehandshake (GTlsConnectionBase  *tls,
					  GCancellable        *cancellable,
					  GError             **error)
{
  GTlsConnectionNss *nss = G_TLS_CONNECTION_NSS (tls);
  GTlsConnectionBaseStatus status;
  SECStatus sec;

  BEGIN_NSS_IO (nss, G_IO_IN | G_IO_OUT, TRUE, cancellable);
  sec = SSL_ReHandshake (nss->prfd, G_IS_TLS_CLIENT_CONNECTION (tls));
  END_NSS_IO (nss, G_IO_IN | G_IO_OUT, status, sec == SECSuccess, error);

  if (error && *error)
    g_prefix_error (error, _("Error performing TLS handshake: "));

  return status;
}

static GTlsConnectionBaseStatus
g_tls_connection_nss_handshake (GTlsConnectionBase  *tls,
				GCancellable        *cancellable,
				GError             **error)
{
  GTlsConnectionNss *nss = G_TLS_CONNECTION_NSS (tls);
  GTlsConnectionBaseStatus status;
  GError *my_error = NULL;
  SECStatus sec;

  nss->priv->handshake_completed = FALSE;

  while (!nss->priv->handshake_completed && !my_error)
    {
      BEGIN_NSS_IO (nss, G_IO_IN | G_IO_OUT, TRUE, cancellable);
      sec = SSL_ForceHandshake (nss->prfd);
      END_NSS_IO (nss, G_IO_IN | G_IO_OUT, status, sec == SECSuccess, &my_error);

      if (!nss->priv->handshake_completed && !my_error)
	{
	  guint8 buf[1024];
	  gssize nread;

	  /* Got app data instead of rehandshake; buffer it and try again */
	  status = g_tls_connection_nss_read (tls, buf, sizeof (buf), TRUE,
					      &nread, cancellable, &my_error);
	  if (status != G_TLS_CONNECTION_BASE_OK)
	    break;
	  if (!tls->app_data_buf)
	    tls->app_data_buf = g_byte_array_new ();
	  g_byte_array_append (tls->app_data_buf, buf, nread);
	}
    }

  if (my_error)
    g_propagate_error (error, my_error);
  if (error && *error)
    g_prefix_error (error, _("Error performing TLS handshake: "));

  return status;
}

static GTlsConnectionBaseStatus
g_tls_connection_nss_complete_handshake (GTlsConnectionBase  *tls,
					 GError             **error)
{
  /* FIXME */
  return G_TLS_CONNECTION_BASE_OK;
}

static GTlsConnectionBaseStatus
g_tls_connection_nss_close (GTlsConnectionBase  *tls,
			    GCancellable        *cancellable,
			    GError             **error)
{
  GTlsConnectionNss *nss = G_TLS_CONNECTION_NSS (tls);
  GTlsConnectionBaseStatus status;
  PRInt32 ret;

  BEGIN_NSS_IO (nss, G_IO_IN, TRUE, cancellable);
  ret = PR_Close (nss->prfd);
  END_NSS_IO (nss, G_IO_IN, status, ret == 0, error);

  nss->prfd = NULL;
  if (error && *error)
    g_prefix_error (error, _("Error performing TLS close: "));

  return status;
}

static void
g_tls_connection_nss_class_init (GTlsConnectionNssClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsConnectionBaseClass *base_class = G_TLS_CONNECTION_BASE_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GTlsConnectionNssPrivate));

  gobject_class->finalize     = g_tls_connection_nss_finalize;

  base_class->request_rehandshake = g_tls_connection_nss_request_rehandshake;
  base_class->handshake           = g_tls_connection_nss_handshake;
  base_class->complete_handshake  = g_tls_connection_nss_complete_handshake;
  base_class->read_fn             = g_tls_connection_nss_read;
  base_class->write_fn            = g_tls_connection_nss_write;
  base_class->close_fn            = g_tls_connection_nss_close;
}

static void
g_tls_connection_nss_initable_iface_init (GInitableIface *iface)
{
  iface->init = g_tls_connection_nss_initable_init;
}
