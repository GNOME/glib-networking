/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2015 NICE s.r.l.
 * Copyright 2019 Igalia S.L.
 * Copyright 2019 Metrological Group B.V.
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
 */

#include "config.h"
#include "gtlsoperationsthread-openssl.h"

#include "gtlsconnection-openssl.h"

#include <glib/gi18n-lib.h>

#define DEFAULT_CIPHER_LIST "HIGH:!DSS:!aNULL@STRENGTH"

static int data_index = -1;

struct _GTlsOperationsThreadOpenssl {
  GTlsOperationsThreadBase parent_instance;

  GTlsOperationsThreadType thread_type;

  BIO *bio;
  SSL_SESSION *session;
  SSL *ssl;
  SSL_CTX *ssl_ctx;

  /* Valid only during current operation. */
  GTlsCertificate *op_own_certificate;

  gboolean handshaking;
  gboolean ever_handshaked;
  gboolean shutting_down;
};

static GInitableIface *g_tls_operations_thread_openssl_parent_initable_iface;

static void g_tls_operations_thread_openssl_initable_iface_init (GInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (GTlsOperationsThreadOpenssl, g_tls_operations_thread_openssl, G_TYPE_TLS_OPERATIONS_THREAD_BASE,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                g_tls_operations_thread_openssl_initable_iface_init);
                         )

static inline gboolean
is_client (GTlsOperationsThreadOpenssl *self)
{
  return self->thread_type == G_TLS_OPERATIONS_THREAD_CLIENT;
}

static inline gboolean
is_server (GTlsOperationsThreadOpenssl *self)
{
  return self->thread_type == G_TLS_OPERATIONS_THREAD_SERVER;
}

static void
g_tls_operations_thread_openssl_set_server_identity (GTlsOperationsThreadBase *base,
                                                     const gchar              *server_identity)
{
  GTlsOperationsThreadOpenssl *self = G_TLS_OPERATIONS_THREAD_OPENSSL (base);

  g_assert (is_client (self));

#if OPENSSL_VERSION_NUMBER >= 0x10002000L && !defined (LIBRESSL_VERSION_NUMBER)
  if (server_identity)
    {
      X509_VERIFY_PARAM *param;

      param = X509_VERIFY_PARAM_new ();
      X509_VERIFY_PARAM_set1_host (param, server_identity, 0);
      SSL_CTX_set1_param (self->ssl_ctx, param);
      X509_VERIFY_PARAM_free (param);

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
      SSL_set_tlsext_host_name (self->ssl, server_identity);
#endif
    }
#endif
}

static void
begin_openssl_io (GTlsOperationsThreadOpenssl *self,
                  GCancellable                *cancellable)
{
  g_tls_bio_set_cancellable (self->bio, cancellable);

  /* FIXME: where exactly to store errors? */
#if 0
  error = g_tls_connection_base_get_read_error (tls);
  g_clear_error (error);
  g_tls_bio_set_read_error (priv->bio, error);
#endif
}

static GTlsOperationStatus
end_openssl_io (GTlsOperationsThreadOpenssl  *self,
                GIOCondition                  direction,
                int                           ret,
                GError                      **error,
                const char                   *err_prefix)
{
  int err_code, err, err_lib, reason;
  GError *my_error = NULL;
  GTlsOperationStatus status;

  g_tls_bio_set_cancellable (self->bio, NULL);

  status = g_tls_operations_thread_base_pop_io (self, direction, ret > 0, &my_error);

  err_code = SSL_get_error (self->ssl, ret);

  if (err_code == SSL_ERROR_ZERO_RETURN)
    return G_TLS_OPERATION_SUCCESS;

  if (status == G_TLS_OPERATION_SUCCESS ||
      status == G_TLS_OPERATION_WOULD_BLOCK ||
      status == G_TLS_OPERATION_TIMED_OUT)
    {
      if (my_error)
        g_propagate_error (error, my_error);
      return status;
    }

  /* This case is documented that it may happen and that is perfectly fine */
  if (err_code == SSL_ERROR_SYSCALL &&
      ((self->shutting_down && !my_error) || g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_BROKEN_PIPE)))
    {
      g_clear_error (&my_error);
      return G_TLS_OPERATION_SUCCESS;
    }

  err = ERR_get_error ();
  err_lib = ERR_GET_LIB (err);
  reason = ERR_GET_REASON (err);

  if (self->handshaking && !self->ever_handshaked)
    {
      if (reason == SSL_R_BAD_PACKET_LENGTH ||
          reason == SSL_R_UNKNOWN_ALERT_TYPE ||
          reason == SSL_R_DECRYPTION_FAILED ||
          reason == SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC ||
          reason == SSL_R_BAD_PROTOCOL_VERSION_NUMBER ||
          reason == SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE ||
          reason == SSL_R_UNKNOWN_PROTOCOL)
        {
          g_clear_error (&my_error);
          g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_NOT_TLS,
                       _("Peer failed to perform TLS handshake: %s"), ERR_reason_error_string (err));
          return G_TLS_OPERATION_ERROR;
        }
    }

#ifdef SSL_R_SHUTDOWN_WHILE_IN_INIT
  /* XXX: this error happens on ubuntu when shutting down the connection, it
   * seems to be a bug in a specific version of openssl, so let's handle it
   * gracefully
   */
  if (reason == SSL_R_SHUTDOWN_WHILE_IN_INIT)
    {
      g_clear_error (&my_error);
      return G_TLS_OPERATION_SUCCESS;
    }
#endif

  if (reason == SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE
#ifdef SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED
      || reason == SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED
#endif
     )
    {
      g_clear_error (&my_error);
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED,
                           _("TLS connection peer did not send a certificate"));
      return status;
    }

  if (reason == SSL_R_CERTIFICATE_VERIFY_FAILED)
    {
      g_clear_error (&my_error);
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                   _("Unacceptable TLS certificate"));
      return G_TLS_OPERATION_ERROR;
    }

  if (reason == SSL_R_TLSV1_ALERT_UNKNOWN_CA)
    {
      g_clear_error (&my_error);
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                   _("Unacceptable TLS certificate authority"));
      return G_TLS_OPERATION_ERROR;
    }

  if (err_lib == ERR_LIB_RSA && reason == RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY)
    {
      g_clear_error (&my_error);
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                           _("Digest too big for RSA key"));
      return G_TLS_OPERATION_ERROR;
    }

  if (my_error)
    g_propagate_error (error, my_error);
  else
    /* FIXME: this is just for debug */
    g_message ("end_openssl_io %s: %d, %d, %d", G_IS_TLS_CLIENT_CONNECTION (tls) ? "client" : "server", err_code, err_lib, reason);

  if (error && !*error)
    {
      char error_str[256];
      ERR_error_string_n (SSL_get_error (self->ssl, ret), error_str, sizeof (error_str));
      *error = g_error_new (G_TLS_ERROR, G_TLS_ERROR_MISC, "%s: %s", err_prefix, err_str);
    }

  return G_TLS_OPERATION_ERROR;
}

#define BEGIN_OPENSSL_IO(self, cancellable)            \
  do {                                                 \
    begin_openssl_io (self, cancellable);

#define END_OPENSSL_IO(self, direction, ret, status, errmsg, err) \
    status = end_openssl_io (self, direction, ret, err, errmsg);  \
  } while (status == G_TLS_OPERATION_TRY_AGAIN);

static GTlsCertificate *
get_peer_certificate (GTlsOperationsThreadOpenssl *self)
{
  X509 *peer;
  STACK_OF (X509) *certs;
  GTlsCertificateOpenssl *chain;
  SSL *ssl;

  peer = SSL_get_peer_certificate (self->ssl);
  if (!peer)
    return NULL;

  certs = SSL_get_peer_cert_chain (self->ssl);
  if (!certs)
    {
      X509_free (peer);
      return NULL;
    }

  chain = g_tls_certificate_openssl_build_chain (peer, certs);
  X509_free (peer);
  if (!chain)
    return NULL;

  return G_TLS_CERTIFICATE (chain);
}

static GTlsOperationStatus
g_tls_operations_thread_openssl_handshake (GTlsOperationsThreadBase  *base,
                                           HandshakeContext          *context,
                                           GTlsCertificate           *own_certificate,
                                           const gchar              **advertised_protocols,
                                           GTlsAuthenticationMode     auth_mode,
                                           gint64                     timeout,
                                           gchar                    **negotiated_protocol,
                                           GList                    **accepted_cas,
                                           GTlsCertificate          **peer_certificate,
                                           gboolean                  *session_resumed,
                                           GCancellable              *cancellable,
                                           GError                   **error)
{
  GTlsOperationsThreadOpenssl *self = G_TLS_OPERATIONS_THREAD_OPENSSL (base);
  GTlsOperationStatus status;
  gboolean accepted = FALSE;
  int ret;

  self->op_own_certificate = own_certificate;

  /* TODO: No support yet for ALPN. */
  g_assert (!advertised_protocols);

  /* FIXME: Doesn't respect timeout. */

  self->handshake_context = context;
  self->handshaking = TRUE;

  BEGIN_OPENSSL_IO (self, cancellable);
  ret = SSL_do_handshake (ssl);
  END_OPENSSL_IO (self, G_IO_IN | G_IO_OUT, ret, status,
                  _("Error performing TLS handshake"), error);

  self->handshake_context = NULL;
  self->handshaking = FALSE;

  if (status == G_TLS_OPERATION_SUCCESS)
    self->ever_handshaked = TRUE;

  *peer_certificate = get_peer_certificate (self);

  /* FIXME: this is really too late to be performing certificate verification.
   * We should be doing it during the handshake.
   */
  if (ret > 0 &&
      !g_tls_operations_thread_base_verify_certificate (G_TLS_OPERATIONS_THREAD_BASE (self),
                                                        *peer_certificate,
                                                        context))
    {
      status = G_TLS_OPERATION_ERROR;
    }

  self->op_own_certificate = NULL;

  /* TODO: No support yet for ALPN. */
  *negotiated_protocol = NULL;

  /* FIXME FIXME FIXME: accepted CAs */

  /* TODO: No support yet for session resumption. */
  *session_resumed = FALSE;

  return status;
}

static GTlsOperationStatus
g_tls_operations_thread_openssl_read (GTlsOperationsThreadBase   *base,
                                      void                       *buffer,
                                      gsize                       size,
                                      gssize                     *nread,
                                      GCancellable               *cancellable,
                                      GError                    **error)
{
  GTlsOperationsThreadOpenssl *self = G_TLS_OPERATIONS_THREAD_OPENSSL (base);
  GTlsOperationStatus status;
  gssize ret;

  BEGIN_OPENSSL_IO (self, cancellable);
  ret = SSL_read (self->ssl, buffer, size);
  END_OPENSSL_IO (self, G_IO_OUT, ret, status,
                  _("Error reading data from TLS socket"), error);


  *nread = MAX (ret, 0);
  return status;
}

static GTlsOperationStatus
g_tls_operations_thread_openssl_write (GTlsOperationsThreadBase  *base,
                                       const void                *buffer,
                                       gsize                      size,
                                       gssize                    *nwrote,
                                       GCancellable              *cancellable,
                                       GError                   **error)
{
  GTlsOperationsThreadOpenssl *self = G_TLS_OPERATIONS_THREAD_OPENSSL (base);
  GTlsOperationStatus status;
  gssize ret;

  BEGIN_OPENSSL_IO (self, cancellable);
  ret = SSL_write (self->ssl, buffer, size);
  END_OPENSSL_IO (self, G_IO_OUT, ret, status,
                  _("Error writing data to TLS socket"), error);
  *nwrote = MAX (ret, 0);
  return status;
}

static GTlsOperationStatus
g_tls_operations_thread_openssl_close (GTlsOperationsThreadBase  *base,
                                       GCancellable              *cancellable,
                                       GError                   **error)
{
  GTlsOperationsThreadOpenssl *self = G_TLS_OPERATIONS_THREAD_OPENSSL (base);
  GTlsOperationStatus status;
  int ret;

  self->shutting_down = TRUE;

  BEGIN_OPENSSL_IO (self, cancellable);
  ret = SSL_shutdown (self->ssl);
  /* Note it is documented that getting 0 is correct when shutting down since
   * it means it will close the write direction
   */
  ret = ret == 0 ? 1 : ret;
  END_OPENSSL_IO (self, G_IO_IN | G_IO_OUT, ret, status,
                  _("Error performing TLS close"), error);

  return status;
}

static gboolean
set_cipher_list (GTlsOperationsThreadOpenssl  *self,
                 GError                      **error)
{
  const gchar *cipher_list;

  cipher_list = g_getenv ("G_TLS_OPENSSL_CIPHER_LIST");
  if (!cipher_list)
    cipher_list = DEFAULT_CIPHER_LIST;

  if (!SSL_CTX_set_cipher_list (self->ssl_ctx, cipher_list))
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Could not create TLS context: %s"),
                   ERR_error_string (ERR_get_error (), NULL));
      return FALSE;
    }

  return TRUE;
}

#ifdef SSL_CTX_set1_sigalgs_list
static void
set_signature_algorithm_list (GTlsOperationsThreadOpenssl *self)
{
  const gchar *signature_algorithm_list;

  signature_algorithm_list = g_getenv ("G_TLS_OPENSSL_SIGNATURE_ALGORITHM_LIST");
  if (!signature_algorithm_list)
    return;

  SSL_CTX_set1_sigalgs_list (self->ssl_ctx, signature_algorithm_list);
}
#endif

#ifdef SSL_CTX_set1_curves_list
static void
set_curve_list (GTlsOperationsThreadOpenssl *self)
{
  const gchar *curve_list;

  curve_list = g_getenv ("G_TLS_OPENSSL_CURVE_LIST");
  if (!curve_list)
    return;

  SSL_CTX_set1_curves_list (self->ssl_ctx, curve_list);
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined (LIBRESSL_VERSION_NUMBER)
static void
ssl_info_callback (const SSL *ssl,
                   int        type,
                   int        val)
{
  g_assert (is_server (self));

  if ((type & SSL_CB_HANDSHAKE_DONE) != 0)
    {
      /* Disable renegotiation (CVE-2009-3555) */
      ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
    }
}
#endif

static int
retrieve_certificate_cb (SSL       *ssl,
                         X509     **x509,
                         EVP_PKEY **pkey)
{
  GTlsOperationsThreadOpenssl *self;
  GTlsCertificate *cert;
  gboolean had_ca_list;

  self = SSL_get_ex_data (ssl, data_index);

  had_ca_list = self->ca_list != NULL;
  self->ca_list = SSL_get_client_CA_list (client->ssl);
  self->ca_list_changed = self->ca_list || had_ca_list;

  if (self->op_own_certificate)
    {
      EVP_PKEY *key;

      key = g_tls_certificate_openssl_get_key (G_TLS_CERTIFICATE_OPENSSL (cert));
      /* increase ref count */
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined (LIBRESSL_VERSION_NUMBER)
      CRYPTO_add (&key->references, 1, CRYPTO_LOCK_EVP_PKEY);
#else
      EVP_PKEY_up_ref (key);
#endif
      *pkey = key;

      *x509 = X509_dup (g_tls_certificate_openssl_get_cert (G_TLS_CERTIFICATE_OPENSSL (cert)));

      return 1;
    }

  g_tls_operations_thread_base_set_missing_requested_client_certificate (G_TLS_OPERATIONS_THREAD_BASE (self));

  return 0;
}

static void
g_tls_operations_thread_openssl_finalize (GObject *object)
{
  GTlsOperationsThreadOpenssl *self = G_TLS_OPERATIONS_THREAD_OPENSSL (object);

  SSL_free (self->ssl);
  SSL_CTX_free (self->ssl_ctx);
  SSL_SESSION_free (self->session);

  g_assert (!self->op_own_certificate);

  G_OBJECT_CLASS (g_tls_operations_thread_openssl_parent_class)->finalize (object);
}

static gboolean
g_tls_operations_thread_openssl_initable_init (GInitable     *initable,
                                               GCancellable  *cancellable,
                                               GError       **error)
{
  GTlsOperationsThreadOpenssl *self = G_TLS_OPERATIONS_THREAD_OPENSSL (initable);
  GIOStream *base_iostream = NULL;
  long options;
  const char *hostname;
  GTlsCertificate *cert; /* FIXME: remove, become part of handshake op? */

  if (!g_tls_operations_thread_openssl_parent_initable_iface->init (initable, cancellable, error))
    return FALSE;

  g_object_get (self,
                "base-io-stream", &base_iostream,
                "thread-type", &self->thread_type,
                NULL);
  g_assert (base_iostream);

  self->session = SSL_SESSION_new ();
  self->ssl_ctx = SSL_CTX_new (is_client (self) ? SSLv23_client_method () : SSLv23_server_method ());
  if (!self->ssl_ctx)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Could not create TLS context: %s"),
                   ERR_error_string (ERR_get_error (), NULL));
      return FALSE;
    }

    if (!set_cipher_list (self, error))
      return FALSE;

  /* Only TLS 1.2 or higher */
  options = SSL_OP_NO_TICKET |
            SSL_OP_NO_COMPRESSION |
#ifdef SSL_OP_NO_TLSv1_1
            SSL_OP_NO_TLSv1_1 |
#endif
            SSL_OP_NO_SSLv2 |
            SSL_OP_NO_SSLv3 |
            SSL_OP_NO_TLSv1;

  if (is_server (self))
    {
      SSL_CTX_set_options (self->ssl_ctx, options);
    }
  else
    {
      options |= SSL_OP_CIPHER_SERVER_PREFERENCE |
                 SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
                 SSL_OP_SINGLE_ECDH_USE;
#ifdef SSL_OP_NO_RENEGOTIATION
      options |= SSL_OP_NO_RENEGOTIATION;
#endif
      SSL_CTX_set_options (self->ssl_ctx, options);
      SSL_CTX_clear_options (self->ssl_ctx, SSL_OP_LEGACY_SERVER_CONNECT);

      SSL_CTX_set_client_cert_cb (self->ssl_ctx, retrieve_certificate_cb);
    }

  SSL_CTX_add_session (self->ssl_ctx, self->session);

#ifdef SSL_CTX_set1_sigalgs_list
  set_signature_algorithm_list (server);
#endif

#ifdef SSL_CTX_set1_curves_list
  set_curve_list (server);
#endif

  if (is_server (self))
    {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined (LIBRESSL_VERSION_NUMBER)
# ifdef SSL_CTX_set_ecdh_auto
      SSL_CTX_set_ecdh_auto (self->ssl_ctx, 1);
# else
      {
        EC_KEY *ecdh;

        ecdh = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
        if (ecdh)
          {
            SSL_CTX_set_tmp_ecdh (self->ssl_ctx, ecdh);
            EC_KEY_free (ecdh);
          }
      }
# endif

      SSL_CTX_set_info_callback (self->ssl_ctx, ssl_info_callback);
#endif

      cert = g_tls_connection_get_certificate (G_TLS_CONNECTION (initable));

#if OPENSSL_VERSION_NUMBER < 0x10002000L
      if (cert && !ssl_ctx_set_certificate (server->ssl_ctx, cert, error))
        return FALSE;
#endif
    }

  self->ssl = SSL_new (self->ssl_ctx);
  if (!self->ssl)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Could not create TLS connection: %s"),
                   ERR_error_string (ERR_get_error (), NULL));
      return FALSE;
    }

  self->bio = g_tls_bio_new (base_iostream);
  SSL_set_bio (ssl, self->bio, self->bio);
  g_object_unref (base_io_stream);

  if (data_index == -1)
    data_index = SSL_get_ex_new_index (0, (void *)"gtlsoperationsthread", NULL, NULL, NULL);
  SSL_set_ex_data (self->ssl, data_index, self);

  if (is_client (self))
    {
      SSL_set_connect_state (client->ssl);
    }
  else
    {
#if OPENSSL_VERSION_NUMBER >= 0x10002000L || defined (LIBRESSL_VERSION_NUMBER)
      if (cert && !ssl_set_certificate (server->ssl, cert, error))
        return FALSE;
#endif
      SSL_set_accept_state (server->ssl);
    }

  return TRUE;
}

static void
g_tls_operations_thread_openssl_init (GTlsOperationsThreadOpenssl *self)
{
}

static void
g_tls_operations_thread_openssl_class_init (GTlsOperationsThreadOpensslClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsOperationsThreadBaseClass *base_class = G_TLS_OPERATIONS_THREAD_BASE_CLASS (klass);

  gobject_class->finalize         = g_tls_operations_thread_openssl_finalize;

  base_class->copy_certificate    = g_tls_operations_thread_openssl_copy_certificate;
  base_class->set_server_identity = g_tls_operations_thread_openssl_set_server_identity;
  base_class->handshake_fn        = g_tls_operations_thread_openssl_handshake;
  base_class->read_fn             = g_tls_operations_thread_openssl_read;
  base_class->write_fn            = g_tls_operations_thread_openssl_write;
  base_class->close_fn            = g_tls_operations_thread_openssl_close;
}

static void
g_tls_operations_thread_openssl_initable_iface_init (GInitableIface *iface)
{
  g_tls_operations_thread_openssl_parent_initable_iface = g_type_interface_peek_parent (iface);

  iface->init = g_tls_operations_thread_openssl_initable_init;
}

GTlsOperationsThreadBase *
g_tls_operations_thread_openssl_new (GIOStream                *base_iostream,
                                     GTlsOperationsThreadType  type)
{
  return g_initable_new (G_TYPE_TLS_OPERATIONS_THREAD_OPENSSL,
                         NULL, NULL,
                         "base-iostream", base_iostream,
                         "thread-type", type,
                         NULL);
}
