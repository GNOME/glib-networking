/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2009 Red Hat, Inc
 * Copyright 2015, 2016 Collabora, Ltd.
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
#include "gtlsoperationsthread-gnutls.h"

#include "gtlsbackend-gnutls.h"
#include "gtlscertificate-gnutls.h"
#include "gtlsconnection-gnutls.h"

#include <errno.h>
#include <glib/gi18n-lib.h>
#include <gnutls/dtls.h>
#include <limits.h>

struct _GTlsOperationsThreadGnutls {
  GTlsOperationsThreadBase parent_instance;

  guint                            init_flags;
  gnutls_certificate_credentials_t creds;

  /* session_data is either the session ticket that was used to resume this
   * connection, or the most recent session ticket received from the server.
   * Because session ticket reuse is generally undesirable, it should only be
   * accessed if session_data_override is set.
   */
  GBytes                  *session_id;
  GBytes                  *session_data;
  gboolean                 session_data_override; /* FIXME: sort this all out */

  gchar                   *server_identity;

  gnutls_session_t         session;

  GIOStream               *base_iostream;
  GInputStream            *base_istream;
  GOutputStream           *base_ostream;
  GDatagramBased          *base_socket;

  gboolean                 handshaking;
  gboolean                 ever_handshaked;

  GCancellable            *op_cancellable;
  GError                  *op_error;

  gnutls_pcert_st         *pcert;
  unsigned int             pcert_length;
  gnutls_privkey_t         pkey;

  GPtrArray               *accepted_cas;
  gboolean                 accepted_cas_changed;
};

enum
{
  PROP_0,
  PROP_BASE_IO_STREAM,
  PROP_BASE_SOCKET,
  PROP_GNUTLS_FLAGS,
  LAST_PROP
};

static GParamSpec *obj_properties[LAST_PROP];

static gnutls_priority_t priority;

G_DEFINE_TYPE (GTlsOperationsThreadGnutls, g_tls_operations_thread_gnutls, G_TYPE_TLS_OPERATIONS_THREAD_BASE)

static inline gboolean
is_dtls (GTlsOperationsThreadGnutls *self)
{
  return self->init_flags & GNUTLS_DATAGRAM;
}

static inline gboolean
is_client (GTlsOperationsThreadGnutls *self)
{
  return self->init_flags & GNUTLS_CLIENT;
}

static inline gboolean
is_server (GTlsOperationsThreadGnutls *self)
{
  return self->init_flags & GNUTLS_SERVER;
}

static GTlsConnectionBaseStatus
end_gnutls_io (GTlsOperationsThreadGnutls  *self,
               GIOCondition                 direction,
               int                          ret,
               GError                     **error,
               const char                  *err_prefix)
{
  GTlsConnectionBase *tls;
  GTlsConnectionBaseStatus status;
  GError *my_error = NULL;

  /* We intentionally do not check for GNUTLS_E_INTERRUPTED here
   * Instead, the caller may poll for the source to become ready again.
   * (Note that GTlsOutputStreamGnutls and GTlsInputStreamGnutls inherit
   * from GPollableOutputStream and GPollableInputStream, respectively.)
   * See also the comment in set_gnutls_error().
   */
  if (ret == GNUTLS_E_AGAIN ||
      ret == GNUTLS_E_WARNING_ALERT_RECEIVED)
    return G_TLS_CONNECTION_BASE_TRY_AGAIN;

  tls = g_tls_operations_thread_base_get_connection (G_TLS_OPERATIONS_THREAD_BASE (self));

  status = g_tls_connection_base_pop_io (tls, direction, ret >= 0, &my_error);
  if (status == G_TLS_CONNECTION_BASE_OK ||
      status == G_TLS_CONNECTION_BASE_WOULD_BLOCK ||
      status == G_TLS_CONNECTION_BASE_TIMED_OUT)
    {
      if (my_error)
        g_propagate_error (error, my_error);
      return status;
    }

  g_assert (status == G_TLS_CONNECTION_BASE_ERROR);

  if (self->handshaking && !self->ever_handshaked)
    {
      if (g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_FAILED) ||
          g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_BROKEN_PIPE))
        {
          g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_NOT_TLS,
                       _("Peer failed to perform TLS handshake: %s"), my_error->message);
          g_clear_error (&my_error);
          return G_TLS_CONNECTION_BASE_ERROR;
        }

      if (status == GNUTLS_E_UNEXPECTED_PACKET_LENGTH ||
          status == GNUTLS_E_DECRYPTION_FAILED ||
          status == GNUTLS_E_UNSUPPORTED_VERSION_PACKET)
        {
          g_clear_error (&my_error);
          g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_NOT_TLS,
                       _("Peer failed to perform TLS handshake: %s"), gnutls_strerror (ret));
          return G_TLS_CONNECTION_BASE_ERROR;
        }
    }

  if (ret == GNUTLS_E_REHANDSHAKE)
    return G_TLS_CONNECTION_BASE_REHANDSHAKE;

  if (ret == GNUTLS_E_PREMATURE_TERMINATION)
    {
      if (self->handshaking && !self->ever_handshaked)
        {
          g_clear_error (&my_error);
          g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_NOT_TLS,
                       _("Peer failed to perform TLS handshake: %s"), gnutls_strerror (ret));
          return G_TLS_CONNECTION_BASE_ERROR;
        }

      if (g_tls_connection_get_require_close_notify (G_TLS_CONNECTION (tls)))
        {
          g_clear_error (&my_error);
          g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_EOF,
                               _("TLS connection closed unexpectedly"));
          return G_TLS_CONNECTION_BASE_ERROR;
        }

      return G_TLS_CONNECTION_BASE_OK;
    }

  if (ret == GNUTLS_E_NO_CERTIFICATE_FOUND || ret == GNUTLS_E_CERTIFICATE_REQUIRED)
    {
      g_clear_error (&my_error);
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED,
                           _("TLS connection peer did not send a certificate"));
      return G_TLS_CONNECTION_BASE_ERROR;
    }

  if (ret == GNUTLS_E_CERTIFICATE_ERROR)
    {
      g_clear_error (&my_error);
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                           _("Unacceptable TLS certificate"));
      return G_TLS_CONNECTION_BASE_ERROR;
    }

  if (ret == GNUTLS_E_FATAL_ALERT_RECEIVED)
    {
      g_clear_error (&my_error);
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Peer sent fatal TLS alert: %s"),
                   gnutls_alert_get_name (gnutls_alert_get (self->session)));
      return G_TLS_CONNECTION_BASE_ERROR;
    }

  if (ret == GNUTLS_E_INAPPROPRIATE_FALLBACK)
    {
      g_clear_error (&my_error);
      g_set_error_literal (error, G_TLS_ERROR,
                           G_TLS_ERROR_INAPPROPRIATE_FALLBACK,
                           _("Protocol version downgrade attack detected"));
      return G_TLS_CONNECTION_BASE_ERROR;
    }

  if (ret == GNUTLS_E_LARGE_PACKET)
    {
      guint mtu = gnutls_dtls_get_data_mtu (self->session);
      g_clear_error (&my_error);
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_MESSAGE_TOO_LARGE,
                   ngettext ("Message is too large for DTLS connection; maximum is %u byte",
                             "Message is too large for DTLS connection; maximum is %u bytes", mtu), mtu);
      return G_TLS_CONNECTION_BASE_ERROR;
    }

  if (ret == GNUTLS_E_TIMEDOUT)
    {
      g_clear_error (&my_error);
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                           _("The operation timed out"));
      return G_TLS_CONNECTION_BASE_ERROR;
    }

  if (error && my_error)
    g_propagate_error (error, my_error);

  if (error && !*error)
    {
      *error = g_error_new (G_TLS_ERROR, G_TLS_ERROR_MISC, "%s: %s",
                            err_prefix, gnutls_strerror (ret));
    }

  return G_TLS_CONNECTION_BASE_ERROR;
}

/* FIXME: do not use GTlsConnectionBase at all. */

#define BEGIN_GNUTLS_IO(self, direction, cancellable)          \
  g_assert (!self->op_error);                                  \
  g_assert (!self->op_cancellable);                            \
  self->op_cancellable = cancellable;                          \
  g_tls_connection_base_push_io (g_tls_operations_thread_base_get_connection (G_TLS_OPERATIONS_THREAD_BASE (self)),        \
                                 direction, 0, cancellable);   \
  do {

#define END_GNUTLS_IO(self, direction, ret, status, errmsg, err)      \
    status = end_gnutls_io (self, direction, ret, err, errmsg);       \
  } while (status == G_TLS_CONNECTION_BASE_TRY_AGAIN);                \
  self->op_cancellable = NULL;                                        \
  if (self->op_error) {                                               \
    g_propagate_error (err, self->op_error);                          \
    self->op_error = NULL;                                            \
  }

static void
initialize_gnutls_priority (void)
{
  const gchar *priority_override;
  const gchar *error_pos = NULL;
  int ret;

  g_assert (!priority);

  priority_override = g_getenv ("G_TLS_GNUTLS_PRIORITY");
  if (priority_override)
    {
      ret = gnutls_priority_init2 (&priority, priority_override, &error_pos, 0);
      if (ret != GNUTLS_E_SUCCESS)
        g_warning ("Failed to set GnuTLS session priority with beginning at %s: %s", error_pos, gnutls_strerror (ret));
      return;
    }

  ret = gnutls_priority_init2 (&priority, "%COMPAT:-VERS-TLS1.1:-VERS-TLS1.0", &error_pos, GNUTLS_PRIORITY_INIT_DEF_APPEND);
  if (ret != GNUTLS_E_SUCCESS)
    g_warning ("Failed to set GnuTLS session priority with error beginning at %s: %s", error_pos, gnutls_strerror (ret));
}

static void
g_tls_operations_thread_gnutls_copy_client_session_state (GTlsOperationsThreadBase *base,
                                                          GTlsOperationsThreadBase *base_source)
{
  GTlsOperationsThreadGnutls *self = G_TLS_OPERATIONS_THREAD_GNUTLS (base);
  GTlsOperationsThreadGnutls *source = G_TLS_OPERATIONS_THREAD_GNUTLS (base_source);

  g_assert (is_client (self));

  /* Precondition: source has handshaked, conn has not. */
  g_return_if_fail (!self->session_id);
  g_return_if_fail (source->session_id);

  /* Prefer to use a new session ticket, if possible. */
  self->session_data = g_tls_backend_gnutls_lookup_session_data (source->session_id);

  if (!self->session_data && source->session_data)
    {
      /* If it's not possible, we'll try to reuse the old ticket, even though
       * this is a privacy risk since TLS 1.3. Applications should not use this
       * function unless they need us to try as hard as possible to resume a
       * session, even at the cost of privacy.
       */
      self->session_data = g_bytes_ref (source->session_data);
    }

  self->session_data_override = !!self->session_data;
}

static void
g_tls_operations_thread_gnutls_set_server_identity (GTlsOperationsThreadBase *base,
                                                    const gchar              *server_identity)
{
  GTlsOperationsThreadGnutls *self = G_TLS_OPERATIONS_THREAD_GNUTLS (base);
  gchar *normalized_hostname;
  size_t len;

  g_assert (is_client (self));

  normalized_hostname = g_strdup (server_identity);
  len = strlen (server_identity);

  if (server_identity[len - 1] == '.')
    {
      normalized_hostname[len - 1] = '\0';
      len--;
    }

  gnutls_server_name_set (self->session, GNUTLS_NAME_DNS,
                          normalized_hostname, len);

  g_clear_pointer (&self->server_identity, g_free);
  self->server_identity = g_steal_pointer (&normalized_hostname);
}

static void
set_handshake_priority (GTlsOperationsThreadGnutls *self)
{
  int ret;

  g_assert (priority);

  ret = gnutls_priority_set (self->session, priority);
  if (ret != GNUTLS_E_SUCCESS)
    g_warning ("Failed to set GnuTLS session priority: %s", gnutls_strerror (ret));
}

static void
set_handshake_timeout (GTlsOperationsThreadGnutls *self,
                       gint64                      timeout)
{
  unsigned int timeout_ms;

  /* Convert from microseconds to milliseconds, but ensure the timeout
   * remains positive.
   */
  timeout_ms = (timeout + 999) / 1000;

  if (is_dtls (self))
    gnutls_dtls_set_timeouts (self->session, 1000 /* default */, timeout_ms);
  else
    gnutls_handshake_set_timeout (self->session, timeout_ms);
}

static void
set_advertised_protocols (GTlsOperationsThreadGnutls  *self,
                          const gchar                **advertised_protocols)
{
  gnutls_datum_t *protocols;
  int n_protos, i;

  n_protos = g_strv_length ((gchar **)advertised_protocols);
  protocols = g_new (gnutls_datum_t, n_protos);
  for (i = 0; advertised_protocols[i]; i++)
    {
      protocols[i].size = strlen (advertised_protocols[i]);
      protocols[i].data = (guchar *)advertised_protocols[i];
    }
  gnutls_alpn_set_protocols (self->session, protocols, n_protos, 0);
  g_free (protocols);
}

static void
compute_session_id (GTlsOperationsThreadGnutls *self)
{
  GSocketAddress *remote_addr;
  GInetAddress *iaddr;
  guint port;

  g_assert (is_client (self));

  /* The testsuite expects handshakes to actually happen. E.g. a test might
   * check to see that a handshake succeeds and then later check that a new
   * handshake fails. If we get really unlucky and the same port number is
   * reused for the server socket between connections, then we'll accidentally
   * resume the old session and skip certificate verification. Such failures
   * are difficult to debug because they require running the tests hundreds of
   * times simultaneously to reproduce (the port number does not get reused
   * quickly enough if the tests are run sequentially).
   *
   * So session resumption will just need to be tested manually.
   */
  if (g_test_initialized ())
    return;

  /* Create a TLS "session ID." We base it on the IP address since
   * different hosts serving the same hostname/service will probably
   * not share the same session cache. We base it on the
   * server-identity because at least some servers will fail (rather
   * than just failing to resume the session) if we don't.
   * (https://bugs.launchpad.net/bugs/823325)
   *
   * Note that our session IDs have no relation to TLS protocol
   * session IDs, e.g. as provided by gnutls_session_get_id2(). Unlike
   * our session IDs, actual TLS session IDs can no longer be used for
   * session resumption.
   */
  if (G_IS_SOCKET_CONNECTION (self->base_iostream))
    {
      remote_addr = g_socket_connection_get_remote_address (G_SOCKET_CONNECTION (self->base_iostream), NULL);
      if (G_IS_INET_SOCKET_ADDRESS (remote_addr))
        {
          GInetSocketAddress *isaddr = G_INET_SOCKET_ADDRESS (remote_addr);
          const gchar *server_hostname;
          gchar *addrstr;
          gchar *session_id;
          gchar *pem;
          gchar *cert_hash = NULL;

          iaddr = g_inet_socket_address_get_address (isaddr);
          port = g_inet_socket_address_get_port (isaddr);

          addrstr = g_inet_address_to_string (iaddr);
          server_hostname = self->server_identity;

          /* If we have a certificate, make its hash part of the session ID, so
           * that different connections to the same server can use different
           * certificates.
           */
          pem = g_tls_operations_thread_base_get_own_certificate_pem (G_TLS_OPERATIONS_THREAD_BASE (self));
          if (pem)
            {
              cert_hash = g_compute_checksum_for_string (G_CHECKSUM_SHA256, pem, -1);
              g_free (pem);
            }

          session_id = g_strdup_printf ("%s/%s/%d/%s", addrstr,
                                        server_hostname ? server_hostname : "",
                                        port,
                                        cert_hash ? cert_hash : "");
          self->session_id = g_bytes_new_take (session_id, strlen (session_id));
          g_free (addrstr);
          g_free (cert_hash);
        }
      g_object_unref (remote_addr);
    }
}

static void
set_session_data (GTlsOperationsThreadGnutls *self)
{
  g_assert (is_client (self));

  compute_session_id (self);

  if (self->session_data_override)
    {
      g_assert (self->session_data);
      gnutls_session_set_data (self->session,
                               g_bytes_get_data (self->session_data, NULL),
                               g_bytes_get_size (self->session_data));
    }
  else if (self->session_id)
    {
      GBytes *session_data;

      session_data = g_tls_backend_gnutls_lookup_session_data (self->session_id);
      if (session_data)
        {
          gnutls_session_set_data (self->session,
                                   g_bytes_get_data (session_data, NULL),
                                   g_bytes_get_size (session_data));
          g_clear_pointer (&self->session_data, g_bytes_unref);
          self->session_data = g_steal_pointer (&session_data);
        }
    }
}

static void
set_authentication_mode (GTlsOperationsThreadGnutls *self,
                         GTlsAuthenticationMode      auth_mode)
{
  gnutls_certificate_request_t req = GNUTLS_CERT_IGNORE;

  g_assert (is_server (self));

  switch (auth_mode)
    {
    case G_TLS_AUTHENTICATION_REQUESTED:
      req = GNUTLS_CERT_REQUEST;
      break;
    case G_TLS_AUTHENTICATION_REQUIRED:
      req = GNUTLS_CERT_REQUIRE;
      break;
    default:
      break;
    }

  gnutls_certificate_server_set_request (self->session, req);
}

static GTlsConnectionBaseStatus
g_tls_operations_thread_gnutls_handshake (GTlsOperationsThreadBase  *base,
                                          const gchar              **advertised_protocols,
                                          GTlsAuthenticationMode     auth_mode,
                                          gint64                     timeout,
                                          GCancellable              *cancellable,
                                          GError                   **error)
{
  GTlsOperationsThreadGnutls *self = G_TLS_OPERATIONS_THREAD_GNUTLS (base);
  GTlsConnectionBase *tls;
  GTlsConnectionBaseStatus status;
  int ret;

  tls = g_tls_operations_thread_base_get_connection (base);

  if (!self->ever_handshaked)
    set_handshake_priority (self);

  if (timeout > 0)
    set_handshake_timeout (self, timeout);

  if (advertised_protocols)
    set_advertised_protocols (self, advertised_protocols);

  if (is_client (self))
    set_session_data (self);

  if (is_server (self))
    set_authentication_mode (self, auth_mode);

  self->handshaking = TRUE;

  BEGIN_GNUTLS_IO (self, G_IO_IN | G_IO_OUT, cancellable);
  ret = gnutls_handshake (self->session);
  if (ret == GNUTLS_E_GOT_APPLICATION_DATA)
    {
      guint8 buf[1024];

      /* Got app data while waiting for rehandshake; buffer it and try again */
      ret = gnutls_record_recv (self->session, buf, sizeof (buf));
      if (ret > -1)
        {
          /* FIXME: no longer belongs in GTlsConnectionBase, don't use GTlsConnectionBase */
          g_tls_connection_base_handshake_thread_buffer_application_data (tls, buf, ret);
          ret = GNUTLS_E_AGAIN;
        }
    }
  END_GNUTLS_IO (self, G_IO_IN | G_IO_OUT, ret, status,
                 _("Error performing TLS handshake"), error);

  self->handshaking = FALSE;
  self->ever_handshaked = TRUE;

  return status;
}

static GTlsConnectionBaseStatus
g_tls_operations_thread_gnutls_read (GTlsOperationsThreadBase  *base,
                                     void                      *buffer,
                                     gsize                      size,
                                     gssize                    *nread,
                                     GCancellable              *cancellable,
                                     GError                   **error)
{
  GTlsOperationsThreadGnutls *self = G_TLS_OPERATIONS_THREAD_GNUTLS (base);
  GTlsConnectionBaseStatus status;
  gssize ret;

  BEGIN_GNUTLS_IO (self, G_IO_IN, cancellable);
  ret = gnutls_record_recv (self->session, buffer, size);
  END_GNUTLS_IO (self, G_IO_IN, ret, status, _("Error reading data from TLS socket"), error);

  *nread = MAX (ret, 0);
  return status;
}

static gsize
input_vectors_from_gnutls_datum_t (GInputVector         *vectors,
                                   guint                 num_vectors,
                                   const gnutls_datum_t *datum)
{
  guint i;
  gsize total = 0;

  /* Copy into the receive vectors. */
  for (i = 0; i < num_vectors && total < datum->size; i++)
    {
      gsize count;
      GInputVector *vec = &vectors[i];

      count = MIN (vec->size, datum->size - total);

      memcpy (vec->buffer, datum->data + total, count);
      total += count;
    }

  g_assert (total <= datum->size);

  return total;
}

static GTlsConnectionBaseStatus
g_tls_operations_thread_gnutls_read_message (GTlsOperationsThreadBase  *base,
                                             GInputVector              *vectors,
                                             guint                      num_vectors,
                                             gssize                    *nread,
                                             GCancellable              *cancellable,
                                             GError                   **error)
{
  GTlsOperationsThreadGnutls *self = G_TLS_OPERATIONS_THREAD_GNUTLS (base);
  GTlsConnectionBaseStatus status;
  gssize ret;
  gnutls_packet_t packet = { 0, };

  BEGIN_GNUTLS_IO (self, G_IO_IN, cancellable);

  /* Receive the entire datagram (zero-copy). */
  ret = gnutls_record_recv_packet (self->session, &packet);

  if (ret > 0)
    {
      gnutls_datum_t data = { 0, };

      gnutls_packet_get (packet, &data, NULL);
      ret = input_vectors_from_gnutls_datum_t (vectors, num_vectors, &data);
      gnutls_packet_deinit (packet);
    }

  END_GNUTLS_IO (self, G_IO_IN, ret, status, _("Error reading data from TLS socket"), error);

  *nread = MAX (ret, 0);
  return status;
}

static GTlsConnectionBaseStatus
g_tls_operations_thread_gnutls_write (GTlsOperationsThreadBase  *base,
                                      const void                *buffer,
                                      gsize                      size,
                                      gssize                    *nwrote,
                                      GCancellable              *cancellable,
                                      GError                   **error)
{
  GTlsOperationsThreadGnutls *self = G_TLS_OPERATIONS_THREAD_GNUTLS (base);
  GTlsConnectionBaseStatus status;
  gssize ret;

  BEGIN_GNUTLS_IO (self, G_IO_OUT, cancellable);
  ret = gnutls_record_send (self->session, buffer, size);
  END_GNUTLS_IO (self, G_IO_OUT, ret, status, _("Error writing data to TLS socket"), error);

  *nwrote = MAX (ret, 0);
  return status;
}

static GTlsConnectionBaseStatus
g_tls_operations_thread_gnutls_write_message (GTlsOperationsThreadBase  *base,
                                              GOutputVector             *vectors,
                                              guint                      num_vectors,
                                              gssize                    *nwrote,
                                              GCancellable              *cancellable,
                                              GError                   **error)
{
  GTlsOperationsThreadGnutls *self = G_TLS_OPERATIONS_THREAD_GNUTLS (base);
  GTlsConnectionBase *connection;
  GTlsConnectionBaseStatus status;
  gssize ret;
  guint i;
  gsize total_message_size;

  connection = g_tls_operations_thread_base_get_connection (base);

  /* Calculate the total message size and check it’s not too big. */
  for (i = 0, total_message_size = 0; i < num_vectors; i++)
    total_message_size += vectors[i].size;

  if (g_tls_connection_base_is_dtls (connection) &&
      gnutls_dtls_get_data_mtu (self->session) < total_message_size)
    {
      char *message;
      guint mtu = gnutls_dtls_get_data_mtu (self->session);

      ret = GNUTLS_E_LARGE_PACKET;
      message = g_strdup_printf("%s %s",
                                ngettext ("Message of size %lu byte is too large for DTLS connection",
                                          "Message of size %lu bytes is too large for DTLS connection", total_message_size),
                                ngettext ("(maximum is %u byte)", "(maximum is %u bytes)", mtu));
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_MESSAGE_TOO_LARGE,
                   message,
                   total_message_size,
                   mtu);
      g_free (message);

      return G_TLS_CONNECTION_BASE_ERROR;
    }

  /* Queue up the data from all the vectors. */
  gnutls_record_cork (self->session);

  for (i = 0; i < num_vectors; i++)
    {
      ret = gnutls_record_send (self->session,
                                vectors[i].buffer, vectors[i].size);

      if (ret < 0 || ret < vectors[i].size)
        {
          /* Uncork to restore state, then bail. The peer will receive a
           * truncated datagram.
           */
          break;
        }
    }

  BEGIN_GNUTLS_IO (self, G_IO_OUT, cancellable);
  ret = gnutls_record_uncork (self->session, 0  /* flags */);
  END_GNUTLS_IO (self, G_IO_OUT, ret, status, _("Error writing data to TLS socket"), error);

  *nwrote = MAX (ret, 0);
  return status;
}

static GTlsConnectionBaseStatus
g_tls_operations_thread_gnutls_close (GTlsOperationsThreadBase  *base,
                                      GCancellable              *cancellable,
                                      GError                   **error)
{
  GTlsOperationsThreadGnutls *self = G_TLS_OPERATIONS_THREAD_GNUTLS (base);
  GTlsConnectionBaseStatus status;
  int ret;

  BEGIN_GNUTLS_IO (self, G_IO_IN | G_IO_OUT, cancellable);
  ret = gnutls_bye (self->session, GNUTLS_SHUT_WR);
  END_GNUTLS_IO (self, G_IO_IN | G_IO_OUT, ret, status, _("Error performing TLS close: %s"), error);

  return status;
}

static void
set_gnutls_error (GTlsOperationsThreadGnutls *self,
                  GError                     *error)
{
  /* We set EINTR rather than EAGAIN for G_IO_ERROR_WOULD_BLOCK so
   * that GNUTLS_E_AGAIN only gets returned for gnutls-internal
   * reasons, not for actual socket EAGAINs (and we have access
   * to @error at the higher levels, so we can distinguish them
   * that way later).
   */

  if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
    gnutls_transport_set_errno (self->session, EINTR);
  else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
    {
      /* Return EAGAIN while handshaking so that GnuTLS handles retries for us
       * internally in its handshaking code.
       */
      if (is_dtls (self) && self->handshaking)
        gnutls_transport_set_errno (self->session, EAGAIN);
      else
        gnutls_transport_set_errno (self->session, EINTR);
    }
  else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT))
    gnutls_transport_set_errno (self->session, EINTR);
  else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_MESSAGE_TOO_LARGE))
    gnutls_transport_set_errno (self->session, EMSGSIZE);
  else
    gnutls_transport_set_errno (self->session, EIO);
}

static ssize_t
g_tls_operations_thread_gnutls_pull_func (gnutls_transport_ptr_t  transport_data,
                                          void                   *buf,
                                          size_t                  buflen)
{
  GTlsOperationsThreadGnutls *self = transport_data;
  ssize_t ret;

  /* If op_error is nonnull when we're called, it means
   * that an error previously occurred, but GnuTLS decided not to
   * propagate it. So it's correct for us to just clear it. (Usually
   * this means it ignored an EAGAIN after a short read, and now
   * we'll return EAGAIN again, which it will obey this time.)
   */
  g_clear_error (&self->op_error);

  if (is_dtls (self))
    {
      GInputVector vector = { buf, buflen };
      GInputMessage message = { NULL, &vector, 1, 0, 0, NULL, NULL };

      ret = g_datagram_based_receive_messages (self->base_socket,
                                               &message, 1,
                                               0, 0,
                                               self->op_cancellable,
                                               &self->op_error);

      if (ret > 0)
        ret = message.bytes_received;
    }
  else
    {
      ret = g_pollable_stream_read (self->base_istream,
                                    buf, buflen,
                                    FALSE,
                                    self->op_cancellable,
                                    &self->op_error);
    }

  if (ret < 0)
    set_gnutls_error (self, self->op_error);

  return ret;
}

static ssize_t
g_tls_operations_thread_gnutls_push_func (gnutls_transport_ptr_t  transport_data,
                                          const void             *buf,
                                          size_t                  buflen)
{
  GTlsOperationsThreadGnutls *self = transport_data;
  ssize_t ret;

  /* See comment in pull_func. */
  g_clear_error (&self->op_error);

  if (is_dtls (self))
    {
      GOutputVector vector = { buf, buflen };
      GOutputMessage message = { NULL, &vector, 1, 0, NULL, 0 };

      ret = g_datagram_based_send_messages (self->base_socket,
                                            &message, 1,
                                            0, 0,
                                            self->op_cancellable,
                                            &self->op_error);

      if (ret > 0)
        ret = message.bytes_sent;
    }
  else
    {
      ret = g_pollable_stream_write (self->base_ostream,
                                     buf, buflen,
                                     FALSE,
                                     self->op_cancellable,
                                     &self->op_error);
    }

  if (ret < 0)
    set_gnutls_error (self, self->op_error);

  return ret;
}

static ssize_t
g_tls_operations_thread_gnutls_vec_push_func (gnutls_transport_ptr_t  transport_data,
                                              const giovec_t         *iov,
                                              int                     iovcnt)
{
  GTlsOperationsThreadGnutls *self = transport_data;
  ssize_t ret;
  GOutputMessage message = { NULL, };
  GOutputVector *vectors;

  g_assert (is_dtls (self));

  /* See comment in pull_func. */
  g_clear_error (&self->op_error);

  /* this entire expression will be evaluated at compile time */
  if (sizeof *iov == sizeof *vectors &&
      sizeof iov->iov_base == sizeof vectors->buffer &&
      G_STRUCT_OFFSET (giovec_t, iov_base) == G_STRUCT_OFFSET (GOutputVector, buffer) &&
      sizeof iov->iov_len == sizeof vectors->size &&
      G_STRUCT_OFFSET (giovec_t, iov_len) == G_STRUCT_OFFSET (GOutputVector, size))
    /* ABI is compatible */
    {
      message.vectors = (GOutputVector *)iov;
      message.num_vectors = iovcnt;
    }
  else
    /* ABI is incompatible */
    {
      gint i;

      message.vectors = g_newa (GOutputVector, iovcnt);
      for (i = 0; i < iovcnt; i++)
        {
          message.vectors[i].buffer = (void *)iov[i].iov_base;
          message.vectors[i].size = iov[i].iov_len;
        }
      message.num_vectors = iovcnt;
    }

  ret = g_datagram_based_send_messages (self->base_socket,
                                        &message, 1,
                                        0, 0,
                                        self->op_cancellable,
                                        &self->op_error);

  if (ret > 0)
    ret = message.bytes_sent;
  else if (ret < 0)
    set_gnutls_error (self, self->op_error);

  return ret;
}

static gboolean
read_pollable_cb (GPollableInputStream *istream,
                  gpointer              user_data)
{
  gboolean *read_done = user_data;

  *read_done = TRUE;

  return G_SOURCE_CONTINUE;
}

static gboolean
read_datagram_based_cb (GDatagramBased *datagram_based,
                        GIOCondition    condition,
                        gpointer        user_data)
{
  gboolean *read_done = user_data;

  *read_done = TRUE;

  return G_SOURCE_CONTINUE;
}

static gboolean
read_timeout_cb (gpointer user_data)
{
  gboolean *timed_out = user_data;

  *timed_out = TRUE;

  return G_SOURCE_REMOVE;
}

static int /* FIXME: can this be removed? switch to GNUTLS_NONBLOCK, right? */
g_tls_operations_thread_gnutls_pull_timeout_func (gnutls_transport_ptr_t transport_data,
                                                  unsigned int           ms)
{
  GTlsOperationsThreadGnutls *self = transport_data;
  /* FIXME: don't use GTlsConnection */
  GTlsConnectionBase *tls = g_tls_operations_thread_base_get_connection (G_TLS_OPERATIONS_THREAD_BASE (self));

  /* Fast path. */
  if (g_tls_connection_base_base_check (tls, G_IO_IN) ||
      g_cancellable_is_cancelled (self->op_cancellable))
    return 1;

  /* If @ms is 0, GnuTLS wants an instant response, so there’s no need to
   * construct and query a #GSource. */
  if (ms > 0)
    {
      GMainContext *ctx = NULL;
      GSource *read_source = NULL, *timeout_source = NULL;
      gboolean read_done = FALSE, timed_out = FALSE;

      ctx = g_main_context_new ();

      /* Create a timeout source. */
      timeout_source = g_timeout_source_new (ms);
      g_source_set_callback (timeout_source, (GSourceFunc)read_timeout_cb,
                             &timed_out, NULL);

      /* Create a read source. We cannot use g_source_set_ready_time() on this
       * to combine it with the @timeout_source, as that could mess with the
       * internals of the #GDatagramBased’s #GSource implementation. */
      if (is_dtls (self))
        {
          read_source = g_datagram_based_create_source (self->base_socket,
                                                        G_IO_IN, NULL);
          g_source_set_callback (read_source, (GSourceFunc)read_datagram_based_cb,
                                 &read_done, NULL);
        }
      else
        {
          read_source = g_pollable_input_stream_create_source (G_POLLABLE_INPUT_STREAM (self->base_istream),
                                                               NULL);
          g_source_set_callback (read_source, (GSourceFunc)read_pollable_cb,
                                 &read_done, NULL);
        }

      g_source_attach (read_source, ctx);
      g_source_attach (timeout_source, ctx);

      while (!read_done && !timed_out)
        g_main_context_iteration (ctx, TRUE);

      g_source_destroy (read_source);
      g_source_destroy (timeout_source);

      g_main_context_unref (ctx);
      g_source_unref (read_source);
      g_source_unref (timeout_source);

      /* If @read_source was dispatched due to cancellation, the resulting error
       * will be handled in g_tls_connection_gnutls_pull_func(). */
      if (g_tls_connection_base_base_check (tls, G_IO_IN) ||
          g_cancellable_is_cancelled (self->op_cancellable))
        return 1;
    }

  return 0;
}

static int
verify_certificate_cb (gnutls_session_t session)
{
  GTlsOperationsThreadGnutls *self = gnutls_session_get_ptr (session);

  /* Return 0 for the handshake to continue, non-zero to terminate.
   * Complete opposite of what OpenSSL does.
   */
  return !g_tls_connection_base_handshake_thread_verify_certificate (tls);
}

static void
clear_gnutls_certificate_copy (GTlsOperationsThreadGnutls *self)
{
  g_tls_certificate_gnutls_copy_free (self->pcert, self->pcert_length, self->pkey);

  self->pcert = NULL;
  self->pcert_length = 0;
  self->pkey = NULL;
}

static int
retrieve_certificate_cb (gnutls_session_t              session,
                         const gnutls_datum_t         *req_ca_rdn,
                         int                           nreqs,
                         const gnutls_pk_algorithm_t  *pk_algos,
                         int                           pk_algos_length,
                         gnutls_pcert_st             **pcert,
                         unsigned int                 *pcert_length,
                         gnutls_privkey_t             *pkey)
{
  GTlsOperationsThreadGnutls *self = gnutls_transport_get_ptr (session);
  gboolean had_accepted_cas;
  GByteArray *dn;
  int i;

  /* FIXME: Here we are supposed to ensure that the certificate supports one of
   * the algorithms given in pk_algos.
   */

  if (is_client (self))
    {
      had_accepted_cas = self->accepted_cas && self->accepted_cas->len != 0;

      g_clear_pointer (&self->accepted_cas, g_ptr_array_unref);
      self->accepted_cas = g_ptr_array_new_with_free_func ((GDestroyNotify)g_byte_array_unref);
      for (i = 0; i < nreqs; i++)
        {
          dn = g_byte_array_new ();
          g_byte_array_append (dn, req_ca_rdn[i].data, req_ca_rdn[i].size);
          g_ptr_array_add (self->accepted_cas, dn);
        }

      self->accepted_cas_changed = self->accepted_cas || had_accepted_cas;
    }

  clear_gnutls_certificate_copy (self);
  g_tls_connection_gnutls_handshake_thread_get_certificate (conn, pcert, pcert_length, pkey);

  if (is_client (self))
    {
      if (*pcert_length == 0)
        {
          g_tls_certificate_gnutls_copy_free (*pcert, *pcert_length, *pkey);

          if (g_tls_connection_base_handshake_thread_request_certificate (tls))
            g_tls_connection_gnutls_handshake_thread_get_certificate (conn, pcert, pcert_length, pkey);

          if (*pcert_length == 0)
            {
              g_tls_certificate_gnutls_copy_free (*pcert, *pcert_length, *pkey);

              /* If there is still no client certificate, this connection will
               * probably fail, but we must not give up yet. The certificate might
               * be optional, e.g. if the server is using
               * G_TLS_AUTHENTICATION_REQUESTED, not G_TLS_AUTHENTICATION_REQUIRED.
               */
              g_tls_connection_base_handshake_thread_set_missing_requested_client_certificate (tls);
              return 0;
            }
        }

      if (!*pkey)
        {
          g_tls_certificate_gnutls_copy_free (*pcert, *pcert_length, *pkey);

          /* No private key. GnuTLS expects it to be non-null if pcert_length is
           * nonzero, so we have to abort now.
           */
          g_tls_connection_base_handshake_thread_set_missing_requested_client_certificate (tls);
          return -1;
        }
    }

  self->pcert = *pcert;
  self->pcert_length = *pcert_length;
  self->pkey = *pkey;

  return 0;
}

static int
session_ticket_received_cb (gnutls_session_t      session,
                            guint                 htype,
                            guint                 when,
                            guint                 incoming,
                            const gnutls_datum_t *msg)
{
  GTlsOperationsThreadGnutls *self = G_TLS_OPERATIONS_THREAD_GNUTLS (gnutls_session_get_ptr (session));
  gnutls_datum_t session_datum;

  if (gnutls_session_get_data2 (session, &session_datum) == GNUTLS_E_SUCCESS)
    {
      g_clear_pointer (&self->session_data, g_bytes_unref);
      self->session_data = g_bytes_new_with_free_func (session_datum.data,
                                                       session_datum.size,
                                                       (GDestroyNotify)gnutls_free,
                                                       session_datum.data);

      if (self->session_id)
        {
          g_tls_backend_gnutls_store_session_data (self->session_id,
                                                   self->session_data);
        }
    }

  return 0;
}

static void
g_tls_operations_thread_gnutls_get_property (GObject    *object,
                                             guint       prop_id,
                                             GValue     *value,
                                             GParamSpec *pspec)
{
  GTlsOperationsThreadGnutls *self = G_TLS_OPERATIONS_THREAD_GNUTLS (object);

  switch (prop_id)
    {
    case PROP_BASE_IO_STREAM:
      g_value_set_object (value, self->base_iostream);
      break;

    case PROP_BASE_SOCKET:
      g_value_set_object (value, self->base_socket);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_operations_thread_gnutls_set_property (GObject      *object,
                                             guint         prop_id,
                                             const GValue *value,
                                             GParamSpec   *pspec)
{
  GTlsOperationsThreadGnutls *self = G_TLS_OPERATIONS_THREAD_GNUTLS (object);

  switch (prop_id)
    {
    case PROP_BASE_IO_STREAM:
      g_assert (!self->base_socket);
      self->base_iostream = g_value_get_object (value);
      self->base_istream = g_io_stream_get_input_stream (self->base_iostream);
      self->base_ostream = g_io_stream_get_output_stream (self->base_iostream);
      break;

    case PROP_BASE_SOCKET:
      g_assert (!self->base_iostream);
      self->base_socket = g_value_get_object (value);
      break;

    case PROP_GNUTLS_FLAGS:
      self->init_flags = g_value_get_uint (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_operations_thread_gnutls_finalize (GObject *object)
{
  GTlsOperationsThreadGnutls *self = G_TLS_OPERATIONS_THREAD_GNUTLS (object);

  g_clear_pointer (&self->session, gnutls_deinit);
  g_clear_pointer (&self->creds, gnutls_certificate_free_credentials);
  g_clear_pointer (&self->session_id, g_bytes_unref);
  g_clear_pointer (&self->session_data, g_bytes_unref);

  g_clear_pointer (&self->server_identity, g_free);
  g_clear_pointer (&self->accepted_cas, g_ptr_array_unref);

  g_clear_object (&self->base_iostream);
  g_clear_object (&self->base_socket);

  clear_gnutls_certificate_copy (self);

  g_assert (!self->op_cancellable);
  g_assert (!self->op_error);

  G_OBJECT_CLASS (g_tls_operations_thread_gnutls_parent_class)->finalize (object);
}

static void
g_tls_operations_thread_gnutls_constructed (GObject *object)
{
  GTlsOperationsThreadGnutls *self = G_TLS_OPERATIONS_THREAD_GNUTLS (object);
  GTlsConnectionBase *tls;
  int ret;

  G_OBJECT_CLASS (g_tls_operations_thread_gnutls_parent_class)->constructed (object);

  tls = g_tls_operations_thread_base_get_connection (G_TLS_OPERATIONS_THREAD_BASE (self));

  ret = gnutls_certificate_allocate_credentials (&self->creds);
  /* FIXME: GInitable? */
#if 0
  if (ret != GNUTLS_E_SUCCESS)
    return FALSE;
#endif
  gnutls_certificate_set_retrieve_function2 (self->creds, retrieve_certificate_cb);

  gnutls_init (&self->session, self->init_flags);

  gnutls_session_set_ptr (self->session, self);
  gnutls_session_set_verify_function (self->session, verify_certificate_cb);

  ret = gnutls_credentials_set (self->session,
                                GNUTLS_CRD_CERTIFICATE,
                                self->creds);
  /* FIXME: GInitable? */
#if 0
  if (ret != 0)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Could not create TLS connection: %s"),
                   gnutls_strerror (status));
      return FALSE;
    }
#endif

  gnutls_transport_set_push_function (self->session,
                                      g_tls_operations_thread_gnutls_push_func);
  gnutls_transport_set_pull_function (self->session,
                                      g_tls_operations_thread_gnutls_pull_func);
  /* FIXME: remove timeout func and switch to GNUTLS_NONBLOCK */
  gnutls_transport_set_pull_timeout_function (self->session,
                                              g_tls_operations_thread_gnutls_pull_timeout_func);
  gnutls_transport_set_ptr (self->session, self);

  if (is_dtls (self))
    {
      /* GDatagramBased supports vectored I/O; GPollableOutputStream does not. */
      gnutls_transport_set_vec_push_function (self->session,
                                              g_tls_operations_thread_gnutls_vec_push_func);

      /* Set reasonable MTU */
      gnutls_dtls_set_mtu (self->session, 1400);
    }

  if (is_client (self))
    {
      gnutls_handshake_set_hook_function (self->session,
                                          GNUTLS_HANDSHAKE_NEW_SESSION_TICKET,
                                          GNUTLS_HOOK_POST,
                                          session_ticket_received_cb);
    }
}

static void
g_tls_operations_thread_gnutls_init (GTlsOperationsThreadGnutls *self)
{
}

static void
g_tls_operations_thread_gnutls_class_init (GTlsOperationsThreadGnutlsClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsOperationsThreadBaseClass *base_class = G_TLS_OPERATIONS_THREAD_BASE_CLASS (klass);

  gobject_class->constructed   = g_tls_operations_thread_gnutls_constructed;
  gobject_class->finalize      = g_tls_operations_thread_gnutls_finalize;
  gobject_class->get_property  = g_tls_operations_thread_gnutls_get_property;
  gobject_class->set_property  = g_tls_operations_thread_gnutls_set_property;

  base_class->copy_client_session_state = g_tls_operations_thread_gnutls_copy_client_session_state;
  base_class->set_server_identity       = g_tls_operations_thread_gnutls_set_server_identity;
  base_class->handshake_fn              = g_tls_operations_thread_gnutls_handshake;
  base_class->read_fn                   = g_tls_operations_thread_gnutls_read;
  base_class->read_message_fn           = g_tls_operations_thread_gnutls_read_message;
  base_class->write_fn                  = g_tls_operations_thread_gnutls_write;
  base_class->write_message_fn          = g_tls_operations_thread_gnutls_write_message;
  base_class->close_fn                  = g_tls_operations_thread_gnutls_close;

  obj_properties[PROP_BASE_IO_STREAM] =
    g_param_spec_object ("base-io-stream",
                         "Base IOStream",
                         "The underlying GIOStream, for TLS connections",
                         G_TYPE_IO_STREAM,
                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

  obj_properties[PROP_BASE_SOCKET] =
    g_param_spec_object ("base-socket",
                         "Base socket",
                         "The underlying GDatagramBased, for DTLS connections",
                         G_TYPE_DATAGRAM_BASED,
                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

  obj_properties[PROP_GNUTLS_FLAGS] =
    g_param_spec_uint ("gnutls-flags",
                       "GnuTLS flags",
                       "Flags for initializing GnuTLS session",
                       0, UINT_MAX, 0,
                       G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

  g_object_class_install_properties (gobject_class, LAST_PROP, obj_properties);

  initialize_gnutls_priority ();
}

GTlsOperationsThreadBase *
g_tls_operations_thread_gnutls_new (GTlsConnectionGnutls *connection,
                                    GIOStream            *base_iostream,
                                    GDatagramBased       *base_socket,
                                    guint                 flags)
{
  return G_TLS_OPERATIONS_THREAD_BASE (g_object_new (G_TYPE_TLS_OPERATIONS_THREAD_GNUTLS,
                                                     "base-iostream", base_iostream,
                                                     "base-socket", base_socket,
                                                     "gnutls-flags", flags,
                                                     "tls-connection", connection,
                                                     NULL));
}

/* FIXME: must remove this! */
gnutls_session_t
g_tls_operations_thread_gnutls_get_session (GTlsOperationsThreadGnutls *self)
{
  return self->session;
}
