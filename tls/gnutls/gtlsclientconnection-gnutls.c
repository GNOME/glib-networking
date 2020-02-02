/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2010 Red Hat, Inc
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
#include "glib.h"

#include <errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <string.h>

#include "gtlsconnection-base.h"
#include "gtlsclientconnection-gnutls.h"
#include "gtlsbackend-gnutls.h"
#include "gtlscertificate-gnutls.h"
#include <glib/gi18n-lib.h>

enum
{
  PROP_0,
  PROP_VALIDATION_FLAGS,
  PROP_SERVER_IDENTITY,
  PROP_USE_SSL3,
  PROP_ACCEPTED_CAS
};

struct _GTlsClientConnectionGnutls
{
  GTlsConnectionGnutls parent_instance;

  GTlsCertificateFlags validation_flags;
  GSocketConnectable *server_identity;
  gboolean use_ssl3;

  /* session_data is either the session ticket that was used to resume this
   * connection, or the most recent session ticket received from the server.
   * Because session ticket reuse is generally undesirable, it should only be
   * accessed if session_data_override is set.
   */
  GBytes *session_id;
  GBytes *session_data;
  gboolean session_data_override;

  GPtrArray *accepted_cas;
  gboolean accepted_cas_changed;

  gnutls_pcert_st *pcert;
  unsigned int pcert_length;
  gnutls_privkey_t pkey;
};

static void g_tls_client_connection_gnutls_initable_interface_init (GInitableIface  *iface);

static void g_tls_client_connection_gnutls_client_connection_interface_init (GTlsClientConnectionInterface *iface);
static void g_tls_client_connection_gnutls_dtls_client_connection_interface_init (GDtlsClientConnectionInterface *iface);

static int g_tls_client_connection_gnutls_handshake_thread_retrieve_function (gnutls_session_t              session,
                                                                              const gnutls_datum_t         *req_ca_rdn,
                                                                              int                           nreqs,
                                                                              const gnutls_pk_algorithm_t  *pk_algos,
                                                                              int                           pk_algos_length,
                                                                              gnutls_pcert_st             **pcert,
                                                                              unsigned int                 *pcert_length,
                                                                              gnutls_privkey_t             *pkey);

static GInitableIface *g_tls_client_connection_gnutls_parent_initable_iface;

G_DEFINE_TYPE_WITH_CODE (GTlsClientConnectionGnutls, g_tls_client_connection_gnutls, G_TYPE_TLS_CONNECTION_GNUTLS,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                g_tls_client_connection_gnutls_initable_interface_init)
                         G_IMPLEMENT_INTERFACE (G_TYPE_TLS_CLIENT_CONNECTION,
                                                g_tls_client_connection_gnutls_client_connection_interface_init);
                         G_IMPLEMENT_INTERFACE (G_TYPE_DTLS_CLIENT_CONNECTION,
                                                g_tls_client_connection_gnutls_dtls_client_connection_interface_init));

static void
clear_gnutls_certificate_copy (GTlsClientConnectionGnutls *gnutls)
{
  g_tls_certificate_gnutls_copy_free (gnutls->pcert, gnutls->pcert_length, gnutls->pkey);

  gnutls->pcert = NULL;
  gnutls->pcert_length = 0;
  gnutls->pkey = NULL;
}

static void
g_tls_client_connection_gnutls_init (GTlsClientConnectionGnutls *gnutls)
{
}

static const gchar *
get_server_identity (GTlsClientConnectionGnutls *gnutls)
{
  if (G_IS_NETWORK_ADDRESS (gnutls->server_identity))
    return g_network_address_get_hostname (G_NETWORK_ADDRESS (gnutls->server_identity));
  else if (G_IS_NETWORK_SERVICE (gnutls->server_identity))
    return g_network_service_get_domain (G_NETWORK_SERVICE (gnutls->server_identity));
  else
    return NULL;
}

static void
g_tls_client_connection_gnutls_compute_session_id (GTlsClientConnectionGnutls *gnutls)
{
  GSocketConnection *base_conn;
  GSocketAddress *remote_addr;
  GInetAddress *iaddr;
  guint port;

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
  g_object_get (G_OBJECT (gnutls), "base-io-stream", &base_conn, NULL);
  if (G_IS_SOCKET_CONNECTION (base_conn))
    {
      remote_addr = g_socket_connection_get_remote_address (base_conn, NULL);
      if (G_IS_INET_SOCKET_ADDRESS (remote_addr))
        {
          GInetSocketAddress *isaddr = G_INET_SOCKET_ADDRESS (remote_addr);
          const gchar *server_hostname;
          gchar *addrstr, *session_id;
          GTlsCertificate *cert = NULL;
          gchar *cert_hash = NULL;

          iaddr = g_inet_socket_address_get_address (isaddr);
          port = g_inet_socket_address_get_port (isaddr);

          addrstr = g_inet_address_to_string (iaddr);
          server_hostname = get_server_identity (gnutls);

          /* If we have a certificate, make its hash part of the session ID, so
           * that different connections to the same server can use different
           * certificates.
           */
          g_object_get (G_OBJECT (gnutls), "certificate", &cert, NULL);
          if (cert)
            {
              GByteArray *der = NULL;
              g_object_get (G_OBJECT (cert), "certificate", &der, NULL);
              if (der)
                {
                  cert_hash = g_compute_checksum_for_data (G_CHECKSUM_SHA256, der->data, der->len);
                  g_byte_array_unref (der);
                }
              g_object_unref (cert);
            }
          session_id = g_strdup_printf ("%s/%s/%d/%s", addrstr,
                                        server_hostname ? server_hostname : "",
                                        port,
                                        cert_hash ? cert_hash : "");
          gnutls->session_id = g_bytes_new_take (session_id, strlen (session_id));
          g_free (addrstr);
          g_free (cert_hash);
        }
      g_object_unref (remote_addr);
    }
  g_clear_object (&base_conn);
}

static int
handshake_thread_session_ticket_received_cb (gnutls_session_t      session,
                                             guint                 htype,
                                             guint                 when,
                                             guint                 incoming,
                                             const gnutls_datum_t *msg)
{
  GTlsClientConnectionGnutls *gnutls = G_TLS_CLIENT_CONNECTION_GNUTLS (gnutls_session_get_ptr (session));
  gnutls_datum_t session_datum;

  if (gnutls_session_get_data2 (session, &session_datum) == GNUTLS_E_SUCCESS)
    {
      g_clear_pointer (&gnutls->session_data, g_bytes_unref);
      gnutls->session_data = g_bytes_new_with_free_func (session_datum.data,
                                                         session_datum.size,
                                                         (GDestroyNotify)gnutls_free,
                                                         session_datum.data);

      if (gnutls->session_id)
        {
          g_tls_backend_gnutls_store_session_data (gnutls->session_id,
                                                   gnutls->session_data);
        }
    }

  return 0;
}

static void
g_tls_client_connection_gnutls_finalize (GObject *object)
{
  GTlsClientConnectionGnutls *gnutls = G_TLS_CLIENT_CONNECTION_GNUTLS (object);

  g_clear_object (&gnutls->server_identity);
  g_clear_pointer (&gnutls->accepted_cas, g_ptr_array_unref);
  g_clear_pointer (&gnutls->session_id, g_bytes_unref);
  g_clear_pointer (&gnutls->session_data, g_bytes_unref);

  clear_gnutls_certificate_copy (gnutls);

  G_OBJECT_CLASS (g_tls_client_connection_gnutls_parent_class)->finalize (object);
}

static gboolean
g_tls_client_connection_gnutls_initable_init (GInitable       *initable,
                                              GCancellable    *cancellable,
                                              GError         **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (initable);
  gnutls_session_t session;
  const gchar *hostname;
  gnutls_certificate_credentials_t creds;

  if (!g_tls_client_connection_gnutls_parent_initable_iface->init (initable, cancellable, error))
    return FALSE;

  creds = g_tls_connection_gnutls_get_credentials (G_TLS_CONNECTION_GNUTLS (gnutls));
  gnutls_certificate_set_retrieve_function2 (creds, g_tls_client_connection_gnutls_handshake_thread_retrieve_function);

  session = g_tls_connection_gnutls_get_session (gnutls);
  hostname = get_server_identity (G_TLS_CLIENT_CONNECTION_GNUTLS (gnutls));
  if (hostname)
    {
      gchar *normalized_hostname = g_strdup (hostname);

      if (hostname[strlen (hostname) - 1] == '.')
        normalized_hostname[strlen (hostname) - 1] = '\0';

      gnutls_server_name_set (session, GNUTLS_NAME_DNS,
                              normalized_hostname, strlen (normalized_hostname));

      g_free (normalized_hostname);
    }

  gnutls_handshake_set_hook_function (session, GNUTLS_HANDSHAKE_NEW_SESSION_TICKET,
                                      GNUTLS_HOOK_POST, handshake_thread_session_ticket_received_cb);

  return TRUE;
}

static void
g_tls_client_connection_gnutls_get_property (GObject    *object,
                                             guint       prop_id,
                                             GValue     *value,
                                             GParamSpec *pspec)
{
  GTlsClientConnectionGnutls *gnutls = G_TLS_CLIENT_CONNECTION_GNUTLS (object);
  GList *accepted_cas;
  gint i;

  switch (prop_id)
    {
    case PROP_VALIDATION_FLAGS:
      g_value_set_flags (value, gnutls->validation_flags);
      break;

    case PROP_SERVER_IDENTITY:
      g_value_set_object (value, gnutls->server_identity);
      break;

    case PROP_USE_SSL3:
      g_value_set_boolean (value, gnutls->use_ssl3);
      break;

    case PROP_ACCEPTED_CAS:
      accepted_cas = NULL;
      if (gnutls->accepted_cas)
        {
          for (i = 0; i < gnutls->accepted_cas->len; ++i)
            {
              accepted_cas = g_list_prepend (accepted_cas, g_byte_array_ref (
                                             gnutls->accepted_cas->pdata[i]));
            }
          accepted_cas = g_list_reverse (accepted_cas);
        }
      g_value_set_pointer (value, accepted_cas);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_client_connection_gnutls_set_property (GObject      *object,
                                             guint         prop_id,
                                             const GValue *value,
                                             GParamSpec   *pspec)
{
  GTlsClientConnectionGnutls *gnutls = G_TLS_CLIENT_CONNECTION_GNUTLS (object);
  const char *hostname;

  switch (prop_id)
    {
    case PROP_VALIDATION_FLAGS:
      gnutls->validation_flags = g_value_get_flags (value);
      break;

    case PROP_SERVER_IDENTITY:
      if (gnutls->server_identity)
        g_object_unref (gnutls->server_identity);
      gnutls->server_identity = g_value_dup_object (value);

      hostname = get_server_identity (gnutls);
      if (hostname)
        {
          gnutls_session_t session = g_tls_connection_gnutls_get_session (G_TLS_CONNECTION_GNUTLS (gnutls));

          /* This will only be triggered if the identity is set after
           * initialization */
          if (session)
            {
              gchar *normalized_hostname = g_strdup (hostname);

              if (hostname[strlen (hostname) - 1] == '.')
                normalized_hostname[strlen (hostname) - 1] = '\0';

              gnutls_server_name_set (session, GNUTLS_NAME_DNS,
                                      normalized_hostname, strlen (normalized_hostname));

              g_free (normalized_hostname);
            }
        }
      break;

    case PROP_USE_SSL3:
      gnutls->use_ssl3 = g_value_get_boolean (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static int
g_tls_client_connection_gnutls_handshake_thread_retrieve_function (gnutls_session_t              session,
                                                                   const gnutls_datum_t         *req_ca_rdn,
                                                                   int                           nreqs,
                                                                   const gnutls_pk_algorithm_t  *pk_algos,
                                                                   int                           pk_algos_length,
                                                                   gnutls_pcert_st             **pcert,
                                                                   unsigned int                 *pcert_length,
                                                                   gnutls_privkey_t             *pkey)
{
  GTlsConnectionBase *tls = gnutls_transport_get_ptr (session);
  GTlsClientConnectionGnutls *gnutls = gnutls_transport_get_ptr (session);
  GTlsConnectionGnutls *conn = G_TLS_CONNECTION_GNUTLS (gnutls);
  GPtrArray *accepted_cas;
  gboolean had_accepted_cas;
  GByteArray *dn;
  int i;

  /* FIXME: Here we are supposed to ensure that the certificate supports one of
   * the algorithms given in pk_algos.
   */

  had_accepted_cas = gnutls->accepted_cas != NULL;

  accepted_cas = g_ptr_array_new_with_free_func ((GDestroyNotify)g_byte_array_unref);
  for (i = 0; i < nreqs; i++)
    {
      dn = g_byte_array_new ();
      g_byte_array_append (dn, req_ca_rdn[i].data, req_ca_rdn[i].size);
      g_ptr_array_add (accepted_cas, dn);
    }

  if (gnutls->accepted_cas)
    g_ptr_array_unref (gnutls->accepted_cas);
  gnutls->accepted_cas = accepted_cas;

  gnutls->accepted_cas_changed = gnutls->accepted_cas || had_accepted_cas;

  clear_gnutls_certificate_copy (gnutls);
  g_tls_connection_gnutls_handshake_thread_get_certificate (conn, pcert, pcert_length, pkey);

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

  gnutls->pcert = *pcert;
  gnutls->pcert_length = *pcert_length;
  gnutls->pkey = *pkey;

  return 0;
}

static void
g_tls_client_connection_gnutls_prepare_handshake (GTlsConnectionBase  *tls,
                                                  gchar              **advertised_protocols)
{
  GTlsClientConnectionGnutls *gnutls = G_TLS_CLIENT_CONNECTION_GNUTLS (tls);

  g_tls_client_connection_gnutls_compute_session_id (gnutls);

  if (gnutls->session_data_override)
    {
      g_assert (gnutls->session_data);
      gnutls_session_set_data (g_tls_connection_gnutls_get_session (G_TLS_CONNECTION_GNUTLS (tls)),
                               g_bytes_get_data (gnutls->session_data, NULL),
                               g_bytes_get_size (gnutls->session_data));
    }
  else if (gnutls->session_id)
    {
      GBytes *session_data;

      session_data = g_tls_backend_gnutls_lookup_session_data (gnutls->session_id);
      if (session_data)
        {
          gnutls_session_set_data (g_tls_connection_gnutls_get_session (G_TLS_CONNECTION_GNUTLS (tls)),
                                   g_bytes_get_data (session_data, NULL),
                                   g_bytes_get_size (session_data));
          g_clear_pointer (&gnutls->session_data, g_bytes_unref);
          gnutls->session_data = g_steal_pointer (&session_data);
        }
    }

  G_TLS_CONNECTION_BASE_CLASS (g_tls_client_connection_gnutls_parent_class)->
    prepare_handshake (tls, advertised_protocols);
}

static void
g_tls_client_connection_gnutls_complete_handshake (GTlsConnectionBase  *tls,
                                                   gboolean             handshake_succeeded,
                                                   gchar              **negotiated_protocol,
                                                   GError             **error)
{
  GTlsClientConnectionGnutls *gnutls = G_TLS_CLIENT_CONNECTION_GNUTLS (tls);
  gnutls_session_t session;
  gnutls_protocol_t version;

  G_TLS_CONNECTION_BASE_CLASS (g_tls_client_connection_gnutls_parent_class)->complete_handshake (tls, handshake_succeeded, negotiated_protocol, error);

  /* It may have changed during the handshake, but we have to wait until here
   * because we can't emit notifies on the handshake thread.
   */
  if (gnutls->accepted_cas_changed)
    g_object_notify (G_OBJECT (gnutls), "accepted-cas");

  if (handshake_succeeded)
    {
      /* If we're not using TLS 1.3, store the session ticket here. We
       * don't normally perform session resumption in TLS 1.2, but we still
       * support it if the application calls copy_session_state() (which
       * doesn't exist for DTLS, so do this for TLS only).
       *
       * Note to distant future: remove this when dropping TLS 1.2 support.
       */
      session = g_tls_connection_gnutls_get_session (G_TLS_CONNECTION_GNUTLS (tls));
      version = gnutls_protocol_get_version (session);
      if (version <= GNUTLS_TLS1_2 && !g_tls_connection_base_is_dtls (tls))
        {
          gnutls_datum_t session_datum;

          if (gnutls_session_get_data2 (g_tls_connection_gnutls_get_session (G_TLS_CONNECTION_GNUTLS (tls)),
                                        &session_datum) == 0)
            {
              g_clear_pointer (&gnutls->session_data, g_bytes_unref);
              gnutls->session_data = g_bytes_new_with_free_func (session_datum.data,
                                                                 session_datum.size,
                                                                 (GDestroyNotify)gnutls_free,
                                                                 session_datum.data);
            }
        }
  }
}

static void
g_tls_client_connection_gnutls_copy_session_state (GTlsClientConnection *conn,
                                                   GTlsClientConnection *source)
{
  GTlsClientConnectionGnutls *gnutls = G_TLS_CLIENT_CONNECTION_GNUTLS (conn);
  GTlsClientConnectionGnutls *gnutls_source = G_TLS_CLIENT_CONNECTION_GNUTLS (source);

  /* Precondition: source has handshaked, conn has not. */
  g_return_if_fail (!gnutls->session_id);
  g_return_if_fail (gnutls_source->session_id);
  g_return_if_fail (!gnutls->session_data);

  /* Prefer to use a new session ticket, if possible. */
  gnutls->session_data = g_tls_backend_gnutls_lookup_session_data (gnutls_source->session_id);

  if (!gnutls->session_data && gnutls_source->session_data)
    {
      /* If it's not possible, we'll try to reuse the old ticket, even though
       * this is a privacy risk. Applications should not use this function
       * unless they need us to try as hard as possible to resume a session,
       * even at the cost of privacy.
       */
      gnutls->session_data = g_bytes_ref (gnutls_source->session_data);
    }

  gnutls->session_data_override = !!gnutls->session_data;
}

static void
g_tls_client_connection_gnutls_class_init (GTlsClientConnectionGnutlsClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsConnectionBaseClass *base_class = G_TLS_CONNECTION_BASE_CLASS (klass);

  gobject_class->get_property = g_tls_client_connection_gnutls_get_property;
  gobject_class->set_property = g_tls_client_connection_gnutls_set_property;
  gobject_class->finalize     = g_tls_client_connection_gnutls_finalize;

  base_class->prepare_handshake  = g_tls_client_connection_gnutls_prepare_handshake;
  base_class->complete_handshake = g_tls_client_connection_gnutls_complete_handshake;

  g_object_class_override_property (gobject_class, PROP_VALIDATION_FLAGS, "validation-flags");
  g_object_class_override_property (gobject_class, PROP_SERVER_IDENTITY, "server-identity");
  g_object_class_override_property (gobject_class, PROP_USE_SSL3, "use-ssl3");
  g_object_class_override_property (gobject_class, PROP_ACCEPTED_CAS, "accepted-cas");
}

static void
g_tls_client_connection_gnutls_client_connection_interface_init (GTlsClientConnectionInterface *iface)
{
  iface->copy_session_state = g_tls_client_connection_gnutls_copy_session_state;
}

static void
g_tls_client_connection_gnutls_initable_interface_init (GInitableIface  *iface)
{
  g_tls_client_connection_gnutls_parent_initable_iface = g_type_interface_peek_parent (iface);

  iface->init = g_tls_client_connection_gnutls_initable_init;
}

static void
g_tls_client_connection_gnutls_dtls_client_connection_interface_init (GDtlsClientConnectionInterface *iface)
{
  /* Nothing here. */
}
