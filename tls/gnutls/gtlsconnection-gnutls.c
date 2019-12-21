/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2009 Red Hat, Inc
 * Copyright 2015, 2016 Collabora, Ltd.
 * Copyright 2019 Igalia S.L.
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

/* FIXME: audit includes to remove */

#include <errno.h>
#include <stdarg.h>
#include <gnutls/dtls.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "gtlsconnection-gnutls.h"
#include "gtlsbackend-gnutls.h"
#include "gtlscertificate-gnutls.h"
#include "gtlsclientconnection-gnutls.h"
#include "gtlsoperationsthread-gnutls.h"

#ifdef G_OS_WIN32
#include <winsock2.h>
#include <winerror.h>

/* It isn’t clear whether MinGW always defines EMSGSIZE. */
#ifndef EMSGSIZE
#define EMSGSIZE WSAEMSGSIZE
#endif
#endif

#include <glib/gi18n-lib.h>
#include <glib/gprintf.h>

static GInitableIface *g_tls_connection_gnutls_parent_initable_iface;

static void g_tls_connection_gnutls_initable_iface_init (GInitableIface *iface);

static int verify_certificate_cb (gnutls_session_t session);

static gnutls_priority_t priority;

typedef struct
{
  gnutls_session_t session; /* FIXME: should be used only by GTlsOperationsThreadGnutls */
  gchar *interaction_id;
  GCancellable *cancellable;
} GTlsConnectionGnutlsPrivate;

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (GTlsConnectionGnutls, g_tls_connection_gnutls, G_TYPE_TLS_CONNECTION_BASE,
                                  G_ADD_PRIVATE (GTlsConnectionGnutls);
                                  G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                         g_tls_connection_gnutls_initable_iface_init);
                                  );

static gint unique_interaction_id = 0;

static void
g_tls_connection_gnutls_init (GTlsConnectionGnutls *gnutls)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  int unique_id;

  unique_id = g_atomic_int_add (&unique_interaction_id, 1);
  priv->interaction_id = g_strdup_printf ("gtls:%d", unique_id);

  priv->cancellable = g_cancellable_new ();
}

static void
g_tls_connection_gnutls_set_handshake_priority (GTlsConnectionGnutls *gnutls)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  int ret;

  g_assert (priority);

  ret = gnutls_priority_set (priv->session, priority);
  if (ret != GNUTLS_E_SUCCESS)
    g_warning ("Failed to set GnuTLS session priority: %s", gnutls_strerror (ret));
}

static gboolean
g_tls_connection_gnutls_initable_init (GInitable     *initable,
                                       GCancellable  *cancellable,
                                       GError       **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (initable);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  if (!g_tls_connection_gnutls_parent_initable_iface->init (initable, cancellable, error))
    return FALSE;

  /* FIXME bad */
  priv->session = g_tls_operations_thread_gnutls_get_session (G_TLS_OPERATIONS_THREAD_GNUTLS (g_tls_connection_base_get_op_thread (G_TLS_CONNECTION_BASE (gnutls))));

  return TRUE;
}

static void
g_tls_connection_gnutls_finalize (GObject *object)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (object);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  if (priv->cancellable)
    {
      g_cancellable_cancel (priv->cancellable);
      g_clear_object (&priv->cancellable);
    }

  g_free (priv->interaction_id);

  G_OBJECT_CLASS (g_tls_connection_gnutls_parent_class)->finalize (object);
}

gnutls_certificate_credentials_t
g_tls_connection_gnutls_get_credentials (GTlsConnectionGnutls *gnutls)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  return priv->creds; /* FIXME: get via op thread? */
}

static int
on_pin_request (void         *userdata,
                int           attempt,
                const char   *token_url,
                const char   *token_label,
                unsigned int  callback_flags,
                char         *pin,
                size_t        pin_max)
{
  GTlsConnection *connection = G_TLS_CONNECTION (userdata);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (G_TLS_CONNECTION_GNUTLS (connection));
  GTlsInteraction *interaction = g_tls_connection_get_interaction (connection);
  GTlsInteractionResult result;
  GTlsPassword *password;
  GTlsPasswordFlags password_flags = 0;
  GError *error = NULL;
  gchar *description;
  int ret = -1;

  if (!interaction)
    return -1;

  if (callback_flags & GNUTLS_PIN_WRONG)
    password_flags |= G_TLS_PASSWORD_RETRY;
  if (callback_flags & GNUTLS_PIN_COUNT_LOW)
    password_flags |= G_TLS_PASSWORD_MANY_TRIES;
  if (callback_flags & GNUTLS_PIN_FINAL_TRY || attempt > 5) /* Give up at some point */
    password_flags |= G_TLS_PASSWORD_FINAL_TRY;

  description = g_strdup_printf (" %s (%s)", token_label, token_url);
  password = g_tls_password_new (password_flags, description);
  result = g_tls_interaction_invoke_ask_password (interaction, password,
                                                  priv->cancellable,
                                                  &error);
  g_free (description);

  switch (result)
    {
    case G_TLS_INTERACTION_FAILED:
      if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        g_warning ("Error getting PIN: %s", error->message);
      g_error_free (error);
      break;
    case G_TLS_INTERACTION_UNHANDLED:
      break;
    case G_TLS_INTERACTION_HANDLED:
      {
        gsize password_size;
        const guchar *password_data = g_tls_password_get_value (password, &password_size);
        if (password_size > pin_max)
          g_warning ("PIN is larger than max PIN size");

        memcpy (pin, password_data, MIN (password_size, pin_max));
        ret = GNUTLS_E_SUCCESS;
        break;
      }
    default:
      g_assert_not_reached ();
    }

  g_object_unref (password);

  return ret;
}

void
g_tls_connection_gnutls_handshake_thread_get_certificate (GTlsConnectionGnutls  *gnutls,
                                                          gnutls_pcert_st      **pcert,
                                                          unsigned int          *pcert_length,
                                                          gnutls_privkey_t      *pkey)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GTlsCertificate *cert;

  cert = g_tls_connection_get_certificate (G_TLS_CONNECTION (gnutls));

  if (cert)
    {
      /* Send along a pre-initialized privkey so we can handle the callback here. */
      gnutls_privkey_t privkey;
      gnutls_privkey_init (&privkey);
      gnutls_privkey_set_pin_function (privkey, on_pin_request, gnutls);

      g_tls_certificate_gnutls_copy (G_TLS_CERTIFICATE_GNUTLS (cert),
                                     priv->interaction_id,
                                     pcert, pcert_length, &privkey);
      *pkey = privkey;
    }
  else
    {
      *pcert = NULL;
      *pcert_length = 0;
      *pkey = NULL;
    }
}

static GTlsOperationsThreadBase *
g_tls_connection_gnutls_create_op_thread (GTlsConnectionBase *tls)
{
  GIOStream *base_io_stream = NULL;
  GDatagramBased *base_socket = NULL;
  gboolean client = G_IS_TLS_CLIENT_CONNECTION (tls);
  guint flags = client ? GNUTLS_CLIENT : GNUTLS_SERVER;
  GTlsOperationsThreadGnutls *thread;

  g_object_get (tls,
                "base-io-stream", &base_io_stream,
                "base-socket", &base_socket,
                NULL);

  /* Ensure we are in TLS mode or DTLS mode. */
  g_return_val_if_fail (!!base_io_stream != !!base_socket, FALSE);

  if (base_socket)
    flags |= GNUTLS_DATAGRAM;

  thread = g_tls_operations_thread_gnutls_new (G_TLS_CONNECTION_GNUTLS (tls),
                                               base_io_stream,
                                               base_socket,
                                               flags);

  g_clear_object (&base_io_stream);
  g_clear_object (&base_socket);

  return thread;
}

static GTlsCertificate *
g_tls_connection_gnutls_retrieve_peer_certificate (GTlsConnectionBase *tls)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  const gnutls_datum_t *certs;
  GTlsCertificateGnutls *chain;
  unsigned int num_certs;

  if (gnutls_certificate_type_get (priv->session) != GNUTLS_CRT_X509)
    return NULL;

  certs = gnutls_certificate_get_peers (priv->session, &num_certs);
  if (!certs || !num_certs)
    return NULL;

  chain = g_tls_certificate_gnutls_build_chain (certs, num_certs, GNUTLS_X509_FMT_DER);
  if (!chain)
    return NULL;

  return G_TLS_CERTIFICATE (chain);
}

static int
verify_certificate_cb (gnutls_session_t session)
{
  GTlsConnectionBase *tls = gnutls_session_get_ptr (session);

  /* Return 0 for the handshake to continue, non-zero to terminate.
   * Complete opposite of what OpenSSL does. */
  return !g_tls_connection_base_handshake_thread_verify_certificate (tls);
}

static void
g_tls_connection_gnutls_complete_handshake (GTlsConnectionBase  *tls,
                                            gchar              **negotiated_protocol,
                                            GError             **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gnutls_datum_t protocol;

  if (gnutls_alpn_get_selected_protocol (priv->session, &protocol) == 0 && protocol.size > 0)
    {
      g_assert (!*negotiated_protocol);
      *negotiated_protocol = g_strndup ((gchar *)protocol.data, protocol.size);
    }
}

static gboolean
g_tls_connection_gnutls_is_session_resumed (GTlsConnectionBase *tls)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  return gnutls_session_is_resumed (priv->session);
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
g_tls_connection_gnutls_class_init (GTlsConnectionGnutlsClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsConnectionBaseClass *base_class = G_TLS_CONNECTION_BASE_CLASS (klass);

  gobject_class->finalize                                = g_tls_connection_gnutls_finalize;

  base_class->create_op_thread                           = g_tls_connection_gnutls_create_op_thread;
  base_class->handshake_thread_safe_renegotiation_status = g_tls_connection_gnutls_handshake_thread_safe_renegotiation_status;
  base_class->retrieve_peer_certificate                  = g_tls_connection_gnutls_retrieve_peer_certificate;
  base_class->complete_handshake                         = g_tls_connection_gnutls_complete_handshake;
  base_class->is_session_resumed                         = g_tls_connection_gnutls_is_session_resumed;

  initialize_gnutls_priority ();
}

static void
g_tls_connection_gnutls_initable_iface_init (GInitableIface *iface)
{
  g_tls_connection_gnutls_parent_initable_iface = g_type_interface_peek_parent (iface);

  iface->init = g_tls_connection_gnutls_initable_init;
}
