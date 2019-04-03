/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2009 Red Hat, Inc
 * Copyright 2015, 2016 Collabora, Ltd.
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
#include <stdarg.h>
#include <gnutls/dtls.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "gtlsconnection-gnutls.h"
#include "gtlsbackend-gnutls.h"
#include "gtlscertificate-gnutls.h"
#include "gtlsclientconnection-gnutls.h"
#include "gtlsinputstream-gnutls.h"
#include "gtlsoutputstream-gnutls.h"
#include "gtlsserverconnection-gnutls.h"

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

/*
 * GTlsConnectionGnutls is the base abstract implementation of TLS and DTLS
 * support, for both the client and server side of a connection. The choice
 * between TLS and DTLS is made by setting the base-io-stream or
 * base-socket properties — exactly one of them must be set at
 * construction time.
 *
 * Client and server specific code is in the GTlsClientConnectionGnutls and
 * GTlsServerConnectionGnutls concrete subclasses, although the line about where
 * code is put is a little blurry, and there are various places in
 * GTlsConnectionGnutls which check G_IS_TLS_CLIENT_CONNECTION(self) to switch
 * to a client-only code path.
 *
 * This abstract class implements a lot of interfaces:
 *  • Derived from GTlsConnection (itself from GIOStream), for TLS and streaming
 *    communications.
 *  • Implements GDtlsConnection and GDatagramBased, for DTLS and datagram
 *    communications.
 *  • Implements GInitable for failable GnuTLS initialisation.
 *
 * The GTlsClientConnectionGnutls and GTlsServerConnectionGnutls subclasses are
 * both derived from GTlsConnectionGnutls (and hence GIOStream), and both
 * implement the relevant TLS and DTLS interfaces:
 *  • GTlsClientConnection
 *  • GDtlsClientConnection
 *  • GTlsServerConnection
 *  • GDtlsServerConnection
 */

static ssize_t g_tls_connection_gnutls_push_func (gnutls_transport_ptr_t  transport_data,
                                                  const void             *buf,
                                                  size_t                  buflen);
static ssize_t g_tls_connection_gnutls_vec_push_func (gnutls_transport_ptr_t  transport_data,
                                                      const giovec_t         *iov,
                                                      int                     iovcnt);
static ssize_t g_tls_connection_gnutls_pull_func (gnutls_transport_ptr_t  transport_data,
                                                  void                   *buf,
                                                  size_t                  buflen);

static int     g_tls_connection_gnutls_pull_timeout_func (gnutls_transport_ptr_t transport_data,
                                                          unsigned int           ms);


static void     g_tls_connection_gnutls_initable_iface_init (GInitableIface  *iface);
static gboolean g_tls_connection_gnutls_initable_init       (GInitable       *initable,
                                                             GCancellable    *cancellable,
                                                             GError         **error);
static void     g_tls_connection_gnutls_dtls_connection_iface_init (GDtlsConnectionInterface *iface);
static void     g_tls_connection_gnutls_datagram_based_iface_init  (GDatagramBasedInterface  *iface);

static void g_tls_connection_gnutls_init_priorities (void);

static int verify_certificate_cb (gnutls_session_t session);

static gboolean do_implicit_handshake (GTlsConnectionGnutls  *gnutls,
                                       gint64                 timeout,
                                       GCancellable          *cancellable,
                                       GError               **error);
static gboolean finish_handshake (GTlsConnectionGnutls  *gnutls,
                                  GTask                 *task,
                                  GError               **error);

enum
{
  PROP_0,
  /* For this class: */
  PROP_BASE_IO_STREAM,
  PROP_BASE_SOCKET,
  /* For GTlsConnection and GDtlsConnection: */
  PROP_REQUIRE_CLOSE_NOTIFY,
  PROP_REHANDSHAKE_MODE,
  PROP_USE_SYSTEM_CERTDB,
  PROP_DATABASE,
  PROP_CERTIFICATE,
  PROP_INTERACTION,
  PROP_PEER_CERTIFICATE,
  PROP_PEER_CERTIFICATE_ERRORS,
#if GLIB_CHECK_VERSION(2, 60, 0)
  PROP_ADVERTISED_PROTOCOLS,
  PROP_NEGOTIATED_PROTOCOL,
#endif
};

typedef struct
{
  /* When operating in stream mode, as a GTlsConnection. These are
   * mutually-exclusive with base_socket. There are two different
   * GIOStreams here: (a) base_io_stream and (b) the GTlsConnectionGnutls
   * itself. base_io_stream is the GIOStream used to create the GTlsConnection,
   * and corresponds to the GTlsConnection::base-io-stream property.
   * base_istream and base_ostream are the GInputStream and GOutputStream,
   * respectively, of base_io_stream. These are for the underlying sockets that
   * don't know about TLS.
   *
   * Then the GTlsConnectionGnutls also has tls_istream and tls_ostream which
   * wrap the aforementioned base streams with a TLS session.
   *
   * When operating in datagram mode, none of these are used.
   */
  GIOStream *base_io_stream;
  GPollableInputStream *base_istream;
  GPollableOutputStream *base_ostream;
  GInputStream *tls_istream;
  GOutputStream *tls_ostream;

  /* When operating in datagram mode, as a GDtlsConnection, the
   * GTlsConnectionGnutls is itself the DTLS GDatagramBased. It uses base_socket
   * for the underlying I/O. It is mutually-exclusive with base_io_stream and
   * the other streams.
   */
  GDatagramBased *base_socket;

  gnutls_certificate_credentials_t creds;
  gnutls_session_t session;

  GTlsCertificate *certificate, *peer_certificate;
  GTlsCertificateFlags peer_certificate_errors;

  GMutex verify_certificate_mutex;
  GCond verify_certificate_condition;
  gboolean peer_certificate_accepted;
  gboolean peer_certificate_examined;

  gboolean require_close_notify;
  GTlsRehandshakeMode rehandshake_mode;
  gboolean is_system_certdb;
  GTlsDatabase *database;
  gboolean database_is_unset;

  /* need_handshake means the next claim_op() will get diverted into
   * an implicit handshake (unless it's an OP_HANDSHAKE or OP_CLOSE*).
   * need_finish_handshake means the next claim_op() will get diverted
   * into finish_handshake() (unless it's an OP_CLOSE*).
   *
   * handshaking is TRUE as soon as a handshake thread is queued. For
   * a sync handshake it becomes FALSE after finish_handshake()
   * completes in the calling thread, but for an async implicit
   * handshake, it becomes FALSE (and need_finish_handshake becomes
   * TRUE) at the end of the handshaking thread (and then the next
   * non-close op will call finish_handshake()). We can't just wait
   * for handshake_thread_completed() to run, because it's possible
   * that its main loop is being blocked by a synchronous op which is
   * waiting for handshaking to become FALSE...
   *
   * started_handshake indicates that the current handshake attempt
   * got at least as far as calling gnutls_handshake() (and so any
   * error should be copied to handshake_error and returned on all
   * future operations). ever_handshaked indicates that TLS has
   * been successfully negotiated at some point.
   */
  gboolean need_handshake, need_finish_handshake, sync_handshake_completed;
  gboolean started_handshake, handshaking, ever_handshaked;
  GMainContext *handshake_context;
  GTask *implicit_handshake;
  GError *handshake_error;
  GByteArray *app_data_buf;

  /* read_closed means the read direction has closed; write_closed similarly.
   * If (and only if) both are set, the entire GTlsConnection is closed. */
  gboolean read_closing, read_closed;
  gboolean write_closing, write_closed;

  GTlsInteraction *interaction;
  gchar *interaction_id;

#if GLIB_CHECK_VERSION(2, 60, 0)
  gchar **advertised_protocols;
  gchar *negotiated_protocol;
#endif

  GMutex        op_mutex;
  GCancellable *waiting_for_op;

  gboolean      reading;
  gint64        read_timeout;
  GError       *read_error;
  GCancellable *read_cancellable;

  gboolean      writing;
  gint64        write_timeout;
  GError       *write_error;
  GCancellable *write_cancellable;
} GTlsConnectionGnutlsPrivate;

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (GTlsConnectionGnutls, g_tls_connection_gnutls, G_TYPE_TLS_CONNECTION,
                                  G_ADD_PRIVATE (GTlsConnectionGnutls);
                                  G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                         g_tls_connection_gnutls_initable_iface_init);
                                  G_IMPLEMENT_INTERFACE (G_TYPE_DATAGRAM_BASED,
                                                         g_tls_connection_gnutls_datagram_based_iface_init);
                                  G_IMPLEMENT_INTERFACE (G_TYPE_DTLS_CONNECTION,
                                                         g_tls_connection_gnutls_dtls_connection_iface_init);
                                  g_tls_connection_gnutls_init_priorities ();
                                  );

static gint unique_interaction_id = 0;

static void
g_tls_connection_gnutls_init (GTlsConnectionGnutls *gnutls)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gint unique_id;

  gnutls_certificate_allocate_credentials (&priv->creds);

  g_mutex_init (&priv->verify_certificate_mutex);
  g_cond_init (&priv->verify_certificate_condition);

  priv->need_handshake = TRUE;

  priv->database_is_unset = TRUE;
  priv->is_system_certdb = TRUE;

  unique_id = g_atomic_int_add (&unique_interaction_id, 1);
  priv->interaction_id = g_strdup_printf ("gtls:%d", unique_id);

  priv->waiting_for_op = g_cancellable_new ();
  g_cancellable_cancel (priv->waiting_for_op);
  g_mutex_init (&priv->op_mutex);
}

/* First field is "fallback", second is "allow unsafe rehandshaking" */
static gnutls_priority_t priorities[2][2];

/* TODO: Get rid of this in favor of gnutls_set_default_priority_append()
 * when upgrading to GnuTLS 3.6.3.
 */
#define DEFAULT_BASE_PRIORITY "NORMAL:%COMPAT"

static void
g_tls_connection_gnutls_init_priorities (void)
{
  const gchar *base_priority;
  gchar *fallback_priority, *unsafe_rehandshake_priority, *fallback_unsafe_rehandshake_priority;
  const guint *protos;
  int ret, i, nprotos, fallback_proto;

  base_priority = g_getenv ("G_TLS_GNUTLS_PRIORITY");
  if (!base_priority)
    base_priority = DEFAULT_BASE_PRIORITY;
  ret = gnutls_priority_init (&priorities[FALSE][FALSE], base_priority, NULL);
  if (ret == GNUTLS_E_INVALID_REQUEST)
    {
      g_warning ("G_TLS_GNUTLS_PRIORITY is invalid; ignoring!");
      base_priority = DEFAULT_BASE_PRIORITY;
      ret = gnutls_priority_init (&priorities[FALSE][FALSE], base_priority, NULL);
      g_warn_if_fail (ret == 0);
    }

  unsafe_rehandshake_priority = g_strdup_printf ("%s:%%UNSAFE_RENEGOTIATION", base_priority);
  ret = gnutls_priority_init (&priorities[FALSE][TRUE], unsafe_rehandshake_priority, NULL);
  g_warn_if_fail (ret == 0);
  g_free (unsafe_rehandshake_priority);

  /* Figure out the lowest SSl/TLS version supported by base_priority */
  nprotos = gnutls_priority_protocol_list (priorities[FALSE][FALSE], &protos);
  fallback_proto = G_MAXUINT;
  for (i = 0; i < nprotos; i++)
    {
      if (protos[i] < fallback_proto)
        fallback_proto = protos[i];
    }
  if (fallback_proto == G_MAXUINT)
    {
      g_warning ("All GNUTLS protocol versions disabled?");
      fallback_priority = g_strdup (base_priority);
    }
  else
    {
      /* %COMPAT is intentionally duplicated here, to ensure it gets added for
       * the fallback even if the default priority has been changed. */
      fallback_priority = g_strdup_printf ("%s:%%COMPAT:!VERS-TLS-ALL:+VERS-%s:%%FALLBACK_SCSV",
                                           DEFAULT_BASE_PRIORITY,
                                           gnutls_protocol_get_name (fallback_proto));
    }
  fallback_unsafe_rehandshake_priority = g_strdup_printf ("%s:%%UNSAFE_RENEGOTIATION",
                                                          fallback_priority);

  ret = gnutls_priority_init (&priorities[TRUE][FALSE], fallback_priority, NULL);
  g_warn_if_fail (ret == 0);
  ret = gnutls_priority_init (&priorities[TRUE][TRUE], fallback_unsafe_rehandshake_priority, NULL);
  g_warn_if_fail (ret == 0);
  g_free (fallback_priority);
  g_free (fallback_unsafe_rehandshake_priority);
}

static void
g_tls_connection_gnutls_set_handshake_priority (GTlsConnectionGnutls *gnutls)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gboolean fallback, unsafe_rehandshake;

  if (G_IS_TLS_CLIENT_CONNECTION (gnutls))
    {
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
      fallback = g_tls_client_connection_get_use_ssl3 (G_TLS_CLIENT_CONNECTION (gnutls));
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
    }
  else
    fallback = FALSE;
  unsafe_rehandshake = (priv->rehandshake_mode == G_TLS_REHANDSHAKE_UNSAFELY);
  gnutls_priority_set (priv->session,
                       priorities[fallback][unsafe_rehandshake]);
}

static gboolean
g_tls_connection_gnutls_is_dtls (GTlsConnectionGnutls *gnutls)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  return (priv->base_socket != NULL);
}

static gboolean
g_tls_connection_gnutls_initable_init (GInitable     *initable,
                                       GCancellable  *cancellable,
                                       GError       **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (initable);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gboolean client = G_IS_TLS_CLIENT_CONNECTION (gnutls);
  guint flags = client ? GNUTLS_CLIENT : GNUTLS_SERVER;
  int status;

  g_return_val_if_fail ((priv->base_istream == NULL) ==
                        (priv->base_ostream == NULL), FALSE);
  g_return_val_if_fail ((priv->base_socket == NULL) !=
                        (priv->base_istream == NULL), FALSE);

  /* Check whether to use DTLS or TLS. */
  if (g_tls_connection_gnutls_is_dtls (gnutls))
    flags |= GNUTLS_DATAGRAM;

  gnutls_init (&priv->session, flags);

  gnutls_session_set_ptr (priv->session, gnutls);
  gnutls_session_set_verify_function (priv->session, verify_certificate_cb);

  status = gnutls_credentials_set (priv->session,
                                   GNUTLS_CRD_CERTIFICATE,
                                   priv->creds);
  if (status != 0)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Could not create TLS connection: %s"),
                   gnutls_strerror (status));
      return FALSE;
    }

  gnutls_transport_set_push_function (priv->session,
                                      g_tls_connection_gnutls_push_func);
  gnutls_transport_set_pull_function (priv->session,
                                      g_tls_connection_gnutls_pull_func);
  gnutls_transport_set_pull_timeout_function (priv->session,
                                              g_tls_connection_gnutls_pull_timeout_func);
  gnutls_transport_set_ptr (priv->session, gnutls);

  /* GDatagramBased supports vectored I/O; GPollableOutputStream does not. */
  if (priv->base_socket != NULL)
    {
      gnutls_transport_set_vec_push_function (priv->session,
                                              g_tls_connection_gnutls_vec_push_func);
    }

  /* Set reasonable MTU */
  if (flags & GNUTLS_DATAGRAM)
    gnutls_dtls_set_mtu (priv->session, 1400);

  /* Create output streams if operating in streaming mode. */
  if (!(flags & GNUTLS_DATAGRAM))
    {
      priv->tls_istream = g_tls_input_stream_gnutls_new (gnutls);
      priv->tls_ostream = g_tls_output_stream_gnutls_new (gnutls);
    }

  return TRUE;
}

static void
g_tls_connection_gnutls_finalize (GObject *object)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (object);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  g_clear_object (&priv->base_io_stream);
  g_clear_object (&priv->base_socket);

  g_clear_object (&priv->tls_istream);
  g_clear_object (&priv->tls_ostream);

  if (priv->session)
    gnutls_deinit (priv->session);
  if (priv->creds)
    gnutls_certificate_free_credentials (priv->creds);

  g_clear_object (&priv->database);
  g_clear_object (&priv->certificate);
  g_clear_object (&priv->peer_certificate);

  g_mutex_clear (&priv->verify_certificate_mutex);
  g_cond_clear (&priv->verify_certificate_condition);

  g_clear_pointer (&priv->app_data_buf, g_byte_array_unref);

  g_free (priv->interaction_id);
  g_clear_object (&priv->interaction);

#if GLIB_CHECK_VERSION(2, 60, 0)
  g_clear_pointer (&priv->advertised_protocols, g_strfreev);
  g_clear_pointer (&priv->negotiated_protocol, g_free);
#endif

  g_clear_error (&priv->handshake_error);
  g_clear_error (&priv->read_error);
  g_clear_error (&priv->write_error);

  g_clear_pointer (&priv->handshake_context, g_main_context_unref);

  /* This must always be NULL here, as it holds a reference to @gnutls as
   * its source object. However, we clear it anyway just in case this changes
   * in future. */
  g_clear_object (&priv->implicit_handshake);

  g_clear_object (&priv->read_cancellable);
  g_clear_object (&priv->write_cancellable);

  g_clear_object (&priv->waiting_for_op);
  g_mutex_clear (&priv->op_mutex);

  G_OBJECT_CLASS (g_tls_connection_gnutls_parent_class)->finalize (object);
}

static void
g_tls_connection_gnutls_get_property (GObject    *object,
                                      guint       prop_id,
                                      GValue     *value,
                                      GParamSpec *pspec)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (object);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GTlsBackend *backend;

  switch (prop_id)
    {
    case PROP_BASE_IO_STREAM:
      g_value_set_object (value, priv->base_io_stream);
      break;

    case PROP_BASE_SOCKET:
      g_value_set_object (value, priv->base_socket);
      break;

    case PROP_REQUIRE_CLOSE_NOTIFY:
      g_value_set_boolean (value, priv->require_close_notify);
      break;

    case PROP_REHANDSHAKE_MODE:
      g_value_set_enum (value, priv->rehandshake_mode);
      break;

    case PROP_USE_SYSTEM_CERTDB:
      g_value_set_boolean (value, priv->is_system_certdb);
      break;

    case PROP_DATABASE:
      if (priv->database_is_unset)
        {
          backend = g_tls_backend_get_default ();
          priv->database =  g_tls_backend_get_default_database (backend);
          priv->database_is_unset = FALSE;
        }
      g_value_set_object (value, priv->database);
      break;

    case PROP_CERTIFICATE:
      g_value_set_object (value, priv->certificate);
      break;

    case PROP_INTERACTION:
      g_value_set_object (value, priv->interaction);
      break;

    case PROP_PEER_CERTIFICATE:
      g_value_set_object (value, priv->peer_certificate);
      break;

    case PROP_PEER_CERTIFICATE_ERRORS:
      g_value_set_flags (value, priv->peer_certificate_errors);
      break;

#if GLIB_CHECK_VERSION(2, 60, 0)
    case PROP_ADVERTISED_PROTOCOLS:
      g_value_set_boxed (value, priv->advertised_protocols);
      break;

    case PROP_NEGOTIATED_PROTOCOL:
      g_value_set_string (value, priv->negotiated_protocol);
      break;
#endif

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_connection_gnutls_set_property (GObject      *object,
                                      guint         prop_id,
                                      const GValue *value,
                                      GParamSpec   *pspec)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (object);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GInputStream *istream;
  GOutputStream *ostream;
  gboolean system_certdb;
  GTlsBackend *backend;

  switch (prop_id)
    {
    case PROP_BASE_IO_STREAM:
      g_assert (g_value_get_object (value) == NULL ||
                priv->base_socket == NULL);

      if (priv->base_io_stream)
        {
          g_object_unref (priv->base_io_stream);
          priv->base_istream = NULL;
          priv->base_ostream = NULL;
        }
      priv->base_io_stream = g_value_dup_object (value);
      if (!priv->base_io_stream)
        return;

      istream = g_io_stream_get_input_stream (priv->base_io_stream);
      ostream = g_io_stream_get_output_stream (priv->base_io_stream);

      if (G_IS_POLLABLE_INPUT_STREAM (istream) &&
          g_pollable_input_stream_can_poll (G_POLLABLE_INPUT_STREAM (istream)))
        priv->base_istream = G_POLLABLE_INPUT_STREAM (istream);
      if (G_IS_POLLABLE_OUTPUT_STREAM (ostream) &&
          g_pollable_output_stream_can_poll (G_POLLABLE_OUTPUT_STREAM (ostream)))
        priv->base_ostream = G_POLLABLE_OUTPUT_STREAM (ostream);
      break;

    case PROP_BASE_SOCKET:
      g_assert (g_value_get_object (value) == NULL ||
                priv->base_io_stream == NULL);

      g_clear_object (&priv->base_socket);
      priv->base_socket = g_value_dup_object (value);
      break;

    case PROP_REQUIRE_CLOSE_NOTIFY:
      priv->require_close_notify = g_value_get_boolean (value);
      break;

    case PROP_REHANDSHAKE_MODE:
      priv->rehandshake_mode = g_value_get_enum (value);
      break;

    case PROP_USE_SYSTEM_CERTDB:
      system_certdb = g_value_get_boolean (value);
      if (system_certdb != priv->is_system_certdb)
        {
          g_clear_object (&priv->database);
          if (system_certdb)
            {
              backend = g_tls_backend_get_default ();
              priv->database = g_tls_backend_get_default_database (backend);
            }
          priv->is_system_certdb = system_certdb;
          priv->database_is_unset = FALSE;
        }
      break;

    case PROP_DATABASE:
      g_clear_object (&priv->database);
      priv->database = g_value_dup_object (value);
      priv->is_system_certdb = FALSE;
      priv->database_is_unset = FALSE;
      break;

    case PROP_CERTIFICATE:
      if (priv->certificate)
        g_object_unref (priv->certificate);
      priv->certificate = g_value_dup_object (value);
      break;

    case PROP_INTERACTION:
      g_clear_object (&priv->interaction);
      priv->interaction = g_value_dup_object (value);
      break;

#if GLIB_CHECK_VERSION(2, 60, 0)
    case PROP_ADVERTISED_PROTOCOLS:
      g_clear_pointer (&priv->advertised_protocols, g_strfreev);
      priv->advertised_protocols = g_value_dup_boxed (value);
      break;
#endif

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

gnutls_certificate_credentials_t
g_tls_connection_gnutls_get_credentials (GTlsConnectionGnutls *gnutls)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  return priv->creds;
}

gnutls_session_t
g_tls_connection_gnutls_get_session (GTlsConnectionGnutls *gnutls)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  return priv->session;
}

void
g_tls_connection_gnutls_get_certificate (GTlsConnectionGnutls  *gnutls,
                                         gnutls_pcert_st      **pcert,
                                         unsigned int          *pcert_length,
                                         gnutls_privkey_t      *pkey)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GTlsCertificate *cert;

  cert = g_tls_connection_get_certificate (G_TLS_CONNECTION (gnutls));

  if (cert)
    {
      g_tls_certificate_gnutls_copy (G_TLS_CERTIFICATE_GNUTLS (cert),
                                     priv->interaction_id,
                                     pcert, pcert_length, pkey);
    }
  else
    {
      *pcert = NULL;
      *pcert_length = 0;
      *pkey = NULL;
    }
}

typedef enum {
  G_TLS_CONNECTION_GNUTLS_OP_HANDSHAKE,
  G_TLS_CONNECTION_GNUTLS_OP_READ,
  G_TLS_CONNECTION_GNUTLS_OP_WRITE,
  G_TLS_CONNECTION_GNUTLS_OP_CLOSE_READ,
  G_TLS_CONNECTION_GNUTLS_OP_CLOSE_WRITE,
  G_TLS_CONNECTION_GNUTLS_OP_CLOSE_BOTH,
} GTlsConnectionGnutlsOp;

static gboolean
claim_op (GTlsConnectionGnutls    *gnutls,
          GTlsConnectionGnutlsOp   op,
          gint64                   timeout,
          GCancellable            *cancellable,
          GError                 **error)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

 try_again:
  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return FALSE;

  g_mutex_lock (&priv->op_mutex);

  if (((op == G_TLS_CONNECTION_GNUTLS_OP_HANDSHAKE ||
        op == G_TLS_CONNECTION_GNUTLS_OP_READ) &&
       (priv->read_closing || priv->read_closed)) ||
      ((op == G_TLS_CONNECTION_GNUTLS_OP_HANDSHAKE ||
        op == G_TLS_CONNECTION_GNUTLS_OP_WRITE) &&
       (priv->write_closing || priv->write_closed)))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CLOSED,
                           _("Connection is closed"));
      g_mutex_unlock (&priv->op_mutex);
      return FALSE;
    }

  if (priv->handshake_error &&
      op != G_TLS_CONNECTION_GNUTLS_OP_CLOSE_BOTH &&
      op != G_TLS_CONNECTION_GNUTLS_OP_CLOSE_READ &&
      op != G_TLS_CONNECTION_GNUTLS_OP_CLOSE_WRITE)
    {
      if (error)
        *error = g_error_copy (priv->handshake_error);
      g_mutex_unlock (&priv->op_mutex);
      return FALSE;
    }

  if (op != G_TLS_CONNECTION_GNUTLS_OP_HANDSHAKE)
    {
      if (op != G_TLS_CONNECTION_GNUTLS_OP_CLOSE_BOTH &&
          op != G_TLS_CONNECTION_GNUTLS_OP_CLOSE_READ &&
          op != G_TLS_CONNECTION_GNUTLS_OP_CLOSE_WRITE &&
          priv->need_handshake)
        {
          priv->need_handshake = FALSE;
          priv->handshaking = TRUE;
          if (!do_implicit_handshake (gnutls, timeout, cancellable, error))
            {
              g_mutex_unlock (&priv->op_mutex);
              return FALSE;
            }
        }

      if (priv->need_finish_handshake &&
          priv->implicit_handshake)
        {
          GError *my_error = NULL;
          gboolean success;

          priv->need_finish_handshake = FALSE;

          g_mutex_unlock (&priv->op_mutex);
          success = finish_handshake (gnutls, priv->implicit_handshake, &my_error);
          g_clear_object (&priv->implicit_handshake);
          g_clear_pointer (&priv->handshake_context, g_main_context_unref);
          g_mutex_lock (&priv->op_mutex);

          if (op != G_TLS_CONNECTION_GNUTLS_OP_CLOSE_BOTH &&
              op != G_TLS_CONNECTION_GNUTLS_OP_CLOSE_READ &&
              op != G_TLS_CONNECTION_GNUTLS_OP_CLOSE_WRITE &&
              (!success || g_cancellable_set_error_if_cancelled (cancellable, &my_error)))
            {
              g_propagate_error (error, my_error);
              g_mutex_unlock (&priv->op_mutex);
              return FALSE;
            }

          g_clear_error (&my_error);
        }
    }

  if (priv->handshaking &&
      timeout != 0 &&
      g_main_context_is_owner (priv->handshake_context))
    {
      /* Cannot perform a blocking operation during a handshake on the
       * same thread that triggered the handshake. The only way this can
       * occur is if the application is doing something weird in its
       * accept-certificate callback. Allowing a blocking op would stall
       * the handshake (forever, if there's no timeout). Even a close
       * op would deadlock here.
       */
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, _("Cannot perform blocking operation during TLS handshake"));
      g_mutex_unlock (&priv->op_mutex);
      return FALSE;
    }

  if ((op != G_TLS_CONNECTION_GNUTLS_OP_WRITE && priv->reading) ||
      (op != G_TLS_CONNECTION_GNUTLS_OP_READ && priv->writing) ||
      (op != G_TLS_CONNECTION_GNUTLS_OP_HANDSHAKE && priv->handshaking))
    {
      GPollFD fds[2];
      int nfds;
      gint64 start_time;
      gint result = 1;  /* if the loop is never entered, it’s as if we cancelled early */

      g_cancellable_reset (priv->waiting_for_op);

      g_mutex_unlock (&priv->op_mutex);

      if (timeout == 0)
        {
          /* Intentionally not translated because this is not a fatal error to be
           * presented to the user, and to avoid this showing up in profiling. */
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK, "Operation would block");
          return FALSE;
        }

      g_cancellable_make_pollfd (priv->waiting_for_op, &fds[0]);
      if (g_cancellable_make_pollfd (cancellable, &fds[1]))
        nfds = 2;
      else
        nfds = 1;

      /* Convert from microseconds to milliseconds. */
      if (timeout != -1)
        timeout = timeout / 1000;

      /* Poll until cancellation or the timeout is reached. */
      start_time = g_get_monotonic_time ();

      while (!g_cancellable_is_cancelled (priv->waiting_for_op) &&
             !g_cancellable_is_cancelled (cancellable))
        {
          result = g_poll (fds, nfds, timeout);

          if (result == 0)
            break;
          if (result != -1 || errno != EINTR)
            continue;

          if (timeout != -1)
            {
              timeout -= (g_get_monotonic_time () - start_time) / 1000;
              if (timeout < 0)
                timeout = 0;
            }
        }

      if (nfds > 1)
        g_cancellable_release_fd (cancellable);

      if (result == 0)
        {
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                               _("Socket I/O timed out"));
          return FALSE;
        }

      goto try_again;
    }

  if (op == G_TLS_CONNECTION_GNUTLS_OP_HANDSHAKE)
    {
      priv->handshaking = TRUE;
      priv->need_handshake = FALSE;
    }
  if (op == G_TLS_CONNECTION_GNUTLS_OP_CLOSE_BOTH ||
      op == G_TLS_CONNECTION_GNUTLS_OP_CLOSE_READ)
    priv->read_closing = TRUE;
  if (op == G_TLS_CONNECTION_GNUTLS_OP_CLOSE_BOTH ||
      op == G_TLS_CONNECTION_GNUTLS_OP_CLOSE_WRITE)
    priv->write_closing = TRUE;

  if (op != G_TLS_CONNECTION_GNUTLS_OP_WRITE)
    priv->reading = TRUE;
  if (op != G_TLS_CONNECTION_GNUTLS_OP_READ)
    priv->writing = TRUE;

  g_mutex_unlock (&priv->op_mutex);
  return TRUE;
}

static void
yield_op (GTlsConnectionGnutls   *gnutls,
          GTlsConnectionGnutlsOp  op)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  g_mutex_lock (&priv->op_mutex);

  if (op == G_TLS_CONNECTION_GNUTLS_OP_HANDSHAKE)
    priv->handshaking = FALSE;
  if (op == G_TLS_CONNECTION_GNUTLS_OP_CLOSE_BOTH ||
      op == G_TLS_CONNECTION_GNUTLS_OP_CLOSE_READ)
    priv->read_closing = FALSE;
  if (op == G_TLS_CONNECTION_GNUTLS_OP_CLOSE_BOTH ||
      op == G_TLS_CONNECTION_GNUTLS_OP_CLOSE_WRITE)
    priv->write_closing = FALSE;

  if (op != G_TLS_CONNECTION_GNUTLS_OP_WRITE)
    priv->reading = FALSE;
  if (op != G_TLS_CONNECTION_GNUTLS_OP_READ)
    priv->writing = FALSE;

  g_cancellable_cancel (priv->waiting_for_op);
  g_mutex_unlock (&priv->op_mutex);
}

static void
begin_gnutls_io (GTlsConnectionGnutls  *gnutls,
                 GIOCondition           direction,
                 gint64                 timeout,
                 GCancellable          *cancellable)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  g_assert (direction & (G_IO_IN | G_IO_OUT));

  if (direction & G_IO_IN)
    {
      priv->read_timeout = timeout;
      priv->read_cancellable = cancellable;
      g_clear_error (&priv->read_error);
    }

  if (direction & G_IO_OUT)
    {
      priv->write_timeout = timeout;
      priv->write_cancellable = cancellable;
      g_clear_error (&priv->write_error);
    }
}

static int
end_gnutls_io (GTlsConnectionGnutls  *gnutls,
               GIOCondition           direction,
               int                    status,
               GError               **error,
               const char            *err_prefix);

static int
end_gnutls_io (GTlsConnectionGnutls  *gnutls,
               GIOCondition           direction,
               int                    status,
               GError               **error,
               const char            *err_prefix)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GError *my_error = NULL;

  g_assert (direction & (G_IO_IN | G_IO_OUT));
  g_assert (!error || !*error);

  /* We intentionally do not check for GNUTLS_E_INTERRUPTED here
   * Instead, the caller may poll for the source to become ready again.
   * (Note that GTlsOutputStreamGnutls and GTlsInputStreamGnutls inherit
   * from GPollableOutputStream and GPollableInputStream, respectively.)
   * See also the comment in set_gnutls_error().
   */
  if (status == GNUTLS_E_AGAIN ||
      status == GNUTLS_E_WARNING_ALERT_RECEIVED)
    return GNUTLS_E_AGAIN;

  if (direction & G_IO_IN)
    {
      priv->read_cancellable = NULL;
      if (status < 0)
        {
          my_error = priv->read_error;
          priv->read_error = NULL;
        }
      else
        g_clear_error (&priv->read_error);
    }
  if (direction & G_IO_OUT)
    {
      priv->write_cancellable = NULL;
      if (status < 0 && !my_error)
        {
          my_error = priv->write_error;
          priv->write_error = NULL;
        }
      else
        g_clear_error (&priv->write_error);
    }

  if (status >= 0)
    return status;

  if (priv->handshaking && !priv->ever_handshaked)
    {
      if (g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_FAILED) ||
          g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_BROKEN_PIPE) ||
          status == GNUTLS_E_UNEXPECTED_PACKET_LENGTH ||
          status == GNUTLS_E_DECRYPTION_FAILED ||
          status == GNUTLS_E_UNSUPPORTED_VERSION_PACKET)
        {
          g_clear_error (&my_error);
          g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_NOT_TLS,
                               _("Peer failed to perform TLS handshake"));
          return GNUTLS_E_PULL_ERROR;
        }
    }

  if (my_error)
    {
      if (!g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK) &&
          !g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT))
        G_TLS_CONNECTION_GNUTLS_GET_CLASS (gnutls)->failed (gnutls);
      g_propagate_error (error, my_error);
      return status;
    }
  else if (status == GNUTLS_E_REHANDSHAKE)
    {
      if (priv->rehandshake_mode == G_TLS_REHANDSHAKE_NEVER)
        {
          g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                               _("Peer requested illegal TLS rehandshake"));
          return GNUTLS_E_PULL_ERROR;
        }

      g_mutex_lock (&priv->op_mutex);
      if (!priv->handshaking)
        priv->need_handshake = TRUE;
      g_mutex_unlock (&priv->op_mutex);
      return status;
    }
  else if (status == GNUTLS_E_PREMATURE_TERMINATION)
    {
      if (priv->handshaking && !priv->ever_handshaked)
        {
          g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_NOT_TLS,
                               _("Peer failed to perform TLS handshake"));
          return GNUTLS_E_PULL_ERROR;
        }
      else if (priv->require_close_notify)
        {
          g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_EOF,
                               _("TLS connection closed unexpectedly"));
          G_TLS_CONNECTION_GNUTLS_GET_CLASS (gnutls)->failed (gnutls);
          return status;
        }
      else
        return 0;
    }
  else if (status == GNUTLS_E_NO_CERTIFICATE_FOUND
#ifdef GNUTLS_E_CERTIFICATE_REQUIRED
           || status == GNUTLS_E_CERTIFICATE_REQUIRED /* Added in GnuTLS 3.6.7 */
#endif
          )
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED,
                           _("TLS connection peer did not send a certificate"));
      return status;
    }
  else if (status == GNUTLS_E_CERTIFICATE_ERROR)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                   _("Unacceptable TLS certificate"));
      return status;
    }
  else if (status == GNUTLS_E_FATAL_ALERT_RECEIVED)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   _("Peer sent fatal TLS alert: %s"),
                   gnutls_alert_get_name (gnutls_alert_get (priv->session)));
      return status;
    }
  else if (status == GNUTLS_E_INAPPROPRIATE_FALLBACK)
    {
      g_set_error_literal (error, G_TLS_ERROR,
#if GLIB_CHECK_VERSION(2, 60, 0)
                           G_TLS_ERROR_INAPPROPRIATE_FALLBACK,
#else
                           G_TLS_ERROR_MISC,
#endif
                           _("Protocol version downgrade attack detected"));
      return status;
    }
  else if (status == GNUTLS_E_LARGE_PACKET)
    {
      guint mtu = gnutls_dtls_get_data_mtu (priv->session);
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_MESSAGE_TOO_LARGE,
                   ngettext ("Message is too large for DTLS connection; maximum is %u byte",
                             "Message is too large for DTLS connection; maximum is %u bytes", mtu), mtu);
      return status;
    }
  else if (status == GNUTLS_E_TIMEDOUT)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                           _("The operation timed out"));
      return status;
    }

  if (error)
    {
      *error = g_error_new (G_TLS_ERROR, G_TLS_ERROR_MISC, "%s: %s",
          err_prefix, gnutls_strerror (status));
    }
  return status;
}

#define BEGIN_GNUTLS_IO(gnutls, direction, timeout, cancellable)        \
  begin_gnutls_io (gnutls, direction, timeout, cancellable);            \
  do {

#define END_GNUTLS_IO(gnutls, direction, ret, errmsg, err)              \
  } while ((ret = end_gnutls_io (gnutls, direction, ret, err, errmsg)) == GNUTLS_E_AGAIN);

/* Checks whether the underlying base stream or GDatagramBased meets
 * @condition. */
static gboolean
g_tls_connection_gnutls_base_check (GTlsConnectionGnutls  *gnutls,
                                    GIOCondition           condition)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  if (g_tls_connection_gnutls_is_dtls (gnutls))
    return g_datagram_based_condition_check (priv->base_socket,
                                             condition);
  else if (condition & G_IO_IN)
    return g_pollable_input_stream_is_readable (priv->base_istream);
  else if (condition & G_IO_OUT)
    return g_pollable_output_stream_is_writable (priv->base_ostream);
  else
    g_assert_not_reached ();
}

/* Checks whether the (D)TLS stream meets @condition; not the underlying base
 * stream or GDatagramBased. */
gboolean
g_tls_connection_gnutls_check (GTlsConnectionGnutls  *gnutls,
                               GIOCondition           condition)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  /* Racy, but worst case is that we just get WOULD_BLOCK back */
  if (priv->need_finish_handshake)
    return TRUE;

  /* If a handshake or close is in progress, then tls_istream and
   * tls_ostream are blocked, regardless of the base stream status.
   */
  if (priv->handshaking)
    return FALSE;

  if (((condition & G_IO_IN) && priv->read_closing) ||
      ((condition & G_IO_OUT) && priv->write_closing))
    return FALSE;

  /* Defer to the base stream or GDatagramBased. */
  return g_tls_connection_gnutls_base_check (gnutls, condition);
}

typedef struct {
  GSource               source;

  GTlsConnectionGnutls *gnutls;
  /* Either a GDatagramBased (datagram mode), or a GPollableInputStream or
   * GPollableOutputStream (streaming mode):
   */
  GObject              *base;

  GSource              *child_source;
  GIOCondition          condition;

  gboolean              io_waiting;
  gboolean              op_waiting;
} GTlsConnectionGnutlsSource;

static gboolean
gnutls_source_prepare (GSource *source,
                       gint    *timeout)
{
  *timeout = -1;
  return FALSE;
}

static gboolean
gnutls_source_check (GSource *source)
{
  return FALSE;
}

/* Use a custom dummy callback instead of g_source_set_dummy_callback(), as that
 * uses a GClosure and is slow. (The GClosure is necessary to deal with any
 * function prototype.) */
static gboolean
dummy_callback (gpointer data)
{
  return G_SOURCE_CONTINUE;
}

static void
gnutls_source_sync (GTlsConnectionGnutlsSource *gnutls_source)
{
  GTlsConnectionGnutls *gnutls = gnutls_source->gnutls;
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gboolean io_waiting, op_waiting;

  /* Was the source destroyed earlier in this main context iteration? */
  if (g_source_is_destroyed ((GSource *)gnutls_source))
    return;

  g_mutex_lock (&priv->op_mutex);
  if (((gnutls_source->condition & G_IO_IN) && priv->reading) ||
      ((gnutls_source->condition & G_IO_OUT) && priv->writing) ||
      (priv->handshaking && !priv->need_finish_handshake))
    op_waiting = TRUE;
  else
    op_waiting = FALSE;

  if (!op_waiting && !priv->need_handshake &&
      !priv->need_finish_handshake)
    io_waiting = TRUE;
  else
    io_waiting = FALSE;
  g_mutex_unlock (&priv->op_mutex);

  if (op_waiting == gnutls_source->op_waiting &&
      io_waiting == gnutls_source->io_waiting)
    return;
  gnutls_source->op_waiting = op_waiting;
  gnutls_source->io_waiting = io_waiting;

  if (gnutls_source->child_source)
    {
      g_source_remove_child_source ((GSource *)gnutls_source,
                                    gnutls_source->child_source);
      g_source_unref (gnutls_source->child_source);
    }

  if (op_waiting)
    gnutls_source->child_source = g_cancellable_source_new (priv->waiting_for_op);
  else if (io_waiting && G_IS_DATAGRAM_BASED (gnutls_source->base))
    gnutls_source->child_source = g_datagram_based_create_source (priv->base_socket, gnutls_source->condition, NULL);
  else if (io_waiting && G_IS_POLLABLE_INPUT_STREAM (gnutls_source->base))
    gnutls_source->child_source = g_pollable_input_stream_create_source (priv->base_istream, NULL);
  else if (io_waiting && G_IS_POLLABLE_OUTPUT_STREAM (gnutls_source->base))
    gnutls_source->child_source = g_pollable_output_stream_create_source (priv->base_ostream, NULL);
  else
    gnutls_source->child_source = g_timeout_source_new (0);

  g_source_set_callback (gnutls_source->child_source, dummy_callback, NULL, NULL);
  g_source_add_child_source ((GSource *)gnutls_source, gnutls_source->child_source);
}

static gboolean
gnutls_source_dispatch (GSource     *source,
                        GSourceFunc  callback,
                        gpointer     user_data)
{
  GDatagramBasedSourceFunc datagram_based_func = (GDatagramBasedSourceFunc)callback;
  GPollableSourceFunc pollable_func = (GPollableSourceFunc)callback;
  GTlsConnectionGnutlsSource *gnutls_source = (GTlsConnectionGnutlsSource *)source;
  gboolean ret;

  if (G_IS_DATAGRAM_BASED (gnutls_source->base))
    ret = (*datagram_based_func) (G_DATAGRAM_BASED (gnutls_source->base),
                                  gnutls_source->condition, user_data);
  else
    ret = (*pollable_func) (gnutls_source->base, user_data);

  if (ret)
    gnutls_source_sync (gnutls_source);

  return ret;
}

static void
gnutls_source_finalize (GSource *source)
{
  GTlsConnectionGnutlsSource *gnutls_source = (GTlsConnectionGnutlsSource *)source;

  g_object_unref (gnutls_source->gnutls);
  g_source_unref (gnutls_source->child_source);
}

static gboolean
g_tls_connection_gnutls_source_closure_callback (GObject  *stream,
                                                 gpointer  data)
{
  GClosure *closure = data;

  GValue param = { 0, };
  GValue result_value = { 0, };
  gboolean result;

  g_value_init (&result_value, G_TYPE_BOOLEAN);

  g_value_init (&param, G_TYPE_OBJECT);
  g_value_set_object (&param, stream);

  g_closure_invoke (closure, &result_value, 1, &param, NULL);

  result = g_value_get_boolean (&result_value);
  g_value_unset (&result_value);
  g_value_unset (&param);

  return result;
}

static gboolean
g_tls_connection_gnutls_source_dtls_closure_callback (GObject  *stream,
                                                      GIOCondition condition,
                                                      gpointer  data)
{
  GClosure *closure = data;

  GValue param[2] = { G_VALUE_INIT, G_VALUE_INIT };
  GValue result_value = G_VALUE_INIT;
  gboolean result;

  g_value_init (&result_value, G_TYPE_BOOLEAN);

  g_value_init (&param[0], G_TYPE_DATAGRAM_BASED);
  g_value_set_object (&param[0], stream);
  g_value_init (&param[1], G_TYPE_IO_CONDITION);
  g_value_set_flags (&param[1], condition);

  g_closure_invoke (closure, &result_value, 2, param, NULL);

  result = g_value_get_boolean (&result_value);
  g_value_unset (&result_value);
  g_value_unset (&param[0]);
  g_value_unset (&param[1]);

  return result;
}

static GSourceFuncs gnutls_tls_source_funcs =
{
  gnutls_source_prepare,
  gnutls_source_check,
  gnutls_source_dispatch,
  gnutls_source_finalize,
  (GSourceFunc)g_tls_connection_gnutls_source_closure_callback,
  (GSourceDummyMarshal)g_cclosure_marshal_generic
};

static GSourceFuncs gnutls_dtls_source_funcs =
{
  gnutls_source_prepare,
  gnutls_source_check,
  gnutls_source_dispatch,
  gnutls_source_finalize,
  (GSourceFunc)g_tls_connection_gnutls_source_dtls_closure_callback,
  (GSourceDummyMarshal)g_cclosure_marshal_generic
};

GSource *
g_tls_connection_gnutls_create_source (GTlsConnectionGnutls  *gnutls,
                                       GIOCondition           condition,
                                       GCancellable          *cancellable)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GSource *source, *cancellable_source;
  GTlsConnectionGnutlsSource *gnutls_source;

  if (g_tls_connection_gnutls_is_dtls (gnutls))
    {
      source = g_source_new (&gnutls_dtls_source_funcs,
                             sizeof (GTlsConnectionGnutlsSource));
    }
  else
    {
      source = g_source_new (&gnutls_tls_source_funcs,
                             sizeof (GTlsConnectionGnutlsSource));
    }
  g_source_set_name (source, "GTlsConnectionGnutlsSource");
  gnutls_source = (GTlsConnectionGnutlsSource *)source;
  gnutls_source->gnutls = g_object_ref (gnutls);
  gnutls_source->condition = condition;
  if (g_tls_connection_gnutls_is_dtls (gnutls))
    gnutls_source->base = G_OBJECT (gnutls);
  else if (priv->tls_istream != NULL && condition & G_IO_IN)
    gnutls_source->base = G_OBJECT (priv->tls_istream);
  else if (priv->tls_ostream != NULL && condition & G_IO_OUT)
    gnutls_source->base = G_OBJECT (priv->tls_ostream);
  else
    g_assert_not_reached ();

  gnutls_source->op_waiting = (gboolean) -1;
  gnutls_source->io_waiting = (gboolean) -1;
  gnutls_source_sync (gnutls_source);

  if (cancellable)
    {
      cancellable_source = g_cancellable_source_new (cancellable);
      g_source_set_dummy_callback (cancellable_source);
      g_source_add_child_source (source, cancellable_source);
      g_source_unref (cancellable_source);
    }

  return source;
}

static GSource *
g_tls_connection_gnutls_dtls_create_source (GDatagramBased  *datagram_based,
                                            GIOCondition     condition,
                                            GCancellable    *cancellable)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (datagram_based);

  return g_tls_connection_gnutls_create_source (gnutls, condition, cancellable);
}

static GIOCondition
g_tls_connection_gnutls_condition_check (GDatagramBased  *datagram_based,
                                         GIOCondition     condition)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (datagram_based);

  return (g_tls_connection_gnutls_check (gnutls, condition)) ? condition : 0;
}

static gboolean
g_tls_connection_gnutls_condition_wait (GDatagramBased  *datagram_based,
                                        GIOCondition     condition,
                                        gint64           timeout,
                                        GCancellable    *cancellable,
                                        GError         **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (datagram_based);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GPollFD fds[2];
  guint n_fds;
  gint result = 1;  /* if the loop is never entered, it’s as if we cancelled early */
  gint64 start_time;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return FALSE;

  /* Convert from microseconds to milliseconds. */
  if (timeout != -1)
    timeout = timeout / 1000;

  start_time = g_get_monotonic_time ();

  g_cancellable_make_pollfd (priv->waiting_for_op, &fds[0]);
  n_fds = 1;

  if (g_cancellable_make_pollfd (cancellable, &fds[1]))
    n_fds++;

  while (!g_tls_connection_gnutls_condition_check (datagram_based, condition) &&
         !g_cancellable_is_cancelled (cancellable))
    {
      result = g_poll (fds, n_fds, timeout);
      if (result == 0)
        break;
      if (result != -1 || errno != EINTR)
        continue;

      if (timeout != -1)
        {
          timeout -= (g_get_monotonic_time () - start_time) / 1000;
          if (timeout < 0)
            timeout = 0;
        }
    }

  if (n_fds > 1)
    g_cancellable_release_fd (cancellable);

  if (result == 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                           _("Socket I/O timed out"));
      return FALSE;
    }

  return !g_cancellable_set_error_if_cancelled (cancellable, error);
}

static void
set_gnutls_error (GTlsConnectionGnutls *gnutls,
                  GError               *error)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  /* We set EINTR rather than EAGAIN for G_IO_ERROR_WOULD_BLOCK so
   * that GNUTLS_E_AGAIN only gets returned for gnutls-internal
   * reasons, not for actual socket EAGAINs (and we have access
   * to @error at the higher levels, so we can distinguish them
   * that way later).
   */

  if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
    gnutls_transport_set_errno (priv->session, EINTR);
  else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
    {
      /* Return EAGAIN while handshaking so that GnuTLS handles retries for us
       * internally in its handshaking code. */
      if (priv->base_socket && priv->handshaking)
        gnutls_transport_set_errno (priv->session, EAGAIN);
      else
        gnutls_transport_set_errno (priv->session, EINTR);
    }
  else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT))
    gnutls_transport_set_errno (priv->session, EINTR);
  else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_MESSAGE_TOO_LARGE))
    gnutls_transport_set_errno (priv->session, EMSGSIZE);
  else
    gnutls_transport_set_errno (priv->session, EIO);
}

static ssize_t
g_tls_connection_gnutls_pull_func (gnutls_transport_ptr_t  transport_data,
                                   void                   *buf,
                                   size_t                  buflen)
{
  GTlsConnectionGnutls *gnutls = transport_data;
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  ssize_t ret;

  /* If priv->read_error is non-%NULL when we're called, it means
   * that an error previously occurred, but gnutls decided not to
   * propagate it. So it's correct for us to just clear it. (Usually
   * this means it ignored an EAGAIN after a short read, and now
   * we'll return EAGAIN again, which it will obey this time.)
   */
  g_clear_error (&priv->read_error);

  if (g_tls_connection_gnutls_is_dtls (gnutls))
    {
      GInputVector vector = { buf, buflen };
      GInputMessage message = { NULL, &vector, 1, 0, 0, NULL, NULL };

      ret = g_datagram_based_receive_messages (priv->base_socket,
                                               &message, 1, 0,
                                               priv->handshaking ? 0 : priv->read_timeout,
                                               priv->read_cancellable,
                                               &priv->read_error);

      if (ret > 0)
        ret = message.bytes_received;
    }
  else
    {
      ret = g_pollable_stream_read (G_INPUT_STREAM (priv->base_istream),
                                    buf, buflen,
                                    (priv->read_timeout != 0),
                                    priv->read_cancellable,
                                    &priv->read_error);
    }

  if (ret < 0)
    set_gnutls_error (gnutls, priv->read_error);

  return ret;
}

static ssize_t
g_tls_connection_gnutls_push_func (gnutls_transport_ptr_t  transport_data,
                                   const void             *buf,
                                   size_t                  buflen)
{
  GTlsConnectionGnutls *gnutls = transport_data;
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  ssize_t ret;

  /* See comment in pull_func. */
  g_clear_error (&priv->write_error);

  if (g_tls_connection_gnutls_is_dtls (gnutls))
    {
      GOutputVector vector = { buf, buflen };
      GOutputMessage message = { NULL, &vector, 1, 0, NULL, 0 };

      ret = g_datagram_based_send_messages (priv->base_socket,
                                            &message, 1, 0,
                                            priv->write_timeout,
                                            priv->write_cancellable,
                                            &priv->write_error);

      if (ret > 0)
        ret = message.bytes_sent;
    }
  else
    {
      ret = g_pollable_stream_write (G_OUTPUT_STREAM (priv->base_ostream),
                                     buf, buflen,
                                     (priv->write_timeout != 0),
                                     priv->write_cancellable,
                                     &priv->write_error);
    }

  if (ret < 0)
    set_gnutls_error (gnutls, priv->write_error);

  return ret;
}

static ssize_t
g_tls_connection_gnutls_vec_push_func (gnutls_transport_ptr_t  transport_data,
                                       const giovec_t         *iov,
                                       int                     iovcnt)
{
  GTlsConnectionGnutls *gnutls = transport_data;
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  ssize_t ret;
  GOutputMessage message = { NULL, };
  GOutputVector *vectors;

  /* This function should only be set if we’re using base_socket. */
  g_assert (priv->base_socket != NULL);

  /* See comment in pull_func. */
  g_clear_error (&priv->write_error);

  /* this entire expression will be evaluated at compile time */
  if (sizeof *iov == sizeof *vectors &&
      sizeof iov->iov_base == sizeof vectors->buffer &&
      G_STRUCT_OFFSET (giovec_t, iov_base) ==
      G_STRUCT_OFFSET (GOutputVector, buffer) &&
      sizeof iov->iov_len == sizeof vectors->size &&
      G_STRUCT_OFFSET (giovec_t, iov_len) ==
      G_STRUCT_OFFSET (GOutputVector, size))
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

  ret = g_datagram_based_send_messages (priv->base_socket,
                                        &message, 1, 0,
                                        priv->write_timeout,
                                        priv->write_cancellable,
                                        &priv->write_error);

  if (ret > 0)
    ret = message.bytes_sent;
  else if (ret < 0)
    set_gnutls_error (gnutls, priv->write_error);

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

static int
g_tls_connection_gnutls_pull_timeout_func (gnutls_transport_ptr_t transport_data,
                                           unsigned int           ms)
{
  GTlsConnectionGnutls *gnutls = transport_data;
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  /* Fast path. */
  if (g_tls_connection_gnutls_base_check (gnutls, G_IO_IN) ||
      g_cancellable_is_cancelled (priv->read_cancellable))
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
      if (g_tls_connection_gnutls_is_dtls (gnutls))
        {
          read_source = g_datagram_based_create_source (priv->base_socket, G_IO_IN, NULL);
          g_source_set_callback (read_source, (GSourceFunc)read_datagram_based_cb,
                                 &read_done, NULL);
        }
      else
        {
          read_source = g_pollable_input_stream_create_source (priv->base_istream, NULL);
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
      if (g_tls_connection_gnutls_base_check (gnutls, G_IO_IN) ||
          g_cancellable_is_cancelled (priv->read_cancellable))
        return 1;
    }

  return 0;
}

static GTlsCertificate *
get_peer_certificate_from_session (GTlsConnectionGnutls *gnutls)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  const gnutls_datum_t *certs;
  GTlsCertificateGnutls *chain;
  unsigned int num_certs;

  certs = gnutls_certificate_get_peers (priv->session, &num_certs);
  if (!certs || !num_certs)
    return NULL;

  chain = g_tls_certificate_gnutls_build_chain (certs, num_certs, GNUTLS_X509_FMT_DER);
  if (!chain)
    return NULL;

  return G_TLS_CERTIFICATE (chain);
}

static GTlsCertificateFlags
verify_peer_certificate (GTlsConnectionGnutls *gnutls,
                         GTlsCertificate      *peer_certificate)
{
  GTlsConnection *conn = G_TLS_CONNECTION (gnutls);
  GSocketConnectable *peer_identity;
  GTlsDatabase *database;
  GTlsCertificateFlags errors;
  gboolean is_client;

  is_client = G_IS_TLS_CLIENT_CONNECTION (gnutls);

  if (!is_client)
    peer_identity = NULL;
  else if (!g_tls_connection_gnutls_is_dtls (gnutls))
    peer_identity = g_tls_client_connection_get_server_identity (G_TLS_CLIENT_CONNECTION (gnutls));
  else
    peer_identity = g_dtls_client_connection_get_server_identity (G_DTLS_CLIENT_CONNECTION (gnutls));

  errors = 0;

  database = g_tls_connection_get_database (conn);
  if (database == NULL)
    {
      errors |= G_TLS_CERTIFICATE_UNKNOWN_CA;
      errors |= g_tls_certificate_verify (peer_certificate, peer_identity, NULL);
    }
  else
    {
      GError *error = NULL;

      errors |= g_tls_database_verify_chain (database, peer_certificate,
                                             is_client ?
                                             G_TLS_DATABASE_PURPOSE_AUTHENTICATE_SERVER :
                                             G_TLS_DATABASE_PURPOSE_AUTHENTICATE_CLIENT,
                                             peer_identity,
                                             g_tls_connection_get_interaction (conn),
                                             G_TLS_DATABASE_VERIFY_NONE,
                                             NULL, &error);
      if (error)
        {
          g_warning ("failure verifying certificate chain: %s",
                     error->message);
          g_assert (errors != 0);
          g_clear_error (&error);
        }
    }

  return errors;
}

static void
update_peer_certificate_and_compute_errors (GTlsConnectionGnutls *gnutls)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  /* This function must be called from the handshake context thread
   * (probably the main thread, NOT the handshake thread) because it
   * emits notifies that are application-visible.
   *
   * verify_certificate_mutex should be locked.
   */
  g_assert (priv->handshake_context);
  g_assert (g_main_context_is_owner (priv->handshake_context));

  g_clear_object (&priv->peer_certificate);
  priv->peer_certificate_errors = 0;

  if (gnutls_certificate_type_get (priv->session) == GNUTLS_CRT_X509)
    {
      priv->peer_certificate = get_peer_certificate_from_session (gnutls);
      if (priv->peer_certificate)
        priv->peer_certificate_errors = verify_peer_certificate (gnutls, priv->peer_certificate);
    }

  g_object_notify (G_OBJECT (gnutls), "peer-certificate");
  g_object_notify (G_OBJECT (gnutls), "peer-certificate-errors");
}

static gboolean
accept_or_reject_peer_certificate (gpointer user_data)
{
  GTlsConnectionGnutls *gnutls = user_data;
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gboolean accepted = FALSE;

  g_assert (g_main_context_is_owner (priv->handshake_context));

  g_mutex_lock (&priv->verify_certificate_mutex);

  update_peer_certificate_and_compute_errors (gnutls);

  if (G_IS_TLS_CLIENT_CONNECTION (gnutls) && priv->peer_certificate != NULL)
    {
      GTlsCertificateFlags validation_flags;

      if (!g_tls_connection_gnutls_is_dtls (gnutls))
        validation_flags =
          g_tls_client_connection_get_validation_flags (G_TLS_CLIENT_CONNECTION (gnutls));
      else
        validation_flags =
          g_dtls_client_connection_get_validation_flags (G_DTLS_CLIENT_CONNECTION (gnutls));

      if ((priv->peer_certificate_errors & validation_flags) == 0)
        accepted = TRUE;
    }

  if (!accepted)
    {
      g_main_context_pop_thread_default (priv->handshake_context);
      accepted = g_tls_connection_emit_accept_certificate (G_TLS_CONNECTION (gnutls),
                                                           priv->peer_certificate,
                                                           priv->peer_certificate_errors);
      g_main_context_push_thread_default (priv->handshake_context);
    }

  priv->peer_certificate_accepted = accepted;

  /* This has to be the very last statement before signaling the
   * condition variable because otherwise the code could spuriously
   * wakeup and continue before we are done here.
   */
  priv->peer_certificate_examined = TRUE;

  g_cond_signal (&priv->verify_certificate_condition);
  g_mutex_unlock (&priv->verify_certificate_mutex);

  g_object_notify (G_OBJECT (gnutls), "peer-certificate");
  g_object_notify (G_OBJECT (gnutls), "peer-certificate-errors");

  return G_SOURCE_REMOVE;
}

static int
verify_certificate_cb (gnutls_session_t session)
{
  GTlsConnectionGnutls *gnutls = gnutls_session_get_ptr (session);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gboolean accepted;

  g_mutex_lock (&priv->verify_certificate_mutex);
  priv->peer_certificate_examined = FALSE;
  priv->peer_certificate_accepted = FALSE;
  g_mutex_unlock (&priv->verify_certificate_mutex);

  /* Invoke the callback on the handshake context's thread. This is
   * necessary because we need to ensure the accept-certificate signal
   * is emitted on the original thread.
   */
  g_assert (priv->handshake_context);
  g_main_context_invoke (priv->handshake_context, accept_or_reject_peer_certificate, gnutls);

  /* We'll block the handshake thread until the original thread has
   * decided whether to accept the certificate.
   */
  g_mutex_lock (&priv->verify_certificate_mutex);
  while (!priv->peer_certificate_examined)
    g_cond_wait (&priv->verify_certificate_condition, &priv->verify_certificate_mutex);
  accepted = priv->peer_certificate_accepted;
  g_mutex_unlock (&priv->verify_certificate_mutex);

  /* Return 0 for the handshake to continue, non-zero to terminate. */
  return !accepted;
}

static void
handshake_thread (GTask        *task,
                  gpointer      object,
                  gpointer      task_data,
                  GCancellable *cancellable)
{
  GTlsConnectionGnutls *gnutls = object;
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GError *error = NULL;
  int ret;
  gint64 start_time;
  gint64 timeout;

  /* A timeout, in microseconds, must be provided as a gint64* task_data. */
  g_assert (task_data != NULL);

  timeout = *((gint64 *)task_data);
  start_time = g_get_monotonic_time ();
  priv->started_handshake = FALSE;

  if (!claim_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_HANDSHAKE,
                 timeout, cancellable, &error))
    {
      g_task_return_error (task, error);
      return;
    }

  g_clear_error (&priv->handshake_error);

  if (priv->ever_handshaked && !priv->implicit_handshake)
    {
      if (priv->rehandshake_mode != G_TLS_REHANDSHAKE_UNSAFELY &&
          !gnutls_safe_renegotiation_status (priv->session))
        {
          g_task_return_new_error (task, G_TLS_ERROR, G_TLS_ERROR_MISC,
                                   _("Peer does not support safe renegotiation"));
          return;
        }

      if (!G_IS_TLS_CLIENT_CONNECTION (gnutls))
        {
          /* Adjust the timeout for the next operation in the sequence. */
          if (timeout > 0)
            {
              unsigned int timeout_ms;

              timeout -= (g_get_monotonic_time () - start_time);
              if (timeout <= 0)
                timeout = 1;

              /* Convert from microseconds to milliseconds, but ensure the timeout
               * remains positive. */
              timeout_ms = (timeout + 999) / 1000;

              gnutls_handshake_set_timeout (priv->session, timeout_ms);
              gnutls_dtls_set_timeouts (priv->session, 1000 /* default */,
                                        timeout_ms);
            }

          BEGIN_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, timeout, cancellable);
          ret = gnutls_rehandshake (priv->session);
          END_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, ret,
                         _("Error performing TLS handshake"), &error);

          if (error)
            {
              g_task_return_error (task, error);
              return;
            }
        }
    }

  priv->started_handshake = TRUE;

  if (!priv->ever_handshaked)
    g_tls_connection_gnutls_set_handshake_priority (gnutls);

  /* Adjust the timeout for the next operation in the sequence. */
  if (timeout > 0)
    {
      unsigned int timeout_ms;

      timeout -= (g_get_monotonic_time () - start_time);
      if (timeout <= 0)
        timeout = 1;

      /* Convert from microseconds to milliseconds, but ensure the timeout
       * remains positive. */
      timeout_ms = (timeout + 999) / 1000;

      gnutls_handshake_set_timeout (priv->session, timeout_ms);
      gnutls_dtls_set_timeouts (priv->session, 1000 /* default */,
                                timeout_ms);
    }

  BEGIN_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, timeout, cancellable);
  ret = gnutls_handshake (priv->session);
  if (ret == GNUTLS_E_GOT_APPLICATION_DATA)
    {
      guint8 buf[1024];

      /* Got app data while waiting for rehandshake; buffer it and try again */
      ret = gnutls_record_recv (priv->session, buf, sizeof (buf));
      if (ret > -1)
        {
          if (!priv->app_data_buf)
            priv->app_data_buf = g_byte_array_new ();
          g_byte_array_append (priv->app_data_buf, buf, ret);
          ret = GNUTLS_E_AGAIN;
        }
    }
  END_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, ret,
                 _("Error performing TLS handshake"), &error);

  /* This calls the finish_handshake code of GTlsClientConnectionGnutls
   * or GTlsServerConnectionGnutls. It has nothing to do with
   * GTlsConnectionGnutls's own finish_handshake function, which still
   * needs to be called at this point.
   */
  G_TLS_CONNECTION_GNUTLS_GET_CLASS (gnutls)->finish_handshake (gnutls, &error);

  if (error)
    {
      g_task_return_error (task, error);
    }
  else
    {
      priv->ever_handshaked = TRUE;
      g_task_return_boolean (task, TRUE);
    }
}

static void
begin_handshake (GTlsConnectionGnutls *gnutls)
{
#if GLIB_CHECK_VERSION(2, 60, 0)
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  if (priv->advertised_protocols)
    {
      gnutls_datum_t *protocols;
      int n_protos, i;

      n_protos = g_strv_length (priv->advertised_protocols);
      protocols = g_new (gnutls_datum_t, n_protos);
      for (i = 0; priv->advertised_protocols[i]; i++)
        {
          protocols[i].size = strlen (priv->advertised_protocols[i]);
          protocols[i].data = g_memdup (priv->advertised_protocols[i], protocols[i].size);
        }
      gnutls_alpn_set_protocols (priv->session, protocols, n_protos, 0);
      g_free (protocols);
    }
#endif

  G_TLS_CONNECTION_GNUTLS_GET_CLASS (gnutls)->begin_handshake (gnutls);
}

#if GLIB_CHECK_VERSION(2, 60, 0)
static void
update_negotiated_protocol (GTlsConnectionGnutls *gnutls)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gchar *orig_negotiated_protocol;
  gnutls_datum_t protocol;

  /*
   * Preserve the prior negotiated protocol before clearing it
   */
  orig_negotiated_protocol = g_steal_pointer (&priv->negotiated_protocol);


  if (gnutls_alpn_get_selected_protocol (priv->session, &protocol) == 0 && protocol.size > 0)
    priv->negotiated_protocol = g_strndup ((gchar *)protocol.data, protocol.size);

  /*
   * Notify only if the negotiated protocol changed
   */
  if (g_strcmp0 (orig_negotiated_protocol, priv->negotiated_protocol) != 0)
    g_object_notify (G_OBJECT (gnutls), "negotiated-protocol");

  g_free (orig_negotiated_protocol);
}
#endif

static gboolean
finish_handshake (GTlsConnectionGnutls  *gnutls,
                  GTask                 *task,
                  GError               **error)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  g_assert (error != NULL);

  if (gnutls_session_is_resumed (priv->session))
    {
      /* Because this session was resumed, we skipped certificate
       * verification on this handshake, so we missed our earlier
       * chance to set peer_certificate and peer_certificate_errors.
       * Do so here instead.
       *
       * The certificate has already been accepted, so we don't do
       * anything with the result here.
       */
      g_mutex_lock (&priv->verify_certificate_mutex);
      update_peer_certificate_and_compute_errors (gnutls);
      priv->peer_certificate_examined = TRUE;
      priv->peer_certificate_accepted = TRUE;
      g_mutex_unlock (&priv->verify_certificate_mutex);
    }

  if (g_task_propagate_boolean (task, error) &&
      priv->peer_certificate && !priv->peer_certificate_accepted)
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                           _("Unacceptable TLS certificate"));
    }

#if GLIB_CHECK_VERSION(2, 60, 0)
  if (!*error && priv->advertised_protocols)
    update_negotiated_protocol (gnutls);
#endif

  if (*error && priv->started_handshake)
    priv->handshake_error = g_error_copy (*error);

  return (*error == NULL);
}

static void
sync_handshake_thread_completed (GObject      *object,
                                 GAsyncResult *result,
                                 gpointer      user_data)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (object);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  g_assert (g_main_context_is_owner (priv->handshake_context));

  g_mutex_lock (&priv->op_mutex);
  priv->sync_handshake_completed = TRUE;
  g_mutex_unlock (&priv->op_mutex);

  g_main_context_wakeup (priv->handshake_context);
}

static void
crank_sync_handshake_context (GTlsConnectionGnutls *gnutls,
                              GCancellable         *cancellable)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  /* need_finish_handshake will be set inside sync_handshake_thread_completed(),
   * which should only ever be invoked while iterating the handshake context
   * here. So need_finish_handshake should only change on this thread.
   */
  g_mutex_lock (&priv->op_mutex);
  priv->sync_handshake_completed = FALSE;
  while (!priv->sync_handshake_completed && !g_cancellable_is_cancelled (cancellable))
    {
      g_mutex_unlock (&priv->op_mutex);
      g_main_context_iteration (priv->handshake_context, TRUE);
      g_mutex_lock (&priv->op_mutex);
    }
  g_mutex_unlock (&priv->op_mutex);
}

static gboolean
g_tls_connection_gnutls_handshake (GTlsConnection   *conn,
                                   GCancellable     *cancellable,
                                   GError          **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (conn);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GTask *task;
  gboolean success;
  gint64 *timeout = NULL;
  GError *my_error = NULL;

  g_assert (priv->handshake_context == NULL);
  priv->handshake_context = g_main_context_new ();

  g_main_context_push_thread_default (priv->handshake_context);

  begin_handshake (gnutls);

  task = g_task_new (conn, cancellable, sync_handshake_thread_completed, NULL);
  g_task_set_source_tag (task, g_tls_connection_gnutls_handshake);
  g_task_set_return_on_cancel (task, TRUE);

  timeout = g_new0 (gint64, 1);
  *timeout = -1;  /* blocking */
  g_task_set_task_data (task, timeout, g_free);

  g_task_run_in_thread (task, handshake_thread);
  crank_sync_handshake_context (gnutls, cancellable);

  success = finish_handshake (gnutls, task, &my_error);

  g_main_context_pop_thread_default (priv->handshake_context);
  g_clear_pointer (&priv->handshake_context, g_main_context_unref);
  g_object_unref (task);

  yield_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_HANDSHAKE);

  if (my_error)
    g_propagate_error (error, my_error);
  return success;
}

static gboolean
g_tls_connection_gnutls_dtls_handshake (GDtlsConnection       *conn,
                                        GCancellable          *cancellable,
                                        GError               **error)
{
  return g_tls_connection_gnutls_handshake (G_TLS_CONNECTION (conn),
                                            cancellable, error);
}

/* In the async version we use two GTasks; one to run handshake_thread() and
 * then call handshake_thread_completed(), and a second to call the caller's
 * original callback after we call finish_handshake().
 */

static void
handshake_thread_completed (GObject      *object,
                            GAsyncResult *result,
                            gpointer      user_data)
{
  GTask *caller_task = user_data;
  GTlsConnectionGnutls *gnutls = g_task_get_source_object (caller_task);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GError *error = NULL;
  gboolean need_finish_handshake, success;

  g_mutex_lock (&priv->op_mutex);
  if (priv->need_finish_handshake)
    {
      need_finish_handshake = TRUE;
      priv->need_finish_handshake = FALSE;
    }
  else
    need_finish_handshake = FALSE;
  g_mutex_unlock (&priv->op_mutex);

  if (need_finish_handshake)
    {
      success = finish_handshake (gnutls, G_TASK (result), &error);
      if (success)
        g_task_return_boolean (caller_task, TRUE);
      else
        g_task_return_error (caller_task, error);
    }
  else if (priv->handshake_error)
    g_task_return_error (caller_task, g_error_copy (priv->handshake_error));
  else
    g_task_return_boolean (caller_task, TRUE);

  g_clear_pointer (&priv->handshake_context, g_main_context_unref);
  g_object_unref (caller_task);
}

static void
async_handshake_thread (GTask        *task,
                        gpointer      object,
                        gpointer      task_data,
                        GCancellable *cancellable)
{
  GTlsConnectionGnutls *gnutls = object;
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  handshake_thread (task, object, task_data, cancellable);

  g_mutex_lock (&priv->op_mutex);
  priv->need_finish_handshake = TRUE;
  /* yield_op will clear handshaking too, but we don't want the
   * connection to be briefly "handshaking && need_finish_handshake"
   * after we unlock the mutex.
   */
  priv->handshaking = FALSE;
  g_mutex_unlock (&priv->op_mutex);

  yield_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_HANDSHAKE);
}

static void
g_tls_connection_gnutls_handshake_async (GTlsConnection       *conn,
                                         int                   io_priority,
                                         GCancellable         *cancellable,
                                         GAsyncReadyCallback   callback,
                                         gpointer              user_data)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (G_TLS_CONNECTION_GNUTLS (conn));
  GTask *thread_task, *caller_task;
  gint64 *timeout = NULL;

  g_assert (!priv->handshake_context);
  priv->handshake_context = g_main_context_ref_thread_default ();

  caller_task = g_task_new (conn, cancellable, callback, user_data);
  g_task_set_source_tag (caller_task, g_tls_connection_gnutls_handshake_async);
  g_task_set_priority (caller_task, io_priority);

  begin_handshake (G_TLS_CONNECTION_GNUTLS (conn));

  thread_task = g_task_new (conn, cancellable,
                            handshake_thread_completed, caller_task);
  g_task_set_source_tag (thread_task, g_tls_connection_gnutls_handshake_async);
  g_task_set_priority (thread_task, io_priority);

  timeout = g_new0 (gint64, 1);
  *timeout = -1;  /* blocking */
  g_task_set_task_data (thread_task, timeout, g_free);

  g_task_run_in_thread (thread_task, async_handshake_thread);
  g_object_unref (thread_task);
}

static gboolean
g_tls_connection_gnutls_handshake_finish (GTlsConnection       *conn,
                                          GAsyncResult         *result,
                                          GError              **error)
{
  g_return_val_if_fail (g_task_is_valid (result, conn), FALSE);

  return g_task_propagate_boolean (G_TASK (result), error);
}

static void
g_tls_connection_gnutls_dtls_handshake_async (GDtlsConnection       *conn,
                                              int                    io_priority,
                                              GCancellable          *cancellable,
                                              GAsyncReadyCallback    callback,
                                              gpointer               user_data)
{
  g_tls_connection_gnutls_handshake_async (G_TLS_CONNECTION (conn), io_priority,
                                           cancellable, callback, user_data);
}

static gboolean
g_tls_connection_gnutls_dtls_handshake_finish (GDtlsConnection       *conn,
                                               GAsyncResult          *result,
                                               GError               **error)
{
  return g_tls_connection_gnutls_handshake_finish (G_TLS_CONNECTION (conn),
                                                   result, error);
}

static gboolean
do_implicit_handshake (GTlsConnectionGnutls  *gnutls,
                       gint64                 timeout,
                       GCancellable          *cancellable,
                       GError               **error)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gint64 *thread_timeout = NULL;

  /* We have op_mutex */

  g_assert (priv->handshake_context == NULL);
  if (timeout != 0)
    {
      priv->handshake_context = g_main_context_new ();
      g_main_context_push_thread_default (priv->handshake_context);
    }
  else
    {
      priv->handshake_context = g_main_context_ref_thread_default ();
    }

  g_assert (priv->implicit_handshake == NULL);
  priv->implicit_handshake = g_task_new (gnutls, cancellable,
                                         timeout ? sync_handshake_thread_completed : NULL,
                                         NULL);
  g_task_set_source_tag (priv->implicit_handshake,
                         do_implicit_handshake);

  thread_timeout = g_new0 (gint64, 1);
  g_task_set_task_data (priv->implicit_handshake,
                        thread_timeout, g_free);

  begin_handshake (gnutls);

  if (timeout != 0)
    {
      GError *my_error = NULL;
      gboolean success;

      /* In the blocking case, run the handshake operation synchronously in
       * another thread, and delegate handling the timeout to that thread; it
       * should return G_IO_ERROR_TIMED_OUT iff (timeout > 0) and the operation
       * times out. If (timeout < 0) it should block indefinitely until the
       * operation is complete or errors. */
      *thread_timeout = timeout;

      g_mutex_unlock (&priv->op_mutex);

      g_task_set_return_on_cancel (priv->implicit_handshake, TRUE);
      g_task_run_in_thread (priv->implicit_handshake, handshake_thread);

      crank_sync_handshake_context (gnutls, cancellable);

      success = finish_handshake (gnutls,
                                  priv->implicit_handshake,
                                  &my_error);

      g_main_context_pop_thread_default (priv->handshake_context);
      g_clear_pointer (&priv->handshake_context, g_main_context_unref);
      g_clear_object (&priv->implicit_handshake);

      yield_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_HANDSHAKE);

      g_mutex_lock (&priv->op_mutex);

      if (my_error)
        g_propagate_error (error, my_error);
      return success;
    }
  else
    {
      /* In the non-blocking case, start the asynchronous handshake operation
       * and return EWOULDBLOCK to the caller, who will handle polling for
       * completion of the handshake and whatever operation they actually cared
       * about. Run the actual operation as blocking in its thread. */
      *thread_timeout = -1;  /* blocking */

      g_task_run_in_thread (priv->implicit_handshake,
                            async_handshake_thread);

      /* Intentionally not translated because this is not a fatal error to be
       * presented to the user, and to avoid this showing up in profiling. */
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK, "Operation would block");
      return FALSE;
    }
}

gssize
g_tls_connection_gnutls_read (GTlsConnectionGnutls  *gnutls,
                              void                  *buffer,
                              gsize                  count,
                              gint64                 timeout,
                              GCancellable          *cancellable,
                              GError               **error)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gssize ret;

  if (priv->app_data_buf && !priv->handshaking)
    {
      ret = MIN (count, priv->app_data_buf->len);
      memcpy (buffer, priv->app_data_buf->data, ret);
      if (ret == priv->app_data_buf->len)
        g_clear_pointer (&priv->app_data_buf, g_byte_array_unref);
      else
        g_byte_array_remove_range (priv->app_data_buf, 0, ret);
      return ret;
    }

 again:
  if (!claim_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_READ,
                 timeout, cancellable, error))
    return -1;

  BEGIN_GNUTLS_IO (gnutls, G_IO_IN, timeout, cancellable);
  ret = gnutls_record_recv (priv->session, buffer, count);
  END_GNUTLS_IO (gnutls, G_IO_IN, ret, _("Error reading data from TLS socket"), error);

  yield_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_READ);

  if (ret >= 0)
    return ret;
  else if (ret == GNUTLS_E_REHANDSHAKE)
    goto again;
  else
    return -1;
}

static gsize
input_vectors_from_gnutls_datum_t (GInputVector          *vectors,
                                   guint                  num_vectors,
                                   const gnutls_datum_t  *datum)
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

static gssize
g_tls_connection_gnutls_read_message (GTlsConnectionGnutls  *gnutls,
                                      GInputVector          *vectors,
                                      guint                  num_vectors,
                                      gint64                 timeout,
                                      GCancellable          *cancellable,
                                      GError               **error)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  guint i;
  gssize ret;
  gnutls_packet_t packet = { 0, };

  /* Copy data out of the app data buffer first. */
  if (priv->app_data_buf && !priv->handshaking)
    {
      ret = 0;

      for (i = 0; i < num_vectors; i++)
        {
          gsize count;
          GInputVector *vec = &vectors[i];

          count = MIN (vec->size, priv->app_data_buf->len);
          ret += count;

          memcpy (vec->buffer, priv->app_data_buf->data, count);
          if (count == priv->app_data_buf->len)
            g_clear_pointer (&priv->app_data_buf, g_byte_array_unref);
          else
            g_byte_array_remove_range (priv->app_data_buf, 0, count);
        }

      return ret;
    }

 again:
  if (!claim_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_READ,
                 timeout, cancellable, error))
    return -1;

  BEGIN_GNUTLS_IO (gnutls, G_IO_IN, timeout, cancellable);

  /* Receive the entire datagram (zero-copy). */
  ret = gnutls_record_recv_packet (priv->session, &packet);

  if (ret > 0)
    {
      gnutls_datum_t data = { 0, };

      gnutls_packet_get (packet, &data, NULL);
      ret = input_vectors_from_gnutls_datum_t (vectors, num_vectors, &data);
      gnutls_packet_deinit (packet);
    }

  END_GNUTLS_IO (gnutls, G_IO_IN, ret, _("Error reading data from TLS socket"), error);

  yield_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_READ);

  if (ret >= 0)
    return ret;
  else if (ret == GNUTLS_E_REHANDSHAKE)
    goto again;
  else
    return -1;
}

static gint
g_tls_connection_gnutls_receive_messages (GDatagramBased  *datagram_based,
                                          GInputMessage   *messages,
                                          guint            num_messages,
                                          gint             flags,
                                          gint64           timeout,
                                          GCancellable    *cancellable,
                                          GError         **error)
{
  GTlsConnectionGnutls *gnutls;
  guint i;
  GError *child_error = NULL;

  gnutls = G_TLS_CONNECTION_GNUTLS (datagram_based);

  if (flags != G_SOCKET_MSG_NONE)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                   _("Receive flags are not supported"));
      return -1;
    }

  for (i = 0; i < num_messages && child_error == NULL; i++)
    {
      GInputMessage *message = &messages[i];
      gssize n_bytes_read;

      n_bytes_read = g_tls_connection_gnutls_read_message (gnutls,
                                                           message->vectors,
                                                           message->num_vectors,
                                                           timeout,
                                                           cancellable,
                                                           &child_error);

      if (message->address != NULL)
        *message->address = NULL;
      message->flags = G_SOCKET_MSG_NONE;
      if (message->control_messages != NULL)
        *message->control_messages = NULL;
      message->num_control_messages = 0;

      if (n_bytes_read > 0)
        {
          message->bytes_received = n_bytes_read;
        }
      else if (n_bytes_read == 0)
        {
          /* EOS. */
          break;
        }
      else if (i > 0 &&
               (g_error_matches (child_error,
                                 G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK) ||
                g_error_matches (child_error,
                                 G_IO_ERROR, G_IO_ERROR_TIMED_OUT)))
        {
          /* Blocked or timed out after receiving some messages successfully. */
          g_clear_error (&child_error);
          break;
        }
      else
        {
          /* Error, including G_IO_ERROR_WOULD_BLOCK or G_IO_ERROR_TIMED_OUT on
           * the first message; or G_IO_ERROR_CANCELLED at any time. */
          break;
        }
    }

  if (child_error != NULL)
    {
      g_propagate_error (error, child_error);
      return -1;
    }

  return i;
}

gssize
g_tls_connection_gnutls_write (GTlsConnectionGnutls  *gnutls,
                               const void            *buffer,
                               gsize                  count,
                               gint64                 timeout,
                               GCancellable          *cancellable,
                               GError               **error)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gssize ret;

 again:
  if (!claim_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_WRITE,
                 timeout, cancellable, error))
    return -1;

  BEGIN_GNUTLS_IO (gnutls, G_IO_OUT, timeout, cancellable);
  ret = gnutls_record_send (priv->session, buffer, count);
  END_GNUTLS_IO (gnutls, G_IO_OUT, ret, _("Error writing data to TLS socket"), error);

  yield_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_WRITE);

  if (ret >= 0)
    return ret;
  else if (ret == GNUTLS_E_REHANDSHAKE)
    goto again;
  else
    return -1;
}

static gssize
g_tls_connection_gnutls_write_message (GTlsConnectionGnutls  *gnutls,
                                       GOutputVector         *vectors,
                                       guint                  num_vectors,
                                       gint64                 timeout,
                                       GCancellable          *cancellable,
                                       GError               **error)
{
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  gssize ret;
  guint i;
  gsize total_message_size;

 again:
  if (!claim_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_WRITE,
                 timeout, cancellable, error))
    return -1;

  /* Calculate the total message size and check it’s not too big. */
  for (i = 0, total_message_size = 0; i < num_vectors; i++)
    total_message_size += vectors[i].size;

  if (priv->base_socket != NULL &&
      gnutls_dtls_get_data_mtu (priv->session) < total_message_size)
    {
      char *message;
      guint mtu = gnutls_dtls_get_data_mtu (priv->session);

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

      goto done;
    }

  /* Queue up the data from all the vectors. */
  gnutls_record_cork (priv->session);

  for (i = 0; i < num_vectors; i++)
    {
      ret = gnutls_record_send (priv->session,
                                vectors[i].buffer, vectors[i].size);

      if (ret < 0 || ret < vectors[i].size)
        {
          /* Uncork to restore state, then bail. The peer will receive a
           * truncated datagram. */
          break;
        }
    }

  BEGIN_GNUTLS_IO (gnutls, G_IO_OUT, timeout, cancellable);
  ret = gnutls_record_uncork (priv->session, 0  /* flags */);
  END_GNUTLS_IO (gnutls, G_IO_OUT, ret, _("Error writing data to TLS socket"), error);

 done:
  yield_op (gnutls, G_TLS_CONNECTION_GNUTLS_OP_WRITE);

  if (ret >= 0)
    return ret;
  else if (ret == GNUTLS_E_REHANDSHAKE)
    goto again;
  else
    return -1;
}

static gint
g_tls_connection_gnutls_send_messages (GDatagramBased  *datagram_based,
                                       GOutputMessage  *messages,
                                       guint            num_messages,
                                       gint             flags,
                                       gint64           timeout,
                                       GCancellable    *cancellable,
                                       GError         **error)
{
  GTlsConnectionGnutls *gnutls;
  guint i;
  GError *child_error = NULL;

  gnutls = G_TLS_CONNECTION_GNUTLS (datagram_based);

  if (flags != G_SOCKET_MSG_NONE)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                   _("Send flags are not supported"));
      return -1;
    }

  for (i = 0; i < num_messages && child_error == NULL; i++)
    {
      GOutputMessage *message = &messages[i];
      gssize n_bytes_sent;

      n_bytes_sent = g_tls_connection_gnutls_write_message (gnutls,
                                                            message->vectors,
                                                            message->num_vectors,
                                                            timeout,
                                                            cancellable,
                                                            &child_error);

      if (n_bytes_sent >= 0)
        {
          message->bytes_sent = n_bytes_sent;
        }
      else if (i > 0 &&
               (g_error_matches (child_error,
                                 G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK) ||
                g_error_matches (child_error,
                                 G_IO_ERROR, G_IO_ERROR_TIMED_OUT)))
        {
          /* Blocked or timed out after sending some messages successfully. */
          g_clear_error (&child_error);
          break;
        }
      else
        {
          /* Error, including G_IO_ERROR_WOULD_BLOCK or G_IO_ERROR_TIMED_OUT
           * on the first message; or G_IO_ERROR_CANCELLED at any time. */
          break;
        }
    }

  if (child_error != NULL)
    {
      g_propagate_error (error, child_error);
      return -1;
    }

  return i;
}

static GInputStream  *
g_tls_connection_gnutls_get_input_stream (GIOStream *stream)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (stream);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  return priv->tls_istream;
}

static GOutputStream *
g_tls_connection_gnutls_get_output_stream (GIOStream *stream)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (stream);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  return priv->tls_ostream;
}

gboolean
g_tls_connection_gnutls_close_internal (GIOStream     *stream,
                                        GTlsDirection  direction,
                                        gint64         timeout,
                                        GCancellable  *cancellable,
                                        GError       **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (stream);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GTlsConnectionGnutlsOp op;
  gboolean success = TRUE;
  int ret = 0;
  GError *gnutls_error = NULL, *stream_error = NULL;

  /* This can be called from g_io_stream_close(), g_input_stream_close(),
   * g_output_stream_close() or g_tls_connection_close(). In all cases, we only
   * do the gnutls_bye() for writing. The difference is how we set the flags on
   * this class and how the underlying stream is closed.
   */

  g_return_val_if_fail (direction != G_TLS_DIRECTION_NONE, FALSE);

  if (direction == G_TLS_DIRECTION_BOTH)
    op = G_TLS_CONNECTION_GNUTLS_OP_CLOSE_BOTH;
  else if (direction == G_TLS_DIRECTION_READ)
    op = G_TLS_CONNECTION_GNUTLS_OP_CLOSE_READ;
  else
    op = G_TLS_CONNECTION_GNUTLS_OP_CLOSE_WRITE;

  if (!claim_op (gnutls, op, timeout, cancellable, error))
    return FALSE;

  if (priv->ever_handshaked && !priv->write_closed &&
      direction & G_TLS_DIRECTION_WRITE)
    {
      BEGIN_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, timeout, cancellable);
      ret = gnutls_bye (priv->session, GNUTLS_SHUT_WR);
      END_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, ret,
                     _("Error performing TLS close"), &gnutls_error);

      priv->write_closed = TRUE;
    }

  if (!priv->read_closed && direction & G_TLS_DIRECTION_READ)
    priv->read_closed = TRUE;

  /* Close the underlying streams. Do this even if the gnutls_bye() call failed,
   * as the parent GIOStream will have set its internal closed flag and hence
   * this implementation will never be called again. */
  if (priv->base_io_stream != NULL)
    {
      if (direction == G_TLS_DIRECTION_BOTH)
        success = g_io_stream_close (priv->base_io_stream,
                                     cancellable, &stream_error);
      else if (direction & G_TLS_DIRECTION_READ)
        success = g_input_stream_close (g_io_stream_get_input_stream (priv->base_io_stream),
                                        cancellable, &stream_error);
      else if (direction & G_TLS_DIRECTION_WRITE)
        success = g_output_stream_close (g_io_stream_get_output_stream (priv->base_io_stream),
                                         cancellable, &stream_error);
    }
  else if (g_tls_connection_gnutls_is_dtls (gnutls))
    {
      /* We do not close underlying #GDatagramBaseds. There is no
       * g_datagram_based_close() method since different datagram-based
       * protocols vary wildly in how they close. */
      success = TRUE;
    }
  else
    {
      g_assert_not_reached ();
    }

  yield_op (gnutls, op);

  /* Propagate errors. */
  if (ret != 0)
    {
      g_propagate_error (error, gnutls_error);
      g_clear_error (&stream_error);
    }
  else if (!success)
    {
      g_propagate_error (error, stream_error);
      g_clear_error (&gnutls_error);
    }

  return success && (ret == 0);
}

static gboolean
g_tls_connection_gnutls_close (GIOStream     *stream,
                               GCancellable  *cancellable,
                               GError       **error)
{
  return g_tls_connection_gnutls_close_internal (stream,
                                                 G_TLS_DIRECTION_BOTH,
                                                 -1,  /* blocking */
                                                 cancellable, error);
}

static gboolean
g_tls_connection_gnutls_dtls_shutdown (GDtlsConnection  *conn,
                                       gboolean          shutdown_read,
                                       gboolean          shutdown_write,
                                       GCancellable     *cancellable,
                                       GError          **error)
{
  GTlsDirection direction = G_TLS_DIRECTION_NONE;

  if (shutdown_read)
    direction |= G_TLS_DIRECTION_READ;
  if (shutdown_write)
    direction |= G_TLS_DIRECTION_WRITE;

  return g_tls_connection_gnutls_close_internal (G_IO_STREAM (conn),
                                                 direction,
                                                 -1,  /* blocking */
                                                 cancellable, error);
}

/* We do async close as synchronous-in-a-thread so we don't need to
 * implement G_IO_IN/G_IO_OUT flip-flopping just for this one case
 * (since handshakes are also done synchronously now).
 */
static void
close_thread (GTask        *task,
              gpointer      object,
              gpointer      task_data,
              GCancellable *cancellable)
{
  GIOStream *stream = object;
  GTlsDirection direction;
  GError *error = NULL;

  direction = GPOINTER_TO_INT (g_task_get_task_data (task));

  if (!g_tls_connection_gnutls_close_internal (stream, direction,
                                               -1,  /* blocking */
                                               cancellable, &error))
    g_task_return_error (task, error);
  else
    g_task_return_boolean (task, TRUE);
}

static void
g_tls_connection_gnutls_close_internal_async (GIOStream           *stream,
                                              GTlsDirection        direction,
                                              int                  io_priority,
                                              GCancellable        *cancellable,
                                              GAsyncReadyCallback  callback,
                                              gpointer             user_data)
{
  GTask *task;

  task = g_task_new (stream, cancellable, callback, user_data);
  g_task_set_source_tag (task, g_tls_connection_gnutls_close_internal_async);
  g_task_set_priority (task, io_priority);
  g_task_set_task_data (task, GINT_TO_POINTER (direction), NULL);
  g_task_run_in_thread (task, close_thread);
  g_object_unref (task);
}

static void
g_tls_connection_gnutls_close_async (GIOStream           *stream,
                                     int                  io_priority,
                                     GCancellable        *cancellable,
                                     GAsyncReadyCallback  callback,
                                     gpointer             user_data)
{
  g_tls_connection_gnutls_close_internal_async (stream, G_TLS_DIRECTION_BOTH,
                                                io_priority, cancellable,
                                                callback, user_data);
}

static gboolean
g_tls_connection_gnutls_close_finish (GIOStream           *stream,
                                      GAsyncResult        *result,
                                      GError             **error)
{
  g_return_val_if_fail (g_task_is_valid (result, stream), FALSE);

  return g_task_propagate_boolean (G_TASK (result), error);
}

static void
g_tls_connection_gnutls_dtls_shutdown_async (GDtlsConnection     *conn,
                                             gboolean             shutdown_read,
                                             gboolean             shutdown_write,
                                             int                  io_priority,
                                             GCancellable        *cancellable,
                                             GAsyncReadyCallback  callback,
                                             gpointer             user_data)
{
  GTlsDirection direction = G_TLS_DIRECTION_NONE;

  if (shutdown_read)
    direction |= G_TLS_DIRECTION_READ;
  if (shutdown_write)
    direction |= G_TLS_DIRECTION_WRITE;

  g_tls_connection_gnutls_close_internal_async (G_IO_STREAM (conn), direction,
                                                io_priority, cancellable,
                                                callback, user_data);
}

static gboolean
g_tls_connection_gnutls_dtls_shutdown_finish (GDtlsConnection  *conn,
                                              GAsyncResult     *result,
                                              GError          **error)
{
  g_return_val_if_fail (g_task_is_valid (result, conn), FALSE);

  return g_task_propagate_boolean (G_TASK (result), error);
}

#if GLIB_CHECK_VERSION(2, 60, 0)
static void
g_tls_connection_gnutls_dtls_set_advertised_protocols (GDtlsConnection     *conn,
                                                       const gchar * const *protocols)
{
  g_object_set (conn, "advertised-protocols", protocols, NULL);
}

const gchar *
g_tls_connection_gnutls_dtls_get_negotiated_protocol (GDtlsConnection *conn)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (conn);
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);

  return priv->negotiated_protocol;
}
#endif

static void
g_tls_connection_gnutls_class_init (GTlsConnectionGnutlsClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsConnectionClass *connection_class = G_TLS_CONNECTION_CLASS (klass);
  GIOStreamClass *iostream_class = G_IO_STREAM_CLASS (klass);

  gobject_class->get_property = g_tls_connection_gnutls_get_property;
  gobject_class->set_property = g_tls_connection_gnutls_set_property;
  gobject_class->finalize     = g_tls_connection_gnutls_finalize;

  connection_class->handshake        = g_tls_connection_gnutls_handshake;
  connection_class->handshake_async  = g_tls_connection_gnutls_handshake_async;
  connection_class->handshake_finish = g_tls_connection_gnutls_handshake_finish;

  iostream_class->get_input_stream  = g_tls_connection_gnutls_get_input_stream;
  iostream_class->get_output_stream = g_tls_connection_gnutls_get_output_stream;
  iostream_class->close_fn          = g_tls_connection_gnutls_close;
  iostream_class->close_async       = g_tls_connection_gnutls_close_async;
  iostream_class->close_finish      = g_tls_connection_gnutls_close_finish;

  /* For GTlsConnection and GDtlsConnection: */
  g_object_class_override_property (gobject_class, PROP_BASE_IO_STREAM, "base-io-stream");
  g_object_class_override_property (gobject_class, PROP_BASE_SOCKET, "base-socket");
  g_object_class_override_property (gobject_class, PROP_REQUIRE_CLOSE_NOTIFY, "require-close-notify");
  g_object_class_override_property (gobject_class, PROP_REHANDSHAKE_MODE, "rehandshake-mode");
  g_object_class_override_property (gobject_class, PROP_USE_SYSTEM_CERTDB, "use-system-certdb");
  g_object_class_override_property (gobject_class, PROP_DATABASE, "database");
  g_object_class_override_property (gobject_class, PROP_CERTIFICATE, "certificate");
  g_object_class_override_property (gobject_class, PROP_INTERACTION, "interaction");
  g_object_class_override_property (gobject_class, PROP_PEER_CERTIFICATE, "peer-certificate");
  g_object_class_override_property (gobject_class, PROP_PEER_CERTIFICATE_ERRORS, "peer-certificate-errors");
#if GLIB_CHECK_VERSION(2, 60, 0)
  g_object_class_override_property (gobject_class, PROP_ADVERTISED_PROTOCOLS, "advertised-protocols");
  g_object_class_override_property (gobject_class, PROP_NEGOTIATED_PROTOCOL, "negotiated-protocol");
#endif
}

static void
g_tls_connection_gnutls_initable_iface_init (GInitableIface *iface)
{
  iface->init = g_tls_connection_gnutls_initable_init;
}

static void
g_tls_connection_gnutls_dtls_connection_iface_init (GDtlsConnectionInterface *iface)
{
  iface->handshake = g_tls_connection_gnutls_dtls_handshake;
  iface->handshake_async = g_tls_connection_gnutls_dtls_handshake_async;
  iface->handshake_finish = g_tls_connection_gnutls_dtls_handshake_finish;
  iface->shutdown = g_tls_connection_gnutls_dtls_shutdown;
  iface->shutdown_async = g_tls_connection_gnutls_dtls_shutdown_async;
  iface->shutdown_finish = g_tls_connection_gnutls_dtls_shutdown_finish;
#if GLIB_CHECK_VERSION(2, 60, 0)
  iface->set_advertised_protocols = g_tls_connection_gnutls_dtls_set_advertised_protocols;
  iface->get_negotiated_protocol = g_tls_connection_gnutls_dtls_get_negotiated_protocol;
#endif
}

static void
g_tls_connection_gnutls_datagram_based_iface_init (GDatagramBasedInterface *iface)
{
  iface->receive_messages = g_tls_connection_gnutls_receive_messages;
  iface->send_messages = g_tls_connection_gnutls_send_messages;
  iface->create_source = g_tls_connection_gnutls_dtls_create_source;
  iface->condition_check = g_tls_connection_gnutls_condition_check;
  iface->condition_wait = g_tls_connection_gnutls_condition_wait;
}

gboolean
g_tls_connection_gnutls_request_certificate (GTlsConnectionGnutls  *gnutls,
                                             GError               **error)
{
  GTlsInteractionResult res = G_TLS_INTERACTION_UNHANDLED;
  GTlsConnectionGnutlsPrivate *priv = g_tls_connection_gnutls_get_instance_private (gnutls);
  GTlsInteraction *interaction;
  GTlsConnection *conn;

  g_return_val_if_fail (G_IS_TLS_CONNECTION_GNUTLS (gnutls), FALSE);

  conn = G_TLS_CONNECTION (gnutls);

  interaction = g_tls_connection_get_interaction (conn);
  if (!interaction)
    return FALSE;

  res = g_tls_interaction_invoke_request_certificate (interaction, conn, 0,
                                                      priv->read_cancellable, error);
  return res != G_TLS_INTERACTION_FAILED;
}

void
GTLS_DEBUG (gpointer    gnutls,
            const char *message,
            ...)
{
  char *result = NULL;
  int ret;

  g_assert (G_IS_TLS_CONNECTION (gnutls));

  va_list args;
  va_start (args, message);

  ret = g_vasprintf (&result, message, args);
  g_assert (ret > 0);

  if (G_IS_TLS_CLIENT_CONNECTION (gnutls))
    g_printf ("CLIENT %p: ", gnutls);
  else if (G_IS_TLS_SERVER_CONNECTION (gnutls))
    g_printf ("SERVER %p: ", gnutls);
  else
    g_assert_not_reached ();

  g_printf ("%s\n", result);

  fflush (stdout);

  g_free (result);
  va_end (args);
}
