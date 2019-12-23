/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2009-2011 Red Hat, Inc
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

#include <errno.h>

#include "gtlsconnection-base.h"
#include "gtlsinputstream.h"
#include "gtlslog.h"
#include "gtlsoperationsthread-base.h"
#include "gtlsoutputstream.h"

#include <glib/gi18n-lib.h>
#include <glib/gprintf.h>

/*
 * GTlsConnectionBase is the base abstract implementation of TLS and DTLS
 * support, for both the client and server side of a connection. The choice
 * between TLS and DTLS is made by setting the base-io-stream or
 * base-socket properties — exactly one of them must be set at
 * construction time.
 *
 * Client- and server-specific code is in the client and server concrete
 * subclasses, although the line about where code is put is a little blurry,
 * and there are various places in GTlsConnectionBase which check
 * G_IS_TLS_CLIENT_CONNECTION(self) to switch to a client-only code path.
 *
 * This abstract class implements a lot of interfaces:
 *  • Derived from GTlsConnection (itself from GIOStream), for TLS and streaming
 *    communications.
 *  • Implements GDtlsConnection and GDatagramBased, for DTLS and datagram
 *    communications.
 *  • Implements GInitable for failable initialization.
 */

typedef struct
{
  /* When operating in stream mode, as a GTlsConnection. These are
   * mutually-exclusive with base_socket. There are two different
   * GIOStreams here: (a) base_io_stream and (b) the GTlsConnection
   * itself. base_io_stream is the GIOStream used to create the GTlsConnection,
   * and corresponds to the GTlsConnection::base-io-stream property.
   * base_istream and base_ostream are the GInputStream and GOutputStream,
   * respectively, of base_io_stream. These are for the underlying sockets that
   * don't know about TLS.
   *
   * Then the GTlsConnection also has tls_istream and tls_ostream, which
   * wrap the aforementioned base streams with a TLS session.
   *
   * When operating in datagram mode, none of these are used.
   */
  GIOStream             *base_io_stream;
  GPollableInputStream  *base_istream;
  GPollableOutputStream *base_ostream;
  GInputStream          *tls_istream;
  GOutputStream         *tls_ostream;

  /* When operating in datagram mode, as a GDtlsConnection, the
   * GTlsConnection is itself the DTLS GDatagramBased. It uses base_socket
   * for the underlying I/O. It is mutually-exclusive with base_io_stream and
   * the other streams.
   */
  GDatagramBased        *base_socket;

  GTlsDatabase          *database;
  GTlsInteraction       *interaction;

  GTlsCertificate       *certificate;
  GTlsCertificate       *peer_certificate;
  GTlsCertificateFlags   peer_certificate_errors;

  gboolean               require_close_notify;
  GTlsRehandshakeMode    rehandshake_mode;

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
   * for async_handshake_thread_completed() to run, because it's
   * possible that its main loop is being blocked by a synchronous op
   * which is waiting for handshaking to become FALSE...
   *
   * started_handshake indicates that the current handshake attempt
   * got at least as far as sending the first handshake packet (and so
   * any error should be copied to handshake_error and returned on all
   * future operations). ever_handshaked indicates that TLS has been
   * successfully negotiated at some point.
   */
  /* FIXME: remove a few of these */
  gboolean       need_handshake;
  gboolean       need_finish_handshake;
  gboolean       started_handshake;
  gboolean       handshaking;
  gboolean       ever_handshaked;
  gboolean       peer_certificate_accepted;
  GTask         *async_implicit_handshake;
  GError        *handshake_error;

  /* read_closed means the read direction has closed; write_closed similarly.
   * If (and only if) both are set, the entire GTlsConnection is closed. */
  gboolean       read_closing, read_closed;
  gboolean       write_closing, write_closed;

  gboolean       reading;
  gboolean       writing;

  gboolean       successful_posthandshake_op;

  gboolean       is_system_certdb;
  gboolean       database_is_unset;

  GMutex         op_mutex;
  GCancellable  *waiting_for_op;

  gchar        **advertised_protocols;
  gchar         *negotiated_protocol;

  GTlsOperationsThreadBase *thread;
} GTlsConnectionBasePrivate;

static void g_tls_connection_base_dtls_connection_iface_init (GDtlsConnectionInterface *iface);

static void g_tls_connection_base_datagram_based_iface_init  (GDatagramBasedInterface  *iface);

static void g_tls_connection_base_initable_iface_init (GInitableIface *iface);

static gboolean do_implicit_handshake (GTlsConnectionBase  *tls,
                                       gint64               timeout,
                                       GCancellable        *cancellable,
                                       GError             **error);

static gboolean finish_handshake (GTlsConnectionBase  *tls,
                                  gboolean             success,
                                  GError             **error);

static void g_tls_connection_base_handshake_async (GTlsConnection      *conn,
                                                   int                  io_priority,
                                                   GCancellable        *cancellable,
                                                   GAsyncReadyCallback  callback,
                                                   gpointer             user_data);

static gboolean g_tls_connection_base_handshake (GTlsConnection   *conn,
                                                 GCancellable     *cancellable,
                                                 GError          **error);

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (GTlsConnectionBase, g_tls_connection_base, G_TYPE_TLS_CONNECTION,
                                  G_ADD_PRIVATE (GTlsConnectionBase);
                                  G_IMPLEMENT_INTERFACE (G_TYPE_DATAGRAM_BASED,
                                                         g_tls_connection_base_datagram_based_iface_init);
                                  G_IMPLEMENT_INTERFACE (G_TYPE_DTLS_CONNECTION,
                                                         g_tls_connection_base_dtls_connection_iface_init);
                                  G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                         g_tls_connection_base_initable_iface_init);
                                  );


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
  PROP_ADVERTISED_PROTOCOLS,
  PROP_NEGOTIATED_PROTOCOL,
};

gboolean
g_tls_connection_base_is_dtls (GTlsConnectionBase *tls)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);

  return priv->base_socket != NULL;
}

static void
g_tls_connection_base_init (GTlsConnectionBase *tls)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);

  priv->need_handshake = TRUE;
  priv->database_is_unset = TRUE;
  priv->is_system_certdb = TRUE;

  g_mutex_init (&priv->op_mutex);

  priv->waiting_for_op = g_cancellable_new ();
}

static gboolean
g_tls_connection_base_initable_init (GInitable    *initable,
                                     GCancellable *cancellable,
                                     GError       **error)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (initable);
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);

  priv->thread = G_TLS_CONNECTION_BASE_GET_CLASS (tls)->create_op_thread (tls);
  if (!priv->thread)
    return FALSE;

  if (priv->certificate)
    g_tls_operations_thread_base_set_own_certificate (priv->thread, priv->certificate);

  if (priv->interaction)
    g_tls_operations_thread_base_set_interaction (priv->thread, priv->interaction);

  return TRUE;
}

static void
g_tls_connection_base_finalize (GObject *object)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (object);
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);

  g_clear_object (&priv->thread);

  g_clear_object (&priv->base_io_stream);
  g_clear_object (&priv->base_socket);

  g_clear_object (&priv->tls_istream);
  g_clear_object (&priv->tls_ostream);

  g_clear_object (&priv->database);
  g_clear_object (&priv->certificate);
  g_clear_object (&priv->peer_certificate);

  g_clear_object (&priv->interaction);

  /* This must always be NULL at this point, as it holds a reference to @tls as
   * its source object. However, we clear it anyway just in case this changes
   * in future. */
  g_clear_object (&priv->async_implicit_handshake);

  g_clear_error (&priv->handshake_error);

  g_clear_object (&priv->waiting_for_op);
  g_mutex_clear (&priv->op_mutex);

  g_clear_pointer (&priv->advertised_protocols, g_strfreev);
  g_clear_pointer (&priv->negotiated_protocol, g_free);

  G_OBJECT_CLASS (g_tls_connection_base_parent_class)->finalize (object);
}

static void
g_tls_connection_base_get_property (GObject    *object,
                                    guint       prop_id,
                                    GValue     *value,
                                    GParamSpec *pspec)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (object);
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);
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

    case PROP_ADVERTISED_PROTOCOLS:
      g_value_set_boxed (value, priv->advertised_protocols);
      break;

    case PROP_NEGOTIATED_PROTOCOL:
      g_value_set_string (value, priv->negotiated_protocol);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_connection_base_set_property (GObject      *object,
                                    guint         prop_id,
                                    const GValue *value,
                                    GParamSpec   *pspec)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (object);
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);
  GInputStream *istream;
  GOutputStream *ostream;
  gboolean system_certdb;
  GTlsBackend *backend;

  switch (prop_id)
    {
    case PROP_BASE_IO_STREAM:
      g_assert (!g_value_get_object (value) || !priv->base_socket);

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
        {
          priv->base_istream = G_POLLABLE_INPUT_STREAM (istream);
          priv->tls_istream = g_tls_input_stream_new (tls);
        }
      if (G_IS_POLLABLE_OUTPUT_STREAM (ostream) &&
          g_pollable_output_stream_can_poll (G_POLLABLE_OUTPUT_STREAM (ostream)))
        {
          priv->base_ostream = G_POLLABLE_OUTPUT_STREAM (ostream);
          priv->tls_ostream = g_tls_output_stream_new (tls);
        }
      break;

    case PROP_BASE_SOCKET:
      g_assert (!g_value_get_object (value) || !priv->base_io_stream);

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

      if (priv->thread)
        g_tls_operations_thread_base_set_own_certificate (priv->thread,
                                                          priv->certificate);
      break;

    case PROP_INTERACTION:
      g_clear_object (&priv->interaction);
      priv->interaction = g_value_dup_object (value);

      if (priv->thread)
        g_tls_operations_thread_base_set_interaction (priv->thread,
                                                      priv->interaction);
      break;

    case PROP_ADVERTISED_PROTOCOLS:
      g_clear_pointer (&priv->advertised_protocols, g_strfreev);
      priv->advertised_protocols = g_value_dup_boxed (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

typedef enum {
  G_TLS_CONNECTION_BASE_OP_HANDSHAKE,
  G_TLS_CONNECTION_BASE_OP_READ,
  G_TLS_CONNECTION_BASE_OP_WRITE,
  G_TLS_CONNECTION_BASE_OP_CLOSE_READ,
  G_TLS_CONNECTION_BASE_OP_CLOSE_WRITE,
  G_TLS_CONNECTION_BASE_OP_CLOSE_BOTH,
} GTlsConnectionBaseOp;

static const gchar *
op_to_string (GTlsConnectionBaseOp op)
{
  switch (op)
    {
    case G_TLS_CONNECTION_BASE_OP_HANDSHAKE:
      return "OP_HANDSHAKE";
    case G_TLS_CONNECTION_BASE_OP_READ:
      return "OP_READ";
    case G_TLS_CONNECTION_BASE_OP_WRITE:
      return "OP_WRITE";
    case G_TLS_CONNECTION_BASE_OP_CLOSE_READ:
      return "OP_CLOSE_READ";
    case G_TLS_CONNECTION_BASE_OP_CLOSE_WRITE:
      return "OP_CLOSE_WRITE";
    case G_TLS_CONNECTION_BASE_OP_CLOSE_BOTH:
      return "OP_CLOSE_BOTH";
    }
  g_assert_not_reached ();
}

static const gchar *
status_to_string (GTlsConnectionBaseStatus st)
{
  switch (st)
    {
    case G_TLS_CONNECTION_BASE_OK:
      return "BASE_OK";
    case G_TLS_CONNECTION_BASE_WOULD_BLOCK:
      return "WOULD_BLOCK";
    case G_TLS_CONNECTION_BASE_TIMED_OUT:
      return "TIMED_OUT";
    case G_TLS_CONNECTION_BASE_REHANDSHAKE:
      return "REHANDSHAKE";
    case G_TLS_CONNECTION_BASE_TRY_AGAIN:
      return "TRY_AGAIN";
    case G_TLS_CONNECTION_BASE_ERROR:
      return "ERROR";
    }
  g_assert_not_reached ();
}

static gboolean
claim_op (GTlsConnectionBase    *tls,
          GTlsConnectionBaseOp   op,
          gint64                 timeout,
          GCancellable          *cancellable,
          GError               **error)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);

  g_tls_log_debug (tls, "claiming operation %s", op_to_string (op));

 try_again:
  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    {
      g_tls_log_debug (tls, "claim_op failed: cancelled");
      return FALSE;
    }

  g_mutex_lock (&priv->op_mutex);

  if (((op == G_TLS_CONNECTION_BASE_OP_HANDSHAKE ||
        op == G_TLS_CONNECTION_BASE_OP_READ) &&
       (priv->read_closing || priv->read_closed)) ||
      ((op == G_TLS_CONNECTION_BASE_OP_HANDSHAKE ||
        op == G_TLS_CONNECTION_BASE_OP_WRITE) &&
       (priv->write_closing || priv->write_closed)))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CLOSED,
                           _("Connection is closed"));
      g_mutex_unlock (&priv->op_mutex);
      g_tls_log_debug (tls, "claim_op failed: connection is closed");
      return FALSE;
    }

  if (priv->handshake_error &&
      op != G_TLS_CONNECTION_BASE_OP_CLOSE_BOTH &&
      op != G_TLS_CONNECTION_BASE_OP_CLOSE_READ &&
      op != G_TLS_CONNECTION_BASE_OP_CLOSE_WRITE)
    {
      if (error)
        *error = g_error_copy (priv->handshake_error);
      g_mutex_unlock (&priv->op_mutex);
      g_tls_log_debug (tls, "claim_op failed: %s", error ? (*error)->message : "no error");
      return FALSE;
    }

  if (op != G_TLS_CONNECTION_BASE_OP_HANDSHAKE)
    {
      if (op != G_TLS_CONNECTION_BASE_OP_CLOSE_BOTH &&
          op != G_TLS_CONNECTION_BASE_OP_CLOSE_READ &&
          op != G_TLS_CONNECTION_BASE_OP_CLOSE_WRITE &&
          priv->need_handshake && !priv->handshaking)
        {
          priv->handshaking = TRUE;
          if (!do_implicit_handshake (tls, timeout, cancellable, error))
            {
              g_mutex_unlock (&priv->op_mutex);
              g_tls_log_debug (tls, "claim_op failed: do_implicit_handshake failed");
              return FALSE;
            }
        }

      /* Performed async implicit handshake? */
      if (priv->need_finish_handshake &&
          priv->async_implicit_handshake)
        {
          GError *my_error = NULL;
          gboolean success;

          priv->need_finish_handshake = FALSE;

          g_mutex_unlock (&priv->op_mutex);

          success = g_task_propagate_boolean (priv->async_implicit_handshake, &my_error);
          g_clear_object (&priv->async_implicit_handshake);

          /* If we already have an error, ignore further errors. */
          success = finish_handshake (tls, success, my_error ? NULL : &my_error);

          g_mutex_lock (&priv->op_mutex);

          if (op != G_TLS_CONNECTION_BASE_OP_CLOSE_BOTH &&
              op != G_TLS_CONNECTION_BASE_OP_CLOSE_READ &&
              op != G_TLS_CONNECTION_BASE_OP_CLOSE_WRITE &&
              (!success || g_cancellable_set_error_if_cancelled (cancellable, &my_error)))
            {
              g_propagate_error (error, my_error);
              g_mutex_unlock (&priv->op_mutex);
              g_tls_log_debug (tls, "claim_op failed: finish_handshake failed");
              return FALSE;
            }

          g_clear_error (&my_error);
        }
    }

  /* FIXME: store a GThread member to bring back this check */
#if 0
  if (priv->handshaking &&
      op != G_TLS_CONNECTION_BASE_OP_HANDSHAKE &&
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
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK, _("Cannot perform blocking operation during TLS handshake"));
      g_mutex_unlock (&priv->op_mutex);
      g_tls_log_debug (tls, "claim_op failed: %s", (*error)->message);
      return FALSE;
    }
#endif

  if ((op != G_TLS_CONNECTION_BASE_OP_WRITE && priv->reading) ||
      (op != G_TLS_CONNECTION_BASE_OP_READ && priv->writing) ||
      (op != G_TLS_CONNECTION_BASE_OP_HANDSHAKE && priv->handshaking))
    {
      GPollFD fds[2];
      int nfds;
      gint64 start_time;
      gint result = 1; /* if the loop is never entered, it's as if we cancelled early */

      g_cancellable_reset (priv->waiting_for_op);

      g_mutex_unlock (&priv->op_mutex);

      if (timeout == 0)
        {
          /* Intentionally not translated because this is not a fatal error to be
           * presented to the user, and to avoid this showing up in profiling.
           */
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK, "Operation would block");
          g_tls_log_debug (tls, "claim_op failed: %s", (*error)->message);
          return FALSE;
        }

      g_cancellable_make_pollfd (priv->waiting_for_op, &fds[0]);
      if (g_cancellable_make_pollfd (cancellable, &fds[1]))
        nfds = 2;
      else
        nfds = 1;

      /* Convert from microseconds to milliseconds. */
      if (timeout != -1)
        timeout /= 1000;

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
          g_tls_log_debug (tls, "claim_op failed: %s", (*error)->message);
          return FALSE;
        }

      goto try_again;
    }

  if (op == G_TLS_CONNECTION_BASE_OP_HANDSHAKE)
    priv->handshaking = TRUE;
  if (op == G_TLS_CONNECTION_BASE_OP_CLOSE_BOTH ||
      op == G_TLS_CONNECTION_BASE_OP_CLOSE_READ)
    priv->read_closing = TRUE;
  if (op == G_TLS_CONNECTION_BASE_OP_CLOSE_BOTH ||
      op == G_TLS_CONNECTION_BASE_OP_CLOSE_WRITE)
    priv->write_closing = TRUE;

  if (op != G_TLS_CONNECTION_BASE_OP_WRITE)
    priv->reading = TRUE;
  if (op != G_TLS_CONNECTION_BASE_OP_READ)
    priv->writing = TRUE;

  g_mutex_unlock (&priv->op_mutex);
  g_tls_log_debug (tls, "claiming operation %s succeeded", op_to_string (op));
  return TRUE;
}

static void
yield_op (GTlsConnectionBase       *tls,
          GTlsConnectionBaseOp      op,
          GTlsConnectionBaseStatus  status)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);

  g_tls_log_debug (tls, "yielding operation %s", op_to_string (op));

  g_mutex_lock (&priv->op_mutex);

  if (op == G_TLS_CONNECTION_BASE_OP_HANDSHAKE)
    priv->handshaking = FALSE;
  else if (status == G_TLS_CONNECTION_BASE_REHANDSHAKE && !priv->handshaking)
    priv->need_handshake = TRUE;

  if (op == G_TLS_CONNECTION_BASE_OP_CLOSE_BOTH ||
      op == G_TLS_CONNECTION_BASE_OP_CLOSE_READ)
    priv->read_closing = FALSE;
  if (op == G_TLS_CONNECTION_BASE_OP_CLOSE_BOTH ||
      op == G_TLS_CONNECTION_BASE_OP_CLOSE_WRITE)
    priv->write_closing = FALSE;

  if (op != G_TLS_CONNECTION_BASE_OP_WRITE)
    priv->reading = FALSE;
  if (op != G_TLS_CONNECTION_BASE_OP_READ)
    priv->writing = FALSE;

  g_cancellable_cancel (priv->waiting_for_op);
  g_mutex_unlock (&priv->op_mutex);
}

/* FIXME: removable? It's only here for OpenSSL GTlsBio */
void
g_tls_connection_base_push_io (GTlsConnectionBase *tls,
                               GIOCondition        direction,
                               gint64              timeout,
                               GCancellable       *cancellable)
{
  g_assert (direction & (G_IO_IN | G_IO_OUT));
  g_return_if_fail (G_IS_TLS_CONNECTION_BASE (tls));

  if (G_TLS_CONNECTION_BASE_GET_CLASS (tls)->push_io)
    {
      G_TLS_CONNECTION_BASE_GET_CLASS (tls)->push_io (tls, direction,
                                                      timeout, cancellable);
    }
}

/* FIXME: rename, if push_io is removed? */
/* FIXME: this is almost certainly inappropriate because it is called on the
 * op thread. It needs to move to the op thread class.
 */
static GTlsConnectionBaseStatus
g_tls_connection_base_real_pop_io (GTlsConnectionBase  *tls,
                                   GIOCondition         direction,
                                   gboolean             success,
                                   GError              *op_error,
                                   GError             **error)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);
  GError *my_error = NULL;

  /* This function MAY or MAY NOT set error when it fails! */

  if (success)
    return G_TLS_CONNECTION_BASE_OK;

  g_assert (op_error);
  g_propagate_error (&my_error, op_error);

  if (g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
    {
      g_propagate_error (error, my_error);
      return G_TLS_CONNECTION_BASE_WOULD_BLOCK;
    }

  if (g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT))
    {
      g_propagate_error (error, my_error);
      return G_TLS_CONNECTION_BASE_TIMED_OUT;
    }

  if (g_tls_operations_thread_base_get_is_missing_requested_client_certificate (priv->thread) &&
      !priv->successful_posthandshake_op)
    {
      GError *interaction_error;

      g_assert (G_IS_TLS_CLIENT_CONNECTION (tls));

      interaction_error = g_tls_operations_thread_base_take_interaction_error (priv->thread);

      /* Probably the server requires a client certificate, but we failed to
       * provide one. With TLS 1.3 the server is no longer able to tell us
       * this, so we just have to guess. If there is an error from the TLS
       * interaction (request for user certificate), we provide that. Otherwise,
       * guess that G_TLS_ERROR_CERTIFICATE_REQUIRED is probably appropriate.
       * This could be wrong, but only applies to the small minority of
       * connections where a client cert is requested but not provided, and then
       * then only if the client has never successfully read or written.
       */
      if (interaction_error)
        {
          g_propagate_error (error, interaction_error);
        }
      else
        {
          g_clear_error (error);
          g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED,
                               _("Server required TLS certificate"));
        }
      g_clear_error (&my_error);
    }
  else if (my_error)
    {
      g_propagate_error (error, my_error);
    }

  return G_TLS_CONNECTION_BASE_ERROR;
}

GTlsConnectionBaseStatus
g_tls_connection_base_pop_io (GTlsConnectionBase  *tls,
                              GIOCondition         direction,
                              gboolean             success,
                              GError              *op_error,
                              GError             **error)
{
  g_assert (direction & (G_IO_IN | G_IO_OUT));
  g_assert (!error || !*error);
  g_return_val_if_fail (G_IS_TLS_CONNECTION_BASE (tls), G_TLS_CONNECTION_BASE_ERROR);

  return G_TLS_CONNECTION_BASE_GET_CLASS (tls)->pop_io (tls, direction,
                                                        success, op_error, error);
}

/* Checks whether the underlying base stream or GDatagramBased meets
 * @condition.
 */
gboolean
g_tls_connection_base_base_check (GTlsConnectionBase *tls,
                                  GIOCondition        condition)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);

  if (g_tls_connection_base_is_dtls (tls))
    return g_datagram_based_condition_check (priv->base_socket, condition);

  if (condition & G_IO_IN)
    return g_pollable_input_stream_is_readable (priv->base_istream);

  if (condition & G_IO_OUT)
    return g_pollable_output_stream_is_writable (priv->base_ostream);

  g_assert_not_reached ();
  return FALSE;
}

/* Checks whether the (D)TLS stream meets @condition; not the underlying base
 * stream or GDatagramBased.
 */
gboolean
g_tls_connection_base_check (GTlsConnectionBase  *tls,
                             GIOCondition         condition)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);

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
  return g_tls_connection_base_base_check (tls, condition);
}

typedef struct {
  GSource             source;

  GTlsConnectionBase *tls;

  /* Either a GDatagramBased (datagram mode), or a GPollableInputStream or
   * a GPollableOutputStream (streaming mode):
   */
  GObject            *base;

  GSource            *child_source;
  GIOCondition        condition;

  gboolean            io_waiting;
  gboolean            op_waiting;
} GTlsConnectionBaseSource;

/* Use a custom dummy callback instead of g_source_set_dummy_callback(), as that
 * uses a GClosure and is slow. (The GClosure is necessary to deal with any
 * function prototype.)
 */
static gboolean
dummy_callback (gpointer data)
{
  return G_SOURCE_CONTINUE;
}

static void
tls_source_sync (GTlsConnectionBaseSource *tls_source)
{
  GTlsConnectionBase *tls = tls_source->tls;
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);
  gboolean io_waiting, op_waiting;

  /* Was the source destroyed earlier in this main context iteration? */
  if (g_source_is_destroyed ((GSource *)tls_source))
    return;

  g_mutex_lock (&priv->op_mutex);
  if (((tls_source->condition & G_IO_IN) && priv->reading) ||
      ((tls_source->condition & G_IO_OUT) && priv->writing) ||
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

  if (op_waiting == tls_source->op_waiting &&
      io_waiting == tls_source->io_waiting)
    return;
  tls_source->op_waiting = op_waiting;
  tls_source->io_waiting = io_waiting;

  if (tls_source->child_source)
    {
      g_source_remove_child_source ((GSource *)tls_source,
                                    tls_source->child_source);
      g_source_unref (tls_source->child_source);
    }

  if (op_waiting)
    tls_source->child_source = g_cancellable_source_new (priv->waiting_for_op);
  else if (io_waiting && G_IS_DATAGRAM_BASED (tls_source->base))
    tls_source->child_source = g_datagram_based_create_source (priv->base_socket, tls_source->condition, NULL);
  else if (io_waiting && G_IS_POLLABLE_INPUT_STREAM (tls_source->base))
    tls_source->child_source = g_pollable_input_stream_create_source (priv->base_istream, NULL);
  else if (io_waiting && G_IS_POLLABLE_OUTPUT_STREAM (tls_source->base))
    tls_source->child_source = g_pollable_output_stream_create_source (priv->base_ostream, NULL);
  else
    tls_source->child_source = g_timeout_source_new (0);

  g_source_set_callback (tls_source->child_source, dummy_callback, NULL, NULL);
  g_source_add_child_source ((GSource *)tls_source, tls_source->child_source);
}

static gboolean
tls_source_dispatch (GSource     *source,
                     GSourceFunc  callback,
                     gpointer     user_data)
{
  GDatagramBasedSourceFunc datagram_based_func = (GDatagramBasedSourceFunc)callback;
  GPollableSourceFunc pollable_func = (GPollableSourceFunc)callback;
  GTlsConnectionBaseSource *tls_source = (GTlsConnectionBaseSource *)source;
  gboolean ret;

  if (G_IS_DATAGRAM_BASED (tls_source->base))
    ret = (*datagram_based_func) (G_DATAGRAM_BASED (tls_source->base),
                                  tls_source->condition, user_data);
  else
    ret = (*pollable_func) (tls_source->base, user_data);

  if (ret)
    tls_source_sync (tls_source);

  return ret;
}

static void
tls_source_finalize (GSource *source)
{
  GTlsConnectionBaseSource *tls_source = (GTlsConnectionBaseSource *)source;

  g_object_unref (tls_source->tls);
  g_source_unref (tls_source->child_source);
}

static gboolean
g_tls_connection_tls_source_closure_callback (GObject  *stream,
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
g_tls_connection_tls_source_dtls_closure_callback (GDatagramBased *datagram_based,
                                                   GIOCondition    condition,
                                                   gpointer        data)
{
  GClosure *closure = data;

  GValue param[2] = { G_VALUE_INIT, G_VALUE_INIT };
  GValue result_value = G_VALUE_INIT;
  gboolean result;

  g_value_init (&result_value, G_TYPE_BOOLEAN);

  g_value_init (&param[0], G_TYPE_DATAGRAM_BASED);
  g_value_set_object (&param[0], datagram_based);
  g_value_init (&param[1], G_TYPE_IO_CONDITION);
  g_value_set_flags (&param[1], condition);

  g_closure_invoke (closure, &result_value, 2, param, NULL);

  result = g_value_get_boolean (&result_value);
  g_value_unset (&result_value);
  g_value_unset (&param[0]);
  g_value_unset (&param[1]);

  return result;
}

static GSourceFuncs tls_source_funcs =
{
  NULL,
  NULL,
  tls_source_dispatch,
  tls_source_finalize,
  (GSourceFunc)g_tls_connection_tls_source_closure_callback,
  (GSourceDummyMarshal)g_cclosure_marshal_generic
};

static GSourceFuncs dtls_source_funcs =
{
  NULL,
  NULL,
  tls_source_dispatch,
  tls_source_finalize,
  (GSourceFunc)g_tls_connection_tls_source_dtls_closure_callback,
  (GSourceDummyMarshal)g_cclosure_marshal_generic
};

/* FIXME: all needs to be threadsafe... */
GSource *
g_tls_connection_base_create_source (GTlsConnectionBase  *tls,
                                     GIOCondition         condition,
                                     GCancellable        *cancellable)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);
  GSource *source, *cancellable_source;
  GTlsConnectionBaseSource *tls_source;

  if (g_tls_connection_base_is_dtls (tls))
    {
      source = g_source_new (&dtls_source_funcs,
                             sizeof (GTlsConnectionBaseSource));
    }
  else
    {
      source = g_source_new (&tls_source_funcs,
                             sizeof (GTlsConnectionBaseSource));
    }
  g_source_set_name (source, "GTlsConnectionBaseSource");
  tls_source = (GTlsConnectionBaseSource *)source;
  tls_source->tls = g_object_ref (tls);
  tls_source->condition = condition;
  if (g_tls_connection_base_is_dtls (tls))
    tls_source->base = G_OBJECT (tls);
  else if (priv->tls_istream && condition & G_IO_IN)
    tls_source->base = G_OBJECT (priv->tls_istream);
  else if (priv->tls_ostream && condition & G_IO_OUT)
    tls_source->base = G_OBJECT (priv->tls_ostream);
  else
    g_assert_not_reached ();

  tls_source->op_waiting = (gboolean) -1;
  tls_source->io_waiting = (gboolean) -1;
  tls_source_sync (tls_source);

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
g_tls_connection_base_dtls_create_source (GDatagramBased  *datagram_based,
                                          GIOCondition     condition,
                                          GCancellable    *cancellable)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (datagram_based);

  return g_tls_connection_base_create_source (tls, condition, cancellable);
}

static GIOCondition
g_tls_connection_base_condition_check (GDatagramBased  *datagram_based,
                                       GIOCondition     condition)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (datagram_based);

  return g_tls_connection_base_check (tls, condition) ? condition : 0;
}

/* Returns a GSource for the underlying GDatagramBased or base stream, not for
 * the GTlsConnectionBase itself.
 */
GSource *
g_tls_connection_base_create_base_source (GTlsConnectionBase *tls,
                                          GIOCondition        condition,
                                          GCancellable       *cancellable)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);

  if (g_tls_connection_base_is_dtls (tls))
    return g_datagram_based_create_source (priv->base_socket, condition, cancellable);
  if (condition & G_IO_IN)
    return g_pollable_input_stream_create_source (priv->base_istream, cancellable);
  if (condition & G_IO_OUT)
    return g_pollable_output_stream_create_source (priv->base_ostream, cancellable);

  g_assert_not_reached ();
}

static gboolean
g_tls_connection_base_condition_wait (GDatagramBased  *datagram_based,
                                      GIOCondition     condition,
                                      gint64           timeout,
                                      GCancellable    *cancellable,
                                      GError         **error)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (datagram_based);
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);
  GPollFD fds[2];
  guint n_fds;
  gint result = 1; /* if the loop is never entered, it's as if we cancelled early */
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

  while (!g_tls_connection_base_condition_check (datagram_based, condition) &&
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

static GTlsCertificateFlags
verify_peer_certificate (GTlsConnectionBase *tls,
                         GTlsCertificate    *peer_certificate)
{
  GSocketConnectable *peer_identity;
  GTlsDatabase *database;
  GTlsCertificateFlags errors;
  gboolean is_client;

  is_client = G_IS_TLS_CLIENT_CONNECTION (tls);

  if (!is_client)
    peer_identity = NULL;
  else if (!g_tls_connection_base_is_dtls (tls))
    peer_identity = g_tls_client_connection_get_server_identity (G_TLS_CLIENT_CONNECTION (tls));
  else
    peer_identity = g_dtls_client_connection_get_server_identity (G_DTLS_CLIENT_CONNECTION (tls));

  errors = 0;

  database = g_tls_connection_get_database (G_TLS_CONNECTION (tls));
  if (!database)
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
                                             g_tls_connection_get_interaction (G_TLS_CONNECTION (tls)),
                                             G_TLS_DATABASE_VERIFY_NONE,
                                             NULL, &error);
      if (error)
        {
          g_tls_log_debug (tls, "failure verifying certificate chain: %s", error->message);
          g_assert (errors != 0);
          g_clear_error (&error);
        }
    }

  return errors;
}

static gboolean
verify_certificate_cb (GTlsOperationsThreadBase *thread,
                       GTlsCertificate          *peer_certificate,
                       GTlsConnectionBase       *tls)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);
  GTlsCertificateFlags peer_certificate_errors = 0;
  gboolean accepted = FALSE;

  /* FIXME: when doing async handshake as sync-on-a-thread, this function will
   * be called from the handshake thread, which is unsafe. The code assumes
   * it is used from the main thread.
   * FIXME: eliminate handshake context.
   */

  if (peer_certificate)
    peer_certificate_errors = verify_peer_certificate (tls, peer_certificate);

  g_set_object (&priv->peer_certificate, peer_certificate);
  g_clear_object (&peer_certificate);

  priv->peer_certificate_errors = peer_certificate_errors;

  g_object_notify (G_OBJECT (tls), "peer-certificate");
  g_object_notify (G_OBJECT (tls), "peer-certificate-errors");

  if (G_IS_TLS_CLIENT_CONNECTION (tls) && priv->peer_certificate)
    {
      GTlsCertificateFlags validation_flags;

      if (!g_tls_connection_base_is_dtls (tls))
        validation_flags =
          g_tls_client_connection_get_validation_flags (G_TLS_CLIENT_CONNECTION (tls));
      else
        validation_flags =
          g_dtls_client_connection_get_validation_flags (G_DTLS_CLIENT_CONNECTION (tls));

      if ((priv->peer_certificate_errors & validation_flags) == 0)
        accepted = TRUE;
    }

  if (!accepted)
    {
      accepted = g_tls_connection_emit_accept_certificate (G_TLS_CONNECTION (tls),
                                                           priv->peer_certificate,
                                                           priv->peer_certificate_errors);
    }

  priv->peer_certificate_accepted = accepted;

  return accepted;
}

static void
session_resumed_cb (GTlsOperationsThreadBase *thread,
                    GTlsCertificate          *peer_certificate,
                    GTlsConnectionBase       *tls)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);

  /* FIXME: when doing async handshake as sync-on-a-thread, this function will
   * be called from the handshake thread, which is unsafe. The code assumes
   * it is used from the main thread.
   * FIXME: eliminate handshake context.
   */

  g_set_object (&priv->peer_certificate, peer_certificate);
  g_clear_object (&peer_certificate);

  priv->peer_certificate_errors = 0;

  g_object_notify (G_OBJECT (tls), "peer-certificate");
  g_object_notify (G_OBJECT (tls), "peer-certificate-errors");
}

static gboolean
handshake (GTlsConnectionBase  *tls,
           gint64               timeout,
           GCancellable        *cancellable,
           GError             **error)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);
  GTlsAuthenticationMode auth_mode = G_TLS_AUTHENTICATION_NONE;
  gchar *original_negotiated_protocol;
  GList *accepted_cas;

  /* FIXME: in async codepaths, this function is still called on a secondary
   * handshake thread. That means use of priv members here needs to be guarded
   * by a mutex. Additionally, it is SUPER UNSAFE to notify negotiated-protocol
   * on this thread. We need to either eliminate this extra thread, or tighten
   * up the threadsafety of this function.
   */

  g_tls_log_debug (tls, "TLS handshake starts");

  priv->started_handshake = FALSE;

  /* FIXME: I don't like this mismatch. If we claim here, let's yield at the
   * bottom. Otherwise, move claim to the caller.
   */
  if (!claim_op (tls, G_TLS_CONNECTION_BASE_OP_HANDSHAKE,
                 timeout, cancellable, error))
    {
      g_tls_log_debug (tls, "TLS handshake failed: claiming op failed");
      return FALSE;
    }

  g_clear_error (&priv->handshake_error);

  if (priv->ever_handshaked && !priv->need_handshake)
    {
      /* Once upon a time, we allowed calling g_tls_connection_handshake()
       * twice in order to request a rehandshake. Now that rehandshaking has
       * been removed from TLS 1.3, we'll instead just ignore the request. We
       * can't throw an error here because this used to be allowed.
       */
      g_tls_log_debug (tls, "Ignoring duplicate TLS handshake request");
      return TRUE;
    }

  if (G_IS_TLS_SERVER_CONNECTION (tls))
    {
      g_object_get (tls,
                    "authentication-mode", &auth_mode,
                    NULL);
    }

  original_negotiated_protocol = g_steal_pointer (&priv->negotiated_protocol);

  priv->started_handshake = TRUE;

  g_tls_operations_thread_base_handshake (priv->thread,
                                          (const gchar **)priv->advertised_protocols,
                                          auth_mode,
                                          timeout,
                                          (GTlsVerifyCertificateFunc)verify_certificate_cb,
                                          (GTlsSessionResumedFunc)session_resumed_cb,
                                          &priv->negotiated_protocol,
                                          &accepted_cas,
                                          cancellable,
                                          tls,
                                          error);

  priv->need_handshake = FALSE;

  /* FIXME: notify should be next to accepted-cas? */
  if (g_strcmp0 (original_negotiated_protocol, priv->negotiated_protocol) != 0)
    g_object_notify (G_OBJECT (tls), "negotiated-protocol");
  g_free (original_negotiated_protocol);

  if (G_IS_TLS_CLIENT_CONNECTION (tls))
    G_TLS_CONNECTION_BASE_GET_CLASS (tls)->set_accepted_cas (tls, accepted_cas);
  else
    g_assert (!accepted_cas);

  if (error && *error)
    {
      g_tls_log_debug (tls, "TLS handshake failed: %s", (*error)->message);
      return FALSE;
    }

  priv->ever_handshaked = TRUE;
  g_tls_log_debug (tls, "TLS handshake succeeded");
  return TRUE;
}

static gboolean
finish_handshake (GTlsConnectionBase  *tls,
                  gboolean             success,
                  GError             **error)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);
  GError *my_error = NULL;

  g_tls_log_debug (tls, "finishing TLS handshake");

  /* FIXME: Return an error from the handshake instead? */
  if (success && priv->peer_certificate && !priv->peer_certificate_accepted)
    {
      g_set_error_literal (&my_error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                           _("Unacceptable TLS certificate"));
    }

  /* FIXME: notify only when accepted-cas has actually changed. */
  if (G_IS_TLS_CLIENT_CONNECTION (tls))
    g_object_notify (G_OBJECT (tls), "accepted-cas");

  if (my_error && priv->started_handshake)
    priv->handshake_error = g_error_copy (my_error);

  if (!my_error) {
    g_tls_log_debug (tls, "TLS handshake has finished successfully");
    return success;
  }

  g_tls_log_debug (tls, "TLS handshake has finished with error: %s", my_error->message);
  g_propagate_error (error, my_error);
  return FALSE;
}

static gboolean
g_tls_connection_base_handshake (GTlsConnection   *conn,
                                 GCancellable     *cancellable,
                                 GError          **error)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (conn);
  gboolean success;
  GError *my_error = NULL;

  g_tls_log_debug (tls, "Starting synchronous TLS handshake");

  success = handshake (tls, -1 /* blocking */, cancellable, error);

  /* If we already have an error, ignore further errors. */
  success = finish_handshake (tls, success, my_error ? NULL : &my_error);

  yield_op (tls, G_TLS_CONNECTION_BASE_OP_HANDSHAKE,
            G_TLS_CONNECTION_BASE_OK);

  if (my_error)
    g_propagate_error (error, my_error);
  return success;
}

static gboolean
g_tls_connection_base_dtls_handshake (GDtlsConnection  *conn,
                                      GCancellable     *cancellable,
                                      GError          **error)
{
  return g_tls_connection_base_handshake (G_TLS_CONNECTION (conn),
                                          cancellable, error);
}

/* In the async version we use two GTasks; one to run
 * handshake_thread() and then call async_handshake_thread_completed(),
 * and a second to call the caller's original callback after we call
 * finish_handshake().
 *
 * Note: async_handshake_thread_completed() is called only for explicit
 * async handshakes, not for implicit async handshakes.
 */

static void
async_handshake_thread_completed (GObject      *object,
                                  GAsyncResult *result,
                                  gpointer      user_data)
{
  GTask *caller_task = user_data;
  GTlsConnectionBase *tls = g_task_get_source_object (caller_task);
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);
  GError *error = NULL;
  gboolean need_finish_handshake, success;

  g_tls_log_debug (tls, "Asynchronous TLS handshake thread completed");

  g_assert (g_task_is_valid (result, object));
  g_assert (g_task_get_source_tag (G_TASK (result)) == g_tls_connection_base_handshake_async);

  g_mutex_lock (&priv->op_mutex);
  if (priv->need_finish_handshake)
    {
      need_finish_handshake = TRUE;
      priv->need_finish_handshake = FALSE;
    }
  else
    need_finish_handshake = FALSE;
  g_mutex_unlock (&priv->op_mutex);

  /* FIXME: this looks weird, why do we ignore the result of the GTask in the !need_finish_handshake case? */
  if (need_finish_handshake)
    {
      success = g_task_propagate_boolean (G_TASK (result), &error);

      /* If we already have an error, ignore further errors. */
      success = finish_handshake (tls, success, error ? NULL : &error);

      if (success)
        g_task_return_boolean (caller_task, TRUE);
      else
        g_task_return_error (caller_task, error);
    }
  else
    {
      if (priv->handshake_error)
        g_task_return_error (caller_task, g_error_copy (priv->handshake_error));
      else
        g_task_return_boolean (caller_task, TRUE);
    }

  g_object_unref (caller_task);
}

static void
async_handshake_thread (GTask        *task,
                        gpointer      object,
                        gpointer      task_data,
                        GCancellable *cancellable)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (object);
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);
  GError *error = NULL;

  g_tls_log_debug (tls, "Asynchronous TLS handshake thread starts");

  handshake (tls, -1 /* blocking */, cancellable, &error);

  g_mutex_lock (&priv->op_mutex);
  priv->need_finish_handshake = TRUE;
  /* yield_op will clear handshaking too, but we don't want the
   * connection to be briefly "handshaking && need_finish_handshake"
   * after we unlock the mutex.
   */
  priv->handshaking = FALSE;
  g_mutex_unlock (&priv->op_mutex);

  yield_op (tls, G_TLS_CONNECTION_BASE_OP_HANDSHAKE,
            G_TLS_CONNECTION_BASE_OK);

  if (error)
    g_task_return_error (task, error);
  else
    g_task_return_boolean (task, TRUE);
}

static void
g_tls_connection_base_handshake_async (GTlsConnection      *conn,
                                       int                  io_priority,
                                       GCancellable        *cancellable,
                                       GAsyncReadyCallback  callback,
                                       gpointer             user_data)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (conn);
  GTask *thread_task, *caller_task;

  g_tls_log_debug (tls, "Starting asynchronous TLS handshake");

  caller_task = g_task_new (conn, cancellable, callback, user_data);
  g_task_set_source_tag (caller_task, g_tls_connection_base_handshake_async);
  g_task_set_name (caller_task, "[glib-networking] g_tls_connection_base_handshake_async (caller task)");
  g_task_set_priority (caller_task, io_priority);

  thread_task = g_task_new (conn, cancellable, async_handshake_thread_completed, caller_task);
  g_task_set_source_tag (thread_task, g_tls_connection_base_handshake_async);
  g_task_set_name (caller_task, "[glib-networking] g_tls_connection_base_handshake_async (thread task)");
  g_task_set_priority (thread_task, io_priority);

  g_task_run_in_thread (thread_task, async_handshake_thread);
  g_object_unref (thread_task);
}

static gboolean
g_tls_connection_base_handshake_finish (GTlsConnection  *conn,
                                        GAsyncResult    *result,
                                        GError         **error)
{
  g_return_val_if_fail (g_task_is_valid (result, conn), FALSE);
  g_return_val_if_fail (g_task_get_source_tag (G_TASK (result)) == g_tls_connection_base_handshake_async, FALSE);

  return g_task_propagate_boolean (G_TASK (result), error);
}

static void
g_tls_connection_base_dtls_handshake_async (GDtlsConnection     *conn,
                                            int                  io_priority,
                                            GCancellable        *cancellable,
                                            GAsyncReadyCallback  callback,
                                            gpointer             user_data)
{
  g_tls_connection_base_handshake_async (G_TLS_CONNECTION (conn), io_priority,
                                         cancellable, callback, user_data);
}

static gboolean
g_tls_connection_base_dtls_handshake_finish (GDtlsConnection  *conn,
                                             GAsyncResult     *result,
                                             GError          **error)
{
  return g_tls_connection_base_handshake_finish (G_TLS_CONNECTION (conn),
                                                 result, error);
}

static gboolean
start_async_implicit_handshake (GTlsConnectionBase  *tls,
                                GCancellable        *cancellable,
                                GError             **error)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);

  g_tls_log_debug (tls, "Starting async implicit handshake");

  /* We have op_mutex */

  g_assert (!priv->async_implicit_handshake);
  priv->async_implicit_handshake = g_task_new (tls, cancellable,
                                               NULL, NULL);
  g_task_set_source_tag (priv->async_implicit_handshake, do_implicit_handshake);
  g_task_set_name (priv->async_implicit_handshake, "[glib-networking] do_implicit_handshake");

  /* In the non-blocking case, start the asynchronous handshake operation
   * and return EWOULDBLOCK to the caller, who will handle polling for
   * completion of the handshake and whatever operation they actually cared
   * about. Run the actual operation as blocking in its thread.
   */

  g_task_run_in_thread (priv->async_implicit_handshake, async_handshake_thread);

  /* Intentionally not translated because this is not a fatal error to be
   * presented to the user, and to avoid this showing up in profiling.
   */
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK, "Operation would block");
  return FALSE;
}

static gboolean
do_sync_implicit_handshake (GTlsConnectionBase  *tls,
                            gint64               timeout,
                            GCancellable        *cancellable,
                            GError             **error)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);
  GError *my_error = NULL;
  gboolean success;

  g_tls_log_debug (tls, "Starting sync implicit handshake");

  /* We have op_mutex */

  g_mutex_unlock (&priv->op_mutex);

  success = handshake (tls, timeout, cancellable, &my_error);

  /* If we already have an error, ignore further errors. */
  success = finish_handshake (tls, success,
                              my_error ? NULL : &my_error);

  yield_op (tls, G_TLS_CONNECTION_BASE_OP_HANDSHAKE,
            G_TLS_CONNECTION_BASE_OK);

  g_mutex_lock (&priv->op_mutex);

  if (my_error)
    g_propagate_error (error, my_error);
  return success;
}

static gboolean
do_implicit_handshake (GTlsConnectionBase  *tls,
                       gint64               timeout,
                       GCancellable        *cancellable,
                       GError             **error)
{
  if (timeout == 0)
    return start_async_implicit_handshake (tls, cancellable, error);

  return do_sync_implicit_handshake (tls, timeout, cancellable, error);
}

gssize
g_tls_connection_base_read (GTlsConnectionBase  *tls,
                            void                *buffer,
                            gsize                size,
                            gint64               timeout,
                            GCancellable        *cancellable,
                            GError             **error)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);
  GTlsConnectionBaseStatus status;
  gssize nread;

  g_tls_log_debug (tls, "starting to read data from TLS connection");

  do
    {
      if (!claim_op (tls, G_TLS_CONNECTION_BASE_OP_READ,
                     timeout, cancellable, error))
        return -1;

      status = g_tls_operations_thread_base_read (priv->thread, buffer, size, timeout, &nread, cancellable, error);

      yield_op (tls, G_TLS_CONNECTION_BASE_OP_READ, status);
    }
  while (status == G_TLS_CONNECTION_BASE_REHANDSHAKE);

  if (status == G_TLS_CONNECTION_BASE_OK)
    {
      priv->successful_posthandshake_op = TRUE;
      g_tls_log_debug (tls, "successfully read %" G_GSSIZE_FORMAT " bytes from TLS connection", nread);
      return nread;
    }

  g_tls_log_debug (tls, "reading data from TLS connection has failed: %s", status_to_string (status));
  return -1;
}

static gssize
g_tls_connection_base_read_message (GTlsConnectionBase  *tls,
                                    GInputVector        *vectors,
                                    guint                num_vectors,
                                    gint64               timeout,
                                    GCancellable        *cancellable,
                                    GError             **error)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);
  GTlsConnectionBaseStatus status;
  gssize nread;

  g_tls_log_debug (tls, "starting to read messages from TLS connection");

  do {
    if (!claim_op (tls, G_TLS_CONNECTION_BASE_OP_READ,
                   timeout, cancellable, error))
      return -1;

    status = g_tls_operations_thread_base_read_message (priv->thread, vectors, num_vectors, timeout, &nread, cancellable, error);
    yield_op (tls, G_TLS_CONNECTION_BASE_OP_READ, status);
  } while (status == G_TLS_CONNECTION_BASE_REHANDSHAKE);

  if (status == G_TLS_CONNECTION_BASE_OK)
    {
      priv->successful_posthandshake_op = TRUE;
      g_tls_log_debug (tls, "successfully read %" G_GSSIZE_FORMAT " bytes from TLS connection", nread);
      return nread;
    }

  g_tls_log_debug (tls, "reading message from TLS connection has failed: %s", status_to_string (status));
  return -1;
}

static gint
g_tls_connection_base_receive_messages (GDatagramBased  *datagram_based,
                                        GInputMessage   *messages,
                                        guint            num_messages,
                                        gint             flags,
                                        gint64           timeout,
                                        GCancellable    *cancellable,
                                        GError         **error)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (datagram_based);
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);
  guint i;
  GError *child_error = NULL;

  if (flags != G_SOCKET_MSG_NONE)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                   _("Receive flags are not supported"));
      return -1;
    }

  for (i = 0; i < num_messages && !child_error; i++)
    {
      GInputMessage *message = &messages[i];
      gssize n_bytes_read;

      n_bytes_read = g_tls_connection_base_read_message (tls,
                                                         message->vectors,
                                                         message->num_vectors,
                                                         timeout,
                                                         cancellable,
                                                         &child_error);

      if (message->address)
        *message->address = NULL;
      message->flags = G_SOCKET_MSG_NONE;
      if (message->control_messages)
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

  if (child_error)
    {
      g_propagate_error (error, child_error);
      return -1;
    }

  priv->successful_posthandshake_op = TRUE;
  return i;
}

gssize
g_tls_connection_base_write (GTlsConnectionBase  *tls,
                             const void          *buffer,
                             gsize                size,
                             gint64               timeout,
                             GCancellable        *cancellable,
                             GError             **error)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);
  GTlsConnectionBaseStatus status;
  gssize nwrote;

  g_tls_log_debug (tls, "starting to write %" G_GSIZE_FORMAT " bytes to TLS connection", size);

  do
    {
      if (!claim_op (tls, G_TLS_CONNECTION_BASE_OP_WRITE,
                     timeout, cancellable, error))
        return -1;

      status = g_tls_operations_thread_base_write (priv->thread, buffer, size, timeout, &nwrote, cancellable, error);
      yield_op (tls, G_TLS_CONNECTION_BASE_OP_WRITE, status);
    }
  while (status == G_TLS_CONNECTION_BASE_REHANDSHAKE);

  if (status == G_TLS_CONNECTION_BASE_OK)
    {
      priv->successful_posthandshake_op = TRUE;
      g_tls_log_debug (tls, "successfully write %" G_GSSIZE_FORMAT " bytes to TLS connection", nwrote);
      return nwrote;
    }

  g_tls_log_debug (tls, "writting data to TLS connection has failed: %s", status_to_string (status));
  return -1;
}

static gssize
g_tls_connection_base_write_message (GTlsConnectionBase  *tls,
                                     GOutputVector       *vectors,
                                     guint                num_vectors,
                                     gint64               timeout,
                                     GCancellable        *cancellable,
                                     GError             **error)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);
  GTlsConnectionBaseStatus status;
  gssize nwrote;

  g_tls_log_debug (tls, "starting to write messages to TLS connection");

  do {
    if (!claim_op (tls, G_TLS_CONNECTION_BASE_OP_WRITE,
                   timeout, cancellable, error))
      return -1;

    status = g_tls_operations_thread_base_write_message (priv->thread, vectors, num_vectors, timeout, &nwrote, cancellable, error);

    yield_op (tls, G_TLS_CONNECTION_BASE_OP_WRITE, status);
  } while (status == G_TLS_CONNECTION_BASE_REHANDSHAKE);

  if (status == G_TLS_CONNECTION_BASE_OK)
    {
      priv->successful_posthandshake_op = TRUE;
      g_tls_log_debug (tls, "successfully write %" G_GSSIZE_FORMAT " bytes to TLS connection", nwrote);
      return nwrote;
    }

  g_tls_log_debug (tls, "writting messages to TLS connection has failed: %s", status_to_string (status));
  return -1;
}

static gint
g_tls_connection_base_send_messages (GDatagramBased  *datagram_based,
                                     GOutputMessage  *messages,
                                     guint            num_messages,
                                     gint             flags,
                                     gint64           timeout,
                                     GCancellable    *cancellable,
                                     GError         **error)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (datagram_based);
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);
  guint i;
  GError *child_error = NULL;

  if (flags != G_SOCKET_MSG_NONE)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                   _("Send flags are not supported"));
      return -1;
    }

  for (i = 0; i < num_messages && !child_error; i++)
    {
      GOutputMessage *message = &messages[i];
      gssize n_bytes_sent;

      n_bytes_sent = g_tls_connection_base_write_message (tls,
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

  if (child_error)
    {
      g_propagate_error (error, child_error);
      return -1;
    }

  priv->successful_posthandshake_op = TRUE;
  return i;
}

static GInputStream *
g_tls_connection_base_get_input_stream (GIOStream *stream)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (stream);
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);

  return priv->tls_istream;
}

static GOutputStream *
g_tls_connection_base_get_output_stream (GIOStream *stream)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (stream);
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);

  return priv->tls_ostream;
}

gboolean
g_tls_connection_base_close_internal (GIOStream      *stream,
                                      GTlsDirection   direction,
                                      gint64          timeout,
                                      GCancellable   *cancellable,
                                      GError        **error)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (stream);
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);
  GTlsConnectionBaseOp op;
  GTlsConnectionBaseStatus status;
  gboolean success = TRUE;
  GError *close_error = NULL, *stream_error = NULL;

  g_tls_log_debug (tls, "starting to close the TLS connection");

  /* This can be called from g_io_stream_close(), g_input_stream_close(),
   * g_output_stream_close(), or g_tls_connection_close(). In all cases, we only
   * do the close_fn() for writing. The difference is how we set the flags on
   * this class and how the underlying stream is closed.
   */

  g_return_val_if_fail (direction != G_TLS_DIRECTION_NONE, FALSE);

  if (direction == G_TLS_DIRECTION_BOTH)
    op = G_TLS_CONNECTION_BASE_OP_CLOSE_BOTH;
  else if (direction == G_TLS_DIRECTION_READ)
    op = G_TLS_CONNECTION_BASE_OP_CLOSE_READ;
  else
    op = G_TLS_CONNECTION_BASE_OP_CLOSE_WRITE;

  if (!claim_op (tls, op, timeout, cancellable, error))
    return FALSE;

  if (priv->ever_handshaked && !priv->write_closed &&
      direction & G_TLS_DIRECTION_WRITE)
    {
      status = g_tls_operations_thread_base_close (priv->thread, cancellable, &close_error);

      priv->write_closed = TRUE;
    }
  else
    status = G_TLS_CONNECTION_BASE_OK;

  if (!priv->read_closed && direction & G_TLS_DIRECTION_READ)
    priv->read_closed = TRUE;

  /* Close the underlying streams. Do this even if the close_fn() call failed,
   * as the parent GIOStream will have set its internal closed flag and hence
   * this implementation will never be called again. */
  if (priv->base_io_stream)
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
  else if (g_tls_connection_base_is_dtls (tls))
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

  yield_op (tls, op, status);

  /* Propagate errors. */
  if (status != G_TLS_CONNECTION_BASE_OK)
    {
      g_tls_log_debug (tls, "error closing TLS connection: %s", close_error->message);
      g_propagate_error (error, close_error);
      g_clear_error (&stream_error);
    }
  else if (!success)
    {
      g_tls_log_debug (tls, "error closing TLS connection: %s", stream_error->message);
      g_propagate_error (error, stream_error);
      g_clear_error (&close_error);
    }
  else
    {
      g_tls_log_debug (tls, "the TLS connection has been closed successfully");
    }

  return success && status == G_TLS_CONNECTION_BASE_OK;
}

static gboolean
g_tls_connection_base_close (GIOStream     *stream,
                             GCancellable  *cancellable,
                             GError       **error)
{
  return g_tls_connection_base_close_internal (stream,
                                               G_TLS_DIRECTION_BOTH,
                                               -1,  /* blocking */
                                               cancellable, error);
}

static gboolean
g_tls_connection_base_dtls_shutdown (GDtlsConnection  *conn,
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

  return g_tls_connection_base_close_internal (G_IO_STREAM (conn),
                                               direction,
                                               -1, /* blocking */
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

  if (!g_tls_connection_base_close_internal (stream, direction,
                                             -1, /* blocking */
                                             cancellable, &error))
    g_task_return_error (task, error);
  else
    g_task_return_boolean (task, TRUE);
}

static void
g_tls_connection_base_close_internal_async (GIOStream           *stream,
                                            GTlsDirection        direction,
                                            int                  io_priority,
                                            GCancellable        *cancellable,
                                            GAsyncReadyCallback  callback,
                                            gpointer             user_data)
{
  GTask *task;

  task = g_task_new (stream, cancellable, callback, user_data);
  g_task_set_source_tag (task, g_tls_connection_base_close_internal_async);
  g_task_set_name (task, "[glib-networking] g_tls_connection_base_close_internal_async");
  g_task_set_priority (task, io_priority);
  g_task_set_task_data (task, GINT_TO_POINTER (direction), NULL);
  g_task_run_in_thread (task, close_thread);
  g_object_unref (task);
}

static void
g_tls_connection_base_close_async (GIOStream           *stream,
                                   int                  io_priority,
                                   GCancellable        *cancellable,
                                   GAsyncReadyCallback  callback,
                                   gpointer             user_data)
{
  g_tls_connection_base_close_internal_async (stream, G_TLS_DIRECTION_BOTH,
                                              io_priority, cancellable,
                                              callback, user_data);
}

static gboolean
g_tls_connection_base_close_finish (GIOStream           *stream,
                                    GAsyncResult        *result,
                                    GError             **error)
{
  g_return_val_if_fail (g_task_is_valid (result, stream), FALSE);
  g_return_val_if_fail (g_task_get_source_tag (G_TASK (result)) == g_tls_connection_base_close_internal_async, FALSE);

  return g_task_propagate_boolean (G_TASK (result), error);
}

static void
g_tls_connection_base_dtls_shutdown_async (GDtlsConnection     *conn,
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

  g_tls_connection_base_close_internal_async (G_IO_STREAM (conn), direction,
                                              io_priority, cancellable,
                                              callback, user_data);
}

static gboolean
g_tls_connection_base_dtls_shutdown_finish (GDtlsConnection  *conn,
                                            GAsyncResult     *result,
                                            GError          **error)
{
  g_return_val_if_fail (g_task_is_valid (result, conn), FALSE);
  g_return_val_if_fail (g_task_get_source_tag (G_TASK (result)) == g_tls_connection_base_close_internal_async, FALSE);

  return g_task_propagate_boolean (G_TASK (result), error);
}

static void
g_tls_connection_base_dtls_set_advertised_protocols (GDtlsConnection     *conn,
                                                     const gchar * const *protocols)
{
  g_object_set (conn, "advertised-protocols", protocols, NULL);
}

const gchar *
g_tls_connection_base_dtls_get_negotiated_protocol (GDtlsConnection *conn)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (conn);
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);

  return priv->negotiated_protocol;
}

GDatagramBased *
g_tls_connection_base_get_base_socket (GTlsConnectionBase *tls)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);

 g_assert (g_tls_connection_base_is_dtls (tls));

  return priv->base_socket;
}

GIOStream *
g_tls_connection_base_get_base_iostream (GTlsConnectionBase *tls)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);

 g_assert (!g_tls_connection_base_is_dtls (tls));

  return priv->base_io_stream;
}

GTlsOperationsThreadBase *
g_tls_connection_base_get_op_thread (GTlsConnectionBase *tls)
{
  GTlsConnectionBasePrivate *priv = g_tls_connection_base_get_instance_private (tls);

  return priv->thread;
}

static void
g_tls_connection_base_class_init (GTlsConnectionBaseClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsConnectionClass *connection_class = G_TLS_CONNECTION_CLASS (klass);
  GIOStreamClass *iostream_class = G_IO_STREAM_CLASS (klass);

  gobject_class->get_property = g_tls_connection_base_get_property;
  gobject_class->set_property = g_tls_connection_base_set_property;
  gobject_class->finalize     = g_tls_connection_base_finalize;

  connection_class->handshake        = g_tls_connection_base_handshake;
  connection_class->handshake_async  = g_tls_connection_base_handshake_async;
  connection_class->handshake_finish = g_tls_connection_base_handshake_finish;

  iostream_class->get_input_stream  = g_tls_connection_base_get_input_stream;
  iostream_class->get_output_stream = g_tls_connection_base_get_output_stream;
  iostream_class->close_fn          = g_tls_connection_base_close;
  iostream_class->close_async       = g_tls_connection_base_close_async;
  iostream_class->close_finish      = g_tls_connection_base_close_finish;

  klass->pop_io = g_tls_connection_base_real_pop_io;

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
  g_object_class_override_property (gobject_class, PROP_ADVERTISED_PROTOCOLS, "advertised-protocols");
  g_object_class_override_property (gobject_class, PROP_NEGOTIATED_PROTOCOL, "negotiated-protocol");
}

static void
g_tls_connection_base_dtls_connection_iface_init (GDtlsConnectionInterface *iface)
{
  iface->handshake = g_tls_connection_base_dtls_handshake;
  iface->handshake_async = g_tls_connection_base_dtls_handshake_async;
  iface->handshake_finish = g_tls_connection_base_dtls_handshake_finish;
  iface->shutdown = g_tls_connection_base_dtls_shutdown;
  iface->shutdown_async = g_tls_connection_base_dtls_shutdown_async;
  iface->shutdown_finish = g_tls_connection_base_dtls_shutdown_finish;
  iface->set_advertised_protocols = g_tls_connection_base_dtls_set_advertised_protocols;
  iface->get_negotiated_protocol = g_tls_connection_base_dtls_get_negotiated_protocol;
}

static void
g_tls_connection_base_datagram_based_iface_init (GDatagramBasedInterface *iface)
{
  iface->receive_messages = g_tls_connection_base_receive_messages;
  iface->send_messages = g_tls_connection_base_send_messages;
  iface->create_source = g_tls_connection_base_dtls_create_source;
  iface->condition_check = g_tls_connection_base_condition_check;
  iface->condition_wait = g_tls_connection_base_condition_wait;
}

static void
g_tls_connection_base_initable_iface_init (GInitableIface *iface)
{
  iface->init = g_tls_connection_base_initable_init;
}
