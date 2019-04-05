/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2009-2011 Red Hat, Inc
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
#include "gtlsoutputstream.h"

#include <glib/gi18n-lib.h>

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
 *  • Implements GInitable for failable initialisation.
 */


static void g_tls_connection_base_dtls_connection_iface_init (GDtlsConnectionInterface *iface);

static void g_tls_connection_base_datagram_based_iface_init  (GDatagramBasedInterface  *iface);

static gboolean do_implicit_handshake (GTlsConnectionBase  *tls,
                                       gint64               timeout,
                                       GCancellable        *cancellable,
                                       GError             **error);
static gboolean finish_handshake (GTlsConnectionBase  *tls,
                                  GTask               *task,
                                  GError             **error);

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (GTlsConnectionBase, g_tls_connection_base, G_TYPE_TLS_CONNECTION,
                                  G_IMPLEMENT_INTERFACE (G_TYPE_DATAGRAM_BASED,
                                                         g_tls_connection_base_datagram_based_iface_init);
                                  G_IMPLEMENT_INTERFACE (G_TYPE_DTLS_CONNECTION,
                                                         g_tls_connection_base_dtls_connection_iface_init);
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
  PROP_PEER_CERTIFICATE_ERRORS
};

static gboolean
g_tls_connection_base_is_dtls (GTlsConnectionBase *tls)
{
  return tls->base_socket != NULL;
}

static void
g_tls_connection_base_init (GTlsConnectionBase *tls)
{
  tls->need_handshake = TRUE;
  tls->database_is_unset = TRUE;
  tls->is_system_certdb = TRUE;

  g_mutex_init (&tls->op_mutex);
  tls->waiting_for_op = g_cancellable_new ();
  g_cancellable_cancel (tls->waiting_for_op);
}

static void
g_tls_connection_base_finalize (GObject *object)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (object);

  g_clear_object (&tls->base_io_stream);
  g_clear_object (&tls->base_socket);

  g_clear_object (&tls->tls_istream);
  g_clear_object (&tls->tls_ostream);

  g_clear_object (&tls->database);
  g_clear_object (&tls->certificate);
  g_clear_error (&tls->certificate_error);
  g_clear_object (&tls->peer_certificate);

  g_clear_object (&tls->interaction);

  /* This must always be NULL at this point, as it holds a reference to @tls as
   * its source object. However, we clear it anyway just in case this changes
   * in future. */
  g_clear_object (&tls->implicit_handshake);

  g_clear_error (&tls->handshake_error);
  g_clear_error (&tls->read_error);
  g_clear_error (&tls->write_error);
  g_clear_object (&tls->read_cancellable);
  g_clear_object (&tls->write_cancellable);

  g_clear_object (&tls->waiting_for_op);
  g_mutex_clear (&tls->op_mutex);

  g_clear_pointer (&tls->app_data_buf, g_byte_array_unref);

  G_OBJECT_CLASS (g_tls_connection_base_parent_class)->finalize (object);
}

static void
g_tls_connection_base_get_property (GObject    *object,
                                    guint       prop_id,
                                    GValue     *value,
                                    GParamSpec *pspec)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (object);
  GTlsBackend *backend;

  switch (prop_id)
    {
    case PROP_BASE_IO_STREAM:
      g_value_set_object (value, tls->base_io_stream);
      break;

    case PROP_BASE_SOCKET:
      g_value_set_object (value, tls->base_socket);
      break;

    case PROP_REQUIRE_CLOSE_NOTIFY:
      g_value_set_boolean (value, tls->require_close_notify);
      break;

    case PROP_REHANDSHAKE_MODE:
      g_value_set_enum (value, tls->rehandshake_mode);
      break;

    case PROP_USE_SYSTEM_CERTDB:
      g_value_set_boolean (value, tls->is_system_certdb);
      break;

    case PROP_DATABASE:
      if (tls->database_is_unset)
        {
          backend = g_tls_backend_get_default ();
          tls->database =  g_tls_backend_get_default_database (backend);
          tls->database_is_unset = FALSE;
        }
      g_value_set_object (value, tls->database);
      break;

    case PROP_CERTIFICATE:
      g_value_set_object (value, tls->certificate);
      break;

    case PROP_INTERACTION:
      g_value_set_object (value, tls->interaction);
      break;

    case PROP_PEER_CERTIFICATE:
      g_value_set_object (value, tls->peer_certificate);
      break;

    case PROP_PEER_CERTIFICATE_ERRORS:
      g_value_set_flags (value, tls->peer_certificate_errors);
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
  GInputStream *istream;
  GOutputStream *ostream;
  gboolean system_certdb;
  GTlsBackend *backend;

  switch (prop_id)
    {
    case PROP_BASE_IO_STREAM:
      g_assert (g_value_get_object (value) == NULL ||
                tls->base_socket == NULL);

      if (tls->base_io_stream)
        {
          g_object_unref (tls->base_io_stream);
          tls->base_istream = NULL;
          tls->base_ostream = NULL;
        }
      tls->base_io_stream = g_value_dup_object (value);
      if (!tls->base_io_stream)
        return;

      istream = g_io_stream_get_input_stream (tls->base_io_stream);
      ostream = g_io_stream_get_output_stream (tls->base_io_stream);

      if (G_IS_POLLABLE_INPUT_STREAM (istream) &&
          g_pollable_input_stream_can_poll (G_POLLABLE_INPUT_STREAM (istream)))
        {
          tls->base_istream = G_POLLABLE_INPUT_STREAM (istream);
          tls->tls_istream = g_tls_input_stream_new (tls);
        }
      if (G_IS_POLLABLE_OUTPUT_STREAM (ostream) &&
          g_pollable_output_stream_can_poll (G_POLLABLE_OUTPUT_STREAM (ostream)))
        {
          tls->base_ostream = G_POLLABLE_OUTPUT_STREAM (ostream);
          tls->tls_ostream = g_tls_output_stream_new (tls);
        }
      break;

    case PROP_BASE_SOCKET:
      g_assert (g_value_get_object (value) == NULL ||
                tls->base_io_stream == NULL);

      g_clear_object (&tls->base_socket);
      tls->base_socket = g_value_dup_object (value);
      break;

    case PROP_REQUIRE_CLOSE_NOTIFY:
      tls->require_close_notify = g_value_get_boolean (value);
      break;

    case PROP_REHANDSHAKE_MODE:
      tls->rehandshake_mode = g_value_get_enum (value);
      break;

    case PROP_USE_SYSTEM_CERTDB:
      system_certdb = g_value_get_boolean (value);
      if (system_certdb != tls->is_system_certdb)
        {
          g_clear_object (&tls->database);
          if (system_certdb)
            {
              backend = g_tls_backend_get_default ();
              tls->database = g_tls_backend_get_default_database (backend);
            }
          tls->is_system_certdb = system_certdb;
          tls->database_is_unset = FALSE;
        }
      break;

    case PROP_DATABASE:
      g_clear_object (&tls->database);
      tls->database = g_value_dup_object (value);
      tls->is_system_certdb = FALSE;
      tls->database_is_unset = FALSE;
      break;

    case PROP_CERTIFICATE:
      if (tls->certificate)
        g_object_unref (tls->certificate);
      tls->certificate = g_value_dup_object (value);
      break;

    case PROP_INTERACTION:
      g_clear_object (&tls->interaction);
      tls->interaction = g_value_dup_object (value);
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

static gboolean
claim_op (GTlsConnectionBase    *tls,
          GTlsConnectionBaseOp   op,
          gint64                 timeout,
          GCancellable          *cancellable,
          GError               **error)
{
 try_again:
  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return FALSE;

  g_mutex_lock (&tls->op_mutex);

  if (((op == G_TLS_CONNECTION_BASE_OP_HANDSHAKE ||
        op == G_TLS_CONNECTION_BASE_OP_READ) &&
       (tls->read_closing || tls->read_closed)) ||
      ((op == G_TLS_CONNECTION_BASE_OP_HANDSHAKE ||
        op == G_TLS_CONNECTION_BASE_OP_WRITE) &&
       (tls->write_closing || tls->write_closed)))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CLOSED,
                           _("Connection is closed"));
      g_mutex_unlock (&tls->op_mutex);
      return FALSE;
    }

  if (tls->handshake_error &&
      op != G_TLS_CONNECTION_BASE_OP_CLOSE_BOTH &&
      op != G_TLS_CONNECTION_BASE_OP_CLOSE_READ &&
      op != G_TLS_CONNECTION_BASE_OP_CLOSE_WRITE)
    {
      if (error)
        *error = g_error_copy (tls->handshake_error);
      g_mutex_unlock (&tls->op_mutex);
      return FALSE;
    }

  if (op != G_TLS_CONNECTION_BASE_OP_HANDSHAKE)
    {
      if (op != G_TLS_CONNECTION_BASE_OP_CLOSE_BOTH &&
          op != G_TLS_CONNECTION_BASE_OP_CLOSE_READ &&
          op != G_TLS_CONNECTION_BASE_OP_CLOSE_WRITE &&
          tls->need_handshake && !tls->handshaking)
        {
          tls->handshaking = TRUE;
          if (!do_implicit_handshake (tls, timeout, cancellable, error))
            {
              g_cancellable_reset (tls->waiting_for_op);
              g_mutex_unlock (&tls->op_mutex);
              return FALSE;
            }
        }

      if (tls->need_finish_handshake &&
          tls->implicit_handshake)
        {
          GError *my_error = NULL;
          gboolean success;

          tls->need_finish_handshake = FALSE;

          g_mutex_unlock (&tls->op_mutex);
          success = finish_handshake (tls, tls->implicit_handshake, &my_error);
          g_clear_object (&tls->implicit_handshake);
          g_mutex_lock (&tls->op_mutex);

          if (op != G_TLS_CONNECTION_BASE_OP_CLOSE_BOTH &&
              op != G_TLS_CONNECTION_BASE_OP_CLOSE_READ &&
              op != G_TLS_CONNECTION_BASE_OP_CLOSE_WRITE &&
              (!success || g_cancellable_set_error_if_cancelled (cancellable, &my_error)))
            {
              g_propagate_error (error, my_error);
              g_mutex_unlock (&tls->op_mutex);
              return FALSE;
            }

          g_clear_error (&my_error);
        }
    }

  if ((op != G_TLS_CONNECTION_BASE_OP_WRITE && tls->reading) ||
      (op != G_TLS_CONNECTION_BASE_OP_READ && tls->writing) ||
      (op != G_TLS_CONNECTION_BASE_OP_HANDSHAKE && tls->handshaking))
    {
      GPollFD fds[2];
      int nfds;
      gint64 start_time;
      gint result = 1; /* if the loop is never entered, it's as if we cancelled early */

      g_cancellable_reset (tls->waiting_for_op);

      g_mutex_unlock (&tls->op_mutex);

      if (timeout == 0)
        {
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK,
                               _("Operation would block"));
          return FALSE;
        }

      g_cancellable_make_pollfd (tls->waiting_for_op, &fds[0]);
      if (g_cancellable_make_pollfd (cancellable, &fds[1]))
        nfds = 2;
      else
        nfds = 1;

      /* Convert from microseconds to milliseconds. */
      if (timeout != -1)
        timeout /= 1000;

      /* Poll until cancellation or the timeout is reached. */
      start_time = g_get_monotonic_time ();

      while (!g_cancellable_is_cancelled (tls->waiting_for_op) &&
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

  if (op == G_TLS_CONNECTION_BASE_OP_HANDSHAKE)
    tls->handshaking = TRUE;
  if (op == G_TLS_CONNECTION_BASE_OP_CLOSE_BOTH ||
      op == G_TLS_CONNECTION_BASE_OP_CLOSE_READ)
    tls->read_closing = TRUE;
  if (op == G_TLS_CONNECTION_BASE_OP_CLOSE_BOTH ||
      op == G_TLS_CONNECTION_BASE_OP_CLOSE_WRITE)
    tls->write_closing = TRUE;

  if (op != G_TLS_CONNECTION_BASE_OP_WRITE)
    tls->reading = TRUE;
  if (op != G_TLS_CONNECTION_BASE_OP_READ)
    tls->writing = TRUE;

  g_mutex_unlock (&tls->op_mutex);
  return TRUE;
}

static void
yield_op (GTlsConnectionBase       *tls,
          GTlsConnectionBaseOp      op,
          GTlsConnectionBaseStatus  status)
{
  g_mutex_lock (&tls->op_mutex);

  if (op == G_TLS_CONNECTION_BASE_OP_HANDSHAKE)
    tls->handshaking = FALSE;
  else if (status == G_TLS_CONNECTION_BASE_REHANDSHAKE && !tls->handshaking)
    tls->need_handshake = TRUE;

  if (op == G_TLS_CONNECTION_BASE_OP_CLOSE_BOTH ||
      op == G_TLS_CONNECTION_BASE_OP_CLOSE_READ)
    tls->read_closing = FALSE;
  if (op == G_TLS_CONNECTION_BASE_OP_CLOSE_BOTH ||
      op == G_TLS_CONNECTION_BASE_OP_CLOSE_WRITE)
    tls->write_closing = FALSE;

  if (op != G_TLS_CONNECTION_BASE_OP_WRITE)
    tls->reading = FALSE;
  if (op != G_TLS_CONNECTION_BASE_OP_READ)
    tls->writing = FALSE;

  g_cancellable_cancel (tls->waiting_for_op);
  g_mutex_unlock (&tls->op_mutex);
}

static void
g_tls_connection_base_real_push_io (GTlsConnectionBase *tls,
                                    GIOCondition        direction,
                                    gint64              timeout,
                                    GCancellable       *cancellable)
{
  if (direction & G_IO_IN)
    {
      tls->read_timeout = timeout;;
      tls->read_cancellable = cancellable;
      g_clear_error (&tls->read_error);
    }

  if (direction & G_IO_OUT)
    {
      tls->write_timeout = timeout;
      tls->write_cancellable = cancellable;
      g_clear_error (&tls->write_error);
    }
}

void
g_tls_connection_base_push_io (GTlsConnectionBase *tls,
                               GIOCondition        direction,
                               gint64              timeout,
                               GCancellable       *cancellable)
{
  g_assert (direction & (G_IO_IN | G_IO_OUT));
  g_return_if_fail (G_IS_TLS_CONNECTION_BASE (tls));

  G_TLS_CONNECTION_BASE_GET_CLASS (tls)->push_io (tls, direction,
                                                  timeout, cancellable);
}

static GTlsConnectionBaseStatus
g_tls_connection_base_real_pop_io (GTlsConnectionBase  *tls,
                                   GIOCondition         direction,
                                   gboolean             success,
                                   GError             **error)
{
  GError *my_error = NULL;

  if (direction & G_IO_IN)
    {
      tls->read_cancellable = NULL;
      if (!success)
        {
          my_error = tls->read_error;
          tls->read_error = NULL;
        }
      else
        g_clear_error (&tls->read_error);
    }
  if (direction & G_IO_OUT)
    {
      tls->write_cancellable = NULL;
      if (!success && !my_error)
        {
          my_error = tls->write_error;
          tls->write_error = NULL;
        }
      else
        g_clear_error (&tls->write_error);
    }

  if (success)
    return G_TLS_CONNECTION_BASE_OK;

  if (g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
    {
      g_propagate_error (error, my_error);
      return G_TLS_CONNECTION_BASE_WOULD_BLOCK;
    }
  else if (g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT))
    {
      g_propagate_error (error, my_error);
      return G_TLS_CONNECTION_BASE_TIMED_OUT;
    }
  else if (my_error)
    g_propagate_error (error, my_error);

  return G_TLS_CONNECTION_BASE_ERROR;
}

GTlsConnectionBaseStatus
g_tls_connection_base_pop_io (GTlsConnectionBase  *tls,
                              GIOCondition         direction,
                              gboolean             success,
                              GError             **error)
{
  g_assert (direction & (G_IO_IN | G_IO_OUT));
  g_assert (!error || !*error);
  g_return_val_if_fail (G_IS_TLS_CONNECTION_BASE (tls), G_TLS_CONNECTION_BASE_ERROR);

  return G_TLS_CONNECTION_BASE_GET_CLASS (tls)->pop_io (tls, direction,
                                                        success, error);
}

/* Checks whether the underlying base stream or GDatagramBased meets
 * @condition. */
static gboolean
g_tls_connection_base_base_check (GTlsConnectionBase *tls,
                                  GIOCondition        condition)
{
  if (g_tls_connection_base_is_dtls (tls))
    return g_datagram_based_condition_check (tls->base_socket, condition);

  if (condition & G_IO_IN)
    return g_pollable_input_stream_is_readable (tls->base_istream);

  if (condition & G_IO_OUT)
    return g_pollable_output_stream_is_writable (tls->base_ostream);

  g_assert_not_reached ();
}

/* Checks whether the (D)TLS stream meets @condition; not the underlying base
 * stream or GDatagramBased. */
gboolean
g_tls_connection_base_check (GTlsConnectionBase  *tls,
                             GIOCondition         condition)
{
  /* Racy, but worst case is that we just get WOULD_BLOCK back */
  if (tls->need_finish_handshake)
    return TRUE;

  /* If a handshake or close is in progress, then tls_istream and
   * tls_ostream are blocked, regardless of the base stream status.
   */
  if (tls->handshaking)
    return FALSE;

  if (((condition & G_IO_IN) && tls->read_closing) ||
      ((condition & G_IO_OUT) && tls->write_closing))
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

static gboolean
tls_source_prepare (GSource *source,
                    gint    *timeout)
{
  *timeout = -1;
  return FALSE;
}

static gboolean
tls_source_check (GSource *source)
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
tls_source_sync (GTlsConnectionBaseSource *tls_source)
{
  GTlsConnectionBase *tls = tls_source->tls;
  gboolean io_waiting, op_waiting;

  /* Was the source destroyed earlier in this main context iteration? */
  if (g_source_is_destroyed ((GSource *) tls_source))
    return;

  g_mutex_lock (&tls->op_mutex);
  if (((tls_source->condition & G_IO_IN) && tls->reading) ||
      ((tls_source->condition & G_IO_OUT) && tls->writing) ||
      (tls->handshaking && !tls->need_finish_handshake))
    op_waiting = TRUE;
  else
    op_waiting = FALSE;

  if (!op_waiting && !tls->need_handshake &&
      !tls->need_finish_handshake)
    io_waiting = TRUE;
  else
    io_waiting = FALSE;
  g_mutex_unlock (&tls->op_mutex);

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
    tls_source->child_source = g_cancellable_source_new (tls->waiting_for_op);
  else if (io_waiting && G_IS_DATAGRAM_BASED (tls_source->base))
    tls_source->child_source = g_datagram_based_create_source (tls->base_socket, tls_source->condition, NULL);
  else if (io_waiting && G_IS_POLLABLE_INPUT_STREAM (tls_source->base))
    tls_source->child_source = g_pollable_input_stream_create_source (tls->base_istream, NULL);
  else if (io_waiting && G_IS_POLLABLE_OUTPUT_STREAM (tls_source->base))
    tls_source->child_source = g_pollable_output_stream_create_source (tls->base_ostream, NULL);
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
g_tls_connection_tls_source_dtls_closure_callback (GObject      *stream,
                                                   GIOCondition  condition,
                                                   gpointer      data)
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

static GSourceFuncs tls_source_funcs =
{
  tls_source_prepare,
  tls_source_check,
  tls_source_dispatch,
  tls_source_finalize,
  (GSourceFunc)g_tls_connection_tls_source_closure_callback,
  (GSourceDummyMarshal)g_cclosure_marshal_generic
};

static GSourceFuncs dtls_source_funcs =
{
  tls_source_prepare,
  tls_source_check,
  tls_source_dispatch,
  tls_source_finalize,
  (GSourceFunc)g_tls_connection_tls_source_dtls_closure_callback,
  (GSourceDummyMarshal)g_cclosure_marshal_generic
};

GSource *
g_tls_connection_base_create_source (GTlsConnectionBase  *tls,
                                     GIOCondition         condition,
                                     GCancellable        *cancellable)
{
  GSource *source, *cancellable_source;
  GTlsConnectionBaseSource *tls_source;

  source = g_source_new (&tls_source_funcs, sizeof (GTlsConnectionBaseSource));

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
  else if (tls->tls_istream != NULL && condition & G_IO_IN)
    tls_source->base = G_OBJECT (tls->tls_istream);
  else if (tls->tls_ostream != NULL && condition & G_IO_OUT)
    tls_source->base = G_OBJECT (tls->tls_ostream);
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

static gboolean
g_tls_connection_base_condition_wait (GDatagramBased  *datagram_based,
                                      GIOCondition     condition,
                                      gint64           timeout,
                                      GCancellable    *cancellable,
                                      GError         **error)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (datagram_based);
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

  g_cancellable_make_pollfd (tls->waiting_for_op, &fds[0]);
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

gboolean
g_tls_connection_base_accept_peer_certificate (GTlsConnectionBase   *tls,
                                               GTlsCertificate      *peer_certificate,
                                               GTlsCertificateFlags  peer_certificate_errors)
{
  gboolean accepted = FALSE;

  if (G_IS_TLS_CLIENT_CONNECTION (tls))
    {
      GTlsCertificateFlags validation_flags;

      if (!g_tls_connection_base_is_dtls (tls))
        validation_flags =
          g_tls_client_connection_get_validation_flags (G_TLS_CLIENT_CONNECTION (tls));
      else
        validation_flags =
          g_dtls_client_connection_get_validation_flags (G_DTLS_CLIENT_CONNECTION (tls));

      if ((peer_certificate_errors & validation_flags) == 0)
        accepted = TRUE;
    }

  if (!accepted)
    {
      accepted = g_tls_connection_emit_accept_certificate (G_TLS_CONNECTION (tls),
                                                           peer_certificate,
                                                           peer_certificate_errors);
    }

  return accepted;
}

void
g_tls_connection_base_set_peer_certificate (GTlsConnectionBase   *tls,
                                            GTlsCertificate      *peer_certificate,
                                            GTlsCertificateFlags  peer_certificate_errors)
{
  g_set_object (&tls->peer_certificate, peer_certificate);

  tls->peer_certificate_errors = peer_certificate_errors;

  g_object_notify (G_OBJECT (tls), "peer-certificate");
  g_object_notify (G_OBJECT (tls), "peer-certificate-errors");
}

static void
handshake_thread (GTask        *task,
                  gpointer      object,
                  gpointer      task_data,
                  GCancellable *cancellable)
{
  GTlsConnectionBase *tls = object;
  GTlsConnectionBaseClass *tls_class = G_TLS_CONNECTION_BASE_GET_CLASS (tls);
  GError *error = NULL;
  gint64 timeout;

  /* A timeout, in microseconds, must be provided as a gint64* task_data. */
  g_assert (task_data != NULL);
  timeout = *((gint64 *)task_data);

  tls->started_handshake = FALSE;
  tls->certificate_requested = FALSE;

  if (!claim_op (tls, G_TLS_CONNECTION_BASE_OP_HANDSHAKE,
                 timeout, cancellable, &error))
    {
      g_task_return_error (task, error);
      return;
    }

  g_clear_error (&tls->handshake_error);

  if (tls->ever_handshaked && !tls->need_handshake)
    {
      GTlsConnectionBaseStatus status;

      status = tls_class->request_rehandshake (tls, timeout, cancellable, &error);
      if (status != G_TLS_CONNECTION_BASE_OK)
        {
          g_task_return_error (task, error);
          return;
        }
    }

  g_clear_object (&tls->peer_certificate);
  tls->peer_certificate_errors = 0;

  tls->started_handshake = TRUE;
  tls_class->handshake (tls, timeout, cancellable, &error);
  tls->need_handshake = FALSE;

  if (error)
    {
      if ((g_error_matches (error, G_IO_ERROR, G_IO_ERROR_FAILED) ||
           g_error_matches (error, G_IO_ERROR, G_IO_ERROR_BROKEN_PIPE) ||
           g_error_matches (error, G_TLS_ERROR, G_TLS_ERROR_NOT_TLS)) &&
          tls->certificate_requested)
        {
          g_clear_error (&error);
          if (tls->certificate_error)
            {
              error = tls->certificate_error;
              tls->certificate_error = NULL;
            }
          else
            {
              g_set_error_literal (&error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED,
                                   _("Server required TLS certificate"));
            }
        }
      g_task_return_error (task, error);
    }
  else
    {
      tls->ever_handshaked = TRUE;
      g_task_return_boolean (task, TRUE);
    }
}

static gboolean
finish_handshake (GTlsConnectionBase  *tls,
                  GTask               *task,
                  GError             **error)
{
  GTlsConnectionBaseClass *tls_class = G_TLS_CONNECTION_BASE_GET_CLASS (tls);
  GError *my_error = NULL;

  if (g_task_propagate_boolean (task, &my_error))
    tls_class->complete_handshake (tls, &my_error);

  if (my_error && tls->started_handshake)
    tls->handshake_error = g_error_copy (my_error);

  if (!my_error)
    return TRUE;

  g_propagate_error (error, my_error);
  return FALSE;
}

static gboolean
g_tls_connection_base_handshake (GTlsConnection   *conn,
                                 GCancellable     *cancellable,
                                 GError          **error)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (conn);
  GTask *task;
  gboolean success;
  gint64 *timeout = NULL;
  GError *my_error = NULL;

  task = g_task_new (conn, cancellable, NULL, NULL);
  g_task_set_source_tag (task, g_tls_connection_base_handshake);

  timeout = g_new0 (gint64, 1);
  *timeout = -1; /* blocking */
  g_task_set_task_data (task, timeout, g_free);

  g_task_run_in_thread_sync (task, handshake_thread);
  success = finish_handshake (tls, task, &my_error);
  g_object_unref (task);

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
 * handshake_thread() and then call handshake_thread_completed(), and
 * a second to call the caller's original callback after we call
 * finish_handshake().
 */

static void
handshake_thread_completed (GObject      *object,
                            GAsyncResult *result,
                            gpointer      user_data)
{
  GTask *caller_task = user_data;
  GTlsConnectionBase *tls = g_task_get_source_object (caller_task);
  GError *error = NULL;
  gboolean need_finish_handshake, success;

  g_mutex_lock (&tls->op_mutex);
  if (tls->need_finish_handshake)
    {
      need_finish_handshake = TRUE;
      tls->need_finish_handshake = FALSE;
    }
  else
    need_finish_handshake = FALSE;
  g_mutex_unlock (&tls->op_mutex);

  if (need_finish_handshake)
    {
      success = finish_handshake (tls, G_TASK (result), &error);
      if (success)
        g_task_return_boolean (caller_task, TRUE);
      else
        g_task_return_error (caller_task, error);
    }
  else if (tls->handshake_error)
    g_task_return_error (caller_task, g_error_copy (tls->handshake_error));
  else
    g_task_return_boolean (caller_task, TRUE);

  g_object_unref (caller_task);
}

static void
async_handshake_thread (GTask        *task,
                        gpointer      object,
                        gpointer      task_data,
                        GCancellable *cancellable)
{
  GTlsConnectionBase *tls = object;

  handshake_thread (task, object, task_data, cancellable);

  g_mutex_lock (&tls->op_mutex);
  tls->need_finish_handshake = TRUE;
  /* yield_op will clear handshaking too, but we don't want the
   * connection to be briefly "handshaking && need_finish_handshake"
   * after we unlock the mutex.
   */
  tls->handshaking = FALSE;
  g_mutex_unlock (&tls->op_mutex);

  yield_op (tls, G_TLS_CONNECTION_BASE_OP_HANDSHAKE,
            G_TLS_CONNECTION_BASE_OK);
}

static void
g_tls_connection_base_handshake_async (GTlsConnection       *conn,
                                       int                   io_priority,
                                       GCancellable         *cancellable,
                                       GAsyncReadyCallback   callback,
                                       gpointer              user_data)
{
  GTask *thread_task, *caller_task;
  gint64 *timeout = NULL;

  caller_task = g_task_new (conn, cancellable, callback, user_data);
  g_task_set_source_tag (caller_task, g_tls_connection_base_handshake_async);
  g_task_set_priority (caller_task, io_priority);
  thread_task = g_task_new (conn, cancellable, handshake_thread_completed, caller_task);
  g_task_set_source_tag (thread_task, g_tls_connection_base_handshake_async);
  g_task_set_priority (thread_task, io_priority);

  timeout = g_new0 (gint64, 1);
  *timeout = -1; /* blocking */
  g_task_set_task_data (thread_task, timeout, g_free);

  g_task_run_in_thread (thread_task, async_handshake_thread);
  g_object_unref (thread_task);
}

static gboolean
g_tls_connection_base_handshake_finish (GTlsConnection       *conn,
                                        GAsyncResult         *result,
                                        GError              **error)
{
  g_return_val_if_fail (g_task_is_valid (result, conn), FALSE);

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

static void
implicit_handshake_completed (GObject      *object,
                              GAsyncResult *result,
                              gpointer      user_data)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (object);

  g_mutex_lock (&tls->op_mutex);
  tls->need_finish_handshake = TRUE;
  g_mutex_unlock (&tls->op_mutex);

  yield_op (tls, G_TLS_CONNECTION_BASE_OP_HANDSHAKE,
            G_TLS_CONNECTION_BASE_OK);
}

static gboolean
do_implicit_handshake (GTlsConnectionBase  *tls,
                       gint64               timeout,
                       GCancellable        *cancellable,
                       GError             **error)
{
  gint64 *thread_timeout = NULL;

  /* We have op_mutex */

  g_assert (tls->implicit_handshake == NULL);
  tls->implicit_handshake = g_task_new (tls, cancellable,
                                        implicit_handshake_completed,
                                        NULL);
  g_task_set_source_tag (tls->implicit_handshake, do_implicit_handshake);

  thread_timeout = g_new0 (gint64, 1);
  g_task_set_task_data (tls->implicit_handshake,
                        thread_timeout, g_free);

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

      g_mutex_unlock (&tls->op_mutex);
      g_task_run_in_thread_sync (tls->implicit_handshake,
                                 handshake_thread);
      success = finish_handshake (tls,
                                  tls->implicit_handshake,
                                  &my_error);
      g_clear_object (&tls->implicit_handshake);
      yield_op (tls, G_TLS_CONNECTION_BASE_OP_HANDSHAKE,
                G_TLS_CONNECTION_BASE_OK);
      g_mutex_lock (&tls->op_mutex);

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
      *thread_timeout = -1; /* blocking */

      g_task_run_in_thread (tls->implicit_handshake,
                            handshake_thread);

      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK,
                           _("Operation would block"));
      return FALSE;
    }
}

gssize
g_tls_connection_base_read (GTlsConnectionBase  *tls,
                            void                *buffer,
                            gsize                count,
                            gint64               timeout,
                            GCancellable        *cancellable,
                            GError             **error)
{
  GTlsConnectionBaseStatus status;
  gssize nread;

  do
    {
      if (!claim_op (tls, G_TLS_CONNECTION_BASE_OP_READ,
                     timeout, cancellable, error))
        return -1;

      if (tls->app_data_buf && !tls->handshaking)
        {
          nread = MIN (count, tls->app_data_buf->len);
          memcpy (buffer, tls->app_data_buf->data, nread);
          if (nread == tls->app_data_buf->len)
            g_clear_pointer (&tls->app_data_buf, g_byte_array_unref);
          else
            g_byte_array_remove_range (tls->app_data_buf, 0, nread);
          status = G_TLS_CONNECTION_BASE_OK;
        }
      else
        {
          status = G_TLS_CONNECTION_BASE_GET_CLASS (tls)->
            read_fn (tls, buffer, count, timeout, &nread, cancellable, error);
        }

      yield_op (tls, G_TLS_CONNECTION_BASE_OP_READ, status);
    }
  while (status == G_TLS_CONNECTION_BASE_REHANDSHAKE);

  if (status == G_TLS_CONNECTION_BASE_OK)
    return nread;
  else
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
  GTlsConnectionBaseStatus status;
  gssize nread;

  do {
    if (!claim_op (tls, G_TLS_CONNECTION_BASE_OP_READ,
                   timeout, cancellable, error))
      return -1;

    /* Copy data out of the app data buffer first. */
    if (tls->app_data_buf && !tls->handshaking)
      {
        nread = 0;

        for (guint i = 0; i < num_vectors; i++)
          {
            gsize count;
            GInputVector *vec = &vectors[i];

            count = MIN (vec->size, tls->app_data_buf->len);
            nread += count;

            memcpy (vec->buffer, tls->app_data_buf->data, count);
            if (count == tls->app_data_buf->len)
              g_clear_pointer (&tls->app_data_buf, g_byte_array_unref);
            else
              g_byte_array_remove_range (tls->app_data_buf, 0, count);
            status = G_TLS_CONNECTION_BASE_OK;
          }
      }
    else
      {
        status = G_TLS_CONNECTION_BASE_GET_CLASS (tls)->
          read_message_fn (tls, vectors, num_vectors, timeout, &nread, cancellable, error);
      }

    yield_op (tls, G_TLS_CONNECTION_BASE_OP_READ, status);
  } while (status == G_TLS_CONNECTION_BASE_REHANDSHAKE);

  if (status == G_TLS_CONNECTION_BASE_OK)
    return nread;
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
  GTlsConnectionBase *tls;
  guint i;
  GError *child_error = NULL;

  tls = G_TLS_CONNECTION_BASE (datagram_based);

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

      n_bytes_read = g_tls_connection_base_read_message (tls,
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
g_tls_connection_base_write (GTlsConnectionBase  *tls,
                             const void          *buffer,
                             gsize                count,
                             gint64               timeout,
                             GCancellable        *cancellable,
                             GError             **error)
{
  GTlsConnectionBaseStatus status;
  gssize nwrote;

  do
    {
      if (!claim_op (tls, G_TLS_CONNECTION_BASE_OP_WRITE,
                     timeout, cancellable, error))
        return -1;

      status = G_TLS_CONNECTION_BASE_GET_CLASS (tls)->
        write_fn (tls, buffer, count, timeout, &nwrote, cancellable, error);

      yield_op (tls, G_TLS_CONNECTION_BASE_OP_WRITE, status);
    }
  while (status == G_TLS_CONNECTION_BASE_REHANDSHAKE);

  if (status == G_TLS_CONNECTION_BASE_OK)
    return nwrote;
  else
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
  GTlsConnectionBaseStatus status;
  gssize nwrote;

  do {
    if (!claim_op (tls, G_TLS_CONNECTION_BASE_OP_WRITE,
                   timeout, cancellable, error))
      return -1;

    status = G_TLS_CONNECTION_BASE_GET_CLASS (tls)->
      write_message_fn (tls, vectors, num_vectors, timeout, &nwrote, cancellable, error);

    yield_op (tls, G_TLS_CONNECTION_BASE_OP_WRITE, status);
  } while (status == G_TLS_CONNECTION_BASE_REHANDSHAKE);

  if (status == G_TLS_CONNECTION_BASE_OK)
    return nwrote;
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
  GTlsConnectionBase *tls;
  guint i;
  GError *child_error = NULL;

  tls = G_TLS_CONNECTION_BASE (datagram_based);

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

  if (child_error != NULL)
    {
      g_propagate_error (error, child_error);
      return -1;
    }

  return i;
}

static GInputStream *
g_tls_connection_base_get_input_stream (GIOStream *stream)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (stream);

  return tls->tls_istream;
}

static GOutputStream *
g_tls_connection_base_get_output_stream (GIOStream *stream)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (stream);

  return tls->tls_ostream;
}

gboolean
g_tls_connection_base_close_internal (GIOStream      *stream,
                                      GTlsDirection   direction,
                                      gint64          timeout,
                                      GCancellable   *cancellable,
                                      GError        **error)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (stream);
  GTlsConnectionBaseOp op;
  GTlsConnectionBaseStatus status;
  gboolean success = TRUE;
  GError *close_error = NULL, *stream_error = NULL;

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

  if (tls->ever_handshaked && !tls->write_closed &&
      direction & G_TLS_DIRECTION_WRITE)
    {
      status = G_TLS_CONNECTION_BASE_GET_CLASS (tls)->
        close_fn (tls, timeout, cancellable, &close_error);

      tls->write_closed = TRUE;
    }
  else
    status = G_TLS_CONNECTION_BASE_OK;

  if (!tls->read_closed && direction & G_TLS_DIRECTION_READ)
    tls->read_closed = TRUE;

  /* Close the underlying streams. Do this even if the close_fn() call failed,
   * as the parent GIOStream will have set its internal closed flag and hence
   * this implementation will never be called again. */
  if (tls->base_io_stream != NULL)
    {
      if (direction == G_TLS_DIRECTION_BOTH)
        success = g_io_stream_close (tls->base_io_stream,
                                     cancellable, &stream_error);
      else if (direction & G_TLS_DIRECTION_READ)
        success = g_input_stream_close (g_io_stream_get_input_stream (tls->base_io_stream),
                                        cancellable, &stream_error);
      else if (direction & G_TLS_DIRECTION_WRITE)
        success = g_output_stream_close (g_io_stream_get_output_stream (tls->base_io_stream),
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
      g_propagate_error (error, close_error);
      g_clear_error (&stream_error);
    }
  else if (!success)
    {
      g_propagate_error (error, stream_error);
      g_clear_error (&close_error);
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

  return g_task_propagate_boolean (G_TASK (result), error);
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

  klass->push_io = g_tls_connection_base_real_push_io;
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
