/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
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

#include "gtlsthread.h"

#include <glib/gi18n-lib.h>
#include <glib/gstdio.h>

/* The purpose of this class is to ensure the underlying TLS library is only
 * ever used on a single thread. There are multiple benefits of this:
 *
 * - OpenSSL objects like the SSL* are not threadsafe and must only be accessed
 *   from a single thread.
 *
 * - With GnuTLS, this dramatically simplifies implementation of post-handshake
 *   authentication and alerts, which are hard to handle when the
 *   gnutls_session_t may be used on multiple threads at once. Moving
 *   gnutls_session_t use to a single thread should also make it easier to
 *   implement support for downloading missing certificates using the
 *   Authority Information Access extension.
 *
 * - GTlsConnectionBase and its subclasses are very complicated, and it has
 *   become difficult to ensure the correctness of the code considering that the
 *   threadsafety semantics of its parent class, GIOStream, allow it to be used
 *   from separate reader and writer threads simultaneously.
 *
 * While the TLS thread class is intended to simplify our code, it has one
 * disadvantage: the TLS thread *must never block* because GIOStream users are
 * allowed to do a sync read and a sync write simultaneously in separate threads
 * threads. Consider a hypothetical scenario:
 *
 * (1) Application starts a read on thread A
 * (2) Application starts a write on thread B
 * (3) Application's peer waits for the write to complete before sending data.
 *
 * In this scenario, the read on thread A is stalled until the write on thread B
 * is completed. The application is allowed to do this and expect it to work,
 * because GIOStream says it will work. If our TLS thread were to block on the
 * read, then the write would never start, and the read could never complete.
 * This means that underlying TLS operations must use async I/O.
 */
struct _GTlsThread {
  GObject parent_instance;

  GTlsConnectionBase *connection; /* unowned */

  GThread *op_thread;
  GMainContext *op_thread_context;

  /* When pushing ops onto the queue, call g_main_context_wakeup() on
   * op_thread_context to ensure the op is noticed.
   */
  GAsyncQueue *queue;
};

typedef enum {
  G_TLS_THREAD_OP_READ,
  G_TLS_THREAD_OP_SHUTDOWN
} GTlsThreadOperationType;

typedef struct {
  GTlsThreadOperationType type;
  GIOCondition condition;
  GTlsConnectionBase *connection; /* FIXME: threadsafety nightmare, not OK */
  void *data; /* unowned */
  gsize size;
  gint64 timeout;
  GCancellable *cancellable;
  GMainLoop *main_loop; /* Running on the ORIGINAL thread, not the op thread. */
  GTlsConnectionBaseStatus result;
  gssize count; /* Bytes read or written */
  GError *error;
} GTlsThreadOperation;

static gboolean process_op (GAsyncQueue         *queue,
                            GTlsThreadOperation *delayed_op,
                            GMainLoop           *main_loop);

static void GTLS_OP_DEBUG (GTlsThreadOperation *op,
                           const char          *message,
                           ...) G_GNUC_UNUSED;

enum
{
  PROP_0,
  PROP_TLS_CONNECTION,
  LAST_PROP
};

static GParamSpec *obj_properties[LAST_PROP];

G_DEFINE_TYPE (GTlsThread, g_tls_thread, G_TYPE_OBJECT)

static GTlsThreadOperation *
g_tls_thread_operation_new (GTlsThreadOperationType  type,
                            GTlsConnectionBase      *connection,
                            void                    *data,
                            gsize                    size,
                            gint64                   timeout,
                            GCancellable            *cancellable,
                            GMainLoop               *main_loop)
{
  GTlsThreadOperation *op;

  op = g_new0 (GTlsThreadOperation, 1);
  op->type = type;
  op->connection = g_object_ref (connection);
  op->data = data;
  op->size = size;
  op->timeout = timeout;
  op->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
  op->main_loop = g_main_loop_ref (main_loop);

  switch (type)
    {
    case G_TLS_THREAD_OP_READ:
      op->condition = G_IO_IN;
      break;
    case G_TLS_THREAD_OP_SHUTDOWN:
      break;
    }

  return op;
}

static GTlsThreadOperation *
g_tls_thread_shutdown_operation_new (void)
{
  GTlsThreadOperation *op;

  op = g_new0 (GTlsThreadOperation, 1);
  op->type = G_TLS_THREAD_OP_SHUTDOWN;

  return op;
}

static void
g_tls_thread_operation_free (GTlsThreadOperation *op)
{
  g_clear_object (&op->connection);
  g_clear_object (&op->cancellable);
  g_clear_pointer (&op->main_loop, g_main_loop_unref);
  g_free (op);
}

GTlsConnectionBaseStatus
g_tls_thread_read (GTlsThread    *self,
                   void          *buffer,
                   gsize          size,
                   gint64         timeout,
                   gssize        *nread,
                   GCancellable  *cancellable,
                   GError       **error)
{
  GTlsThreadOperation *op;
  GMainContext *main_context;
  GMainLoop *main_loop;
  GTlsConnectionBaseStatus result;

  main_context = g_main_context_new ();
  main_loop = g_main_loop_new (main_context, FALSE);
  op = g_tls_thread_operation_new (G_TLS_THREAD_OP_READ,
                                   self->connection,
                                   buffer, size, timeout,
                                   cancellable, main_loop);
  g_async_queue_push (self->queue, op);
  g_main_context_wakeup (self->op_thread_context);
GTLS_OP_DEBUG (op, "%s: timeout=%zd: starting read...", __FUNCTION__, timeout);
  g_main_loop_run (main_loop);

  *nread = op->count;

  if (op->error)
    {
      g_propagate_error (error, op->error);
      op->error = NULL;
    }

GTLS_OP_DEBUG (op, "%s: nread=%zd error=%s", __FUNCTION__, *nread, error && *error ? (*error)->message : NULL);

  result = op->result;

  g_tls_thread_operation_free (op);
  g_main_context_unref (main_context);
  g_main_loop_unref (main_loop);

  return result;
}

typedef struct {
  GSource source;

  GAsyncQueue *queue;
} GTlsOpQueueSource;

typedef gboolean (*GTlsOpQueueSourceFunc) (GAsyncQueue         *queue,
                                           GTlsThreadOperation *op,
                                           GMainLoop           *main_loop);

static gboolean
queue_has_pending_op (GAsyncQueue *queue)
{
  GTlsThreadOperation *op;
  gboolean ready = FALSE;

  g_async_queue_lock (queue);

  op = g_async_queue_try_pop_unlocked (queue);
  if (op)
    {
      g_async_queue_push_front_unlocked (queue, op);
      ready = TRUE;
    }

  g_async_queue_unlock (queue);

  return ready;
}

static gboolean
tls_op_queue_source_prepare (GSource *source,
                             gint    *timeout)
{
  GTlsOpQueueSource *op_source = (GTlsOpQueueSource *)source;
  gboolean ready;

  ready = queue_has_pending_op (op_source->queue);

  /* If we are ready to dispatch, timeout should be 0 to ensure poll() returns
   * immediately. Otherwise, we are in no hurry and can wait "forever." If
   * a new op is pushed onto the queue, the code performing the push is
   * responsible for calling g_main_context_wakeup() to end the wait.
   */
  *timeout = ready ? 0 : -1;

  return ready;
}

static gboolean
tls_op_queue_source_check (GSource *source)
{
  GTlsOpQueueSource *op_source = (GTlsOpQueueSource *)source;

  return queue_has_pending_op (op_source->queue);
}

static gboolean
tls_op_queue_source_dispatch (GSource     *source,
                              GSourceFunc  callback,
                              gpointer     user_data)
{
  GTlsOpQueueSource *op_source = (GTlsOpQueueSource *)source;

  return ((GTlsOpQueueSourceFunc)callback) (op_source->queue,
                                            NULL, /* no delayed source */
                                            user_data);
}

static void
tls_op_queue_source_finalize (GSource *source)
{
  GTlsOpQueueSource *op_source = (GTlsOpQueueSource *)source;

  g_async_queue_unref (op_source->queue);
}

static gboolean
tls_op_queue_source_closure_callback (GAsyncQueue *queue,
                                      GMainLoop   *main_loop,
                                      gpointer     data)
{
  GClosure *closure = data;

  GValue param[3] = { G_VALUE_INIT, G_VALUE_INIT, G_VALUE_INIT };
  GValue result_value = G_VALUE_INIT;
  gboolean result;

  g_value_init (&result_value, G_TYPE_BOOLEAN);

  g_value_init (&param[0], G_TYPE_POINTER);
  g_value_set_pointer (&param[0], queue);
  g_value_init (&param[1], G_TYPE_POINTER);
  g_value_set_pointer (&param[1], NULL);
  g_value_init (&param[2], G_TYPE_MAIN_LOOP);
  g_value_set_pointer (&param[2], main_loop);

  g_closure_invoke (closure, &result_value, 3, param, NULL);

  result = g_value_get_boolean (&result_value);
  g_value_unset (&result_value);
  g_value_unset (&param[0]);
  g_value_unset (&param[1]);
  g_value_unset (&param[2]);

  return result;
}

static GSourceFuncs tls_op_queue_source_funcs =
{
  tls_op_queue_source_prepare,
  tls_op_queue_source_check,
  tls_op_queue_source_dispatch,
  tls_op_queue_source_finalize,
  (GSourceFunc)tls_op_queue_source_closure_callback,
  (GSourceDummyMarshal)g_cclosure_marshal_generic
};

static GSource *
tls_op_queue_source_new (GAsyncQueue *queue)
{
  GTlsOpQueueSource *source;

  source = (GTlsOpQueueSource *)g_source_new (&tls_op_queue_source_funcs, sizeof (GTlsOpQueueSource));
  source->queue = g_async_queue_ref (queue);

  return (GSource *)source;
}

typedef struct
{
  GAsyncQueue *queue;
  GTlsThreadOperation *op;
  GMainLoop *main_loop;
} DelayedOpAsyncData;

static DelayedOpAsyncData *
delayed_op_async_data_new (GAsyncQueue         *queue,
                           GTlsThreadOperation *op,
                           GMainLoop           *main_loop)
{
  DelayedOpAsyncData *data;

  data = g_new (DelayedOpAsyncData, 1);

  /* No refs because these are guaranteed to outlive data. */
  data->queue = queue;
  data->op = op;
  data->main_loop = main_loop;

  return data;
}

static void
delayed_op_async_data_free (DelayedOpAsyncData *data)
{
  g_free (data);
}

static gboolean
resume_tls_op (GObject  *pollable_stream,
               gpointer  user_data)
{
  DelayedOpAsyncData *data = (DelayedOpAsyncData *)user_data;
  gboolean ret;
GTLS_OP_DEBUG (data->op, "%s: resuming op %p", __FUNCTION__, data->op);
  ret = process_op (data->queue, data->op, data->main_loop);
  g_assert (ret == G_SOURCE_CONTINUE);

  delayed_op_async_data_free (data);

  return G_SOURCE_REMOVE;
}

static gboolean
resume_dtls_op (GDatagramBased *datagram_based,
                GIOCondition    condition,
                gpointer        user_data)
{
  DelayedOpAsyncData *data = (DelayedOpAsyncData *)user_data;
  gboolean ret;

  ret = process_op (data->queue, data->op, data->main_loop);
  g_assert (ret == G_SOURCE_CONTINUE);

  delayed_op_async_data_free (data);

  return G_SOURCE_REMOVE;
}

/* Use a custom dummy callback instead of g_source_set_dummy_callback(), as that
 * uses a GClosure and is slow. (The GClosure is necessary to deal with any
 * function prototype.)
 */
static gboolean
dummy_callback (gpointer data)
{
  return G_SOURCE_CONTINUE;
}

static gboolean
process_op (GAsyncQueue         *queue,
            GTlsThreadOperation *delayed_op,
            GMainLoop           *main_loop)
{
  GTlsThreadOperation *op;

  /* There are three reasons this function could be called:
   *
   * (1) A delayed operation is ready to perform I/O.
   * (2) A delayed operation has timed out.
   * (3) A new operation has been added to the queue.
   */
  if (delayed_op)
    {
      op = delayed_op;
GTLS_OP_DEBUG (op, "%s: delayed_op=%p type=%d", __FUNCTION__, delayed_op, op->type);
      if (!g_tls_connection_base_check (op->connection, op->condition))
        {
          /* Not ready. Either we timed out, or were cancelled. */
          /* FIXME: very fragile, assumes op->cancellable is the GTlsConnectionBase's cancellable */
          if (g_cancellable_is_cancelled (op->cancellable))
            {
              GTLS_OP_DEBUG (op, "Delayed op %p cancelled!", op);
              op->count = 0;
              g_clear_error (&op->error);
              g_set_error (&op->error, G_IO_ERROR, G_IO_ERROR_CANCELLED,
                           _("Operation cancelled"));
              goto finished;
            }
          else /* FIXME: this could trigger if GTlsConnectionBase yielded an op, even if op isn't ready. We need to do the check timeout/reschedule dance */
            {
              GTLS_OP_DEBUG (op, "Delayed op %p timed out!", op);
              g_assert (op->timeout != -1);
              op->count = 0;
              g_clear_error (&op->error);
              g_set_error (&op->error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                           _("Socket I/O timed out"));
              goto finished;
            }
        }
    }
  else
    {
      op = g_async_queue_try_pop (queue);
      g_assert (op);
GTLS_OP_DEBUG (op, "%s: New op %p from queue", __FUNCTION__, op);
      if (op->type == G_TLS_THREAD_OP_SHUTDOWN)
        {
          /* Note that main_loop is running on here on the op thread for the
           * lifetime of this GTlsThread. This will shut down the whole thing. This
           * is different from op->main_loop, which runs on the original thread.
           */
          g_main_loop_quit (main_loop);
          return G_SOURCE_REMOVE;
        }
    }

  switch (op->type)
    {
    /* FIXME: handle all op types, including handshake and directional closes */
    case G_TLS_THREAD_OP_READ:
      op->result = G_TLS_CONNECTION_BASE_GET_CLASS (op->connection)->read_fn (op->connection,
                                                                              op->data, op->size,
                                                                              &op->count,
                                                                              op->cancellable,
                                                                              &op->error);
      break;
    case G_TLS_THREAD_OP_SHUTDOWN:
      g_assert_not_reached ();
    }

  if (op->result == G_TLS_CONNECTION_BASE_WOULD_BLOCK &&
      op->timeout != 0)
    {
      GSource *tls_source;
      GSource *timeout_source;
      GMainContext *main_context;
      DelayedOpAsyncData *data;

      tls_source = g_tls_connection_base_create_source (op->connection,
                                                        op->condition,
                                                        op->cancellable);
      if (op->timeout > 0)
        {
          /* tls_source should fire if (a) we're ready to ready/write without
           * blocking, or (b) the timeout has elasped.
           */
          timeout_source = g_timeout_source_new (op->timeout);
          g_source_set_callback (timeout_source, dummy_callback, NULL, NULL);
          g_source_add_child_source (tls_source, timeout_source);
          g_source_unref (timeout_source);
        }

      data = delayed_op_async_data_new (queue, op, main_loop);
      if (g_tls_connection_base_is_dtls (op->connection))
        g_source_set_callback (tls_source, G_SOURCE_FUNC (resume_dtls_op), data, NULL);
      else
        g_source_set_callback (tls_source, G_SOURCE_FUNC (resume_tls_op), data, NULL);
GTLS_OP_DEBUG (op, "%s: created tls_source %p for op %p", __FUNCTION__, tls_source, op);
      main_context = g_main_loop_get_context (main_loop);
      g_source_attach (tls_source, main_context);
      g_source_unref (tls_source);

      return G_SOURCE_CONTINUE;
    }

finished:
  /* op->main_loop is running on the original thread to block the original
   * thread until op has completed on the op thread, which it just has.
   * This is different from main_loop, which is running the op thread.
   */
  g_main_loop_quit (op->main_loop);

  return G_SOURCE_CONTINUE;
}

static gpointer
tls_op_thread (gpointer data)
{
  GTlsThread *self = G_TLS_THREAD (data);
  GMainLoop *main_loop;
  GSource *source;

  main_loop = g_main_loop_new (self->op_thread_context, FALSE);

  g_main_context_push_thread_default (self->op_thread_context);

  source = tls_op_queue_source_new (self->queue);
  g_source_set_callback (source, G_SOURCE_FUNC (process_op), main_loop, NULL);
  g_source_attach (source, self->op_thread_context);
  g_source_unref (source);

  g_main_loop_run (main_loop);

  /* FIXME FIXME: what happens if there are still ops in progress?
   * They should be cancelled somehow. Figure out how. Assert this has happened?
   */

  g_main_context_pop_thread_default (self->op_thread_context);

  g_main_loop_unref (main_loop);

  return NULL;
}

static void
g_tls_thread_get_property (GObject    *object,
                           guint       prop_id,
                           GValue     *value,
                           GParamSpec *pspec)
{
  GTlsThread *self = G_TLS_THREAD (object);

  switch (prop_id)
    {
    case PROP_TLS_CONNECTION:
      g_assert (self->connection);
      g_value_set_object (value, self->connection);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_thread_set_property (GObject      *object,
                           guint         prop_id,
                           const GValue *value,
                           GParamSpec   *pspec)
{
  GTlsThread *self = G_TLS_THREAD (object);

  switch (prop_id)
    {
    case PROP_TLS_CONNECTION:
      self->connection = g_value_get_object (value);

      /* This weak pointer is not required for correctness, because the
       * GTlsThread should never outlive its GTlsConnection. It's only here
       * as a sanity-check and debugging aid, to ensure self->connection
       * isn't ever dangling.
       */
      g_object_add_weak_pointer (G_OBJECT (self->connection),
                                 (gpointer *)&self->connection);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_thread_init (GTlsThread *self)
{
  self->queue = g_async_queue_new ();
  self->op_thread_context = g_main_context_new ();
  self->op_thread = g_thread_new ("[glib-networking] GTlsThreadBase TLS operations thread",
                                  tls_op_thread,
                                  self);
}

static void
g_tls_thread_finalize (GObject *object)
{
  GTlsThread *self = G_TLS_THREAD (object);
  GTlsThreadOperation *op;

  op = g_tls_thread_shutdown_operation_new ();
  g_async_queue_push (self->queue, op);
  g_main_context_wakeup (self->op_thread_context);

  g_clear_pointer (&self->op_thread, g_thread_join);
  g_clear_pointer (&self->op_thread_context, g_main_context_unref);
  g_clear_pointer (&self->queue, g_async_queue_unref);
  g_tls_thread_operation_free (op);

  g_clear_weak_pointer (&self->connection);

  G_OBJECT_CLASS (g_tls_thread_parent_class)->finalize (object);
}

static void
g_tls_thread_class_init (GTlsThreadClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize     = g_tls_thread_finalize;
  gobject_class->get_property = g_tls_thread_get_property;
  gobject_class->set_property = g_tls_thread_set_property;

  obj_properties[PROP_TLS_CONNECTION] =
    g_param_spec_object ("tls-connection",
                         "TLS Connection",
                         "The thread's GTlsConnection",
                         G_TYPE_TLS_CONNECTION_BASE,
                         G_PARAM_READABLE | G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

  g_object_class_install_properties (gobject_class, LAST_PROP, obj_properties);
}

GTlsThread *
g_tls_thread_new (GTlsConnectionBase *tls)
{
  GTlsThread *thread;

  thread = g_object_new (G_TYPE_TLS_THREAD,
                         "tls-connection", tls,
                         NULL);
  return thread;
}

// FIXME: Redundant
static void
GTLS_OP_DEBUG (GTlsThreadOperation *op,
               const char          *message,
               ...)
{
  char *result = NULL;
  GTlsConnection *connection = op->connection ? G_TLS_CONNECTION (op->connection) : NULL;
  int ret;
  va_list args;

  va_start (args, message);

  ret = g_vasprintf (&result, message, args);
  g_assert (ret > 0);

  if (!connection)
    g_printf ("(Shutdown op): ");
  else if (G_IS_TLS_CLIENT_CONNECTION (connection))
    g_printf ("CLIENT %p: ", connection);
  else if (G_IS_TLS_SERVER_CONNECTION (connection))
    g_printf ("SERVER %p: ", connection);
  else
    g_assert_not_reached ();

  g_printf ("%s\n", result);

  fflush (stdout);

  g_free (result);
  va_end (args);
}
