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

#include "gtlsthread-base.h"

/* The purpose of this class is to ensure the underlying TLS library is only
 * ever used on a single thread. There are multiple benefits of this:
 *
 * - OpenSSL objects like the SSL* are not threadsafe and must only be accessed
 *   from a single thread.
 *
 * - With GnuTLS, this dramatically simplifies implementation of post-handshake
 *   authentication and alerts, which are hard to handle when the
 *   gnutls_session_t may be used on multiple threads at once.
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
 * This means that underlying TLS operations must use async I/O. To emulate
 * blocking operations, we will have to use poll().
 */
typedef struct {
  GThread *thread;
  GAsyncQueue *queue;
} GTlsThreadBasePrivate;

typedef enum {
  G_TLS_THREAD_OP_READ,
  G_TLS_THREAD_OP_SHUTDOWN
} GTlsThreadOperationType;

typedef struct {
  GTlsThreadOperationType type;
  void *data; /* unowned */
  gsize size;
  gint64 timeout;
  GCancellable *cancellable;
  GMainLoop *main_loop;
  gint result;
} GTlsThreadOperation;

G_DEFINE_ABSTRACT_TYPE_WITH_PRIVATE (GTlsThreadBase, g_tls_thread_base, G_TYPE_TLS_THREAD_BASE)

static GTlsThreadOperation *
g_tls_thread_operation_new (GTlsThreadOperationType  type,
                            void                    *data,
                            gsize                    size,
                            gint64                   timeout,
                            GCancellable            *cancellable,
                            GMainLoop               *main_loop,
                            gint                     result)
{
  GTlsThreadOperation *op;

  op = g_new (GTlsThreadOperation, 1);
  op->type = type;
  op->data = data;
  op->size = size;
  op->timeout = timeout;
  op->cancellable = g_object_ref (cancellable);
  op->main_loop = g_main_loop_ref (main_loop);
  op->result = 0;

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
  g_clear_pointer (&op->data, g_free);
  g_clear_object (&op->cancellable);
  g_clear_pointer (&op->main_context, g_main_loop_unref);
  g_free (op);
}

gssize
g_tls_thread_base_read (GTlsThreadBase  *tls,
                        void            *buffer,
                        gsize            size,
                        gint64           timeout,
                        GCancellable    *cancellable,
                        GError         **error)
{
  GTlsThreadBasePrivate *priv = g_tls_thread_base_get_instance_private (tls);
  GTlsThreadOperation *op;
  GMainContext *main_context;
  GMainLoop *main_loop;

  main_context = g_main_context_new ();
  main_loop = g_main_loop_new (main_context, FALSE);
  op = g_tls_thread_operation_new (G_TLS_THREAD_OP_READ,
                                   buffer, size, timeout,
                                   cancellable, main_loop);
  g_async_queue_push (priv->queue, op);

  /* FIXME: must respect timeout somehow */
  g_main_loop_run (main_loop);

  /* FIXME: do something with result */

  g_main_context_unref (main_context);
  g_main_loop_unref (main_loop);
}

static gpointer
tls_thread (gpointer data)
{
  GAsyncQueue *queue = g_object_ref (data);
  gboolean done = FALSE;

  while (!done)
    {
      GTlsThreadOperation *op;

      op = g_async_queue_pop (queue);

      switch (op->type)
        {
        case G_TLS_THREAD_OP_READ:
          /* FIXME: handle this */
          break;
        case G_TLS_THREAD_OP_SHUTDOWN:
          break;
        }

      if (op->type != G_TLS_THREAD_OP_SHUTDOWN)
        g_main_loop_quit (op->main_loop);
      else
        done = TRUE;

      g_tls_thread_operation_free (op);
    }

  g_object_unref (queue);
}

static void
g_tls_thread_base_init (GTlsThreadBase *tls)
{
  GTlsThreadBasePrivate *priv = g_tls_thread_base_get_instance_private (tls);

  priv->thread = g_thread_new ("[glib-networking] GTlsThreadBase TLS operations thread", tls_thread, priv->queue);
  priv->async_queue = g_async_queue_new_full (g_tls_thread_operation_free);
}

static void
g_tls_thread_base_dispose (GObject *object)
{
  GTlsThreadBase *thread = G_TLS_THREAD_BASE (object);
  GTlsThreadBasePrivate *priv = g_tls_thread_base_get_instance_private (thread);
  GTlsThreadOperation *op;

  if (priv->queue)
    {
      g_async_queue_push (priv->queue, g_tls_thread_shutdown_operation_new ());
      g_clear_pointer (&priv->thread, g_thread_join);
      g_clear_pointer (&priv->queue, g_async_queue_unref);
    }

  G_OBJECT_CLASS (g_tls_thread_base_parent_class)->dispose (object);
}

static void
g_tls_thread_base_class_init (GTlsThreadBaseClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->dispose = g_tls_thread_base_dispose;
}
