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
#include "gtlsoperationsthread-base.h"

#include <glib/gi18n-lib.h>

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
 * While the TLS thread class is intended to simplify our code, it has one major
 * disadvantage: the TLS thread *must never block* because GIOStream users are
 * allowed to do a sync read and a sync write simultaneously in separate
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
 *
 * This means that underlying TLS operations must use entirely nonblocking I/O.
 * We specify a timeout of 0 for every operation to ensure it returns
 * immediately with an error if I/O cannot be performed immediately. If so, we
 * create a GSource that will trigger later on, when possibly ready to perform
 * I/O. In this way, we can simultaneously handle separate synchronous read and
 * write operations on one thread without either one blocking the other.
 */
typedef struct {
  /* FIXME: remove to prevent misuse? */
  GTlsConnectionBase *connection;

  GThread *op_thread;
  GMainContext *op_thread_context;

  GAsyncQueue *queue;

  /* This mutex guards everything below. It's a bit of a failure of design.
   * Ideally we wouldn't need to share this data between threads and would
   * instead return data from the op thread to the calling thread using the op
   * struct.
   *
   * TODO: some of this could move into the op struct?
   */
  GMutex mutex;
  gchar *own_certificate_pem;
  GTlsInteraction *interaction;
  GError *interaction_error;
  gboolean missing_requested_client_certificate;
} GTlsOperationsThreadBasePrivate;

typedef enum {
  G_TLS_THREAD_OP_COPY_CLIENT_SESSION_STATE,
  G_TLS_THREAD_OP_SET_SERVER_IDENTITY,
  G_TLS_THREAD_OP_HANDSHAKE,
  G_TLS_THREAD_OP_READ,
  G_TLS_THREAD_OP_READ_MESSAGE,
  G_TLS_THREAD_OP_WRITE,
  G_TLS_THREAD_OP_WRITE_MESSAGE,
  G_TLS_THREAD_OP_CLOSE,
  G_TLS_THREAD_OP_SHUTDOWN_THREAD
} GTlsThreadOperationType;

struct _HandshakeContext
{
  GMainContext *caller_context;
  GTlsVerifyCertificateFunc verify_callback;
  gboolean certificate_verified; /* FIXME: remove and track is_session_resumed instead */
  gpointer user_data;
};

typedef struct {
  HandshakeContext *context;
  gchar **advertised_protocols;
  GTlsAuthenticationMode auth_mode;
  gchar *negotiated_protocol;
  GList *accepted_cas;
  GTlsCertificate *peer_certificate;
} HandshakeData;

typedef struct {
  GTlsThreadOperationType type;
  GIOCondition io_condition;

  GTlsOperationsThreadBase *thread;
  GTlsConnectionBase *connection; /* FIXME: threadsafety nightmare, not OK */

  /* Op input */
  union {
    GTlsOperationsThreadBase *source; /* for copy client session state */
    gchar *server_identity;           /* for set server identity */
    HandshakeData *handshake_data;    /* for handshake */
    void *data;                       /* for read/write */
    GInputVector *input_vectors;      /* for read message */
    GOutputVector *output_vectors;    /* for write message */
  };
  union {
    gsize size;        /* for read/write */
    guint num_vectors; /* for read/write message */
  };
  gint64 timeout;
  gint64 start_time;

  GCancellable *cancellable;

  /* Op output */
  GTlsConnectionBaseStatus result;
  gssize count; /* Bytes read or written */
  GError *error;

  GMutex finished_mutex;
  GCond finished_condition;
  gboolean finished;
} GTlsThreadOperation;

static gboolean process_op (GAsyncQueue         *queue,
                            GTlsThreadOperation *delayed_op,
                            GMainLoop           *main_loop);

enum
{
  PROP_0,
  PROP_TLS_CONNECTION,
  LAST_PROP
};

static GParamSpec *obj_properties[LAST_PROP];

static void g_tls_operations_thread_base_initable_iface_init (GInitableIface *iface);

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (GTlsOperationsThreadBase, g_tls_operations_thread_base, G_TYPE_OBJECT,
                                  G_ADD_PRIVATE (GTlsOperationsThreadBase);
                                  G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                         g_tls_operations_thread_base_initable_iface_init);)

GTlsConnectionBase *
g_tls_operations_thread_base_get_connection (GTlsOperationsThreadBase *self)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);

  return priv->connection;
}

void
g_tls_operations_thread_base_set_own_certificate (GTlsOperationsThreadBase *self,
                                                  GTlsCertificate          *cert)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);

  g_mutex_lock (&priv->mutex);
  g_clear_pointer (&priv->own_certificate_pem, g_free);
  g_object_get (cert,
                "certificate-pem", &priv->own_certificate_pem,
                NULL);
  g_mutex_unlock (&priv->mutex);
}

gchar *
g_tls_operations_thread_base_get_own_certificate_pem (GTlsOperationsThreadBase *self)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  gchar *copy;

  g_mutex_lock (&priv->mutex);
  copy = g_strdup (priv->own_certificate_pem);
  g_mutex_unlock (&priv->mutex);

  return copy;
}

void
g_tls_operations_thread_base_set_interaction (GTlsOperationsThreadBase *self,
                                              GTlsInteraction          *interaction)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);

  g_mutex_lock (&priv->mutex);
  g_clear_object (&priv->interaction);
  priv->interaction = g_object_ref (interaction);
  g_mutex_unlock (&priv->mutex);
}

GTlsInteraction *
g_tls_operations_thread_base_ref_interaction (GTlsOperationsThreadBase *self)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GTlsInteraction *ref = NULL;

  g_mutex_lock (&priv->mutex);
  if (priv->interaction)
    ref = g_object_ref (priv->interaction);
  g_mutex_unlock (&priv->mutex);

  return ref;
}

GError *
g_tls_operations_thread_base_take_interaction_error (GTlsOperationsThreadBase *self)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GError *error;

  g_mutex_lock (&priv->mutex);
  error = g_steal_pointer (&priv->interaction_error);
  g_mutex_unlock (&priv->mutex);

  return error;
}

gboolean
g_tls_operations_thread_base_request_certificate (GTlsOperationsThreadBase *self,
                                                  GCancellable             *cancellable)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GTlsInteractionResult res = G_TLS_INTERACTION_UNHANDLED;

  g_mutex_lock (&priv->mutex);
  g_clear_error (&priv->interaction_error);
  res = g_tls_interaction_invoke_request_certificate (priv->interaction,
                                                      G_TLS_CONNECTION (priv->connection),
                                                      0,
                                                      cancellable,
                                                      &priv->interaction_error);
  g_mutex_unlock (&priv->mutex);

  return res != G_TLS_INTERACTION_FAILED;
}

void
g_tls_operations_thread_base_set_is_missing_requested_client_certificate (GTlsOperationsThreadBase *self)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);

  g_mutex_lock (&priv->mutex);
  priv->missing_requested_client_certificate = TRUE;
  g_mutex_unlock (&priv->mutex);
}

gboolean
g_tls_operations_thread_base_get_is_missing_requested_client_certificate (GTlsOperationsThreadBase *self)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  gboolean ret;

  g_mutex_lock (&priv->mutex);
  ret = priv->missing_requested_client_certificate;
  g_mutex_unlock (&priv->mutex);

  return ret;
}

static HandshakeContext *
handshake_context_new (GMainContext              *caller_context,
                       GTlsVerifyCertificateFunc  verify_callback,
                       gpointer                   user_data)
{
  HandshakeContext *context;

  context = g_new0 (HandshakeContext, 1);
  context->caller_context = g_main_context_ref (caller_context);
  context->verify_callback = verify_callback;
  context->user_data = user_data;

  return context;
}

static void
handshake_context_free (HandshakeContext *context)
{
  g_main_context_unref (context->caller_context);

  g_free (context);
}

static HandshakeData *
handshake_data_new (HandshakeContext        *context,
                    const gchar            **advertised_protocols,
                    GTlsAuthenticationMode   mode)
{
  HandshakeData *data;

  data = g_new0 (HandshakeData, 1);
  data->context = context;
  data->advertised_protocols = g_strdupv ((gchar **)advertised_protocols);
  data->auth_mode = mode;

  return data;
}

static void
handshake_data_free (HandshakeData *data)
{
  g_strfreev (data->advertised_protocols);

  g_clear_object (&data->peer_certificate);

  g_assert (!data->accepted_cas);
  g_assert (!data->negotiated_protocol);

  g_free (data);
}

static GTlsThreadOperation *
g_tls_thread_copy_client_session_state_operation_new (GTlsOperationsThreadBase *thread,
                                                      GTlsConnectionBase       *connection,
                                                      GTlsOperationsThreadBase *source)
{
  GTlsThreadOperation *op;

  op = g_new0 (GTlsThreadOperation, 1);
  op->type = G_TLS_THREAD_OP_COPY_CLIENT_SESSION_STATE;
  op->thread = thread;
  op->connection = connection;
  op->source = source;

  g_mutex_init (&op->finished_mutex);
  g_cond_init (&op->finished_condition);

  return op;
}

static GTlsThreadOperation *
g_tls_thread_set_server_identity_operation_new (GTlsOperationsThreadBase *thread,
                                                GTlsConnectionBase       *connection,
                                                const gchar              *server_identity)
{
  GTlsThreadOperation *op;

  op = g_new0 (GTlsThreadOperation, 1);
  op->type = G_TLS_THREAD_OP_SET_SERVER_IDENTITY;
  op->thread = thread;
  op->connection = connection;
  op->server_identity = g_strdup (server_identity);

  g_mutex_init (&op->finished_mutex);
  g_cond_init (&op->finished_condition);

  return op;
}

static GTlsThreadOperation *
g_tls_thread_handshake_operation_new (GTlsOperationsThreadBase  *thread,
                                      HandshakeContext          *context,
                                      GTlsConnectionBase        *connection,
                                      const gchar              **advertised_protocols,
                                      GTlsAuthenticationMode     auth_mode,
                                      gint64                     timeout,
                                      GCancellable              *cancellable)
{
  GTlsThreadOperation *op;

  op = g_new0 (GTlsThreadOperation, 1);
  op->type = G_TLS_THREAD_OP_HANDSHAKE;
  op->io_condition = G_IO_IN | G_IO_OUT;
  op->thread = thread;
  op->connection = connection;
  op->timeout = timeout;
  op->cancellable = cancellable;

  op->handshake_data = handshake_data_new (context,
                                           advertised_protocols,
                                           auth_mode);

  g_mutex_init (&op->finished_mutex);
  g_cond_init (&op->finished_condition);

  return op;
}

static GTlsThreadOperation *
g_tls_thread_read_operation_new (GTlsOperationsThreadBase *thread,
                                 GTlsConnectionBase       *connection,
                                 void                     *data,
                                 gsize                     size,
                                 gint64                    timeout,
                                 GCancellable             *cancellable)
{
  GTlsThreadOperation *op;

  op = g_new0 (GTlsThreadOperation, 1);
  op->type = G_TLS_THREAD_OP_READ;
  op->io_condition = G_IO_IN;
  op->thread = thread;
  op->connection = connection;
  op->data = data;
  op->size = size;
  op->timeout = timeout;
  op->cancellable = cancellable;

  g_mutex_init (&op->finished_mutex);
  g_cond_init (&op->finished_condition);

  return op;
}

static GTlsThreadOperation *
g_tls_thread_read_message_operation_new (GTlsOperationsThreadBase *thread,
                                         GTlsConnectionBase       *connection,
                                         GInputVector             *vectors,
                                         guint                     num_vectors,
                                         gint64                    timeout,
                                         GCancellable             *cancellable)
{
  GTlsThreadOperation *op;

  op = g_new0 (GTlsThreadOperation, 1);
  op->type = G_TLS_THREAD_OP_READ_MESSAGE;
  op->io_condition = G_IO_IN;
  op->thread = thread;
  op->connection = connection;
  op->input_vectors = vectors;
  op->num_vectors = num_vectors;
  op->timeout = timeout;
  op->cancellable = cancellable;

  g_mutex_init (&op->finished_mutex);
  g_cond_init (&op->finished_condition);

  return op;
}

static GTlsThreadOperation *
g_tls_thread_write_operation_new (GTlsOperationsThreadBase *thread,
                                  GTlsConnectionBase       *connection,
                                  const void               *data,
                                  gsize                     size,
                                  gint64                    timeout,
                                  GCancellable             *cancellable)
{
  GTlsThreadOperation *op;

  op = g_new0 (GTlsThreadOperation, 1);
  op->type = G_TLS_THREAD_OP_WRITE;
  op->io_condition = G_IO_OUT;
  op->thread = thread;
  op->connection = connection;
  op->data = (void *)data;
  op->size = size;
  op->timeout = timeout;
  op->cancellable = cancellable;

  g_mutex_init (&op->finished_mutex);
  g_cond_init (&op->finished_condition);

  return op;
}

static GTlsThreadOperation *
g_tls_thread_write_message_operation_new (GTlsOperationsThreadBase *thread,
                                          GTlsConnectionBase       *connection,
                                          GOutputVector            *vectors,
                                          guint                     num_vectors,
                                          gint64                    timeout,
                                          GCancellable             *cancellable)
{
  GTlsThreadOperation *op;

  op = g_new0 (GTlsThreadOperation, 1);
  op->type = G_TLS_THREAD_OP_WRITE_MESSAGE;
  op->io_condition = G_IO_OUT;
  op->thread = thread;
  op->connection = connection;
  op->output_vectors = vectors;
  op->num_vectors = num_vectors;
  op->timeout = timeout;
  op->cancellable = cancellable;

  g_mutex_init (&op->finished_mutex);
  g_cond_init (&op->finished_condition);

  return op;
}

static GTlsThreadOperation *
g_tls_thread_close_operation_new (GTlsOperationsThreadBase *thread,
                                  GTlsConnectionBase       *connection,
                                  GCancellable             *cancellable)
{
  GTlsThreadOperation *op;

  op = g_new0 (GTlsThreadOperation, 1);
  op->type = G_TLS_THREAD_OP_CLOSE;
  op->io_condition = G_IO_IN | G_IO_OUT;
  op->thread = thread;
  op->connection = connection;
  op->timeout = -1;
  op->cancellable = cancellable;

  g_mutex_init (&op->finished_mutex);
  g_cond_init (&op->finished_condition);

  return op;
}

static GTlsThreadOperation *
g_tls_thread_shutdown_operation_new (void)
{
  GTlsThreadOperation *op;

  op = g_new0 (GTlsThreadOperation, 1);
  op->type = G_TLS_THREAD_OP_SHUTDOWN_THREAD;

  return op;
}

static void
g_tls_thread_operation_free (GTlsThreadOperation *op)
{
  if (op->type == G_TLS_THREAD_OP_SET_SERVER_IDENTITY)
    g_free (op->server_identity);

  if (op->type == G_TLS_THREAD_OP_HANDSHAKE)
    handshake_data_free (op->handshake_data);

  if (op->type != G_TLS_THREAD_OP_SHUTDOWN_THREAD)
    {
      g_mutex_clear (&op->finished_mutex);
      g_cond_clear (&op->finished_condition);
    }

  g_free (op);
}

static void
wait_for_op_completion (GTlsThreadOperation *op)
{
  g_mutex_lock (&op->finished_mutex);
  while (!op->finished)
    g_cond_wait (&op->finished_condition, &op->finished_mutex);
  g_mutex_unlock (&op->finished_mutex);
}

static GTlsConnectionBaseStatus
execute_op (GTlsOperationsThreadBase *self,
            GTlsThreadOperation      *op,
            gssize                   *count,
            GError                  **error)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GTlsConnectionBaseStatus result;

  g_async_queue_push (priv->queue, op);
  g_main_context_wakeup (priv->op_thread_context);

  wait_for_op_completion (op);

  if (count)
    *count = op->count;

  result = op->result;

  if (op->error)
    {
      g_propagate_error (error, op->error);
      op->error = NULL;
    }

  return result;
}

void
g_tls_operations_thread_base_copy_client_session_state (GTlsOperationsThreadBase *self,
                                                        GTlsOperationsThreadBase *source)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GTlsThreadOperation *op;

  g_assert (!g_main_context_is_owner (priv->op_thread_context));

  op = g_tls_thread_copy_client_session_state_operation_new (self,
                                                             priv->connection,
                                                             source);
  execute_op (self, op, NULL, NULL);
  g_tls_thread_operation_free (op);
}

void
g_tls_operations_thread_base_set_server_identity (GTlsOperationsThreadBase *self,
                                                  const gchar              *server_identity)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GTlsThreadOperation *op;

  g_assert (!g_main_context_is_owner (priv->op_thread_context));

  op = g_tls_thread_set_server_identity_operation_new (self,
                                                       priv->connection,
                                                       server_identity);
  execute_op (self, op, NULL, NULL);
  g_tls_thread_operation_free (op);
}

typedef struct {
  GTlsOperationsThreadBase *thread;
  GTlsCertificate *peer_certificate;
  HandshakeContext *context;

  gboolean result;
  gboolean complete;
  GMutex mutex;
  GCond condition;
} VerifyCertificateData;

static VerifyCertificateData *
verify_certificate_data_new (GTlsOperationsThreadBase *thread,
                             GTlsCertificate          *peer_certificate,
                             HandshakeContext         *context)
{
  VerifyCertificateData *data;

  data = g_new0 (VerifyCertificateData, 1);
  data->thread = g_object_ref (thread);
  data->peer_certificate = g_object_ref (peer_certificate);
  data->context = context;

  g_mutex_init (&data->mutex);
  g_cond_init (&data->condition);

  return data;
}

static void
verify_certificate_data_free (VerifyCertificateData *data)
{
  g_object_unref (data->thread);
  g_object_unref (data->peer_certificate);

  g_mutex_clear (&data->mutex);
  g_cond_clear (&data->condition);

  g_free (data);
}

static gboolean
execute_verify_certificate_callback_cb (VerifyCertificateData *data)
{
  data->result = data->context->verify_callback (data->thread,
                                                 data->peer_certificate,
                                                 data->context->user_data);

  g_mutex_lock (&data->mutex);
  data->complete = TRUE;
  g_mutex_unlock (&data->mutex);

  return G_SOURCE_REMOVE;
}

gboolean
g_tls_operations_thread_base_verify_certificate (GTlsOperationsThreadBase *self,
                                                 GTlsCertificate          *peer_certificate,
                                                 HandshakeContext         *context)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  VerifyCertificateData *data;
  gboolean accepted;

  g_assert (g_main_context_is_owner (priv->op_thread_context));

  data = verify_certificate_data_new (self, peer_certificate, context);

  /* Invoke the caller's callback on the calling thread, not the op thread. */
  g_main_context_invoke (context->caller_context,
                         (GSourceFunc)execute_verify_certificate_callback_cb,
                         data);

  /* Block the op thread until the calling thread's callback finishes. */
  g_mutex_lock (&data->mutex);
  while (!data->complete)
    g_cond_wait (&data->condition, &data->mutex);
  g_mutex_unlock (&data->mutex);

  context->certificate_verified = TRUE; /* FIXME: not good, not accurate */
  accepted = data->result;

  verify_certificate_data_free (data);

  return accepted;
}

GTlsConnectionBaseStatus
g_tls_operations_thread_base_handshake (GTlsOperationsThreadBase   *self,
                                        const gchar               **advertised_protocols,
                                        GTlsAuthenticationMode      auth_mode,
                                        gint64                      timeout,
                                        GTlsVerifyCertificateFunc   verify_callback,
                                        GTlsSessionResumedFunc      resumed_callback,
                                        gchar                     **negotiated_protocol,
                                        GList                     **accepted_cas,
                                        GCancellable               *cancellable,
                                        gpointer                    user_data,
                                        GError                    **error)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GTlsConnectionBaseStatus status;
  GTlsThreadOperation *op;
  HandshakeContext *context;

  g_assert (!g_main_context_is_owner (priv->op_thread_context));

  g_mutex_lock (&priv->mutex);
  priv->missing_requested_client_certificate = FALSE;
  g_mutex_unlock (&priv->mutex);

  context = handshake_context_new (g_main_context_get_thread_default (),
                                   verify_callback,
                                   user_data);

  op = g_tls_thread_handshake_operation_new (self,
                                             context,
                                             priv->connection,
                                             advertised_protocols,
                                             auth_mode,
                                             timeout,
                                             cancellable);
  status = execute_op (self, op, NULL, error);

  /* FIXME: is this right? Probably we should really check for session resumption? is_session_resumed? */
  if (!context->certificate_verified)
    resumed_callback (self, op->handshake_data->peer_certificate, user_data);

  *negotiated_protocol = g_steal_pointer (&op->handshake_data->negotiated_protocol);
  *accepted_cas = g_steal_pointer (&op->handshake_data->accepted_cas);

  handshake_context_free (context);
  g_tls_thread_operation_free (op);

  return status;
}

GTlsConnectionBaseStatus
g_tls_operations_thread_base_read (GTlsOperationsThreadBase  *self,
                                   void                      *buffer,
                                   gsize                      size,
                                   gint64                     timeout,
                                   gssize                    *nread,
                                   GCancellable              *cancellable,
                                   GError                   **error)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GTlsConnectionBaseStatus status;
  GTlsThreadOperation *op;

  g_assert (!g_main_context_is_owner (priv->op_thread_context));

  op = g_tls_thread_read_operation_new (self,
                                        priv->connection,
                                        buffer, size,
                                        timeout,
                                        cancellable);
  status = execute_op (self, op, nread, error);
  g_tls_thread_operation_free (op);

  return status;
}

GTlsConnectionBaseStatus
g_tls_operations_thread_base_read_message (GTlsOperationsThreadBase  *self,
                                           GInputVector              *vectors,
                                           guint                      num_vectors,
                                           gint64                     timeout,
                                           gssize                    *nread,
                                           GCancellable              *cancellable,
                                           GError                   **error)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GTlsConnectionBaseStatus status;
  GTlsThreadOperation *op;

  g_assert (!g_main_context_is_owner (priv->op_thread_context));

  op = g_tls_thread_read_message_operation_new (self,
                                                priv->connection,
                                                vectors, num_vectors,
                                                timeout,
                                                cancellable);
  status = execute_op (self, op, nread, error);
  g_tls_thread_operation_free (op);

  return status;
}

GTlsConnectionBaseStatus
g_tls_operations_thread_base_write (GTlsOperationsThreadBase  *self,
                                    const void                *buffer,
                                    gsize                      size,
                                    gint64                     timeout,
                                    gssize                    *nwrote,
                                    GCancellable              *cancellable,
                                    GError                   **error)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GTlsConnectionBaseStatus status;
  GTlsThreadOperation *op;

  g_assert (!g_main_context_is_owner (priv->op_thread_context));

  op = g_tls_thread_write_operation_new (self,
                                         priv->connection,
                                         buffer, size,
                                         timeout,
                                         cancellable);
  status = execute_op (self, op, nwrote, error);
  g_tls_thread_operation_free (op);

  return status;
}

GTlsConnectionBaseStatus
g_tls_operations_thread_base_write_message (GTlsOperationsThreadBase  *self,
                                            GOutputVector             *vectors,
                                            guint                      num_vectors,
                                            gint64                     timeout,
                                            gssize                    *nwrote,
                                            GCancellable              *cancellable,
                                            GError                   **error)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GTlsConnectionBaseStatus status;
  GTlsThreadOperation *op;

  g_assert (!g_main_context_is_owner (priv->op_thread_context));

  op = g_tls_thread_write_message_operation_new (self,
                                                 priv->connection,
                                                 vectors, num_vectors,
                                                 timeout,
                                                 cancellable);
  status = execute_op (self, op, nwrote, error);
  g_tls_thread_operation_free (op);

  return status;
}

GTlsConnectionBaseStatus
g_tls_operations_thread_base_close (GTlsOperationsThreadBase  *self,
                                    GCancellable              *cancellable,
                                    GError                   **error)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GTlsConnectionBaseStatus status;
  GTlsThreadOperation *op;

  g_assert (!g_main_context_is_owner (priv->op_thread_context));

  op = g_tls_thread_close_operation_new (self,
                                         priv->connection,
                                         cancellable);
  status = execute_op (self, op, NULL, error);
  g_tls_thread_operation_free (op);

  return status;
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

/* TODO: Move this into GLib so we don't need a custom source. glib#94 */
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

static void
adjust_op_timeout (GTlsThreadOperation *op)
{
  GSocket *socket = NULL;

  /* Nonblocking? */
  if (op->timeout == 0)
    return;

  if (g_tls_connection_base_is_dtls (op->connection))
    {
      GDatagramBased *base_socket = g_tls_connection_base_get_base_socket (op->connection);

      if (G_IS_SOCKET (base_socket))
        socket = (GSocket *)base_socket;
    }
  else
    {
      GIOStream *base_stream = g_tls_connection_base_get_base_iostream (op->connection);

      if (G_IS_SOCKET_CONNECTION (base_stream))
        socket = g_socket_connection_get_socket ((GSocketConnection *)base_stream);
    }

  /* We have to "massage" the timeout here because we are using only nonblocking
   * I/O, so the underlying socket will never time out even if a timeout has
   * been set. But if we are emulating a blocking operation, we need to make
   * sure we don't block for longer than the underyling timeout.
   */
  if (socket)
    {
      gint64 socket_timeout = g_socket_get_timeout (socket);

      if (socket_timeout > 0)
        {
          if (op->timeout == -1)
            op->timeout = socket_timeout;

          g_assert (op->timeout > 0);
          op->timeout = MIN (op->timeout, socket_timeout);
        }
    }
}

static gboolean
process_op (GAsyncQueue         *queue,
            GTlsThreadOperation *delayed_op,
            GMainLoop           *main_loop)
{
  GTlsThreadOperation *op;
  GTlsOperationsThreadBaseClass *base_class;

  if (delayed_op)
    {
      op = delayed_op;
      g_clear_error (&op->error);

      if (op->timeout != -1)
        {
          op->timeout -= g_get_monotonic_time () - op->start_time;
          op->timeout = MAX (op->timeout, 0);
        }

      g_assert (op->io_condition != 0);
      if (!g_tls_connection_base_base_check (op->connection, op->io_condition))
        {
          /* Not ready for I/O. Either we timed out, or were cancelled, or we
           * could have a spurious wakeup caused by GTlsConnectionBase yield_op.
           */
          /* FIXME: very fragile, assumes op->cancellable is the GTlsConnectionBase's cancellable */
          if (g_cancellable_is_cancelled (op->cancellable))
            {
              op->count = 0;
              g_set_error (&op->error, G_IO_ERROR, G_IO_ERROR_CANCELLED,
                           _("Operation cancelled"));
              goto finished;
            }

          if (op->timeout == 0)
            {
              op->count = 0;
              g_set_error (&op->error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                           _("Socket I/O timed out"));
              goto finished;
            }

          /* Spurious wakeup. Try again later. */
          op->result = G_TLS_CONNECTION_BASE_WOULD_BLOCK;
          goto wait;
        }
    }
  else
    {
      op = g_async_queue_try_pop (queue);
      g_assert (op);

      if (op->type == G_TLS_THREAD_OP_SHUTDOWN_THREAD)
        {
          g_main_loop_quit (main_loop);
          return G_SOURCE_REMOVE;
        }

      adjust_op_timeout (op);
    }

  if (op->type != G_TLS_THREAD_OP_SHUTDOWN_THREAD)
    {
      g_assert (op->thread);
      base_class = G_TLS_OPERATIONS_THREAD_BASE_GET_CLASS (op->thread);
    }

  switch (op->type)
    {
    case G_TLS_THREAD_OP_COPY_CLIENT_SESSION_STATE:
      if (base_class->copy_client_session_state)
        base_class->copy_client_session_state (op->thread, op->source);
      break;
    case G_TLS_THREAD_OP_SET_SERVER_IDENTITY:
      g_assert (base_class->set_server_identity);
      base_class->set_server_identity (op->thread,
                                       op->server_identity);
      break;
    case G_TLS_THREAD_OP_HANDSHAKE:
      op->result = base_class->handshake_fn (op->thread,
                                             op->handshake_data->context,
                                             (const gchar **)op->handshake_data->advertised_protocols,
                                             op->handshake_data->auth_mode,
                                             op->timeout,
                                             &op->handshake_data->negotiated_protocol,
                                             &op->handshake_data->accepted_cas,
                                             &op->handshake_data->peer_certificate,
                                             op->cancellable,
                                             &op->error);
      break;
    case G_TLS_THREAD_OP_READ:
      op->result = base_class->read_fn (op->thread,
                                        op->data, op->size,
                                        &op->count,
                                        op->cancellable,
                                        &op->error);
      break;
    case G_TLS_THREAD_OP_READ_MESSAGE:
      g_assert (base_class->read_message_fn);
      op->result = base_class->read_message_fn (op->thread,
                                                op->input_vectors, op->num_vectors,
                                                &op->count,
                                                op->cancellable,
                                                &op->error);
      break;
    case G_TLS_THREAD_OP_WRITE:
      op->result = base_class->write_fn (op->thread,
                                         op->data, op->size,
                                         &op->count,
                                         op->cancellable,
                                         &op->error);
      break;
    case G_TLS_THREAD_OP_WRITE_MESSAGE:
      g_assert (base_class->write_message_fn);
      op->result = base_class->write_message_fn (op->thread,
                                                 op->output_vectors, op->num_vectors,
                                                 &op->count,
                                                 op->cancellable,
                                                 &op->error);
      break;
    case G_TLS_THREAD_OP_CLOSE:
      op->result = base_class->close_fn (op->thread,
                                         op->cancellable,
                                         &op->error);
      break;
    case G_TLS_THREAD_OP_SHUTDOWN_THREAD:
      g_assert_not_reached ();
    }

wait:
  if (op->result == G_TLS_CONNECTION_BASE_WOULD_BLOCK &&
      op->timeout != 0)
    {
      GSource *tls_source;
      GSource *timeout_source;
      GMainContext *main_context;
      DelayedOpAsyncData *data;

      tls_source = g_tls_connection_base_create_base_source (op->connection,
                                                             op->io_condition,
                                                             op->cancellable);
      if (op->timeout > 0)
        {
          op->start_time = g_get_monotonic_time ();

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

      main_context = g_main_loop_get_context (main_loop);
      g_source_attach (tls_source, main_context);
      g_source_unref (tls_source);

      return G_SOURCE_CONTINUE;
    }

finished:
  g_mutex_lock (&op->finished_mutex);
  op->finished = TRUE;
  g_cond_signal (&op->finished_condition);
  g_mutex_unlock (&op->finished_mutex);

  return G_SOURCE_CONTINUE;
}

static gpointer
tls_op_thread (gpointer data)
{
  GTlsOperationsThreadBase *self = G_TLS_OPERATIONS_THREAD_BASE (data);
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GMainLoop *main_loop;
  GSource *source;

  main_loop = g_main_loop_new (priv->op_thread_context, FALSE);

  g_main_context_push_thread_default (priv->op_thread_context);

  source = tls_op_queue_source_new (priv->queue);
  g_source_set_callback (source, G_SOURCE_FUNC (process_op), main_loop, NULL);
  g_source_attach (source, priv->op_thread_context);
  g_source_unref (source);

  g_main_loop_run (main_loop);

  g_assert (!queue_has_pending_op (priv->queue));

  g_main_context_pop_thread_default (priv->op_thread_context);

  g_main_loop_unref (main_loop);

  return NULL;
}

static void
g_tls_operations_thread_base_get_property (GObject    *object,
                                           guint       prop_id,
                                           GValue     *value,
                                           GParamSpec *pspec)
{
  GTlsOperationsThreadBase *self = G_TLS_OPERATIONS_THREAD_BASE (object);
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);

  switch (prop_id)
    {
    case PROP_TLS_CONNECTION:
      g_assert (priv->connection);
      g_value_set_object (value, priv->connection);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_operations_thread_base_set_property (GObject      *object,
                                           guint         prop_id,
                                           const GValue *value,
                                           GParamSpec   *pspec)
{
  GTlsOperationsThreadBase *self = G_TLS_OPERATIONS_THREAD_BASE (object);
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);

  switch (prop_id)
    {
    case PROP_TLS_CONNECTION:
      priv->connection = g_value_get_object (value);

      /* This weak pointer is not required for correctness, because the
       * thread should never outlive its GTlsConnection. It's only here
       * as a sanity-check and debugging aid, to ensure priv->connection
       * isn't ever dangling.
       */
      g_object_add_weak_pointer (G_OBJECT (priv->connection),
                                 (gpointer *)&priv->connection);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static gboolean
g_tls_operations_thread_base_initable_init (GInitable     *initable,
                                            GCancellable  *cancellable,
                                            GError       **error)
{
  return TRUE;
}

static void
g_tls_operations_thread_base_init (GTlsOperationsThreadBase *self)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);

  priv->queue = g_async_queue_new ();
  priv->op_thread_context = g_main_context_new ();
  priv->op_thread = g_thread_new ("[glib-networking] GTlsOperationsThreadBase TLS operations thread",
                                  tls_op_thread,
                                  self);

  g_mutex_init (&priv->mutex);
}

static void
g_tls_operations_thread_base_finalize (GObject *object)
{
  GTlsOperationsThreadBase *self = G_TLS_OPERATIONS_THREAD_BASE (object);
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GTlsThreadOperation *op;

  op = g_tls_thread_shutdown_operation_new ();
  g_async_queue_push (priv->queue, op);
  g_main_context_wakeup (priv->op_thread_context);

  g_clear_pointer (&priv->op_thread, g_thread_join);
  g_clear_pointer (&priv->op_thread_context, g_main_context_unref);
  g_clear_pointer (&priv->queue, g_async_queue_unref);
  g_tls_thread_operation_free (op);

  g_clear_weak_pointer (&priv->connection);

  g_mutex_clear (&priv->mutex);

  g_clear_pointer (&priv->own_certificate_pem, g_free);
  g_clear_object (&priv->interaction);
  g_clear_error (&priv->interaction_error);

  G_OBJECT_CLASS (g_tls_operations_thread_base_parent_class)->finalize (object);
}

static void
g_tls_operations_thread_base_class_init (GTlsOperationsThreadBaseClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize     = g_tls_operations_thread_base_finalize;
  gobject_class->get_property = g_tls_operations_thread_base_get_property;
  gobject_class->set_property = g_tls_operations_thread_base_set_property;

  /* FIXME: remove this. subclass has been designed to not need it!
   * Move base_iostream and base_socket up to this level.
   */
  obj_properties[PROP_TLS_CONNECTION] =
    g_param_spec_object ("tls-connection",
                         "TLS Connection",
                         "The thread's GTlsConnection",
                         G_TYPE_TLS_CONNECTION_BASE,
                         G_PARAM_READABLE | G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

  g_object_class_install_properties (gobject_class, LAST_PROP, obj_properties);
}

static void
g_tls_operations_thread_base_initable_iface_init (GInitableIface *iface)
{
  iface->init = g_tls_operations_thread_base_initable_init;
}
