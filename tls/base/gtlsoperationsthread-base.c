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

#include "tls-base-builtins.h"

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
 * disadvantage: the TLS thread *must never block* during read or write
 * operations, because GIOStream users are allowed to do a sync read and a sync
 * write simultaneously in separate threads. Consider a hypothetical scenario:
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
  /* Objects explicitly designed for unlocked multithreaded use. */
  GThread *op_thread;
  GMainContext *op_thread_context;
  GAsyncQueue *queue;

  /* Never mutated after construction. */
  GTlsOperationsThreadType thread_type;

  /* GIOStream is only partially threadsafe, and GDatagramBased is not
   * threadsafe at all. Although they are shared across threads, we try to
   * ensure that we only use them on one thread at any given time.
   */
  GIOStream *base_iostream;
  GDatagramBased *base_socket;

  /* This mutex guards everything below. It's a bit of a failure of design.
   * Ideally we wouldn't need to share this data between threads and would
   * instead pass data to the op thread and return data from the op thread
   * using the op struct. But this is not always easy.
   *
   * FIXME: what of this can move into the op struct? The booleans are needed
   * for more than handshakes, so they'd need to be part of every op.
   */
  GMutex mutex;

  GTlsInteraction *interaction;
  GError *interaction_error;
  gboolean missing_requested_client_certificate;
  gboolean performed_successful_posthandshake_op;
  gboolean require_close_notify;
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
  GTlsCertificate *own_certificate;
  gchar **advertised_protocols;
  GTlsAuthenticationMode auth_mode;
  gboolean require_close_notify;
  gchar *negotiated_protocol;
  GList *accepted_cas;
  GTlsCertificate *peer_certificate;
} HandshakeData;

typedef struct {
  GTlsThreadOperationType type;
  GIOCondition io_condition;

  GTlsOperationsThreadBase *thread;

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
  GTlsOperationStatus result;
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
  REQUEST_CERTIFICATE,

  LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum
{
  PROP_0,
  PROP_BASE_IO_STREAM,
  PROP_BASE_SOCKET,
  PROP_THREAD_TYPE,
  LAST_PROP
};

static GParamSpec *obj_properties[LAST_PROP];

static void g_tls_operations_thread_base_initable_iface_init (GInitableIface *iface);

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (GTlsOperationsThreadBase, g_tls_operations_thread_base, G_TYPE_OBJECT,
                                  G_ADD_PRIVATE (GTlsOperationsThreadBase);
                                  G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                         g_tls_operations_thread_base_initable_iface_init);)

static inline gboolean
is_dtls (GTlsOperationsThreadBase *self)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);

  return !!priv->base_socket;
}

static inline gboolean
is_client (GTlsOperationsThreadBase *self)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);

  return priv->thread_type == G_TLS_OPERATIONS_THREAD_CLIENT;
}

static inline gboolean
is_server (GTlsOperationsThreadBase *self)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);

  return priv->thread_type == G_TLS_OPERATIONS_THREAD_SERVER;
}

void
g_tls_operations_thread_base_set_interaction (GTlsOperationsThreadBase *self,
                                              GTlsInteraction          *interaction)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);

  g_mutex_lock (&priv->mutex);
  g_clear_object (&priv->interaction);
  priv->interaction = interaction? g_object_ref (interaction) : NULL;
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

static GError *
take_interaction_error (GTlsOperationsThreadBase *self)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GError *error;

  g_mutex_lock (&priv->mutex);
  error = g_steal_pointer (&priv->interaction_error);
  g_mutex_unlock (&priv->mutex);

  return error;
}

gboolean
g_tls_operations_thread_base_request_certificate (GTlsOperationsThreadBase  *self,
                                                  GCancellable              *cancellable,
                                                  GTlsCertificate          **own_certificate)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GTlsInteractionResult result = G_TLS_INTERACTION_UNHANDLED;
  GTlsCertificate *cert = NULL;

  g_mutex_lock (&priv->mutex);

  g_clear_error (&priv->interaction_error);
  g_signal_emit (self, signals[REQUEST_CERTIFICATE], 0,
                 priv->interaction,
                 &cert,
                 cancellable,
                 &priv->interaction_error,
                 &result);

  if (cert)
    *own_certificate = G_TLS_OPERATIONS_THREAD_BASE_GET_CLASS (self)->copy_certificate (self, cert);
  else
    *own_certificate = NULL;

  g_mutex_unlock (&priv->mutex);

  return result != G_TLS_INTERACTION_FAILED;
}

void
g_tls_operations_thread_base_set_missing_requested_client_certificate (GTlsOperationsThreadBase *self)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);

  /* For client connections only */

  g_mutex_lock (&priv->mutex);
  priv->missing_requested_client_certificate = TRUE;
  g_mutex_unlock (&priv->mutex);
}

static gboolean
get_is_missing_requested_client_certificate (GTlsOperationsThreadBase *self)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  gboolean ret;

  g_mutex_lock (&priv->mutex);
  ret = priv->missing_requested_client_certificate;
  g_mutex_unlock (&priv->mutex);

  return ret;
}

void
g_tls_operations_thread_base_set_close_notify_required (GTlsOperationsThreadBase *self,
                                                        gboolean                  required)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);

  g_mutex_lock (&priv->mutex);
  priv->require_close_notify = required;
  g_mutex_unlock (&priv->mutex);
}

gboolean
g_tls_operations_thread_base_get_close_notify_required (GTlsOperationsThreadBase *self)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  gboolean ret;

  g_mutex_lock (&priv->mutex);
  ret = priv->require_close_notify;
  g_mutex_unlock (&priv->mutex);

  return ret;
}

static void
set_performed_successful_posthandshake_op (GTlsOperationsThreadBase *self)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);

  g_mutex_lock (&priv->mutex);
  priv->performed_successful_posthandshake_op = TRUE;
  g_mutex_unlock (&priv->mutex);
}

static gboolean
has_performed_successful_posthandshake_op (GTlsOperationsThreadBase *self)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  gboolean ret;

  g_mutex_lock (&priv->mutex);
  ret = priv->performed_successful_posthandshake_op;
  g_mutex_unlock (&priv->mutex);

  return ret;
}

void
g_tls_operations_thread_base_push_io (GTlsOperationsThreadBase *self,
                                      GIOCondition              direction,
                                      GCancellable             *cancellable)
{
  /* FIXME: this is weird, can't we get rid of it on OpenSSL side? */
  if (G_TLS_OPERATIONS_THREAD_BASE_GET_CLASS (self)->push_io)
    {
      G_TLS_OPERATIONS_THREAD_BASE_GET_CLASS (self)->push_io (self, direction, cancellable);
    }
}

static GTlsOperationStatus
g_tls_operations_thread_base_real_pop_io (GTlsOperationsThreadBase  *self,
                                          GIOCondition               direction,
                                          gboolean                   success,
                                          GError                    *op_error /* owned */,
                                          GError                   **error)
{
  /* This function MAY or MAY NOT set error when it fails! */

  if (success)
    {
      g_assert (!op_error);
      return G_TLS_OPERATION_SUCCESS;
    }

  if (g_error_matches (op_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
    {
      g_propagate_error (error, op_error);
      return G_TLS_OPERATION_WOULD_BLOCK;
    }

  if (g_error_matches (op_error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT))
    {
      g_propagate_error (error, op_error);
      return G_TLS_OPERATION_TIMED_OUT;
    }

  if (get_is_missing_requested_client_certificate (self) &&
      !has_performed_successful_posthandshake_op (self))
    {
      GError *interaction_error;

      interaction_error = take_interaction_error (self);

      /* We are a client connection.
       *
       * Probably the server requires a client certificate, but we failed to
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

      if (op_error)
        g_error_free (op_error);
    }
  else if (op_error)
    {
      g_propagate_error (error, op_error);
    }

  return G_TLS_OPERATION_ERROR;
}

GTlsOperationStatus
g_tls_operations_thread_base_pop_io (GTlsOperationsThreadBase  *self,
                                     GIOCondition               direction,
                                     gboolean                   success,
                                     GError                    *op_error,
                                     GError                   **error)
{
  return G_TLS_OPERATIONS_THREAD_BASE_GET_CLASS (self)->pop_io (self, direction,
                                                                success, op_error, error);
}

static HandshakeContext *
handshake_context_new (GTlsVerifyCertificateFunc  verify_callback,
                       gpointer                   user_data)
{
  HandshakeContext *context;

  context = g_new0 (HandshakeContext, 1);
  context->caller_context = g_main_context_ref_thread_default ();
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
                    GTlsCertificate         *own_certificate,
                    const gchar            **advertised_protocols,
                    GTlsAuthenticationMode   mode)
{
  HandshakeData *data;

  data = g_new0 (HandshakeData, 1);
  data->context = context;
  data->own_certificate = own_certificate ? g_object_ref (own_certificate) : NULL;
  data->advertised_protocols = g_strdupv ((gchar **)advertised_protocols);
  data->auth_mode = mode;

  return data;
}

static void
handshake_data_free (HandshakeData *data)
{
  g_strfreev (data->advertised_protocols);

  g_clear_object (&data->own_certificate);
  g_clear_object (&data->peer_certificate);

  g_assert (!data->accepted_cas);
  g_assert (!data->negotiated_protocol);

  g_free (data);
}

static GTlsThreadOperation *
g_tls_thread_copy_client_session_state_operation_new (GTlsOperationsThreadBase *thread,
                                                      GTlsOperationsThreadBase *source)
{
  GTlsThreadOperation *op;

  op = g_new0 (GTlsThreadOperation, 1);
  op->type = G_TLS_THREAD_OP_COPY_CLIENT_SESSION_STATE;
  op->thread = thread;
  op->source = source;

  g_mutex_init (&op->finished_mutex);
  g_cond_init (&op->finished_condition);

  return op;
}

static GTlsThreadOperation *
g_tls_thread_set_server_identity_operation_new (GTlsOperationsThreadBase *thread,
                                                const gchar              *server_identity)
{
  GTlsThreadOperation *op;

  op = g_new0 (GTlsThreadOperation, 1);
  op->type = G_TLS_THREAD_OP_SET_SERVER_IDENTITY;
  op->thread = thread;
  op->server_identity = g_strdup (server_identity);

  g_mutex_init (&op->finished_mutex);
  g_cond_init (&op->finished_condition);

  return op;
}

static GTlsThreadOperation *
g_tls_thread_handshake_operation_new (GTlsOperationsThreadBase  *thread,
                                      HandshakeContext          *context,
                                      GTlsCertificate           *own_certificate,
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
  op->timeout = timeout;
  op->cancellable = cancellable;

  op->handshake_data = handshake_data_new (context,
                                           own_certificate,
                                           advertised_protocols,
                                           auth_mode);

  g_mutex_init (&op->finished_mutex);
  g_cond_init (&op->finished_condition);

  return op;
}

static GTlsThreadOperation *
g_tls_thread_read_operation_new (GTlsOperationsThreadBase *thread,
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
                                  GCancellable             *cancellable)
{
  GTlsThreadOperation *op;

  op = g_new0 (GTlsThreadOperation, 1);
  op->type = G_TLS_THREAD_OP_CLOSE;
  op->io_condition = G_IO_IN | G_IO_OUT;
  op->thread = thread;
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

static GTlsOperationStatus
execute_op (GTlsOperationsThreadBase *self,
            GTlsThreadOperation      *op,
            gssize                   *count,
            GError                  **error)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GTlsOperationStatus result;

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

  op = g_tls_thread_copy_client_session_state_operation_new (self, source);
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

  op = g_tls_thread_set_server_identity_operation_new (self, server_identity);
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
  g_cond_signal (&data->condition);
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
  g_assert (G_IS_TLS_CERTIFICATE (peer_certificate));
  g_assert (context);

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

GTlsOperationStatus
g_tls_operations_thread_base_handshake (GTlsOperationsThreadBase   *self,
                                        GTlsCertificate            *own_certificate,
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
  GTlsOperationStatus status;
  GTlsThreadOperation *op;
  GTlsCertificate *copied_cert;
  HandshakeContext *context;

  g_assert (!g_main_context_is_owner (priv->op_thread_context));

  g_mutex_lock (&priv->mutex);
  priv->missing_requested_client_certificate = FALSE;
  g_mutex_unlock (&priv->mutex);

  context = handshake_context_new (verify_callback,
                                   user_data);

  copied_cert = G_TLS_OPERATIONS_THREAD_BASE_GET_CLASS (self)->copy_certificate (self,
                                                                                 own_certificate);

  op = g_tls_thread_handshake_operation_new (self,
                                             context,
                                             copied_cert,
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
  g_clear_object (&copied_cert);

  return status;
}

GTlsOperationStatus
g_tls_operations_thread_base_read (GTlsOperationsThreadBase  *self,
                                   void                      *buffer,
                                   gsize                      size,
                                   gint64                     timeout,
                                   gssize                    *nread,
                                   GCancellable              *cancellable,
                                   GError                   **error)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GTlsOperationStatus status;
  GTlsThreadOperation *op;

  g_assert (!g_main_context_is_owner (priv->op_thread_context));

  op = g_tls_thread_read_operation_new (self,
                                        buffer, size,
                                        timeout,
                                        cancellable);
  status = execute_op (self, op, nread, error);
  g_tls_thread_operation_free (op);

  return status;
}

GTlsOperationStatus
g_tls_operations_thread_base_read_message (GTlsOperationsThreadBase  *self,
                                           GInputVector              *vectors,
                                           guint                      num_vectors,
                                           gint64                     timeout,
                                           gssize                    *nread,
                                           GCancellable              *cancellable,
                                           GError                   **error)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GTlsOperationStatus status;
  GTlsThreadOperation *op;

  g_assert (!g_main_context_is_owner (priv->op_thread_context));

  op = g_tls_thread_read_message_operation_new (self,
                                                vectors, num_vectors,
                                                timeout,
                                                cancellable);
  status = execute_op (self, op, nread, error);
  g_tls_thread_operation_free (op);

  return status;
}

GTlsOperationStatus
g_tls_operations_thread_base_write (GTlsOperationsThreadBase  *self,
                                    const void                *buffer,
                                    gsize                      size,
                                    gint64                     timeout,
                                    gssize                    *nwrote,
                                    GCancellable              *cancellable,
                                    GError                   **error)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GTlsOperationStatus status;
  GTlsThreadOperation *op;

  g_assert (!g_main_context_is_owner (priv->op_thread_context));

  op = g_tls_thread_write_operation_new (self,
                                         buffer, size,
                                         timeout,
                                         cancellable);
  status = execute_op (self, op, nwrote, error);
  g_tls_thread_operation_free (op);

  return status;
}

GTlsOperationStatus
g_tls_operations_thread_base_write_message (GTlsOperationsThreadBase  *self,
                                            GOutputVector             *vectors,
                                            guint                      num_vectors,
                                            gint64                     timeout,
                                            gssize                    *nwrote,
                                            GCancellable              *cancellable,
                                            GError                   **error)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GTlsOperationStatus status;
  GTlsThreadOperation *op;

  g_assert (!g_main_context_is_owner (priv->op_thread_context));

  op = g_tls_thread_write_message_operation_new (self,
                                                 vectors, num_vectors,
                                                 timeout,
                                                 cancellable);
  status = execute_op (self, op, nwrote, error);
  g_tls_thread_operation_free (op);

  return status;
}

GTlsOperationStatus
g_tls_operations_thread_base_close (GTlsOperationsThreadBase  *self,
                                    GCancellable              *cancellable,
                                    GError                   **error)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);
  GTlsOperationStatus status;
  GTlsThreadOperation *op;

  g_assert (!g_main_context_is_owner (priv->op_thread_context));

  op = g_tls_thread_close_operation_new (self, cancellable);
  status = execute_op (self, op, NULL, error);
  g_tls_thread_operation_free (op);

  return status;
}

GIOStream *
g_tls_operations_thread_base_get_base_iostream (GTlsOperationsThreadBase *self)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);

  return priv->base_iostream;
}

GDatagramBased *
g_tls_operations_thread_base_get_base_socket (GTlsOperationsThreadBase *self)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);

  return priv->base_socket;
}

gboolean
g_tls_operations_thread_base_check (GTlsOperationsThreadBase *self,
                                    GIOCondition              condition)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);

  if (is_dtls (self))
    return g_datagram_based_condition_check (priv->base_socket, condition);

  if (condition & G_IO_IN)
    {
      GInputStream *istream = g_io_stream_get_input_stream (priv->base_iostream);
      return g_pollable_input_stream_is_readable (G_POLLABLE_INPUT_STREAM (istream));
    }

  if (condition & G_IO_OUT)
    {
      GOutputStream *ostream = g_io_stream_get_output_stream (priv->base_iostream);
      return g_pollable_output_stream_is_writable (G_POLLABLE_OUTPUT_STREAM (ostream));
    }

  g_assert_not_reached ();
  return FALSE;
}

static GSource *
create_base_source (GTlsOperationsThreadBase *self,
                    GIOCondition              condition,
                    GCancellable             *cancellable)
{
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (self);

  if (is_dtls (self))
    return g_datagram_based_create_source (priv->base_socket, condition, cancellable);

  if (condition & G_IO_IN)
    {
      GInputStream *istream = g_io_stream_get_input_stream (priv->base_iostream);
      return g_pollable_input_stream_create_source (G_POLLABLE_INPUT_STREAM (istream), cancellable);
    }

  if (condition & G_IO_OUT)
    {
      GOutputStream *ostream = g_io_stream_get_output_stream (priv->base_iostream);
      return g_pollable_output_stream_create_source (G_POLLABLE_OUTPUT_STREAM (ostream), cancellable);
    }

  g_assert_not_reached ();
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
  GTlsOperationsThreadBasePrivate *priv = g_tls_operations_thread_base_get_instance_private (op->thread);
  GSocket *socket = NULL;

  /* Nonblocking? */
  if (op->timeout == 0)
    return;

  if (is_dtls (op->thread))
    {
      if (G_IS_SOCKET (priv->base_socket))
        socket = (GSocket *)priv->base_socket;
    }
  else
    {
      if (G_IS_SOCKET_CONNECTION (priv->base_iostream))
        socket = g_socket_connection_get_socket ((GSocketConnection *)priv->base_iostream);
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
  gboolean performed_posthandshake_op = FALSE;

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
      if (!g_tls_operations_thread_base_check (op->thread, op->io_condition))
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
          op->result = G_TLS_OPERATION_WOULD_BLOCK;
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
                                             op->handshake_data->own_certificate,
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
      performed_posthandshake_op = TRUE;
      break;
    case G_TLS_THREAD_OP_READ_MESSAGE:
      g_assert (base_class->read_message_fn);
      op->result = base_class->read_message_fn (op->thread,
                                                op->input_vectors, op->num_vectors,
                                                &op->count,
                                                op->cancellable,
                                                &op->error);
      performed_posthandshake_op = TRUE;
      break;
    case G_TLS_THREAD_OP_WRITE:
      op->result = base_class->write_fn (op->thread,
                                         op->data, op->size,
                                         &op->count,
                                         op->cancellable,
                                         &op->error);
      performed_posthandshake_op = TRUE;
      break;
    case G_TLS_THREAD_OP_WRITE_MESSAGE:
      g_assert (base_class->write_message_fn);
      op->result = base_class->write_message_fn (op->thread,
                                                 op->output_vectors, op->num_vectors,
                                                 &op->count,
                                                 op->cancellable,
                                                 &op->error);
      performed_posthandshake_op = TRUE;
      break;
    case G_TLS_THREAD_OP_CLOSE:
      op->result = base_class->close_fn (op->thread,
                                         op->cancellable,
                                         &op->error);
      performed_posthandshake_op = TRUE;
      break;
    case G_TLS_THREAD_OP_SHUTDOWN_THREAD:
      g_assert_not_reached ();
    }

  if (op->result == G_TLS_OPERATION_SUCCESS && performed_posthandshake_op)
    set_performed_successful_posthandshake_op (op->thread);

wait:
  if (op->result == G_TLS_OPERATION_WOULD_BLOCK &&
      op->timeout != 0)
    {
      GSource *tls_source;
      GSource *timeout_source;
      GMainContext *main_context;
      DelayedOpAsyncData *data;

      tls_source = create_base_source (op->thread,
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
      if (is_dtls (op->thread))
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
    case PROP_BASE_IO_STREAM:
      g_value_set_object (value, priv->base_iostream);
      break;

    case PROP_BASE_SOCKET:
      g_value_set_object (value, priv->base_socket);
      break;

    case PROP_THREAD_TYPE:
      g_value_set_enum (value, priv->thread_type);
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
    case PROP_BASE_IO_STREAM:
      priv->base_iostream = g_value_dup_object (value);
      if (priv->base_iostream)
        g_assert (!priv->base_socket);
      break;

    case PROP_BASE_SOCKET:
      priv->base_socket = g_value_dup_object (value);
      if (priv->base_socket)
        g_assert (!priv->base_iostream);
      break;

    case PROP_THREAD_TYPE:
      priv->thread_type = g_value_get_enum (value);
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

  g_clear_object (&priv->base_iostream);
  g_clear_object (&priv->base_socket);

  g_mutex_clear (&priv->mutex);

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

  klass->pop_io = g_tls_operations_thread_base_real_pop_io;

  signals[REQUEST_CERTIFICATE] =
    g_signal_new ("operations-thread-request-certificate",
		              G_TYPE_TLS_OPERATIONS_THREAD_BASE,
		              G_SIGNAL_RUN_LAST, 0,
		              g_signal_accumulator_first_wins,
		              NULL, NULL,
		              G_TYPE_TLS_INTERACTION_RESULT, 4,
		              G_TYPE_TLS_INTERACTION,
		              G_TYPE_POINTER,
		              G_TYPE_CANCELLABLE,
		              G_TYPE_POINTER);

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

  obj_properties[PROP_THREAD_TYPE] =
    g_param_spec_enum ("thread-type",
                       "Thread type",
                       "Whether this thread runs a TLS client or server",
                       G_TYPE_TLS_OPERATIONS_THREAD_TYPE,
                       0,
                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

  g_object_class_install_properties (gobject_class, LAST_PROP, obj_properties);
}

static void
g_tls_operations_thread_base_initable_iface_init (GInitableIface *iface)
{
  iface->init = g_tls_operations_thread_base_initable_init;
}
