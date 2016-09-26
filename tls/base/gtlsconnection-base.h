/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2009-2011 Red Hat, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 *
 * In addition, when the library is used with OpenSSL, a special
 * exception applies. Refer to the LICENSE_EXCEPTION file for details.
 */

#ifndef __G_TLS_CONNECTION_BASE_H__
#define __G_TLS_CONNECTION_BASE_H__

#include <gio/gio.h>

G_BEGIN_DECLS

#define G_TYPE_TLS_CONNECTION_BASE            (g_tls_connection_base_get_type ())
#define G_TLS_CONNECTION_BASE(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), G_TYPE_TLS_CONNECTION_BASE, GTlsConnectionBase))
#define G_TLS_CONNECTION_BASE_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), G_TYPE_TLS_CONNECTION_BASE, GTlsConnectionBaseClass))
#define G_IS_TLS_CONNECTION_BASE(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), G_TYPE_TLS_CONNECTION_BASE))
#define G_IS_TLS_CONNECTION_BASE_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), G_TYPE_TLS_CONNECTION_BASE))
#define G_TLS_CONNECTION_BASE_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), G_TYPE_TLS_CONNECTION_BASE, GTlsConnectionBaseClass))

typedef struct _GTlsConnectionBasePrivate                   GTlsConnectionBasePrivate;
typedef struct _GTlsConnectionBaseClass                     GTlsConnectionBaseClass;
typedef struct _GTlsConnectionBase                          GTlsConnectionBase;

typedef enum {
  G_TLS_CONNECTION_BASE_OK,
  G_TLS_CONNECTION_BASE_WOULD_BLOCK,
  G_TLS_CONNECTION_BASE_TIMED_OUT,
  G_TLS_CONNECTION_BASE_REHANDSHAKE,
  G_TLS_CONNECTION_BASE_TRY_AGAIN,
  G_TLS_CONNECTION_BASE_ERROR,
} GTlsConnectionBaseStatus;

struct _GTlsConnectionBaseClass
{
  GTlsConnectionClass parent_class;

  GTlsConnectionBaseStatus (*request_rehandshake)  (GTlsConnectionBase  *tls,
						    GCancellable        *cancellable,
						    GError             **error);
  GTlsConnectionBaseStatus (*handshake)            (GTlsConnectionBase  *tls,
						    GCancellable        *cancellable,
						    GError             **error);
  GTlsConnectionBaseStatus (*complete_handshake)   (GTlsConnectionBase  *tls,
						    GError             **error);

  void                     (*push_io)              (GTlsConnectionBase  *tls,
                                                    GIOCondition         direction,
                                                    gboolean             blocking,
                                                    GCancellable        *cancellable);
  GTlsConnectionBaseStatus (*pop_io)               (GTlsConnectionBase  *tls,
                                                    GIOCondition         direction,
                                                    gboolean             success,
                                                    GError             **error);

  GTlsConnectionBaseStatus (*read_fn)              (GTlsConnectionBase  *tls,
						    void                *buffer,
						    gsize                count,
						    gboolean             blocking,
						    gssize              *nread,
						    GCancellable        *cancellable,
						    GError             **error);
  GTlsConnectionBaseStatus (*write_fn)             (GTlsConnectionBase  *tls,
						    const void          *buffer,
						    gsize                count,
						    gboolean             blocking,
						    gssize              *nwrote,
						    GCancellable        *cancellable,
						    GError             **error);

  GTlsConnectionBaseStatus (*close_fn)             (GTlsConnectionBase  *tls,
						    GCancellable        *cancellable,
						    GError             **error);
};

struct _GTlsConnectionBase
{
  GTlsConnection         parent_instance;

  GIOStream             *base_io_stream;
  GPollableInputStream  *base_istream;
  GPollableOutputStream *base_ostream;

  GTlsDatabase          *database;
  GTlsInteraction       *interaction;

  GTlsCertificate       *certificate;
  gboolean               certificate_requested;
  GError                *certificate_error;
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
   * for handshake_thread_completed() to run, because it's possible
   * that its main loop is being blocked by a synchronous op which is
   * waiting for handshaking to become FALSE...
   *
   * started_handshake indicates that the current handshake attempt
   * got at least as far as sending the first handshake packet (and so
   * any error should be copied to handshake_error and returned on all
   * future operations). ever_handshaked indicates that TLS has been
   * successfully negotiated at some point.
   */
  gboolean       need_handshake;
  gboolean       need_finish_handshake;
  gboolean       started_handshake;
  gboolean       handshaking;
  gboolean       ever_handshaked;
  GTask         *implicit_handshake;
  GError        *handshake_error;
  GByteArray    *app_data_buf;

  /* read_closed means the read direction has closed; write_closed similarly.
   * If (and only if) both are set, the entire GTlsConnection is closed. */
  gboolean       read_closing, read_closed;
  gboolean       write_closing, write_closed;

  gboolean       reading;
  gboolean       read_blocking;
  GError        *read_error;
  GCancellable  *read_cancellable;

  gboolean       writing;
  gboolean       write_blocking;
  GError        *write_error;
  GCancellable  *write_cancellable;

  /*< private >*/
  gboolean       is_system_certdb;
  gboolean       database_is_unset;

  GInputStream  *tls_istream;
  GOutputStream *tls_ostream;

  GMutex         op_mutex;
  GCancellable  *waiting_for_op;
};

GType g_tls_connection_base_get_type (void) G_GNUC_CONST;

gboolean g_tls_connection_base_accept_peer_certificate (GTlsConnectionBase   *tls,
                                                        GTlsCertificate      *peer_certificate,
                                                        GTlsCertificateFlags  peer_certificate_errors);

void g_tls_connection_base_set_peer_certificate (GTlsConnectionBase   *tls,
						 GTlsCertificate      *peer_certificate,
						 GTlsCertificateFlags  peer_certificate_errors);

void     g_tls_connection_base_push_io       (GTlsConnectionBase *tls,
					      GIOCondition        direction,
					      gboolean            blocking,
					      GCancellable       *cancellable);
GTlsConnectionBaseStatus
         g_tls_connection_base_pop_io        (GTlsConnectionBase  *tls,
					      GIOCondition         direction,
					      gboolean             success,
					      GError             **error);

gssize   g_tls_connection_base_read          (GTlsConnectionBase  *tls,
					      void                *buffer,
					      gsize                size,
					      gboolean             blocking,
					      GCancellable        *cancellable,
					      GError             **error);
gssize   g_tls_connection_base_write         (GTlsConnectionBase  *tls,
					      const void          *buffer,
					      gsize                size,
					      gboolean             blocking,
					      GCancellable        *cancellable,
					      GError             **error);

gboolean g_tls_connection_base_check         (GTlsConnectionBase  *tls,
					      GIOCondition         condition);
GSource *g_tls_connection_base_create_source (GTlsConnectionBase  *tls,
					      GIOCondition         condition,
					      GCancellable        *cancellable);

typedef enum {
	G_TLS_DIRECTION_NONE = 0,
	G_TLS_DIRECTION_READ = 1 << 0,
	G_TLS_DIRECTION_WRITE = 1 << 1,
} GTlsDirection;

#define G_TLS_DIRECTION_BOTH (G_TLS_DIRECTION_READ | G_TLS_DIRECTION_WRITE)

gboolean g_tls_connection_base_close_internal (GIOStream     *stream,
                                               GTlsDirection  direction,
                                               GCancellable  *cancellable,
                                               GError       **error);

G_END_DECLS

#endif /* __G_TLS_CONNECTION_BASE_H___ */
