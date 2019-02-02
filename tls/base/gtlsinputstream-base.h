/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2010 Red Hat, Inc.
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

#ifndef __G_TLS_INPUT_STREAM_BASE_H__
#define __G_TLS_INPUT_STREAM_BASE_H__

#include <gio/gio.h>
#include "gtlsconnection-base.h"

G_BEGIN_DECLS

#define G_TYPE_TLS_INPUT_STREAM_BASE            (g_tls_input_stream_base_get_type ())
#define G_TLS_INPUT_STREAM_BASE(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), G_TYPE_TLS_INPUT_STREAM_BASE, GTlsInputStreamBase))
#define G_TLS_INPUT_STREAM_BASE_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), G_TYPE_TLS_INPUT_STREAM_BASE, GTlsInputStreamBaseClass))
#define G_IS_TLS_INPUT_STREAM_BASE(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), G_TYPE_TLS_INPUT_STREAM_BASE))
#define G_IS_TLS_INPUT_STREAM_BASE_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), G_TYPE_TLS_INPUT_STREAM_BASE))
#define G_TLS_INPUT_STREAM_BASE_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), G_TYPE_TLS_INPUT_STREAM_BASE, GTlsInputStreamBaseClass))

typedef struct _GTlsInputStreamBasePrivate GTlsInputStreamBasePrivate;
typedef struct _GTlsInputStreamBaseClass   GTlsInputStreamBaseClass;
typedef struct _GTlsInputStreamBase        GTlsInputStreamBase;

struct _GTlsInputStreamBaseClass
{
  GInputStreamClass parent_class;
};

struct _GTlsInputStreamBase
{
  GInputStream parent_instance;
  GTlsInputStreamBasePrivate *priv;
};

GType         g_tls_input_stream_base_get_type (void) G_GNUC_CONST;
GInputStream *g_tls_input_stream_base_new      (GTlsConnectionBase *conn);

G_END_DECLS

#endif /* __G_TLS_INPUT_STREAM_BASE_H___ */
