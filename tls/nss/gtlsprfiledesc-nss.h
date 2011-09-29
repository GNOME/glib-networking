/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2011 Red Hat, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 */

#ifndef __G_TLS_PRFILEDESC_NSS_H__
#define __G_TLS_PRFILEDESC_NSS_H__

#include <nspr.h>

#include "gtlsconnection-nss.h"

PRFileDesc *g_tls_prfiledesc_new (GTlsConnectionNss *nss);

#endif /* __G_TLS_PRFILEDESC_NSS_H__ */
