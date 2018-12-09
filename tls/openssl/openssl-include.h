/*
 * gtlscertificate-openssl.h
 *
 * Copyright (C) 2015 NICE s.r.l.
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, when the library is used with OpenSSL, a special
 * exception applies. Refer to the LICENSE_EXCEPTION file for details.
 *
 * Authors: Ignacio Casal Quinteiro
 *          Christoph Reiter
 */

/* Due to name clashes between Windows and openssl headers we have to
 * make sure windows.h is included before openssl and that we undef the
 * clashing macros.
 */

#ifndef __G_TLS_OPENSSL_INCLUDE_H__
#define __G_TLS_OPENSSL_INCLUDE_H__

#include "glib.h"

#ifdef G_OS_WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
/* These are defined by the Windows headers, but clash with openssl */
#undef X509_NAME
#undef X509_CERT_PAIR
#undef X509_EXTENSIONS
#undef OCSP_REQUEST
#undef OCSP_RESPONSE
#endif

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/crypto.h>
#if (OPENSSL_VERSION_NUMBER >= 0x0090808fL) && !defined(OPENSSL_NO_OCSP)
#include <openssl/ocsp.h>
#endif

#endif /* __G_TLS_OPENSSL_INCLUDE_H__ */
