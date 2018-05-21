/* v3_utl.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 1999-2003 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 * In addition, when the library is used with OpenSSL, a special
 * exception applies. Refer to the LICENSE_EXCEPTION file for details.
 *
 */
/* X509 v3 extension utilities */

#ifndef __G_TLS_OPENSSL_UTIL_H__
#define __G_TLS_OPENSSL_UTIL_H__

#include "openssl-include.h"

/*
 * Always check subject name for host match even if subject alt names present
 */
# define G_TLS_X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT    0x1
/* Disable wildcard matching for dnsName fields and common name. */
# define G_TLS_X509_CHECK_FLAG_NO_WILDCARDS    0x2
/* Wildcards must not match a partial label. */
# define G_TLS_X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS 0x4
/* Allow (non-partial) wildcards to match multiple labels. */
# define G_TLS_X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS 0x8
/* Constraint verifier subdomain patterns to match a single labels. */
# define G_TLS_X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS 0x10
/*
 * Match reference identifiers starting with "." to any sub-domain.
 * This is a non-public flag, turned on implicitly when the subject
 * reference identity is a DNS name.
 */
# define _G_TLS_X509_CHECK_FLAG_DOT_SUBDOMAINS 0x8000

int g_tls_X509_check_host(X509 *x, const char *chk, size_t chklen,
                    unsigned int flags, char **peername);

int g_tls_X509_check_email(X509 *x, const char *chk, size_t chklen,
                     unsigned int flags);

int g_tls_X509_check_ip(X509 *x, const unsigned char *chk, size_t chklen,
                  unsigned int flags);

#endif /* __G_TLS_OPENSSL_UTIL_H__ */


