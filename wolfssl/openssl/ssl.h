/* ssl.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */



/*  ssl.h defines wolfssl_openssl compatibility layer
 *
 */


#ifndef WOLFSSL_OPENSSL_H_
#define WOLFSSL_OPENSSL_H_

/* wolfssl_openssl compatibility layer */
#ifndef OPENSSL_EXTRA_SSL_GUARD
#define OPENSSL_EXTRA_SSL_GUARD
#include <wolfssl/ssl.h>
#endif /* OPENSSL_EXTRA_SSL_GUARD */

#include <wolfssl/openssl/tls1.h>
#ifndef WOLFCRYPT_ONLY
#include <wolfssl/openssl/evp.h>
#endif
#include <wolfssl/openssl/bio.h>


/* need MIN_CODE_E to determine wolfSSL error range */
#include <wolfssl/wolfcrypt/error-crypt.h>

/* all NID_* values are in asn.h */
#include <wolfssl/wolfcrypt/asn.h>

#include <wolfssl/openssl/x509.h>

#ifdef __cplusplus
    extern "C" {
#endif

#ifdef _WIN32
    /* wincrypt.h clashes */
    #undef X509_NAME
#endif

#ifdef WOLFSSL_UTASKER
    /* tcpip.h clashes */
    #undef ASN1_INTEGER
#endif


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* !WOLFSSL_OPENSSL_H_ */
