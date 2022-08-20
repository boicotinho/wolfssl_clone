/* x509_str.c
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if !defined(WOLFSSL_X509_STORE_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning x509_str.c does not need to be compiled separately from ssl.c
    #endif
#else

#ifndef WOLFCRYPT_ONLY


/*******************************************************************************
 * START OF X509_STORE_CTX APIs
 ******************************************************************************/






#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)
int wolfSSL_X509_STORE_CTX_get1_issuer(WOLFSSL_X509 **issuer,
    WOLFSSL_X509_STORE_CTX *ctx, WOLFSSL_X509 *x)
{
    WOLFSSL_STACK* node;

    if (issuer == NULL || ctx == NULL || x == NULL)
        return WOLFSSL_FATAL_ERROR;

    if (ctx->chain != NULL) {
        for (node = ctx->chain; node != NULL; node = node->next) {
            if (wolfSSL_X509_check_issued(node->data.x509, x) == X509_V_OK) {
                *issuer = x;
                return WOLFSSL_SUCCESS;
            }
        }
    }

    /* Result is ignored when passed to wolfSSL_OCSP_cert_to_id(). */

    return x509GetIssuerFromCM(issuer, ctx->store->cm, x);
}
#endif /* WOLFSSL_NGINX || WOLFSSL_HAPROXY || OPENSSL_EXTRA || OPENSSL_ALL */

/*******************************************************************************
 * END OF X509_STORE_CTX APIs
 ******************************************************************************/

/*******************************************************************************
 * START OF X509_STORE APIs
 ******************************************************************************/




/*******************************************************************************
 * END OF X509_STORE APIs
 ******************************************************************************/


#endif /* !WOLFCRYPT_ONLY */

#endif /* !WOLFSSL_X509_STORE_INCLUDED */

