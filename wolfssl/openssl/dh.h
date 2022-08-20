/* dh.h
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

/* dh.h for openSSL */


#ifndef WOLFSSL_DH_H_
#define WOLFSSL_DH_H_

#include <wolfssl/openssl/bn.h>
#include <wolfssl/openssl/opensslv.h>

#ifdef __cplusplus
    extern "C" {
#endif

#ifndef WOLFSSL_DH_TYPE_DEFINED /* guard on redeclaration */
    typedef struct WOLFSSL_DH       WOLFSSL_DH;
    #define WOLFSSL_DH_TYPE_DEFINED
#endif

struct WOLFSSL_DH {
    WOLFSSL_BIGNUM* p;
    WOLFSSL_BIGNUM* g;
    WOLFSSL_BIGNUM* q;
    WOLFSSL_BIGNUM* pub_key;     /* openssh deference g^x */
    WOLFSSL_BIGNUM* priv_key;    /* openssh deference x   */
    void*          internal;     /* our DH */
    char           inSet;        /* internal set from external ? */
    char           exSet;        /* external set from internal ? */
    /*added for lighttpd openssl compatibility, go back and add a getter in
     * lighttpd src code.
     */
    int length;
    wolfSSL_Mutex refMutex;      /* ref count mutex */
    int refCount;                /* reference count */
};

WOLFSSL_API WOLFSSL_DH *wolfSSL_d2i_DHparams(WOLFSSL_DH **dh,
                                         const unsigned char **pp, long length);
WOLFSSL_API int wolfSSL_i2d_DHparams(const WOLFSSL_DH *dh, unsigned char **out);
WOLFSSL_API WOLFSSL_DH* wolfSSL_DH_new(void);
WOLFSSL_API WOLFSSL_DH* wolSSL_DH_new_by_nid(int nid);
WOLFSSL_API void        wolfSSL_DH_free(WOLFSSL_DH* dh);
WOLFSSL_API WOLFSSL_DH* wolfSSL_DH_dup(WOLFSSL_DH* dh);
WOLFSSL_API int         wolfSSL_DH_up_ref(WOLFSSL_DH* dh);

WOLFSSL_API int wolfSSL_DH_check(const WOLFSSL_DH *dh, int *codes);
WOLFSSL_API int wolfSSL_DH_size(WOLFSSL_DH* dh);
WOLFSSL_API int wolfSSL_DH_generate_key(WOLFSSL_DH* dh);
WOLFSSL_API int wolfSSL_DH_compute_key(unsigned char* key, const WOLFSSL_BIGNUM* pub,
                                     WOLFSSL_DH* dh);
WOLFSSL_API int wolfSSL_DH_LoadDer(WOLFSSL_DH* dh, const unsigned char* derBuf,
                                   int derSz);
WOLFSSL_API int wolfSSL_DH_set_length(WOLFSSL_DH* dh, long len);
WOLFSSL_API int wolfSSL_DH_set0_pqg(WOLFSSL_DH *dh, WOLFSSL_BIGNUM *p,
    WOLFSSL_BIGNUM *q, WOLFSSL_BIGNUM *g);

WOLFSSL_API WOLFSSL_DH* wolfSSL_DH_get_2048_256(void);


#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_DH_H_ */
