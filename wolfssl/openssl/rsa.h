/* rsa.h
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

/* rsa.h for openSSL */


#ifndef WOLFSSL_RSA_H_
#define WOLFSSL_RSA_H_

#include <wolfssl/openssl/bn.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif


typedef struct WOLFSSL_RSA_METHOD {
    int flags;
    char *name;
} WOLFSSL_RSA_METHOD;

#ifndef WOLFSSL_RSA_TYPE_DEFINED /* guard on redeclaration */
#define WOLFSSL_RSA_TYPE_DEFINED
typedef struct WOLFSSL_RSA {
#ifdef WC_RSA_BLINDING
    WC_RNG* rng;              /* for PrivateDecrypt blinding */
#endif
    WOLFSSL_BIGNUM* n;
    WOLFSSL_BIGNUM* e;
    WOLFSSL_BIGNUM* d;
    WOLFSSL_BIGNUM* p;
    WOLFSSL_BIGNUM* q;
    WOLFSSL_BIGNUM* dmp1;      /* dP */
    WOLFSSL_BIGNUM* dmq1;      /* dQ */
    WOLFSSL_BIGNUM* iqmp;      /* u */
    void*          heap;
    void*          internal;  /* our RSA */
#ifdef HAVE_EX_DATA
    WOLFSSL_CRYPTO_EX_DATA ex_data;  /* external data */
#endif
    word16 pkcs8HeaderSz;

    /* bits */
    byte inSet:1;     /* internal set from external ? */
    byte exSet:1;     /* external set from internal ? */
    byte ownRng:1;    /* flag for if the rng should be free'd */
} WOLFSSL_RSA;
#endif


WOLFSSL_API WOLFSSL_RSA* wolfSSL_RSA_new_ex(void* heap, int devId);
WOLFSSL_API WOLFSSL_RSA* wolfSSL_RSA_new(void);
WOLFSSL_API void        wolfSSL_RSA_free(WOLFSSL_RSA* rsa);

WOLFSSL_API int wolfSSL_RSA_generate_key_ex(WOLFSSL_RSA* rsa, int bits,
                                            WOLFSSL_BIGNUM* bn, void* cb);

WOLFSSL_API int wolfSSL_RSA_blinding_on(WOLFSSL_RSA* rsa, WOLFSSL_BN_CTX* bn);
WOLFSSL_API int wolfSSL_RSA_check_key(const WOLFSSL_RSA* rsa);
WOLFSSL_API int wolfSSL_RSA_public_encrypt(int len, const unsigned char* fr,
                                       unsigned char* to, WOLFSSL_RSA* rsa,
                                       int padding);
WOLFSSL_API int wolfSSL_RSA_private_decrypt(int len, const unsigned char* fr,
                                       unsigned char* to, WOLFSSL_RSA* rsa,
                                       int padding);
WOLFSSL_API int wolfSSL_RSA_private_encrypt(int len, const unsigned char* in,
                            unsigned char* out, WOLFSSL_RSA* rsa, int padding);

WOLFSSL_API int wolfSSL_RSA_size(const WOLFSSL_RSA* rsa);
WOLFSSL_API int wolfSSL_RSA_bits(const WOLFSSL_RSA* rsa);
WOLFSSL_API int wolfSSL_RSA_sign(int type, const unsigned char* m,
                               unsigned int mLen, unsigned char* sigRet,
                               unsigned int* sigLen, WOLFSSL_RSA* rsa);
WOLFSSL_API int wolfSSL_RSA_sign_ex(int type, const unsigned char* m,
                               unsigned int mLen, unsigned char* sigRet,
                               unsigned int* sigLen, WOLFSSL_RSA* rsa,
                               int flag);
WOLFSSL_API int wolfSSL_RSA_sign_generic_padding(int type, const unsigned char* m,
                               unsigned int mLen, unsigned char* sigRet,
                               unsigned int* sigLen, WOLFSSL_RSA* rsa, int flag,
                               int padding);
WOLFSSL_API int wolfSSL_RSA_verify(int type, const unsigned char* m,
                               unsigned int mLen, const unsigned char* sig,
                               unsigned int sigLen, WOLFSSL_RSA* rsa);
WOLFSSL_API int wolfSSL_RSA_verify_ex(int type, const unsigned char* m,
                               unsigned int mLen, const unsigned char* sig,
                               unsigned int sigLen, WOLFSSL_RSA* rsa,
                               int padding);
WOLFSSL_API int wolfSSL_RSA_public_decrypt(int flen, const unsigned char* from,
                               unsigned char* to, WOLFSSL_RSA* rsa, int padding);
WOLFSSL_API int wolfSSL_RSA_GenAdd(WOLFSSL_RSA* rsa);
WOLFSSL_API int wolfSSL_RSA_LoadDer(WOLFSSL_RSA* rsa,
                               const unsigned char* derBuf, int derSz);
WOLFSSL_API int wolfSSL_RSA_LoadDer_ex(WOLFSSL_RSA* rsa,
                               const unsigned char* derBuf, int derSz, int opt);

WOLFSSL_API WOLFSSL_RSA_METHOD *wolfSSL_RSA_meth_new(const char *name, int flags);
WOLFSSL_API void wolfSSL_RSA_meth_free(WOLFSSL_RSA_METHOD *meth);
WOLFSSL_API int wolfSSL_RSA_meth_set(WOLFSSL_RSA_METHOD *rsa, void* p);
WOLFSSL_API int wolfSSL_RSA_set_method(WOLFSSL_RSA *rsa, WOLFSSL_RSA_METHOD *meth);
WOLFSSL_API const WOLFSSL_RSA_METHOD* wolfSSL_RSA_get_method(const WOLFSSL_RSA *rsa);
WOLFSSL_API const WOLFSSL_RSA_METHOD* wolfSSL_RSA_get_default_method(void);

WOLFSSL_API void wolfSSL_RSA_get0_crt_params(const WOLFSSL_RSA *r,
                                             const WOLFSSL_BIGNUM **dmp1,
                                             const WOLFSSL_BIGNUM **dmq1,
                                             const WOLFSSL_BIGNUM **iqmp);
WOLFSSL_API int wolfSSL_RSA_set0_crt_params(WOLFSSL_RSA *r, WOLFSSL_BIGNUM *dmp1,
                                            WOLFSSL_BIGNUM *dmq1, WOLFSSL_BIGNUM *iqmp);
WOLFSSL_API void wolfSSL_RSA_get0_factors(const WOLFSSL_RSA *r, const WOLFSSL_BIGNUM **p,
                                          const WOLFSSL_BIGNUM **q);
WOLFSSL_API int wolfSSL_RSA_set0_factors(WOLFSSL_RSA *r, WOLFSSL_BIGNUM *p, WOLFSSL_BIGNUM *q);
WOLFSSL_API void wolfSSL_RSA_get0_key(const WOLFSSL_RSA *r, const WOLFSSL_BIGNUM **n,
                                      const WOLFSSL_BIGNUM **e, const WOLFSSL_BIGNUM **d);
WOLFSSL_API int wolfSSL_RSA_set0_key(WOLFSSL_RSA *r, WOLFSSL_BIGNUM *n, WOLFSSL_BIGNUM *e,
                                     WOLFSSL_BIGNUM *d);
WOLFSSL_API int wolfSSL_RSA_flags(const WOLFSSL_RSA *r);
WOLFSSL_API void wolfSSL_RSA_set_flags(WOLFSSL_RSA *r, int flags);
WOLFSSL_API void wolfSSL_RSA_clear_flags(WOLFSSL_RSA *r, int flags);
WOLFSSL_API int wolfSSL_RSA_test_flags(const WOLFSSL_RSA *r, int flags);

WOLFSSL_API WOLFSSL_RSA* wolfSSL_RSAPublicKey_dup(WOLFSSL_RSA *rsa);

WOLFSSL_API void* wolfSSL_RSA_get_ex_data(const WOLFSSL_RSA *rsa, int idx);
WOLFSSL_API int wolfSSL_RSA_set_ex_data(WOLFSSL_RSA *rsa, int idx, void *data);


#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* header */
