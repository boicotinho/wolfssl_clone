/* sha.h
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

/* sha.h for openssl */


#ifndef WOLFSSL_SHA_H_
#define WOLFSSL_SHA_H_

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_PREFIX
#include "prefix_sha.h"
#endif

#ifdef __cplusplus
    extern "C" {
#endif

typedef struct WOLFSSL_SHA_CTX {
    /* big enough to hold wolfcrypt Sha, but check on init */
#if defined(STM32_HASH)
    void* holder[(112 + WC_ASYNC_DEV_SIZE + sizeof(STM32_HASH_Context)) / sizeof(void*)];
#else
    void* holder[(112 + WC_ASYNC_DEV_SIZE) / sizeof(void*)];
#endif
    #if defined(WOLFSSL_DEVCRYPTO_HASH) || defined(WOLFSSL_HASH_KEEP)
    void* keephash_holder[sizeof(void*) + (2 * sizeof(unsigned int))];
    #endif
} WOLFSSL_SHA_CTX;

WOLFSSL_API int wolfSSL_SHA_Init(WOLFSSL_SHA_CTX* sha);
WOLFSSL_API int wolfSSL_SHA_Update(WOLFSSL_SHA_CTX* sha, const void* input,
                           unsigned long sz);
WOLFSSL_API int wolfSSL_SHA_Final(byte* input, WOLFSSL_SHA_CTX* sha);
WOLFSSL_API int wolfSSL_SHA_Transform(WOLFSSL_SHA_CTX* sha,
                                         const unsigned char* data);
/* SHA1 points to above, shouldn't use SHA0 ever */
WOLFSSL_API int wolfSSL_SHA1_Init(WOLFSSL_SHA_CTX* sha);
WOLFSSL_API int wolfSSL_SHA1_Update(WOLFSSL_SHA_CTX* sha, const void* input,
                            unsigned long sz);
WOLFSSL_API int wolfSSL_SHA1_Final(byte* output, WOLFSSL_SHA_CTX* sha);
WOLFSSL_API int wolfSSL_SHA1_Transform(WOLFSSL_SHA_CTX* sha,
                                          const unsigned char *data);


/* Using ALIGN16 because when AES-NI is enabled digest and buffer in Sha256
 * struct are 16 byte aligned. Any dereference to those elements after casting
 * to Sha224, is expected to also be 16 byte aligned addresses.  */
typedef struct WOLFSSL_SHA224_CTX {
    /* big enough to hold wolfcrypt Sha224, but check on init */
    ALIGN16 void* holder[(272 + WC_ASYNC_DEV_SIZE) / sizeof(void*)];
} WOLFSSL_SHA224_CTX;

WOLFSSL_API int wolfSSL_SHA224_Init(WOLFSSL_SHA224_CTX* sha);
WOLFSSL_API int wolfSSL_SHA224_Update(WOLFSSL_SHA224_CTX* sha, const void* input,
                           unsigned long sz);
WOLFSSL_API int wolfSSL_SHA224_Final(byte* output, WOLFSSL_SHA224_CTX* sha);

/* Using ALIGN16 because when AES-NI is enabled digest and buffer in Sha256
 * struct are 16 byte aligned. Any dereference to those elements after casting
 * to Sha256, is expected to also be 16 byte aligned addresses.  */
typedef struct WOLFSSL_SHA256_CTX {
    /* big enough to hold wolfcrypt Sha256, but check on init */
    ALIGN16 void* holder[(272 + WC_ASYNC_DEV_SIZE) / sizeof(void*)];
} WOLFSSL_SHA256_CTX;

WOLFSSL_API int wolfSSL_SHA256_Init(WOLFSSL_SHA256_CTX* sha256);
WOLFSSL_API int wolfSSL_SHA256_Update(WOLFSSL_SHA256_CTX* sha, const void* input,
                              unsigned long sz);
WOLFSSL_API int wolfSSL_SHA256_Final(byte* output, WOLFSSL_SHA256_CTX* sha);
WOLFSSL_API int wolfSSL_SHA256_Transform(WOLFSSL_SHA256_CTX* sha256,
                                                const unsigned char *data);

typedef struct WOLFSSL_SHA384_CTX {
    /* big enough to hold wolfCrypt Sha384, but check on init */
    void* holder[(268 + WC_ASYNC_DEV_SIZE) / sizeof(void*)];
} WOLFSSL_SHA384_CTX;

WOLFSSL_API int wolfSSL_SHA384_Init(WOLFSSL_SHA384_CTX* sha);
WOLFSSL_API int wolfSSL_SHA384_Update(WOLFSSL_SHA384_CTX* sha, const void* input,
                           unsigned long sz);
WOLFSSL_API int wolfSSL_SHA384_Final(byte* output, WOLFSSL_SHA384_CTX* sha);


typedef struct WOLFSSL_SHA512_CTX {
    /* big enough to hold wolfCrypt Sha384, but check on init */
    void* holder[(288 + WC_ASYNC_DEV_SIZE) / sizeof(void*)];
} WOLFSSL_SHA512_CTX;

WOLFSSL_API int wolfSSL_SHA512_Init(WOLFSSL_SHA512_CTX* sha);
WOLFSSL_API int wolfSSL_SHA512_Update(WOLFSSL_SHA512_CTX* sha,
                                      const void* input, unsigned long sz);
WOLFSSL_API int wolfSSL_SHA512_Final(byte* output, WOLFSSL_SHA512_CTX* sha);
WOLFSSL_API int wolfSSL_SHA512_Transform(WOLFSSL_SHA512_CTX* sha512,
                                         const unsigned char* data);

#if !defined(WOLFSSL_NOSHA512_224)
typedef struct WOLFSSL_SHA512_CTX WOLFSSL_SHA512_224_CTX;
typedef WOLFSSL_SHA512_224_CTX SHA512_224_CTX;

WOLFSSL_API int wolfSSL_SHA512_224_Init(WOLFSSL_SHA512_CTX* sha);
WOLFSSL_API int wolfSSL_SHA512_224_Update(WOLFSSL_SHA512_224_CTX* sha,
                                        const void* input, unsigned long sz);
WOLFSSL_API int wolfSSL_SHA512_224_Final(byte* output,
                                         WOLFSSL_SHA512_224_CTX* sha);
WOLFSSL_API int wolfSSL_SHA512_224_Transform(WOLFSSL_SHA512_CTX* sha512,
                                          const unsigned char* data);

#endif /* !WOLFSSL_NOSHA512_224 */

#if !defined(WOLFSSL_NOSHA512_256)
typedef struct WOLFSSL_SHA512_CTX WOLFSSL_SHA512_256_CTX;
typedef WOLFSSL_SHA512_256_CTX SHA512_256_CTX;

WOLFSSL_API int wolfSSL_SHA512_256_Init(WOLFSSL_SHA512_CTX* sha);
WOLFSSL_API int wolfSSL_SHA512_256_Update(WOLFSSL_SHA512_256_CTX* sha,
                                        const void* input, unsigned long sz);
WOLFSSL_API int wolfSSL_SHA512_256_Final(byte* output, WOLFSSL_SHA512_256_CTX* sha);
WOLFSSL_API int wolfSSL_SHA512_256_Transform(WOLFSSL_SHA512_CTX* sha512,
                                          const unsigned char* data);

#endif /* !WOLFSSL_NOSHA512_256 */






#ifdef __cplusplus
    }  /* extern "C" */
#endif


#endif /* WOLFSSL_SHA_H_ */

