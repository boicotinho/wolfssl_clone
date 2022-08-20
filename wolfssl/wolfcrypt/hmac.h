/* hmac.h
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

/*!
    \file wolfssl/wolfcrypt/hmac.h
*/

#ifndef WOLF_CRYPT_HMAC_H
#define WOLF_CRYPT_HMAC_H

#include <wolfssl/wolfcrypt/hash.h>





#ifdef __cplusplus
    extern "C" {
#endif

/* avoid redefinition of structs */


#if defined(WOLFSSL_DEVCRYPTO_AES) || defined(WOLFSSL_DEVCRYPTO_HMAC)
    #include <wolfssl/wolfcrypt/port/devcrypto/wc_devcrypto.h>
#endif

#ifndef NO_OLD_WC_NAMES
    #define HMAC_BLOCK_SIZE WC_HMAC_BLOCK_SIZE
#endif

#define WC_HMAC_INNER_HASH_KEYED_SW     1
#define WC_HMAC_INNER_HASH_KEYED_DEV    2

enum {
    HMAC_FIPS_MIN_KEY = 14,   /* 112 bit key length minimum */

    IPAD    = 0x36,
    OPAD    = 0x5C,

/* If any hash is not enabled, add the ID here. */
#ifdef NO_MD5
    WC_MD5     = WC_HASH_TYPE_MD5,
#endif
};

/* Select the largest available hash for the buffer size. */
#define WC_HMAC_BLOCK_SIZE WC_MAX_BLOCK_SIZE



/* hmac hash union */
typedef union {
#ifndef NO_MD5
    wc_Md5 md5;
#endif
    wc_Sha sha;
    wc_Sha224 sha224;
    wc_Sha256 sha256;
    wc_Sha384 sha384;
    wc_Sha512 sha512;
    wc_Sha3 sha3;
} wc_HmacHash;

/* Hmac digest */
struct Hmac {
    wc_HmacHash hash;
    word32  ipad[WC_HMAC_BLOCK_SIZE  / sizeof(word32)];  /* same block size all*/
    word32  opad[WC_HMAC_BLOCK_SIZE  / sizeof(word32)];
    word32  innerHash[WC_MAX_DIGEST_SIZE / sizeof(word32)];
    void*   heap;                 /* heap hint */
    byte    macType;              /* md5 sha or sha256 */
    byte    innerHashKeyed;       /* keyed flag */
#ifdef WOLFSSL_KCAPI_HMAC
    struct kcapi_handle* handle;
#endif
#if defined(WOLFSSL_DEVCRYPTO) && defined(WOLFSSL_DEVCRYPTO_HMAC)
    WC_CRYPTODEV ctx;
#endif
};

#ifndef WC_HMAC_TYPE_DEFINED
    typedef struct Hmac Hmac;
    #define WC_HMAC_TYPE_DEFINED
#endif



/* does init */
WOLFSSL_API int wc_HmacSetKey(Hmac* hmac, int type, const byte* key, word32 keySz);
WOLFSSL_API int wc_HmacUpdate(Hmac* hmac, const byte* in, word32 sz);
WOLFSSL_API int wc_HmacFinal(Hmac* hmac, byte* out);
#ifdef WOLFSSL_KCAPI_HMAC
WOLFSSL_API int wc_HmacSetKey_Software(Hmac* hmac, int type, const byte* key,
                                       word32 keySz);
WOLFSSL_API int wc_HmacUpdate_Software(Hmac* hmac, const byte* in, word32 sz);
WOLFSSL_API int wc_HmacFinal_Software(Hmac* hmac, byte* out);
#endif
WOLFSSL_API int wc_HmacSizeByType(int type);

WOLFSSL_API int wc_HmacInit(Hmac* hmac, void* heap, int devId);
WOLFSSL_API void wc_HmacFree(Hmac* hmac);

WOLFSSL_API int wolfSSL_GetHmacMaxSize(void);

WOLFSSL_LOCAL int _InitHmac(Hmac* hmac, int type, void* heap);

#ifdef HAVE_HKDF

WOLFSSL_API int wc_HKDF_Extract(int type, const byte* salt, word32 saltSz,
                                const byte* inKey, word32 inKeySz, byte* out);
WOLFSSL_API int wc_HKDF_Expand(int type, const byte* inKey, word32 inKeySz,
                               const byte* info, word32 infoSz,
                               byte* out, word32 outSz);

WOLFSSL_API int wc_HKDF(int type, const byte* inKey, word32 inKeySz,
                    const byte* salt, word32 saltSz,
                    const byte* info, word32 infoSz,
                    byte* out, word32 outSz);

#endif /* HAVE_HKDF */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_HMAC_H */
