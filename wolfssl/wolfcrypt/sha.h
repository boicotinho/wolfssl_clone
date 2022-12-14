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

/*!
    \file wolfssl/wolfcrypt/sha.h
*/


#ifndef WOLF_CRYPT_SHA_H
#define WOLF_CRYPT_SHA_H

#include <wolfssl/wolfcrypt/types.h>




#ifdef FREESCALE_LTC_SHA
    #include "fsl_ltc.h"
#endif


#ifdef __cplusplus
    extern "C" {
#endif

/* avoid redefinition of structs */

#ifdef WOLFSSL_MICROCHIP_PIC32MZ
    #include <wolfssl/wolfcrypt/port/pic32/pic32mz-crypt.h>
#endif
#ifdef STM32_HASH
    #include <wolfssl/wolfcrypt/port/st/stm32.h>
#endif
#ifdef WOLFSSL_ESP32WROOM32_CRYPT
    #include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#endif

#if !defined(NO_OLD_SHA_NAMES)
    #define SHA             WC_SHA
#endif

#ifndef NO_OLD_WC_NAMES
    #define Sha             wc_Sha
    #define SHA_BLOCK_SIZE  WC_SHA_BLOCK_SIZE
    #define SHA_DIGEST_SIZE WC_SHA_DIGEST_SIZE
    #define SHA_PAD_SIZE    WC_SHA_PAD_SIZE
#endif

/* in bytes */
enum {
    WC_SHA              =  WC_HASH_TYPE_SHA,
    WC_SHA_BLOCK_SIZE   = 64,
    WC_SHA_DIGEST_SIZE  = 20,
    WC_SHA_PAD_SIZE     = 56
};


#if defined(WOLFSSL_TI_HASH)
    #include "wolfssl/wolfcrypt/port/ti/ti-hash.h"

#elif defined(WOLFSSL_IMX6_CAAM)
    #include "wolfssl/wolfcrypt/port/caam/wolfcaam_sha.h"
#elif defined(WOLFSSL_RENESAS_TSIP_CRYPT) && \
   !defined(NO_WOLFSSL_RENESAS_TSIP_CRYPT_HASH)
    #include "wolfssl/wolfcrypt/port/Renesas/renesas-tsip-crypt.h"
#else


#if defined(WOLFSSL_HAVE_PSA) && !defined(WOLFSSL_PSA_NO_HASH)
#include <psa/crypto.h>
#undef  WOLFSSL_NO_HASH_RAW
#define WOLFSSL_NO_HASH_RAW
#endif

/* Sha digest */
struct wc_Sha {
#ifdef FREESCALE_LTC_SHA
        ltc_hash_ctx_t ctx;
#elif defined(STM32_HASH)
        STM32_HASH_Context stmCtx;
#elif defined(WOLFSSL_HAVE_PSA) && !defined(WOLFSSL_PSA_NO_HASH)
        psa_hash_operation_t psa_ctx;
#else
        word32  buffLen;   /* in bytes          */
        word32  loLen;     /* length in bytes   */
        word32  hiLen;     /* length in bytes   */
        word32  buffer[WC_SHA_BLOCK_SIZE  / sizeof(word32)];
    #ifdef WOLFSSL_PIC32MZ_HASH
        word32  digest[PIC32_DIGEST_SIZE / sizeof(word32)];
    #else
        word32  digest[WC_SHA_DIGEST_SIZE / sizeof(word32)];
    #endif
        void*   heap;
    #ifdef WOLFSSL_PIC32MZ_HASH
        hashUpdCache cache; /* cache for updates */
    #endif
    #if defined(WOLFSSL_DEVCRYPTO_HASH) || defined(WOLFSSL_HASH_KEEP)
        byte*  msg;
        word32 used;
        word32 len;
    #endif
#endif
#if defined(WOLFSSL_ESP32WROOM32_CRYPT) && \
   !defined(NO_WOLFSSL_ESP32WROOM32_CRYPT_HASH)
    WC_ESP32SHA ctx;
#endif
};

#ifndef WC_SHA_TYPE_DEFINED
    typedef struct wc_Sha wc_Sha;
    #define WC_SHA_TYPE_DEFINED
#endif

#endif /* WOLFSSL_TI_HASH */



WOLFSSL_API int wc_InitSha(wc_Sha* sha);
WOLFSSL_API int wc_InitSha_ex(wc_Sha* sha, void* heap, int devId);
WOLFSSL_API int wc_ShaUpdate(wc_Sha* sha, const byte* data, word32 len);
WOLFSSL_API int wc_ShaFinalRaw(wc_Sha* sha, byte* hash);
WOLFSSL_API int wc_ShaFinal(wc_Sha* sha, byte* hash);
WOLFSSL_API void wc_ShaFree(wc_Sha* sha);

WOLFSSL_API int wc_ShaGetHash(wc_Sha* sha, byte* hash);
WOLFSSL_API int wc_ShaCopy(wc_Sha* src, wc_Sha* dst);

#ifdef WOLFSSL_PIC32MZ_HASH
WOLFSSL_API void wc_ShaSizeSet(wc_Sha* sha, word32 len);
#endif


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_SHA_H */

