/* sha256.c
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

/* For more info on the algorithm, see https://tools.ietf.org/html/rfc6234 */
/*

DESCRIPTION
This library provides the interface to SHA-256 secure hash algorithms.
SHA-256 performs processing on message blocks to produce a final hash digest
output. It can be used to hash a message, M, having a length of L bits,
where 0 <= L < 2^64.

*/
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

/*
 * SHA256 Build Options:
 * USE_SLOW_SHA256:            Reduces code size by not partially unrolling
                                (~2KB smaller and ~25% slower) (default OFF)
 * WOLFSSL_SHA256_BY_SPEC:     Uses the Ch/Maj based on SHA256 specification
                                (default ON)
 * WOLFSSL_SHA256_ALT_CH_MAJ:  Alternate Ch/Maj that is easier for compilers to
                                optimize and recognize as SHA256 (default OFF)
 * SHA256_MANY_REGISTERS:      A SHA256 version that keeps all data in registers
                                and partial unrolled (default OFF)
 */

/* Default SHA256 to use Ch/Maj based on specification */
#if !defined(WOLFSSL_SHA256_BY_SPEC) && !defined(WOLFSSL_SHA256_ALT_CH_MAJ)
    #define WOLFSSL_SHA256_BY_SPEC
#endif


#if !defined(WOLFSSL_ARMASM)


#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/cpuid.h>
#include <wolfssl/wolfcrypt/hash.h>


/* fips wrapper calls, user can call direct */


#if defined(WOLFSSL_TI_HASH)
    /* #include <wolfcrypt/src/port/ti/ti-hash.c> included by wc_port.c */
#elif defined(WOLFSSL_PSOC6_CRYPTO)


#else

#include <wolfssl/wolfcrypt/logging.h>

    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>

#ifdef WOLFSSL_DEVCRYPTO_HASH
    #include <wolfssl/wolfcrypt/port/devcrypto/wc_devcrypto.h>
#endif


    #if defined(__GNUC__) && ((__GNUC__ < 4) || \
                              (__GNUC__ == 4 && __GNUC_MINOR__ <= 8))
        #undef  NO_AVX2_SUPPORT
        #define NO_AVX2_SUPPORT
    #endif
    #if defined(__clang__) && ((__clang_major__ < 3) || \
                               (__clang_major__ == 3 && __clang_minor__ <= 5))
        #define NO_AVX2_SUPPORT
    #elif defined(__clang__) && defined(NO_AVX2_SUPPORT)
        #undef NO_AVX2_SUPPORT
    #endif

    #define HAVE_INTEL_AVX1
    #ifndef NO_AVX2_SUPPORT
        #define HAVE_INTEL_AVX2
    #endif

#if defined(HAVE_INTEL_AVX2)
    #define HAVE_INTEL_RORX
#endif


#if !defined(WOLFSSL_PIC32MZ_HASH) && !defined(STM32_HASH_SHA2) && (!defined(WOLFSSL_IMX6_CAAM) || defined(NO_IMX6_CAAM_HASH) ) && !defined(WOLFSSL_AFALG_HASH) && !defined(WOLFSSL_DEVCRYPTO_HASH) && (!defined(WOLFSSL_ESP32WROOM32_CRYPT) || defined(NO_WOLFSSL_ESP32WROOM32_CRYPT_HASH)) && (!defined(WOLFSSL_RENESAS_TSIP_CRYPT) || defined(NO_WOLFSSL_RENESAS_TSIP_HASH)) && !defined(WOLFSSL_PSOC6_CRYPTO) && !defined(WOLFSSL_IMXRT_DCP) && !defined(WOLFSSL_KCAPI_HASH) && !defined(WOLFSSL_SE050_HASH) && (!defined(WOLFSSL_RENESAS_SCEPROTECT) || defined(NO_WOLFSSL_RENESAS_SCEPROTECT_HASH)) && (!defined(WOLFSSL_HAVE_PSA) || defined(WOLFSSL_PSA_NO_HASH))



static int InitSha256(wc_Sha256* sha256)
{
    int ret = 0;

    if (sha256 == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(sha256->digest, 0, sizeof(sha256->digest));
    sha256->digest[0] = 0x6A09E667L;
    sha256->digest[1] = 0xBB67AE85L;
    sha256->digest[2] = 0x3C6EF372L;
    sha256->digest[3] = 0xA54FF53AL;
    sha256->digest[4] = 0x510E527FL;
    sha256->digest[5] = 0x9B05688CL;
    sha256->digest[6] = 0x1F83D9ABL;
    sha256->digest[7] = 0x5BE0CD19L;

    sha256->buffLen = 0;
    sha256->loLen   = 0;
    sha256->hiLen   = 0;
#ifdef WOLFSSL_HASH_FLAGS
    sha256->flags = 0;
#endif
#ifdef WOLFSSL_HASH_KEEP
    sha256->msg  = NULL;
    sha256->len  = 0;
    sha256->used = 0;
#endif


    return ret;
}
#endif


/* Hardware Acceleration */

    /* in case intel instructions aren't available, plus we need the K[] global */
    #define NEED_SOFT_SHA256

    /*****
    Intel AVX1/AVX2 Macro Control Structure

    #define HAVE_INTEL_AVX1
    #define HAVE_INTEL_AVX2

    #define HAVE_INTEL_RORX


    int InitSha256(wc_Sha256* sha256) {
         Save/Recover XMM, YMM
         ...
    }

    #if defined(HAVE_INTEL_AVX1)|| defined(HAVE_INTEL_AVX2)
      Transform_Sha256(); Function prototype
    #else
      Transform_Sha256() {   }
      int Sha256Final() {
         Save/Recover XMM, YMM
         ...
      }
    #endif

    #if defined(HAVE_INTEL_AVX1)|| defined(HAVE_INTEL_AVX2)
        #if defined(HAVE_INTEL_RORX
             #define RND with rorx instruction
        #else
            #define RND
        #endif
    #endif

    #if defined(HAVE_INTEL_AVX1)

       #define XMM Instructions/inline asm

       int Transform_Sha256() {
           Stitched Message Sched/Round
        }

    #elif defined(HAVE_INTEL_AVX2)

      #define YMM Instructions/inline asm

      int Transform_Sha256() {
          More granular Stitched Message Sched/Round
      }

    #endif

    */

    /* Each platform needs to query info type 1 from cpuid to see if aesni is
     * supported. Also, let's setup a macro for proper linkage w/o ABI conflicts
     */

    /* #if defined(HAVE_INTEL_AVX1/2) at the tail of sha256 */
    static int Transform_Sha256(wc_Sha256* sha256, const byte* data);

#ifdef __cplusplus
    extern "C" {
#endif

        extern int Transform_Sha256_AVX1(wc_Sha256 *sha256, const byte* data);
        extern int Transform_Sha256_AVX1_Len(wc_Sha256* sha256,
                                             const byte* data, word32 len);
    #if defined(HAVE_INTEL_AVX2)
        extern int Transform_Sha256_AVX2(wc_Sha256 *sha256, const byte* data);
        extern int Transform_Sha256_AVX2_Len(wc_Sha256* sha256,
                                             const byte* data, word32 len);
        #ifdef HAVE_INTEL_RORX
        extern int Transform_Sha256_AVX1_RORX(wc_Sha256 *sha256, const byte* data);
        extern int Transform_Sha256_AVX1_RORX_Len(wc_Sha256* sha256,
                                                  const byte* data, word32 len);
        extern int Transform_Sha256_AVX2_RORX(wc_Sha256 *sha256, const byte* data);
        extern int Transform_Sha256_AVX2_RORX_Len(wc_Sha256* sha256,
                                                  const byte* data, word32 len);
        #endif /* HAVE_INTEL_RORX */
    #endif /* HAVE_INTEL_AVX2 */

#ifdef __cplusplus
    }  /* extern "C" */
#endif

    static int (*Transform_Sha256_p)(wc_Sha256* sha256, const byte* data);
                                                       /* = _Transform_Sha256 */
    static int (*Transform_Sha256_Len_p)(wc_Sha256* sha256, const byte* data,
                                         word32 len);
                                                                    /* = NULL */
    static int transform_check = 0;
    static word32 intel_flags;
    static int Transform_Sha256_is_vectorized = 0;

    static WC_INLINE int inline_XTRANSFORM(wc_Sha256* S, const byte* D) {
        int ret;
        ret = (*Transform_Sha256_p)(S, D);
        return ret;
    }
#define XTRANSFORM(...) inline_XTRANSFORM(__VA_ARGS__)

    static WC_INLINE int inline_XTRANSFORM_LEN(wc_Sha256* S, const byte* D, word32 L) {
        int ret;
        ret = (*Transform_Sha256_Len_p)(S, D, L);
        return ret;
    }
#define XTRANSFORM_LEN(...) inline_XTRANSFORM_LEN(__VA_ARGS__)

    static void Sha256_SetTransform(void)
    {

        if (transform_check)
            return;

        intel_flags = cpuid_get_flags();

    #ifdef HAVE_INTEL_AVX2
        if (1 && IS_INTEL_AVX2(intel_flags)) {
        #ifdef HAVE_INTEL_RORX
            if (IS_INTEL_BMI2(intel_flags)) {
                Transform_Sha256_p = Transform_Sha256_AVX2_RORX;
                Transform_Sha256_Len_p = Transform_Sha256_AVX2_RORX_Len;
                Transform_Sha256_is_vectorized = 1;
            }
            else
        #endif
            if (1)
            {
                Transform_Sha256_p = Transform_Sha256_AVX2;
                Transform_Sha256_Len_p = Transform_Sha256_AVX2_Len;
                Transform_Sha256_is_vectorized = 1;
            }
        #ifdef HAVE_INTEL_RORX
            else {
                Transform_Sha256_p = Transform_Sha256_AVX1_RORX;
                Transform_Sha256_Len_p = Transform_Sha256_AVX1_RORX_Len;
                Transform_Sha256_is_vectorized = 1;
            }
        #endif
        }
        else
    #endif
        if (IS_INTEL_AVX1(intel_flags)) {
            Transform_Sha256_p = Transform_Sha256_AVX1;
            Transform_Sha256_Len_p = Transform_Sha256_AVX1_Len;
            Transform_Sha256_is_vectorized = 1;
        }
        else
        {
            Transform_Sha256_p = Transform_Sha256;
            Transform_Sha256_Len_p = NULL;
            Transform_Sha256_is_vectorized = 0;
        }

        transform_check = 1;
    }

#if !defined(WOLFSSL_KCAPI_HASH)
    int wc_InitSha256_ex(wc_Sha256* sha256, void* heap, int devId)
    {
        int ret = 0;
        if (sha256 == NULL)
            return BAD_FUNC_ARG;

        sha256->heap = heap;
    #ifdef WOLFSSL_SMALL_STACK_CACHE
        sha256->W = NULL;
    #endif

        ret = InitSha256(sha256);
        if (ret != 0)
            return ret;

        /* choose best Transform function under this runtime environment */
        Sha256_SetTransform();

        (void)devId;

        return ret;
    }
#endif /* !WOLFSSL_KCAPI_HASH */



    static const FLASH_QUALIFIER ALIGN32 word32 K[64] = {
        0x428A2F98L, 0x71374491L, 0xB5C0FBCFL, 0xE9B5DBA5L, 0x3956C25BL,
        0x59F111F1L, 0x923F82A4L, 0xAB1C5ED5L, 0xD807AA98L, 0x12835B01L,
        0x243185BEL, 0x550C7DC3L, 0x72BE5D74L, 0x80DEB1FEL, 0x9BDC06A7L,
        0xC19BF174L, 0xE49B69C1L, 0xEFBE4786L, 0x0FC19DC6L, 0x240CA1CCL,
        0x2DE92C6FL, 0x4A7484AAL, 0x5CB0A9DCL, 0x76F988DAL, 0x983E5152L,
        0xA831C66DL, 0xB00327C8L, 0xBF597FC7L, 0xC6E00BF3L, 0xD5A79147L,
        0x06CA6351L, 0x14292967L, 0x27B70A85L, 0x2E1B2138L, 0x4D2C6DFCL,
        0x53380D13L, 0x650A7354L, 0x766A0ABBL, 0x81C2C92EL, 0x92722C85L,
        0xA2BFE8A1L, 0xA81A664BL, 0xC24B8B70L, 0xC76C51A3L, 0xD192E819L,
        0xD6990624L, 0xF40E3585L, 0x106AA070L, 0x19A4C116L, 0x1E376C08L,
        0x2748774CL, 0x34B0BCB5L, 0x391C0CB3L, 0x4ED8AA4AL, 0x5B9CCA4FL,
        0x682E6FF3L, 0x748F82EEL, 0x78A5636FL, 0x84C87814L, 0x8CC70208L,
        0x90BEFFFAL, 0xA4506CEBL, 0xBEF9A3F7L, 0xC67178F2L
    };

/* Both versions of Ch and Maj are logically the same, but with the second set
    the compilers can recognize them better for optimization */
#ifdef WOLFSSL_SHA256_BY_SPEC
    /* SHA256 math based on specification */
    #define Ch(x,y,z)       ((z) ^ ((x) & ((y) ^ (z))))
    #define Maj(x,y,z)      ((((x) | (y)) & (z)) | ((x) & (y)))
#else
    /* SHA256 math reworked for easier compiler optimization */
    #define Ch(x,y,z)       ((((y) ^ (z)) & (x)) ^ (z))
    #define Maj(x,y,z)      ((((x) ^ (y)) & ((y) ^ (z))) ^ (y))
#endif
    #define R(x, n)         (((x) & 0xFFFFFFFFU) >> (n))

    #define S(x, n)         rotrFixed(x, n)
    #define Sigma0(x)       (S(x, 2)  ^ S(x, 13) ^ S(x, 22))
    #define Sigma1(x)       (S(x, 6)  ^ S(x, 11) ^ S(x, 25))
    #define Gamma0(x)       (S(x, 7)  ^ S(x, 18) ^ R(x, 3))
    #define Gamma1(x)       (S(x, 17) ^ S(x, 19) ^ R(x, 10))

    #define a(i) S[(0-(i)) & 7]
    #define b(i) S[(1-(i)) & 7]
    #define c(i) S[(2-(i)) & 7]
    #define d(i) S[(3-(i)) & 7]
    #define e(i) S[(4-(i)) & 7]
    #define f(i) S[(5-(i)) & 7]
    #define g(i) S[(6-(i)) & 7]
    #define h(i) S[(7-(i)) & 7]


#ifndef SHA256_MANY_REGISTERS
    #define RND(j) \
         t0 = h(j) + Sigma1(e(j)) + Ch(e(j), f(j), g(j)) + K[i+(j)] + W[i+(j)]; \
         t1 = Sigma0(a(j)) + Maj(a(j), b(j), c(j)); \
         d(j) += t0; \
         h(j)  = t0 + t1

    static int Transform_Sha256(wc_Sha256* sha256, const byte* data)
    {
        word32 S[8], t0, t1;
        int i;

    #ifdef WOLFSSL_SMALL_STACK_CACHE
        word32* W = sha256->W;
        if (W == NULL) {
            W = (word32*)XMALLOC(sizeof(word32) * WC_SHA256_BLOCK_SIZE, NULL,
                                                           DYNAMIC_TYPE_DIGEST);
            if (W == NULL)
                return MEMORY_E;
            sha256->W = W;
        }
    #else
        word32 W[WC_SHA256_BLOCK_SIZE];
    #endif

        /* Copy context->state[] to working vars */
        for (i = 0; i < 8; i++)
            S[i] = sha256->digest[i];

        for (i = 0; i < 16; i++)
            W[i] = *((const word32*)&data[i*sizeof(word32)]);

        for (i = 16; i < WC_SHA256_BLOCK_SIZE; i++)
            W[i] = Gamma1(W[i-2]) + W[i-7] + Gamma0(W[i-15]) + W[i-16];

    #ifdef USE_SLOW_SHA256
        /* not unrolled - ~2k smaller and ~25% slower */
        for (i = 0; i < WC_SHA256_BLOCK_SIZE; i += 8) {
            int j;
            for (j = 0; j < 8; j++) { /* braces needed here for macros {} */
                RND(j);
            }
        }
    #else
        /* partially loop unrolled */
        for (i = 0; i < WC_SHA256_BLOCK_SIZE; i += 8) {
            RND(0); RND(1); RND(2); RND(3);
            RND(4); RND(5); RND(6); RND(7);
        }
    #endif /* USE_SLOW_SHA256 */

        /* Add the working vars back into digest state[] */
        for (i = 0; i < 8; i++) {
            sha256->digest[i] += S[i];
        }

        return 0;
    }
#else
    /* SHA256 version that keeps all data in registers */
    #define SCHED1(j) (W[j] = *((word32*)&data[j*sizeof(word32)]))
    #define SCHED(j) (               \
                   W[ j     & 15] += \
            Gamma1(W[(j-2)  & 15])+  \
                   W[(j-7)  & 15] +  \
            Gamma0(W[(j-15) & 15])   \
        )

    #define RND1(j) \
         t0 = h(j) + Sigma1(e(j)) + Ch(e(j), f(j), g(j)) + K[i+j] + SCHED1(j); \
         t1 = Sigma0(a(j)) + Maj(a(j), b(j), c(j)); \
         d(j) += t0; \
         h(j)  = t0 + t1
    #define RNDN(j) \
         t0 = h(j) + Sigma1(e(j)) + Ch(e(j), f(j), g(j)) + K[i+j] + SCHED(j); \
         t1 = Sigma0(a(j)) + Maj(a(j), b(j), c(j)); \
         d(j) += t0; \
         h(j)  = t0 + t1

    static int Transform_Sha256(wc_Sha256* sha256, const byte* data)
    {
        word32 S[8], t0, t1;
        int i;
        word32 W[WC_SHA256_BLOCK_SIZE/sizeof(word32)];

        /* Copy digest to working vars */
        S[0] = sha256->digest[0];
        S[1] = sha256->digest[1];
        S[2] = sha256->digest[2];
        S[3] = sha256->digest[3];
        S[4] = sha256->digest[4];
        S[5] = sha256->digest[5];
        S[6] = sha256->digest[6];
        S[7] = sha256->digest[7];

        i = 0;
        RND1( 0); RND1( 1); RND1( 2); RND1( 3);
        RND1( 4); RND1( 5); RND1( 6); RND1( 7);
        RND1( 8); RND1( 9); RND1(10); RND1(11);
        RND1(12); RND1(13); RND1(14); RND1(15);
        /* 64 operations, partially loop unrolled */
        for (i = 16; i < 64; i += 16) {
            RNDN( 0); RNDN( 1); RNDN( 2); RNDN( 3);
            RNDN( 4); RNDN( 5); RNDN( 6); RNDN( 7);
            RNDN( 8); RNDN( 9); RNDN(10); RNDN(11);
            RNDN(12); RNDN(13); RNDN(14); RNDN(15);
        }

        /* Add the working vars back into digest */
        sha256->digest[0] += S[0];
        sha256->digest[1] += S[1];
        sha256->digest[2] += S[2];
        sha256->digest[3] += S[3];
        sha256->digest[4] += S[4];
        sha256->digest[5] += S[5];
        sha256->digest[6] += S[6];
        sha256->digest[7] += S[7];

        return 0;
    }
#endif /* SHA256_MANY_REGISTERS */
/* End wc_ software implementation */



    static WC_INLINE void AddLength(wc_Sha256* sha256, word32 len)
    {
        word32 tmp = sha256->loLen;
        if ((sha256->loLen += len) < tmp) {
            sha256->hiLen++;                       /* carry low to high */
        }
    }

    /* do block size increments/updates */
    static WC_INLINE int Sha256Update(wc_Sha256* sha256, const byte* data, word32 len)
    {
        int ret = 0;
        word32 blocksLen;
        byte* local;

        if (sha256 == NULL || (data == NULL && len > 0)) {
            return BAD_FUNC_ARG;
        }

        if (data == NULL && len == 0) {
            /* valid, but do nothing */
            return 0;
        }

        /* check that internal buffLen is valid */
        if (sha256->buffLen >= WC_SHA256_BLOCK_SIZE) {
            return BUFFER_E;
        }

        /* add length for final */
        AddLength(sha256, len);

        local = (byte*)sha256->buffer;

        /* process any remainder from previous operation */
        if (sha256->buffLen > 0) {
            blocksLen = min(len, WC_SHA256_BLOCK_SIZE - sha256->buffLen);
            XMEMCPY(&local[sha256->buffLen], data, blocksLen);

            sha256->buffLen += blocksLen;
            data            += blocksLen;
            len             -= blocksLen;

            if (sha256->buffLen == WC_SHA256_BLOCK_SIZE) {
            #if defined(LITTLE_ENDIAN_ORDER) && !defined(FREESCALE_MMCAU_SHA)
                if (!IS_INTEL_AVX1(intel_flags) && !IS_INTEL_AVX2(intel_flags))
                {
                    ByteReverseWords(sha256->buffer, sha256->buffer,
                        WC_SHA256_BLOCK_SIZE);
                }
            #endif

            #if defined(WOLFSSL_ESP32WROOM32_CRYPT) && \
                !defined(NO_WOLFSSL_ESP32WROOM32_CRYPT_HASH)
                if (sha256->ctx.mode == ESP32_SHA_INIT){
                    esp_sha_try_hw_lock(&sha256->ctx);
                }
                if (sha256->ctx.mode == ESP32_SHA_SW){
                    ret = XTRANSFORM(sha256, (const byte*)local);
                } else {
                    esp_sha256_process(sha256, (const byte*)local);
                }
            #else
                ret = XTRANSFORM(sha256, (const byte*)local);
            #endif

                if (ret == 0)
                    sha256->buffLen = 0;
                else
                    len = 0; /* error */
            }
        }

        /* process blocks */
        if (Transform_Sha256_Len_p != NULL)
        {
            /* get number of blocks */
            /* 64-1 = 0x3F (~ Inverted = 0xFFFFFFC0) */
            /* len (masked by 0xFFFFFFC0) returns block aligned length */
            blocksLen = len & ~(WC_SHA256_BLOCK_SIZE-1);
            if (blocksLen > 0) {
                /* Byte reversal and alignment handled in function if required */
                XTRANSFORM_LEN(sha256, data, blocksLen);
                data += blocksLen;
                len  -= blocksLen;
            }
        }
        else
        {
            while (len >= WC_SHA256_BLOCK_SIZE) {
                word32* local32 = sha256->buffer;
                /* optimization to avoid memcpy if data pointer is properly aligned */
                /* Intel transform function requires use of sha256->buffer */
                /* Little Endian requires byte swap, so can't use data directly */
                {
                    XMEMCPY(local32, data, WC_SHA256_BLOCK_SIZE);
                }

                data += WC_SHA256_BLOCK_SIZE;
                len  -= WC_SHA256_BLOCK_SIZE;

            #if defined(LITTLE_ENDIAN_ORDER) && !defined(FREESCALE_MMCAU_SHA)
                if (!IS_INTEL_AVX1(intel_flags) && !IS_INTEL_AVX2(intel_flags))
                {
                    ByteReverseWords(local32, local32, WC_SHA256_BLOCK_SIZE);
                }
            #endif

            #if defined(WOLFSSL_ESP32WROOM32_CRYPT) && \
                !defined(NO_WOLFSSL_ESP32WROOM32_CRYPT_HASH)
                if (sha256->ctx.mode == ESP32_SHA_INIT){
                    esp_sha_try_hw_lock(&sha256->ctx);
                }
                if (sha256->ctx.mode == ESP32_SHA_SW){
                    ret = XTRANSFORM(sha256, (const byte*)local32);
                } else {
                    esp_sha256_process(sha256, (const byte*)local32);
                }
            #else
                ret = XTRANSFORM(sha256, (const byte*)local32);
            #endif

                if (ret != 0)
                    break;
            }
        }

        /* save remainder */
        if (ret == 0 && len > 0) {
            XMEMCPY(local, data, len);
            sha256->buffLen = len;
        }

        return ret;
    }

#if defined(WOLFSSL_KCAPI_HASH)
    /* implemented in wolfcrypt/src/port/kcapi/kcapi_hash.c */

#else
    int wc_Sha256Update(wc_Sha256* sha256, const byte* data, word32 len)
    {
        if (sha256 == NULL || (data == NULL && len > 0)) {
            return BAD_FUNC_ARG;
        }

        if (data == NULL && len == 0) {
            /* valid, but do nothing */
            return 0;
        }


        return Sha256Update(sha256, data, len);
    }
#endif

    static WC_INLINE int Sha256Final(wc_Sha256* sha256)
    {

        int ret;
        byte* local;

        if (sha256 == NULL) {
            return BAD_FUNC_ARG;
        }

        local = (byte*)sha256->buffer;
        local[sha256->buffLen++] = 0x80; /* add 1 */

        /* pad with zeros */
        if (sha256->buffLen > WC_SHA256_PAD_SIZE) {
            XMEMSET(&local[sha256->buffLen], 0,
                WC_SHA256_BLOCK_SIZE - sha256->buffLen);
            sha256->buffLen += WC_SHA256_BLOCK_SIZE - sha256->buffLen;

        #if defined(LITTLE_ENDIAN_ORDER) && !defined(FREESCALE_MMCAU_SHA)
            if (!IS_INTEL_AVX1(intel_flags) && !IS_INTEL_AVX2(intel_flags))
            {
                ByteReverseWords(sha256->buffer, sha256->buffer,
                                                      WC_SHA256_BLOCK_SIZE);
            }
        #endif

        #if defined(WOLFSSL_ESP32WROOM32_CRYPT) && \
             !defined(NO_WOLFSSL_ESP32WROOM32_CRYPT_HASH)
            if (sha256->ctx.mode == ESP32_SHA_INIT) {
                esp_sha_try_hw_lock(&sha256->ctx);
            }
            if (sha256->ctx.mode == ESP32_SHA_SW) {
                ret = XTRANSFORM(sha256, (const byte*)local);
            } else {
                ret = esp_sha256_process(sha256, (const byte*)local);
            }
        #else
            ret = XTRANSFORM(sha256, (const byte*)local);
        #endif
            if (ret != 0)
                return ret;

            sha256->buffLen = 0;
        }
        XMEMSET(&local[sha256->buffLen], 0,
            WC_SHA256_PAD_SIZE - sha256->buffLen);

        /* put lengths in bits */
        sha256->hiLen = (sha256->loLen >> (8 * sizeof(sha256->loLen) - 3)) +
                                                         (sha256->hiLen << 3);
        sha256->loLen = sha256->loLen << 3;

        /* store lengths */
    #if defined(LITTLE_ENDIAN_ORDER) && !defined(FREESCALE_MMCAU_SHA)
        if (!IS_INTEL_AVX1(intel_flags) && !IS_INTEL_AVX2(intel_flags))
        {
            ByteReverseWords(sha256->buffer, sha256->buffer,
                WC_SHA256_BLOCK_SIZE);
        }
    #endif
        /* ! length ordering dependent on digest endian type ! */
        XMEMCPY(&local[WC_SHA256_PAD_SIZE], &sha256->hiLen, sizeof(word32));
        XMEMCPY(&local[WC_SHA256_PAD_SIZE + sizeof(word32)], &sha256->loLen,
                sizeof(word32));

        /* Kinetis requires only these bytes reversed */
        if (IS_INTEL_AVX1(intel_flags) || IS_INTEL_AVX2(intel_flags))
        {
            ByteReverseWords(
                &sha256->buffer[WC_SHA256_PAD_SIZE / sizeof(word32)],
                &sha256->buffer[WC_SHA256_PAD_SIZE / sizeof(word32)],
                2 * sizeof(word32));
        }

    #if defined(WOLFSSL_ESP32WROOM32_CRYPT) && \
         !defined(NO_WOLFSSL_ESP32WROOM32_CRYPT_HASH)
        if (sha256->ctx.mode == ESP32_SHA_INIT) {
            esp_sha_try_hw_lock(&sha256->ctx);
        }
        if (sha256->ctx.mode == ESP32_SHA_SW) {
            ret = XTRANSFORM(sha256, (const byte*)local);
        } else {
            ret = esp_sha256_digest_process(sha256, 1);
        }
    #else
        ret = XTRANSFORM(sha256, (const byte*)local);
    #endif

        return ret;
    }

#if !defined(WOLFSSL_KCAPI_HASH)

    int wc_Sha256FinalRaw(wc_Sha256* sha256, byte* hash)
    {
    #ifdef LITTLE_ENDIAN_ORDER
        word32 digest[WC_SHA256_DIGEST_SIZE / sizeof(word32)];
    #endif

        if (sha256 == NULL || hash == NULL) {
            return BAD_FUNC_ARG;
        }

    #ifdef LITTLE_ENDIAN_ORDER
        ByteReverseWords((word32*)digest, (word32*)sha256->digest,
                                                         WC_SHA256_DIGEST_SIZE);
        XMEMCPY(hash, digest, WC_SHA256_DIGEST_SIZE);
    #else
        XMEMCPY(hash, sha256->digest, WC_SHA256_DIGEST_SIZE);
    #endif

        return 0;
    }

    int wc_Sha256Final(wc_Sha256* sha256, byte* hash)
    {
        int ret;

        if (sha256 == NULL || hash == NULL) {
            return BAD_FUNC_ARG;
        }



        ret = Sha256Final(sha256);
        if (ret != 0)
            return ret;

    #if defined(LITTLE_ENDIAN_ORDER)
        ByteReverseWords(sha256->digest, sha256->digest, WC_SHA256_DIGEST_SIZE);
    #endif
        XMEMCPY(hash, sha256->digest, WC_SHA256_DIGEST_SIZE);

        return InitSha256(sha256);  /* reset state */
    }

#endif /* !WOLFSSL_KCAPI_HASH */



#ifdef STM32_HASH_SHA2

    /* Supports CubeMX HAL or Standard Peripheral Library */

    int wc_InitSha224_ex(wc_Sha224* sha224, void* heap, int devId)
    {
        if (sha224 == NULL)
            return BAD_FUNC_ARG;

        (void)devId;
        (void)heap;

        XMEMSET(sha224, 0, sizeof(wc_Sha224));
        wc_Stm32_Hash_Init(&sha224->stmCtx);
        return 0;
    }

    int wc_Sha224Update(wc_Sha224* sha224, const byte* data, word32 len)
    {
        int ret = 0;

        if (sha224 == NULL || (data == NULL && len > 0)) {
            return BAD_FUNC_ARG;
        }

        ret = wolfSSL_CryptHwMutexLock();
        if (ret == 0) {
            ret = wc_Stm32_Hash_Update(&sha224->stmCtx,
                HASH_AlgoSelection_SHA224, data, len);
            wolfSSL_CryptHwMutexUnLock();
        }
        return ret;
    }

    int wc_Sha224Final(wc_Sha224* sha224, byte* hash)
    {
        int ret = 0;

        if (sha224 == NULL || hash == NULL) {
            return BAD_FUNC_ARG;
        }

        ret = wolfSSL_CryptHwMutexLock();
        if (ret == 0) {
            ret = wc_Stm32_Hash_Final(&sha224->stmCtx,
                HASH_AlgoSelection_SHA224, hash, WC_SHA224_DIGEST_SIZE);
            wolfSSL_CryptHwMutexUnLock();
        }

        (void)wc_InitSha224(sha224); /* reset state */

        return ret;
    }
#elif defined(WOLFSSL_IMX6_CAAM) && !defined(NO_IMX6_CAAM_HASH)
    /* functions defined in wolfcrypt/src/port/caam/caam_sha256.c */

#elif defined(WOLFSSL_AFALG_HASH)
    #error SHA224 currently not supported with AF_ALG enabled

#elif defined(WOLFSSL_DEVCRYPTO_HASH)
    /* implemented in wolfcrypt/src/port/devcrypto/devcrypt_hash.c */

#elif defined(WOLFSSL_KCAPI_HASH) && !defined(WOLFSSL_NO_KCAPI_SHA224)
    /* implemented in wolfcrypt/src/port/kcapi/kcapi_hash.c */

#elif defined(WOLFSSL_HAVE_PSA) && !defined(WOLFSSL_PSA_NO_HASH)
    /* implemented in wolfcrypt/src/port/psa/psa_hash.c */

#else

    #define NEED_SOFT_SHA224


    static int InitSha224(wc_Sha224* sha224)
    {
        int ret = 0;

        if (sha224 == NULL) {
            return BAD_FUNC_ARG;
        }

        sha224->digest[0] = 0xc1059ed8;
        sha224->digest[1] = 0x367cd507;
        sha224->digest[2] = 0x3070dd17;
        sha224->digest[3] = 0xf70e5939;
        sha224->digest[4] = 0xffc00b31;
        sha224->digest[5] = 0x68581511;
        sha224->digest[6] = 0x64f98fa7;
        sha224->digest[7] = 0xbefa4fa4;

        sha224->buffLen = 0;
        sha224->loLen   = 0;
        sha224->hiLen   = 0;

        /* choose best Transform function under this runtime environment */
        Sha256_SetTransform();
    #ifdef WOLFSSL_HASH_FLAGS
        sha224->flags = 0;
    #endif
    #ifdef WOLFSSL_HASH_KEEP
        sha224->msg  = NULL;
        sha224->len  = 0;
        sha224->used = 0;
    #endif


        return ret;
    }

#endif

#ifdef NEED_SOFT_SHA224
    int wc_InitSha224_ex(wc_Sha224* sha224, void* heap, int devId)
    {
        int ret = 0;

        if (sha224 == NULL)
            return BAD_FUNC_ARG;

        sha224->heap = heap;
    #ifdef WOLFSSL_SMALL_STACK_CACHE
        sha224->W = NULL;
    #endif

        ret = InitSha224(sha224);
        if (ret != 0)
            return ret;

        (void)devId;

        return ret;
    }

    int wc_Sha224Update(wc_Sha224* sha224, const byte* data, word32 len)
    {
        int ret;

        if (sha224 == NULL || (data == NULL && len > 0)) {
            return BAD_FUNC_ARG;
        }


        ret = Sha256Update((wc_Sha256*)sha224, data, len);

        return ret;
    }

    int wc_Sha224Final(wc_Sha224* sha224, byte* hash)
    {
        int ret;

        if (sha224 == NULL || hash == NULL) {
            return BAD_FUNC_ARG;
        }


        ret = Sha256Final((wc_Sha256*)sha224);
        if (ret != 0)
            return ret;

    #if defined(LITTLE_ENDIAN_ORDER)
        ByteReverseWords(sha224->digest, sha224->digest, WC_SHA224_DIGEST_SIZE);
    #endif
        XMEMCPY(hash, sha224->digest, WC_SHA224_DIGEST_SIZE);

        return InitSha224(sha224);  /* reset state */
    }
#endif /* end of SHA224 software implementation */

    int wc_InitSha224(wc_Sha224* sha224)
    {
        int devId = INVALID_DEVID;

        return wc_InitSha224_ex(sha224, NULL, devId);
    }

#if !defined(WOLFSSL_HAVE_PSA) || defined(WOLFSSL_PSA_NO_HASH)
    /* implemented in wolfcrypt/src/port/psa/psa_hash.c */

    void wc_Sha224Free(wc_Sha224* sha224)
    {
        if (sha224 == NULL)
            return;

#ifdef WOLFSSL_SMALL_STACK_CACHE
    if (sha224->W != NULL) {
        XFREE(sha224->W, NULL, DYNAMIC_TYPE_DIGEST);
        sha224->W = NULL;
    }
#endif


    #ifdef WOLFSSL_PIC32MZ_HASH
        wc_Sha256Pic32Free(sha224);
    #endif
    #if defined(WOLFSSL_KCAPI_HASH)
        KcapiHashFree(&sha224->kcapi);
    #endif
    }
#endif /* WOLFSSL_SHA224 */


int wc_InitSha256(wc_Sha256* sha256)
{
    int devId = INVALID_DEVID;

    return wc_InitSha256_ex(sha256, NULL, devId);
}

#if !defined(WOLFSSL_HAVE_PSA) || defined(WOLFSSL_PSA_NO_HASH)
    /* implemented in wolfcrypt/src/port/psa/psa_hash.c */

void wc_Sha256Free(wc_Sha256* sha256)
{
    if (sha256 == NULL)
        return;

#ifdef WOLFSSL_SMALL_STACK_CACHE
    if (sha256->W != NULL) {
        XFREE(sha256->W, NULL, DYNAMIC_TYPE_DIGEST);
        sha256->W = NULL;
    }
#endif

#ifdef WOLFSSL_PIC32MZ_HASH
    wc_Sha256Pic32Free(sha256);
#endif
#if defined(WOLFSSL_AFALG_HASH)
    if (sha256->alFd > 0) {
        close(sha256->alFd);
        sha256->alFd = -1; /* avoid possible double close on socket */
    }
    if (sha256->rdFd > 0) {
        close(sha256->rdFd);
        sha256->rdFd = -1; /* avoid possible double close on socket */
    }
#endif /* WOLFSSL_AFALG_HASH */
#ifdef WOLFSSL_DEVCRYPTO_HASH
    wc_DevCryptoFree(&sha256->ctx);
#endif /* WOLFSSL_DEVCRYPTO */
#if (defined(WOLFSSL_AFALG_HASH) && defined(WOLFSSL_AFALG_HASH_KEEP)) || \
    (defined(WOLFSSL_DEVCRYPTO_HASH) && defined(WOLFSSL_DEVCRYPTO_HASH_KEEP)) || \
    (defined(WOLFSSL_RENESAS_TSIP_CRYPT) && \
    !defined(NO_WOLFSSL_RENESAS_TSIP_CRYPT_HASH)) || \
    (defined(WOLFSSL_RENESAS_SCEPROTECT) && \
    !defined(NO_WOLFSSL_RENESAS_SCEPROTECT_HASH)) || \
    defined(WOLFSSL_HASH_KEEP)

    if (sha256->msg != NULL) {
        XFREE(sha256->msg, sha256->heap, DYNAMIC_TYPE_TMP_BUFFER);
        sha256->msg = NULL;
    }
#endif
#if defined(WOLFSSL_KCAPI_HASH)
    KcapiHashFree(&sha256->kcapi);
#endif
#ifdef WOLFSSL_IMXRT_DCP
    DCPSha256Free(sha256);
#endif
}

#endif /* !defined(WOLFSSL_HAVE_PSA) || defined(WOLFSSL_PSA_NO_HASH) */
#ifdef WOLFSSL_HASH_KEEP
/* Some hardware have issues with update, this function stores the data to be
 * hashed into an array. Once ready, the Final operation is called on all of the
 * data to be hashed at once.
 * returns 0 on success
 */
int wc_Sha256_Grow(wc_Sha256* sha256, const byte* in, int inSz)
{
    return _wc_Hash_Grow(&(sha256->msg), &(sha256->used), &(sha256->len), in,
                        inSz, sha256->heap);
}
int wc_Sha224_Grow(wc_Sha224* sha224, const byte* in, int inSz)
{
    return _wc_Hash_Grow(&(sha224->msg), &(sha224->used), &(sha224->len), in,
                        inSz, sha224->heap);
}
#endif /* WOLFSSL_HASH_KEEP */

#endif /* !WOLFSSL_TI_HASH */


#ifndef WOLFSSL_TI_HASH

#if defined(WOLFSSL_KCAPI_HASH) && !defined(WOLFSSL_NO_KCAPI_SHA224)
    /* implemented in wolfcrypt/src/port/kcapi/kcapi_hash.c */
#elif defined(WOLFSSL_HAVE_PSA) && !defined(WOLFSSL_PSA_NO_HASH)
    /* implemented in wolfcrypt/src/port/psa/psa_hash.c */

#else

    int wc_Sha224GetHash(wc_Sha224* sha224, byte* hash)
    {
        int ret;
        wc_Sha224 tmpSha224;

        wc_InitSha224(&tmpSha224);
        if (sha224 == NULL || hash == NULL)
            return BAD_FUNC_ARG;

        ret = wc_Sha224Copy(sha224, &tmpSha224);
        if (ret == 0) {
            ret = wc_Sha224Final(&tmpSha224, hash);
            wc_Sha224Free(&tmpSha224);
        }
        return ret;
    }
    int wc_Sha224Copy(wc_Sha224* src, wc_Sha224* dst)
    {
        int ret = 0;

        if (src == NULL || dst == NULL)
            return BAD_FUNC_ARG;

        XMEMCPY(dst, src, sizeof(wc_Sha224));
    #ifdef WOLFSSL_SMALL_STACK_CACHE
        dst->W = NULL;
    #endif


    #ifdef WOLFSSL_HASH_FLAGS
        dst->flags |= WC_HASH_FLAG_ISCOPY;
    #endif
    #if defined(WOLFSSL_HASH_KEEP)
        if (src->msg != NULL) {
            dst->msg = (byte*)XMALLOC(src->len, dst->heap,
                                      DYNAMIC_TYPE_TMP_BUFFER);
            if (dst->msg == NULL)
                return MEMORY_E;
            XMEMCPY(dst->msg, src->msg, src->len);
        }
    #endif

        return ret;
    }

#endif /* WOLFSSL_KCAPI_HASH && !WOLFSSL_NO_KCAPI_SHA224 */

#ifdef WOLFSSL_HASH_FLAGS
    int wc_Sha224SetFlags(wc_Sha224* sha224, word32 flags)
    {
        if (sha224) {
            sha224->flags = flags;
        }
        return 0;
    }
    int wc_Sha224GetFlags(wc_Sha224* sha224, word32* flags)
    {
        if (sha224 && flags) {
            *flags = sha224->flags;
        }
        return 0;
    }
#endif


#ifdef WOLFSSL_AFALG_HASH
    /* implemented in wolfcrypt/src/port/af_alg/afalg_hash.c */

#elif defined(WOLFSSL_DEVCRYPTO_HASH)
    /* implemented in wolfcrypt/src/port/devcrypto/devcrypt_hash.c */

#elif defined(WOLFSSL_RENESAS_TSIP_CRYPT) && \
    !defined(NO_WOLFSSL_RENESAS_TSIP_CRYPT_HASH)

    /* implemented in wolfcrypt/src/port/Renesas/renesas_tsip_sha.c */

#elif defined(WOLFSSL_RENESAS_SCEPROTECT) && \
    !defined(NO_WOLFSSL_RENESAS_SCEPROTECT_HASH)

    /* implemented in wolfcrypt/src/port/Renesas/renesas_sce_sha.c */

#elif defined(WOLFSSL_PSOC6_CRYPTO)
    /* implemented in wolfcrypt/src/port/cypress/psoc6_crypto.c */
#elif defined(WOLFSSL_IMXRT_DCP)
    /* implemented in wolfcrypt/src/port/nxp/dcp_port.c */
#elif defined(WOLFSSL_KCAPI_HASH)
    /* implemented in wolfcrypt/src/port/kcapi/kcapi_hash.c */

#elif defined(WOLFSSL_HAVE_PSA) && !defined(WOLFSSL_PSA_NO_HASH)
    /* implemented in wolfcrypt/src/port/psa/psa_hash.c */

#else

int wc_Sha256GetHash(wc_Sha256* sha256, byte* hash)
{
    int ret;
    wc_Sha256 tmpSha256;

    if (sha256 == NULL || hash == NULL)
        return BAD_FUNC_ARG;

#if  defined(WOLFSSL_ESP32WROOM32_CRYPT) && \
    !defined(NO_WOLFSSL_ESP32WROOM32_CRYPT_HASH)
    if(sha256->ctx.mode == ESP32_SHA_INIT){
        esp_sha_try_hw_lock(&sha256->ctx);
    }
    if(sha256->ctx.mode == ESP32_SHA_HW)
    {
        esp_sha256_digest_process(sha256, 0);
    }
#endif
    ret = wc_Sha256Copy(sha256, &tmpSha256);
    if (ret == 0) {
        ret = wc_Sha256Final(&tmpSha256, hash);
#if  defined(WOLFSSL_ESP32WROOM32_CRYPT) && \
    !defined(NO_WOLFSSL_ESP32WROOM32_CRYPT_HASH)
        sha256->ctx.mode = ESP32_SHA_SW;
#endif

        wc_Sha256Free(&tmpSha256);
    }
    return ret;
}
int wc_Sha256Copy(wc_Sha256* src, wc_Sha256* dst)
{
    int ret = 0;

    if (src == NULL || dst == NULL)
        return BAD_FUNC_ARG;

    XMEMCPY(dst, src, sizeof(wc_Sha256));
#ifdef WOLFSSL_SMALL_STACK_CACHE
    dst->W = NULL;
#endif


#ifdef WOLFSSL_PIC32MZ_HASH
    ret = wc_Pic32HashCopy(&src->cache, &dst->cache);
#endif
#if  defined(WOLFSSL_ESP32WROOM32_CRYPT) && \
    !defined(NO_WOLFSSL_ESP32WROOM32_CRYPT_HASH)
     dst->ctx.mode = src->ctx.mode;
     dst->ctx.isfirstblock = src->ctx.isfirstblock;
     dst->ctx.sha_type = src->ctx.sha_type;
#endif
#ifdef WOLFSSL_HASH_FLAGS
     dst->flags |= WC_HASH_FLAG_ISCOPY;
#endif
#if defined(WOLFSSL_HASH_KEEP)
    if (src->msg != NULL) {
        dst->msg = (byte*)XMALLOC(src->len, dst->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (dst->msg == NULL)
            return MEMORY_E;
        XMEMCPY(dst->msg, src->msg, src->len);
    }
#endif

    return ret;
}
#endif

#ifdef WOLFSSL_HASH_FLAGS
int wc_Sha256SetFlags(wc_Sha256* sha256, word32 flags)
{
    if (sha256) {
        sha256->flags = flags;
    }
    return 0;
}
int wc_Sha256GetFlags(wc_Sha256* sha256, word32* flags)
{
    if (sha256 && flags) {
        *flags = sha256->flags;
    }
    return 0;
}
#endif
#endif /* !WOLFSSL_TI_HASH */

#endif /* NO_SHA256 */
