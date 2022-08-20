/* poly1305.c
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
/*

DESCRIPTION
This library contains implementation for the Poly1305 authenticator.

Based off the public domain implementations by Andrew Moon
and Daniel J. Bernstein

*/


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/poly1305.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/cpuid.h>
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#ifdef CHACHA_AEAD_TEST
    #include <stdio.h>
#endif


    #include <emmintrin.h>
    #include <immintrin.h>

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

static word32 intel_flags = 0;
static word32 cpu_flags_set = 0;

    #if defined(__GNUC__)
        #define POLY1305_NOINLINE __attribute__((noinline))
    #else
        #define POLY1305_NOINLINE
    #endif

    #if defined(__GNUC__)
        #if defined(__SIZEOF_INT128__)
            PEDANTIC_EXTENSION typedef unsigned __int128 word128;
        #else
            typedef unsigned word128 __attribute__((mode(TI)));
        #endif

        #define MUL(out, x, y) out = ((word128)(x) * (y))
        #define ADD(out, in) (out) += (in)
        #define ADDLO(out, in) (out) += (in)
        #define SHR(in, shift) (word64)((in) >> (shift))
        #define LO(in) (word64)(in)
    #endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Process one block (16 bytes) of data.
 *
 * ctx  Poly1305 context.
 * m    One block of message data.
 */
extern void poly1305_block_avx(Poly1305* ctx, const unsigned char *m);
/* Process multiple blocks (n * 16 bytes) of data.
 *
 * ctx    Poly1305 context.
 * m      Blocks of message data.
 * bytes  The number of bytes to process.
 */
extern void poly1305_blocks_avx(Poly1305* ctx, const unsigned char* m,
                                size_t bytes);
/* Set the key to use when processing data.
 * Initialize the context.
 *
 * ctx  Poly1305 context.
 * key  The key data (16 bytes).
 */
extern void poly1305_setkey_avx(Poly1305* ctx, const byte* key);
/* Calculate the final result - authentication data.
 * Zeros out the private data in the context.
 *
 * ctx  Poly1305 context.
 * mac  Buffer to hold 16 bytes.
 */
extern void poly1305_final_avx(Poly1305* ctx, byte* mac);

#ifdef HAVE_INTEL_AVX2
/* Process multiple blocks (n * 16 bytes) of data.
 *
 * ctx    Poly1305 context.
 * m      Blocks of message data.
 * bytes  The number of bytes to process.
 */
extern void poly1305_blocks_avx2(Poly1305* ctx, const unsigned char* m,
                                 size_t bytes);
/* Calculate R^1, R^2, R^3 and R^4 and store them in the context.
 *
 * ctx    Poly1305 context.
 */
extern void poly1305_calc_powers_avx2(Poly1305* ctx);
/* Set the key to use when processing data.
 * Initialize the context.
 * Calls AVX set key function as final function calls AVX code.
 *
 * ctx  Poly1305 context.
 * key  The key data (16 bytes).
 */
extern void poly1305_setkey_avx2(Poly1305* ctx, const byte* key);
/* Calculate the final result - authentication data.
 * Zeros out the private data in the context.
 * Calls AVX final function to quickly process last blocks.
 *
 * ctx  Poly1305 context.
 * mac  Buffer to hold 16 bytes - authentication data.
 */
extern void poly1305_final_avx2(Poly1305* ctx, byte* mac);
#endif

#ifdef __cplusplus
    }  /* extern "C" */
#endif


/* convert 32-bit unsigned to little endian 64 bit type as byte array */
static WC_INLINE void u32tole64(const word32 inLe32, byte outLe64[8])
{
    *(word64*)outLe64 = inLe32;
}


#if !defined(WOLFSSL_ARMASM) || !defined(__aarch64__)
/*
This local function operates on a message with a given number of bytes
with a given ctx pointer to a Poly1305 structure.
*/
static int poly1305_blocks(Poly1305* ctx, const unsigned char *m,
                     size_t bytes)
{
    /* AVX2 is handled in wc_Poly1305Update. */
    SAVE_VECTOR_REGISTERS(return _svr_ret;);
    poly1305_blocks_avx(ctx, m, bytes);
    RESTORE_VECTOR_REGISTERS();
    return 0;
}

/*
This local function is used for the last call when a message with a given
number of bytes is less than the block size.
*/
static int poly1305_block(Poly1305* ctx, const unsigned char *m)
{
    /* No call to poly1305_block when AVX2, AVX2 does 4 blocks at a time. */
    SAVE_VECTOR_REGISTERS(return _svr_ret;);
    poly1305_block_avx(ctx, m);
    RESTORE_VECTOR_REGISTERS();
    return 0;
}
#endif /* !defined(WOLFSSL_ARMASM) || !defined(__aarch64__) */

#if !defined(WOLFSSL_ARMASM) || !defined(__aarch64__)
int wc_Poly1305SetKey(Poly1305* ctx, const byte* key, word32 keySz)
{

    if (key == NULL)
        return BAD_FUNC_ARG;

#ifdef CHACHA_AEAD_TEST
    word32 k;
    printf("Poly key used:\n");
    for (k = 0; k < keySz; k++) {
        printf("%02x", key[k]);
        if ((k+1) % 8 == 0)
            printf("\n");
    }
    printf("\n");
#endif

    if (keySz != 32 || ctx == NULL)
        return BAD_FUNC_ARG;

    if (!cpu_flags_set) {
        intel_flags = cpuid_get_flags();
        cpu_flags_set = 1;
    }
    SAVE_VECTOR_REGISTERS(return _svr_ret;);
    #ifdef HAVE_INTEL_AVX2
    if (IS_INTEL_AVX2(intel_flags))
        poly1305_setkey_avx2(ctx, key);
    else
    #endif
        poly1305_setkey_avx(ctx, key);
    RESTORE_VECTOR_REGISTERS();

    return 0;
}

int wc_Poly1305Final(Poly1305* ctx, byte* mac)
{

    if (ctx == NULL || mac == NULL)
        return BAD_FUNC_ARG;

    SAVE_VECTOR_REGISTERS(return _svr_ret;);
    #ifdef HAVE_INTEL_AVX2
    if (IS_INTEL_AVX2(intel_flags))
        poly1305_final_avx2(ctx, mac);
    else
    #endif
        poly1305_final_avx(ctx, mac);
    RESTORE_VECTOR_REGISTERS();

    return 0;
}
#endif /* !defined(WOLFSSL_ARMASM) || !defined(__aarch64__) */


int wc_Poly1305Update(Poly1305* ctx, const byte* m, word32 bytes)
{
    size_t i;

    if (ctx == NULL || (m == NULL && bytes > 0))
        return BAD_FUNC_ARG;

    if (bytes == 0) {
        /* valid, but do nothing */
        return 0;
    }
#ifdef CHACHA_AEAD_TEST
    word32 k;
    printf("Raw input to poly:\n");
    for (k = 0; k < bytes; k++) {
        printf("%02x", m[k]);
        if ((k+1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
#endif

    #ifdef HAVE_INTEL_AVX2
    if (IS_INTEL_AVX2(intel_flags)) {
        SAVE_VECTOR_REGISTERS(return _svr_ret;);

        /* handle leftover */

        if (ctx->leftover) {
            size_t want = sizeof(ctx->buffer) - ctx->leftover;
            if (want > bytes)
                want = bytes;

            for (i = 0; i < want; i++)
                ctx->buffer[ctx->leftover + i] = m[i];
            bytes -= (word32)want;
            m += want;
            ctx->leftover += want;
            if (ctx->leftover < sizeof(ctx->buffer)) {
                RESTORE_VECTOR_REGISTERS();
                return 0;
            }

            if (!ctx->started)
                poly1305_calc_powers_avx2(ctx);
            poly1305_blocks_avx2(ctx, ctx->buffer, sizeof(ctx->buffer));
            ctx->leftover = 0;
        }

        /* process full blocks */
        if (bytes >= sizeof(ctx->buffer)) {
            size_t want = bytes & ~(sizeof(ctx->buffer) - 1);

            if (!ctx->started)
                poly1305_calc_powers_avx2(ctx);
            poly1305_blocks_avx2(ctx, m, want);
            m += want;
            bytes -= (word32)want;
        }

        /* store leftover */
        if (bytes) {
            for (i = 0; i < bytes; i++)
                ctx->buffer[ctx->leftover + i] = m[i];
            ctx->leftover += bytes;
        }
        RESTORE_VECTOR_REGISTERS();
    }
    else
    #endif
    {
        /* handle leftover */
        if (ctx->leftover) {
            size_t want = (POLY1305_BLOCK_SIZE - ctx->leftover);
            if (want > bytes)
                want = bytes;
            for (i = 0; i < want; i++)
                ctx->buffer[ctx->leftover + i] = m[i];
            bytes -= (word32)want;
            m += want;
            ctx->leftover += want;
            if (ctx->leftover < POLY1305_BLOCK_SIZE)
                return 0;
            poly1305_block(ctx, ctx->buffer);
            ctx->leftover = 0;
        }

        /* process full blocks */
        if (bytes >= POLY1305_BLOCK_SIZE) {
            size_t want = (bytes & ~(POLY1305_BLOCK_SIZE - 1));
#if !defined(WOLFSSL_ARMASM) || !defined(__aarch64__)
            int ret;
            ret = poly1305_blocks(ctx, m, want);
            if (ret != 0)
                return ret;
#else
            poly1305_blocks(ctx, m, want);
#endif
            m += want;
            bytes -= (word32)want;
        }

        /* store leftover */
        if (bytes) {
            for (i = 0; i < bytes; i++)
                ctx->buffer[ctx->leftover + i] = m[i];
            ctx->leftover += bytes;
        }
    }

    return 0;
}

/*  Takes a Poly1305 struct that has a key loaded and pads the provided length
    ctx        : Initialized Poly1305 struct to use
    lenToPad   : Current number of bytes updated that needs padding to 16
 */
int wc_Poly1305_Pad(Poly1305* ctx, word32 lenToPad)
{
    int ret = 0;
    word32 paddingLen;
    byte padding[WC_POLY1305_PAD_SZ - 1];

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }
    if (lenToPad == 0) {
        return 0; /* nothing needs to be done */
    }

    XMEMSET(padding, 0, sizeof(padding));

    /* Pad length to 16 bytes */
    paddingLen = (-(int)lenToPad) & (WC_POLY1305_PAD_SZ - 1);
    if ((paddingLen > 0) && (paddingLen < WC_POLY1305_PAD_SZ)) {
        ret = wc_Poly1305Update(ctx, padding, paddingLen);
    }
    return ret;
}

/*  Takes a Poly1305 struct that has a key loaded and adds the AEAD length
    encoding in 64-bit little endian
    aadSz      : Size of the additional authentication data
    dataSz     : Size of the plaintext or ciphertext
 */
int wc_Poly1305_EncodeSizes(Poly1305* ctx, word32 aadSz, word32 dataSz)
{
    int ret;
    byte little64[16]; /* sizeof(word64) * 2 */

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(little64, 0, sizeof(little64));

    /* size of additional data and input data as little endian 64 bit types */
    u32tole64(aadSz,  little64);
    u32tole64(dataSz, little64 + 8);
    ret = wc_Poly1305Update(ctx, little64, sizeof(little64));

    return ret;
}

#ifdef WORD64_AVAILABLE
int wc_Poly1305_EncodeSizes64(Poly1305* ctx, word64 aadSz, word64 dataSz)
{
    int ret;
    word64 little64[2];

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef BIG_ENDIAN_ORDER
    little64[0] = ByteReverseWord64(aadSz);
    little64[1] = ByteReverseWord64(dataSz);
#else
    little64[0] = aadSz;
    little64[1] = dataSz;
#endif

    ret = wc_Poly1305Update(ctx, (byte *)little64, sizeof(little64));

    return ret;
}
#endif

/*  Takes in an initialized Poly1305 struct that has a key loaded and creates
    a MAC (tag) using recent TLS AEAD padding scheme.
    ctx        : Initialized Poly1305 struct to use
    additional : Additional data to use
    addSz      : Size of additional buffer
    input      : Input buffer to create tag from
    sz         : Size of input buffer
    tag        : Buffer to hold created tag
    tagSz      : Size of input tag buffer (must be at least
                 WC_POLY1305_MAC_SZ(16))
 */
int wc_Poly1305_MAC(Poly1305* ctx, const byte* additional, word32 addSz,
                    const byte* input, word32 sz, byte* tag, word32 tagSz)
{
    int ret;

    /* sanity check on arguments */
    if (ctx == NULL || input == NULL || tag == NULL ||
                                                   tagSz < WC_POLY1305_MAC_SZ) {
        return BAD_FUNC_ARG;
    }

    /* additional allowed to be 0 */
    if (addSz > 0) {
        if (additional == NULL)
            return BAD_FUNC_ARG;

        /* additional data plus padding */
        if ((ret = wc_Poly1305Update(ctx, additional, addSz)) != 0) {
            return ret;
        }
        /* pad additional data */
        if ((ret = wc_Poly1305_Pad(ctx, addSz)) != 0) {
            return ret;
        }
    }

    /* input plus padding */
    if ((ret = wc_Poly1305Update(ctx, input, sz)) != 0) {
        return ret;
    }
    /* pad input data */
    if ((ret = wc_Poly1305_Pad(ctx, sz)) != 0) {
        return ret;
    }

    /* encode size of AAD and input data as little endian 64 bit types */
    if ((ret = wc_Poly1305_EncodeSizes(ctx, addSz, sz)) != 0) {
        return ret;
    }

    /* Finalize the auth tag */
    ret = wc_Poly1305Final(ctx, tag);

    return ret;

}
