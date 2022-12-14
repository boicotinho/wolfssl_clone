/* sp.c
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

/* Implementation by Sean Parkinson. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/cpuid.h>
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>

#ifdef RSA_LOW_MEM
#ifndef WOLFSSL_SP_SMALL
#define WOLFSSL_SP_SMALL
#endif
#endif

#include <wolfssl/wolfcrypt/sp.h>

#ifdef WOLFSSL_SP_ARM64_ASM
#define SP_PRINT_NUM(var, name, total, words, bits)         \
    do {                                                    \
        int ii;                                             \
        fprintf(stderr, name "=0x");                        \
        for (ii = ((bits + 63) / 64) - 1; ii >= 0; ii--)    \
            fprintf(stderr, SP_PRINT_FMT, (var)[ii]);       \
        fprintf(stderr, "\n");                              \
    } while (0)

#define SP_PRINT_VAL(var, name)                             \
    fprintf(stderr, name "=0x" SP_PRINT_FMT "\n", var)

#define SP_PRINT_INT(var, name)                             \
    fprintf(stderr, name "=%d\n", var)

#if defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH)
#ifndef WOLFSSL_SP_NO_2048
/* Read big endian unsigned byte array into r.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  Byte array.
 * n  Number of bytes in array to read.
 */
static void sp_2048_from_bin(sp_digit* r, int size, const byte* a, int n)
{
    sp_int64 nl = n;
    sp_int64 size8 = size * 8;

    __asm__ __volatile__ (
        "add	x4, %[a], %[n]\n\t"
        "mov	x5, %[r]\n\t"
        "sub	x4, x4, 8\n\t"
        "subs	x6, %[n], 8\n\t"
        "mov	x7, xzr\n\t"
        "blt	2f\n\t"
        /* Put in mulitples of 8 bytes. */
        "1:\n\t"
        "ldr	x8, [x4], -8\n\t"
        "subs	x6, x6, 8\n\t"
        "rev	x8, x8\n\t"
        "str	x8, [x5], 8\n\t"
        "add	x7, x7, 8\n\t"
        "b.ge	1b\n\t"
        "2:\n\t"
        "cmp	x6, -7\n\t"
        "b.lt	20f\n\t"
        /* Put in less than 8 bytes. */
        "str	xzr, [x5]\n\t"
        "add	x7, x7, 8\n\t"
        "add	x4, x4, 7\n\t"
        "b.eq	17f\n\t"
        "cmp	x6, -5\n\t"
        "b.lt	16f\n\t"
        "b.eq	15f\n\t"
        "cmp	x6, -3\n\t"
        "b.lt	14f\n\t"
        "b.eq	13f\n\t"
        "cmp	x6, -2\n\t"
        "b.eq	12f\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "12:\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "13:\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "14:\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "15:\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "16:\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "17:\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "20:\n\t"
        "add	x5, %[r], x7\n\t"
        "subs	x7, %[size], x7\n\t"
        "b.eq	30f\n\t"
        /* Zero out remaining words. */
        "21:\n\t"
        "subs	x7, x7, 8\n\t"
        "str	xzr, [x5], 8\n\t"
        "b.gt	21b\n\t"
        "30:\n\t"
        :
        : [r] "r" (r), [size] "r" (size8), [a] "r" (a), [n] "r" (nl)
        : "memory", "x4", "x5", "x6", "x7", "x8"
    );
}

/* Convert an mp_int to an array of sp_digit.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  A multi-precision integer.
 */
static void sp_2048_from_mp(sp_digit* r, int size, const mp_int* a)
{
#if DIGIT_BIT == 64
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 64
    int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0xffffffffffffffffl;
        s = 64U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 64U) <= (word32)DIGIT_BIT) {
            s += 64U;
            r[j] &= 0xffffffffffffffffl;
            if (j + 1 >= size) {
                break;
            }
            if (s < (word32)DIGIT_BIT) {
                /* lint allow cast of mismatch word32 and mp_digit */
                r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
            }
            else {
                r[++j] = (sp_digit)0;
            }
        }
        s = (word32)DIGIT_BIT - s;
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
#else
    int i;
    int j = 0;
    int s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i]) << s;
        if (s + DIGIT_BIT >= 64) {
            r[j] &= 0xffffffffffffffffl;
            if (j + 1 >= size) {
                break;
            }
            s = 64 - s;
            if (s == DIGIT_BIT) {
                r[++j] = 0;
                s = 0;
            }
            else {
                r[++j] = a->dp[i] >> s;
                s = DIGIT_BIT - s;
            }
        }
        else {
            s += DIGIT_BIT;
        }
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
#endif
}

/* Write r as big endian to byte array.
 * Fixed length number of bytes written: 256
 *
 * r  A single precision integer.
 * a  Byte array.
 */
static void sp_2048_to_bin_32(sp_digit* r, byte* a)
{
    int i;
    int j = 0;

    for (i = 31; i >= 0; i--, j += 8) {
        __asm__ __volatile__ (
            "ldr	x4, [%[r]]\n\t"
            "rev	x4, x4\n\t"
            "str	x4, [%[a]]\n\t"
            :
            : [r] "r" (r + i), [a] "r" (a + j)
            : "memory", "x4"
        );
    }
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && (!defined(WOLFSSL_RSA_PUBLIC_ONLY) || !defined(WOLFSSL_SP_SMALL))) || defined(WOLFSSL_HAVE_SP_DH)
/* Normalize the values in each word to 64.
 *
 * a  Array of sp_digit to normalize.
 */
#define sp_2048_norm_32(a)

#endif /* (WOLFSSL_HAVE_SP_RSA && (!WOLFSSL_RSA_PUBLIC_ONLY || !WOLFSSL_SP_SMALL)) || WOLFSSL_HAVE_SP_DH */
/* Normalize the values in each word to 64.
 *
 * a  Array of sp_digit to normalize.
 */
#define sp_2048_norm_32(a)

#ifndef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static void sp_2048_mul_8(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x8, x9, [%[a], 0]\n\t"
        "ldp	x10, x11, [%[a], 16]\n\t"
        "ldp	x12, x13, [%[a], 32]\n\t"
        "ldp	x14, x15, [%[a], 48]\n\t"
        "ldp	x16, x17, [%[b], 0]\n\t"
        "ldp	x19, x20, [%[b], 16]\n\t"
        "ldp	x21, x22, [%[b], 32]\n\t"
        "ldp	x23, x24, [%[b], 48]\n\t"
        "#  A[0] * B[0]\n\t"
        "mul	x3, x8, x16\n\t"
        "umulh	x4, x8, x16\n\t"
        "str	x3, [%[r]]\n\t"
        "#  A[0] * B[1]\n\t"
        "mul	x6, x8, x17\n\t"
        "umulh	x7, x8, x17\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[1] * B[0]\n\t"
        "mul	x6, x9, x16\n\t"
        "adc	x5, xzr, x7\n\t"
        "umulh	x7, x9, x16\n\t"
        "adds	x4, x4, x6\n\t"
        "adcs	x5, x5, x7\n\t"
        "str	x4, [%[r], 8]\n\t"
        "adc	x3, xzr, xzr\n\t"
        "#  A[0] * B[2]\n\t"
        "mul	x6, x8, x19\n\t"
        "umulh	x7, x8, x19\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[1] * B[1]\n\t"
        "mul	x6, x9, x17\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x9, x17\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[2] * B[0]\n\t"
        "mul	x6, x10, x16\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x10, x16\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "adcs	x3, x3, x7\n\t"
        "str	x5, [%[r], 16]\n\t"
        "adc	x4, x4, xzr\n\t"
        "#  A[0] * B[3]\n\t"
        "mul	x6, x8, x20\n\t"
        "umulh	x7, x8, x20\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[1] * B[2]\n\t"
        "mul	x6, x9, x19\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x9, x19\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[2] * B[1]\n\t"
        "mul	x6, x10, x17\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x10, x17\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[3] * B[0]\n\t"
        "mul	x6, x11, x16\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x11, x16\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "adcs	x4, x4, x7\n\t"
        "str	x3, [%[r], 24]\n\t"
        "adc	x5, x5, xzr\n\t"
        "#  A[0] * B[4]\n\t"
        "mul	x6, x8, x21\n\t"
        "umulh	x7, x8, x21\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[1] * B[3]\n\t"
        "mul	x6, x9, x20\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x9, x20\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[2] * B[2]\n\t"
        "mul	x6, x10, x19\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x10, x19\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[3] * B[1]\n\t"
        "mul	x6, x11, x17\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x11, x17\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[4] * B[0]\n\t"
        "mul	x6, x12, x16\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x12, x16\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "adcs	x5, x5, x7\n\t"
        "str	x4, [%[r], 32]\n\t"
        "adc	x3, x3, xzr\n\t"
        "#  A[0] * B[5]\n\t"
        "mul	x6, x8, x22\n\t"
        "umulh	x7, x8, x22\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[1] * B[4]\n\t"
        "mul	x6, x9, x21\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x9, x21\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[2] * B[3]\n\t"
        "mul	x6, x10, x20\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x10, x20\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[3] * B[2]\n\t"
        "mul	x6, x11, x19\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x11, x19\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[4] * B[1]\n\t"
        "mul	x6, x12, x17\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x12, x17\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[5] * B[0]\n\t"
        "mul	x6, x13, x16\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x13, x16\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "adcs	x3, x3, x7\n\t"
        "str	x5, [%[r], 40]\n\t"
        "adc	x4, x4, xzr\n\t"
        "#  A[0] * B[6]\n\t"
        "mul	x6, x8, x23\n\t"
        "umulh	x7, x8, x23\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[1] * B[5]\n\t"
        "mul	x6, x9, x22\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x9, x22\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[2] * B[4]\n\t"
        "mul	x6, x10, x21\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x10, x21\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[3] * B[3]\n\t"
        "mul	x6, x11, x20\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x11, x20\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[4] * B[2]\n\t"
        "mul	x6, x12, x19\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x12, x19\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[5] * B[1]\n\t"
        "mul	x6, x13, x17\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x13, x17\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[6] * B[0]\n\t"
        "mul	x6, x14, x16\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x14, x16\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "adcs	x4, x4, x7\n\t"
        "str	x3, [%[r], 48]\n\t"
        "adc	x5, x5, xzr\n\t"
        "#  A[0] * B[7]\n\t"
        "mul	x6, x8, x24\n\t"
        "umulh	x7, x8, x24\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[1] * B[6]\n\t"
        "mul	x6, x9, x23\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x9, x23\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[2] * B[5]\n\t"
        "mul	x6, x10, x22\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x10, x22\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[3] * B[4]\n\t"
        "mul	x6, x11, x21\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x11, x21\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[4] * B[3]\n\t"
        "mul	x6, x12, x20\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x12, x20\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[5] * B[2]\n\t"
        "mul	x6, x13, x19\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x13, x19\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[6] * B[1]\n\t"
        "mul	x6, x14, x17\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x14, x17\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[7] * B[0]\n\t"
        "mul	x6, x15, x16\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x15, x16\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "adcs	x5, x5, x7\n\t"
        "str	x4, [%[r], 56]\n\t"
        "adc	x3, x3, xzr\n\t"
        "#  A[1] * B[7]\n\t"
        "mul	x6, x9, x24\n\t"
        "umulh	x7, x9, x24\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[2] * B[6]\n\t"
        "mul	x6, x10, x23\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x10, x23\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[3] * B[5]\n\t"
        "mul	x6, x11, x22\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x11, x22\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[4] * B[4]\n\t"
        "mul	x6, x12, x21\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x12, x21\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[5] * B[3]\n\t"
        "mul	x6, x13, x20\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x13, x20\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[6] * B[2]\n\t"
        "mul	x6, x14, x19\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x14, x19\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[7] * B[1]\n\t"
        "mul	x6, x15, x17\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x15, x17\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "adcs	x3, x3, x7\n\t"
        "str	x5, [%[r], 64]\n\t"
        "adc	x4, x4, xzr\n\t"
        "#  A[2] * B[7]\n\t"
        "mul	x6, x10, x24\n\t"
        "umulh	x7, x10, x24\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[3] * B[6]\n\t"
        "mul	x6, x11, x23\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x11, x23\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[4] * B[5]\n\t"
        "mul	x6, x12, x22\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x12, x22\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[5] * B[4]\n\t"
        "mul	x6, x13, x21\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x13, x21\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[6] * B[3]\n\t"
        "mul	x6, x14, x20\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x14, x20\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[7] * B[2]\n\t"
        "mul	x6, x15, x19\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x15, x19\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "adcs	x4, x4, x7\n\t"
        "str	x3, [%[r], 72]\n\t"
        "adc	x5, x5, xzr\n\t"
        "#  A[3] * B[7]\n\t"
        "mul	x6, x11, x24\n\t"
        "umulh	x7, x11, x24\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[4] * B[6]\n\t"
        "mul	x6, x12, x23\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x12, x23\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[5] * B[5]\n\t"
        "mul	x6, x13, x22\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x13, x22\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[6] * B[4]\n\t"
        "mul	x6, x14, x21\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x14, x21\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[7] * B[3]\n\t"
        "mul	x6, x15, x20\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x15, x20\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "adcs	x5, x5, x7\n\t"
        "str	x4, [%[r], 80]\n\t"
        "adc	x3, x3, xzr\n\t"
        "#  A[4] * B[7]\n\t"
        "mul	x6, x12, x24\n\t"
        "umulh	x7, x12, x24\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[5] * B[6]\n\t"
        "mul	x6, x13, x23\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x13, x23\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[6] * B[5]\n\t"
        "mul	x6, x14, x22\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x14, x22\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[7] * B[4]\n\t"
        "mul	x6, x15, x21\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x15, x21\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "adcs	x3, x3, x7\n\t"
        "str	x5, [%[r], 88]\n\t"
        "adc	x4, x4, xzr\n\t"
        "#  A[5] * B[7]\n\t"
        "mul	x6, x13, x24\n\t"
        "umulh	x7, x13, x24\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[6] * B[6]\n\t"
        "mul	x6, x14, x23\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x14, x23\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[7] * B[5]\n\t"
        "mul	x6, x15, x22\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x15, x22\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "adcs	x4, x4, x7\n\t"
        "str	x3, [%[r], 96]\n\t"
        "adc	x5, x5, xzr\n\t"
        "#  A[6] * B[7]\n\t"
        "mul	x6, x14, x24\n\t"
        "umulh	x7, x14, x24\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[7] * B[6]\n\t"
        "mul	x6, x15, x23\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x15, x23\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "adcs	x5, x5, x7\n\t"
        "str	x4, [%[r], 104]\n\t"
        "adc	x3, x3, xzr\n\t"
        "#  A[7] * B[7]\n\t"
        "mul	x6, x15, x24\n\t"
        "umulh	x7, x15, x24\n\t"
        "adds	x5, x5, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "stp	x5, x3, [%[r], 112]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "x24"
    );
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_2048_add_8(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x7, x8, [%[b], 0]\n\t"
        "adds	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 16]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldp	x3, x4, [%[a], 32]\n\t"
        "ldp	x7, x8, [%[b], 32]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 48]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 48]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 32]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 48]\n\t"
        "cset	%[r], cs\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return (sp_digit)r;
}

/* Add digit to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static void sp_2048_add_word_8(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "adds	x3, x3, %[b]\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldp	x3, x4, [%[a], 32]\n\t"
        "ldp	x5, x6, [%[a], 48]\n\t"
        "adcs	x3, x3, xzr\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 32]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 48]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6"
    );
}

/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer and result.
 * b  A single precision integer.
 */
static sp_digit sp_2048_sub_in_place_16(sp_digit* a, const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x2, x3, [%[a], 0]\n\t"
        "ldp	x6, x7, [%[b], 0]\n\t"
        "subs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 16]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 16]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 0]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 16]\n\t"
        "ldp	x2, x3, [%[a], 32]\n\t"
        "ldp	x6, x7, [%[b], 32]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 48]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 48]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 32]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 48]\n\t"
        "ldp	x2, x3, [%[a], 64]\n\t"
        "ldp	x6, x7, [%[b], 64]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 80]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 80]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 64]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 80]\n\t"
        "ldp	x2, x3, [%[a], 96]\n\t"
        "ldp	x6, x7, [%[b], 96]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 112]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 112]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 96]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 112]\n\t"
        "csetm	%[a], cc\n\t"
        : [a] "+r" (a)
        : [b] "r" (b)
        : "memory", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );

    return (sp_digit)a;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_2048_add_16(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x7, x8, [%[b], 0]\n\t"
        "adds	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 16]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldp	x3, x4, [%[a], 32]\n\t"
        "ldp	x7, x8, [%[b], 32]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 48]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 48]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 32]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 48]\n\t"
        "ldp	x3, x4, [%[a], 64]\n\t"
        "ldp	x7, x8, [%[b], 64]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 80]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 80]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 64]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 80]\n\t"
        "ldp	x3, x4, [%[a], 96]\n\t"
        "ldp	x7, x8, [%[b], 96]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 112]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 112]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 96]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 112]\n\t"
        "cset	%[r], cs\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return (sp_digit)r;
}

#ifndef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static sp_digit sp_2048_cond_add_8(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    __asm__ __volatile__ (

        "ldp	x8, x9, [%[b], 0]\n\t"
        "ldp	x10, x11, [%[b], 16]\n\t"
        "ldp	x4, x5, [%[a], 0]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 16]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adds	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 0]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 16]\n\t"
        "ldp	x8, x9, [%[b], 32]\n\t"
        "ldp	x10, x11, [%[b], 48]\n\t"
        "ldp	x4, x5, [%[a], 32]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 48]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adcs	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 32]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 48]\n\t"
        "cset	%[r], cs\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    return (sp_digit)r;
}
#endif /* !WOLFSSL_SP_SMALL */

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_16(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[16];
    sp_digit a1[8];
    sp_digit b1[8];
    sp_digit* z2 = r + 16;
    sp_digit u;
    sp_digit ca;
    sp_digit cb;

    ca = sp_2048_add_8(a1, a, &a[8]);
    cb = sp_2048_add_8(b1, b, &b[8]);
    u  = ca & cb;

    sp_2048_mul_8(z2, &a[8], &b[8]);
    sp_2048_mul_8(z0, a, b);
    sp_2048_mul_8(z1, a1, b1);

    u += sp_2048_sub_in_place_16(z1, z0);
    u += sp_2048_sub_in_place_16(z1, z2);
    u += sp_2048_cond_add_8(z1 + 8, z1 + 8, a1, 0 - cb);
    u += sp_2048_cond_add_8(z1 + 8, z1 + 8, b1, 0 - ca);

    u += sp_2048_add_16(r + 8, r + 8, z1);
    (void)sp_2048_add_word_8(r + 24, r + 24, u);
}

/* Add digit to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static void sp_2048_add_word_16(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "adds	x3, x3, %[b]\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldp	x3, x4, [%[a], 32]\n\t"
        "ldp	x5, x6, [%[a], 48]\n\t"
        "adcs	x3, x3, xzr\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 32]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 48]\n\t"
        "ldp	x3, x4, [%[a], 64]\n\t"
        "ldp	x5, x6, [%[a], 80]\n\t"
        "adcs	x3, x3, xzr\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 64]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 80]\n\t"
        "ldp	x3, x4, [%[a], 96]\n\t"
        "ldp	x5, x6, [%[a], 112]\n\t"
        "adcs	x3, x3, xzr\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 96]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 112]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6"
    );
}

/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer and result.
 * b  A single precision integer.
 */
static sp_digit sp_2048_sub_in_place_32(sp_digit* a, const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x2, x3, [%[a], 0]\n\t"
        "ldp	x6, x7, [%[b], 0]\n\t"
        "subs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 16]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 16]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 0]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 16]\n\t"
        "ldp	x2, x3, [%[a], 32]\n\t"
        "ldp	x6, x7, [%[b], 32]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 48]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 48]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 32]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 48]\n\t"
        "ldp	x2, x3, [%[a], 64]\n\t"
        "ldp	x6, x7, [%[b], 64]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 80]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 80]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 64]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 80]\n\t"
        "ldp	x2, x3, [%[a], 96]\n\t"
        "ldp	x6, x7, [%[b], 96]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 112]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 112]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 96]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 112]\n\t"
        "ldp	x2, x3, [%[a], 128]\n\t"
        "ldp	x6, x7, [%[b], 128]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 144]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 144]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 128]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 144]\n\t"
        "ldp	x2, x3, [%[a], 160]\n\t"
        "ldp	x6, x7, [%[b], 160]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 176]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 176]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 160]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 176]\n\t"
        "ldp	x2, x3, [%[a], 192]\n\t"
        "ldp	x6, x7, [%[b], 192]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 208]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 208]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 192]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 208]\n\t"
        "ldp	x2, x3, [%[a], 224]\n\t"
        "ldp	x6, x7, [%[b], 224]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 240]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 240]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 224]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 240]\n\t"
        "csetm	%[a], cc\n\t"
        : [a] "+r" (a)
        : [b] "r" (b)
        : "memory", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );

    return (sp_digit)a;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_2048_add_32(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x7, x8, [%[b], 0]\n\t"
        "adds	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 16]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldp	x3, x4, [%[a], 32]\n\t"
        "ldp	x7, x8, [%[b], 32]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 48]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 48]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 32]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 48]\n\t"
        "ldp	x3, x4, [%[a], 64]\n\t"
        "ldp	x7, x8, [%[b], 64]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 80]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 80]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 64]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 80]\n\t"
        "ldp	x3, x4, [%[a], 96]\n\t"
        "ldp	x7, x8, [%[b], 96]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 112]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 112]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 96]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 112]\n\t"
        "ldp	x3, x4, [%[a], 128]\n\t"
        "ldp	x7, x8, [%[b], 128]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 144]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 144]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 128]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 144]\n\t"
        "ldp	x3, x4, [%[a], 160]\n\t"
        "ldp	x7, x8, [%[b], 160]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 176]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 176]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 160]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 176]\n\t"
        "ldp	x3, x4, [%[a], 192]\n\t"
        "ldp	x7, x8, [%[b], 192]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 208]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 208]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 192]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 208]\n\t"
        "ldp	x3, x4, [%[a], 224]\n\t"
        "ldp	x7, x8, [%[b], 224]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 240]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 240]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 224]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 240]\n\t"
        "cset	%[r], cs\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return (sp_digit)r;
}

#ifndef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static sp_digit sp_2048_cond_add_16(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    __asm__ __volatile__ (

        "ldp	x8, x9, [%[b], 0]\n\t"
        "ldp	x10, x11, [%[b], 16]\n\t"
        "ldp	x4, x5, [%[a], 0]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 16]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adds	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 0]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 16]\n\t"
        "ldp	x8, x9, [%[b], 32]\n\t"
        "ldp	x10, x11, [%[b], 48]\n\t"
        "ldp	x4, x5, [%[a], 32]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 48]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adcs	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 32]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 48]\n\t"
        "ldp	x8, x9, [%[b], 64]\n\t"
        "ldp	x10, x11, [%[b], 80]\n\t"
        "ldp	x4, x5, [%[a], 64]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 80]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adcs	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 64]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 80]\n\t"
        "ldp	x8, x9, [%[b], 96]\n\t"
        "ldp	x10, x11, [%[b], 112]\n\t"
        "ldp	x4, x5, [%[a], 96]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 112]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adcs	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 96]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 112]\n\t"
        "cset	%[r], cs\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    return (sp_digit)r;
}
#endif /* !WOLFSSL_SP_SMALL */

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_32(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[32];
    sp_digit a1[16];
    sp_digit b1[16];
    sp_digit* z2 = r + 32;
    sp_digit u;
    sp_digit ca;
    sp_digit cb;

    ca = sp_2048_add_16(a1, a, &a[16]);
    cb = sp_2048_add_16(b1, b, &b[16]);
    u  = ca & cb;

    sp_2048_mul_16(z2, &a[16], &b[16]);
    sp_2048_mul_16(z0, a, b);
    sp_2048_mul_16(z1, a1, b1);

    u += sp_2048_sub_in_place_32(z1, z0);
    u += sp_2048_sub_in_place_32(z1, z2);
    u += sp_2048_cond_add_16(z1 + 16, z1 + 16, a1, 0 - cb);
    u += sp_2048_cond_add_16(z1 + 16, z1 + 16, b1, 0 - ca);

    u += sp_2048_add_32(r + 16, r + 16, z1);
    (void)sp_2048_add_word_16(r + 48, r + 48, u);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
static void sp_2048_sqr_16(sp_digit* r, const sp_digit* a)
{
    __asm__ __volatile__ (
        "ldp	x10, x11, [%[a], 0]\n\t"
        "ldp	x12, x13, [%[a], 16]\n\t"
        "ldp	x14, x15, [%[a], 32]\n\t"
        "ldp	x16, x17, [%[a], 48]\n\t"
        "ldp	x19, x20, [%[a], 64]\n\t"
        "ldp	x21, x22, [%[a], 80]\n\t"
        "ldp	x23, x24, [%[a], 96]\n\t"
        "ldp	x25, x26, [%[a], 112]\n\t"
        "#  A[0] * A[0]\n\t"
        "mul	x2, x10, x10\n\t"
        "umulh	x3, x10, x10\n\t"
        "str	x2, [%[r]]\n\t"
        "mov	x4, xzr\n\t"
        "#  A[0] * A[1]\n\t"
        "mul	x8, x10, x11\n\t"
        "umulh	x9, x10, x11\n\t"
        "adds	x3, x3, x8\n\t"
        "adcs	x4, x4, x9\n\t"
        "adc	x2, xzr, xzr\n\t"
        "adds	x3, x3, x8\n\t"
        "str	x3, [%[r], 8]\n\t"
        "#  A[0] * A[2]\n\t"
        "mul	x8, x10, x12\n\t"
        "adcs	x4, x4, x9\n\t"
        "umulh	x9, x10, x12\n\t"
        "adc	x2, x2, xzr\n\t"
        "adds	x4, x4, x8\n\t"
        "adcs	x2, x2, x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x4, x4, x8\n\t"
        "#  A[1] * A[1]\n\t"
        "mul	x8, x11, x11\n\t"
        "adcs	x2, x2, x9\n\t"
        "umulh	x9, x11, x11\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x8\n\t"
        "str	x4, [%[r], 16]\n\t"
        "#  A[0] * A[3]\n\t"
        "mul	x8, x10, x13\n\t"
        "adcs	x2, x2, x9\n\t"
        "umulh	x9, x10, x13\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x2, x2, x8\n\t"
        "adcs	x3, x3, x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x2, x2, x8\n\t"
        "#  A[1] * A[2]\n\t"
        "mul	x8, x11, x12\n\t"
        "adcs	x3, x3, x9\n\t"
        "umulh	x9, x11, x12\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x2, x2, x8\n\t"
        "adcs	x3, x3, x9\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x2, x2, x8\n\t"
        "str	x2, [%[r], 24]\n\t"
        "#  A[0] * A[4]\n\t"
        "mul	x8, x10, x14\n\t"
        "adcs	x3, x3, x9\n\t"
        "umulh	x9, x10, x14\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x3, x3, x8\n\t"
        "adcs	x4, x4, x9\n\t"
        "adc	x2, xzr, xzr\n\t"
        "adds	x3, x3, x8\n\t"
        "#  A[1] * A[3]\n\t"
        "mul	x8, x11, x13\n\t"
        "adcs	x4, x4, x9\n\t"
        "umulh	x9, x11, x13\n\t"
        "adc	x2, x2, xzr\n\t"
        "adds	x3, x3, x8\n\t"
        "adcs	x4, x4, x9\n\t"
        "adc	x2, x2, xzr\n\t"
        "adds	x3, x3, x8\n\t"
        "#  A[2] * A[2]\n\t"
        "mul	x8, x12, x12\n\t"
        "adcs	x4, x4, x9\n\t"
        "umulh	x9, x12, x12\n\t"
        "adc	x2, x2, xzr\n\t"
        "adds	x3, x3, x8\n\t"
        "str	x3, [%[r], 32]\n\t"
        "#  A[0] * A[5]\n\t"
        "mul	x5, x10, x15\n\t"
        "adcs	x4, x4, x9\n\t"
        "umulh	x6, x10, x15\n\t"
        "adc	x2, x2, xzr\n\t"
        "mov	x3, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[4]\n\t"
        "mul	x8, x11, x14\n\t"
        "umulh	x9, x11, x14\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[2] * A[3]\n\t"
        "mul	x8, x12, x13\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x12, x13\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x4, x4, x5\n\t"
        "adcs	x2, x2, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x4, [%[r], 40]\n\t"
        "#  A[0] * A[6]\n\t"
        "mul	x5, x10, x16\n\t"
        "umulh	x6, x10, x16\n\t"
        "mov	x4, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[5]\n\t"
        "mul	x8, x11, x15\n\t"
        "umulh	x9, x11, x15\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[2] * A[4]\n\t"
        "mul	x8, x12, x14\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x12, x14\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[3] * A[3]\n\t"
        "mul	x8, x13, x13\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x13, x13\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x2, x2, x5\n\t"
        "adcs	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "str	x2, [%[r], 48]\n\t"
        "#  A[0] * A[7]\n\t"
        "mul	x5, x10, x17\n\t"
        "umulh	x6, x10, x17\n\t"
        "mov	x2, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[6]\n\t"
        "mul	x8, x11, x16\n\t"
        "umulh	x9, x11, x16\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[2] * A[5]\n\t"
        "mul	x8, x12, x15\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x12, x15\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[3] * A[4]\n\t"
        "mul	x8, x13, x14\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x13, x14\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x3, x3, x5\n\t"
        "adcs	x4, x4, x6\n\t"
        "adc	x2, x2, x7\n\t"
        "str	x3, [%[r], 56]\n\t"
        "#  A[0] * A[8]\n\t"
        "mul	x5, x10, x19\n\t"
        "umulh	x6, x10, x19\n\t"
        "mov	x3, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[7]\n\t"
        "mul	x8, x11, x17\n\t"
        "umulh	x9, x11, x17\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[2] * A[6]\n\t"
        "mul	x8, x12, x16\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x12, x16\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[3] * A[5]\n\t"
        "mul	x8, x13, x15\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x13, x15\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[4] * A[4]\n\t"
        "mul	x8, x14, x14\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x14, x14\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x4, x4, x5\n\t"
        "adcs	x2, x2, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x4, [%[r], 64]\n\t"
        "#  A[0] * A[9]\n\t"
        "mul	x5, x10, x20\n\t"
        "umulh	x6, x10, x20\n\t"
        "mov	x4, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[8]\n\t"
        "mul	x8, x11, x19\n\t"
        "umulh	x9, x11, x19\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[2] * A[7]\n\t"
        "mul	x8, x12, x17\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x12, x17\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[3] * A[6]\n\t"
        "mul	x8, x13, x16\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x13, x16\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[4] * A[5]\n\t"
        "mul	x8, x14, x15\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x14, x15\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x2, x2, x5\n\t"
        "adcs	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "str	x2, [%[r], 72]\n\t"
        "#  A[0] * A[10]\n\t"
        "mul	x5, x10, x21\n\t"
        "umulh	x6, x10, x21\n\t"
        "mov	x2, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[9]\n\t"
        "mul	x8, x11, x20\n\t"
        "umulh	x9, x11, x20\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[2] * A[8]\n\t"
        "mul	x8, x12, x19\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x12, x19\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[3] * A[7]\n\t"
        "mul	x8, x13, x17\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x13, x17\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[4] * A[6]\n\t"
        "mul	x8, x14, x16\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x14, x16\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[5] * A[5]\n\t"
        "mul	x8, x15, x15\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x15, x15\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x3, x3, x5\n\t"
        "adcs	x4, x4, x6\n\t"
        "adc	x2, x2, x7\n\t"
        "str	x3, [%[r], 80]\n\t"
        "#  A[0] * A[11]\n\t"
        "mul	x5, x10, x22\n\t"
        "umulh	x6, x10, x22\n\t"
        "mov	x3, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[10]\n\t"
        "mul	x8, x11, x21\n\t"
        "umulh	x9, x11, x21\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[2] * A[9]\n\t"
        "mul	x8, x12, x20\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x12, x20\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[3] * A[8]\n\t"
        "mul	x8, x13, x19\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x13, x19\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[4] * A[7]\n\t"
        "mul	x8, x14, x17\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x14, x17\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[5] * A[6]\n\t"
        "mul	x8, x15, x16\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x15, x16\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x4, x4, x5\n\t"
        "adcs	x2, x2, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x4, [%[r], 88]\n\t"
        "#  A[0] * A[12]\n\t"
        "mul	x5, x10, x23\n\t"
        "umulh	x6, x10, x23\n\t"
        "mov	x4, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[11]\n\t"
        "mul	x8, x11, x22\n\t"
        "umulh	x9, x11, x22\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[2] * A[10]\n\t"
        "mul	x8, x12, x21\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x12, x21\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[3] * A[9]\n\t"
        "mul	x8, x13, x20\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x13, x20\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[4] * A[8]\n\t"
        "mul	x8, x14, x19\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x14, x19\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[5] * A[7]\n\t"
        "mul	x8, x15, x17\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x15, x17\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[6] * A[6]\n\t"
        "mul	x8, x16, x16\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x16, x16\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x2, x2, x5\n\t"
        "adcs	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "str	x2, [%[r], 96]\n\t"
        "#  A[0] * A[13]\n\t"
        "mul	x5, x10, x24\n\t"
        "umulh	x6, x10, x24\n\t"
        "mov	x2, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[12]\n\t"
        "mul	x8, x11, x23\n\t"
        "umulh	x9, x11, x23\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[2] * A[11]\n\t"
        "mul	x8, x12, x22\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x12, x22\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[3] * A[10]\n\t"
        "mul	x8, x13, x21\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x13, x21\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[4] * A[9]\n\t"
        "mul	x8, x14, x20\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x14, x20\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[5] * A[8]\n\t"
        "mul	x8, x15, x19\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x15, x19\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[6] * A[7]\n\t"
        "mul	x8, x16, x17\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x16, x17\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x3, x3, x5\n\t"
        "adcs	x4, x4, x6\n\t"
        "adc	x2, x2, x7\n\t"
        "str	x3, [%[r], 104]\n\t"
        "#  A[0] * A[14]\n\t"
        "mul	x5, x10, x25\n\t"
        "umulh	x6, x10, x25\n\t"
        "mov	x3, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[13]\n\t"
        "mul	x8, x11, x24\n\t"
        "umulh	x9, x11, x24\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[2] * A[12]\n\t"
        "mul	x8, x12, x23\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x12, x23\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[3] * A[11]\n\t"
        "mul	x8, x13, x22\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x13, x22\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[4] * A[10]\n\t"
        "mul	x8, x14, x21\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x14, x21\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[5] * A[9]\n\t"
        "mul	x8, x15, x20\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x15, x20\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[6] * A[8]\n\t"
        "mul	x8, x16, x19\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x16, x19\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[7] * A[7]\n\t"
        "mul	x8, x17, x17\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x17, x17\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x4, x4, x5\n\t"
        "adcs	x2, x2, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x4, [%[r], 112]\n\t"
        "#  A[0] * A[15]\n\t"
        "mul	x5, x10, x26\n\t"
        "umulh	x6, x10, x26\n\t"
        "mov	x4, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[14]\n\t"
        "mul	x8, x11, x25\n\t"
        "umulh	x9, x11, x25\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[2] * A[13]\n\t"
        "mul	x8, x12, x24\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x12, x24\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[3] * A[12]\n\t"
        "mul	x8, x13, x23\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x13, x23\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[4] * A[11]\n\t"
        "mul	x8, x14, x22\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x14, x22\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[5] * A[10]\n\t"
        "mul	x8, x15, x21\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x15, x21\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[6] * A[9]\n\t"
        "mul	x8, x16, x20\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x16, x20\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[7] * A[8]\n\t"
        "mul	x8, x17, x19\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x17, x19\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x2, x2, x5\n\t"
        "adcs	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "str	x2, [%[r], 120]\n\t"
        "#  A[1] * A[15]\n\t"
        "mul	x5, x11, x26\n\t"
        "umulh	x6, x11, x26\n\t"
        "mov	x2, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[2] * A[14]\n\t"
        "mul	x8, x12, x25\n\t"
        "umulh	x9, x12, x25\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[3] * A[13]\n\t"
        "mul	x8, x13, x24\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x13, x24\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[4] * A[12]\n\t"
        "mul	x8, x14, x23\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x14, x23\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[5] * A[11]\n\t"
        "mul	x8, x15, x22\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x15, x22\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[6] * A[10]\n\t"
        "mul	x8, x16, x21\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x16, x21\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[7] * A[9]\n\t"
        "mul	x8, x17, x20\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x17, x20\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[8] * A[8]\n\t"
        "mul	x8, x19, x19\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x19, x19\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x3, x3, x5\n\t"
        "adcs	x4, x4, x6\n\t"
        "adc	x2, x2, x7\n\t"
        "str	x3, [%[r], 128]\n\t"
        "#  A[2] * A[15]\n\t"
        "mul	x5, x12, x26\n\t"
        "umulh	x6, x12, x26\n\t"
        "mov	x3, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[3] * A[14]\n\t"
        "mul	x8, x13, x25\n\t"
        "umulh	x9, x13, x25\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[4] * A[13]\n\t"
        "mul	x8, x14, x24\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x14, x24\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[5] * A[12]\n\t"
        "mul	x8, x15, x23\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x15, x23\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[6] * A[11]\n\t"
        "mul	x8, x16, x22\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x16, x22\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[7] * A[10]\n\t"
        "mul	x8, x17, x21\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x17, x21\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[8] * A[9]\n\t"
        "mul	x8, x19, x20\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x19, x20\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x4, x4, x5\n\t"
        "adcs	x2, x2, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x4, [%[r], 136]\n\t"
        "#  A[3] * A[15]\n\t"
        "mul	x5, x13, x26\n\t"
        "umulh	x6, x13, x26\n\t"
        "mov	x4, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[4] * A[14]\n\t"
        "mul	x8, x14, x25\n\t"
        "umulh	x9, x14, x25\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[5] * A[13]\n\t"
        "mul	x8, x15, x24\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x15, x24\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[6] * A[12]\n\t"
        "mul	x8, x16, x23\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x16, x23\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[7] * A[11]\n\t"
        "mul	x8, x17, x22\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x17, x22\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[8] * A[10]\n\t"
        "mul	x8, x19, x21\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x19, x21\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[9] * A[9]\n\t"
        "mul	x8, x20, x20\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x20, x20\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x2, x2, x5\n\t"
        "adcs	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "str	x2, [%[r], 144]\n\t"
        "#  A[4] * A[15]\n\t"
        "mul	x5, x14, x26\n\t"
        "umulh	x6, x14, x26\n\t"
        "mov	x2, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[5] * A[14]\n\t"
        "mul	x8, x15, x25\n\t"
        "umulh	x9, x15, x25\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[6] * A[13]\n\t"
        "mul	x8, x16, x24\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x16, x24\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[7] * A[12]\n\t"
        "mul	x8, x17, x23\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x17, x23\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[8] * A[11]\n\t"
        "mul	x8, x19, x22\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x19, x22\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[9] * A[10]\n\t"
        "mul	x8, x20, x21\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x20, x21\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x3, x3, x5\n\t"
        "adcs	x4, x4, x6\n\t"
        "adc	x2, x2, x7\n\t"
        "str	x3, [%[r], 152]\n\t"
        "#  A[5] * A[15]\n\t"
        "mul	x5, x15, x26\n\t"
        "umulh	x6, x15, x26\n\t"
        "mov	x3, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[6] * A[14]\n\t"
        "mul	x8, x16, x25\n\t"
        "umulh	x9, x16, x25\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[7] * A[13]\n\t"
        "mul	x8, x17, x24\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x17, x24\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[8] * A[12]\n\t"
        "mul	x8, x19, x23\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x19, x23\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[9] * A[11]\n\t"
        "mul	x8, x20, x22\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x20, x22\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[10] * A[10]\n\t"
        "mul	x8, x21, x21\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x21, x21\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x4, x4, x5\n\t"
        "adcs	x2, x2, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x4, [%[r], 160]\n\t"
        "#  A[6] * A[15]\n\t"
        "mul	x5, x16, x26\n\t"
        "umulh	x6, x16, x26\n\t"
        "mov	x4, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[7] * A[14]\n\t"
        "mul	x8, x17, x25\n\t"
        "umulh	x9, x17, x25\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[8] * A[13]\n\t"
        "mul	x8, x19, x24\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x19, x24\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[9] * A[12]\n\t"
        "mul	x8, x20, x23\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x20, x23\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[10] * A[11]\n\t"
        "mul	x8, x21, x22\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x21, x22\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x2, x2, x5\n\t"
        "adcs	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "str	x2, [%[r], 168]\n\t"
        "#  A[7] * A[15]\n\t"
        "mul	x5, x17, x26\n\t"
        "umulh	x6, x17, x26\n\t"
        "mov	x2, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[8] * A[14]\n\t"
        "mul	x8, x19, x25\n\t"
        "umulh	x9, x19, x25\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[9] * A[13]\n\t"
        "mul	x8, x20, x24\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x20, x24\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[10] * A[12]\n\t"
        "mul	x8, x21, x23\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x21, x23\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[11] * A[11]\n\t"
        "mul	x8, x22, x22\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x22, x22\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x3, x3, x5\n\t"
        "adcs	x4, x4, x6\n\t"
        "adc	x2, x2, x7\n\t"
        "str	x3, [%[r], 176]\n\t"
        "#  A[8] * A[15]\n\t"
        "mul	x5, x19, x26\n\t"
        "umulh	x6, x19, x26\n\t"
        "mov	x3, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[9] * A[14]\n\t"
        "mul	x8, x20, x25\n\t"
        "umulh	x9, x20, x25\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[10] * A[13]\n\t"
        "mul	x8, x21, x24\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x21, x24\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[11] * A[12]\n\t"
        "mul	x8, x22, x23\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x22, x23\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x4, x4, x5\n\t"
        "adcs	x2, x2, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x4, [%[r], 184]\n\t"
        "#  A[9] * A[15]\n\t"
        "mul	x5, x20, x26\n\t"
        "umulh	x6, x20, x26\n\t"
        "mov	x4, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[10] * A[14]\n\t"
        "mul	x8, x21, x25\n\t"
        "umulh	x9, x21, x25\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[11] * A[13]\n\t"
        "mul	x8, x22, x24\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x22, x24\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[12] * A[12]\n\t"
        "mul	x8, x23, x23\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x23, x23\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x2, x2, x5\n\t"
        "adcs	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "str	x2, [%[r], 192]\n\t"
        "#  A[10] * A[15]\n\t"
        "mul	x5, x21, x26\n\t"
        "umulh	x6, x21, x26\n\t"
        "mov	x2, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[11] * A[14]\n\t"
        "mul	x8, x22, x25\n\t"
        "umulh	x9, x22, x25\n\t"
        "adds	x5, x5, x8\n\t"
        "#  A[12] * A[13]\n\t"
        "mul	x8, x23, x24\n\t"
        "adcs	x6, x6, x9\n\t"
        "umulh	x9, x23, x24\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x3, x3, x5\n\t"
        "adcs	x4, x4, x6\n\t"
        "adc	x2, x2, x7\n\t"
        "str	x3, [%[r], 200]\n\t"
        "#  A[11] * A[15]\n\t"
        "mul	x8, x22, x26\n\t"
        "umulh	x9, x22, x26\n\t"
        "adds	x4, x4, x8\n\t"
        "adcs	x2, x2, x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x4, x4, x8\n\t"
        "#  A[12] * A[14]\n\t"
        "mul	x8, x23, x25\n\t"
        "adcs	x2, x2, x9\n\t"
        "umulh	x9, x23, x25\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x8\n\t"
        "adcs	x2, x2, x9\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x8\n\t"
        "#  A[13] * A[13]\n\t"
        "mul	x8, x24, x24\n\t"
        "adcs	x2, x2, x9\n\t"
        "umulh	x9, x24, x24\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x8\n\t"
        "str	x4, [%[r], 208]\n\t"
        "#  A[12] * A[15]\n\t"
        "mul	x8, x23, x26\n\t"
        "adcs	x2, x2, x9\n\t"
        "umulh	x9, x23, x26\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x2, x2, x8\n\t"
        "adcs	x3, x3, x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x2, x2, x8\n\t"
        "#  A[13] * A[14]\n\t"
        "mul	x8, x24, x25\n\t"
        "adcs	x3, x3, x9\n\t"
        "umulh	x9, x24, x25\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x2, x2, x8\n\t"
        "adcs	x3, x3, x9\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x2, x2, x8\n\t"
        "str	x2, [%[r], 216]\n\t"
        "#  A[13] * A[15]\n\t"
        "mul	x8, x24, x26\n\t"
        "adcs	x3, x3, x9\n\t"
        "umulh	x9, x24, x26\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x3, x3, x8\n\t"
        "adcs	x4, x4, x9\n\t"
        "adc	x2, xzr, xzr\n\t"
        "adds	x3, x3, x8\n\t"
        "#  A[14] * A[14]\n\t"
        "mul	x8, x25, x25\n\t"
        "adcs	x4, x4, x9\n\t"
        "umulh	x9, x25, x25\n\t"
        "adc	x2, x2, xzr\n\t"
        "adds	x3, x3, x8\n\t"
        "str	x3, [%[r], 224]\n\t"
        "#  A[14] * A[15]\n\t"
        "mul	x8, x25, x26\n\t"
        "adcs	x4, x4, x9\n\t"
        "umulh	x9, x25, x26\n\t"
        "adc	x2, x2, xzr\n\t"
        "adds	x4, x4, x8\n\t"
        "adcs	x2, x2, x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x4, x4, x8\n\t"
        "str	x4, [%[r], 232]\n\t"
        "#  A[15] * A[15]\n\t"
        "mul	x8, x26, x26\n\t"
        "adcs	x2, x2, x9\n\t"
        "umulh	x9, x26, x26\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x2, x2, x8\n\t"
        "adc	x3, x3, x9\n\t"
        "stp	x2, x3, [%[r], 240]\n\t"
        :
        : [r] "r" (r), [a] "r" (a)
        : "memory", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26"
    );
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_2048_sub_16(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x7, x8, [%[b], 0]\n\t"
        "subs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 16]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldp	x3, x4, [%[a], 32]\n\t"
        "ldp	x7, x8, [%[b], 32]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 48]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 48]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 32]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 48]\n\t"
        "ldp	x3, x4, [%[a], 64]\n\t"
        "ldp	x7, x8, [%[b], 64]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 80]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 80]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 64]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 80]\n\t"
        "ldp	x3, x4, [%[a], 96]\n\t"
        "ldp	x7, x8, [%[b], 96]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 112]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 112]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 96]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 112]\n\t"
        "csetm	%[r], cc\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return (sp_digit)r;
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_32(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit* z2 = r + 32;
    sp_digit z1[32];
    sp_digit* a1 = z1;
    sp_digit* zero = z1 + 16;
    sp_digit u;
    sp_digit mask;
    sp_digit* p1;
    sp_digit* p2;

    XMEMSET(zero, 0, sizeof(sp_digit) * 16);

    mask = sp_2048_sub_16(a1, a, &a[16]);
    p1 = (sp_digit*)(((sp_digit)zero &   mask ) | ((sp_digit)a1 & (~mask)));
    p2 = (sp_digit*)(((sp_digit)zero & (~mask)) | ((sp_digit)a1 &   mask ));
    (void)sp_2048_sub_16(a1, p1, p2);

    sp_2048_sqr_16(z2, &a[16]);
    sp_2048_sqr_16(z0, a);
    sp_2048_sqr_16(z1, a1);

    u = 0;
    u -= sp_2048_sub_in_place_32(z1, z2);
    u -= sp_2048_sub_in_place_32(z1, z0);
    u += sp_2048_sub_in_place_32(r + 16, z1);
    sp_2048_add_word_16(r + 48, r + 48, u);
}

#endif /* !WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_2048_add_32(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "add	x11, %[a], 256\n\t"
        "\n1:\n\t"
        "adds	%[c], %[c], #-1\n\t"
        "ldp	x3, x4, [%[a]], #16\n\t"
        "ldp	x5, x6, [%[a]], #16\n\t"
        "ldp	x7, x8, [%[b]], #16\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x9, x10, [%[b]], #16\n\t"
        "adcs	x4, x4, x8\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r]], #16\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r]], #16\n\t"
        "cset	%[c], cs\n\t"
        "cmp	%[a], x11\n\t"
        "b.ne	1b\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    return c;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_2048_sub_in_place_32(sp_digit* a, const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "add	x10, %[a], 256\n\t"
        "\n1:\n\t"
        "subs	%[c], xzr, %[c]\n\t"
        "ldp	x2, x3, [%[a]]\n\t"
        "ldp	x4, x5, [%[a], #16]\n\t"
        "ldp	x6, x7, [%[b]], #16\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x8, x9, [%[b]], #16\n\t"
        "sbcs	x3, x3, x7\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a]], #16\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a]], #16\n\t"
        "csetm	%[c], cc\n\t"
        "cmp	%[a], x10\n\t"
        "b.ne	1b\n\t"
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return c;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static void sp_2048_mul_32(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    sp_digit tmp[64];

    __asm__ __volatile__ (
        "mov	x5, xzr\n\t"
        "mov	x6, xzr\n\t"
        "mov	x7, xzr\n\t"
        "mov	x8, xzr\n\t"
        "\n1:\n\t"
        "subs	x3, x5, 248\n\t"
        "csel	x3, xzr, x3, cc\n\t"
        "sub	x4, x5, x3\n\t"
        "\n2:\n\t"
        "ldr	x10, [%[a], x3]\n\t"
        "ldr	x11, [%[b], x4]\n\t"
        "mul	x9, x10, x11\n\t"
        "umulh	x10, x10, x11\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "add	x3, x3, #8\n\t"
        "sub	x4, x4, #8\n\t"
        "cmp	x3, 256\n\t"
        "b.eq	3f\n\t"
        "cmp	x3, x5\n\t"
        "b.le	2b\n\t"
        "\n3:\n\t"
        "str	x6, [%[r], x5]\n\t"
        "mov	x6, x7\n\t"
        "mov	x7, x8\n\t"
        "mov	x8, #0\n\t"
        "add	x5, x5, #8\n\t"
        "cmp	x5, 496\n\t"
        "b.le	1b\n\t"
        "str	x6, [%[r], x5]\n\t"
        :
        : [r] "r" (tmp), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    XMEMCPY(r, tmp, sizeof(tmp));
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
static void sp_2048_sqr_32(sp_digit* r, const sp_digit* a)
{
    sp_digit tmp[64];

    __asm__ __volatile__ (
        "mov	x6, xzr\n\t"
        "mov	x7, xzr\n\t"
        "mov	x8, xzr\n\t"
        "mov	x5, xzr\n\t"
        "\n1:\n\t"
        "subs	x3, x5, 248\n\t"
        "csel	x3, xzr, x3, cc\n\t"
        "sub	x4, x5, x3\n\t"
        "\n2:\n\t"
        "cmp	x4, x3\n\t"
        "b.eq	4f\n\t"
        "ldr	x10, [%[a], x3]\n\t"
        "ldr	x11, [%[a], x4]\n\t"
        "mul	x9, x10, x11\n\t"
        "umulh	x10, x10, x11\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "b.al	5f\n\t"
        "\n4:\n\t"
        "ldr	x10, [%[a], x3]\n\t"
        "mul	x9, x10, x10\n\t"
        "umulh	x10, x10, x10\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "\n5:\n\t"
        "add	x3, x3, #8\n\t"
        "sub	x4, x4, #8\n\t"
        "cmp	x3, 256\n\t"
        "b.eq	3f\n\t"
        "cmp	x3, x4\n\t"
        "b.gt	3f\n\t"
        "cmp	x3, x5\n\t"
        "b.le	2b\n\t"
        "\n3:\n\t"
        "str	x6, [%[r], x5]\n\t"
        "mov	x6, x7\n\t"
        "mov	x7, x8\n\t"
        "mov	x8, #0\n\t"
        "add	x5, x5, #8\n\t"
        "cmp	x5, 496\n\t"
        "b.le	1b\n\t"
        "str	x6, [%[r], x5]\n\t"
        :
        : [r] "r" (tmp), [a] "r" (a)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    XMEMCPY(r, tmp, sizeof(tmp));
}

#endif /* WOLFSSL_SP_SMALL */
#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_2048_add_16(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "add	x11, %[a], 128\n\t"
        "\n1:\n\t"
        "adds	%[c], %[c], #-1\n\t"
        "ldp	x3, x4, [%[a]], #16\n\t"
        "ldp	x5, x6, [%[a]], #16\n\t"
        "ldp	x7, x8, [%[b]], #16\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x9, x10, [%[b]], #16\n\t"
        "adcs	x4, x4, x8\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r]], #16\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r]], #16\n\t"
        "cset	%[c], cs\n\t"
        "cmp	%[a], x11\n\t"
        "b.ne	1b\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    return c;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_2048_sub_in_place_16(sp_digit* a, const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "add	x10, %[a], 128\n\t"
        "\n1:\n\t"
        "subs	%[c], xzr, %[c]\n\t"
        "ldp	x2, x3, [%[a]]\n\t"
        "ldp	x4, x5, [%[a], #16]\n\t"
        "ldp	x6, x7, [%[b]], #16\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x8, x9, [%[b]], #16\n\t"
        "sbcs	x3, x3, x7\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a]], #16\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a]], #16\n\t"
        "csetm	%[c], cc\n\t"
        "cmp	%[a], x10\n\t"
        "b.ne	1b\n\t"
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return c;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static void sp_2048_mul_16(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    sp_digit tmp[32];

    __asm__ __volatile__ (
        "mov	x5, xzr\n\t"
        "mov	x6, xzr\n\t"
        "mov	x7, xzr\n\t"
        "mov	x8, xzr\n\t"
        "\n1:\n\t"
        "subs	x3, x5, 120\n\t"
        "csel	x3, xzr, x3, cc\n\t"
        "sub	x4, x5, x3\n\t"
        "\n2:\n\t"
        "ldr	x10, [%[a], x3]\n\t"
        "ldr	x11, [%[b], x4]\n\t"
        "mul	x9, x10, x11\n\t"
        "umulh	x10, x10, x11\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "add	x3, x3, #8\n\t"
        "sub	x4, x4, #8\n\t"
        "cmp	x3, 128\n\t"
        "b.eq	3f\n\t"
        "cmp	x3, x5\n\t"
        "b.le	2b\n\t"
        "\n3:\n\t"
        "str	x6, [%[r], x5]\n\t"
        "mov	x6, x7\n\t"
        "mov	x7, x8\n\t"
        "mov	x8, #0\n\t"
        "add	x5, x5, #8\n\t"
        "cmp	x5, 240\n\t"
        "b.le	1b\n\t"
        "str	x6, [%[r], x5]\n\t"
        :
        : [r] "r" (tmp), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    XMEMCPY(r, tmp, sizeof(tmp));
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
static void sp_2048_sqr_16(sp_digit* r, const sp_digit* a)
{
    sp_digit tmp[32];

    __asm__ __volatile__ (
        "mov	x6, xzr\n\t"
        "mov	x7, xzr\n\t"
        "mov	x8, xzr\n\t"
        "mov	x5, xzr\n\t"
        "\n1:\n\t"
        "subs	x3, x5, 120\n\t"
        "csel	x3, xzr, x3, cc\n\t"
        "sub	x4, x5, x3\n\t"
        "\n2:\n\t"
        "cmp	x4, x3\n\t"
        "b.eq	4f\n\t"
        "ldr	x10, [%[a], x3]\n\t"
        "ldr	x11, [%[a], x4]\n\t"
        "mul	x9, x10, x11\n\t"
        "umulh	x10, x10, x11\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "b.al	5f\n\t"
        "\n4:\n\t"
        "ldr	x10, [%[a], x3]\n\t"
        "mul	x9, x10, x10\n\t"
        "umulh	x10, x10, x10\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "\n5:\n\t"
        "add	x3, x3, #8\n\t"
        "sub	x4, x4, #8\n\t"
        "cmp	x3, 128\n\t"
        "b.eq	3f\n\t"
        "cmp	x3, x4\n\t"
        "b.gt	3f\n\t"
        "cmp	x3, x5\n\t"
        "b.le	2b\n\t"
        "\n3:\n\t"
        "str	x6, [%[r], x5]\n\t"
        "mov	x6, x7\n\t"
        "mov	x7, x8\n\t"
        "mov	x8, #0\n\t"
        "add	x5, x5, #8\n\t"
        "cmp	x5, 240\n\t"
        "b.le	1b\n\t"
        "str	x6, [%[r], x5]\n\t"
        :
        : [r] "r" (tmp), [a] "r" (a)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    XMEMCPY(r, tmp, sizeof(tmp));
}

#endif /* WOLFSSL_SP_SMALL */
#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) | WOLFSSL_HAVE_SP_DH */

/* Caclulate the bottom digit of -1/a mod 2^n.
 *
 * a    A single precision number.
 * rho  Bottom word of inverse.
 */
static void sp_2048_mont_setup(const sp_digit* a, sp_digit* rho)
{
    sp_digit x;
    sp_digit b;

    b = a[0];
    x = (((b + 2) & 4) << 1) + b; /* here x*a==1 mod 2**4 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**8 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**16 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**32 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**64 */

    /* rho = -1/m mod b */
    *rho = (sp_digit)0 - x;
}

/* Mul a by digit b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision digit.
 */
static void sp_2048_mul_d_32(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "# A[0] * B\n\t"
        "ldr	x8, [%[a]]\n\t"
        "mul	x5, %[b], x8\n\t"
        "umulh	x3, %[b], x8\n\t"
        "mov	x4, xzr\n\t"
        "str	x5, [%[r]]\n\t"
        "mov	x5, xzr\n\t"
        "mov	x9, #8\n\t"
        "1:\n\t"
        "ldr	x8, [%[a], x9]\n\t"
        "mul	x6, %[b], x8\n\t"
        "umulh	x7, %[b], x8\n\t"
        "adds	x3, x3, x6\n\t"
        "adcs	x4, x4, x7\n\t"
        "adc	x5, xzr, xzr\n\t"
        "str	x3, [%[r], x9]\n\t"
        "mov	x3, x4\n\t"
        "mov	x4, x5\n\t"
        "mov	x5, #0\n\t"
        "add	x9, x9, #8\n\t"
        "cmp	x9, 256\n\t"
        "b.lt	1b\n\t"
        "str	x3, [%[r], 256]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );
#else
    __asm__ __volatile__ (
        "# A[0] * B\n\t"
        "ldp	x9, x10, [%[a]]\n\t"
        "mul	x3, %[b], x9\n\t"
        "umulh	x4, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "# A[1] * B\n\t"
        "str	x3, [%[r]]\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[2] * B\n\t"
        "ldp	x9, x10, [%[a], 16]\n\t"
        "str	x4, [%[r], 8]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[3] * B\n\t"
        "str	x5, [%[r], 16]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[4] * B\n\t"
        "ldp	x9, x10, [%[a], 32]\n\t"
        "str	x3, [%[r], 24]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[5] * B\n\t"
        "str	x4, [%[r], 32]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[6] * B\n\t"
        "ldp	x9, x10, [%[a], 48]\n\t"
        "str	x5, [%[r], 40]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[7] * B\n\t"
        "str	x3, [%[r], 48]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[8] * B\n\t"
        "ldp	x9, x10, [%[a], 64]\n\t"
        "str	x4, [%[r], 56]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[9] * B\n\t"
        "str	x5, [%[r], 64]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[10] * B\n\t"
        "ldp	x9, x10, [%[a], 80]\n\t"
        "str	x3, [%[r], 72]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[11] * B\n\t"
        "str	x4, [%[r], 80]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[12] * B\n\t"
        "ldp	x9, x10, [%[a], 96]\n\t"
        "str	x5, [%[r], 88]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[13] * B\n\t"
        "str	x3, [%[r], 96]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[14] * B\n\t"
        "ldp	x9, x10, [%[a], 112]\n\t"
        "str	x4, [%[r], 104]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[15] * B\n\t"
        "str	x5, [%[r], 112]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[16] * B\n\t"
        "ldp	x9, x10, [%[a], 128]\n\t"
        "str	x3, [%[r], 120]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[17] * B\n\t"
        "str	x4, [%[r], 128]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[18] * B\n\t"
        "ldp	x9, x10, [%[a], 144]\n\t"
        "str	x5, [%[r], 136]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[19] * B\n\t"
        "str	x3, [%[r], 144]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[20] * B\n\t"
        "ldp	x9, x10, [%[a], 160]\n\t"
        "str	x4, [%[r], 152]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[21] * B\n\t"
        "str	x5, [%[r], 160]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[22] * B\n\t"
        "ldp	x9, x10, [%[a], 176]\n\t"
        "str	x3, [%[r], 168]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[23] * B\n\t"
        "str	x4, [%[r], 176]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[24] * B\n\t"
        "ldp	x9, x10, [%[a], 192]\n\t"
        "str	x5, [%[r], 184]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[25] * B\n\t"
        "str	x3, [%[r], 192]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[26] * B\n\t"
        "ldp	x9, x10, [%[a], 208]\n\t"
        "str	x4, [%[r], 200]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[27] * B\n\t"
        "str	x5, [%[r], 208]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[28] * B\n\t"
        "ldp	x9, x10, [%[a], 224]\n\t"
        "str	x3, [%[r], 216]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[29] * B\n\t"
        "str	x4, [%[r], 224]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[30] * B\n\t"
        "ldp	x9, x10, [%[a], 240]\n\t"
        "str	x5, [%[r], 232]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[31] * B\n\t"
        "str	x3, [%[r], 240]\n\t"
        "mul	x6, %[b], x10\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "adc	x5, x5, x7\n\t"
        "stp	x4, x5, [%[r], 248]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );
#endif
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 2048 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_2048_mont_norm_16(sp_digit* r, const sp_digit* m)
{
    XMEMSET(r, 0, sizeof(sp_digit) * 16);

    /* r = 2^n mod m */
    sp_2048_sub_in_place_16(r, m);
}

/* Reduce the number back to 2048 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
SP_NOINLINE static void sp_2048_mont_reduce_16(sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    __asm__ __volatile__ (
        "ldp	x12, x13, [%[a], 0]\n\t"
        "ldp	x14, x15, [%[a], 16]\n\t"
        "ldp	x16, x17, [%[a], 32]\n\t"
        "ldp	x19, x20, [%[a], 48]\n\t"
        "ldp	x21, x22, [%[a], 64]\n\t"
        "ldp	x23, x24, [%[a], 80]\n\t"
        "ldp	x25, x26, [%[a], 96]\n\t"
        "ldp	x27, x28, [%[a], 112]\n\t"
        "mov	x3, xzr\n\t"
        "# i = 0..15\n\t"
        "mov	x4, 16\n\t"
        "\n1:\n\t"
        "# mu = a[i] * mp\n\t"
        "mul	x9, %[mp], x12\n\t"
        "# a[i+0] += m[0] * mu\n\t"
        "ldp	x10, x11, [%[m], 0]\n\t"
        "mul	x7, x10, x9\n\t"
        "umulh	x8, x10, x9\n\t"
        "adds	x12, x12, x7\n\t"
        "# a[i+1] += m[1] * mu\n\t"
        "adc	x6, x8, xzr\n\t"
        "mul	x7, x11, x9\n\t"
        "umulh	x8, x11, x9\n\t"
        "adds	x12, x13, x7\n\t"
        "# a[i+2] += m[2] * mu\n\t"
        "ldp	x11, x10, [%[m], 16]\n\t"
        "adc	x5, x8, xzr\n\t"
        "adds	x12, x12, x6\n\t"
        "mul	x7, x11, x9\n\t"
        "adc	x5, x5, xzr\n\t"
        "umulh	x8, x11, x9\n\t"
        "adds	x13, x14, x7\n\t"
        "# a[i+3] += m[3] * mu\n\t"
        "adc	x6, x8, xzr\n\t"
        "adds	x13, x13, x5\n\t"
        "mul	x7, x10, x9\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x8, x10, x9\n\t"
        "adds	x14, x15, x7\n\t"
        "# a[i+4] += m[4] * mu\n\t"
        "ldp	x11, x10, [%[m], 32]\n\t"
        "adc	x5, x8, xzr\n\t"
        "adds	x14, x14, x6\n\t"
        "mul	x7, x11, x9\n\t"
        "adc	x5, x5, xzr\n\t"
        "umulh	x8, x11, x9\n\t"
        "adds	x15, x16, x7\n\t"
        "# a[i+5] += m[5] * mu\n\t"
        "adc	x6, x8, xzr\n\t"
        "adds	x15, x15, x5\n\t"
        "mul	x7, x10, x9\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x8, x10, x9\n\t"
        "adds	x16, x17, x7\n\t"
        "# a[i+6] += m[6] * mu\n\t"
        "ldp	x11, x10, [%[m], 48]\n\t"
        "adc	x5, x8, xzr\n\t"
        "adds	x16, x16, x6\n\t"
        "mul	x7, x11, x9\n\t"
        "adc	x5, x5, xzr\n\t"
        "umulh	x8, x11, x9\n\t"
        "adds	x17, x19, x7\n\t"
        "# a[i+7] += m[7] * mu\n\t"
        "adc	x6, x8, xzr\n\t"
        "adds	x17, x17, x5\n\t"
        "mul	x7, x10, x9\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x8, x10, x9\n\t"
        "adds	x19, x20, x7\n\t"
        "# a[i+8] += m[8] * mu\n\t"
        "ldp	x11, x10, [%[m], 64]\n\t"
        "adc	x5, x8, xzr\n\t"
        "adds	x19, x19, x6\n\t"
        "mul	x7, x11, x9\n\t"
        "adc	x5, x5, xzr\n\t"
        "umulh	x8, x11, x9\n\t"
        "adds	x20, x21, x7\n\t"
        "# a[i+9] += m[9] * mu\n\t"
        "adc	x6, x8, xzr\n\t"
        "adds	x20, x20, x5\n\t"
        "mul	x7, x10, x9\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x8, x10, x9\n\t"
        "adds	x21, x22, x7\n\t"
        "# a[i+10] += m[10] * mu\n\t"
        "ldp	x11, x10, [%[m], 80]\n\t"
        "adc	x5, x8, xzr\n\t"
        "adds	x21, x21, x6\n\t"
        "mul	x7, x11, x9\n\t"
        "adc	x5, x5, xzr\n\t"
        "umulh	x8, x11, x9\n\t"
        "adds	x22, x23, x7\n\t"
        "# a[i+11] += m[11] * mu\n\t"
        "adc	x6, x8, xzr\n\t"
        "adds	x22, x22, x5\n\t"
        "mul	x7, x10, x9\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x8, x10, x9\n\t"
        "adds	x23, x24, x7\n\t"
        "# a[i+12] += m[12] * mu\n\t"
        "ldp	x11, x10, [%[m], 96]\n\t"
        "adc	x5, x8, xzr\n\t"
        "adds	x23, x23, x6\n\t"
        "mul	x7, x11, x9\n\t"
        "adc	x5, x5, xzr\n\t"
        "umulh	x8, x11, x9\n\t"
        "adds	x24, x25, x7\n\t"
        "# a[i+13] += m[13] * mu\n\t"
        "adc	x6, x8, xzr\n\t"
        "adds	x24, x24, x5\n\t"
        "mul	x7, x10, x9\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x8, x10, x9\n\t"
        "adds	x25, x26, x7\n\t"
        "# a[i+14] += m[14] * mu\n\t"
        "ldp	x11, x10, [%[m], 112]\n\t"
        "adc	x5, x8, xzr\n\t"
        "adds	x25, x25, x6\n\t"
        "mul	x7, x11, x9\n\t"
        "adc	x5, x5, xzr\n\t"
        "umulh	x8, x11, x9\n\t"
        "adds	x26, x27, x7\n\t"
        "# a[i+15] += m[15] * mu\n\t"
        "ldr	x10, [%[m], 120]\n\t"
        "adc	x6, x8, xzr\n\t"
        "adds	x26, x26, x5\n\t"
        "mul	x7, x10, x9\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x8, x10, x9\n\t"
        "adds	x6, x6, x7\n\t"
        "adcs	x8, x8, x3\n\t"
        "cset	x3, cs\n\t"
        "adds	x27, x28, x6\n\t"
        "ldr	x28, [%[a], 128]\n\t"
        "adcs	x28, x28, x8\n\t"
        "adc	x3, x3, xzr\n\t"
        "subs	x4, x4, 1\n\t"
        "add	%[a], %[a], 8\n\t"
        "bne	1b\n\t"
        "# Create mask\n\t"
        "neg	x3, x3\n\t"
        "mov	x9, %[a]\n\t"
        "sub	%[a], %[a], 128\n\t"
        "# Subtract masked modulus\n\t"
        "ldp	x4, x5, [%[m], 0]\n\t"
        "ldp	x6, x7, [%[m], 16]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "subs	x12, x12, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x13, x13, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x14, x14, x6\n\t"
        "stp	x12, x13, [%[a], 0]\n\t"
        "sbcs	x15, x15, x7\n\t"
        "stp	x14, x15, [%[a], 16]\n\t"
        "ldp	x4, x5, [%[m], 32]\n\t"
        "ldp	x6, x7, [%[m], 48]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x16, x16, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x17, x17, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x19, x19, x6\n\t"
        "stp	x16, x17, [%[a], 32]\n\t"
        "sbcs	x20, x20, x7\n\t"
        "stp	x19, x20, [%[a], 48]\n\t"
        "ldp	x4, x5, [%[m], 64]\n\t"
        "ldp	x6, x7, [%[m], 80]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x21, x21, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x22, x22, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x23, x23, x6\n\t"
        "stp	x21, x22, [%[a], 64]\n\t"
        "sbcs	x24, x24, x7\n\t"
        "stp	x23, x24, [%[a], 80]\n\t"
        "ldp	x4, x5, [%[m], 96]\n\t"
        "ldp	x6, x7, [%[m], 112]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x25, x25, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x26, x26, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x27, x27, x6\n\t"
        "stp	x25, x26, [%[a], 96]\n\t"
        "sbcs	x28, x28, x7\n\t"
        "stp	x27, x28, [%[a], 112]\n\t"
        : [a] "+r" (a), [mp] "+r" (mp)
        : [m] "r" (m)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28"
    );

}

/* Multiply two Montgomery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montgomery form.
 * b   Second number to multiply in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_2048_mont_mul_16(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_2048_mul_16(r, a, b);
    sp_2048_mont_reduce_16(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_2048_mont_sqr_16(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_2048_sqr_16(r, a);
    sp_2048_mont_reduce_16(r, m, mp);
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not copying.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static sp_digit sp_2048_cond_sub_16(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	x8, #0\n\t"
        "1:\n\t"
        "subs	%[c], xzr, %[c]\n\t"
        "ldr	x4, [%[a], x8]\n\t"
        "ldr	x5, [%[b], x8]\n\t"
        "and	x5, x5, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "csetm	%[c], cc\n\t"
        "str	x4, [%[r], x8]\n\t"
        "add	x8, x8, #8\n\t"
        "cmp	x8, 128\n\t"
        "b.lt	1b\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x6", "x5", "x7", "x8", "x9", "x10", "x11", "x12"
    );

    return c;
#else
    __asm__ __volatile__ (

        "ldp	x5, x7, [%[b], 0]\n\t"
        "ldp	x11, x12, [%[b], 16]\n\t"
        "ldp	x4, x6, [%[a], 0]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 16]\n\t"
        "and	x7, x7, %[m]\n\t"
        "subs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 0]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 16]\n\t"
        "ldp	x5, x7, [%[b], 32]\n\t"
        "ldp	x11, x12, [%[b], 48]\n\t"
        "ldp	x4, x6, [%[a], 32]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 48]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 32]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 48]\n\t"
        "ldp	x5, x7, [%[b], 64]\n\t"
        "ldp	x11, x12, [%[b], 80]\n\t"
        "ldp	x4, x6, [%[a], 64]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 80]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 64]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 80]\n\t"
        "ldp	x5, x7, [%[b], 96]\n\t"
        "ldp	x11, x12, [%[b], 112]\n\t"
        "ldp	x4, x6, [%[a], 96]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 112]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 96]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 112]\n\t"
        "csetm	%[r], cc\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x6", "x5", "x7", "x8", "x9", "x10", "x11", "x12"
    );

    return (sp_digit)r;
#endif /* WOLFSSL_SP_SMALL */
}

/* Mul a by digit b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision digit.
 */
static void sp_2048_mul_d_16(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "# A[0] * B\n\t"
        "ldr	x8, [%[a]]\n\t"
        "mul	x5, %[b], x8\n\t"
        "umulh	x3, %[b], x8\n\t"
        "mov	x4, xzr\n\t"
        "str	x5, [%[r]]\n\t"
        "mov	x5, xzr\n\t"
        "mov	x9, #8\n\t"
        "1:\n\t"
        "ldr	x8, [%[a], x9]\n\t"
        "mul	x6, %[b], x8\n\t"
        "umulh	x7, %[b], x8\n\t"
        "adds	x3, x3, x6\n\t"
        "adcs	x4, x4, x7\n\t"
        "adc	x5, xzr, xzr\n\t"
        "str	x3, [%[r], x9]\n\t"
        "mov	x3, x4\n\t"
        "mov	x4, x5\n\t"
        "mov	x5, #0\n\t"
        "add	x9, x9, #8\n\t"
        "cmp	x9, 128\n\t"
        "b.lt	1b\n\t"
        "str	x3, [%[r], 128]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );
#else
    __asm__ __volatile__ (
        "# A[0] * B\n\t"
        "ldp	x9, x10, [%[a]]\n\t"
        "mul	x3, %[b], x9\n\t"
        "umulh	x4, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "# A[1] * B\n\t"
        "str	x3, [%[r]]\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[2] * B\n\t"
        "ldp	x9, x10, [%[a], 16]\n\t"
        "str	x4, [%[r], 8]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[3] * B\n\t"
        "str	x5, [%[r], 16]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[4] * B\n\t"
        "ldp	x9, x10, [%[a], 32]\n\t"
        "str	x3, [%[r], 24]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[5] * B\n\t"
        "str	x4, [%[r], 32]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[6] * B\n\t"
        "ldp	x9, x10, [%[a], 48]\n\t"
        "str	x5, [%[r], 40]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[7] * B\n\t"
        "str	x3, [%[r], 48]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[8] * B\n\t"
        "ldp	x9, x10, [%[a], 64]\n\t"
        "str	x4, [%[r], 56]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[9] * B\n\t"
        "str	x5, [%[r], 64]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[10] * B\n\t"
        "ldp	x9, x10, [%[a], 80]\n\t"
        "str	x3, [%[r], 72]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[11] * B\n\t"
        "str	x4, [%[r], 80]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[12] * B\n\t"
        "ldp	x9, x10, [%[a], 96]\n\t"
        "str	x5, [%[r], 88]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[13] * B\n\t"
        "str	x3, [%[r], 96]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[14] * B\n\t"
        "ldp	x9, x10, [%[a], 112]\n\t"
        "str	x4, [%[r], 104]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[15] * B\n\t"
        "str	x5, [%[r], 112]\n\t"
        "mul	x6, %[b], x10\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "stp	x3, x4, [%[r], 120]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );
#endif
}

/* Divide the double width number (d1|d0) by the divisor. (d1|d0 / div)
 *
 * Assumes divisor has higest bit set.
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The divisor.
 * returns the result of the division.
 */
static sp_digit div_2048_word_16(sp_digit d1, sp_digit d0, sp_digit div)
{
    __asm__ __volatile__ (
        "lsr	x8, %[div], 32\n\t"
        "add	x5, x8, 1\n\t"

        "udiv	x3, %[d1], x5\n\t"
        "lsl	x7, %[div], 32\n\t"
        "movz	x9, #1, lsl 32\n\t"
        "lsl	x6, x3, 32\n\t"
        "mul	x4, %[div], x6\n\t"
        "umulh	x3, %[div], x6\n\t"
        "subs	%[d0], %[d0], x4\n\t"
        "sbc	%[d1], %[d1], x3\n\t"

        "cmp	%[d1], x5\n\t"
        "cset	x9, ge\n\t"
        "csetm	x10, ge\n\t"
        "lsl	x9, x9, #32\n\t"
        "and	x7, x7, x10\n\t"
        "and	x8, x8, x10\n\t"
        "subs	%[d0], %[d0], x7\n\t"
        "add	x6, x6, x9\n\t"
        "sbc	%[d1], %[d1], x8\n\t"

        "extr	x3, %[d1], %[d0], 32\n\t"

        "udiv	x3, x3, x5\n\t"
        "add	x6, x6, x3\n\t"
        "mul	x4, %[div], x3\n\t"
        "umulh	x3, %[div], x3\n\t"
        "subs	%[d0], %[d0], x4\n\t"
        "sbc	%[d1], %[d1], x3\n\t"

        "extr	x3, %[d1], %[d0], 32\n\t"

        "udiv   x3, x3, x5\n\t"
        "add    x6, x6, x3\n\t"
        "mul    x4, %[div], x3\n\t"
        "sub    %[d0], %[d0], x4\n\t"

        "udiv	x3, %[d0], %[div]\n\t"
        "add	%[d1], x6, x3\n\t"

        : [d1] "+r" (d1), [d0] "+r" (d0)
        : [div] "r" (div)
        : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return d1;
}

/* AND m into each word of a and store in r.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * m  Mask to AND against each digit.
 */
static void sp_2048_mask_16(sp_digit* r, const sp_digit* a, sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<16; i++) {
        r[i] = a[i] & m;
    }
#else
    int i;

    for (i = 0; i < 16; i += 8) {
        r[i+0] = a[i+0] & m;
        r[i+1] = a[i+1] & m;
        r[i+2] = a[i+2] & m;
        r[i+3] = a[i+3] & m;
        r[i+4] = a[i+4] & m;
        r[i+5] = a[i+5] & m;
        r[i+6] = a[i+6] & m;
        r[i+7] = a[i+7] & m;
    }
#endif
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_int64 sp_2048_cmp_16(const sp_digit* a, const sp_digit* b)
{
#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "mov	x3, #0\n\t"
        "mov	x2, #-1\n\t"
        "mov	x10, #16\n\t"
        "add	%[a], %[a], #112\n\t"
        "add	%[b], %[b], #112\n\t"
        "1:\n\t"
        "ldp	x6, x7, [%[a]], -16\n\t"
        "ldp	x8, x9, [%[b]], -16\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x10, x10, #2\n\t"
        "b.ne	1b\n\t"
        "cmp	x2, #0\n\t"
        "cset	%[a], eq\n\t"
        "orr	%[a], %[a], x3\n\t"
        : [a] "+r" (a), [b] "+r" (b)
        :
        : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );
#else
    __asm__ __volatile__ (
        "mov	x3, #0\n\t"
        "mov	x2, #-1\n\t"
        "ldp	x6, x7, [%[a], 112]\n\t"
        "ldp	x8, x9, [%[b], 112]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 96]\n\t"
        "ldp	x8, x9, [%[b], 96]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 80]\n\t"
        "ldp	x8, x9, [%[b], 80]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 64]\n\t"
        "ldp	x8, x9, [%[b], 64]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 48]\n\t"
        "ldp	x8, x9, [%[b], 48]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 32]\n\t"
        "ldp	x8, x9, [%[b], 32]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 16]\n\t"
        "ldp	x8, x9, [%[b], 16]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 0]\n\t"
        "ldp	x8, x9, [%[b], 0]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "cmp	x2, #0\n\t"
        "cset	%[a], eq\n\t"
        "orr	%[a], %[a], x3\n\t"
        : [a] "+r" (a)
        : [b] "r" (b)
        : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );
#endif

    return (sp_int64)a;
}

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_2048_div_16(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    sp_digit t1[32], t2[17];
    sp_digit div, r1;
    int i;

    (void)m;

    div = d[15];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 16);
    for (i = 15; i >= 0; i--) {
        sp_digit hi = t1[16 + i] - (t1[16 + i] == div);
        r1 = div_2048_word_16(hi, t1[16 + i - 1], div);

        sp_2048_mul_d_16(t2, d, r1);
        t1[16 + i] += sp_2048_sub_in_place_16(&t1[i], t2);
        t1[16 + i] -= t2[16];
        sp_2048_mask_16(t2, d, t1[16 + i]);
        t1[16 + i] += sp_2048_add_16(&t1[i], &t1[i], t2);
        sp_2048_mask_16(t2, d, t1[16 + i]);
        t1[16 + i] += sp_2048_add_16(&t1[i], &t1[i], t2);
    }

    r1 = sp_2048_cmp_16(t1, d) >= 0;
    sp_2048_cond_sub_16(r, t1, d, (sp_digit)0 - r1);

    return MP_OKAY;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_2048_mod_16(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_2048_div_16(a, m, NULL, r);
}

#ifdef WOLFSSL_SP_SMALL
/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success.
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even or exponent is 0.
 */
static int sp_2048_mod_exp_16(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[16 * 32];
    sp_digit* t[16];
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<16; i++) {
            t[i] = td + i * 32;
        }

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_16(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 16U);
        if (reduceA != 0) {
            err = sp_2048_mod_16(t[1] + 16, a, m);
            if (err == MP_OKAY) {
                err = sp_2048_mod_16(t[1], t[1], m);
            }
        }
        else {
            XMEMCPY(t[1] + 16, a, sizeof(sp_digit) * 16);
            err = sp_2048_mod_16(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_2048_mont_sqr_16(t[ 2], t[ 1], m, mp);
        sp_2048_mont_mul_16(t[ 3], t[ 2], t[ 1], m, mp);
        sp_2048_mont_sqr_16(t[ 4], t[ 2], m, mp);
        sp_2048_mont_mul_16(t[ 5], t[ 3], t[ 2], m, mp);
        sp_2048_mont_sqr_16(t[ 6], t[ 3], m, mp);
        sp_2048_mont_mul_16(t[ 7], t[ 4], t[ 3], m, mp);
        sp_2048_mont_sqr_16(t[ 8], t[ 4], m, mp);
        sp_2048_mont_mul_16(t[ 9], t[ 5], t[ 4], m, mp);
        sp_2048_mont_sqr_16(t[10], t[ 5], m, mp);
        sp_2048_mont_mul_16(t[11], t[ 6], t[ 5], m, mp);
        sp_2048_mont_sqr_16(t[12], t[ 6], m, mp);
        sp_2048_mont_mul_16(t[13], t[ 7], t[ 6], m, mp);
        sp_2048_mont_sqr_16(t[14], t[ 7], m, mp);
        sp_2048_mont_mul_16(t[15], t[ 8], t[ 7], m, mp);

        i = (bits - 1) / 64;
        n = e[i--];
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        c -= bits % 4;
        if (c == 64) {
            c = 60;
        }
        if (c < 0) {
            /* Number of bits in top word is less than number needed. */
            c = -c;
            y = (byte)(n << c);
            n = e[i--];
            y |= (byte)(n >> (64 - c));
            n <<= c;
            c = 64 - c;
        }
        else if (c == 0) {
            /* All bits in top word used. */
            y = (byte)n;
        }
        else {
            y = (byte)(n >> c);
            n <<= 64 - c;
        }
        XMEMCPY(r, t[y], sizeof(sp_digit) * 16);
        for (; i>=0 || c>=4; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 60);
                n <<= 4;
                c = 60;
            }
            else if (c < 4) {
                y = (byte)(n >> 60);
                n = e[i--];
                c = 4 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }
            else {
                y = (byte)((n >> 60) & 0xf);
                n <<= 4;
                c -= 4;
            }

            sp_2048_mont_sqr_16(r, r, m, mp);
            sp_2048_mont_sqr_16(r, r, m, mp);
            sp_2048_mont_sqr_16(r, r, m, mp);
            sp_2048_mont_sqr_16(r, r, m, mp);

            sp_2048_mont_mul_16(r, r, t[y], m, mp);
        }

        XMEMSET(&r[16], 0, sizeof(sp_digit) * 16U);
        sp_2048_mont_reduce_16(r, m, mp);

        mask = 0 - (sp_2048_cmp_16(r, m) >= 0);
        sp_2048_cond_sub_16(r, r, m, mask);
    }


    return err;
}
#else
/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success.
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even or exponent is 0.
 */
static int sp_2048_mod_exp_16(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[32 * 32];
    sp_digit* t[32];
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<32; i++) {
            t[i] = td + i * 32;
        }

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_16(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 16U);
        if (reduceA != 0) {
            err = sp_2048_mod_16(t[1] + 16, a, m);
            if (err == MP_OKAY) {
                err = sp_2048_mod_16(t[1], t[1], m);
            }
        }
        else {
            XMEMCPY(t[1] + 16, a, sizeof(sp_digit) * 16);
            err = sp_2048_mod_16(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_2048_mont_sqr_16(t[ 2], t[ 1], m, mp);
        sp_2048_mont_mul_16(t[ 3], t[ 2], t[ 1], m, mp);
        sp_2048_mont_sqr_16(t[ 4], t[ 2], m, mp);
        sp_2048_mont_mul_16(t[ 5], t[ 3], t[ 2], m, mp);
        sp_2048_mont_sqr_16(t[ 6], t[ 3], m, mp);
        sp_2048_mont_mul_16(t[ 7], t[ 4], t[ 3], m, mp);
        sp_2048_mont_sqr_16(t[ 8], t[ 4], m, mp);
        sp_2048_mont_mul_16(t[ 9], t[ 5], t[ 4], m, mp);
        sp_2048_mont_sqr_16(t[10], t[ 5], m, mp);
        sp_2048_mont_mul_16(t[11], t[ 6], t[ 5], m, mp);
        sp_2048_mont_sqr_16(t[12], t[ 6], m, mp);
        sp_2048_mont_mul_16(t[13], t[ 7], t[ 6], m, mp);
        sp_2048_mont_sqr_16(t[14], t[ 7], m, mp);
        sp_2048_mont_mul_16(t[15], t[ 8], t[ 7], m, mp);
        sp_2048_mont_sqr_16(t[16], t[ 8], m, mp);
        sp_2048_mont_mul_16(t[17], t[ 9], t[ 8], m, mp);
        sp_2048_mont_sqr_16(t[18], t[ 9], m, mp);
        sp_2048_mont_mul_16(t[19], t[10], t[ 9], m, mp);
        sp_2048_mont_sqr_16(t[20], t[10], m, mp);
        sp_2048_mont_mul_16(t[21], t[11], t[10], m, mp);
        sp_2048_mont_sqr_16(t[22], t[11], m, mp);
        sp_2048_mont_mul_16(t[23], t[12], t[11], m, mp);
        sp_2048_mont_sqr_16(t[24], t[12], m, mp);
        sp_2048_mont_mul_16(t[25], t[13], t[12], m, mp);
        sp_2048_mont_sqr_16(t[26], t[13], m, mp);
        sp_2048_mont_mul_16(t[27], t[14], t[13], m, mp);
        sp_2048_mont_sqr_16(t[28], t[14], m, mp);
        sp_2048_mont_mul_16(t[29], t[15], t[14], m, mp);
        sp_2048_mont_sqr_16(t[30], t[15], m, mp);
        sp_2048_mont_mul_16(t[31], t[16], t[15], m, mp);

        i = (bits - 1) / 64;
        n = e[i--];
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        c -= bits % 5;
        if (c == 64) {
            c = 59;
        }
        if (c < 0) {
            /* Number of bits in top word is less than number needed. */
            c = -c;
            y = (byte)(n << c);
            n = e[i--];
            y |= (byte)(n >> (64 - c));
            n <<= c;
            c = 64 - c;
        }
        else if (c == 0) {
            /* All bits in top word used. */
            y = (byte)n;
        }
        else {
            y = (byte)(n >> c);
            n <<= 64 - c;
        }
        XMEMCPY(r, t[y], sizeof(sp_digit) * 16);
        for (; i>=0 || c>=5; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 59);
                n <<= 5;
                c = 59;
            }
            else if (c < 5) {
                y = (byte)(n >> 59);
                n = e[i--];
                c = 5 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }
            else {
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c -= 5;
            }

            sp_2048_mont_sqr_16(r, r, m, mp);
            sp_2048_mont_sqr_16(r, r, m, mp);
            sp_2048_mont_sqr_16(r, r, m, mp);
            sp_2048_mont_sqr_16(r, r, m, mp);
            sp_2048_mont_sqr_16(r, r, m, mp);

            sp_2048_mont_mul_16(r, r, t[y], m, mp);
        }

        XMEMSET(&r[16], 0, sizeof(sp_digit) * 16U);
        sp_2048_mont_reduce_16(r, m, mp);

        mask = 0 - (sp_2048_cmp_16(r, m) >= 0);
        sp_2048_cond_sub_16(r, r, m, mask);
    }


    return err;
}
#endif /* WOLFSSL_SP_SMALL */

#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) | WOLFSSL_HAVE_SP_DH */

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 2048 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_2048_mont_norm_32(sp_digit* r, const sp_digit* m)
{
    XMEMSET(r, 0, sizeof(sp_digit) * 32);

    /* r = 2^n mod m */
    sp_2048_sub_in_place_32(r, m);
}

#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) | WOLFSSL_HAVE_SP_DH */
/* Reduce the number back to 2048 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
SP_NOINLINE static void sp_2048_mont_reduce_32(sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    __asm__ __volatile__ (
        "ldp	x11, x12, [%[a], 0]\n\t"
        "ldp	x13, x14, [%[a], 16]\n\t"
        "ldp	x15, x16, [%[a], 32]\n\t"
        "ldp	x17, x19, [%[a], 48]\n\t"
        "ldp	x20, x21, [%[a], 64]\n\t"
        "ldp	x22, x23, [%[a], 80]\n\t"
        "# No carry yet\n\t"
        "mov	x3, xzr\n\t"
        "# i = 0..31\n\t"
        "mov	x4, 32\n\t"
        "\n1:\n\t"
        "# mu = a[i] * mp\n\t"
        "mul	x10, %[mp], x11\n\t"
        "ldp	x24, x25, [%[m], 0]\n\t"
        "ldp	x26, x27, [%[m], 16]\n\t"
        "# a[i+0] += m[0] * mu\n\t"
        "mul	x5, x24, x10\n\t"
        "umulh	x6, x24, x10\n\t"
        "# a[i+1] += m[1] * mu\n\t"
        "adds	x11, x11, x5\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x11, x12, x5\n\t"
        "# a[i+2] += m[2] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x11, x11, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x12, x13, x5\n\t"
        "# a[i+3] += m[3] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x12, x12, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x13, x14, x5\n\t"
        "ldp	x24, x25, [%[m], 32]\n\t"
        "ldp	x26, x27, [%[m], 48]\n\t"
        "# a[i+4] += m[4] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x13, x13, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x14, x15, x5\n\t"
        "# a[i+5] += m[5] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x14, x14, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x15, x16, x5\n\t"
        "# a[i+6] += m[6] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x15, x15, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x16, x17, x5\n\t"
        "# a[i+7] += m[7] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x16, x16, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x17, x19, x5\n\t"
        "ldp	x24, x25, [%[m], 64]\n\t"
        "ldp	x26, x27, [%[m], 80]\n\t"
        "# a[i+8] += m[8] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x17, x17, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x19, x20, x5\n\t"
        "# a[i+9] += m[9] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x19, x19, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x20, x21, x5\n\t"
        "# a[i+10] += m[10] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x20, x20, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x21, x22, x5\n\t"
        "# a[i+11] += m[11] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x21, x21, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x22, x23, x5\n\t"
        "ldp	x24, x25, [%[m], 96]\n\t"
        "ldp	x26, x27, [%[m], 112]\n\t"
        "# a[i+12] += m[12] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x22, x22, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "ldr	x23, [%[a], 96]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x23, x23, x5\n\t"
        "# a[i+13] += m[13] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x23, x23, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "ldp	x8, x9, [%[a], 104]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+14] += m[14] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 104]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+15] += m[15] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 112]\n\t"
        "ldp	x8, x9, [%[a], 120]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 128]\n\t"
        "ldp	x26, x27, [%[m], 144]\n\t"
        "# a[i+16] += m[16] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 120]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+17] += m[17] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 128]\n\t"
        "ldp	x8, x9, [%[a], 136]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+18] += m[18] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 136]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+19] += m[19] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 144]\n\t"
        "ldp	x8, x9, [%[a], 152]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 160]\n\t"
        "ldp	x26, x27, [%[m], 176]\n\t"
        "# a[i+20] += m[20] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 152]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+21] += m[21] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 160]\n\t"
        "ldp	x8, x9, [%[a], 168]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+22] += m[22] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 168]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+23] += m[23] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 176]\n\t"
        "ldp	x8, x9, [%[a], 184]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 192]\n\t"
        "ldp	x26, x27, [%[m], 208]\n\t"
        "# a[i+24] += m[24] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 184]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+25] += m[25] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 192]\n\t"
        "ldp	x8, x9, [%[a], 200]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+26] += m[26] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 200]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+27] += m[27] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 208]\n\t"
        "ldp	x8, x9, [%[a], 216]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 224]\n\t"
        "ldp	x26, x27, [%[m], 240]\n\t"
        "# a[i+28] += m[28] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 216]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+29] += m[29] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 224]\n\t"
        "ldp	x8, x9, [%[a], 232]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+30] += m[30] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 232]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+31] += m[31] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 240]\n\t"
        "umulh	x7, x27, x10\n\t"
        "ldp	x8, x9, [%[a], 248]\n\t"
        "adds	x5, x5, x6\n\t"
        "adcs	x7, x7, x3\n\t"
        "cset	x3, cs\n\t"
        "adds	x8, x8, x5\n\t"
        "str	x8, [%[a], 248]\n\t"
        "adcs	x9, x9, x7\n\t"
        "str	x9, [%[a], 256]\n\t"
        "adc	x3, x3, xzr\n\t"
        "subs	x4, x4, 1\n\t"
        "add	%[a], %[a], 8\n\t"
        "b.ne	1b\n\t"
        "# Create mask\n\t"
        "neg	x3, x3\n\t"
        "mov   %[mp], %[a]\n\t"
        "sub	%[a], %[a], 256\n\t"
        "# Subtract masked modulus\n\t"
        "ldp	x4, x5, [%[m], 0]\n\t"
        "ldp	x6, x7, [%[m], 16]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "subs	x11, x11, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x12, x12, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x13, x13, x6\n\t"
        "stp	x11, x12, [%[a], 0]\n\t"
        "sbcs	x14, x14, x7\n\t"
        "stp	x13, x14, [%[a], 16]\n\t"
        "ldp	x4, x5, [%[m], 32]\n\t"
        "ldp	x6, x7, [%[m], 48]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x15, x15, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x16, x16, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x17, x17, x6\n\t"
        "stp	x15, x16, [%[a], 32]\n\t"
        "sbcs	x19, x19, x7\n\t"
        "stp	x17, x19, [%[a], 48]\n\t"
        "ldp	x4, x5, [%[m], 64]\n\t"
        "ldp	x6, x7, [%[m], 80]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x20, x20, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x21, x21, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x22, x22, x6\n\t"
        "stp	x20, x21, [%[a], 64]\n\t"
        "sbcs	x23, x23, x7\n\t"
        "stp	x22, x23, [%[a], 80]\n\t"
        "ldp	x4, x5, [%[m], 96]\n\t"
        "ldp	x6, x7, [%[m], 112]\n\t"
        "ldp	x8, x9, [%[mp], 96]\n\t"
        "ldp	x10, x11, [%[mp], 112]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 96]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 112]\n\t"
        "ldp	x4, x5, [%[m], 128]\n\t"
        "ldp	x6, x7, [%[m], 144]\n\t"
        "ldp	x8, x9, [%[mp], 128]\n\t"
        "ldp	x10, x11, [%[mp], 144]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 128]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 144]\n\t"
        "ldp	x4, x5, [%[m], 160]\n\t"
        "ldp	x6, x7, [%[m], 176]\n\t"
        "ldp	x8, x9, [%[mp], 160]\n\t"
        "ldp	x10, x11, [%[mp], 176]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 160]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 176]\n\t"
        "ldp	x4, x5, [%[m], 192]\n\t"
        "ldp	x6, x7, [%[m], 208]\n\t"
        "ldp	x8, x9, [%[mp], 192]\n\t"
        "ldp	x10, x11, [%[mp], 208]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 192]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 208]\n\t"
        "ldp	x4, x5, [%[m], 224]\n\t"
        "ldp	x6, x7, [%[m], 240]\n\t"
        "ldp	x8, x9, [%[mp], 224]\n\t"
        "ldp	x10, x11, [%[mp], 240]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 224]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 240]\n\t"
        : [a] "+r" (a), [mp] "+r" (mp)
        : [m] "r" (m)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x10", "x8", "x9", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27"
    );

}

/* Multiply two Montgomery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montgomery form.
 * b   Second number to multiply in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_2048_mont_mul_32(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_2048_mul_32(r, a, b);
    sp_2048_mont_reduce_32(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_2048_mont_sqr_32(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_2048_sqr_32(r, a);
    sp_2048_mont_reduce_32(r, m, mp);
}

#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_2048_sub_32(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "add	x11, %[a], 256\n\t"
        "\n1:\n\t"
        "subs	%[c], xzr, %[c]\n\t"
        "ldp	x3, x4, [%[a]], #16\n\t"
        "ldp	x5, x6, [%[a]], #16\n\t"
        "ldp	x7, x8, [%[b]], #16\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x9, x10, [%[b]], #16\n\t"
        "sbcs	x4, x4, x8\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r]], #16\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r]], #16\n\t"
        "csetm	%[c], cc\n\t"
        "cmp	%[a], x11\n\t"
        "b.ne	1b\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    return c;
}

#else
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_2048_sub_32(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x7, x8, [%[b], 0]\n\t"
        "subs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 16]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldp	x3, x4, [%[a], 32]\n\t"
        "ldp	x7, x8, [%[b], 32]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 48]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 48]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 32]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 48]\n\t"
        "ldp	x3, x4, [%[a], 64]\n\t"
        "ldp	x7, x8, [%[b], 64]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 80]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 80]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 64]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 80]\n\t"
        "ldp	x3, x4, [%[a], 96]\n\t"
        "ldp	x7, x8, [%[b], 96]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 112]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 112]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 96]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 112]\n\t"
        "ldp	x3, x4, [%[a], 128]\n\t"
        "ldp	x7, x8, [%[b], 128]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 144]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 144]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 128]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 144]\n\t"
        "ldp	x3, x4, [%[a], 160]\n\t"
        "ldp	x7, x8, [%[b], 160]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 176]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 176]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 160]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 176]\n\t"
        "ldp	x3, x4, [%[a], 192]\n\t"
        "ldp	x7, x8, [%[b], 192]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 208]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 208]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 192]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 208]\n\t"
        "ldp	x3, x4, [%[a], 224]\n\t"
        "ldp	x7, x8, [%[b], 224]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 240]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 240]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 224]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 240]\n\t"
        "csetm	%[r], cc\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return (sp_digit)r;
}

#endif /* WOLFSSL_SP_SMALL */
/* Divide the double width number (d1|d0) by the divisor. (d1|d0 / div)
 *
 * Assumes divisor has higest bit set.
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The divisor.
 * returns the result of the division.
 */
static sp_digit div_2048_word_32_cond(sp_digit d1, sp_digit d0, sp_digit div)
{
    __asm__ __volatile__ (
        "lsr	x8, %[div], 32\n\t"
        "add	x5, x8, 1\n\t"

        "udiv	x3, %[d1], x5\n\t"
        "lsl	x7, %[div], 32\n\t"
        "movz	x9, #1, lsl 32\n\t"
        "lsl	x6, x3, 32\n\t"
        "mul	x4, %[div], x6\n\t"
        "umulh	x3, %[div], x6\n\t"
        "subs	%[d0], %[d0], x4\n\t"
        "sbc	%[d1], %[d1], x3\n\t"

        "cmp	%[d1], x5\n\t"
        "b.lt	1f\n\t"
        "subs	%[d0], %[d0], x7\n\t"
        "add	x6, x6, x9\n\t"
        "sbc	%[d1], %[d1], x8\n\t"
        "1:\n\t"

        "extr	x3, %[d1], %[d0], 32\n\t"

        "udiv	x3, x3, x5\n\t"
        "add	x6, x6, x3\n\t"
        "mul	x4, %[div], x3\n\t"
        "umulh	x3, %[div], x3\n\t"
        "subs	%[d0], %[d0], x4\n\t"
        "sbc	%[d1], %[d1], x3\n\t"

        "extr	x3, %[d1], %[d0], 32\n\t"

        "cmp	x3, x5\n\t"
        "b.lt	2f\n\t"
        "udiv   x3, x3, x5\n\t"
        "add    x6, x6, x3\n\t"
        "mul    x4, %[div], x3\n\t"
        "sub    %[d0], %[d0], x4\n\t"
        "2:\n\t"

        "udiv	x3, %[d0], %[div]\n\t"
        "add	%[d1], x6, x3\n\t"

        : [d1] "+r" (d1), [d0] "+r" (d0)
        : [div] "r" (div)
        : "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );

    return d1;
}

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_2048_div_32_cond(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    sp_digit t1[64], t2[33];
    sp_digit div, r1;
    int i;

    (void)m;

    div = d[31];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 32);
    for (i = 31; i >= 0; i--) {
        if (t1[32 + i] == div) {
            r1 = SP_DIGIT_MAX;
        }
        else {
            r1 = div_2048_word_32_cond(t1[32 + i], t1[32 + i - 1], div);
        }

        sp_2048_mul_d_32(t2, d, r1);
        t1[32 + i] += sp_2048_sub_in_place_32(&t1[i], t2);
        t1[32 + i] -= t2[32];
        if (t1[32 + i] != 0) {
            t1[32 + i] += sp_2048_add_32(&t1[i], &t1[i], d);
            if (t1[32 + i] != 0)
                t1[32 + i] += sp_2048_add_32(&t1[i], &t1[i], d);
        }
    }

    for (i = 31; i > 0; i--) {
        if (t1[i] != d[i])
            break;
    }
    if (t1[i] >= d[i]) {
        sp_2048_sub_32(r, t1, d);
    }
    else {
        XMEMCPY(r, t1, sizeof(*t1) * 32);
    }

    return MP_OKAY;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_2048_mod_32_cond(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_2048_div_32_cond(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not copying.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static sp_digit sp_2048_cond_sub_32(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	x8, #0\n\t"
        "1:\n\t"
        "subs	%[c], xzr, %[c]\n\t"
        "ldr	x4, [%[a], x8]\n\t"
        "ldr	x5, [%[b], x8]\n\t"
        "and	x5, x5, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "csetm	%[c], cc\n\t"
        "str	x4, [%[r], x8]\n\t"
        "add	x8, x8, #8\n\t"
        "cmp	x8, 256\n\t"
        "b.lt	1b\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x6", "x5", "x7", "x8", "x9", "x10", "x11", "x12"
    );

    return c;
#else
    __asm__ __volatile__ (

        "ldp	x5, x7, [%[b], 0]\n\t"
        "ldp	x11, x12, [%[b], 16]\n\t"
        "ldp	x4, x6, [%[a], 0]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 16]\n\t"
        "and	x7, x7, %[m]\n\t"
        "subs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 0]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 16]\n\t"
        "ldp	x5, x7, [%[b], 32]\n\t"
        "ldp	x11, x12, [%[b], 48]\n\t"
        "ldp	x4, x6, [%[a], 32]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 48]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 32]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 48]\n\t"
        "ldp	x5, x7, [%[b], 64]\n\t"
        "ldp	x11, x12, [%[b], 80]\n\t"
        "ldp	x4, x6, [%[a], 64]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 80]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 64]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 80]\n\t"
        "ldp	x5, x7, [%[b], 96]\n\t"
        "ldp	x11, x12, [%[b], 112]\n\t"
        "ldp	x4, x6, [%[a], 96]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 112]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 96]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 112]\n\t"
        "ldp	x5, x7, [%[b], 128]\n\t"
        "ldp	x11, x12, [%[b], 144]\n\t"
        "ldp	x4, x6, [%[a], 128]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 144]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 128]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 144]\n\t"
        "ldp	x5, x7, [%[b], 160]\n\t"
        "ldp	x11, x12, [%[b], 176]\n\t"
        "ldp	x4, x6, [%[a], 160]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 176]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 160]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 176]\n\t"
        "ldp	x5, x7, [%[b], 192]\n\t"
        "ldp	x11, x12, [%[b], 208]\n\t"
        "ldp	x4, x6, [%[a], 192]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 208]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 192]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 208]\n\t"
        "ldp	x5, x7, [%[b], 224]\n\t"
        "ldp	x11, x12, [%[b], 240]\n\t"
        "ldp	x4, x6, [%[a], 224]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 240]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 224]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 240]\n\t"
        "csetm	%[r], cc\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x6", "x5", "x7", "x8", "x9", "x10", "x11", "x12"
    );

    return (sp_digit)r;
#endif /* WOLFSSL_SP_SMALL */
}

/* Divide the double width number (d1|d0) by the divisor. (d1|d0 / div)
 *
 * Assumes divisor has higest bit set.
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The divisor.
 * returns the result of the division.
 */
static sp_digit div_2048_word_32(sp_digit d1, sp_digit d0, sp_digit div)
{
    __asm__ __volatile__ (
        "lsr	x8, %[div], 32\n\t"
        "add	x5, x8, 1\n\t"

        "udiv	x3, %[d1], x5\n\t"
        "lsl	x7, %[div], 32\n\t"
        "movz	x9, #1, lsl 32\n\t"
        "lsl	x6, x3, 32\n\t"
        "mul	x4, %[div], x6\n\t"
        "umulh	x3, %[div], x6\n\t"
        "subs	%[d0], %[d0], x4\n\t"
        "sbc	%[d1], %[d1], x3\n\t"

        "cmp	%[d1], x5\n\t"
        "cset	x9, ge\n\t"
        "csetm	x10, ge\n\t"
        "lsl	x9, x9, #32\n\t"
        "and	x7, x7, x10\n\t"
        "and	x8, x8, x10\n\t"
        "subs	%[d0], %[d0], x7\n\t"
        "add	x6, x6, x9\n\t"
        "sbc	%[d1], %[d1], x8\n\t"

        "extr	x3, %[d1], %[d0], 32\n\t"

        "udiv	x3, x3, x5\n\t"
        "add	x6, x6, x3\n\t"
        "mul	x4, %[div], x3\n\t"
        "umulh	x3, %[div], x3\n\t"
        "subs	%[d0], %[d0], x4\n\t"
        "sbc	%[d1], %[d1], x3\n\t"

        "extr	x3, %[d1], %[d0], 32\n\t"

        "udiv   x3, x3, x5\n\t"
        "add    x6, x6, x3\n\t"
        "mul    x4, %[div], x3\n\t"
        "sub    %[d0], %[d0], x4\n\t"

        "udiv	x3, %[d0], %[div]\n\t"
        "add	%[d1], x6, x3\n\t"

        : [d1] "+r" (d1), [d0] "+r" (d0)
        : [div] "r" (div)
        : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return d1;
}

/* AND m into each word of a and store in r.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * m  Mask to AND against each digit.
 */
static void sp_2048_mask_32(sp_digit* r, const sp_digit* a, sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<32; i++) {
        r[i] = a[i] & m;
    }
#else
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i+0] = a[i+0] & m;
        r[i+1] = a[i+1] & m;
        r[i+2] = a[i+2] & m;
        r[i+3] = a[i+3] & m;
        r[i+4] = a[i+4] & m;
        r[i+5] = a[i+5] & m;
        r[i+6] = a[i+6] & m;
        r[i+7] = a[i+7] & m;
    }
#endif
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_int64 sp_2048_cmp_32(const sp_digit* a, const sp_digit* b)
{
#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "mov	x3, #0\n\t"
        "mov	x2, #-1\n\t"
        "mov	x10, #32\n\t"
        "add	%[a], %[a], #240\n\t"
        "add	%[b], %[b], #240\n\t"
        "1:\n\t"
        "ldp	x6, x7, [%[a]], -16\n\t"
        "ldp	x8, x9, [%[b]], -16\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x10, x10, #2\n\t"
        "b.ne	1b\n\t"
        "cmp	x2, #0\n\t"
        "cset	%[a], eq\n\t"
        "orr	%[a], %[a], x3\n\t"
        : [a] "+r" (a), [b] "+r" (b)
        :
        : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );
#else
    __asm__ __volatile__ (
        "mov	x3, #0\n\t"
        "mov	x2, #-1\n\t"
        "ldp	x6, x7, [%[a], 240]\n\t"
        "ldp	x8, x9, [%[b], 240]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 224]\n\t"
        "ldp	x8, x9, [%[b], 224]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 208]\n\t"
        "ldp	x8, x9, [%[b], 208]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 192]\n\t"
        "ldp	x8, x9, [%[b], 192]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 176]\n\t"
        "ldp	x8, x9, [%[b], 176]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 160]\n\t"
        "ldp	x8, x9, [%[b], 160]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 144]\n\t"
        "ldp	x8, x9, [%[b], 144]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 128]\n\t"
        "ldp	x8, x9, [%[b], 128]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 112]\n\t"
        "ldp	x8, x9, [%[b], 112]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 96]\n\t"
        "ldp	x8, x9, [%[b], 96]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 80]\n\t"
        "ldp	x8, x9, [%[b], 80]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 64]\n\t"
        "ldp	x8, x9, [%[b], 64]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 48]\n\t"
        "ldp	x8, x9, [%[b], 48]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 32]\n\t"
        "ldp	x8, x9, [%[b], 32]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 16]\n\t"
        "ldp	x8, x9, [%[b], 16]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 0]\n\t"
        "ldp	x8, x9, [%[b], 0]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "cmp	x2, #0\n\t"
        "cset	%[a], eq\n\t"
        "orr	%[a], %[a], x3\n\t"
        : [a] "+r" (a)
        : [b] "r" (b)
        : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );
#endif

    return (sp_int64)a;
}

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_2048_div_32(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    sp_digit t1[64], t2[33];
    sp_digit div, r1;
    int i;

    (void)m;

    div = d[31];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 32);
    for (i = 31; i >= 0; i--) {
        sp_digit hi = t1[32 + i] - (t1[32 + i] == div);
        r1 = div_2048_word_32(hi, t1[32 + i - 1], div);

        sp_2048_mul_d_32(t2, d, r1);
        t1[32 + i] += sp_2048_sub_in_place_32(&t1[i], t2);
        t1[32 + i] -= t2[32];
        sp_2048_mask_32(t2, d, t1[32 + i]);
        t1[32 + i] += sp_2048_add_32(&t1[i], &t1[i], t2);
        sp_2048_mask_32(t2, d, t1[32 + i]);
        t1[32 + i] += sp_2048_add_32(&t1[i], &t1[i], t2);
    }

    r1 = sp_2048_cmp_32(t1, d) >= 0;
    sp_2048_cond_sub_32(r, t1, d, (sp_digit)0 - r1);

    return MP_OKAY;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_2048_mod_32(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_2048_div_32(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || \
                                                     defined(WOLFSSL_HAVE_SP_DH)
#ifdef WOLFSSL_SP_SMALL
/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success.
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even or exponent is 0.
 */
static int sp_2048_mod_exp_32(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[32 * 64];
    sp_digit* t[32];
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<32; i++) {
            t[i] = td + i * 64;
        }

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_32(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 32U);
        if (reduceA != 0) {
            err = sp_2048_mod_32(t[1] + 32, a, m);
            if (err == MP_OKAY) {
                err = sp_2048_mod_32(t[1], t[1], m);
            }
        }
        else {
            XMEMCPY(t[1] + 32, a, sizeof(sp_digit) * 32);
            err = sp_2048_mod_32(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_2048_mont_sqr_32(t[ 2], t[ 1], m, mp);
        sp_2048_mont_mul_32(t[ 3], t[ 2], t[ 1], m, mp);
        sp_2048_mont_sqr_32(t[ 4], t[ 2], m, mp);
        sp_2048_mont_mul_32(t[ 5], t[ 3], t[ 2], m, mp);
        sp_2048_mont_sqr_32(t[ 6], t[ 3], m, mp);
        sp_2048_mont_mul_32(t[ 7], t[ 4], t[ 3], m, mp);
        sp_2048_mont_sqr_32(t[ 8], t[ 4], m, mp);
        sp_2048_mont_mul_32(t[ 9], t[ 5], t[ 4], m, mp);
        sp_2048_mont_sqr_32(t[10], t[ 5], m, mp);
        sp_2048_mont_mul_32(t[11], t[ 6], t[ 5], m, mp);
        sp_2048_mont_sqr_32(t[12], t[ 6], m, mp);
        sp_2048_mont_mul_32(t[13], t[ 7], t[ 6], m, mp);
        sp_2048_mont_sqr_32(t[14], t[ 7], m, mp);
        sp_2048_mont_mul_32(t[15], t[ 8], t[ 7], m, mp);
        sp_2048_mont_sqr_32(t[16], t[ 8], m, mp);
        sp_2048_mont_mul_32(t[17], t[ 9], t[ 8], m, mp);
        sp_2048_mont_sqr_32(t[18], t[ 9], m, mp);
        sp_2048_mont_mul_32(t[19], t[10], t[ 9], m, mp);
        sp_2048_mont_sqr_32(t[20], t[10], m, mp);
        sp_2048_mont_mul_32(t[21], t[11], t[10], m, mp);
        sp_2048_mont_sqr_32(t[22], t[11], m, mp);
        sp_2048_mont_mul_32(t[23], t[12], t[11], m, mp);
        sp_2048_mont_sqr_32(t[24], t[12], m, mp);
        sp_2048_mont_mul_32(t[25], t[13], t[12], m, mp);
        sp_2048_mont_sqr_32(t[26], t[13], m, mp);
        sp_2048_mont_mul_32(t[27], t[14], t[13], m, mp);
        sp_2048_mont_sqr_32(t[28], t[14], m, mp);
        sp_2048_mont_mul_32(t[29], t[15], t[14], m, mp);
        sp_2048_mont_sqr_32(t[30], t[15], m, mp);
        sp_2048_mont_mul_32(t[31], t[16], t[15], m, mp);

        i = (bits - 1) / 64;
        n = e[i--];
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        c -= bits % 5;
        if (c == 64) {
            c = 59;
        }
        if (c < 0) {
            /* Number of bits in top word is less than number needed. */
            c = -c;
            y = (byte)(n << c);
            n = e[i--];
            y |= (byte)(n >> (64 - c));
            n <<= c;
            c = 64 - c;
        }
        else if (c == 0) {
            /* All bits in top word used. */
            y = (byte)n;
        }
        else {
            y = (byte)(n >> c);
            n <<= 64 - c;
        }
        XMEMCPY(r, t[y], sizeof(sp_digit) * 32);
        for (; i>=0 || c>=5; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 59);
                n <<= 5;
                c = 59;
            }
            else if (c < 5) {
                y = (byte)(n >> 59);
                n = e[i--];
                c = 5 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }
            else {
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c -= 5;
            }

            sp_2048_mont_sqr_32(r, r, m, mp);
            sp_2048_mont_sqr_32(r, r, m, mp);
            sp_2048_mont_sqr_32(r, r, m, mp);
            sp_2048_mont_sqr_32(r, r, m, mp);
            sp_2048_mont_sqr_32(r, r, m, mp);

            sp_2048_mont_mul_32(r, r, t[y], m, mp);
        }

        XMEMSET(&r[32], 0, sizeof(sp_digit) * 32U);
        sp_2048_mont_reduce_32(r, m, mp);

        mask = 0 - (sp_2048_cmp_32(r, m) >= 0);
        sp_2048_cond_sub_32(r, r, m, mask);
    }


    return err;
}
#else
/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success.
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even or exponent is 0.
 */
static int sp_2048_mod_exp_32(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[64 * 64];
    sp_digit* t[64];
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<64; i++) {
            t[i] = td + i * 64;
        }

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_32(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 32U);
        if (reduceA != 0) {
            err = sp_2048_mod_32(t[1] + 32, a, m);
            if (err == MP_OKAY) {
                err = sp_2048_mod_32(t[1], t[1], m);
            }
        }
        else {
            XMEMCPY(t[1] + 32, a, sizeof(sp_digit) * 32);
            err = sp_2048_mod_32(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_2048_mont_sqr_32(t[ 2], t[ 1], m, mp);
        sp_2048_mont_mul_32(t[ 3], t[ 2], t[ 1], m, mp);
        sp_2048_mont_sqr_32(t[ 4], t[ 2], m, mp);
        sp_2048_mont_mul_32(t[ 5], t[ 3], t[ 2], m, mp);
        sp_2048_mont_sqr_32(t[ 6], t[ 3], m, mp);
        sp_2048_mont_mul_32(t[ 7], t[ 4], t[ 3], m, mp);
        sp_2048_mont_sqr_32(t[ 8], t[ 4], m, mp);
        sp_2048_mont_mul_32(t[ 9], t[ 5], t[ 4], m, mp);
        sp_2048_mont_sqr_32(t[10], t[ 5], m, mp);
        sp_2048_mont_mul_32(t[11], t[ 6], t[ 5], m, mp);
        sp_2048_mont_sqr_32(t[12], t[ 6], m, mp);
        sp_2048_mont_mul_32(t[13], t[ 7], t[ 6], m, mp);
        sp_2048_mont_sqr_32(t[14], t[ 7], m, mp);
        sp_2048_mont_mul_32(t[15], t[ 8], t[ 7], m, mp);
        sp_2048_mont_sqr_32(t[16], t[ 8], m, mp);
        sp_2048_mont_mul_32(t[17], t[ 9], t[ 8], m, mp);
        sp_2048_mont_sqr_32(t[18], t[ 9], m, mp);
        sp_2048_mont_mul_32(t[19], t[10], t[ 9], m, mp);
        sp_2048_mont_sqr_32(t[20], t[10], m, mp);
        sp_2048_mont_mul_32(t[21], t[11], t[10], m, mp);
        sp_2048_mont_sqr_32(t[22], t[11], m, mp);
        sp_2048_mont_mul_32(t[23], t[12], t[11], m, mp);
        sp_2048_mont_sqr_32(t[24], t[12], m, mp);
        sp_2048_mont_mul_32(t[25], t[13], t[12], m, mp);
        sp_2048_mont_sqr_32(t[26], t[13], m, mp);
        sp_2048_mont_mul_32(t[27], t[14], t[13], m, mp);
        sp_2048_mont_sqr_32(t[28], t[14], m, mp);
        sp_2048_mont_mul_32(t[29], t[15], t[14], m, mp);
        sp_2048_mont_sqr_32(t[30], t[15], m, mp);
        sp_2048_mont_mul_32(t[31], t[16], t[15], m, mp);
        sp_2048_mont_sqr_32(t[32], t[16], m, mp);
        sp_2048_mont_mul_32(t[33], t[17], t[16], m, mp);
        sp_2048_mont_sqr_32(t[34], t[17], m, mp);
        sp_2048_mont_mul_32(t[35], t[18], t[17], m, mp);
        sp_2048_mont_sqr_32(t[36], t[18], m, mp);
        sp_2048_mont_mul_32(t[37], t[19], t[18], m, mp);
        sp_2048_mont_sqr_32(t[38], t[19], m, mp);
        sp_2048_mont_mul_32(t[39], t[20], t[19], m, mp);
        sp_2048_mont_sqr_32(t[40], t[20], m, mp);
        sp_2048_mont_mul_32(t[41], t[21], t[20], m, mp);
        sp_2048_mont_sqr_32(t[42], t[21], m, mp);
        sp_2048_mont_mul_32(t[43], t[22], t[21], m, mp);
        sp_2048_mont_sqr_32(t[44], t[22], m, mp);
        sp_2048_mont_mul_32(t[45], t[23], t[22], m, mp);
        sp_2048_mont_sqr_32(t[46], t[23], m, mp);
        sp_2048_mont_mul_32(t[47], t[24], t[23], m, mp);
        sp_2048_mont_sqr_32(t[48], t[24], m, mp);
        sp_2048_mont_mul_32(t[49], t[25], t[24], m, mp);
        sp_2048_mont_sqr_32(t[50], t[25], m, mp);
        sp_2048_mont_mul_32(t[51], t[26], t[25], m, mp);
        sp_2048_mont_sqr_32(t[52], t[26], m, mp);
        sp_2048_mont_mul_32(t[53], t[27], t[26], m, mp);
        sp_2048_mont_sqr_32(t[54], t[27], m, mp);
        sp_2048_mont_mul_32(t[55], t[28], t[27], m, mp);
        sp_2048_mont_sqr_32(t[56], t[28], m, mp);
        sp_2048_mont_mul_32(t[57], t[29], t[28], m, mp);
        sp_2048_mont_sqr_32(t[58], t[29], m, mp);
        sp_2048_mont_mul_32(t[59], t[30], t[29], m, mp);
        sp_2048_mont_sqr_32(t[60], t[30], m, mp);
        sp_2048_mont_mul_32(t[61], t[31], t[30], m, mp);
        sp_2048_mont_sqr_32(t[62], t[31], m, mp);
        sp_2048_mont_mul_32(t[63], t[32], t[31], m, mp);

        i = (bits - 1) / 64;
        n = e[i--];
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        c -= bits % 6;
        if (c == 64) {
            c = 58;
        }
        if (c < 0) {
            /* Number of bits in top word is less than number needed. */
            c = -c;
            y = (byte)(n << c);
            n = e[i--];
            y |= (byte)(n >> (64 - c));
            n <<= c;
            c = 64 - c;
        }
        else if (c == 0) {
            /* All bits in top word used. */
            y = (byte)n;
        }
        else {
            y = (byte)(n >> c);
            n <<= 64 - c;
        }
        XMEMCPY(r, t[y], sizeof(sp_digit) * 32);
        for (; i>=0 || c>=6; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 58);
                n <<= 6;
                c = 58;
            }
            else if (c < 6) {
                y = (byte)(n >> 58);
                n = e[i--];
                c = 6 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }
            else {
                y = (byte)((n >> 58) & 0x3f);
                n <<= 6;
                c -= 6;
            }

            sp_2048_mont_sqr_32(r, r, m, mp);
            sp_2048_mont_sqr_32(r, r, m, mp);
            sp_2048_mont_sqr_32(r, r, m, mp);
            sp_2048_mont_sqr_32(r, r, m, mp);
            sp_2048_mont_sqr_32(r, r, m, mp);
            sp_2048_mont_sqr_32(r, r, m, mp);

            sp_2048_mont_mul_32(r, r, t[y], m, mp);
        }

        XMEMSET(&r[32], 0, sizeof(sp_digit) * 32U);
        sp_2048_mont_reduce_32(r, m, mp);

        mask = 0 - (sp_2048_cmp_32(r, m) >= 0);
        sp_2048_cond_sub_32(r, r, m, mask);
    }


    return err;
}
#endif /* WOLFSSL_SP_SMALL */
#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || WOLFSSL_HAVE_SP_DH */

#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || WOLFSSL_HAVE_SP_DH */
#ifdef WOLFSSL_HAVE_SP_RSA
/* RSA public key operation.
 *
 * in      Array of bytes representing the number to exponentiate, base.
 * inLen   Number of bytes in base.
 * em      Public exponent.
 * mm      Modulus.
 * out     Buffer to hold big-endian bytes of exponentiation result.
 *         Must be at least 256 bytes long.
 * outLen  Number of bytes in result.
 * returns 0 on success, MP_TO_E when the outLen is too small, MP_READ_E when
 * an array is too long and MEMORY_E when dynamic memory allocation fails.
 */
int sp_RsaPublic_2048(const byte* in, word32 inLen, const mp_int* em,
    const mp_int* mm, byte* out, word32* outLen)
{
    sp_digit a[32 * 5];
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit *ah = NULL;
    sp_digit e[1] = {0};
    int err = MP_OKAY;

    if (*outLen < 256) {
        err = MP_TO_E;
    }
    else if (mp_count_bits(em) > 64 || inLen > 256 ||
                                                     mp_count_bits(mm) != 2048) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mm)) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        ah = a + 32;
        r = a + 32 * 2;
        m = r + 32 * 2;

        sp_2048_from_bin(ah, 32, in, inLen);
#if DIGIT_BIT >= 64
        e[0] = em->dp[0];
#else
        e[0] = em->dp[0];
        if (em->used > 1) {
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
        }
#endif
        if (e[0] == 0) {
            err = MP_EXPTMOD_E;
        }
    }
    if (err == MP_OKAY) {
        sp_2048_from_mp(m, 32, mm);

        if (e[0] == 0x10001) {
            int i;
            sp_digit mp;

            sp_2048_mont_setup(m, &mp);

            /* Convert to Montgomery form. */
            XMEMSET(a, 0, sizeof(sp_digit) * 32);
            err = sp_2048_mod_32_cond(r, a, m);
            /* Montgomery form: r = a.R mod m */

            if (err == MP_OKAY) {
                /* r = a ^ 0x10000 => r = a squared 16 times */
                for (i = 15; i >= 0; i--) {
                    sp_2048_mont_sqr_32(r, r, m, mp);
                }
                /* mont_red(r.R.R) = (r.R.R / R) mod m = r.R mod m
                 * mont_red(r.R * a) = (r.R.a / R) mod m = r.a mod m
                 */
                sp_2048_mont_mul_32(r, r, ah, m, mp);

                for (i = 31; i > 0; i--) {
                    if (r[i] != m[i]) {
                        break;
                    }
                }
                if (r[i] >= m[i]) {
                    sp_2048_sub_in_place_32(r, m);
                }
            }
        }
        else if (e[0] == 0x3) {
            if (err == MP_OKAY) {
                sp_2048_sqr_32(r, ah);
                err = sp_2048_mod_32_cond(r, r, m);
            }
            if (err == MP_OKAY) {
                sp_2048_mul_32(r, ah, r);
                err = sp_2048_mod_32_cond(r, r, m);
            }
        }
        else {
            int i;
            sp_digit mp;

            sp_2048_mont_setup(m, &mp);

            /* Convert to Montgomery form. */
            XMEMSET(a, 0, sizeof(sp_digit) * 32);
            err = sp_2048_mod_32_cond(a, a, m);

            if (err == MP_OKAY) {
                for (i = 63; i >= 0; i--) {
                    if (e[0] >> i) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 32);
                for (i--; i >= 0; i--) {
                    sp_2048_mont_sqr_32(r, r, m, mp);
                    if (((e[0] >> i) & 1) == 1) {
                        sp_2048_mont_mul_32(r, r, a, m, mp);
                    }
                }
                XMEMSET(&r[32], 0, sizeof(sp_digit) * 32);
                sp_2048_mont_reduce_32(r, m, mp);

                for (i = 31; i > 0; i--) {
                    if (r[i] != m[i]) {
                        break;
                    }
                }
                if (r[i] >= m[i]) {
                    sp_2048_sub_in_place_32(r, m);
                }
            }
        }
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin_32(r, out);
        *outLen = 256;
    }


    return err;
}

#ifndef WOLFSSL_RSA_PUBLIC_ONLY
#ifdef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static sp_digit sp_2048_cond_add_16(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	x8, #0\n\t"
        "1:\n\t"
        "adds	%[c], %[c], #-1\n\t"
        "ldr	x4, [%[a], x8]\n\t"
        "ldr	x5, [%[b], x8]\n\t"
        "and	x5, x5, %[m]\n\t"
        "adcs	x4, x4, x5\n\t"
        "cset	%[c], cs\n\t"
        "str	x4, [%[r], x8]\n\t"
        "add	x8, x8, #8\n\t"
        "cmp	x8, 128\n\t"
        "b.lt	1b\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x5", "x8", "x9", "x10", "x11", "x12"
    );

    return c;
}
#endif /* WOLFSSL_SP_SMALL */

/* RSA private key operation.
 *
 * in      Array of bytes representing the number to exponentiate, base.
 * inLen   Number of bytes in base.
 * dm      Private exponent.
 * pm      First prime.
 * qm      Second prime.
 * dpm     First prime's CRT exponent.
 * dqm     Second prime's CRT exponent.
 * qim     Inverse of second prime mod p.
 * mm      Modulus.
 * out     Buffer to hold big-endian bytes of exponentiation result.
 *         Must be at least 256 bytes long.
 * outLen  Number of bytes in result.
 * returns 0 on success, MP_TO_E when the outLen is too small, MP_READ_E when
 * an array is too long and MEMORY_E when dynamic memory allocation fails.
 */
int sp_RsaPrivate_2048(const byte* in, word32 inLen, const mp_int* dm,
    const mp_int* pm, const mp_int* qm, const mp_int* dpm, const mp_int* dqm,
    const mp_int* qim, const mp_int* mm, byte* out, word32* outLen)
{
#if defined(SP_RSA_PRIVATE_EXP_D) || defined(RSA_LOW_MEM)
    sp_digit  d[32 * 4];
    sp_digit* a = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;

    (void)pm;
    (void)qm;
    (void)dpm;
    (void)dqm;
    (void)qim;

    if (*outLen < 256U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(dm) > 2048) {
           err = MP_READ_E;
        }
        else if (inLen > 256) {
            err = MP_READ_E;
        }
        else if (mp_count_bits(mm) != 2048) {
            err = MP_READ_E;
        }
        else if (mp_iseven(mm)) {
            err = MP_VAL;
        }
    }


    if (err == MP_OKAY) {
        a = d + 32;
        m = a + 64;
        r = a;

        sp_2048_from_bin(a, 32, in, inLen);
        sp_2048_from_mp(d, 32, dm);
        sp_2048_from_mp(m, 32, mm);
        err = sp_2048_mod_exp_32(r, a, d, 2048, m, 0);
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin_32(r, out);
        *outLen = 256;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 32);
    }

    return err;
#else
    sp_digit a[16 * 11];
    sp_digit* p = NULL;
    sp_digit* q = NULL;
    sp_digit* dp = NULL;
    sp_digit* tmpa = NULL;
    sp_digit* tmpb = NULL;
    sp_digit* r = NULL;
    sp_digit* qi = NULL;
    sp_digit* dq = NULL;
    sp_digit c;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 256) {
        err = MP_TO_E;
    }
    else if (inLen > 256 || mp_count_bits(mm) != 2048) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mm)) {
        err = MP_VAL;
    }
    else if (mp_iseven(pm)) {
        err = MP_VAL;
    }
    else if (mp_iseven(qm)) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        p = a + 32 * 2;
        q = p + 16;
        qi = dq = dp = q + 16;
        tmpa = qi + 16;
        tmpb = tmpa + 32;
        r = a;

        sp_2048_from_bin(a, 32, in, inLen);
        sp_2048_from_mp(p, 16, pm);
        sp_2048_from_mp(q, 16, qm);
        sp_2048_from_mp(dp, 16, dpm);

        err = sp_2048_mod_exp_16(tmpa, a, dp, 1024, p, 1);
    }
    if (err == MP_OKAY) {
        sp_2048_from_mp(dq, 16, dqm);
        err = sp_2048_mod_exp_16(tmpb, a, dq, 1024, q, 1);
    }

    if (err == MP_OKAY) {
        c = sp_2048_sub_in_place_16(tmpa, tmpb);
        c += sp_2048_cond_add_16(tmpa, tmpa, p, c);
        sp_2048_cond_add_16(tmpa, tmpa, p, c);

        sp_2048_from_mp(qi, 16, qim);
        sp_2048_mul_16(tmpa, tmpa, qi);
        err = sp_2048_mod_16(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_2048_mul_16(tmpa, q, tmpa);
        XMEMSET(&tmpb[16], 0, sizeof(sp_digit) * 16);
        sp_2048_add_32(r, tmpb, tmpa);

        sp_2048_to_bin_32(r, out);
        *outLen = 256;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 16 * 11);
    }
#endif /* SP_RSA_PRIVATE_EXP_D || RSA_LOW_MEM */
    return err;
}
#endif /* WOLFSSL_RSA_PUBLIC_ONLY */
#endif /* WOLFSSL_HAVE_SP_RSA */
#if defined(WOLFSSL_HAVE_SP_DH) || (defined(WOLFSSL_HAVE_SP_RSA) && \
                                              !defined(WOLFSSL_RSA_PUBLIC_ONLY))
/* Convert an array of sp_digit to an mp_int.
 *
 * a  A single precision integer.
 * r  A multi-precision integer.
 */
static int sp_2048_to_mp(const sp_digit* a, mp_int* r)
{
    int err;

    err = mp_grow(r, (2048 + DIGIT_BIT - 1) / DIGIT_BIT);
    if (err == MP_OKAY) { /*lint !e774 case where err is always MP_OKAY*/
#if DIGIT_BIT == 64
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 32);
        r->used = 32;
        mp_clamp(r);
#elif DIGIT_BIT < 64
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 32; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 64) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 64 - s;
        }
        r->used = (2048 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 32; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 64 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 64 - s;
            }
            else {
                s += 64;
            }
        }
        r->used = (2048 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#endif
    }

    return err;
}

/* Perform the modular exponentiation for Diffie-Hellman.
 *
 * base  Base. MP integer.
 * exp   Exponent. MP integer.
 * mod   Modulus. MP integer.
 * res   Result. MP integer.
 * returns 0 on success, MP_READ_E if there are too many bytes in an array
 * and MEMORY_E if memory allocation fails.
 */
int sp_ModExp_2048(const mp_int* base, const mp_int* exp, const mp_int* mod,
    mp_int* res)
{
    int err = MP_OKAY;
    sp_digit b[64];
    sp_digit e[32];
    sp_digit m[32];
    sp_digit* r = b;
    int expBits = mp_count_bits(exp);

    if (mp_count_bits(base) > 2048) {
        err = MP_READ_E;
    }
    else if (expBits > 2048) {
        err = MP_READ_E;
    }
    else if (mp_count_bits(mod) != 2048) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mod)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        sp_2048_from_mp(b, 32, base);
        sp_2048_from_mp(e, 32, exp);
        sp_2048_from_mp(m, 32, mod);

        err = sp_2048_mod_exp_32(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_2048_to_mp(r, res);
    }

    XMEMSET(e, 0, sizeof(e));

    return err;
}

#ifdef WOLFSSL_HAVE_SP_DH

static void sp_2048_lshift_32(sp_digit* r, const sp_digit* a, byte n)
{
    word64 n64 = n;
    __asm__ __volatile__ (
        "mov	x6, 63\n\t"
        "sub	x6, x6, %[n]\n\t"
        "ldr	x3, [%[a], 248]\n\t"
        "lsr	x4, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x4, x4, x6\n\t"
        "ldr	x2, [%[a], 240]\n\t"
        "str	x4, [%[r], 256]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 232]\n\t"
        "str	x3, [%[r], 248]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 224]\n\t"
        "str	x2, [%[r], 240]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 216]\n\t"
        "str	x4, [%[r], 232]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 208]\n\t"
        "str	x3, [%[r], 224]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 200]\n\t"
        "str	x2, [%[r], 216]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 192]\n\t"
        "str	x4, [%[r], 208]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 184]\n\t"
        "str	x3, [%[r], 200]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 176]\n\t"
        "str	x2, [%[r], 192]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 168]\n\t"
        "str	x4, [%[r], 184]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 160]\n\t"
        "str	x3, [%[r], 176]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 152]\n\t"
        "str	x2, [%[r], 168]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 144]\n\t"
        "str	x4, [%[r], 160]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 136]\n\t"
        "str	x3, [%[r], 152]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 128]\n\t"
        "str	x2, [%[r], 144]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 120]\n\t"
        "str	x4, [%[r], 136]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 112]\n\t"
        "str	x3, [%[r], 128]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 104]\n\t"
        "str	x2, [%[r], 120]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 96]\n\t"
        "str	x4, [%[r], 112]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 88]\n\t"
        "str	x3, [%[r], 104]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 80]\n\t"
        "str	x2, [%[r], 96]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 72]\n\t"
        "str	x4, [%[r], 88]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 64]\n\t"
        "str	x3, [%[r], 80]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 56]\n\t"
        "str	x2, [%[r], 72]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 48]\n\t"
        "str	x4, [%[r], 64]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 40]\n\t"
        "str	x3, [%[r], 56]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 32]\n\t"
        "str	x2, [%[r], 48]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 24]\n\t"
        "str	x4, [%[r], 40]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 16]\n\t"
        "str	x3, [%[r], 32]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 8]\n\t"
        "str	x2, [%[r], 24]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 0]\n\t"
        "str	x4, [%[r], 16]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "stp	x2, x3, [%[r]]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [n] "r" (n64)
        : "memory", "x2", "x3", "x4", "x5", "x6"
    );
}

/* Modular exponentiate 2 to the e mod m. (r = 2^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success.
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even.
 */
static int sp_2048_mod_exp_2_32(sp_digit* r, const sp_digit* e, int bits,
        const sp_digit* m)
{
    sp_digit td[97];
    sp_digit* norm = NULL;
    sp_digit* tmp = NULL;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit o;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        tmp = td + 64;

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_32(norm, m);

        i = (bits - 1) / 64;
        n = e[i--];
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        c -= bits % 6;
        if (c == 64) {
            c = 58;
        }
        if (c < 0) {
            /* Number of bits in top word is less than number needed. */
            c = -c;
            y = (byte)(n << c);
            n = e[i--];
            y |= (byte)(n >> (64 - c));
            n <<= c;
            c = 64 - c;
        }
        else if (c == 0) {
            /* All bits in top word used. */
            y = (byte)n;
        }
        else {
            y = (byte)(n >> c);
            n <<= 64 - c;
        }
        sp_2048_lshift_32(r, norm, y);
        for (; i>=0 || c>=6; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 58);
                n <<= 6;
                c = 58;
            }
            else if (c < 6) {
                y = (byte)(n >> 58);
                n = e[i--];
                c = 6 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }
            else {
                y = (byte)((n >> 58) & 0x3f);
                n <<= 6;
                c -= 6;
            }

            sp_2048_mont_sqr_32(r, r, m, mp);
            sp_2048_mont_sqr_32(r, r, m, mp);
            sp_2048_mont_sqr_32(r, r, m, mp);
            sp_2048_mont_sqr_32(r, r, m, mp);
            sp_2048_mont_sqr_32(r, r, m, mp);
            sp_2048_mont_sqr_32(r, r, m, mp);

            sp_2048_lshift_32(r, r, y);
            sp_2048_mul_d_32(tmp, norm, r[32]);
            r[32] = 0;
            o = sp_2048_add_32(r, r, tmp);
            sp_2048_cond_sub_32(r, r, m, (sp_digit)0 - o);
        }

        XMEMSET(&r[32], 0, sizeof(sp_digit) * 32U);
        sp_2048_mont_reduce_32(r, m, mp);

        mask = 0 - (sp_2048_cmp_32(r, m) >= 0);
        sp_2048_cond_sub_32(r, r, m, mask);
    }


    return err;
}

/* Perform the modular exponentiation for Diffie-Hellman.
 *
 * base     Base.
 * exp      Array of bytes that is the exponent.
 * expLen   Length of data, in bytes, in exponent.
 * mod      Modulus.
 * out      Buffer to hold big-endian bytes of exponentiation result.
 *          Must be at least 256 bytes long.
 * outLen   Length, in bytes, of exponentiation result.
 * returns 0 on success, MP_READ_E if there are too many bytes in an array
 * and MEMORY_E if memory allocation fails.
 */
int sp_DhExp_2048(const mp_int* base, const byte* exp, word32 expLen,
    const mp_int* mod, byte* out, word32* outLen)
{
    int err = MP_OKAY;
    sp_digit b[64];
    sp_digit e[32];
    sp_digit m[32];
    sp_digit* r = b;
    word32 i;

    if (mp_count_bits(base) > 2048) {
        err = MP_READ_E;
    }
    else if (expLen > 256) {
        err = MP_READ_E;
    }
    else if (mp_count_bits(mod) != 2048) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mod)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        sp_2048_from_mp(b, 32, base);
        sp_2048_from_bin(e, 32, exp, expLen);
        sp_2048_from_mp(m, 32, mod);

        if (base->used == 1 && base->dp[0] == 2 && m[31] == (sp_digit)-1)
            err = sp_2048_mod_exp_2_32(r, e, expLen * 8, m);
        else
            err = sp_2048_mod_exp_32(r, b, e, expLen * 8, m, 0);

    }

    if (err == MP_OKAY) {
        sp_2048_to_bin_32(r, out);
        *outLen = 256;
        for (i=0; i<256 && out[i] == 0; i++) {
            /* Search for first non-zero. */
        }
        *outLen -= i;
        XMEMMOVE(out, out + i, *outLen);

    }

    XMEMSET(e, 0, sizeof(e));

    return err;
}
#endif /* WOLFSSL_HAVE_SP_DH */

/* Perform the modular exponentiation for Diffie-Hellman.
 *
 * base  Base. MP integer.
 * exp   Exponent. MP integer.
 * mod   Modulus. MP integer.
 * res   Result. MP integer.
 * returns 0 on success, MP_READ_E if there are too many bytes in an array
 * and MEMORY_E if memory allocation fails.
 */
int sp_ModExp_1024(const mp_int* base, const mp_int* exp, const mp_int* mod,
    mp_int* res)
{
    int err = MP_OKAY;
    sp_digit b[32];
    sp_digit e[16];
    sp_digit m[16];
    sp_digit* r = b;
    int expBits = mp_count_bits(exp);

    if (mp_count_bits(base) > 1024) {
        err = MP_READ_E;
    }
    else if (expBits > 1024) {
        err = MP_READ_E;
    }
    else if (mp_count_bits(mod) != 1024) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mod)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        sp_2048_from_mp(b, 16, base);
        sp_2048_from_mp(e, 16, exp);
        sp_2048_from_mp(m, 16, mod);

        err = sp_2048_mod_exp_16(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 16, 0, sizeof(*r) * 16U);
        err = sp_2048_to_mp(r, res);
        res->used = mod->used;
        mp_clamp(res);
    }

    XMEMSET(e, 0, sizeof(e));

    return err;
}

#endif /* WOLFSSL_HAVE_SP_DH | (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) */

#endif /* !WOLFSSL_SP_NO_2048 */

#ifndef WOLFSSL_SP_NO_3072
/* Read big endian unsigned byte array into r.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  Byte array.
 * n  Number of bytes in array to read.
 */
static void sp_3072_from_bin(sp_digit* r, int size, const byte* a, int n)
{
    sp_int64 nl = n;
    sp_int64 size8 = size * 8;

    __asm__ __volatile__ (
        "add	x4, %[a], %[n]\n\t"
        "mov	x5, %[r]\n\t"
        "sub	x4, x4, 8\n\t"
        "subs	x6, %[n], 8\n\t"
        "mov	x7, xzr\n\t"
        "blt	2f\n\t"
        /* Put in mulitples of 8 bytes. */
        "1:\n\t"
        "ldr	x8, [x4], -8\n\t"
        "subs	x6, x6, 8\n\t"
        "rev	x8, x8\n\t"
        "str	x8, [x5], 8\n\t"
        "add	x7, x7, 8\n\t"
        "b.ge	1b\n\t"
        "2:\n\t"
        "cmp	x6, -7\n\t"
        "b.lt	20f\n\t"
        /* Put in less than 8 bytes. */
        "str	xzr, [x5]\n\t"
        "add	x7, x7, 8\n\t"
        "add	x4, x4, 7\n\t"
        "b.eq	17f\n\t"
        "cmp	x6, -5\n\t"
        "b.lt	16f\n\t"
        "b.eq	15f\n\t"
        "cmp	x6, -3\n\t"
        "b.lt	14f\n\t"
        "b.eq	13f\n\t"
        "cmp	x6, -2\n\t"
        "b.eq	12f\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "12:\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "13:\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "14:\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "15:\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "16:\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "17:\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "20:\n\t"
        "add	x5, %[r], x7\n\t"
        "subs	x7, %[size], x7\n\t"
        "b.eq	30f\n\t"
        /* Zero out remaining words. */
        "21:\n\t"
        "subs	x7, x7, 8\n\t"
        "str	xzr, [x5], 8\n\t"
        "b.gt	21b\n\t"
        "30:\n\t"
        :
        : [r] "r" (r), [size] "r" (size8), [a] "r" (a), [n] "r" (nl)
        : "memory", "x4", "x5", "x6", "x7", "x8"
    );
}

/* Convert an mp_int to an array of sp_digit.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  A multi-precision integer.
 */
static void sp_3072_from_mp(sp_digit* r, int size, const mp_int* a)
{
#if DIGIT_BIT == 64
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 64
    int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0xffffffffffffffffl;
        s = 64U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 64U) <= (word32)DIGIT_BIT) {
            s += 64U;
            r[j] &= 0xffffffffffffffffl;
            if (j + 1 >= size) {
                break;
            }
            if (s < (word32)DIGIT_BIT) {
                /* lint allow cast of mismatch word32 and mp_digit */
                r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
            }
            else {
                r[++j] = (sp_digit)0;
            }
        }
        s = (word32)DIGIT_BIT - s;
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
#else
    int i;
    int j = 0;
    int s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i]) << s;
        if (s + DIGIT_BIT >= 64) {
            r[j] &= 0xffffffffffffffffl;
            if (j + 1 >= size) {
                break;
            }
            s = 64 - s;
            if (s == DIGIT_BIT) {
                r[++j] = 0;
                s = 0;
            }
            else {
                r[++j] = a->dp[i] >> s;
                s = DIGIT_BIT - s;
            }
        }
        else {
            s += DIGIT_BIT;
        }
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
#endif
}

/* Write r as big endian to byte array.
 * Fixed length number of bytes written: 384
 *
 * r  A single precision integer.
 * a  Byte array.
 */
static void sp_3072_to_bin_48(sp_digit* r, byte* a)
{
    int i;
    int j = 0;

    for (i = 47; i >= 0; i--, j += 8) {
        __asm__ __volatile__ (
            "ldr	x4, [%[r]]\n\t"
            "rev	x4, x4\n\t"
            "str	x4, [%[a]]\n\t"
            :
            : [r] "r" (r + i), [a] "r" (a + j)
            : "memory", "x4"
        );
    }
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && (!defined(WOLFSSL_RSA_PUBLIC_ONLY) || !defined(WOLFSSL_SP_SMALL))) || defined(WOLFSSL_HAVE_SP_DH)
/* Normalize the values in each word to 64.
 *
 * a  Array of sp_digit to normalize.
 */
#define sp_3072_norm_48(a)

#endif /* (WOLFSSL_HAVE_SP_RSA && (!WOLFSSL_RSA_PUBLIC_ONLY || !WOLFSSL_SP_SMALL)) || WOLFSSL_HAVE_SP_DH */
/* Normalize the values in each word to 64.
 *
 * a  Array of sp_digit to normalize.
 */
#define sp_3072_norm_48(a)

#ifndef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static void sp_3072_mul_6(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x8, x9, [%[a], 0]\n\t"
        "ldp	x10, x11, [%[a], 16]\n\t"
        "ldp	x12, x13, [%[a], 32]\n\t"
        "ldp	x14, x15, [%[b], 0]\n\t"
        "ldp	x16, x17, [%[b], 16]\n\t"
        "ldp	x19, x20, [%[b], 32]\n\t"
        "#  A[0] * B[0]\n\t"
        "mul	x3, x8, x14\n\t"
        "umulh	x4, x8, x14\n\t"
        "str	x3, [%[r]]\n\t"
        "#  A[0] * B[1]\n\t"
        "mul	x6, x8, x15\n\t"
        "umulh	x7, x8, x15\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[1] * B[0]\n\t"
        "mul	x6, x9, x14\n\t"
        "adc	x5, xzr, x7\n\t"
        "umulh	x7, x9, x14\n\t"
        "adds	x4, x4, x6\n\t"
        "adcs	x5, x5, x7\n\t"
        "str	x4, [%[r], 8]\n\t"
        "adc	x3, xzr, xzr\n\t"
        "#  A[0] * B[2]\n\t"
        "mul	x6, x8, x16\n\t"
        "umulh	x7, x8, x16\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[1] * B[1]\n\t"
        "mul	x6, x9, x15\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x9, x15\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[2] * B[0]\n\t"
        "mul	x6, x10, x14\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x10, x14\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "adcs	x3, x3, x7\n\t"
        "str	x5, [%[r], 16]\n\t"
        "adc	x4, x4, xzr\n\t"
        "#  A[0] * B[3]\n\t"
        "mul	x6, x8, x17\n\t"
        "umulh	x7, x8, x17\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[1] * B[2]\n\t"
        "mul	x6, x9, x16\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x9, x16\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[2] * B[1]\n\t"
        "mul	x6, x10, x15\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x10, x15\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[3] * B[0]\n\t"
        "mul	x6, x11, x14\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x11, x14\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "adcs	x4, x4, x7\n\t"
        "str	x3, [%[r], 24]\n\t"
        "adc	x5, x5, xzr\n\t"
        "#  A[0] * B[4]\n\t"
        "mul	x6, x8, x19\n\t"
        "umulh	x7, x8, x19\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[1] * B[3]\n\t"
        "mul	x6, x9, x17\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x9, x17\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[2] * B[2]\n\t"
        "mul	x6, x10, x16\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x10, x16\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[3] * B[1]\n\t"
        "mul	x6, x11, x15\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x11, x15\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[4] * B[0]\n\t"
        "mul	x6, x12, x14\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x12, x14\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "adcs	x5, x5, x7\n\t"
        "str	x4, [%[r], 32]\n\t"
        "adc	x3, x3, xzr\n\t"
        "#  A[0] * B[5]\n\t"
        "mul	x6, x8, x20\n\t"
        "umulh	x7, x8, x20\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[1] * B[4]\n\t"
        "mul	x6, x9, x19\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x9, x19\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[2] * B[3]\n\t"
        "mul	x6, x10, x17\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x10, x17\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[3] * B[2]\n\t"
        "mul	x6, x11, x16\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x11, x16\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[4] * B[1]\n\t"
        "mul	x6, x12, x15\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x12, x15\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[5] * B[0]\n\t"
        "mul	x6, x13, x14\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x13, x14\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "adcs	x3, x3, x7\n\t"
        "str	x5, [%[r], 40]\n\t"
        "adc	x4, x4, xzr\n\t"
        "#  A[1] * B[5]\n\t"
        "mul	x6, x9, x20\n\t"
        "umulh	x7, x9, x20\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[2] * B[4]\n\t"
        "mul	x6, x10, x19\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x10, x19\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[3] * B[3]\n\t"
        "mul	x6, x11, x17\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x11, x17\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[4] * B[2]\n\t"
        "mul	x6, x12, x16\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x12, x16\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[5] * B[1]\n\t"
        "mul	x6, x13, x15\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x13, x15\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "adcs	x4, x4, x7\n\t"
        "str	x3, [%[r], 48]\n\t"
        "adc	x5, x5, xzr\n\t"
        "#  A[2] * B[5]\n\t"
        "mul	x6, x10, x20\n\t"
        "umulh	x7, x10, x20\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[3] * B[4]\n\t"
        "mul	x6, x11, x19\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x11, x19\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[4] * B[3]\n\t"
        "mul	x6, x12, x17\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x12, x17\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "#  A[5] * B[2]\n\t"
        "mul	x6, x13, x16\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, x13, x16\n\t"
        "adc	x3, x3, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "adcs	x5, x5, x7\n\t"
        "str	x4, [%[r], 56]\n\t"
        "adc	x3, x3, xzr\n\t"
        "#  A[3] * B[5]\n\t"
        "mul	x6, x11, x20\n\t"
        "umulh	x7, x11, x20\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[4] * B[4]\n\t"
        "mul	x6, x12, x19\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x12, x19\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "#  A[5] * B[3]\n\t"
        "mul	x6, x13, x17\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, x13, x17\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "adcs	x3, x3, x7\n\t"
        "str	x5, [%[r], 64]\n\t"
        "adc	x4, x4, xzr\n\t"
        "#  A[4] * B[5]\n\t"
        "mul	x6, x12, x20\n\t"
        "umulh	x7, x12, x20\n\t"
        "adds	x3, x3, x6\n\t"
        "#  A[5] * B[4]\n\t"
        "mul	x6, x13, x19\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, x13, x19\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "adcs	x4, x4, x7\n\t"
        "str	x3, [%[r], 72]\n\t"
        "adc	x5, x5, xzr\n\t"
        "#  A[5] * B[5]\n\t"
        "mul	x6, x13, x20\n\t"
        "umulh	x7, x13, x20\n\t"
        "adds	x4, x4, x6\n\t"
        "adc	x5, x5, x7\n\t"
        "stp	x4, x5, [%[r], 80]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20"
    );
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_3072_add_6(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x7, x8, [%[b], 0]\n\t"
        "adds	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 16]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldr	x3, [%[a], 32]\n\t"
        "ldr	x4, [%[a], 40]\n\t"
        "ldr	x7, [%[b], 32]\n\t"
        "ldr	x8, [%[b], 40]\n\t"
        "adcs	x3, x3, x7\n\t"
        "adcs	x4, x4, x8\n\t"
        "str	x3, [%[r], 32]\n\t"
        "str	x4, [%[r], 40]\n\t"
        "cset	%[r], cs\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return (sp_digit)r;
}

/* Add digit to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static void sp_3072_add_word_6(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "adds	x3, x3, %[b]\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldr		x3, [%[a], 32]\n\t"
        "ldr		x4, [%[a], 40]\n\t"
        "adcs	x3, x3, xzr\n\t"
        "adcs	x4, x4, xzr\n\t"
        "str		x3, [%[r], 32]\n\t"
        "str		x4, [%[r], 40]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6"
    );
}

/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer and result.
 * b  A single precision integer.
 */
static sp_digit sp_3072_sub_in_place_12(sp_digit* a, const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x2, x3, [%[a], 0]\n\t"
        "ldp	x6, x7, [%[b], 0]\n\t"
        "subs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 16]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 16]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 0]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 16]\n\t"
        "ldp	x2, x3, [%[a], 32]\n\t"
        "ldp	x6, x7, [%[b], 32]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 48]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 48]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 32]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 48]\n\t"
        "ldp	x2, x3, [%[a], 64]\n\t"
        "ldp	x6, x7, [%[b], 64]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 80]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 80]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 64]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 80]\n\t"
        "csetm	%[a], cc\n\t"
        : [a] "+r" (a)
        : [b] "r" (b)
        : "memory", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );

    return (sp_digit)a;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_3072_add_12(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x7, x8, [%[b], 0]\n\t"
        "adds	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 16]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldp	x3, x4, [%[a], 32]\n\t"
        "ldp	x7, x8, [%[b], 32]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 48]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 48]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 32]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 48]\n\t"
        "ldp	x3, x4, [%[a], 64]\n\t"
        "ldp	x7, x8, [%[b], 64]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 80]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 80]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 64]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 80]\n\t"
        "cset	%[r], cs\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return (sp_digit)r;
}

#ifndef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static sp_digit sp_3072_cond_add_6(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    __asm__ __volatile__ (

        "ldp	x8, x9, [%[b], 0]\n\t"
        "ldp	x10, x11, [%[b], 16]\n\t"
        "ldp	x4, x5, [%[a], 0]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 16]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adds	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 0]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 16]\n\t"
        "ldp	x8, x9, [%[b], 32]\n\t"
        "ldp	x4, x5, [%[a], 32]\n\t"
        "and	x8, x8, %[m]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adcs	x4, x4, x8\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[r], 32]\n\t"
        "cset	%[r], cs\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    return (sp_digit)r;
}
#endif /* !WOLFSSL_SP_SMALL */

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_12(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[12];
    sp_digit a1[6];
    sp_digit b1[6];
    sp_digit* z2 = r + 12;
    sp_digit u;
    sp_digit ca;
    sp_digit cb;

    ca = sp_3072_add_6(a1, a, &a[6]);
    cb = sp_3072_add_6(b1, b, &b[6]);
    u  = ca & cb;

    sp_3072_mul_6(z2, &a[6], &b[6]);
    sp_3072_mul_6(z0, a, b);
    sp_3072_mul_6(z1, a1, b1);

    u += sp_3072_sub_in_place_12(z1, z0);
    u += sp_3072_sub_in_place_12(z1, z2);
    u += sp_3072_cond_add_6(z1 + 6, z1 + 6, a1, 0 - cb);
    u += sp_3072_cond_add_6(z1 + 6, z1 + 6, b1, 0 - ca);

    u += sp_3072_add_12(r + 6, r + 6, z1);
    (void)sp_3072_add_word_6(r + 18, r + 18, u);
}

/* Add digit to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static void sp_3072_add_word_12(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "adds	x3, x3, %[b]\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldp	x3, x4, [%[a], 32]\n\t"
        "ldp	x5, x6, [%[a], 48]\n\t"
        "adcs	x3, x3, xzr\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 32]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 48]\n\t"
        "ldp	x3, x4, [%[a], 64]\n\t"
        "ldp	x5, x6, [%[a], 80]\n\t"
        "adcs	x3, x3, xzr\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 64]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 80]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6"
    );
}

/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer and result.
 * b  A single precision integer.
 */
static sp_digit sp_3072_sub_in_place_24(sp_digit* a, const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x2, x3, [%[a], 0]\n\t"
        "ldp	x6, x7, [%[b], 0]\n\t"
        "subs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 16]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 16]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 0]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 16]\n\t"
        "ldp	x2, x3, [%[a], 32]\n\t"
        "ldp	x6, x7, [%[b], 32]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 48]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 48]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 32]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 48]\n\t"
        "ldp	x2, x3, [%[a], 64]\n\t"
        "ldp	x6, x7, [%[b], 64]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 80]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 80]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 64]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 80]\n\t"
        "ldp	x2, x3, [%[a], 96]\n\t"
        "ldp	x6, x7, [%[b], 96]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 112]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 112]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 96]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 112]\n\t"
        "ldp	x2, x3, [%[a], 128]\n\t"
        "ldp	x6, x7, [%[b], 128]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 144]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 144]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 128]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 144]\n\t"
        "ldp	x2, x3, [%[a], 160]\n\t"
        "ldp	x6, x7, [%[b], 160]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 176]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 176]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 160]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 176]\n\t"
        "csetm	%[a], cc\n\t"
        : [a] "+r" (a)
        : [b] "r" (b)
        : "memory", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );

    return (sp_digit)a;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_3072_add_24(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x7, x8, [%[b], 0]\n\t"
        "adds	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 16]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldp	x3, x4, [%[a], 32]\n\t"
        "ldp	x7, x8, [%[b], 32]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 48]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 48]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 32]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 48]\n\t"
        "ldp	x3, x4, [%[a], 64]\n\t"
        "ldp	x7, x8, [%[b], 64]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 80]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 80]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 64]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 80]\n\t"
        "ldp	x3, x4, [%[a], 96]\n\t"
        "ldp	x7, x8, [%[b], 96]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 112]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 112]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 96]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 112]\n\t"
        "ldp	x3, x4, [%[a], 128]\n\t"
        "ldp	x7, x8, [%[b], 128]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 144]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 144]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 128]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 144]\n\t"
        "ldp	x3, x4, [%[a], 160]\n\t"
        "ldp	x7, x8, [%[b], 160]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 176]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 176]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 160]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 176]\n\t"
        "cset	%[r], cs\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return (sp_digit)r;
}

#ifndef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static sp_digit sp_3072_cond_add_12(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    __asm__ __volatile__ (

        "ldp	x8, x9, [%[b], 0]\n\t"
        "ldp	x10, x11, [%[b], 16]\n\t"
        "ldp	x4, x5, [%[a], 0]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 16]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adds	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 0]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 16]\n\t"
        "ldp	x8, x9, [%[b], 32]\n\t"
        "ldp	x10, x11, [%[b], 48]\n\t"
        "ldp	x4, x5, [%[a], 32]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 48]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adcs	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 32]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 48]\n\t"
        "ldp	x8, x9, [%[b], 64]\n\t"
        "ldp	x10, x11, [%[b], 80]\n\t"
        "ldp	x4, x5, [%[a], 64]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 80]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adcs	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 64]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 80]\n\t"
        "cset	%[r], cs\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    return (sp_digit)r;
}
#endif /* !WOLFSSL_SP_SMALL */

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_24(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[24];
    sp_digit a1[12];
    sp_digit b1[12];
    sp_digit* z2 = r + 24;
    sp_digit u;
    sp_digit ca;
    sp_digit cb;

    ca = sp_3072_add_12(a1, a, &a[12]);
    cb = sp_3072_add_12(b1, b, &b[12]);
    u  = ca & cb;

    sp_3072_mul_12(z2, &a[12], &b[12]);
    sp_3072_mul_12(z0, a, b);
    sp_3072_mul_12(z1, a1, b1);

    u += sp_3072_sub_in_place_24(z1, z0);
    u += sp_3072_sub_in_place_24(z1, z2);
    u += sp_3072_cond_add_12(z1 + 12, z1 + 12, a1, 0 - cb);
    u += sp_3072_cond_add_12(z1 + 12, z1 + 12, b1, 0 - ca);

    u += sp_3072_add_24(r + 12, r + 12, z1);
    (void)sp_3072_add_word_12(r + 36, r + 36, u);
}

/* Add digit to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static void sp_3072_add_word_24(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "adds	x3, x3, %[b]\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldp	x3, x4, [%[a], 32]\n\t"
        "ldp	x5, x6, [%[a], 48]\n\t"
        "adcs	x3, x3, xzr\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 32]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 48]\n\t"
        "ldp	x3, x4, [%[a], 64]\n\t"
        "ldp	x5, x6, [%[a], 80]\n\t"
        "adcs	x3, x3, xzr\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 64]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 80]\n\t"
        "ldp	x3, x4, [%[a], 96]\n\t"
        "ldp	x5, x6, [%[a], 112]\n\t"
        "adcs	x3, x3, xzr\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 96]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 112]\n\t"
        "ldp	x3, x4, [%[a], 128]\n\t"
        "ldp	x5, x6, [%[a], 144]\n\t"
        "adcs	x3, x3, xzr\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 128]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 144]\n\t"
        "ldp	x3, x4, [%[a], 160]\n\t"
        "ldp	x5, x6, [%[a], 176]\n\t"
        "adcs	x3, x3, xzr\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 160]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 176]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6"
    );
}

/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer and result.
 * b  A single precision integer.
 */
static sp_digit sp_3072_sub_in_place_48(sp_digit* a, const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x2, x3, [%[a], 0]\n\t"
        "ldp	x6, x7, [%[b], 0]\n\t"
        "subs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 16]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 16]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 0]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 16]\n\t"
        "ldp	x2, x3, [%[a], 32]\n\t"
        "ldp	x6, x7, [%[b], 32]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 48]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 48]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 32]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 48]\n\t"
        "ldp	x2, x3, [%[a], 64]\n\t"
        "ldp	x6, x7, [%[b], 64]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 80]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 80]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 64]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 80]\n\t"
        "ldp	x2, x3, [%[a], 96]\n\t"
        "ldp	x6, x7, [%[b], 96]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 112]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 112]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 96]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 112]\n\t"
        "ldp	x2, x3, [%[a], 128]\n\t"
        "ldp	x6, x7, [%[b], 128]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 144]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 144]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 128]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 144]\n\t"
        "ldp	x2, x3, [%[a], 160]\n\t"
        "ldp	x6, x7, [%[b], 160]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 176]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 176]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 160]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 176]\n\t"
        "ldp	x2, x3, [%[a], 192]\n\t"
        "ldp	x6, x7, [%[b], 192]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 208]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 208]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 192]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 208]\n\t"
        "ldp	x2, x3, [%[a], 224]\n\t"
        "ldp	x6, x7, [%[b], 224]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 240]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 240]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 224]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 240]\n\t"
        "ldp	x2, x3, [%[a], 256]\n\t"
        "ldp	x6, x7, [%[b], 256]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 272]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 272]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 256]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 272]\n\t"
        "ldp	x2, x3, [%[a], 288]\n\t"
        "ldp	x6, x7, [%[b], 288]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 304]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 304]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 288]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 304]\n\t"
        "ldp	x2, x3, [%[a], 320]\n\t"
        "ldp	x6, x7, [%[b], 320]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 336]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 336]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 320]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 336]\n\t"
        "ldp	x2, x3, [%[a], 352]\n\t"
        "ldp	x6, x7, [%[b], 352]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 368]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 368]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 352]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 368]\n\t"
        "csetm	%[a], cc\n\t"
        : [a] "+r" (a)
        : [b] "r" (b)
        : "memory", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );

    return (sp_digit)a;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_3072_add_48(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x7, x8, [%[b], 0]\n\t"
        "adds	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 16]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldp	x3, x4, [%[a], 32]\n\t"
        "ldp	x7, x8, [%[b], 32]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 48]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 48]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 32]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 48]\n\t"
        "ldp	x3, x4, [%[a], 64]\n\t"
        "ldp	x7, x8, [%[b], 64]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 80]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 80]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 64]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 80]\n\t"
        "ldp	x3, x4, [%[a], 96]\n\t"
        "ldp	x7, x8, [%[b], 96]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 112]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 112]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 96]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 112]\n\t"
        "ldp	x3, x4, [%[a], 128]\n\t"
        "ldp	x7, x8, [%[b], 128]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 144]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 144]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 128]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 144]\n\t"
        "ldp	x3, x4, [%[a], 160]\n\t"
        "ldp	x7, x8, [%[b], 160]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 176]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 176]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 160]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 176]\n\t"
        "ldp	x3, x4, [%[a], 192]\n\t"
        "ldp	x7, x8, [%[b], 192]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 208]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 208]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 192]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 208]\n\t"
        "ldp	x3, x4, [%[a], 224]\n\t"
        "ldp	x7, x8, [%[b], 224]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 240]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 240]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 224]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 240]\n\t"
        "ldp	x3, x4, [%[a], 256]\n\t"
        "ldp	x7, x8, [%[b], 256]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 272]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 272]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 256]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 272]\n\t"
        "ldp	x3, x4, [%[a], 288]\n\t"
        "ldp	x7, x8, [%[b], 288]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 304]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 304]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 288]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 304]\n\t"
        "ldp	x3, x4, [%[a], 320]\n\t"
        "ldp	x7, x8, [%[b], 320]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 336]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 336]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 320]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 336]\n\t"
        "ldp	x3, x4, [%[a], 352]\n\t"
        "ldp	x7, x8, [%[b], 352]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 368]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 368]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 352]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 368]\n\t"
        "cset	%[r], cs\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return (sp_digit)r;
}

#ifndef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static sp_digit sp_3072_cond_add_24(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    __asm__ __volatile__ (

        "ldp	x8, x9, [%[b], 0]\n\t"
        "ldp	x10, x11, [%[b], 16]\n\t"
        "ldp	x4, x5, [%[a], 0]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 16]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adds	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 0]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 16]\n\t"
        "ldp	x8, x9, [%[b], 32]\n\t"
        "ldp	x10, x11, [%[b], 48]\n\t"
        "ldp	x4, x5, [%[a], 32]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 48]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adcs	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 32]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 48]\n\t"
        "ldp	x8, x9, [%[b], 64]\n\t"
        "ldp	x10, x11, [%[b], 80]\n\t"
        "ldp	x4, x5, [%[a], 64]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 80]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adcs	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 64]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 80]\n\t"
        "ldp	x8, x9, [%[b], 96]\n\t"
        "ldp	x10, x11, [%[b], 112]\n\t"
        "ldp	x4, x5, [%[a], 96]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 112]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adcs	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 96]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 112]\n\t"
        "ldp	x8, x9, [%[b], 128]\n\t"
        "ldp	x10, x11, [%[b], 144]\n\t"
        "ldp	x4, x5, [%[a], 128]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 144]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adcs	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 128]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 144]\n\t"
        "ldp	x8, x9, [%[b], 160]\n\t"
        "ldp	x10, x11, [%[b], 176]\n\t"
        "ldp	x4, x5, [%[a], 160]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 176]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adcs	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 160]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 176]\n\t"
        "cset	%[r], cs\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    return (sp_digit)r;
}
#endif /* !WOLFSSL_SP_SMALL */

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_48(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[48];
    sp_digit a1[24];
    sp_digit b1[24];
    sp_digit* z2 = r + 48;
    sp_digit u;
    sp_digit ca;
    sp_digit cb;

    ca = sp_3072_add_24(a1, a, &a[24]);
    cb = sp_3072_add_24(b1, b, &b[24]);
    u  = ca & cb;

    sp_3072_mul_24(z2, &a[24], &b[24]);
    sp_3072_mul_24(z0, a, b);
    sp_3072_mul_24(z1, a1, b1);

    u += sp_3072_sub_in_place_48(z1, z0);
    u += sp_3072_sub_in_place_48(z1, z2);
    u += sp_3072_cond_add_24(z1 + 24, z1 + 24, a1, 0 - cb);
    u += sp_3072_cond_add_24(z1 + 24, z1 + 24, b1, 0 - ca);

    u += sp_3072_add_48(r + 24, r + 24, z1);
    (void)sp_3072_add_word_24(r + 72, r + 72, u);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
static void sp_3072_sqr_24(sp_digit* r, const sp_digit* a)
{
    sp_digit tmp[24];

    __asm__ __volatile__ (
        "#  A[0] * A[0]\n\t"
        "ldr	x9, [%[a], 0]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x3, x9, x9\n\t"
        "mov	x4, xzr\n\t"
        "str	x8, [%[tmp]]\n\t"
        "#  A[0] * A[1]\n\t"
        "ldr	x9, [%[a], 8]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x3, x3, x8\n\t"
        "adcs	x4, x4, x9\n\t"
        "adc	x2, xzr, xzr\n\t"
        "adds	x3, x3, x8\n\t"
        "adcs	x4, x4, x9\n\t"
        "adc	x2, x2, xzr\n\t"
        "str	x3, [%[tmp], 8]\n\t"
        "#  A[0] * A[2]\n\t"
        "ldr	x9, [%[a], 16]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x4, x4, x8\n\t"
        "adcs	x2, x2, x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x4, x4, x8\n\t"
        "adcs	x2, x2, x9\n\t"
        "adc	x3, x3, xzr\n\t"
        "#  A[1] * A[1]\n\t"
        "ldr	x9, [%[a], 8]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x4, x4, x8\n\t"
        "adcs	x2, x2, x9\n\t"
        "adc	x3, x3, xzr\n\t"
        "str	x4, [%[tmp], 16]\n\t"
        "#  A[0] * A[3]\n\t"
        "ldr	x9, [%[a], 24]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x2, x2, x8\n\t"
        "adcs	x3, x3, x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x2, x2, x8\n\t"
        "adcs	x3, x3, x9\n\t"
        "adc	x4, x4, xzr\n\t"
        "#  A[1] * A[2]\n\t"
        "ldr	x9, [%[a], 16]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x2, x2, x8\n\t"
        "adcs	x3, x3, x9\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x2, x2, x8\n\t"
        "adcs	x3, x3, x9\n\t"
        "adc	x4, x4, xzr\n\t"
        "str	x2, [%[tmp], 24]\n\t"
        "#  A[0] * A[4]\n\t"
        "ldr	x9, [%[a], 32]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x3, x3, x8\n\t"
        "adcs	x4, x4, x9\n\t"
        "adc	x2, xzr, xzr\n\t"
        "adds	x3, x3, x8\n\t"
        "adcs	x4, x4, x9\n\t"
        "adc	x2, x2, xzr\n\t"
        "#  A[1] * A[3]\n\t"
        "ldr	x9, [%[a], 24]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x3, x3, x8\n\t"
        "adcs	x4, x4, x9\n\t"
        "adc	x2, x2, xzr\n\t"
        "adds	x3, x3, x8\n\t"
        "adcs	x4, x4, x9\n\t"
        "adc	x2, x2, xzr\n\t"
        "#  A[2] * A[2]\n\t"
        "ldr	x9, [%[a], 16]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x3, x3, x8\n\t"
        "adcs	x4, x4, x9\n\t"
        "adc	x2, x2, xzr\n\t"
        "str	x3, [%[tmp], 32]\n\t"
        "#  A[0] * A[5]\n\t"
        "ldr	x9, [%[a], 40]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x3, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[4]\n\t"
        "ldr	x9, [%[a], 32]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[2] * A[3]\n\t"
        "ldr	x9, [%[a], 24]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x4, x4, x5\n\t"
        "adcs	x2, x2, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x4, [%[tmp], 40]\n\t"
        "#  A[0] * A[6]\n\t"
        "ldr	x9, [%[a], 48]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x4, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[5]\n\t"
        "ldr	x9, [%[a], 40]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[2] * A[4]\n\t"
        "ldr	x9, [%[a], 32]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[3] * A[3]\n\t"
        "ldr	x9, [%[a], 24]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x2, x2, x5\n\t"
        "adcs	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "str	x2, [%[tmp], 48]\n\t"
        "#  A[0] * A[7]\n\t"
        "ldr	x9, [%[a], 56]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x2, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[6]\n\t"
        "ldr	x9, [%[a], 48]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[2] * A[5]\n\t"
        "ldr	x9, [%[a], 40]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[3] * A[4]\n\t"
        "ldr	x9, [%[a], 32]\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x3, x3, x5\n\t"
        "adcs	x4, x4, x6\n\t"
        "adc	x2, x2, x7\n\t"
        "str	x3, [%[tmp], 56]\n\t"
        "#  A[0] * A[8]\n\t"
        "ldr	x9, [%[a], 64]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x3, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[7]\n\t"
        "ldr	x9, [%[a], 56]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[2] * A[6]\n\t"
        "ldr	x9, [%[a], 48]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[3] * A[5]\n\t"
        "ldr	x9, [%[a], 40]\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[4] * A[4]\n\t"
        "ldr	x9, [%[a], 32]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x4, x4, x5\n\t"
        "adcs	x2, x2, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x4, [%[tmp], 64]\n\t"
        "#  A[0] * A[9]\n\t"
        "ldr	x9, [%[a], 72]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x4, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[8]\n\t"
        "ldr	x9, [%[a], 64]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[2] * A[7]\n\t"
        "ldr	x9, [%[a], 56]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[3] * A[6]\n\t"
        "ldr	x9, [%[a], 48]\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[4] * A[5]\n\t"
        "ldr	x9, [%[a], 40]\n\t"
        "ldr	x10, [%[a], 32]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x2, x2, x5\n\t"
        "adcs	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "str	x2, [%[tmp], 72]\n\t"
        "#  A[0] * A[10]\n\t"
        "ldr	x9, [%[a], 80]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x2, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[9]\n\t"
        "ldr	x9, [%[a], 72]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[2] * A[8]\n\t"
        "ldr	x9, [%[a], 64]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[3] * A[7]\n\t"
        "ldr	x9, [%[a], 56]\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[4] * A[6]\n\t"
        "ldr	x9, [%[a], 48]\n\t"
        "ldr	x10, [%[a], 32]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[5] * A[5]\n\t"
        "ldr	x9, [%[a], 40]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x3, x3, x5\n\t"
        "adcs	x4, x4, x6\n\t"
        "adc	x2, x2, x7\n\t"
        "str	x3, [%[tmp], 80]\n\t"
        "#  A[0] * A[11]\n\t"
        "ldr	x9, [%[a], 88]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x3, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[10]\n\t"
        "ldr	x9, [%[a], 80]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[2] * A[9]\n\t"
        "ldr	x9, [%[a], 72]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[3] * A[8]\n\t"
        "ldr	x9, [%[a], 64]\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[4] * A[7]\n\t"
        "ldr	x9, [%[a], 56]\n\t"
        "ldr	x10, [%[a], 32]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[5] * A[6]\n\t"
        "ldr	x9, [%[a], 48]\n\t"
        "ldr	x10, [%[a], 40]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x4, x4, x5\n\t"
        "adcs	x2, x2, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x4, [%[tmp], 88]\n\t"
        "#  A[0] * A[12]\n\t"
        "ldr	x9, [%[a], 96]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x4, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[11]\n\t"
        "ldr	x9, [%[a], 88]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[2] * A[10]\n\t"
        "ldr	x9, [%[a], 80]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[3] * A[9]\n\t"
        "ldr	x9, [%[a], 72]\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[4] * A[8]\n\t"
        "ldr	x9, [%[a], 64]\n\t"
        "ldr	x10, [%[a], 32]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[5] * A[7]\n\t"
        "ldr	x9, [%[a], 56]\n\t"
        "ldr	x10, [%[a], 40]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[6] * A[6]\n\t"
        "ldr	x9, [%[a], 48]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x2, x2, x5\n\t"
        "adcs	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "str	x2, [%[tmp], 96]\n\t"
        "#  A[0] * A[13]\n\t"
        "ldr	x9, [%[a], 104]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x2, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[12]\n\t"
        "ldr	x9, [%[a], 96]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[2] * A[11]\n\t"
        "ldr	x9, [%[a], 88]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[3] * A[10]\n\t"
        "ldr	x9, [%[a], 80]\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[4] * A[9]\n\t"
        "ldr	x9, [%[a], 72]\n\t"
        "ldr	x10, [%[a], 32]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[5] * A[8]\n\t"
        "ldr	x9, [%[a], 64]\n\t"
        "ldr	x10, [%[a], 40]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[6] * A[7]\n\t"
        "ldr	x9, [%[a], 56]\n\t"
        "ldr	x10, [%[a], 48]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x3, x3, x5\n\t"
        "adcs	x4, x4, x6\n\t"
        "adc	x2, x2, x7\n\t"
        "str	x3, [%[tmp], 104]\n\t"
        "#  A[0] * A[14]\n\t"
        "ldr	x9, [%[a], 112]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x3, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[13]\n\t"
        "ldr	x9, [%[a], 104]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[2] * A[12]\n\t"
        "ldr	x9, [%[a], 96]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[3] * A[11]\n\t"
        "ldr	x9, [%[a], 88]\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[4] * A[10]\n\t"
        "ldr	x9, [%[a], 80]\n\t"
        "ldr	x10, [%[a], 32]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[5] * A[9]\n\t"
        "ldr	x9, [%[a], 72]\n\t"
        "ldr	x10, [%[a], 40]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[6] * A[8]\n\t"
        "ldr	x9, [%[a], 64]\n\t"
        "ldr	x10, [%[a], 48]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[7] * A[7]\n\t"
        "ldr	x9, [%[a], 56]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x4, x4, x5\n\t"
        "adcs	x2, x2, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x4, [%[tmp], 112]\n\t"
        "#  A[0] * A[15]\n\t"
        "ldr	x9, [%[a], 120]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x4, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[14]\n\t"
        "ldr	x9, [%[a], 112]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[2] * A[13]\n\t"
        "ldr	x9, [%[a], 104]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[3] * A[12]\n\t"
        "ldr	x9, [%[a], 96]\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[4] * A[11]\n\t"
        "ldr	x9, [%[a], 88]\n\t"
        "ldr	x10, [%[a], 32]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[5] * A[10]\n\t"
        "ldr	x9, [%[a], 80]\n\t"
        "ldr	x10, [%[a], 40]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[6] * A[9]\n\t"
        "ldr	x9, [%[a], 72]\n\t"
        "ldr	x10, [%[a], 48]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[7] * A[8]\n\t"
        "ldr	x9, [%[a], 64]\n\t"
        "ldr	x10, [%[a], 56]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x2, x2, x5\n\t"
        "adcs	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "str	x2, [%[tmp], 120]\n\t"
        "#  A[0] * A[16]\n\t"
        "ldr	x9, [%[a], 128]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x2, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[15]\n\t"
        "ldr	x9, [%[a], 120]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[2] * A[14]\n\t"
        "ldr	x9, [%[a], 112]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[3] * A[13]\n\t"
        "ldr	x9, [%[a], 104]\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[4] * A[12]\n\t"
        "ldr	x9, [%[a], 96]\n\t"
        "ldr	x10, [%[a], 32]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[5] * A[11]\n\t"
        "ldr	x9, [%[a], 88]\n\t"
        "ldr	x10, [%[a], 40]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[6] * A[10]\n\t"
        "ldr	x9, [%[a], 80]\n\t"
        "ldr	x10, [%[a], 48]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[7] * A[9]\n\t"
        "ldr	x9, [%[a], 72]\n\t"
        "ldr	x10, [%[a], 56]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[8] * A[8]\n\t"
        "ldr	x9, [%[a], 64]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x3, x3, x5\n\t"
        "adcs	x4, x4, x6\n\t"
        "adc	x2, x2, x7\n\t"
        "str	x3, [%[tmp], 128]\n\t"
        "#  A[0] * A[17]\n\t"
        "ldr	x9, [%[a], 136]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x3, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[16]\n\t"
        "ldr	x9, [%[a], 128]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[2] * A[15]\n\t"
        "ldr	x9, [%[a], 120]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[3] * A[14]\n\t"
        "ldr	x9, [%[a], 112]\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[4] * A[13]\n\t"
        "ldr	x9, [%[a], 104]\n\t"
        "ldr	x10, [%[a], 32]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[5] * A[12]\n\t"
        "ldr	x9, [%[a], 96]\n\t"
        "ldr	x10, [%[a], 40]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[6] * A[11]\n\t"
        "ldr	x9, [%[a], 88]\n\t"
        "ldr	x10, [%[a], 48]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[7] * A[10]\n\t"
        "ldr	x9, [%[a], 80]\n\t"
        "ldr	x10, [%[a], 56]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[8] * A[9]\n\t"
        "ldr	x9, [%[a], 72]\n\t"
        "ldr	x10, [%[a], 64]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x4, x4, x5\n\t"
        "adcs	x2, x2, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x4, [%[tmp], 136]\n\t"
        "#  A[0] * A[18]\n\t"
        "ldr	x9, [%[a], 144]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x4, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[17]\n\t"
        "ldr	x9, [%[a], 136]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[2] * A[16]\n\t"
        "ldr	x9, [%[a], 128]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[3] * A[15]\n\t"
        "ldr	x9, [%[a], 120]\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[4] * A[14]\n\t"
        "ldr	x9, [%[a], 112]\n\t"
        "ldr	x10, [%[a], 32]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[5] * A[13]\n\t"
        "ldr	x9, [%[a], 104]\n\t"
        "ldr	x10, [%[a], 40]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[6] * A[12]\n\t"
        "ldr	x9, [%[a], 96]\n\t"
        "ldr	x10, [%[a], 48]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[7] * A[11]\n\t"
        "ldr	x9, [%[a], 88]\n\t"
        "ldr	x10, [%[a], 56]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[8] * A[10]\n\t"
        "ldr	x9, [%[a], 80]\n\t"
        "ldr	x10, [%[a], 64]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[9] * A[9]\n\t"
        "ldr	x9, [%[a], 72]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x2, x2, x5\n\t"
        "adcs	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "str	x2, [%[tmp], 144]\n\t"
        "#  A[0] * A[19]\n\t"
        "ldr	x9, [%[a], 152]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x2, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[18]\n\t"
        "ldr	x9, [%[a], 144]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[2] * A[17]\n\t"
        "ldr	x9, [%[a], 136]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[3] * A[16]\n\t"
        "ldr	x9, [%[a], 128]\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[4] * A[15]\n\t"
        "ldr	x9, [%[a], 120]\n\t"
        "ldr	x10, [%[a], 32]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[5] * A[14]\n\t"
        "ldr	x9, [%[a], 112]\n\t"
        "ldr	x10, [%[a], 40]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[6] * A[13]\n\t"
        "ldr	x9, [%[a], 104]\n\t"
        "ldr	x10, [%[a], 48]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[7] * A[12]\n\t"
        "ldr	x9, [%[a], 96]\n\t"
        "ldr	x10, [%[a], 56]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[8] * A[11]\n\t"
        "ldr	x9, [%[a], 88]\n\t"
        "ldr	x10, [%[a], 64]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[9] * A[10]\n\t"
        "ldr	x9, [%[a], 80]\n\t"
        "ldr	x10, [%[a], 72]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x3, x3, x5\n\t"
        "adcs	x4, x4, x6\n\t"
        "adc	x2, x2, x7\n\t"
        "str	x3, [%[tmp], 152]\n\t"
        "#  A[0] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x3, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[19]\n\t"
        "ldr	x9, [%[a], 152]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[2] * A[18]\n\t"
        "ldr	x9, [%[a], 144]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[3] * A[17]\n\t"
        "ldr	x9, [%[a], 136]\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[4] * A[16]\n\t"
        "ldr	x9, [%[a], 128]\n\t"
        "ldr	x10, [%[a], 32]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[5] * A[15]\n\t"
        "ldr	x9, [%[a], 120]\n\t"
        "ldr	x10, [%[a], 40]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[6] * A[14]\n\t"
        "ldr	x9, [%[a], 112]\n\t"
        "ldr	x10, [%[a], 48]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[7] * A[13]\n\t"
        "ldr	x9, [%[a], 104]\n\t"
        "ldr	x10, [%[a], 56]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[8] * A[12]\n\t"
        "ldr	x9, [%[a], 96]\n\t"
        "ldr	x10, [%[a], 64]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[9] * A[11]\n\t"
        "ldr	x9, [%[a], 88]\n\t"
        "ldr	x10, [%[a], 72]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[10] * A[10]\n\t"
        "ldr	x9, [%[a], 80]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x4, x4, x5\n\t"
        "adcs	x2, x2, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x4, [%[tmp], 160]\n\t"
        "#  A[0] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x4, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[2] * A[19]\n\t"
        "ldr	x9, [%[a], 152]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[3] * A[18]\n\t"
        "ldr	x9, [%[a], 144]\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[4] * A[17]\n\t"
        "ldr	x9, [%[a], 136]\n\t"
        "ldr	x10, [%[a], 32]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[5] * A[16]\n\t"
        "ldr	x9, [%[a], 128]\n\t"
        "ldr	x10, [%[a], 40]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[6] * A[15]\n\t"
        "ldr	x9, [%[a], 120]\n\t"
        "ldr	x10, [%[a], 48]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[7] * A[14]\n\t"
        "ldr	x9, [%[a], 112]\n\t"
        "ldr	x10, [%[a], 56]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[8] * A[13]\n\t"
        "ldr	x9, [%[a], 104]\n\t"
        "ldr	x10, [%[a], 64]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[9] * A[12]\n\t"
        "ldr	x9, [%[a], 96]\n\t"
        "ldr	x10, [%[a], 72]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[10] * A[11]\n\t"
        "ldr	x9, [%[a], 88]\n\t"
        "ldr	x10, [%[a], 80]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x2, x2, x5\n\t"
        "adcs	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "str	x2, [%[tmp], 168]\n\t"
        "#  A[0] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x2, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[2] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[3] * A[19]\n\t"
        "ldr	x9, [%[a], 152]\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[4] * A[18]\n\t"
        "ldr	x9, [%[a], 144]\n\t"
        "ldr	x10, [%[a], 32]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[5] * A[17]\n\t"
        "ldr	x9, [%[a], 136]\n\t"
        "ldr	x10, [%[a], 40]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[6] * A[16]\n\t"
        "ldr	x9, [%[a], 128]\n\t"
        "ldr	x10, [%[a], 48]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[7] * A[15]\n\t"
        "ldr	x9, [%[a], 120]\n\t"
        "ldr	x10, [%[a], 56]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[8] * A[14]\n\t"
        "ldr	x9, [%[a], 112]\n\t"
        "ldr	x10, [%[a], 64]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[9] * A[13]\n\t"
        "ldr	x9, [%[a], 104]\n\t"
        "ldr	x10, [%[a], 72]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[10] * A[12]\n\t"
        "ldr	x9, [%[a], 96]\n\t"
        "ldr	x10, [%[a], 80]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[11] * A[11]\n\t"
        "ldr	x9, [%[a], 88]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x3, x3, x5\n\t"
        "adcs	x4, x4, x6\n\t"
        "adc	x2, x2, x7\n\t"
        "str	x3, [%[tmp], 176]\n\t"
        "#  A[0] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 0]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x3, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[1] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[2] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[3] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[4] * A[19]\n\t"
        "ldr	x9, [%[a], 152]\n\t"
        "ldr	x10, [%[a], 32]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[5] * A[18]\n\t"
        "ldr	x9, [%[a], 144]\n\t"
        "ldr	x10, [%[a], 40]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[6] * A[17]\n\t"
        "ldr	x9, [%[a], 136]\n\t"
        "ldr	x10, [%[a], 48]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[7] * A[16]\n\t"
        "ldr	x9, [%[a], 128]\n\t"
        "ldr	x10, [%[a], 56]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[8] * A[15]\n\t"
        "ldr	x9, [%[a], 120]\n\t"
        "ldr	x10, [%[a], 64]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[9] * A[14]\n\t"
        "ldr	x9, [%[a], 112]\n\t"
        "ldr	x10, [%[a], 72]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[10] * A[13]\n\t"
        "ldr	x9, [%[a], 104]\n\t"
        "ldr	x10, [%[a], 80]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[11] * A[12]\n\t"
        "ldr	x9, [%[a], 96]\n\t"
        "ldr	x10, [%[a], 88]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x4, x4, x5\n\t"
        "adcs	x2, x2, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x4, [%[tmp], 184]\n\t"
        "#  A[1] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 8]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x4, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[2] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[3] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[4] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "ldr	x10, [%[a], 32]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[5] * A[19]\n\t"
        "ldr	x9, [%[a], 152]\n\t"
        "ldr	x10, [%[a], 40]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[6] * A[18]\n\t"
        "ldr	x9, [%[a], 144]\n\t"
        "ldr	x10, [%[a], 48]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[7] * A[17]\n\t"
        "ldr	x9, [%[a], 136]\n\t"
        "ldr	x10, [%[a], 56]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[8] * A[16]\n\t"
        "ldr	x9, [%[a], 128]\n\t"
        "ldr	x10, [%[a], 64]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[9] * A[15]\n\t"
        "ldr	x9, [%[a], 120]\n\t"
        "ldr	x10, [%[a], 72]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[10] * A[14]\n\t"
        "ldr	x9, [%[a], 112]\n\t"
        "ldr	x10, [%[a], 80]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[11] * A[13]\n\t"
        "ldr	x9, [%[a], 104]\n\t"
        "ldr	x10, [%[a], 88]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[12] * A[12]\n\t"
        "ldr	x9, [%[a], 96]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x2, x2, x5\n\t"
        "adcs	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "str	x2, [%[r], 192]\n\t"
        "#  A[2] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 16]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x2, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[3] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[4] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 32]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[5] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "ldr	x10, [%[a], 40]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[6] * A[19]\n\t"
        "ldr	x9, [%[a], 152]\n\t"
        "ldr	x10, [%[a], 48]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[7] * A[18]\n\t"
        "ldr	x9, [%[a], 144]\n\t"
        "ldr	x10, [%[a], 56]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[8] * A[17]\n\t"
        "ldr	x9, [%[a], 136]\n\t"
        "ldr	x10, [%[a], 64]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[9] * A[16]\n\t"
        "ldr	x9, [%[a], 128]\n\t"
        "ldr	x10, [%[a], 72]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[10] * A[15]\n\t"
        "ldr	x9, [%[a], 120]\n\t"
        "ldr	x10, [%[a], 80]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[11] * A[14]\n\t"
        "ldr	x9, [%[a], 112]\n\t"
        "ldr	x10, [%[a], 88]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[12] * A[13]\n\t"
        "ldr	x9, [%[a], 104]\n\t"
        "ldr	x10, [%[a], 96]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x3, x3, x5\n\t"
        "adcs	x4, x4, x6\n\t"
        "adc	x2, x2, x7\n\t"
        "str	x3, [%[r], 200]\n\t"
        "#  A[3] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x3, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[4] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 32]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[5] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 40]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[6] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "ldr	x10, [%[a], 48]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[7] * A[19]\n\t"
        "ldr	x9, [%[a], 152]\n\t"
        "ldr	x10, [%[a], 56]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[8] * A[18]\n\t"
        "ldr	x9, [%[a], 144]\n\t"
        "ldr	x10, [%[a], 64]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[9] * A[17]\n\t"
        "ldr	x9, [%[a], 136]\n\t"
        "ldr	x10, [%[a], 72]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[10] * A[16]\n\t"
        "ldr	x9, [%[a], 128]\n\t"
        "ldr	x10, [%[a], 80]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[11] * A[15]\n\t"
        "ldr	x9, [%[a], 120]\n\t"
        "ldr	x10, [%[a], 88]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[12] * A[14]\n\t"
        "ldr	x9, [%[a], 112]\n\t"
        "ldr	x10, [%[a], 96]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[13] * A[13]\n\t"
        "ldr	x9, [%[a], 104]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x4, x4, x5\n\t"
        "adcs	x2, x2, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x4, [%[r], 208]\n\t"
        "#  A[4] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 32]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x4, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[5] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 40]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[6] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 48]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[7] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "ldr	x10, [%[a], 56]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[8] * A[19]\n\t"
        "ldr	x9, [%[a], 152]\n\t"
        "ldr	x10, [%[a], 64]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[9] * A[18]\n\t"
        "ldr	x9, [%[a], 144]\n\t"
        "ldr	x10, [%[a], 72]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[10] * A[17]\n\t"
        "ldr	x9, [%[a], 136]\n\t"
        "ldr	x10, [%[a], 80]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[11] * A[16]\n\t"
        "ldr	x9, [%[a], 128]\n\t"
        "ldr	x10, [%[a], 88]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[12] * A[15]\n\t"
        "ldr	x9, [%[a], 120]\n\t"
        "ldr	x10, [%[a], 96]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[13] * A[14]\n\t"
        "ldr	x9, [%[a], 112]\n\t"
        "ldr	x10, [%[a], 104]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x2, x2, x5\n\t"
        "adcs	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "str	x2, [%[r], 216]\n\t"
        "#  A[5] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 40]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x2, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[6] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 48]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[7] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 56]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[8] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "ldr	x10, [%[a], 64]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[9] * A[19]\n\t"
        "ldr	x9, [%[a], 152]\n\t"
        "ldr	x10, [%[a], 72]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[10] * A[18]\n\t"
        "ldr	x9, [%[a], 144]\n\t"
        "ldr	x10, [%[a], 80]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[11] * A[17]\n\t"
        "ldr	x9, [%[a], 136]\n\t"
        "ldr	x10, [%[a], 88]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[12] * A[16]\n\t"
        "ldr	x9, [%[a], 128]\n\t"
        "ldr	x10, [%[a], 96]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[13] * A[15]\n\t"
        "ldr	x9, [%[a], 120]\n\t"
        "ldr	x10, [%[a], 104]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[14] * A[14]\n\t"
        "ldr	x9, [%[a], 112]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x3, x3, x5\n\t"
        "adcs	x4, x4, x6\n\t"
        "adc	x2, x2, x7\n\t"
        "str	x3, [%[r], 224]\n\t"
        "#  A[6] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 48]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x3, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[7] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 56]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[8] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 64]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[9] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "ldr	x10, [%[a], 72]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[10] * A[19]\n\t"
        "ldr	x9, [%[a], 152]\n\t"
        "ldr	x10, [%[a], 80]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[11] * A[18]\n\t"
        "ldr	x9, [%[a], 144]\n\t"
        "ldr	x10, [%[a], 88]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[12] * A[17]\n\t"
        "ldr	x9, [%[a], 136]\n\t"
        "ldr	x10, [%[a], 96]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[13] * A[16]\n\t"
        "ldr	x9, [%[a], 128]\n\t"
        "ldr	x10, [%[a], 104]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[14] * A[15]\n\t"
        "ldr	x9, [%[a], 120]\n\t"
        "ldr	x10, [%[a], 112]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x4, x4, x5\n\t"
        "adcs	x2, x2, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x4, [%[r], 232]\n\t"
        "#  A[7] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 56]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x4, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[8] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 64]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[9] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 72]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[10] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "ldr	x10, [%[a], 80]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[11] * A[19]\n\t"
        "ldr	x9, [%[a], 152]\n\t"
        "ldr	x10, [%[a], 88]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[12] * A[18]\n\t"
        "ldr	x9, [%[a], 144]\n\t"
        "ldr	x10, [%[a], 96]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[13] * A[17]\n\t"
        "ldr	x9, [%[a], 136]\n\t"
        "ldr	x10, [%[a], 104]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[14] * A[16]\n\t"
        "ldr	x9, [%[a], 128]\n\t"
        "ldr	x10, [%[a], 112]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[15] * A[15]\n\t"
        "ldr	x9, [%[a], 120]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x2, x2, x5\n\t"
        "adcs	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "str	x2, [%[r], 240]\n\t"
        "#  A[8] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 64]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x2, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[9] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 72]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[10] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 80]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[11] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "ldr	x10, [%[a], 88]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[12] * A[19]\n\t"
        "ldr	x9, [%[a], 152]\n\t"
        "ldr	x10, [%[a], 96]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[13] * A[18]\n\t"
        "ldr	x9, [%[a], 144]\n\t"
        "ldr	x10, [%[a], 104]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[14] * A[17]\n\t"
        "ldr	x9, [%[a], 136]\n\t"
        "ldr	x10, [%[a], 112]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[15] * A[16]\n\t"
        "ldr	x9, [%[a], 128]\n\t"
        "ldr	x10, [%[a], 120]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x3, x3, x5\n\t"
        "adcs	x4, x4, x6\n\t"
        "adc	x2, x2, x7\n\t"
        "str	x3, [%[r], 248]\n\t"
        "#  A[9] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 72]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x3, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[10] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 80]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[11] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 88]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[12] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "ldr	x10, [%[a], 96]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[13] * A[19]\n\t"
        "ldr	x9, [%[a], 152]\n\t"
        "ldr	x10, [%[a], 104]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[14] * A[18]\n\t"
        "ldr	x9, [%[a], 144]\n\t"
        "ldr	x10, [%[a], 112]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[15] * A[17]\n\t"
        "ldr	x9, [%[a], 136]\n\t"
        "ldr	x10, [%[a], 120]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[16] * A[16]\n\t"
        "ldr	x9, [%[a], 128]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x4, x4, x5\n\t"
        "adcs	x2, x2, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x4, [%[r], 256]\n\t"
        "#  A[10] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 80]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x4, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[11] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 88]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[12] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 96]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[13] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "ldr	x10, [%[a], 104]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[14] * A[19]\n\t"
        "ldr	x9, [%[a], 152]\n\t"
        "ldr	x10, [%[a], 112]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[15] * A[18]\n\t"
        "ldr	x9, [%[a], 144]\n\t"
        "ldr	x10, [%[a], 120]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[16] * A[17]\n\t"
        "ldr	x9, [%[a], 136]\n\t"
        "ldr	x10, [%[a], 128]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x2, x2, x5\n\t"
        "adcs	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "str	x2, [%[r], 264]\n\t"
        "#  A[11] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 88]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x2, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[12] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 96]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[13] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 104]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[14] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "ldr	x10, [%[a], 112]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[15] * A[19]\n\t"
        "ldr	x9, [%[a], 152]\n\t"
        "ldr	x10, [%[a], 120]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[16] * A[18]\n\t"
        "ldr	x9, [%[a], 144]\n\t"
        "ldr	x10, [%[a], 128]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[17] * A[17]\n\t"
        "ldr	x9, [%[a], 136]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x3, x3, x5\n\t"
        "adcs	x4, x4, x6\n\t"
        "adc	x2, x2, x7\n\t"
        "str	x3, [%[r], 272]\n\t"
        "#  A[12] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 96]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x3, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[13] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 104]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[14] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 112]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[15] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "ldr	x10, [%[a], 120]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[16] * A[19]\n\t"
        "ldr	x9, [%[a], 152]\n\t"
        "ldr	x10, [%[a], 128]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[17] * A[18]\n\t"
        "ldr	x9, [%[a], 144]\n\t"
        "ldr	x10, [%[a], 136]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x4, x4, x5\n\t"
        "adcs	x2, x2, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x4, [%[r], 280]\n\t"
        "#  A[13] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 104]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x4, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[14] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 112]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[15] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 120]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[16] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "ldr	x10, [%[a], 128]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[17] * A[19]\n\t"
        "ldr	x9, [%[a], 152]\n\t"
        "ldr	x10, [%[a], 136]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[18] * A[18]\n\t"
        "ldr	x9, [%[a], 144]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x2, x2, x5\n\t"
        "adcs	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "str	x2, [%[r], 288]\n\t"
        "#  A[14] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 112]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x2, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[15] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 120]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[16] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 128]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[17] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "ldr	x10, [%[a], 136]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[18] * A[19]\n\t"
        "ldr	x9, [%[a], 152]\n\t"
        "ldr	x10, [%[a], 144]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x3, x3, x5\n\t"
        "adcs	x4, x4, x6\n\t"
        "adc	x2, x2, x7\n\t"
        "str	x3, [%[r], 296]\n\t"
        "#  A[15] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 120]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x3, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[16] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 128]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[17] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 136]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[18] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "ldr	x10, [%[a], 144]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[19] * A[19]\n\t"
        "ldr	x9, [%[a], 152]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x4, x4, x5\n\t"
        "adcs	x2, x2, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x4, [%[r], 304]\n\t"
        "#  A[16] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 128]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x4, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[17] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 136]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[18] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 144]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[19] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "ldr	x10, [%[a], 152]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x2, x2, x5\n\t"
        "adcs	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "str	x2, [%[r], 312]\n\t"
        "#  A[17] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 136]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x2, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[18] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 144]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[19] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 152]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[20] * A[20]\n\t"
        "ldr	x9, [%[a], 160]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x3, x3, x5\n\t"
        "adcs	x4, x4, x6\n\t"
        "adc	x2, x2, x7\n\t"
        "str	x3, [%[r], 320]\n\t"
        "#  A[18] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 144]\n\t"
        "mul	x5, x9, x10\n\t"
        "umulh	x6, x9, x10\n\t"
        "mov	x3, xzr\n\t"
        "mov	x7, xzr\n\t"
        "#  A[19] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 152]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "#  A[20] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "ldr	x10, [%[a], 160]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x5, x5, x8\n\t"
        "adcs	x6, x6, x9\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x5, x5, x5\n\t"
        "adcs	x6, x6, x6\n\t"
        "adc	x7, x7, x7\n\t"
        "adds	x4, x4, x5\n\t"
        "adcs	x2, x2, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x4, [%[r], 328]\n\t"
        "#  A[19] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 152]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x2, x2, x8\n\t"
        "adcs	x3, x3, x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x2, x2, x8\n\t"
        "adcs	x3, x3, x9\n\t"
        "adc	x4, x4, xzr\n\t"
        "#  A[20] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 160]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x2, x2, x8\n\t"
        "adcs	x3, x3, x9\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x2, x2, x8\n\t"
        "adcs	x3, x3, x9\n\t"
        "adc	x4, x4, xzr\n\t"
        "#  A[21] * A[21]\n\t"
        "ldr	x9, [%[a], 168]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x2, x2, x8\n\t"
        "adcs	x3, x3, x9\n\t"
        "adc	x4, x4, xzr\n\t"
        "str	x2, [%[r], 336]\n\t"
        "#  A[20] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 160]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x3, x3, x8\n\t"
        "adcs	x4, x4, x9\n\t"
        "adc	x2, xzr, xzr\n\t"
        "adds	x3, x3, x8\n\t"
        "adcs	x4, x4, x9\n\t"
        "adc	x2, x2, xzr\n\t"
        "#  A[21] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "ldr	x10, [%[a], 168]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x3, x3, x8\n\t"
        "adcs	x4, x4, x9\n\t"
        "adc	x2, x2, xzr\n\t"
        "adds	x3, x3, x8\n\t"
        "adcs	x4, x4, x9\n\t"
        "adc	x2, x2, xzr\n\t"
        "str	x3, [%[r], 344]\n\t"
        "#  A[21] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 168]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x4, x4, x8\n\t"
        "adcs	x2, x2, x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x4, x4, x8\n\t"
        "adcs	x2, x2, x9\n\t"
        "adc	x3, x3, xzr\n\t"
        "#  A[22] * A[22]\n\t"
        "ldr	x9, [%[a], 176]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x4, x4, x8\n\t"
        "adcs	x2, x2, x9\n\t"
        "adc	x3, x3, xzr\n\t"
        "str	x4, [%[r], 352]\n\t"
        "#  A[22] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "ldr	x10, [%[a], 176]\n\t"
        "mul	x8, x9, x10\n\t"
        "umulh	x9, x9, x10\n\t"
        "adds	x2, x2, x8\n\t"
        "adcs	x3, x3, x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x2, x2, x8\n\t"
        "adcs	x3, x3, x9\n\t"
        "adc	x4, x4, xzr\n\t"
        "str	x2, [%[r], 360]\n\t"
        "#  A[23] * A[23]\n\t"
        "ldr	x9, [%[a], 184]\n\t"
        "mul	x8, x9, x9\n\t"
        "umulh	x9, x9, x9\n\t"
        "adds	x3, x3, x8\n\t"
        "adc	x4, x4, x9\n\t"
        "stp	x3, x4, [%[r], 368]\n\t"
        "ldp	x9, x10, [%[tmp], 0]\n\t"
        "stp	x9, x10, [%[r], 0]\n\t"
        "ldp	x9, x10, [%[tmp], 16]\n\t"
        "stp	x9, x10, [%[r], 16]\n\t"
        "ldp	x9, x10, [%[tmp], 32]\n\t"
        "stp	x9, x10, [%[r], 32]\n\t"
        "ldp	x9, x10, [%[tmp], 48]\n\t"
        "stp	x9, x10, [%[r], 48]\n\t"
        "ldp	x9, x10, [%[tmp], 64]\n\t"
        "stp	x9, x10, [%[r], 64]\n\t"
        "ldp	x9, x10, [%[tmp], 80]\n\t"
        "stp	x9, x10, [%[r], 80]\n\t"
        "ldp	x9, x10, [%[tmp], 96]\n\t"
        "stp	x9, x10, [%[r], 96]\n\t"
        "ldp	x9, x10, [%[tmp], 112]\n\t"
        "stp	x9, x10, [%[r], 112]\n\t"
        "ldp	x9, x10, [%[tmp], 128]\n\t"
        "stp	x9, x10, [%[r], 128]\n\t"
        "ldp	x9, x10, [%[tmp], 144]\n\t"
        "stp	x9, x10, [%[r], 144]\n\t"
        "ldp	x9, x10, [%[tmp], 160]\n\t"
        "stp	x9, x10, [%[r], 160]\n\t"
        "ldp	x9, x10, [%[tmp], 176]\n\t"
        "stp	x9, x10, [%[r], 176]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [tmp] "r" (tmp)
        : "memory", "x2", "x3", "x4", "x8", "x9", "x10", "x5", "x6", "x7"
    );
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_3072_sub_24(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x7, x8, [%[b], 0]\n\t"
        "subs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 16]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldp	x3, x4, [%[a], 32]\n\t"
        "ldp	x7, x8, [%[b], 32]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 48]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 48]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 32]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 48]\n\t"
        "ldp	x3, x4, [%[a], 64]\n\t"
        "ldp	x7, x8, [%[b], 64]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 80]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 80]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 64]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 80]\n\t"
        "ldp	x3, x4, [%[a], 96]\n\t"
        "ldp	x7, x8, [%[b], 96]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 112]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 112]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 96]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 112]\n\t"
        "ldp	x3, x4, [%[a], 128]\n\t"
        "ldp	x7, x8, [%[b], 128]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 144]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 144]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 128]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 144]\n\t"
        "ldp	x3, x4, [%[a], 160]\n\t"
        "ldp	x7, x8, [%[b], 160]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 176]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 176]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 160]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 176]\n\t"
        "csetm	%[r], cc\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return (sp_digit)r;
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_48(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit* z2 = r + 48;
    sp_digit z1[48];
    sp_digit* a1 = z1;
    sp_digit* zero = z1 + 24;
    sp_digit u;
    sp_digit mask;
    sp_digit* p1;
    sp_digit* p2;

    XMEMSET(zero, 0, sizeof(sp_digit) * 24);

    mask = sp_3072_sub_24(a1, a, &a[24]);
    p1 = (sp_digit*)(((sp_digit)zero &   mask ) | ((sp_digit)a1 & (~mask)));
    p2 = (sp_digit*)(((sp_digit)zero & (~mask)) | ((sp_digit)a1 &   mask ));
    (void)sp_3072_sub_24(a1, p1, p2);

    sp_3072_sqr_24(z2, &a[24]);
    sp_3072_sqr_24(z0, a);
    sp_3072_sqr_24(z1, a1);

    u = 0;
    u -= sp_3072_sub_in_place_48(z1, z2);
    u -= sp_3072_sub_in_place_48(z1, z0);
    u += sp_3072_sub_in_place_48(r + 24, z1);
    sp_3072_add_word_24(r + 72, r + 72, u);
}

#endif /* !WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_3072_add_48(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "add	x11, %[a], 384\n\t"
        "\n1:\n\t"
        "adds	%[c], %[c], #-1\n\t"
        "ldp	x3, x4, [%[a]], #16\n\t"
        "ldp	x5, x6, [%[a]], #16\n\t"
        "ldp	x7, x8, [%[b]], #16\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x9, x10, [%[b]], #16\n\t"
        "adcs	x4, x4, x8\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r]], #16\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r]], #16\n\t"
        "cset	%[c], cs\n\t"
        "cmp	%[a], x11\n\t"
        "b.ne	1b\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    return c;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_3072_sub_in_place_48(sp_digit* a, const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "add	x10, %[a], 384\n\t"
        "\n1:\n\t"
        "subs	%[c], xzr, %[c]\n\t"
        "ldp	x2, x3, [%[a]]\n\t"
        "ldp	x4, x5, [%[a], #16]\n\t"
        "ldp	x6, x7, [%[b]], #16\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x8, x9, [%[b]], #16\n\t"
        "sbcs	x3, x3, x7\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a]], #16\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a]], #16\n\t"
        "csetm	%[c], cc\n\t"
        "cmp	%[a], x10\n\t"
        "b.ne	1b\n\t"
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return c;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static void sp_3072_mul_48(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    sp_digit tmp[96];

    __asm__ __volatile__ (
        "mov	x5, xzr\n\t"
        "mov	x6, xzr\n\t"
        "mov	x7, xzr\n\t"
        "mov	x8, xzr\n\t"
        "\n1:\n\t"
        "subs	x3, x5, 376\n\t"
        "csel	x3, xzr, x3, cc\n\t"
        "sub	x4, x5, x3\n\t"
        "\n2:\n\t"
        "ldr	x10, [%[a], x3]\n\t"
        "ldr	x11, [%[b], x4]\n\t"
        "mul	x9, x10, x11\n\t"
        "umulh	x10, x10, x11\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "add	x3, x3, #8\n\t"
        "sub	x4, x4, #8\n\t"
        "cmp	x3, 384\n\t"
        "b.eq	3f\n\t"
        "cmp	x3, x5\n\t"
        "b.le	2b\n\t"
        "\n3:\n\t"
        "str	x6, [%[r], x5]\n\t"
        "mov	x6, x7\n\t"
        "mov	x7, x8\n\t"
        "mov	x8, #0\n\t"
        "add	x5, x5, #8\n\t"
        "cmp	x5, 752\n\t"
        "b.le	1b\n\t"
        "str	x6, [%[r], x5]\n\t"
        :
        : [r] "r" (tmp), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    XMEMCPY(r, tmp, sizeof(tmp));
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
static void sp_3072_sqr_48(sp_digit* r, const sp_digit* a)
{
    sp_digit tmp[96];

    __asm__ __volatile__ (
        "mov	x6, xzr\n\t"
        "mov	x7, xzr\n\t"
        "mov	x8, xzr\n\t"
        "mov	x5, xzr\n\t"
        "\n1:\n\t"
        "subs	x3, x5, 376\n\t"
        "csel	x3, xzr, x3, cc\n\t"
        "sub	x4, x5, x3\n\t"
        "\n2:\n\t"
        "cmp	x4, x3\n\t"
        "b.eq	4f\n\t"
        "ldr	x10, [%[a], x3]\n\t"
        "ldr	x11, [%[a], x4]\n\t"
        "mul	x9, x10, x11\n\t"
        "umulh	x10, x10, x11\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "b.al	5f\n\t"
        "\n4:\n\t"
        "ldr	x10, [%[a], x3]\n\t"
        "mul	x9, x10, x10\n\t"
        "umulh	x10, x10, x10\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "\n5:\n\t"
        "add	x3, x3, #8\n\t"
        "sub	x4, x4, #8\n\t"
        "cmp	x3, 384\n\t"
        "b.eq	3f\n\t"
        "cmp	x3, x4\n\t"
        "b.gt	3f\n\t"
        "cmp	x3, x5\n\t"
        "b.le	2b\n\t"
        "\n3:\n\t"
        "str	x6, [%[r], x5]\n\t"
        "mov	x6, x7\n\t"
        "mov	x7, x8\n\t"
        "mov	x8, #0\n\t"
        "add	x5, x5, #8\n\t"
        "cmp	x5, 752\n\t"
        "b.le	1b\n\t"
        "str	x6, [%[r], x5]\n\t"
        :
        : [r] "r" (tmp), [a] "r" (a)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    XMEMCPY(r, tmp, sizeof(tmp));
}

#endif /* WOLFSSL_SP_SMALL */
#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_3072_add_24(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "add	x11, %[a], 192\n\t"
        "\n1:\n\t"
        "adds	%[c], %[c], #-1\n\t"
        "ldp	x3, x4, [%[a]], #16\n\t"
        "ldp	x5, x6, [%[a]], #16\n\t"
        "ldp	x7, x8, [%[b]], #16\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x9, x10, [%[b]], #16\n\t"
        "adcs	x4, x4, x8\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r]], #16\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r]], #16\n\t"
        "cset	%[c], cs\n\t"
        "cmp	%[a], x11\n\t"
        "b.ne	1b\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    return c;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_3072_sub_in_place_24(sp_digit* a, const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "add	x10, %[a], 192\n\t"
        "\n1:\n\t"
        "subs	%[c], xzr, %[c]\n\t"
        "ldp	x2, x3, [%[a]]\n\t"
        "ldp	x4, x5, [%[a], #16]\n\t"
        "ldp	x6, x7, [%[b]], #16\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x8, x9, [%[b]], #16\n\t"
        "sbcs	x3, x3, x7\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a]], #16\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a]], #16\n\t"
        "csetm	%[c], cc\n\t"
        "cmp	%[a], x10\n\t"
        "b.ne	1b\n\t"
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return c;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static void sp_3072_mul_24(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    sp_digit tmp[48];

    __asm__ __volatile__ (
        "mov	x5, xzr\n\t"
        "mov	x6, xzr\n\t"
        "mov	x7, xzr\n\t"
        "mov	x8, xzr\n\t"
        "\n1:\n\t"
        "subs	x3, x5, 184\n\t"
        "csel	x3, xzr, x3, cc\n\t"
        "sub	x4, x5, x3\n\t"
        "\n2:\n\t"
        "ldr	x10, [%[a], x3]\n\t"
        "ldr	x11, [%[b], x4]\n\t"
        "mul	x9, x10, x11\n\t"
        "umulh	x10, x10, x11\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "add	x3, x3, #8\n\t"
        "sub	x4, x4, #8\n\t"
        "cmp	x3, 192\n\t"
        "b.eq	3f\n\t"
        "cmp	x3, x5\n\t"
        "b.le	2b\n\t"
        "\n3:\n\t"
        "str	x6, [%[r], x5]\n\t"
        "mov	x6, x7\n\t"
        "mov	x7, x8\n\t"
        "mov	x8, #0\n\t"
        "add	x5, x5, #8\n\t"
        "cmp	x5, 368\n\t"
        "b.le	1b\n\t"
        "str	x6, [%[r], x5]\n\t"
        :
        : [r] "r" (tmp), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    XMEMCPY(r, tmp, sizeof(tmp));
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
static void sp_3072_sqr_24(sp_digit* r, const sp_digit* a)
{
    sp_digit tmp[48];

    __asm__ __volatile__ (
        "mov	x6, xzr\n\t"
        "mov	x7, xzr\n\t"
        "mov	x8, xzr\n\t"
        "mov	x5, xzr\n\t"
        "\n1:\n\t"
        "subs	x3, x5, 184\n\t"
        "csel	x3, xzr, x3, cc\n\t"
        "sub	x4, x5, x3\n\t"
        "\n2:\n\t"
        "cmp	x4, x3\n\t"
        "b.eq	4f\n\t"
        "ldr	x10, [%[a], x3]\n\t"
        "ldr	x11, [%[a], x4]\n\t"
        "mul	x9, x10, x11\n\t"
        "umulh	x10, x10, x11\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "b.al	5f\n\t"
        "\n4:\n\t"
        "ldr	x10, [%[a], x3]\n\t"
        "mul	x9, x10, x10\n\t"
        "umulh	x10, x10, x10\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "\n5:\n\t"
        "add	x3, x3, #8\n\t"
        "sub	x4, x4, #8\n\t"
        "cmp	x3, 192\n\t"
        "b.eq	3f\n\t"
        "cmp	x3, x4\n\t"
        "b.gt	3f\n\t"
        "cmp	x3, x5\n\t"
        "b.le	2b\n\t"
        "\n3:\n\t"
        "str	x6, [%[r], x5]\n\t"
        "mov	x6, x7\n\t"
        "mov	x7, x8\n\t"
        "mov	x8, #0\n\t"
        "add	x5, x5, #8\n\t"
        "cmp	x5, 368\n\t"
        "b.le	1b\n\t"
        "str	x6, [%[r], x5]\n\t"
        :
        : [r] "r" (tmp), [a] "r" (a)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    XMEMCPY(r, tmp, sizeof(tmp));
}

#endif /* WOLFSSL_SP_SMALL */
#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) | WOLFSSL_HAVE_SP_DH */

/* Caclulate the bottom digit of -1/a mod 2^n.
 *
 * a    A single precision number.
 * rho  Bottom word of inverse.
 */
static void sp_3072_mont_setup(const sp_digit* a, sp_digit* rho)
{
    sp_digit x;
    sp_digit b;

    b = a[0];
    x = (((b + 2) & 4) << 1) + b; /* here x*a==1 mod 2**4 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**8 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**16 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**32 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**64 */

    /* rho = -1/m mod b */
    *rho = (sp_digit)0 - x;
}

/* Mul a by digit b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision digit.
 */
static void sp_3072_mul_d_48(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "# A[0] * B\n\t"
        "ldr	x8, [%[a]]\n\t"
        "mul	x5, %[b], x8\n\t"
        "umulh	x3, %[b], x8\n\t"
        "mov	x4, xzr\n\t"
        "str	x5, [%[r]]\n\t"
        "mov	x5, xzr\n\t"
        "mov	x9, #8\n\t"
        "1:\n\t"
        "ldr	x8, [%[a], x9]\n\t"
        "mul	x6, %[b], x8\n\t"
        "umulh	x7, %[b], x8\n\t"
        "adds	x3, x3, x6\n\t"
        "adcs	x4, x4, x7\n\t"
        "adc	x5, xzr, xzr\n\t"
        "str	x3, [%[r], x9]\n\t"
        "mov	x3, x4\n\t"
        "mov	x4, x5\n\t"
        "mov	x5, #0\n\t"
        "add	x9, x9, #8\n\t"
        "cmp	x9, 384\n\t"
        "b.lt	1b\n\t"
        "str	x3, [%[r], 384]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );
#else
    __asm__ __volatile__ (
        "# A[0] * B\n\t"
        "ldp	x9, x10, [%[a]]\n\t"
        "mul	x3, %[b], x9\n\t"
        "umulh	x4, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "# A[1] * B\n\t"
        "str	x3, [%[r]]\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[2] * B\n\t"
        "ldp	x9, x10, [%[a], 16]\n\t"
        "str	x4, [%[r], 8]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[3] * B\n\t"
        "str	x5, [%[r], 16]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[4] * B\n\t"
        "ldp	x9, x10, [%[a], 32]\n\t"
        "str	x3, [%[r], 24]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[5] * B\n\t"
        "str	x4, [%[r], 32]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[6] * B\n\t"
        "ldp	x9, x10, [%[a], 48]\n\t"
        "str	x5, [%[r], 40]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[7] * B\n\t"
        "str	x3, [%[r], 48]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[8] * B\n\t"
        "ldp	x9, x10, [%[a], 64]\n\t"
        "str	x4, [%[r], 56]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[9] * B\n\t"
        "str	x5, [%[r], 64]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[10] * B\n\t"
        "ldp	x9, x10, [%[a], 80]\n\t"
        "str	x3, [%[r], 72]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[11] * B\n\t"
        "str	x4, [%[r], 80]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[12] * B\n\t"
        "ldp	x9, x10, [%[a], 96]\n\t"
        "str	x5, [%[r], 88]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[13] * B\n\t"
        "str	x3, [%[r], 96]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[14] * B\n\t"
        "ldp	x9, x10, [%[a], 112]\n\t"
        "str	x4, [%[r], 104]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[15] * B\n\t"
        "str	x5, [%[r], 112]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[16] * B\n\t"
        "ldp	x9, x10, [%[a], 128]\n\t"
        "str	x3, [%[r], 120]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[17] * B\n\t"
        "str	x4, [%[r], 128]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[18] * B\n\t"
        "ldp	x9, x10, [%[a], 144]\n\t"
        "str	x5, [%[r], 136]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[19] * B\n\t"
        "str	x3, [%[r], 144]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[20] * B\n\t"
        "ldp	x9, x10, [%[a], 160]\n\t"
        "str	x4, [%[r], 152]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[21] * B\n\t"
        "str	x5, [%[r], 160]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[22] * B\n\t"
        "ldp	x9, x10, [%[a], 176]\n\t"
        "str	x3, [%[r], 168]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[23] * B\n\t"
        "str	x4, [%[r], 176]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[24] * B\n\t"
        "ldp	x9, x10, [%[a], 192]\n\t"
        "str	x5, [%[r], 184]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[25] * B\n\t"
        "str	x3, [%[r], 192]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[26] * B\n\t"
        "ldp	x9, x10, [%[a], 208]\n\t"
        "str	x4, [%[r], 200]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[27] * B\n\t"
        "str	x5, [%[r], 208]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[28] * B\n\t"
        "ldp	x9, x10, [%[a], 224]\n\t"
        "str	x3, [%[r], 216]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[29] * B\n\t"
        "str	x4, [%[r], 224]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[30] * B\n\t"
        "ldp	x9, x10, [%[a], 240]\n\t"
        "str	x5, [%[r], 232]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[31] * B\n\t"
        "str	x3, [%[r], 240]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[32] * B\n\t"
        "ldp	x9, x10, [%[a], 256]\n\t"
        "str	x4, [%[r], 248]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[33] * B\n\t"
        "str	x5, [%[r], 256]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[34] * B\n\t"
        "ldp	x9, x10, [%[a], 272]\n\t"
        "str	x3, [%[r], 264]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[35] * B\n\t"
        "str	x4, [%[r], 272]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[36] * B\n\t"
        "ldp	x9, x10, [%[a], 288]\n\t"
        "str	x5, [%[r], 280]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[37] * B\n\t"
        "str	x3, [%[r], 288]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[38] * B\n\t"
        "ldp	x9, x10, [%[a], 304]\n\t"
        "str	x4, [%[r], 296]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[39] * B\n\t"
        "str	x5, [%[r], 304]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[40] * B\n\t"
        "ldp	x9, x10, [%[a], 320]\n\t"
        "str	x3, [%[r], 312]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[41] * B\n\t"
        "str	x4, [%[r], 320]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[42] * B\n\t"
        "ldp	x9, x10, [%[a], 336]\n\t"
        "str	x5, [%[r], 328]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[43] * B\n\t"
        "str	x3, [%[r], 336]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[44] * B\n\t"
        "ldp	x9, x10, [%[a], 352]\n\t"
        "str	x4, [%[r], 344]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[45] * B\n\t"
        "str	x5, [%[r], 352]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[46] * B\n\t"
        "ldp	x9, x10, [%[a], 368]\n\t"
        "str	x3, [%[r], 360]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[47] * B\n\t"
        "str	x4, [%[r], 368]\n\t"
        "mul	x6, %[b], x10\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x5, [%[r], 376]\n\t"
        "str	x3, [%[r], 384]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );
#endif
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 3072 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_3072_mont_norm_24(sp_digit* r, const sp_digit* m)
{
    XMEMSET(r, 0, sizeof(sp_digit) * 24);

    /* r = 2^n mod m */
    sp_3072_sub_in_place_24(r, m);
}

/* Reduce the number back to 3072 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
SP_NOINLINE static void sp_3072_mont_reduce_24(sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    __asm__ __volatile__ (
        "ldp	x11, x12, [%[a], 0]\n\t"
        "ldp	x13, x14, [%[a], 16]\n\t"
        "ldp	x15, x16, [%[a], 32]\n\t"
        "ldp	x17, x19, [%[a], 48]\n\t"
        "ldp	x20, x21, [%[a], 64]\n\t"
        "ldp	x22, x23, [%[a], 80]\n\t"
        "# No carry yet\n\t"
        "mov	x3, xzr\n\t"
        "# i = 0..23\n\t"
        "mov	x4, 24\n\t"
        "\n1:\n\t"
        "# mu = a[i] * mp\n\t"
        "mul	x10, %[mp], x11\n\t"
        "ldp	x24, x25, [%[m], 0]\n\t"
        "ldp	x26, x27, [%[m], 16]\n\t"
        "# a[i+0] += m[0] * mu\n\t"
        "mul	x5, x24, x10\n\t"
        "umulh	x6, x24, x10\n\t"
        "# a[i+1] += m[1] * mu\n\t"
        "adds	x11, x11, x5\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x11, x12, x5\n\t"
        "# a[i+2] += m[2] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x11, x11, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x12, x13, x5\n\t"
        "# a[i+3] += m[3] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x12, x12, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x13, x14, x5\n\t"
        "ldp	x24, x25, [%[m], 32]\n\t"
        "ldp	x26, x27, [%[m], 48]\n\t"
        "# a[i+4] += m[4] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x13, x13, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x14, x15, x5\n\t"
        "# a[i+5] += m[5] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x14, x14, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x15, x16, x5\n\t"
        "# a[i+6] += m[6] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x15, x15, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x16, x17, x5\n\t"
        "# a[i+7] += m[7] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x16, x16, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x17, x19, x5\n\t"
        "ldp	x24, x25, [%[m], 64]\n\t"
        "ldp	x26, x27, [%[m], 80]\n\t"
        "# a[i+8] += m[8] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x17, x17, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x19, x20, x5\n\t"
        "# a[i+9] += m[9] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x19, x19, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x20, x21, x5\n\t"
        "# a[i+10] += m[10] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x20, x20, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x21, x22, x5\n\t"
        "# a[i+11] += m[11] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x21, x21, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x22, x23, x5\n\t"
        "ldp	x24, x25, [%[m], 96]\n\t"
        "ldp	x26, x27, [%[m], 112]\n\t"
        "# a[i+12] += m[12] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x22, x22, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "ldr	x23, [%[a], 96]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x23, x23, x5\n\t"
        "# a[i+13] += m[13] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x23, x23, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "ldp	x8, x9, [%[a], 104]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+14] += m[14] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 104]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+15] += m[15] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 112]\n\t"
        "ldp	x8, x9, [%[a], 120]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 128]\n\t"
        "ldp	x26, x27, [%[m], 144]\n\t"
        "# a[i+16] += m[16] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 120]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+17] += m[17] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 128]\n\t"
        "ldp	x8, x9, [%[a], 136]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+18] += m[18] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 136]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+19] += m[19] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 144]\n\t"
        "ldp	x8, x9, [%[a], 152]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 160]\n\t"
        "ldp	x26, x27, [%[m], 176]\n\t"
        "# a[i+20] += m[20] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 152]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+21] += m[21] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 160]\n\t"
        "ldp	x8, x9, [%[a], 168]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+22] += m[22] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 168]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+23] += m[23] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 176]\n\t"
        "umulh	x7, x27, x10\n\t"
        "ldp	x8, x9, [%[a], 184]\n\t"
        "adds	x5, x5, x6\n\t"
        "adcs	x7, x7, x3\n\t"
        "cset	x3, cs\n\t"
        "adds	x8, x8, x5\n\t"
        "str	x8, [%[a], 184]\n\t"
        "adcs	x9, x9, x7\n\t"
        "str	x9, [%[a], 192]\n\t"
        "adc	x3, x3, xzr\n\t"
        "subs	x4, x4, 1\n\t"
        "add	%[a], %[a], 8\n\t"
        "b.ne	1b\n\t"
        "# Create mask\n\t"
        "neg	x3, x3\n\t"
        "mov   %[mp], %[a]\n\t"
        "sub	%[a], %[a], 192\n\t"
        "# Subtract masked modulus\n\t"
        "ldp	x4, x5, [%[m], 0]\n\t"
        "ldp	x6, x7, [%[m], 16]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "subs	x11, x11, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x12, x12, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x13, x13, x6\n\t"
        "stp	x11, x12, [%[a], 0]\n\t"
        "sbcs	x14, x14, x7\n\t"
        "stp	x13, x14, [%[a], 16]\n\t"
        "ldp	x4, x5, [%[m], 32]\n\t"
        "ldp	x6, x7, [%[m], 48]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x15, x15, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x16, x16, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x17, x17, x6\n\t"
        "stp	x15, x16, [%[a], 32]\n\t"
        "sbcs	x19, x19, x7\n\t"
        "stp	x17, x19, [%[a], 48]\n\t"
        "ldp	x4, x5, [%[m], 64]\n\t"
        "ldp	x6, x7, [%[m], 80]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x20, x20, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x21, x21, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x22, x22, x6\n\t"
        "stp	x20, x21, [%[a], 64]\n\t"
        "sbcs	x23, x23, x7\n\t"
        "stp	x22, x23, [%[a], 80]\n\t"
        "ldp	x4, x5, [%[m], 96]\n\t"
        "ldp	x6, x7, [%[m], 112]\n\t"
        "ldp	x8, x9, [%[mp], 96]\n\t"
        "ldp	x10, x11, [%[mp], 112]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 96]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 112]\n\t"
        "ldp	x4, x5, [%[m], 128]\n\t"
        "ldp	x6, x7, [%[m], 144]\n\t"
        "ldp	x8, x9, [%[mp], 128]\n\t"
        "ldp	x10, x11, [%[mp], 144]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 128]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 144]\n\t"
        "ldp	x4, x5, [%[m], 160]\n\t"
        "ldp	x6, x7, [%[m], 176]\n\t"
        "ldp	x8, x9, [%[mp], 160]\n\t"
        "ldp	x10, x11, [%[mp], 176]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 160]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 176]\n\t"
        : [a] "+r" (a), [mp] "+r" (mp)
        : [m] "r" (m)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x10", "x8", "x9", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27"
    );

}

/* Multiply two Montgomery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montgomery form.
 * b   Second number to multiply in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_3072_mont_mul_24(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_3072_mul_24(r, a, b);
    sp_3072_mont_reduce_24(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_3072_mont_sqr_24(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_3072_sqr_24(r, a);
    sp_3072_mont_reduce_24(r, m, mp);
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not copying.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static sp_digit sp_3072_cond_sub_24(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	x8, #0\n\t"
        "1:\n\t"
        "subs	%[c], xzr, %[c]\n\t"
        "ldr	x4, [%[a], x8]\n\t"
        "ldr	x5, [%[b], x8]\n\t"
        "and	x5, x5, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "csetm	%[c], cc\n\t"
        "str	x4, [%[r], x8]\n\t"
        "add	x8, x8, #8\n\t"
        "cmp	x8, 192\n\t"
        "b.lt	1b\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x6", "x5", "x7", "x8", "x9", "x10", "x11", "x12"
    );

    return c;
#else
    __asm__ __volatile__ (

        "ldp	x5, x7, [%[b], 0]\n\t"
        "ldp	x11, x12, [%[b], 16]\n\t"
        "ldp	x4, x6, [%[a], 0]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 16]\n\t"
        "and	x7, x7, %[m]\n\t"
        "subs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 0]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 16]\n\t"
        "ldp	x5, x7, [%[b], 32]\n\t"
        "ldp	x11, x12, [%[b], 48]\n\t"
        "ldp	x4, x6, [%[a], 32]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 48]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 32]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 48]\n\t"
        "ldp	x5, x7, [%[b], 64]\n\t"
        "ldp	x11, x12, [%[b], 80]\n\t"
        "ldp	x4, x6, [%[a], 64]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 80]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 64]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 80]\n\t"
        "ldp	x5, x7, [%[b], 96]\n\t"
        "ldp	x11, x12, [%[b], 112]\n\t"
        "ldp	x4, x6, [%[a], 96]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 112]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 96]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 112]\n\t"
        "ldp	x5, x7, [%[b], 128]\n\t"
        "ldp	x11, x12, [%[b], 144]\n\t"
        "ldp	x4, x6, [%[a], 128]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 144]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 128]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 144]\n\t"
        "ldp	x5, x7, [%[b], 160]\n\t"
        "ldp	x11, x12, [%[b], 176]\n\t"
        "ldp	x4, x6, [%[a], 160]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 176]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 160]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 176]\n\t"
        "csetm	%[r], cc\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x6", "x5", "x7", "x8", "x9", "x10", "x11", "x12"
    );

    return (sp_digit)r;
#endif /* WOLFSSL_SP_SMALL */
}

/* Mul a by digit b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision digit.
 */
static void sp_3072_mul_d_24(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "# A[0] * B\n\t"
        "ldr	x8, [%[a]]\n\t"
        "mul	x5, %[b], x8\n\t"
        "umulh	x3, %[b], x8\n\t"
        "mov	x4, xzr\n\t"
        "str	x5, [%[r]]\n\t"
        "mov	x5, xzr\n\t"
        "mov	x9, #8\n\t"
        "1:\n\t"
        "ldr	x8, [%[a], x9]\n\t"
        "mul	x6, %[b], x8\n\t"
        "umulh	x7, %[b], x8\n\t"
        "adds	x3, x3, x6\n\t"
        "adcs	x4, x4, x7\n\t"
        "adc	x5, xzr, xzr\n\t"
        "str	x3, [%[r], x9]\n\t"
        "mov	x3, x4\n\t"
        "mov	x4, x5\n\t"
        "mov	x5, #0\n\t"
        "add	x9, x9, #8\n\t"
        "cmp	x9, 192\n\t"
        "b.lt	1b\n\t"
        "str	x3, [%[r], 192]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );
#else
    __asm__ __volatile__ (
        "# A[0] * B\n\t"
        "ldp	x9, x10, [%[a]]\n\t"
        "mul	x3, %[b], x9\n\t"
        "umulh	x4, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "# A[1] * B\n\t"
        "str	x3, [%[r]]\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[2] * B\n\t"
        "ldp	x9, x10, [%[a], 16]\n\t"
        "str	x4, [%[r], 8]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[3] * B\n\t"
        "str	x5, [%[r], 16]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[4] * B\n\t"
        "ldp	x9, x10, [%[a], 32]\n\t"
        "str	x3, [%[r], 24]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[5] * B\n\t"
        "str	x4, [%[r], 32]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[6] * B\n\t"
        "ldp	x9, x10, [%[a], 48]\n\t"
        "str	x5, [%[r], 40]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[7] * B\n\t"
        "str	x3, [%[r], 48]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[8] * B\n\t"
        "ldp	x9, x10, [%[a], 64]\n\t"
        "str	x4, [%[r], 56]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[9] * B\n\t"
        "str	x5, [%[r], 64]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[10] * B\n\t"
        "ldp	x9, x10, [%[a], 80]\n\t"
        "str	x3, [%[r], 72]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[11] * B\n\t"
        "str	x4, [%[r], 80]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[12] * B\n\t"
        "ldp	x9, x10, [%[a], 96]\n\t"
        "str	x5, [%[r], 88]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[13] * B\n\t"
        "str	x3, [%[r], 96]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[14] * B\n\t"
        "ldp	x9, x10, [%[a], 112]\n\t"
        "str	x4, [%[r], 104]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[15] * B\n\t"
        "str	x5, [%[r], 112]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[16] * B\n\t"
        "ldp	x9, x10, [%[a], 128]\n\t"
        "str	x3, [%[r], 120]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[17] * B\n\t"
        "str	x4, [%[r], 128]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[18] * B\n\t"
        "ldp	x9, x10, [%[a], 144]\n\t"
        "str	x5, [%[r], 136]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[19] * B\n\t"
        "str	x3, [%[r], 144]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[20] * B\n\t"
        "ldp	x9, x10, [%[a], 160]\n\t"
        "str	x4, [%[r], 152]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[21] * B\n\t"
        "str	x5, [%[r], 160]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[22] * B\n\t"
        "ldp	x9, x10, [%[a], 176]\n\t"
        "str	x3, [%[r], 168]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[23] * B\n\t"
        "str	x4, [%[r], 176]\n\t"
        "mul	x6, %[b], x10\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "str	x5, [%[r], 184]\n\t"
        "str	x3, [%[r], 192]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );
#endif
}

/* Divide the double width number (d1|d0) by the divisor. (d1|d0 / div)
 *
 * Assumes divisor has higest bit set.
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The divisor.
 * returns the result of the division.
 */
static sp_digit div_3072_word_24(sp_digit d1, sp_digit d0, sp_digit div)
{
    __asm__ __volatile__ (
        "lsr	x8, %[div], 32\n\t"
        "add	x5, x8, 1\n\t"

        "udiv	x3, %[d1], x5\n\t"
        "lsl	x7, %[div], 32\n\t"
        "movz	x9, #1, lsl 32\n\t"
        "lsl	x6, x3, 32\n\t"
        "mul	x4, %[div], x6\n\t"
        "umulh	x3, %[div], x6\n\t"
        "subs	%[d0], %[d0], x4\n\t"
        "sbc	%[d1], %[d1], x3\n\t"

        "cmp	%[d1], x5\n\t"
        "cset	x9, ge\n\t"
        "csetm	x10, ge\n\t"
        "lsl	x9, x9, #32\n\t"
        "and	x7, x7, x10\n\t"
        "and	x8, x8, x10\n\t"
        "subs	%[d0], %[d0], x7\n\t"
        "add	x6, x6, x9\n\t"
        "sbc	%[d1], %[d1], x8\n\t"

        "extr	x3, %[d1], %[d0], 32\n\t"

        "udiv	x3, x3, x5\n\t"
        "add	x6, x6, x3\n\t"
        "mul	x4, %[div], x3\n\t"
        "umulh	x3, %[div], x3\n\t"
        "subs	%[d0], %[d0], x4\n\t"
        "sbc	%[d1], %[d1], x3\n\t"

        "extr	x3, %[d1], %[d0], 32\n\t"

        "udiv   x3, x3, x5\n\t"
        "add    x6, x6, x3\n\t"
        "mul    x4, %[div], x3\n\t"
        "sub    %[d0], %[d0], x4\n\t"

        "udiv	x3, %[d0], %[div]\n\t"
        "add	%[d1], x6, x3\n\t"

        : [d1] "+r" (d1), [d0] "+r" (d0)
        : [div] "r" (div)
        : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return d1;
}

/* AND m into each word of a and store in r.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * m  Mask to AND against each digit.
 */
static void sp_3072_mask_24(sp_digit* r, const sp_digit* a, sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<24; i++) {
        r[i] = a[i] & m;
    }
#else
    int i;

    for (i = 0; i < 24; i += 8) {
        r[i+0] = a[i+0] & m;
        r[i+1] = a[i+1] & m;
        r[i+2] = a[i+2] & m;
        r[i+3] = a[i+3] & m;
        r[i+4] = a[i+4] & m;
        r[i+5] = a[i+5] & m;
        r[i+6] = a[i+6] & m;
        r[i+7] = a[i+7] & m;
    }
#endif
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_int64 sp_3072_cmp_24(const sp_digit* a, const sp_digit* b)
{
#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "mov	x3, #0\n\t"
        "mov	x2, #-1\n\t"
        "mov	x10, #24\n\t"
        "add	%[a], %[a], #176\n\t"
        "add	%[b], %[b], #176\n\t"
        "1:\n\t"
        "ldp	x6, x7, [%[a]], -16\n\t"
        "ldp	x8, x9, [%[b]], -16\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x10, x10, #2\n\t"
        "b.ne	1b\n\t"
        "cmp	x2, #0\n\t"
        "cset	%[a], eq\n\t"
        "orr	%[a], %[a], x3\n\t"
        : [a] "+r" (a), [b] "+r" (b)
        :
        : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );
#else
    __asm__ __volatile__ (
        "mov	x3, #0\n\t"
        "mov	x2, #-1\n\t"
        "ldp	x6, x7, [%[a], 176]\n\t"
        "ldp	x8, x9, [%[b], 176]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 160]\n\t"
        "ldp	x8, x9, [%[b], 160]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 144]\n\t"
        "ldp	x8, x9, [%[b], 144]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 128]\n\t"
        "ldp	x8, x9, [%[b], 128]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 112]\n\t"
        "ldp	x8, x9, [%[b], 112]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 96]\n\t"
        "ldp	x8, x9, [%[b], 96]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 80]\n\t"
        "ldp	x8, x9, [%[b], 80]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 64]\n\t"
        "ldp	x8, x9, [%[b], 64]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 48]\n\t"
        "ldp	x8, x9, [%[b], 48]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 32]\n\t"
        "ldp	x8, x9, [%[b], 32]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 16]\n\t"
        "ldp	x8, x9, [%[b], 16]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 0]\n\t"
        "ldp	x8, x9, [%[b], 0]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "cmp	x2, #0\n\t"
        "cset	%[a], eq\n\t"
        "orr	%[a], %[a], x3\n\t"
        : [a] "+r" (a)
        : [b] "r" (b)
        : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );
#endif

    return (sp_int64)a;
}

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_3072_div_24(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    sp_digit t1[48], t2[25];
    sp_digit div, r1;
    int i;

    (void)m;

    div = d[23];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 24);
    for (i = 23; i >= 0; i--) {
        sp_digit hi = t1[24 + i] - (t1[24 + i] == div);
        r1 = div_3072_word_24(hi, t1[24 + i - 1], div);

        sp_3072_mul_d_24(t2, d, r1);
        t1[24 + i] += sp_3072_sub_in_place_24(&t1[i], t2);
        t1[24 + i] -= t2[24];
        sp_3072_mask_24(t2, d, t1[24 + i]);
        t1[24 + i] += sp_3072_add_24(&t1[i], &t1[i], t2);
        sp_3072_mask_24(t2, d, t1[24 + i]);
        t1[24 + i] += sp_3072_add_24(&t1[i], &t1[i], t2);
    }

    r1 = sp_3072_cmp_24(t1, d) >= 0;
    sp_3072_cond_sub_24(r, t1, d, (sp_digit)0 - r1);

    return MP_OKAY;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_3072_mod_24(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_3072_div_24(a, m, NULL, r);
}

#ifdef WOLFSSL_SP_SMALL
/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success.
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even or exponent is 0.
 */
static int sp_3072_mod_exp_24(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[16 * 48];
    sp_digit* t[16];
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<16; i++) {
            t[i] = td + i * 48;
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_24(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 24U);
        if (reduceA != 0) {
            err = sp_3072_mod_24(t[1] + 24, a, m);
            if (err == MP_OKAY) {
                err = sp_3072_mod_24(t[1], t[1], m);
            }
        }
        else {
            XMEMCPY(t[1] + 24, a, sizeof(sp_digit) * 24);
            err = sp_3072_mod_24(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_3072_mont_sqr_24(t[ 2], t[ 1], m, mp);
        sp_3072_mont_mul_24(t[ 3], t[ 2], t[ 1], m, mp);
        sp_3072_mont_sqr_24(t[ 4], t[ 2], m, mp);
        sp_3072_mont_mul_24(t[ 5], t[ 3], t[ 2], m, mp);
        sp_3072_mont_sqr_24(t[ 6], t[ 3], m, mp);
        sp_3072_mont_mul_24(t[ 7], t[ 4], t[ 3], m, mp);
        sp_3072_mont_sqr_24(t[ 8], t[ 4], m, mp);
        sp_3072_mont_mul_24(t[ 9], t[ 5], t[ 4], m, mp);
        sp_3072_mont_sqr_24(t[10], t[ 5], m, mp);
        sp_3072_mont_mul_24(t[11], t[ 6], t[ 5], m, mp);
        sp_3072_mont_sqr_24(t[12], t[ 6], m, mp);
        sp_3072_mont_mul_24(t[13], t[ 7], t[ 6], m, mp);
        sp_3072_mont_sqr_24(t[14], t[ 7], m, mp);
        sp_3072_mont_mul_24(t[15], t[ 8], t[ 7], m, mp);

        i = (bits - 1) / 64;
        n = e[i--];
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        c -= bits % 4;
        if (c == 64) {
            c = 60;
        }
        if (c < 0) {
            /* Number of bits in top word is less than number needed. */
            c = -c;
            y = (byte)(n << c);
            n = e[i--];
            y |= (byte)(n >> (64 - c));
            n <<= c;
            c = 64 - c;
        }
        else if (c == 0) {
            /* All bits in top word used. */
            y = (byte)n;
        }
        else {
            y = (byte)(n >> c);
            n <<= 64 - c;
        }
        XMEMCPY(r, t[y], sizeof(sp_digit) * 24);
        for (; i>=0 || c>=4; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 60);
                n <<= 4;
                c = 60;
            }
            else if (c < 4) {
                y = (byte)(n >> 60);
                n = e[i--];
                c = 4 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }
            else {
                y = (byte)((n >> 60) & 0xf);
                n <<= 4;
                c -= 4;
            }

            sp_3072_mont_sqr_24(r, r, m, mp);
            sp_3072_mont_sqr_24(r, r, m, mp);
            sp_3072_mont_sqr_24(r, r, m, mp);
            sp_3072_mont_sqr_24(r, r, m, mp);

            sp_3072_mont_mul_24(r, r, t[y], m, mp);
        }

        XMEMSET(&r[24], 0, sizeof(sp_digit) * 24U);
        sp_3072_mont_reduce_24(r, m, mp);

        mask = 0 - (sp_3072_cmp_24(r, m) >= 0);
        sp_3072_cond_sub_24(r, r, m, mask);
    }


    return err;
}
#else
/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success.
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even or exponent is 0.
 */
static int sp_3072_mod_exp_24(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[32 * 48];
    sp_digit* t[32];
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<32; i++) {
            t[i] = td + i * 48;
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_24(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 24U);
        if (reduceA != 0) {
            err = sp_3072_mod_24(t[1] + 24, a, m);
            if (err == MP_OKAY) {
                err = sp_3072_mod_24(t[1], t[1], m);
            }
        }
        else {
            XMEMCPY(t[1] + 24, a, sizeof(sp_digit) * 24);
            err = sp_3072_mod_24(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_3072_mont_sqr_24(t[ 2], t[ 1], m, mp);
        sp_3072_mont_mul_24(t[ 3], t[ 2], t[ 1], m, mp);
        sp_3072_mont_sqr_24(t[ 4], t[ 2], m, mp);
        sp_3072_mont_mul_24(t[ 5], t[ 3], t[ 2], m, mp);
        sp_3072_mont_sqr_24(t[ 6], t[ 3], m, mp);
        sp_3072_mont_mul_24(t[ 7], t[ 4], t[ 3], m, mp);
        sp_3072_mont_sqr_24(t[ 8], t[ 4], m, mp);
        sp_3072_mont_mul_24(t[ 9], t[ 5], t[ 4], m, mp);
        sp_3072_mont_sqr_24(t[10], t[ 5], m, mp);
        sp_3072_mont_mul_24(t[11], t[ 6], t[ 5], m, mp);
        sp_3072_mont_sqr_24(t[12], t[ 6], m, mp);
        sp_3072_mont_mul_24(t[13], t[ 7], t[ 6], m, mp);
        sp_3072_mont_sqr_24(t[14], t[ 7], m, mp);
        sp_3072_mont_mul_24(t[15], t[ 8], t[ 7], m, mp);
        sp_3072_mont_sqr_24(t[16], t[ 8], m, mp);
        sp_3072_mont_mul_24(t[17], t[ 9], t[ 8], m, mp);
        sp_3072_mont_sqr_24(t[18], t[ 9], m, mp);
        sp_3072_mont_mul_24(t[19], t[10], t[ 9], m, mp);
        sp_3072_mont_sqr_24(t[20], t[10], m, mp);
        sp_3072_mont_mul_24(t[21], t[11], t[10], m, mp);
        sp_3072_mont_sqr_24(t[22], t[11], m, mp);
        sp_3072_mont_mul_24(t[23], t[12], t[11], m, mp);
        sp_3072_mont_sqr_24(t[24], t[12], m, mp);
        sp_3072_mont_mul_24(t[25], t[13], t[12], m, mp);
        sp_3072_mont_sqr_24(t[26], t[13], m, mp);
        sp_3072_mont_mul_24(t[27], t[14], t[13], m, mp);
        sp_3072_mont_sqr_24(t[28], t[14], m, mp);
        sp_3072_mont_mul_24(t[29], t[15], t[14], m, mp);
        sp_3072_mont_sqr_24(t[30], t[15], m, mp);
        sp_3072_mont_mul_24(t[31], t[16], t[15], m, mp);

        i = (bits - 1) / 64;
        n = e[i--];
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        c -= bits % 5;
        if (c == 64) {
            c = 59;
        }
        if (c < 0) {
            /* Number of bits in top word is less than number needed. */
            c = -c;
            y = (byte)(n << c);
            n = e[i--];
            y |= (byte)(n >> (64 - c));
            n <<= c;
            c = 64 - c;
        }
        else if (c == 0) {
            /* All bits in top word used. */
            y = (byte)n;
        }
        else {
            y = (byte)(n >> c);
            n <<= 64 - c;
        }
        XMEMCPY(r, t[y], sizeof(sp_digit) * 24);
        for (; i>=0 || c>=5; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 59);
                n <<= 5;
                c = 59;
            }
            else if (c < 5) {
                y = (byte)(n >> 59);
                n = e[i--];
                c = 5 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }
            else {
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c -= 5;
            }

            sp_3072_mont_sqr_24(r, r, m, mp);
            sp_3072_mont_sqr_24(r, r, m, mp);
            sp_3072_mont_sqr_24(r, r, m, mp);
            sp_3072_mont_sqr_24(r, r, m, mp);
            sp_3072_mont_sqr_24(r, r, m, mp);

            sp_3072_mont_mul_24(r, r, t[y], m, mp);
        }

        XMEMSET(&r[24], 0, sizeof(sp_digit) * 24U);
        sp_3072_mont_reduce_24(r, m, mp);

        mask = 0 - (sp_3072_cmp_24(r, m) >= 0);
        sp_3072_cond_sub_24(r, r, m, mask);
    }


    return err;
}
#endif /* WOLFSSL_SP_SMALL */

#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) | WOLFSSL_HAVE_SP_DH */

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 3072 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_3072_mont_norm_48(sp_digit* r, const sp_digit* m)
{
    XMEMSET(r, 0, sizeof(sp_digit) * 48);

    /* r = 2^n mod m */
    sp_3072_sub_in_place_48(r, m);
}

#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) | WOLFSSL_HAVE_SP_DH */
/* Reduce the number back to 3072 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
SP_NOINLINE static void sp_3072_mont_reduce_48(sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    __asm__ __volatile__ (
        "ldp	x11, x12, [%[a], 0]\n\t"
        "ldp	x13, x14, [%[a], 16]\n\t"
        "ldp	x15, x16, [%[a], 32]\n\t"
        "ldp	x17, x19, [%[a], 48]\n\t"
        "ldp	x20, x21, [%[a], 64]\n\t"
        "ldp	x22, x23, [%[a], 80]\n\t"
        "# No carry yet\n\t"
        "mov	x3, xzr\n\t"
        "# i = 0..47\n\t"
        "mov	x4, 48\n\t"
        "\n1:\n\t"
        "# mu = a[i] * mp\n\t"
        "mul	x10, %[mp], x11\n\t"
        "ldp	x24, x25, [%[m], 0]\n\t"
        "ldp	x26, x27, [%[m], 16]\n\t"
        "# a[i+0] += m[0] * mu\n\t"
        "mul	x5, x24, x10\n\t"
        "umulh	x6, x24, x10\n\t"
        "# a[i+1] += m[1] * mu\n\t"
        "adds	x11, x11, x5\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x11, x12, x5\n\t"
        "# a[i+2] += m[2] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x11, x11, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x12, x13, x5\n\t"
        "# a[i+3] += m[3] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x12, x12, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x13, x14, x5\n\t"
        "ldp	x24, x25, [%[m], 32]\n\t"
        "ldp	x26, x27, [%[m], 48]\n\t"
        "# a[i+4] += m[4] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x13, x13, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x14, x15, x5\n\t"
        "# a[i+5] += m[5] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x14, x14, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x15, x16, x5\n\t"
        "# a[i+6] += m[6] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x15, x15, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x16, x17, x5\n\t"
        "# a[i+7] += m[7] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x16, x16, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x17, x19, x5\n\t"
        "ldp	x24, x25, [%[m], 64]\n\t"
        "ldp	x26, x27, [%[m], 80]\n\t"
        "# a[i+8] += m[8] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x17, x17, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x19, x20, x5\n\t"
        "# a[i+9] += m[9] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x19, x19, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x20, x21, x5\n\t"
        "# a[i+10] += m[10] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x20, x20, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x21, x22, x5\n\t"
        "# a[i+11] += m[11] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x21, x21, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x22, x23, x5\n\t"
        "ldp	x24, x25, [%[m], 96]\n\t"
        "ldp	x26, x27, [%[m], 112]\n\t"
        "# a[i+12] += m[12] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x22, x22, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "ldr	x23, [%[a], 96]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x23, x23, x5\n\t"
        "# a[i+13] += m[13] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x23, x23, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "ldp	x8, x9, [%[a], 104]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+14] += m[14] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 104]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+15] += m[15] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 112]\n\t"
        "ldp	x8, x9, [%[a], 120]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 128]\n\t"
        "ldp	x26, x27, [%[m], 144]\n\t"
        "# a[i+16] += m[16] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 120]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+17] += m[17] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 128]\n\t"
        "ldp	x8, x9, [%[a], 136]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+18] += m[18] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 136]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+19] += m[19] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 144]\n\t"
        "ldp	x8, x9, [%[a], 152]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 160]\n\t"
        "ldp	x26, x27, [%[m], 176]\n\t"
        "# a[i+20] += m[20] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 152]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+21] += m[21] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 160]\n\t"
        "ldp	x8, x9, [%[a], 168]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+22] += m[22] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 168]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+23] += m[23] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 176]\n\t"
        "ldp	x8, x9, [%[a], 184]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 192]\n\t"
        "ldp	x26, x27, [%[m], 208]\n\t"
        "# a[i+24] += m[24] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 184]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+25] += m[25] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 192]\n\t"
        "ldp	x8, x9, [%[a], 200]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+26] += m[26] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 200]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+27] += m[27] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 208]\n\t"
        "ldp	x8, x9, [%[a], 216]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 224]\n\t"
        "ldp	x26, x27, [%[m], 240]\n\t"
        "# a[i+28] += m[28] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 216]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+29] += m[29] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 224]\n\t"
        "ldp	x8, x9, [%[a], 232]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+30] += m[30] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 232]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+31] += m[31] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 240]\n\t"
        "ldp	x8, x9, [%[a], 248]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 256]\n\t"
        "ldp	x26, x27, [%[m], 272]\n\t"
        "# a[i+32] += m[32] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 248]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+33] += m[33] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 256]\n\t"
        "ldp	x8, x9, [%[a], 264]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+34] += m[34] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 264]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+35] += m[35] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 272]\n\t"
        "ldp	x8, x9, [%[a], 280]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 288]\n\t"
        "ldp	x26, x27, [%[m], 304]\n\t"
        "# a[i+36] += m[36] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 280]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+37] += m[37] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 288]\n\t"
        "ldp	x8, x9, [%[a], 296]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+38] += m[38] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 296]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+39] += m[39] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 304]\n\t"
        "ldp	x8, x9, [%[a], 312]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 320]\n\t"
        "ldp	x26, x27, [%[m], 336]\n\t"
        "# a[i+40] += m[40] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 312]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+41] += m[41] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 320]\n\t"
        "ldp	x8, x9, [%[a], 328]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+42] += m[42] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 328]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+43] += m[43] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 336]\n\t"
        "ldp	x8, x9, [%[a], 344]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 352]\n\t"
        "ldp	x26, x27, [%[m], 368]\n\t"
        "# a[i+44] += m[44] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 344]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+45] += m[45] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 352]\n\t"
        "ldp	x8, x9, [%[a], 360]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+46] += m[46] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 360]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+47] += m[47] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 368]\n\t"
        "umulh	x7, x27, x10\n\t"
        "ldp	x8, x9, [%[a], 376]\n\t"
        "adds	x5, x5, x6\n\t"
        "adcs	x7, x7, x3\n\t"
        "cset	x3, cs\n\t"
        "adds	x8, x8, x5\n\t"
        "str	x8, [%[a], 376]\n\t"
        "adcs	x9, x9, x7\n\t"
        "str	x9, [%[a], 384]\n\t"
        "adc	x3, x3, xzr\n\t"
        "subs	x4, x4, 1\n\t"
        "add	%[a], %[a], 8\n\t"
        "b.ne	1b\n\t"
        "# Create mask\n\t"
        "neg	x3, x3\n\t"
        "mov   %[mp], %[a]\n\t"
        "sub	%[a], %[a], 384\n\t"
        "# Subtract masked modulus\n\t"
        "ldp	x4, x5, [%[m], 0]\n\t"
        "ldp	x6, x7, [%[m], 16]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "subs	x11, x11, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x12, x12, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x13, x13, x6\n\t"
        "stp	x11, x12, [%[a], 0]\n\t"
        "sbcs	x14, x14, x7\n\t"
        "stp	x13, x14, [%[a], 16]\n\t"
        "ldp	x4, x5, [%[m], 32]\n\t"
        "ldp	x6, x7, [%[m], 48]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x15, x15, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x16, x16, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x17, x17, x6\n\t"
        "stp	x15, x16, [%[a], 32]\n\t"
        "sbcs	x19, x19, x7\n\t"
        "stp	x17, x19, [%[a], 48]\n\t"
        "ldp	x4, x5, [%[m], 64]\n\t"
        "ldp	x6, x7, [%[m], 80]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x20, x20, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x21, x21, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x22, x22, x6\n\t"
        "stp	x20, x21, [%[a], 64]\n\t"
        "sbcs	x23, x23, x7\n\t"
        "stp	x22, x23, [%[a], 80]\n\t"
        "ldp	x4, x5, [%[m], 96]\n\t"
        "ldp	x6, x7, [%[m], 112]\n\t"
        "ldp	x8, x9, [%[mp], 96]\n\t"
        "ldp	x10, x11, [%[mp], 112]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 96]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 112]\n\t"
        "ldp	x4, x5, [%[m], 128]\n\t"
        "ldp	x6, x7, [%[m], 144]\n\t"
        "ldp	x8, x9, [%[mp], 128]\n\t"
        "ldp	x10, x11, [%[mp], 144]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 128]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 144]\n\t"
        "ldp	x4, x5, [%[m], 160]\n\t"
        "ldp	x6, x7, [%[m], 176]\n\t"
        "ldp	x8, x9, [%[mp], 160]\n\t"
        "ldp	x10, x11, [%[mp], 176]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 160]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 176]\n\t"
        "ldp	x4, x5, [%[m], 192]\n\t"
        "ldp	x6, x7, [%[m], 208]\n\t"
        "ldp	x8, x9, [%[mp], 192]\n\t"
        "ldp	x10, x11, [%[mp], 208]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 192]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 208]\n\t"
        "ldp	x4, x5, [%[m], 224]\n\t"
        "ldp	x6, x7, [%[m], 240]\n\t"
        "ldp	x8, x9, [%[mp], 224]\n\t"
        "ldp	x10, x11, [%[mp], 240]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 224]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 240]\n\t"
        "ldp	x4, x5, [%[m], 256]\n\t"
        "ldp	x6, x7, [%[m], 272]\n\t"
        "ldp	x8, x9, [%[mp], 256]\n\t"
        "ldp	x10, x11, [%[mp], 272]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 256]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 272]\n\t"
        "ldp	x4, x5, [%[m], 288]\n\t"
        "ldp	x6, x7, [%[m], 304]\n\t"
        "ldp	x8, x9, [%[mp], 288]\n\t"
        "ldp	x10, x11, [%[mp], 304]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 288]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 304]\n\t"
        "ldp	x4, x5, [%[m], 320]\n\t"
        "ldp	x6, x7, [%[m], 336]\n\t"
        "ldp	x8, x9, [%[mp], 320]\n\t"
        "ldp	x10, x11, [%[mp], 336]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 320]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 336]\n\t"
        "ldp	x4, x5, [%[m], 352]\n\t"
        "ldp	x6, x7, [%[m], 368]\n\t"
        "ldp	x8, x9, [%[mp], 352]\n\t"
        "ldp	x10, x11, [%[mp], 368]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 352]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 368]\n\t"
        : [a] "+r" (a), [mp] "+r" (mp)
        : [m] "r" (m)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x10", "x8", "x9", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27"
    );

}

/* Multiply two Montgomery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montgomery form.
 * b   Second number to multiply in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_3072_mont_mul_48(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_3072_mul_48(r, a, b);
    sp_3072_mont_reduce_48(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_3072_mont_sqr_48(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_3072_sqr_48(r, a);
    sp_3072_mont_reduce_48(r, m, mp);
}

#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_3072_sub_48(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "add	x11, %[a], 384\n\t"
        "\n1:\n\t"
        "subs	%[c], xzr, %[c]\n\t"
        "ldp	x3, x4, [%[a]], #16\n\t"
        "ldp	x5, x6, [%[a]], #16\n\t"
        "ldp	x7, x8, [%[b]], #16\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x9, x10, [%[b]], #16\n\t"
        "sbcs	x4, x4, x8\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r]], #16\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r]], #16\n\t"
        "csetm	%[c], cc\n\t"
        "cmp	%[a], x11\n\t"
        "b.ne	1b\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    return c;
}

#else
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_3072_sub_48(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x7, x8, [%[b], 0]\n\t"
        "subs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 16]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldp	x3, x4, [%[a], 32]\n\t"
        "ldp	x7, x8, [%[b], 32]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 48]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 48]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 32]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 48]\n\t"
        "ldp	x3, x4, [%[a], 64]\n\t"
        "ldp	x7, x8, [%[b], 64]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 80]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 80]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 64]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 80]\n\t"
        "ldp	x3, x4, [%[a], 96]\n\t"
        "ldp	x7, x8, [%[b], 96]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 112]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 112]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 96]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 112]\n\t"
        "ldp	x3, x4, [%[a], 128]\n\t"
        "ldp	x7, x8, [%[b], 128]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 144]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 144]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 128]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 144]\n\t"
        "ldp	x3, x4, [%[a], 160]\n\t"
        "ldp	x7, x8, [%[b], 160]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 176]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 176]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 160]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 176]\n\t"
        "ldp	x3, x4, [%[a], 192]\n\t"
        "ldp	x7, x8, [%[b], 192]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 208]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 208]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 192]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 208]\n\t"
        "ldp	x3, x4, [%[a], 224]\n\t"
        "ldp	x7, x8, [%[b], 224]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 240]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 240]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 224]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 240]\n\t"
        "ldp	x3, x4, [%[a], 256]\n\t"
        "ldp	x7, x8, [%[b], 256]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 272]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 272]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 256]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 272]\n\t"
        "ldp	x3, x4, [%[a], 288]\n\t"
        "ldp	x7, x8, [%[b], 288]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 304]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 304]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 288]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 304]\n\t"
        "ldp	x3, x4, [%[a], 320]\n\t"
        "ldp	x7, x8, [%[b], 320]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 336]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 336]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 320]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 336]\n\t"
        "ldp	x3, x4, [%[a], 352]\n\t"
        "ldp	x7, x8, [%[b], 352]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 368]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 368]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 352]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 368]\n\t"
        "csetm	%[r], cc\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return (sp_digit)r;
}

#endif /* WOLFSSL_SP_SMALL */
/* Divide the double width number (d1|d0) by the divisor. (d1|d0 / div)
 *
 * Assumes divisor has higest bit set.
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The divisor.
 * returns the result of the division.
 */
static sp_digit div_3072_word_48_cond(sp_digit d1, sp_digit d0, sp_digit div)
{
    __asm__ __volatile__ (
        "lsr	x8, %[div], 32\n\t"
        "add	x5, x8, 1\n\t"

        "udiv	x3, %[d1], x5\n\t"
        "lsl	x7, %[div], 32\n\t"
        "movz	x9, #1, lsl 32\n\t"
        "lsl	x6, x3, 32\n\t"
        "mul	x4, %[div], x6\n\t"
        "umulh	x3, %[div], x6\n\t"
        "subs	%[d0], %[d0], x4\n\t"
        "sbc	%[d1], %[d1], x3\n\t"

        "cmp	%[d1], x5\n\t"
        "b.lt	1f\n\t"
        "subs	%[d0], %[d0], x7\n\t"
        "add	x6, x6, x9\n\t"
        "sbc	%[d1], %[d1], x8\n\t"
        "1:\n\t"

        "extr	x3, %[d1], %[d0], 32\n\t"

        "udiv	x3, x3, x5\n\t"
        "add	x6, x6, x3\n\t"
        "mul	x4, %[div], x3\n\t"
        "umulh	x3, %[div], x3\n\t"
        "subs	%[d0], %[d0], x4\n\t"
        "sbc	%[d1], %[d1], x3\n\t"

        "extr	x3, %[d1], %[d0], 32\n\t"

        "cmp	x3, x5\n\t"
        "b.lt	2f\n\t"
        "udiv   x3, x3, x5\n\t"
        "add    x6, x6, x3\n\t"
        "mul    x4, %[div], x3\n\t"
        "sub    %[d0], %[d0], x4\n\t"
        "2:\n\t"

        "udiv	x3, %[d0], %[div]\n\t"
        "add	%[d1], x6, x3\n\t"

        : [d1] "+r" (d1), [d0] "+r" (d0)
        : [div] "r" (div)
        : "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );

    return d1;
}

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_3072_div_48_cond(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    sp_digit t1[96], t2[49];
    sp_digit div, r1;
    int i;

    (void)m;

    div = d[47];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 48);
    for (i = 47; i >= 0; i--) {
        if (t1[48 + i] == div) {
            r1 = SP_DIGIT_MAX;
        }
        else {
            r1 = div_3072_word_48_cond(t1[48 + i], t1[48 + i - 1], div);
        }

        sp_3072_mul_d_48(t2, d, r1);
        t1[48 + i] += sp_3072_sub_in_place_48(&t1[i], t2);
        t1[48 + i] -= t2[48];
        if (t1[48 + i] != 0) {
            t1[48 + i] += sp_3072_add_48(&t1[i], &t1[i], d);
            if (t1[48 + i] != 0)
                t1[48 + i] += sp_3072_add_48(&t1[i], &t1[i], d);
        }
    }

    for (i = 47; i > 0; i--) {
        if (t1[i] != d[i])
            break;
    }
    if (t1[i] >= d[i]) {
        sp_3072_sub_48(r, t1, d);
    }
    else {
        XMEMCPY(r, t1, sizeof(*t1) * 48);
    }

    return MP_OKAY;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_3072_mod_48_cond(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_3072_div_48_cond(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not copying.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static sp_digit sp_3072_cond_sub_48(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	x8, #0\n\t"
        "1:\n\t"
        "subs	%[c], xzr, %[c]\n\t"
        "ldr	x4, [%[a], x8]\n\t"
        "ldr	x5, [%[b], x8]\n\t"
        "and	x5, x5, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "csetm	%[c], cc\n\t"
        "str	x4, [%[r], x8]\n\t"
        "add	x8, x8, #8\n\t"
        "cmp	x8, 384\n\t"
        "b.lt	1b\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x6", "x5", "x7", "x8", "x9", "x10", "x11", "x12"
    );

    return c;
#else
    __asm__ __volatile__ (

        "ldp	x5, x7, [%[b], 0]\n\t"
        "ldp	x11, x12, [%[b], 16]\n\t"
        "ldp	x4, x6, [%[a], 0]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 16]\n\t"
        "and	x7, x7, %[m]\n\t"
        "subs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 0]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 16]\n\t"
        "ldp	x5, x7, [%[b], 32]\n\t"
        "ldp	x11, x12, [%[b], 48]\n\t"
        "ldp	x4, x6, [%[a], 32]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 48]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 32]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 48]\n\t"
        "ldp	x5, x7, [%[b], 64]\n\t"
        "ldp	x11, x12, [%[b], 80]\n\t"
        "ldp	x4, x6, [%[a], 64]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 80]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 64]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 80]\n\t"
        "ldp	x5, x7, [%[b], 96]\n\t"
        "ldp	x11, x12, [%[b], 112]\n\t"
        "ldp	x4, x6, [%[a], 96]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 112]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 96]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 112]\n\t"
        "ldp	x5, x7, [%[b], 128]\n\t"
        "ldp	x11, x12, [%[b], 144]\n\t"
        "ldp	x4, x6, [%[a], 128]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 144]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 128]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 144]\n\t"
        "ldp	x5, x7, [%[b], 160]\n\t"
        "ldp	x11, x12, [%[b], 176]\n\t"
        "ldp	x4, x6, [%[a], 160]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 176]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 160]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 176]\n\t"
        "ldp	x5, x7, [%[b], 192]\n\t"
        "ldp	x11, x12, [%[b], 208]\n\t"
        "ldp	x4, x6, [%[a], 192]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 208]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 192]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 208]\n\t"
        "ldp	x5, x7, [%[b], 224]\n\t"
        "ldp	x11, x12, [%[b], 240]\n\t"
        "ldp	x4, x6, [%[a], 224]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 240]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 224]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 240]\n\t"
        "ldp	x5, x7, [%[b], 256]\n\t"
        "ldp	x11, x12, [%[b], 272]\n\t"
        "ldp	x4, x6, [%[a], 256]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 272]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 256]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 272]\n\t"
        "ldp	x5, x7, [%[b], 288]\n\t"
        "ldp	x11, x12, [%[b], 304]\n\t"
        "ldp	x4, x6, [%[a], 288]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 304]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 288]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 304]\n\t"
        "ldp	x5, x7, [%[b], 320]\n\t"
        "ldp	x11, x12, [%[b], 336]\n\t"
        "ldp	x4, x6, [%[a], 320]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 336]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 320]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 336]\n\t"
        "ldp	x5, x7, [%[b], 352]\n\t"
        "ldp	x11, x12, [%[b], 368]\n\t"
        "ldp	x4, x6, [%[a], 352]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 368]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 352]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 368]\n\t"
        "csetm	%[r], cc\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x6", "x5", "x7", "x8", "x9", "x10", "x11", "x12"
    );

    return (sp_digit)r;
#endif /* WOLFSSL_SP_SMALL */
}

/* Divide the double width number (d1|d0) by the divisor. (d1|d0 / div)
 *
 * Assumes divisor has higest bit set.
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The divisor.
 * returns the result of the division.
 */
static sp_digit div_3072_word_48(sp_digit d1, sp_digit d0, sp_digit div)
{
    __asm__ __volatile__ (
        "lsr	x8, %[div], 32\n\t"
        "add	x5, x8, 1\n\t"

        "udiv	x3, %[d1], x5\n\t"
        "lsl	x7, %[div], 32\n\t"
        "movz	x9, #1, lsl 32\n\t"
        "lsl	x6, x3, 32\n\t"
        "mul	x4, %[div], x6\n\t"
        "umulh	x3, %[div], x6\n\t"
        "subs	%[d0], %[d0], x4\n\t"
        "sbc	%[d1], %[d1], x3\n\t"

        "cmp	%[d1], x5\n\t"
        "cset	x9, ge\n\t"
        "csetm	x10, ge\n\t"
        "lsl	x9, x9, #32\n\t"
        "and	x7, x7, x10\n\t"
        "and	x8, x8, x10\n\t"
        "subs	%[d0], %[d0], x7\n\t"
        "add	x6, x6, x9\n\t"
        "sbc	%[d1], %[d1], x8\n\t"

        "extr	x3, %[d1], %[d0], 32\n\t"

        "udiv	x3, x3, x5\n\t"
        "add	x6, x6, x3\n\t"
        "mul	x4, %[div], x3\n\t"
        "umulh	x3, %[div], x3\n\t"
        "subs	%[d0], %[d0], x4\n\t"
        "sbc	%[d1], %[d1], x3\n\t"

        "extr	x3, %[d1], %[d0], 32\n\t"

        "udiv   x3, x3, x5\n\t"
        "add    x6, x6, x3\n\t"
        "mul    x4, %[div], x3\n\t"
        "sub    %[d0], %[d0], x4\n\t"

        "udiv	x3, %[d0], %[div]\n\t"
        "add	%[d1], x6, x3\n\t"

        : [d1] "+r" (d1), [d0] "+r" (d0)
        : [div] "r" (div)
        : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return d1;
}

/* AND m into each word of a and store in r.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * m  Mask to AND against each digit.
 */
static void sp_3072_mask_48(sp_digit* r, const sp_digit* a, sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<48; i++) {
        r[i] = a[i] & m;
    }
#else
    int i;

    for (i = 0; i < 48; i += 8) {
        r[i+0] = a[i+0] & m;
        r[i+1] = a[i+1] & m;
        r[i+2] = a[i+2] & m;
        r[i+3] = a[i+3] & m;
        r[i+4] = a[i+4] & m;
        r[i+5] = a[i+5] & m;
        r[i+6] = a[i+6] & m;
        r[i+7] = a[i+7] & m;
    }
#endif
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_int64 sp_3072_cmp_48(const sp_digit* a, const sp_digit* b)
{
#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "mov	x3, #0\n\t"
        "mov	x2, #-1\n\t"
        "mov	x10, #48\n\t"
        "add	%[a], %[a], #368\n\t"
        "add	%[b], %[b], #368\n\t"
        "1:\n\t"
        "ldp	x6, x7, [%[a]], -16\n\t"
        "ldp	x8, x9, [%[b]], -16\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x10, x10, #2\n\t"
        "b.ne	1b\n\t"
        "cmp	x2, #0\n\t"
        "cset	%[a], eq\n\t"
        "orr	%[a], %[a], x3\n\t"
        : [a] "+r" (a), [b] "+r" (b)
        :
        : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );
#else
    __asm__ __volatile__ (
        "mov	x3, #0\n\t"
        "mov	x2, #-1\n\t"
        "ldp	x6, x7, [%[a], 368]\n\t"
        "ldp	x8, x9, [%[b], 368]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 352]\n\t"
        "ldp	x8, x9, [%[b], 352]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 336]\n\t"
        "ldp	x8, x9, [%[b], 336]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 320]\n\t"
        "ldp	x8, x9, [%[b], 320]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 304]\n\t"
        "ldp	x8, x9, [%[b], 304]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 288]\n\t"
        "ldp	x8, x9, [%[b], 288]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 272]\n\t"
        "ldp	x8, x9, [%[b], 272]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 256]\n\t"
        "ldp	x8, x9, [%[b], 256]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 240]\n\t"
        "ldp	x8, x9, [%[b], 240]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 224]\n\t"
        "ldp	x8, x9, [%[b], 224]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 208]\n\t"
        "ldp	x8, x9, [%[b], 208]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 192]\n\t"
        "ldp	x8, x9, [%[b], 192]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 176]\n\t"
        "ldp	x8, x9, [%[b], 176]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 160]\n\t"
        "ldp	x8, x9, [%[b], 160]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 144]\n\t"
        "ldp	x8, x9, [%[b], 144]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 128]\n\t"
        "ldp	x8, x9, [%[b], 128]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 112]\n\t"
        "ldp	x8, x9, [%[b], 112]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 96]\n\t"
        "ldp	x8, x9, [%[b], 96]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 80]\n\t"
        "ldp	x8, x9, [%[b], 80]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 64]\n\t"
        "ldp	x8, x9, [%[b], 64]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 48]\n\t"
        "ldp	x8, x9, [%[b], 48]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 32]\n\t"
        "ldp	x8, x9, [%[b], 32]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 16]\n\t"
        "ldp	x8, x9, [%[b], 16]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 0]\n\t"
        "ldp	x8, x9, [%[b], 0]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "cmp	x2, #0\n\t"
        "cset	%[a], eq\n\t"
        "orr	%[a], %[a], x3\n\t"
        : [a] "+r" (a)
        : [b] "r" (b)
        : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );
#endif

    return (sp_int64)a;
}

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_3072_div_48(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    sp_digit t1[96], t2[49];
    sp_digit div, r1;
    int i;

    (void)m;

    div = d[47];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 48);
    for (i = 47; i >= 0; i--) {
        sp_digit hi = t1[48 + i] - (t1[48 + i] == div);
        r1 = div_3072_word_48(hi, t1[48 + i - 1], div);

        sp_3072_mul_d_48(t2, d, r1);
        t1[48 + i] += sp_3072_sub_in_place_48(&t1[i], t2);
        t1[48 + i] -= t2[48];
        sp_3072_mask_48(t2, d, t1[48 + i]);
        t1[48 + i] += sp_3072_add_48(&t1[i], &t1[i], t2);
        sp_3072_mask_48(t2, d, t1[48 + i]);
        t1[48 + i] += sp_3072_add_48(&t1[i], &t1[i], t2);
    }

    r1 = sp_3072_cmp_48(t1, d) >= 0;
    sp_3072_cond_sub_48(r, t1, d, (sp_digit)0 - r1);

    return MP_OKAY;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_3072_mod_48(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_3072_div_48(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || \
                                                     defined(WOLFSSL_HAVE_SP_DH)
#ifdef WOLFSSL_SP_SMALL
/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success.
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even or exponent is 0.
 */
static int sp_3072_mod_exp_48(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[8 * 96];
    sp_digit* t[8];
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<8; i++) {
            t[i] = td + i * 96;
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_48(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 48U);
        if (reduceA != 0) {
            err = sp_3072_mod_48(t[1] + 48, a, m);
            if (err == MP_OKAY) {
                err = sp_3072_mod_48(t[1], t[1], m);
            }
        }
        else {
            XMEMCPY(t[1] + 48, a, sizeof(sp_digit) * 48);
            err = sp_3072_mod_48(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_3072_mont_sqr_48(t[ 2], t[ 1], m, mp);
        sp_3072_mont_mul_48(t[ 3], t[ 2], t[ 1], m, mp);
        sp_3072_mont_sqr_48(t[ 4], t[ 2], m, mp);
        sp_3072_mont_mul_48(t[ 5], t[ 3], t[ 2], m, mp);
        sp_3072_mont_sqr_48(t[ 6], t[ 3], m, mp);
        sp_3072_mont_mul_48(t[ 7], t[ 4], t[ 3], m, mp);

        i = (bits - 1) / 64;
        n = e[i--];
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        c -= bits % 3;
        if (c == 64) {
            c = 61;
        }
        if (c < 0) {
            /* Number of bits in top word is less than number needed. */
            c = -c;
            y = (byte)(n << c);
            n = e[i--];
            y |= (byte)(n >> (64 - c));
            n <<= c;
            c = 64 - c;
        }
        else if (c == 0) {
            /* All bits in top word used. */
            y = (byte)n;
        }
        else {
            y = (byte)(n >> c);
            n <<= 64 - c;
        }
        XMEMCPY(r, t[y], sizeof(sp_digit) * 48);
        for (; i>=0 || c>=3; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 61);
                n <<= 3;
                c = 61;
            }
            else if (c < 3) {
                y = (byte)(n >> 61);
                n = e[i--];
                c = 3 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }
            else {
                y = (byte)((n >> 61) & 0x7);
                n <<= 3;
                c -= 3;
            }

            sp_3072_mont_sqr_48(r, r, m, mp);
            sp_3072_mont_sqr_48(r, r, m, mp);
            sp_3072_mont_sqr_48(r, r, m, mp);

            sp_3072_mont_mul_48(r, r, t[y], m, mp);
        }

        XMEMSET(&r[48], 0, sizeof(sp_digit) * 48U);
        sp_3072_mont_reduce_48(r, m, mp);

        mask = 0 - (sp_3072_cmp_48(r, m) >= 0);
        sp_3072_cond_sub_48(r, r, m, mask);
    }


    return err;
}
#else
/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success.
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even or exponent is 0.
 */
static int sp_3072_mod_exp_48(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[16 * 96];
    sp_digit* t[16];
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<16; i++) {
            t[i] = td + i * 96;
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_48(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 48U);
        if (reduceA != 0) {
            err = sp_3072_mod_48(t[1] + 48, a, m);
            if (err == MP_OKAY) {
                err = sp_3072_mod_48(t[1], t[1], m);
            }
        }
        else {
            XMEMCPY(t[1] + 48, a, sizeof(sp_digit) * 48);
            err = sp_3072_mod_48(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_3072_mont_sqr_48(t[ 2], t[ 1], m, mp);
        sp_3072_mont_mul_48(t[ 3], t[ 2], t[ 1], m, mp);
        sp_3072_mont_sqr_48(t[ 4], t[ 2], m, mp);
        sp_3072_mont_mul_48(t[ 5], t[ 3], t[ 2], m, mp);
        sp_3072_mont_sqr_48(t[ 6], t[ 3], m, mp);
        sp_3072_mont_mul_48(t[ 7], t[ 4], t[ 3], m, mp);
        sp_3072_mont_sqr_48(t[ 8], t[ 4], m, mp);
        sp_3072_mont_mul_48(t[ 9], t[ 5], t[ 4], m, mp);
        sp_3072_mont_sqr_48(t[10], t[ 5], m, mp);
        sp_3072_mont_mul_48(t[11], t[ 6], t[ 5], m, mp);
        sp_3072_mont_sqr_48(t[12], t[ 6], m, mp);
        sp_3072_mont_mul_48(t[13], t[ 7], t[ 6], m, mp);
        sp_3072_mont_sqr_48(t[14], t[ 7], m, mp);
        sp_3072_mont_mul_48(t[15], t[ 8], t[ 7], m, mp);

        i = (bits - 1) / 64;
        n = e[i--];
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        c -= bits % 4;
        if (c == 64) {
            c = 60;
        }
        if (c < 0) {
            /* Number of bits in top word is less than number needed. */
            c = -c;
            y = (byte)(n << c);
            n = e[i--];
            y |= (byte)(n >> (64 - c));
            n <<= c;
            c = 64 - c;
        }
        else if (c == 0) {
            /* All bits in top word used. */
            y = (byte)n;
        }
        else {
            y = (byte)(n >> c);
            n <<= 64 - c;
        }
        XMEMCPY(r, t[y], sizeof(sp_digit) * 48);
        for (; i>=0 || c>=4; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 60);
                n <<= 4;
                c = 60;
            }
            else if (c < 4) {
                y = (byte)(n >> 60);
                n = e[i--];
                c = 4 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }
            else {
                y = (byte)((n >> 60) & 0xf);
                n <<= 4;
                c -= 4;
            }

            sp_3072_mont_sqr_48(r, r, m, mp);
            sp_3072_mont_sqr_48(r, r, m, mp);
            sp_3072_mont_sqr_48(r, r, m, mp);
            sp_3072_mont_sqr_48(r, r, m, mp);

            sp_3072_mont_mul_48(r, r, t[y], m, mp);
        }

        XMEMSET(&r[48], 0, sizeof(sp_digit) * 48U);
        sp_3072_mont_reduce_48(r, m, mp);

        mask = 0 - (sp_3072_cmp_48(r, m) >= 0);
        sp_3072_cond_sub_48(r, r, m, mask);
    }


    return err;
}
#endif /* WOLFSSL_SP_SMALL */
#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || WOLFSSL_HAVE_SP_DH */

#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || WOLFSSL_HAVE_SP_DH */
#ifdef WOLFSSL_HAVE_SP_RSA
/* RSA public key operation.
 *
 * in      Array of bytes representing the number to exponentiate, base.
 * inLen   Number of bytes in base.
 * em      Public exponent.
 * mm      Modulus.
 * out     Buffer to hold big-endian bytes of exponentiation result.
 *         Must be at least 384 bytes long.
 * outLen  Number of bytes in result.
 * returns 0 on success, MP_TO_E when the outLen is too small, MP_READ_E when
 * an array is too long and MEMORY_E when dynamic memory allocation fails.
 */
int sp_RsaPublic_3072(const byte* in, word32 inLen, const mp_int* em,
    const mp_int* mm, byte* out, word32* outLen)
{
    sp_digit a[48 * 5];
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit *ah = NULL;
    sp_digit e[1] = {0};
    int err = MP_OKAY;

    if (*outLen < 384) {
        err = MP_TO_E;
    }
    else if (mp_count_bits(em) > 64 || inLen > 384 ||
                                                     mp_count_bits(mm) != 3072) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mm)) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        ah = a + 48;
        r = a + 48 * 2;
        m = r + 48 * 2;

        sp_3072_from_bin(ah, 48, in, inLen);
#if DIGIT_BIT >= 64
        e[0] = em->dp[0];
#else
        e[0] = em->dp[0];
        if (em->used > 1) {
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
        }
#endif
        if (e[0] == 0) {
            err = MP_EXPTMOD_E;
        }
    }
    if (err == MP_OKAY) {
        sp_3072_from_mp(m, 48, mm);

        if (e[0] == 0x10001) {
            int i;
            sp_digit mp;

            sp_3072_mont_setup(m, &mp);

            /* Convert to Montgomery form. */
            XMEMSET(a, 0, sizeof(sp_digit) * 48);
            err = sp_3072_mod_48_cond(r, a, m);
            /* Montgomery form: r = a.R mod m */

            if (err == MP_OKAY) {
                /* r = a ^ 0x10000 => r = a squared 16 times */
                for (i = 15; i >= 0; i--) {
                    sp_3072_mont_sqr_48(r, r, m, mp);
                }
                /* mont_red(r.R.R) = (r.R.R / R) mod m = r.R mod m
                 * mont_red(r.R * a) = (r.R.a / R) mod m = r.a mod m
                 */
                sp_3072_mont_mul_48(r, r, ah, m, mp);

                for (i = 47; i > 0; i--) {
                    if (r[i] != m[i]) {
                        break;
                    }
                }
                if (r[i] >= m[i]) {
                    sp_3072_sub_in_place_48(r, m);
                }
            }
        }
        else if (e[0] == 0x3) {
            if (err == MP_OKAY) {
                sp_3072_sqr_48(r, ah);
                err = sp_3072_mod_48_cond(r, r, m);
            }
            if (err == MP_OKAY) {
                sp_3072_mul_48(r, ah, r);
                err = sp_3072_mod_48_cond(r, r, m);
            }
        }
        else {
            int i;
            sp_digit mp;

            sp_3072_mont_setup(m, &mp);

            /* Convert to Montgomery form. */
            XMEMSET(a, 0, sizeof(sp_digit) * 48);
            err = sp_3072_mod_48_cond(a, a, m);

            if (err == MP_OKAY) {
                for (i = 63; i >= 0; i--) {
                    if (e[0] >> i) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 48);
                for (i--; i >= 0; i--) {
                    sp_3072_mont_sqr_48(r, r, m, mp);
                    if (((e[0] >> i) & 1) == 1) {
                        sp_3072_mont_mul_48(r, r, a, m, mp);
                    }
                }
                XMEMSET(&r[48], 0, sizeof(sp_digit) * 48);
                sp_3072_mont_reduce_48(r, m, mp);

                for (i = 47; i > 0; i--) {
                    if (r[i] != m[i]) {
                        break;
                    }
                }
                if (r[i] >= m[i]) {
                    sp_3072_sub_in_place_48(r, m);
                }
            }
        }
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_48(r, out);
        *outLen = 384;
    }


    return err;
}

#ifndef WOLFSSL_RSA_PUBLIC_ONLY
#ifdef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static sp_digit sp_3072_cond_add_24(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	x8, #0\n\t"
        "1:\n\t"
        "adds	%[c], %[c], #-1\n\t"
        "ldr	x4, [%[a], x8]\n\t"
        "ldr	x5, [%[b], x8]\n\t"
        "and	x5, x5, %[m]\n\t"
        "adcs	x4, x4, x5\n\t"
        "cset	%[c], cs\n\t"
        "str	x4, [%[r], x8]\n\t"
        "add	x8, x8, #8\n\t"
        "cmp	x8, 192\n\t"
        "b.lt	1b\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x5", "x8", "x9", "x10", "x11", "x12"
    );

    return c;
}
#endif /* WOLFSSL_SP_SMALL */

/* RSA private key operation.
 *
 * in      Array of bytes representing the number to exponentiate, base.
 * inLen   Number of bytes in base.
 * dm      Private exponent.
 * pm      First prime.
 * qm      Second prime.
 * dpm     First prime's CRT exponent.
 * dqm     Second prime's CRT exponent.
 * qim     Inverse of second prime mod p.
 * mm      Modulus.
 * out     Buffer to hold big-endian bytes of exponentiation result.
 *         Must be at least 384 bytes long.
 * outLen  Number of bytes in result.
 * returns 0 on success, MP_TO_E when the outLen is too small, MP_READ_E when
 * an array is too long and MEMORY_E when dynamic memory allocation fails.
 */
int sp_RsaPrivate_3072(const byte* in, word32 inLen, const mp_int* dm,
    const mp_int* pm, const mp_int* qm, const mp_int* dpm, const mp_int* dqm,
    const mp_int* qim, const mp_int* mm, byte* out, word32* outLen)
{
#if defined(SP_RSA_PRIVATE_EXP_D) || defined(RSA_LOW_MEM)
    sp_digit  d[48 * 4];
    sp_digit* a = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;

    (void)pm;
    (void)qm;
    (void)dpm;
    (void)dqm;
    (void)qim;

    if (*outLen < 384U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(dm) > 3072) {
           err = MP_READ_E;
        }
        else if (inLen > 384) {
            err = MP_READ_E;
        }
        else if (mp_count_bits(mm) != 3072) {
            err = MP_READ_E;
        }
        else if (mp_iseven(mm)) {
            err = MP_VAL;
        }
    }


    if (err == MP_OKAY) {
        a = d + 48;
        m = a + 96;
        r = a;

        sp_3072_from_bin(a, 48, in, inLen);
        sp_3072_from_mp(d, 48, dm);
        sp_3072_from_mp(m, 48, mm);
        err = sp_3072_mod_exp_48(r, a, d, 3072, m, 0);
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_48(r, out);
        *outLen = 384;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 48);
    }

    return err;
#else
    sp_digit a[24 * 11];
    sp_digit* p = NULL;
    sp_digit* q = NULL;
    sp_digit* dp = NULL;
    sp_digit* tmpa = NULL;
    sp_digit* tmpb = NULL;
    sp_digit* r = NULL;
    sp_digit* qi = NULL;
    sp_digit* dq = NULL;
    sp_digit c;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 384) {
        err = MP_TO_E;
    }
    else if (inLen > 384 || mp_count_bits(mm) != 3072) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mm)) {
        err = MP_VAL;
    }
    else if (mp_iseven(pm)) {
        err = MP_VAL;
    }
    else if (mp_iseven(qm)) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        p = a + 48 * 2;
        q = p + 24;
        qi = dq = dp = q + 24;
        tmpa = qi + 24;
        tmpb = tmpa + 48;
        r = a;

        sp_3072_from_bin(a, 48, in, inLen);
        sp_3072_from_mp(p, 24, pm);
        sp_3072_from_mp(q, 24, qm);
        sp_3072_from_mp(dp, 24, dpm);

        err = sp_3072_mod_exp_24(tmpa, a, dp, 1536, p, 1);
    }
    if (err == MP_OKAY) {
        sp_3072_from_mp(dq, 24, dqm);
        err = sp_3072_mod_exp_24(tmpb, a, dq, 1536, q, 1);
    }

    if (err == MP_OKAY) {
        c = sp_3072_sub_in_place_24(tmpa, tmpb);
        c += sp_3072_cond_add_24(tmpa, tmpa, p, c);
        sp_3072_cond_add_24(tmpa, tmpa, p, c);

        sp_3072_from_mp(qi, 24, qim);
        sp_3072_mul_24(tmpa, tmpa, qi);
        err = sp_3072_mod_24(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_3072_mul_24(tmpa, q, tmpa);
        XMEMSET(&tmpb[24], 0, sizeof(sp_digit) * 24);
        sp_3072_add_48(r, tmpb, tmpa);

        sp_3072_to_bin_48(r, out);
        *outLen = 384;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 24 * 11);
    }
#endif /* SP_RSA_PRIVATE_EXP_D || RSA_LOW_MEM */
    return err;
}
#endif /* WOLFSSL_RSA_PUBLIC_ONLY */
#endif /* WOLFSSL_HAVE_SP_RSA */
#if defined(WOLFSSL_HAVE_SP_DH) || (defined(WOLFSSL_HAVE_SP_RSA) && \
                                              !defined(WOLFSSL_RSA_PUBLIC_ONLY))
/* Convert an array of sp_digit to an mp_int.
 *
 * a  A single precision integer.
 * r  A multi-precision integer.
 */
static int sp_3072_to_mp(const sp_digit* a, mp_int* r)
{
    int err;

    err = mp_grow(r, (3072 + DIGIT_BIT - 1) / DIGIT_BIT);
    if (err == MP_OKAY) { /*lint !e774 case where err is always MP_OKAY*/
#if DIGIT_BIT == 64
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 48);
        r->used = 48;
        mp_clamp(r);
#elif DIGIT_BIT < 64
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 48; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 64) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 64 - s;
        }
        r->used = (3072 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 48; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 64 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 64 - s;
            }
            else {
                s += 64;
            }
        }
        r->used = (3072 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#endif
    }

    return err;
}

/* Perform the modular exponentiation for Diffie-Hellman.
 *
 * base  Base. MP integer.
 * exp   Exponent. MP integer.
 * mod   Modulus. MP integer.
 * res   Result. MP integer.
 * returns 0 on success, MP_READ_E if there are too many bytes in an array
 * and MEMORY_E if memory allocation fails.
 */
int sp_ModExp_3072(const mp_int* base, const mp_int* exp, const mp_int* mod,
    mp_int* res)
{
    int err = MP_OKAY;
    sp_digit b[96];
    sp_digit e[48];
    sp_digit m[48];
    sp_digit* r = b;
    int expBits = mp_count_bits(exp);

    if (mp_count_bits(base) > 3072) {
        err = MP_READ_E;
    }
    else if (expBits > 3072) {
        err = MP_READ_E;
    }
    else if (mp_count_bits(mod) != 3072) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mod)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        sp_3072_from_mp(b, 48, base);
        sp_3072_from_mp(e, 48, exp);
        sp_3072_from_mp(m, 48, mod);

        err = sp_3072_mod_exp_48(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_3072_to_mp(r, res);
    }

    XMEMSET(e, 0, sizeof(e));

    return err;
}

#ifdef WOLFSSL_HAVE_SP_DH

#ifdef HAVE_FFDHE_3072
static void sp_3072_lshift_48(sp_digit* r, const sp_digit* a, byte n)
{
    word64 n64 = n;
    __asm__ __volatile__ (
        "mov	x6, 63\n\t"
        "sub	x6, x6, %[n]\n\t"
        "ldr	x3, [%[a], 376]\n\t"
        "lsr	x4, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x4, x4, x6\n\t"
        "ldr	x2, [%[a], 368]\n\t"
        "str	x4, [%[r], 384]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 360]\n\t"
        "str	x3, [%[r], 376]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 352]\n\t"
        "str	x2, [%[r], 368]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 344]\n\t"
        "str	x4, [%[r], 360]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 336]\n\t"
        "str	x3, [%[r], 352]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 328]\n\t"
        "str	x2, [%[r], 344]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 320]\n\t"
        "str	x4, [%[r], 336]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 312]\n\t"
        "str	x3, [%[r], 328]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 304]\n\t"
        "str	x2, [%[r], 320]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 296]\n\t"
        "str	x4, [%[r], 312]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 288]\n\t"
        "str	x3, [%[r], 304]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 280]\n\t"
        "str	x2, [%[r], 296]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 272]\n\t"
        "str	x4, [%[r], 288]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 264]\n\t"
        "str	x3, [%[r], 280]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 256]\n\t"
        "str	x2, [%[r], 272]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 248]\n\t"
        "str	x4, [%[r], 264]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 240]\n\t"
        "str	x3, [%[r], 256]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 232]\n\t"
        "str	x2, [%[r], 248]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 224]\n\t"
        "str	x4, [%[r], 240]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 216]\n\t"
        "str	x3, [%[r], 232]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 208]\n\t"
        "str	x2, [%[r], 224]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 200]\n\t"
        "str	x4, [%[r], 216]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 192]\n\t"
        "str	x3, [%[r], 208]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 184]\n\t"
        "str	x2, [%[r], 200]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 176]\n\t"
        "str	x4, [%[r], 192]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 168]\n\t"
        "str	x3, [%[r], 184]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 160]\n\t"
        "str	x2, [%[r], 176]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 152]\n\t"
        "str	x4, [%[r], 168]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 144]\n\t"
        "str	x3, [%[r], 160]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 136]\n\t"
        "str	x2, [%[r], 152]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 128]\n\t"
        "str	x4, [%[r], 144]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 120]\n\t"
        "str	x3, [%[r], 136]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 112]\n\t"
        "str	x2, [%[r], 128]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 104]\n\t"
        "str	x4, [%[r], 120]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 96]\n\t"
        "str	x3, [%[r], 112]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 88]\n\t"
        "str	x2, [%[r], 104]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 80]\n\t"
        "str	x4, [%[r], 96]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 72]\n\t"
        "str	x3, [%[r], 88]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 64]\n\t"
        "str	x2, [%[r], 80]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 56]\n\t"
        "str	x4, [%[r], 72]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 48]\n\t"
        "str	x3, [%[r], 64]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 40]\n\t"
        "str	x2, [%[r], 56]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 32]\n\t"
        "str	x4, [%[r], 48]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 24]\n\t"
        "str	x3, [%[r], 40]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 16]\n\t"
        "str	x2, [%[r], 32]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 8]\n\t"
        "str	x4, [%[r], 24]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 0]\n\t"
        "str	x3, [%[r], 16]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "stp	x4, x2, [%[r]]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [n] "r" (n64)
        : "memory", "x2", "x3", "x4", "x5", "x6"
    );
}

/* Modular exponentiate 2 to the e mod m. (r = 2^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success.
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even.
 */
static int sp_3072_mod_exp_2_48(sp_digit* r, const sp_digit* e, int bits,
        const sp_digit* m)
{
    sp_digit td[145];
    sp_digit* norm = NULL;
    sp_digit* tmp = NULL;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit o;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        tmp = td + 96;

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_48(norm, m);

        i = (bits - 1) / 64;
        n = e[i--];
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        c -= bits % 6;
        if (c == 64) {
            c = 58;
        }
        if (c < 0) {
            /* Number of bits in top word is less than number needed. */
            c = -c;
            y = (byte)(n << c);
            n = e[i--];
            y |= (byte)(n >> (64 - c));
            n <<= c;
            c = 64 - c;
        }
        else if (c == 0) {
            /* All bits in top word used. */
            y = (byte)n;
        }
        else {
            y = (byte)(n >> c);
            n <<= 64 - c;
        }
        sp_3072_lshift_48(r, norm, y);
        for (; i>=0 || c>=6; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 58);
                n <<= 6;
                c = 58;
            }
            else if (c < 6) {
                y = (byte)(n >> 58);
                n = e[i--];
                c = 6 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }
            else {
                y = (byte)((n >> 58) & 0x3f);
                n <<= 6;
                c -= 6;
            }

            sp_3072_mont_sqr_48(r, r, m, mp);
            sp_3072_mont_sqr_48(r, r, m, mp);
            sp_3072_mont_sqr_48(r, r, m, mp);
            sp_3072_mont_sqr_48(r, r, m, mp);
            sp_3072_mont_sqr_48(r, r, m, mp);
            sp_3072_mont_sqr_48(r, r, m, mp);

            sp_3072_lshift_48(r, r, y);
            sp_3072_mul_d_48(tmp, norm, r[48]);
            r[48] = 0;
            o = sp_3072_add_48(r, r, tmp);
            sp_3072_cond_sub_48(r, r, m, (sp_digit)0 - o);
        }

        XMEMSET(&r[48], 0, sizeof(sp_digit) * 48U);
        sp_3072_mont_reduce_48(r, m, mp);

        mask = 0 - (sp_3072_cmp_48(r, m) >= 0);
        sp_3072_cond_sub_48(r, r, m, mask);
    }


    return err;
}
#endif /* HAVE_FFDHE_3072 */

/* Perform the modular exponentiation for Diffie-Hellman.
 *
 * base     Base.
 * exp      Array of bytes that is the exponent.
 * expLen   Length of data, in bytes, in exponent.
 * mod      Modulus.
 * out      Buffer to hold big-endian bytes of exponentiation result.
 *          Must be at least 384 bytes long.
 * outLen   Length, in bytes, of exponentiation result.
 * returns 0 on success, MP_READ_E if there are too many bytes in an array
 * and MEMORY_E if memory allocation fails.
 */
int sp_DhExp_3072(const mp_int* base, const byte* exp, word32 expLen,
    const mp_int* mod, byte* out, word32* outLen)
{
    int err = MP_OKAY;
    sp_digit b[96];
    sp_digit e[48];
    sp_digit m[48];
    sp_digit* r = b;
    word32 i;

    if (mp_count_bits(base) > 3072) {
        err = MP_READ_E;
    }
    else if (expLen > 384) {
        err = MP_READ_E;
    }
    else if (mp_count_bits(mod) != 3072) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mod)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        sp_3072_from_mp(b, 48, base);
        sp_3072_from_bin(e, 48, exp, expLen);
        sp_3072_from_mp(m, 48, mod);

    #ifdef HAVE_FFDHE_3072
        if (base->used == 1 && base->dp[0] == 2 && m[47] == (sp_digit)-1)
            err = sp_3072_mod_exp_2_48(r, e, expLen * 8, m);
        else
    #endif
            err = sp_3072_mod_exp_48(r, b, e, expLen * 8, m, 0);

    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_48(r, out);
        *outLen = 384;
        for (i=0; i<384 && out[i] == 0; i++) {
            /* Search for first non-zero. */
        }
        *outLen -= i;
        XMEMMOVE(out, out + i, *outLen);

    }

    XMEMSET(e, 0, sizeof(e));

    return err;
}
#endif /* WOLFSSL_HAVE_SP_DH */

/* Perform the modular exponentiation for Diffie-Hellman.
 *
 * base  Base. MP integer.
 * exp   Exponent. MP integer.
 * mod   Modulus. MP integer.
 * res   Result. MP integer.
 * returns 0 on success, MP_READ_E if there are too many bytes in an array
 * and MEMORY_E if memory allocation fails.
 */
int sp_ModExp_1536(const mp_int* base, const mp_int* exp, const mp_int* mod,
    mp_int* res)
{
    int err = MP_OKAY;
    sp_digit b[48];
    sp_digit e[24];
    sp_digit m[24];
    sp_digit* r = b;
    int expBits = mp_count_bits(exp);

    if (mp_count_bits(base) > 1536) {
        err = MP_READ_E;
    }
    else if (expBits > 1536) {
        err = MP_READ_E;
    }
    else if (mp_count_bits(mod) != 1536) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mod)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        sp_3072_from_mp(b, 24, base);
        sp_3072_from_mp(e, 24, exp);
        sp_3072_from_mp(m, 24, mod);

        err = sp_3072_mod_exp_24(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 24, 0, sizeof(*r) * 24U);
        err = sp_3072_to_mp(r, res);
        res->used = mod->used;
        mp_clamp(res);
    }

    XMEMSET(e, 0, sizeof(e));

    return err;
}

#endif /* WOLFSSL_HAVE_SP_DH | (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) */

#endif /* !WOLFSSL_SP_NO_3072 */

#ifdef WOLFSSL_SP_4096
/* Read big endian unsigned byte array into r.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  Byte array.
 * n  Number of bytes in array to read.
 */
static void sp_4096_from_bin(sp_digit* r, int size, const byte* a, int n)
{
    sp_int64 nl = n;
    sp_int64 size8 = size * 8;

    __asm__ __volatile__ (
        "add	x4, %[a], %[n]\n\t"
        "mov	x5, %[r]\n\t"
        "sub	x4, x4, 8\n\t"
        "subs	x6, %[n], 8\n\t"
        "mov	x7, xzr\n\t"
        "blt	2f\n\t"
        /* Put in mulitples of 8 bytes. */
        "1:\n\t"
        "ldr	x8, [x4], -8\n\t"
        "subs	x6, x6, 8\n\t"
        "rev	x8, x8\n\t"
        "str	x8, [x5], 8\n\t"
        "add	x7, x7, 8\n\t"
        "b.ge	1b\n\t"
        "2:\n\t"
        "cmp	x6, -7\n\t"
        "b.lt	20f\n\t"
        /* Put in less than 8 bytes. */
        "str	xzr, [x5]\n\t"
        "add	x7, x7, 8\n\t"
        "add	x4, x4, 7\n\t"
        "b.eq	17f\n\t"
        "cmp	x6, -5\n\t"
        "b.lt	16f\n\t"
        "b.eq	15f\n\t"
        "cmp	x6, -3\n\t"
        "b.lt	14f\n\t"
        "b.eq	13f\n\t"
        "cmp	x6, -2\n\t"
        "b.eq	12f\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "12:\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "13:\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "14:\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "15:\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "16:\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "17:\n\t"
        "ldrb	w8, [x4], -1\n\t"
        "strb	w8, [x5], 1\n\t"
        "20:\n\t"
        "add	x5, %[r], x7\n\t"
        "subs	x7, %[size], x7\n\t"
        "b.eq	30f\n\t"
        /* Zero out remaining words. */
        "21:\n\t"
        "subs	x7, x7, 8\n\t"
        "str	xzr, [x5], 8\n\t"
        "b.gt	21b\n\t"
        "30:\n\t"
        :
        : [r] "r" (r), [size] "r" (size8), [a] "r" (a), [n] "r" (nl)
        : "memory", "x4", "x5", "x6", "x7", "x8"
    );
}

/* Convert an mp_int to an array of sp_digit.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  A multi-precision integer.
 */
static void sp_4096_from_mp(sp_digit* r, int size, const mp_int* a)
{
#if DIGIT_BIT == 64
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 64
    int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0xffffffffffffffffl;
        s = 64U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 64U) <= (word32)DIGIT_BIT) {
            s += 64U;
            r[j] &= 0xffffffffffffffffl;
            if (j + 1 >= size) {
                break;
            }
            if (s < (word32)DIGIT_BIT) {
                /* lint allow cast of mismatch word32 and mp_digit */
                r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
            }
            else {
                r[++j] = (sp_digit)0;
            }
        }
        s = (word32)DIGIT_BIT - s;
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
#else
    int i;
    int j = 0;
    int s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i]) << s;
        if (s + DIGIT_BIT >= 64) {
            r[j] &= 0xffffffffffffffffl;
            if (j + 1 >= size) {
                break;
            }
            s = 64 - s;
            if (s == DIGIT_BIT) {
                r[++j] = 0;
                s = 0;
            }
            else {
                r[++j] = a->dp[i] >> s;
                s = DIGIT_BIT - s;
            }
        }
        else {
            s += DIGIT_BIT;
        }
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
#endif
}

/* Write r as big endian to byte array.
 * Fixed length number of bytes written: 512
 *
 * r  A single precision integer.
 * a  Byte array.
 */
static void sp_4096_to_bin_64(sp_digit* r, byte* a)
{
    int i;
    int j = 0;

    for (i = 63; i >= 0; i--, j += 8) {
        __asm__ __volatile__ (
            "ldr	x4, [%[r]]\n\t"
            "rev	x4, x4\n\t"
            "str	x4, [%[a]]\n\t"
            :
            : [r] "r" (r + i), [a] "r" (a + j)
            : "memory", "x4"
        );
    }
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && (!defined(WOLFSSL_RSA_PUBLIC_ONLY) || !defined(WOLFSSL_SP_SMALL))) || defined(WOLFSSL_HAVE_SP_DH)
/* Normalize the values in each word to 64.
 *
 * a  Array of sp_digit to normalize.
 */
#define sp_4096_norm_64(a)

#endif /* (WOLFSSL_HAVE_SP_RSA && (!WOLFSSL_RSA_PUBLIC_ONLY || !WOLFSSL_SP_SMALL)) || WOLFSSL_HAVE_SP_DH */
/* Normalize the values in each word to 64.
 *
 * a  Array of sp_digit to normalize.
 */
#define sp_4096_norm_64(a)

#ifndef WOLFSSL_SP_SMALL
/* Add digit to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static void sp_4096_add_word_32(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "adds	x3, x3, %[b]\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldp	x3, x4, [%[a], 32]\n\t"
        "ldp	x5, x6, [%[a], 48]\n\t"
        "adcs	x3, x3, xzr\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 32]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 48]\n\t"
        "ldp	x3, x4, [%[a], 64]\n\t"
        "ldp	x5, x6, [%[a], 80]\n\t"
        "adcs	x3, x3, xzr\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 64]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 80]\n\t"
        "ldp	x3, x4, [%[a], 96]\n\t"
        "ldp	x5, x6, [%[a], 112]\n\t"
        "adcs	x3, x3, xzr\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 96]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 112]\n\t"
        "ldp	x3, x4, [%[a], 128]\n\t"
        "ldp	x5, x6, [%[a], 144]\n\t"
        "adcs	x3, x3, xzr\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 128]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 144]\n\t"
        "ldp	x3, x4, [%[a], 160]\n\t"
        "ldp	x5, x6, [%[a], 176]\n\t"
        "adcs	x3, x3, xzr\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 160]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 176]\n\t"
        "ldp	x3, x4, [%[a], 192]\n\t"
        "ldp	x5, x6, [%[a], 208]\n\t"
        "adcs	x3, x3, xzr\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 192]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 208]\n\t"
        "ldp	x3, x4, [%[a], 224]\n\t"
        "ldp	x5, x6, [%[a], 240]\n\t"
        "adcs	x3, x3, xzr\n\t"
        "adcs	x4, x4, xzr\n\t"
        "adcs	x5, x5, xzr\n\t"
        "stp	x3, x4, [%[r], 224]\n\t"
        "adcs	x6, x6, xzr\n\t"
        "stp	x5, x6, [%[r], 240]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6"
    );
}

/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer and result.
 * b  A single precision integer.
 */
static sp_digit sp_4096_sub_in_place_64(sp_digit* a, const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x2, x3, [%[a], 0]\n\t"
        "ldp	x6, x7, [%[b], 0]\n\t"
        "subs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 16]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 16]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 0]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 16]\n\t"
        "ldp	x2, x3, [%[a], 32]\n\t"
        "ldp	x6, x7, [%[b], 32]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 48]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 48]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 32]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 48]\n\t"
        "ldp	x2, x3, [%[a], 64]\n\t"
        "ldp	x6, x7, [%[b], 64]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 80]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 80]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 64]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 80]\n\t"
        "ldp	x2, x3, [%[a], 96]\n\t"
        "ldp	x6, x7, [%[b], 96]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 112]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 112]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 96]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 112]\n\t"
        "ldp	x2, x3, [%[a], 128]\n\t"
        "ldp	x6, x7, [%[b], 128]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 144]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 144]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 128]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 144]\n\t"
        "ldp	x2, x3, [%[a], 160]\n\t"
        "ldp	x6, x7, [%[b], 160]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 176]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 176]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 160]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 176]\n\t"
        "ldp	x2, x3, [%[a], 192]\n\t"
        "ldp	x6, x7, [%[b], 192]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 208]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 208]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 192]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 208]\n\t"
        "ldp	x2, x3, [%[a], 224]\n\t"
        "ldp	x6, x7, [%[b], 224]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 240]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 240]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 224]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 240]\n\t"
        "ldp	x2, x3, [%[a], 256]\n\t"
        "ldp	x6, x7, [%[b], 256]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 272]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 272]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 256]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 272]\n\t"
        "ldp	x2, x3, [%[a], 288]\n\t"
        "ldp	x6, x7, [%[b], 288]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 304]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 304]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 288]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 304]\n\t"
        "ldp	x2, x3, [%[a], 320]\n\t"
        "ldp	x6, x7, [%[b], 320]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 336]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 336]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 320]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 336]\n\t"
        "ldp	x2, x3, [%[a], 352]\n\t"
        "ldp	x6, x7, [%[b], 352]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 368]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 368]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 352]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 368]\n\t"
        "ldp	x2, x3, [%[a], 384]\n\t"
        "ldp	x6, x7, [%[b], 384]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 400]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 400]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 384]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 400]\n\t"
        "ldp	x2, x3, [%[a], 416]\n\t"
        "ldp	x6, x7, [%[b], 416]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 432]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 432]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 416]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 432]\n\t"
        "ldp	x2, x3, [%[a], 448]\n\t"
        "ldp	x6, x7, [%[b], 448]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 464]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 464]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 448]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 464]\n\t"
        "ldp	x2, x3, [%[a], 480]\n\t"
        "ldp	x6, x7, [%[b], 480]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 496]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 496]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 480]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 496]\n\t"
        "csetm	%[a], cc\n\t"
        : [a] "+r" (a)
        : [b] "r" (b)
        : "memory", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );

    return (sp_digit)a;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_4096_add_64(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x7, x8, [%[b], 0]\n\t"
        "adds	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 16]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldp	x3, x4, [%[a], 32]\n\t"
        "ldp	x7, x8, [%[b], 32]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 48]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 48]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 32]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 48]\n\t"
        "ldp	x3, x4, [%[a], 64]\n\t"
        "ldp	x7, x8, [%[b], 64]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 80]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 80]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 64]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 80]\n\t"
        "ldp	x3, x4, [%[a], 96]\n\t"
        "ldp	x7, x8, [%[b], 96]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 112]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 112]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 96]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 112]\n\t"
        "ldp	x3, x4, [%[a], 128]\n\t"
        "ldp	x7, x8, [%[b], 128]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 144]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 144]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 128]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 144]\n\t"
        "ldp	x3, x4, [%[a], 160]\n\t"
        "ldp	x7, x8, [%[b], 160]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 176]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 176]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 160]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 176]\n\t"
        "ldp	x3, x4, [%[a], 192]\n\t"
        "ldp	x7, x8, [%[b], 192]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 208]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 208]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 192]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 208]\n\t"
        "ldp	x3, x4, [%[a], 224]\n\t"
        "ldp	x7, x8, [%[b], 224]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 240]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 240]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 224]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 240]\n\t"
        "ldp	x3, x4, [%[a], 256]\n\t"
        "ldp	x7, x8, [%[b], 256]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 272]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 272]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 256]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 272]\n\t"
        "ldp	x3, x4, [%[a], 288]\n\t"
        "ldp	x7, x8, [%[b], 288]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 304]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 304]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 288]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 304]\n\t"
        "ldp	x3, x4, [%[a], 320]\n\t"
        "ldp	x7, x8, [%[b], 320]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 336]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 336]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 320]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 336]\n\t"
        "ldp	x3, x4, [%[a], 352]\n\t"
        "ldp	x7, x8, [%[b], 352]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 368]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 368]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 352]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 368]\n\t"
        "ldp	x3, x4, [%[a], 384]\n\t"
        "ldp	x7, x8, [%[b], 384]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 400]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 400]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 384]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 400]\n\t"
        "ldp	x3, x4, [%[a], 416]\n\t"
        "ldp	x7, x8, [%[b], 416]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 432]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 432]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 416]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 432]\n\t"
        "ldp	x3, x4, [%[a], 448]\n\t"
        "ldp	x7, x8, [%[b], 448]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 464]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 464]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 448]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 464]\n\t"
        "ldp	x3, x4, [%[a], 480]\n\t"
        "ldp	x7, x8, [%[b], 480]\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 496]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 496]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 480]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 496]\n\t"
        "cset	%[r], cs\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return (sp_digit)r;
}

#ifndef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static sp_digit sp_4096_cond_add_32(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    __asm__ __volatile__ (

        "ldp	x8, x9, [%[b], 0]\n\t"
        "ldp	x10, x11, [%[b], 16]\n\t"
        "ldp	x4, x5, [%[a], 0]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 16]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adds	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 0]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 16]\n\t"
        "ldp	x8, x9, [%[b], 32]\n\t"
        "ldp	x10, x11, [%[b], 48]\n\t"
        "ldp	x4, x5, [%[a], 32]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 48]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adcs	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 32]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 48]\n\t"
        "ldp	x8, x9, [%[b], 64]\n\t"
        "ldp	x10, x11, [%[b], 80]\n\t"
        "ldp	x4, x5, [%[a], 64]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 80]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adcs	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 64]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 80]\n\t"
        "ldp	x8, x9, [%[b], 96]\n\t"
        "ldp	x10, x11, [%[b], 112]\n\t"
        "ldp	x4, x5, [%[a], 96]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 112]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adcs	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 96]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 112]\n\t"
        "ldp	x8, x9, [%[b], 128]\n\t"
        "ldp	x10, x11, [%[b], 144]\n\t"
        "ldp	x4, x5, [%[a], 128]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 144]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adcs	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 128]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 144]\n\t"
        "ldp	x8, x9, [%[b], 160]\n\t"
        "ldp	x10, x11, [%[b], 176]\n\t"
        "ldp	x4, x5, [%[a], 160]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 176]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adcs	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 160]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 176]\n\t"
        "ldp	x8, x9, [%[b], 192]\n\t"
        "ldp	x10, x11, [%[b], 208]\n\t"
        "ldp	x4, x5, [%[a], 192]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 208]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adcs	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 192]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 208]\n\t"
        "ldp	x8, x9, [%[b], 224]\n\t"
        "ldp	x10, x11, [%[b], 240]\n\t"
        "ldp	x4, x5, [%[a], 224]\n\t"
        "and	x8, x8, %[m]\n\t"
        "ldp	x6, x7, [%[a], 240]\n\t"
        "and	x9, x9, %[m]\n\t"
        "adcs	x4, x4, x8\n\t"
        "and	x10, x10, %[m]\n\t"
        "adcs	x5, x5, x9\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x4, x5, [%[r], 224]\n\t"
        "adcs	x7, x7, x11\n\t"
        "stp	x6, x7, [%[r], 240]\n\t"
        "cset	%[r], cs\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    return (sp_digit)r;
}
#endif /* !WOLFSSL_SP_SMALL */

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_4096_mul_64(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[64];
    sp_digit a1[32];
    sp_digit b1[32];
    sp_digit* z2 = r + 64;
    sp_digit u;
    sp_digit ca;
    sp_digit cb;

    ca = sp_2048_add_32(a1, a, &a[32]);
    cb = sp_2048_add_32(b1, b, &b[32]);
    u  = ca & cb;

    sp_2048_mul_32(z2, &a[32], &b[32]);
    sp_2048_mul_32(z0, a, b);
    sp_2048_mul_32(z1, a1, b1);

    u += sp_4096_sub_in_place_64(z1, z0);
    u += sp_4096_sub_in_place_64(z1, z2);
    u += sp_4096_cond_add_32(z1 + 32, z1 + 32, a1, 0 - cb);
    u += sp_4096_cond_add_32(z1 + 32, z1 + 32, b1, 0 - ca);

    u += sp_4096_add_64(r + 32, r + 32, z1);
    (void)sp_4096_add_word_32(r + 96, r + 96, u);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_4096_sqr_64(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit* z2 = r + 64;
    sp_digit z1[64];
    sp_digit* a1 = z1;
    sp_digit* zero = z1 + 32;
    sp_digit u;
    sp_digit mask;
    sp_digit* p1;
    sp_digit* p2;

    XMEMSET(zero, 0, sizeof(sp_digit) * 32);

    mask = sp_2048_sub_32(a1, a, &a[32]);
    p1 = (sp_digit*)(((sp_digit)zero &   mask ) | ((sp_digit)a1 & (~mask)));
    p2 = (sp_digit*)(((sp_digit)zero & (~mask)) | ((sp_digit)a1 &   mask ));
    (void)sp_2048_sub_32(a1, p1, p2);

    sp_2048_sqr_32(z2, &a[32]);
    sp_2048_sqr_32(z0, a);
    sp_2048_sqr_32(z1, a1);

    u = 0;
    u -= sp_4096_sub_in_place_64(z1, z2);
    u -= sp_4096_sub_in_place_64(z1, z0);
    u += sp_4096_sub_in_place_64(r + 32, z1);
    sp_4096_add_word_32(r + 96, r + 96, u);
}

#endif /* !WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_4096_add_64(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "add	x11, %[a], 512\n\t"
        "\n1:\n\t"
        "adds	%[c], %[c], #-1\n\t"
        "ldp	x3, x4, [%[a]], #16\n\t"
        "ldp	x5, x6, [%[a]], #16\n\t"
        "ldp	x7, x8, [%[b]], #16\n\t"
        "adcs	x3, x3, x7\n\t"
        "ldp	x9, x10, [%[b]], #16\n\t"
        "adcs	x4, x4, x8\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r]], #16\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r]], #16\n\t"
        "cset	%[c], cs\n\t"
        "cmp	%[a], x11\n\t"
        "b.ne	1b\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    return c;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_4096_sub_in_place_64(sp_digit* a, const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "add	x10, %[a], 512\n\t"
        "\n1:\n\t"
        "subs	%[c], xzr, %[c]\n\t"
        "ldp	x2, x3, [%[a]]\n\t"
        "ldp	x4, x5, [%[a], #16]\n\t"
        "ldp	x6, x7, [%[b]], #16\n\t"
        "sbcs	x2, x2, x6\n\t"
        "ldp	x8, x9, [%[b]], #16\n\t"
        "sbcs	x3, x3, x7\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a]], #16\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a]], #16\n\t"
        "csetm	%[c], cc\n\t"
        "cmp	%[a], x10\n\t"
        "b.ne	1b\n\t"
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return c;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static void sp_4096_mul_64(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    sp_digit tmp[128];

    __asm__ __volatile__ (
        "mov	x5, xzr\n\t"
        "mov	x6, xzr\n\t"
        "mov	x7, xzr\n\t"
        "mov	x8, xzr\n\t"
        "\n1:\n\t"
        "subs	x3, x5, 504\n\t"
        "csel	x3, xzr, x3, cc\n\t"
        "sub	x4, x5, x3\n\t"
        "\n2:\n\t"
        "ldr	x10, [%[a], x3]\n\t"
        "ldr	x11, [%[b], x4]\n\t"
        "mul	x9, x10, x11\n\t"
        "umulh	x10, x10, x11\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "add	x3, x3, #8\n\t"
        "sub	x4, x4, #8\n\t"
        "cmp	x3, 512\n\t"
        "b.eq	3f\n\t"
        "cmp	x3, x5\n\t"
        "b.le	2b\n\t"
        "\n3:\n\t"
        "str	x6, [%[r], x5]\n\t"
        "mov	x6, x7\n\t"
        "mov	x7, x8\n\t"
        "mov	x8, #0\n\t"
        "add	x5, x5, #8\n\t"
        "cmp	x5, 1008\n\t"
        "b.le	1b\n\t"
        "str	x6, [%[r], x5]\n\t"
        :
        : [r] "r" (tmp), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    XMEMCPY(r, tmp, sizeof(tmp));
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
static void sp_4096_sqr_64(sp_digit* r, const sp_digit* a)
{
    sp_digit tmp[128];

    __asm__ __volatile__ (
        "mov	x6, xzr\n\t"
        "mov	x7, xzr\n\t"
        "mov	x8, xzr\n\t"
        "mov	x5, xzr\n\t"
        "\n1:\n\t"
        "subs	x3, x5, 504\n\t"
        "csel	x3, xzr, x3, cc\n\t"
        "sub	x4, x5, x3\n\t"
        "\n2:\n\t"
        "cmp	x4, x3\n\t"
        "b.eq	4f\n\t"
        "ldr	x10, [%[a], x3]\n\t"
        "ldr	x11, [%[a], x4]\n\t"
        "mul	x9, x10, x11\n\t"
        "umulh	x10, x10, x11\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "b.al	5f\n\t"
        "\n4:\n\t"
        "ldr	x10, [%[a], x3]\n\t"
        "mul	x9, x10, x10\n\t"
        "umulh	x10, x10, x10\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "\n5:\n\t"
        "add	x3, x3, #8\n\t"
        "sub	x4, x4, #8\n\t"
        "cmp	x3, 512\n\t"
        "b.eq	3f\n\t"
        "cmp	x3, x4\n\t"
        "b.gt	3f\n\t"
        "cmp	x3, x5\n\t"
        "b.le	2b\n\t"
        "\n3:\n\t"
        "str	x6, [%[r], x5]\n\t"
        "mov	x6, x7\n\t"
        "mov	x7, x8\n\t"
        "mov	x8, #0\n\t"
        "add	x5, x5, #8\n\t"
        "cmp	x5, 1008\n\t"
        "b.le	1b\n\t"
        "str	x6, [%[r], x5]\n\t"
        :
        : [r] "r" (tmp), [a] "r" (a)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    XMEMCPY(r, tmp, sizeof(tmp));
}

#endif /* WOLFSSL_SP_SMALL */
/* Caclulate the bottom digit of -1/a mod 2^n.
 *
 * a    A single precision number.
 * rho  Bottom word of inverse.
 */
static void sp_4096_mont_setup(const sp_digit* a, sp_digit* rho)
{
    sp_digit x;
    sp_digit b;

    b = a[0];
    x = (((b + 2) & 4) << 1) + b; /* here x*a==1 mod 2**4 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**8 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**16 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**32 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**64 */

    /* rho = -1/m mod b */
    *rho = (sp_digit)0 - x;
}

/* Mul a by digit b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision digit.
 */
static void sp_4096_mul_d_64(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "# A[0] * B\n\t"
        "ldr	x8, [%[a]]\n\t"
        "mul	x5, %[b], x8\n\t"
        "umulh	x3, %[b], x8\n\t"
        "mov	x4, xzr\n\t"
        "str	x5, [%[r]]\n\t"
        "mov	x5, xzr\n\t"
        "mov	x9, #8\n\t"
        "1:\n\t"
        "ldr	x8, [%[a], x9]\n\t"
        "mul	x6, %[b], x8\n\t"
        "umulh	x7, %[b], x8\n\t"
        "adds	x3, x3, x6\n\t"
        "adcs	x4, x4, x7\n\t"
        "adc	x5, xzr, xzr\n\t"
        "str	x3, [%[r], x9]\n\t"
        "mov	x3, x4\n\t"
        "mov	x4, x5\n\t"
        "mov	x5, #0\n\t"
        "add	x9, x9, #8\n\t"
        "cmp	x9, 512\n\t"
        "b.lt	1b\n\t"
        "str	x3, [%[r], 512]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );
#else
    __asm__ __volatile__ (
        "# A[0] * B\n\t"
        "ldp	x9, x10, [%[a]]\n\t"
        "mul	x3, %[b], x9\n\t"
        "umulh	x4, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "# A[1] * B\n\t"
        "str	x3, [%[r]]\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[2] * B\n\t"
        "ldp	x9, x10, [%[a], 16]\n\t"
        "str	x4, [%[r], 8]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[3] * B\n\t"
        "str	x5, [%[r], 16]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[4] * B\n\t"
        "ldp	x9, x10, [%[a], 32]\n\t"
        "str	x3, [%[r], 24]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[5] * B\n\t"
        "str	x4, [%[r], 32]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[6] * B\n\t"
        "ldp	x9, x10, [%[a], 48]\n\t"
        "str	x5, [%[r], 40]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[7] * B\n\t"
        "str	x3, [%[r], 48]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[8] * B\n\t"
        "ldp	x9, x10, [%[a], 64]\n\t"
        "str	x4, [%[r], 56]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[9] * B\n\t"
        "str	x5, [%[r], 64]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[10] * B\n\t"
        "ldp	x9, x10, [%[a], 80]\n\t"
        "str	x3, [%[r], 72]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[11] * B\n\t"
        "str	x4, [%[r], 80]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[12] * B\n\t"
        "ldp	x9, x10, [%[a], 96]\n\t"
        "str	x5, [%[r], 88]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[13] * B\n\t"
        "str	x3, [%[r], 96]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[14] * B\n\t"
        "ldp	x9, x10, [%[a], 112]\n\t"
        "str	x4, [%[r], 104]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[15] * B\n\t"
        "str	x5, [%[r], 112]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[16] * B\n\t"
        "ldp	x9, x10, [%[a], 128]\n\t"
        "str	x3, [%[r], 120]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[17] * B\n\t"
        "str	x4, [%[r], 128]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[18] * B\n\t"
        "ldp	x9, x10, [%[a], 144]\n\t"
        "str	x5, [%[r], 136]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[19] * B\n\t"
        "str	x3, [%[r], 144]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[20] * B\n\t"
        "ldp	x9, x10, [%[a], 160]\n\t"
        "str	x4, [%[r], 152]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[21] * B\n\t"
        "str	x5, [%[r], 160]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[22] * B\n\t"
        "ldp	x9, x10, [%[a], 176]\n\t"
        "str	x3, [%[r], 168]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[23] * B\n\t"
        "str	x4, [%[r], 176]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[24] * B\n\t"
        "ldp	x9, x10, [%[a], 192]\n\t"
        "str	x5, [%[r], 184]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[25] * B\n\t"
        "str	x3, [%[r], 192]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[26] * B\n\t"
        "ldp	x9, x10, [%[a], 208]\n\t"
        "str	x4, [%[r], 200]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[27] * B\n\t"
        "str	x5, [%[r], 208]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[28] * B\n\t"
        "ldp	x9, x10, [%[a], 224]\n\t"
        "str	x3, [%[r], 216]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[29] * B\n\t"
        "str	x4, [%[r], 224]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[30] * B\n\t"
        "ldp	x9, x10, [%[a], 240]\n\t"
        "str	x5, [%[r], 232]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[31] * B\n\t"
        "str	x3, [%[r], 240]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[32] * B\n\t"
        "ldp	x9, x10, [%[a], 256]\n\t"
        "str	x4, [%[r], 248]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[33] * B\n\t"
        "str	x5, [%[r], 256]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[34] * B\n\t"
        "ldp	x9, x10, [%[a], 272]\n\t"
        "str	x3, [%[r], 264]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[35] * B\n\t"
        "str	x4, [%[r], 272]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[36] * B\n\t"
        "ldp	x9, x10, [%[a], 288]\n\t"
        "str	x5, [%[r], 280]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[37] * B\n\t"
        "str	x3, [%[r], 288]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[38] * B\n\t"
        "ldp	x9, x10, [%[a], 304]\n\t"
        "str	x4, [%[r], 296]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[39] * B\n\t"
        "str	x5, [%[r], 304]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[40] * B\n\t"
        "ldp	x9, x10, [%[a], 320]\n\t"
        "str	x3, [%[r], 312]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[41] * B\n\t"
        "str	x4, [%[r], 320]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[42] * B\n\t"
        "ldp	x9, x10, [%[a], 336]\n\t"
        "str	x5, [%[r], 328]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[43] * B\n\t"
        "str	x3, [%[r], 336]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[44] * B\n\t"
        "ldp	x9, x10, [%[a], 352]\n\t"
        "str	x4, [%[r], 344]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[45] * B\n\t"
        "str	x5, [%[r], 352]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[46] * B\n\t"
        "ldp	x9, x10, [%[a], 368]\n\t"
        "str	x3, [%[r], 360]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[47] * B\n\t"
        "str	x4, [%[r], 368]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[48] * B\n\t"
        "ldp	x9, x10, [%[a], 384]\n\t"
        "str	x5, [%[r], 376]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[49] * B\n\t"
        "str	x3, [%[r], 384]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[50] * B\n\t"
        "ldp	x9, x10, [%[a], 400]\n\t"
        "str	x4, [%[r], 392]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[51] * B\n\t"
        "str	x5, [%[r], 400]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[52] * B\n\t"
        "ldp	x9, x10, [%[a], 416]\n\t"
        "str	x3, [%[r], 408]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[53] * B\n\t"
        "str	x4, [%[r], 416]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[54] * B\n\t"
        "ldp	x9, x10, [%[a], 432]\n\t"
        "str	x5, [%[r], 424]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[55] * B\n\t"
        "str	x3, [%[r], 432]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[56] * B\n\t"
        "ldp	x9, x10, [%[a], 448]\n\t"
        "str	x4, [%[r], 440]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[57] * B\n\t"
        "str	x5, [%[r], 448]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[58] * B\n\t"
        "ldp	x9, x10, [%[a], 464]\n\t"
        "str	x3, [%[r], 456]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[59] * B\n\t"
        "str	x4, [%[r], 464]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[60] * B\n\t"
        "ldp	x9, x10, [%[a], 480]\n\t"
        "str	x5, [%[r], 472]\n\t"
        "adcs	x3, x3, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x5, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[61] * B\n\t"
        "str	x3, [%[r], 480]\n\t"
        "adcs	x4, x4, x7\n\t"
        "mul	x6, %[b], x10\n\t"
        "mov	x3, xzr\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[62] * B\n\t"
        "ldp	x9, x10, [%[a], 496]\n\t"
        "str	x4, [%[r], 488]\n\t"
        "adcs	x5, x5, x7\n\t"
        "mul	x6, %[b], x9\n\t"
        "mov	x4, xzr\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[63] * B\n\t"
        "str	x5, [%[r], 496]\n\t"
        "mul	x6, %[b], x10\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, %[b], x10\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "adc	x4, x4, x7\n\t"
        "stp	x3, x4, [%[r], 504]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );
#endif
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 4096 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_4096_mont_norm_64(sp_digit* r, const sp_digit* m)
{
    XMEMSET(r, 0, sizeof(sp_digit) * 64);

    /* r = 2^n mod m */
    sp_4096_sub_in_place_64(r, m);
}

#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) | WOLFSSL_HAVE_SP_DH */
/* Reduce the number back to 4096 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
SP_NOINLINE static void sp_4096_mont_reduce_64(sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    __asm__ __volatile__ (
        "ldp	x11, x12, [%[a], 0]\n\t"
        "ldp	x13, x14, [%[a], 16]\n\t"
        "ldp	x15, x16, [%[a], 32]\n\t"
        "ldp	x17, x19, [%[a], 48]\n\t"
        "ldp	x20, x21, [%[a], 64]\n\t"
        "ldp	x22, x23, [%[a], 80]\n\t"
        "# No carry yet\n\t"
        "mov	x3, xzr\n\t"
        "# i = 0..63\n\t"
        "mov	x4, 64\n\t"
        "\n1:\n\t"
        "# mu = a[i] * mp\n\t"
        "mul	x10, %[mp], x11\n\t"
        "ldp	x24, x25, [%[m], 0]\n\t"
        "ldp	x26, x27, [%[m], 16]\n\t"
        "# a[i+0] += m[0] * mu\n\t"
        "mul	x5, x24, x10\n\t"
        "umulh	x6, x24, x10\n\t"
        "# a[i+1] += m[1] * mu\n\t"
        "adds	x11, x11, x5\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x11, x12, x5\n\t"
        "# a[i+2] += m[2] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x11, x11, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x12, x13, x5\n\t"
        "# a[i+3] += m[3] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x12, x12, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x13, x14, x5\n\t"
        "ldp	x24, x25, [%[m], 32]\n\t"
        "ldp	x26, x27, [%[m], 48]\n\t"
        "# a[i+4] += m[4] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x13, x13, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x14, x15, x5\n\t"
        "# a[i+5] += m[5] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x14, x14, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x15, x16, x5\n\t"
        "# a[i+6] += m[6] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x15, x15, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x16, x17, x5\n\t"
        "# a[i+7] += m[7] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x16, x16, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x17, x19, x5\n\t"
        "ldp	x24, x25, [%[m], 64]\n\t"
        "ldp	x26, x27, [%[m], 80]\n\t"
        "# a[i+8] += m[8] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x17, x17, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x19, x20, x5\n\t"
        "# a[i+9] += m[9] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x19, x19, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x20, x21, x5\n\t"
        "# a[i+10] += m[10] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x20, x20, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x21, x22, x5\n\t"
        "# a[i+11] += m[11] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x21, x21, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x22, x23, x5\n\t"
        "ldp	x24, x25, [%[m], 96]\n\t"
        "ldp	x26, x27, [%[m], 112]\n\t"
        "# a[i+12] += m[12] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x22, x22, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "ldr	x23, [%[a], 96]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x23, x23, x5\n\t"
        "# a[i+13] += m[13] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x23, x23, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "ldp	x8, x9, [%[a], 104]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+14] += m[14] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 104]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+15] += m[15] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 112]\n\t"
        "ldp	x8, x9, [%[a], 120]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 128]\n\t"
        "ldp	x26, x27, [%[m], 144]\n\t"
        "# a[i+16] += m[16] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 120]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+17] += m[17] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 128]\n\t"
        "ldp	x8, x9, [%[a], 136]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+18] += m[18] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 136]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+19] += m[19] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 144]\n\t"
        "ldp	x8, x9, [%[a], 152]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 160]\n\t"
        "ldp	x26, x27, [%[m], 176]\n\t"
        "# a[i+20] += m[20] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 152]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+21] += m[21] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 160]\n\t"
        "ldp	x8, x9, [%[a], 168]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+22] += m[22] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 168]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+23] += m[23] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 176]\n\t"
        "ldp	x8, x9, [%[a], 184]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 192]\n\t"
        "ldp	x26, x27, [%[m], 208]\n\t"
        "# a[i+24] += m[24] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 184]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+25] += m[25] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 192]\n\t"
        "ldp	x8, x9, [%[a], 200]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+26] += m[26] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 200]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+27] += m[27] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 208]\n\t"
        "ldp	x8, x9, [%[a], 216]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 224]\n\t"
        "ldp	x26, x27, [%[m], 240]\n\t"
        "# a[i+28] += m[28] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 216]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+29] += m[29] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 224]\n\t"
        "ldp	x8, x9, [%[a], 232]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+30] += m[30] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 232]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+31] += m[31] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 240]\n\t"
        "ldp	x8, x9, [%[a], 248]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 256]\n\t"
        "ldp	x26, x27, [%[m], 272]\n\t"
        "# a[i+32] += m[32] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 248]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+33] += m[33] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 256]\n\t"
        "ldp	x8, x9, [%[a], 264]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+34] += m[34] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 264]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+35] += m[35] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 272]\n\t"
        "ldp	x8, x9, [%[a], 280]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 288]\n\t"
        "ldp	x26, x27, [%[m], 304]\n\t"
        "# a[i+36] += m[36] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 280]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+37] += m[37] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 288]\n\t"
        "ldp	x8, x9, [%[a], 296]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+38] += m[38] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 296]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+39] += m[39] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 304]\n\t"
        "ldp	x8, x9, [%[a], 312]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 320]\n\t"
        "ldp	x26, x27, [%[m], 336]\n\t"
        "# a[i+40] += m[40] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 312]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+41] += m[41] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 320]\n\t"
        "ldp	x8, x9, [%[a], 328]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+42] += m[42] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 328]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+43] += m[43] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 336]\n\t"
        "ldp	x8, x9, [%[a], 344]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 352]\n\t"
        "ldp	x26, x27, [%[m], 368]\n\t"
        "# a[i+44] += m[44] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 344]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+45] += m[45] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 352]\n\t"
        "ldp	x8, x9, [%[a], 360]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+46] += m[46] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 360]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+47] += m[47] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 368]\n\t"
        "ldp	x8, x9, [%[a], 376]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 384]\n\t"
        "ldp	x26, x27, [%[m], 400]\n\t"
        "# a[i+48] += m[48] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 376]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+49] += m[49] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 384]\n\t"
        "ldp	x8, x9, [%[a], 392]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+50] += m[50] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 392]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+51] += m[51] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 400]\n\t"
        "ldp	x8, x9, [%[a], 408]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 416]\n\t"
        "ldp	x26, x27, [%[m], 432]\n\t"
        "# a[i+52] += m[52] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 408]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+53] += m[53] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 416]\n\t"
        "ldp	x8, x9, [%[a], 424]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+54] += m[54] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 424]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+55] += m[55] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 432]\n\t"
        "ldp	x8, x9, [%[a], 440]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 448]\n\t"
        "ldp	x26, x27, [%[m], 464]\n\t"
        "# a[i+56] += m[56] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 440]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+57] += m[57] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 448]\n\t"
        "ldp	x8, x9, [%[a], 456]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+58] += m[58] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 456]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+59] += m[59] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 464]\n\t"
        "ldp	x8, x9, [%[a], 472]\n\t"
        "umulh	x7, x27, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "ldp	x24, x25, [%[m], 480]\n\t"
        "ldp	x26, x27, [%[m], 496]\n\t"
        "# a[i+60] += m[60] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x24, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 472]\n\t"
        "umulh	x6, x24, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+61] += m[61] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x25, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 480]\n\t"
        "ldp	x8, x9, [%[a], 488]\n\t"
        "umulh	x7, x25, x10\n\t"
        "adds	x8, x8, x5\n\t"
        "# a[i+62] += m[62] * mu\n\t"
        "adc	x7, x7, xzr\n\t"
        "adds	x8, x8, x6\n\t"
        "mul	x5, x26, x10\n\t"
        "adc	x7, x7, xzr\n\t"
        "str	x8, [%[a], 488]\n\t"
        "umulh	x6, x26, x10\n\t"
        "adds	x9, x9, x5\n\t"
        "# a[i+63] += m[63] * mu\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x9, x9, x7\n\t"
        "mul	x5, x27, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "str	x9, [%[a], 496]\n\t"
        "umulh	x7, x27, x10\n\t"
        "ldp	x8, x9, [%[a], 504]\n\t"
        "adds	x5, x5, x6\n\t"
        "adcs	x7, x7, x3\n\t"
        "cset	x3, cs\n\t"
        "adds	x8, x8, x5\n\t"
        "str	x8, [%[a], 504]\n\t"
        "adcs	x9, x9, x7\n\t"
        "str	x9, [%[a], 512]\n\t"
        "adc	x3, x3, xzr\n\t"
        "subs	x4, x4, 1\n\t"
        "add	%[a], %[a], 8\n\t"
        "b.ne	1b\n\t"
        "# Create mask\n\t"
        "neg	x3, x3\n\t"
        "mov   %[mp], %[a]\n\t"
        "sub	%[a], %[a], 512\n\t"
        "# Subtract masked modulus\n\t"
        "ldp	x4, x5, [%[m], 0]\n\t"
        "ldp	x6, x7, [%[m], 16]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "subs	x11, x11, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x12, x12, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x13, x13, x6\n\t"
        "stp	x11, x12, [%[a], 0]\n\t"
        "sbcs	x14, x14, x7\n\t"
        "stp	x13, x14, [%[a], 16]\n\t"
        "ldp	x4, x5, [%[m], 32]\n\t"
        "ldp	x6, x7, [%[m], 48]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x15, x15, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x16, x16, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x17, x17, x6\n\t"
        "stp	x15, x16, [%[a], 32]\n\t"
        "sbcs	x19, x19, x7\n\t"
        "stp	x17, x19, [%[a], 48]\n\t"
        "ldp	x4, x5, [%[m], 64]\n\t"
        "ldp	x6, x7, [%[m], 80]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x20, x20, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x21, x21, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x22, x22, x6\n\t"
        "stp	x20, x21, [%[a], 64]\n\t"
        "sbcs	x23, x23, x7\n\t"
        "stp	x22, x23, [%[a], 80]\n\t"
        "ldp	x4, x5, [%[m], 96]\n\t"
        "ldp	x6, x7, [%[m], 112]\n\t"
        "ldp	x8, x9, [%[mp], 96]\n\t"
        "ldp	x10, x11, [%[mp], 112]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 96]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 112]\n\t"
        "ldp	x4, x5, [%[m], 128]\n\t"
        "ldp	x6, x7, [%[m], 144]\n\t"
        "ldp	x8, x9, [%[mp], 128]\n\t"
        "ldp	x10, x11, [%[mp], 144]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 128]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 144]\n\t"
        "ldp	x4, x5, [%[m], 160]\n\t"
        "ldp	x6, x7, [%[m], 176]\n\t"
        "ldp	x8, x9, [%[mp], 160]\n\t"
        "ldp	x10, x11, [%[mp], 176]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 160]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 176]\n\t"
        "ldp	x4, x5, [%[m], 192]\n\t"
        "ldp	x6, x7, [%[m], 208]\n\t"
        "ldp	x8, x9, [%[mp], 192]\n\t"
        "ldp	x10, x11, [%[mp], 208]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 192]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 208]\n\t"
        "ldp	x4, x5, [%[m], 224]\n\t"
        "ldp	x6, x7, [%[m], 240]\n\t"
        "ldp	x8, x9, [%[mp], 224]\n\t"
        "ldp	x10, x11, [%[mp], 240]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 224]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 240]\n\t"
        "ldp	x4, x5, [%[m], 256]\n\t"
        "ldp	x6, x7, [%[m], 272]\n\t"
        "ldp	x8, x9, [%[mp], 256]\n\t"
        "ldp	x10, x11, [%[mp], 272]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 256]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 272]\n\t"
        "ldp	x4, x5, [%[m], 288]\n\t"
        "ldp	x6, x7, [%[m], 304]\n\t"
        "ldp	x8, x9, [%[mp], 288]\n\t"
        "ldp	x10, x11, [%[mp], 304]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 288]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 304]\n\t"
        "ldp	x4, x5, [%[m], 320]\n\t"
        "ldp	x6, x7, [%[m], 336]\n\t"
        "ldp	x8, x9, [%[mp], 320]\n\t"
        "ldp	x10, x11, [%[mp], 336]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 320]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 336]\n\t"
        "ldp	x4, x5, [%[m], 352]\n\t"
        "ldp	x6, x7, [%[m], 368]\n\t"
        "ldp	x8, x9, [%[mp], 352]\n\t"
        "ldp	x10, x11, [%[mp], 368]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 352]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 368]\n\t"
        "ldp	x4, x5, [%[m], 384]\n\t"
        "ldp	x6, x7, [%[m], 400]\n\t"
        "ldp	x8, x9, [%[mp], 384]\n\t"
        "ldp	x10, x11, [%[mp], 400]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 384]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 400]\n\t"
        "ldp	x4, x5, [%[m], 416]\n\t"
        "ldp	x6, x7, [%[m], 432]\n\t"
        "ldp	x8, x9, [%[mp], 416]\n\t"
        "ldp	x10, x11, [%[mp], 432]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 416]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 432]\n\t"
        "ldp	x4, x5, [%[m], 448]\n\t"
        "ldp	x6, x7, [%[m], 464]\n\t"
        "ldp	x8, x9, [%[mp], 448]\n\t"
        "ldp	x10, x11, [%[mp], 464]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 448]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 464]\n\t"
        "ldp	x4, x5, [%[m], 480]\n\t"
        "ldp	x6, x7, [%[m], 496]\n\t"
        "ldp	x8, x9, [%[mp], 480]\n\t"
        "ldp	x10, x11, [%[mp], 496]\n\t"
        "and	x4, x4, x3\n\t"
        "and	x5, x5, x3\n\t"
        "sbcs	x8, x8, x4\n\t"
        "and	x6, x6, x3\n\t"
        "sbcs	x9, x9, x5\n\t"
        "and	x7, x7, x3\n\t"
        "sbcs	x10, x10, x6\n\t"
        "stp	x8, x9, [%[a], 480]\n\t"
        "sbcs	x11, x11, x7\n\t"
        "stp	x10, x11, [%[a], 496]\n\t"
        : [a] "+r" (a), [mp] "+r" (mp)
        : [m] "r" (m)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x10", "x8", "x9", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27"
    );

}

/* Multiply two Montgomery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montgomery form.
 * b   Second number to multiply in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_4096_mont_mul_64(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_4096_mul_64(r, a, b);
    sp_4096_mont_reduce_64(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_4096_mont_sqr_64(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_4096_sqr_64(r, a);
    sp_4096_mont_reduce_64(r, m, mp);
}

#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_4096_sub_64(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "add	x11, %[a], 512\n\t"
        "\n1:\n\t"
        "subs	%[c], xzr, %[c]\n\t"
        "ldp	x3, x4, [%[a]], #16\n\t"
        "ldp	x5, x6, [%[a]], #16\n\t"
        "ldp	x7, x8, [%[b]], #16\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x9, x10, [%[b]], #16\n\t"
        "sbcs	x4, x4, x8\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r]], #16\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r]], #16\n\t"
        "csetm	%[c], cc\n\t"
        "cmp	%[a], x11\n\t"
        "b.ne	1b\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    return c;
}

#else
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_4096_sub_64(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x7, x8, [%[b], 0]\n\t"
        "subs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 16]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldp	x3, x4, [%[a], 32]\n\t"
        "ldp	x7, x8, [%[b], 32]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 48]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 48]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 32]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 48]\n\t"
        "ldp	x3, x4, [%[a], 64]\n\t"
        "ldp	x7, x8, [%[b], 64]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 80]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 80]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 64]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 80]\n\t"
        "ldp	x3, x4, [%[a], 96]\n\t"
        "ldp	x7, x8, [%[b], 96]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 112]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 112]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 96]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 112]\n\t"
        "ldp	x3, x4, [%[a], 128]\n\t"
        "ldp	x7, x8, [%[b], 128]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 144]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 144]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 128]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 144]\n\t"
        "ldp	x3, x4, [%[a], 160]\n\t"
        "ldp	x7, x8, [%[b], 160]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 176]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 176]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 160]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 176]\n\t"
        "ldp	x3, x4, [%[a], 192]\n\t"
        "ldp	x7, x8, [%[b], 192]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 208]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 208]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 192]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 208]\n\t"
        "ldp	x3, x4, [%[a], 224]\n\t"
        "ldp	x7, x8, [%[b], 224]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 240]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 240]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 224]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 240]\n\t"
        "ldp	x3, x4, [%[a], 256]\n\t"
        "ldp	x7, x8, [%[b], 256]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 272]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 272]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 256]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 272]\n\t"
        "ldp	x3, x4, [%[a], 288]\n\t"
        "ldp	x7, x8, [%[b], 288]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 304]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 304]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 288]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 304]\n\t"
        "ldp	x3, x4, [%[a], 320]\n\t"
        "ldp	x7, x8, [%[b], 320]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 336]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 336]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 320]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 336]\n\t"
        "ldp	x3, x4, [%[a], 352]\n\t"
        "ldp	x7, x8, [%[b], 352]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 368]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 368]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 352]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 368]\n\t"
        "ldp	x3, x4, [%[a], 384]\n\t"
        "ldp	x7, x8, [%[b], 384]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 400]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 400]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 384]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 400]\n\t"
        "ldp	x3, x4, [%[a], 416]\n\t"
        "ldp	x7, x8, [%[b], 416]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 432]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 432]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 416]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 432]\n\t"
        "ldp	x3, x4, [%[a], 448]\n\t"
        "ldp	x7, x8, [%[b], 448]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 464]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 464]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 448]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 464]\n\t"
        "ldp	x3, x4, [%[a], 480]\n\t"
        "ldp	x7, x8, [%[b], 480]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 496]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 496]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 480]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 496]\n\t"
        "csetm	%[r], cc\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return (sp_digit)r;
}

#endif /* WOLFSSL_SP_SMALL */
/* Divide the double width number (d1|d0) by the divisor. (d1|d0 / div)
 *
 * Assumes divisor has higest bit set.
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The divisor.
 * returns the result of the division.
 */
static sp_digit div_4096_word_64_cond(sp_digit d1, sp_digit d0, sp_digit div)
{
    __asm__ __volatile__ (
        "lsr	x8, %[div], 32\n\t"
        "add	x5, x8, 1\n\t"

        "udiv	x3, %[d1], x5\n\t"
        "lsl	x7, %[div], 32\n\t"
        "movz	x9, #1, lsl 32\n\t"
        "lsl	x6, x3, 32\n\t"
        "mul	x4, %[div], x6\n\t"
        "umulh	x3, %[div], x6\n\t"
        "subs	%[d0], %[d0], x4\n\t"
        "sbc	%[d1], %[d1], x3\n\t"

        "cmp	%[d1], x5\n\t"
        "b.lt	1f\n\t"
        "subs	%[d0], %[d0], x7\n\t"
        "add	x6, x6, x9\n\t"
        "sbc	%[d1], %[d1], x8\n\t"
        "1:\n\t"

        "extr	x3, %[d1], %[d0], 32\n\t"

        "udiv	x3, x3, x5\n\t"
        "add	x6, x6, x3\n\t"
        "mul	x4, %[div], x3\n\t"
        "umulh	x3, %[div], x3\n\t"
        "subs	%[d0], %[d0], x4\n\t"
        "sbc	%[d1], %[d1], x3\n\t"

        "extr	x3, %[d1], %[d0], 32\n\t"

        "cmp	x3, x5\n\t"
        "b.lt	2f\n\t"
        "udiv   x3, x3, x5\n\t"
        "add    x6, x6, x3\n\t"
        "mul    x4, %[div], x3\n\t"
        "sub    %[d0], %[d0], x4\n\t"
        "2:\n\t"

        "udiv	x3, %[d0], %[div]\n\t"
        "add	%[d1], x6, x3\n\t"

        : [d1] "+r" (d1), [d0] "+r" (d0)
        : [div] "r" (div)
        : "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );

    return d1;
}

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_4096_div_64_cond(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    sp_digit t1[128], t2[65];
    sp_digit div, r1;
    int i;

    (void)m;

    div = d[63];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 64);
    for (i = 63; i >= 0; i--) {
        if (t1[64 + i] == div) {
            r1 = SP_DIGIT_MAX;
        }
        else {
            r1 = div_4096_word_64_cond(t1[64 + i], t1[64 + i - 1], div);
        }

        sp_4096_mul_d_64(t2, d, r1);
        t1[64 + i] += sp_4096_sub_in_place_64(&t1[i], t2);
        t1[64 + i] -= t2[64];
        if (t1[64 + i] != 0) {
            t1[64 + i] += sp_4096_add_64(&t1[i], &t1[i], d);
            if (t1[64 + i] != 0)
                t1[64 + i] += sp_4096_add_64(&t1[i], &t1[i], d);
        }
    }

    for (i = 63; i > 0; i--) {
        if (t1[i] != d[i])
            break;
    }
    if (t1[i] >= d[i]) {
        sp_4096_sub_64(r, t1, d);
    }
    else {
        XMEMCPY(r, t1, sizeof(*t1) * 64);
    }

    return MP_OKAY;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_4096_mod_64_cond(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_4096_div_64_cond(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not copying.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static sp_digit sp_4096_cond_sub_64(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	x8, #0\n\t"
        "1:\n\t"
        "subs	%[c], xzr, %[c]\n\t"
        "ldr	x4, [%[a], x8]\n\t"
        "ldr	x5, [%[b], x8]\n\t"
        "and	x5, x5, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "csetm	%[c], cc\n\t"
        "str	x4, [%[r], x8]\n\t"
        "add	x8, x8, #8\n\t"
        "cmp	x8, 512\n\t"
        "b.lt	1b\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x6", "x5", "x7", "x8", "x9", "x10", "x11", "x12"
    );

    return c;
#else
    __asm__ __volatile__ (

        "ldp	x5, x7, [%[b], 0]\n\t"
        "ldp	x11, x12, [%[b], 16]\n\t"
        "ldp	x4, x6, [%[a], 0]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 16]\n\t"
        "and	x7, x7, %[m]\n\t"
        "subs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 0]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 16]\n\t"
        "ldp	x5, x7, [%[b], 32]\n\t"
        "ldp	x11, x12, [%[b], 48]\n\t"
        "ldp	x4, x6, [%[a], 32]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 48]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 32]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 48]\n\t"
        "ldp	x5, x7, [%[b], 64]\n\t"
        "ldp	x11, x12, [%[b], 80]\n\t"
        "ldp	x4, x6, [%[a], 64]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 80]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 64]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 80]\n\t"
        "ldp	x5, x7, [%[b], 96]\n\t"
        "ldp	x11, x12, [%[b], 112]\n\t"
        "ldp	x4, x6, [%[a], 96]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 112]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 96]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 112]\n\t"
        "ldp	x5, x7, [%[b], 128]\n\t"
        "ldp	x11, x12, [%[b], 144]\n\t"
        "ldp	x4, x6, [%[a], 128]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 144]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 128]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 144]\n\t"
        "ldp	x5, x7, [%[b], 160]\n\t"
        "ldp	x11, x12, [%[b], 176]\n\t"
        "ldp	x4, x6, [%[a], 160]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 176]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 160]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 176]\n\t"
        "ldp	x5, x7, [%[b], 192]\n\t"
        "ldp	x11, x12, [%[b], 208]\n\t"
        "ldp	x4, x6, [%[a], 192]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 208]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 192]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 208]\n\t"
        "ldp	x5, x7, [%[b], 224]\n\t"
        "ldp	x11, x12, [%[b], 240]\n\t"
        "ldp	x4, x6, [%[a], 224]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 240]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 224]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 240]\n\t"
        "ldp	x5, x7, [%[b], 256]\n\t"
        "ldp	x11, x12, [%[b], 272]\n\t"
        "ldp	x4, x6, [%[a], 256]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 272]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 256]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 272]\n\t"
        "ldp	x5, x7, [%[b], 288]\n\t"
        "ldp	x11, x12, [%[b], 304]\n\t"
        "ldp	x4, x6, [%[a], 288]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 304]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 288]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 304]\n\t"
        "ldp	x5, x7, [%[b], 320]\n\t"
        "ldp	x11, x12, [%[b], 336]\n\t"
        "ldp	x4, x6, [%[a], 320]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 336]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 320]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 336]\n\t"
        "ldp	x5, x7, [%[b], 352]\n\t"
        "ldp	x11, x12, [%[b], 368]\n\t"
        "ldp	x4, x6, [%[a], 352]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 368]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 352]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 368]\n\t"
        "ldp	x5, x7, [%[b], 384]\n\t"
        "ldp	x11, x12, [%[b], 400]\n\t"
        "ldp	x4, x6, [%[a], 384]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 400]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 384]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 400]\n\t"
        "ldp	x5, x7, [%[b], 416]\n\t"
        "ldp	x11, x12, [%[b], 432]\n\t"
        "ldp	x4, x6, [%[a], 416]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 432]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 416]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 432]\n\t"
        "ldp	x5, x7, [%[b], 448]\n\t"
        "ldp	x11, x12, [%[b], 464]\n\t"
        "ldp	x4, x6, [%[a], 448]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 464]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 448]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 464]\n\t"
        "ldp	x5, x7, [%[b], 480]\n\t"
        "ldp	x11, x12, [%[b], 496]\n\t"
        "ldp	x4, x6, [%[a], 480]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 496]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 480]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 496]\n\t"
        "csetm	%[r], cc\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x6", "x5", "x7", "x8", "x9", "x10", "x11", "x12"
    );

    return (sp_digit)r;
#endif /* WOLFSSL_SP_SMALL */
}

/* Divide the double width number (d1|d0) by the divisor. (d1|d0 / div)
 *
 * Assumes divisor has higest bit set.
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The divisor.
 * returns the result of the division.
 */
static sp_digit div_4096_word_64(sp_digit d1, sp_digit d0, sp_digit div)
{
    __asm__ __volatile__ (
        "lsr	x8, %[div], 32\n\t"
        "add	x5, x8, 1\n\t"

        "udiv	x3, %[d1], x5\n\t"
        "lsl	x7, %[div], 32\n\t"
        "movz	x9, #1, lsl 32\n\t"
        "lsl	x6, x3, 32\n\t"
        "mul	x4, %[div], x6\n\t"
        "umulh	x3, %[div], x6\n\t"
        "subs	%[d0], %[d0], x4\n\t"
        "sbc	%[d1], %[d1], x3\n\t"

        "cmp	%[d1], x5\n\t"
        "cset	x9, ge\n\t"
        "csetm	x10, ge\n\t"
        "lsl	x9, x9, #32\n\t"
        "and	x7, x7, x10\n\t"
        "and	x8, x8, x10\n\t"
        "subs	%[d0], %[d0], x7\n\t"
        "add	x6, x6, x9\n\t"
        "sbc	%[d1], %[d1], x8\n\t"

        "extr	x3, %[d1], %[d0], 32\n\t"

        "udiv	x3, x3, x5\n\t"
        "add	x6, x6, x3\n\t"
        "mul	x4, %[div], x3\n\t"
        "umulh	x3, %[div], x3\n\t"
        "subs	%[d0], %[d0], x4\n\t"
        "sbc	%[d1], %[d1], x3\n\t"

        "extr	x3, %[d1], %[d0], 32\n\t"

        "udiv   x3, x3, x5\n\t"
        "add    x6, x6, x3\n\t"
        "mul    x4, %[div], x3\n\t"
        "sub    %[d0], %[d0], x4\n\t"

        "udiv	x3, %[d0], %[div]\n\t"
        "add	%[d1], x6, x3\n\t"

        : [d1] "+r" (d1), [d0] "+r" (d0)
        : [div] "r" (div)
        : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return d1;
}

/* AND m into each word of a and store in r.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * m  Mask to AND against each digit.
 */
static void sp_4096_mask_64(sp_digit* r, const sp_digit* a, sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<64; i++) {
        r[i] = a[i] & m;
    }
#else
    int i;

    for (i = 0; i < 64; i += 8) {
        r[i+0] = a[i+0] & m;
        r[i+1] = a[i+1] & m;
        r[i+2] = a[i+2] & m;
        r[i+3] = a[i+3] & m;
        r[i+4] = a[i+4] & m;
        r[i+5] = a[i+5] & m;
        r[i+6] = a[i+6] & m;
        r[i+7] = a[i+7] & m;
    }
#endif
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_int64 sp_4096_cmp_64(const sp_digit* a, const sp_digit* b)
{
#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "mov	x3, #0\n\t"
        "mov	x2, #-1\n\t"
        "mov	x10, #64\n\t"
        "add	%[a], %[a], #496\n\t"
        "add	%[b], %[b], #496\n\t"
        "1:\n\t"
        "ldp	x6, x7, [%[a]], -16\n\t"
        "ldp	x8, x9, [%[b]], -16\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x10, x10, #2\n\t"
        "b.ne	1b\n\t"
        "cmp	x2, #0\n\t"
        "cset	%[a], eq\n\t"
        "orr	%[a], %[a], x3\n\t"
        : [a] "+r" (a), [b] "+r" (b)
        :
        : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );
#else
    __asm__ __volatile__ (
        "mov	x3, #0\n\t"
        "mov	x2, #-1\n\t"
        "ldp	x6, x7, [%[a], 496]\n\t"
        "ldp	x8, x9, [%[b], 496]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 480]\n\t"
        "ldp	x8, x9, [%[b], 480]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 464]\n\t"
        "ldp	x8, x9, [%[b], 464]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 448]\n\t"
        "ldp	x8, x9, [%[b], 448]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 432]\n\t"
        "ldp	x8, x9, [%[b], 432]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 416]\n\t"
        "ldp	x8, x9, [%[b], 416]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 400]\n\t"
        "ldp	x8, x9, [%[b], 400]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 384]\n\t"
        "ldp	x8, x9, [%[b], 384]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 368]\n\t"
        "ldp	x8, x9, [%[b], 368]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 352]\n\t"
        "ldp	x8, x9, [%[b], 352]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 336]\n\t"
        "ldp	x8, x9, [%[b], 336]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 320]\n\t"
        "ldp	x8, x9, [%[b], 320]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 304]\n\t"
        "ldp	x8, x9, [%[b], 304]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 288]\n\t"
        "ldp	x8, x9, [%[b], 288]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 272]\n\t"
        "ldp	x8, x9, [%[b], 272]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 256]\n\t"
        "ldp	x8, x9, [%[b], 256]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 240]\n\t"
        "ldp	x8, x9, [%[b], 240]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 224]\n\t"
        "ldp	x8, x9, [%[b], 224]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 208]\n\t"
        "ldp	x8, x9, [%[b], 208]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 192]\n\t"
        "ldp	x8, x9, [%[b], 192]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 176]\n\t"
        "ldp	x8, x9, [%[b], 176]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 160]\n\t"
        "ldp	x8, x9, [%[b], 160]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 144]\n\t"
        "ldp	x8, x9, [%[b], 144]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 128]\n\t"
        "ldp	x8, x9, [%[b], 128]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 112]\n\t"
        "ldp	x8, x9, [%[b], 112]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 96]\n\t"
        "ldp	x8, x9, [%[b], 96]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 80]\n\t"
        "ldp	x8, x9, [%[b], 80]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 64]\n\t"
        "ldp	x8, x9, [%[b], 64]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 48]\n\t"
        "ldp	x8, x9, [%[b], 48]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 32]\n\t"
        "ldp	x8, x9, [%[b], 32]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 16]\n\t"
        "ldp	x8, x9, [%[b], 16]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "ldp	x6, x7, [%[a], 0]\n\t"
        "ldp	x8, x9, [%[b], 0]\n\t"
        "subs	x7, x7, x9\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "subs	x6, x6, x8\n\t"
        "csel	x4, x2, xzr, lo\n\t"
        "csetm	x5, eq\n\t"
        "orr	x3, x3, x4\n\t"
        "and	x2, x2, x5\n\t"
        "cmp	x2, #0\n\t"
        "cset	%[a], eq\n\t"
        "orr	%[a], %[a], x3\n\t"
        : [a] "+r" (a)
        : [b] "r" (b)
        : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );
#endif

    return (sp_int64)a;
}

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_4096_div_64(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    sp_digit t1[128], t2[65];
    sp_digit div, r1;
    int i;

    (void)m;

    div = d[63];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 64);
    for (i = 63; i >= 0; i--) {
        sp_digit hi = t1[64 + i] - (t1[64 + i] == div);
        r1 = div_4096_word_64(hi, t1[64 + i - 1], div);

        sp_4096_mul_d_64(t2, d, r1);
        t1[64 + i] += sp_4096_sub_in_place_64(&t1[i], t2);
        t1[64 + i] -= t2[64];
        sp_4096_mask_64(t2, d, t1[64 + i]);
        t1[64 + i] += sp_4096_add_64(&t1[i], &t1[i], t2);
        sp_4096_mask_64(t2, d, t1[64 + i]);
        t1[64 + i] += sp_4096_add_64(&t1[i], &t1[i], t2);
    }

    r1 = sp_4096_cmp_64(t1, d) >= 0;
    sp_4096_cond_sub_64(r, t1, d, (sp_digit)0 - r1);

    return MP_OKAY;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_4096_mod_64(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_4096_div_64(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || \
                                                     defined(WOLFSSL_HAVE_SP_DH)
#ifdef WOLFSSL_SP_SMALL
/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success.
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even or exponent is 0.
 */
static int sp_4096_mod_exp_64(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[8 * 128];
    sp_digit* t[8];
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<8; i++) {
            t[i] = td + i * 128;
        }

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_64(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 64U);
        if (reduceA != 0) {
            err = sp_4096_mod_64(t[1] + 64, a, m);
            if (err == MP_OKAY) {
                err = sp_4096_mod_64(t[1], t[1], m);
            }
        }
        else {
            XMEMCPY(t[1] + 64, a, sizeof(sp_digit) * 64);
            err = sp_4096_mod_64(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_4096_mont_sqr_64(t[ 2], t[ 1], m, mp);
        sp_4096_mont_mul_64(t[ 3], t[ 2], t[ 1], m, mp);
        sp_4096_mont_sqr_64(t[ 4], t[ 2], m, mp);
        sp_4096_mont_mul_64(t[ 5], t[ 3], t[ 2], m, mp);
        sp_4096_mont_sqr_64(t[ 6], t[ 3], m, mp);
        sp_4096_mont_mul_64(t[ 7], t[ 4], t[ 3], m, mp);

        i = (bits - 1) / 64;
        n = e[i--];
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        c -= bits % 3;
        if (c == 64) {
            c = 61;
        }
        if (c < 0) {
            /* Number of bits in top word is less than number needed. */
            c = -c;
            y = (byte)(n << c);
            n = e[i--];
            y |= (byte)(n >> (64 - c));
            n <<= c;
            c = 64 - c;
        }
        else if (c == 0) {
            /* All bits in top word used. */
            y = (byte)n;
        }
        else {
            y = (byte)(n >> c);
            n <<= 64 - c;
        }
        XMEMCPY(r, t[y], sizeof(sp_digit) * 64);
        for (; i>=0 || c>=3; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 61);
                n <<= 3;
                c = 61;
            }
            else if (c < 3) {
                y = (byte)(n >> 61);
                n = e[i--];
                c = 3 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }
            else {
                y = (byte)((n >> 61) & 0x7);
                n <<= 3;
                c -= 3;
            }

            sp_4096_mont_sqr_64(r, r, m, mp);
            sp_4096_mont_sqr_64(r, r, m, mp);
            sp_4096_mont_sqr_64(r, r, m, mp);

            sp_4096_mont_mul_64(r, r, t[y], m, mp);
        }

        XMEMSET(&r[64], 0, sizeof(sp_digit) * 64U);
        sp_4096_mont_reduce_64(r, m, mp);

        mask = 0 - (sp_4096_cmp_64(r, m) >= 0);
        sp_4096_cond_sub_64(r, r, m, mask);
    }


    return err;
}
#else
/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success.
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even or exponent is 0.
 */
static int sp_4096_mod_exp_64(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[16 * 128];
    sp_digit* t[16];
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<16; i++) {
            t[i] = td + i * 128;
        }

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_64(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 64U);
        if (reduceA != 0) {
            err = sp_4096_mod_64(t[1] + 64, a, m);
            if (err == MP_OKAY) {
                err = sp_4096_mod_64(t[1], t[1], m);
            }
        }
        else {
            XMEMCPY(t[1] + 64, a, sizeof(sp_digit) * 64);
            err = sp_4096_mod_64(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_4096_mont_sqr_64(t[ 2], t[ 1], m, mp);
        sp_4096_mont_mul_64(t[ 3], t[ 2], t[ 1], m, mp);
        sp_4096_mont_sqr_64(t[ 4], t[ 2], m, mp);
        sp_4096_mont_mul_64(t[ 5], t[ 3], t[ 2], m, mp);
        sp_4096_mont_sqr_64(t[ 6], t[ 3], m, mp);
        sp_4096_mont_mul_64(t[ 7], t[ 4], t[ 3], m, mp);
        sp_4096_mont_sqr_64(t[ 8], t[ 4], m, mp);
        sp_4096_mont_mul_64(t[ 9], t[ 5], t[ 4], m, mp);
        sp_4096_mont_sqr_64(t[10], t[ 5], m, mp);
        sp_4096_mont_mul_64(t[11], t[ 6], t[ 5], m, mp);
        sp_4096_mont_sqr_64(t[12], t[ 6], m, mp);
        sp_4096_mont_mul_64(t[13], t[ 7], t[ 6], m, mp);
        sp_4096_mont_sqr_64(t[14], t[ 7], m, mp);
        sp_4096_mont_mul_64(t[15], t[ 8], t[ 7], m, mp);

        i = (bits - 1) / 64;
        n = e[i--];
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        c -= bits % 4;
        if (c == 64) {
            c = 60;
        }
        if (c < 0) {
            /* Number of bits in top word is less than number needed. */
            c = -c;
            y = (byte)(n << c);
            n = e[i--];
            y |= (byte)(n >> (64 - c));
            n <<= c;
            c = 64 - c;
        }
        else if (c == 0) {
            /* All bits in top word used. */
            y = (byte)n;
        }
        else {
            y = (byte)(n >> c);
            n <<= 64 - c;
        }
        XMEMCPY(r, t[y], sizeof(sp_digit) * 64);
        for (; i>=0 || c>=4; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 60);
                n <<= 4;
                c = 60;
            }
            else if (c < 4) {
                y = (byte)(n >> 60);
                n = e[i--];
                c = 4 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }
            else {
                y = (byte)((n >> 60) & 0xf);
                n <<= 4;
                c -= 4;
            }

            sp_4096_mont_sqr_64(r, r, m, mp);
            sp_4096_mont_sqr_64(r, r, m, mp);
            sp_4096_mont_sqr_64(r, r, m, mp);
            sp_4096_mont_sqr_64(r, r, m, mp);

            sp_4096_mont_mul_64(r, r, t[y], m, mp);
        }

        XMEMSET(&r[64], 0, sizeof(sp_digit) * 64U);
        sp_4096_mont_reduce_64(r, m, mp);

        mask = 0 - (sp_4096_cmp_64(r, m) >= 0);
        sp_4096_cond_sub_64(r, r, m, mask);
    }


    return err;
}
#endif /* WOLFSSL_SP_SMALL */
#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || WOLFSSL_HAVE_SP_DH */

#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || WOLFSSL_HAVE_SP_DH */
#ifdef WOLFSSL_HAVE_SP_RSA
/* RSA public key operation.
 *
 * in      Array of bytes representing the number to exponentiate, base.
 * inLen   Number of bytes in base.
 * em      Public exponent.
 * mm      Modulus.
 * out     Buffer to hold big-endian bytes of exponentiation result.
 *         Must be at least 512 bytes long.
 * outLen  Number of bytes in result.
 * returns 0 on success, MP_TO_E when the outLen is too small, MP_READ_E when
 * an array is too long and MEMORY_E when dynamic memory allocation fails.
 */
int sp_RsaPublic_4096(const byte* in, word32 inLen, const mp_int* em,
    const mp_int* mm, byte* out, word32* outLen)
{
    sp_digit a[64 * 5];
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit *ah = NULL;
    sp_digit e[1] = {0};
    int err = MP_OKAY;

    if (*outLen < 512) {
        err = MP_TO_E;
    }
    else if (mp_count_bits(em) > 64 || inLen > 512 ||
                                                     mp_count_bits(mm) != 4096) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mm)) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        ah = a + 64;
        r = a + 64 * 2;
        m = r + 64 * 2;

        sp_4096_from_bin(ah, 64, in, inLen);
#if DIGIT_BIT >= 64
        e[0] = em->dp[0];
#else
        e[0] = em->dp[0];
        if (em->used > 1) {
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
        }
#endif
        if (e[0] == 0) {
            err = MP_EXPTMOD_E;
        }
    }
    if (err == MP_OKAY) {
        sp_4096_from_mp(m, 64, mm);

        if (e[0] == 0x10001) {
            int i;
            sp_digit mp;

            sp_4096_mont_setup(m, &mp);

            /* Convert to Montgomery form. */
            XMEMSET(a, 0, sizeof(sp_digit) * 64);
            err = sp_4096_mod_64_cond(r, a, m);
            /* Montgomery form: r = a.R mod m */

            if (err == MP_OKAY) {
                /* r = a ^ 0x10000 => r = a squared 16 times */
                for (i = 15; i >= 0; i--) {
                    sp_4096_mont_sqr_64(r, r, m, mp);
                }
                /* mont_red(r.R.R) = (r.R.R / R) mod m = r.R mod m
                 * mont_red(r.R * a) = (r.R.a / R) mod m = r.a mod m
                 */
                sp_4096_mont_mul_64(r, r, ah, m, mp);

                for (i = 63; i > 0; i--) {
                    if (r[i] != m[i]) {
                        break;
                    }
                }
                if (r[i] >= m[i]) {
                    sp_4096_sub_in_place_64(r, m);
                }
            }
        }
        else if (e[0] == 0x3) {
            if (err == MP_OKAY) {
                sp_4096_sqr_64(r, ah);
                err = sp_4096_mod_64_cond(r, r, m);
            }
            if (err == MP_OKAY) {
                sp_4096_mul_64(r, ah, r);
                err = sp_4096_mod_64_cond(r, r, m);
            }
        }
        else {
            int i;
            sp_digit mp;

            sp_4096_mont_setup(m, &mp);

            /* Convert to Montgomery form. */
            XMEMSET(a, 0, sizeof(sp_digit) * 64);
            err = sp_4096_mod_64_cond(a, a, m);

            if (err == MP_OKAY) {
                for (i = 63; i >= 0; i--) {
                    if (e[0] >> i) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 64);
                for (i--; i >= 0; i--) {
                    sp_4096_mont_sqr_64(r, r, m, mp);
                    if (((e[0] >> i) & 1) == 1) {
                        sp_4096_mont_mul_64(r, r, a, m, mp);
                    }
                }
                XMEMSET(&r[64], 0, sizeof(sp_digit) * 64);
                sp_4096_mont_reduce_64(r, m, mp);

                for (i = 63; i > 0; i--) {
                    if (r[i] != m[i]) {
                        break;
                    }
                }
                if (r[i] >= m[i]) {
                    sp_4096_sub_in_place_64(r, m);
                }
            }
        }
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_64(r, out);
        *outLen = 512;
    }


    return err;
}

#ifndef WOLFSSL_RSA_PUBLIC_ONLY
#ifdef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static sp_digit sp_4096_cond_add_32(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	x8, #0\n\t"
        "1:\n\t"
        "adds	%[c], %[c], #-1\n\t"
        "ldr	x4, [%[a], x8]\n\t"
        "ldr	x5, [%[b], x8]\n\t"
        "and	x5, x5, %[m]\n\t"
        "adcs	x4, x4, x5\n\t"
        "cset	%[c], cs\n\t"
        "str	x4, [%[r], x8]\n\t"
        "add	x8, x8, #8\n\t"
        "cmp	x8, 256\n\t"
        "b.lt	1b\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x5", "x8", "x9", "x10", "x11", "x12"
    );

    return c;
}
#endif /* WOLFSSL_SP_SMALL */

/* RSA private key operation.
 *
 * in      Array of bytes representing the number to exponentiate, base.
 * inLen   Number of bytes in base.
 * dm      Private exponent.
 * pm      First prime.
 * qm      Second prime.
 * dpm     First prime's CRT exponent.
 * dqm     Second prime's CRT exponent.
 * qim     Inverse of second prime mod p.
 * mm      Modulus.
 * out     Buffer to hold big-endian bytes of exponentiation result.
 *         Must be at least 512 bytes long.
 * outLen  Number of bytes in result.
 * returns 0 on success, MP_TO_E when the outLen is too small, MP_READ_E when
 * an array is too long and MEMORY_E when dynamic memory allocation fails.
 */
int sp_RsaPrivate_4096(const byte* in, word32 inLen, const mp_int* dm,
    const mp_int* pm, const mp_int* qm, const mp_int* dpm, const mp_int* dqm,
    const mp_int* qim, const mp_int* mm, byte* out, word32* outLen)
{
#if defined(SP_RSA_PRIVATE_EXP_D) || defined(RSA_LOW_MEM)
    sp_digit  d[64 * 4];
    sp_digit* a = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;

    (void)pm;
    (void)qm;
    (void)dpm;
    (void)dqm;
    (void)qim;

    if (*outLen < 512U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(dm) > 4096) {
           err = MP_READ_E;
        }
        else if (inLen > 512) {
            err = MP_READ_E;
        }
        else if (mp_count_bits(mm) != 4096) {
            err = MP_READ_E;
        }
        else if (mp_iseven(mm)) {
            err = MP_VAL;
        }
    }


    if (err == MP_OKAY) {
        a = d + 64;
        m = a + 128;
        r = a;

        sp_4096_from_bin(a, 64, in, inLen);
        sp_4096_from_mp(d, 64, dm);
        sp_4096_from_mp(m, 64, mm);
        err = sp_4096_mod_exp_64(r, a, d, 4096, m, 0);
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_64(r, out);
        *outLen = 512;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 64);
    }

    return err;
#else
    sp_digit a[32 * 11];
    sp_digit* p = NULL;
    sp_digit* q = NULL;
    sp_digit* dp = NULL;
    sp_digit* tmpa = NULL;
    sp_digit* tmpb = NULL;
    sp_digit* r = NULL;
    sp_digit* qi = NULL;
    sp_digit* dq = NULL;
    sp_digit c;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 512) {
        err = MP_TO_E;
    }
    else if (inLen > 512 || mp_count_bits(mm) != 4096) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mm)) {
        err = MP_VAL;
    }
    else if (mp_iseven(pm)) {
        err = MP_VAL;
    }
    else if (mp_iseven(qm)) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        p = a + 64 * 2;
        q = p + 32;
        qi = dq = dp = q + 32;
        tmpa = qi + 32;
        tmpb = tmpa + 64;
        r = a;

        sp_4096_from_bin(a, 64, in, inLen);
        sp_4096_from_mp(p, 32, pm);
        sp_4096_from_mp(q, 32, qm);
        sp_4096_from_mp(dp, 32, dpm);

        err = sp_2048_mod_exp_32(tmpa, a, dp, 2048, p, 1);
    }
    if (err == MP_OKAY) {
        sp_4096_from_mp(dq, 32, dqm);
        err = sp_2048_mod_exp_32(tmpb, a, dq, 2048, q, 1);
    }

    if (err == MP_OKAY) {
        c = sp_2048_sub_in_place_32(tmpa, tmpb);
        c += sp_4096_cond_add_32(tmpa, tmpa, p, c);
        sp_4096_cond_add_32(tmpa, tmpa, p, c);

        sp_2048_from_mp(qi, 32, qim);
        sp_2048_mul_32(tmpa, tmpa, qi);
        err = sp_2048_mod_32(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_2048_mul_32(tmpa, q, tmpa);
        XMEMSET(&tmpb[32], 0, sizeof(sp_digit) * 32);
        sp_4096_add_64(r, tmpb, tmpa);

        sp_4096_to_bin_64(r, out);
        *outLen = 512;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 32 * 11);
    }
#endif /* SP_RSA_PRIVATE_EXP_D || RSA_LOW_MEM */
    return err;
}
#endif /* WOLFSSL_RSA_PUBLIC_ONLY */
#endif /* WOLFSSL_HAVE_SP_RSA */
#if defined(WOLFSSL_HAVE_SP_DH) || (defined(WOLFSSL_HAVE_SP_RSA) && \
                                              !defined(WOLFSSL_RSA_PUBLIC_ONLY))
/* Convert an array of sp_digit to an mp_int.
 *
 * a  A single precision integer.
 * r  A multi-precision integer.
 */
static int sp_4096_to_mp(const sp_digit* a, mp_int* r)
{
    int err;

    err = mp_grow(r, (4096 + DIGIT_BIT - 1) / DIGIT_BIT);
    if (err == MP_OKAY) { /*lint !e774 case where err is always MP_OKAY*/
#if DIGIT_BIT == 64
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 64);
        r->used = 64;
        mp_clamp(r);
#elif DIGIT_BIT < 64
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 64; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 64) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 64 - s;
        }
        r->used = (4096 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 64; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 64 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 64 - s;
            }
            else {
                s += 64;
            }
        }
        r->used = (4096 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#endif
    }

    return err;
}

/* Perform the modular exponentiation for Diffie-Hellman.
 *
 * base  Base. MP integer.
 * exp   Exponent. MP integer.
 * mod   Modulus. MP integer.
 * res   Result. MP integer.
 * returns 0 on success, MP_READ_E if there are too many bytes in an array
 * and MEMORY_E if memory allocation fails.
 */
int sp_ModExp_4096(const mp_int* base, const mp_int* exp, const mp_int* mod,
    mp_int* res)
{
    int err = MP_OKAY;
    sp_digit b[128];
    sp_digit e[64];
    sp_digit m[64];
    sp_digit* r = b;
    int expBits = mp_count_bits(exp);

    if (mp_count_bits(base) > 4096) {
        err = MP_READ_E;
    }
    else if (expBits > 4096) {
        err = MP_READ_E;
    }
    else if (mp_count_bits(mod) != 4096) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mod)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        sp_4096_from_mp(b, 64, base);
        sp_4096_from_mp(e, 64, exp);
        sp_4096_from_mp(m, 64, mod);

        err = sp_4096_mod_exp_64(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_4096_to_mp(r, res);
    }

    XMEMSET(e, 0, sizeof(e));

    return err;
}

#ifdef WOLFSSL_HAVE_SP_DH

#ifdef HAVE_FFDHE_4096
static void sp_4096_lshift_64(sp_digit* r, const sp_digit* a, byte n)
{
    word64 n64 = n;
    __asm__ __volatile__ (
        "mov	x6, 63\n\t"
        "sub	x6, x6, %[n]\n\t"
        "ldr	x3, [%[a], 504]\n\t"
        "lsr	x4, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x4, x4, x6\n\t"
        "ldr	x2, [%[a], 496]\n\t"
        "str	x4, [%[r], 512]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 488]\n\t"
        "str	x3, [%[r], 504]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 480]\n\t"
        "str	x2, [%[r], 496]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 472]\n\t"
        "str	x4, [%[r], 488]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 464]\n\t"
        "str	x3, [%[r], 480]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 456]\n\t"
        "str	x2, [%[r], 472]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 448]\n\t"
        "str	x4, [%[r], 464]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 440]\n\t"
        "str	x3, [%[r], 456]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 432]\n\t"
        "str	x2, [%[r], 448]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 424]\n\t"
        "str	x4, [%[r], 440]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 416]\n\t"
        "str	x3, [%[r], 432]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 408]\n\t"
        "str	x2, [%[r], 424]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 400]\n\t"
        "str	x4, [%[r], 416]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 392]\n\t"
        "str	x3, [%[r], 408]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 384]\n\t"
        "str	x2, [%[r], 400]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 376]\n\t"
        "str	x4, [%[r], 392]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 368]\n\t"
        "str	x3, [%[r], 384]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 360]\n\t"
        "str	x2, [%[r], 376]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 352]\n\t"
        "str	x4, [%[r], 368]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 344]\n\t"
        "str	x3, [%[r], 360]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 336]\n\t"
        "str	x2, [%[r], 352]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 328]\n\t"
        "str	x4, [%[r], 344]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 320]\n\t"
        "str	x3, [%[r], 336]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 312]\n\t"
        "str	x2, [%[r], 328]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 304]\n\t"
        "str	x4, [%[r], 320]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 296]\n\t"
        "str	x3, [%[r], 312]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 288]\n\t"
        "str	x2, [%[r], 304]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 280]\n\t"
        "str	x4, [%[r], 296]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 272]\n\t"
        "str	x3, [%[r], 288]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 264]\n\t"
        "str	x2, [%[r], 280]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 256]\n\t"
        "str	x4, [%[r], 272]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 248]\n\t"
        "str	x3, [%[r], 264]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 240]\n\t"
        "str	x2, [%[r], 256]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 232]\n\t"
        "str	x4, [%[r], 248]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 224]\n\t"
        "str	x3, [%[r], 240]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 216]\n\t"
        "str	x2, [%[r], 232]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 208]\n\t"
        "str	x4, [%[r], 224]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 200]\n\t"
        "str	x3, [%[r], 216]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 192]\n\t"
        "str	x2, [%[r], 208]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 184]\n\t"
        "str	x4, [%[r], 200]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 176]\n\t"
        "str	x3, [%[r], 192]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 168]\n\t"
        "str	x2, [%[r], 184]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 160]\n\t"
        "str	x4, [%[r], 176]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 152]\n\t"
        "str	x3, [%[r], 168]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 144]\n\t"
        "str	x2, [%[r], 160]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 136]\n\t"
        "str	x4, [%[r], 152]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 128]\n\t"
        "str	x3, [%[r], 144]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 120]\n\t"
        "str	x2, [%[r], 136]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 112]\n\t"
        "str	x4, [%[r], 128]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 104]\n\t"
        "str	x3, [%[r], 120]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 96]\n\t"
        "str	x2, [%[r], 112]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 88]\n\t"
        "str	x4, [%[r], 104]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 80]\n\t"
        "str	x3, [%[r], 96]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 72]\n\t"
        "str	x2, [%[r], 88]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 64]\n\t"
        "str	x4, [%[r], 80]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 56]\n\t"
        "str	x3, [%[r], 72]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 48]\n\t"
        "str	x2, [%[r], 64]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 40]\n\t"
        "str	x4, [%[r], 56]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 32]\n\t"
        "str	x3, [%[r], 48]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 24]\n\t"
        "str	x2, [%[r], 40]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "ldr	x2, [%[a], 16]\n\t"
        "str	x4, [%[r], 32]\n\t"
        "lsr	x5, x2, 1\n\t"
        "lsl	x2, x2, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x3, x3, x5\n\t"
        "ldr	x4, [%[a], 8]\n\t"
        "str	x3, [%[r], 24]\n\t"
        "lsr	x5, x4, 1\n\t"
        "lsl	x4, x4, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x2, x2, x5\n\t"
        "ldr	x3, [%[a], 0]\n\t"
        "str	x2, [%[r], 16]\n\t"
        "lsr	x5, x3, 1\n\t"
        "lsl	x3, x3, %[n]\n\t"
        "lsr	x5, x5, x6\n\t"
        "orr	x4, x4, x5\n\t"
        "stp	x3, x4, [%[r]]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [n] "r" (n64)
        : "memory", "x2", "x3", "x4", "x5", "x6"
    );
}

/* Modular exponentiate 2 to the e mod m. (r = 2^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success.
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even.
 */
static int sp_4096_mod_exp_2_64(sp_digit* r, const sp_digit* e, int bits,
        const sp_digit* m)
{
    sp_digit td[193];
    sp_digit* norm = NULL;
    sp_digit* tmp = NULL;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit o;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        tmp = td + 128;

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_64(norm, m);

        i = (bits - 1) / 64;
        n = e[i--];
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        c -= bits % 6;
        if (c == 64) {
            c = 58;
        }
        if (c < 0) {
            /* Number of bits in top word is less than number needed. */
            c = -c;
            y = (byte)(n << c);
            n = e[i--];
            y |= (byte)(n >> (64 - c));
            n <<= c;
            c = 64 - c;
        }
        else if (c == 0) {
            /* All bits in top word used. */
            y = (byte)n;
        }
        else {
            y = (byte)(n >> c);
            n <<= 64 - c;
        }
        sp_4096_lshift_64(r, norm, y);
        for (; i>=0 || c>=6; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 58);
                n <<= 6;
                c = 58;
            }
            else if (c < 6) {
                y = (byte)(n >> 58);
                n = e[i--];
                c = 6 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }
            else {
                y = (byte)((n >> 58) & 0x3f);
                n <<= 6;
                c -= 6;
            }

            sp_4096_mont_sqr_64(r, r, m, mp);
            sp_4096_mont_sqr_64(r, r, m, mp);
            sp_4096_mont_sqr_64(r, r, m, mp);
            sp_4096_mont_sqr_64(r, r, m, mp);
            sp_4096_mont_sqr_64(r, r, m, mp);
            sp_4096_mont_sqr_64(r, r, m, mp);

            sp_4096_lshift_64(r, r, y);
            sp_4096_mul_d_64(tmp, norm, r[64]);
            r[64] = 0;
            o = sp_4096_add_64(r, r, tmp);
            sp_4096_cond_sub_64(r, r, m, (sp_digit)0 - o);
        }

        XMEMSET(&r[64], 0, sizeof(sp_digit) * 64U);
        sp_4096_mont_reduce_64(r, m, mp);

        mask = 0 - (sp_4096_cmp_64(r, m) >= 0);
        sp_4096_cond_sub_64(r, r, m, mask);
    }


    return err;
}
#endif /* HAVE_FFDHE_4096 */

/* Perform the modular exponentiation for Diffie-Hellman.
 *
 * base     Base.
 * exp      Array of bytes that is the exponent.
 * expLen   Length of data, in bytes, in exponent.
 * mod      Modulus.
 * out      Buffer to hold big-endian bytes of exponentiation result.
 *          Must be at least 512 bytes long.
 * outLen   Length, in bytes, of exponentiation result.
 * returns 0 on success, MP_READ_E if there are too many bytes in an array
 * and MEMORY_E if memory allocation fails.
 */
int sp_DhExp_4096(const mp_int* base, const byte* exp, word32 expLen,
    const mp_int* mod, byte* out, word32* outLen)
{
    int err = MP_OKAY;
    sp_digit b[128];
    sp_digit e[64];
    sp_digit m[64];
    sp_digit* r = b;
    word32 i;

    if (mp_count_bits(base) > 4096) {
        err = MP_READ_E;
    }
    else if (expLen > 512) {
        err = MP_READ_E;
    }
    else if (mp_count_bits(mod) != 4096) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mod)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        sp_4096_from_mp(b, 64, base);
        sp_4096_from_bin(e, 64, exp, expLen);
        sp_4096_from_mp(m, 64, mod);

    #ifdef HAVE_FFDHE_4096
        if (base->used == 1 && base->dp[0] == 2 && m[63] == (sp_digit)-1)
            err = sp_4096_mod_exp_2_64(r, e, expLen * 8, m);
        else
    #endif
            err = sp_4096_mod_exp_64(r, b, e, expLen * 8, m, 0);

    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_64(r, out);
        *outLen = 512;
        for (i=0; i<512 && out[i] == 0; i++) {
            /* Search for first non-zero. */
        }
        *outLen -= i;
        XMEMMOVE(out, out + i, *outLen);

    }

    XMEMSET(e, 0, sizeof(e));

    return err;
}
#endif /* WOLFSSL_HAVE_SP_DH */

#endif /* WOLFSSL_HAVE_SP_DH | (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) */

#endif /* WOLFSSL_SP_4096 */

#endif /* WOLFSSL_HAVE_SP_RSA | WOLFSSL_HAVE_SP_DH */
#endif /* WOLFSSL_SP_ARM64_ASM */
#endif /* WOLFSSL_HAVE_SP_RSA | WOLFSSL_HAVE_SP_DH | WOLFSSL_HAVE_SP_ECC */
