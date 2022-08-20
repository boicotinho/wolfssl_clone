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

#ifdef WOLFSSL_SP_ARM32_ASM
#define SP_PRINT_NUM(var, name, total, words, bits)         \
    do {                                                    \
        int ii;                                             \
        fprintf(stderr, name "=0x");                        \
        for (ii = ((bits + 31) / 32) - 1; ii >= 0; ii--)    \
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
    int i;
    int j;
    byte* d;

    for (i = n - 1,j = 0; i >= 3; i -= 4) {
        r[j]  = ((sp_digit)a[i - 0] <<  0) |
                ((sp_digit)a[i - 1] <<  8) |
                ((sp_digit)a[i - 2] << 16) |
                ((sp_digit)a[i - 3] << 24);
        j++;
    }

    if (i >= 0) {
        r[j] = 0;

        d = (byte*)r;
        switch (i) {
            case 2: d[n - 1 - 2] = a[2]; //fallthrough
            case 1: d[n - 1 - 1] = a[1]; //fallthrough
            case 0: d[n - 1 - 0] = a[0]; //fallthrough
        }
        j++;
    }

    for (; j < size; j++) {
        r[j] = 0;
    }
}

/* Convert an mp_int to an array of sp_digit.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  A multi-precision integer.
 */
static void sp_2048_from_mp(sp_digit* r, int size, const mp_int* a)
{
#if DIGIT_BIT == 32
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 32
    int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0xffffffff;
        s = 32U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 32U) <= (word32)DIGIT_BIT) {
            s += 32U;
            r[j] &= 0xffffffff;
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
        if (s + DIGIT_BIT >= 32) {
            r[j] &= 0xffffffff;
            if (j + 1 >= size) {
                break;
            }
            s = 32 - s;
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
static void sp_2048_to_bin_64(sp_digit* r, byte* a)
{
    int i;
    int j = 0;

    for (i = 63; i >= 0; i--) {
        a[j++] = r[i] >> 24;
        a[j++] = r[i] >> 16;
        a[j++] = r[i] >> 8;
        a[j++] = r[i] >> 0;
    }
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && (!defined(WOLFSSL_RSA_PUBLIC_ONLY) || !defined(WOLFSSL_SP_SMALL))) || defined(WOLFSSL_HAVE_SP_DH)
/* Normalize the values in each word to 32.
 *
 * a  Array of sp_digit to normalize.
 */
#define sp_2048_norm_64(a)

#endif /* (WOLFSSL_HAVE_SP_RSA && (!WOLFSSL_RSA_PUBLIC_ONLY || !WOLFSSL_SP_SMALL)) || WOLFSSL_HAVE_SP_DH */
/* Normalize the values in each word to 32.
 *
 * a  Array of sp_digit to normalize.
 */
#define sp_2048_norm_64(a)

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
        "sub	sp, sp, #32\n\t"
        "mov	r10, #0\n\t"
        "#  A[0] * B[0]\n\t"
        "ldr	r11, [%[a], #0]\n\t"
        "ldr	r12, [%[b], #0]\n\t"
        "umull	r3, r4, r11, r12\n\t"
        "mov	r5, #0\n\t"
        "str	r3, [sp]\n\t"
        "#  A[0] * B[1]\n\t"
        "ldr	r9, [%[b], #4]\n\t"
        "umull	r6, r7, r11, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "#  A[1] * B[0]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "str	r4, [sp, #4]\n\t"
        "#  A[2] * B[0]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "#  A[1] * B[1]\n\t"
        "ldr	r11, [%[a], #4]\n\t"
        "ldr	r12, [%[b], #4]\n\t"
        "umull	r6, r7, r11, r12\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[0] * B[2]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "ldr	r9, [%[b], #8]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "str	r5, [sp, #8]\n\t"
        "#  A[0] * B[3]\n\t"
        "ldr	r9, [%[b], #12]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "#  A[1] * B[2]\n\t"
        "ldr	r9, [%[b], #8]\n\t"
        "umull	r6, r7, r11, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[2] * B[1]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[3] * B[0]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "ldr	r9, [%[b], #0]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "str	r3, [sp, #12]\n\t"
        "#  A[4] * B[0]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "#  A[3] * B[1]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[2] * B[2]\n\t"
        "ldr	r11, [%[a], #8]\n\t"
        "ldr	r12, [%[b], #8]\n\t"
        "umull	r6, r7, r11, r12\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[1] * B[3]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "ldr	r9, [%[b], #12]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[0] * B[4]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "ldr	r9, [%[b], #16]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "str	r4, [sp, #16]\n\t"
        "#  A[0] * B[5]\n\t"
        "ldr	r9, [%[b], #20]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "#  A[1] * B[4]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "ldr	r9, [%[b], #16]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[2] * B[3]\n\t"
        "ldr	r9, [%[b], #12]\n\t"
        "umull	r6, r7, r11, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[3] * B[2]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[4] * B[1]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "ldr	r9, [%[b], #4]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[5] * B[0]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "ldr	r9, [%[b], #0]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "str	r5, [sp, #20]\n\t"
        "#  A[6] * B[0]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "#  A[5] * B[1]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "ldr	r9, [%[b], #4]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[4] * B[2]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[3] * B[3]\n\t"
        "ldr	r11, [%[a], #12]\n\t"
        "ldr	r12, [%[b], #12]\n\t"
        "umull	r6, r7, r11, r12\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[2] * B[4]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "ldr	r9, [%[b], #16]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[1] * B[5]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "ldr	r9, [%[b], #20]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[0] * B[6]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "ldr	r9, [%[b], #24]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "str	r3, [sp, #24]\n\t"
        "#  A[0] * B[7]\n\t"
        "ldr	r9, [%[b], #28]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "#  A[1] * B[6]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "ldr	r9, [%[b], #24]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[2] * B[5]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "ldr	r9, [%[b], #20]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[3] * B[4]\n\t"
        "ldr	r9, [%[b], #16]\n\t"
        "umull	r6, r7, r11, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[4] * B[3]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[5] * B[2]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "ldr	r9, [%[b], #8]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[6] * B[1]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "ldr	r9, [%[b], #4]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[7] * B[0]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "ldr	r9, [%[b], #0]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "str	r4, [sp, #28]\n\t"
        "#  A[7] * B[1]\n\t"
        "ldr	r9, [%[b], #4]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "#  A[6] * B[2]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "ldr	r9, [%[b], #8]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[5] * B[3]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[4] * B[4]\n\t"
        "ldr	r11, [%[a], #16]\n\t"
        "ldr	r12, [%[b], #16]\n\t"
        "umull	r6, r7, r11, r12\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[3] * B[5]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "ldr	r9, [%[b], #20]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[2] * B[6]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "ldr	r9, [%[b], #24]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[1] * B[7]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "ldr	r9, [%[b], #28]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "str	r5, [%[r], #32]\n\t"
        "#  A[2] * B[7]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "#  A[3] * B[6]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "ldr	r9, [%[b], #24]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[4] * B[5]\n\t"
        "ldr	r9, [%[b], #20]\n\t"
        "umull	r6, r7, r11, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[5] * B[4]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[6] * B[3]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "ldr	r9, [%[b], #12]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[7] * B[2]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "ldr	r9, [%[b], #8]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "str	r3, [%[r], #36]\n\t"
        "#  A[7] * B[3]\n\t"
        "ldr	r9, [%[b], #12]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "#  A[6] * B[4]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[5] * B[5]\n\t"
        "ldr	r11, [%[a], #20]\n\t"
        "ldr	r12, [%[b], #20]\n\t"
        "umull	r6, r7, r11, r12\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[4] * B[6]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "ldr	r9, [%[b], #24]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[3] * B[7]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "ldr	r9, [%[b], #28]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "str	r4, [%[r], #40]\n\t"
        "#  A[4] * B[7]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "#  A[5] * B[6]\n\t"
        "ldr	r9, [%[b], #24]\n\t"
        "umull	r6, r7, r11, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[6] * B[5]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[7] * B[4]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "ldr	r9, [%[b], #16]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "str	r5, [%[r], #44]\n\t"
        "#  A[7] * B[5]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "#  A[6] * B[6]\n\t"
        "ldr	r11, [%[a], #24]\n\t"
        "ldr	r12, [%[b], #24]\n\t"
        "umull	r6, r7, r11, r12\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[5] * B[7]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "ldr	r9, [%[b], #28]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "str	r3, [%[r], #48]\n\t"
        "#  A[6] * B[7]\n\t"
        "umull	r6, r7, r11, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "#  A[7] * B[6]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "str	r4, [%[r], #52]\n\t"
        "#  A[7] * B[7]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adc	r3, r3, r7\n\t"
        "str	r5, [%[r], #56]\n\t"
        "str	r3, [%[r], #60]\n\t"
        "ldm	sp!, {r3, r4, r5, r6}\n\t"
        "stm	%[r]!, {r3, r4, r5, r6}\n\t"
        "ldm	sp!, {r3, r4, r5, r6}\n\t"
        "stm	%[r]!, {r3, r4, r5, r6}\n\t"
        "sub	%[r], %[r], #32\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
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
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r14, #0\n\t"
        "ldrd	r3, r4, [%[a], #0]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b], #0]\n\t"
        "ldrd	r9, r10, [%[b], #8]\n\t"
        "adds	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #0]\n\t"
        "strd	r5, r6, [%[r], #8]\n\t"
        "ldrd	r3, r4, [%[a], #16]\n\t"
        "ldrd	r5, r6, [%[a], #24]\n\t"
        "ldrd	r7, r8, [%[b], #16]\n\t"
        "ldrd	r9, r10, [%[b], #24]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #16]\n\t"
        "strd	r5, r6, [%[r], #24]\n\t"
        "adc	%[c], r14, r14\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14"
    );

    return c;
}

/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer and result.
 * b  A single precision integer.
 */
static sp_digit sp_2048_sub_in_place_16(sp_digit* a, const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldrd	r2, r3, [%[a], #0]\n\t"
        "ldrd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r6, r7, [%[b], #0]\n\t"
        "ldrd	r8, r9, [%[b], #8]\n\t"
        "subs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #0]\n\t"
        "strd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r2, r3, [%[a], #16]\n\t"
        "ldrd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r6, r7, [%[b], #16]\n\t"
        "ldrd	r8, r9, [%[b], #24]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #16]\n\t"
        "strd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r2, r3, [%[a], #32]\n\t"
        "ldrd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r6, r7, [%[b], #32]\n\t"
        "ldrd	r8, r9, [%[b], #40]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #32]\n\t"
        "strd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r2, r3, [%[a], #48]\n\t"
        "ldrd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r6, r7, [%[b], #48]\n\t"
        "ldrd	r8, r9, [%[b], #56]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #48]\n\t"
        "strd	r4, r5, [%[a], #56]\n\t"
        "sbc	%[c], r9, r9\n\t"
        : [c] "+r" (c)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9"
    );

    return c;
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
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r14, #0\n\t"
        "ldrd	r3, r4, [%[a], #0]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b], #0]\n\t"
        "ldrd	r9, r10, [%[b], #8]\n\t"
        "adds	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #0]\n\t"
        "strd	r5, r6, [%[r], #8]\n\t"
        "ldrd	r3, r4, [%[a], #16]\n\t"
        "ldrd	r5, r6, [%[a], #24]\n\t"
        "ldrd	r7, r8, [%[b], #16]\n\t"
        "ldrd	r9, r10, [%[b], #24]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #16]\n\t"
        "strd	r5, r6, [%[r], #24]\n\t"
        "ldrd	r3, r4, [%[a], #32]\n\t"
        "ldrd	r5, r6, [%[a], #40]\n\t"
        "ldrd	r7, r8, [%[b], #32]\n\t"
        "ldrd	r9, r10, [%[b], #40]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #32]\n\t"
        "strd	r5, r6, [%[r], #40]\n\t"
        "ldrd	r3, r4, [%[a], #48]\n\t"
        "ldrd	r5, r6, [%[a], #56]\n\t"
        "ldrd	r7, r8, [%[b], #48]\n\t"
        "ldrd	r9, r10, [%[b], #56]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #48]\n\t"
        "strd	r5, r6, [%[r], #56]\n\t"
        "adc	%[c], r14, r14\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14"
    );

    return c;
}

/* AND m into each word of a and store in r.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * m  Mask to AND against each digit.
 */
static void sp_2048_mask_8(sp_digit* r, const sp_digit* a, sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<8; i++) {
        r[i] = a[i] & m;
    }
#else
    r[0] = a[0] & m;
    r[1] = a[1] & m;
    r[2] = a[2] & m;
    r[3] = a[3] & m;
    r[4] = a[4] & m;
    r[5] = a[5] & m;
    r[6] = a[6] & m;
    r[7] = a[7] & m;
#endif
}

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
    sp_2048_mask_8(a1, a1, 0 - cb);
    u += sp_2048_add_8(z1 + 8, z1 + 8, a1);
    sp_2048_mask_8(b1, b1, 0 - ca);
    u += sp_2048_add_8(z1 + 8, z1 + 8, b1);

    u += sp_2048_add_16(r + 8, r + 8, z1);
    XMEMSET(a1 + 1, 0, sizeof(sp_digit) * (8 - 1));
    a1[0] = u;
    (void)sp_2048_add_8(r + 24, r + 24, a1);
}

/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer and result.
 * b  A single precision integer.
 */
static sp_digit sp_2048_sub_in_place_32(sp_digit* a, const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldrd	r2, r3, [%[a], #0]\n\t"
        "ldrd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r6, r7, [%[b], #0]\n\t"
        "ldrd	r8, r9, [%[b], #8]\n\t"
        "subs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #0]\n\t"
        "strd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r2, r3, [%[a], #16]\n\t"
        "ldrd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r6, r7, [%[b], #16]\n\t"
        "ldrd	r8, r9, [%[b], #24]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #16]\n\t"
        "strd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r2, r3, [%[a], #32]\n\t"
        "ldrd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r6, r7, [%[b], #32]\n\t"
        "ldrd	r8, r9, [%[b], #40]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #32]\n\t"
        "strd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r2, r3, [%[a], #48]\n\t"
        "ldrd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r6, r7, [%[b], #48]\n\t"
        "ldrd	r8, r9, [%[b], #56]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #48]\n\t"
        "strd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r2, r3, [%[a], #64]\n\t"
        "ldrd	r4, r5, [%[a], #72]\n\t"
        "ldrd	r6, r7, [%[b], #64]\n\t"
        "ldrd	r8, r9, [%[b], #72]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #64]\n\t"
        "strd	r4, r5, [%[a], #72]\n\t"
        "ldrd	r2, r3, [%[a], #80]\n\t"
        "ldrd	r4, r5, [%[a], #88]\n\t"
        "ldrd	r6, r7, [%[b], #80]\n\t"
        "ldrd	r8, r9, [%[b], #88]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #80]\n\t"
        "strd	r4, r5, [%[a], #88]\n\t"
        "ldrd	r2, r3, [%[a], #96]\n\t"
        "ldrd	r4, r5, [%[a], #104]\n\t"
        "ldrd	r6, r7, [%[b], #96]\n\t"
        "ldrd	r8, r9, [%[b], #104]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #96]\n\t"
        "strd	r4, r5, [%[a], #104]\n\t"
        "ldrd	r2, r3, [%[a], #112]\n\t"
        "ldrd	r4, r5, [%[a], #120]\n\t"
        "ldrd	r6, r7, [%[b], #112]\n\t"
        "ldrd	r8, r9, [%[b], #120]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #112]\n\t"
        "strd	r4, r5, [%[a], #120]\n\t"
        "sbc	%[c], r9, r9\n\t"
        : [c] "+r" (c)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9"
    );

    return c;
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
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r14, #0\n\t"
        "ldrd	r3, r4, [%[a], #0]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b], #0]\n\t"
        "ldrd	r9, r10, [%[b], #8]\n\t"
        "adds	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #0]\n\t"
        "strd	r5, r6, [%[r], #8]\n\t"
        "ldrd	r3, r4, [%[a], #16]\n\t"
        "ldrd	r5, r6, [%[a], #24]\n\t"
        "ldrd	r7, r8, [%[b], #16]\n\t"
        "ldrd	r9, r10, [%[b], #24]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #16]\n\t"
        "strd	r5, r6, [%[r], #24]\n\t"
        "ldrd	r3, r4, [%[a], #32]\n\t"
        "ldrd	r5, r6, [%[a], #40]\n\t"
        "ldrd	r7, r8, [%[b], #32]\n\t"
        "ldrd	r9, r10, [%[b], #40]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #32]\n\t"
        "strd	r5, r6, [%[r], #40]\n\t"
        "ldrd	r3, r4, [%[a], #48]\n\t"
        "ldrd	r5, r6, [%[a], #56]\n\t"
        "ldrd	r7, r8, [%[b], #48]\n\t"
        "ldrd	r9, r10, [%[b], #56]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #48]\n\t"
        "strd	r5, r6, [%[r], #56]\n\t"
        "ldrd	r3, r4, [%[a], #64]\n\t"
        "ldrd	r5, r6, [%[a], #72]\n\t"
        "ldrd	r7, r8, [%[b], #64]\n\t"
        "ldrd	r9, r10, [%[b], #72]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #64]\n\t"
        "strd	r5, r6, [%[r], #72]\n\t"
        "ldrd	r3, r4, [%[a], #80]\n\t"
        "ldrd	r5, r6, [%[a], #88]\n\t"
        "ldrd	r7, r8, [%[b], #80]\n\t"
        "ldrd	r9, r10, [%[b], #88]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #80]\n\t"
        "strd	r5, r6, [%[r], #88]\n\t"
        "ldrd	r3, r4, [%[a], #96]\n\t"
        "ldrd	r5, r6, [%[a], #104]\n\t"
        "ldrd	r7, r8, [%[b], #96]\n\t"
        "ldrd	r9, r10, [%[b], #104]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #96]\n\t"
        "strd	r5, r6, [%[r], #104]\n\t"
        "ldrd	r3, r4, [%[a], #112]\n\t"
        "ldrd	r5, r6, [%[a], #120]\n\t"
        "ldrd	r7, r8, [%[b], #112]\n\t"
        "ldrd	r9, r10, [%[b], #120]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #112]\n\t"
        "strd	r5, r6, [%[r], #120]\n\t"
        "adc	%[c], r14, r14\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14"
    );

    return c;
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
    sp_2048_mask_16(a1, a1, 0 - cb);
    u += sp_2048_add_16(z1 + 16, z1 + 16, a1);
    sp_2048_mask_16(b1, b1, 0 - ca);
    u += sp_2048_add_16(z1 + 16, z1 + 16, b1);

    u += sp_2048_add_32(r + 16, r + 16, z1);
    XMEMSET(a1 + 1, 0, sizeof(sp_digit) * (16 - 1));
    a1[0] = u;
    (void)sp_2048_add_16(r + 48, r + 48, a1);
}

/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer and result.
 * b  A single precision integer.
 */
static sp_digit sp_2048_sub_in_place_64(sp_digit* a, const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldrd	r2, r3, [%[a], #0]\n\t"
        "ldrd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r6, r7, [%[b], #0]\n\t"
        "ldrd	r8, r9, [%[b], #8]\n\t"
        "subs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #0]\n\t"
        "strd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r2, r3, [%[a], #16]\n\t"
        "ldrd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r6, r7, [%[b], #16]\n\t"
        "ldrd	r8, r9, [%[b], #24]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #16]\n\t"
        "strd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r2, r3, [%[a], #32]\n\t"
        "ldrd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r6, r7, [%[b], #32]\n\t"
        "ldrd	r8, r9, [%[b], #40]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #32]\n\t"
        "strd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r2, r3, [%[a], #48]\n\t"
        "ldrd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r6, r7, [%[b], #48]\n\t"
        "ldrd	r8, r9, [%[b], #56]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #48]\n\t"
        "strd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r2, r3, [%[a], #64]\n\t"
        "ldrd	r4, r5, [%[a], #72]\n\t"
        "ldrd	r6, r7, [%[b], #64]\n\t"
        "ldrd	r8, r9, [%[b], #72]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #64]\n\t"
        "strd	r4, r5, [%[a], #72]\n\t"
        "ldrd	r2, r3, [%[a], #80]\n\t"
        "ldrd	r4, r5, [%[a], #88]\n\t"
        "ldrd	r6, r7, [%[b], #80]\n\t"
        "ldrd	r8, r9, [%[b], #88]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #80]\n\t"
        "strd	r4, r5, [%[a], #88]\n\t"
        "ldrd	r2, r3, [%[a], #96]\n\t"
        "ldrd	r4, r5, [%[a], #104]\n\t"
        "ldrd	r6, r7, [%[b], #96]\n\t"
        "ldrd	r8, r9, [%[b], #104]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #96]\n\t"
        "strd	r4, r5, [%[a], #104]\n\t"
        "ldrd	r2, r3, [%[a], #112]\n\t"
        "ldrd	r4, r5, [%[a], #120]\n\t"
        "ldrd	r6, r7, [%[b], #112]\n\t"
        "ldrd	r8, r9, [%[b], #120]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #112]\n\t"
        "strd	r4, r5, [%[a], #120]\n\t"
        "ldrd	r2, r3, [%[a], #128]\n\t"
        "ldrd	r4, r5, [%[a], #136]\n\t"
        "ldrd	r6, r7, [%[b], #128]\n\t"
        "ldrd	r8, r9, [%[b], #136]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #128]\n\t"
        "strd	r4, r5, [%[a], #136]\n\t"
        "ldrd	r2, r3, [%[a], #144]\n\t"
        "ldrd	r4, r5, [%[a], #152]\n\t"
        "ldrd	r6, r7, [%[b], #144]\n\t"
        "ldrd	r8, r9, [%[b], #152]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #144]\n\t"
        "strd	r4, r5, [%[a], #152]\n\t"
        "ldrd	r2, r3, [%[a], #160]\n\t"
        "ldrd	r4, r5, [%[a], #168]\n\t"
        "ldrd	r6, r7, [%[b], #160]\n\t"
        "ldrd	r8, r9, [%[b], #168]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #160]\n\t"
        "strd	r4, r5, [%[a], #168]\n\t"
        "ldrd	r2, r3, [%[a], #176]\n\t"
        "ldrd	r4, r5, [%[a], #184]\n\t"
        "ldrd	r6, r7, [%[b], #176]\n\t"
        "ldrd	r8, r9, [%[b], #184]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #176]\n\t"
        "strd	r4, r5, [%[a], #184]\n\t"
        "ldrd	r2, r3, [%[a], #192]\n\t"
        "ldrd	r4, r5, [%[a], #200]\n\t"
        "ldrd	r6, r7, [%[b], #192]\n\t"
        "ldrd	r8, r9, [%[b], #200]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #192]\n\t"
        "strd	r4, r5, [%[a], #200]\n\t"
        "ldrd	r2, r3, [%[a], #208]\n\t"
        "ldrd	r4, r5, [%[a], #216]\n\t"
        "ldrd	r6, r7, [%[b], #208]\n\t"
        "ldrd	r8, r9, [%[b], #216]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #208]\n\t"
        "strd	r4, r5, [%[a], #216]\n\t"
        "ldrd	r2, r3, [%[a], #224]\n\t"
        "ldrd	r4, r5, [%[a], #232]\n\t"
        "ldrd	r6, r7, [%[b], #224]\n\t"
        "ldrd	r8, r9, [%[b], #232]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #224]\n\t"
        "strd	r4, r5, [%[a], #232]\n\t"
        "ldrd	r2, r3, [%[a], #240]\n\t"
        "ldrd	r4, r5, [%[a], #248]\n\t"
        "ldrd	r6, r7, [%[b], #240]\n\t"
        "ldrd	r8, r9, [%[b], #248]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #240]\n\t"
        "strd	r4, r5, [%[a], #248]\n\t"
        "sbc	%[c], r9, r9\n\t"
        : [c] "+r" (c)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9"
    );

    return c;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_2048_add_64(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r14, #0\n\t"
        "ldrd	r3, r4, [%[a], #0]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b], #0]\n\t"
        "ldrd	r9, r10, [%[b], #8]\n\t"
        "adds	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #0]\n\t"
        "strd	r5, r6, [%[r], #8]\n\t"
        "ldrd	r3, r4, [%[a], #16]\n\t"
        "ldrd	r5, r6, [%[a], #24]\n\t"
        "ldrd	r7, r8, [%[b], #16]\n\t"
        "ldrd	r9, r10, [%[b], #24]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #16]\n\t"
        "strd	r5, r6, [%[r], #24]\n\t"
        "ldrd	r3, r4, [%[a], #32]\n\t"
        "ldrd	r5, r6, [%[a], #40]\n\t"
        "ldrd	r7, r8, [%[b], #32]\n\t"
        "ldrd	r9, r10, [%[b], #40]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #32]\n\t"
        "strd	r5, r6, [%[r], #40]\n\t"
        "ldrd	r3, r4, [%[a], #48]\n\t"
        "ldrd	r5, r6, [%[a], #56]\n\t"
        "ldrd	r7, r8, [%[b], #48]\n\t"
        "ldrd	r9, r10, [%[b], #56]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #48]\n\t"
        "strd	r5, r6, [%[r], #56]\n\t"
        "ldrd	r3, r4, [%[a], #64]\n\t"
        "ldrd	r5, r6, [%[a], #72]\n\t"
        "ldrd	r7, r8, [%[b], #64]\n\t"
        "ldrd	r9, r10, [%[b], #72]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #64]\n\t"
        "strd	r5, r6, [%[r], #72]\n\t"
        "ldrd	r3, r4, [%[a], #80]\n\t"
        "ldrd	r5, r6, [%[a], #88]\n\t"
        "ldrd	r7, r8, [%[b], #80]\n\t"
        "ldrd	r9, r10, [%[b], #88]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #80]\n\t"
        "strd	r5, r6, [%[r], #88]\n\t"
        "ldrd	r3, r4, [%[a], #96]\n\t"
        "ldrd	r5, r6, [%[a], #104]\n\t"
        "ldrd	r7, r8, [%[b], #96]\n\t"
        "ldrd	r9, r10, [%[b], #104]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #96]\n\t"
        "strd	r5, r6, [%[r], #104]\n\t"
        "ldrd	r3, r4, [%[a], #112]\n\t"
        "ldrd	r5, r6, [%[a], #120]\n\t"
        "ldrd	r7, r8, [%[b], #112]\n\t"
        "ldrd	r9, r10, [%[b], #120]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #112]\n\t"
        "strd	r5, r6, [%[r], #120]\n\t"
        "ldrd	r3, r4, [%[a], #128]\n\t"
        "ldrd	r5, r6, [%[a], #136]\n\t"
        "ldrd	r7, r8, [%[b], #128]\n\t"
        "ldrd	r9, r10, [%[b], #136]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #128]\n\t"
        "strd	r5, r6, [%[r], #136]\n\t"
        "ldrd	r3, r4, [%[a], #144]\n\t"
        "ldrd	r5, r6, [%[a], #152]\n\t"
        "ldrd	r7, r8, [%[b], #144]\n\t"
        "ldrd	r9, r10, [%[b], #152]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #144]\n\t"
        "strd	r5, r6, [%[r], #152]\n\t"
        "ldrd	r3, r4, [%[a], #160]\n\t"
        "ldrd	r5, r6, [%[a], #168]\n\t"
        "ldrd	r7, r8, [%[b], #160]\n\t"
        "ldrd	r9, r10, [%[b], #168]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #160]\n\t"
        "strd	r5, r6, [%[r], #168]\n\t"
        "ldrd	r3, r4, [%[a], #176]\n\t"
        "ldrd	r5, r6, [%[a], #184]\n\t"
        "ldrd	r7, r8, [%[b], #176]\n\t"
        "ldrd	r9, r10, [%[b], #184]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #176]\n\t"
        "strd	r5, r6, [%[r], #184]\n\t"
        "ldrd	r3, r4, [%[a], #192]\n\t"
        "ldrd	r5, r6, [%[a], #200]\n\t"
        "ldrd	r7, r8, [%[b], #192]\n\t"
        "ldrd	r9, r10, [%[b], #200]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #192]\n\t"
        "strd	r5, r6, [%[r], #200]\n\t"
        "ldrd	r3, r4, [%[a], #208]\n\t"
        "ldrd	r5, r6, [%[a], #216]\n\t"
        "ldrd	r7, r8, [%[b], #208]\n\t"
        "ldrd	r9, r10, [%[b], #216]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #208]\n\t"
        "strd	r5, r6, [%[r], #216]\n\t"
        "ldrd	r3, r4, [%[a], #224]\n\t"
        "ldrd	r5, r6, [%[a], #232]\n\t"
        "ldrd	r7, r8, [%[b], #224]\n\t"
        "ldrd	r9, r10, [%[b], #232]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #224]\n\t"
        "strd	r5, r6, [%[r], #232]\n\t"
        "ldrd	r3, r4, [%[a], #240]\n\t"
        "ldrd	r5, r6, [%[a], #248]\n\t"
        "ldrd	r7, r8, [%[b], #240]\n\t"
        "ldrd	r9, r10, [%[b], #248]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #240]\n\t"
        "strd	r5, r6, [%[r], #248]\n\t"
        "adc	%[c], r14, r14\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14"
    );

    return c;
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

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_64(sp_digit* r, const sp_digit* a,
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

    u += sp_2048_sub_in_place_64(z1, z0);
    u += sp_2048_sub_in_place_64(z1, z2);
    sp_2048_mask_32(a1, a1, 0 - cb);
    u += sp_2048_add_32(z1 + 32, z1 + 32, a1);
    sp_2048_mask_32(b1, b1, 0 - ca);
    u += sp_2048_add_32(z1 + 32, z1 + 32, b1);

    u += sp_2048_add_64(r + 32, r + 32, z1);
    XMEMSET(a1 + 1, 0, sizeof(sp_digit) * (32 - 1));
    a1[0] = u;
    (void)sp_2048_add_32(r + 96, r + 96, a1);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
static void sp_2048_sqr_8(sp_digit* r, const sp_digit* a)
{
    __asm__ __volatile__ (
        "sub	sp, sp, #32\n\t"
        "mov	r12, #0\n\t"
        "#  A[0] * A[0]\n\t"
        "ldr	r10, [%[a], #0]\n\t"
        "umull	r8, r3, r10, r10\n\t"
        "mov	r4, #0\n\t"
        "str	r8, [sp]\n\t"
        "#  A[0] * A[1]\n\t"
        "ldr	r10, [%[a], #4]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r12, r12\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r2, r12\n\t"
        "str	r3, [sp, #4]\n\t"
        "#  A[0] * A[2]\n\t"
        "ldr	r10, [%[a], #8]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r4, r4, r8\n\t"
        "adcs	r2, r2, r9\n\t"
        "adc	r3, r12, r12\n\t"
        "adds	r4, r4, r8\n\t"
        "adcs	r2, r2, r9\n\t"
        "adc	r3, r3, r12\n\t"
        "#  A[1] * A[1]\n\t"
        "ldr	r10, [%[a], #4]\n\t"
        "umull	r8, r9, r10, r10\n\t"
        "adds	r4, r4, r8\n\t"
        "adcs	r2, r2, r9\n\t"
        "adc	r3, r3, r12\n\t"
        "str	r4, [sp, #8]\n\t"
        "#  A[0] * A[3]\n\t"
        "ldr	r10, [%[a], #12]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r2, r2, r8\n\t"
        "adcs	r3, r3, r9\n\t"
        "adc	r4, r12, r12\n\t"
        "adds	r2, r2, r8\n\t"
        "adcs	r3, r3, r9\n\t"
        "adc	r4, r4, r12\n\t"
        "#  A[1] * A[2]\n\t"
        "ldr	r10, [%[a], #8]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r2, r2, r8\n\t"
        "adcs	r3, r3, r9\n\t"
        "adc	r4, r4, r12\n\t"
        "adds	r2, r2, r8\n\t"
        "adcs	r3, r3, r9\n\t"
        "adc	r4, r4, r12\n\t"
        "str	r2, [sp, #12]\n\t"
        "#  A[0] * A[4]\n\t"
        "ldr	r10, [%[a], #16]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r12, r12\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r2, r12\n\t"
        "#  A[1] * A[3]\n\t"
        "ldr	r10, [%[a], #12]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r2, r12\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r2, r12\n\t"
        "#  A[2] * A[2]\n\t"
        "ldr	r10, [%[a], #8]\n\t"
        "umull	r8, r9, r10, r10\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r2, r12\n\t"
        "str	r3, [sp, #16]\n\t"
        "#  A[0] * A[5]\n\t"
        "ldr	r10, [%[a], #20]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "umull	r5, r6, r10, r8\n\t"
        "mov	r3, #0\n\t"
        "mov	r7, #0\n\t"
        "#  A[1] * A[4]\n\t"
        "ldr	r10, [%[a], #16]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[2] * A[3]\n\t"
        "ldr	r10, [%[a], #12]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "adds	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adc	r7, r7, r7\n\t"
        "adds	r4, r4, r5\n\t"
        "adcs	r2, r2, r6\n\t"
        "adc	r3, r3, r7\n\t"
        "str	r4, [sp, #20]\n\t"
        "#  A[0] * A[6]\n\t"
        "ldr	r10, [%[a], #24]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "umull	r5, r6, r10, r8\n\t"
        "mov	r4, #0\n\t"
        "mov	r7, #0\n\t"
        "#  A[1] * A[5]\n\t"
        "ldr	r10, [%[a], #20]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[2] * A[4]\n\t"
        "ldr	r10, [%[a], #16]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[3] * A[3]\n\t"
        "ldr	r10, [%[a], #12]\n\t"
        "umull	r8, r9, r10, r10\n\t"
        "adds	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adc	r7, r7, r7\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "adds	r2, r2, r5\n\t"
        "adcs	r3, r3, r6\n\t"
        "adc	r4, r4, r7\n\t"
        "str	r2, [sp, #24]\n\t"
        "#  A[0] * A[7]\n\t"
        "ldr	r10, [%[a], #28]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "umull	r5, r6, r10, r8\n\t"
        "mov	r2, #0\n\t"
        "mov	r7, #0\n\t"
        "#  A[1] * A[6]\n\t"
        "ldr	r10, [%[a], #24]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[2] * A[5]\n\t"
        "ldr	r10, [%[a], #20]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[3] * A[4]\n\t"
        "ldr	r10, [%[a], #16]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "adds	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adc	r7, r7, r7\n\t"
        "adds	r3, r3, r5\n\t"
        "adcs	r4, r4, r6\n\t"
        "adc	r2, r2, r7\n\t"
        "str	r3, [sp, #28]\n\t"
        "#  A[1] * A[7]\n\t"
        "ldr	r10, [%[a], #28]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r5, r6, r10, r8\n\t"
        "mov	r3, #0\n\t"
        "mov	r7, #0\n\t"
        "#  A[2] * A[6]\n\t"
        "ldr	r10, [%[a], #24]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[3] * A[5]\n\t"
        "ldr	r10, [%[a], #20]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[4] * A[4]\n\t"
        "ldr	r10, [%[a], #16]\n\t"
        "umull	r8, r9, r10, r10\n\t"
        "adds	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adc	r7, r7, r7\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "adds	r4, r4, r5\n\t"
        "adcs	r2, r2, r6\n\t"
        "adc	r3, r3, r7\n\t"
        "str	r4, [%[r], #32]\n\t"
        "#  A[2] * A[7]\n\t"
        "ldr	r10, [%[a], #28]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r5, r6, r10, r8\n\t"
        "mov	r4, #0\n\t"
        "mov	r7, #0\n\t"
        "#  A[3] * A[6]\n\t"
        "ldr	r10, [%[a], #24]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[4] * A[5]\n\t"
        "ldr	r10, [%[a], #20]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "adds	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adc	r7, r7, r7\n\t"
        "adds	r2, r2, r5\n\t"
        "adcs	r3, r3, r6\n\t"
        "adc	r4, r4, r7\n\t"
        "str	r2, [%[r], #36]\n\t"
        "#  A[3] * A[7]\n\t"
        "ldr	r10, [%[a], #28]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r12, r12\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r2, r12\n\t"
        "#  A[4] * A[6]\n\t"
        "ldr	r10, [%[a], #24]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r2, r12\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r2, r12\n\t"
        "#  A[5] * A[5]\n\t"
        "ldr	r10, [%[a], #20]\n\t"
        "umull	r8, r9, r10, r10\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r2, r12\n\t"
        "str	r3, [%[r], #40]\n\t"
        "#  A[4] * A[7]\n\t"
        "ldr	r10, [%[a], #28]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r4, r4, r8\n\t"
        "adcs	r2, r2, r9\n\t"
        "adc	r3, r12, r12\n\t"
        "adds	r4, r4, r8\n\t"
        "adcs	r2, r2, r9\n\t"
        "adc	r3, r3, r12\n\t"
        "#  A[5] * A[6]\n\t"
        "ldr	r10, [%[a], #24]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r4, r4, r8\n\t"
        "adcs	r2, r2, r9\n\t"
        "adc	r3, r3, r12\n\t"
        "adds	r4, r4, r8\n\t"
        "adcs	r2, r2, r9\n\t"
        "adc	r3, r3, r12\n\t"
        "str	r4, [%[r], #44]\n\t"
        "#  A[5] * A[7]\n\t"
        "ldr	r10, [%[a], #28]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r2, r2, r8\n\t"
        "adcs	r3, r3, r9\n\t"
        "adc	r4, r12, r12\n\t"
        "adds	r2, r2, r8\n\t"
        "adcs	r3, r3, r9\n\t"
        "adc	r4, r4, r12\n\t"
        "#  A[6] * A[6]\n\t"
        "ldr	r10, [%[a], #24]\n\t"
        "umull	r8, r9, r10, r10\n\t"
        "adds	r2, r2, r8\n\t"
        "adcs	r3, r3, r9\n\t"
        "adc	r4, r4, r12\n\t"
        "str	r2, [%[r], #48]\n\t"
        "#  A[6] * A[7]\n\t"
        "ldr	r10, [%[a], #28]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r12, r12\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r2, r12\n\t"
        "str	r3, [%[r], #52]\n\t"
        "#  A[7] * A[7]\n\t"
        "ldr	r10, [%[a], #28]\n\t"
        "umull	r8, r9, r10, r10\n\t"
        "adds	r4, r4, r8\n\t"
        "adc	r2, r2, r9\n\t"
        "str	r4, [%[r], #56]\n\t"
        "str	r2, [%[r], #60]\n\t"
        "ldm	sp!, {r2, r3, r4, r8}\n\t"
        "stm	%[r]!, {r2, r3, r4, r8}\n\t"
        "ldm	sp!, {r2, r3, r4, r8}\n\t"
        "stm	%[r]!, {r2, r3, r4, r8}\n\t"
        "sub	%[r], %[r], #32\n\t"
        :
        : [r] "r" (r), [a] "r" (a)
        : "memory", "r2", "r3", "r4", "r8", "r9", "r10", "r8", "r5", "r6", "r7", "r12"
    );
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_2048_sub_8(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldrd	r3, r4, [%[a], #0]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b], #0]\n\t"
        "ldrd	r9, r10, [%[b], #8]\n\t"
        "subs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #0]\n\t"
        "strd	r5, r6, [%[r], #8]\n\t"
        "ldrd	r3, r4, [%[a], #16]\n\t"
        "ldrd	r5, r6, [%[a], #24]\n\t"
        "ldrd	r7, r8, [%[b], #16]\n\t"
        "ldrd	r9, r10, [%[b], #24]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #16]\n\t"
        "strd	r5, r6, [%[r], #24]\n\t"
        "sbc	%[c], %[c], #0\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
    );

    return c;
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_16(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit* z2 = r + 16;
    sp_digit z1[16];
    sp_digit* a1 = z1;
    sp_digit zero[8];
    sp_digit u;
    sp_digit mask;
    sp_digit* p1;
    sp_digit* p2;

    XMEMSET(zero, 0, sizeof(sp_digit) * 8);

    mask = sp_2048_sub_8(a1, a, &a[8]);
    p1 = (sp_digit*)(((sp_digit)zero &   mask ) | ((sp_digit)a1 & (~mask)));
    p2 = (sp_digit*)(((sp_digit)zero & (~mask)) | ((sp_digit)a1 &   mask ));
    (void)sp_2048_sub_8(a1, p1, p2);

    sp_2048_sqr_8(z2, &a[8]);
    sp_2048_sqr_8(z0, a);
    sp_2048_sqr_8(z1, a1);

    u = 0;
    u -= sp_2048_sub_in_place_16(z1, z2);
    u -= sp_2048_sub_in_place_16(z1, z0);
    u += sp_2048_sub_in_place_16(r + 8, z1);
    zero[0] = u;
    (void)sp_2048_add_8(r + 24, r + 24, zero);
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
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldrd	r3, r4, [%[a], #0]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b], #0]\n\t"
        "ldrd	r9, r10, [%[b], #8]\n\t"
        "subs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #0]\n\t"
        "strd	r5, r6, [%[r], #8]\n\t"
        "ldrd	r3, r4, [%[a], #16]\n\t"
        "ldrd	r5, r6, [%[a], #24]\n\t"
        "ldrd	r7, r8, [%[b], #16]\n\t"
        "ldrd	r9, r10, [%[b], #24]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #16]\n\t"
        "strd	r5, r6, [%[r], #24]\n\t"
        "ldrd	r3, r4, [%[a], #32]\n\t"
        "ldrd	r5, r6, [%[a], #40]\n\t"
        "ldrd	r7, r8, [%[b], #32]\n\t"
        "ldrd	r9, r10, [%[b], #40]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #32]\n\t"
        "strd	r5, r6, [%[r], #40]\n\t"
        "ldrd	r3, r4, [%[a], #48]\n\t"
        "ldrd	r5, r6, [%[a], #56]\n\t"
        "ldrd	r7, r8, [%[b], #48]\n\t"
        "ldrd	r9, r10, [%[b], #56]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #48]\n\t"
        "strd	r5, r6, [%[r], #56]\n\t"
        "sbc	%[c], %[c], #0\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
    );

    return c;
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
    sp_digit zero[16];
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
    zero[0] = u;
    (void)sp_2048_add_16(r + 48, r + 48, zero);
}

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
        "ldrd	r3, r4, [%[a], #0]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b], #0]\n\t"
        "ldrd	r9, r10, [%[b], #8]\n\t"
        "subs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #0]\n\t"
        "strd	r5, r6, [%[r], #8]\n\t"
        "ldrd	r3, r4, [%[a], #16]\n\t"
        "ldrd	r5, r6, [%[a], #24]\n\t"
        "ldrd	r7, r8, [%[b], #16]\n\t"
        "ldrd	r9, r10, [%[b], #24]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #16]\n\t"
        "strd	r5, r6, [%[r], #24]\n\t"
        "ldrd	r3, r4, [%[a], #32]\n\t"
        "ldrd	r5, r6, [%[a], #40]\n\t"
        "ldrd	r7, r8, [%[b], #32]\n\t"
        "ldrd	r9, r10, [%[b], #40]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #32]\n\t"
        "strd	r5, r6, [%[r], #40]\n\t"
        "ldrd	r3, r4, [%[a], #48]\n\t"
        "ldrd	r5, r6, [%[a], #56]\n\t"
        "ldrd	r7, r8, [%[b], #48]\n\t"
        "ldrd	r9, r10, [%[b], #56]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #48]\n\t"
        "strd	r5, r6, [%[r], #56]\n\t"
        "ldrd	r3, r4, [%[a], #64]\n\t"
        "ldrd	r5, r6, [%[a], #72]\n\t"
        "ldrd	r7, r8, [%[b], #64]\n\t"
        "ldrd	r9, r10, [%[b], #72]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #64]\n\t"
        "strd	r5, r6, [%[r], #72]\n\t"
        "ldrd	r3, r4, [%[a], #80]\n\t"
        "ldrd	r5, r6, [%[a], #88]\n\t"
        "ldrd	r7, r8, [%[b], #80]\n\t"
        "ldrd	r9, r10, [%[b], #88]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #80]\n\t"
        "strd	r5, r6, [%[r], #88]\n\t"
        "ldrd	r3, r4, [%[a], #96]\n\t"
        "ldrd	r5, r6, [%[a], #104]\n\t"
        "ldrd	r7, r8, [%[b], #96]\n\t"
        "ldrd	r9, r10, [%[b], #104]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #96]\n\t"
        "strd	r5, r6, [%[r], #104]\n\t"
        "ldrd	r3, r4, [%[a], #112]\n\t"
        "ldrd	r5, r6, [%[a], #120]\n\t"
        "ldrd	r7, r8, [%[b], #112]\n\t"
        "ldrd	r9, r10, [%[b], #120]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #112]\n\t"
        "strd	r5, r6, [%[r], #120]\n\t"
        "sbc	%[c], %[c], #0\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
    );

    return c;
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_64(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit* z2 = r + 64;
    sp_digit z1[64];
    sp_digit* a1 = z1;
    sp_digit zero[32];
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
    u -= sp_2048_sub_in_place_64(z1, z2);
    u -= sp_2048_sub_in_place_64(z1, z0);
    u += sp_2048_sub_in_place_64(r + 32, z1);
    zero[0] = u;
    (void)sp_2048_add_32(r + 96, r + 96, zero);
}

#endif /* !WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_2048_add_64(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "add	r14, %[a], #256\n\t"
        "\n1:\n\t"
        "adds	%[c], %[c], #-1\n\t"
        "ldrd	r3, r4, [%[a]], #8\n\t"
        "ldrd	r5, r6, [%[a]], #8\n\t"
        "ldrd	r7, r8, [%[b]], #8\n\t"
        "ldrd	r9, r10, [%[b]], #8\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r]], #8\n\t"
        "strd	r5, r6, [%[r]], #8\n\t"
        "mov	r3, #0\n\t"
        "adc	%[c], r3, #0\n\t"
        "cmp	%[a], r14\n\t"
        "bne	1b\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14"
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
static sp_digit sp_2048_sub_in_place_64(sp_digit* a, const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r14, #0\n\t"
        "add	r12, %[a], #256\n\t"
        "\n1:\n\t"
        "subs	%[c], r14, %[c]\n\t"
        "ldrd	r3, r4, [%[a]]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b]], #8\n\t"
        "ldrd	r9, r10, [%[b]], #8\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[a]], #8\n\t"
        "strd	r5, r6, [%[a]], #8\n\t"
        "sbc	%[c], r14, r14\n\t"
        "cmp	%[a], r12\n\t"
        "bne	1b\n\t"
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r12", "r14"
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
static void sp_2048_mul_64(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    __asm__ __volatile__ (
        "sub	sp, sp, #512\n\t"
        "mov	r5, #0\n\t"
        "mov	r6, #0\n\t"
        "mov	r7, #0\n\t"
        "mov	r8, #0\n\t"
        "\n1:\n\t"
        "subs	r3, r5, #252\n\t"
        "it	cc\n\t"
        "movcc	r3, #0\n\t"
        "sub	r4, r5, r3\n\t"
        "\n2:\n\t"
        "ldr	r14, [%[a], r3]\n\t"
        "ldr	r12, [%[b], r4]\n\t"
        "umull	r9, r10, r14, r12\n\t"
        "adds	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "adc	r8, r8, #0\n\t"
        "add	r3, r3, #4\n\t"
        "sub	r4, r4, #4\n\t"
        "cmp	r3, #256\n\t"
        "beq	3f\n\t"
        "cmp	r3, r5\n\t"
        "ble	2b\n\t"
        "\n3:\n\t"
        "str	r6, [sp, r5]\n\t"
        "mov	r6, r7\n\t"
        "mov	r7, r8\n\t"
        "mov	r8, #0\n\t"
        "add	r5, r5, #4\n\t"
        "cmp	r5, #504\n\t"
        "ble	1b\n\t"
        "str	r6, [sp, r5]\n\t"
        "\n4:\n\t"
        "ldr	r6, [sp, #0]\n\t"
        "ldr	r7, [sp, #4]\n\t"
        "ldr	r8, [sp, #8]\n\t"
        "ldr	r3, [sp, #12]\n\t"
        "str	r6, [%[r], #0]\n\t"
        "str	r7, [%[r], #4]\n\t"
        "str	r8, [%[r], #8]\n\t"
        "str	r3, [%[r], #12]\n\t"
        "add	sp, sp, #16\n\t"
        "add	%[r], %[r], #16\n\t"
        "subs	r5, r5, #16\n\t"
        "bgt	4b\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14", "r12"
    );
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
static void sp_2048_sqr_64(sp_digit* r, const sp_digit* a)
{
    __asm__ __volatile__ (
        "sub	sp, sp, #512\n\t"
        "mov	r12, #0\n\t"
        "mov	r6, #0\n\t"
        "mov	r7, #0\n\t"
        "mov	r8, #0\n\t"
        "mov	r5, #0\n\t"
        "\n1:\n\t"
        "subs	r3, r5, #252\n\t"
        "it	cc\n\t"
        "movcc	r3, r12\n\t"
        "sub	r4, r5, r3\n\t"
        "\n2:\n\t"
        "cmp	r4, r3\n\t"
        "beq	4f\n\t"
        "ldr	r14, [%[a], r3]\n\t"
        "ldr	r9, [%[a], r4]\n\t"
        "umull	r9, r10, r14, r9\n\t"
        "adds	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "adc	r8, r8, r12\n\t"
        "adds	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "adc	r8, r8, r12\n\t"
        "bal	5f\n\t"
        "\n4:\n\t"
        "ldr	r14, [%[a], r3]\n\t"
        "umull	r9, r10, r14, r14\n\t"
        "adds	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "adc	r8, r8, r12\n\t"
        "\n5:\n\t"
        "add	r3, r3, #4\n\t"
        "sub	r4, r4, #4\n\t"
        "cmp	r3, #256\n\t"
        "beq	3f\n\t"
        "cmp	r3, r4\n\t"
        "bgt	3f\n\t"
        "cmp	r3, r5\n\t"
        "ble	2b\n\t"
        "\n3:\n\t"
        "str	r6, [sp, r5]\n\t"
        "mov	r6, r7\n\t"
        "mov	r7, r8\n\t"
        "mov	r8, #0\n\t"
        "add	r5, r5, #4\n\t"
        "cmp	r5, #504\n\t"
        "ble	1b\n\t"
        "str	r6, [sp, r5]\n\t"
        "\n4:\n\t"
        "ldrd	r6, r7, [sp, #0]\n\t"
        "ldrd	r8, r9, [sp, #8]\n\t"
        "strd	r6, r7, [%[r], #0]\n\t"
        "strd	r8, r9, [%[r], #8]\n\t"
        "add	sp, sp, #16\n\t"
        "add	%[r], %[r], #16\n\t"
        "subs	r5, r5, #16\n\t"
        "bgt	4b\n\t"
        : [r] "+r" (r)
        : [a] "r" (a)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14", "r9", "r12"
    );
}

#endif /* WOLFSSL_SP_SMALL */
#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
#ifdef WOLFSSL_SP_SMALL
/* AND m into each word of a and store in r.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * m  Mask to AND against each digit.
 */
static void sp_2048_mask_32(sp_digit* r, const sp_digit* a, sp_digit m)
{
    int i;

    for (i=0; i<32; i++) {
        r[i] = a[i] & m;
    }
}

#endif /* WOLFSSL_SP_SMALL */
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
        "add	r14, %[a], #128\n\t"
        "\n1:\n\t"
        "adds	%[c], %[c], #-1\n\t"
        "ldrd	r3, r4, [%[a]], #8\n\t"
        "ldrd	r5, r6, [%[a]], #8\n\t"
        "ldrd	r7, r8, [%[b]], #8\n\t"
        "ldrd	r9, r10, [%[b]], #8\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r]], #8\n\t"
        "strd	r5, r6, [%[r]], #8\n\t"
        "mov	r3, #0\n\t"
        "adc	%[c], r3, #0\n\t"
        "cmp	%[a], r14\n\t"
        "bne	1b\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14"
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
        "mov	r14, #0\n\t"
        "add	r12, %[a], #128\n\t"
        "\n1:\n\t"
        "subs	%[c], r14, %[c]\n\t"
        "ldrd	r3, r4, [%[a]]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b]], #8\n\t"
        "ldrd	r9, r10, [%[b]], #8\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[a]], #8\n\t"
        "strd	r5, r6, [%[a]], #8\n\t"
        "sbc	%[c], r14, r14\n\t"
        "cmp	%[a], r12\n\t"
        "bne	1b\n\t"
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r12", "r14"
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
    __asm__ __volatile__ (
        "sub	sp, sp, #256\n\t"
        "mov	r5, #0\n\t"
        "mov	r6, #0\n\t"
        "mov	r7, #0\n\t"
        "mov	r8, #0\n\t"
        "\n1:\n\t"
        "subs	r3, r5, #124\n\t"
        "it	cc\n\t"
        "movcc	r3, #0\n\t"
        "sub	r4, r5, r3\n\t"
        "\n2:\n\t"
        "ldr	r14, [%[a], r3]\n\t"
        "ldr	r12, [%[b], r4]\n\t"
        "umull	r9, r10, r14, r12\n\t"
        "adds	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "adc	r8, r8, #0\n\t"
        "add	r3, r3, #4\n\t"
        "sub	r4, r4, #4\n\t"
        "cmp	r3, #128\n\t"
        "beq	3f\n\t"
        "cmp	r3, r5\n\t"
        "ble	2b\n\t"
        "\n3:\n\t"
        "str	r6, [sp, r5]\n\t"
        "mov	r6, r7\n\t"
        "mov	r7, r8\n\t"
        "mov	r8, #0\n\t"
        "add	r5, r5, #4\n\t"
        "cmp	r5, #248\n\t"
        "ble	1b\n\t"
        "str	r6, [sp, r5]\n\t"
        "\n4:\n\t"
        "ldr	r6, [sp, #0]\n\t"
        "ldr	r7, [sp, #4]\n\t"
        "ldr	r8, [sp, #8]\n\t"
        "ldr	r3, [sp, #12]\n\t"
        "str	r6, [%[r], #0]\n\t"
        "str	r7, [%[r], #4]\n\t"
        "str	r8, [%[r], #8]\n\t"
        "str	r3, [%[r], #12]\n\t"
        "add	sp, sp, #16\n\t"
        "add	%[r], %[r], #16\n\t"
        "subs	r5, r5, #16\n\t"
        "bgt	4b\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14", "r12"
    );
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
static void sp_2048_sqr_32(sp_digit* r, const sp_digit* a)
{
    __asm__ __volatile__ (
        "sub	sp, sp, #256\n\t"
        "mov	r12, #0\n\t"
        "mov	r6, #0\n\t"
        "mov	r7, #0\n\t"
        "mov	r8, #0\n\t"
        "mov	r5, #0\n\t"
        "\n1:\n\t"
        "subs	r3, r5, #124\n\t"
        "it	cc\n\t"
        "movcc	r3, r12\n\t"
        "sub	r4, r5, r3\n\t"
        "\n2:\n\t"
        "cmp	r4, r3\n\t"
        "beq	4f\n\t"
        "ldr	r14, [%[a], r3]\n\t"
        "ldr	r9, [%[a], r4]\n\t"
        "umull	r9, r10, r14, r9\n\t"
        "adds	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "adc	r8, r8, r12\n\t"
        "adds	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "adc	r8, r8, r12\n\t"
        "bal	5f\n\t"
        "\n4:\n\t"
        "ldr	r14, [%[a], r3]\n\t"
        "umull	r9, r10, r14, r14\n\t"
        "adds	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "adc	r8, r8, r12\n\t"
        "\n5:\n\t"
        "add	r3, r3, #4\n\t"
        "sub	r4, r4, #4\n\t"
        "cmp	r3, #128\n\t"
        "beq	3f\n\t"
        "cmp	r3, r4\n\t"
        "bgt	3f\n\t"
        "cmp	r3, r5\n\t"
        "ble	2b\n\t"
        "\n3:\n\t"
        "str	r6, [sp, r5]\n\t"
        "mov	r6, r7\n\t"
        "mov	r7, r8\n\t"
        "mov	r8, #0\n\t"
        "add	r5, r5, #4\n\t"
        "cmp	r5, #248\n\t"
        "ble	1b\n\t"
        "str	r6, [sp, r5]\n\t"
        "\n4:\n\t"
        "ldrd	r6, r7, [sp, #0]\n\t"
        "ldrd	r8, r9, [sp, #8]\n\t"
        "strd	r6, r7, [%[r], #0]\n\t"
        "strd	r8, r9, [%[r], #8]\n\t"
        "add	sp, sp, #16\n\t"
        "add	%[r], %[r], #16\n\t"
        "subs	r5, r5, #16\n\t"
        "bgt	4b\n\t"
        : [r] "+r" (r)
        : [a] "r" (a)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14", "r9", "r12"
    );
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

    /* rho = -1/m mod b */
    *rho = (sp_digit)0 - x;
}

/* Mul a by digit b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision digit.
 */
static void sp_2048_mul_d_64(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "mov	r10, #0\n\t"
        "# A[0] * B\n\t"
        "ldr	r8, [%[a]]\n\t"
        "umull	r5, r3, %[b], r8\n\t"
        "mov	r4, #0\n\t"
        "str	r5, [%[r]]\n\t"
        "mov	r5, #0\n\t"
        "mov	r9, #4\n\t"
        "1:\n\t"
        "ldr	r8, [%[a], r9]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "str	r3, [%[r], r9]\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "mov	r5, #0\n\t"
        "add	r9, r9, #4\n\t"
        "cmp	r9, #256\n\t"
        "blt	1b\n\t"
        "str	r3, [%[r], #256]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
    );
#else
    __asm__ __volatile__ (
        "mov	r10, #0\n\t"
        "# A[0] * B\n\t"
        "ldr	r8, [%[a]]\n\t"
        "umull	r3, r4, %[b], r8\n\t"
        "mov	r5, #0\n\t"
        "str	r3, [%[r]]\n\t"
        "# A[1] * B\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #4]\n\t"
        "# A[2] * B\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #8]\n\t"
        "# A[3] * B\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #12]\n\t"
        "# A[4] * B\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #16]\n\t"
        "# A[5] * B\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #20]\n\t"
        "# A[6] * B\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #24]\n\t"
        "# A[7] * B\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #28]\n\t"
        "# A[8] * B\n\t"
        "ldr	r8, [%[a], #32]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #32]\n\t"
        "# A[9] * B\n\t"
        "ldr	r8, [%[a], #36]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #36]\n\t"
        "# A[10] * B\n\t"
        "ldr	r8, [%[a], #40]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #40]\n\t"
        "# A[11] * B\n\t"
        "ldr	r8, [%[a], #44]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #44]\n\t"
        "# A[12] * B\n\t"
        "ldr	r8, [%[a], #48]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #48]\n\t"
        "# A[13] * B\n\t"
        "ldr	r8, [%[a], #52]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #52]\n\t"
        "# A[14] * B\n\t"
        "ldr	r8, [%[a], #56]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #56]\n\t"
        "# A[15] * B\n\t"
        "ldr	r8, [%[a], #60]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #60]\n\t"
        "# A[16] * B\n\t"
        "ldr	r8, [%[a], #64]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #64]\n\t"
        "# A[17] * B\n\t"
        "ldr	r8, [%[a], #68]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #68]\n\t"
        "# A[18] * B\n\t"
        "ldr	r8, [%[a], #72]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #72]\n\t"
        "# A[19] * B\n\t"
        "ldr	r8, [%[a], #76]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #76]\n\t"
        "# A[20] * B\n\t"
        "ldr	r8, [%[a], #80]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #80]\n\t"
        "# A[21] * B\n\t"
        "ldr	r8, [%[a], #84]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #84]\n\t"
        "# A[22] * B\n\t"
        "ldr	r8, [%[a], #88]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #88]\n\t"
        "# A[23] * B\n\t"
        "ldr	r8, [%[a], #92]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #92]\n\t"
        "# A[24] * B\n\t"
        "ldr	r8, [%[a], #96]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #96]\n\t"
        "# A[25] * B\n\t"
        "ldr	r8, [%[a], #100]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #100]\n\t"
        "# A[26] * B\n\t"
        "ldr	r8, [%[a], #104]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #104]\n\t"
        "# A[27] * B\n\t"
        "ldr	r8, [%[a], #108]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #108]\n\t"
        "# A[28] * B\n\t"
        "ldr	r8, [%[a], #112]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #112]\n\t"
        "# A[29] * B\n\t"
        "ldr	r8, [%[a], #116]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #116]\n\t"
        "# A[30] * B\n\t"
        "ldr	r8, [%[a], #120]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #120]\n\t"
        "# A[31] * B\n\t"
        "ldr	r8, [%[a], #124]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #124]\n\t"
        "# A[32] * B\n\t"
        "ldr	r8, [%[a], #128]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #128]\n\t"
        "# A[33] * B\n\t"
        "ldr	r8, [%[a], #132]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #132]\n\t"
        "# A[34] * B\n\t"
        "ldr	r8, [%[a], #136]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #136]\n\t"
        "# A[35] * B\n\t"
        "ldr	r8, [%[a], #140]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #140]\n\t"
        "# A[36] * B\n\t"
        "ldr	r8, [%[a], #144]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #144]\n\t"
        "# A[37] * B\n\t"
        "ldr	r8, [%[a], #148]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #148]\n\t"
        "# A[38] * B\n\t"
        "ldr	r8, [%[a], #152]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #152]\n\t"
        "# A[39] * B\n\t"
        "ldr	r8, [%[a], #156]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #156]\n\t"
        "# A[40] * B\n\t"
        "ldr	r8, [%[a], #160]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #160]\n\t"
        "# A[41] * B\n\t"
        "ldr	r8, [%[a], #164]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #164]\n\t"
        "# A[42] * B\n\t"
        "ldr	r8, [%[a], #168]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #168]\n\t"
        "# A[43] * B\n\t"
        "ldr	r8, [%[a], #172]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #172]\n\t"
        "# A[44] * B\n\t"
        "ldr	r8, [%[a], #176]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #176]\n\t"
        "# A[45] * B\n\t"
        "ldr	r8, [%[a], #180]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #180]\n\t"
        "# A[46] * B\n\t"
        "ldr	r8, [%[a], #184]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #184]\n\t"
        "# A[47] * B\n\t"
        "ldr	r8, [%[a], #188]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #188]\n\t"
        "# A[48] * B\n\t"
        "ldr	r8, [%[a], #192]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #192]\n\t"
        "# A[49] * B\n\t"
        "ldr	r8, [%[a], #196]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #196]\n\t"
        "# A[50] * B\n\t"
        "ldr	r8, [%[a], #200]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #200]\n\t"
        "# A[51] * B\n\t"
        "ldr	r8, [%[a], #204]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #204]\n\t"
        "# A[52] * B\n\t"
        "ldr	r8, [%[a], #208]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #208]\n\t"
        "# A[53] * B\n\t"
        "ldr	r8, [%[a], #212]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #212]\n\t"
        "# A[54] * B\n\t"
        "ldr	r8, [%[a], #216]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #216]\n\t"
        "# A[55] * B\n\t"
        "ldr	r8, [%[a], #220]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #220]\n\t"
        "# A[56] * B\n\t"
        "ldr	r8, [%[a], #224]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #224]\n\t"
        "# A[57] * B\n\t"
        "ldr	r8, [%[a], #228]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #228]\n\t"
        "# A[58] * B\n\t"
        "ldr	r8, [%[a], #232]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #232]\n\t"
        "# A[59] * B\n\t"
        "ldr	r8, [%[a], #236]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #236]\n\t"
        "# A[60] * B\n\t"
        "ldr	r8, [%[a], #240]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #240]\n\t"
        "# A[61] * B\n\t"
        "ldr	r8, [%[a], #244]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #244]\n\t"
        "# A[62] * B\n\t"
        "ldr	r8, [%[a], #248]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #248]\n\t"
        "# A[63] * B\n\t"
        "ldr	r8, [%[a], #252]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adc	r4, r4, r7\n\t"
        "str	r3, [%[r], #252]\n\t"
        "str	r4, [%[r], #256]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
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
static void sp_2048_mont_norm_32(sp_digit* r, const sp_digit* m)
{
    XMEMSET(r, 0, sizeof(sp_digit) * 32);

    /* r = 2^n mod m */
    sp_2048_sub_in_place_32(r, m);
}

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
    sp_digit c = 0;

#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "mov	r9, #0\n\t"
        "mov	r8, #0\n\t"
        "1:\n\t"
        "subs	%[c], r9, %[c]\n\t"
        "ldr	r4, [%[a], r8]\n\t"
        "ldr	r6, [%[b], r8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbc	%[c], r9, r9\n\t"
        "str	r4, [%[r], r8]\n\t"
        "add	r8, r8, #4\n\t"
        "cmp	r8, #128\n\t"
        "blt	1b\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9"
    );
#else
    __asm__ __volatile__ (

        "mov	r9, #0\n\t"
        "ldrd	r4, r5, [%[a], #0]\n\t"
        "ldrd	r6, r7, [%[b], #0]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "subs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #0]\n\t"
        "ldrd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r6, r7, [%[b], #8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #8]\n\t"
        "ldrd	r4, r5, [%[a], #16]\n\t"
        "ldrd	r6, r7, [%[b], #16]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #16]\n\t"
        "ldrd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r6, r7, [%[b], #24]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #24]\n\t"
        "ldrd	r4, r5, [%[a], #32]\n\t"
        "ldrd	r6, r7, [%[b], #32]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #32]\n\t"
        "ldrd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r6, r7, [%[b], #40]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #40]\n\t"
        "ldrd	r4, r5, [%[a], #48]\n\t"
        "ldrd	r6, r7, [%[b], #48]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #48]\n\t"
        "ldrd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r6, r7, [%[b], #56]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #56]\n\t"
        "ldrd	r4, r5, [%[a], #64]\n\t"
        "ldrd	r6, r7, [%[b], #64]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #64]\n\t"
        "ldrd	r4, r5, [%[a], #72]\n\t"
        "ldrd	r6, r7, [%[b], #72]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #72]\n\t"
        "ldrd	r4, r5, [%[a], #80]\n\t"
        "ldrd	r6, r7, [%[b], #80]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #80]\n\t"
        "ldrd	r4, r5, [%[a], #88]\n\t"
        "ldrd	r6, r7, [%[b], #88]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #88]\n\t"
        "ldrd	r4, r5, [%[a], #96]\n\t"
        "ldrd	r6, r7, [%[b], #96]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #96]\n\t"
        "ldrd	r4, r5, [%[a], #104]\n\t"
        "ldrd	r6, r7, [%[b], #104]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #104]\n\t"
        "ldrd	r4, r5, [%[a], #112]\n\t"
        "ldrd	r6, r7, [%[b], #112]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #112]\n\t"
        "ldrd	r4, r5, [%[a], #120]\n\t"
        "ldrd	r6, r7, [%[b], #120]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #120]\n\t"
        "sbc	%[c], r9, r9\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9"
    );
#endif /* WOLFSSL_SP_SMALL */

    return c;
}

/* Reduce the number back to 2048 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
SP_NOINLINE static void sp_2048_mont_reduce_32(sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    sp_digit ca = 0;

    __asm__ __volatile__ (
        "ldr   r11, [%[m], #0]\n\t"
        "# i = 0\n\t"
        "mov	r12, #0\n\t"
        "ldr	r10, [%[a], #0]\n\t"
        "ldr	r14, [%[a], #4]\n\t"
        "\n1:\n\t"
        "# mu = a[i] * mp\n\t"
        "mul	r8, %[mp], r10\n\t"
        "# a[i+0] += m[0] * mu\n\t"
        "ldr	r9, [%[a], #0]\n\t"
        "umull	r6, r7, r8, r11\n\t"
        "adds	r10, r10, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "# a[i+1] += m[1] * mu\n\t"
        "ldr       r7, [%[m], #4]\n\t"
        "ldr	r9, [%[a], #4]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r10, r14, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r10, r10, r5\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+2] += m[2] * mu\n\t"
        "ldr       r7, [%[m], #8]\n\t"
        "ldr	r14, [%[a], #8]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r14, r14, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r14, r14, r4\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+3] += m[3] * mu\n\t"
        "ldr       r7, [%[m], #12]\n\t"
        "ldr	r9, [%[a], #12]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #12]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+4] += m[4] * mu\n\t"
        "ldr       r7, [%[m], #16]\n\t"
        "ldr	r9, [%[a], #16]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #16]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+5] += m[5] * mu\n\t"
        "ldr       r7, [%[m], #20]\n\t"
        "ldr	r9, [%[a], #20]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #20]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+6] += m[6] * mu\n\t"
        "ldr       r7, [%[m], #24]\n\t"
        "ldr	r9, [%[a], #24]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #24]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+7] += m[7] * mu\n\t"
        "ldr       r7, [%[m], #28]\n\t"
        "ldr	r9, [%[a], #28]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #28]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+8] += m[8] * mu\n\t"
        "ldr       r7, [%[m], #32]\n\t"
        "ldr	r9, [%[a], #32]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #32]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+9] += m[9] * mu\n\t"
        "ldr       r7, [%[m], #36]\n\t"
        "ldr	r9, [%[a], #36]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #36]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+10] += m[10] * mu\n\t"
        "ldr       r7, [%[m], #40]\n\t"
        "ldr	r9, [%[a], #40]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #40]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+11] += m[11] * mu\n\t"
        "ldr       r7, [%[m], #44]\n\t"
        "ldr	r9, [%[a], #44]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #44]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+12] += m[12] * mu\n\t"
        "ldr       r7, [%[m], #48]\n\t"
        "ldr	r9, [%[a], #48]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #48]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+13] += m[13] * mu\n\t"
        "ldr       r7, [%[m], #52]\n\t"
        "ldr	r9, [%[a], #52]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #52]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+14] += m[14] * mu\n\t"
        "ldr       r7, [%[m], #56]\n\t"
        "ldr	r9, [%[a], #56]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #56]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+15] += m[15] * mu\n\t"
        "ldr       r7, [%[m], #60]\n\t"
        "ldr	r9, [%[a], #60]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #60]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+16] += m[16] * mu\n\t"
        "ldr       r7, [%[m], #64]\n\t"
        "ldr	r9, [%[a], #64]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #64]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+17] += m[17] * mu\n\t"
        "ldr       r7, [%[m], #68]\n\t"
        "ldr	r9, [%[a], #68]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #68]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+18] += m[18] * mu\n\t"
        "ldr       r7, [%[m], #72]\n\t"
        "ldr	r9, [%[a], #72]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #72]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+19] += m[19] * mu\n\t"
        "ldr       r7, [%[m], #76]\n\t"
        "ldr	r9, [%[a], #76]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #76]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+20] += m[20] * mu\n\t"
        "ldr       r7, [%[m], #80]\n\t"
        "ldr	r9, [%[a], #80]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #80]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+21] += m[21] * mu\n\t"
        "ldr       r7, [%[m], #84]\n\t"
        "ldr	r9, [%[a], #84]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #84]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+22] += m[22] * mu\n\t"
        "ldr       r7, [%[m], #88]\n\t"
        "ldr	r9, [%[a], #88]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #88]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+23] += m[23] * mu\n\t"
        "ldr       r7, [%[m], #92]\n\t"
        "ldr	r9, [%[a], #92]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #92]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+24] += m[24] * mu\n\t"
        "ldr       r7, [%[m], #96]\n\t"
        "ldr	r9, [%[a], #96]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #96]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+25] += m[25] * mu\n\t"
        "ldr       r7, [%[m], #100]\n\t"
        "ldr	r9, [%[a], #100]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #100]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+26] += m[26] * mu\n\t"
        "ldr       r7, [%[m], #104]\n\t"
        "ldr	r9, [%[a], #104]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #104]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+27] += m[27] * mu\n\t"
        "ldr       r7, [%[m], #108]\n\t"
        "ldr	r9, [%[a], #108]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #108]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+28] += m[28] * mu\n\t"
        "ldr       r7, [%[m], #112]\n\t"
        "ldr	r9, [%[a], #112]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #112]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+29] += m[29] * mu\n\t"
        "ldr       r7, [%[m], #116]\n\t"
        "ldr	r9, [%[a], #116]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #116]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+30] += m[30] * mu\n\t"
        "ldr       r7, [%[m], #120]\n\t"
        "ldr	r9, [%[a], #120]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #120]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+31] += m[31] * mu\n\t"
        "ldr	r7, [%[m], #124]\n\t"
        "ldr   r9, [%[a], #124]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r7, r7, %[ca]\n\t"
        "mov	%[ca], #0\n\t"
        "adc	%[ca], %[ca], %[ca]\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #124]\n\t"
        "ldr	r9, [%[a], #128]\n\t"
        "adcs	r9, r9, r7\n\t"
        "str	r9, [%[a], #128]\n\t"
        "adc	%[ca], %[ca], #0\n\t"
        "# i += 1\n\t"
        "add	%[a], %[a], #4\n\t"
        "add	r12, r12, #4\n\t"
        "cmp	r12, #128\n\t"
        "blt	1b\n\t"
        "str	r10, [%[a], #0]\n\t"
        "str	r14, [%[a], #4]\n\t"
        : [ca] "+r" (ca), [a] "+r" (a)
        : [m] "r" (m), [mp] "r" (mp)
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14", "r12", "r11"
    );

    sp_2048_cond_sub_32(a - 32, a, m, (sp_digit)0 - ca);
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
        "mov	r10, #0\n\t"
        "# A[0] * B\n\t"
        "ldr	r8, [%[a]]\n\t"
        "umull	r5, r3, %[b], r8\n\t"
        "mov	r4, #0\n\t"
        "str	r5, [%[r]]\n\t"
        "mov	r5, #0\n\t"
        "mov	r9, #4\n\t"
        "1:\n\t"
        "ldr	r8, [%[a], r9]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "str	r3, [%[r], r9]\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "mov	r5, #0\n\t"
        "add	r9, r9, #4\n\t"
        "cmp	r9, #128\n\t"
        "blt	1b\n\t"
        "str	r3, [%[r], #128]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
    );
#else
    __asm__ __volatile__ (
        "mov	r10, #0\n\t"
        "# A[0] * B\n\t"
        "ldr	r8, [%[a]]\n\t"
        "umull	r3, r4, %[b], r8\n\t"
        "mov	r5, #0\n\t"
        "str	r3, [%[r]]\n\t"
        "# A[1] * B\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #4]\n\t"
        "# A[2] * B\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #8]\n\t"
        "# A[3] * B\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #12]\n\t"
        "# A[4] * B\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #16]\n\t"
        "# A[5] * B\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #20]\n\t"
        "# A[6] * B\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #24]\n\t"
        "# A[7] * B\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #28]\n\t"
        "# A[8] * B\n\t"
        "ldr	r8, [%[a], #32]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #32]\n\t"
        "# A[9] * B\n\t"
        "ldr	r8, [%[a], #36]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #36]\n\t"
        "# A[10] * B\n\t"
        "ldr	r8, [%[a], #40]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #40]\n\t"
        "# A[11] * B\n\t"
        "ldr	r8, [%[a], #44]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #44]\n\t"
        "# A[12] * B\n\t"
        "ldr	r8, [%[a], #48]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #48]\n\t"
        "# A[13] * B\n\t"
        "ldr	r8, [%[a], #52]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #52]\n\t"
        "# A[14] * B\n\t"
        "ldr	r8, [%[a], #56]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #56]\n\t"
        "# A[15] * B\n\t"
        "ldr	r8, [%[a], #60]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #60]\n\t"
        "# A[16] * B\n\t"
        "ldr	r8, [%[a], #64]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #64]\n\t"
        "# A[17] * B\n\t"
        "ldr	r8, [%[a], #68]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #68]\n\t"
        "# A[18] * B\n\t"
        "ldr	r8, [%[a], #72]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #72]\n\t"
        "# A[19] * B\n\t"
        "ldr	r8, [%[a], #76]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #76]\n\t"
        "# A[20] * B\n\t"
        "ldr	r8, [%[a], #80]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #80]\n\t"
        "# A[21] * B\n\t"
        "ldr	r8, [%[a], #84]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #84]\n\t"
        "# A[22] * B\n\t"
        "ldr	r8, [%[a], #88]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #88]\n\t"
        "# A[23] * B\n\t"
        "ldr	r8, [%[a], #92]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #92]\n\t"
        "# A[24] * B\n\t"
        "ldr	r8, [%[a], #96]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #96]\n\t"
        "# A[25] * B\n\t"
        "ldr	r8, [%[a], #100]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #100]\n\t"
        "# A[26] * B\n\t"
        "ldr	r8, [%[a], #104]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #104]\n\t"
        "# A[27] * B\n\t"
        "ldr	r8, [%[a], #108]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #108]\n\t"
        "# A[28] * B\n\t"
        "ldr	r8, [%[a], #112]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #112]\n\t"
        "# A[29] * B\n\t"
        "ldr	r8, [%[a], #116]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #116]\n\t"
        "# A[30] * B\n\t"
        "ldr	r8, [%[a], #120]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #120]\n\t"
        "# A[31] * B\n\t"
        "ldr	r8, [%[a], #124]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adc	r5, r5, r7\n\t"
        "str	r4, [%[r], #124]\n\t"
        "str	r5, [%[r], #128]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
    );
#endif
}

/* Divide the double width number (d1|d0) by the divisor. (d1|d0 / div)
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The divisor.
 * returns the result of the division.
 *
 * Note that this is an approximate div. It may give an answer 1 larger.
 */
static sp_digit div_2048_word_32(sp_digit d1, sp_digit d0, sp_digit div)
{
    sp_digit r = 0;

    __asm__ __volatile__ (
        "lsr	r5, %[div], #1\n\t"
        "add	r5, r5, #1\n\t"
        "mov	r6, %[d0]\n\t"
        "mov	r7, %[d1]\n\t"
        "# Do top 32\n\t"
        "subs	r8, r5, r7\n\t"
        "sbc	r8, r8, r8\n\t"
        "add	%[r], %[r], %[r]\n\t"
        "sub	%[r], %[r], r8\n\t"
        "and	r8, r8, r5\n\t"
        "subs	r7, r7, r8\n\t"
        "# Next 30 bits\n\t"
        "mov	r4, #29\n\t"
        "1:\n\t"
        "movs	r6, r6, lsl #1\n\t"
        "adc	r7, r7, r7\n\t"
        "subs	r8, r5, r7\n\t"
        "sbc	r8, r8, r8\n\t"
        "add	%[r], %[r], %[r]\n\t"
        "sub	%[r], %[r], r8\n\t"
        "and	r8, r8, r5\n\t"
        "subs	r7, r7, r8\n\t"
        "subs	r4, r4, #1\n\t"
        "bpl	1b\n\t"
        "add	%[r], %[r], %[r]\n\t"
        "add	%[r], %[r], #1\n\t"
        "umull	r4, r5, %[r], %[div]\n\t"
        "subs	r4, %[d0], r4\n\t"
        "sbc	r5, %[d1], r5\n\t"
        "add	%[r], %[r], r5\n\t"
        "umull	r4, r5, %[r], %[div]\n\t"
        "subs	r4, %[d0], r4\n\t"
        "sbc	r5, %[d1], r5\n\t"
        "add	%[r], %[r], r5\n\t"
        "umull	r4, r5, %[r], %[div]\n\t"
        "subs	r4, %[d0], r4\n\t"
        "sbc	r5, %[d1], r5\n\t"
        "add	%[r], %[r], r5\n\t"
        "subs	r8, %[div], r4\n\t"
        "sbc	r8, r8, r8\n\t"
        "sub	%[r], %[r], r8\n\t"
        : [r] "+r" (r)
        : [d1] "r" (d1), [d0] "r" (d0), [div] "r" (div)
        : "r4", "r5", "r6", "r7", "r8"
    );
    return r;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_int32 sp_2048_cmp_32(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = -1;
    sp_digit one = 1;


#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "mov	r7, #0\n\t"
        "mov	r3, #-1\n\t"
        "mov	r6, #124\n\t"
        "1:\n\t"
        "ldr	r4, [%[a], r6]\n\t"
        "ldr	r5, [%[b], r6]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "subs	r6, r6, #4\n\t"
        "bcs	1b\n\t"
        "eor	%[r], %[r], r3\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [one] "r" (one)
        : "r3", "r4", "r5", "r6", "r7"
    );
#else
    __asm__ __volatile__ (
        "mov	r7, #0\n\t"
        "mov	r3, #-1\n\t"
        "ldr	r4, [%[a], #124]\n\t"
        "ldr	r5, [%[b], #124]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #120]\n\t"
        "ldr	r5, [%[b], #120]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #116]\n\t"
        "ldr	r5, [%[b], #116]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #112]\n\t"
        "ldr	r5, [%[b], #112]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #108]\n\t"
        "ldr	r5, [%[b], #108]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #104]\n\t"
        "ldr	r5, [%[b], #104]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #100]\n\t"
        "ldr	r5, [%[b], #100]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #96]\n\t"
        "ldr	r5, [%[b], #96]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #92]\n\t"
        "ldr	r5, [%[b], #92]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #88]\n\t"
        "ldr	r5, [%[b], #88]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #84]\n\t"
        "ldr	r5, [%[b], #84]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #80]\n\t"
        "ldr	r5, [%[b], #80]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #76]\n\t"
        "ldr	r5, [%[b], #76]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #72]\n\t"
        "ldr	r5, [%[b], #72]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #68]\n\t"
        "ldr	r5, [%[b], #68]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #64]\n\t"
        "ldr	r5, [%[b], #64]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #60]\n\t"
        "ldr	r5, [%[b], #60]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #56]\n\t"
        "ldr	r5, [%[b], #56]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #52]\n\t"
        "ldr	r5, [%[b], #52]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #48]\n\t"
        "ldr	r5, [%[b], #48]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #44]\n\t"
        "ldr	r5, [%[b], #44]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #40]\n\t"
        "ldr	r5, [%[b], #40]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #36]\n\t"
        "ldr	r5, [%[b], #36]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #32]\n\t"
        "ldr	r5, [%[b], #32]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #28]\n\t"
        "ldr	r5, [%[b], #28]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #24]\n\t"
        "ldr	r5, [%[b], #24]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #20]\n\t"
        "ldr	r5, [%[b], #20]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #16]\n\t"
        "ldr	r5, [%[b], #16]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #12]\n\t"
        "ldr	r5, [%[b], #12]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #8]\n\t"
        "ldr	r5, [%[b], #8]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #4]\n\t"
        "ldr	r5, [%[b], #4]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #0]\n\t"
        "ldr	r5, [%[b], #0]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "eor	%[r], %[r], r3\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [one] "r" (one)
        : "r3", "r4", "r5", "r6", "r7"
    );
#endif

    return r;
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
    sp_digit td[16 * 64];
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

        i = (bits - 1) / 32;
        n = e[i--];
        c = bits & 31;
        if (c == 0) {
            c = 32;
        }
        c -= bits % 4;
        if (c == 32) {
            c = 28;
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
            n <<= 32 - c;
        }
        XMEMCPY(r, t[y], sizeof(sp_digit) * 32);
        for (; i>=0 || c>=4; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 28);
                n <<= 4;
                c = 28;
            }
            else if (c < 4) {
                y = (byte)(n >> 28);
                n = e[i--];
                c = 4 - c;
                y |= (byte)(n >> (32 - c));
                n <<= c;
                c = 32 - c;
            }
            else {
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c -= 4;
            }

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

        i = (bits - 1) / 32;
        n = e[i--];
        c = bits & 31;
        if (c == 0) {
            c = 32;
        }
        c -= bits % 5;
        if (c == 32) {
            c = 27;
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
            n <<= 32 - c;
        }
        XMEMCPY(r, t[y], sizeof(sp_digit) * 32);
        for (; i>=0 || c>=5; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 27);
                n <<= 5;
                c = 27;
            }
            else if (c < 5) {
                y = (byte)(n >> 27);
                n = e[i--];
                c = 5 - c;
                y |= (byte)(n >> (32 - c));
                n <<= c;
                c = 32 - c;
            }
            else {
                y = (byte)((n >> 27) & 0x1f);
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
#endif /* WOLFSSL_SP_SMALL */

#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) | WOLFSSL_HAVE_SP_DH */

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 2048 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_2048_mont_norm_64(sp_digit* r, const sp_digit* m)
{
    XMEMSET(r, 0, sizeof(sp_digit) * 64);

    /* r = 2^n mod m */
    sp_2048_sub_in_place_64(r, m);
}

#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) | WOLFSSL_HAVE_SP_DH */
/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not copying.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static sp_digit sp_2048_cond_sub_64(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    sp_digit c = 0;

#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "mov	r9, #0\n\t"
        "mov	r8, #0\n\t"
        "1:\n\t"
        "subs	%[c], r9, %[c]\n\t"
        "ldr	r4, [%[a], r8]\n\t"
        "ldr	r6, [%[b], r8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbc	%[c], r9, r9\n\t"
        "str	r4, [%[r], r8]\n\t"
        "add	r8, r8, #4\n\t"
        "cmp	r8, #256\n\t"
        "blt	1b\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9"
    );
#else
    __asm__ __volatile__ (

        "mov	r9, #0\n\t"
        "ldrd	r4, r5, [%[a], #0]\n\t"
        "ldrd	r6, r7, [%[b], #0]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "subs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #0]\n\t"
        "ldrd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r6, r7, [%[b], #8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #8]\n\t"
        "ldrd	r4, r5, [%[a], #16]\n\t"
        "ldrd	r6, r7, [%[b], #16]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #16]\n\t"
        "ldrd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r6, r7, [%[b], #24]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #24]\n\t"
        "ldrd	r4, r5, [%[a], #32]\n\t"
        "ldrd	r6, r7, [%[b], #32]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #32]\n\t"
        "ldrd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r6, r7, [%[b], #40]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #40]\n\t"
        "ldrd	r4, r5, [%[a], #48]\n\t"
        "ldrd	r6, r7, [%[b], #48]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #48]\n\t"
        "ldrd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r6, r7, [%[b], #56]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #56]\n\t"
        "ldrd	r4, r5, [%[a], #64]\n\t"
        "ldrd	r6, r7, [%[b], #64]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #64]\n\t"
        "ldrd	r4, r5, [%[a], #72]\n\t"
        "ldrd	r6, r7, [%[b], #72]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #72]\n\t"
        "ldrd	r4, r5, [%[a], #80]\n\t"
        "ldrd	r6, r7, [%[b], #80]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #80]\n\t"
        "ldrd	r4, r5, [%[a], #88]\n\t"
        "ldrd	r6, r7, [%[b], #88]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #88]\n\t"
        "ldrd	r4, r5, [%[a], #96]\n\t"
        "ldrd	r6, r7, [%[b], #96]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #96]\n\t"
        "ldrd	r4, r5, [%[a], #104]\n\t"
        "ldrd	r6, r7, [%[b], #104]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #104]\n\t"
        "ldrd	r4, r5, [%[a], #112]\n\t"
        "ldrd	r6, r7, [%[b], #112]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #112]\n\t"
        "ldrd	r4, r5, [%[a], #120]\n\t"
        "ldrd	r6, r7, [%[b], #120]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #120]\n\t"
        "ldrd	r4, r5, [%[a], #128]\n\t"
        "ldrd	r6, r7, [%[b], #128]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #128]\n\t"
        "ldrd	r4, r5, [%[a], #136]\n\t"
        "ldrd	r6, r7, [%[b], #136]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #136]\n\t"
        "ldrd	r4, r5, [%[a], #144]\n\t"
        "ldrd	r6, r7, [%[b], #144]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #144]\n\t"
        "ldrd	r4, r5, [%[a], #152]\n\t"
        "ldrd	r6, r7, [%[b], #152]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #152]\n\t"
        "ldrd	r4, r5, [%[a], #160]\n\t"
        "ldrd	r6, r7, [%[b], #160]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #160]\n\t"
        "ldrd	r4, r5, [%[a], #168]\n\t"
        "ldrd	r6, r7, [%[b], #168]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #168]\n\t"
        "ldrd	r4, r5, [%[a], #176]\n\t"
        "ldrd	r6, r7, [%[b], #176]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #176]\n\t"
        "ldrd	r4, r5, [%[a], #184]\n\t"
        "ldrd	r6, r7, [%[b], #184]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #184]\n\t"
        "ldrd	r4, r5, [%[a], #192]\n\t"
        "ldrd	r6, r7, [%[b], #192]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #192]\n\t"
        "ldrd	r4, r5, [%[a], #200]\n\t"
        "ldrd	r6, r7, [%[b], #200]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #200]\n\t"
        "ldrd	r4, r5, [%[a], #208]\n\t"
        "ldrd	r6, r7, [%[b], #208]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #208]\n\t"
        "ldrd	r4, r5, [%[a], #216]\n\t"
        "ldrd	r6, r7, [%[b], #216]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #216]\n\t"
        "ldrd	r4, r5, [%[a], #224]\n\t"
        "ldrd	r6, r7, [%[b], #224]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #224]\n\t"
        "ldrd	r4, r5, [%[a], #232]\n\t"
        "ldrd	r6, r7, [%[b], #232]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #232]\n\t"
        "ldrd	r4, r5, [%[a], #240]\n\t"
        "ldrd	r6, r7, [%[b], #240]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #240]\n\t"
        "ldrd	r4, r5, [%[a], #248]\n\t"
        "ldrd	r6, r7, [%[b], #248]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #248]\n\t"
        "sbc	%[c], r9, r9\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9"
    );
#endif /* WOLFSSL_SP_SMALL */

    return c;
}

/* Reduce the number back to 2048 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
SP_NOINLINE static void sp_2048_mont_reduce_64(sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    sp_digit ca = 0;

    __asm__ __volatile__ (
        "ldr   r11, [%[m], #0]\n\t"
        "# i = 0\n\t"
        "mov	r12, #0\n\t"
        "ldr	r10, [%[a], #0]\n\t"
        "ldr	r14, [%[a], #4]\n\t"
        "\n1:\n\t"
        "# mu = a[i] * mp\n\t"
        "mul	r8, %[mp], r10\n\t"
        "# a[i+0] += m[0] * mu\n\t"
        "ldr	r9, [%[a], #0]\n\t"
        "umull	r6, r7, r8, r11\n\t"
        "adds	r10, r10, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "# a[i+1] += m[1] * mu\n\t"
        "ldr       r7, [%[m], #4]\n\t"
        "ldr	r9, [%[a], #4]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r10, r14, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r10, r10, r5\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+2] += m[2] * mu\n\t"
        "ldr       r7, [%[m], #8]\n\t"
        "ldr	r14, [%[a], #8]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r14, r14, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r14, r14, r4\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+3] += m[3] * mu\n\t"
        "ldr       r7, [%[m], #12]\n\t"
        "ldr	r9, [%[a], #12]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #12]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+4] += m[4] * mu\n\t"
        "ldr       r7, [%[m], #16]\n\t"
        "ldr	r9, [%[a], #16]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #16]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+5] += m[5] * mu\n\t"
        "ldr       r7, [%[m], #20]\n\t"
        "ldr	r9, [%[a], #20]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #20]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+6] += m[6] * mu\n\t"
        "ldr       r7, [%[m], #24]\n\t"
        "ldr	r9, [%[a], #24]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #24]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+7] += m[7] * mu\n\t"
        "ldr       r7, [%[m], #28]\n\t"
        "ldr	r9, [%[a], #28]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #28]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+8] += m[8] * mu\n\t"
        "ldr       r7, [%[m], #32]\n\t"
        "ldr	r9, [%[a], #32]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #32]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+9] += m[9] * mu\n\t"
        "ldr       r7, [%[m], #36]\n\t"
        "ldr	r9, [%[a], #36]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #36]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+10] += m[10] * mu\n\t"
        "ldr       r7, [%[m], #40]\n\t"
        "ldr	r9, [%[a], #40]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #40]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+11] += m[11] * mu\n\t"
        "ldr       r7, [%[m], #44]\n\t"
        "ldr	r9, [%[a], #44]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #44]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+12] += m[12] * mu\n\t"
        "ldr       r7, [%[m], #48]\n\t"
        "ldr	r9, [%[a], #48]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #48]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+13] += m[13] * mu\n\t"
        "ldr       r7, [%[m], #52]\n\t"
        "ldr	r9, [%[a], #52]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #52]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+14] += m[14] * mu\n\t"
        "ldr       r7, [%[m], #56]\n\t"
        "ldr	r9, [%[a], #56]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #56]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+15] += m[15] * mu\n\t"
        "ldr       r7, [%[m], #60]\n\t"
        "ldr	r9, [%[a], #60]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #60]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+16] += m[16] * mu\n\t"
        "ldr       r7, [%[m], #64]\n\t"
        "ldr	r9, [%[a], #64]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #64]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+17] += m[17] * mu\n\t"
        "ldr       r7, [%[m], #68]\n\t"
        "ldr	r9, [%[a], #68]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #68]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+18] += m[18] * mu\n\t"
        "ldr       r7, [%[m], #72]\n\t"
        "ldr	r9, [%[a], #72]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #72]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+19] += m[19] * mu\n\t"
        "ldr       r7, [%[m], #76]\n\t"
        "ldr	r9, [%[a], #76]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #76]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+20] += m[20] * mu\n\t"
        "ldr       r7, [%[m], #80]\n\t"
        "ldr	r9, [%[a], #80]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #80]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+21] += m[21] * mu\n\t"
        "ldr       r7, [%[m], #84]\n\t"
        "ldr	r9, [%[a], #84]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #84]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+22] += m[22] * mu\n\t"
        "ldr       r7, [%[m], #88]\n\t"
        "ldr	r9, [%[a], #88]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #88]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+23] += m[23] * mu\n\t"
        "ldr       r7, [%[m], #92]\n\t"
        "ldr	r9, [%[a], #92]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #92]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+24] += m[24] * mu\n\t"
        "ldr       r7, [%[m], #96]\n\t"
        "ldr	r9, [%[a], #96]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #96]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+25] += m[25] * mu\n\t"
        "ldr       r7, [%[m], #100]\n\t"
        "ldr	r9, [%[a], #100]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #100]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+26] += m[26] * mu\n\t"
        "ldr       r7, [%[m], #104]\n\t"
        "ldr	r9, [%[a], #104]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #104]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+27] += m[27] * mu\n\t"
        "ldr       r7, [%[m], #108]\n\t"
        "ldr	r9, [%[a], #108]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #108]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+28] += m[28] * mu\n\t"
        "ldr       r7, [%[m], #112]\n\t"
        "ldr	r9, [%[a], #112]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #112]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+29] += m[29] * mu\n\t"
        "ldr       r7, [%[m], #116]\n\t"
        "ldr	r9, [%[a], #116]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #116]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+30] += m[30] * mu\n\t"
        "ldr       r7, [%[m], #120]\n\t"
        "ldr	r9, [%[a], #120]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #120]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+31] += m[31] * mu\n\t"
        "ldr       r7, [%[m], #124]\n\t"
        "ldr	r9, [%[a], #124]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #124]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+32] += m[32] * mu\n\t"
        "ldr       r7, [%[m], #128]\n\t"
        "ldr	r9, [%[a], #128]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #128]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+33] += m[33] * mu\n\t"
        "ldr       r7, [%[m], #132]\n\t"
        "ldr	r9, [%[a], #132]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #132]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+34] += m[34] * mu\n\t"
        "ldr       r7, [%[m], #136]\n\t"
        "ldr	r9, [%[a], #136]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #136]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+35] += m[35] * mu\n\t"
        "ldr       r7, [%[m], #140]\n\t"
        "ldr	r9, [%[a], #140]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #140]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+36] += m[36] * mu\n\t"
        "ldr       r7, [%[m], #144]\n\t"
        "ldr	r9, [%[a], #144]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #144]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+37] += m[37] * mu\n\t"
        "ldr       r7, [%[m], #148]\n\t"
        "ldr	r9, [%[a], #148]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #148]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+38] += m[38] * mu\n\t"
        "ldr       r7, [%[m], #152]\n\t"
        "ldr	r9, [%[a], #152]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #152]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+39] += m[39] * mu\n\t"
        "ldr       r7, [%[m], #156]\n\t"
        "ldr	r9, [%[a], #156]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #156]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+40] += m[40] * mu\n\t"
        "ldr       r7, [%[m], #160]\n\t"
        "ldr	r9, [%[a], #160]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #160]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+41] += m[41] * mu\n\t"
        "ldr       r7, [%[m], #164]\n\t"
        "ldr	r9, [%[a], #164]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #164]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+42] += m[42] * mu\n\t"
        "ldr       r7, [%[m], #168]\n\t"
        "ldr	r9, [%[a], #168]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #168]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+43] += m[43] * mu\n\t"
        "ldr       r7, [%[m], #172]\n\t"
        "ldr	r9, [%[a], #172]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #172]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+44] += m[44] * mu\n\t"
        "ldr       r7, [%[m], #176]\n\t"
        "ldr	r9, [%[a], #176]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #176]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+45] += m[45] * mu\n\t"
        "ldr       r7, [%[m], #180]\n\t"
        "ldr	r9, [%[a], #180]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #180]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+46] += m[46] * mu\n\t"
        "ldr       r7, [%[m], #184]\n\t"
        "ldr	r9, [%[a], #184]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #184]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+47] += m[47] * mu\n\t"
        "ldr       r7, [%[m], #188]\n\t"
        "ldr	r9, [%[a], #188]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #188]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+48] += m[48] * mu\n\t"
        "ldr       r7, [%[m], #192]\n\t"
        "ldr	r9, [%[a], #192]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #192]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+49] += m[49] * mu\n\t"
        "ldr       r7, [%[m], #196]\n\t"
        "ldr	r9, [%[a], #196]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #196]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+50] += m[50] * mu\n\t"
        "ldr       r7, [%[m], #200]\n\t"
        "ldr	r9, [%[a], #200]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #200]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+51] += m[51] * mu\n\t"
        "ldr       r7, [%[m], #204]\n\t"
        "ldr	r9, [%[a], #204]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #204]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+52] += m[52] * mu\n\t"
        "ldr       r7, [%[m], #208]\n\t"
        "ldr	r9, [%[a], #208]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #208]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+53] += m[53] * mu\n\t"
        "ldr       r7, [%[m], #212]\n\t"
        "ldr	r9, [%[a], #212]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #212]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+54] += m[54] * mu\n\t"
        "ldr       r7, [%[m], #216]\n\t"
        "ldr	r9, [%[a], #216]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #216]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+55] += m[55] * mu\n\t"
        "ldr       r7, [%[m], #220]\n\t"
        "ldr	r9, [%[a], #220]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #220]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+56] += m[56] * mu\n\t"
        "ldr       r7, [%[m], #224]\n\t"
        "ldr	r9, [%[a], #224]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #224]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+57] += m[57] * mu\n\t"
        "ldr       r7, [%[m], #228]\n\t"
        "ldr	r9, [%[a], #228]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #228]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+58] += m[58] * mu\n\t"
        "ldr       r7, [%[m], #232]\n\t"
        "ldr	r9, [%[a], #232]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #232]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+59] += m[59] * mu\n\t"
        "ldr       r7, [%[m], #236]\n\t"
        "ldr	r9, [%[a], #236]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #236]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+60] += m[60] * mu\n\t"
        "ldr       r7, [%[m], #240]\n\t"
        "ldr	r9, [%[a], #240]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #240]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+61] += m[61] * mu\n\t"
        "ldr       r7, [%[m], #244]\n\t"
        "ldr	r9, [%[a], #244]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #244]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+62] += m[62] * mu\n\t"
        "ldr       r7, [%[m], #248]\n\t"
        "ldr	r9, [%[a], #248]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #248]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+63] += m[63] * mu\n\t"
        "ldr	r7, [%[m], #252]\n\t"
        "ldr   r9, [%[a], #252]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r7, r7, %[ca]\n\t"
        "mov	%[ca], #0\n\t"
        "adc	%[ca], %[ca], %[ca]\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #252]\n\t"
        "ldr	r9, [%[a], #256]\n\t"
        "adcs	r9, r9, r7\n\t"
        "str	r9, [%[a], #256]\n\t"
        "adc	%[ca], %[ca], #0\n\t"
        "# i += 1\n\t"
        "add	%[a], %[a], #4\n\t"
        "add	r12, r12, #4\n\t"
        "cmp	r12, #256\n\t"
        "blt	1b\n\t"
        "str	r10, [%[a], #0]\n\t"
        "str	r14, [%[a], #4]\n\t"
        : [ca] "+r" (ca), [a] "+r" (a)
        : [m] "r" (m), [mp] "r" (mp)
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14", "r12", "r11"
    );

    sp_2048_cond_sub_64(a - 64, a, m, (sp_digit)0 - ca);
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
SP_NOINLINE static void sp_2048_mont_mul_64(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_2048_mul_64(r, a, b);
    sp_2048_mont_reduce_64(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_2048_mont_sqr_64(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_2048_sqr_64(r, a);
    sp_2048_mont_reduce_64(r, m, mp);
}

#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_2048_sub_64(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "add	r14, %[a], #256\n\t"
        "\n1:\n\t"
        "rsbs	%[c], %[c], #0\n\t"
        "ldrd	r3, r4, [%[a]], #8\n\t"
        "ldrd	r5, r6, [%[a]], #8\n\t"
        "ldrd	r7, r8, [%[b]], #8\n\t"
        "ldrd	r9, r10, [%[b]], #8\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r]], #8\n\t"
        "strd	r5, r6, [%[r]], #8\n\t"
        "sbc	%[c], r3, r3\n\t"
        "cmp	%[a], r14\n\t"
        "bne	1b\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14"
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
static sp_digit sp_2048_sub_64(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldrd	r3, r4, [%[a], #0]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b], #0]\n\t"
        "ldrd	r9, r10, [%[b], #8]\n\t"
        "subs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #0]\n\t"
        "strd	r5, r6, [%[r], #8]\n\t"
        "ldrd	r3, r4, [%[a], #16]\n\t"
        "ldrd	r5, r6, [%[a], #24]\n\t"
        "ldrd	r7, r8, [%[b], #16]\n\t"
        "ldrd	r9, r10, [%[b], #24]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #16]\n\t"
        "strd	r5, r6, [%[r], #24]\n\t"
        "ldrd	r3, r4, [%[a], #32]\n\t"
        "ldrd	r5, r6, [%[a], #40]\n\t"
        "ldrd	r7, r8, [%[b], #32]\n\t"
        "ldrd	r9, r10, [%[b], #40]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #32]\n\t"
        "strd	r5, r6, [%[r], #40]\n\t"
        "ldrd	r3, r4, [%[a], #48]\n\t"
        "ldrd	r5, r6, [%[a], #56]\n\t"
        "ldrd	r7, r8, [%[b], #48]\n\t"
        "ldrd	r9, r10, [%[b], #56]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #48]\n\t"
        "strd	r5, r6, [%[r], #56]\n\t"
        "ldrd	r3, r4, [%[a], #64]\n\t"
        "ldrd	r5, r6, [%[a], #72]\n\t"
        "ldrd	r7, r8, [%[b], #64]\n\t"
        "ldrd	r9, r10, [%[b], #72]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #64]\n\t"
        "strd	r5, r6, [%[r], #72]\n\t"
        "ldrd	r3, r4, [%[a], #80]\n\t"
        "ldrd	r5, r6, [%[a], #88]\n\t"
        "ldrd	r7, r8, [%[b], #80]\n\t"
        "ldrd	r9, r10, [%[b], #88]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #80]\n\t"
        "strd	r5, r6, [%[r], #88]\n\t"
        "ldrd	r3, r4, [%[a], #96]\n\t"
        "ldrd	r5, r6, [%[a], #104]\n\t"
        "ldrd	r7, r8, [%[b], #96]\n\t"
        "ldrd	r9, r10, [%[b], #104]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #96]\n\t"
        "strd	r5, r6, [%[r], #104]\n\t"
        "ldrd	r3, r4, [%[a], #112]\n\t"
        "ldrd	r5, r6, [%[a], #120]\n\t"
        "ldrd	r7, r8, [%[b], #112]\n\t"
        "ldrd	r9, r10, [%[b], #120]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #112]\n\t"
        "strd	r5, r6, [%[r], #120]\n\t"
        "ldrd	r3, r4, [%[a], #128]\n\t"
        "ldrd	r5, r6, [%[a], #136]\n\t"
        "ldrd	r7, r8, [%[b], #128]\n\t"
        "ldrd	r9, r10, [%[b], #136]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #128]\n\t"
        "strd	r5, r6, [%[r], #136]\n\t"
        "ldrd	r3, r4, [%[a], #144]\n\t"
        "ldrd	r5, r6, [%[a], #152]\n\t"
        "ldrd	r7, r8, [%[b], #144]\n\t"
        "ldrd	r9, r10, [%[b], #152]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #144]\n\t"
        "strd	r5, r6, [%[r], #152]\n\t"
        "ldrd	r3, r4, [%[a], #160]\n\t"
        "ldrd	r5, r6, [%[a], #168]\n\t"
        "ldrd	r7, r8, [%[b], #160]\n\t"
        "ldrd	r9, r10, [%[b], #168]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #160]\n\t"
        "strd	r5, r6, [%[r], #168]\n\t"
        "ldrd	r3, r4, [%[a], #176]\n\t"
        "ldrd	r5, r6, [%[a], #184]\n\t"
        "ldrd	r7, r8, [%[b], #176]\n\t"
        "ldrd	r9, r10, [%[b], #184]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #176]\n\t"
        "strd	r5, r6, [%[r], #184]\n\t"
        "ldrd	r3, r4, [%[a], #192]\n\t"
        "ldrd	r5, r6, [%[a], #200]\n\t"
        "ldrd	r7, r8, [%[b], #192]\n\t"
        "ldrd	r9, r10, [%[b], #200]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #192]\n\t"
        "strd	r5, r6, [%[r], #200]\n\t"
        "ldrd	r3, r4, [%[a], #208]\n\t"
        "ldrd	r5, r6, [%[a], #216]\n\t"
        "ldrd	r7, r8, [%[b], #208]\n\t"
        "ldrd	r9, r10, [%[b], #216]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #208]\n\t"
        "strd	r5, r6, [%[r], #216]\n\t"
        "ldrd	r3, r4, [%[a], #224]\n\t"
        "ldrd	r5, r6, [%[a], #232]\n\t"
        "ldrd	r7, r8, [%[b], #224]\n\t"
        "ldrd	r9, r10, [%[b], #232]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #224]\n\t"
        "strd	r5, r6, [%[r], #232]\n\t"
        "ldrd	r3, r4, [%[a], #240]\n\t"
        "ldrd	r5, r6, [%[a], #248]\n\t"
        "ldrd	r7, r8, [%[b], #240]\n\t"
        "ldrd	r9, r10, [%[b], #248]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #240]\n\t"
        "strd	r5, r6, [%[r], #248]\n\t"
        "sbc	%[c], %[c], #0\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
    );

    return c;
}

#endif /* WOLFSSL_SP_SMALL */
/* Divide the double width number (d1|d0) by the divisor. (d1|d0 / div)
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The divisor.
 * returns the result of the division.
 *
 * Note that this is an approximate div. It may give an answer 1 larger.
 */
static sp_digit div_2048_word_64(sp_digit d1, sp_digit d0, sp_digit div)
{
    sp_digit r = 0;

    __asm__ __volatile__ (
        "lsr	r5, %[div], #1\n\t"
        "add	r5, r5, #1\n\t"
        "mov	r6, %[d0]\n\t"
        "mov	r7, %[d1]\n\t"
        "# Do top 32\n\t"
        "subs	r8, r5, r7\n\t"
        "sbc	r8, r8, r8\n\t"
        "add	%[r], %[r], %[r]\n\t"
        "sub	%[r], %[r], r8\n\t"
        "and	r8, r8, r5\n\t"
        "subs	r7, r7, r8\n\t"
        "# Next 30 bits\n\t"
        "mov	r4, #29\n\t"
        "1:\n\t"
        "movs	r6, r6, lsl #1\n\t"
        "adc	r7, r7, r7\n\t"
        "subs	r8, r5, r7\n\t"
        "sbc	r8, r8, r8\n\t"
        "add	%[r], %[r], %[r]\n\t"
        "sub	%[r], %[r], r8\n\t"
        "and	r8, r8, r5\n\t"
        "subs	r7, r7, r8\n\t"
        "subs	r4, r4, #1\n\t"
        "bpl	1b\n\t"
        "add	%[r], %[r], %[r]\n\t"
        "add	%[r], %[r], #1\n\t"
        "umull	r4, r5, %[r], %[div]\n\t"
        "subs	r4, %[d0], r4\n\t"
        "sbc	r5, %[d1], r5\n\t"
        "add	%[r], %[r], r5\n\t"
        "umull	r4, r5, %[r], %[div]\n\t"
        "subs	r4, %[d0], r4\n\t"
        "sbc	r5, %[d1], r5\n\t"
        "add	%[r], %[r], r5\n\t"
        "umull	r4, r5, %[r], %[div]\n\t"
        "subs	r4, %[d0], r4\n\t"
        "sbc	r5, %[d1], r5\n\t"
        "add	%[r], %[r], r5\n\t"
        "subs	r8, %[div], r4\n\t"
        "sbc	r8, r8, r8\n\t"
        "sub	%[r], %[r], r8\n\t"
        : [r] "+r" (r)
        : [d1] "r" (d1), [d0] "r" (d0), [div] "r" (div)
        : "r4", "r5", "r6", "r7", "r8"
    );
    return r;
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
static WC_INLINE int sp_2048_div_64_cond(const sp_digit* a, const sp_digit* d, sp_digit* m,
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
            r1 = div_2048_word_64(t1[64 + i], t1[64 + i - 1], div);
        }

        sp_2048_mul_d_64(t2, d, r1);
        t1[64 + i] += sp_2048_sub_in_place_64(&t1[i], t2);
        t1[64 + i] -= t2[64];
        if (t1[64 + i] != 0) {
            t1[64 + i] += sp_2048_add_64(&t1[i], &t1[i], d);
            if (t1[64 + i] != 0)
                t1[64 + i] += sp_2048_add_64(&t1[i], &t1[i], d);
        }
    }

    for (i = 63; i > 0; i--) {
        if (t1[i] != d[i])
            break;
    }
    if (t1[i] >= d[i]) {
        sp_2048_sub_64(r, t1, d);
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
static WC_INLINE int sp_2048_mod_64_cond(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_2048_div_64_cond(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
#if defined(WOLFSSL_HAVE_SP_DH) || !defined(WOLFSSL_RSA_PUBLIC_ONLY)
/* AND m into each word of a and store in r.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * m  Mask to AND against each digit.
 */
static void sp_2048_mask_64(sp_digit* r, const sp_digit* a, sp_digit m)
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
static sp_int32 sp_2048_cmp_64(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = -1;
    sp_digit one = 1;


#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "mov	r7, #0\n\t"
        "mov	r3, #-1\n\t"
        "mov	r6, #252\n\t"
        "1:\n\t"
        "ldr	r4, [%[a], r6]\n\t"
        "ldr	r5, [%[b], r6]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "subs	r6, r6, #4\n\t"
        "bcs	1b\n\t"
        "eor	%[r], %[r], r3\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [one] "r" (one)
        : "r3", "r4", "r5", "r6", "r7"
    );
#else
    __asm__ __volatile__ (
        "mov	r7, #0\n\t"
        "mov	r3, #-1\n\t"
        "ldr	r4, [%[a], #252]\n\t"
        "ldr	r5, [%[b], #252]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #248]\n\t"
        "ldr	r5, [%[b], #248]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #244]\n\t"
        "ldr	r5, [%[b], #244]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #240]\n\t"
        "ldr	r5, [%[b], #240]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #236]\n\t"
        "ldr	r5, [%[b], #236]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #232]\n\t"
        "ldr	r5, [%[b], #232]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #228]\n\t"
        "ldr	r5, [%[b], #228]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #224]\n\t"
        "ldr	r5, [%[b], #224]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #220]\n\t"
        "ldr	r5, [%[b], #220]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #216]\n\t"
        "ldr	r5, [%[b], #216]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #212]\n\t"
        "ldr	r5, [%[b], #212]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #208]\n\t"
        "ldr	r5, [%[b], #208]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #204]\n\t"
        "ldr	r5, [%[b], #204]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #200]\n\t"
        "ldr	r5, [%[b], #200]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #196]\n\t"
        "ldr	r5, [%[b], #196]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #192]\n\t"
        "ldr	r5, [%[b], #192]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #188]\n\t"
        "ldr	r5, [%[b], #188]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #184]\n\t"
        "ldr	r5, [%[b], #184]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #180]\n\t"
        "ldr	r5, [%[b], #180]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #176]\n\t"
        "ldr	r5, [%[b], #176]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #172]\n\t"
        "ldr	r5, [%[b], #172]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #168]\n\t"
        "ldr	r5, [%[b], #168]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #164]\n\t"
        "ldr	r5, [%[b], #164]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #160]\n\t"
        "ldr	r5, [%[b], #160]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #156]\n\t"
        "ldr	r5, [%[b], #156]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #152]\n\t"
        "ldr	r5, [%[b], #152]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #148]\n\t"
        "ldr	r5, [%[b], #148]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #144]\n\t"
        "ldr	r5, [%[b], #144]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #140]\n\t"
        "ldr	r5, [%[b], #140]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #136]\n\t"
        "ldr	r5, [%[b], #136]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #132]\n\t"
        "ldr	r5, [%[b], #132]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #128]\n\t"
        "ldr	r5, [%[b], #128]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #124]\n\t"
        "ldr	r5, [%[b], #124]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #120]\n\t"
        "ldr	r5, [%[b], #120]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #116]\n\t"
        "ldr	r5, [%[b], #116]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #112]\n\t"
        "ldr	r5, [%[b], #112]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #108]\n\t"
        "ldr	r5, [%[b], #108]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #104]\n\t"
        "ldr	r5, [%[b], #104]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #100]\n\t"
        "ldr	r5, [%[b], #100]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #96]\n\t"
        "ldr	r5, [%[b], #96]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #92]\n\t"
        "ldr	r5, [%[b], #92]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #88]\n\t"
        "ldr	r5, [%[b], #88]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #84]\n\t"
        "ldr	r5, [%[b], #84]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #80]\n\t"
        "ldr	r5, [%[b], #80]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #76]\n\t"
        "ldr	r5, [%[b], #76]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #72]\n\t"
        "ldr	r5, [%[b], #72]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #68]\n\t"
        "ldr	r5, [%[b], #68]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #64]\n\t"
        "ldr	r5, [%[b], #64]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #60]\n\t"
        "ldr	r5, [%[b], #60]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #56]\n\t"
        "ldr	r5, [%[b], #56]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #52]\n\t"
        "ldr	r5, [%[b], #52]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #48]\n\t"
        "ldr	r5, [%[b], #48]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #44]\n\t"
        "ldr	r5, [%[b], #44]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #40]\n\t"
        "ldr	r5, [%[b], #40]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #36]\n\t"
        "ldr	r5, [%[b], #36]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #32]\n\t"
        "ldr	r5, [%[b], #32]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #28]\n\t"
        "ldr	r5, [%[b], #28]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #24]\n\t"
        "ldr	r5, [%[b], #24]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #20]\n\t"
        "ldr	r5, [%[b], #20]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #16]\n\t"
        "ldr	r5, [%[b], #16]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #12]\n\t"
        "ldr	r5, [%[b], #12]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #8]\n\t"
        "ldr	r5, [%[b], #8]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #4]\n\t"
        "ldr	r5, [%[b], #4]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #0]\n\t"
        "ldr	r5, [%[b], #0]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "eor	%[r], %[r], r3\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [one] "r" (one)
        : "r3", "r4", "r5", "r6", "r7"
    );
#endif

    return r;
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
static WC_INLINE int sp_2048_div_64(const sp_digit* a, const sp_digit* d, sp_digit* m,
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
        r1 = div_2048_word_64(hi, t1[64 + i - 1], div);

        sp_2048_mul_d_64(t2, d, r1);
        t1[64 + i] += sp_2048_sub_in_place_64(&t1[i], t2);
        t1[64 + i] -= t2[64];
        sp_2048_mask_64(t2, d, t1[64 + i]);
        t1[64 + i] += sp_2048_add_64(&t1[i], &t1[i], t2);
        sp_2048_mask_64(t2, d, t1[64 + i]);
        t1[64 + i] += sp_2048_add_64(&t1[i], &t1[i], t2);
    }

    r1 = sp_2048_cmp_64(t1, d) >= 0;
    sp_2048_cond_sub_64(r, t1, d, (sp_digit)0 - r1);

    return MP_OKAY;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_2048_mod_64(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_2048_div_64(a, m, NULL, r);
}

#endif /* WOLFSSL_HAVE_SP_DH || !WOLFSSL_RSA_PUBLIC_ONLY */
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
static int sp_2048_mod_exp_64(sp_digit* r, const sp_digit* a, const sp_digit* e,
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

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_64(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 64U);
        if (reduceA != 0) {
            err = sp_2048_mod_64(t[1] + 64, a, m);
            if (err == MP_OKAY) {
                err = sp_2048_mod_64(t[1], t[1], m);
            }
        }
        else {
            XMEMCPY(t[1] + 64, a, sizeof(sp_digit) * 64);
            err = sp_2048_mod_64(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_2048_mont_sqr_64(t[ 2], t[ 1], m, mp);
        sp_2048_mont_mul_64(t[ 3], t[ 2], t[ 1], m, mp);
        sp_2048_mont_sqr_64(t[ 4], t[ 2], m, mp);
        sp_2048_mont_mul_64(t[ 5], t[ 3], t[ 2], m, mp);
        sp_2048_mont_sqr_64(t[ 6], t[ 3], m, mp);
        sp_2048_mont_mul_64(t[ 7], t[ 4], t[ 3], m, mp);

        i = (bits - 1) / 32;
        n = e[i--];
        c = bits & 31;
        if (c == 0) {
            c = 32;
        }
        c -= bits % 3;
        if (c == 32) {
            c = 29;
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
            n <<= 32 - c;
        }
        XMEMCPY(r, t[y], sizeof(sp_digit) * 64);
        for (; i>=0 || c>=3; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 29);
                n <<= 3;
                c = 29;
            }
            else if (c < 3) {
                y = (byte)(n >> 29);
                n = e[i--];
                c = 3 - c;
                y |= (byte)(n >> (32 - c));
                n <<= c;
                c = 32 - c;
            }
            else {
                y = (byte)((n >> 29) & 0x7);
                n <<= 3;
                c -= 3;
            }

            sp_2048_mont_sqr_64(r, r, m, mp);
            sp_2048_mont_sqr_64(r, r, m, mp);
            sp_2048_mont_sqr_64(r, r, m, mp);

            sp_2048_mont_mul_64(r, r, t[y], m, mp);
        }

        XMEMSET(&r[64], 0, sizeof(sp_digit) * 64U);
        sp_2048_mont_reduce_64(r, m, mp);

        mask = 0 - (sp_2048_cmp_64(r, m) >= 0);
        sp_2048_cond_sub_64(r, r, m, mask);
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
static int sp_2048_mod_exp_64(sp_digit* r, const sp_digit* a, const sp_digit* e,
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

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_64(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 64U);
        if (reduceA != 0) {
            err = sp_2048_mod_64(t[1] + 64, a, m);
            if (err == MP_OKAY) {
                err = sp_2048_mod_64(t[1], t[1], m);
            }
        }
        else {
            XMEMCPY(t[1] + 64, a, sizeof(sp_digit) * 64);
            err = sp_2048_mod_64(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_2048_mont_sqr_64(t[ 2], t[ 1], m, mp);
        sp_2048_mont_mul_64(t[ 3], t[ 2], t[ 1], m, mp);
        sp_2048_mont_sqr_64(t[ 4], t[ 2], m, mp);
        sp_2048_mont_mul_64(t[ 5], t[ 3], t[ 2], m, mp);
        sp_2048_mont_sqr_64(t[ 6], t[ 3], m, mp);
        sp_2048_mont_mul_64(t[ 7], t[ 4], t[ 3], m, mp);
        sp_2048_mont_sqr_64(t[ 8], t[ 4], m, mp);
        sp_2048_mont_mul_64(t[ 9], t[ 5], t[ 4], m, mp);
        sp_2048_mont_sqr_64(t[10], t[ 5], m, mp);
        sp_2048_mont_mul_64(t[11], t[ 6], t[ 5], m, mp);
        sp_2048_mont_sqr_64(t[12], t[ 6], m, mp);
        sp_2048_mont_mul_64(t[13], t[ 7], t[ 6], m, mp);
        sp_2048_mont_sqr_64(t[14], t[ 7], m, mp);
        sp_2048_mont_mul_64(t[15], t[ 8], t[ 7], m, mp);

        i = (bits - 1) / 32;
        n = e[i--];
        c = bits & 31;
        if (c == 0) {
            c = 32;
        }
        c -= bits % 4;
        if (c == 32) {
            c = 28;
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
            n <<= 32 - c;
        }
        XMEMCPY(r, t[y], sizeof(sp_digit) * 64);
        for (; i>=0 || c>=4; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 28);
                n <<= 4;
                c = 28;
            }
            else if (c < 4) {
                y = (byte)(n >> 28);
                n = e[i--];
                c = 4 - c;
                y |= (byte)(n >> (32 - c));
                n <<= c;
                c = 32 - c;
            }
            else {
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c -= 4;
            }

            sp_2048_mont_sqr_64(r, r, m, mp);
            sp_2048_mont_sqr_64(r, r, m, mp);
            sp_2048_mont_sqr_64(r, r, m, mp);
            sp_2048_mont_sqr_64(r, r, m, mp);

            sp_2048_mont_mul_64(r, r, t[y], m, mp);
        }

        XMEMSET(&r[64], 0, sizeof(sp_digit) * 64U);
        sp_2048_mont_reduce_64(r, m, mp);

        mask = 0 - (sp_2048_cmp_64(r, m) >= 0);
        sp_2048_cond_sub_64(r, r, m, mask);
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
    sp_digit a[64 * 5];
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit *ah = NULL;
    sp_digit e[1] = {0};
    int err = MP_OKAY;

    if (*outLen < 256) {
        err = MP_TO_E;
    }
    else if (mp_count_bits(em) > 32 || inLen > 256 ||
                                                     mp_count_bits(mm) != 2048) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mm)) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        ah = a + 64;
        r = a + 64 * 2;
        m = r + 64 * 2;

        sp_2048_from_bin(ah, 64, in, inLen);
#if DIGIT_BIT >= 32
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
        sp_2048_from_mp(m, 64, mm);

        if (e[0] == 0x10001) {
            int i;
            sp_digit mp;

            sp_2048_mont_setup(m, &mp);

            /* Convert to Montgomery form. */
            XMEMSET(a, 0, sizeof(sp_digit) * 64);
            err = sp_2048_mod_64_cond(r, a, m);
            /* Montgomery form: r = a.R mod m */

            if (err == MP_OKAY) {
                /* r = a ^ 0x10000 => r = a squared 16 times */
                for (i = 15; i >= 0; i--) {
                    sp_2048_mont_sqr_64(r, r, m, mp);
                }
                /* mont_red(r.R.R) = (r.R.R / R) mod m = r.R mod m
                 * mont_red(r.R * a) = (r.R.a / R) mod m = r.a mod m
                 */
                sp_2048_mont_mul_64(r, r, ah, m, mp);

                for (i = 63; i > 0; i--) {
                    if (r[i] != m[i]) {
                        break;
                    }
                }
                if (r[i] >= m[i]) {
                    sp_2048_sub_in_place_64(r, m);
                }
            }
        }
        else if (e[0] == 0x3) {
            if (err == MP_OKAY) {
                sp_2048_sqr_64(r, ah);
                err = sp_2048_mod_64_cond(r, r, m);
            }
            if (err == MP_OKAY) {
                sp_2048_mul_64(r, ah, r);
                err = sp_2048_mod_64_cond(r, r, m);
            }
        }
        else {
            int i;
            sp_digit mp;

            sp_2048_mont_setup(m, &mp);

            /* Convert to Montgomery form. */
            XMEMSET(a, 0, sizeof(sp_digit) * 64);
            err = sp_2048_mod_64_cond(a, a, m);

            if (err == MP_OKAY) {
                for (i = 31; i >= 0; i--) {
                    if (e[0] >> i) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 64);
                for (i--; i >= 0; i--) {
                    sp_2048_mont_sqr_64(r, r, m, mp);
                    if (((e[0] >> i) & 1) == 1) {
                        sp_2048_mont_mul_64(r, r, a, m, mp);
                    }
                }
                XMEMSET(&r[64], 0, sizeof(sp_digit) * 64);
                sp_2048_mont_reduce_64(r, m, mp);

                for (i = 63; i > 0; i--) {
                    if (r[i] != m[i]) {
                        break;
                    }
                }
                if (r[i] >= m[i]) {
                    sp_2048_sub_in_place_64(r, m);
                }
            }
        }
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin_64(r, out);
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
static sp_digit sp_2048_cond_add_32(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r7, #0\n\t"
        "mov	r6, #0\n\t"
        "1:\n\t"
        "adds	%[c], %[c], #-1\n\t"
        "ldr	r4, [%[a], r6]\n\t"
        "ldr	r5, [%[b], r6]\n\t"
        "and	r5, r5, %[m]\n\t"
        "adcs	r4, r4, r5\n\t"
        "adc	%[c], r7, r7\n\t"
        "str	r4, [%[r], r6]\n\t"
        "add	r6, r6, #4\n\t"
        "cmp	r6, #128\n\t"
        "blt	1b\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r4", "r5", "r6", "r7"
    );

    return c;
}
#endif /* WOLFSSL_SP_SMALL */

#ifndef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static sp_digit sp_2048_cond_add_32(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    sp_digit c = 0;

    __asm__ __volatile__ (

        "mov	r8, #0\n\t"
        "ldrd	r4, r5, [%[a], #0]\n\t"
        "ldrd	r6, r7, [%[b], #0]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #0]\n\t"
        "ldrd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r6, r7, [%[b], #8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #8]\n\t"
        "ldrd	r4, r5, [%[a], #16]\n\t"
        "ldrd	r6, r7, [%[b], #16]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #16]\n\t"
        "ldrd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r6, r7, [%[b], #24]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #24]\n\t"
        "ldrd	r4, r5, [%[a], #32]\n\t"
        "ldrd	r6, r7, [%[b], #32]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #32]\n\t"
        "ldrd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r6, r7, [%[b], #40]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #40]\n\t"
        "ldrd	r4, r5, [%[a], #48]\n\t"
        "ldrd	r6, r7, [%[b], #48]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #48]\n\t"
        "ldrd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r6, r7, [%[b], #56]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #56]\n\t"
        "ldrd	r4, r5, [%[a], #64]\n\t"
        "ldrd	r6, r7, [%[b], #64]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #64]\n\t"
        "ldrd	r4, r5, [%[a], #72]\n\t"
        "ldrd	r6, r7, [%[b], #72]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #72]\n\t"
        "ldrd	r4, r5, [%[a], #80]\n\t"
        "ldrd	r6, r7, [%[b], #80]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #80]\n\t"
        "ldrd	r4, r5, [%[a], #88]\n\t"
        "ldrd	r6, r7, [%[b], #88]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #88]\n\t"
        "ldrd	r4, r5, [%[a], #96]\n\t"
        "ldrd	r6, r7, [%[b], #96]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #96]\n\t"
        "ldrd	r4, r5, [%[a], #104]\n\t"
        "ldrd	r6, r7, [%[b], #104]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #104]\n\t"
        "ldrd	r4, r5, [%[a], #112]\n\t"
        "ldrd	r6, r7, [%[b], #112]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #112]\n\t"
        "ldrd	r4, r5, [%[a], #120]\n\t"
        "ldrd	r6, r7, [%[b], #120]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #120]\n\t"
        "adc	%[c], r8, r8\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r4", "r5", "r6", "r7", "r8"
    );

    return c;
}
#endif /* !WOLFSSL_SP_SMALL */

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
        a = d + 64;
        m = a + 128;
        r = a;

        sp_2048_from_bin(a, 64, in, inLen);
        sp_2048_from_mp(d, 64, dm);
        sp_2048_from_mp(m, 64, mm);
        err = sp_2048_mod_exp_64(r, a, d, 2048, m, 0);
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin_64(r, out);
        *outLen = 256;
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
        p = a + 64 * 2;
        q = p + 32;
        qi = dq = dp = q + 32;
        tmpa = qi + 32;
        tmpb = tmpa + 64;
        r = a;

        sp_2048_from_bin(a, 64, in, inLen);
        sp_2048_from_mp(p, 32, pm);
        sp_2048_from_mp(q, 32, qm);
        sp_2048_from_mp(dp, 32, dpm);

        err = sp_2048_mod_exp_32(tmpa, a, dp, 1024, p, 1);
    }
    if (err == MP_OKAY) {
        sp_2048_from_mp(dq, 32, dqm);
        err = sp_2048_mod_exp_32(tmpb, a, dq, 1024, q, 1);
    }

    if (err == MP_OKAY) {
        c = sp_2048_sub_in_place_32(tmpa, tmpb);
        c += sp_2048_cond_add_32(tmpa, tmpa, p, c);
        sp_2048_cond_add_32(tmpa, tmpa, p, c);

        sp_2048_from_mp(qi, 32, qim);
        sp_2048_mul_32(tmpa, tmpa, qi);
        err = sp_2048_mod_32(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_2048_mul_32(tmpa, q, tmpa);
        XMEMSET(&tmpb[32], 0, sizeof(sp_digit) * 32);
        sp_2048_add_64(r, tmpb, tmpa);

        sp_2048_to_bin_64(r, out);
        *outLen = 256;
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
static int sp_2048_to_mp(const sp_digit* a, mp_int* r)
{
    int err;

    err = mp_grow(r, (2048 + DIGIT_BIT - 1) / DIGIT_BIT);
    if (err == MP_OKAY) { /*lint !e774 case where err is always MP_OKAY*/
#if DIGIT_BIT == 32
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 64);
        r->used = 64;
        mp_clamp(r);
#elif DIGIT_BIT < 32
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 64; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 32) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 32 - s;
        }
        r->used = (2048 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 64; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 32 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 32 - s;
            }
            else {
                s += 32;
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
    sp_digit b[128];
    sp_digit e[64];
    sp_digit m[64];
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
        sp_2048_from_mp(b, 64, base);
        sp_2048_from_mp(e, 64, exp);
        sp_2048_from_mp(m, 64, mod);

        err = sp_2048_mod_exp_64(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_2048_to_mp(r, res);
    }

    XMEMSET(e, 0, sizeof(e));

    return err;
}

#ifdef WOLFSSL_HAVE_SP_DH

static void sp_2048_lshift_64(sp_digit* r, const sp_digit* a, byte n)
{
    __asm__ __volatile__ (
        "rsb	r6, %[n], #31\n\t"
        "ldr	r3, [%[a], #252]\n\t"
        "lsr	r4, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r4, r4, r6\n\t"
        "ldr	r2, [%[a], #248]\n\t"
        "str	r4, [%[r], #256]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #244]\n\t"
        "str	r3, [%[r], #252]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #240]\n\t"
        "str	r2, [%[r], #248]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #236]\n\t"
        "str	r4, [%[r], #244]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #232]\n\t"
        "str	r3, [%[r], #240]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #228]\n\t"
        "str	r2, [%[r], #236]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #224]\n\t"
        "str	r4, [%[r], #232]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #220]\n\t"
        "str	r3, [%[r], #228]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #216]\n\t"
        "str	r2, [%[r], #224]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #212]\n\t"
        "str	r4, [%[r], #220]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #208]\n\t"
        "str	r3, [%[r], #216]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #204]\n\t"
        "str	r2, [%[r], #212]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #200]\n\t"
        "str	r4, [%[r], #208]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #196]\n\t"
        "str	r3, [%[r], #204]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #192]\n\t"
        "str	r2, [%[r], #200]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #188]\n\t"
        "str	r4, [%[r], #196]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #184]\n\t"
        "str	r3, [%[r], #192]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #180]\n\t"
        "str	r2, [%[r], #188]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #176]\n\t"
        "str	r4, [%[r], #184]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #172]\n\t"
        "str	r3, [%[r], #180]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #168]\n\t"
        "str	r2, [%[r], #176]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #164]\n\t"
        "str	r4, [%[r], #172]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #160]\n\t"
        "str	r3, [%[r], #168]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #156]\n\t"
        "str	r2, [%[r], #164]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #152]\n\t"
        "str	r4, [%[r], #160]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #148]\n\t"
        "str	r3, [%[r], #156]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #144]\n\t"
        "str	r2, [%[r], #152]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #140]\n\t"
        "str	r4, [%[r], #148]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #136]\n\t"
        "str	r3, [%[r], #144]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #132]\n\t"
        "str	r2, [%[r], #140]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #128]\n\t"
        "str	r4, [%[r], #136]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #124]\n\t"
        "str	r3, [%[r], #132]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #120]\n\t"
        "str	r2, [%[r], #128]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #116]\n\t"
        "str	r4, [%[r], #124]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #112]\n\t"
        "str	r3, [%[r], #120]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #108]\n\t"
        "str	r2, [%[r], #116]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #104]\n\t"
        "str	r4, [%[r], #112]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #100]\n\t"
        "str	r3, [%[r], #108]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #96]\n\t"
        "str	r2, [%[r], #104]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #92]\n\t"
        "str	r4, [%[r], #100]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #88]\n\t"
        "str	r3, [%[r], #96]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #84]\n\t"
        "str	r2, [%[r], #92]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #80]\n\t"
        "str	r4, [%[r], #88]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #76]\n\t"
        "str	r3, [%[r], #84]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #72]\n\t"
        "str	r2, [%[r], #80]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #68]\n\t"
        "str	r4, [%[r], #76]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #64]\n\t"
        "str	r3, [%[r], #72]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #60]\n\t"
        "str	r2, [%[r], #68]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #56]\n\t"
        "str	r4, [%[r], #64]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #52]\n\t"
        "str	r3, [%[r], #60]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #48]\n\t"
        "str	r2, [%[r], #56]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #44]\n\t"
        "str	r4, [%[r], #52]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #40]\n\t"
        "str	r3, [%[r], #48]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #36]\n\t"
        "str	r2, [%[r], #44]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #32]\n\t"
        "str	r4, [%[r], #40]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #28]\n\t"
        "str	r3, [%[r], #36]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #24]\n\t"
        "str	r2, [%[r], #32]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #20]\n\t"
        "str	r4, [%[r], #28]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #16]\n\t"
        "str	r3, [%[r], #24]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #12]\n\t"
        "str	r2, [%[r], #20]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #8]\n\t"
        "str	r4, [%[r], #16]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #4]\n\t"
        "str	r3, [%[r], #12]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #0]\n\t"
        "str	r2, [%[r], #8]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "strd	r3, r4, [%[r]]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [n] "r" (n)
        : "memory", "r2", "r3", "r4", "r5", "r6"
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
static int sp_2048_mod_exp_2_64(sp_digit* r, const sp_digit* e, int bits,
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

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_64(norm, m);

        i = (bits - 1) / 32;
        n = e[i--];
        c = bits & 31;
        if (c == 0) {
            c = 32;
        }
        c -= bits % 5;
        if (c == 32) {
            c = 27;
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
            n <<= 32 - c;
        }
        sp_2048_lshift_64(r, norm, y);
        for (; i>=0 || c>=5; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 27);
                n <<= 5;
                c = 27;
            }
            else if (c < 5) {
                y = (byte)(n >> 27);
                n = e[i--];
                c = 5 - c;
                y |= (byte)(n >> (32 - c));
                n <<= c;
                c = 32 - c;
            }
            else {
                y = (byte)((n >> 27) & 0x1f);
                n <<= 5;
                c -= 5;
            }

            sp_2048_mont_sqr_64(r, r, m, mp);
            sp_2048_mont_sqr_64(r, r, m, mp);
            sp_2048_mont_sqr_64(r, r, m, mp);
            sp_2048_mont_sqr_64(r, r, m, mp);
            sp_2048_mont_sqr_64(r, r, m, mp);

            sp_2048_lshift_64(r, r, y);
            sp_2048_mul_d_64(tmp, norm, r[64]);
            r[64] = 0;
            o = sp_2048_add_64(r, r, tmp);
            sp_2048_cond_sub_64(r, r, m, (sp_digit)0 - o);
        }

        XMEMSET(&r[64], 0, sizeof(sp_digit) * 64U);
        sp_2048_mont_reduce_64(r, m, mp);

        mask = 0 - (sp_2048_cmp_64(r, m) >= 0);
        sp_2048_cond_sub_64(r, r, m, mask);
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
    sp_digit b[128];
    sp_digit e[64];
    sp_digit m[64];
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
        sp_2048_from_mp(b, 64, base);
        sp_2048_from_bin(e, 64, exp, expLen);
        sp_2048_from_mp(m, 64, mod);

        if (base->used == 1 && base->dp[0] == 2 && m[63] == (sp_digit)-1)
            err = sp_2048_mod_exp_2_64(r, e, expLen * 8, m);
        else
            err = sp_2048_mod_exp_64(r, b, e, expLen * 8, m, 0);

    }

    if (err == MP_OKAY) {
        sp_2048_to_bin_64(r, out);
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
    sp_digit b[64];
    sp_digit e[32];
    sp_digit m[32];
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
        sp_2048_from_mp(b, 32, base);
        sp_2048_from_mp(e, 32, exp);
        sp_2048_from_mp(m, 32, mod);

        err = sp_2048_mod_exp_32(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 32, 0, sizeof(*r) * 32U);
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
    int i;
    int j;
    byte* d;

    for (i = n - 1,j = 0; i >= 3; i -= 4) {
        r[j]  = ((sp_digit)a[i - 0] <<  0) |
                ((sp_digit)a[i - 1] <<  8) |
                ((sp_digit)a[i - 2] << 16) |
                ((sp_digit)a[i - 3] << 24);
        j++;
    }

    if (i >= 0) {
        r[j] = 0;

        d = (byte*)r;
        switch (i) {
            case 2: d[n - 1 - 2] = a[2]; //fallthrough
            case 1: d[n - 1 - 1] = a[1]; //fallthrough
            case 0: d[n - 1 - 0] = a[0]; //fallthrough
        }
        j++;
    }

    for (; j < size; j++) {
        r[j] = 0;
    }
}

/* Convert an mp_int to an array of sp_digit.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  A multi-precision integer.
 */
static void sp_3072_from_mp(sp_digit* r, int size, const mp_int* a)
{
#if DIGIT_BIT == 32
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 32
    int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0xffffffff;
        s = 32U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 32U) <= (word32)DIGIT_BIT) {
            s += 32U;
            r[j] &= 0xffffffff;
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
        if (s + DIGIT_BIT >= 32) {
            r[j] &= 0xffffffff;
            if (j + 1 >= size) {
                break;
            }
            s = 32 - s;
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
static void sp_3072_to_bin_96(sp_digit* r, byte* a)
{
    int i;
    int j = 0;

    for (i = 95; i >= 0; i--) {
        a[j++] = r[i] >> 24;
        a[j++] = r[i] >> 16;
        a[j++] = r[i] >> 8;
        a[j++] = r[i] >> 0;
    }
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && (!defined(WOLFSSL_RSA_PUBLIC_ONLY) || !defined(WOLFSSL_SP_SMALL))) || defined(WOLFSSL_HAVE_SP_DH)
/* Normalize the values in each word to 32.
 *
 * a  Array of sp_digit to normalize.
 */
#define sp_3072_norm_96(a)

#endif /* (WOLFSSL_HAVE_SP_RSA && (!WOLFSSL_RSA_PUBLIC_ONLY || !WOLFSSL_SP_SMALL)) || WOLFSSL_HAVE_SP_DH */
/* Normalize the values in each word to 32.
 *
 * a  Array of sp_digit to normalize.
 */
#define sp_3072_norm_96(a)

#ifndef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static void sp_3072_mul_12(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    __asm__ __volatile__ (
        "sub	sp, sp, #48\n\t"
        "mov	r10, #0\n\t"
        "#  A[0] * B[0]\n\t"
        "ldr	r11, [%[a], #0]\n\t"
        "ldr	r12, [%[b], #0]\n\t"
        "umull	r3, r4, r11, r12\n\t"
        "mov	r5, #0\n\t"
        "str	r3, [sp]\n\t"
        "#  A[0] * B[1]\n\t"
        "ldr	r9, [%[b], #4]\n\t"
        "umull	r6, r7, r11, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "#  A[1] * B[0]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "str	r4, [sp, #4]\n\t"
        "#  A[2] * B[0]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "#  A[1] * B[1]\n\t"
        "ldr	r11, [%[a], #4]\n\t"
        "ldr	r12, [%[b], #4]\n\t"
        "umull	r6, r7, r11, r12\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[0] * B[2]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "ldr	r9, [%[b], #8]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "str	r5, [sp, #8]\n\t"
        "#  A[0] * B[3]\n\t"
        "ldr	r9, [%[b], #12]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "#  A[1] * B[2]\n\t"
        "ldr	r9, [%[b], #8]\n\t"
        "umull	r6, r7, r11, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[2] * B[1]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[3] * B[0]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "ldr	r9, [%[b], #0]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "str	r3, [sp, #12]\n\t"
        "#  A[4] * B[0]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "#  A[3] * B[1]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[2] * B[2]\n\t"
        "ldr	r11, [%[a], #8]\n\t"
        "ldr	r12, [%[b], #8]\n\t"
        "umull	r6, r7, r11, r12\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[1] * B[3]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "ldr	r9, [%[b], #12]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[0] * B[4]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "ldr	r9, [%[b], #16]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "str	r4, [sp, #16]\n\t"
        "#  A[0] * B[5]\n\t"
        "ldr	r9, [%[b], #20]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "#  A[1] * B[4]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "ldr	r9, [%[b], #16]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[2] * B[3]\n\t"
        "ldr	r9, [%[b], #12]\n\t"
        "umull	r6, r7, r11, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[3] * B[2]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[4] * B[1]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "ldr	r9, [%[b], #4]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[5] * B[0]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "ldr	r9, [%[b], #0]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "str	r5, [sp, #20]\n\t"
        "#  A[6] * B[0]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "#  A[5] * B[1]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "ldr	r9, [%[b], #4]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[4] * B[2]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[3] * B[3]\n\t"
        "ldr	r11, [%[a], #12]\n\t"
        "ldr	r12, [%[b], #12]\n\t"
        "umull	r6, r7, r11, r12\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[2] * B[4]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "ldr	r9, [%[b], #16]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[1] * B[5]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "ldr	r9, [%[b], #20]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[0] * B[6]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "ldr	r9, [%[b], #24]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "str	r3, [sp, #24]\n\t"
        "#  A[0] * B[7]\n\t"
        "ldr	r9, [%[b], #28]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "#  A[1] * B[6]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "ldr	r9, [%[b], #24]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[2] * B[5]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "ldr	r9, [%[b], #20]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[3] * B[4]\n\t"
        "ldr	r9, [%[b], #16]\n\t"
        "umull	r6, r7, r11, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[4] * B[3]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[5] * B[2]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "ldr	r9, [%[b], #8]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[6] * B[1]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "ldr	r9, [%[b], #4]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[7] * B[0]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "ldr	r9, [%[b], #0]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "str	r4, [sp, #28]\n\t"
        "#  A[8] * B[0]\n\t"
        "ldr	r8, [%[a], #32]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "#  A[7] * B[1]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "ldr	r9, [%[b], #4]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[6] * B[2]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "ldr	r9, [%[b], #8]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[5] * B[3]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[4] * B[4]\n\t"
        "ldr	r11, [%[a], #16]\n\t"
        "ldr	r12, [%[b], #16]\n\t"
        "umull	r6, r7, r11, r12\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[3] * B[5]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "ldr	r9, [%[b], #20]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[2] * B[6]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "ldr	r9, [%[b], #24]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[1] * B[7]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "ldr	r9, [%[b], #28]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[0] * B[8]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "ldr	r9, [%[b], #32]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "str	r5, [sp, #32]\n\t"
        "#  A[0] * B[9]\n\t"
        "ldr	r9, [%[b], #36]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "#  A[1] * B[8]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "ldr	r9, [%[b], #32]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[2] * B[7]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "ldr	r9, [%[b], #28]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[3] * B[6]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "ldr	r9, [%[b], #24]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[4] * B[5]\n\t"
        "ldr	r9, [%[b], #20]\n\t"
        "umull	r6, r7, r11, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[5] * B[4]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[6] * B[3]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "ldr	r9, [%[b], #12]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[7] * B[2]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "ldr	r9, [%[b], #8]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[8] * B[1]\n\t"
        "ldr	r8, [%[a], #32]\n\t"
        "ldr	r9, [%[b], #4]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[9] * B[0]\n\t"
        "ldr	r8, [%[a], #36]\n\t"
        "ldr	r9, [%[b], #0]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "str	r3, [sp, #36]\n\t"
        "#  A[10] * B[0]\n\t"
        "ldr	r8, [%[a], #40]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "#  A[9] * B[1]\n\t"
        "ldr	r8, [%[a], #36]\n\t"
        "ldr	r9, [%[b], #4]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[8] * B[2]\n\t"
        "ldr	r8, [%[a], #32]\n\t"
        "ldr	r9, [%[b], #8]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[7] * B[3]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "ldr	r9, [%[b], #12]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[6] * B[4]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[5] * B[5]\n\t"
        "ldr	r11, [%[a], #20]\n\t"
        "ldr	r12, [%[b], #20]\n\t"
        "umull	r6, r7, r11, r12\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[4] * B[6]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "ldr	r9, [%[b], #24]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[3] * B[7]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "ldr	r9, [%[b], #28]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[2] * B[8]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "ldr	r9, [%[b], #32]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[1] * B[9]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "ldr	r9, [%[b], #36]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[0] * B[10]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "ldr	r9, [%[b], #40]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "str	r4, [sp, #40]\n\t"
        "#  A[0] * B[11]\n\t"
        "ldr	r9, [%[b], #44]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "#  A[1] * B[10]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "ldr	r9, [%[b], #40]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[2] * B[9]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "ldr	r9, [%[b], #36]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[3] * B[8]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "ldr	r9, [%[b], #32]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[4] * B[7]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "ldr	r9, [%[b], #28]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[5] * B[6]\n\t"
        "ldr	r9, [%[b], #24]\n\t"
        "umull	r6, r7, r11, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[6] * B[5]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[7] * B[4]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "ldr	r9, [%[b], #16]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[8] * B[3]\n\t"
        "ldr	r8, [%[a], #32]\n\t"
        "ldr	r9, [%[b], #12]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[9] * B[2]\n\t"
        "ldr	r8, [%[a], #36]\n\t"
        "ldr	r9, [%[b], #8]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[10] * B[1]\n\t"
        "ldr	r8, [%[a], #40]\n\t"
        "ldr	r9, [%[b], #4]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[11] * B[0]\n\t"
        "ldr	r8, [%[a], #44]\n\t"
        "ldr	r9, [%[b], #0]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "str	r5, [sp, #44]\n\t"
        "#  A[11] * B[1]\n\t"
        "ldr	r9, [%[b], #4]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "#  A[10] * B[2]\n\t"
        "ldr	r8, [%[a], #40]\n\t"
        "ldr	r9, [%[b], #8]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[9] * B[3]\n\t"
        "ldr	r8, [%[a], #36]\n\t"
        "ldr	r9, [%[b], #12]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[8] * B[4]\n\t"
        "ldr	r8, [%[a], #32]\n\t"
        "ldr	r9, [%[b], #16]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[7] * B[5]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[6] * B[6]\n\t"
        "ldr	r11, [%[a], #24]\n\t"
        "ldr	r12, [%[b], #24]\n\t"
        "umull	r6, r7, r11, r12\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[5] * B[7]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "ldr	r9, [%[b], #28]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[4] * B[8]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "ldr	r9, [%[b], #32]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[3] * B[9]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "ldr	r9, [%[b], #36]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[2] * B[10]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "ldr	r9, [%[b], #40]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[1] * B[11]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "ldr	r9, [%[b], #44]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "str	r3, [%[r], #48]\n\t"
        "#  A[2] * B[11]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "#  A[3] * B[10]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "ldr	r9, [%[b], #40]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[4] * B[9]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "ldr	r9, [%[b], #36]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[5] * B[8]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "ldr	r9, [%[b], #32]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[6] * B[7]\n\t"
        "ldr	r9, [%[b], #28]\n\t"
        "umull	r6, r7, r11, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[7] * B[6]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[8] * B[5]\n\t"
        "ldr	r8, [%[a], #32]\n\t"
        "ldr	r9, [%[b], #20]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[9] * B[4]\n\t"
        "ldr	r8, [%[a], #36]\n\t"
        "ldr	r9, [%[b], #16]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[10] * B[3]\n\t"
        "ldr	r8, [%[a], #40]\n\t"
        "ldr	r9, [%[b], #12]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[11] * B[2]\n\t"
        "ldr	r8, [%[a], #44]\n\t"
        "ldr	r9, [%[b], #8]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "str	r4, [%[r], #52]\n\t"
        "#  A[11] * B[3]\n\t"
        "ldr	r9, [%[b], #12]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "#  A[10] * B[4]\n\t"
        "ldr	r8, [%[a], #40]\n\t"
        "ldr	r9, [%[b], #16]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[9] * B[5]\n\t"
        "ldr	r8, [%[a], #36]\n\t"
        "ldr	r9, [%[b], #20]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[8] * B[6]\n\t"
        "ldr	r8, [%[a], #32]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[7] * B[7]\n\t"
        "ldr	r11, [%[a], #28]\n\t"
        "ldr	r12, [%[b], #28]\n\t"
        "umull	r6, r7, r11, r12\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[6] * B[8]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "ldr	r9, [%[b], #32]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[5] * B[9]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "ldr	r9, [%[b], #36]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[4] * B[10]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "ldr	r9, [%[b], #40]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[3] * B[11]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "ldr	r9, [%[b], #44]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "str	r5, [%[r], #56]\n\t"
        "#  A[4] * B[11]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "#  A[5] * B[10]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "ldr	r9, [%[b], #40]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[6] * B[9]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "ldr	r9, [%[b], #36]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[7] * B[8]\n\t"
        "ldr	r9, [%[b], #32]\n\t"
        "umull	r6, r7, r11, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[8] * B[7]\n\t"
        "ldr	r8, [%[a], #32]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[9] * B[6]\n\t"
        "ldr	r8, [%[a], #36]\n\t"
        "ldr	r9, [%[b], #24]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[10] * B[5]\n\t"
        "ldr	r8, [%[a], #40]\n\t"
        "ldr	r9, [%[b], #20]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[11] * B[4]\n\t"
        "ldr	r8, [%[a], #44]\n\t"
        "ldr	r9, [%[b], #16]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "str	r3, [%[r], #60]\n\t"
        "#  A[11] * B[5]\n\t"
        "ldr	r9, [%[b], #20]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "#  A[10] * B[6]\n\t"
        "ldr	r8, [%[a], #40]\n\t"
        "ldr	r9, [%[b], #24]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[9] * B[7]\n\t"
        "ldr	r8, [%[a], #36]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[8] * B[8]\n\t"
        "ldr	r11, [%[a], #32]\n\t"
        "ldr	r12, [%[b], #32]\n\t"
        "umull	r6, r7, r11, r12\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[7] * B[9]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "ldr	r9, [%[b], #36]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[6] * B[10]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "ldr	r9, [%[b], #40]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[5] * B[11]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "ldr	r9, [%[b], #44]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "str	r4, [%[r], #64]\n\t"
        "#  A[6] * B[11]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "#  A[7] * B[10]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "ldr	r9, [%[b], #40]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[8] * B[9]\n\t"
        "ldr	r9, [%[b], #36]\n\t"
        "umull	r6, r7, r11, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[9] * B[8]\n\t"
        "ldr	r8, [%[a], #36]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[10] * B[7]\n\t"
        "ldr	r8, [%[a], #40]\n\t"
        "ldr	r9, [%[b], #28]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[11] * B[6]\n\t"
        "ldr	r8, [%[a], #44]\n\t"
        "ldr	r9, [%[b], #24]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "str	r5, [%[r], #68]\n\t"
        "#  A[11] * B[7]\n\t"
        "ldr	r9, [%[b], #28]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "#  A[10] * B[8]\n\t"
        "ldr	r8, [%[a], #40]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[9] * B[9]\n\t"
        "ldr	r11, [%[a], #36]\n\t"
        "ldr	r12, [%[b], #36]\n\t"
        "umull	r6, r7, r11, r12\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[8] * B[10]\n\t"
        "ldr	r8, [%[a], #32]\n\t"
        "ldr	r9, [%[b], #40]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "#  A[7] * B[11]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "ldr	r9, [%[b], #44]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "str	r3, [%[r], #72]\n\t"
        "#  A[8] * B[11]\n\t"
        "ldr	r8, [%[a], #32]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "#  A[9] * B[10]\n\t"
        "ldr	r9, [%[b], #40]\n\t"
        "umull	r6, r7, r11, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[10] * B[9]\n\t"
        "ldr	r8, [%[a], #40]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "#  A[11] * B[8]\n\t"
        "ldr	r8, [%[a], #44]\n\t"
        "ldr	r9, [%[b], #32]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r3, r10\n\t"
        "str	r4, [%[r], #76]\n\t"
        "#  A[11] * B[9]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "#  A[10] * B[10]\n\t"
        "ldr	r11, [%[a], #40]\n\t"
        "ldr	r12, [%[b], #40]\n\t"
        "umull	r6, r7, r11, r12\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "#  A[9] * B[11]\n\t"
        "ldr	r8, [%[a], #36]\n\t"
        "ldr	r9, [%[b], #44]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r4, r10\n\t"
        "str	r5, [%[r], #80]\n\t"
        "#  A[10] * B[11]\n\t"
        "umull	r6, r7, r11, r9\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "#  A[11] * B[10]\n\t"
        "ldr	r8, [%[a], #44]\n\t"
        "umull	r6, r7, r8, r12\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "str	r3, [%[r], #84]\n\t"
        "#  A[11] * B[11]\n\t"
        "umull	r6, r7, r8, r9\n\t"
        "adds	r4, r4, r6\n\t"
        "adc	r5, r5, r7\n\t"
        "str	r4, [%[r], #88]\n\t"
        "str	r5, [%[r], #92]\n\t"
        "ldm	sp!, {r3, r4, r5, r6}\n\t"
        "stm	%[r]!, {r3, r4, r5, r6}\n\t"
        "ldm	sp!, {r3, r4, r5, r6}\n\t"
        "stm	%[r]!, {r3, r4, r5, r6}\n\t"
        "ldm	sp!, {r3, r4, r5, r6}\n\t"
        "stm	%[r]!, {r3, r4, r5, r6}\n\t"
        "sub	%[r], %[r], #48\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
    );
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
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r14, #0\n\t"
        "ldrd	r3, r4, [%[a], #0]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b], #0]\n\t"
        "ldrd	r9, r10, [%[b], #8]\n\t"
        "adds	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #0]\n\t"
        "strd	r5, r6, [%[r], #8]\n\t"
        "ldrd	r3, r4, [%[a], #16]\n\t"
        "ldrd	r5, r6, [%[a], #24]\n\t"
        "ldrd	r7, r8, [%[b], #16]\n\t"
        "ldrd	r9, r10, [%[b], #24]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #16]\n\t"
        "strd	r5, r6, [%[r], #24]\n\t"
        "ldrd	r3, r4, [%[a], #32]\n\t"
        "ldrd	r5, r6, [%[a], #40]\n\t"
        "ldrd	r7, r8, [%[b], #32]\n\t"
        "ldrd	r9, r10, [%[b], #40]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #32]\n\t"
        "strd	r5, r6, [%[r], #40]\n\t"
        "adc	%[c], r14, r14\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14"
    );

    return c;
}

/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer and result.
 * b  A single precision integer.
 */
static sp_digit sp_3072_sub_in_place_24(sp_digit* a, const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldrd	r2, r3, [%[a], #0]\n\t"
        "ldrd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r6, r7, [%[b], #0]\n\t"
        "ldrd	r8, r9, [%[b], #8]\n\t"
        "subs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #0]\n\t"
        "strd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r2, r3, [%[a], #16]\n\t"
        "ldrd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r6, r7, [%[b], #16]\n\t"
        "ldrd	r8, r9, [%[b], #24]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #16]\n\t"
        "strd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r2, r3, [%[a], #32]\n\t"
        "ldrd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r6, r7, [%[b], #32]\n\t"
        "ldrd	r8, r9, [%[b], #40]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #32]\n\t"
        "strd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r2, r3, [%[a], #48]\n\t"
        "ldrd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r6, r7, [%[b], #48]\n\t"
        "ldrd	r8, r9, [%[b], #56]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #48]\n\t"
        "strd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r2, r3, [%[a], #64]\n\t"
        "ldrd	r4, r5, [%[a], #72]\n\t"
        "ldrd	r6, r7, [%[b], #64]\n\t"
        "ldrd	r8, r9, [%[b], #72]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #64]\n\t"
        "strd	r4, r5, [%[a], #72]\n\t"
        "ldrd	r2, r3, [%[a], #80]\n\t"
        "ldrd	r4, r5, [%[a], #88]\n\t"
        "ldrd	r6, r7, [%[b], #80]\n\t"
        "ldrd	r8, r9, [%[b], #88]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #80]\n\t"
        "strd	r4, r5, [%[a], #88]\n\t"
        "sbc	%[c], r9, r9\n\t"
        : [c] "+r" (c)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9"
    );

    return c;
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
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r14, #0\n\t"
        "ldrd	r3, r4, [%[a], #0]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b], #0]\n\t"
        "ldrd	r9, r10, [%[b], #8]\n\t"
        "adds	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #0]\n\t"
        "strd	r5, r6, [%[r], #8]\n\t"
        "ldrd	r3, r4, [%[a], #16]\n\t"
        "ldrd	r5, r6, [%[a], #24]\n\t"
        "ldrd	r7, r8, [%[b], #16]\n\t"
        "ldrd	r9, r10, [%[b], #24]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #16]\n\t"
        "strd	r5, r6, [%[r], #24]\n\t"
        "ldrd	r3, r4, [%[a], #32]\n\t"
        "ldrd	r5, r6, [%[a], #40]\n\t"
        "ldrd	r7, r8, [%[b], #32]\n\t"
        "ldrd	r9, r10, [%[b], #40]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #32]\n\t"
        "strd	r5, r6, [%[r], #40]\n\t"
        "ldrd	r3, r4, [%[a], #48]\n\t"
        "ldrd	r5, r6, [%[a], #56]\n\t"
        "ldrd	r7, r8, [%[b], #48]\n\t"
        "ldrd	r9, r10, [%[b], #56]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #48]\n\t"
        "strd	r5, r6, [%[r], #56]\n\t"
        "ldrd	r3, r4, [%[a], #64]\n\t"
        "ldrd	r5, r6, [%[a], #72]\n\t"
        "ldrd	r7, r8, [%[b], #64]\n\t"
        "ldrd	r9, r10, [%[b], #72]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #64]\n\t"
        "strd	r5, r6, [%[r], #72]\n\t"
        "ldrd	r3, r4, [%[a], #80]\n\t"
        "ldrd	r5, r6, [%[a], #88]\n\t"
        "ldrd	r7, r8, [%[b], #80]\n\t"
        "ldrd	r9, r10, [%[b], #88]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #80]\n\t"
        "strd	r5, r6, [%[r], #88]\n\t"
        "adc	%[c], r14, r14\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14"
    );

    return c;
}

/* AND m into each word of a and store in r.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * m  Mask to AND against each digit.
 */
static void sp_3072_mask_12(sp_digit* r, const sp_digit* a, sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<12; i++) {
        r[i] = a[i] & m;
    }
#else
    r[0] = a[0] & m;
    r[1] = a[1] & m;
    r[2] = a[2] & m;
    r[3] = a[3] & m;
    r[4] = a[4] & m;
    r[5] = a[5] & m;
    r[6] = a[6] & m;
    r[7] = a[7] & m;
    r[8] = a[8] & m;
    r[9] = a[9] & m;
    r[10] = a[10] & m;
    r[11] = a[11] & m;
#endif
}

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
    sp_3072_mask_12(a1, a1, 0 - cb);
    u += sp_3072_add_12(z1 + 12, z1 + 12, a1);
    sp_3072_mask_12(b1, b1, 0 - ca);
    u += sp_3072_add_12(z1 + 12, z1 + 12, b1);

    u += sp_3072_add_24(r + 12, r + 12, z1);
    XMEMSET(a1 + 1, 0, sizeof(sp_digit) * (12 - 1));
    a1[0] = u;
    (void)sp_3072_add_12(r + 36, r + 36, a1);
}

/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer and result.
 * b  A single precision integer.
 */
static sp_digit sp_3072_sub_in_place_48(sp_digit* a, const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldrd	r2, r3, [%[a], #0]\n\t"
        "ldrd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r6, r7, [%[b], #0]\n\t"
        "ldrd	r8, r9, [%[b], #8]\n\t"
        "subs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #0]\n\t"
        "strd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r2, r3, [%[a], #16]\n\t"
        "ldrd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r6, r7, [%[b], #16]\n\t"
        "ldrd	r8, r9, [%[b], #24]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #16]\n\t"
        "strd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r2, r3, [%[a], #32]\n\t"
        "ldrd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r6, r7, [%[b], #32]\n\t"
        "ldrd	r8, r9, [%[b], #40]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #32]\n\t"
        "strd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r2, r3, [%[a], #48]\n\t"
        "ldrd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r6, r7, [%[b], #48]\n\t"
        "ldrd	r8, r9, [%[b], #56]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #48]\n\t"
        "strd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r2, r3, [%[a], #64]\n\t"
        "ldrd	r4, r5, [%[a], #72]\n\t"
        "ldrd	r6, r7, [%[b], #64]\n\t"
        "ldrd	r8, r9, [%[b], #72]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #64]\n\t"
        "strd	r4, r5, [%[a], #72]\n\t"
        "ldrd	r2, r3, [%[a], #80]\n\t"
        "ldrd	r4, r5, [%[a], #88]\n\t"
        "ldrd	r6, r7, [%[b], #80]\n\t"
        "ldrd	r8, r9, [%[b], #88]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #80]\n\t"
        "strd	r4, r5, [%[a], #88]\n\t"
        "ldrd	r2, r3, [%[a], #96]\n\t"
        "ldrd	r4, r5, [%[a], #104]\n\t"
        "ldrd	r6, r7, [%[b], #96]\n\t"
        "ldrd	r8, r9, [%[b], #104]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #96]\n\t"
        "strd	r4, r5, [%[a], #104]\n\t"
        "ldrd	r2, r3, [%[a], #112]\n\t"
        "ldrd	r4, r5, [%[a], #120]\n\t"
        "ldrd	r6, r7, [%[b], #112]\n\t"
        "ldrd	r8, r9, [%[b], #120]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #112]\n\t"
        "strd	r4, r5, [%[a], #120]\n\t"
        "ldrd	r2, r3, [%[a], #128]\n\t"
        "ldrd	r4, r5, [%[a], #136]\n\t"
        "ldrd	r6, r7, [%[b], #128]\n\t"
        "ldrd	r8, r9, [%[b], #136]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #128]\n\t"
        "strd	r4, r5, [%[a], #136]\n\t"
        "ldrd	r2, r3, [%[a], #144]\n\t"
        "ldrd	r4, r5, [%[a], #152]\n\t"
        "ldrd	r6, r7, [%[b], #144]\n\t"
        "ldrd	r8, r9, [%[b], #152]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #144]\n\t"
        "strd	r4, r5, [%[a], #152]\n\t"
        "ldrd	r2, r3, [%[a], #160]\n\t"
        "ldrd	r4, r5, [%[a], #168]\n\t"
        "ldrd	r6, r7, [%[b], #160]\n\t"
        "ldrd	r8, r9, [%[b], #168]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #160]\n\t"
        "strd	r4, r5, [%[a], #168]\n\t"
        "ldrd	r2, r3, [%[a], #176]\n\t"
        "ldrd	r4, r5, [%[a], #184]\n\t"
        "ldrd	r6, r7, [%[b], #176]\n\t"
        "ldrd	r8, r9, [%[b], #184]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #176]\n\t"
        "strd	r4, r5, [%[a], #184]\n\t"
        "sbc	%[c], r9, r9\n\t"
        : [c] "+r" (c)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9"
    );

    return c;
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
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r14, #0\n\t"
        "ldrd	r3, r4, [%[a], #0]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b], #0]\n\t"
        "ldrd	r9, r10, [%[b], #8]\n\t"
        "adds	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #0]\n\t"
        "strd	r5, r6, [%[r], #8]\n\t"
        "ldrd	r3, r4, [%[a], #16]\n\t"
        "ldrd	r5, r6, [%[a], #24]\n\t"
        "ldrd	r7, r8, [%[b], #16]\n\t"
        "ldrd	r9, r10, [%[b], #24]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #16]\n\t"
        "strd	r5, r6, [%[r], #24]\n\t"
        "ldrd	r3, r4, [%[a], #32]\n\t"
        "ldrd	r5, r6, [%[a], #40]\n\t"
        "ldrd	r7, r8, [%[b], #32]\n\t"
        "ldrd	r9, r10, [%[b], #40]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #32]\n\t"
        "strd	r5, r6, [%[r], #40]\n\t"
        "ldrd	r3, r4, [%[a], #48]\n\t"
        "ldrd	r5, r6, [%[a], #56]\n\t"
        "ldrd	r7, r8, [%[b], #48]\n\t"
        "ldrd	r9, r10, [%[b], #56]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #48]\n\t"
        "strd	r5, r6, [%[r], #56]\n\t"
        "ldrd	r3, r4, [%[a], #64]\n\t"
        "ldrd	r5, r6, [%[a], #72]\n\t"
        "ldrd	r7, r8, [%[b], #64]\n\t"
        "ldrd	r9, r10, [%[b], #72]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #64]\n\t"
        "strd	r5, r6, [%[r], #72]\n\t"
        "ldrd	r3, r4, [%[a], #80]\n\t"
        "ldrd	r5, r6, [%[a], #88]\n\t"
        "ldrd	r7, r8, [%[b], #80]\n\t"
        "ldrd	r9, r10, [%[b], #88]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #80]\n\t"
        "strd	r5, r6, [%[r], #88]\n\t"
        "ldrd	r3, r4, [%[a], #96]\n\t"
        "ldrd	r5, r6, [%[a], #104]\n\t"
        "ldrd	r7, r8, [%[b], #96]\n\t"
        "ldrd	r9, r10, [%[b], #104]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #96]\n\t"
        "strd	r5, r6, [%[r], #104]\n\t"
        "ldrd	r3, r4, [%[a], #112]\n\t"
        "ldrd	r5, r6, [%[a], #120]\n\t"
        "ldrd	r7, r8, [%[b], #112]\n\t"
        "ldrd	r9, r10, [%[b], #120]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #112]\n\t"
        "strd	r5, r6, [%[r], #120]\n\t"
        "ldrd	r3, r4, [%[a], #128]\n\t"
        "ldrd	r5, r6, [%[a], #136]\n\t"
        "ldrd	r7, r8, [%[b], #128]\n\t"
        "ldrd	r9, r10, [%[b], #136]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #128]\n\t"
        "strd	r5, r6, [%[r], #136]\n\t"
        "ldrd	r3, r4, [%[a], #144]\n\t"
        "ldrd	r5, r6, [%[a], #152]\n\t"
        "ldrd	r7, r8, [%[b], #144]\n\t"
        "ldrd	r9, r10, [%[b], #152]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #144]\n\t"
        "strd	r5, r6, [%[r], #152]\n\t"
        "ldrd	r3, r4, [%[a], #160]\n\t"
        "ldrd	r5, r6, [%[a], #168]\n\t"
        "ldrd	r7, r8, [%[b], #160]\n\t"
        "ldrd	r9, r10, [%[b], #168]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #160]\n\t"
        "strd	r5, r6, [%[r], #168]\n\t"
        "ldrd	r3, r4, [%[a], #176]\n\t"
        "ldrd	r5, r6, [%[a], #184]\n\t"
        "ldrd	r7, r8, [%[b], #176]\n\t"
        "ldrd	r9, r10, [%[b], #184]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #176]\n\t"
        "strd	r5, r6, [%[r], #184]\n\t"
        "adc	%[c], r14, r14\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14"
    );

    return c;
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
    sp_3072_mask_24(a1, a1, 0 - cb);
    u += sp_3072_add_24(z1 + 24, z1 + 24, a1);
    sp_3072_mask_24(b1, b1, 0 - ca);
    u += sp_3072_add_24(z1 + 24, z1 + 24, b1);

    u += sp_3072_add_48(r + 24, r + 24, z1);
    XMEMSET(a1 + 1, 0, sizeof(sp_digit) * (24 - 1));
    a1[0] = u;
    (void)sp_3072_add_24(r + 72, r + 72, a1);
}

/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer and result.
 * b  A single precision integer.
 */
static sp_digit sp_3072_sub_in_place_96(sp_digit* a, const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldrd	r2, r3, [%[a], #0]\n\t"
        "ldrd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r6, r7, [%[b], #0]\n\t"
        "ldrd	r8, r9, [%[b], #8]\n\t"
        "subs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #0]\n\t"
        "strd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r2, r3, [%[a], #16]\n\t"
        "ldrd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r6, r7, [%[b], #16]\n\t"
        "ldrd	r8, r9, [%[b], #24]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #16]\n\t"
        "strd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r2, r3, [%[a], #32]\n\t"
        "ldrd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r6, r7, [%[b], #32]\n\t"
        "ldrd	r8, r9, [%[b], #40]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #32]\n\t"
        "strd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r2, r3, [%[a], #48]\n\t"
        "ldrd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r6, r7, [%[b], #48]\n\t"
        "ldrd	r8, r9, [%[b], #56]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #48]\n\t"
        "strd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r2, r3, [%[a], #64]\n\t"
        "ldrd	r4, r5, [%[a], #72]\n\t"
        "ldrd	r6, r7, [%[b], #64]\n\t"
        "ldrd	r8, r9, [%[b], #72]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #64]\n\t"
        "strd	r4, r5, [%[a], #72]\n\t"
        "ldrd	r2, r3, [%[a], #80]\n\t"
        "ldrd	r4, r5, [%[a], #88]\n\t"
        "ldrd	r6, r7, [%[b], #80]\n\t"
        "ldrd	r8, r9, [%[b], #88]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #80]\n\t"
        "strd	r4, r5, [%[a], #88]\n\t"
        "ldrd	r2, r3, [%[a], #96]\n\t"
        "ldrd	r4, r5, [%[a], #104]\n\t"
        "ldrd	r6, r7, [%[b], #96]\n\t"
        "ldrd	r8, r9, [%[b], #104]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #96]\n\t"
        "strd	r4, r5, [%[a], #104]\n\t"
        "ldrd	r2, r3, [%[a], #112]\n\t"
        "ldrd	r4, r5, [%[a], #120]\n\t"
        "ldrd	r6, r7, [%[b], #112]\n\t"
        "ldrd	r8, r9, [%[b], #120]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #112]\n\t"
        "strd	r4, r5, [%[a], #120]\n\t"
        "ldrd	r2, r3, [%[a], #128]\n\t"
        "ldrd	r4, r5, [%[a], #136]\n\t"
        "ldrd	r6, r7, [%[b], #128]\n\t"
        "ldrd	r8, r9, [%[b], #136]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #128]\n\t"
        "strd	r4, r5, [%[a], #136]\n\t"
        "ldrd	r2, r3, [%[a], #144]\n\t"
        "ldrd	r4, r5, [%[a], #152]\n\t"
        "ldrd	r6, r7, [%[b], #144]\n\t"
        "ldrd	r8, r9, [%[b], #152]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #144]\n\t"
        "strd	r4, r5, [%[a], #152]\n\t"
        "ldrd	r2, r3, [%[a], #160]\n\t"
        "ldrd	r4, r5, [%[a], #168]\n\t"
        "ldrd	r6, r7, [%[b], #160]\n\t"
        "ldrd	r8, r9, [%[b], #168]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #160]\n\t"
        "strd	r4, r5, [%[a], #168]\n\t"
        "ldrd	r2, r3, [%[a], #176]\n\t"
        "ldrd	r4, r5, [%[a], #184]\n\t"
        "ldrd	r6, r7, [%[b], #176]\n\t"
        "ldrd	r8, r9, [%[b], #184]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #176]\n\t"
        "strd	r4, r5, [%[a], #184]\n\t"
        "ldrd	r2, r3, [%[a], #192]\n\t"
        "ldrd	r4, r5, [%[a], #200]\n\t"
        "ldrd	r6, r7, [%[b], #192]\n\t"
        "ldrd	r8, r9, [%[b], #200]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #192]\n\t"
        "strd	r4, r5, [%[a], #200]\n\t"
        "ldrd	r2, r3, [%[a], #208]\n\t"
        "ldrd	r4, r5, [%[a], #216]\n\t"
        "ldrd	r6, r7, [%[b], #208]\n\t"
        "ldrd	r8, r9, [%[b], #216]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #208]\n\t"
        "strd	r4, r5, [%[a], #216]\n\t"
        "ldrd	r2, r3, [%[a], #224]\n\t"
        "ldrd	r4, r5, [%[a], #232]\n\t"
        "ldrd	r6, r7, [%[b], #224]\n\t"
        "ldrd	r8, r9, [%[b], #232]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #224]\n\t"
        "strd	r4, r5, [%[a], #232]\n\t"
        "ldrd	r2, r3, [%[a], #240]\n\t"
        "ldrd	r4, r5, [%[a], #248]\n\t"
        "ldrd	r6, r7, [%[b], #240]\n\t"
        "ldrd	r8, r9, [%[b], #248]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #240]\n\t"
        "strd	r4, r5, [%[a], #248]\n\t"
        "ldrd	r2, r3, [%[a], #256]\n\t"
        "ldrd	r4, r5, [%[a], #264]\n\t"
        "ldrd	r6, r7, [%[b], #256]\n\t"
        "ldrd	r8, r9, [%[b], #264]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #256]\n\t"
        "strd	r4, r5, [%[a], #264]\n\t"
        "ldrd	r2, r3, [%[a], #272]\n\t"
        "ldrd	r4, r5, [%[a], #280]\n\t"
        "ldrd	r6, r7, [%[b], #272]\n\t"
        "ldrd	r8, r9, [%[b], #280]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #272]\n\t"
        "strd	r4, r5, [%[a], #280]\n\t"
        "ldrd	r2, r3, [%[a], #288]\n\t"
        "ldrd	r4, r5, [%[a], #296]\n\t"
        "ldrd	r6, r7, [%[b], #288]\n\t"
        "ldrd	r8, r9, [%[b], #296]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #288]\n\t"
        "strd	r4, r5, [%[a], #296]\n\t"
        "ldrd	r2, r3, [%[a], #304]\n\t"
        "ldrd	r4, r5, [%[a], #312]\n\t"
        "ldrd	r6, r7, [%[b], #304]\n\t"
        "ldrd	r8, r9, [%[b], #312]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #304]\n\t"
        "strd	r4, r5, [%[a], #312]\n\t"
        "ldrd	r2, r3, [%[a], #320]\n\t"
        "ldrd	r4, r5, [%[a], #328]\n\t"
        "ldrd	r6, r7, [%[b], #320]\n\t"
        "ldrd	r8, r9, [%[b], #328]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #320]\n\t"
        "strd	r4, r5, [%[a], #328]\n\t"
        "ldrd	r2, r3, [%[a], #336]\n\t"
        "ldrd	r4, r5, [%[a], #344]\n\t"
        "ldrd	r6, r7, [%[b], #336]\n\t"
        "ldrd	r8, r9, [%[b], #344]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #336]\n\t"
        "strd	r4, r5, [%[a], #344]\n\t"
        "ldrd	r2, r3, [%[a], #352]\n\t"
        "ldrd	r4, r5, [%[a], #360]\n\t"
        "ldrd	r6, r7, [%[b], #352]\n\t"
        "ldrd	r8, r9, [%[b], #360]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #352]\n\t"
        "strd	r4, r5, [%[a], #360]\n\t"
        "ldrd	r2, r3, [%[a], #368]\n\t"
        "ldrd	r4, r5, [%[a], #376]\n\t"
        "ldrd	r6, r7, [%[b], #368]\n\t"
        "ldrd	r8, r9, [%[b], #376]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #368]\n\t"
        "strd	r4, r5, [%[a], #376]\n\t"
        "sbc	%[c], r9, r9\n\t"
        : [c] "+r" (c)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9"
    );

    return c;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_3072_add_96(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r14, #0\n\t"
        "ldrd	r3, r4, [%[a], #0]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b], #0]\n\t"
        "ldrd	r9, r10, [%[b], #8]\n\t"
        "adds	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #0]\n\t"
        "strd	r5, r6, [%[r], #8]\n\t"
        "ldrd	r3, r4, [%[a], #16]\n\t"
        "ldrd	r5, r6, [%[a], #24]\n\t"
        "ldrd	r7, r8, [%[b], #16]\n\t"
        "ldrd	r9, r10, [%[b], #24]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #16]\n\t"
        "strd	r5, r6, [%[r], #24]\n\t"
        "ldrd	r3, r4, [%[a], #32]\n\t"
        "ldrd	r5, r6, [%[a], #40]\n\t"
        "ldrd	r7, r8, [%[b], #32]\n\t"
        "ldrd	r9, r10, [%[b], #40]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #32]\n\t"
        "strd	r5, r6, [%[r], #40]\n\t"
        "ldrd	r3, r4, [%[a], #48]\n\t"
        "ldrd	r5, r6, [%[a], #56]\n\t"
        "ldrd	r7, r8, [%[b], #48]\n\t"
        "ldrd	r9, r10, [%[b], #56]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #48]\n\t"
        "strd	r5, r6, [%[r], #56]\n\t"
        "ldrd	r3, r4, [%[a], #64]\n\t"
        "ldrd	r5, r6, [%[a], #72]\n\t"
        "ldrd	r7, r8, [%[b], #64]\n\t"
        "ldrd	r9, r10, [%[b], #72]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #64]\n\t"
        "strd	r5, r6, [%[r], #72]\n\t"
        "ldrd	r3, r4, [%[a], #80]\n\t"
        "ldrd	r5, r6, [%[a], #88]\n\t"
        "ldrd	r7, r8, [%[b], #80]\n\t"
        "ldrd	r9, r10, [%[b], #88]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #80]\n\t"
        "strd	r5, r6, [%[r], #88]\n\t"
        "ldrd	r3, r4, [%[a], #96]\n\t"
        "ldrd	r5, r6, [%[a], #104]\n\t"
        "ldrd	r7, r8, [%[b], #96]\n\t"
        "ldrd	r9, r10, [%[b], #104]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #96]\n\t"
        "strd	r5, r6, [%[r], #104]\n\t"
        "ldrd	r3, r4, [%[a], #112]\n\t"
        "ldrd	r5, r6, [%[a], #120]\n\t"
        "ldrd	r7, r8, [%[b], #112]\n\t"
        "ldrd	r9, r10, [%[b], #120]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #112]\n\t"
        "strd	r5, r6, [%[r], #120]\n\t"
        "ldrd	r3, r4, [%[a], #128]\n\t"
        "ldrd	r5, r6, [%[a], #136]\n\t"
        "ldrd	r7, r8, [%[b], #128]\n\t"
        "ldrd	r9, r10, [%[b], #136]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #128]\n\t"
        "strd	r5, r6, [%[r], #136]\n\t"
        "ldrd	r3, r4, [%[a], #144]\n\t"
        "ldrd	r5, r6, [%[a], #152]\n\t"
        "ldrd	r7, r8, [%[b], #144]\n\t"
        "ldrd	r9, r10, [%[b], #152]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #144]\n\t"
        "strd	r5, r6, [%[r], #152]\n\t"
        "ldrd	r3, r4, [%[a], #160]\n\t"
        "ldrd	r5, r6, [%[a], #168]\n\t"
        "ldrd	r7, r8, [%[b], #160]\n\t"
        "ldrd	r9, r10, [%[b], #168]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #160]\n\t"
        "strd	r5, r6, [%[r], #168]\n\t"
        "ldrd	r3, r4, [%[a], #176]\n\t"
        "ldrd	r5, r6, [%[a], #184]\n\t"
        "ldrd	r7, r8, [%[b], #176]\n\t"
        "ldrd	r9, r10, [%[b], #184]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #176]\n\t"
        "strd	r5, r6, [%[r], #184]\n\t"
        "ldrd	r3, r4, [%[a], #192]\n\t"
        "ldrd	r5, r6, [%[a], #200]\n\t"
        "ldrd	r7, r8, [%[b], #192]\n\t"
        "ldrd	r9, r10, [%[b], #200]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #192]\n\t"
        "strd	r5, r6, [%[r], #200]\n\t"
        "ldrd	r3, r4, [%[a], #208]\n\t"
        "ldrd	r5, r6, [%[a], #216]\n\t"
        "ldrd	r7, r8, [%[b], #208]\n\t"
        "ldrd	r9, r10, [%[b], #216]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #208]\n\t"
        "strd	r5, r6, [%[r], #216]\n\t"
        "ldrd	r3, r4, [%[a], #224]\n\t"
        "ldrd	r5, r6, [%[a], #232]\n\t"
        "ldrd	r7, r8, [%[b], #224]\n\t"
        "ldrd	r9, r10, [%[b], #232]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #224]\n\t"
        "strd	r5, r6, [%[r], #232]\n\t"
        "ldrd	r3, r4, [%[a], #240]\n\t"
        "ldrd	r5, r6, [%[a], #248]\n\t"
        "ldrd	r7, r8, [%[b], #240]\n\t"
        "ldrd	r9, r10, [%[b], #248]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #240]\n\t"
        "strd	r5, r6, [%[r], #248]\n\t"
        "ldrd	r3, r4, [%[a], #256]\n\t"
        "ldrd	r5, r6, [%[a], #264]\n\t"
        "ldrd	r7, r8, [%[b], #256]\n\t"
        "ldrd	r9, r10, [%[b], #264]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #256]\n\t"
        "strd	r5, r6, [%[r], #264]\n\t"
        "ldrd	r3, r4, [%[a], #272]\n\t"
        "ldrd	r5, r6, [%[a], #280]\n\t"
        "ldrd	r7, r8, [%[b], #272]\n\t"
        "ldrd	r9, r10, [%[b], #280]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #272]\n\t"
        "strd	r5, r6, [%[r], #280]\n\t"
        "ldrd	r3, r4, [%[a], #288]\n\t"
        "ldrd	r5, r6, [%[a], #296]\n\t"
        "ldrd	r7, r8, [%[b], #288]\n\t"
        "ldrd	r9, r10, [%[b], #296]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #288]\n\t"
        "strd	r5, r6, [%[r], #296]\n\t"
        "ldrd	r3, r4, [%[a], #304]\n\t"
        "ldrd	r5, r6, [%[a], #312]\n\t"
        "ldrd	r7, r8, [%[b], #304]\n\t"
        "ldrd	r9, r10, [%[b], #312]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #304]\n\t"
        "strd	r5, r6, [%[r], #312]\n\t"
        "ldrd	r3, r4, [%[a], #320]\n\t"
        "ldrd	r5, r6, [%[a], #328]\n\t"
        "ldrd	r7, r8, [%[b], #320]\n\t"
        "ldrd	r9, r10, [%[b], #328]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #320]\n\t"
        "strd	r5, r6, [%[r], #328]\n\t"
        "ldrd	r3, r4, [%[a], #336]\n\t"
        "ldrd	r5, r6, [%[a], #344]\n\t"
        "ldrd	r7, r8, [%[b], #336]\n\t"
        "ldrd	r9, r10, [%[b], #344]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #336]\n\t"
        "strd	r5, r6, [%[r], #344]\n\t"
        "ldrd	r3, r4, [%[a], #352]\n\t"
        "ldrd	r5, r6, [%[a], #360]\n\t"
        "ldrd	r7, r8, [%[b], #352]\n\t"
        "ldrd	r9, r10, [%[b], #360]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #352]\n\t"
        "strd	r5, r6, [%[r], #360]\n\t"
        "ldrd	r3, r4, [%[a], #368]\n\t"
        "ldrd	r5, r6, [%[a], #376]\n\t"
        "ldrd	r7, r8, [%[b], #368]\n\t"
        "ldrd	r9, r10, [%[b], #376]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #368]\n\t"
        "strd	r5, r6, [%[r], #376]\n\t"
        "adc	%[c], r14, r14\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14"
    );

    return c;
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

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_96(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[96];
    sp_digit a1[48];
    sp_digit b1[48];
    sp_digit* z2 = r + 96;
    sp_digit u;
    sp_digit ca;
    sp_digit cb;

    ca = sp_3072_add_48(a1, a, &a[48]);
    cb = sp_3072_add_48(b1, b, &b[48]);
    u  = ca & cb;

    sp_3072_mul_48(z2, &a[48], &b[48]);
    sp_3072_mul_48(z0, a, b);
    sp_3072_mul_48(z1, a1, b1);

    u += sp_3072_sub_in_place_96(z1, z0);
    u += sp_3072_sub_in_place_96(z1, z2);
    sp_3072_mask_48(a1, a1, 0 - cb);
    u += sp_3072_add_48(z1 + 48, z1 + 48, a1);
    sp_3072_mask_48(b1, b1, 0 - ca);
    u += sp_3072_add_48(z1 + 48, z1 + 48, b1);

    u += sp_3072_add_96(r + 48, r + 48, z1);
    XMEMSET(a1 + 1, 0, sizeof(sp_digit) * (48 - 1));
    a1[0] = u;
    (void)sp_3072_add_48(r + 144, r + 144, a1);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
static void sp_3072_sqr_12(sp_digit* r, const sp_digit* a)
{
    __asm__ __volatile__ (
        "sub	sp, sp, #48\n\t"
        "mov	r12, #0\n\t"
        "#  A[0] * A[0]\n\t"
        "ldr	r10, [%[a], #0]\n\t"
        "umull	r8, r3, r10, r10\n\t"
        "mov	r4, #0\n\t"
        "str	r8, [sp]\n\t"
        "#  A[0] * A[1]\n\t"
        "ldr	r10, [%[a], #4]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r12, r12\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r2, r12\n\t"
        "str	r3, [sp, #4]\n\t"
        "#  A[0] * A[2]\n\t"
        "ldr	r10, [%[a], #8]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r4, r4, r8\n\t"
        "adcs	r2, r2, r9\n\t"
        "adc	r3, r12, r12\n\t"
        "adds	r4, r4, r8\n\t"
        "adcs	r2, r2, r9\n\t"
        "adc	r3, r3, r12\n\t"
        "#  A[1] * A[1]\n\t"
        "ldr	r10, [%[a], #4]\n\t"
        "umull	r8, r9, r10, r10\n\t"
        "adds	r4, r4, r8\n\t"
        "adcs	r2, r2, r9\n\t"
        "adc	r3, r3, r12\n\t"
        "str	r4, [sp, #8]\n\t"
        "#  A[0] * A[3]\n\t"
        "ldr	r10, [%[a], #12]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r2, r2, r8\n\t"
        "adcs	r3, r3, r9\n\t"
        "adc	r4, r12, r12\n\t"
        "adds	r2, r2, r8\n\t"
        "adcs	r3, r3, r9\n\t"
        "adc	r4, r4, r12\n\t"
        "#  A[1] * A[2]\n\t"
        "ldr	r10, [%[a], #8]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r2, r2, r8\n\t"
        "adcs	r3, r3, r9\n\t"
        "adc	r4, r4, r12\n\t"
        "adds	r2, r2, r8\n\t"
        "adcs	r3, r3, r9\n\t"
        "adc	r4, r4, r12\n\t"
        "str	r2, [sp, #12]\n\t"
        "#  A[0] * A[4]\n\t"
        "ldr	r10, [%[a], #16]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r12, r12\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r2, r12\n\t"
        "#  A[1] * A[3]\n\t"
        "ldr	r10, [%[a], #12]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r2, r12\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r2, r12\n\t"
        "#  A[2] * A[2]\n\t"
        "ldr	r10, [%[a], #8]\n\t"
        "umull	r8, r9, r10, r10\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r2, r12\n\t"
        "str	r3, [sp, #16]\n\t"
        "#  A[0] * A[5]\n\t"
        "ldr	r10, [%[a], #20]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "umull	r5, r6, r10, r8\n\t"
        "mov	r3, #0\n\t"
        "mov	r7, #0\n\t"
        "#  A[1] * A[4]\n\t"
        "ldr	r10, [%[a], #16]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[2] * A[3]\n\t"
        "ldr	r10, [%[a], #12]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "adds	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adc	r7, r7, r7\n\t"
        "adds	r4, r4, r5\n\t"
        "adcs	r2, r2, r6\n\t"
        "adc	r3, r3, r7\n\t"
        "str	r4, [sp, #20]\n\t"
        "#  A[0] * A[6]\n\t"
        "ldr	r10, [%[a], #24]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "umull	r5, r6, r10, r8\n\t"
        "mov	r4, #0\n\t"
        "mov	r7, #0\n\t"
        "#  A[1] * A[5]\n\t"
        "ldr	r10, [%[a], #20]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[2] * A[4]\n\t"
        "ldr	r10, [%[a], #16]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[3] * A[3]\n\t"
        "ldr	r10, [%[a], #12]\n\t"
        "umull	r8, r9, r10, r10\n\t"
        "adds	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adc	r7, r7, r7\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "adds	r2, r2, r5\n\t"
        "adcs	r3, r3, r6\n\t"
        "adc	r4, r4, r7\n\t"
        "str	r2, [sp, #24]\n\t"
        "#  A[0] * A[7]\n\t"
        "ldr	r10, [%[a], #28]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "umull	r5, r6, r10, r8\n\t"
        "mov	r2, #0\n\t"
        "mov	r7, #0\n\t"
        "#  A[1] * A[6]\n\t"
        "ldr	r10, [%[a], #24]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[2] * A[5]\n\t"
        "ldr	r10, [%[a], #20]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[3] * A[4]\n\t"
        "ldr	r10, [%[a], #16]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "adds	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adc	r7, r7, r7\n\t"
        "adds	r3, r3, r5\n\t"
        "adcs	r4, r4, r6\n\t"
        "adc	r2, r2, r7\n\t"
        "str	r3, [sp, #28]\n\t"
        "#  A[0] * A[8]\n\t"
        "ldr	r10, [%[a], #32]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "umull	r5, r6, r10, r8\n\t"
        "mov	r3, #0\n\t"
        "mov	r7, #0\n\t"
        "#  A[1] * A[7]\n\t"
        "ldr	r10, [%[a], #28]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[2] * A[6]\n\t"
        "ldr	r10, [%[a], #24]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[3] * A[5]\n\t"
        "ldr	r10, [%[a], #20]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[4] * A[4]\n\t"
        "ldr	r10, [%[a], #16]\n\t"
        "umull	r8, r9, r10, r10\n\t"
        "adds	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adc	r7, r7, r7\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "adds	r4, r4, r5\n\t"
        "adcs	r2, r2, r6\n\t"
        "adc	r3, r3, r7\n\t"
        "str	r4, [sp, #32]\n\t"
        "#  A[0] * A[9]\n\t"
        "ldr	r10, [%[a], #36]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "umull	r5, r6, r10, r8\n\t"
        "mov	r4, #0\n\t"
        "mov	r7, #0\n\t"
        "#  A[1] * A[8]\n\t"
        "ldr	r10, [%[a], #32]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[2] * A[7]\n\t"
        "ldr	r10, [%[a], #28]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[3] * A[6]\n\t"
        "ldr	r10, [%[a], #24]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[4] * A[5]\n\t"
        "ldr	r10, [%[a], #20]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "adds	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adc	r7, r7, r7\n\t"
        "adds	r2, r2, r5\n\t"
        "adcs	r3, r3, r6\n\t"
        "adc	r4, r4, r7\n\t"
        "str	r2, [sp, #36]\n\t"
        "#  A[0] * A[10]\n\t"
        "ldr	r10, [%[a], #40]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "umull	r5, r6, r10, r8\n\t"
        "mov	r2, #0\n\t"
        "mov	r7, #0\n\t"
        "#  A[1] * A[9]\n\t"
        "ldr	r10, [%[a], #36]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[2] * A[8]\n\t"
        "ldr	r10, [%[a], #32]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[3] * A[7]\n\t"
        "ldr	r10, [%[a], #28]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[4] * A[6]\n\t"
        "ldr	r10, [%[a], #24]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[5] * A[5]\n\t"
        "ldr	r10, [%[a], #20]\n\t"
        "umull	r8, r9, r10, r10\n\t"
        "adds	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adc	r7, r7, r7\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "adds	r3, r3, r5\n\t"
        "adcs	r4, r4, r6\n\t"
        "adc	r2, r2, r7\n\t"
        "str	r3, [sp, #40]\n\t"
        "#  A[0] * A[11]\n\t"
        "ldr	r10, [%[a], #44]\n\t"
        "ldr	r8, [%[a], #0]\n\t"
        "umull	r5, r6, r10, r8\n\t"
        "mov	r3, #0\n\t"
        "mov	r7, #0\n\t"
        "#  A[1] * A[10]\n\t"
        "ldr	r10, [%[a], #40]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[2] * A[9]\n\t"
        "ldr	r10, [%[a], #36]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[3] * A[8]\n\t"
        "ldr	r10, [%[a], #32]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[4] * A[7]\n\t"
        "ldr	r10, [%[a], #28]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[5] * A[6]\n\t"
        "ldr	r10, [%[a], #24]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "adds	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adc	r7, r7, r7\n\t"
        "adds	r4, r4, r5\n\t"
        "adcs	r2, r2, r6\n\t"
        "adc	r3, r3, r7\n\t"
        "str	r4, [sp, #44]\n\t"
        "#  A[1] * A[11]\n\t"
        "ldr	r10, [%[a], #44]\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r5, r6, r10, r8\n\t"
        "mov	r4, #0\n\t"
        "mov	r7, #0\n\t"
        "#  A[2] * A[10]\n\t"
        "ldr	r10, [%[a], #40]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[3] * A[9]\n\t"
        "ldr	r10, [%[a], #36]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[4] * A[8]\n\t"
        "ldr	r10, [%[a], #32]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[5] * A[7]\n\t"
        "ldr	r10, [%[a], #28]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[6] * A[6]\n\t"
        "ldr	r10, [%[a], #24]\n\t"
        "umull	r8, r9, r10, r10\n\t"
        "adds	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adc	r7, r7, r7\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "adds	r2, r2, r5\n\t"
        "adcs	r3, r3, r6\n\t"
        "adc	r4, r4, r7\n\t"
        "str	r2, [%[r], #48]\n\t"
        "#  A[2] * A[11]\n\t"
        "ldr	r10, [%[a], #44]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r5, r6, r10, r8\n\t"
        "mov	r2, #0\n\t"
        "mov	r7, #0\n\t"
        "#  A[3] * A[10]\n\t"
        "ldr	r10, [%[a], #40]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[4] * A[9]\n\t"
        "ldr	r10, [%[a], #36]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[5] * A[8]\n\t"
        "ldr	r10, [%[a], #32]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[6] * A[7]\n\t"
        "ldr	r10, [%[a], #28]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "adds	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adc	r7, r7, r7\n\t"
        "adds	r3, r3, r5\n\t"
        "adcs	r4, r4, r6\n\t"
        "adc	r2, r2, r7\n\t"
        "str	r3, [%[r], #52]\n\t"
        "#  A[3] * A[11]\n\t"
        "ldr	r10, [%[a], #44]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r5, r6, r10, r8\n\t"
        "mov	r3, #0\n\t"
        "mov	r7, #0\n\t"
        "#  A[4] * A[10]\n\t"
        "ldr	r10, [%[a], #40]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[5] * A[9]\n\t"
        "ldr	r10, [%[a], #36]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[6] * A[8]\n\t"
        "ldr	r10, [%[a], #32]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[7] * A[7]\n\t"
        "ldr	r10, [%[a], #28]\n\t"
        "umull	r8, r9, r10, r10\n\t"
        "adds	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adc	r7, r7, r7\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "adds	r4, r4, r5\n\t"
        "adcs	r2, r2, r6\n\t"
        "adc	r3, r3, r7\n\t"
        "str	r4, [%[r], #56]\n\t"
        "#  A[4] * A[11]\n\t"
        "ldr	r10, [%[a], #44]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r5, r6, r10, r8\n\t"
        "mov	r4, #0\n\t"
        "mov	r7, #0\n\t"
        "#  A[5] * A[10]\n\t"
        "ldr	r10, [%[a], #40]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[6] * A[9]\n\t"
        "ldr	r10, [%[a], #36]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[7] * A[8]\n\t"
        "ldr	r10, [%[a], #32]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "adds	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adc	r7, r7, r7\n\t"
        "adds	r2, r2, r5\n\t"
        "adcs	r3, r3, r6\n\t"
        "adc	r4, r4, r7\n\t"
        "str	r2, [%[r], #60]\n\t"
        "#  A[5] * A[11]\n\t"
        "ldr	r10, [%[a], #44]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r5, r6, r10, r8\n\t"
        "mov	r2, #0\n\t"
        "mov	r7, #0\n\t"
        "#  A[6] * A[10]\n\t"
        "ldr	r10, [%[a], #40]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[7] * A[9]\n\t"
        "ldr	r10, [%[a], #36]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[8] * A[8]\n\t"
        "ldr	r10, [%[a], #32]\n\t"
        "umull	r8, r9, r10, r10\n\t"
        "adds	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adc	r7, r7, r7\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "adds	r3, r3, r5\n\t"
        "adcs	r4, r4, r6\n\t"
        "adc	r2, r2, r7\n\t"
        "str	r3, [%[r], #64]\n\t"
        "#  A[6] * A[11]\n\t"
        "ldr	r10, [%[a], #44]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r5, r6, r10, r8\n\t"
        "mov	r3, #0\n\t"
        "mov	r7, #0\n\t"
        "#  A[7] * A[10]\n\t"
        "ldr	r10, [%[a], #40]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "#  A[8] * A[9]\n\t"
        "ldr	r10, [%[a], #36]\n\t"
        "ldr	r8, [%[a], #32]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r5, r5, r8\n\t"
        "adcs	r6, r6, r9\n\t"
        "adc	r7, r7, r12\n\t"
        "adds	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adc	r7, r7, r7\n\t"
        "adds	r4, r4, r5\n\t"
        "adcs	r2, r2, r6\n\t"
        "adc	r3, r3, r7\n\t"
        "str	r4, [%[r], #68]\n\t"
        "#  A[7] * A[11]\n\t"
        "ldr	r10, [%[a], #44]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r2, r2, r8\n\t"
        "adcs	r3, r3, r9\n\t"
        "adc	r4, r12, r12\n\t"
        "adds	r2, r2, r8\n\t"
        "adcs	r3, r3, r9\n\t"
        "adc	r4, r4, r12\n\t"
        "#  A[8] * A[10]\n\t"
        "ldr	r10, [%[a], #40]\n\t"
        "ldr	r8, [%[a], #32]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r2, r2, r8\n\t"
        "adcs	r3, r3, r9\n\t"
        "adc	r4, r4, r12\n\t"
        "adds	r2, r2, r8\n\t"
        "adcs	r3, r3, r9\n\t"
        "adc	r4, r4, r12\n\t"
        "#  A[9] * A[9]\n\t"
        "ldr	r10, [%[a], #36]\n\t"
        "umull	r8, r9, r10, r10\n\t"
        "adds	r2, r2, r8\n\t"
        "adcs	r3, r3, r9\n\t"
        "adc	r4, r4, r12\n\t"
        "str	r2, [%[r], #72]\n\t"
        "#  A[8] * A[11]\n\t"
        "ldr	r10, [%[a], #44]\n\t"
        "ldr	r8, [%[a], #32]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r12, r12\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r2, r12\n\t"
        "#  A[9] * A[10]\n\t"
        "ldr	r10, [%[a], #40]\n\t"
        "ldr	r8, [%[a], #36]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r2, r12\n\t"
        "adds	r3, r3, r8\n\t"
        "adcs	r4, r4, r9\n\t"
        "adc	r2, r2, r12\n\t"
        "str	r3, [%[r], #76]\n\t"
        "#  A[9] * A[11]\n\t"
        "ldr	r10, [%[a], #44]\n\t"
        "ldr	r8, [%[a], #36]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r4, r4, r8\n\t"
        "adcs	r2, r2, r9\n\t"
        "adc	r3, r12, r12\n\t"
        "adds	r4, r4, r8\n\t"
        "adcs	r2, r2, r9\n\t"
        "adc	r3, r3, r12\n\t"
        "#  A[10] * A[10]\n\t"
        "ldr	r10, [%[a], #40]\n\t"
        "umull	r8, r9, r10, r10\n\t"
        "adds	r4, r4, r8\n\t"
        "adcs	r2, r2, r9\n\t"
        "adc	r3, r3, r12\n\t"
        "str	r4, [%[r], #80]\n\t"
        "#  A[10] * A[11]\n\t"
        "ldr	r10, [%[a], #44]\n\t"
        "ldr	r8, [%[a], #40]\n\t"
        "umull	r8, r9, r10, r8\n\t"
        "adds	r2, r2, r8\n\t"
        "adcs	r3, r3, r9\n\t"
        "adc	r4, r12, r12\n\t"
        "adds	r2, r2, r8\n\t"
        "adcs	r3, r3, r9\n\t"
        "adc	r4, r4, r12\n\t"
        "str	r2, [%[r], #84]\n\t"
        "#  A[11] * A[11]\n\t"
        "ldr	r10, [%[a], #44]\n\t"
        "umull	r8, r9, r10, r10\n\t"
        "adds	r3, r3, r8\n\t"
        "adc	r4, r4, r9\n\t"
        "str	r3, [%[r], #88]\n\t"
        "str	r4, [%[r], #92]\n\t"
        "ldm	sp!, {r2, r3, r4, r8}\n\t"
        "stm	%[r]!, {r2, r3, r4, r8}\n\t"
        "ldm	sp!, {r2, r3, r4, r8}\n\t"
        "stm	%[r]!, {r2, r3, r4, r8}\n\t"
        "ldm	sp!, {r2, r3, r4, r8}\n\t"
        "stm	%[r]!, {r2, r3, r4, r8}\n\t"
        "sub	%[r], %[r], #48\n\t"
        :
        : [r] "r" (r), [a] "r" (a)
        : "memory", "r2", "r3", "r4", "r8", "r9", "r10", "r8", "r5", "r6", "r7", "r12"
    );
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_3072_sub_12(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldrd	r3, r4, [%[a], #0]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b], #0]\n\t"
        "ldrd	r9, r10, [%[b], #8]\n\t"
        "subs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #0]\n\t"
        "strd	r5, r6, [%[r], #8]\n\t"
        "ldrd	r3, r4, [%[a], #16]\n\t"
        "ldrd	r5, r6, [%[a], #24]\n\t"
        "ldrd	r7, r8, [%[b], #16]\n\t"
        "ldrd	r9, r10, [%[b], #24]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #16]\n\t"
        "strd	r5, r6, [%[r], #24]\n\t"
        "ldrd	r3, r4, [%[a], #32]\n\t"
        "ldrd	r5, r6, [%[a], #40]\n\t"
        "ldrd	r7, r8, [%[b], #32]\n\t"
        "ldrd	r9, r10, [%[b], #40]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #32]\n\t"
        "strd	r5, r6, [%[r], #40]\n\t"
        "sbc	%[c], %[c], #0\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
    );

    return c;
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_24(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit* z2 = r + 24;
    sp_digit z1[24];
    sp_digit* a1 = z1;
    sp_digit zero[12];
    sp_digit u;
    sp_digit mask;
    sp_digit* p1;
    sp_digit* p2;

    XMEMSET(zero, 0, sizeof(sp_digit) * 12);

    mask = sp_3072_sub_12(a1, a, &a[12]);
    p1 = (sp_digit*)(((sp_digit)zero &   mask ) | ((sp_digit)a1 & (~mask)));
    p2 = (sp_digit*)(((sp_digit)zero & (~mask)) | ((sp_digit)a1 &   mask ));
    (void)sp_3072_sub_12(a1, p1, p2);

    sp_3072_sqr_12(z2, &a[12]);
    sp_3072_sqr_12(z0, a);
    sp_3072_sqr_12(z1, a1);

    u = 0;
    u -= sp_3072_sub_in_place_24(z1, z2);
    u -= sp_3072_sub_in_place_24(z1, z0);
    u += sp_3072_sub_in_place_24(r + 12, z1);
    zero[0] = u;
    (void)sp_3072_add_12(r + 36, r + 36, zero);
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
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldrd	r3, r4, [%[a], #0]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b], #0]\n\t"
        "ldrd	r9, r10, [%[b], #8]\n\t"
        "subs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #0]\n\t"
        "strd	r5, r6, [%[r], #8]\n\t"
        "ldrd	r3, r4, [%[a], #16]\n\t"
        "ldrd	r5, r6, [%[a], #24]\n\t"
        "ldrd	r7, r8, [%[b], #16]\n\t"
        "ldrd	r9, r10, [%[b], #24]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #16]\n\t"
        "strd	r5, r6, [%[r], #24]\n\t"
        "ldrd	r3, r4, [%[a], #32]\n\t"
        "ldrd	r5, r6, [%[a], #40]\n\t"
        "ldrd	r7, r8, [%[b], #32]\n\t"
        "ldrd	r9, r10, [%[b], #40]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #32]\n\t"
        "strd	r5, r6, [%[r], #40]\n\t"
        "ldrd	r3, r4, [%[a], #48]\n\t"
        "ldrd	r5, r6, [%[a], #56]\n\t"
        "ldrd	r7, r8, [%[b], #48]\n\t"
        "ldrd	r9, r10, [%[b], #56]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #48]\n\t"
        "strd	r5, r6, [%[r], #56]\n\t"
        "ldrd	r3, r4, [%[a], #64]\n\t"
        "ldrd	r5, r6, [%[a], #72]\n\t"
        "ldrd	r7, r8, [%[b], #64]\n\t"
        "ldrd	r9, r10, [%[b], #72]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #64]\n\t"
        "strd	r5, r6, [%[r], #72]\n\t"
        "ldrd	r3, r4, [%[a], #80]\n\t"
        "ldrd	r5, r6, [%[a], #88]\n\t"
        "ldrd	r7, r8, [%[b], #80]\n\t"
        "ldrd	r9, r10, [%[b], #88]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #80]\n\t"
        "strd	r5, r6, [%[r], #88]\n\t"
        "sbc	%[c], %[c], #0\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
    );

    return c;
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
    sp_digit zero[24];
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
    zero[0] = u;
    (void)sp_3072_add_24(r + 72, r + 72, zero);
}

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
        "ldrd	r3, r4, [%[a], #0]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b], #0]\n\t"
        "ldrd	r9, r10, [%[b], #8]\n\t"
        "subs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #0]\n\t"
        "strd	r5, r6, [%[r], #8]\n\t"
        "ldrd	r3, r4, [%[a], #16]\n\t"
        "ldrd	r5, r6, [%[a], #24]\n\t"
        "ldrd	r7, r8, [%[b], #16]\n\t"
        "ldrd	r9, r10, [%[b], #24]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #16]\n\t"
        "strd	r5, r6, [%[r], #24]\n\t"
        "ldrd	r3, r4, [%[a], #32]\n\t"
        "ldrd	r5, r6, [%[a], #40]\n\t"
        "ldrd	r7, r8, [%[b], #32]\n\t"
        "ldrd	r9, r10, [%[b], #40]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #32]\n\t"
        "strd	r5, r6, [%[r], #40]\n\t"
        "ldrd	r3, r4, [%[a], #48]\n\t"
        "ldrd	r5, r6, [%[a], #56]\n\t"
        "ldrd	r7, r8, [%[b], #48]\n\t"
        "ldrd	r9, r10, [%[b], #56]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #48]\n\t"
        "strd	r5, r6, [%[r], #56]\n\t"
        "ldrd	r3, r4, [%[a], #64]\n\t"
        "ldrd	r5, r6, [%[a], #72]\n\t"
        "ldrd	r7, r8, [%[b], #64]\n\t"
        "ldrd	r9, r10, [%[b], #72]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #64]\n\t"
        "strd	r5, r6, [%[r], #72]\n\t"
        "ldrd	r3, r4, [%[a], #80]\n\t"
        "ldrd	r5, r6, [%[a], #88]\n\t"
        "ldrd	r7, r8, [%[b], #80]\n\t"
        "ldrd	r9, r10, [%[b], #88]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #80]\n\t"
        "strd	r5, r6, [%[r], #88]\n\t"
        "ldrd	r3, r4, [%[a], #96]\n\t"
        "ldrd	r5, r6, [%[a], #104]\n\t"
        "ldrd	r7, r8, [%[b], #96]\n\t"
        "ldrd	r9, r10, [%[b], #104]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #96]\n\t"
        "strd	r5, r6, [%[r], #104]\n\t"
        "ldrd	r3, r4, [%[a], #112]\n\t"
        "ldrd	r5, r6, [%[a], #120]\n\t"
        "ldrd	r7, r8, [%[b], #112]\n\t"
        "ldrd	r9, r10, [%[b], #120]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #112]\n\t"
        "strd	r5, r6, [%[r], #120]\n\t"
        "ldrd	r3, r4, [%[a], #128]\n\t"
        "ldrd	r5, r6, [%[a], #136]\n\t"
        "ldrd	r7, r8, [%[b], #128]\n\t"
        "ldrd	r9, r10, [%[b], #136]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #128]\n\t"
        "strd	r5, r6, [%[r], #136]\n\t"
        "ldrd	r3, r4, [%[a], #144]\n\t"
        "ldrd	r5, r6, [%[a], #152]\n\t"
        "ldrd	r7, r8, [%[b], #144]\n\t"
        "ldrd	r9, r10, [%[b], #152]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #144]\n\t"
        "strd	r5, r6, [%[r], #152]\n\t"
        "ldrd	r3, r4, [%[a], #160]\n\t"
        "ldrd	r5, r6, [%[a], #168]\n\t"
        "ldrd	r7, r8, [%[b], #160]\n\t"
        "ldrd	r9, r10, [%[b], #168]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #160]\n\t"
        "strd	r5, r6, [%[r], #168]\n\t"
        "ldrd	r3, r4, [%[a], #176]\n\t"
        "ldrd	r5, r6, [%[a], #184]\n\t"
        "ldrd	r7, r8, [%[b], #176]\n\t"
        "ldrd	r9, r10, [%[b], #184]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #176]\n\t"
        "strd	r5, r6, [%[r], #184]\n\t"
        "sbc	%[c], %[c], #0\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
    );

    return c;
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_96(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit* z2 = r + 96;
    sp_digit z1[96];
    sp_digit* a1 = z1;
    sp_digit zero[48];
    sp_digit u;
    sp_digit mask;
    sp_digit* p1;
    sp_digit* p2;

    XMEMSET(zero, 0, sizeof(sp_digit) * 48);

    mask = sp_3072_sub_48(a1, a, &a[48]);
    p1 = (sp_digit*)(((sp_digit)zero &   mask ) | ((sp_digit)a1 & (~mask)));
    p2 = (sp_digit*)(((sp_digit)zero & (~mask)) | ((sp_digit)a1 &   mask ));
    (void)sp_3072_sub_48(a1, p1, p2);

    sp_3072_sqr_48(z2, &a[48]);
    sp_3072_sqr_48(z0, a);
    sp_3072_sqr_48(z1, a1);

    u = 0;
    u -= sp_3072_sub_in_place_96(z1, z2);
    u -= sp_3072_sub_in_place_96(z1, z0);
    u += sp_3072_sub_in_place_96(r + 48, z1);
    zero[0] = u;
    (void)sp_3072_add_48(r + 144, r + 144, zero);
}

#endif /* !WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_3072_add_96(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "add	r14, %[a], #384\n\t"
        "\n1:\n\t"
        "adds	%[c], %[c], #-1\n\t"
        "ldrd	r3, r4, [%[a]], #8\n\t"
        "ldrd	r5, r6, [%[a]], #8\n\t"
        "ldrd	r7, r8, [%[b]], #8\n\t"
        "ldrd	r9, r10, [%[b]], #8\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r]], #8\n\t"
        "strd	r5, r6, [%[r]], #8\n\t"
        "mov	r3, #0\n\t"
        "adc	%[c], r3, #0\n\t"
        "cmp	%[a], r14\n\t"
        "bne	1b\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14"
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
static sp_digit sp_3072_sub_in_place_96(sp_digit* a, const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r14, #0\n\t"
        "add	r12, %[a], #384\n\t"
        "\n1:\n\t"
        "subs	%[c], r14, %[c]\n\t"
        "ldrd	r3, r4, [%[a]]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b]], #8\n\t"
        "ldrd	r9, r10, [%[b]], #8\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[a]], #8\n\t"
        "strd	r5, r6, [%[a]], #8\n\t"
        "sbc	%[c], r14, r14\n\t"
        "cmp	%[a], r12\n\t"
        "bne	1b\n\t"
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r12", "r14"
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
static void sp_3072_mul_96(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    __asm__ __volatile__ (
        "sub	sp, sp, #768\n\t"
        "mov	r5, #0\n\t"
        "mov	r6, #0\n\t"
        "mov	r7, #0\n\t"
        "mov	r8, #0\n\t"
        "\n1:\n\t"
        "subs	r3, r5, #380\n\t"
        "it	cc\n\t"
        "movcc	r3, #0\n\t"
        "sub	r4, r5, r3\n\t"
        "\n2:\n\t"
        "ldr	r14, [%[a], r3]\n\t"
        "ldr	r12, [%[b], r4]\n\t"
        "umull	r9, r10, r14, r12\n\t"
        "adds	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "adc	r8, r8, #0\n\t"
        "add	r3, r3, #4\n\t"
        "sub	r4, r4, #4\n\t"
        "cmp	r3, #384\n\t"
        "beq	3f\n\t"
        "cmp	r3, r5\n\t"
        "ble	2b\n\t"
        "\n3:\n\t"
        "str	r6, [sp, r5]\n\t"
        "mov	r6, r7\n\t"
        "mov	r7, r8\n\t"
        "mov	r8, #0\n\t"
        "add	r5, r5, #4\n\t"
        "cmp	r5, #760\n\t"
        "ble	1b\n\t"
        "str	r6, [sp, r5]\n\t"
        "\n4:\n\t"
        "ldr	r6, [sp, #0]\n\t"
        "ldr	r7, [sp, #4]\n\t"
        "ldr	r8, [sp, #8]\n\t"
        "ldr	r3, [sp, #12]\n\t"
        "str	r6, [%[r], #0]\n\t"
        "str	r7, [%[r], #4]\n\t"
        "str	r8, [%[r], #8]\n\t"
        "str	r3, [%[r], #12]\n\t"
        "add	sp, sp, #16\n\t"
        "add	%[r], %[r], #16\n\t"
        "subs	r5, r5, #16\n\t"
        "bgt	4b\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14", "r12"
    );
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
static void sp_3072_sqr_96(sp_digit* r, const sp_digit* a)
{
    __asm__ __volatile__ (
        "sub	sp, sp, #768\n\t"
        "mov	r12, #0\n\t"
        "mov	r6, #0\n\t"
        "mov	r7, #0\n\t"
        "mov	r8, #0\n\t"
        "mov	r5, #0\n\t"
        "\n1:\n\t"
        "subs	r3, r5, #380\n\t"
        "it	cc\n\t"
        "movcc	r3, r12\n\t"
        "sub	r4, r5, r3\n\t"
        "\n2:\n\t"
        "cmp	r4, r3\n\t"
        "beq	4f\n\t"
        "ldr	r14, [%[a], r3]\n\t"
        "ldr	r9, [%[a], r4]\n\t"
        "umull	r9, r10, r14, r9\n\t"
        "adds	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "adc	r8, r8, r12\n\t"
        "adds	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "adc	r8, r8, r12\n\t"
        "bal	5f\n\t"
        "\n4:\n\t"
        "ldr	r14, [%[a], r3]\n\t"
        "umull	r9, r10, r14, r14\n\t"
        "adds	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "adc	r8, r8, r12\n\t"
        "\n5:\n\t"
        "add	r3, r3, #4\n\t"
        "sub	r4, r4, #4\n\t"
        "cmp	r3, #384\n\t"
        "beq	3f\n\t"
        "cmp	r3, r4\n\t"
        "bgt	3f\n\t"
        "cmp	r3, r5\n\t"
        "ble	2b\n\t"
        "\n3:\n\t"
        "str	r6, [sp, r5]\n\t"
        "mov	r6, r7\n\t"
        "mov	r7, r8\n\t"
        "mov	r8, #0\n\t"
        "add	r5, r5, #4\n\t"
        "cmp	r5, #760\n\t"
        "ble	1b\n\t"
        "str	r6, [sp, r5]\n\t"
        "\n4:\n\t"
        "ldrd	r6, r7, [sp, #0]\n\t"
        "ldrd	r8, r9, [sp, #8]\n\t"
        "strd	r6, r7, [%[r], #0]\n\t"
        "strd	r8, r9, [%[r], #8]\n\t"
        "add	sp, sp, #16\n\t"
        "add	%[r], %[r], #16\n\t"
        "subs	r5, r5, #16\n\t"
        "bgt	4b\n\t"
        : [r] "+r" (r)
        : [a] "r" (a)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14", "r9", "r12"
    );
}

#endif /* WOLFSSL_SP_SMALL */
#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
#ifdef WOLFSSL_SP_SMALL
/* AND m into each word of a and store in r.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * m  Mask to AND against each digit.
 */
static void sp_3072_mask_48(sp_digit* r, const sp_digit* a, sp_digit m)
{
    int i;

    for (i=0; i<48; i++) {
        r[i] = a[i] & m;
    }
}

#endif /* WOLFSSL_SP_SMALL */
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
        "add	r14, %[a], #192\n\t"
        "\n1:\n\t"
        "adds	%[c], %[c], #-1\n\t"
        "ldrd	r3, r4, [%[a]], #8\n\t"
        "ldrd	r5, r6, [%[a]], #8\n\t"
        "ldrd	r7, r8, [%[b]], #8\n\t"
        "ldrd	r9, r10, [%[b]], #8\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r]], #8\n\t"
        "strd	r5, r6, [%[r]], #8\n\t"
        "mov	r3, #0\n\t"
        "adc	%[c], r3, #0\n\t"
        "cmp	%[a], r14\n\t"
        "bne	1b\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14"
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
        "mov	r14, #0\n\t"
        "add	r12, %[a], #192\n\t"
        "\n1:\n\t"
        "subs	%[c], r14, %[c]\n\t"
        "ldrd	r3, r4, [%[a]]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b]], #8\n\t"
        "ldrd	r9, r10, [%[b]], #8\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[a]], #8\n\t"
        "strd	r5, r6, [%[a]], #8\n\t"
        "sbc	%[c], r14, r14\n\t"
        "cmp	%[a], r12\n\t"
        "bne	1b\n\t"
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r12", "r14"
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
    __asm__ __volatile__ (
        "sub	sp, sp, #384\n\t"
        "mov	r5, #0\n\t"
        "mov	r6, #0\n\t"
        "mov	r7, #0\n\t"
        "mov	r8, #0\n\t"
        "\n1:\n\t"
        "subs	r3, r5, #188\n\t"
        "it	cc\n\t"
        "movcc	r3, #0\n\t"
        "sub	r4, r5, r3\n\t"
        "\n2:\n\t"
        "ldr	r14, [%[a], r3]\n\t"
        "ldr	r12, [%[b], r4]\n\t"
        "umull	r9, r10, r14, r12\n\t"
        "adds	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "adc	r8, r8, #0\n\t"
        "add	r3, r3, #4\n\t"
        "sub	r4, r4, #4\n\t"
        "cmp	r3, #192\n\t"
        "beq	3f\n\t"
        "cmp	r3, r5\n\t"
        "ble	2b\n\t"
        "\n3:\n\t"
        "str	r6, [sp, r5]\n\t"
        "mov	r6, r7\n\t"
        "mov	r7, r8\n\t"
        "mov	r8, #0\n\t"
        "add	r5, r5, #4\n\t"
        "cmp	r5, #376\n\t"
        "ble	1b\n\t"
        "str	r6, [sp, r5]\n\t"
        "\n4:\n\t"
        "ldr	r6, [sp, #0]\n\t"
        "ldr	r7, [sp, #4]\n\t"
        "ldr	r8, [sp, #8]\n\t"
        "ldr	r3, [sp, #12]\n\t"
        "str	r6, [%[r], #0]\n\t"
        "str	r7, [%[r], #4]\n\t"
        "str	r8, [%[r], #8]\n\t"
        "str	r3, [%[r], #12]\n\t"
        "add	sp, sp, #16\n\t"
        "add	%[r], %[r], #16\n\t"
        "subs	r5, r5, #16\n\t"
        "bgt	4b\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14", "r12"
    );
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
static void sp_3072_sqr_48(sp_digit* r, const sp_digit* a)
{
    __asm__ __volatile__ (
        "sub	sp, sp, #384\n\t"
        "mov	r12, #0\n\t"
        "mov	r6, #0\n\t"
        "mov	r7, #0\n\t"
        "mov	r8, #0\n\t"
        "mov	r5, #0\n\t"
        "\n1:\n\t"
        "subs	r3, r5, #188\n\t"
        "it	cc\n\t"
        "movcc	r3, r12\n\t"
        "sub	r4, r5, r3\n\t"
        "\n2:\n\t"
        "cmp	r4, r3\n\t"
        "beq	4f\n\t"
        "ldr	r14, [%[a], r3]\n\t"
        "ldr	r9, [%[a], r4]\n\t"
        "umull	r9, r10, r14, r9\n\t"
        "adds	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "adc	r8, r8, r12\n\t"
        "adds	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "adc	r8, r8, r12\n\t"
        "bal	5f\n\t"
        "\n4:\n\t"
        "ldr	r14, [%[a], r3]\n\t"
        "umull	r9, r10, r14, r14\n\t"
        "adds	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "adc	r8, r8, r12\n\t"
        "\n5:\n\t"
        "add	r3, r3, #4\n\t"
        "sub	r4, r4, #4\n\t"
        "cmp	r3, #192\n\t"
        "beq	3f\n\t"
        "cmp	r3, r4\n\t"
        "bgt	3f\n\t"
        "cmp	r3, r5\n\t"
        "ble	2b\n\t"
        "\n3:\n\t"
        "str	r6, [sp, r5]\n\t"
        "mov	r6, r7\n\t"
        "mov	r7, r8\n\t"
        "mov	r8, #0\n\t"
        "add	r5, r5, #4\n\t"
        "cmp	r5, #376\n\t"
        "ble	1b\n\t"
        "str	r6, [sp, r5]\n\t"
        "\n4:\n\t"
        "ldrd	r6, r7, [sp, #0]\n\t"
        "ldrd	r8, r9, [sp, #8]\n\t"
        "strd	r6, r7, [%[r], #0]\n\t"
        "strd	r8, r9, [%[r], #8]\n\t"
        "add	sp, sp, #16\n\t"
        "add	%[r], %[r], #16\n\t"
        "subs	r5, r5, #16\n\t"
        "bgt	4b\n\t"
        : [r] "+r" (r)
        : [a] "r" (a)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14", "r9", "r12"
    );
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

    /* rho = -1/m mod b */
    *rho = (sp_digit)0 - x;
}

/* Mul a by digit b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision digit.
 */
static void sp_3072_mul_d_96(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "mov	r10, #0\n\t"
        "# A[0] * B\n\t"
        "ldr	r8, [%[a]]\n\t"
        "umull	r5, r3, %[b], r8\n\t"
        "mov	r4, #0\n\t"
        "str	r5, [%[r]]\n\t"
        "mov	r5, #0\n\t"
        "mov	r9, #4\n\t"
        "1:\n\t"
        "ldr	r8, [%[a], r9]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "str	r3, [%[r], r9]\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "mov	r5, #0\n\t"
        "add	r9, r9, #4\n\t"
        "cmp	r9, #384\n\t"
        "blt	1b\n\t"
        "str	r3, [%[r], #384]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
    );
#else
    __asm__ __volatile__ (
        "mov	r10, #0\n\t"
        "# A[0] * B\n\t"
        "ldr	r8, [%[a]]\n\t"
        "umull	r3, r4, %[b], r8\n\t"
        "mov	r5, #0\n\t"
        "str	r3, [%[r]]\n\t"
        "# A[1] * B\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #4]\n\t"
        "# A[2] * B\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #8]\n\t"
        "# A[3] * B\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #12]\n\t"
        "# A[4] * B\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #16]\n\t"
        "# A[5] * B\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #20]\n\t"
        "# A[6] * B\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #24]\n\t"
        "# A[7] * B\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #28]\n\t"
        "# A[8] * B\n\t"
        "ldr	r8, [%[a], #32]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #32]\n\t"
        "# A[9] * B\n\t"
        "ldr	r8, [%[a], #36]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #36]\n\t"
        "# A[10] * B\n\t"
        "ldr	r8, [%[a], #40]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #40]\n\t"
        "# A[11] * B\n\t"
        "ldr	r8, [%[a], #44]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #44]\n\t"
        "# A[12] * B\n\t"
        "ldr	r8, [%[a], #48]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #48]\n\t"
        "# A[13] * B\n\t"
        "ldr	r8, [%[a], #52]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #52]\n\t"
        "# A[14] * B\n\t"
        "ldr	r8, [%[a], #56]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #56]\n\t"
        "# A[15] * B\n\t"
        "ldr	r8, [%[a], #60]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #60]\n\t"
        "# A[16] * B\n\t"
        "ldr	r8, [%[a], #64]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #64]\n\t"
        "# A[17] * B\n\t"
        "ldr	r8, [%[a], #68]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #68]\n\t"
        "# A[18] * B\n\t"
        "ldr	r8, [%[a], #72]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #72]\n\t"
        "# A[19] * B\n\t"
        "ldr	r8, [%[a], #76]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #76]\n\t"
        "# A[20] * B\n\t"
        "ldr	r8, [%[a], #80]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #80]\n\t"
        "# A[21] * B\n\t"
        "ldr	r8, [%[a], #84]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #84]\n\t"
        "# A[22] * B\n\t"
        "ldr	r8, [%[a], #88]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #88]\n\t"
        "# A[23] * B\n\t"
        "ldr	r8, [%[a], #92]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #92]\n\t"
        "# A[24] * B\n\t"
        "ldr	r8, [%[a], #96]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #96]\n\t"
        "# A[25] * B\n\t"
        "ldr	r8, [%[a], #100]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #100]\n\t"
        "# A[26] * B\n\t"
        "ldr	r8, [%[a], #104]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #104]\n\t"
        "# A[27] * B\n\t"
        "ldr	r8, [%[a], #108]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #108]\n\t"
        "# A[28] * B\n\t"
        "ldr	r8, [%[a], #112]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #112]\n\t"
        "# A[29] * B\n\t"
        "ldr	r8, [%[a], #116]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #116]\n\t"
        "# A[30] * B\n\t"
        "ldr	r8, [%[a], #120]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #120]\n\t"
        "# A[31] * B\n\t"
        "ldr	r8, [%[a], #124]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #124]\n\t"
        "# A[32] * B\n\t"
        "ldr	r8, [%[a], #128]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #128]\n\t"
        "# A[33] * B\n\t"
        "ldr	r8, [%[a], #132]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #132]\n\t"
        "# A[34] * B\n\t"
        "ldr	r8, [%[a], #136]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #136]\n\t"
        "# A[35] * B\n\t"
        "ldr	r8, [%[a], #140]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #140]\n\t"
        "# A[36] * B\n\t"
        "ldr	r8, [%[a], #144]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #144]\n\t"
        "# A[37] * B\n\t"
        "ldr	r8, [%[a], #148]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #148]\n\t"
        "# A[38] * B\n\t"
        "ldr	r8, [%[a], #152]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #152]\n\t"
        "# A[39] * B\n\t"
        "ldr	r8, [%[a], #156]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #156]\n\t"
        "# A[40] * B\n\t"
        "ldr	r8, [%[a], #160]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #160]\n\t"
        "# A[41] * B\n\t"
        "ldr	r8, [%[a], #164]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #164]\n\t"
        "# A[42] * B\n\t"
        "ldr	r8, [%[a], #168]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #168]\n\t"
        "# A[43] * B\n\t"
        "ldr	r8, [%[a], #172]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #172]\n\t"
        "# A[44] * B\n\t"
        "ldr	r8, [%[a], #176]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #176]\n\t"
        "# A[45] * B\n\t"
        "ldr	r8, [%[a], #180]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #180]\n\t"
        "# A[46] * B\n\t"
        "ldr	r8, [%[a], #184]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #184]\n\t"
        "# A[47] * B\n\t"
        "ldr	r8, [%[a], #188]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #188]\n\t"
        "# A[48] * B\n\t"
        "ldr	r8, [%[a], #192]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #192]\n\t"
        "# A[49] * B\n\t"
        "ldr	r8, [%[a], #196]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #196]\n\t"
        "# A[50] * B\n\t"
        "ldr	r8, [%[a], #200]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #200]\n\t"
        "# A[51] * B\n\t"
        "ldr	r8, [%[a], #204]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #204]\n\t"
        "# A[52] * B\n\t"
        "ldr	r8, [%[a], #208]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #208]\n\t"
        "# A[53] * B\n\t"
        "ldr	r8, [%[a], #212]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #212]\n\t"
        "# A[54] * B\n\t"
        "ldr	r8, [%[a], #216]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #216]\n\t"
        "# A[55] * B\n\t"
        "ldr	r8, [%[a], #220]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #220]\n\t"
        "# A[56] * B\n\t"
        "ldr	r8, [%[a], #224]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #224]\n\t"
        "# A[57] * B\n\t"
        "ldr	r8, [%[a], #228]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #228]\n\t"
        "# A[58] * B\n\t"
        "ldr	r8, [%[a], #232]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #232]\n\t"
        "# A[59] * B\n\t"
        "ldr	r8, [%[a], #236]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #236]\n\t"
        "# A[60] * B\n\t"
        "ldr	r8, [%[a], #240]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #240]\n\t"
        "# A[61] * B\n\t"
        "ldr	r8, [%[a], #244]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #244]\n\t"
        "# A[62] * B\n\t"
        "ldr	r8, [%[a], #248]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #248]\n\t"
        "# A[63] * B\n\t"
        "ldr	r8, [%[a], #252]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #252]\n\t"
        "# A[64] * B\n\t"
        "ldr	r8, [%[a], #256]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #256]\n\t"
        "# A[65] * B\n\t"
        "ldr	r8, [%[a], #260]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #260]\n\t"
        "# A[66] * B\n\t"
        "ldr	r8, [%[a], #264]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #264]\n\t"
        "# A[67] * B\n\t"
        "ldr	r8, [%[a], #268]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #268]\n\t"
        "# A[68] * B\n\t"
        "ldr	r8, [%[a], #272]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #272]\n\t"
        "# A[69] * B\n\t"
        "ldr	r8, [%[a], #276]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #276]\n\t"
        "# A[70] * B\n\t"
        "ldr	r8, [%[a], #280]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #280]\n\t"
        "# A[71] * B\n\t"
        "ldr	r8, [%[a], #284]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #284]\n\t"
        "# A[72] * B\n\t"
        "ldr	r8, [%[a], #288]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #288]\n\t"
        "# A[73] * B\n\t"
        "ldr	r8, [%[a], #292]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #292]\n\t"
        "# A[74] * B\n\t"
        "ldr	r8, [%[a], #296]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #296]\n\t"
        "# A[75] * B\n\t"
        "ldr	r8, [%[a], #300]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #300]\n\t"
        "# A[76] * B\n\t"
        "ldr	r8, [%[a], #304]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #304]\n\t"
        "# A[77] * B\n\t"
        "ldr	r8, [%[a], #308]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #308]\n\t"
        "# A[78] * B\n\t"
        "ldr	r8, [%[a], #312]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #312]\n\t"
        "# A[79] * B\n\t"
        "ldr	r8, [%[a], #316]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #316]\n\t"
        "# A[80] * B\n\t"
        "ldr	r8, [%[a], #320]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #320]\n\t"
        "# A[81] * B\n\t"
        "ldr	r8, [%[a], #324]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #324]\n\t"
        "# A[82] * B\n\t"
        "ldr	r8, [%[a], #328]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #328]\n\t"
        "# A[83] * B\n\t"
        "ldr	r8, [%[a], #332]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #332]\n\t"
        "# A[84] * B\n\t"
        "ldr	r8, [%[a], #336]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #336]\n\t"
        "# A[85] * B\n\t"
        "ldr	r8, [%[a], #340]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #340]\n\t"
        "# A[86] * B\n\t"
        "ldr	r8, [%[a], #344]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #344]\n\t"
        "# A[87] * B\n\t"
        "ldr	r8, [%[a], #348]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #348]\n\t"
        "# A[88] * B\n\t"
        "ldr	r8, [%[a], #352]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #352]\n\t"
        "# A[89] * B\n\t"
        "ldr	r8, [%[a], #356]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #356]\n\t"
        "# A[90] * B\n\t"
        "ldr	r8, [%[a], #360]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #360]\n\t"
        "# A[91] * B\n\t"
        "ldr	r8, [%[a], #364]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #364]\n\t"
        "# A[92] * B\n\t"
        "ldr	r8, [%[a], #368]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #368]\n\t"
        "# A[93] * B\n\t"
        "ldr	r8, [%[a], #372]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #372]\n\t"
        "# A[94] * B\n\t"
        "ldr	r8, [%[a], #376]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #376]\n\t"
        "# A[95] * B\n\t"
        "ldr	r8, [%[a], #380]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adc	r3, r3, r7\n\t"
        "str	r5, [%[r], #380]\n\t"
        "str	r3, [%[r], #384]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
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
static void sp_3072_mont_norm_48(sp_digit* r, const sp_digit* m)
{
    XMEMSET(r, 0, sizeof(sp_digit) * 48);

    /* r = 2^n mod m */
    sp_3072_sub_in_place_48(r, m);
}

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
    sp_digit c = 0;

#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "mov	r9, #0\n\t"
        "mov	r8, #0\n\t"
        "1:\n\t"
        "subs	%[c], r9, %[c]\n\t"
        "ldr	r4, [%[a], r8]\n\t"
        "ldr	r6, [%[b], r8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbc	%[c], r9, r9\n\t"
        "str	r4, [%[r], r8]\n\t"
        "add	r8, r8, #4\n\t"
        "cmp	r8, #192\n\t"
        "blt	1b\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9"
    );
#else
    __asm__ __volatile__ (

        "mov	r9, #0\n\t"
        "ldrd	r4, r5, [%[a], #0]\n\t"
        "ldrd	r6, r7, [%[b], #0]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "subs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #0]\n\t"
        "ldrd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r6, r7, [%[b], #8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #8]\n\t"
        "ldrd	r4, r5, [%[a], #16]\n\t"
        "ldrd	r6, r7, [%[b], #16]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #16]\n\t"
        "ldrd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r6, r7, [%[b], #24]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #24]\n\t"
        "ldrd	r4, r5, [%[a], #32]\n\t"
        "ldrd	r6, r7, [%[b], #32]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #32]\n\t"
        "ldrd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r6, r7, [%[b], #40]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #40]\n\t"
        "ldrd	r4, r5, [%[a], #48]\n\t"
        "ldrd	r6, r7, [%[b], #48]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #48]\n\t"
        "ldrd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r6, r7, [%[b], #56]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #56]\n\t"
        "ldrd	r4, r5, [%[a], #64]\n\t"
        "ldrd	r6, r7, [%[b], #64]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #64]\n\t"
        "ldrd	r4, r5, [%[a], #72]\n\t"
        "ldrd	r6, r7, [%[b], #72]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #72]\n\t"
        "ldrd	r4, r5, [%[a], #80]\n\t"
        "ldrd	r6, r7, [%[b], #80]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #80]\n\t"
        "ldrd	r4, r5, [%[a], #88]\n\t"
        "ldrd	r6, r7, [%[b], #88]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #88]\n\t"
        "ldrd	r4, r5, [%[a], #96]\n\t"
        "ldrd	r6, r7, [%[b], #96]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #96]\n\t"
        "ldrd	r4, r5, [%[a], #104]\n\t"
        "ldrd	r6, r7, [%[b], #104]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #104]\n\t"
        "ldrd	r4, r5, [%[a], #112]\n\t"
        "ldrd	r6, r7, [%[b], #112]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #112]\n\t"
        "ldrd	r4, r5, [%[a], #120]\n\t"
        "ldrd	r6, r7, [%[b], #120]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #120]\n\t"
        "ldrd	r4, r5, [%[a], #128]\n\t"
        "ldrd	r6, r7, [%[b], #128]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #128]\n\t"
        "ldrd	r4, r5, [%[a], #136]\n\t"
        "ldrd	r6, r7, [%[b], #136]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #136]\n\t"
        "ldrd	r4, r5, [%[a], #144]\n\t"
        "ldrd	r6, r7, [%[b], #144]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #144]\n\t"
        "ldrd	r4, r5, [%[a], #152]\n\t"
        "ldrd	r6, r7, [%[b], #152]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #152]\n\t"
        "ldrd	r4, r5, [%[a], #160]\n\t"
        "ldrd	r6, r7, [%[b], #160]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #160]\n\t"
        "ldrd	r4, r5, [%[a], #168]\n\t"
        "ldrd	r6, r7, [%[b], #168]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #168]\n\t"
        "ldrd	r4, r5, [%[a], #176]\n\t"
        "ldrd	r6, r7, [%[b], #176]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #176]\n\t"
        "ldrd	r4, r5, [%[a], #184]\n\t"
        "ldrd	r6, r7, [%[b], #184]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #184]\n\t"
        "sbc	%[c], r9, r9\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9"
    );
#endif /* WOLFSSL_SP_SMALL */

    return c;
}

/* Reduce the number back to 3072 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
SP_NOINLINE static void sp_3072_mont_reduce_48(sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    sp_digit ca = 0;

    __asm__ __volatile__ (
        "ldr   r11, [%[m], #0]\n\t"
        "# i = 0\n\t"
        "mov	r12, #0\n\t"
        "ldr	r10, [%[a], #0]\n\t"
        "ldr	r14, [%[a], #4]\n\t"
        "\n1:\n\t"
        "# mu = a[i] * mp\n\t"
        "mul	r8, %[mp], r10\n\t"
        "# a[i+0] += m[0] * mu\n\t"
        "ldr	r9, [%[a], #0]\n\t"
        "umull	r6, r7, r8, r11\n\t"
        "adds	r10, r10, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "# a[i+1] += m[1] * mu\n\t"
        "ldr       r7, [%[m], #4]\n\t"
        "ldr	r9, [%[a], #4]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r10, r14, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r10, r10, r5\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+2] += m[2] * mu\n\t"
        "ldr       r7, [%[m], #8]\n\t"
        "ldr	r14, [%[a], #8]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r14, r14, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r14, r14, r4\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+3] += m[3] * mu\n\t"
        "ldr       r7, [%[m], #12]\n\t"
        "ldr	r9, [%[a], #12]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #12]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+4] += m[4] * mu\n\t"
        "ldr       r7, [%[m], #16]\n\t"
        "ldr	r9, [%[a], #16]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #16]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+5] += m[5] * mu\n\t"
        "ldr       r7, [%[m], #20]\n\t"
        "ldr	r9, [%[a], #20]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #20]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+6] += m[6] * mu\n\t"
        "ldr       r7, [%[m], #24]\n\t"
        "ldr	r9, [%[a], #24]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #24]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+7] += m[7] * mu\n\t"
        "ldr       r7, [%[m], #28]\n\t"
        "ldr	r9, [%[a], #28]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #28]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+8] += m[8] * mu\n\t"
        "ldr       r7, [%[m], #32]\n\t"
        "ldr	r9, [%[a], #32]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #32]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+9] += m[9] * mu\n\t"
        "ldr       r7, [%[m], #36]\n\t"
        "ldr	r9, [%[a], #36]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #36]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+10] += m[10] * mu\n\t"
        "ldr       r7, [%[m], #40]\n\t"
        "ldr	r9, [%[a], #40]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #40]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+11] += m[11] * mu\n\t"
        "ldr       r7, [%[m], #44]\n\t"
        "ldr	r9, [%[a], #44]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #44]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+12] += m[12] * mu\n\t"
        "ldr       r7, [%[m], #48]\n\t"
        "ldr	r9, [%[a], #48]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #48]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+13] += m[13] * mu\n\t"
        "ldr       r7, [%[m], #52]\n\t"
        "ldr	r9, [%[a], #52]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #52]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+14] += m[14] * mu\n\t"
        "ldr       r7, [%[m], #56]\n\t"
        "ldr	r9, [%[a], #56]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #56]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+15] += m[15] * mu\n\t"
        "ldr       r7, [%[m], #60]\n\t"
        "ldr	r9, [%[a], #60]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #60]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+16] += m[16] * mu\n\t"
        "ldr       r7, [%[m], #64]\n\t"
        "ldr	r9, [%[a], #64]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #64]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+17] += m[17] * mu\n\t"
        "ldr       r7, [%[m], #68]\n\t"
        "ldr	r9, [%[a], #68]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #68]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+18] += m[18] * mu\n\t"
        "ldr       r7, [%[m], #72]\n\t"
        "ldr	r9, [%[a], #72]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #72]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+19] += m[19] * mu\n\t"
        "ldr       r7, [%[m], #76]\n\t"
        "ldr	r9, [%[a], #76]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #76]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+20] += m[20] * mu\n\t"
        "ldr       r7, [%[m], #80]\n\t"
        "ldr	r9, [%[a], #80]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #80]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+21] += m[21] * mu\n\t"
        "ldr       r7, [%[m], #84]\n\t"
        "ldr	r9, [%[a], #84]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #84]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+22] += m[22] * mu\n\t"
        "ldr       r7, [%[m], #88]\n\t"
        "ldr	r9, [%[a], #88]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #88]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+23] += m[23] * mu\n\t"
        "ldr       r7, [%[m], #92]\n\t"
        "ldr	r9, [%[a], #92]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #92]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+24] += m[24] * mu\n\t"
        "ldr       r7, [%[m], #96]\n\t"
        "ldr	r9, [%[a], #96]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #96]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+25] += m[25] * mu\n\t"
        "ldr       r7, [%[m], #100]\n\t"
        "ldr	r9, [%[a], #100]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #100]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+26] += m[26] * mu\n\t"
        "ldr       r7, [%[m], #104]\n\t"
        "ldr	r9, [%[a], #104]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #104]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+27] += m[27] * mu\n\t"
        "ldr       r7, [%[m], #108]\n\t"
        "ldr	r9, [%[a], #108]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #108]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+28] += m[28] * mu\n\t"
        "ldr       r7, [%[m], #112]\n\t"
        "ldr	r9, [%[a], #112]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #112]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+29] += m[29] * mu\n\t"
        "ldr       r7, [%[m], #116]\n\t"
        "ldr	r9, [%[a], #116]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #116]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+30] += m[30] * mu\n\t"
        "ldr       r7, [%[m], #120]\n\t"
        "ldr	r9, [%[a], #120]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #120]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+31] += m[31] * mu\n\t"
        "ldr       r7, [%[m], #124]\n\t"
        "ldr	r9, [%[a], #124]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #124]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+32] += m[32] * mu\n\t"
        "ldr       r7, [%[m], #128]\n\t"
        "ldr	r9, [%[a], #128]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #128]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+33] += m[33] * mu\n\t"
        "ldr       r7, [%[m], #132]\n\t"
        "ldr	r9, [%[a], #132]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #132]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+34] += m[34] * mu\n\t"
        "ldr       r7, [%[m], #136]\n\t"
        "ldr	r9, [%[a], #136]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #136]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+35] += m[35] * mu\n\t"
        "ldr       r7, [%[m], #140]\n\t"
        "ldr	r9, [%[a], #140]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #140]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+36] += m[36] * mu\n\t"
        "ldr       r7, [%[m], #144]\n\t"
        "ldr	r9, [%[a], #144]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #144]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+37] += m[37] * mu\n\t"
        "ldr       r7, [%[m], #148]\n\t"
        "ldr	r9, [%[a], #148]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #148]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+38] += m[38] * mu\n\t"
        "ldr       r7, [%[m], #152]\n\t"
        "ldr	r9, [%[a], #152]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #152]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+39] += m[39] * mu\n\t"
        "ldr       r7, [%[m], #156]\n\t"
        "ldr	r9, [%[a], #156]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #156]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+40] += m[40] * mu\n\t"
        "ldr       r7, [%[m], #160]\n\t"
        "ldr	r9, [%[a], #160]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #160]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+41] += m[41] * mu\n\t"
        "ldr       r7, [%[m], #164]\n\t"
        "ldr	r9, [%[a], #164]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #164]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+42] += m[42] * mu\n\t"
        "ldr       r7, [%[m], #168]\n\t"
        "ldr	r9, [%[a], #168]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #168]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+43] += m[43] * mu\n\t"
        "ldr       r7, [%[m], #172]\n\t"
        "ldr	r9, [%[a], #172]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #172]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+44] += m[44] * mu\n\t"
        "ldr       r7, [%[m], #176]\n\t"
        "ldr	r9, [%[a], #176]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #176]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+45] += m[45] * mu\n\t"
        "ldr       r7, [%[m], #180]\n\t"
        "ldr	r9, [%[a], #180]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #180]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+46] += m[46] * mu\n\t"
        "ldr       r7, [%[m], #184]\n\t"
        "ldr	r9, [%[a], #184]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #184]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+47] += m[47] * mu\n\t"
        "ldr	r7, [%[m], #188]\n\t"
        "ldr   r9, [%[a], #188]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r7, r7, %[ca]\n\t"
        "mov	%[ca], #0\n\t"
        "adc	%[ca], %[ca], %[ca]\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #188]\n\t"
        "ldr	r9, [%[a], #192]\n\t"
        "adcs	r9, r9, r7\n\t"
        "str	r9, [%[a], #192]\n\t"
        "adc	%[ca], %[ca], #0\n\t"
        "# i += 1\n\t"
        "add	%[a], %[a], #4\n\t"
        "add	r12, r12, #4\n\t"
        "cmp	r12, #192\n\t"
        "blt	1b\n\t"
        "str	r10, [%[a], #0]\n\t"
        "str	r14, [%[a], #4]\n\t"
        : [ca] "+r" (ca), [a] "+r" (a)
        : [m] "r" (m), [mp] "r" (mp)
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14", "r12", "r11"
    );

    sp_3072_cond_sub_48(a - 48, a, m, (sp_digit)0 - ca);
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
        "mov	r10, #0\n\t"
        "# A[0] * B\n\t"
        "ldr	r8, [%[a]]\n\t"
        "umull	r5, r3, %[b], r8\n\t"
        "mov	r4, #0\n\t"
        "str	r5, [%[r]]\n\t"
        "mov	r5, #0\n\t"
        "mov	r9, #4\n\t"
        "1:\n\t"
        "ldr	r8, [%[a], r9]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "str	r3, [%[r], r9]\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "mov	r5, #0\n\t"
        "add	r9, r9, #4\n\t"
        "cmp	r9, #192\n\t"
        "blt	1b\n\t"
        "str	r3, [%[r], #192]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
    );
#else
    __asm__ __volatile__ (
        "mov	r10, #0\n\t"
        "# A[0] * B\n\t"
        "ldr	r8, [%[a]]\n\t"
        "umull	r3, r4, %[b], r8\n\t"
        "mov	r5, #0\n\t"
        "str	r3, [%[r]]\n\t"
        "# A[1] * B\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #4]\n\t"
        "# A[2] * B\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #8]\n\t"
        "# A[3] * B\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #12]\n\t"
        "# A[4] * B\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #16]\n\t"
        "# A[5] * B\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #20]\n\t"
        "# A[6] * B\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #24]\n\t"
        "# A[7] * B\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #28]\n\t"
        "# A[8] * B\n\t"
        "ldr	r8, [%[a], #32]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #32]\n\t"
        "# A[9] * B\n\t"
        "ldr	r8, [%[a], #36]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #36]\n\t"
        "# A[10] * B\n\t"
        "ldr	r8, [%[a], #40]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #40]\n\t"
        "# A[11] * B\n\t"
        "ldr	r8, [%[a], #44]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #44]\n\t"
        "# A[12] * B\n\t"
        "ldr	r8, [%[a], #48]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #48]\n\t"
        "# A[13] * B\n\t"
        "ldr	r8, [%[a], #52]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #52]\n\t"
        "# A[14] * B\n\t"
        "ldr	r8, [%[a], #56]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #56]\n\t"
        "# A[15] * B\n\t"
        "ldr	r8, [%[a], #60]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #60]\n\t"
        "# A[16] * B\n\t"
        "ldr	r8, [%[a], #64]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #64]\n\t"
        "# A[17] * B\n\t"
        "ldr	r8, [%[a], #68]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #68]\n\t"
        "# A[18] * B\n\t"
        "ldr	r8, [%[a], #72]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #72]\n\t"
        "# A[19] * B\n\t"
        "ldr	r8, [%[a], #76]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #76]\n\t"
        "# A[20] * B\n\t"
        "ldr	r8, [%[a], #80]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #80]\n\t"
        "# A[21] * B\n\t"
        "ldr	r8, [%[a], #84]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #84]\n\t"
        "# A[22] * B\n\t"
        "ldr	r8, [%[a], #88]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #88]\n\t"
        "# A[23] * B\n\t"
        "ldr	r8, [%[a], #92]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #92]\n\t"
        "# A[24] * B\n\t"
        "ldr	r8, [%[a], #96]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #96]\n\t"
        "# A[25] * B\n\t"
        "ldr	r8, [%[a], #100]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #100]\n\t"
        "# A[26] * B\n\t"
        "ldr	r8, [%[a], #104]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #104]\n\t"
        "# A[27] * B\n\t"
        "ldr	r8, [%[a], #108]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #108]\n\t"
        "# A[28] * B\n\t"
        "ldr	r8, [%[a], #112]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #112]\n\t"
        "# A[29] * B\n\t"
        "ldr	r8, [%[a], #116]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #116]\n\t"
        "# A[30] * B\n\t"
        "ldr	r8, [%[a], #120]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #120]\n\t"
        "# A[31] * B\n\t"
        "ldr	r8, [%[a], #124]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #124]\n\t"
        "# A[32] * B\n\t"
        "ldr	r8, [%[a], #128]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #128]\n\t"
        "# A[33] * B\n\t"
        "ldr	r8, [%[a], #132]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #132]\n\t"
        "# A[34] * B\n\t"
        "ldr	r8, [%[a], #136]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #136]\n\t"
        "# A[35] * B\n\t"
        "ldr	r8, [%[a], #140]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #140]\n\t"
        "# A[36] * B\n\t"
        "ldr	r8, [%[a], #144]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #144]\n\t"
        "# A[37] * B\n\t"
        "ldr	r8, [%[a], #148]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #148]\n\t"
        "# A[38] * B\n\t"
        "ldr	r8, [%[a], #152]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #152]\n\t"
        "# A[39] * B\n\t"
        "ldr	r8, [%[a], #156]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #156]\n\t"
        "# A[40] * B\n\t"
        "ldr	r8, [%[a], #160]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #160]\n\t"
        "# A[41] * B\n\t"
        "ldr	r8, [%[a], #164]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #164]\n\t"
        "# A[42] * B\n\t"
        "ldr	r8, [%[a], #168]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #168]\n\t"
        "# A[43] * B\n\t"
        "ldr	r8, [%[a], #172]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #172]\n\t"
        "# A[44] * B\n\t"
        "ldr	r8, [%[a], #176]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #176]\n\t"
        "# A[45] * B\n\t"
        "ldr	r8, [%[a], #180]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #180]\n\t"
        "# A[46] * B\n\t"
        "ldr	r8, [%[a], #184]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #184]\n\t"
        "# A[47] * B\n\t"
        "ldr	r8, [%[a], #188]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adc	r3, r3, r7\n\t"
        "str	r5, [%[r], #188]\n\t"
        "str	r3, [%[r], #192]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
    );
#endif
}

/* Divide the double width number (d1|d0) by the divisor. (d1|d0 / div)
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The divisor.
 * returns the result of the division.
 *
 * Note that this is an approximate div. It may give an answer 1 larger.
 */
static sp_digit div_3072_word_48(sp_digit d1, sp_digit d0, sp_digit div)
{
    sp_digit r = 0;

    __asm__ __volatile__ (
        "lsr	r5, %[div], #1\n\t"
        "add	r5, r5, #1\n\t"
        "mov	r6, %[d0]\n\t"
        "mov	r7, %[d1]\n\t"
        "# Do top 32\n\t"
        "subs	r8, r5, r7\n\t"
        "sbc	r8, r8, r8\n\t"
        "add	%[r], %[r], %[r]\n\t"
        "sub	%[r], %[r], r8\n\t"
        "and	r8, r8, r5\n\t"
        "subs	r7, r7, r8\n\t"
        "# Next 30 bits\n\t"
        "mov	r4, #29\n\t"
        "1:\n\t"
        "movs	r6, r6, lsl #1\n\t"
        "adc	r7, r7, r7\n\t"
        "subs	r8, r5, r7\n\t"
        "sbc	r8, r8, r8\n\t"
        "add	%[r], %[r], %[r]\n\t"
        "sub	%[r], %[r], r8\n\t"
        "and	r8, r8, r5\n\t"
        "subs	r7, r7, r8\n\t"
        "subs	r4, r4, #1\n\t"
        "bpl	1b\n\t"
        "add	%[r], %[r], %[r]\n\t"
        "add	%[r], %[r], #1\n\t"
        "umull	r4, r5, %[r], %[div]\n\t"
        "subs	r4, %[d0], r4\n\t"
        "sbc	r5, %[d1], r5\n\t"
        "add	%[r], %[r], r5\n\t"
        "umull	r4, r5, %[r], %[div]\n\t"
        "subs	r4, %[d0], r4\n\t"
        "sbc	r5, %[d1], r5\n\t"
        "add	%[r], %[r], r5\n\t"
        "umull	r4, r5, %[r], %[div]\n\t"
        "subs	r4, %[d0], r4\n\t"
        "sbc	r5, %[d1], r5\n\t"
        "add	%[r], %[r], r5\n\t"
        "subs	r8, %[div], r4\n\t"
        "sbc	r8, r8, r8\n\t"
        "sub	%[r], %[r], r8\n\t"
        : [r] "+r" (r)
        : [d1] "r" (d1), [d0] "r" (d0), [div] "r" (div)
        : "r4", "r5", "r6", "r7", "r8"
    );
    return r;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_int32 sp_3072_cmp_48(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = -1;
    sp_digit one = 1;


#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "mov	r7, #0\n\t"
        "mov	r3, #-1\n\t"
        "mov	r6, #188\n\t"
        "1:\n\t"
        "ldr	r4, [%[a], r6]\n\t"
        "ldr	r5, [%[b], r6]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "subs	r6, r6, #4\n\t"
        "bcs	1b\n\t"
        "eor	%[r], %[r], r3\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [one] "r" (one)
        : "r3", "r4", "r5", "r6", "r7"
    );
#else
    __asm__ __volatile__ (
        "mov	r7, #0\n\t"
        "mov	r3, #-1\n\t"
        "ldr	r4, [%[a], #188]\n\t"
        "ldr	r5, [%[b], #188]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #184]\n\t"
        "ldr	r5, [%[b], #184]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #180]\n\t"
        "ldr	r5, [%[b], #180]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #176]\n\t"
        "ldr	r5, [%[b], #176]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #172]\n\t"
        "ldr	r5, [%[b], #172]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #168]\n\t"
        "ldr	r5, [%[b], #168]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #164]\n\t"
        "ldr	r5, [%[b], #164]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #160]\n\t"
        "ldr	r5, [%[b], #160]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #156]\n\t"
        "ldr	r5, [%[b], #156]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #152]\n\t"
        "ldr	r5, [%[b], #152]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #148]\n\t"
        "ldr	r5, [%[b], #148]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #144]\n\t"
        "ldr	r5, [%[b], #144]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #140]\n\t"
        "ldr	r5, [%[b], #140]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #136]\n\t"
        "ldr	r5, [%[b], #136]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #132]\n\t"
        "ldr	r5, [%[b], #132]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #128]\n\t"
        "ldr	r5, [%[b], #128]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #124]\n\t"
        "ldr	r5, [%[b], #124]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #120]\n\t"
        "ldr	r5, [%[b], #120]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #116]\n\t"
        "ldr	r5, [%[b], #116]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #112]\n\t"
        "ldr	r5, [%[b], #112]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #108]\n\t"
        "ldr	r5, [%[b], #108]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #104]\n\t"
        "ldr	r5, [%[b], #104]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #100]\n\t"
        "ldr	r5, [%[b], #100]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #96]\n\t"
        "ldr	r5, [%[b], #96]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #92]\n\t"
        "ldr	r5, [%[b], #92]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #88]\n\t"
        "ldr	r5, [%[b], #88]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #84]\n\t"
        "ldr	r5, [%[b], #84]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #80]\n\t"
        "ldr	r5, [%[b], #80]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #76]\n\t"
        "ldr	r5, [%[b], #76]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #72]\n\t"
        "ldr	r5, [%[b], #72]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #68]\n\t"
        "ldr	r5, [%[b], #68]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #64]\n\t"
        "ldr	r5, [%[b], #64]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #60]\n\t"
        "ldr	r5, [%[b], #60]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #56]\n\t"
        "ldr	r5, [%[b], #56]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #52]\n\t"
        "ldr	r5, [%[b], #52]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #48]\n\t"
        "ldr	r5, [%[b], #48]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #44]\n\t"
        "ldr	r5, [%[b], #44]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #40]\n\t"
        "ldr	r5, [%[b], #40]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #36]\n\t"
        "ldr	r5, [%[b], #36]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #32]\n\t"
        "ldr	r5, [%[b], #32]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #28]\n\t"
        "ldr	r5, [%[b], #28]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #24]\n\t"
        "ldr	r5, [%[b], #24]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #20]\n\t"
        "ldr	r5, [%[b], #20]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #16]\n\t"
        "ldr	r5, [%[b], #16]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #12]\n\t"
        "ldr	r5, [%[b], #12]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #8]\n\t"
        "ldr	r5, [%[b], #8]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #4]\n\t"
        "ldr	r5, [%[b], #4]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #0]\n\t"
        "ldr	r5, [%[b], #0]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "eor	%[r], %[r], r3\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [one] "r" (one)
        : "r3", "r4", "r5", "r6", "r7"
    );
#endif

    return r;
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

        i = (bits - 1) / 32;
        n = e[i--];
        c = bits & 31;
        if (c == 0) {
            c = 32;
        }
        c -= bits % 4;
        if (c == 32) {
            c = 28;
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
            n <<= 32 - c;
        }
        XMEMCPY(r, t[y], sizeof(sp_digit) * 48);
        for (; i>=0 || c>=4; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 28);
                n <<= 4;
                c = 28;
            }
            else if (c < 4) {
                y = (byte)(n >> 28);
                n = e[i--];
                c = 4 - c;
                y |= (byte)(n >> (32 - c));
                n <<= c;
                c = 32 - c;
            }
            else {
                y = (byte)((n >> 28) & 0xf);
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
    sp_digit td[32 * 96];
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
        sp_3072_mont_sqr_48(t[16], t[ 8], m, mp);
        sp_3072_mont_mul_48(t[17], t[ 9], t[ 8], m, mp);
        sp_3072_mont_sqr_48(t[18], t[ 9], m, mp);
        sp_3072_mont_mul_48(t[19], t[10], t[ 9], m, mp);
        sp_3072_mont_sqr_48(t[20], t[10], m, mp);
        sp_3072_mont_mul_48(t[21], t[11], t[10], m, mp);
        sp_3072_mont_sqr_48(t[22], t[11], m, mp);
        sp_3072_mont_mul_48(t[23], t[12], t[11], m, mp);
        sp_3072_mont_sqr_48(t[24], t[12], m, mp);
        sp_3072_mont_mul_48(t[25], t[13], t[12], m, mp);
        sp_3072_mont_sqr_48(t[26], t[13], m, mp);
        sp_3072_mont_mul_48(t[27], t[14], t[13], m, mp);
        sp_3072_mont_sqr_48(t[28], t[14], m, mp);
        sp_3072_mont_mul_48(t[29], t[15], t[14], m, mp);
        sp_3072_mont_sqr_48(t[30], t[15], m, mp);
        sp_3072_mont_mul_48(t[31], t[16], t[15], m, mp);

        i = (bits - 1) / 32;
        n = e[i--];
        c = bits & 31;
        if (c == 0) {
            c = 32;
        }
        c -= bits % 5;
        if (c == 32) {
            c = 27;
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
            n <<= 32 - c;
        }
        XMEMCPY(r, t[y], sizeof(sp_digit) * 48);
        for (; i>=0 || c>=5; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 27);
                n <<= 5;
                c = 27;
            }
            else if (c < 5) {
                y = (byte)(n >> 27);
                n = e[i--];
                c = 5 - c;
                y |= (byte)(n >> (32 - c));
                n <<= c;
                c = 32 - c;
            }
            else {
                y = (byte)((n >> 27) & 0x1f);
                n <<= 5;
                c -= 5;
            }

            sp_3072_mont_sqr_48(r, r, m, mp);
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

#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) | WOLFSSL_HAVE_SP_DH */

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 3072 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_3072_mont_norm_96(sp_digit* r, const sp_digit* m)
{
    XMEMSET(r, 0, sizeof(sp_digit) * 96);

    /* r = 2^n mod m */
    sp_3072_sub_in_place_96(r, m);
}

#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) | WOLFSSL_HAVE_SP_DH */
/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not copying.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static sp_digit sp_3072_cond_sub_96(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    sp_digit c = 0;

#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "mov	r9, #0\n\t"
        "mov	r8, #0\n\t"
        "1:\n\t"
        "subs	%[c], r9, %[c]\n\t"
        "ldr	r4, [%[a], r8]\n\t"
        "ldr	r6, [%[b], r8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbc	%[c], r9, r9\n\t"
        "str	r4, [%[r], r8]\n\t"
        "add	r8, r8, #4\n\t"
        "cmp	r8, #384\n\t"
        "blt	1b\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9"
    );
#else
    __asm__ __volatile__ (

        "mov	r9, #0\n\t"
        "ldrd	r4, r5, [%[a], #0]\n\t"
        "ldrd	r6, r7, [%[b], #0]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "subs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #0]\n\t"
        "ldrd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r6, r7, [%[b], #8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #8]\n\t"
        "ldrd	r4, r5, [%[a], #16]\n\t"
        "ldrd	r6, r7, [%[b], #16]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #16]\n\t"
        "ldrd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r6, r7, [%[b], #24]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #24]\n\t"
        "ldrd	r4, r5, [%[a], #32]\n\t"
        "ldrd	r6, r7, [%[b], #32]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #32]\n\t"
        "ldrd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r6, r7, [%[b], #40]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #40]\n\t"
        "ldrd	r4, r5, [%[a], #48]\n\t"
        "ldrd	r6, r7, [%[b], #48]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #48]\n\t"
        "ldrd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r6, r7, [%[b], #56]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #56]\n\t"
        "ldrd	r4, r5, [%[a], #64]\n\t"
        "ldrd	r6, r7, [%[b], #64]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #64]\n\t"
        "ldrd	r4, r5, [%[a], #72]\n\t"
        "ldrd	r6, r7, [%[b], #72]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #72]\n\t"
        "ldrd	r4, r5, [%[a], #80]\n\t"
        "ldrd	r6, r7, [%[b], #80]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #80]\n\t"
        "ldrd	r4, r5, [%[a], #88]\n\t"
        "ldrd	r6, r7, [%[b], #88]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #88]\n\t"
        "ldrd	r4, r5, [%[a], #96]\n\t"
        "ldrd	r6, r7, [%[b], #96]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #96]\n\t"
        "ldrd	r4, r5, [%[a], #104]\n\t"
        "ldrd	r6, r7, [%[b], #104]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #104]\n\t"
        "ldrd	r4, r5, [%[a], #112]\n\t"
        "ldrd	r6, r7, [%[b], #112]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #112]\n\t"
        "ldrd	r4, r5, [%[a], #120]\n\t"
        "ldrd	r6, r7, [%[b], #120]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #120]\n\t"
        "ldrd	r4, r5, [%[a], #128]\n\t"
        "ldrd	r6, r7, [%[b], #128]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #128]\n\t"
        "ldrd	r4, r5, [%[a], #136]\n\t"
        "ldrd	r6, r7, [%[b], #136]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #136]\n\t"
        "ldrd	r4, r5, [%[a], #144]\n\t"
        "ldrd	r6, r7, [%[b], #144]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #144]\n\t"
        "ldrd	r4, r5, [%[a], #152]\n\t"
        "ldrd	r6, r7, [%[b], #152]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #152]\n\t"
        "ldrd	r4, r5, [%[a], #160]\n\t"
        "ldrd	r6, r7, [%[b], #160]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #160]\n\t"
        "ldrd	r4, r5, [%[a], #168]\n\t"
        "ldrd	r6, r7, [%[b], #168]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #168]\n\t"
        "ldrd	r4, r5, [%[a], #176]\n\t"
        "ldrd	r6, r7, [%[b], #176]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #176]\n\t"
        "ldrd	r4, r5, [%[a], #184]\n\t"
        "ldrd	r6, r7, [%[b], #184]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #184]\n\t"
        "ldrd	r4, r5, [%[a], #192]\n\t"
        "ldrd	r6, r7, [%[b], #192]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #192]\n\t"
        "ldrd	r4, r5, [%[a], #200]\n\t"
        "ldrd	r6, r7, [%[b], #200]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #200]\n\t"
        "ldrd	r4, r5, [%[a], #208]\n\t"
        "ldrd	r6, r7, [%[b], #208]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #208]\n\t"
        "ldrd	r4, r5, [%[a], #216]\n\t"
        "ldrd	r6, r7, [%[b], #216]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #216]\n\t"
        "ldrd	r4, r5, [%[a], #224]\n\t"
        "ldrd	r6, r7, [%[b], #224]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #224]\n\t"
        "ldrd	r4, r5, [%[a], #232]\n\t"
        "ldrd	r6, r7, [%[b], #232]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #232]\n\t"
        "ldrd	r4, r5, [%[a], #240]\n\t"
        "ldrd	r6, r7, [%[b], #240]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #240]\n\t"
        "ldrd	r4, r5, [%[a], #248]\n\t"
        "ldrd	r6, r7, [%[b], #248]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #248]\n\t"
        "ldrd	r4, r5, [%[a], #256]\n\t"
        "ldrd	r6, r7, [%[b], #256]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #256]\n\t"
        "ldrd	r4, r5, [%[a], #264]\n\t"
        "ldrd	r6, r7, [%[b], #264]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #264]\n\t"
        "ldrd	r4, r5, [%[a], #272]\n\t"
        "ldrd	r6, r7, [%[b], #272]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #272]\n\t"
        "ldrd	r4, r5, [%[a], #280]\n\t"
        "ldrd	r6, r7, [%[b], #280]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #280]\n\t"
        "ldrd	r4, r5, [%[a], #288]\n\t"
        "ldrd	r6, r7, [%[b], #288]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #288]\n\t"
        "ldrd	r4, r5, [%[a], #296]\n\t"
        "ldrd	r6, r7, [%[b], #296]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #296]\n\t"
        "ldrd	r4, r5, [%[a], #304]\n\t"
        "ldrd	r6, r7, [%[b], #304]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #304]\n\t"
        "ldrd	r4, r5, [%[a], #312]\n\t"
        "ldrd	r6, r7, [%[b], #312]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #312]\n\t"
        "ldrd	r4, r5, [%[a], #320]\n\t"
        "ldrd	r6, r7, [%[b], #320]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #320]\n\t"
        "ldrd	r4, r5, [%[a], #328]\n\t"
        "ldrd	r6, r7, [%[b], #328]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #328]\n\t"
        "ldrd	r4, r5, [%[a], #336]\n\t"
        "ldrd	r6, r7, [%[b], #336]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #336]\n\t"
        "ldrd	r4, r5, [%[a], #344]\n\t"
        "ldrd	r6, r7, [%[b], #344]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #344]\n\t"
        "ldrd	r4, r5, [%[a], #352]\n\t"
        "ldrd	r6, r7, [%[b], #352]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #352]\n\t"
        "ldrd	r4, r5, [%[a], #360]\n\t"
        "ldrd	r6, r7, [%[b], #360]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #360]\n\t"
        "ldrd	r4, r5, [%[a], #368]\n\t"
        "ldrd	r6, r7, [%[b], #368]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #368]\n\t"
        "ldrd	r4, r5, [%[a], #376]\n\t"
        "ldrd	r6, r7, [%[b], #376]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #376]\n\t"
        "sbc	%[c], r9, r9\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9"
    );
#endif /* WOLFSSL_SP_SMALL */

    return c;
}

/* Reduce the number back to 3072 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
SP_NOINLINE static void sp_3072_mont_reduce_96(sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    sp_digit ca = 0;

    __asm__ __volatile__ (
        "ldr   r11, [%[m], #0]\n\t"
        "# i = 0\n\t"
        "mov	r12, #0\n\t"
        "ldr	r10, [%[a], #0]\n\t"
        "ldr	r14, [%[a], #4]\n\t"
        "\n1:\n\t"
        "# mu = a[i] * mp\n\t"
        "mul	r8, %[mp], r10\n\t"
        "# a[i+0] += m[0] * mu\n\t"
        "ldr	r9, [%[a], #0]\n\t"
        "umull	r6, r7, r8, r11\n\t"
        "adds	r10, r10, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "# a[i+1] += m[1] * mu\n\t"
        "ldr       r7, [%[m], #4]\n\t"
        "ldr	r9, [%[a], #4]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r10, r14, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r10, r10, r5\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+2] += m[2] * mu\n\t"
        "ldr       r7, [%[m], #8]\n\t"
        "ldr	r14, [%[a], #8]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r14, r14, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r14, r14, r4\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+3] += m[3] * mu\n\t"
        "ldr       r7, [%[m], #12]\n\t"
        "ldr	r9, [%[a], #12]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #12]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+4] += m[4] * mu\n\t"
        "ldr       r7, [%[m], #16]\n\t"
        "ldr	r9, [%[a], #16]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #16]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+5] += m[5] * mu\n\t"
        "ldr       r7, [%[m], #20]\n\t"
        "ldr	r9, [%[a], #20]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #20]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+6] += m[6] * mu\n\t"
        "ldr       r7, [%[m], #24]\n\t"
        "ldr	r9, [%[a], #24]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #24]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+7] += m[7] * mu\n\t"
        "ldr       r7, [%[m], #28]\n\t"
        "ldr	r9, [%[a], #28]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #28]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+8] += m[8] * mu\n\t"
        "ldr       r7, [%[m], #32]\n\t"
        "ldr	r9, [%[a], #32]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #32]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+9] += m[9] * mu\n\t"
        "ldr       r7, [%[m], #36]\n\t"
        "ldr	r9, [%[a], #36]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #36]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+10] += m[10] * mu\n\t"
        "ldr       r7, [%[m], #40]\n\t"
        "ldr	r9, [%[a], #40]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #40]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+11] += m[11] * mu\n\t"
        "ldr       r7, [%[m], #44]\n\t"
        "ldr	r9, [%[a], #44]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #44]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+12] += m[12] * mu\n\t"
        "ldr       r7, [%[m], #48]\n\t"
        "ldr	r9, [%[a], #48]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #48]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+13] += m[13] * mu\n\t"
        "ldr       r7, [%[m], #52]\n\t"
        "ldr	r9, [%[a], #52]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #52]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+14] += m[14] * mu\n\t"
        "ldr       r7, [%[m], #56]\n\t"
        "ldr	r9, [%[a], #56]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #56]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+15] += m[15] * mu\n\t"
        "ldr       r7, [%[m], #60]\n\t"
        "ldr	r9, [%[a], #60]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #60]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+16] += m[16] * mu\n\t"
        "ldr       r7, [%[m], #64]\n\t"
        "ldr	r9, [%[a], #64]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #64]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+17] += m[17] * mu\n\t"
        "ldr       r7, [%[m], #68]\n\t"
        "ldr	r9, [%[a], #68]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #68]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+18] += m[18] * mu\n\t"
        "ldr       r7, [%[m], #72]\n\t"
        "ldr	r9, [%[a], #72]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #72]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+19] += m[19] * mu\n\t"
        "ldr       r7, [%[m], #76]\n\t"
        "ldr	r9, [%[a], #76]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #76]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+20] += m[20] * mu\n\t"
        "ldr       r7, [%[m], #80]\n\t"
        "ldr	r9, [%[a], #80]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #80]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+21] += m[21] * mu\n\t"
        "ldr       r7, [%[m], #84]\n\t"
        "ldr	r9, [%[a], #84]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #84]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+22] += m[22] * mu\n\t"
        "ldr       r7, [%[m], #88]\n\t"
        "ldr	r9, [%[a], #88]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #88]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+23] += m[23] * mu\n\t"
        "ldr       r7, [%[m], #92]\n\t"
        "ldr	r9, [%[a], #92]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #92]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+24] += m[24] * mu\n\t"
        "ldr       r7, [%[m], #96]\n\t"
        "ldr	r9, [%[a], #96]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #96]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+25] += m[25] * mu\n\t"
        "ldr       r7, [%[m], #100]\n\t"
        "ldr	r9, [%[a], #100]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #100]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+26] += m[26] * mu\n\t"
        "ldr       r7, [%[m], #104]\n\t"
        "ldr	r9, [%[a], #104]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #104]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+27] += m[27] * mu\n\t"
        "ldr       r7, [%[m], #108]\n\t"
        "ldr	r9, [%[a], #108]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #108]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+28] += m[28] * mu\n\t"
        "ldr       r7, [%[m], #112]\n\t"
        "ldr	r9, [%[a], #112]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #112]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+29] += m[29] * mu\n\t"
        "ldr       r7, [%[m], #116]\n\t"
        "ldr	r9, [%[a], #116]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #116]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+30] += m[30] * mu\n\t"
        "ldr       r7, [%[m], #120]\n\t"
        "ldr	r9, [%[a], #120]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #120]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+31] += m[31] * mu\n\t"
        "ldr       r7, [%[m], #124]\n\t"
        "ldr	r9, [%[a], #124]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #124]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+32] += m[32] * mu\n\t"
        "ldr       r7, [%[m], #128]\n\t"
        "ldr	r9, [%[a], #128]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #128]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+33] += m[33] * mu\n\t"
        "ldr       r7, [%[m], #132]\n\t"
        "ldr	r9, [%[a], #132]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #132]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+34] += m[34] * mu\n\t"
        "ldr       r7, [%[m], #136]\n\t"
        "ldr	r9, [%[a], #136]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #136]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+35] += m[35] * mu\n\t"
        "ldr       r7, [%[m], #140]\n\t"
        "ldr	r9, [%[a], #140]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #140]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+36] += m[36] * mu\n\t"
        "ldr       r7, [%[m], #144]\n\t"
        "ldr	r9, [%[a], #144]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #144]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+37] += m[37] * mu\n\t"
        "ldr       r7, [%[m], #148]\n\t"
        "ldr	r9, [%[a], #148]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #148]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+38] += m[38] * mu\n\t"
        "ldr       r7, [%[m], #152]\n\t"
        "ldr	r9, [%[a], #152]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #152]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+39] += m[39] * mu\n\t"
        "ldr       r7, [%[m], #156]\n\t"
        "ldr	r9, [%[a], #156]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #156]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+40] += m[40] * mu\n\t"
        "ldr       r7, [%[m], #160]\n\t"
        "ldr	r9, [%[a], #160]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #160]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+41] += m[41] * mu\n\t"
        "ldr       r7, [%[m], #164]\n\t"
        "ldr	r9, [%[a], #164]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #164]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+42] += m[42] * mu\n\t"
        "ldr       r7, [%[m], #168]\n\t"
        "ldr	r9, [%[a], #168]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #168]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+43] += m[43] * mu\n\t"
        "ldr       r7, [%[m], #172]\n\t"
        "ldr	r9, [%[a], #172]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #172]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+44] += m[44] * mu\n\t"
        "ldr       r7, [%[m], #176]\n\t"
        "ldr	r9, [%[a], #176]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #176]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+45] += m[45] * mu\n\t"
        "ldr       r7, [%[m], #180]\n\t"
        "ldr	r9, [%[a], #180]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #180]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+46] += m[46] * mu\n\t"
        "ldr       r7, [%[m], #184]\n\t"
        "ldr	r9, [%[a], #184]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #184]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+47] += m[47] * mu\n\t"
        "ldr       r7, [%[m], #188]\n\t"
        "ldr	r9, [%[a], #188]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #188]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+48] += m[48] * mu\n\t"
        "ldr       r7, [%[m], #192]\n\t"
        "ldr	r9, [%[a], #192]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #192]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+49] += m[49] * mu\n\t"
        "ldr       r7, [%[m], #196]\n\t"
        "ldr	r9, [%[a], #196]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #196]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+50] += m[50] * mu\n\t"
        "ldr       r7, [%[m], #200]\n\t"
        "ldr	r9, [%[a], #200]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #200]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+51] += m[51] * mu\n\t"
        "ldr       r7, [%[m], #204]\n\t"
        "ldr	r9, [%[a], #204]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #204]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+52] += m[52] * mu\n\t"
        "ldr       r7, [%[m], #208]\n\t"
        "ldr	r9, [%[a], #208]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #208]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+53] += m[53] * mu\n\t"
        "ldr       r7, [%[m], #212]\n\t"
        "ldr	r9, [%[a], #212]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #212]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+54] += m[54] * mu\n\t"
        "ldr       r7, [%[m], #216]\n\t"
        "ldr	r9, [%[a], #216]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #216]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+55] += m[55] * mu\n\t"
        "ldr       r7, [%[m], #220]\n\t"
        "ldr	r9, [%[a], #220]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #220]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+56] += m[56] * mu\n\t"
        "ldr       r7, [%[m], #224]\n\t"
        "ldr	r9, [%[a], #224]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #224]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+57] += m[57] * mu\n\t"
        "ldr       r7, [%[m], #228]\n\t"
        "ldr	r9, [%[a], #228]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #228]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+58] += m[58] * mu\n\t"
        "ldr       r7, [%[m], #232]\n\t"
        "ldr	r9, [%[a], #232]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #232]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+59] += m[59] * mu\n\t"
        "ldr       r7, [%[m], #236]\n\t"
        "ldr	r9, [%[a], #236]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #236]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+60] += m[60] * mu\n\t"
        "ldr       r7, [%[m], #240]\n\t"
        "ldr	r9, [%[a], #240]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #240]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+61] += m[61] * mu\n\t"
        "ldr       r7, [%[m], #244]\n\t"
        "ldr	r9, [%[a], #244]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #244]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+62] += m[62] * mu\n\t"
        "ldr       r7, [%[m], #248]\n\t"
        "ldr	r9, [%[a], #248]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #248]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+63] += m[63] * mu\n\t"
        "ldr       r7, [%[m], #252]\n\t"
        "ldr	r9, [%[a], #252]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #252]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+64] += m[64] * mu\n\t"
        "ldr       r7, [%[m], #256]\n\t"
        "ldr	r9, [%[a], #256]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #256]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+65] += m[65] * mu\n\t"
        "ldr       r7, [%[m], #260]\n\t"
        "ldr	r9, [%[a], #260]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #260]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+66] += m[66] * mu\n\t"
        "ldr       r7, [%[m], #264]\n\t"
        "ldr	r9, [%[a], #264]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #264]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+67] += m[67] * mu\n\t"
        "ldr       r7, [%[m], #268]\n\t"
        "ldr	r9, [%[a], #268]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #268]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+68] += m[68] * mu\n\t"
        "ldr       r7, [%[m], #272]\n\t"
        "ldr	r9, [%[a], #272]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #272]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+69] += m[69] * mu\n\t"
        "ldr       r7, [%[m], #276]\n\t"
        "ldr	r9, [%[a], #276]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #276]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+70] += m[70] * mu\n\t"
        "ldr       r7, [%[m], #280]\n\t"
        "ldr	r9, [%[a], #280]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #280]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+71] += m[71] * mu\n\t"
        "ldr       r7, [%[m], #284]\n\t"
        "ldr	r9, [%[a], #284]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #284]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+72] += m[72] * mu\n\t"
        "ldr       r7, [%[m], #288]\n\t"
        "ldr	r9, [%[a], #288]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #288]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+73] += m[73] * mu\n\t"
        "ldr       r7, [%[m], #292]\n\t"
        "ldr	r9, [%[a], #292]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #292]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+74] += m[74] * mu\n\t"
        "ldr       r7, [%[m], #296]\n\t"
        "ldr	r9, [%[a], #296]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #296]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+75] += m[75] * mu\n\t"
        "ldr       r7, [%[m], #300]\n\t"
        "ldr	r9, [%[a], #300]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #300]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+76] += m[76] * mu\n\t"
        "ldr       r7, [%[m], #304]\n\t"
        "ldr	r9, [%[a], #304]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #304]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+77] += m[77] * mu\n\t"
        "ldr       r7, [%[m], #308]\n\t"
        "ldr	r9, [%[a], #308]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #308]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+78] += m[78] * mu\n\t"
        "ldr       r7, [%[m], #312]\n\t"
        "ldr	r9, [%[a], #312]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #312]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+79] += m[79] * mu\n\t"
        "ldr       r7, [%[m], #316]\n\t"
        "ldr	r9, [%[a], #316]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #316]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+80] += m[80] * mu\n\t"
        "ldr       r7, [%[m], #320]\n\t"
        "ldr	r9, [%[a], #320]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #320]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+81] += m[81] * mu\n\t"
        "ldr       r7, [%[m], #324]\n\t"
        "ldr	r9, [%[a], #324]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #324]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+82] += m[82] * mu\n\t"
        "ldr       r7, [%[m], #328]\n\t"
        "ldr	r9, [%[a], #328]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #328]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+83] += m[83] * mu\n\t"
        "ldr       r7, [%[m], #332]\n\t"
        "ldr	r9, [%[a], #332]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #332]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+84] += m[84] * mu\n\t"
        "ldr       r7, [%[m], #336]\n\t"
        "ldr	r9, [%[a], #336]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #336]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+85] += m[85] * mu\n\t"
        "ldr       r7, [%[m], #340]\n\t"
        "ldr	r9, [%[a], #340]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #340]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+86] += m[86] * mu\n\t"
        "ldr       r7, [%[m], #344]\n\t"
        "ldr	r9, [%[a], #344]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #344]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+87] += m[87] * mu\n\t"
        "ldr       r7, [%[m], #348]\n\t"
        "ldr	r9, [%[a], #348]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #348]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+88] += m[88] * mu\n\t"
        "ldr       r7, [%[m], #352]\n\t"
        "ldr	r9, [%[a], #352]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #352]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+89] += m[89] * mu\n\t"
        "ldr       r7, [%[m], #356]\n\t"
        "ldr	r9, [%[a], #356]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #356]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+90] += m[90] * mu\n\t"
        "ldr       r7, [%[m], #360]\n\t"
        "ldr	r9, [%[a], #360]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #360]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+91] += m[91] * mu\n\t"
        "ldr       r7, [%[m], #364]\n\t"
        "ldr	r9, [%[a], #364]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #364]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+92] += m[92] * mu\n\t"
        "ldr       r7, [%[m], #368]\n\t"
        "ldr	r9, [%[a], #368]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #368]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+93] += m[93] * mu\n\t"
        "ldr       r7, [%[m], #372]\n\t"
        "ldr	r9, [%[a], #372]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #372]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+94] += m[94] * mu\n\t"
        "ldr       r7, [%[m], #376]\n\t"
        "ldr	r9, [%[a], #376]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #376]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+95] += m[95] * mu\n\t"
        "ldr	r7, [%[m], #380]\n\t"
        "ldr   r9, [%[a], #380]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r7, r7, %[ca]\n\t"
        "mov	%[ca], #0\n\t"
        "adc	%[ca], %[ca], %[ca]\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #380]\n\t"
        "ldr	r9, [%[a], #384]\n\t"
        "adcs	r9, r9, r7\n\t"
        "str	r9, [%[a], #384]\n\t"
        "adc	%[ca], %[ca], #0\n\t"
        "# i += 1\n\t"
        "add	%[a], %[a], #4\n\t"
        "add	r12, r12, #4\n\t"
        "cmp	r12, #384\n\t"
        "blt	1b\n\t"
        "str	r10, [%[a], #0]\n\t"
        "str	r14, [%[a], #4]\n\t"
        : [ca] "+r" (ca), [a] "+r" (a)
        : [m] "r" (m), [mp] "r" (mp)
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14", "r12", "r11"
    );

    sp_3072_cond_sub_96(a - 96, a, m, (sp_digit)0 - ca);
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
SP_NOINLINE static void sp_3072_mont_mul_96(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_3072_mul_96(r, a, b);
    sp_3072_mont_reduce_96(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_3072_mont_sqr_96(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_3072_sqr_96(r, a);
    sp_3072_mont_reduce_96(r, m, mp);
}

#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_3072_sub_96(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "add	r14, %[a], #384\n\t"
        "\n1:\n\t"
        "rsbs	%[c], %[c], #0\n\t"
        "ldrd	r3, r4, [%[a]], #8\n\t"
        "ldrd	r5, r6, [%[a]], #8\n\t"
        "ldrd	r7, r8, [%[b]], #8\n\t"
        "ldrd	r9, r10, [%[b]], #8\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r]], #8\n\t"
        "strd	r5, r6, [%[r]], #8\n\t"
        "sbc	%[c], r3, r3\n\t"
        "cmp	%[a], r14\n\t"
        "bne	1b\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14"
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
static sp_digit sp_3072_sub_96(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldrd	r3, r4, [%[a], #0]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b], #0]\n\t"
        "ldrd	r9, r10, [%[b], #8]\n\t"
        "subs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #0]\n\t"
        "strd	r5, r6, [%[r], #8]\n\t"
        "ldrd	r3, r4, [%[a], #16]\n\t"
        "ldrd	r5, r6, [%[a], #24]\n\t"
        "ldrd	r7, r8, [%[b], #16]\n\t"
        "ldrd	r9, r10, [%[b], #24]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #16]\n\t"
        "strd	r5, r6, [%[r], #24]\n\t"
        "ldrd	r3, r4, [%[a], #32]\n\t"
        "ldrd	r5, r6, [%[a], #40]\n\t"
        "ldrd	r7, r8, [%[b], #32]\n\t"
        "ldrd	r9, r10, [%[b], #40]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #32]\n\t"
        "strd	r5, r6, [%[r], #40]\n\t"
        "ldrd	r3, r4, [%[a], #48]\n\t"
        "ldrd	r5, r6, [%[a], #56]\n\t"
        "ldrd	r7, r8, [%[b], #48]\n\t"
        "ldrd	r9, r10, [%[b], #56]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #48]\n\t"
        "strd	r5, r6, [%[r], #56]\n\t"
        "ldrd	r3, r4, [%[a], #64]\n\t"
        "ldrd	r5, r6, [%[a], #72]\n\t"
        "ldrd	r7, r8, [%[b], #64]\n\t"
        "ldrd	r9, r10, [%[b], #72]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #64]\n\t"
        "strd	r5, r6, [%[r], #72]\n\t"
        "ldrd	r3, r4, [%[a], #80]\n\t"
        "ldrd	r5, r6, [%[a], #88]\n\t"
        "ldrd	r7, r8, [%[b], #80]\n\t"
        "ldrd	r9, r10, [%[b], #88]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #80]\n\t"
        "strd	r5, r6, [%[r], #88]\n\t"
        "ldrd	r3, r4, [%[a], #96]\n\t"
        "ldrd	r5, r6, [%[a], #104]\n\t"
        "ldrd	r7, r8, [%[b], #96]\n\t"
        "ldrd	r9, r10, [%[b], #104]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #96]\n\t"
        "strd	r5, r6, [%[r], #104]\n\t"
        "ldrd	r3, r4, [%[a], #112]\n\t"
        "ldrd	r5, r6, [%[a], #120]\n\t"
        "ldrd	r7, r8, [%[b], #112]\n\t"
        "ldrd	r9, r10, [%[b], #120]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #112]\n\t"
        "strd	r5, r6, [%[r], #120]\n\t"
        "ldrd	r3, r4, [%[a], #128]\n\t"
        "ldrd	r5, r6, [%[a], #136]\n\t"
        "ldrd	r7, r8, [%[b], #128]\n\t"
        "ldrd	r9, r10, [%[b], #136]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #128]\n\t"
        "strd	r5, r6, [%[r], #136]\n\t"
        "ldrd	r3, r4, [%[a], #144]\n\t"
        "ldrd	r5, r6, [%[a], #152]\n\t"
        "ldrd	r7, r8, [%[b], #144]\n\t"
        "ldrd	r9, r10, [%[b], #152]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #144]\n\t"
        "strd	r5, r6, [%[r], #152]\n\t"
        "ldrd	r3, r4, [%[a], #160]\n\t"
        "ldrd	r5, r6, [%[a], #168]\n\t"
        "ldrd	r7, r8, [%[b], #160]\n\t"
        "ldrd	r9, r10, [%[b], #168]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #160]\n\t"
        "strd	r5, r6, [%[r], #168]\n\t"
        "ldrd	r3, r4, [%[a], #176]\n\t"
        "ldrd	r5, r6, [%[a], #184]\n\t"
        "ldrd	r7, r8, [%[b], #176]\n\t"
        "ldrd	r9, r10, [%[b], #184]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #176]\n\t"
        "strd	r5, r6, [%[r], #184]\n\t"
        "ldrd	r3, r4, [%[a], #192]\n\t"
        "ldrd	r5, r6, [%[a], #200]\n\t"
        "ldrd	r7, r8, [%[b], #192]\n\t"
        "ldrd	r9, r10, [%[b], #200]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #192]\n\t"
        "strd	r5, r6, [%[r], #200]\n\t"
        "ldrd	r3, r4, [%[a], #208]\n\t"
        "ldrd	r5, r6, [%[a], #216]\n\t"
        "ldrd	r7, r8, [%[b], #208]\n\t"
        "ldrd	r9, r10, [%[b], #216]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #208]\n\t"
        "strd	r5, r6, [%[r], #216]\n\t"
        "ldrd	r3, r4, [%[a], #224]\n\t"
        "ldrd	r5, r6, [%[a], #232]\n\t"
        "ldrd	r7, r8, [%[b], #224]\n\t"
        "ldrd	r9, r10, [%[b], #232]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #224]\n\t"
        "strd	r5, r6, [%[r], #232]\n\t"
        "ldrd	r3, r4, [%[a], #240]\n\t"
        "ldrd	r5, r6, [%[a], #248]\n\t"
        "ldrd	r7, r8, [%[b], #240]\n\t"
        "ldrd	r9, r10, [%[b], #248]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #240]\n\t"
        "strd	r5, r6, [%[r], #248]\n\t"
        "ldrd	r3, r4, [%[a], #256]\n\t"
        "ldrd	r5, r6, [%[a], #264]\n\t"
        "ldrd	r7, r8, [%[b], #256]\n\t"
        "ldrd	r9, r10, [%[b], #264]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #256]\n\t"
        "strd	r5, r6, [%[r], #264]\n\t"
        "ldrd	r3, r4, [%[a], #272]\n\t"
        "ldrd	r5, r6, [%[a], #280]\n\t"
        "ldrd	r7, r8, [%[b], #272]\n\t"
        "ldrd	r9, r10, [%[b], #280]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #272]\n\t"
        "strd	r5, r6, [%[r], #280]\n\t"
        "ldrd	r3, r4, [%[a], #288]\n\t"
        "ldrd	r5, r6, [%[a], #296]\n\t"
        "ldrd	r7, r8, [%[b], #288]\n\t"
        "ldrd	r9, r10, [%[b], #296]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #288]\n\t"
        "strd	r5, r6, [%[r], #296]\n\t"
        "ldrd	r3, r4, [%[a], #304]\n\t"
        "ldrd	r5, r6, [%[a], #312]\n\t"
        "ldrd	r7, r8, [%[b], #304]\n\t"
        "ldrd	r9, r10, [%[b], #312]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #304]\n\t"
        "strd	r5, r6, [%[r], #312]\n\t"
        "ldrd	r3, r4, [%[a], #320]\n\t"
        "ldrd	r5, r6, [%[a], #328]\n\t"
        "ldrd	r7, r8, [%[b], #320]\n\t"
        "ldrd	r9, r10, [%[b], #328]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #320]\n\t"
        "strd	r5, r6, [%[r], #328]\n\t"
        "ldrd	r3, r4, [%[a], #336]\n\t"
        "ldrd	r5, r6, [%[a], #344]\n\t"
        "ldrd	r7, r8, [%[b], #336]\n\t"
        "ldrd	r9, r10, [%[b], #344]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #336]\n\t"
        "strd	r5, r6, [%[r], #344]\n\t"
        "ldrd	r3, r4, [%[a], #352]\n\t"
        "ldrd	r5, r6, [%[a], #360]\n\t"
        "ldrd	r7, r8, [%[b], #352]\n\t"
        "ldrd	r9, r10, [%[b], #360]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #352]\n\t"
        "strd	r5, r6, [%[r], #360]\n\t"
        "ldrd	r3, r4, [%[a], #368]\n\t"
        "ldrd	r5, r6, [%[a], #376]\n\t"
        "ldrd	r7, r8, [%[b], #368]\n\t"
        "ldrd	r9, r10, [%[b], #376]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #368]\n\t"
        "strd	r5, r6, [%[r], #376]\n\t"
        "sbc	%[c], %[c], #0\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
    );

    return c;
}

#endif /* WOLFSSL_SP_SMALL */
/* Divide the double width number (d1|d0) by the divisor. (d1|d0 / div)
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The divisor.
 * returns the result of the division.
 *
 * Note that this is an approximate div. It may give an answer 1 larger.
 */
static sp_digit div_3072_word_96(sp_digit d1, sp_digit d0, sp_digit div)
{
    sp_digit r = 0;

    __asm__ __volatile__ (
        "lsr	r5, %[div], #1\n\t"
        "add	r5, r5, #1\n\t"
        "mov	r6, %[d0]\n\t"
        "mov	r7, %[d1]\n\t"
        "# Do top 32\n\t"
        "subs	r8, r5, r7\n\t"
        "sbc	r8, r8, r8\n\t"
        "add	%[r], %[r], %[r]\n\t"
        "sub	%[r], %[r], r8\n\t"
        "and	r8, r8, r5\n\t"
        "subs	r7, r7, r8\n\t"
        "# Next 30 bits\n\t"
        "mov	r4, #29\n\t"
        "1:\n\t"
        "movs	r6, r6, lsl #1\n\t"
        "adc	r7, r7, r7\n\t"
        "subs	r8, r5, r7\n\t"
        "sbc	r8, r8, r8\n\t"
        "add	%[r], %[r], %[r]\n\t"
        "sub	%[r], %[r], r8\n\t"
        "and	r8, r8, r5\n\t"
        "subs	r7, r7, r8\n\t"
        "subs	r4, r4, #1\n\t"
        "bpl	1b\n\t"
        "add	%[r], %[r], %[r]\n\t"
        "add	%[r], %[r], #1\n\t"
        "umull	r4, r5, %[r], %[div]\n\t"
        "subs	r4, %[d0], r4\n\t"
        "sbc	r5, %[d1], r5\n\t"
        "add	%[r], %[r], r5\n\t"
        "umull	r4, r5, %[r], %[div]\n\t"
        "subs	r4, %[d0], r4\n\t"
        "sbc	r5, %[d1], r5\n\t"
        "add	%[r], %[r], r5\n\t"
        "umull	r4, r5, %[r], %[div]\n\t"
        "subs	r4, %[d0], r4\n\t"
        "sbc	r5, %[d1], r5\n\t"
        "add	%[r], %[r], r5\n\t"
        "subs	r8, %[div], r4\n\t"
        "sbc	r8, r8, r8\n\t"
        "sub	%[r], %[r], r8\n\t"
        : [r] "+r" (r)
        : [d1] "r" (d1), [d0] "r" (d0), [div] "r" (div)
        : "r4", "r5", "r6", "r7", "r8"
    );
    return r;
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
static WC_INLINE int sp_3072_div_96_cond(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    sp_digit t1[192], t2[97];
    sp_digit div, r1;
    int i;

    (void)m;

    div = d[95];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 96);
    for (i = 95; i >= 0; i--) {
        if (t1[96 + i] == div) {
            r1 = SP_DIGIT_MAX;
        }
        else {
            r1 = div_3072_word_96(t1[96 + i], t1[96 + i - 1], div);
        }

        sp_3072_mul_d_96(t2, d, r1);
        t1[96 + i] += sp_3072_sub_in_place_96(&t1[i], t2);
        t1[96 + i] -= t2[96];
        if (t1[96 + i] != 0) {
            t1[96 + i] += sp_3072_add_96(&t1[i], &t1[i], d);
            if (t1[96 + i] != 0)
                t1[96 + i] += sp_3072_add_96(&t1[i], &t1[i], d);
        }
    }

    for (i = 95; i > 0; i--) {
        if (t1[i] != d[i])
            break;
    }
    if (t1[i] >= d[i]) {
        sp_3072_sub_96(r, t1, d);
    }
    else {
        XMEMCPY(r, t1, sizeof(*t1) * 96);
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
static WC_INLINE int sp_3072_mod_96_cond(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_3072_div_96_cond(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
#if defined(WOLFSSL_HAVE_SP_DH) || !defined(WOLFSSL_RSA_PUBLIC_ONLY)
/* AND m into each word of a and store in r.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * m  Mask to AND against each digit.
 */
static void sp_3072_mask_96(sp_digit* r, const sp_digit* a, sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<96; i++) {
        r[i] = a[i] & m;
    }
#else
    int i;

    for (i = 0; i < 96; i += 8) {
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
static sp_int32 sp_3072_cmp_96(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = -1;
    sp_digit one = 1;


#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "mov	r7, #0\n\t"
        "mov	r3, #-1\n\t"
        "mov	r6, #380\n\t"
        "1:\n\t"
        "ldr	r4, [%[a], r6]\n\t"
        "ldr	r5, [%[b], r6]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "subs	r6, r6, #4\n\t"
        "bcs	1b\n\t"
        "eor	%[r], %[r], r3\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [one] "r" (one)
        : "r3", "r4", "r5", "r6", "r7"
    );
#else
    __asm__ __volatile__ (
        "mov	r7, #0\n\t"
        "mov	r3, #-1\n\t"
        "ldr	r4, [%[a], #380]\n\t"
        "ldr	r5, [%[b], #380]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #376]\n\t"
        "ldr	r5, [%[b], #376]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #372]\n\t"
        "ldr	r5, [%[b], #372]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #368]\n\t"
        "ldr	r5, [%[b], #368]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #364]\n\t"
        "ldr	r5, [%[b], #364]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #360]\n\t"
        "ldr	r5, [%[b], #360]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #356]\n\t"
        "ldr	r5, [%[b], #356]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #352]\n\t"
        "ldr	r5, [%[b], #352]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #348]\n\t"
        "ldr	r5, [%[b], #348]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #344]\n\t"
        "ldr	r5, [%[b], #344]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #340]\n\t"
        "ldr	r5, [%[b], #340]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #336]\n\t"
        "ldr	r5, [%[b], #336]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #332]\n\t"
        "ldr	r5, [%[b], #332]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #328]\n\t"
        "ldr	r5, [%[b], #328]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #324]\n\t"
        "ldr	r5, [%[b], #324]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #320]\n\t"
        "ldr	r5, [%[b], #320]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #316]\n\t"
        "ldr	r5, [%[b], #316]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #312]\n\t"
        "ldr	r5, [%[b], #312]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #308]\n\t"
        "ldr	r5, [%[b], #308]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #304]\n\t"
        "ldr	r5, [%[b], #304]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #300]\n\t"
        "ldr	r5, [%[b], #300]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #296]\n\t"
        "ldr	r5, [%[b], #296]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #292]\n\t"
        "ldr	r5, [%[b], #292]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #288]\n\t"
        "ldr	r5, [%[b], #288]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #284]\n\t"
        "ldr	r5, [%[b], #284]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #280]\n\t"
        "ldr	r5, [%[b], #280]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #276]\n\t"
        "ldr	r5, [%[b], #276]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #272]\n\t"
        "ldr	r5, [%[b], #272]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #268]\n\t"
        "ldr	r5, [%[b], #268]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #264]\n\t"
        "ldr	r5, [%[b], #264]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #260]\n\t"
        "ldr	r5, [%[b], #260]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #256]\n\t"
        "ldr	r5, [%[b], #256]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #252]\n\t"
        "ldr	r5, [%[b], #252]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #248]\n\t"
        "ldr	r5, [%[b], #248]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #244]\n\t"
        "ldr	r5, [%[b], #244]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #240]\n\t"
        "ldr	r5, [%[b], #240]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #236]\n\t"
        "ldr	r5, [%[b], #236]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #232]\n\t"
        "ldr	r5, [%[b], #232]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #228]\n\t"
        "ldr	r5, [%[b], #228]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #224]\n\t"
        "ldr	r5, [%[b], #224]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #220]\n\t"
        "ldr	r5, [%[b], #220]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #216]\n\t"
        "ldr	r5, [%[b], #216]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #212]\n\t"
        "ldr	r5, [%[b], #212]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #208]\n\t"
        "ldr	r5, [%[b], #208]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #204]\n\t"
        "ldr	r5, [%[b], #204]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #200]\n\t"
        "ldr	r5, [%[b], #200]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #196]\n\t"
        "ldr	r5, [%[b], #196]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #192]\n\t"
        "ldr	r5, [%[b], #192]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #188]\n\t"
        "ldr	r5, [%[b], #188]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #184]\n\t"
        "ldr	r5, [%[b], #184]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #180]\n\t"
        "ldr	r5, [%[b], #180]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #176]\n\t"
        "ldr	r5, [%[b], #176]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #172]\n\t"
        "ldr	r5, [%[b], #172]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #168]\n\t"
        "ldr	r5, [%[b], #168]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #164]\n\t"
        "ldr	r5, [%[b], #164]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #160]\n\t"
        "ldr	r5, [%[b], #160]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #156]\n\t"
        "ldr	r5, [%[b], #156]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #152]\n\t"
        "ldr	r5, [%[b], #152]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #148]\n\t"
        "ldr	r5, [%[b], #148]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #144]\n\t"
        "ldr	r5, [%[b], #144]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #140]\n\t"
        "ldr	r5, [%[b], #140]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #136]\n\t"
        "ldr	r5, [%[b], #136]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #132]\n\t"
        "ldr	r5, [%[b], #132]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #128]\n\t"
        "ldr	r5, [%[b], #128]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #124]\n\t"
        "ldr	r5, [%[b], #124]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #120]\n\t"
        "ldr	r5, [%[b], #120]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #116]\n\t"
        "ldr	r5, [%[b], #116]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #112]\n\t"
        "ldr	r5, [%[b], #112]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #108]\n\t"
        "ldr	r5, [%[b], #108]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #104]\n\t"
        "ldr	r5, [%[b], #104]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #100]\n\t"
        "ldr	r5, [%[b], #100]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #96]\n\t"
        "ldr	r5, [%[b], #96]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #92]\n\t"
        "ldr	r5, [%[b], #92]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #88]\n\t"
        "ldr	r5, [%[b], #88]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #84]\n\t"
        "ldr	r5, [%[b], #84]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #80]\n\t"
        "ldr	r5, [%[b], #80]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #76]\n\t"
        "ldr	r5, [%[b], #76]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #72]\n\t"
        "ldr	r5, [%[b], #72]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #68]\n\t"
        "ldr	r5, [%[b], #68]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #64]\n\t"
        "ldr	r5, [%[b], #64]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #60]\n\t"
        "ldr	r5, [%[b], #60]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #56]\n\t"
        "ldr	r5, [%[b], #56]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #52]\n\t"
        "ldr	r5, [%[b], #52]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #48]\n\t"
        "ldr	r5, [%[b], #48]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #44]\n\t"
        "ldr	r5, [%[b], #44]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #40]\n\t"
        "ldr	r5, [%[b], #40]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #36]\n\t"
        "ldr	r5, [%[b], #36]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #32]\n\t"
        "ldr	r5, [%[b], #32]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #28]\n\t"
        "ldr	r5, [%[b], #28]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #24]\n\t"
        "ldr	r5, [%[b], #24]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #20]\n\t"
        "ldr	r5, [%[b], #20]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #16]\n\t"
        "ldr	r5, [%[b], #16]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #12]\n\t"
        "ldr	r5, [%[b], #12]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #8]\n\t"
        "ldr	r5, [%[b], #8]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #4]\n\t"
        "ldr	r5, [%[b], #4]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #0]\n\t"
        "ldr	r5, [%[b], #0]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "eor	%[r], %[r], r3\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [one] "r" (one)
        : "r3", "r4", "r5", "r6", "r7"
    );
#endif

    return r;
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
static WC_INLINE int sp_3072_div_96(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    sp_digit t1[192], t2[97];
    sp_digit div, r1;
    int i;

    (void)m;

    div = d[95];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 96);
    for (i = 95; i >= 0; i--) {
        sp_digit hi = t1[96 + i] - (t1[96 + i] == div);
        r1 = div_3072_word_96(hi, t1[96 + i - 1], div);

        sp_3072_mul_d_96(t2, d, r1);
        t1[96 + i] += sp_3072_sub_in_place_96(&t1[i], t2);
        t1[96 + i] -= t2[96];
        sp_3072_mask_96(t2, d, t1[96 + i]);
        t1[96 + i] += sp_3072_add_96(&t1[i], &t1[i], t2);
        sp_3072_mask_96(t2, d, t1[96 + i]);
        t1[96 + i] += sp_3072_add_96(&t1[i], &t1[i], t2);
    }

    r1 = sp_3072_cmp_96(t1, d) >= 0;
    sp_3072_cond_sub_96(r, t1, d, (sp_digit)0 - r1);

    return MP_OKAY;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_3072_mod_96(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_3072_div_96(a, m, NULL, r);
}

#endif /* WOLFSSL_HAVE_SP_DH || !WOLFSSL_RSA_PUBLIC_ONLY */
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
static int sp_3072_mod_exp_96(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[8 * 192];
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
            t[i] = td + i * 192;
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_96(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 96U);
        if (reduceA != 0) {
            err = sp_3072_mod_96(t[1] + 96, a, m);
            if (err == MP_OKAY) {
                err = sp_3072_mod_96(t[1], t[1], m);
            }
        }
        else {
            XMEMCPY(t[1] + 96, a, sizeof(sp_digit) * 96);
            err = sp_3072_mod_96(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_3072_mont_sqr_96(t[ 2], t[ 1], m, mp);
        sp_3072_mont_mul_96(t[ 3], t[ 2], t[ 1], m, mp);
        sp_3072_mont_sqr_96(t[ 4], t[ 2], m, mp);
        sp_3072_mont_mul_96(t[ 5], t[ 3], t[ 2], m, mp);
        sp_3072_mont_sqr_96(t[ 6], t[ 3], m, mp);
        sp_3072_mont_mul_96(t[ 7], t[ 4], t[ 3], m, mp);

        i = (bits - 1) / 32;
        n = e[i--];
        c = bits & 31;
        if (c == 0) {
            c = 32;
        }
        c -= bits % 3;
        if (c == 32) {
            c = 29;
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
            n <<= 32 - c;
        }
        XMEMCPY(r, t[y], sizeof(sp_digit) * 96);
        for (; i>=0 || c>=3; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 29);
                n <<= 3;
                c = 29;
            }
            else if (c < 3) {
                y = (byte)(n >> 29);
                n = e[i--];
                c = 3 - c;
                y |= (byte)(n >> (32 - c));
                n <<= c;
                c = 32 - c;
            }
            else {
                y = (byte)((n >> 29) & 0x7);
                n <<= 3;
                c -= 3;
            }

            sp_3072_mont_sqr_96(r, r, m, mp);
            sp_3072_mont_sqr_96(r, r, m, mp);
            sp_3072_mont_sqr_96(r, r, m, mp);

            sp_3072_mont_mul_96(r, r, t[y], m, mp);
        }

        XMEMSET(&r[96], 0, sizeof(sp_digit) * 96U);
        sp_3072_mont_reduce_96(r, m, mp);

        mask = 0 - (sp_3072_cmp_96(r, m) >= 0);
        sp_3072_cond_sub_96(r, r, m, mask);
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
static int sp_3072_mod_exp_96(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[16 * 192];
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
            t[i] = td + i * 192;
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_96(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 96U);
        if (reduceA != 0) {
            err = sp_3072_mod_96(t[1] + 96, a, m);
            if (err == MP_OKAY) {
                err = sp_3072_mod_96(t[1], t[1], m);
            }
        }
        else {
            XMEMCPY(t[1] + 96, a, sizeof(sp_digit) * 96);
            err = sp_3072_mod_96(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_3072_mont_sqr_96(t[ 2], t[ 1], m, mp);
        sp_3072_mont_mul_96(t[ 3], t[ 2], t[ 1], m, mp);
        sp_3072_mont_sqr_96(t[ 4], t[ 2], m, mp);
        sp_3072_mont_mul_96(t[ 5], t[ 3], t[ 2], m, mp);
        sp_3072_mont_sqr_96(t[ 6], t[ 3], m, mp);
        sp_3072_mont_mul_96(t[ 7], t[ 4], t[ 3], m, mp);
        sp_3072_mont_sqr_96(t[ 8], t[ 4], m, mp);
        sp_3072_mont_mul_96(t[ 9], t[ 5], t[ 4], m, mp);
        sp_3072_mont_sqr_96(t[10], t[ 5], m, mp);
        sp_3072_mont_mul_96(t[11], t[ 6], t[ 5], m, mp);
        sp_3072_mont_sqr_96(t[12], t[ 6], m, mp);
        sp_3072_mont_mul_96(t[13], t[ 7], t[ 6], m, mp);
        sp_3072_mont_sqr_96(t[14], t[ 7], m, mp);
        sp_3072_mont_mul_96(t[15], t[ 8], t[ 7], m, mp);

        i = (bits - 1) / 32;
        n = e[i--];
        c = bits & 31;
        if (c == 0) {
            c = 32;
        }
        c -= bits % 4;
        if (c == 32) {
            c = 28;
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
            n <<= 32 - c;
        }
        XMEMCPY(r, t[y], sizeof(sp_digit) * 96);
        for (; i>=0 || c>=4; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 28);
                n <<= 4;
                c = 28;
            }
            else if (c < 4) {
                y = (byte)(n >> 28);
                n = e[i--];
                c = 4 - c;
                y |= (byte)(n >> (32 - c));
                n <<= c;
                c = 32 - c;
            }
            else {
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c -= 4;
            }

            sp_3072_mont_sqr_96(r, r, m, mp);
            sp_3072_mont_sqr_96(r, r, m, mp);
            sp_3072_mont_sqr_96(r, r, m, mp);
            sp_3072_mont_sqr_96(r, r, m, mp);

            sp_3072_mont_mul_96(r, r, t[y], m, mp);
        }

        XMEMSET(&r[96], 0, sizeof(sp_digit) * 96U);
        sp_3072_mont_reduce_96(r, m, mp);

        mask = 0 - (sp_3072_cmp_96(r, m) >= 0);
        sp_3072_cond_sub_96(r, r, m, mask);
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
    sp_digit a[96 * 5];
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit *ah = NULL;
    sp_digit e[1] = {0};
    int err = MP_OKAY;

    if (*outLen < 384) {
        err = MP_TO_E;
    }
    else if (mp_count_bits(em) > 32 || inLen > 384 ||
                                                     mp_count_bits(mm) != 3072) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mm)) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        ah = a + 96;
        r = a + 96 * 2;
        m = r + 96 * 2;

        sp_3072_from_bin(ah, 96, in, inLen);
#if DIGIT_BIT >= 32
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
        sp_3072_from_mp(m, 96, mm);

        if (e[0] == 0x10001) {
            int i;
            sp_digit mp;

            sp_3072_mont_setup(m, &mp);

            /* Convert to Montgomery form. */
            XMEMSET(a, 0, sizeof(sp_digit) * 96);
            err = sp_3072_mod_96_cond(r, a, m);
            /* Montgomery form: r = a.R mod m */

            if (err == MP_OKAY) {
                /* r = a ^ 0x10000 => r = a squared 16 times */
                for (i = 15; i >= 0; i--) {
                    sp_3072_mont_sqr_96(r, r, m, mp);
                }
                /* mont_red(r.R.R) = (r.R.R / R) mod m = r.R mod m
                 * mont_red(r.R * a) = (r.R.a / R) mod m = r.a mod m
                 */
                sp_3072_mont_mul_96(r, r, ah, m, mp);

                for (i = 95; i > 0; i--) {
                    if (r[i] != m[i]) {
                        break;
                    }
                }
                if (r[i] >= m[i]) {
                    sp_3072_sub_in_place_96(r, m);
                }
            }
        }
        else if (e[0] == 0x3) {
            if (err == MP_OKAY) {
                sp_3072_sqr_96(r, ah);
                err = sp_3072_mod_96_cond(r, r, m);
            }
            if (err == MP_OKAY) {
                sp_3072_mul_96(r, ah, r);
                err = sp_3072_mod_96_cond(r, r, m);
            }
        }
        else {
            int i;
            sp_digit mp;

            sp_3072_mont_setup(m, &mp);

            /* Convert to Montgomery form. */
            XMEMSET(a, 0, sizeof(sp_digit) * 96);
            err = sp_3072_mod_96_cond(a, a, m);

            if (err == MP_OKAY) {
                for (i = 31; i >= 0; i--) {
                    if (e[0] >> i) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 96);
                for (i--; i >= 0; i--) {
                    sp_3072_mont_sqr_96(r, r, m, mp);
                    if (((e[0] >> i) & 1) == 1) {
                        sp_3072_mont_mul_96(r, r, a, m, mp);
                    }
                }
                XMEMSET(&r[96], 0, sizeof(sp_digit) * 96);
                sp_3072_mont_reduce_96(r, m, mp);

                for (i = 95; i > 0; i--) {
                    if (r[i] != m[i]) {
                        break;
                    }
                }
                if (r[i] >= m[i]) {
                    sp_3072_sub_in_place_96(r, m);
                }
            }
        }
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_96(r, out);
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
static sp_digit sp_3072_cond_add_48(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r7, #0\n\t"
        "mov	r6, #0\n\t"
        "1:\n\t"
        "adds	%[c], %[c], #-1\n\t"
        "ldr	r4, [%[a], r6]\n\t"
        "ldr	r5, [%[b], r6]\n\t"
        "and	r5, r5, %[m]\n\t"
        "adcs	r4, r4, r5\n\t"
        "adc	%[c], r7, r7\n\t"
        "str	r4, [%[r], r6]\n\t"
        "add	r6, r6, #4\n\t"
        "cmp	r6, #192\n\t"
        "blt	1b\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r4", "r5", "r6", "r7"
    );

    return c;
}
#endif /* WOLFSSL_SP_SMALL */

#ifndef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static sp_digit sp_3072_cond_add_48(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    sp_digit c = 0;

    __asm__ __volatile__ (

        "mov	r8, #0\n\t"
        "ldrd	r4, r5, [%[a], #0]\n\t"
        "ldrd	r6, r7, [%[b], #0]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #0]\n\t"
        "ldrd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r6, r7, [%[b], #8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #8]\n\t"
        "ldrd	r4, r5, [%[a], #16]\n\t"
        "ldrd	r6, r7, [%[b], #16]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #16]\n\t"
        "ldrd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r6, r7, [%[b], #24]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #24]\n\t"
        "ldrd	r4, r5, [%[a], #32]\n\t"
        "ldrd	r6, r7, [%[b], #32]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #32]\n\t"
        "ldrd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r6, r7, [%[b], #40]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #40]\n\t"
        "ldrd	r4, r5, [%[a], #48]\n\t"
        "ldrd	r6, r7, [%[b], #48]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #48]\n\t"
        "ldrd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r6, r7, [%[b], #56]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #56]\n\t"
        "ldrd	r4, r5, [%[a], #64]\n\t"
        "ldrd	r6, r7, [%[b], #64]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #64]\n\t"
        "ldrd	r4, r5, [%[a], #72]\n\t"
        "ldrd	r6, r7, [%[b], #72]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #72]\n\t"
        "ldrd	r4, r5, [%[a], #80]\n\t"
        "ldrd	r6, r7, [%[b], #80]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #80]\n\t"
        "ldrd	r4, r5, [%[a], #88]\n\t"
        "ldrd	r6, r7, [%[b], #88]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #88]\n\t"
        "ldrd	r4, r5, [%[a], #96]\n\t"
        "ldrd	r6, r7, [%[b], #96]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #96]\n\t"
        "ldrd	r4, r5, [%[a], #104]\n\t"
        "ldrd	r6, r7, [%[b], #104]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #104]\n\t"
        "ldrd	r4, r5, [%[a], #112]\n\t"
        "ldrd	r6, r7, [%[b], #112]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #112]\n\t"
        "ldrd	r4, r5, [%[a], #120]\n\t"
        "ldrd	r6, r7, [%[b], #120]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #120]\n\t"
        "ldrd	r4, r5, [%[a], #128]\n\t"
        "ldrd	r6, r7, [%[b], #128]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #128]\n\t"
        "ldrd	r4, r5, [%[a], #136]\n\t"
        "ldrd	r6, r7, [%[b], #136]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #136]\n\t"
        "ldrd	r4, r5, [%[a], #144]\n\t"
        "ldrd	r6, r7, [%[b], #144]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #144]\n\t"
        "ldrd	r4, r5, [%[a], #152]\n\t"
        "ldrd	r6, r7, [%[b], #152]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #152]\n\t"
        "ldrd	r4, r5, [%[a], #160]\n\t"
        "ldrd	r6, r7, [%[b], #160]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #160]\n\t"
        "ldrd	r4, r5, [%[a], #168]\n\t"
        "ldrd	r6, r7, [%[b], #168]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #168]\n\t"
        "ldrd	r4, r5, [%[a], #176]\n\t"
        "ldrd	r6, r7, [%[b], #176]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #176]\n\t"
        "ldrd	r4, r5, [%[a], #184]\n\t"
        "ldrd	r6, r7, [%[b], #184]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #184]\n\t"
        "adc	%[c], r8, r8\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r4", "r5", "r6", "r7", "r8"
    );

    return c;
}
#endif /* !WOLFSSL_SP_SMALL */

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
    sp_digit  d[96 * 4];
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
        a = d + 96;
        m = a + 192;
        r = a;

        sp_3072_from_bin(a, 96, in, inLen);
        sp_3072_from_mp(d, 96, dm);
        sp_3072_from_mp(m, 96, mm);
        err = sp_3072_mod_exp_96(r, a, d, 3072, m, 0);
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_96(r, out);
        *outLen = 384;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 96);
    }

    return err;
#else
    sp_digit a[48 * 11];
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
        p = a + 96 * 2;
        q = p + 48;
        qi = dq = dp = q + 48;
        tmpa = qi + 48;
        tmpb = tmpa + 96;
        r = a;

        sp_3072_from_bin(a, 96, in, inLen);
        sp_3072_from_mp(p, 48, pm);
        sp_3072_from_mp(q, 48, qm);
        sp_3072_from_mp(dp, 48, dpm);

        err = sp_3072_mod_exp_48(tmpa, a, dp, 1536, p, 1);
    }
    if (err == MP_OKAY) {
        sp_3072_from_mp(dq, 48, dqm);
        err = sp_3072_mod_exp_48(tmpb, a, dq, 1536, q, 1);
    }

    if (err == MP_OKAY) {
        c = sp_3072_sub_in_place_48(tmpa, tmpb);
        c += sp_3072_cond_add_48(tmpa, tmpa, p, c);
        sp_3072_cond_add_48(tmpa, tmpa, p, c);

        sp_3072_from_mp(qi, 48, qim);
        sp_3072_mul_48(tmpa, tmpa, qi);
        err = sp_3072_mod_48(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_3072_mul_48(tmpa, q, tmpa);
        XMEMSET(&tmpb[48], 0, sizeof(sp_digit) * 48);
        sp_3072_add_96(r, tmpb, tmpa);

        sp_3072_to_bin_96(r, out);
        *outLen = 384;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 48 * 11);
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
#if DIGIT_BIT == 32
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 96);
        r->used = 96;
        mp_clamp(r);
#elif DIGIT_BIT < 32
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 96; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 32) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 32 - s;
        }
        r->used = (3072 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 96; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 32 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 32 - s;
            }
            else {
                s += 32;
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
    sp_digit b[192];
    sp_digit e[96];
    sp_digit m[96];
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
        sp_3072_from_mp(b, 96, base);
        sp_3072_from_mp(e, 96, exp);
        sp_3072_from_mp(m, 96, mod);

        err = sp_3072_mod_exp_96(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_3072_to_mp(r, res);
    }

    XMEMSET(e, 0, sizeof(e));

    return err;
}

#ifdef WOLFSSL_HAVE_SP_DH

#ifdef HAVE_FFDHE_3072
static void sp_3072_lshift_96(sp_digit* r, const sp_digit* a, byte n)
{
    __asm__ __volatile__ (
        "rsb	r6, %[n], #31\n\t"
        "ldr	r3, [%[a], #380]\n\t"
        "lsr	r4, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r4, r4, r6\n\t"
        "ldr	r2, [%[a], #376]\n\t"
        "str	r4, [%[r], #384]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #372]\n\t"
        "str	r3, [%[r], #380]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #368]\n\t"
        "str	r2, [%[r], #376]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #364]\n\t"
        "str	r4, [%[r], #372]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #360]\n\t"
        "str	r3, [%[r], #368]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #356]\n\t"
        "str	r2, [%[r], #364]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #352]\n\t"
        "str	r4, [%[r], #360]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #348]\n\t"
        "str	r3, [%[r], #356]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #344]\n\t"
        "str	r2, [%[r], #352]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #340]\n\t"
        "str	r4, [%[r], #348]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #336]\n\t"
        "str	r3, [%[r], #344]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #332]\n\t"
        "str	r2, [%[r], #340]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #328]\n\t"
        "str	r4, [%[r], #336]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #324]\n\t"
        "str	r3, [%[r], #332]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #320]\n\t"
        "str	r2, [%[r], #328]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #316]\n\t"
        "str	r4, [%[r], #324]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #312]\n\t"
        "str	r3, [%[r], #320]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #308]\n\t"
        "str	r2, [%[r], #316]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #304]\n\t"
        "str	r4, [%[r], #312]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #300]\n\t"
        "str	r3, [%[r], #308]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #296]\n\t"
        "str	r2, [%[r], #304]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #292]\n\t"
        "str	r4, [%[r], #300]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #288]\n\t"
        "str	r3, [%[r], #296]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #284]\n\t"
        "str	r2, [%[r], #292]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #280]\n\t"
        "str	r4, [%[r], #288]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #276]\n\t"
        "str	r3, [%[r], #284]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #272]\n\t"
        "str	r2, [%[r], #280]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #268]\n\t"
        "str	r4, [%[r], #276]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #264]\n\t"
        "str	r3, [%[r], #272]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #260]\n\t"
        "str	r2, [%[r], #268]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #256]\n\t"
        "str	r4, [%[r], #264]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #252]\n\t"
        "str	r3, [%[r], #260]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #248]\n\t"
        "str	r2, [%[r], #256]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #244]\n\t"
        "str	r4, [%[r], #252]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #240]\n\t"
        "str	r3, [%[r], #248]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #236]\n\t"
        "str	r2, [%[r], #244]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #232]\n\t"
        "str	r4, [%[r], #240]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #228]\n\t"
        "str	r3, [%[r], #236]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #224]\n\t"
        "str	r2, [%[r], #232]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #220]\n\t"
        "str	r4, [%[r], #228]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #216]\n\t"
        "str	r3, [%[r], #224]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #212]\n\t"
        "str	r2, [%[r], #220]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #208]\n\t"
        "str	r4, [%[r], #216]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #204]\n\t"
        "str	r3, [%[r], #212]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #200]\n\t"
        "str	r2, [%[r], #208]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #196]\n\t"
        "str	r4, [%[r], #204]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #192]\n\t"
        "str	r3, [%[r], #200]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #188]\n\t"
        "str	r2, [%[r], #196]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #184]\n\t"
        "str	r4, [%[r], #192]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #180]\n\t"
        "str	r3, [%[r], #188]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #176]\n\t"
        "str	r2, [%[r], #184]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #172]\n\t"
        "str	r4, [%[r], #180]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #168]\n\t"
        "str	r3, [%[r], #176]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #164]\n\t"
        "str	r2, [%[r], #172]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #160]\n\t"
        "str	r4, [%[r], #168]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #156]\n\t"
        "str	r3, [%[r], #164]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #152]\n\t"
        "str	r2, [%[r], #160]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #148]\n\t"
        "str	r4, [%[r], #156]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #144]\n\t"
        "str	r3, [%[r], #152]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #140]\n\t"
        "str	r2, [%[r], #148]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #136]\n\t"
        "str	r4, [%[r], #144]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #132]\n\t"
        "str	r3, [%[r], #140]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #128]\n\t"
        "str	r2, [%[r], #136]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #124]\n\t"
        "str	r4, [%[r], #132]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #120]\n\t"
        "str	r3, [%[r], #128]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #116]\n\t"
        "str	r2, [%[r], #124]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #112]\n\t"
        "str	r4, [%[r], #120]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #108]\n\t"
        "str	r3, [%[r], #116]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #104]\n\t"
        "str	r2, [%[r], #112]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #100]\n\t"
        "str	r4, [%[r], #108]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #96]\n\t"
        "str	r3, [%[r], #104]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #92]\n\t"
        "str	r2, [%[r], #100]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #88]\n\t"
        "str	r4, [%[r], #96]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #84]\n\t"
        "str	r3, [%[r], #92]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #80]\n\t"
        "str	r2, [%[r], #88]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #76]\n\t"
        "str	r4, [%[r], #84]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #72]\n\t"
        "str	r3, [%[r], #80]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #68]\n\t"
        "str	r2, [%[r], #76]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #64]\n\t"
        "str	r4, [%[r], #72]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #60]\n\t"
        "str	r3, [%[r], #68]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #56]\n\t"
        "str	r2, [%[r], #64]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #52]\n\t"
        "str	r4, [%[r], #60]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #48]\n\t"
        "str	r3, [%[r], #56]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #44]\n\t"
        "str	r2, [%[r], #52]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #40]\n\t"
        "str	r4, [%[r], #48]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #36]\n\t"
        "str	r3, [%[r], #44]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #32]\n\t"
        "str	r2, [%[r], #40]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #28]\n\t"
        "str	r4, [%[r], #36]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #24]\n\t"
        "str	r3, [%[r], #32]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #20]\n\t"
        "str	r2, [%[r], #28]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #16]\n\t"
        "str	r4, [%[r], #24]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #12]\n\t"
        "str	r3, [%[r], #20]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #8]\n\t"
        "str	r2, [%[r], #16]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #4]\n\t"
        "str	r4, [%[r], #12]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #0]\n\t"
        "str	r3, [%[r], #8]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "strd	r4, r2, [%[r]]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [n] "r" (n)
        : "memory", "r2", "r3", "r4", "r5", "r6"
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
static int sp_3072_mod_exp_2_96(sp_digit* r, const sp_digit* e, int bits,
        const sp_digit* m)
{
    sp_digit td[289];
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
        tmp = td + 192;

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_96(norm, m);

        i = (bits - 1) / 32;
        n = e[i--];
        c = bits & 31;
        if (c == 0) {
            c = 32;
        }
        c -= bits % 5;
        if (c == 32) {
            c = 27;
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
            n <<= 32 - c;
        }
        sp_3072_lshift_96(r, norm, y);
        for (; i>=0 || c>=5; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 27);
                n <<= 5;
                c = 27;
            }
            else if (c < 5) {
                y = (byte)(n >> 27);
                n = e[i--];
                c = 5 - c;
                y |= (byte)(n >> (32 - c));
                n <<= c;
                c = 32 - c;
            }
            else {
                y = (byte)((n >> 27) & 0x1f);
                n <<= 5;
                c -= 5;
            }

            sp_3072_mont_sqr_96(r, r, m, mp);
            sp_3072_mont_sqr_96(r, r, m, mp);
            sp_3072_mont_sqr_96(r, r, m, mp);
            sp_3072_mont_sqr_96(r, r, m, mp);
            sp_3072_mont_sqr_96(r, r, m, mp);

            sp_3072_lshift_96(r, r, y);
            sp_3072_mul_d_96(tmp, norm, r[96]);
            r[96] = 0;
            o = sp_3072_add_96(r, r, tmp);
            sp_3072_cond_sub_96(r, r, m, (sp_digit)0 - o);
        }

        XMEMSET(&r[96], 0, sizeof(sp_digit) * 96U);
        sp_3072_mont_reduce_96(r, m, mp);

        mask = 0 - (sp_3072_cmp_96(r, m) >= 0);
        sp_3072_cond_sub_96(r, r, m, mask);
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
    sp_digit b[192];
    sp_digit e[96];
    sp_digit m[96];
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
        sp_3072_from_mp(b, 96, base);
        sp_3072_from_bin(e, 96, exp, expLen);
        sp_3072_from_mp(m, 96, mod);

    #ifdef HAVE_FFDHE_3072
        if (base->used == 1 && base->dp[0] == 2 && m[95] == (sp_digit)-1)
            err = sp_3072_mod_exp_2_96(r, e, expLen * 8, m);
        else
    #endif
            err = sp_3072_mod_exp_96(r, b, e, expLen * 8, m, 0);

    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_96(r, out);
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
    sp_digit b[96];
    sp_digit e[48];
    sp_digit m[48];
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
        sp_3072_from_mp(b, 48, base);
        sp_3072_from_mp(e, 48, exp);
        sp_3072_from_mp(m, 48, mod);

        err = sp_3072_mod_exp_48(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 48, 0, sizeof(*r) * 48U);
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
    int i;
    int j;
    byte* d;

    for (i = n - 1,j = 0; i >= 3; i -= 4) {
        r[j]  = ((sp_digit)a[i - 0] <<  0) |
                ((sp_digit)a[i - 1] <<  8) |
                ((sp_digit)a[i - 2] << 16) |
                ((sp_digit)a[i - 3] << 24);
        j++;
    }

    if (i >= 0) {
        r[j] = 0;

        d = (byte*)r;
        switch (i) {
            case 2: d[n - 1 - 2] = a[2]; //fallthrough
            case 1: d[n - 1 - 1] = a[1]; //fallthrough
            case 0: d[n - 1 - 0] = a[0]; //fallthrough
        }
        j++;
    }

    for (; j < size; j++) {
        r[j] = 0;
    }
}

/* Convert an mp_int to an array of sp_digit.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  A multi-precision integer.
 */
static void sp_4096_from_mp(sp_digit* r, int size, const mp_int* a)
{
#if DIGIT_BIT == 32
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 32
    int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0xffffffff;
        s = 32U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 32U) <= (word32)DIGIT_BIT) {
            s += 32U;
            r[j] &= 0xffffffff;
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
        if (s + DIGIT_BIT >= 32) {
            r[j] &= 0xffffffff;
            if (j + 1 >= size) {
                break;
            }
            s = 32 - s;
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
static void sp_4096_to_bin_128(sp_digit* r, byte* a)
{
    int i;
    int j = 0;

    for (i = 127; i >= 0; i--) {
        a[j++] = r[i] >> 24;
        a[j++] = r[i] >> 16;
        a[j++] = r[i] >> 8;
        a[j++] = r[i] >> 0;
    }
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && (!defined(WOLFSSL_RSA_PUBLIC_ONLY) || !defined(WOLFSSL_SP_SMALL))) || defined(WOLFSSL_HAVE_SP_DH)
/* Normalize the values in each word to 32.
 *
 * a  Array of sp_digit to normalize.
 */
#define sp_4096_norm_128(a)

#endif /* (WOLFSSL_HAVE_SP_RSA && (!WOLFSSL_RSA_PUBLIC_ONLY || !WOLFSSL_SP_SMALL)) || WOLFSSL_HAVE_SP_DH */
/* Normalize the values in each word to 32.
 *
 * a  Array of sp_digit to normalize.
 */
#define sp_4096_norm_128(a)

#ifndef WOLFSSL_SP_SMALL
/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer and result.
 * b  A single precision integer.
 */
static sp_digit sp_4096_sub_in_place_128(sp_digit* a, const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldrd	r2, r3, [%[a], #0]\n\t"
        "ldrd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r6, r7, [%[b], #0]\n\t"
        "ldrd	r8, r9, [%[b], #8]\n\t"
        "subs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #0]\n\t"
        "strd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r2, r3, [%[a], #16]\n\t"
        "ldrd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r6, r7, [%[b], #16]\n\t"
        "ldrd	r8, r9, [%[b], #24]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #16]\n\t"
        "strd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r2, r3, [%[a], #32]\n\t"
        "ldrd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r6, r7, [%[b], #32]\n\t"
        "ldrd	r8, r9, [%[b], #40]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #32]\n\t"
        "strd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r2, r3, [%[a], #48]\n\t"
        "ldrd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r6, r7, [%[b], #48]\n\t"
        "ldrd	r8, r9, [%[b], #56]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #48]\n\t"
        "strd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r2, r3, [%[a], #64]\n\t"
        "ldrd	r4, r5, [%[a], #72]\n\t"
        "ldrd	r6, r7, [%[b], #64]\n\t"
        "ldrd	r8, r9, [%[b], #72]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #64]\n\t"
        "strd	r4, r5, [%[a], #72]\n\t"
        "ldrd	r2, r3, [%[a], #80]\n\t"
        "ldrd	r4, r5, [%[a], #88]\n\t"
        "ldrd	r6, r7, [%[b], #80]\n\t"
        "ldrd	r8, r9, [%[b], #88]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #80]\n\t"
        "strd	r4, r5, [%[a], #88]\n\t"
        "ldrd	r2, r3, [%[a], #96]\n\t"
        "ldrd	r4, r5, [%[a], #104]\n\t"
        "ldrd	r6, r7, [%[b], #96]\n\t"
        "ldrd	r8, r9, [%[b], #104]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #96]\n\t"
        "strd	r4, r5, [%[a], #104]\n\t"
        "ldrd	r2, r3, [%[a], #112]\n\t"
        "ldrd	r4, r5, [%[a], #120]\n\t"
        "ldrd	r6, r7, [%[b], #112]\n\t"
        "ldrd	r8, r9, [%[b], #120]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #112]\n\t"
        "strd	r4, r5, [%[a], #120]\n\t"
        "ldrd	r2, r3, [%[a], #128]\n\t"
        "ldrd	r4, r5, [%[a], #136]\n\t"
        "ldrd	r6, r7, [%[b], #128]\n\t"
        "ldrd	r8, r9, [%[b], #136]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #128]\n\t"
        "strd	r4, r5, [%[a], #136]\n\t"
        "ldrd	r2, r3, [%[a], #144]\n\t"
        "ldrd	r4, r5, [%[a], #152]\n\t"
        "ldrd	r6, r7, [%[b], #144]\n\t"
        "ldrd	r8, r9, [%[b], #152]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #144]\n\t"
        "strd	r4, r5, [%[a], #152]\n\t"
        "ldrd	r2, r3, [%[a], #160]\n\t"
        "ldrd	r4, r5, [%[a], #168]\n\t"
        "ldrd	r6, r7, [%[b], #160]\n\t"
        "ldrd	r8, r9, [%[b], #168]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #160]\n\t"
        "strd	r4, r5, [%[a], #168]\n\t"
        "ldrd	r2, r3, [%[a], #176]\n\t"
        "ldrd	r4, r5, [%[a], #184]\n\t"
        "ldrd	r6, r7, [%[b], #176]\n\t"
        "ldrd	r8, r9, [%[b], #184]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #176]\n\t"
        "strd	r4, r5, [%[a], #184]\n\t"
        "ldrd	r2, r3, [%[a], #192]\n\t"
        "ldrd	r4, r5, [%[a], #200]\n\t"
        "ldrd	r6, r7, [%[b], #192]\n\t"
        "ldrd	r8, r9, [%[b], #200]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #192]\n\t"
        "strd	r4, r5, [%[a], #200]\n\t"
        "ldrd	r2, r3, [%[a], #208]\n\t"
        "ldrd	r4, r5, [%[a], #216]\n\t"
        "ldrd	r6, r7, [%[b], #208]\n\t"
        "ldrd	r8, r9, [%[b], #216]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #208]\n\t"
        "strd	r4, r5, [%[a], #216]\n\t"
        "ldrd	r2, r3, [%[a], #224]\n\t"
        "ldrd	r4, r5, [%[a], #232]\n\t"
        "ldrd	r6, r7, [%[b], #224]\n\t"
        "ldrd	r8, r9, [%[b], #232]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #224]\n\t"
        "strd	r4, r5, [%[a], #232]\n\t"
        "ldrd	r2, r3, [%[a], #240]\n\t"
        "ldrd	r4, r5, [%[a], #248]\n\t"
        "ldrd	r6, r7, [%[b], #240]\n\t"
        "ldrd	r8, r9, [%[b], #248]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #240]\n\t"
        "strd	r4, r5, [%[a], #248]\n\t"
        "ldrd	r2, r3, [%[a], #256]\n\t"
        "ldrd	r4, r5, [%[a], #264]\n\t"
        "ldrd	r6, r7, [%[b], #256]\n\t"
        "ldrd	r8, r9, [%[b], #264]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #256]\n\t"
        "strd	r4, r5, [%[a], #264]\n\t"
        "ldrd	r2, r3, [%[a], #272]\n\t"
        "ldrd	r4, r5, [%[a], #280]\n\t"
        "ldrd	r6, r7, [%[b], #272]\n\t"
        "ldrd	r8, r9, [%[b], #280]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #272]\n\t"
        "strd	r4, r5, [%[a], #280]\n\t"
        "ldrd	r2, r3, [%[a], #288]\n\t"
        "ldrd	r4, r5, [%[a], #296]\n\t"
        "ldrd	r6, r7, [%[b], #288]\n\t"
        "ldrd	r8, r9, [%[b], #296]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #288]\n\t"
        "strd	r4, r5, [%[a], #296]\n\t"
        "ldrd	r2, r3, [%[a], #304]\n\t"
        "ldrd	r4, r5, [%[a], #312]\n\t"
        "ldrd	r6, r7, [%[b], #304]\n\t"
        "ldrd	r8, r9, [%[b], #312]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #304]\n\t"
        "strd	r4, r5, [%[a], #312]\n\t"
        "ldrd	r2, r3, [%[a], #320]\n\t"
        "ldrd	r4, r5, [%[a], #328]\n\t"
        "ldrd	r6, r7, [%[b], #320]\n\t"
        "ldrd	r8, r9, [%[b], #328]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #320]\n\t"
        "strd	r4, r5, [%[a], #328]\n\t"
        "ldrd	r2, r3, [%[a], #336]\n\t"
        "ldrd	r4, r5, [%[a], #344]\n\t"
        "ldrd	r6, r7, [%[b], #336]\n\t"
        "ldrd	r8, r9, [%[b], #344]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #336]\n\t"
        "strd	r4, r5, [%[a], #344]\n\t"
        "ldrd	r2, r3, [%[a], #352]\n\t"
        "ldrd	r4, r5, [%[a], #360]\n\t"
        "ldrd	r6, r7, [%[b], #352]\n\t"
        "ldrd	r8, r9, [%[b], #360]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #352]\n\t"
        "strd	r4, r5, [%[a], #360]\n\t"
        "ldrd	r2, r3, [%[a], #368]\n\t"
        "ldrd	r4, r5, [%[a], #376]\n\t"
        "ldrd	r6, r7, [%[b], #368]\n\t"
        "ldrd	r8, r9, [%[b], #376]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #368]\n\t"
        "strd	r4, r5, [%[a], #376]\n\t"
        "ldrd	r2, r3, [%[a], #384]\n\t"
        "ldrd	r4, r5, [%[a], #392]\n\t"
        "ldrd	r6, r7, [%[b], #384]\n\t"
        "ldrd	r8, r9, [%[b], #392]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #384]\n\t"
        "strd	r4, r5, [%[a], #392]\n\t"
        "ldrd	r2, r3, [%[a], #400]\n\t"
        "ldrd	r4, r5, [%[a], #408]\n\t"
        "ldrd	r6, r7, [%[b], #400]\n\t"
        "ldrd	r8, r9, [%[b], #408]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #400]\n\t"
        "strd	r4, r5, [%[a], #408]\n\t"
        "ldrd	r2, r3, [%[a], #416]\n\t"
        "ldrd	r4, r5, [%[a], #424]\n\t"
        "ldrd	r6, r7, [%[b], #416]\n\t"
        "ldrd	r8, r9, [%[b], #424]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #416]\n\t"
        "strd	r4, r5, [%[a], #424]\n\t"
        "ldrd	r2, r3, [%[a], #432]\n\t"
        "ldrd	r4, r5, [%[a], #440]\n\t"
        "ldrd	r6, r7, [%[b], #432]\n\t"
        "ldrd	r8, r9, [%[b], #440]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #432]\n\t"
        "strd	r4, r5, [%[a], #440]\n\t"
        "ldrd	r2, r3, [%[a], #448]\n\t"
        "ldrd	r4, r5, [%[a], #456]\n\t"
        "ldrd	r6, r7, [%[b], #448]\n\t"
        "ldrd	r8, r9, [%[b], #456]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #448]\n\t"
        "strd	r4, r5, [%[a], #456]\n\t"
        "ldrd	r2, r3, [%[a], #464]\n\t"
        "ldrd	r4, r5, [%[a], #472]\n\t"
        "ldrd	r6, r7, [%[b], #464]\n\t"
        "ldrd	r8, r9, [%[b], #472]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #464]\n\t"
        "strd	r4, r5, [%[a], #472]\n\t"
        "ldrd	r2, r3, [%[a], #480]\n\t"
        "ldrd	r4, r5, [%[a], #488]\n\t"
        "ldrd	r6, r7, [%[b], #480]\n\t"
        "ldrd	r8, r9, [%[b], #488]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #480]\n\t"
        "strd	r4, r5, [%[a], #488]\n\t"
        "ldrd	r2, r3, [%[a], #496]\n\t"
        "ldrd	r4, r5, [%[a], #504]\n\t"
        "ldrd	r6, r7, [%[b], #496]\n\t"
        "ldrd	r8, r9, [%[b], #504]\n\t"
        "sbcs	r2, r2, r6\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "strd	r2, r3, [%[a], #496]\n\t"
        "strd	r4, r5, [%[a], #504]\n\t"
        "sbc	%[c], r9, r9\n\t"
        : [c] "+r" (c)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9"
    );

    return c;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_4096_add_128(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r14, #0\n\t"
        "ldrd	r3, r4, [%[a], #0]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b], #0]\n\t"
        "ldrd	r9, r10, [%[b], #8]\n\t"
        "adds	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #0]\n\t"
        "strd	r5, r6, [%[r], #8]\n\t"
        "ldrd	r3, r4, [%[a], #16]\n\t"
        "ldrd	r5, r6, [%[a], #24]\n\t"
        "ldrd	r7, r8, [%[b], #16]\n\t"
        "ldrd	r9, r10, [%[b], #24]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #16]\n\t"
        "strd	r5, r6, [%[r], #24]\n\t"
        "ldrd	r3, r4, [%[a], #32]\n\t"
        "ldrd	r5, r6, [%[a], #40]\n\t"
        "ldrd	r7, r8, [%[b], #32]\n\t"
        "ldrd	r9, r10, [%[b], #40]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #32]\n\t"
        "strd	r5, r6, [%[r], #40]\n\t"
        "ldrd	r3, r4, [%[a], #48]\n\t"
        "ldrd	r5, r6, [%[a], #56]\n\t"
        "ldrd	r7, r8, [%[b], #48]\n\t"
        "ldrd	r9, r10, [%[b], #56]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #48]\n\t"
        "strd	r5, r6, [%[r], #56]\n\t"
        "ldrd	r3, r4, [%[a], #64]\n\t"
        "ldrd	r5, r6, [%[a], #72]\n\t"
        "ldrd	r7, r8, [%[b], #64]\n\t"
        "ldrd	r9, r10, [%[b], #72]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #64]\n\t"
        "strd	r5, r6, [%[r], #72]\n\t"
        "ldrd	r3, r4, [%[a], #80]\n\t"
        "ldrd	r5, r6, [%[a], #88]\n\t"
        "ldrd	r7, r8, [%[b], #80]\n\t"
        "ldrd	r9, r10, [%[b], #88]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #80]\n\t"
        "strd	r5, r6, [%[r], #88]\n\t"
        "ldrd	r3, r4, [%[a], #96]\n\t"
        "ldrd	r5, r6, [%[a], #104]\n\t"
        "ldrd	r7, r8, [%[b], #96]\n\t"
        "ldrd	r9, r10, [%[b], #104]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #96]\n\t"
        "strd	r5, r6, [%[r], #104]\n\t"
        "ldrd	r3, r4, [%[a], #112]\n\t"
        "ldrd	r5, r6, [%[a], #120]\n\t"
        "ldrd	r7, r8, [%[b], #112]\n\t"
        "ldrd	r9, r10, [%[b], #120]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #112]\n\t"
        "strd	r5, r6, [%[r], #120]\n\t"
        "ldrd	r3, r4, [%[a], #128]\n\t"
        "ldrd	r5, r6, [%[a], #136]\n\t"
        "ldrd	r7, r8, [%[b], #128]\n\t"
        "ldrd	r9, r10, [%[b], #136]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #128]\n\t"
        "strd	r5, r6, [%[r], #136]\n\t"
        "ldrd	r3, r4, [%[a], #144]\n\t"
        "ldrd	r5, r6, [%[a], #152]\n\t"
        "ldrd	r7, r8, [%[b], #144]\n\t"
        "ldrd	r9, r10, [%[b], #152]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #144]\n\t"
        "strd	r5, r6, [%[r], #152]\n\t"
        "ldrd	r3, r4, [%[a], #160]\n\t"
        "ldrd	r5, r6, [%[a], #168]\n\t"
        "ldrd	r7, r8, [%[b], #160]\n\t"
        "ldrd	r9, r10, [%[b], #168]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #160]\n\t"
        "strd	r5, r6, [%[r], #168]\n\t"
        "ldrd	r3, r4, [%[a], #176]\n\t"
        "ldrd	r5, r6, [%[a], #184]\n\t"
        "ldrd	r7, r8, [%[b], #176]\n\t"
        "ldrd	r9, r10, [%[b], #184]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #176]\n\t"
        "strd	r5, r6, [%[r], #184]\n\t"
        "ldrd	r3, r4, [%[a], #192]\n\t"
        "ldrd	r5, r6, [%[a], #200]\n\t"
        "ldrd	r7, r8, [%[b], #192]\n\t"
        "ldrd	r9, r10, [%[b], #200]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #192]\n\t"
        "strd	r5, r6, [%[r], #200]\n\t"
        "ldrd	r3, r4, [%[a], #208]\n\t"
        "ldrd	r5, r6, [%[a], #216]\n\t"
        "ldrd	r7, r8, [%[b], #208]\n\t"
        "ldrd	r9, r10, [%[b], #216]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #208]\n\t"
        "strd	r5, r6, [%[r], #216]\n\t"
        "ldrd	r3, r4, [%[a], #224]\n\t"
        "ldrd	r5, r6, [%[a], #232]\n\t"
        "ldrd	r7, r8, [%[b], #224]\n\t"
        "ldrd	r9, r10, [%[b], #232]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #224]\n\t"
        "strd	r5, r6, [%[r], #232]\n\t"
        "ldrd	r3, r4, [%[a], #240]\n\t"
        "ldrd	r5, r6, [%[a], #248]\n\t"
        "ldrd	r7, r8, [%[b], #240]\n\t"
        "ldrd	r9, r10, [%[b], #248]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #240]\n\t"
        "strd	r5, r6, [%[r], #248]\n\t"
        "ldrd	r3, r4, [%[a], #256]\n\t"
        "ldrd	r5, r6, [%[a], #264]\n\t"
        "ldrd	r7, r8, [%[b], #256]\n\t"
        "ldrd	r9, r10, [%[b], #264]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #256]\n\t"
        "strd	r5, r6, [%[r], #264]\n\t"
        "ldrd	r3, r4, [%[a], #272]\n\t"
        "ldrd	r5, r6, [%[a], #280]\n\t"
        "ldrd	r7, r8, [%[b], #272]\n\t"
        "ldrd	r9, r10, [%[b], #280]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #272]\n\t"
        "strd	r5, r6, [%[r], #280]\n\t"
        "ldrd	r3, r4, [%[a], #288]\n\t"
        "ldrd	r5, r6, [%[a], #296]\n\t"
        "ldrd	r7, r8, [%[b], #288]\n\t"
        "ldrd	r9, r10, [%[b], #296]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #288]\n\t"
        "strd	r5, r6, [%[r], #296]\n\t"
        "ldrd	r3, r4, [%[a], #304]\n\t"
        "ldrd	r5, r6, [%[a], #312]\n\t"
        "ldrd	r7, r8, [%[b], #304]\n\t"
        "ldrd	r9, r10, [%[b], #312]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #304]\n\t"
        "strd	r5, r6, [%[r], #312]\n\t"
        "ldrd	r3, r4, [%[a], #320]\n\t"
        "ldrd	r5, r6, [%[a], #328]\n\t"
        "ldrd	r7, r8, [%[b], #320]\n\t"
        "ldrd	r9, r10, [%[b], #328]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #320]\n\t"
        "strd	r5, r6, [%[r], #328]\n\t"
        "ldrd	r3, r4, [%[a], #336]\n\t"
        "ldrd	r5, r6, [%[a], #344]\n\t"
        "ldrd	r7, r8, [%[b], #336]\n\t"
        "ldrd	r9, r10, [%[b], #344]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #336]\n\t"
        "strd	r5, r6, [%[r], #344]\n\t"
        "ldrd	r3, r4, [%[a], #352]\n\t"
        "ldrd	r5, r6, [%[a], #360]\n\t"
        "ldrd	r7, r8, [%[b], #352]\n\t"
        "ldrd	r9, r10, [%[b], #360]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #352]\n\t"
        "strd	r5, r6, [%[r], #360]\n\t"
        "ldrd	r3, r4, [%[a], #368]\n\t"
        "ldrd	r5, r6, [%[a], #376]\n\t"
        "ldrd	r7, r8, [%[b], #368]\n\t"
        "ldrd	r9, r10, [%[b], #376]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #368]\n\t"
        "strd	r5, r6, [%[r], #376]\n\t"
        "ldrd	r3, r4, [%[a], #384]\n\t"
        "ldrd	r5, r6, [%[a], #392]\n\t"
        "ldrd	r7, r8, [%[b], #384]\n\t"
        "ldrd	r9, r10, [%[b], #392]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #384]\n\t"
        "strd	r5, r6, [%[r], #392]\n\t"
        "ldrd	r3, r4, [%[a], #400]\n\t"
        "ldrd	r5, r6, [%[a], #408]\n\t"
        "ldrd	r7, r8, [%[b], #400]\n\t"
        "ldrd	r9, r10, [%[b], #408]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #400]\n\t"
        "strd	r5, r6, [%[r], #408]\n\t"
        "ldrd	r3, r4, [%[a], #416]\n\t"
        "ldrd	r5, r6, [%[a], #424]\n\t"
        "ldrd	r7, r8, [%[b], #416]\n\t"
        "ldrd	r9, r10, [%[b], #424]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #416]\n\t"
        "strd	r5, r6, [%[r], #424]\n\t"
        "ldrd	r3, r4, [%[a], #432]\n\t"
        "ldrd	r5, r6, [%[a], #440]\n\t"
        "ldrd	r7, r8, [%[b], #432]\n\t"
        "ldrd	r9, r10, [%[b], #440]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #432]\n\t"
        "strd	r5, r6, [%[r], #440]\n\t"
        "ldrd	r3, r4, [%[a], #448]\n\t"
        "ldrd	r5, r6, [%[a], #456]\n\t"
        "ldrd	r7, r8, [%[b], #448]\n\t"
        "ldrd	r9, r10, [%[b], #456]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #448]\n\t"
        "strd	r5, r6, [%[r], #456]\n\t"
        "ldrd	r3, r4, [%[a], #464]\n\t"
        "ldrd	r5, r6, [%[a], #472]\n\t"
        "ldrd	r7, r8, [%[b], #464]\n\t"
        "ldrd	r9, r10, [%[b], #472]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #464]\n\t"
        "strd	r5, r6, [%[r], #472]\n\t"
        "ldrd	r3, r4, [%[a], #480]\n\t"
        "ldrd	r5, r6, [%[a], #488]\n\t"
        "ldrd	r7, r8, [%[b], #480]\n\t"
        "ldrd	r9, r10, [%[b], #488]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #480]\n\t"
        "strd	r5, r6, [%[r], #488]\n\t"
        "ldrd	r3, r4, [%[a], #496]\n\t"
        "ldrd	r5, r6, [%[a], #504]\n\t"
        "ldrd	r7, r8, [%[b], #496]\n\t"
        "ldrd	r9, r10, [%[b], #504]\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #496]\n\t"
        "strd	r5, r6, [%[r], #504]\n\t"
        "adc	%[c], r14, r14\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14"
    );

    return c;
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_4096_mul_128(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[128];
    sp_digit a1[64];
    sp_digit b1[64];
    sp_digit* z2 = r + 128;
    sp_digit u;
    sp_digit ca;
    sp_digit cb;

    ca = sp_2048_add_64(a1, a, &a[64]);
    cb = sp_2048_add_64(b1, b, &b[64]);
    u  = ca & cb;

    sp_2048_mul_64(z2, &a[64], &b[64]);
    sp_2048_mul_64(z0, a, b);
    sp_2048_mul_64(z1, a1, b1);

    u += sp_4096_sub_in_place_128(z1, z0);
    u += sp_4096_sub_in_place_128(z1, z2);
    sp_2048_mask_64(a1, a1, 0 - cb);
    u += sp_2048_add_64(z1 + 64, z1 + 64, a1);
    sp_2048_mask_64(b1, b1, 0 - ca);
    u += sp_2048_add_64(z1 + 64, z1 + 64, b1);

    u += sp_4096_add_128(r + 64, r + 64, z1);
    XMEMSET(a1 + 1, 0, sizeof(sp_digit) * (64 - 1));
    a1[0] = u;
    (void)sp_2048_add_64(r + 192, r + 192, a1);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_4096_sqr_128(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit* z2 = r + 128;
    sp_digit z1[128];
    sp_digit* a1 = z1;
    sp_digit zero[64];
    sp_digit u;
    sp_digit mask;
    sp_digit* p1;
    sp_digit* p2;

    XMEMSET(zero, 0, sizeof(sp_digit) * 64);

    mask = sp_2048_sub_64(a1, a, &a[64]);
    p1 = (sp_digit*)(((sp_digit)zero &   mask ) | ((sp_digit)a1 & (~mask)));
    p2 = (sp_digit*)(((sp_digit)zero & (~mask)) | ((sp_digit)a1 &   mask ));
    (void)sp_2048_sub_64(a1, p1, p2);

    sp_2048_sqr_64(z2, &a[64]);
    sp_2048_sqr_64(z0, a);
    sp_2048_sqr_64(z1, a1);

    u = 0;
    u -= sp_4096_sub_in_place_128(z1, z2);
    u -= sp_4096_sub_in_place_128(z1, z0);
    u += sp_4096_sub_in_place_128(r + 64, z1);
    zero[0] = u;
    (void)sp_2048_add_64(r + 192, r + 192, zero);
}

#endif /* !WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_4096_add_128(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "add	r14, %[a], #512\n\t"
        "\n1:\n\t"
        "adds	%[c], %[c], #-1\n\t"
        "ldrd	r3, r4, [%[a]], #8\n\t"
        "ldrd	r5, r6, [%[a]], #8\n\t"
        "ldrd	r7, r8, [%[b]], #8\n\t"
        "ldrd	r9, r10, [%[b]], #8\n\t"
        "adcs	r3, r3, r7\n\t"
        "adcs	r4, r4, r8\n\t"
        "adcs	r5, r5, r9\n\t"
        "adcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r]], #8\n\t"
        "strd	r5, r6, [%[r]], #8\n\t"
        "mov	r3, #0\n\t"
        "adc	%[c], r3, #0\n\t"
        "cmp	%[a], r14\n\t"
        "bne	1b\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14"
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
static sp_digit sp_4096_sub_in_place_128(sp_digit* a, const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r14, #0\n\t"
        "add	r12, %[a], #512\n\t"
        "\n1:\n\t"
        "subs	%[c], r14, %[c]\n\t"
        "ldrd	r3, r4, [%[a]]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b]], #8\n\t"
        "ldrd	r9, r10, [%[b]], #8\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[a]], #8\n\t"
        "strd	r5, r6, [%[a]], #8\n\t"
        "sbc	%[c], r14, r14\n\t"
        "cmp	%[a], r12\n\t"
        "bne	1b\n\t"
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r12", "r14"
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
static void sp_4096_mul_128(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    __asm__ __volatile__ (
        "sub	sp, sp, #1024\n\t"
        "mov	r5, #0\n\t"
        "mov	r6, #0\n\t"
        "mov	r7, #0\n\t"
        "mov	r8, #0\n\t"
        "\n1:\n\t"
        "subs	r3, r5, #508\n\t"
        "it	cc\n\t"
        "movcc	r3, #0\n\t"
        "sub	r4, r5, r3\n\t"
        "\n2:\n\t"
        "ldr	r14, [%[a], r3]\n\t"
        "ldr	r12, [%[b], r4]\n\t"
        "umull	r9, r10, r14, r12\n\t"
        "adds	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "adc	r8, r8, #0\n\t"
        "add	r3, r3, #4\n\t"
        "sub	r4, r4, #4\n\t"
        "cmp	r3, #512\n\t"
        "beq	3f\n\t"
        "cmp	r3, r5\n\t"
        "ble	2b\n\t"
        "\n3:\n\t"
        "str	r6, [sp, r5]\n\t"
        "mov	r6, r7\n\t"
        "mov	r7, r8\n\t"
        "mov	r8, #0\n\t"
        "add	r5, r5, #4\n\t"
        "cmp	r5, #1016\n\t"
        "ble	1b\n\t"
        "str	r6, [sp, r5]\n\t"
        "\n4:\n\t"
        "ldr	r6, [sp, #0]\n\t"
        "ldr	r7, [sp, #4]\n\t"
        "ldr	r8, [sp, #8]\n\t"
        "ldr	r3, [sp, #12]\n\t"
        "str	r6, [%[r], #0]\n\t"
        "str	r7, [%[r], #4]\n\t"
        "str	r8, [%[r], #8]\n\t"
        "str	r3, [%[r], #12]\n\t"
        "add	sp, sp, #16\n\t"
        "add	%[r], %[r], #16\n\t"
        "subs	r5, r5, #16\n\t"
        "bgt	4b\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14", "r12"
    );
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
static void sp_4096_sqr_128(sp_digit* r, const sp_digit* a)
{
    __asm__ __volatile__ (
        "sub	sp, sp, #1024\n\t"
        "mov	r12, #0\n\t"
        "mov	r6, #0\n\t"
        "mov	r7, #0\n\t"
        "mov	r8, #0\n\t"
        "mov	r5, #0\n\t"
        "\n1:\n\t"
        "subs	r3, r5, #508\n\t"
        "it	cc\n\t"
        "movcc	r3, r12\n\t"
        "sub	r4, r5, r3\n\t"
        "\n2:\n\t"
        "cmp	r4, r3\n\t"
        "beq	4f\n\t"
        "ldr	r14, [%[a], r3]\n\t"
        "ldr	r9, [%[a], r4]\n\t"
        "umull	r9, r10, r14, r9\n\t"
        "adds	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "adc	r8, r8, r12\n\t"
        "adds	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "adc	r8, r8, r12\n\t"
        "bal	5f\n\t"
        "\n4:\n\t"
        "ldr	r14, [%[a], r3]\n\t"
        "umull	r9, r10, r14, r14\n\t"
        "adds	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "adc	r8, r8, r12\n\t"
        "\n5:\n\t"
        "add	r3, r3, #4\n\t"
        "sub	r4, r4, #4\n\t"
        "cmp	r3, #512\n\t"
        "beq	3f\n\t"
        "cmp	r3, r4\n\t"
        "bgt	3f\n\t"
        "cmp	r3, r5\n\t"
        "ble	2b\n\t"
        "\n3:\n\t"
        "str	r6, [sp, r5]\n\t"
        "mov	r6, r7\n\t"
        "mov	r7, r8\n\t"
        "mov	r8, #0\n\t"
        "add	r5, r5, #4\n\t"
        "cmp	r5, #1016\n\t"
        "ble	1b\n\t"
        "str	r6, [sp, r5]\n\t"
        "\n4:\n\t"
        "ldrd	r6, r7, [sp, #0]\n\t"
        "ldrd	r8, r9, [sp, #8]\n\t"
        "strd	r6, r7, [%[r], #0]\n\t"
        "strd	r8, r9, [%[r], #8]\n\t"
        "add	sp, sp, #16\n\t"
        "add	%[r], %[r], #16\n\t"
        "subs	r5, r5, #16\n\t"
        "bgt	4b\n\t"
        : [r] "+r" (r)
        : [a] "r" (a)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14", "r9", "r12"
    );
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

    /* rho = -1/m mod b */
    *rho = (sp_digit)0 - x;
}

/* Mul a by digit b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision digit.
 */
static void sp_4096_mul_d_128(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "mov	r10, #0\n\t"
        "# A[0] * B\n\t"
        "ldr	r8, [%[a]]\n\t"
        "umull	r5, r3, %[b], r8\n\t"
        "mov	r4, #0\n\t"
        "str	r5, [%[r]]\n\t"
        "mov	r5, #0\n\t"
        "mov	r9, #4\n\t"
        "1:\n\t"
        "ldr	r8, [%[a], r9]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r5, r10\n\t"
        "str	r3, [%[r], r9]\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "mov	r5, #0\n\t"
        "add	r9, r9, #4\n\t"
        "cmp	r9, #512\n\t"
        "blt	1b\n\t"
        "str	r3, [%[r], #512]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
    );
#else
    __asm__ __volatile__ (
        "mov	r10, #0\n\t"
        "# A[0] * B\n\t"
        "ldr	r8, [%[a]]\n\t"
        "umull	r3, r4, %[b], r8\n\t"
        "mov	r5, #0\n\t"
        "str	r3, [%[r]]\n\t"
        "# A[1] * B\n\t"
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #4]\n\t"
        "# A[2] * B\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #8]\n\t"
        "# A[3] * B\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #12]\n\t"
        "# A[4] * B\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #16]\n\t"
        "# A[5] * B\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #20]\n\t"
        "# A[6] * B\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #24]\n\t"
        "# A[7] * B\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #28]\n\t"
        "# A[8] * B\n\t"
        "ldr	r8, [%[a], #32]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #32]\n\t"
        "# A[9] * B\n\t"
        "ldr	r8, [%[a], #36]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #36]\n\t"
        "# A[10] * B\n\t"
        "ldr	r8, [%[a], #40]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #40]\n\t"
        "# A[11] * B\n\t"
        "ldr	r8, [%[a], #44]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #44]\n\t"
        "# A[12] * B\n\t"
        "ldr	r8, [%[a], #48]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #48]\n\t"
        "# A[13] * B\n\t"
        "ldr	r8, [%[a], #52]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #52]\n\t"
        "# A[14] * B\n\t"
        "ldr	r8, [%[a], #56]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #56]\n\t"
        "# A[15] * B\n\t"
        "ldr	r8, [%[a], #60]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #60]\n\t"
        "# A[16] * B\n\t"
        "ldr	r8, [%[a], #64]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #64]\n\t"
        "# A[17] * B\n\t"
        "ldr	r8, [%[a], #68]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #68]\n\t"
        "# A[18] * B\n\t"
        "ldr	r8, [%[a], #72]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #72]\n\t"
        "# A[19] * B\n\t"
        "ldr	r8, [%[a], #76]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #76]\n\t"
        "# A[20] * B\n\t"
        "ldr	r8, [%[a], #80]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #80]\n\t"
        "# A[21] * B\n\t"
        "ldr	r8, [%[a], #84]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #84]\n\t"
        "# A[22] * B\n\t"
        "ldr	r8, [%[a], #88]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #88]\n\t"
        "# A[23] * B\n\t"
        "ldr	r8, [%[a], #92]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #92]\n\t"
        "# A[24] * B\n\t"
        "ldr	r8, [%[a], #96]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #96]\n\t"
        "# A[25] * B\n\t"
        "ldr	r8, [%[a], #100]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #100]\n\t"
        "# A[26] * B\n\t"
        "ldr	r8, [%[a], #104]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #104]\n\t"
        "# A[27] * B\n\t"
        "ldr	r8, [%[a], #108]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #108]\n\t"
        "# A[28] * B\n\t"
        "ldr	r8, [%[a], #112]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #112]\n\t"
        "# A[29] * B\n\t"
        "ldr	r8, [%[a], #116]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #116]\n\t"
        "# A[30] * B\n\t"
        "ldr	r8, [%[a], #120]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #120]\n\t"
        "# A[31] * B\n\t"
        "ldr	r8, [%[a], #124]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #124]\n\t"
        "# A[32] * B\n\t"
        "ldr	r8, [%[a], #128]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #128]\n\t"
        "# A[33] * B\n\t"
        "ldr	r8, [%[a], #132]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #132]\n\t"
        "# A[34] * B\n\t"
        "ldr	r8, [%[a], #136]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #136]\n\t"
        "# A[35] * B\n\t"
        "ldr	r8, [%[a], #140]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #140]\n\t"
        "# A[36] * B\n\t"
        "ldr	r8, [%[a], #144]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #144]\n\t"
        "# A[37] * B\n\t"
        "ldr	r8, [%[a], #148]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #148]\n\t"
        "# A[38] * B\n\t"
        "ldr	r8, [%[a], #152]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #152]\n\t"
        "# A[39] * B\n\t"
        "ldr	r8, [%[a], #156]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #156]\n\t"
        "# A[40] * B\n\t"
        "ldr	r8, [%[a], #160]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #160]\n\t"
        "# A[41] * B\n\t"
        "ldr	r8, [%[a], #164]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #164]\n\t"
        "# A[42] * B\n\t"
        "ldr	r8, [%[a], #168]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #168]\n\t"
        "# A[43] * B\n\t"
        "ldr	r8, [%[a], #172]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #172]\n\t"
        "# A[44] * B\n\t"
        "ldr	r8, [%[a], #176]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #176]\n\t"
        "# A[45] * B\n\t"
        "ldr	r8, [%[a], #180]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #180]\n\t"
        "# A[46] * B\n\t"
        "ldr	r8, [%[a], #184]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #184]\n\t"
        "# A[47] * B\n\t"
        "ldr	r8, [%[a], #188]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #188]\n\t"
        "# A[48] * B\n\t"
        "ldr	r8, [%[a], #192]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #192]\n\t"
        "# A[49] * B\n\t"
        "ldr	r8, [%[a], #196]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #196]\n\t"
        "# A[50] * B\n\t"
        "ldr	r8, [%[a], #200]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #200]\n\t"
        "# A[51] * B\n\t"
        "ldr	r8, [%[a], #204]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #204]\n\t"
        "# A[52] * B\n\t"
        "ldr	r8, [%[a], #208]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #208]\n\t"
        "# A[53] * B\n\t"
        "ldr	r8, [%[a], #212]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #212]\n\t"
        "# A[54] * B\n\t"
        "ldr	r8, [%[a], #216]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #216]\n\t"
        "# A[55] * B\n\t"
        "ldr	r8, [%[a], #220]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #220]\n\t"
        "# A[56] * B\n\t"
        "ldr	r8, [%[a], #224]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #224]\n\t"
        "# A[57] * B\n\t"
        "ldr	r8, [%[a], #228]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #228]\n\t"
        "# A[58] * B\n\t"
        "ldr	r8, [%[a], #232]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #232]\n\t"
        "# A[59] * B\n\t"
        "ldr	r8, [%[a], #236]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #236]\n\t"
        "# A[60] * B\n\t"
        "ldr	r8, [%[a], #240]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #240]\n\t"
        "# A[61] * B\n\t"
        "ldr	r8, [%[a], #244]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #244]\n\t"
        "# A[62] * B\n\t"
        "ldr	r8, [%[a], #248]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #248]\n\t"
        "# A[63] * B\n\t"
        "ldr	r8, [%[a], #252]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #252]\n\t"
        "# A[64] * B\n\t"
        "ldr	r8, [%[a], #256]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #256]\n\t"
        "# A[65] * B\n\t"
        "ldr	r8, [%[a], #260]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #260]\n\t"
        "# A[66] * B\n\t"
        "ldr	r8, [%[a], #264]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #264]\n\t"
        "# A[67] * B\n\t"
        "ldr	r8, [%[a], #268]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #268]\n\t"
        "# A[68] * B\n\t"
        "ldr	r8, [%[a], #272]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #272]\n\t"
        "# A[69] * B\n\t"
        "ldr	r8, [%[a], #276]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #276]\n\t"
        "# A[70] * B\n\t"
        "ldr	r8, [%[a], #280]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #280]\n\t"
        "# A[71] * B\n\t"
        "ldr	r8, [%[a], #284]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #284]\n\t"
        "# A[72] * B\n\t"
        "ldr	r8, [%[a], #288]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #288]\n\t"
        "# A[73] * B\n\t"
        "ldr	r8, [%[a], #292]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #292]\n\t"
        "# A[74] * B\n\t"
        "ldr	r8, [%[a], #296]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #296]\n\t"
        "# A[75] * B\n\t"
        "ldr	r8, [%[a], #300]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #300]\n\t"
        "# A[76] * B\n\t"
        "ldr	r8, [%[a], #304]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #304]\n\t"
        "# A[77] * B\n\t"
        "ldr	r8, [%[a], #308]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #308]\n\t"
        "# A[78] * B\n\t"
        "ldr	r8, [%[a], #312]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #312]\n\t"
        "# A[79] * B\n\t"
        "ldr	r8, [%[a], #316]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #316]\n\t"
        "# A[80] * B\n\t"
        "ldr	r8, [%[a], #320]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #320]\n\t"
        "# A[81] * B\n\t"
        "ldr	r8, [%[a], #324]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #324]\n\t"
        "# A[82] * B\n\t"
        "ldr	r8, [%[a], #328]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #328]\n\t"
        "# A[83] * B\n\t"
        "ldr	r8, [%[a], #332]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #332]\n\t"
        "# A[84] * B\n\t"
        "ldr	r8, [%[a], #336]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #336]\n\t"
        "# A[85] * B\n\t"
        "ldr	r8, [%[a], #340]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #340]\n\t"
        "# A[86] * B\n\t"
        "ldr	r8, [%[a], #344]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #344]\n\t"
        "# A[87] * B\n\t"
        "ldr	r8, [%[a], #348]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #348]\n\t"
        "# A[88] * B\n\t"
        "ldr	r8, [%[a], #352]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #352]\n\t"
        "# A[89] * B\n\t"
        "ldr	r8, [%[a], #356]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #356]\n\t"
        "# A[90] * B\n\t"
        "ldr	r8, [%[a], #360]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #360]\n\t"
        "# A[91] * B\n\t"
        "ldr	r8, [%[a], #364]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #364]\n\t"
        "# A[92] * B\n\t"
        "ldr	r8, [%[a], #368]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #368]\n\t"
        "# A[93] * B\n\t"
        "ldr	r8, [%[a], #372]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #372]\n\t"
        "# A[94] * B\n\t"
        "ldr	r8, [%[a], #376]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #376]\n\t"
        "# A[95] * B\n\t"
        "ldr	r8, [%[a], #380]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #380]\n\t"
        "# A[96] * B\n\t"
        "ldr	r8, [%[a], #384]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #384]\n\t"
        "# A[97] * B\n\t"
        "ldr	r8, [%[a], #388]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #388]\n\t"
        "# A[98] * B\n\t"
        "ldr	r8, [%[a], #392]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #392]\n\t"
        "# A[99] * B\n\t"
        "ldr	r8, [%[a], #396]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #396]\n\t"
        "# A[100] * B\n\t"
        "ldr	r8, [%[a], #400]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #400]\n\t"
        "# A[101] * B\n\t"
        "ldr	r8, [%[a], #404]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #404]\n\t"
        "# A[102] * B\n\t"
        "ldr	r8, [%[a], #408]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #408]\n\t"
        "# A[103] * B\n\t"
        "ldr	r8, [%[a], #412]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #412]\n\t"
        "# A[104] * B\n\t"
        "ldr	r8, [%[a], #416]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #416]\n\t"
        "# A[105] * B\n\t"
        "ldr	r8, [%[a], #420]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #420]\n\t"
        "# A[106] * B\n\t"
        "ldr	r8, [%[a], #424]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #424]\n\t"
        "# A[107] * B\n\t"
        "ldr	r8, [%[a], #428]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #428]\n\t"
        "# A[108] * B\n\t"
        "ldr	r8, [%[a], #432]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #432]\n\t"
        "# A[109] * B\n\t"
        "ldr	r8, [%[a], #436]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #436]\n\t"
        "# A[110] * B\n\t"
        "ldr	r8, [%[a], #440]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #440]\n\t"
        "# A[111] * B\n\t"
        "ldr	r8, [%[a], #444]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #444]\n\t"
        "# A[112] * B\n\t"
        "ldr	r8, [%[a], #448]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #448]\n\t"
        "# A[113] * B\n\t"
        "ldr	r8, [%[a], #452]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #452]\n\t"
        "# A[114] * B\n\t"
        "ldr	r8, [%[a], #456]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #456]\n\t"
        "# A[115] * B\n\t"
        "ldr	r8, [%[a], #460]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #460]\n\t"
        "# A[116] * B\n\t"
        "ldr	r8, [%[a], #464]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #464]\n\t"
        "# A[117] * B\n\t"
        "ldr	r8, [%[a], #468]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #468]\n\t"
        "# A[118] * B\n\t"
        "ldr	r8, [%[a], #472]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #472]\n\t"
        "# A[119] * B\n\t"
        "ldr	r8, [%[a], #476]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #476]\n\t"
        "# A[120] * B\n\t"
        "ldr	r8, [%[a], #480]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #480]\n\t"
        "# A[121] * B\n\t"
        "ldr	r8, [%[a], #484]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #484]\n\t"
        "# A[122] * B\n\t"
        "ldr	r8, [%[a], #488]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #488]\n\t"
        "# A[123] * B\n\t"
        "ldr	r8, [%[a], #492]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #492]\n\t"
        "# A[124] * B\n\t"
        "ldr	r8, [%[a], #496]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "adc	r3, r10, r10\n\t"
        "str	r4, [%[r], #496]\n\t"
        "# A[125] * B\n\t"
        "ldr	r8, [%[a], #500]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r7\n\t"
        "adc	r4, r10, r10\n\t"
        "str	r5, [%[r], #500]\n\t"
        "# A[126] * B\n\t"
        "ldr	r8, [%[a], #504]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r7\n\t"
        "adc	r5, r10, r10\n\t"
        "str	r3, [%[r], #504]\n\t"
        "# A[127] * B\n\t"
        "ldr	r8, [%[a], #508]\n\t"
        "umull	r6, r7, %[b], r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adc	r5, r5, r7\n\t"
        "str	r4, [%[r], #508]\n\t"
        "str	r5, [%[r], #512]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
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
static void sp_4096_mont_norm_128(sp_digit* r, const sp_digit* m)
{
    XMEMSET(r, 0, sizeof(sp_digit) * 128);

    /* r = 2^n mod m */
    sp_4096_sub_in_place_128(r, m);
}

#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) | WOLFSSL_HAVE_SP_DH */
/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not copying.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static sp_digit sp_4096_cond_sub_128(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    sp_digit c = 0;

#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "mov	r9, #0\n\t"
        "mov	r8, #0\n\t"
        "1:\n\t"
        "subs	%[c], r9, %[c]\n\t"
        "ldr	r4, [%[a], r8]\n\t"
        "ldr	r6, [%[b], r8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbc	%[c], r9, r9\n\t"
        "str	r4, [%[r], r8]\n\t"
        "add	r8, r8, #4\n\t"
        "cmp	r8, #512\n\t"
        "blt	1b\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9"
    );
#else
    __asm__ __volatile__ (

        "mov	r9, #0\n\t"
        "ldrd	r4, r5, [%[a], #0]\n\t"
        "ldrd	r6, r7, [%[b], #0]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "subs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #0]\n\t"
        "ldrd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r6, r7, [%[b], #8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #8]\n\t"
        "ldrd	r4, r5, [%[a], #16]\n\t"
        "ldrd	r6, r7, [%[b], #16]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #16]\n\t"
        "ldrd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r6, r7, [%[b], #24]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #24]\n\t"
        "ldrd	r4, r5, [%[a], #32]\n\t"
        "ldrd	r6, r7, [%[b], #32]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #32]\n\t"
        "ldrd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r6, r7, [%[b], #40]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #40]\n\t"
        "ldrd	r4, r5, [%[a], #48]\n\t"
        "ldrd	r6, r7, [%[b], #48]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #48]\n\t"
        "ldrd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r6, r7, [%[b], #56]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #56]\n\t"
        "ldrd	r4, r5, [%[a], #64]\n\t"
        "ldrd	r6, r7, [%[b], #64]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #64]\n\t"
        "ldrd	r4, r5, [%[a], #72]\n\t"
        "ldrd	r6, r7, [%[b], #72]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #72]\n\t"
        "ldrd	r4, r5, [%[a], #80]\n\t"
        "ldrd	r6, r7, [%[b], #80]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #80]\n\t"
        "ldrd	r4, r5, [%[a], #88]\n\t"
        "ldrd	r6, r7, [%[b], #88]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #88]\n\t"
        "ldrd	r4, r5, [%[a], #96]\n\t"
        "ldrd	r6, r7, [%[b], #96]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #96]\n\t"
        "ldrd	r4, r5, [%[a], #104]\n\t"
        "ldrd	r6, r7, [%[b], #104]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #104]\n\t"
        "ldrd	r4, r5, [%[a], #112]\n\t"
        "ldrd	r6, r7, [%[b], #112]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #112]\n\t"
        "ldrd	r4, r5, [%[a], #120]\n\t"
        "ldrd	r6, r7, [%[b], #120]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #120]\n\t"
        "ldrd	r4, r5, [%[a], #128]\n\t"
        "ldrd	r6, r7, [%[b], #128]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #128]\n\t"
        "ldrd	r4, r5, [%[a], #136]\n\t"
        "ldrd	r6, r7, [%[b], #136]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #136]\n\t"
        "ldrd	r4, r5, [%[a], #144]\n\t"
        "ldrd	r6, r7, [%[b], #144]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #144]\n\t"
        "ldrd	r4, r5, [%[a], #152]\n\t"
        "ldrd	r6, r7, [%[b], #152]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #152]\n\t"
        "ldrd	r4, r5, [%[a], #160]\n\t"
        "ldrd	r6, r7, [%[b], #160]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #160]\n\t"
        "ldrd	r4, r5, [%[a], #168]\n\t"
        "ldrd	r6, r7, [%[b], #168]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #168]\n\t"
        "ldrd	r4, r5, [%[a], #176]\n\t"
        "ldrd	r6, r7, [%[b], #176]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #176]\n\t"
        "ldrd	r4, r5, [%[a], #184]\n\t"
        "ldrd	r6, r7, [%[b], #184]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #184]\n\t"
        "ldrd	r4, r5, [%[a], #192]\n\t"
        "ldrd	r6, r7, [%[b], #192]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #192]\n\t"
        "ldrd	r4, r5, [%[a], #200]\n\t"
        "ldrd	r6, r7, [%[b], #200]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #200]\n\t"
        "ldrd	r4, r5, [%[a], #208]\n\t"
        "ldrd	r6, r7, [%[b], #208]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #208]\n\t"
        "ldrd	r4, r5, [%[a], #216]\n\t"
        "ldrd	r6, r7, [%[b], #216]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #216]\n\t"
        "ldrd	r4, r5, [%[a], #224]\n\t"
        "ldrd	r6, r7, [%[b], #224]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #224]\n\t"
        "ldrd	r4, r5, [%[a], #232]\n\t"
        "ldrd	r6, r7, [%[b], #232]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #232]\n\t"
        "ldrd	r4, r5, [%[a], #240]\n\t"
        "ldrd	r6, r7, [%[b], #240]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #240]\n\t"
        "ldrd	r4, r5, [%[a], #248]\n\t"
        "ldrd	r6, r7, [%[b], #248]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #248]\n\t"
        "ldrd	r4, r5, [%[a], #256]\n\t"
        "ldrd	r6, r7, [%[b], #256]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #256]\n\t"
        "ldrd	r4, r5, [%[a], #264]\n\t"
        "ldrd	r6, r7, [%[b], #264]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #264]\n\t"
        "ldrd	r4, r5, [%[a], #272]\n\t"
        "ldrd	r6, r7, [%[b], #272]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #272]\n\t"
        "ldrd	r4, r5, [%[a], #280]\n\t"
        "ldrd	r6, r7, [%[b], #280]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #280]\n\t"
        "ldrd	r4, r5, [%[a], #288]\n\t"
        "ldrd	r6, r7, [%[b], #288]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #288]\n\t"
        "ldrd	r4, r5, [%[a], #296]\n\t"
        "ldrd	r6, r7, [%[b], #296]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #296]\n\t"
        "ldrd	r4, r5, [%[a], #304]\n\t"
        "ldrd	r6, r7, [%[b], #304]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #304]\n\t"
        "ldrd	r4, r5, [%[a], #312]\n\t"
        "ldrd	r6, r7, [%[b], #312]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #312]\n\t"
        "ldrd	r4, r5, [%[a], #320]\n\t"
        "ldrd	r6, r7, [%[b], #320]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #320]\n\t"
        "ldrd	r4, r5, [%[a], #328]\n\t"
        "ldrd	r6, r7, [%[b], #328]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #328]\n\t"
        "ldrd	r4, r5, [%[a], #336]\n\t"
        "ldrd	r6, r7, [%[b], #336]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #336]\n\t"
        "ldrd	r4, r5, [%[a], #344]\n\t"
        "ldrd	r6, r7, [%[b], #344]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #344]\n\t"
        "ldrd	r4, r5, [%[a], #352]\n\t"
        "ldrd	r6, r7, [%[b], #352]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #352]\n\t"
        "ldrd	r4, r5, [%[a], #360]\n\t"
        "ldrd	r6, r7, [%[b], #360]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #360]\n\t"
        "ldrd	r4, r5, [%[a], #368]\n\t"
        "ldrd	r6, r7, [%[b], #368]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #368]\n\t"
        "ldrd	r4, r5, [%[a], #376]\n\t"
        "ldrd	r6, r7, [%[b], #376]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #376]\n\t"
        "ldrd	r4, r5, [%[a], #384]\n\t"
        "ldrd	r6, r7, [%[b], #384]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #384]\n\t"
        "ldrd	r4, r5, [%[a], #392]\n\t"
        "ldrd	r6, r7, [%[b], #392]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #392]\n\t"
        "ldrd	r4, r5, [%[a], #400]\n\t"
        "ldrd	r6, r7, [%[b], #400]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #400]\n\t"
        "ldrd	r4, r5, [%[a], #408]\n\t"
        "ldrd	r6, r7, [%[b], #408]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #408]\n\t"
        "ldrd	r4, r5, [%[a], #416]\n\t"
        "ldrd	r6, r7, [%[b], #416]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #416]\n\t"
        "ldrd	r4, r5, [%[a], #424]\n\t"
        "ldrd	r6, r7, [%[b], #424]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #424]\n\t"
        "ldrd	r4, r5, [%[a], #432]\n\t"
        "ldrd	r6, r7, [%[b], #432]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #432]\n\t"
        "ldrd	r4, r5, [%[a], #440]\n\t"
        "ldrd	r6, r7, [%[b], #440]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #440]\n\t"
        "ldrd	r4, r5, [%[a], #448]\n\t"
        "ldrd	r6, r7, [%[b], #448]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #448]\n\t"
        "ldrd	r4, r5, [%[a], #456]\n\t"
        "ldrd	r6, r7, [%[b], #456]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #456]\n\t"
        "ldrd	r4, r5, [%[a], #464]\n\t"
        "ldrd	r6, r7, [%[b], #464]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #464]\n\t"
        "ldrd	r4, r5, [%[a], #472]\n\t"
        "ldrd	r6, r7, [%[b], #472]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #472]\n\t"
        "ldrd	r4, r5, [%[a], #480]\n\t"
        "ldrd	r6, r7, [%[b], #480]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #480]\n\t"
        "ldrd	r4, r5, [%[a], #488]\n\t"
        "ldrd	r6, r7, [%[b], #488]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #488]\n\t"
        "ldrd	r4, r5, [%[a], #496]\n\t"
        "ldrd	r6, r7, [%[b], #496]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #496]\n\t"
        "ldrd	r4, r5, [%[a], #504]\n\t"
        "ldrd	r6, r7, [%[b], #504]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #504]\n\t"
        "sbc	%[c], r9, r9\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9"
    );
#endif /* WOLFSSL_SP_SMALL */

    return c;
}

/* Reduce the number back to 4096 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
SP_NOINLINE static void sp_4096_mont_reduce_128(sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    sp_digit ca = 0;

    __asm__ __volatile__ (
        "ldr   r11, [%[m], #0]\n\t"
        "# i = 0\n\t"
        "mov	r12, #0\n\t"
        "ldr	r10, [%[a], #0]\n\t"
        "ldr	r14, [%[a], #4]\n\t"
        "\n1:\n\t"
        "# mu = a[i] * mp\n\t"
        "mul	r8, %[mp], r10\n\t"
        "# a[i+0] += m[0] * mu\n\t"
        "ldr	r9, [%[a], #0]\n\t"
        "umull	r6, r7, r8, r11\n\t"
        "adds	r10, r10, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "# a[i+1] += m[1] * mu\n\t"
        "ldr       r7, [%[m], #4]\n\t"
        "ldr	r9, [%[a], #4]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r10, r14, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r10, r10, r5\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+2] += m[2] * mu\n\t"
        "ldr       r7, [%[m], #8]\n\t"
        "ldr	r14, [%[a], #8]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r14, r14, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r14, r14, r4\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+3] += m[3] * mu\n\t"
        "ldr       r7, [%[m], #12]\n\t"
        "ldr	r9, [%[a], #12]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #12]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+4] += m[4] * mu\n\t"
        "ldr       r7, [%[m], #16]\n\t"
        "ldr	r9, [%[a], #16]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #16]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+5] += m[5] * mu\n\t"
        "ldr       r7, [%[m], #20]\n\t"
        "ldr	r9, [%[a], #20]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #20]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+6] += m[6] * mu\n\t"
        "ldr       r7, [%[m], #24]\n\t"
        "ldr	r9, [%[a], #24]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #24]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+7] += m[7] * mu\n\t"
        "ldr       r7, [%[m], #28]\n\t"
        "ldr	r9, [%[a], #28]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #28]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+8] += m[8] * mu\n\t"
        "ldr       r7, [%[m], #32]\n\t"
        "ldr	r9, [%[a], #32]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #32]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+9] += m[9] * mu\n\t"
        "ldr       r7, [%[m], #36]\n\t"
        "ldr	r9, [%[a], #36]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #36]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+10] += m[10] * mu\n\t"
        "ldr       r7, [%[m], #40]\n\t"
        "ldr	r9, [%[a], #40]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #40]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+11] += m[11] * mu\n\t"
        "ldr       r7, [%[m], #44]\n\t"
        "ldr	r9, [%[a], #44]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #44]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+12] += m[12] * mu\n\t"
        "ldr       r7, [%[m], #48]\n\t"
        "ldr	r9, [%[a], #48]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #48]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+13] += m[13] * mu\n\t"
        "ldr       r7, [%[m], #52]\n\t"
        "ldr	r9, [%[a], #52]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #52]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+14] += m[14] * mu\n\t"
        "ldr       r7, [%[m], #56]\n\t"
        "ldr	r9, [%[a], #56]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #56]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+15] += m[15] * mu\n\t"
        "ldr       r7, [%[m], #60]\n\t"
        "ldr	r9, [%[a], #60]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #60]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+16] += m[16] * mu\n\t"
        "ldr       r7, [%[m], #64]\n\t"
        "ldr	r9, [%[a], #64]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #64]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+17] += m[17] * mu\n\t"
        "ldr       r7, [%[m], #68]\n\t"
        "ldr	r9, [%[a], #68]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #68]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+18] += m[18] * mu\n\t"
        "ldr       r7, [%[m], #72]\n\t"
        "ldr	r9, [%[a], #72]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #72]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+19] += m[19] * mu\n\t"
        "ldr       r7, [%[m], #76]\n\t"
        "ldr	r9, [%[a], #76]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #76]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+20] += m[20] * mu\n\t"
        "ldr       r7, [%[m], #80]\n\t"
        "ldr	r9, [%[a], #80]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #80]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+21] += m[21] * mu\n\t"
        "ldr       r7, [%[m], #84]\n\t"
        "ldr	r9, [%[a], #84]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #84]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+22] += m[22] * mu\n\t"
        "ldr       r7, [%[m], #88]\n\t"
        "ldr	r9, [%[a], #88]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #88]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+23] += m[23] * mu\n\t"
        "ldr       r7, [%[m], #92]\n\t"
        "ldr	r9, [%[a], #92]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #92]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+24] += m[24] * mu\n\t"
        "ldr       r7, [%[m], #96]\n\t"
        "ldr	r9, [%[a], #96]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #96]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+25] += m[25] * mu\n\t"
        "ldr       r7, [%[m], #100]\n\t"
        "ldr	r9, [%[a], #100]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #100]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+26] += m[26] * mu\n\t"
        "ldr       r7, [%[m], #104]\n\t"
        "ldr	r9, [%[a], #104]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #104]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+27] += m[27] * mu\n\t"
        "ldr       r7, [%[m], #108]\n\t"
        "ldr	r9, [%[a], #108]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #108]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+28] += m[28] * mu\n\t"
        "ldr       r7, [%[m], #112]\n\t"
        "ldr	r9, [%[a], #112]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #112]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+29] += m[29] * mu\n\t"
        "ldr       r7, [%[m], #116]\n\t"
        "ldr	r9, [%[a], #116]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #116]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+30] += m[30] * mu\n\t"
        "ldr       r7, [%[m], #120]\n\t"
        "ldr	r9, [%[a], #120]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #120]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+31] += m[31] * mu\n\t"
        "ldr       r7, [%[m], #124]\n\t"
        "ldr	r9, [%[a], #124]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #124]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+32] += m[32] * mu\n\t"
        "ldr       r7, [%[m], #128]\n\t"
        "ldr	r9, [%[a], #128]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #128]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+33] += m[33] * mu\n\t"
        "ldr       r7, [%[m], #132]\n\t"
        "ldr	r9, [%[a], #132]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #132]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+34] += m[34] * mu\n\t"
        "ldr       r7, [%[m], #136]\n\t"
        "ldr	r9, [%[a], #136]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #136]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+35] += m[35] * mu\n\t"
        "ldr       r7, [%[m], #140]\n\t"
        "ldr	r9, [%[a], #140]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #140]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+36] += m[36] * mu\n\t"
        "ldr       r7, [%[m], #144]\n\t"
        "ldr	r9, [%[a], #144]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #144]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+37] += m[37] * mu\n\t"
        "ldr       r7, [%[m], #148]\n\t"
        "ldr	r9, [%[a], #148]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #148]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+38] += m[38] * mu\n\t"
        "ldr       r7, [%[m], #152]\n\t"
        "ldr	r9, [%[a], #152]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #152]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+39] += m[39] * mu\n\t"
        "ldr       r7, [%[m], #156]\n\t"
        "ldr	r9, [%[a], #156]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #156]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+40] += m[40] * mu\n\t"
        "ldr       r7, [%[m], #160]\n\t"
        "ldr	r9, [%[a], #160]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #160]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+41] += m[41] * mu\n\t"
        "ldr       r7, [%[m], #164]\n\t"
        "ldr	r9, [%[a], #164]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #164]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+42] += m[42] * mu\n\t"
        "ldr       r7, [%[m], #168]\n\t"
        "ldr	r9, [%[a], #168]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #168]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+43] += m[43] * mu\n\t"
        "ldr       r7, [%[m], #172]\n\t"
        "ldr	r9, [%[a], #172]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #172]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+44] += m[44] * mu\n\t"
        "ldr       r7, [%[m], #176]\n\t"
        "ldr	r9, [%[a], #176]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #176]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+45] += m[45] * mu\n\t"
        "ldr       r7, [%[m], #180]\n\t"
        "ldr	r9, [%[a], #180]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #180]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+46] += m[46] * mu\n\t"
        "ldr       r7, [%[m], #184]\n\t"
        "ldr	r9, [%[a], #184]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #184]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+47] += m[47] * mu\n\t"
        "ldr       r7, [%[m], #188]\n\t"
        "ldr	r9, [%[a], #188]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #188]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+48] += m[48] * mu\n\t"
        "ldr       r7, [%[m], #192]\n\t"
        "ldr	r9, [%[a], #192]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #192]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+49] += m[49] * mu\n\t"
        "ldr       r7, [%[m], #196]\n\t"
        "ldr	r9, [%[a], #196]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #196]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+50] += m[50] * mu\n\t"
        "ldr       r7, [%[m], #200]\n\t"
        "ldr	r9, [%[a], #200]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #200]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+51] += m[51] * mu\n\t"
        "ldr       r7, [%[m], #204]\n\t"
        "ldr	r9, [%[a], #204]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #204]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+52] += m[52] * mu\n\t"
        "ldr       r7, [%[m], #208]\n\t"
        "ldr	r9, [%[a], #208]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #208]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+53] += m[53] * mu\n\t"
        "ldr       r7, [%[m], #212]\n\t"
        "ldr	r9, [%[a], #212]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #212]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+54] += m[54] * mu\n\t"
        "ldr       r7, [%[m], #216]\n\t"
        "ldr	r9, [%[a], #216]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #216]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+55] += m[55] * mu\n\t"
        "ldr       r7, [%[m], #220]\n\t"
        "ldr	r9, [%[a], #220]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #220]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+56] += m[56] * mu\n\t"
        "ldr       r7, [%[m], #224]\n\t"
        "ldr	r9, [%[a], #224]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #224]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+57] += m[57] * mu\n\t"
        "ldr       r7, [%[m], #228]\n\t"
        "ldr	r9, [%[a], #228]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #228]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+58] += m[58] * mu\n\t"
        "ldr       r7, [%[m], #232]\n\t"
        "ldr	r9, [%[a], #232]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #232]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+59] += m[59] * mu\n\t"
        "ldr       r7, [%[m], #236]\n\t"
        "ldr	r9, [%[a], #236]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #236]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+60] += m[60] * mu\n\t"
        "ldr       r7, [%[m], #240]\n\t"
        "ldr	r9, [%[a], #240]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #240]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+61] += m[61] * mu\n\t"
        "ldr       r7, [%[m], #244]\n\t"
        "ldr	r9, [%[a], #244]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #244]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+62] += m[62] * mu\n\t"
        "ldr       r7, [%[m], #248]\n\t"
        "ldr	r9, [%[a], #248]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #248]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+63] += m[63] * mu\n\t"
        "ldr       r7, [%[m], #252]\n\t"
        "ldr	r9, [%[a], #252]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #252]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+64] += m[64] * mu\n\t"
        "ldr       r7, [%[m], #256]\n\t"
        "ldr	r9, [%[a], #256]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #256]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+65] += m[65] * mu\n\t"
        "ldr       r7, [%[m], #260]\n\t"
        "ldr	r9, [%[a], #260]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #260]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+66] += m[66] * mu\n\t"
        "ldr       r7, [%[m], #264]\n\t"
        "ldr	r9, [%[a], #264]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #264]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+67] += m[67] * mu\n\t"
        "ldr       r7, [%[m], #268]\n\t"
        "ldr	r9, [%[a], #268]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #268]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+68] += m[68] * mu\n\t"
        "ldr       r7, [%[m], #272]\n\t"
        "ldr	r9, [%[a], #272]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #272]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+69] += m[69] * mu\n\t"
        "ldr       r7, [%[m], #276]\n\t"
        "ldr	r9, [%[a], #276]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #276]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+70] += m[70] * mu\n\t"
        "ldr       r7, [%[m], #280]\n\t"
        "ldr	r9, [%[a], #280]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #280]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+71] += m[71] * mu\n\t"
        "ldr       r7, [%[m], #284]\n\t"
        "ldr	r9, [%[a], #284]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #284]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+72] += m[72] * mu\n\t"
        "ldr       r7, [%[m], #288]\n\t"
        "ldr	r9, [%[a], #288]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #288]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+73] += m[73] * mu\n\t"
        "ldr       r7, [%[m], #292]\n\t"
        "ldr	r9, [%[a], #292]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #292]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+74] += m[74] * mu\n\t"
        "ldr       r7, [%[m], #296]\n\t"
        "ldr	r9, [%[a], #296]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #296]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+75] += m[75] * mu\n\t"
        "ldr       r7, [%[m], #300]\n\t"
        "ldr	r9, [%[a], #300]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #300]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+76] += m[76] * mu\n\t"
        "ldr       r7, [%[m], #304]\n\t"
        "ldr	r9, [%[a], #304]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #304]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+77] += m[77] * mu\n\t"
        "ldr       r7, [%[m], #308]\n\t"
        "ldr	r9, [%[a], #308]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #308]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+78] += m[78] * mu\n\t"
        "ldr       r7, [%[m], #312]\n\t"
        "ldr	r9, [%[a], #312]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #312]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+79] += m[79] * mu\n\t"
        "ldr       r7, [%[m], #316]\n\t"
        "ldr	r9, [%[a], #316]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #316]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+80] += m[80] * mu\n\t"
        "ldr       r7, [%[m], #320]\n\t"
        "ldr	r9, [%[a], #320]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #320]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+81] += m[81] * mu\n\t"
        "ldr       r7, [%[m], #324]\n\t"
        "ldr	r9, [%[a], #324]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #324]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+82] += m[82] * mu\n\t"
        "ldr       r7, [%[m], #328]\n\t"
        "ldr	r9, [%[a], #328]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #328]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+83] += m[83] * mu\n\t"
        "ldr       r7, [%[m], #332]\n\t"
        "ldr	r9, [%[a], #332]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #332]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+84] += m[84] * mu\n\t"
        "ldr       r7, [%[m], #336]\n\t"
        "ldr	r9, [%[a], #336]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #336]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+85] += m[85] * mu\n\t"
        "ldr       r7, [%[m], #340]\n\t"
        "ldr	r9, [%[a], #340]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #340]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+86] += m[86] * mu\n\t"
        "ldr       r7, [%[m], #344]\n\t"
        "ldr	r9, [%[a], #344]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #344]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+87] += m[87] * mu\n\t"
        "ldr       r7, [%[m], #348]\n\t"
        "ldr	r9, [%[a], #348]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #348]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+88] += m[88] * mu\n\t"
        "ldr       r7, [%[m], #352]\n\t"
        "ldr	r9, [%[a], #352]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #352]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+89] += m[89] * mu\n\t"
        "ldr       r7, [%[m], #356]\n\t"
        "ldr	r9, [%[a], #356]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #356]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+90] += m[90] * mu\n\t"
        "ldr       r7, [%[m], #360]\n\t"
        "ldr	r9, [%[a], #360]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #360]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+91] += m[91] * mu\n\t"
        "ldr       r7, [%[m], #364]\n\t"
        "ldr	r9, [%[a], #364]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #364]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+92] += m[92] * mu\n\t"
        "ldr       r7, [%[m], #368]\n\t"
        "ldr	r9, [%[a], #368]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #368]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+93] += m[93] * mu\n\t"
        "ldr       r7, [%[m], #372]\n\t"
        "ldr	r9, [%[a], #372]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #372]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+94] += m[94] * mu\n\t"
        "ldr       r7, [%[m], #376]\n\t"
        "ldr	r9, [%[a], #376]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #376]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+95] += m[95] * mu\n\t"
        "ldr       r7, [%[m], #380]\n\t"
        "ldr	r9, [%[a], #380]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #380]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+96] += m[96] * mu\n\t"
        "ldr       r7, [%[m], #384]\n\t"
        "ldr	r9, [%[a], #384]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #384]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+97] += m[97] * mu\n\t"
        "ldr       r7, [%[m], #388]\n\t"
        "ldr	r9, [%[a], #388]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #388]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+98] += m[98] * mu\n\t"
        "ldr       r7, [%[m], #392]\n\t"
        "ldr	r9, [%[a], #392]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #392]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+99] += m[99] * mu\n\t"
        "ldr       r7, [%[m], #396]\n\t"
        "ldr	r9, [%[a], #396]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #396]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+100] += m[100] * mu\n\t"
        "ldr       r7, [%[m], #400]\n\t"
        "ldr	r9, [%[a], #400]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #400]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+101] += m[101] * mu\n\t"
        "ldr       r7, [%[m], #404]\n\t"
        "ldr	r9, [%[a], #404]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #404]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+102] += m[102] * mu\n\t"
        "ldr       r7, [%[m], #408]\n\t"
        "ldr	r9, [%[a], #408]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #408]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+103] += m[103] * mu\n\t"
        "ldr       r7, [%[m], #412]\n\t"
        "ldr	r9, [%[a], #412]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #412]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+104] += m[104] * mu\n\t"
        "ldr       r7, [%[m], #416]\n\t"
        "ldr	r9, [%[a], #416]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #416]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+105] += m[105] * mu\n\t"
        "ldr       r7, [%[m], #420]\n\t"
        "ldr	r9, [%[a], #420]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #420]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+106] += m[106] * mu\n\t"
        "ldr       r7, [%[m], #424]\n\t"
        "ldr	r9, [%[a], #424]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #424]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+107] += m[107] * mu\n\t"
        "ldr       r7, [%[m], #428]\n\t"
        "ldr	r9, [%[a], #428]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #428]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+108] += m[108] * mu\n\t"
        "ldr       r7, [%[m], #432]\n\t"
        "ldr	r9, [%[a], #432]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #432]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+109] += m[109] * mu\n\t"
        "ldr       r7, [%[m], #436]\n\t"
        "ldr	r9, [%[a], #436]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #436]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+110] += m[110] * mu\n\t"
        "ldr       r7, [%[m], #440]\n\t"
        "ldr	r9, [%[a], #440]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #440]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+111] += m[111] * mu\n\t"
        "ldr       r7, [%[m], #444]\n\t"
        "ldr	r9, [%[a], #444]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #444]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+112] += m[112] * mu\n\t"
        "ldr       r7, [%[m], #448]\n\t"
        "ldr	r9, [%[a], #448]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #448]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+113] += m[113] * mu\n\t"
        "ldr       r7, [%[m], #452]\n\t"
        "ldr	r9, [%[a], #452]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #452]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+114] += m[114] * mu\n\t"
        "ldr       r7, [%[m], #456]\n\t"
        "ldr	r9, [%[a], #456]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #456]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+115] += m[115] * mu\n\t"
        "ldr       r7, [%[m], #460]\n\t"
        "ldr	r9, [%[a], #460]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #460]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+116] += m[116] * mu\n\t"
        "ldr       r7, [%[m], #464]\n\t"
        "ldr	r9, [%[a], #464]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #464]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+117] += m[117] * mu\n\t"
        "ldr       r7, [%[m], #468]\n\t"
        "ldr	r9, [%[a], #468]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #468]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+118] += m[118] * mu\n\t"
        "ldr       r7, [%[m], #472]\n\t"
        "ldr	r9, [%[a], #472]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #472]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+119] += m[119] * mu\n\t"
        "ldr       r7, [%[m], #476]\n\t"
        "ldr	r9, [%[a], #476]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #476]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+120] += m[120] * mu\n\t"
        "ldr       r7, [%[m], #480]\n\t"
        "ldr	r9, [%[a], #480]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #480]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+121] += m[121] * mu\n\t"
        "ldr       r7, [%[m], #484]\n\t"
        "ldr	r9, [%[a], #484]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #484]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+122] += m[122] * mu\n\t"
        "ldr       r7, [%[m], #488]\n\t"
        "ldr	r9, [%[a], #488]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #488]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+123] += m[123] * mu\n\t"
        "ldr       r7, [%[m], #492]\n\t"
        "ldr	r9, [%[a], #492]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #492]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+124] += m[124] * mu\n\t"
        "ldr       r7, [%[m], #496]\n\t"
        "ldr	r9, [%[a], #496]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #496]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+125] += m[125] * mu\n\t"
        "ldr       r7, [%[m], #500]\n\t"
        "ldr	r9, [%[a], #500]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r4, r7, #0\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #500]\n\t"
        "adc	r4, r4, #0\n\t"
        "# a[i+126] += m[126] * mu\n\t"
        "ldr       r7, [%[m], #504]\n\t"
        "ldr	r9, [%[a], #504]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r9, r9, r6\n\t"
        "adc	r5, r7, #0\n\t"
        "adds	r9, r9, r4\n\t"
        "str	r9, [%[a], #504]\n\t"
        "adc	r5, r5, #0\n\t"
        "# a[i+127] += m[127] * mu\n\t"
        "ldr	r7, [%[m], #508]\n\t"
        "ldr   r9, [%[a], #508]\n\t"
        "umull	r6, r7, r8, r7\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r7, r7, %[ca]\n\t"
        "mov	%[ca], #0\n\t"
        "adc	%[ca], %[ca], %[ca]\n\t"
        "adds	r9, r9, r5\n\t"
        "str	r9, [%[a], #508]\n\t"
        "ldr	r9, [%[a], #512]\n\t"
        "adcs	r9, r9, r7\n\t"
        "str	r9, [%[a], #512]\n\t"
        "adc	%[ca], %[ca], #0\n\t"
        "# i += 1\n\t"
        "add	%[a], %[a], #4\n\t"
        "add	r12, r12, #4\n\t"
        "cmp	r12, #512\n\t"
        "blt	1b\n\t"
        "str	r10, [%[a], #0]\n\t"
        "str	r14, [%[a], #4]\n\t"
        : [ca] "+r" (ca), [a] "+r" (a)
        : [m] "r" (m), [mp] "r" (mp)
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14", "r12", "r11"
    );

    sp_4096_cond_sub_128(a - 128, a, m, (sp_digit)0 - ca);
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
SP_NOINLINE static void sp_4096_mont_mul_128(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_4096_mul_128(r, a, b);
    sp_4096_mont_reduce_128(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_4096_mont_sqr_128(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_4096_sqr_128(r, a);
    sp_4096_mont_reduce_128(r, m, mp);
}

#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_4096_sub_128(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "add	r14, %[a], #512\n\t"
        "\n1:\n\t"
        "rsbs	%[c], %[c], #0\n\t"
        "ldrd	r3, r4, [%[a]], #8\n\t"
        "ldrd	r5, r6, [%[a]], #8\n\t"
        "ldrd	r7, r8, [%[b]], #8\n\t"
        "ldrd	r9, r10, [%[b]], #8\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r]], #8\n\t"
        "strd	r5, r6, [%[r]], #8\n\t"
        "sbc	%[c], r3, r3\n\t"
        "cmp	%[a], r14\n\t"
        "bne	1b\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14"
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
static sp_digit sp_4096_sub_128(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldrd	r3, r4, [%[a], #0]\n\t"
        "ldrd	r5, r6, [%[a], #8]\n\t"
        "ldrd	r7, r8, [%[b], #0]\n\t"
        "ldrd	r9, r10, [%[b], #8]\n\t"
        "subs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #0]\n\t"
        "strd	r5, r6, [%[r], #8]\n\t"
        "ldrd	r3, r4, [%[a], #16]\n\t"
        "ldrd	r5, r6, [%[a], #24]\n\t"
        "ldrd	r7, r8, [%[b], #16]\n\t"
        "ldrd	r9, r10, [%[b], #24]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #16]\n\t"
        "strd	r5, r6, [%[r], #24]\n\t"
        "ldrd	r3, r4, [%[a], #32]\n\t"
        "ldrd	r5, r6, [%[a], #40]\n\t"
        "ldrd	r7, r8, [%[b], #32]\n\t"
        "ldrd	r9, r10, [%[b], #40]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #32]\n\t"
        "strd	r5, r6, [%[r], #40]\n\t"
        "ldrd	r3, r4, [%[a], #48]\n\t"
        "ldrd	r5, r6, [%[a], #56]\n\t"
        "ldrd	r7, r8, [%[b], #48]\n\t"
        "ldrd	r9, r10, [%[b], #56]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #48]\n\t"
        "strd	r5, r6, [%[r], #56]\n\t"
        "ldrd	r3, r4, [%[a], #64]\n\t"
        "ldrd	r5, r6, [%[a], #72]\n\t"
        "ldrd	r7, r8, [%[b], #64]\n\t"
        "ldrd	r9, r10, [%[b], #72]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #64]\n\t"
        "strd	r5, r6, [%[r], #72]\n\t"
        "ldrd	r3, r4, [%[a], #80]\n\t"
        "ldrd	r5, r6, [%[a], #88]\n\t"
        "ldrd	r7, r8, [%[b], #80]\n\t"
        "ldrd	r9, r10, [%[b], #88]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #80]\n\t"
        "strd	r5, r6, [%[r], #88]\n\t"
        "ldrd	r3, r4, [%[a], #96]\n\t"
        "ldrd	r5, r6, [%[a], #104]\n\t"
        "ldrd	r7, r8, [%[b], #96]\n\t"
        "ldrd	r9, r10, [%[b], #104]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #96]\n\t"
        "strd	r5, r6, [%[r], #104]\n\t"
        "ldrd	r3, r4, [%[a], #112]\n\t"
        "ldrd	r5, r6, [%[a], #120]\n\t"
        "ldrd	r7, r8, [%[b], #112]\n\t"
        "ldrd	r9, r10, [%[b], #120]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #112]\n\t"
        "strd	r5, r6, [%[r], #120]\n\t"
        "ldrd	r3, r4, [%[a], #128]\n\t"
        "ldrd	r5, r6, [%[a], #136]\n\t"
        "ldrd	r7, r8, [%[b], #128]\n\t"
        "ldrd	r9, r10, [%[b], #136]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #128]\n\t"
        "strd	r5, r6, [%[r], #136]\n\t"
        "ldrd	r3, r4, [%[a], #144]\n\t"
        "ldrd	r5, r6, [%[a], #152]\n\t"
        "ldrd	r7, r8, [%[b], #144]\n\t"
        "ldrd	r9, r10, [%[b], #152]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #144]\n\t"
        "strd	r5, r6, [%[r], #152]\n\t"
        "ldrd	r3, r4, [%[a], #160]\n\t"
        "ldrd	r5, r6, [%[a], #168]\n\t"
        "ldrd	r7, r8, [%[b], #160]\n\t"
        "ldrd	r9, r10, [%[b], #168]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #160]\n\t"
        "strd	r5, r6, [%[r], #168]\n\t"
        "ldrd	r3, r4, [%[a], #176]\n\t"
        "ldrd	r5, r6, [%[a], #184]\n\t"
        "ldrd	r7, r8, [%[b], #176]\n\t"
        "ldrd	r9, r10, [%[b], #184]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #176]\n\t"
        "strd	r5, r6, [%[r], #184]\n\t"
        "ldrd	r3, r4, [%[a], #192]\n\t"
        "ldrd	r5, r6, [%[a], #200]\n\t"
        "ldrd	r7, r8, [%[b], #192]\n\t"
        "ldrd	r9, r10, [%[b], #200]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #192]\n\t"
        "strd	r5, r6, [%[r], #200]\n\t"
        "ldrd	r3, r4, [%[a], #208]\n\t"
        "ldrd	r5, r6, [%[a], #216]\n\t"
        "ldrd	r7, r8, [%[b], #208]\n\t"
        "ldrd	r9, r10, [%[b], #216]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #208]\n\t"
        "strd	r5, r6, [%[r], #216]\n\t"
        "ldrd	r3, r4, [%[a], #224]\n\t"
        "ldrd	r5, r6, [%[a], #232]\n\t"
        "ldrd	r7, r8, [%[b], #224]\n\t"
        "ldrd	r9, r10, [%[b], #232]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #224]\n\t"
        "strd	r5, r6, [%[r], #232]\n\t"
        "ldrd	r3, r4, [%[a], #240]\n\t"
        "ldrd	r5, r6, [%[a], #248]\n\t"
        "ldrd	r7, r8, [%[b], #240]\n\t"
        "ldrd	r9, r10, [%[b], #248]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #240]\n\t"
        "strd	r5, r6, [%[r], #248]\n\t"
        "ldrd	r3, r4, [%[a], #256]\n\t"
        "ldrd	r5, r6, [%[a], #264]\n\t"
        "ldrd	r7, r8, [%[b], #256]\n\t"
        "ldrd	r9, r10, [%[b], #264]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #256]\n\t"
        "strd	r5, r6, [%[r], #264]\n\t"
        "ldrd	r3, r4, [%[a], #272]\n\t"
        "ldrd	r5, r6, [%[a], #280]\n\t"
        "ldrd	r7, r8, [%[b], #272]\n\t"
        "ldrd	r9, r10, [%[b], #280]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #272]\n\t"
        "strd	r5, r6, [%[r], #280]\n\t"
        "ldrd	r3, r4, [%[a], #288]\n\t"
        "ldrd	r5, r6, [%[a], #296]\n\t"
        "ldrd	r7, r8, [%[b], #288]\n\t"
        "ldrd	r9, r10, [%[b], #296]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #288]\n\t"
        "strd	r5, r6, [%[r], #296]\n\t"
        "ldrd	r3, r4, [%[a], #304]\n\t"
        "ldrd	r5, r6, [%[a], #312]\n\t"
        "ldrd	r7, r8, [%[b], #304]\n\t"
        "ldrd	r9, r10, [%[b], #312]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #304]\n\t"
        "strd	r5, r6, [%[r], #312]\n\t"
        "ldrd	r3, r4, [%[a], #320]\n\t"
        "ldrd	r5, r6, [%[a], #328]\n\t"
        "ldrd	r7, r8, [%[b], #320]\n\t"
        "ldrd	r9, r10, [%[b], #328]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #320]\n\t"
        "strd	r5, r6, [%[r], #328]\n\t"
        "ldrd	r3, r4, [%[a], #336]\n\t"
        "ldrd	r5, r6, [%[a], #344]\n\t"
        "ldrd	r7, r8, [%[b], #336]\n\t"
        "ldrd	r9, r10, [%[b], #344]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #336]\n\t"
        "strd	r5, r6, [%[r], #344]\n\t"
        "ldrd	r3, r4, [%[a], #352]\n\t"
        "ldrd	r5, r6, [%[a], #360]\n\t"
        "ldrd	r7, r8, [%[b], #352]\n\t"
        "ldrd	r9, r10, [%[b], #360]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #352]\n\t"
        "strd	r5, r6, [%[r], #360]\n\t"
        "ldrd	r3, r4, [%[a], #368]\n\t"
        "ldrd	r5, r6, [%[a], #376]\n\t"
        "ldrd	r7, r8, [%[b], #368]\n\t"
        "ldrd	r9, r10, [%[b], #376]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #368]\n\t"
        "strd	r5, r6, [%[r], #376]\n\t"
        "ldrd	r3, r4, [%[a], #384]\n\t"
        "ldrd	r5, r6, [%[a], #392]\n\t"
        "ldrd	r7, r8, [%[b], #384]\n\t"
        "ldrd	r9, r10, [%[b], #392]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #384]\n\t"
        "strd	r5, r6, [%[r], #392]\n\t"
        "ldrd	r3, r4, [%[a], #400]\n\t"
        "ldrd	r5, r6, [%[a], #408]\n\t"
        "ldrd	r7, r8, [%[b], #400]\n\t"
        "ldrd	r9, r10, [%[b], #408]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #400]\n\t"
        "strd	r5, r6, [%[r], #408]\n\t"
        "ldrd	r3, r4, [%[a], #416]\n\t"
        "ldrd	r5, r6, [%[a], #424]\n\t"
        "ldrd	r7, r8, [%[b], #416]\n\t"
        "ldrd	r9, r10, [%[b], #424]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #416]\n\t"
        "strd	r5, r6, [%[r], #424]\n\t"
        "ldrd	r3, r4, [%[a], #432]\n\t"
        "ldrd	r5, r6, [%[a], #440]\n\t"
        "ldrd	r7, r8, [%[b], #432]\n\t"
        "ldrd	r9, r10, [%[b], #440]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #432]\n\t"
        "strd	r5, r6, [%[r], #440]\n\t"
        "ldrd	r3, r4, [%[a], #448]\n\t"
        "ldrd	r5, r6, [%[a], #456]\n\t"
        "ldrd	r7, r8, [%[b], #448]\n\t"
        "ldrd	r9, r10, [%[b], #456]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #448]\n\t"
        "strd	r5, r6, [%[r], #456]\n\t"
        "ldrd	r3, r4, [%[a], #464]\n\t"
        "ldrd	r5, r6, [%[a], #472]\n\t"
        "ldrd	r7, r8, [%[b], #464]\n\t"
        "ldrd	r9, r10, [%[b], #472]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #464]\n\t"
        "strd	r5, r6, [%[r], #472]\n\t"
        "ldrd	r3, r4, [%[a], #480]\n\t"
        "ldrd	r5, r6, [%[a], #488]\n\t"
        "ldrd	r7, r8, [%[b], #480]\n\t"
        "ldrd	r9, r10, [%[b], #488]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #480]\n\t"
        "strd	r5, r6, [%[r], #488]\n\t"
        "ldrd	r3, r4, [%[a], #496]\n\t"
        "ldrd	r5, r6, [%[a], #504]\n\t"
        "ldrd	r7, r8, [%[b], #496]\n\t"
        "ldrd	r9, r10, [%[b], #504]\n\t"
        "sbcs	r3, r3, r7\n\t"
        "sbcs	r4, r4, r8\n\t"
        "sbcs	r5, r5, r9\n\t"
        "sbcs	r6, r6, r10\n\t"
        "strd	r3, r4, [%[r], #496]\n\t"
        "strd	r5, r6, [%[r], #504]\n\t"
        "sbc	%[c], %[c], #0\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
    );

    return c;
}

#endif /* WOLFSSL_SP_SMALL */
/* Divide the double width number (d1|d0) by the divisor. (d1|d0 / div)
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The divisor.
 * returns the result of the division.
 *
 * Note that this is an approximate div. It may give an answer 1 larger.
 */
static sp_digit div_4096_word_128(sp_digit d1, sp_digit d0, sp_digit div)
{
    sp_digit r = 0;

    __asm__ __volatile__ (
        "lsr	r5, %[div], #1\n\t"
        "add	r5, r5, #1\n\t"
        "mov	r6, %[d0]\n\t"
        "mov	r7, %[d1]\n\t"
        "# Do top 32\n\t"
        "subs	r8, r5, r7\n\t"
        "sbc	r8, r8, r8\n\t"
        "add	%[r], %[r], %[r]\n\t"
        "sub	%[r], %[r], r8\n\t"
        "and	r8, r8, r5\n\t"
        "subs	r7, r7, r8\n\t"
        "# Next 30 bits\n\t"
        "mov	r4, #29\n\t"
        "1:\n\t"
        "movs	r6, r6, lsl #1\n\t"
        "adc	r7, r7, r7\n\t"
        "subs	r8, r5, r7\n\t"
        "sbc	r8, r8, r8\n\t"
        "add	%[r], %[r], %[r]\n\t"
        "sub	%[r], %[r], r8\n\t"
        "and	r8, r8, r5\n\t"
        "subs	r7, r7, r8\n\t"
        "subs	r4, r4, #1\n\t"
        "bpl	1b\n\t"
        "add	%[r], %[r], %[r]\n\t"
        "add	%[r], %[r], #1\n\t"
        "umull	r4, r5, %[r], %[div]\n\t"
        "subs	r4, %[d0], r4\n\t"
        "sbc	r5, %[d1], r5\n\t"
        "add	%[r], %[r], r5\n\t"
        "umull	r4, r5, %[r], %[div]\n\t"
        "subs	r4, %[d0], r4\n\t"
        "sbc	r5, %[d1], r5\n\t"
        "add	%[r], %[r], r5\n\t"
        "umull	r4, r5, %[r], %[div]\n\t"
        "subs	r4, %[d0], r4\n\t"
        "sbc	r5, %[d1], r5\n\t"
        "add	%[r], %[r], r5\n\t"
        "subs	r8, %[div], r4\n\t"
        "sbc	r8, r8, r8\n\t"
        "sub	%[r], %[r], r8\n\t"
        : [r] "+r" (r)
        : [d1] "r" (d1), [d0] "r" (d0), [div] "r" (div)
        : "r4", "r5", "r6", "r7", "r8"
    );
    return r;
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
static WC_INLINE int sp_4096_div_128_cond(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    sp_digit t1[256], t2[129];
    sp_digit div, r1;
    int i;

    (void)m;

    div = d[127];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 128);
    for (i = 127; i >= 0; i--) {
        if (t1[128 + i] == div) {
            r1 = SP_DIGIT_MAX;
        }
        else {
            r1 = div_4096_word_128(t1[128 + i], t1[128 + i - 1], div);
        }

        sp_4096_mul_d_128(t2, d, r1);
        t1[128 + i] += sp_4096_sub_in_place_128(&t1[i], t2);
        t1[128 + i] -= t2[128];
        if (t1[128 + i] != 0) {
            t1[128 + i] += sp_4096_add_128(&t1[i], &t1[i], d);
            if (t1[128 + i] != 0)
                t1[128 + i] += sp_4096_add_128(&t1[i], &t1[i], d);
        }
    }

    for (i = 127; i > 0; i--) {
        if (t1[i] != d[i])
            break;
    }
    if (t1[i] >= d[i]) {
        sp_4096_sub_128(r, t1, d);
    }
    else {
        XMEMCPY(r, t1, sizeof(*t1) * 128);
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
static WC_INLINE int sp_4096_mod_128_cond(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_4096_div_128_cond(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
#if defined(WOLFSSL_HAVE_SP_DH) || !defined(WOLFSSL_RSA_PUBLIC_ONLY)
/* AND m into each word of a and store in r.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * m  Mask to AND against each digit.
 */
static void sp_4096_mask_128(sp_digit* r, const sp_digit* a, sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<128; i++) {
        r[i] = a[i] & m;
    }
#else
    int i;

    for (i = 0; i < 128; i += 8) {
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
static sp_int32 sp_4096_cmp_128(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = -1;
    sp_digit one = 1;


#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "mov	r7, #0\n\t"
        "mov	r3, #-1\n\t"
        "mov	r6, #508\n\t"
        "1:\n\t"
        "ldr	r4, [%[a], r6]\n\t"
        "ldr	r5, [%[b], r6]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "subs	r6, r6, #4\n\t"
        "bcs	1b\n\t"
        "eor	%[r], %[r], r3\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [one] "r" (one)
        : "r3", "r4", "r5", "r6", "r7"
    );
#else
    __asm__ __volatile__ (
        "mov	r7, #0\n\t"
        "mov	r3, #-1\n\t"
        "ldr	r4, [%[a], #508]\n\t"
        "ldr	r5, [%[b], #508]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #504]\n\t"
        "ldr	r5, [%[b], #504]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #500]\n\t"
        "ldr	r5, [%[b], #500]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #496]\n\t"
        "ldr	r5, [%[b], #496]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #492]\n\t"
        "ldr	r5, [%[b], #492]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #488]\n\t"
        "ldr	r5, [%[b], #488]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #484]\n\t"
        "ldr	r5, [%[b], #484]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #480]\n\t"
        "ldr	r5, [%[b], #480]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #476]\n\t"
        "ldr	r5, [%[b], #476]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #472]\n\t"
        "ldr	r5, [%[b], #472]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #468]\n\t"
        "ldr	r5, [%[b], #468]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #464]\n\t"
        "ldr	r5, [%[b], #464]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #460]\n\t"
        "ldr	r5, [%[b], #460]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #456]\n\t"
        "ldr	r5, [%[b], #456]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #452]\n\t"
        "ldr	r5, [%[b], #452]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #448]\n\t"
        "ldr	r5, [%[b], #448]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #444]\n\t"
        "ldr	r5, [%[b], #444]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #440]\n\t"
        "ldr	r5, [%[b], #440]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #436]\n\t"
        "ldr	r5, [%[b], #436]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #432]\n\t"
        "ldr	r5, [%[b], #432]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #428]\n\t"
        "ldr	r5, [%[b], #428]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #424]\n\t"
        "ldr	r5, [%[b], #424]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #420]\n\t"
        "ldr	r5, [%[b], #420]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #416]\n\t"
        "ldr	r5, [%[b], #416]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #412]\n\t"
        "ldr	r5, [%[b], #412]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #408]\n\t"
        "ldr	r5, [%[b], #408]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #404]\n\t"
        "ldr	r5, [%[b], #404]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #400]\n\t"
        "ldr	r5, [%[b], #400]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #396]\n\t"
        "ldr	r5, [%[b], #396]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #392]\n\t"
        "ldr	r5, [%[b], #392]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #388]\n\t"
        "ldr	r5, [%[b], #388]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #384]\n\t"
        "ldr	r5, [%[b], #384]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #380]\n\t"
        "ldr	r5, [%[b], #380]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #376]\n\t"
        "ldr	r5, [%[b], #376]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #372]\n\t"
        "ldr	r5, [%[b], #372]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #368]\n\t"
        "ldr	r5, [%[b], #368]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #364]\n\t"
        "ldr	r5, [%[b], #364]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #360]\n\t"
        "ldr	r5, [%[b], #360]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #356]\n\t"
        "ldr	r5, [%[b], #356]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #352]\n\t"
        "ldr	r5, [%[b], #352]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #348]\n\t"
        "ldr	r5, [%[b], #348]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #344]\n\t"
        "ldr	r5, [%[b], #344]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #340]\n\t"
        "ldr	r5, [%[b], #340]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #336]\n\t"
        "ldr	r5, [%[b], #336]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #332]\n\t"
        "ldr	r5, [%[b], #332]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #328]\n\t"
        "ldr	r5, [%[b], #328]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #324]\n\t"
        "ldr	r5, [%[b], #324]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #320]\n\t"
        "ldr	r5, [%[b], #320]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #316]\n\t"
        "ldr	r5, [%[b], #316]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #312]\n\t"
        "ldr	r5, [%[b], #312]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #308]\n\t"
        "ldr	r5, [%[b], #308]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #304]\n\t"
        "ldr	r5, [%[b], #304]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #300]\n\t"
        "ldr	r5, [%[b], #300]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #296]\n\t"
        "ldr	r5, [%[b], #296]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #292]\n\t"
        "ldr	r5, [%[b], #292]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #288]\n\t"
        "ldr	r5, [%[b], #288]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #284]\n\t"
        "ldr	r5, [%[b], #284]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #280]\n\t"
        "ldr	r5, [%[b], #280]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #276]\n\t"
        "ldr	r5, [%[b], #276]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #272]\n\t"
        "ldr	r5, [%[b], #272]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #268]\n\t"
        "ldr	r5, [%[b], #268]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #264]\n\t"
        "ldr	r5, [%[b], #264]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #260]\n\t"
        "ldr	r5, [%[b], #260]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #256]\n\t"
        "ldr	r5, [%[b], #256]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #252]\n\t"
        "ldr	r5, [%[b], #252]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #248]\n\t"
        "ldr	r5, [%[b], #248]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #244]\n\t"
        "ldr	r5, [%[b], #244]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #240]\n\t"
        "ldr	r5, [%[b], #240]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #236]\n\t"
        "ldr	r5, [%[b], #236]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #232]\n\t"
        "ldr	r5, [%[b], #232]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #228]\n\t"
        "ldr	r5, [%[b], #228]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #224]\n\t"
        "ldr	r5, [%[b], #224]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #220]\n\t"
        "ldr	r5, [%[b], #220]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #216]\n\t"
        "ldr	r5, [%[b], #216]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #212]\n\t"
        "ldr	r5, [%[b], #212]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #208]\n\t"
        "ldr	r5, [%[b], #208]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #204]\n\t"
        "ldr	r5, [%[b], #204]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #200]\n\t"
        "ldr	r5, [%[b], #200]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #196]\n\t"
        "ldr	r5, [%[b], #196]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #192]\n\t"
        "ldr	r5, [%[b], #192]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #188]\n\t"
        "ldr	r5, [%[b], #188]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #184]\n\t"
        "ldr	r5, [%[b], #184]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #180]\n\t"
        "ldr	r5, [%[b], #180]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #176]\n\t"
        "ldr	r5, [%[b], #176]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #172]\n\t"
        "ldr	r5, [%[b], #172]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #168]\n\t"
        "ldr	r5, [%[b], #168]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #164]\n\t"
        "ldr	r5, [%[b], #164]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #160]\n\t"
        "ldr	r5, [%[b], #160]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #156]\n\t"
        "ldr	r5, [%[b], #156]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #152]\n\t"
        "ldr	r5, [%[b], #152]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #148]\n\t"
        "ldr	r5, [%[b], #148]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #144]\n\t"
        "ldr	r5, [%[b], #144]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #140]\n\t"
        "ldr	r5, [%[b], #140]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #136]\n\t"
        "ldr	r5, [%[b], #136]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #132]\n\t"
        "ldr	r5, [%[b], #132]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #128]\n\t"
        "ldr	r5, [%[b], #128]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #124]\n\t"
        "ldr	r5, [%[b], #124]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #120]\n\t"
        "ldr	r5, [%[b], #120]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #116]\n\t"
        "ldr	r5, [%[b], #116]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #112]\n\t"
        "ldr	r5, [%[b], #112]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #108]\n\t"
        "ldr	r5, [%[b], #108]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #104]\n\t"
        "ldr	r5, [%[b], #104]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #100]\n\t"
        "ldr	r5, [%[b], #100]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #96]\n\t"
        "ldr	r5, [%[b], #96]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #92]\n\t"
        "ldr	r5, [%[b], #92]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #88]\n\t"
        "ldr	r5, [%[b], #88]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #84]\n\t"
        "ldr	r5, [%[b], #84]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #80]\n\t"
        "ldr	r5, [%[b], #80]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #76]\n\t"
        "ldr	r5, [%[b], #76]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #72]\n\t"
        "ldr	r5, [%[b], #72]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #68]\n\t"
        "ldr	r5, [%[b], #68]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #64]\n\t"
        "ldr	r5, [%[b], #64]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #60]\n\t"
        "ldr	r5, [%[b], #60]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #56]\n\t"
        "ldr	r5, [%[b], #56]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #52]\n\t"
        "ldr	r5, [%[b], #52]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #48]\n\t"
        "ldr	r5, [%[b], #48]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #44]\n\t"
        "ldr	r5, [%[b], #44]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #40]\n\t"
        "ldr	r5, [%[b], #40]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #36]\n\t"
        "ldr	r5, [%[b], #36]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #32]\n\t"
        "ldr	r5, [%[b], #32]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #28]\n\t"
        "ldr	r5, [%[b], #28]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #24]\n\t"
        "ldr	r5, [%[b], #24]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #20]\n\t"
        "ldr	r5, [%[b], #20]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #16]\n\t"
        "ldr	r5, [%[b], #16]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #12]\n\t"
        "ldr	r5, [%[b], #12]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #8]\n\t"
        "ldr	r5, [%[b], #8]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #4]\n\t"
        "ldr	r5, [%[b], #4]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "ldr	r4, [%[a], #0]\n\t"
        "ldr	r5, [%[b], #0]\n\t"
        "and	r4, r4, r3\n\t"
        "and	r5, r5, r3\n\t"
        "subs	r4, r4, r5\n\t"
        "it	hi\n\t"
        "movhi	%[r], %[one]\n\t"
        "it	lo\n\t"
        "movlo	%[r], r3\n\t"
        "it	ne\n\t"
        "movne	r3, r7\n\t"
        "eor	%[r], %[r], r3\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [one] "r" (one)
        : "r3", "r4", "r5", "r6", "r7"
    );
#endif

    return r;
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
static WC_INLINE int sp_4096_div_128(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    sp_digit t1[256], t2[129];
    sp_digit div, r1;
    int i;

    (void)m;

    div = d[127];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 128);
    for (i = 127; i >= 0; i--) {
        sp_digit hi = t1[128 + i] - (t1[128 + i] == div);
        r1 = div_4096_word_128(hi, t1[128 + i - 1], div);

        sp_4096_mul_d_128(t2, d, r1);
        t1[128 + i] += sp_4096_sub_in_place_128(&t1[i], t2);
        t1[128 + i] -= t2[128];
        sp_4096_mask_128(t2, d, t1[128 + i]);
        t1[128 + i] += sp_4096_add_128(&t1[i], &t1[i], t2);
        sp_4096_mask_128(t2, d, t1[128 + i]);
        t1[128 + i] += sp_4096_add_128(&t1[i], &t1[i], t2);
    }

    r1 = sp_4096_cmp_128(t1, d) >= 0;
    sp_4096_cond_sub_128(r, t1, d, (sp_digit)0 - r1);

    return MP_OKAY;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_4096_mod_128(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_4096_div_128(a, m, NULL, r);
}

#endif /* WOLFSSL_HAVE_SP_DH || !WOLFSSL_RSA_PUBLIC_ONLY */
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
static int sp_4096_mod_exp_128(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[8 * 256];
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
            t[i] = td + i * 256;
        }

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_128(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 128U);
        if (reduceA != 0) {
            err = sp_4096_mod_128(t[1] + 128, a, m);
            if (err == MP_OKAY) {
                err = sp_4096_mod_128(t[1], t[1], m);
            }
        }
        else {
            XMEMCPY(t[1] + 128, a, sizeof(sp_digit) * 128);
            err = sp_4096_mod_128(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_4096_mont_sqr_128(t[ 2], t[ 1], m, mp);
        sp_4096_mont_mul_128(t[ 3], t[ 2], t[ 1], m, mp);
        sp_4096_mont_sqr_128(t[ 4], t[ 2], m, mp);
        sp_4096_mont_mul_128(t[ 5], t[ 3], t[ 2], m, mp);
        sp_4096_mont_sqr_128(t[ 6], t[ 3], m, mp);
        sp_4096_mont_mul_128(t[ 7], t[ 4], t[ 3], m, mp);

        i = (bits - 1) / 32;
        n = e[i--];
        c = bits & 31;
        if (c == 0) {
            c = 32;
        }
        c -= bits % 3;
        if (c == 32) {
            c = 29;
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
            n <<= 32 - c;
        }
        XMEMCPY(r, t[y], sizeof(sp_digit) * 128);
        for (; i>=0 || c>=3; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 29);
                n <<= 3;
                c = 29;
            }
            else if (c < 3) {
                y = (byte)(n >> 29);
                n = e[i--];
                c = 3 - c;
                y |= (byte)(n >> (32 - c));
                n <<= c;
                c = 32 - c;
            }
            else {
                y = (byte)((n >> 29) & 0x7);
                n <<= 3;
                c -= 3;
            }

            sp_4096_mont_sqr_128(r, r, m, mp);
            sp_4096_mont_sqr_128(r, r, m, mp);
            sp_4096_mont_sqr_128(r, r, m, mp);

            sp_4096_mont_mul_128(r, r, t[y], m, mp);
        }

        XMEMSET(&r[128], 0, sizeof(sp_digit) * 128U);
        sp_4096_mont_reduce_128(r, m, mp);

        mask = 0 - (sp_4096_cmp_128(r, m) >= 0);
        sp_4096_cond_sub_128(r, r, m, mask);
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
static int sp_4096_mod_exp_128(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[16 * 256];
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
            t[i] = td + i * 256;
        }

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_128(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 128U);
        if (reduceA != 0) {
            err = sp_4096_mod_128(t[1] + 128, a, m);
            if (err == MP_OKAY) {
                err = sp_4096_mod_128(t[1], t[1], m);
            }
        }
        else {
            XMEMCPY(t[1] + 128, a, sizeof(sp_digit) * 128);
            err = sp_4096_mod_128(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_4096_mont_sqr_128(t[ 2], t[ 1], m, mp);
        sp_4096_mont_mul_128(t[ 3], t[ 2], t[ 1], m, mp);
        sp_4096_mont_sqr_128(t[ 4], t[ 2], m, mp);
        sp_4096_mont_mul_128(t[ 5], t[ 3], t[ 2], m, mp);
        sp_4096_mont_sqr_128(t[ 6], t[ 3], m, mp);
        sp_4096_mont_mul_128(t[ 7], t[ 4], t[ 3], m, mp);
        sp_4096_mont_sqr_128(t[ 8], t[ 4], m, mp);
        sp_4096_mont_mul_128(t[ 9], t[ 5], t[ 4], m, mp);
        sp_4096_mont_sqr_128(t[10], t[ 5], m, mp);
        sp_4096_mont_mul_128(t[11], t[ 6], t[ 5], m, mp);
        sp_4096_mont_sqr_128(t[12], t[ 6], m, mp);
        sp_4096_mont_mul_128(t[13], t[ 7], t[ 6], m, mp);
        sp_4096_mont_sqr_128(t[14], t[ 7], m, mp);
        sp_4096_mont_mul_128(t[15], t[ 8], t[ 7], m, mp);

        i = (bits - 1) / 32;
        n = e[i--];
        c = bits & 31;
        if (c == 0) {
            c = 32;
        }
        c -= bits % 4;
        if (c == 32) {
            c = 28;
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
            n <<= 32 - c;
        }
        XMEMCPY(r, t[y], sizeof(sp_digit) * 128);
        for (; i>=0 || c>=4; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 28);
                n <<= 4;
                c = 28;
            }
            else if (c < 4) {
                y = (byte)(n >> 28);
                n = e[i--];
                c = 4 - c;
                y |= (byte)(n >> (32 - c));
                n <<= c;
                c = 32 - c;
            }
            else {
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c -= 4;
            }

            sp_4096_mont_sqr_128(r, r, m, mp);
            sp_4096_mont_sqr_128(r, r, m, mp);
            sp_4096_mont_sqr_128(r, r, m, mp);
            sp_4096_mont_sqr_128(r, r, m, mp);

            sp_4096_mont_mul_128(r, r, t[y], m, mp);
        }

        XMEMSET(&r[128], 0, sizeof(sp_digit) * 128U);
        sp_4096_mont_reduce_128(r, m, mp);

        mask = 0 - (sp_4096_cmp_128(r, m) >= 0);
        sp_4096_cond_sub_128(r, r, m, mask);
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
    sp_digit a[128 * 5];
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit *ah = NULL;
    sp_digit e[1] = {0};
    int err = MP_OKAY;

    if (*outLen < 512) {
        err = MP_TO_E;
    }
    else if (mp_count_bits(em) > 32 || inLen > 512 ||
                                                     mp_count_bits(mm) != 4096) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mm)) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        ah = a + 128;
        r = a + 128 * 2;
        m = r + 128 * 2;

        sp_4096_from_bin(ah, 128, in, inLen);
#if DIGIT_BIT >= 32
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
        sp_4096_from_mp(m, 128, mm);

        if (e[0] == 0x10001) {
            int i;
            sp_digit mp;

            sp_4096_mont_setup(m, &mp);

            /* Convert to Montgomery form. */
            XMEMSET(a, 0, sizeof(sp_digit) * 128);
            err = sp_4096_mod_128_cond(r, a, m);
            /* Montgomery form: r = a.R mod m */

            if (err == MP_OKAY) {
                /* r = a ^ 0x10000 => r = a squared 16 times */
                for (i = 15; i >= 0; i--) {
                    sp_4096_mont_sqr_128(r, r, m, mp);
                }
                /* mont_red(r.R.R) = (r.R.R / R) mod m = r.R mod m
                 * mont_red(r.R * a) = (r.R.a / R) mod m = r.a mod m
                 */
                sp_4096_mont_mul_128(r, r, ah, m, mp);

                for (i = 127; i > 0; i--) {
                    if (r[i] != m[i]) {
                        break;
                    }
                }
                if (r[i] >= m[i]) {
                    sp_4096_sub_in_place_128(r, m);
                }
            }
        }
        else if (e[0] == 0x3) {
            if (err == MP_OKAY) {
                sp_4096_sqr_128(r, ah);
                err = sp_4096_mod_128_cond(r, r, m);
            }
            if (err == MP_OKAY) {
                sp_4096_mul_128(r, ah, r);
                err = sp_4096_mod_128_cond(r, r, m);
            }
        }
        else {
            int i;
            sp_digit mp;

            sp_4096_mont_setup(m, &mp);

            /* Convert to Montgomery form. */
            XMEMSET(a, 0, sizeof(sp_digit) * 128);
            err = sp_4096_mod_128_cond(a, a, m);

            if (err == MP_OKAY) {
                for (i = 31; i >= 0; i--) {
                    if (e[0] >> i) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 128);
                for (i--; i >= 0; i--) {
                    sp_4096_mont_sqr_128(r, r, m, mp);
                    if (((e[0] >> i) & 1) == 1) {
                        sp_4096_mont_mul_128(r, r, a, m, mp);
                    }
                }
                XMEMSET(&r[128], 0, sizeof(sp_digit) * 128);
                sp_4096_mont_reduce_128(r, m, mp);

                for (i = 127; i > 0; i--) {
                    if (r[i] != m[i]) {
                        break;
                    }
                }
                if (r[i] >= m[i]) {
                    sp_4096_sub_in_place_128(r, m);
                }
            }
        }
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_128(r, out);
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
static sp_digit sp_4096_cond_add_64(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r7, #0\n\t"
        "mov	r6, #0\n\t"
        "1:\n\t"
        "adds	%[c], %[c], #-1\n\t"
        "ldr	r4, [%[a], r6]\n\t"
        "ldr	r5, [%[b], r6]\n\t"
        "and	r5, r5, %[m]\n\t"
        "adcs	r4, r4, r5\n\t"
        "adc	%[c], r7, r7\n\t"
        "str	r4, [%[r], r6]\n\t"
        "add	r6, r6, #4\n\t"
        "cmp	r6, #256\n\t"
        "blt	1b\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r4", "r5", "r6", "r7"
    );

    return c;
}
#endif /* WOLFSSL_SP_SMALL */

#ifndef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static sp_digit sp_4096_cond_add_64(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    sp_digit c = 0;

    __asm__ __volatile__ (

        "mov	r8, #0\n\t"
        "ldrd	r4, r5, [%[a], #0]\n\t"
        "ldrd	r6, r7, [%[b], #0]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #0]\n\t"
        "ldrd	r4, r5, [%[a], #8]\n\t"
        "ldrd	r6, r7, [%[b], #8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #8]\n\t"
        "ldrd	r4, r5, [%[a], #16]\n\t"
        "ldrd	r6, r7, [%[b], #16]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #16]\n\t"
        "ldrd	r4, r5, [%[a], #24]\n\t"
        "ldrd	r6, r7, [%[b], #24]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #24]\n\t"
        "ldrd	r4, r5, [%[a], #32]\n\t"
        "ldrd	r6, r7, [%[b], #32]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #32]\n\t"
        "ldrd	r4, r5, [%[a], #40]\n\t"
        "ldrd	r6, r7, [%[b], #40]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #40]\n\t"
        "ldrd	r4, r5, [%[a], #48]\n\t"
        "ldrd	r6, r7, [%[b], #48]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #48]\n\t"
        "ldrd	r4, r5, [%[a], #56]\n\t"
        "ldrd	r6, r7, [%[b], #56]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #56]\n\t"
        "ldrd	r4, r5, [%[a], #64]\n\t"
        "ldrd	r6, r7, [%[b], #64]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #64]\n\t"
        "ldrd	r4, r5, [%[a], #72]\n\t"
        "ldrd	r6, r7, [%[b], #72]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #72]\n\t"
        "ldrd	r4, r5, [%[a], #80]\n\t"
        "ldrd	r6, r7, [%[b], #80]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #80]\n\t"
        "ldrd	r4, r5, [%[a], #88]\n\t"
        "ldrd	r6, r7, [%[b], #88]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #88]\n\t"
        "ldrd	r4, r5, [%[a], #96]\n\t"
        "ldrd	r6, r7, [%[b], #96]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #96]\n\t"
        "ldrd	r4, r5, [%[a], #104]\n\t"
        "ldrd	r6, r7, [%[b], #104]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #104]\n\t"
        "ldrd	r4, r5, [%[a], #112]\n\t"
        "ldrd	r6, r7, [%[b], #112]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #112]\n\t"
        "ldrd	r4, r5, [%[a], #120]\n\t"
        "ldrd	r6, r7, [%[b], #120]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #120]\n\t"
        "ldrd	r4, r5, [%[a], #128]\n\t"
        "ldrd	r6, r7, [%[b], #128]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #128]\n\t"
        "ldrd	r4, r5, [%[a], #136]\n\t"
        "ldrd	r6, r7, [%[b], #136]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #136]\n\t"
        "ldrd	r4, r5, [%[a], #144]\n\t"
        "ldrd	r6, r7, [%[b], #144]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #144]\n\t"
        "ldrd	r4, r5, [%[a], #152]\n\t"
        "ldrd	r6, r7, [%[b], #152]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #152]\n\t"
        "ldrd	r4, r5, [%[a], #160]\n\t"
        "ldrd	r6, r7, [%[b], #160]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #160]\n\t"
        "ldrd	r4, r5, [%[a], #168]\n\t"
        "ldrd	r6, r7, [%[b], #168]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #168]\n\t"
        "ldrd	r4, r5, [%[a], #176]\n\t"
        "ldrd	r6, r7, [%[b], #176]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #176]\n\t"
        "ldrd	r4, r5, [%[a], #184]\n\t"
        "ldrd	r6, r7, [%[b], #184]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #184]\n\t"
        "ldrd	r4, r5, [%[a], #192]\n\t"
        "ldrd	r6, r7, [%[b], #192]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #192]\n\t"
        "ldrd	r4, r5, [%[a], #200]\n\t"
        "ldrd	r6, r7, [%[b], #200]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #200]\n\t"
        "ldrd	r4, r5, [%[a], #208]\n\t"
        "ldrd	r6, r7, [%[b], #208]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #208]\n\t"
        "ldrd	r4, r5, [%[a], #216]\n\t"
        "ldrd	r6, r7, [%[b], #216]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #216]\n\t"
        "ldrd	r4, r5, [%[a], #224]\n\t"
        "ldrd	r6, r7, [%[b], #224]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #224]\n\t"
        "ldrd	r4, r5, [%[a], #232]\n\t"
        "ldrd	r6, r7, [%[b], #232]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #232]\n\t"
        "ldrd	r4, r5, [%[a], #240]\n\t"
        "ldrd	r6, r7, [%[b], #240]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #240]\n\t"
        "ldrd	r4, r5, [%[a], #248]\n\t"
        "ldrd	r6, r7, [%[b], #248]\n\t"
        "and	r6, r6, %[m]\n\t"
        "and	r7, r7, %[m]\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r7\n\t"
        "strd	r4, r5, [%[r], #248]\n\t"
        "adc	%[c], r8, r8\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r4", "r5", "r6", "r7", "r8"
    );

    return c;
}
#endif /* !WOLFSSL_SP_SMALL */

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
    sp_digit  d[128 * 4];
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
        a = d + 128;
        m = a + 256;
        r = a;

        sp_4096_from_bin(a, 128, in, inLen);
        sp_4096_from_mp(d, 128, dm);
        sp_4096_from_mp(m, 128, mm);
        err = sp_4096_mod_exp_128(r, a, d, 4096, m, 0);
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_128(r, out);
        *outLen = 512;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 128);
    }

    return err;
#else
    sp_digit a[64 * 11];
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
        p = a + 128 * 2;
        q = p + 64;
        qi = dq = dp = q + 64;
        tmpa = qi + 64;
        tmpb = tmpa + 128;
        r = a;

        sp_4096_from_bin(a, 128, in, inLen);
        sp_4096_from_mp(p, 64, pm);
        sp_4096_from_mp(q, 64, qm);
        sp_4096_from_mp(dp, 64, dpm);

        err = sp_2048_mod_exp_64(tmpa, a, dp, 2048, p, 1);
    }
    if (err == MP_OKAY) {
        sp_4096_from_mp(dq, 64, dqm);
        err = sp_2048_mod_exp_64(tmpb, a, dq, 2048, q, 1);
    }

    if (err == MP_OKAY) {
        c = sp_2048_sub_in_place_64(tmpa, tmpb);
        c += sp_4096_cond_add_64(tmpa, tmpa, p, c);
        sp_4096_cond_add_64(tmpa, tmpa, p, c);

        sp_2048_from_mp(qi, 64, qim);
        sp_2048_mul_64(tmpa, tmpa, qi);
        err = sp_2048_mod_64(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_2048_mul_64(tmpa, q, tmpa);
        XMEMSET(&tmpb[64], 0, sizeof(sp_digit) * 64);
        sp_4096_add_128(r, tmpb, tmpa);

        sp_4096_to_bin_128(r, out);
        *outLen = 512;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 64 * 11);
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
#if DIGIT_BIT == 32
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 128);
        r->used = 128;
        mp_clamp(r);
#elif DIGIT_BIT < 32
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 128; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 32) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 32 - s;
        }
        r->used = (4096 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 128; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 32 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 32 - s;
            }
            else {
                s += 32;
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
    sp_digit b[256];
    sp_digit e[128];
    sp_digit m[128];
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
        sp_4096_from_mp(b, 128, base);
        sp_4096_from_mp(e, 128, exp);
        sp_4096_from_mp(m, 128, mod);

        err = sp_4096_mod_exp_128(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_4096_to_mp(r, res);
    }

    XMEMSET(e, 0, sizeof(e));

    return err;
}

#ifdef WOLFSSL_HAVE_SP_DH

#ifdef HAVE_FFDHE_4096
static void sp_4096_lshift_128(sp_digit* r, const sp_digit* a, byte n)
{
    __asm__ __volatile__ (
        "rsb	r6, %[n], #31\n\t"
        "ldr	r3, [%[a], #508]\n\t"
        "lsr	r4, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r4, r4, r6\n\t"
        "ldr	r2, [%[a], #504]\n\t"
        "str	r4, [%[r], #512]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #500]\n\t"
        "str	r3, [%[r], #508]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #496]\n\t"
        "str	r2, [%[r], #504]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #492]\n\t"
        "str	r4, [%[r], #500]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #488]\n\t"
        "str	r3, [%[r], #496]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #484]\n\t"
        "str	r2, [%[r], #492]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #480]\n\t"
        "str	r4, [%[r], #488]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #476]\n\t"
        "str	r3, [%[r], #484]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #472]\n\t"
        "str	r2, [%[r], #480]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #468]\n\t"
        "str	r4, [%[r], #476]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #464]\n\t"
        "str	r3, [%[r], #472]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #460]\n\t"
        "str	r2, [%[r], #468]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #456]\n\t"
        "str	r4, [%[r], #464]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #452]\n\t"
        "str	r3, [%[r], #460]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #448]\n\t"
        "str	r2, [%[r], #456]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #444]\n\t"
        "str	r4, [%[r], #452]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #440]\n\t"
        "str	r3, [%[r], #448]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #436]\n\t"
        "str	r2, [%[r], #444]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #432]\n\t"
        "str	r4, [%[r], #440]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #428]\n\t"
        "str	r3, [%[r], #436]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #424]\n\t"
        "str	r2, [%[r], #432]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #420]\n\t"
        "str	r4, [%[r], #428]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #416]\n\t"
        "str	r3, [%[r], #424]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #412]\n\t"
        "str	r2, [%[r], #420]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #408]\n\t"
        "str	r4, [%[r], #416]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #404]\n\t"
        "str	r3, [%[r], #412]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #400]\n\t"
        "str	r2, [%[r], #408]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #396]\n\t"
        "str	r4, [%[r], #404]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #392]\n\t"
        "str	r3, [%[r], #400]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #388]\n\t"
        "str	r2, [%[r], #396]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #384]\n\t"
        "str	r4, [%[r], #392]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #380]\n\t"
        "str	r3, [%[r], #388]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #376]\n\t"
        "str	r2, [%[r], #384]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #372]\n\t"
        "str	r4, [%[r], #380]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #368]\n\t"
        "str	r3, [%[r], #376]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #364]\n\t"
        "str	r2, [%[r], #372]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #360]\n\t"
        "str	r4, [%[r], #368]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #356]\n\t"
        "str	r3, [%[r], #364]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #352]\n\t"
        "str	r2, [%[r], #360]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #348]\n\t"
        "str	r4, [%[r], #356]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #344]\n\t"
        "str	r3, [%[r], #352]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #340]\n\t"
        "str	r2, [%[r], #348]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #336]\n\t"
        "str	r4, [%[r], #344]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #332]\n\t"
        "str	r3, [%[r], #340]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #328]\n\t"
        "str	r2, [%[r], #336]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #324]\n\t"
        "str	r4, [%[r], #332]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #320]\n\t"
        "str	r3, [%[r], #328]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #316]\n\t"
        "str	r2, [%[r], #324]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #312]\n\t"
        "str	r4, [%[r], #320]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #308]\n\t"
        "str	r3, [%[r], #316]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #304]\n\t"
        "str	r2, [%[r], #312]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #300]\n\t"
        "str	r4, [%[r], #308]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #296]\n\t"
        "str	r3, [%[r], #304]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #292]\n\t"
        "str	r2, [%[r], #300]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #288]\n\t"
        "str	r4, [%[r], #296]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #284]\n\t"
        "str	r3, [%[r], #292]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #280]\n\t"
        "str	r2, [%[r], #288]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #276]\n\t"
        "str	r4, [%[r], #284]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #272]\n\t"
        "str	r3, [%[r], #280]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #268]\n\t"
        "str	r2, [%[r], #276]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #264]\n\t"
        "str	r4, [%[r], #272]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #260]\n\t"
        "str	r3, [%[r], #268]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #256]\n\t"
        "str	r2, [%[r], #264]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #252]\n\t"
        "str	r4, [%[r], #260]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #248]\n\t"
        "str	r3, [%[r], #256]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #244]\n\t"
        "str	r2, [%[r], #252]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #240]\n\t"
        "str	r4, [%[r], #248]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #236]\n\t"
        "str	r3, [%[r], #244]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #232]\n\t"
        "str	r2, [%[r], #240]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #228]\n\t"
        "str	r4, [%[r], #236]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #224]\n\t"
        "str	r3, [%[r], #232]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #220]\n\t"
        "str	r2, [%[r], #228]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #216]\n\t"
        "str	r4, [%[r], #224]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #212]\n\t"
        "str	r3, [%[r], #220]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #208]\n\t"
        "str	r2, [%[r], #216]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #204]\n\t"
        "str	r4, [%[r], #212]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #200]\n\t"
        "str	r3, [%[r], #208]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #196]\n\t"
        "str	r2, [%[r], #204]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #192]\n\t"
        "str	r4, [%[r], #200]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #188]\n\t"
        "str	r3, [%[r], #196]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #184]\n\t"
        "str	r2, [%[r], #192]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #180]\n\t"
        "str	r4, [%[r], #188]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #176]\n\t"
        "str	r3, [%[r], #184]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #172]\n\t"
        "str	r2, [%[r], #180]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #168]\n\t"
        "str	r4, [%[r], #176]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #164]\n\t"
        "str	r3, [%[r], #172]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #160]\n\t"
        "str	r2, [%[r], #168]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #156]\n\t"
        "str	r4, [%[r], #164]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #152]\n\t"
        "str	r3, [%[r], #160]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #148]\n\t"
        "str	r2, [%[r], #156]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #144]\n\t"
        "str	r4, [%[r], #152]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #140]\n\t"
        "str	r3, [%[r], #148]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #136]\n\t"
        "str	r2, [%[r], #144]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #132]\n\t"
        "str	r4, [%[r], #140]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #128]\n\t"
        "str	r3, [%[r], #136]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #124]\n\t"
        "str	r2, [%[r], #132]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #120]\n\t"
        "str	r4, [%[r], #128]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #116]\n\t"
        "str	r3, [%[r], #124]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #112]\n\t"
        "str	r2, [%[r], #120]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #108]\n\t"
        "str	r4, [%[r], #116]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #104]\n\t"
        "str	r3, [%[r], #112]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #100]\n\t"
        "str	r2, [%[r], #108]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #96]\n\t"
        "str	r4, [%[r], #104]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #92]\n\t"
        "str	r3, [%[r], #100]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #88]\n\t"
        "str	r2, [%[r], #96]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #84]\n\t"
        "str	r4, [%[r], #92]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #80]\n\t"
        "str	r3, [%[r], #88]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #76]\n\t"
        "str	r2, [%[r], #84]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #72]\n\t"
        "str	r4, [%[r], #80]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #68]\n\t"
        "str	r3, [%[r], #76]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #64]\n\t"
        "str	r2, [%[r], #72]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #60]\n\t"
        "str	r4, [%[r], #68]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #56]\n\t"
        "str	r3, [%[r], #64]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #52]\n\t"
        "str	r2, [%[r], #60]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #48]\n\t"
        "str	r4, [%[r], #56]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #44]\n\t"
        "str	r3, [%[r], #52]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #40]\n\t"
        "str	r2, [%[r], #48]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #36]\n\t"
        "str	r4, [%[r], #44]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #32]\n\t"
        "str	r3, [%[r], #40]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #28]\n\t"
        "str	r2, [%[r], #36]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #24]\n\t"
        "str	r4, [%[r], #32]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #20]\n\t"
        "str	r3, [%[r], #28]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #16]\n\t"
        "str	r2, [%[r], #24]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #12]\n\t"
        "str	r4, [%[r], #20]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "ldr	r4, [%[a], #8]\n\t"
        "str	r3, [%[r], #16]\n\t"
        "lsr	r5, r4, #1\n\t"
        "lsl	r4, r4, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r2, r2, r5\n\t"
        "ldr	r3, [%[a], #4]\n\t"
        "str	r2, [%[r], #12]\n\t"
        "lsr	r5, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r4, r4, r5\n\t"
        "ldr	r2, [%[a], #0]\n\t"
        "str	r4, [%[r], #8]\n\t"
        "lsr	r5, r2, #1\n\t"
        "lsl	r2, r2, %[n]\n\t"
        "lsr	r5, r5, r6\n\t"
        "orr	r3, r3, r5\n\t"
        "strd	r2, r3, [%[r]]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [n] "r" (n)
        : "memory", "r2", "r3", "r4", "r5", "r6"
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
static int sp_4096_mod_exp_2_128(sp_digit* r, const sp_digit* e, int bits,
        const sp_digit* m)
{
    sp_digit td[385];
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
        tmp = td + 256;

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_128(norm, m);

        i = (bits - 1) / 32;
        n = e[i--];
        c = bits & 31;
        if (c == 0) {
            c = 32;
        }
        c -= bits % 5;
        if (c == 32) {
            c = 27;
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
            n <<= 32 - c;
        }
        sp_4096_lshift_128(r, norm, y);
        for (; i>=0 || c>=5; ) {
            if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 27);
                n <<= 5;
                c = 27;
            }
            else if (c < 5) {
                y = (byte)(n >> 27);
                n = e[i--];
                c = 5 - c;
                y |= (byte)(n >> (32 - c));
                n <<= c;
                c = 32 - c;
            }
            else {
                y = (byte)((n >> 27) & 0x1f);
                n <<= 5;
                c -= 5;
            }

            sp_4096_mont_sqr_128(r, r, m, mp);
            sp_4096_mont_sqr_128(r, r, m, mp);
            sp_4096_mont_sqr_128(r, r, m, mp);
            sp_4096_mont_sqr_128(r, r, m, mp);
            sp_4096_mont_sqr_128(r, r, m, mp);

            sp_4096_lshift_128(r, r, y);
            sp_4096_mul_d_128(tmp, norm, r[128]);
            r[128] = 0;
            o = sp_4096_add_128(r, r, tmp);
            sp_4096_cond_sub_128(r, r, m, (sp_digit)0 - o);
        }

        XMEMSET(&r[128], 0, sizeof(sp_digit) * 128U);
        sp_4096_mont_reduce_128(r, m, mp);

        mask = 0 - (sp_4096_cmp_128(r, m) >= 0);
        sp_4096_cond_sub_128(r, r, m, mask);
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
    sp_digit b[256];
    sp_digit e[128];
    sp_digit m[128];
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
        sp_4096_from_mp(b, 128, base);
        sp_4096_from_bin(e, 128, exp, expLen);
        sp_4096_from_mp(m, 128, mod);

    #ifdef HAVE_FFDHE_4096
        if (base->used == 1 && base->dp[0] == 2 && m[127] == (sp_digit)-1)
            err = sp_4096_mod_exp_2_128(r, e, expLen * 8, m);
        else
    #endif
            err = sp_4096_mod_exp_128(r, b, e, expLen * 8, m, 0);

    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_128(r, out);
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
#endif /* WOLFSSL_SP_ARM32_ASM */
#endif /* WOLFSSL_HAVE_SP_RSA | WOLFSSL_HAVE_SP_DH | WOLFSSL_HAVE_SP_ECC */
