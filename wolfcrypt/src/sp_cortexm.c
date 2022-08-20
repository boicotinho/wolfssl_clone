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

#ifdef __IAR_SYSTEMS_ICC__
#define __asm__        asm
#define __volatile__   volatile
#endif /* __IAR_SYSTEMS_ICC__ */
#ifdef __KEIL__
#define __asm__        __asm
#define __volatile__   volatile
#endif

#ifdef WOLFSSL_SP_ARM_CORTEX_M_ASM
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
SP_NOINLINE static void sp_2048_mul_8(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit tmp_arr[8];
    sp_digit* tmp = tmp_arr;

    __asm__ __volatile__ (
        /* A[0] * B[0] */
        "ldr	r6, [%[a], #0]\n\t"
        "ldr	r8, [%[b], #0]\n\t"
        "umull	r3, r4, r6, r8\n\t"
        "mov	r5, #0\n\t"
        "str	r3, [%[tmp], #0]\n\t"
        "mov	r3, #0\n\t"
        /* A[0] * B[1] */
        "ldr	r8, [%[b], #4]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adc	r5, r5, r8\n\t"
        /* A[1] * B[0] */
        "ldr	r6, [%[a], #4]\n\t"
        "ldr	r8, [%[b], #0]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        "str	r4, [%[tmp], #4]\n\t"
        "mov	r4, #0\n\t"
        /* A[0] * B[2] */
        "ldr	r6, [%[a], #0]\n\t"
        "ldr	r8, [%[b], #8]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        /* A[1] * B[1] */
        "ldr	r6, [%[a], #4]\n\t"
        "ldr	r8, [%[b], #4]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        /* A[2] * B[0] */
        "ldr	r6, [%[a], #8]\n\t"
        "ldr	r8, [%[b], #0]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        "str	r5, [%[tmp], #8]\n\t"
        "mov	r5, #0\n\t"
        /* A[0] * B[3] */
        "ldr	r6, [%[a], #0]\n\t"
        "ldr	r8, [%[b], #12]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[1] * B[2] */
        "ldr	r6, [%[a], #4]\n\t"
        "ldr	r8, [%[b], #8]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[2] * B[1] */
        "ldr	r6, [%[a], #8]\n\t"
        "ldr	r8, [%[b], #4]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[3] * B[0] */
        "ldr	r6, [%[a], #12]\n\t"
        "ldr	r8, [%[b], #0]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        "str	r3, [%[tmp], #12]\n\t"
        "mov	r3, #0\n\t"
        /* A[0] * B[4] */
        "ldr	r6, [%[a], #0]\n\t"
        "ldr	r8, [%[b], #16]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        /* A[1] * B[3] */
        "ldr	r6, [%[a], #4]\n\t"
        "ldr	r8, [%[b], #12]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        /* A[2] * B[2] */
        "ldr	r6, [%[a], #8]\n\t"
        "ldr	r8, [%[b], #8]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        /* A[3] * B[1] */
        "ldr	r6, [%[a], #12]\n\t"
        "ldr	r8, [%[b], #4]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        /* A[4] * B[0] */
        "ldr	r6, [%[a], #16]\n\t"
        "ldr	r8, [%[b], #0]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        "str	r4, [%[tmp], #16]\n\t"
        "mov	r4, #0\n\t"
        /* A[0] * B[5] */
        "ldr	r6, [%[a], #0]\n\t"
        "ldr	r8, [%[b], #20]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        /* A[1] * B[4] */
        "ldr	r6, [%[a], #4]\n\t"
        "ldr	r8, [%[b], #16]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        /* A[2] * B[3] */
        "ldr	r6, [%[a], #8]\n\t"
        "ldr	r8, [%[b], #12]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        /* A[3] * B[2] */
        "ldr	r6, [%[a], #12]\n\t"
        "ldr	r8, [%[b], #8]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        /* A[4] * B[1] */
        "ldr	r6, [%[a], #16]\n\t"
        "ldr	r8, [%[b], #4]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        /* A[5] * B[0] */
        "ldr	r6, [%[a], #20]\n\t"
        "ldr	r8, [%[b], #0]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        "str	r5, [%[tmp], #20]\n\t"
        "mov	r5, #0\n\t"
        /* A[0] * B[6] */
        "ldr	r6, [%[a], #0]\n\t"
        "ldr	r8, [%[b], #24]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[1] * B[5] */
        "ldr	r6, [%[a], #4]\n\t"
        "ldr	r8, [%[b], #20]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[2] * B[4] */
        "ldr	r6, [%[a], #8]\n\t"
        "ldr	r8, [%[b], #16]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[3] * B[3] */
        "ldr	r6, [%[a], #12]\n\t"
        "ldr	r8, [%[b], #12]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[4] * B[2] */
        "ldr	r6, [%[a], #16]\n\t"
        "ldr	r8, [%[b], #8]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[5] * B[1] */
        "ldr	r6, [%[a], #20]\n\t"
        "ldr	r8, [%[b], #4]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[6] * B[0] */
        "ldr	r6, [%[a], #24]\n\t"
        "ldr	r8, [%[b], #0]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        "str	r3, [%[tmp], #24]\n\t"
        "mov	r3, #0\n\t"
        /* A[0] * B[7] */
        "ldr	r6, [%[a], #0]\n\t"
        "ldr	r8, [%[b], #28]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        /* A[1] * B[6] */
        "ldr	r6, [%[a], #4]\n\t"
        "ldr	r8, [%[b], #24]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        /* A[2] * B[5] */
        "ldr	r6, [%[a], #8]\n\t"
        "ldr	r8, [%[b], #20]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        /* A[3] * B[4] */
        "ldr	r6, [%[a], #12]\n\t"
        "ldr	r8, [%[b], #16]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        /* A[4] * B[3] */
        "ldr	r6, [%[a], #16]\n\t"
        "ldr	r8, [%[b], #12]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        /* A[5] * B[2] */
        "ldr	r6, [%[a], #20]\n\t"
        "ldr	r8, [%[b], #8]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        /* A[6] * B[1] */
        "ldr	r6, [%[a], #24]\n\t"
        "ldr	r8, [%[b], #4]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        /* A[7] * B[0] */
        "ldr	r6, [%[a], #28]\n\t"
        "ldr	r8, [%[b], #0]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        "str	r4, [%[tmp], #28]\n\t"
        "mov	r4, #0\n\t"
        /* A[1] * B[7] */
        "ldr	r6, [%[a], #4]\n\t"
        "ldr	r8, [%[b], #28]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        /* A[2] * B[6] */
        "ldr	r6, [%[a], #8]\n\t"
        "ldr	r8, [%[b], #24]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        /* A[3] * B[5] */
        "ldr	r6, [%[a], #12]\n\t"
        "ldr	r8, [%[b], #20]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        /* A[4] * B[4] */
        "ldr	r6, [%[a], #16]\n\t"
        "ldr	r8, [%[b], #16]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        /* A[5] * B[3] */
        "ldr	r6, [%[a], #20]\n\t"
        "ldr	r8, [%[b], #12]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        /* A[6] * B[2] */
        "ldr	r6, [%[a], #24]\n\t"
        "ldr	r8, [%[b], #8]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        /* A[7] * B[1] */
        "ldr	r6, [%[a], #28]\n\t"
        "ldr	r8, [%[b], #4]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        "str	r5, [%[r], #32]\n\t"
        "mov	r5, #0\n\t"
        /* A[2] * B[7] */
        "ldr	r6, [%[a], #8]\n\t"
        "ldr	r8, [%[b], #28]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[3] * B[6] */
        "ldr	r6, [%[a], #12]\n\t"
        "ldr	r8, [%[b], #24]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[4] * B[5] */
        "ldr	r6, [%[a], #16]\n\t"
        "ldr	r8, [%[b], #20]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[5] * B[4] */
        "ldr	r6, [%[a], #20]\n\t"
        "ldr	r8, [%[b], #16]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[6] * B[3] */
        "ldr	r6, [%[a], #24]\n\t"
        "ldr	r8, [%[b], #12]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[7] * B[2] */
        "ldr	r6, [%[a], #28]\n\t"
        "ldr	r8, [%[b], #8]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        "str	r3, [%[r], #36]\n\t"
        "mov	r3, #0\n\t"
        /* A[3] * B[7] */
        "ldr	r6, [%[a], #12]\n\t"
        "ldr	r8, [%[b], #28]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        /* A[4] * B[6] */
        "ldr	r6, [%[a], #16]\n\t"
        "ldr	r8, [%[b], #24]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        /* A[5] * B[5] */
        "ldr	r6, [%[a], #20]\n\t"
        "ldr	r8, [%[b], #20]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        /* A[6] * B[4] */
        "ldr	r6, [%[a], #24]\n\t"
        "ldr	r8, [%[b], #16]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        /* A[7] * B[3] */
        "ldr	r6, [%[a], #28]\n\t"
        "ldr	r8, [%[b], #12]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        "str	r4, [%[r], #40]\n\t"
        "mov	r4, #0\n\t"
        /* A[4] * B[7] */
        "ldr	r6, [%[a], #16]\n\t"
        "ldr	r8, [%[b], #28]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        /* A[5] * B[6] */
        "ldr	r6, [%[a], #20]\n\t"
        "ldr	r8, [%[b], #24]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        /* A[6] * B[5] */
        "ldr	r6, [%[a], #24]\n\t"
        "ldr	r8, [%[b], #20]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        /* A[7] * B[4] */
        "ldr	r6, [%[a], #28]\n\t"
        "ldr	r8, [%[b], #16]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        "str	r5, [%[r], #44]\n\t"
        "mov	r5, #0\n\t"
        /* A[5] * B[7] */
        "ldr	r6, [%[a], #20]\n\t"
        "ldr	r8, [%[b], #28]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[6] * B[6] */
        "ldr	r6, [%[a], #24]\n\t"
        "ldr	r8, [%[b], #24]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[7] * B[5] */
        "ldr	r6, [%[a], #28]\n\t"
        "ldr	r8, [%[b], #20]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        "str	r3, [%[r], #48]\n\t"
        "mov	r3, #0\n\t"
        /* A[6] * B[7] */
        "ldr	r6, [%[a], #24]\n\t"
        "ldr	r8, [%[b], #28]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        /* A[7] * B[6] */
        "ldr	r6, [%[a], #28]\n\t"
        "ldr	r8, [%[b], #24]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        "str	r4, [%[r], #52]\n\t"
        "mov	r4, #0\n\t"
        /* A[7] * B[7] */
        "ldr	r6, [%[a], #28]\n\t"
        "ldr	r8, [%[b], #28]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adc	r3, r3, r8\n\t"
        "str	r5, [%[r], #56]\n\t"
        "str	r3, [%[r], #60]\n\t"
        /* Transfer tmp to r */
        "ldr	r3, [%[tmp], #0]\n\t"
        "ldr	r4, [%[tmp], #4]\n\t"
        "ldr	r5, [%[tmp], #8]\n\t"
        "ldr	r6, [%[tmp], #12]\n\t"
        "str	r3, [%[r], #0]\n\t"
        "str	r4, [%[r], #4]\n\t"
        "str	r5, [%[r], #8]\n\t"
        "str	r6, [%[r], #12]\n\t"
        "ldr	r3, [%[tmp], #16]\n\t"
        "ldr	r4, [%[tmp], #20]\n\t"
        "ldr	r5, [%[tmp], #24]\n\t"
        "ldr	r6, [%[tmp], #28]\n\t"
        "str	r3, [%[r], #16]\n\t"
        "str	r4, [%[r], #20]\n\t"
        "str	r5, [%[r], #24]\n\t"
        "str	r6, [%[r], #28]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [tmp] "r" (tmp)
        : "memory", "r3", "r4", "r5", "r6", "r8"
    );
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_2048_add_8(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "mov	%[c], #0\n\t"
        "adc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
    );

    return c;
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_2048_sub_in_place_16(sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "subs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6"
    );

    return c;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_2048_add_16(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "mov	%[c], #0\n\t"
        "adc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_2048_sub_in_place_32(sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "subs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6"
    );

    return c;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_2048_add_32(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "mov	%[c], #0\n\t"
        "adc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_2048_sub_in_place_64(sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "subs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6"
    );

    return c;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_2048_add_64(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "mov	%[c], #0\n\t"
        "adc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static void sp_2048_sqr_8(sp_digit* r, const sp_digit* a)
{
    sp_digit tmp_arr[8];
    sp_digit* tmp = tmp_arr;
    __asm__ __volatile__ (
        /* A[0] * A[0] */
        "ldr	r6, [%[a], #0]\n\t"
        "umull	r3, r4, r6, r6\n\t"
        "mov	r5, #0\n\t"
        "str	r3, [%[tmp], #0]\n\t"
        "mov	r3, #0\n\t"
        /* A[0] * A[1] */
        "ldr	r8, [%[a], #4]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adc	r5, r5, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        "str	r4, [%[tmp], #4]\n\t"
        "mov	r4, #0\n\t"
        /* A[0] * A[2] */
        "ldr	r6, [%[a], #0]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adc	r3, r3, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        /* A[1] * A[1] */
        "ldr	r6, [%[a], #4]\n\t"
        "umull	r6, r8, r6, r6\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        "str	r5, [%[tmp], #8]\n\t"
        "mov	r5, #0\n\t"
        /* A[0] * A[3] */
        "ldr	r6, [%[a], #0]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r9, r10, r6, r8\n\t"
        "mov	r11, #0\n\t"
        /* A[1] * A[2] */
        "ldr	r6, [%[a], #4]\n\t"
        "ldr	r8, [%[a], #8]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r9, r9, r6\n\t"
        "adcs 	r10, r10, r8\n\t"
        "adc	r11, r11, #0\n\t"
        "adds	r9, r9, r9\n\t"
        "adcs	r10, r10, r10\n\t"
        "adc	r11, r11, r11\n\t"
        "adds	r3, r3, r9\n\t"
        "adcs	r4, r4, r10\n\t"
        "adc	r5, r5, r11\n\t"
        "str	r3, [%[tmp], #12]\n\t"
        "mov	r3, #0\n\t"
        /* A[0] * A[4] */
        "ldr	r6, [%[a], #0]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r9, r10, r6, r8\n\t"
        "mov	r11, #0\n\t"
        /* A[1] * A[3] */
        "ldr	r6, [%[a], #4]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r9, r9, r6\n\t"
        "adcs 	r10, r10, r8\n\t"
        "adc	r11, r11, #0\n\t"
        /* A[2] * A[2] */
        "ldr	r6, [%[a], #8]\n\t"
        "umull	r6, r8, r6, r6\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        "adds	r9, r9, r9\n\t"
        "adcs	r10, r10, r10\n\t"
        "adc	r11, r11, r11\n\t"
        "adds	r4, r4, r9\n\t"
        "adcs	r5, r5, r10\n\t"
        "adc	r3, r3, r11\n\t"
        "str	r4, [%[tmp], #16]\n\t"
        "mov	r4, #0\n\t"
        /* A[0] * A[5] */
        "ldr	r6, [%[a], #0]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r9, r10, r6, r8\n\t"
        "mov	r11, #0\n\t"
        /* A[1] * A[4] */
        "ldr	r6, [%[a], #4]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r9, r9, r6\n\t"
        "adcs 	r10, r10, r8\n\t"
        "adc	r11, r11, #0\n\t"
        /* A[2] * A[3] */
        "ldr	r6, [%[a], #8]\n\t"
        "ldr	r8, [%[a], #12]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r9, r9, r6\n\t"
        "adcs 	r10, r10, r8\n\t"
        "adc	r11, r11, #0\n\t"
        "adds	r9, r9, r9\n\t"
        "adcs	r10, r10, r10\n\t"
        "adc	r11, r11, r11\n\t"
        "adds	r5, r5, r9\n\t"
        "adcs	r3, r3, r10\n\t"
        "adc	r4, r4, r11\n\t"
        "str	r5, [%[tmp], #20]\n\t"
        "mov	r5, #0\n\t"
        /* A[0] * A[6] */
        "ldr	r6, [%[a], #0]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r9, r10, r6, r8\n\t"
        "mov	r11, #0\n\t"
        /* A[1] * A[5] */
        "ldr	r6, [%[a], #4]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r9, r9, r6\n\t"
        "adcs 	r10, r10, r8\n\t"
        "adc	r11, r11, #0\n\t"
        /* A[2] * A[4] */
        "ldr	r6, [%[a], #8]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r9, r9, r6\n\t"
        "adcs 	r10, r10, r8\n\t"
        "adc	r11, r11, #0\n\t"
        /* A[3] * A[3] */
        "ldr	r6, [%[a], #12]\n\t"
        "umull	r6, r8, r6, r6\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        "adds	r9, r9, r9\n\t"
        "adcs	r10, r10, r10\n\t"
        "adc	r11, r11, r11\n\t"
        "adds	r3, r3, r9\n\t"
        "adcs	r4, r4, r10\n\t"
        "adc	r5, r5, r11\n\t"
        "str	r3, [%[tmp], #24]\n\t"
        "mov	r3, #0\n\t"
        /* A[0] * A[7] */
        "ldr	r6, [%[a], #0]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "umull	r9, r10, r6, r8\n\t"
        "mov	r11, #0\n\t"
        /* A[1] * A[6] */
        "ldr	r6, [%[a], #4]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r9, r9, r6\n\t"
        "adcs 	r10, r10, r8\n\t"
        "adc	r11, r11, #0\n\t"
        /* A[2] * A[5] */
        "ldr	r6, [%[a], #8]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r9, r9, r6\n\t"
        "adcs 	r10, r10, r8\n\t"
        "adc	r11, r11, #0\n\t"
        /* A[3] * A[4] */
        "ldr	r6, [%[a], #12]\n\t"
        "ldr	r8, [%[a], #16]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r9, r9, r6\n\t"
        "adcs 	r10, r10, r8\n\t"
        "adc	r11, r11, #0\n\t"
        "adds	r9, r9, r9\n\t"
        "adcs	r10, r10, r10\n\t"
        "adc	r11, r11, r11\n\t"
        "adds	r4, r4, r9\n\t"
        "adcs	r5, r5, r10\n\t"
        "adc	r3, r3, r11\n\t"
        "str	r4, [%[tmp], #28]\n\t"
        "mov	r4, #0\n\t"
        /* A[1] * A[7] */
        "ldr	r6, [%[a], #4]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "umull	r9, r10, r6, r8\n\t"
        "mov	r11, #0\n\t"
        /* A[2] * A[6] */
        "ldr	r6, [%[a], #8]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r9, r9, r6\n\t"
        "adcs 	r10, r10, r8\n\t"
        "adc	r11, r11, #0\n\t"
        /* A[3] * A[5] */
        "ldr	r6, [%[a], #12]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r9, r9, r6\n\t"
        "adcs 	r10, r10, r8\n\t"
        "adc	r11, r11, #0\n\t"
        /* A[4] * A[4] */
        "ldr	r6, [%[a], #16]\n\t"
        "umull	r6, r8, r6, r6\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        "adds	r9, r9, r9\n\t"
        "adcs	r10, r10, r10\n\t"
        "adc	r11, r11, r11\n\t"
        "adds	r5, r5, r9\n\t"
        "adcs	r3, r3, r10\n\t"
        "adc	r4, r4, r11\n\t"
        "str	r5, [%[r], #32]\n\t"
        "mov	r5, #0\n\t"
        /* A[2] * A[7] */
        "ldr	r6, [%[a], #8]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "umull	r9, r10, r6, r8\n\t"
        "mov	r11, #0\n\t"
        /* A[3] * A[6] */
        "ldr	r6, [%[a], #12]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r9, r9, r6\n\t"
        "adcs 	r10, r10, r8\n\t"
        "adc	r11, r11, #0\n\t"
        /* A[4] * A[5] */
        "ldr	r6, [%[a], #16]\n\t"
        "ldr	r8, [%[a], #20]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r9, r9, r6\n\t"
        "adcs 	r10, r10, r8\n\t"
        "adc	r11, r11, #0\n\t"
        "adds	r9, r9, r9\n\t"
        "adcs	r10, r10, r10\n\t"
        "adc	r11, r11, r11\n\t"
        "adds	r3, r3, r9\n\t"
        "adcs	r4, r4, r10\n\t"
        "adc	r5, r5, r11\n\t"
        "str	r3, [%[r], #36]\n\t"
        "mov	r3, #0\n\t"
        /* A[3] * A[7] */
        "ldr	r6, [%[a], #12]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "umull	r9, r10, r6, r8\n\t"
        "mov	r11, #0\n\t"
        /* A[4] * A[6] */
        "ldr	r6, [%[a], #16]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r9, r9, r6\n\t"
        "adcs 	r10, r10, r8\n\t"
        "adc	r11, r11, #0\n\t"
        /* A[5] * A[5] */
        "ldr	r6, [%[a], #20]\n\t"
        "umull	r6, r8, r6, r6\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        "adds	r9, r9, r9\n\t"
        "adcs	r10, r10, r10\n\t"
        "adc	r11, r11, r11\n\t"
        "adds	r4, r4, r9\n\t"
        "adcs	r5, r5, r10\n\t"
        "adc	r3, r3, r11\n\t"
        "str	r4, [%[r], #40]\n\t"
        "mov	r4, #0\n\t"
        /* A[4] * A[7] */
        "ldr	r6, [%[a], #16]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        /* A[5] * A[6] */
        "ldr	r6, [%[a], #20]\n\t"
        "ldr	r8, [%[a], #24]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r3, r3, r8\n\t"
        "adc	r4, r4, #0\n\t"
        "str	r5, [%[r], #44]\n\t"
        "mov	r5, #0\n\t"
        /* A[5] * A[7] */
        "ldr	r6, [%[a], #20]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[6] * A[6] */
        "ldr	r6, [%[a], #24]\n\t"
        "umull	r6, r8, r6, r6\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        "str	r3, [%[r], #48]\n\t"
        "mov	r3, #0\n\t"
        /* A[6] * A[7] */
        "ldr	r6, [%[a], #24]\n\t"
        "ldr	r8, [%[a], #28]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs 	r5, r5, r8\n\t"
        "adc	r3, r3, #0\n\t"
        "str	r4, [%[r], #52]\n\t"
        "mov	r4, #0\n\t"
        /* A[7] * A[7] */
        "ldr	r6, [%[a], #28]\n\t"
        "umull	r6, r8, r6, r6\n\t"
        "adds	r5, r5, r6\n\t"
        "adc	r3, r3, r8\n\t"
        "str	r5, [%[r], #56]\n\t"
        "str	r3, [%[r], #60]\n\t"
        /* Transfer tmp to r */
        "ldr	r3, [%[tmp], #0]\n\t"
        "ldr	r4, [%[tmp], #4]\n\t"
        "ldr	r5, [%[tmp], #8]\n\t"
        "ldr	r6, [%[tmp], #12]\n\t"
        "str	r3, [%[r], #0]\n\t"
        "str	r4, [%[r], #4]\n\t"
        "str	r5, [%[r], #8]\n\t"
        "str	r6, [%[r], #12]\n\t"
        "ldr	r3, [%[tmp], #16]\n\t"
        "ldr	r4, [%[tmp], #20]\n\t"
        "ldr	r5, [%[tmp], #24]\n\t"
        "ldr	r6, [%[tmp], #28]\n\t"
        "str	r3, [%[r], #16]\n\t"
        "str	r4, [%[r], #20]\n\t"
        "str	r5, [%[r], #24]\n\t"
        "str	r6, [%[r], #28]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [tmp] "r" (tmp)
        : "memory", "r3", "r4", "r5", "r6", "r8", "r9", "r10", "r11"
    );
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_2048_sub_8(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "subs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_digit sp_2048_sub_16(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "subs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_digit sp_2048_sub_32(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "subs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_digit sp_2048_add_64(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r6, %[a]\n\t"
        "mov	r8, #0\n\t"
        "add	r6, r6, #256\n\t"
        "sub	r8, r8, #1\n\t"
        "\n1:\n\t"
        "adds	%[c], %[c], r8\n\t"
        "ldr	r4, [%[a]]\n\t"
        "ldr	r5, [%[b]]\n\t"
        "adcs	r4, r4, r5\n\t"
        "str	r4, [%[r]]\n\t"
        "mov	%[c], #0\n\t"
        "adc	%[c], %[c], %[c]\n\t"
        "add	%[a], %[a], #4\n\t"
        "add	%[b], %[b], #4\n\t"
        "add	%[r], %[r], #4\n\t"
        "cmp	%[a], r6\n\t"
#ifdef __GNUC__
        "bne	1b\n\t"
#else
        "bne.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_digit sp_2048_sub_in_place_64(sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;
    __asm__ __volatile__ (
        "mov	r8, %[a]\n\t"
        "add	r8, r8, #256\n\t"
        "\n1:\n\t"
        "mov	r5, #0\n\t"
        "subs	r5, r5, %[c]\n\t"
        "ldr	r3, [%[a]]\n\t"
        "ldr	r4, [%[a], #4]\n\t"
        "ldr	r5, [%[b]]\n\t"
        "ldr	r6, [%[b], #4]\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "str	r3, [%[a]]\n\t"
        "str	r4, [%[a], #4]\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        "add	%[a], %[a], #8\n\t"
        "add	%[b], %[b], #8\n\t"
        "cmp	%[a], r8\n\t"
#ifdef __GNUC__
        "bne	1b\n\t"
#else
        "bne.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static void sp_2048_mul_64(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit tmp_arr[64 * 2];
    sp_digit* tmp = tmp_arr;
    __asm__ __volatile__ (
        "mov	r3, #0\n\t"
        "mov	r4, #0\n\t"
        "mov	r9, r3\n\t"
        "mov	r12, %[r]\n\t"
        "mov	r10, %[a]\n\t"
        "mov	r11, %[b]\n\t"
        "mov	r6, #1\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, r10\n\t"
        "mov	r14, r6\n\t"
        "\n1:\n\t"
        "mov	%[r], #0\n\t"
        "mov	r5, #0\n\t"
        "mov	r6, #252\n\t"
        "mov	%[a], r9\n\t"
        "subs	%[a], %[a], r6\n\t"
        "sbc	r6, r6, r6\n\t"
        "mvn	r6, r6\n\t"
        "and	%[a], %[a], r6\n\t"
        "mov	%[b], r9\n\t"
        "sub	%[b], %[b], %[a]\n\t"
        "add	%[a], %[a], r10\n\t"
        "add	%[b], %[b], r11\n\t"
        "\n2:\n\t"
        /* Multiply Start */
        "ldr	r6, [%[a]]\n\t"
        "ldr	r8, [%[b]]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        /* Multiply Done */
        "add	%[a], %[a], #4\n\t"
        "sub	%[b], %[b], #4\n\t"
        "cmp	%[a], r14\n\t"
#ifdef __GNUC__
        "beq	3f\n\t"
#else
        "beq.n	3f\n\t"
#endif /* __GNUC__ */
        "mov	r6, r9\n\t"
        "add	r6, r6, r10\n\t"
        "cmp	%[a], r6\n\t"
#ifdef __GNUC__
        "ble	2b\n\t"
#else
        "ble.n	2b\n\t"
#endif /* __GNUC__ */
        "\n3:\n\t"
        "mov	%[r], r12\n\t"
        "mov	r8, r9\n\t"
        "str	r3, [%[r], r8]\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "add	r8, r8, #4\n\t"
        "mov	r9, r8\n\t"
        "mov	r6, #1\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, #248\n\t"
        "cmp	r8, r6\n\t"
#ifdef __GNUC__
        "ble	1b\n\t"
#else
        "ble.n	1b\n\t"
#endif /* __GNUC__ */
        "str	r3, [%[r], r8]\n\t"
        "mov	%[a], r10\n\t"
        "mov	%[b], r11\n\t"
        :
        : [r] "r" (tmp), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r8", "r9", "r10", "r11", "r12", "r14"
    );

    XMEMCPY(r, tmp_arr, sizeof(tmp_arr));
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_64(sp_digit* r, const sp_digit* a)
{
    __asm__ __volatile__ (
        "mov	r3, #0\n\t"
        "mov	r4, #0\n\t"
        "mov	r5, #0\n\t"
        "mov	r9, r3\n\t"
        "mov	r12, %[r]\n\t"
        "mov	r6, #2\n\t"
        "lsl	r6, r6, #8\n\t"
        "neg	r6, r6\n\t"
        "add	sp, sp, r6\n\t"
        "mov	r11, sp\n\t"
        "mov	r10, %[a]\n\t"
        "\n1:\n\t"
        "mov	%[r], #0\n\t"
        "mov	r6, #252\n\t"
        "mov	%[a], r9\n\t"
        "subs	%[a], %[a], r6\n\t"
        "sbc	r6, r6, r6\n\t"
        "mvn	r6, r6\n\t"
        "and	%[a], %[a], r6\n\t"
        "mov	r2, r9\n\t"
        "sub	r2, r2, %[a]\n\t"
        "add	%[a], %[a], r10\n\t"
        "add	r2, r2, r10\n\t"
        "\n2:\n\t"
        "cmp	r2, %[a]\n\t"
#ifdef __GNUC__
        "beq	4f\n\t"
#else
        "beq.n	4f\n\t"
#endif /* __GNUC__ */
        /* Multiply * 2: Start */
        "ldr	r6, [%[a]]\n\t"
        "ldr	r8, [r2]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        /* Multiply * 2: Done */
#ifdef __GNUC__
        "bal	5f\n\t"
#else
        "bal.n	5f\n\t"
#endif /* __GNUC__ */
        "\n4:\n\t"
        /* Square: Start */
        "ldr	r6, [%[a]]\n\t"
        "umull	r6, r8, r6, r6\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        /* Square: Done */
        "\n5:\n\t"
        "add	%[a], %[a], #4\n\t"
        "sub	r2, r2, #4\n\t"
        "mov	r6, #1\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, r10\n\t"
        "cmp	%[a], r6\n\t"
#ifdef __GNUC__
        "beq	3f\n\t"
#else
        "beq.n	3f\n\t"
#endif /* __GNUC__ */
        "cmp	%[a], r2\n\t"
#ifdef __GNUC__
        "bgt	3f\n\t"
#else
        "bgt.n	3f\n\t"
#endif /* __GNUC__ */
        "mov	r8, r9\n\t"
        "add	r8, r8, r10\n\t"
        "cmp	%[a], r8\n\t"
#ifdef __GNUC__
        "ble	2b\n\t"
#else
        "ble.n	2b\n\t"
#endif /* __GNUC__ */
        "\n3:\n\t"
        "mov	%[r], r11\n\t"
        "mov	r8, r9\n\t"
        "str	r3, [%[r], r8]\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "mov	r5, #0\n\t"
        "add	r8, r8, #4\n\t"
        "mov	r9, r8\n\t"
        "mov	r6, #1\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, #248\n\t"
        "cmp	r8, r6\n\t"
#ifdef __GNUC__
        "ble	1b\n\t"
#else
        "ble.n	1b\n\t"
#endif /* __GNUC__ */
        "mov	%[a], r10\n\t"
        "str	r3, [%[r], r8]\n\t"
        "mov	%[r], r12\n\t"
        "mov	%[a], r11\n\t"
        "mov	r3, #1\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #252\n\t"
        "\n4:\n\t"
        "ldr	r6, [%[a], r3]\n\t"
        "str	r6, [%[r], r3]\n\t"
        "subs	r3, r3, #4\n\t"
#ifdef __GNUC__
        "bge	4b\n\t"
#else
        "bge.n	4b\n\t"
#endif /* __GNUC__ */
        "mov	r6, #2\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	sp, sp, r6\n\t"
        :
        : [r] "r" (r), [a] "r" (a)
        : "memory", "r2", "r3", "r4", "r5", "r6", "r8", "r9", "r10", "r11", "r12"
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
SP_NOINLINE static sp_digit sp_2048_add_32(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r6, %[a]\n\t"
        "mov	r8, #0\n\t"
        "add	r6, r6, #128\n\t"
        "sub	r8, r8, #1\n\t"
        "\n1:\n\t"
        "adds	%[c], %[c], r8\n\t"
        "ldr	r4, [%[a]]\n\t"
        "ldr	r5, [%[b]]\n\t"
        "adcs	r4, r4, r5\n\t"
        "str	r4, [%[r]]\n\t"
        "mov	%[c], #0\n\t"
        "adc	%[c], %[c], %[c]\n\t"
        "add	%[a], %[a], #4\n\t"
        "add	%[b], %[b], #4\n\t"
        "add	%[r], %[r], #4\n\t"
        "cmp	%[a], r6\n\t"
#ifdef __GNUC__
        "bne	1b\n\t"
#else
        "bne.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_digit sp_2048_sub_in_place_32(sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;
    __asm__ __volatile__ (
        "mov	r8, %[a]\n\t"
        "add	r8, r8, #128\n\t"
        "\n1:\n\t"
        "mov	r5, #0\n\t"
        "subs	r5, r5, %[c]\n\t"
        "ldr	r3, [%[a]]\n\t"
        "ldr	r4, [%[a], #4]\n\t"
        "ldr	r5, [%[b]]\n\t"
        "ldr	r6, [%[b], #4]\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "str	r3, [%[a]]\n\t"
        "str	r4, [%[a], #4]\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        "add	%[a], %[a], #8\n\t"
        "add	%[b], %[b], #8\n\t"
        "cmp	%[a], r8\n\t"
#ifdef __GNUC__
        "bne	1b\n\t"
#else
        "bne.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static void sp_2048_mul_32(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit tmp_arr[32 * 2];
    sp_digit* tmp = tmp_arr;
    __asm__ __volatile__ (
        "mov	r3, #0\n\t"
        "mov	r4, #0\n\t"
        "mov	r9, r3\n\t"
        "mov	r12, %[r]\n\t"
        "mov	r10, %[a]\n\t"
        "mov	r11, %[b]\n\t"
        "mov	r6, #128\n\t"
        "add	r6, r6, r10\n\t"
        "mov	r14, r6\n\t"
        "\n1:\n\t"
        "mov	%[r], #0\n\t"
        "mov	r5, #0\n\t"
        "mov	r6, #124\n\t"
        "mov	%[a], r9\n\t"
        "subs	%[a], %[a], r6\n\t"
        "sbc	r6, r6, r6\n\t"
        "mvn	r6, r6\n\t"
        "and	%[a], %[a], r6\n\t"
        "mov	%[b], r9\n\t"
        "sub	%[b], %[b], %[a]\n\t"
        "add	%[a], %[a], r10\n\t"
        "add	%[b], %[b], r11\n\t"
        "\n2:\n\t"
        /* Multiply Start */
        "ldr	r6, [%[a]]\n\t"
        "ldr	r8, [%[b]]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        /* Multiply Done */
        "add	%[a], %[a], #4\n\t"
        "sub	%[b], %[b], #4\n\t"
        "cmp	%[a], r14\n\t"
#ifdef __GNUC__
        "beq	3f\n\t"
#else
        "beq.n	3f\n\t"
#endif /* __GNUC__ */
        "mov	r6, r9\n\t"
        "add	r6, r6, r10\n\t"
        "cmp	%[a], r6\n\t"
#ifdef __GNUC__
        "ble	2b\n\t"
#else
        "ble.n	2b\n\t"
#endif /* __GNUC__ */
        "\n3:\n\t"
        "mov	%[r], r12\n\t"
        "mov	r8, r9\n\t"
        "str	r3, [%[r], r8]\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "add	r8, r8, #4\n\t"
        "mov	r9, r8\n\t"
        "mov	r6, #248\n\t"
        "cmp	r8, r6\n\t"
#ifdef __GNUC__
        "ble	1b\n\t"
#else
        "ble.n	1b\n\t"
#endif /* __GNUC__ */
        "str	r3, [%[r], r8]\n\t"
        "mov	%[a], r10\n\t"
        "mov	%[b], r11\n\t"
        :
        : [r] "r" (tmp), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r8", "r9", "r10", "r11", "r12", "r14"
    );

    XMEMCPY(r, tmp_arr, sizeof(tmp_arr));
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_32(sp_digit* r, const sp_digit* a)
{
    __asm__ __volatile__ (
        "mov	r3, #0\n\t"
        "mov	r4, #0\n\t"
        "mov	r5, #0\n\t"
        "mov	r9, r3\n\t"
        "mov	r12, %[r]\n\t"
        "mov	r6, #1\n\t"
        "lsl	r6, r6, #8\n\t"
        "neg	r6, r6\n\t"
        "add	sp, sp, r6\n\t"
        "mov	r11, sp\n\t"
        "mov	r10, %[a]\n\t"
        "\n1:\n\t"
        "mov	%[r], #0\n\t"
        "mov	r6, #124\n\t"
        "mov	%[a], r9\n\t"
        "subs	%[a], %[a], r6\n\t"
        "sbc	r6, r6, r6\n\t"
        "mvn	r6, r6\n\t"
        "and	%[a], %[a], r6\n\t"
        "mov	r2, r9\n\t"
        "sub	r2, r2, %[a]\n\t"
        "add	%[a], %[a], r10\n\t"
        "add	r2, r2, r10\n\t"
        "\n2:\n\t"
        "cmp	r2, %[a]\n\t"
#ifdef __GNUC__
        "beq	4f\n\t"
#else
        "beq.n	4f\n\t"
#endif /* __GNUC__ */
        /* Multiply * 2: Start */
        "ldr	r6, [%[a]]\n\t"
        "ldr	r8, [r2]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        /* Multiply * 2: Done */
#ifdef __GNUC__
        "bal	5f\n\t"
#else
        "bal.n	5f\n\t"
#endif /* __GNUC__ */
        "\n4:\n\t"
        /* Square: Start */
        "ldr	r6, [%[a]]\n\t"
        "umull	r6, r8, r6, r6\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        /* Square: Done */
        "\n5:\n\t"
        "add	%[a], %[a], #4\n\t"
        "sub	r2, r2, #4\n\t"
        "mov	r6, #128\n\t"
        "add	r6, r6, r10\n\t"
        "cmp	%[a], r6\n\t"
#ifdef __GNUC__
        "beq	3f\n\t"
#else
        "beq.n	3f\n\t"
#endif /* __GNUC__ */
        "cmp	%[a], r2\n\t"
#ifdef __GNUC__
        "bgt	3f\n\t"
#else
        "bgt.n	3f\n\t"
#endif /* __GNUC__ */
        "mov	r8, r9\n\t"
        "add	r8, r8, r10\n\t"
        "cmp	%[a], r8\n\t"
#ifdef __GNUC__
        "ble	2b\n\t"
#else
        "ble.n	2b\n\t"
#endif /* __GNUC__ */
        "\n3:\n\t"
        "mov	%[r], r11\n\t"
        "mov	r8, r9\n\t"
        "str	r3, [%[r], r8]\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "mov	r5, #0\n\t"
        "add	r8, r8, #4\n\t"
        "mov	r9, r8\n\t"
        "mov	r6, #248\n\t"
        "cmp	r8, r6\n\t"
#ifdef __GNUC__
        "ble	1b\n\t"
#else
        "ble.n	1b\n\t"
#endif /* __GNUC__ */
        "mov	%[a], r10\n\t"
        "str	r3, [%[r], r8]\n\t"
        "mov	%[r], r12\n\t"
        "mov	%[a], r11\n\t"
        "mov	r3, #252\n\t"
        "\n4:\n\t"
        "ldr	r6, [%[a], r3]\n\t"
        "str	r6, [%[r], r3]\n\t"
        "subs	r3, r3, #4\n\t"
#ifdef __GNUC__
        "bge	4b\n\t"
#else
        "bge.n	4b\n\t"
#endif /* __GNUC__ */
        "mov	r6, #1\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	sp, sp, r6\n\t"
        :
        : [r] "r" (r), [a] "r" (a)
        : "memory", "r2", "r3", "r4", "r5", "r6", "r8", "r9", "r10", "r11", "r12"
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
SP_NOINLINE static void sp_2048_mul_d_64(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
    __asm__ __volatile__ (
        "add	r9, %[a], #256\n\t"
        /* A[0] * B */
        "ldr	r6, [%[a]], #4\n\t"
        "umull	r5, r3, r6, %[b]\n\t"
        "mov	r4, #0\n\t"
        "str	r5, [%[r]], #4\n\t"
        /* A[0] * B - Done */
        "\n1:\n\t"
        "mov	r5, #0\n\t"
        /* A[] * B */
        "ldr	r6, [%[a]], #4\n\t"
        "umull	r6, r8, r6, %[b]\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[] * B - Done */
        "str	r3, [%[r]], #4\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "cmp	%[a], r9\n\t"
#ifdef __GNUC__
        "blt	1b\n\t"
#else
        "blt.n	1b\n\t"
#endif /* __GNUC__ */
        "str	r3, [%[r]]\n\t"
        : [r] "+r" (r), [a] "+r" (a)
        : [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r8", "r9"
    );
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
SP_NOINLINE static sp_digit sp_2048_cond_sub_32(sp_digit* r, const sp_digit* a,
        const sp_digit* b, sp_digit m)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r5, #128\n\t"
        "mov	r9, r5\n\t"
        "mov	r8, #0\n\t"
        "\n1:\n\t"
        "ldr	r6, [%[b], r8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "mov	r5, #0\n\t"
        "subs	r5, r5, %[c]\n\t"
        "ldr	r5, [%[a], r8]\n\t"
        "sbcs	r5, r5, r6\n\t"
        "sbcs	%[c], %[c], %[c]\n\t"
        "str	r5, [%[r], r8]\n\t"
        "add	r8, r8, #4\n\t"
        "cmp	r8, r9\n\t"
#ifdef __GNUC__
        "blt	1b\n\t"
#else
        "blt.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r5", "r6", "r8", "r9"
    );

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
        "mov	r9, %[mp]\n\t"
        "mov	r12, %[m]\n\t"
        "mov	r10, %[a]\n\t"
        "mov	r4, #0\n\t"
        "add	r11, r10, #128\n\t"
        "\n1:\n\t"
        /* mu = a[i] * mp */
        "mov	%[mp], r9\n\t"
        "ldr	%[a], [r10]\n\t"
        "mul	%[mp], %[mp], %[a]\n\t"
        "mov	%[m], r12\n\t"
        "add	r14, r10, #120\n\t"
        "\n2:\n\t"
        /* a[i+j] += m[j] * mu */
        "ldr	%[a], [r10]\n\t"
        "mov	r5, #0\n\t"
        /* Multiply m[j] and mu - Start */
        "ldr	r8, [%[m]], #4\n\t"
        "umull	r6, r8, %[mp], r8\n\t"
        "adds	%[a], %[a], r6\n\t"
        "adc	r5, r5, r8\n\t"
        /* Multiply m[j] and mu - Done */
        "adds	r4, r4, %[a]\n\t"
        "adc	r5, r5, #0\n\t"
        "str	r4, [r10], #4\n\t"
        /* a[i+j+1] += m[j+1] * mu */
        "ldr	%[a], [r10]\n\t"
        "mov	r4, #0\n\t"
        /* Multiply m[j] and mu - Start */
        "ldr	r8, [%[m]], #4\n\t"
        "umull	r6, r8, %[mp], r8\n\t"
        "adds	%[a], %[a], r6\n\t"
        "adc	r4, r4, r8\n\t"
        /* Multiply m[j] and mu - Done */
        "adds	r5, r5, %[a]\n\t"
        "adc	r4, r4, #0\n\t"
        "str	r5, [r10], #4\n\t"
        "cmp	r10, r14\n\t"
#ifdef __GNUC__
        "blt	2b\n\t"
#else
        "blt.n	2b\n\t"
#endif /* __GNUC__ */
        /* a[i+30] += m[30] * mu */
        "ldr	%[a], [r10]\n\t"
        "mov	r5, #0\n\t"
        /* Multiply m[j] and mu - Start */
        "ldr	r8, [%[m]], #4\n\t"
        "umull	r6, r8, %[mp], r8\n\t"
        "adds	%[a], %[a], r6\n\t"
        "adc	r5, r5, r8\n\t"
        /* Multiply m[j] and mu - Done */
        "adds	r4, r4, %[a]\n\t"
        "adc	r5, r5, #0\n\t"
        "str	r4, [r10], #4\n\t"
        /* a[i+31] += m[31] * mu */
        "mov	r4, %[ca]\n\t"
        "mov	%[ca], #0\n\t"
        /* Multiply m[31] and mu - Start */
        "ldr	r8, [%[m]]\n\t"
        "umull	r6, r8, %[mp], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	%[ca], %[ca], #0\n\t"
        /* Multiply m[31] and mu - Done */
        "ldr	r6, [r10]\n\t"
        "ldr	r8, [r10, #4]\n\t"
        "adds	r6, r6, r5\n\t"
        "adcs	r8, r8, r4\n\t"
        "adc	%[ca], %[ca], #0\n\t"
        "str	r6, [r10]\n\t"
        "str	r8, [r10, #4]\n\t"
        /* Next word in a */
        "sub	r10, r10, #120\n\t"
        "cmp	r10, r11\n\t"
#ifdef __GNUC__
        "blt	1b\n\t"
#else
        "blt.n	1b\n\t"
#endif /* __GNUC__ */
        "mov	%[a], r10\n\t"
        "mov	%[m], r12\n\t"
        : [ca] "+r" (ca), [a] "+r" (a)
        : [m] "r" (m), [mp] "r" (mp)
        : "memory", "r4", "r5", "r6", "r8", "r9", "r10", "r11", "r12", "r14"
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
SP_NOINLINE static void sp_2048_mul_d_32(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
    __asm__ __volatile__ (
        "add	r9, %[a], #128\n\t"
        /* A[0] * B */
        "ldr	r6, [%[a]], #4\n\t"
        "umull	r5, r3, r6, %[b]\n\t"
        "mov	r4, #0\n\t"
        "str	r5, [%[r]], #4\n\t"
        /* A[0] * B - Done */
        "\n1:\n\t"
        "mov	r5, #0\n\t"
        /* A[] * B */
        "ldr	r6, [%[a]], #4\n\t"
        "umull	r6, r8, r6, %[b]\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[] * B - Done */
        "str	r3, [%[r]], #4\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "cmp	%[a], r9\n\t"
#ifdef __GNUC__
        "blt	1b\n\t"
#else
        "blt.n	1b\n\t"
#endif /* __GNUC__ */
        "str	r3, [%[r]]\n\t"
        : [r] "+r" (r), [a] "+r" (a)
        : [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r8", "r9"
    );
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
SP_NOINLINE static sp_digit div_2048_word_32(sp_digit d1, sp_digit d0,
        sp_digit div)
{
    sp_digit r = 0;

    __asm__ __volatile__ (
        "lsr	r6, %[div], #16\n\t"
        "add	r6, r6, #1\n\t"
        "udiv	r4, %[d1], r6\n\t"
        "lsl	r8, r4, #16\n\t"
        "umull	r4, r5, %[div], r8\n\t"
        "subs	%[d0], %[d0], r4\n\t"
        "sbc	%[d1], %[d1], r5\n\t"
        "udiv	r5, %[d1], r6\n\t"
        "lsl	r4, r5, #16\n\t"
        "add	r8, r8, r4\n\t"
        "umull	r4, r5, %[div], r4\n\t"
        "subs	%[d0], %[d0], r4\n\t"
        "sbc	%[d1], %[d1], r5\n\t"
        "lsl	r4, %[d1], #16\n\t"
        "orr	r4, r4, %[d0], lsr #16\n\t"
        "udiv	r4, r4, r6\n\t"
        "add	r8, r8, r4\n\t"
        "umull	r4, r5, %[div], r4\n\t"
        "subs	%[d0], %[d0], r4\n\t"
        "sbc	%[d1], %[d1], r5\n\t"
        "lsl	r4, %[d1], #16\n\t"
        "orr	r4, r4, %[d0], lsr #16\n\t"
        "udiv	r4, r4, r6\n\t"
        "add	r8, r8, r4\n\t"
        "umull	r4, r5, %[div], r4\n\t"
        "subs	%[d0], %[d0], r4\n\t"
        "sbc	%[d1], %[d1], r5\n\t"
        "udiv	r4, %[d0], %[div]\n\t"
        "add	r8, r8, r4\n\t"
        "mov	%[r], r8\n\t"
        : [r] "+r" (r)
        : [d1] "r" (d1), [d0] "r" (d0), [div] "r" (div)
        : "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_int32 sp_2048_cmp_32(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;


    __asm__ __volatile__ (
        "mov	r3, #0\n\t"
        "mvn	r3, r3\n\t"
        "mov	r6, #124\n\t"
        "\n1:\n\t"
        "ldr	r8, [%[a], r6]\n\t"
        "ldr	r5, [%[b], r6]\n\t"
        "and	r8, r8, r3\n\t"
        "and	r5, r5, r3\n\t"
        "mov	r4, r8\n\t"
        "subs	r8, r8, r5\n\t"
        "sbc	r8, r8, r8\n\t"
        "add	%[r], %[r], r8\n\t"
        "mvn	r8, r8\n\t"
        "and	r3, r3, r8\n\t"
        "subs	r5, r5, r4\n\t"
        "sbc	r8, r8, r8\n\t"
        "sub	%[r], %[r], r8\n\t"
        "mvn	r8, r8\n\t"
        "and	r3, r3, r8\n\t"
        "sub	r6, r6, #4\n\t"
        "cmp	r6, #0\n\t"
#ifdef __GNUC__
        "bge	1b\n\t"
#else
        "bge.n	1b\n\t"
#endif /* __GNUC__ */
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "r3", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_digit sp_2048_cond_sub_64(sp_digit* r, const sp_digit* a,
        const sp_digit* b, sp_digit m)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r5, #1\n\t"
        "lsl	r5, r5, #8\n\t"
        "mov	r9, r5\n\t"
        "mov	r8, #0\n\t"
        "\n1:\n\t"
        "ldr	r6, [%[b], r8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "mov	r5, #0\n\t"
        "subs	r5, r5, %[c]\n\t"
        "ldr	r5, [%[a], r8]\n\t"
        "sbcs	r5, r5, r6\n\t"
        "sbcs	%[c], %[c], %[c]\n\t"
        "str	r5, [%[r], r8]\n\t"
        "add	r8, r8, #4\n\t"
        "cmp	r8, r9\n\t"
#ifdef __GNUC__
        "blt	1b\n\t"
#else
        "blt.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r5", "r6", "r8", "r9"
    );

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
        "mov	r9, %[mp]\n\t"
        "mov	r12, %[m]\n\t"
        "mov	r10, %[a]\n\t"
        "mov	r4, #0\n\t"
        "add	r11, r10, #256\n\t"
        "\n1:\n\t"
        /* mu = a[i] * mp */
        "mov	%[mp], r9\n\t"
        "ldr	%[a], [r10]\n\t"
        "mul	%[mp], %[mp], %[a]\n\t"
        "mov	%[m], r12\n\t"
        "add	r14, r10, #248\n\t"
        "\n2:\n\t"
        /* a[i+j] += m[j] * mu */
        "ldr	%[a], [r10]\n\t"
        "mov	r5, #0\n\t"
        /* Multiply m[j] and mu - Start */
        "ldr	r8, [%[m]], #4\n\t"
        "umull	r6, r8, %[mp], r8\n\t"
        "adds	%[a], %[a], r6\n\t"
        "adc	r5, r5, r8\n\t"
        /* Multiply m[j] and mu - Done */
        "adds	r4, r4, %[a]\n\t"
        "adc	r5, r5, #0\n\t"
        "str	r4, [r10], #4\n\t"
        /* a[i+j+1] += m[j+1] * mu */
        "ldr	%[a], [r10]\n\t"
        "mov	r4, #0\n\t"
        /* Multiply m[j] and mu - Start */
        "ldr	r8, [%[m]], #4\n\t"
        "umull	r6, r8, %[mp], r8\n\t"
        "adds	%[a], %[a], r6\n\t"
        "adc	r4, r4, r8\n\t"
        /* Multiply m[j] and mu - Done */
        "adds	r5, r5, %[a]\n\t"
        "adc	r4, r4, #0\n\t"
        "str	r5, [r10], #4\n\t"
        "cmp	r10, r14\n\t"
#ifdef __GNUC__
        "blt	2b\n\t"
#else
        "blt.n	2b\n\t"
#endif /* __GNUC__ */
        /* a[i+62] += m[62] * mu */
        "ldr	%[a], [r10]\n\t"
        "mov	r5, #0\n\t"
        /* Multiply m[j] and mu - Start */
        "ldr	r8, [%[m]], #4\n\t"
        "umull	r6, r8, %[mp], r8\n\t"
        "adds	%[a], %[a], r6\n\t"
        "adc	r5, r5, r8\n\t"
        /* Multiply m[j] and mu - Done */
        "adds	r4, r4, %[a]\n\t"
        "adc	r5, r5, #0\n\t"
        "str	r4, [r10], #4\n\t"
        /* a[i+63] += m[63] * mu */
        "mov	r4, %[ca]\n\t"
        "mov	%[ca], #0\n\t"
        /* Multiply m[63] and mu - Start */
        "ldr	r8, [%[m]]\n\t"
        "umull	r6, r8, %[mp], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	%[ca], %[ca], #0\n\t"
        /* Multiply m[63] and mu - Done */
        "ldr	r6, [r10]\n\t"
        "ldr	r8, [r10, #4]\n\t"
        "adds	r6, r6, r5\n\t"
        "adcs	r8, r8, r4\n\t"
        "adc	%[ca], %[ca], #0\n\t"
        "str	r6, [r10]\n\t"
        "str	r8, [r10, #4]\n\t"
        /* Next word in a */
        "sub	r10, r10, #248\n\t"
        "cmp	r10, r11\n\t"
#ifdef __GNUC__
        "blt	1b\n\t"
#else
        "blt.n	1b\n\t"
#endif /* __GNUC__ */
        "mov	%[a], r10\n\t"
        "mov	%[m], r12\n\t"
        : [ca] "+r" (ca), [a] "+r" (a)
        : [m] "r" (m), [mp] "r" (mp)
        : "memory", "r4", "r5", "r6", "r8", "r9", "r10", "r11", "r12", "r14"
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
SP_NOINLINE static sp_digit sp_2048_sub_64(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r6, %[a]\n\t"
        "mov	r5, #1\n\t"
        "lsl	r5, r5, #8\n\t"
        "add	r6, r6, r5\n\t"
        "\n1:\n\t"
        "mov	r5, #0\n\t"
        "subs	r5, r5, %[c]\n\t"
        "ldr	r4, [%[a]]\n\t"
        "ldr	r5, [%[b]]\n\t"
        "sbcs	r4, r4, r5\n\t"
        "str	r4, [%[r]]\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        "add	%[a], %[a], #4\n\t"
        "add	%[b], %[b], #4\n\t"
        "add	%[r], %[r], #4\n\t"
        "cmp	%[a], r6\n\t"
#ifdef __GNUC__
        "bne	1b\n\t"
#else
        "bne.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6"
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
SP_NOINLINE static sp_digit sp_2048_sub_64(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "subs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_digit div_2048_word_64(sp_digit d1, sp_digit d0,
        sp_digit div)
{
    sp_digit r = 0;

    __asm__ __volatile__ (
        "lsr	r6, %[div], #16\n\t"
        "add	r6, r6, #1\n\t"
        "udiv	r4, %[d1], r6\n\t"
        "lsl	r8, r4, #16\n\t"
        "umull	r4, r5, %[div], r8\n\t"
        "subs	%[d0], %[d0], r4\n\t"
        "sbc	%[d1], %[d1], r5\n\t"
        "udiv	r5, %[d1], r6\n\t"
        "lsl	r4, r5, #16\n\t"
        "add	r8, r8, r4\n\t"
        "umull	r4, r5, %[div], r4\n\t"
        "subs	%[d0], %[d0], r4\n\t"
        "sbc	%[d1], %[d1], r5\n\t"
        "lsl	r4, %[d1], #16\n\t"
        "orr	r4, r4, %[d0], lsr #16\n\t"
        "udiv	r4, r4, r6\n\t"
        "add	r8, r8, r4\n\t"
        "umull	r4, r5, %[div], r4\n\t"
        "subs	%[d0], %[d0], r4\n\t"
        "sbc	%[d1], %[d1], r5\n\t"
        "lsl	r4, %[d1], #16\n\t"
        "orr	r4, r4, %[d0], lsr #16\n\t"
        "udiv	r4, r4, r6\n\t"
        "add	r8, r8, r4\n\t"
        "umull	r4, r5, %[div], r4\n\t"
        "subs	%[d0], %[d0], r4\n\t"
        "sbc	%[d1], %[d1], r5\n\t"
        "udiv	r4, %[d0], %[div]\n\t"
        "add	r8, r8, r4\n\t"
        "mov	%[r], r8\n\t"
        : [r] "+r" (r)
        : [d1] "r" (d1), [d0] "r" (d0), [div] "r" (div)
        : "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_int32 sp_2048_cmp_64(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;


    __asm__ __volatile__ (
        "mov	r3, #0\n\t"
        "mvn	r3, r3\n\t"
        "mov	r6, #252\n\t"
        "\n1:\n\t"
        "ldr	r8, [%[a], r6]\n\t"
        "ldr	r5, [%[b], r6]\n\t"
        "and	r8, r8, r3\n\t"
        "and	r5, r5, r3\n\t"
        "mov	r4, r8\n\t"
        "subs	r8, r8, r5\n\t"
        "sbc	r8, r8, r8\n\t"
        "add	%[r], %[r], r8\n\t"
        "mvn	r8, r8\n\t"
        "and	r3, r3, r8\n\t"
        "subs	r5, r5, r4\n\t"
        "sbc	r8, r8, r8\n\t"
        "sub	%[r], %[r], r8\n\t"
        "mvn	r8, r8\n\t"
        "and	r3, r3, r8\n\t"
        "sub	r6, r6, #4\n\t"
        "cmp	r6, #0\n\t"
#ifdef __GNUC__
        "bge	1b\n\t"
#else
        "bge.n	1b\n\t"
#endif /* __GNUC__ */
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "r3", "r4", "r5", "r6", "r8"
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
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
SP_NOINLINE static sp_digit sp_2048_cond_add_32(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r5, #128\n\t"
        "mov	r9, r5\n\t"
        "mov	r8, #0\n\t"
        "\n1:\n\t"
        "ldr	r6, [%[b], r8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "adds	r5, %[c], #-1\n\t"
        "ldr	r5, [%[a], r8]\n\t"
        "adcs	r5, r5, r6\n\t"
        "mov	%[c], #0\n\t"
        "adcs	%[c], %[c], %[c]\n\t"
        "str	r5, [%[r], r8]\n\t"
        "add	r8, r8, #4\n\t"
        "cmp	r8, r9\n\t"
#ifdef __GNUC__
        "blt	1b\n\t"
#else
        "blt.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r5", "r6", "r8", "r9"
    );

    return c;
}

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
        "mov	r6, #31\n\t"
        "sub	r6, r6, %[n]\n\t"
        "add	%[a], %[a], #192\n\t"
        "add	%[r], %[r], #192\n\t"
        "ldr	r3, [%[a], #60]\n\t"
        "lsr	r4, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r4, r4, r6\n\t"
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
        "sub	%[a], %[a], #64\n\t"
        "sub	%[r], %[r], #64\n\t"
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
        "sub	%[a], %[a], #64\n\t"
        "sub	%[r], %[r], #64\n\t"
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
        "sub	%[a], %[a], #64\n\t"
        "sub	%[r], %[r], #64\n\t"
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
        "str	r3, [%[r]]\n\t"
        "str	r4, [%[r], #4]\n\t"
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
SP_NOINLINE static void sp_3072_mul_12(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit tmp_arr[12 * 2];
    sp_digit* tmp = tmp_arr;
    __asm__ __volatile__ (
        "mov	r3, #0\n\t"
        "mov	r4, #0\n\t"
        "mov	r9, r3\n\t"
        "mov	r12, %[r]\n\t"
        "mov	r10, %[a]\n\t"
        "mov	r11, %[b]\n\t"
        "mov	r6, #48\n\t"
        "add	r6, r6, r10\n\t"
        "mov	r14, r6\n\t"
        "\n1:\n\t"
        "mov	%[r], #0\n\t"
        "mov	r5, #0\n\t"
        "mov	r6, #44\n\t"
        "mov	%[a], r9\n\t"
        "subs	%[a], %[a], r6\n\t"
        "sbc	r6, r6, r6\n\t"
        "mvn	r6, r6\n\t"
        "and	%[a], %[a], r6\n\t"
        "mov	%[b], r9\n\t"
        "sub	%[b], %[b], %[a]\n\t"
        "add	%[a], %[a], r10\n\t"
        "add	%[b], %[b], r11\n\t"
        "\n2:\n\t"
        /* Multiply Start */
        "ldr	r6, [%[a]]\n\t"
        "ldr	r8, [%[b]]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        /* Multiply Done */
        "add	%[a], %[a], #4\n\t"
        "sub	%[b], %[b], #4\n\t"
        "cmp	%[a], r14\n\t"
#ifdef __GNUC__
        "beq	3f\n\t"
#else
        "beq.n	3f\n\t"
#endif /* __GNUC__ */
        "mov	r6, r9\n\t"
        "add	r6, r6, r10\n\t"
        "cmp	%[a], r6\n\t"
#ifdef __GNUC__
        "ble	2b\n\t"
#else
        "ble.n	2b\n\t"
#endif /* __GNUC__ */
        "\n3:\n\t"
        "mov	%[r], r12\n\t"
        "mov	r8, r9\n\t"
        "str	r3, [%[r], r8]\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "add	r8, r8, #4\n\t"
        "mov	r9, r8\n\t"
        "mov	r6, #88\n\t"
        "cmp	r8, r6\n\t"
#ifdef __GNUC__
        "ble	1b\n\t"
#else
        "ble.n	1b\n\t"
#endif /* __GNUC__ */
        "str	r3, [%[r], r8]\n\t"
        "mov	%[a], r10\n\t"
        "mov	%[b], r11\n\t"
        :
        : [r] "r" (tmp), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r8", "r9", "r10", "r11", "r12", "r14"
    );

    XMEMCPY(r, tmp_arr, sizeof(tmp_arr));
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_3072_add_12(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "mov	%[c], #0\n\t"
        "adc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
    );

    return c;
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_3072_sub_in_place_24(sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "subs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6"
    );

    return c;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_3072_add_24(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "mov	%[c], #0\n\t"
        "adc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_3072_sub_in_place_48(sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "subs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6"
    );

    return c;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_3072_add_48(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "mov	%[c], #0\n\t"
        "adc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_3072_sub_in_place_96(sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "subs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6"
    );

    return c;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_3072_add_96(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "mov	%[c], #0\n\t"
        "adc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static void sp_3072_sqr_12(sp_digit* r, const sp_digit* a)
{
    __asm__ __volatile__ (
        "mov	r3, #0\n\t"
        "mov	r4, #0\n\t"
        "mov	r5, #0\n\t"
        "mov	r9, r3\n\t"
        "mov	r12, %[r]\n\t"
        "mov	r6, #96\n\t"
        "neg	r6, r6\n\t"
        "add	sp, sp, r6\n\t"
        "mov	r11, sp\n\t"
        "mov	r10, %[a]\n\t"
        "\n1:\n\t"
        "mov	%[r], #0\n\t"
        "mov	r6, #44\n\t"
        "mov	%[a], r9\n\t"
        "subs	%[a], %[a], r6\n\t"
        "sbc	r6, r6, r6\n\t"
        "mvn	r6, r6\n\t"
        "and	%[a], %[a], r6\n\t"
        "mov	r2, r9\n\t"
        "sub	r2, r2, %[a]\n\t"
        "add	%[a], %[a], r10\n\t"
        "add	r2, r2, r10\n\t"
        "\n2:\n\t"
        "cmp	r2, %[a]\n\t"
#ifdef __GNUC__
        "beq	4f\n\t"
#else
        "beq.n	4f\n\t"
#endif /* __GNUC__ */
        /* Multiply * 2: Start */
        "ldr	r6, [%[a]]\n\t"
        "ldr	r8, [r2]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        /* Multiply * 2: Done */
#ifdef __GNUC__
        "bal	5f\n\t"
#else
        "bal.n	5f\n\t"
#endif /* __GNUC__ */
        "\n4:\n\t"
        /* Square: Start */
        "ldr	r6, [%[a]]\n\t"
        "umull	r6, r8, r6, r6\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        /* Square: Done */
        "\n5:\n\t"
        "add	%[a], %[a], #4\n\t"
        "sub	r2, r2, #4\n\t"
        "mov	r6, #48\n\t"
        "add	r6, r6, r10\n\t"
        "cmp	%[a], r6\n\t"
#ifdef __GNUC__
        "beq	3f\n\t"
#else
        "beq.n	3f\n\t"
#endif /* __GNUC__ */
        "cmp	%[a], r2\n\t"
#ifdef __GNUC__
        "bgt	3f\n\t"
#else
        "bgt.n	3f\n\t"
#endif /* __GNUC__ */
        "mov	r8, r9\n\t"
        "add	r8, r8, r10\n\t"
        "cmp	%[a], r8\n\t"
#ifdef __GNUC__
        "ble	2b\n\t"
#else
        "ble.n	2b\n\t"
#endif /* __GNUC__ */
        "\n3:\n\t"
        "mov	%[r], r11\n\t"
        "mov	r8, r9\n\t"
        "str	r3, [%[r], r8]\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "mov	r5, #0\n\t"
        "add	r8, r8, #4\n\t"
        "mov	r9, r8\n\t"
        "mov	r6, #88\n\t"
        "cmp	r8, r6\n\t"
#ifdef __GNUC__
        "ble	1b\n\t"
#else
        "ble.n	1b\n\t"
#endif /* __GNUC__ */
        "mov	%[a], r10\n\t"
        "str	r3, [%[r], r8]\n\t"
        "mov	%[r], r12\n\t"
        "mov	%[a], r11\n\t"
        "mov	r3, #92\n\t"
        "\n4:\n\t"
        "ldr	r6, [%[a], r3]\n\t"
        "str	r6, [%[r], r3]\n\t"
        "subs	r3, r3, #4\n\t"
#ifdef __GNUC__
        "bge	4b\n\t"
#else
        "bge.n	4b\n\t"
#endif /* __GNUC__ */
        "mov	r6, #96\n\t"
        "add	sp, sp, r6\n\t"
        :
        : [r] "r" (r), [a] "r" (a)
        : "memory", "r2", "r3", "r4", "r5", "r6", "r8", "r9", "r10", "r11", "r12"
    );
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_3072_sub_12(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "subs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_digit sp_3072_sub_24(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "subs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_digit sp_3072_sub_48(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "subs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_digit sp_3072_add_96(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r6, %[a]\n\t"
        "mov	r8, #0\n\t"
        "add	r6, r6, #384\n\t"
        "sub	r8, r8, #1\n\t"
        "\n1:\n\t"
        "adds	%[c], %[c], r8\n\t"
        "ldr	r4, [%[a]]\n\t"
        "ldr	r5, [%[b]]\n\t"
        "adcs	r4, r4, r5\n\t"
        "str	r4, [%[r]]\n\t"
        "mov	%[c], #0\n\t"
        "adc	%[c], %[c], %[c]\n\t"
        "add	%[a], %[a], #4\n\t"
        "add	%[b], %[b], #4\n\t"
        "add	%[r], %[r], #4\n\t"
        "cmp	%[a], r6\n\t"
#ifdef __GNUC__
        "bne	1b\n\t"
#else
        "bne.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_digit sp_3072_sub_in_place_96(sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;
    __asm__ __volatile__ (
        "mov	r8, %[a]\n\t"
        "add	r8, r8, #384\n\t"
        "\n1:\n\t"
        "mov	r5, #0\n\t"
        "subs	r5, r5, %[c]\n\t"
        "ldr	r3, [%[a]]\n\t"
        "ldr	r4, [%[a], #4]\n\t"
        "ldr	r5, [%[b]]\n\t"
        "ldr	r6, [%[b], #4]\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "str	r3, [%[a]]\n\t"
        "str	r4, [%[a], #4]\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        "add	%[a], %[a], #8\n\t"
        "add	%[b], %[b], #8\n\t"
        "cmp	%[a], r8\n\t"
#ifdef __GNUC__
        "bne	1b\n\t"
#else
        "bne.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static void sp_3072_mul_96(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit tmp_arr[96 * 2];
    sp_digit* tmp = tmp_arr;
    __asm__ __volatile__ (
        "mov	r3, #0\n\t"
        "mov	r4, #0\n\t"
        "mov	r9, r3\n\t"
        "mov	r12, %[r]\n\t"
        "mov	r10, %[a]\n\t"
        "mov	r11, %[b]\n\t"
        "mov	r6, #1\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, #128\n\t"
        "add	r6, r6, r10\n\t"
        "mov	r14, r6\n\t"
        "\n1:\n\t"
        "mov	%[r], #0\n\t"
        "mov	r5, #0\n\t"
        "mov	r6, #1\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, #124\n\t"
        "mov	%[a], r9\n\t"
        "subs	%[a], %[a], r6\n\t"
        "sbc	r6, r6, r6\n\t"
        "mvn	r6, r6\n\t"
        "and	%[a], %[a], r6\n\t"
        "mov	%[b], r9\n\t"
        "sub	%[b], %[b], %[a]\n\t"
        "add	%[a], %[a], r10\n\t"
        "add	%[b], %[b], r11\n\t"
        "\n2:\n\t"
        /* Multiply Start */
        "ldr	r6, [%[a]]\n\t"
        "ldr	r8, [%[b]]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        /* Multiply Done */
        "add	%[a], %[a], #4\n\t"
        "sub	%[b], %[b], #4\n\t"
        "cmp	%[a], r14\n\t"
#ifdef __GNUC__
        "beq	3f\n\t"
#else
        "beq.n	3f\n\t"
#endif /* __GNUC__ */
        "mov	r6, r9\n\t"
        "add	r6, r6, r10\n\t"
        "cmp	%[a], r6\n\t"
#ifdef __GNUC__
        "ble	2b\n\t"
#else
        "ble.n	2b\n\t"
#endif /* __GNUC__ */
        "\n3:\n\t"
        "mov	%[r], r12\n\t"
        "mov	r8, r9\n\t"
        "str	r3, [%[r], r8]\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "add	r8, r8, #4\n\t"
        "mov	r9, r8\n\t"
        "mov	r6, #2\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, #248\n\t"
        "cmp	r8, r6\n\t"
#ifdef __GNUC__
        "ble	1b\n\t"
#else
        "ble.n	1b\n\t"
#endif /* __GNUC__ */
        "str	r3, [%[r], r8]\n\t"
        "mov	%[a], r10\n\t"
        "mov	%[b], r11\n\t"
        :
        : [r] "r" (tmp), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r8", "r9", "r10", "r11", "r12", "r14"
    );

    XMEMCPY(r, tmp_arr, sizeof(tmp_arr));
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_96(sp_digit* r, const sp_digit* a)
{
    __asm__ __volatile__ (
        "mov	r3, #0\n\t"
        "mov	r4, #0\n\t"
        "mov	r5, #0\n\t"
        "mov	r9, r3\n\t"
        "mov	r12, %[r]\n\t"
        "mov	r6, #3\n\t"
        "lsl	r6, r6, #8\n\t"
        "neg	r6, r6\n\t"
        "add	sp, sp, r6\n\t"
        "mov	r11, sp\n\t"
        "mov	r10, %[a]\n\t"
        "\n1:\n\t"
        "mov	%[r], #0\n\t"
        "mov	r6, #1\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, #124\n\t"
        "mov	%[a], r9\n\t"
        "subs	%[a], %[a], r6\n\t"
        "sbc	r6, r6, r6\n\t"
        "mvn	r6, r6\n\t"
        "and	%[a], %[a], r6\n\t"
        "mov	r2, r9\n\t"
        "sub	r2, r2, %[a]\n\t"
        "add	%[a], %[a], r10\n\t"
        "add	r2, r2, r10\n\t"
        "\n2:\n\t"
        "cmp	r2, %[a]\n\t"
#ifdef __GNUC__
        "beq	4f\n\t"
#else
        "beq.n	4f\n\t"
#endif /* __GNUC__ */
        /* Multiply * 2: Start */
        "ldr	r6, [%[a]]\n\t"
        "ldr	r8, [r2]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        /* Multiply * 2: Done */
#ifdef __GNUC__
        "bal	5f\n\t"
#else
        "bal.n	5f\n\t"
#endif /* __GNUC__ */
        "\n4:\n\t"
        /* Square: Start */
        "ldr	r6, [%[a]]\n\t"
        "umull	r6, r8, r6, r6\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        /* Square: Done */
        "\n5:\n\t"
        "add	%[a], %[a], #4\n\t"
        "sub	r2, r2, #4\n\t"
        "mov	r6, #1\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, #128\n\t"
        "add	r6, r6, r10\n\t"
        "cmp	%[a], r6\n\t"
#ifdef __GNUC__
        "beq	3f\n\t"
#else
        "beq.n	3f\n\t"
#endif /* __GNUC__ */
        "cmp	%[a], r2\n\t"
#ifdef __GNUC__
        "bgt	3f\n\t"
#else
        "bgt.n	3f\n\t"
#endif /* __GNUC__ */
        "mov	r8, r9\n\t"
        "add	r8, r8, r10\n\t"
        "cmp	%[a], r8\n\t"
#ifdef __GNUC__
        "ble	2b\n\t"
#else
        "ble.n	2b\n\t"
#endif /* __GNUC__ */
        "\n3:\n\t"
        "mov	%[r], r11\n\t"
        "mov	r8, r9\n\t"
        "str	r3, [%[r], r8]\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "mov	r5, #0\n\t"
        "add	r8, r8, #4\n\t"
        "mov	r9, r8\n\t"
        "mov	r6, #2\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, #248\n\t"
        "cmp	r8, r6\n\t"
#ifdef __GNUC__
        "ble	1b\n\t"
#else
        "ble.n	1b\n\t"
#endif /* __GNUC__ */
        "mov	%[a], r10\n\t"
        "str	r3, [%[r], r8]\n\t"
        "mov	%[r], r12\n\t"
        "mov	%[a], r11\n\t"
        "mov	r3, #2\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #252\n\t"
        "\n4:\n\t"
        "ldr	r6, [%[a], r3]\n\t"
        "str	r6, [%[r], r3]\n\t"
        "subs	r3, r3, #4\n\t"
#ifdef __GNUC__
        "bge	4b\n\t"
#else
        "bge.n	4b\n\t"
#endif /* __GNUC__ */
        "mov	r6, #3\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	sp, sp, r6\n\t"
        :
        : [r] "r" (r), [a] "r" (a)
        : "memory", "r2", "r3", "r4", "r5", "r6", "r8", "r9", "r10", "r11", "r12"
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
SP_NOINLINE static sp_digit sp_3072_add_48(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r6, %[a]\n\t"
        "mov	r8, #0\n\t"
        "add	r6, r6, #192\n\t"
        "sub	r8, r8, #1\n\t"
        "\n1:\n\t"
        "adds	%[c], %[c], r8\n\t"
        "ldr	r4, [%[a]]\n\t"
        "ldr	r5, [%[b]]\n\t"
        "adcs	r4, r4, r5\n\t"
        "str	r4, [%[r]]\n\t"
        "mov	%[c], #0\n\t"
        "adc	%[c], %[c], %[c]\n\t"
        "add	%[a], %[a], #4\n\t"
        "add	%[b], %[b], #4\n\t"
        "add	%[r], %[r], #4\n\t"
        "cmp	%[a], r6\n\t"
#ifdef __GNUC__
        "bne	1b\n\t"
#else
        "bne.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_digit sp_3072_sub_in_place_48(sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;
    __asm__ __volatile__ (
        "mov	r8, %[a]\n\t"
        "add	r8, r8, #192\n\t"
        "\n1:\n\t"
        "mov	r5, #0\n\t"
        "subs	r5, r5, %[c]\n\t"
        "ldr	r3, [%[a]]\n\t"
        "ldr	r4, [%[a], #4]\n\t"
        "ldr	r5, [%[b]]\n\t"
        "ldr	r6, [%[b], #4]\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "str	r3, [%[a]]\n\t"
        "str	r4, [%[a], #4]\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        "add	%[a], %[a], #8\n\t"
        "add	%[b], %[b], #8\n\t"
        "cmp	%[a], r8\n\t"
#ifdef __GNUC__
        "bne	1b\n\t"
#else
        "bne.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static void sp_3072_mul_48(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit tmp_arr[48 * 2];
    sp_digit* tmp = tmp_arr;
    __asm__ __volatile__ (
        "mov	r3, #0\n\t"
        "mov	r4, #0\n\t"
        "mov	r9, r3\n\t"
        "mov	r12, %[r]\n\t"
        "mov	r10, %[a]\n\t"
        "mov	r11, %[b]\n\t"
        "mov	r6, #192\n\t"
        "add	r6, r6, r10\n\t"
        "mov	r14, r6\n\t"
        "\n1:\n\t"
        "mov	%[r], #0\n\t"
        "mov	r5, #0\n\t"
        "mov	r6, #188\n\t"
        "mov	%[a], r9\n\t"
        "subs	%[a], %[a], r6\n\t"
        "sbc	r6, r6, r6\n\t"
        "mvn	r6, r6\n\t"
        "and	%[a], %[a], r6\n\t"
        "mov	%[b], r9\n\t"
        "sub	%[b], %[b], %[a]\n\t"
        "add	%[a], %[a], r10\n\t"
        "add	%[b], %[b], r11\n\t"
        "\n2:\n\t"
        /* Multiply Start */
        "ldr	r6, [%[a]]\n\t"
        "ldr	r8, [%[b]]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        /* Multiply Done */
        "add	%[a], %[a], #4\n\t"
        "sub	%[b], %[b], #4\n\t"
        "cmp	%[a], r14\n\t"
#ifdef __GNUC__
        "beq	3f\n\t"
#else
        "beq.n	3f\n\t"
#endif /* __GNUC__ */
        "mov	r6, r9\n\t"
        "add	r6, r6, r10\n\t"
        "cmp	%[a], r6\n\t"
#ifdef __GNUC__
        "ble	2b\n\t"
#else
        "ble.n	2b\n\t"
#endif /* __GNUC__ */
        "\n3:\n\t"
        "mov	%[r], r12\n\t"
        "mov	r8, r9\n\t"
        "str	r3, [%[r], r8]\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "add	r8, r8, #4\n\t"
        "mov	r9, r8\n\t"
        "mov	r6, #1\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, #120\n\t"
        "cmp	r8, r6\n\t"
#ifdef __GNUC__
        "ble	1b\n\t"
#else
        "ble.n	1b\n\t"
#endif /* __GNUC__ */
        "str	r3, [%[r], r8]\n\t"
        "mov	%[a], r10\n\t"
        "mov	%[b], r11\n\t"
        :
        : [r] "r" (tmp), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r8", "r9", "r10", "r11", "r12", "r14"
    );

    XMEMCPY(r, tmp_arr, sizeof(tmp_arr));
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_48(sp_digit* r, const sp_digit* a)
{
    __asm__ __volatile__ (
        "mov	r3, #0\n\t"
        "mov	r4, #0\n\t"
        "mov	r5, #0\n\t"
        "mov	r9, r3\n\t"
        "mov	r12, %[r]\n\t"
        "mov	r6, #1\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, #128\n\t"
        "neg	r6, r6\n\t"
        "add	sp, sp, r6\n\t"
        "mov	r11, sp\n\t"
        "mov	r10, %[a]\n\t"
        "\n1:\n\t"
        "mov	%[r], #0\n\t"
        "mov	r6, #188\n\t"
        "mov	%[a], r9\n\t"
        "subs	%[a], %[a], r6\n\t"
        "sbc	r6, r6, r6\n\t"
        "mvn	r6, r6\n\t"
        "and	%[a], %[a], r6\n\t"
        "mov	r2, r9\n\t"
        "sub	r2, r2, %[a]\n\t"
        "add	%[a], %[a], r10\n\t"
        "add	r2, r2, r10\n\t"
        "\n2:\n\t"
        "cmp	r2, %[a]\n\t"
#ifdef __GNUC__
        "beq	4f\n\t"
#else
        "beq.n	4f\n\t"
#endif /* __GNUC__ */
        /* Multiply * 2: Start */
        "ldr	r6, [%[a]]\n\t"
        "ldr	r8, [r2]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        /* Multiply * 2: Done */
#ifdef __GNUC__
        "bal	5f\n\t"
#else
        "bal.n	5f\n\t"
#endif /* __GNUC__ */
        "\n4:\n\t"
        /* Square: Start */
        "ldr	r6, [%[a]]\n\t"
        "umull	r6, r8, r6, r6\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        /* Square: Done */
        "\n5:\n\t"
        "add	%[a], %[a], #4\n\t"
        "sub	r2, r2, #4\n\t"
        "mov	r6, #192\n\t"
        "add	r6, r6, r10\n\t"
        "cmp	%[a], r6\n\t"
#ifdef __GNUC__
        "beq	3f\n\t"
#else
        "beq.n	3f\n\t"
#endif /* __GNUC__ */
        "cmp	%[a], r2\n\t"
#ifdef __GNUC__
        "bgt	3f\n\t"
#else
        "bgt.n	3f\n\t"
#endif /* __GNUC__ */
        "mov	r8, r9\n\t"
        "add	r8, r8, r10\n\t"
        "cmp	%[a], r8\n\t"
#ifdef __GNUC__
        "ble	2b\n\t"
#else
        "ble.n	2b\n\t"
#endif /* __GNUC__ */
        "\n3:\n\t"
        "mov	%[r], r11\n\t"
        "mov	r8, r9\n\t"
        "str	r3, [%[r], r8]\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "mov	r5, #0\n\t"
        "add	r8, r8, #4\n\t"
        "mov	r9, r8\n\t"
        "mov	r6, #1\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, #120\n\t"
        "cmp	r8, r6\n\t"
#ifdef __GNUC__
        "ble	1b\n\t"
#else
        "ble.n	1b\n\t"
#endif /* __GNUC__ */
        "mov	%[a], r10\n\t"
        "str	r3, [%[r], r8]\n\t"
        "mov	%[r], r12\n\t"
        "mov	%[a], r11\n\t"
        "mov	r3, #1\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #124\n\t"
        "\n4:\n\t"
        "ldr	r6, [%[a], r3]\n\t"
        "str	r6, [%[r], r3]\n\t"
        "subs	r3, r3, #4\n\t"
#ifdef __GNUC__
        "bge	4b\n\t"
#else
        "bge.n	4b\n\t"
#endif /* __GNUC__ */
        "mov	r6, #1\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, #128\n\t"
        "add	sp, sp, r6\n\t"
        :
        : [r] "r" (r), [a] "r" (a)
        : "memory", "r2", "r3", "r4", "r5", "r6", "r8", "r9", "r10", "r11", "r12"
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
SP_NOINLINE static void sp_3072_mul_d_96(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
    __asm__ __volatile__ (
        "add	r9, %[a], #384\n\t"
        /* A[0] * B */
        "ldr	r6, [%[a]], #4\n\t"
        "umull	r5, r3, r6, %[b]\n\t"
        "mov	r4, #0\n\t"
        "str	r5, [%[r]], #4\n\t"
        /* A[0] * B - Done */
        "\n1:\n\t"
        "mov	r5, #0\n\t"
        /* A[] * B */
        "ldr	r6, [%[a]], #4\n\t"
        "umull	r6, r8, r6, %[b]\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[] * B - Done */
        "str	r3, [%[r]], #4\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "cmp	%[a], r9\n\t"
#ifdef __GNUC__
        "blt	1b\n\t"
#else
        "blt.n	1b\n\t"
#endif /* __GNUC__ */
        "str	r3, [%[r]]\n\t"
        : [r] "+r" (r), [a] "+r" (a)
        : [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r8", "r9"
    );
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
SP_NOINLINE static sp_digit sp_3072_cond_sub_48(sp_digit* r, const sp_digit* a,
        const sp_digit* b, sp_digit m)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r5, #192\n\t"
        "mov	r9, r5\n\t"
        "mov	r8, #0\n\t"
        "\n1:\n\t"
        "ldr	r6, [%[b], r8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "mov	r5, #0\n\t"
        "subs	r5, r5, %[c]\n\t"
        "ldr	r5, [%[a], r8]\n\t"
        "sbcs	r5, r5, r6\n\t"
        "sbcs	%[c], %[c], %[c]\n\t"
        "str	r5, [%[r], r8]\n\t"
        "add	r8, r8, #4\n\t"
        "cmp	r8, r9\n\t"
#ifdef __GNUC__
        "blt	1b\n\t"
#else
        "blt.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r5", "r6", "r8", "r9"
    );

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
        "mov	r9, %[mp]\n\t"
        "mov	r12, %[m]\n\t"
        "mov	r10, %[a]\n\t"
        "mov	r4, #0\n\t"
        "add	r11, r10, #192\n\t"
        "\n1:\n\t"
        /* mu = a[i] * mp */
        "mov	%[mp], r9\n\t"
        "ldr	%[a], [r10]\n\t"
        "mul	%[mp], %[mp], %[a]\n\t"
        "mov	%[m], r12\n\t"
        "add	r14, r10, #184\n\t"
        "\n2:\n\t"
        /* a[i+j] += m[j] * mu */
        "ldr	%[a], [r10]\n\t"
        "mov	r5, #0\n\t"
        /* Multiply m[j] and mu - Start */
        "ldr	r8, [%[m]], #4\n\t"
        "umull	r6, r8, %[mp], r8\n\t"
        "adds	%[a], %[a], r6\n\t"
        "adc	r5, r5, r8\n\t"
        /* Multiply m[j] and mu - Done */
        "adds	r4, r4, %[a]\n\t"
        "adc	r5, r5, #0\n\t"
        "str	r4, [r10], #4\n\t"
        /* a[i+j+1] += m[j+1] * mu */
        "ldr	%[a], [r10]\n\t"
        "mov	r4, #0\n\t"
        /* Multiply m[j] and mu - Start */
        "ldr	r8, [%[m]], #4\n\t"
        "umull	r6, r8, %[mp], r8\n\t"
        "adds	%[a], %[a], r6\n\t"
        "adc	r4, r4, r8\n\t"
        /* Multiply m[j] and mu - Done */
        "adds	r5, r5, %[a]\n\t"
        "adc	r4, r4, #0\n\t"
        "str	r5, [r10], #4\n\t"
        "cmp	r10, r14\n\t"
#ifdef __GNUC__
        "blt	2b\n\t"
#else
        "blt.n	2b\n\t"
#endif /* __GNUC__ */
        /* a[i+46] += m[46] * mu */
        "ldr	%[a], [r10]\n\t"
        "mov	r5, #0\n\t"
        /* Multiply m[j] and mu - Start */
        "ldr	r8, [%[m]], #4\n\t"
        "umull	r6, r8, %[mp], r8\n\t"
        "adds	%[a], %[a], r6\n\t"
        "adc	r5, r5, r8\n\t"
        /* Multiply m[j] and mu - Done */
        "adds	r4, r4, %[a]\n\t"
        "adc	r5, r5, #0\n\t"
        "str	r4, [r10], #4\n\t"
        /* a[i+47] += m[47] * mu */
        "mov	r4, %[ca]\n\t"
        "mov	%[ca], #0\n\t"
        /* Multiply m[47] and mu - Start */
        "ldr	r8, [%[m]]\n\t"
        "umull	r6, r8, %[mp], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	%[ca], %[ca], #0\n\t"
        /* Multiply m[47] and mu - Done */
        "ldr	r6, [r10]\n\t"
        "ldr	r8, [r10, #4]\n\t"
        "adds	r6, r6, r5\n\t"
        "adcs	r8, r8, r4\n\t"
        "adc	%[ca], %[ca], #0\n\t"
        "str	r6, [r10]\n\t"
        "str	r8, [r10, #4]\n\t"
        /* Next word in a */
        "sub	r10, r10, #184\n\t"
        "cmp	r10, r11\n\t"
#ifdef __GNUC__
        "blt	1b\n\t"
#else
        "blt.n	1b\n\t"
#endif /* __GNUC__ */
        "mov	%[a], r10\n\t"
        "mov	%[m], r12\n\t"
        : [ca] "+r" (ca), [a] "+r" (a)
        : [m] "r" (m), [mp] "r" (mp)
        : "memory", "r4", "r5", "r6", "r8", "r9", "r10", "r11", "r12", "r14"
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
SP_NOINLINE static void sp_3072_mul_d_48(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
    __asm__ __volatile__ (
        "add	r9, %[a], #192\n\t"
        /* A[0] * B */
        "ldr	r6, [%[a]], #4\n\t"
        "umull	r5, r3, r6, %[b]\n\t"
        "mov	r4, #0\n\t"
        "str	r5, [%[r]], #4\n\t"
        /* A[0] * B - Done */
        "\n1:\n\t"
        "mov	r5, #0\n\t"
        /* A[] * B */
        "ldr	r6, [%[a]], #4\n\t"
        "umull	r6, r8, r6, %[b]\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[] * B - Done */
        "str	r3, [%[r]], #4\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "cmp	%[a], r9\n\t"
#ifdef __GNUC__
        "blt	1b\n\t"
#else
        "blt.n	1b\n\t"
#endif /* __GNUC__ */
        "str	r3, [%[r]]\n\t"
        : [r] "+r" (r), [a] "+r" (a)
        : [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r8", "r9"
    );
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
SP_NOINLINE static sp_digit div_3072_word_48(sp_digit d1, sp_digit d0,
        sp_digit div)
{
    sp_digit r = 0;

    __asm__ __volatile__ (
        "lsr	r6, %[div], #16\n\t"
        "add	r6, r6, #1\n\t"
        "udiv	r4, %[d1], r6\n\t"
        "lsl	r8, r4, #16\n\t"
        "umull	r4, r5, %[div], r8\n\t"
        "subs	%[d0], %[d0], r4\n\t"
        "sbc	%[d1], %[d1], r5\n\t"
        "udiv	r5, %[d1], r6\n\t"
        "lsl	r4, r5, #16\n\t"
        "add	r8, r8, r4\n\t"
        "umull	r4, r5, %[div], r4\n\t"
        "subs	%[d0], %[d0], r4\n\t"
        "sbc	%[d1], %[d1], r5\n\t"
        "lsl	r4, %[d1], #16\n\t"
        "orr	r4, r4, %[d0], lsr #16\n\t"
        "udiv	r4, r4, r6\n\t"
        "add	r8, r8, r4\n\t"
        "umull	r4, r5, %[div], r4\n\t"
        "subs	%[d0], %[d0], r4\n\t"
        "sbc	%[d1], %[d1], r5\n\t"
        "lsl	r4, %[d1], #16\n\t"
        "orr	r4, r4, %[d0], lsr #16\n\t"
        "udiv	r4, r4, r6\n\t"
        "add	r8, r8, r4\n\t"
        "umull	r4, r5, %[div], r4\n\t"
        "subs	%[d0], %[d0], r4\n\t"
        "sbc	%[d1], %[d1], r5\n\t"
        "udiv	r4, %[d0], %[div]\n\t"
        "add	r8, r8, r4\n\t"
        "mov	%[r], r8\n\t"
        : [r] "+r" (r)
        : [d1] "r" (d1), [d0] "r" (d0), [div] "r" (div)
        : "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_int32 sp_3072_cmp_48(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;


    __asm__ __volatile__ (
        "mov	r3, #0\n\t"
        "mvn	r3, r3\n\t"
        "mov	r6, #188\n\t"
        "\n1:\n\t"
        "ldr	r8, [%[a], r6]\n\t"
        "ldr	r5, [%[b], r6]\n\t"
        "and	r8, r8, r3\n\t"
        "and	r5, r5, r3\n\t"
        "mov	r4, r8\n\t"
        "subs	r8, r8, r5\n\t"
        "sbc	r8, r8, r8\n\t"
        "add	%[r], %[r], r8\n\t"
        "mvn	r8, r8\n\t"
        "and	r3, r3, r8\n\t"
        "subs	r5, r5, r4\n\t"
        "sbc	r8, r8, r8\n\t"
        "sub	%[r], %[r], r8\n\t"
        "mvn	r8, r8\n\t"
        "and	r3, r3, r8\n\t"
        "sub	r6, r6, #4\n\t"
        "cmp	r6, #0\n\t"
#ifdef __GNUC__
        "bge	1b\n\t"
#else
        "bge.n	1b\n\t"
#endif /* __GNUC__ */
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "r3", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_digit sp_3072_cond_sub_96(sp_digit* r, const sp_digit* a,
        const sp_digit* b, sp_digit m)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r5, #1\n\t"
        "lsl	r5, r5, #8\n\t"
        "add	r5, r5, #128\n\t"
        "mov	r9, r5\n\t"
        "mov	r8, #0\n\t"
        "\n1:\n\t"
        "ldr	r6, [%[b], r8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "mov	r5, #0\n\t"
        "subs	r5, r5, %[c]\n\t"
        "ldr	r5, [%[a], r8]\n\t"
        "sbcs	r5, r5, r6\n\t"
        "sbcs	%[c], %[c], %[c]\n\t"
        "str	r5, [%[r], r8]\n\t"
        "add	r8, r8, #4\n\t"
        "cmp	r8, r9\n\t"
#ifdef __GNUC__
        "blt	1b\n\t"
#else
        "blt.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r5", "r6", "r8", "r9"
    );

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
        "mov	r9, %[mp]\n\t"
        "mov	r12, %[m]\n\t"
        "mov	r10, %[a]\n\t"
        "mov	r4, #0\n\t"
        "add	r11, r10, #384\n\t"
        "\n1:\n\t"
        /* mu = a[i] * mp */
        "mov	%[mp], r9\n\t"
        "ldr	%[a], [r10]\n\t"
        "mul	%[mp], %[mp], %[a]\n\t"
        "mov	%[m], r12\n\t"
        "add	r14, r10, #376\n\t"
        "\n2:\n\t"
        /* a[i+j] += m[j] * mu */
        "ldr	%[a], [r10]\n\t"
        "mov	r5, #0\n\t"
        /* Multiply m[j] and mu - Start */
        "ldr	r8, [%[m]], #4\n\t"
        "umull	r6, r8, %[mp], r8\n\t"
        "adds	%[a], %[a], r6\n\t"
        "adc	r5, r5, r8\n\t"
        /* Multiply m[j] and mu - Done */
        "adds	r4, r4, %[a]\n\t"
        "adc	r5, r5, #0\n\t"
        "str	r4, [r10], #4\n\t"
        /* a[i+j+1] += m[j+1] * mu */
        "ldr	%[a], [r10]\n\t"
        "mov	r4, #0\n\t"
        /* Multiply m[j] and mu - Start */
        "ldr	r8, [%[m]], #4\n\t"
        "umull	r6, r8, %[mp], r8\n\t"
        "adds	%[a], %[a], r6\n\t"
        "adc	r4, r4, r8\n\t"
        /* Multiply m[j] and mu - Done */
        "adds	r5, r5, %[a]\n\t"
        "adc	r4, r4, #0\n\t"
        "str	r5, [r10], #4\n\t"
        "cmp	r10, r14\n\t"
#ifdef __GNUC__
        "blt	2b\n\t"
#else
        "blt.n	2b\n\t"
#endif /* __GNUC__ */
        /* a[i+94] += m[94] * mu */
        "ldr	%[a], [r10]\n\t"
        "mov	r5, #0\n\t"
        /* Multiply m[j] and mu - Start */
        "ldr	r8, [%[m]], #4\n\t"
        "umull	r6, r8, %[mp], r8\n\t"
        "adds	%[a], %[a], r6\n\t"
        "adc	r5, r5, r8\n\t"
        /* Multiply m[j] and mu - Done */
        "adds	r4, r4, %[a]\n\t"
        "adc	r5, r5, #0\n\t"
        "str	r4, [r10], #4\n\t"
        /* a[i+95] += m[95] * mu */
        "mov	r4, %[ca]\n\t"
        "mov	%[ca], #0\n\t"
        /* Multiply m[95] and mu - Start */
        "ldr	r8, [%[m]]\n\t"
        "umull	r6, r8, %[mp], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	%[ca], %[ca], #0\n\t"
        /* Multiply m[95] and mu - Done */
        "ldr	r6, [r10]\n\t"
        "ldr	r8, [r10, #4]\n\t"
        "adds	r6, r6, r5\n\t"
        "adcs	r8, r8, r4\n\t"
        "adc	%[ca], %[ca], #0\n\t"
        "str	r6, [r10]\n\t"
        "str	r8, [r10, #4]\n\t"
        /* Next word in a */
        "sub	r10, r10, #376\n\t"
        "cmp	r10, r11\n\t"
#ifdef __GNUC__
        "blt	1b\n\t"
#else
        "blt.n	1b\n\t"
#endif /* __GNUC__ */
        "mov	%[a], r10\n\t"
        "mov	%[m], r12\n\t"
        : [ca] "+r" (ca), [a] "+r" (a)
        : [m] "r" (m), [mp] "r" (mp)
        : "memory", "r4", "r5", "r6", "r8", "r9", "r10", "r11", "r12", "r14"
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
SP_NOINLINE static sp_digit sp_3072_sub_96(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r6, %[a]\n\t"
        "mov	r5, #1\n\t"
        "lsl	r5, r5, #8\n\t"
        "add	r5, r5, #128\n\t"
        "add	r6, r6, r5\n\t"
        "\n1:\n\t"
        "mov	r5, #0\n\t"
        "subs	r5, r5, %[c]\n\t"
        "ldr	r4, [%[a]]\n\t"
        "ldr	r5, [%[b]]\n\t"
        "sbcs	r4, r4, r5\n\t"
        "str	r4, [%[r]]\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        "add	%[a], %[a], #4\n\t"
        "add	%[b], %[b], #4\n\t"
        "add	%[r], %[r], #4\n\t"
        "cmp	%[a], r6\n\t"
#ifdef __GNUC__
        "bne	1b\n\t"
#else
        "bne.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6"
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
SP_NOINLINE static sp_digit sp_3072_sub_96(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "subs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_digit div_3072_word_96(sp_digit d1, sp_digit d0,
        sp_digit div)
{
    sp_digit r = 0;

    __asm__ __volatile__ (
        "lsr	r6, %[div], #16\n\t"
        "add	r6, r6, #1\n\t"
        "udiv	r4, %[d1], r6\n\t"
        "lsl	r8, r4, #16\n\t"
        "umull	r4, r5, %[div], r8\n\t"
        "subs	%[d0], %[d0], r4\n\t"
        "sbc	%[d1], %[d1], r5\n\t"
        "udiv	r5, %[d1], r6\n\t"
        "lsl	r4, r5, #16\n\t"
        "add	r8, r8, r4\n\t"
        "umull	r4, r5, %[div], r4\n\t"
        "subs	%[d0], %[d0], r4\n\t"
        "sbc	%[d1], %[d1], r5\n\t"
        "lsl	r4, %[d1], #16\n\t"
        "orr	r4, r4, %[d0], lsr #16\n\t"
        "udiv	r4, r4, r6\n\t"
        "add	r8, r8, r4\n\t"
        "umull	r4, r5, %[div], r4\n\t"
        "subs	%[d0], %[d0], r4\n\t"
        "sbc	%[d1], %[d1], r5\n\t"
        "lsl	r4, %[d1], #16\n\t"
        "orr	r4, r4, %[d0], lsr #16\n\t"
        "udiv	r4, r4, r6\n\t"
        "add	r8, r8, r4\n\t"
        "umull	r4, r5, %[div], r4\n\t"
        "subs	%[d0], %[d0], r4\n\t"
        "sbc	%[d1], %[d1], r5\n\t"
        "udiv	r4, %[d0], %[div]\n\t"
        "add	r8, r8, r4\n\t"
        "mov	%[r], r8\n\t"
        : [r] "+r" (r)
        : [d1] "r" (d1), [d0] "r" (d0), [div] "r" (div)
        : "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_int32 sp_3072_cmp_96(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;


    __asm__ __volatile__ (
        "mov	r3, #0\n\t"
        "mvn	r3, r3\n\t"
        "mov	r6, #1\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, #124\n\t"
        "\n1:\n\t"
        "ldr	r8, [%[a], r6]\n\t"
        "ldr	r5, [%[b], r6]\n\t"
        "and	r8, r8, r3\n\t"
        "and	r5, r5, r3\n\t"
        "mov	r4, r8\n\t"
        "subs	r8, r8, r5\n\t"
        "sbc	r8, r8, r8\n\t"
        "add	%[r], %[r], r8\n\t"
        "mvn	r8, r8\n\t"
        "and	r3, r3, r8\n\t"
        "subs	r5, r5, r4\n\t"
        "sbc	r8, r8, r8\n\t"
        "sub	%[r], %[r], r8\n\t"
        "mvn	r8, r8\n\t"
        "and	r3, r3, r8\n\t"
        "sub	r6, r6, #4\n\t"
        "cmp	r6, #0\n\t"
#ifdef __GNUC__
        "bge	1b\n\t"
#else
        "bge.n	1b\n\t"
#endif /* __GNUC__ */
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "r3", "r4", "r5", "r6", "r8"
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
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
SP_NOINLINE static sp_digit sp_3072_cond_add_48(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r5, #192\n\t"
        "mov	r9, r5\n\t"
        "mov	r8, #0\n\t"
        "\n1:\n\t"
        "ldr	r6, [%[b], r8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "adds	r5, %[c], #-1\n\t"
        "ldr	r5, [%[a], r8]\n\t"
        "adcs	r5, r5, r6\n\t"
        "mov	%[c], #0\n\t"
        "adcs	%[c], %[c], %[c]\n\t"
        "str	r5, [%[r], r8]\n\t"
        "add	r8, r8, #4\n\t"
        "cmp	r8, r9\n\t"
#ifdef __GNUC__
        "blt	1b\n\t"
#else
        "blt.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r5", "r6", "r8", "r9"
    );

    return c;
}

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
        "mov	r6, #31\n\t"
        "sub	r6, r6, %[n]\n\t"
        "add	%[a], %[a], #320\n\t"
        "add	%[r], %[r], #320\n\t"
        "ldr	r3, [%[a], #60]\n\t"
        "lsr	r4, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r4, r4, r6\n\t"
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
        "sub	%[a], %[a], #64\n\t"
        "sub	%[r], %[r], #64\n\t"
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
        "sub	%[a], %[a], #64\n\t"
        "sub	%[r], %[r], #64\n\t"
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
        "sub	%[a], %[a], #64\n\t"
        "sub	%[r], %[r], #64\n\t"
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
        "sub	%[a], %[a], #64\n\t"
        "sub	%[r], %[r], #64\n\t"
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
        "sub	%[a], %[a], #64\n\t"
        "sub	%[r], %[r], #64\n\t"
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
        "str	r4, [%[r]]\n\t"
        "str	r2, [%[r], #4]\n\t"
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
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_4096_sub_in_place_128(sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "subs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "ldm	%[a], {r3, r4}\n\t"
        "ldm	%[b]!, {r5, r6}\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "stm	%[a]!, {r3, r4}\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6"
    );

    return c;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static sp_digit sp_4096_add_128(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adds	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "adcs	r4, r4, r6\n\t"
        "adcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "mov	%[c], #0\n\t"
        "adc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_digit sp_4096_add_128(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r6, %[a]\n\t"
        "mov	r8, #0\n\t"
        "add	r6, r6, #512\n\t"
        "sub	r8, r8, #1\n\t"
        "\n1:\n\t"
        "adds	%[c], %[c], r8\n\t"
        "ldr	r4, [%[a]]\n\t"
        "ldr	r5, [%[b]]\n\t"
        "adcs	r4, r4, r5\n\t"
        "str	r4, [%[r]]\n\t"
        "mov	%[c], #0\n\t"
        "adc	%[c], %[c], %[c]\n\t"
        "add	%[a], %[a], #4\n\t"
        "add	%[b], %[b], #4\n\t"
        "add	%[r], %[r], #4\n\t"
        "cmp	%[a], r6\n\t"
#ifdef __GNUC__
        "bne	1b\n\t"
#else
        "bne.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_digit sp_4096_sub_in_place_128(sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;
    __asm__ __volatile__ (
        "mov	r8, %[a]\n\t"
        "add	r8, r8, #512\n\t"
        "\n1:\n\t"
        "mov	r5, #0\n\t"
        "subs	r5, r5, %[c]\n\t"
        "ldr	r3, [%[a]]\n\t"
        "ldr	r4, [%[a], #4]\n\t"
        "ldr	r5, [%[b]]\n\t"
        "ldr	r6, [%[b], #4]\n\t"
        "sbcs	r3, r3, r5\n\t"
        "sbcs	r4, r4, r6\n\t"
        "str	r3, [%[a]]\n\t"
        "str	r4, [%[a], #4]\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        "add	%[a], %[a], #8\n\t"
        "add	%[b], %[b], #8\n\t"
        "cmp	%[a], r8\n\t"
#ifdef __GNUC__
        "bne	1b\n\t"
#else
        "bne.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static void sp_4096_mul_128(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit tmp_arr[128 * 2];
    sp_digit* tmp = tmp_arr;
    __asm__ __volatile__ (
        "mov	r3, #0\n\t"
        "mov	r4, #0\n\t"
        "mov	r9, r3\n\t"
        "mov	r12, %[r]\n\t"
        "mov	r10, %[a]\n\t"
        "mov	r11, %[b]\n\t"
        "mov	r6, #2\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, r10\n\t"
        "mov	r14, r6\n\t"
        "\n1:\n\t"
        "mov	%[r], #0\n\t"
        "mov	r5, #0\n\t"
        "mov	r6, #1\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, #252\n\t"
        "mov	%[a], r9\n\t"
        "subs	%[a], %[a], r6\n\t"
        "sbc	r6, r6, r6\n\t"
        "mvn	r6, r6\n\t"
        "and	%[a], %[a], r6\n\t"
        "mov	%[b], r9\n\t"
        "sub	%[b], %[b], %[a]\n\t"
        "add	%[a], %[a], r10\n\t"
        "add	%[b], %[b], r11\n\t"
        "\n2:\n\t"
        /* Multiply Start */
        "ldr	r6, [%[a]]\n\t"
        "ldr	r8, [%[b]]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        /* Multiply Done */
        "add	%[a], %[a], #4\n\t"
        "sub	%[b], %[b], #4\n\t"
        "cmp	%[a], r14\n\t"
#ifdef __GNUC__
        "beq	3f\n\t"
#else
        "beq.n	3f\n\t"
#endif /* __GNUC__ */
        "mov	r6, r9\n\t"
        "add	r6, r6, r10\n\t"
        "cmp	%[a], r6\n\t"
#ifdef __GNUC__
        "ble	2b\n\t"
#else
        "ble.n	2b\n\t"
#endif /* __GNUC__ */
        "\n3:\n\t"
        "mov	%[r], r12\n\t"
        "mov	r8, r9\n\t"
        "str	r3, [%[r], r8]\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "add	r8, r8, #4\n\t"
        "mov	r9, r8\n\t"
        "mov	r6, #3\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, #248\n\t"
        "cmp	r8, r6\n\t"
#ifdef __GNUC__
        "ble	1b\n\t"
#else
        "ble.n	1b\n\t"
#endif /* __GNUC__ */
        "str	r3, [%[r], r8]\n\t"
        "mov	%[a], r10\n\t"
        "mov	%[b], r11\n\t"
        :
        : [r] "r" (tmp), [a] "r" (a), [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r8", "r9", "r10", "r11", "r12", "r14"
    );

    XMEMCPY(r, tmp_arr, sizeof(tmp_arr));
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_4096_sqr_128(sp_digit* r, const sp_digit* a)
{
    __asm__ __volatile__ (
        "mov	r3, #0\n\t"
        "mov	r4, #0\n\t"
        "mov	r5, #0\n\t"
        "mov	r9, r3\n\t"
        "mov	r12, %[r]\n\t"
        "mov	r6, #4\n\t"
        "lsl	r6, r6, #8\n\t"
        "neg	r6, r6\n\t"
        "add	sp, sp, r6\n\t"
        "mov	r11, sp\n\t"
        "mov	r10, %[a]\n\t"
        "\n1:\n\t"
        "mov	%[r], #0\n\t"
        "mov	r6, #1\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, #252\n\t"
        "mov	%[a], r9\n\t"
        "subs	%[a], %[a], r6\n\t"
        "sbc	r6, r6, r6\n\t"
        "mvn	r6, r6\n\t"
        "and	%[a], %[a], r6\n\t"
        "mov	r2, r9\n\t"
        "sub	r2, r2, %[a]\n\t"
        "add	%[a], %[a], r10\n\t"
        "add	r2, r2, r10\n\t"
        "\n2:\n\t"
        "cmp	r2, %[a]\n\t"
#ifdef __GNUC__
        "beq	4f\n\t"
#else
        "beq.n	4f\n\t"
#endif /* __GNUC__ */
        /* Multiply * 2: Start */
        "ldr	r6, [%[a]]\n\t"
        "ldr	r8, [r2]\n\t"
        "umull	r6, r8, r6, r8\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        /* Multiply * 2: Done */
#ifdef __GNUC__
        "bal	5f\n\t"
#else
        "bal.n	5f\n\t"
#endif /* __GNUC__ */
        "\n4:\n\t"
        /* Square: Start */
        "ldr	r6, [%[a]]\n\t"
        "umull	r6, r8, r6, r6\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs	r4, r4, r8\n\t"
        "adc	r5, r5, %[r]\n\t"
        /* Square: Done */
        "\n5:\n\t"
        "add	%[a], %[a], #4\n\t"
        "sub	r2, r2, #4\n\t"
        "mov	r6, #2\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, r10\n\t"
        "cmp	%[a], r6\n\t"
#ifdef __GNUC__
        "beq	3f\n\t"
#else
        "beq.n	3f\n\t"
#endif /* __GNUC__ */
        "cmp	%[a], r2\n\t"
#ifdef __GNUC__
        "bgt	3f\n\t"
#else
        "bgt.n	3f\n\t"
#endif /* __GNUC__ */
        "mov	r8, r9\n\t"
        "add	r8, r8, r10\n\t"
        "cmp	%[a], r8\n\t"
#ifdef __GNUC__
        "ble	2b\n\t"
#else
        "ble.n	2b\n\t"
#endif /* __GNUC__ */
        "\n3:\n\t"
        "mov	%[r], r11\n\t"
        "mov	r8, r9\n\t"
        "str	r3, [%[r], r8]\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "mov	r5, #0\n\t"
        "add	r8, r8, #4\n\t"
        "mov	r9, r8\n\t"
        "mov	r6, #3\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, #248\n\t"
        "cmp	r8, r6\n\t"
#ifdef __GNUC__
        "ble	1b\n\t"
#else
        "ble.n	1b\n\t"
#endif /* __GNUC__ */
        "mov	%[a], r10\n\t"
        "str	r3, [%[r], r8]\n\t"
        "mov	%[r], r12\n\t"
        "mov	%[a], r11\n\t"
        "mov	r3, #3\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #252\n\t"
        "\n4:\n\t"
        "ldr	r6, [%[a], r3]\n\t"
        "str	r6, [%[r], r3]\n\t"
        "subs	r3, r3, #4\n\t"
#ifdef __GNUC__
        "bge	4b\n\t"
#else
        "bge.n	4b\n\t"
#endif /* __GNUC__ */
        "mov	r6, #4\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	sp, sp, r6\n\t"
        :
        : [r] "r" (r), [a] "r" (a)
        : "memory", "r2", "r3", "r4", "r5", "r6", "r8", "r9", "r10", "r11", "r12"
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
SP_NOINLINE static void sp_4096_mul_d_128(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
    __asm__ __volatile__ (
        "add	r9, %[a], #512\n\t"
        /* A[0] * B */
        "ldr	r6, [%[a]], #4\n\t"
        "umull	r5, r3, r6, %[b]\n\t"
        "mov	r4, #0\n\t"
        "str	r5, [%[r]], #4\n\t"
        /* A[0] * B - Done */
        "\n1:\n\t"
        "mov	r5, #0\n\t"
        /* A[] * B */
        "ldr	r6, [%[a]], #4\n\t"
        "umull	r6, r8, r6, %[b]\n\t"
        "adds	r3, r3, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	r5, r5, #0\n\t"
        /* A[] * B - Done */
        "str	r3, [%[r]], #4\n\t"
        "mov	r3, r4\n\t"
        "mov	r4, r5\n\t"
        "cmp	%[a], r9\n\t"
#ifdef __GNUC__
        "blt	1b\n\t"
#else
        "blt.n	1b\n\t"
#endif /* __GNUC__ */
        "str	r3, [%[r]]\n\t"
        : [r] "+r" (r), [a] "+r" (a)
        : [b] "r" (b)
        : "memory", "r3", "r4", "r5", "r6", "r8", "r9"
    );
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
SP_NOINLINE static sp_digit sp_4096_cond_sub_128(sp_digit* r, const sp_digit* a,
        const sp_digit* b, sp_digit m)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r5, #2\n\t"
        "lsl	r5, r5, #8\n\t"
        "mov	r9, r5\n\t"
        "mov	r8, #0\n\t"
        "\n1:\n\t"
        "ldr	r6, [%[b], r8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "mov	r5, #0\n\t"
        "subs	r5, r5, %[c]\n\t"
        "ldr	r5, [%[a], r8]\n\t"
        "sbcs	r5, r5, r6\n\t"
        "sbcs	%[c], %[c], %[c]\n\t"
        "str	r5, [%[r], r8]\n\t"
        "add	r8, r8, #4\n\t"
        "cmp	r8, r9\n\t"
#ifdef __GNUC__
        "blt	1b\n\t"
#else
        "blt.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r5", "r6", "r8", "r9"
    );

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
        "mov	r9, %[mp]\n\t"
        "mov	r12, %[m]\n\t"
        "mov	r10, %[a]\n\t"
        "mov	r4, #0\n\t"
        "add	r11, r10, #512\n\t"
        "\n1:\n\t"
        /* mu = a[i] * mp */
        "mov	%[mp], r9\n\t"
        "ldr	%[a], [r10]\n\t"
        "mul	%[mp], %[mp], %[a]\n\t"
        "mov	%[m], r12\n\t"
        "add	r14, r10, #504\n\t"
        "\n2:\n\t"
        /* a[i+j] += m[j] * mu */
        "ldr	%[a], [r10]\n\t"
        "mov	r5, #0\n\t"
        /* Multiply m[j] and mu - Start */
        "ldr	r8, [%[m]], #4\n\t"
        "umull	r6, r8, %[mp], r8\n\t"
        "adds	%[a], %[a], r6\n\t"
        "adc	r5, r5, r8\n\t"
        /* Multiply m[j] and mu - Done */
        "adds	r4, r4, %[a]\n\t"
        "adc	r5, r5, #0\n\t"
        "str	r4, [r10], #4\n\t"
        /* a[i+j+1] += m[j+1] * mu */
        "ldr	%[a], [r10]\n\t"
        "mov	r4, #0\n\t"
        /* Multiply m[j] and mu - Start */
        "ldr	r8, [%[m]], #4\n\t"
        "umull	r6, r8, %[mp], r8\n\t"
        "adds	%[a], %[a], r6\n\t"
        "adc	r4, r4, r8\n\t"
        /* Multiply m[j] and mu - Done */
        "adds	r5, r5, %[a]\n\t"
        "adc	r4, r4, #0\n\t"
        "str	r5, [r10], #4\n\t"
        "cmp	r10, r14\n\t"
#ifdef __GNUC__
        "blt	2b\n\t"
#else
        "blt.n	2b\n\t"
#endif /* __GNUC__ */
        /* a[i+126] += m[126] * mu */
        "ldr	%[a], [r10]\n\t"
        "mov	r5, #0\n\t"
        /* Multiply m[j] and mu - Start */
        "ldr	r8, [%[m]], #4\n\t"
        "umull	r6, r8, %[mp], r8\n\t"
        "adds	%[a], %[a], r6\n\t"
        "adc	r5, r5, r8\n\t"
        /* Multiply m[j] and mu - Done */
        "adds	r4, r4, %[a]\n\t"
        "adc	r5, r5, #0\n\t"
        "str	r4, [r10], #4\n\t"
        /* a[i+127] += m[127] * mu */
        "mov	r4, %[ca]\n\t"
        "mov	%[ca], #0\n\t"
        /* Multiply m[127] and mu - Start */
        "ldr	r8, [%[m]]\n\t"
        "umull	r6, r8, %[mp], r8\n\t"
        "adds	r5, r5, r6\n\t"
        "adcs 	r4, r4, r8\n\t"
        "adc	%[ca], %[ca], #0\n\t"
        /* Multiply m[127] and mu - Done */
        "ldr	r6, [r10]\n\t"
        "ldr	r8, [r10, #4]\n\t"
        "adds	r6, r6, r5\n\t"
        "adcs	r8, r8, r4\n\t"
        "adc	%[ca], %[ca], #0\n\t"
        "str	r6, [r10]\n\t"
        "str	r8, [r10, #4]\n\t"
        /* Next word in a */
        "sub	r10, r10, #504\n\t"
        "cmp	r10, r11\n\t"
#ifdef __GNUC__
        "blt	1b\n\t"
#else
        "blt.n	1b\n\t"
#endif /* __GNUC__ */
        "mov	%[a], r10\n\t"
        "mov	%[m], r12\n\t"
        : [ca] "+r" (ca), [a] "+r" (a)
        : [m] "r" (m), [mp] "r" (mp)
        : "memory", "r4", "r5", "r6", "r8", "r9", "r10", "r11", "r12", "r14"
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
SP_NOINLINE static sp_digit sp_4096_sub_128(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r6, %[a]\n\t"
        "mov	r5, #2\n\t"
        "lsl	r5, r5, #8\n\t"
        "add	r6, r6, r5\n\t"
        "\n1:\n\t"
        "mov	r5, #0\n\t"
        "subs	r5, r5, %[c]\n\t"
        "ldr	r4, [%[a]]\n\t"
        "ldr	r5, [%[b]]\n\t"
        "sbcs	r4, r4, r5\n\t"
        "str	r4, [%[r]]\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        "add	%[a], %[a], #4\n\t"
        "add	%[b], %[b], #4\n\t"
        "add	%[r], %[r], #4\n\t"
        "cmp	%[a], r6\n\t"
#ifdef __GNUC__
        "bne	1b\n\t"
#else
        "bne.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6"
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
SP_NOINLINE static sp_digit sp_4096_sub_128(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "subs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r8}\n\t"
        "sbcs	r4, r4, r6\n\t"
        "sbcs	r5, r5, r8\n\t"
        "stm	%[r]!, {r4, r5}\n\t"
        "sbc	%[c], %[c], %[c]\n\t"
        : [c] "+r" (c), [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_digit div_4096_word_128(sp_digit d1, sp_digit d0,
        sp_digit div)
{
    sp_digit r = 0;

    __asm__ __volatile__ (
        "lsr	r6, %[div], #16\n\t"
        "add	r6, r6, #1\n\t"
        "udiv	r4, %[d1], r6\n\t"
        "lsl	r8, r4, #16\n\t"
        "umull	r4, r5, %[div], r8\n\t"
        "subs	%[d0], %[d0], r4\n\t"
        "sbc	%[d1], %[d1], r5\n\t"
        "udiv	r5, %[d1], r6\n\t"
        "lsl	r4, r5, #16\n\t"
        "add	r8, r8, r4\n\t"
        "umull	r4, r5, %[div], r4\n\t"
        "subs	%[d0], %[d0], r4\n\t"
        "sbc	%[d1], %[d1], r5\n\t"
        "lsl	r4, %[d1], #16\n\t"
        "orr	r4, r4, %[d0], lsr #16\n\t"
        "udiv	r4, r4, r6\n\t"
        "add	r8, r8, r4\n\t"
        "umull	r4, r5, %[div], r4\n\t"
        "subs	%[d0], %[d0], r4\n\t"
        "sbc	%[d1], %[d1], r5\n\t"
        "lsl	r4, %[d1], #16\n\t"
        "orr	r4, r4, %[d0], lsr #16\n\t"
        "udiv	r4, r4, r6\n\t"
        "add	r8, r8, r4\n\t"
        "umull	r4, r5, %[div], r4\n\t"
        "subs	%[d0], %[d0], r4\n\t"
        "sbc	%[d1], %[d1], r5\n\t"
        "udiv	r4, %[d0], %[div]\n\t"
        "add	r8, r8, r4\n\t"
        "mov	%[r], r8\n\t"
        : [r] "+r" (r)
        : [d1] "r" (d1), [d0] "r" (d0), [div] "r" (div)
        : "r4", "r5", "r6", "r8"
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
SP_NOINLINE static sp_int32 sp_4096_cmp_128(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;


    __asm__ __volatile__ (
        "mov	r3, #0\n\t"
        "mvn	r3, r3\n\t"
        "mov	r6, #1\n\t"
        "lsl	r6, r6, #8\n\t"
        "add	r6, r6, #252\n\t"
        "\n1:\n\t"
        "ldr	r8, [%[a], r6]\n\t"
        "ldr	r5, [%[b], r6]\n\t"
        "and	r8, r8, r3\n\t"
        "and	r5, r5, r3\n\t"
        "mov	r4, r8\n\t"
        "subs	r8, r8, r5\n\t"
        "sbc	r8, r8, r8\n\t"
        "add	%[r], %[r], r8\n\t"
        "mvn	r8, r8\n\t"
        "and	r3, r3, r8\n\t"
        "subs	r5, r5, r4\n\t"
        "sbc	r8, r8, r8\n\t"
        "sub	%[r], %[r], r8\n\t"
        "mvn	r8, r8\n\t"
        "and	r3, r3, r8\n\t"
        "sub	r6, r6, #4\n\t"
        "cmp	r6, #0\n\t"
#ifdef __GNUC__
        "bge	1b\n\t"
#else
        "bge.n	1b\n\t"
#endif /* __GNUC__ */
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "r3", "r4", "r5", "r6", "r8"
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
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
SP_NOINLINE static sp_digit sp_4096_cond_add_64(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	r5, #1\n\t"
        "lsl	r5, r5, #8\n\t"
        "mov	r9, r5\n\t"
        "mov	r8, #0\n\t"
        "\n1:\n\t"
        "ldr	r6, [%[b], r8]\n\t"
        "and	r6, r6, %[m]\n\t"
        "adds	r5, %[c], #-1\n\t"
        "ldr	r5, [%[a], r8]\n\t"
        "adcs	r5, r5, r6\n\t"
        "mov	%[c], #0\n\t"
        "adcs	%[c], %[c], %[c]\n\t"
        "str	r5, [%[r], r8]\n\t"
        "add	r8, r8, #4\n\t"
        "cmp	r8, r9\n\t"
#ifdef __GNUC__
        "blt	1b\n\t"
#else
        "blt.n	1b\n\t"
#endif /* __GNUC__ */
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "r5", "r6", "r8", "r9"
    );

    return c;
}

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
        "mov	r6, #31\n\t"
        "sub	r6, r6, %[n]\n\t"
        "add	%[a], %[a], #448\n\t"
        "add	%[r], %[r], #448\n\t"
        "ldr	r3, [%[a], #60]\n\t"
        "lsr	r4, r3, #1\n\t"
        "lsl	r3, r3, %[n]\n\t"
        "lsr	r4, r4, r6\n\t"
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
        "sub	%[a], %[a], #64\n\t"
        "sub	%[r], %[r], #64\n\t"
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
        "sub	%[a], %[a], #64\n\t"
        "sub	%[r], %[r], #64\n\t"
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
        "sub	%[a], %[a], #64\n\t"
        "sub	%[r], %[r], #64\n\t"
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
        "sub	%[a], %[a], #64\n\t"
        "sub	%[r], %[r], #64\n\t"
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
        "sub	%[a], %[a], #64\n\t"
        "sub	%[r], %[r], #64\n\t"
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
        "sub	%[a], %[a], #64\n\t"
        "sub	%[r], %[r], #64\n\t"
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
        "sub	%[a], %[a], #64\n\t"
        "sub	%[r], %[r], #64\n\t"
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
        "str	r2, [%[r]]\n\t"
        "str	r3, [%[r], #4]\n\t"
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
#endif /* WOLFSSL_SP_ARM_CORTEX_M_ASM */
#endif /* WOLFSSL_HAVE_SP_RSA | WOLFSSL_HAVE_SP_DH | WOLFSSL_HAVE_SP_ECC */
