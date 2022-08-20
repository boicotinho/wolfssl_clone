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
#ifndef SP_RSA_PRIVATE_EXP_D
#define SP_RSA_PRIVATE_EXP_D
#endif

#ifndef WOLFSSL_SP_SMALL
#define WOLFSSL_SP_SMALL
#endif
#endif

#include <wolfssl/wolfcrypt/sp.h>

#ifndef WOLFSSL_SP_ASM
#if SP_WORD_SIZE == 32
#define SP_PRINT_NUM(var, name, total, words, bits)   \
    do {                                              \
        int ii;                                       \
        byte nb[(bits + 7) / 8];                      \
        sp_digit _s[words];                           \
        XMEMCPY(_s, var, sizeof(_s));                 \
        sp_##total##_norm_##words(_s);                \
        sp_##total##_to_bin_##words(_s, nb);          \
        fprintf(stderr, name "=0x");                  \
        for (ii=0; ii<(bits + 7) / 8; ii++)           \
            fprintf(stderr, "%02x", nb[ii]);          \
        fprintf(stderr, "\n");                        \
    } while (0)

#define SP_PRINT_VAL(var, name)                       \
    fprintf(stderr, name "=0x" SP_PRINT_FMT "\n", var)

#define SP_PRINT_INT(var, name)                       \
    fprintf(stderr, name "=%d\n", var)

#if (((!defined(WC_NO_CACHE_RESISTANT) &&  (defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH))) ||  (defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP))) &&  !defined(WOLFSSL_RSA_PUBLIC_ONLY))
/* Mask for address to obfuscate which of the two address will be used. */
static const size_t addr_mask[2] = { 0, (size_t)-1 };
#endif

#if defined(WOLFSSL_SP_NONBLOCK) && (!defined(WOLFSSL_SP_NO_MALLOC) ||                                      !defined(WOLFSSL_SP_SMALL))
    #error SP non-blocking requires small and no-malloc (WOLFSSL_SP_SMALL and WOLFSSL_SP_NO_MALLOC)
#endif

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
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = n-1; i >= 0; i--) {
        r[j] |= (((sp_digit)a[i]) << s);
        if (s >= 21U) {
            r[j] &= 0x1fffffff;
            s = 29U - s;
            if (j + 1 >= size) {
                break;
            }
            r[++j] = (sp_digit)a[i] >> s;
            s = 8U - s;
        }
        else {
            s += 8U;
        }
    }

    for (j++; j < size; j++) {
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
#if DIGIT_BIT == 29
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 29
    int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0x1fffffff;
        s = 29U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 29U) <= (word32)DIGIT_BIT) {
            s += 29U;
            r[j] &= 0x1fffffff;
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
        if (s + DIGIT_BIT >= 29) {
            r[j] &= 0x1fffffff;
            if (j + 1 >= size) {
                break;
            }
            s = 29 - s;
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
static void sp_2048_to_bin_72(sp_digit* r, byte* a)
{
    int i;
    int j;
    int s = 0;
    int b;

    for (i=0; i<71; i++) {
        r[i+1] += r[i] >> 29;
        r[i] &= 0x1fffffff;
    }
    j = 2055 / 8 - 1;
    a[j] = 0;
    for (i=0; i<72 && j>=0; i++) {
        b = 0;
        /* lint allow cast of mismatch sp_digit and int */
        a[j--] |= (byte)(r[i] << s); /*lint !e9033*/
        b += 8 - s;
        if (j < 0) {
            break;
        }
        while (b < 29) {
            a[j--] = (byte)(r[i] >> b);
            b += 8;
            if (j < 0) {
                break;
            }
        }
        s = 8 - (b - 29);
        if (j >= 0) {
            a[j] = 0;
        }
        if (s != 0) {
            j++;
        }
    }
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && (!defined(WOLFSSL_RSA_PUBLIC_ONLY) || !defined(WOLFSSL_SP_SMALL))) || defined(WOLFSSL_HAVE_SP_DH)
/* Normalize the values in each word to 29 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_2048_norm_36(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 35; i++) {
        a[i+1] += a[i] >> 29;
        a[i] &= 0x1fffffff;
    }
#else
    int i;
    for (i = 0; i < 32; i += 8) {
        a[i+1] += a[i+0] >> 29; a[i+0] &= 0x1fffffff;
        a[i+2] += a[i+1] >> 29; a[i+1] &= 0x1fffffff;
        a[i+3] += a[i+2] >> 29; a[i+2] &= 0x1fffffff;
        a[i+4] += a[i+3] >> 29; a[i+3] &= 0x1fffffff;
        a[i+5] += a[i+4] >> 29; a[i+4] &= 0x1fffffff;
        a[i+6] += a[i+5] >> 29; a[i+5] &= 0x1fffffff;
        a[i+7] += a[i+6] >> 29; a[i+6] &= 0x1fffffff;
        a[i+8] += a[i+7] >> 29; a[i+7] &= 0x1fffffff;
    }
    a[33] += a[32] >> 29; a[32] &= 0x1fffffff;
    a[34] += a[33] >> 29; a[33] &= 0x1fffffff;
    a[35] += a[34] >> 29; a[34] &= 0x1fffffff;
#endif /* WOLFSSL_SP_SMALL */
}

#endif /* (WOLFSSL_HAVE_SP_RSA && (!WOLFSSL_RSA_PUBLIC_ONLY || !WOLFSSL_SP_SMALL)) || WOLFSSL_HAVE_SP_DH */
/* Normalize the values in each word to 29 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_2048_norm_72(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 71; i++) {
        a[i+1] += a[i] >> 29;
        a[i] &= 0x1fffffff;
    }
#else
    int i;
    for (i = 0; i < 64; i += 8) {
        a[i+1] += a[i+0] >> 29; a[i+0] &= 0x1fffffff;
        a[i+2] += a[i+1] >> 29; a[i+1] &= 0x1fffffff;
        a[i+3] += a[i+2] >> 29; a[i+2] &= 0x1fffffff;
        a[i+4] += a[i+3] >> 29; a[i+3] &= 0x1fffffff;
        a[i+5] += a[i+4] >> 29; a[i+4] &= 0x1fffffff;
        a[i+6] += a[i+5] >> 29; a[i+5] &= 0x1fffffff;
        a[i+7] += a[i+6] >> 29; a[i+6] &= 0x1fffffff;
        a[i+8] += a[i+7] >> 29; a[i+7] &= 0x1fffffff;
    }
    a[65] += a[64] >> 29; a[64] &= 0x1fffffff;
    a[66] += a[65] >> 29; a[65] &= 0x1fffffff;
    a[67] += a[66] >> 29; a[66] &= 0x1fffffff;
    a[68] += a[67] >> 29; a[67] &= 0x1fffffff;
    a[69] += a[68] >> 29; a[68] &= 0x1fffffff;
    a[70] += a[69] >> 29; a[69] &= 0x1fffffff;
    a[71] += a[70] >> 29; a[70] &= 0x1fffffff;
#endif /* WOLFSSL_SP_SMALL */
}

#ifndef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_12(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_uint64 t0   = ((sp_uint64)a[ 0]) * b[ 0];
    sp_uint64 t1   = ((sp_uint64)a[ 0]) * b[ 1]
                 + ((sp_uint64)a[ 1]) * b[ 0];
    sp_uint64 t2   = ((sp_uint64)a[ 0]) * b[ 2]
                 + ((sp_uint64)a[ 1]) * b[ 1]
                 + ((sp_uint64)a[ 2]) * b[ 0];
    sp_uint64 t3   = ((sp_uint64)a[ 0]) * b[ 3]
                 + ((sp_uint64)a[ 1]) * b[ 2]
                 + ((sp_uint64)a[ 2]) * b[ 1]
                 + ((sp_uint64)a[ 3]) * b[ 0];
    sp_uint64 t4   = ((sp_uint64)a[ 0]) * b[ 4]
                 + ((sp_uint64)a[ 1]) * b[ 3]
                 + ((sp_uint64)a[ 2]) * b[ 2]
                 + ((sp_uint64)a[ 3]) * b[ 1]
                 + ((sp_uint64)a[ 4]) * b[ 0];
    sp_uint64 t5   = ((sp_uint64)a[ 0]) * b[ 5]
                 + ((sp_uint64)a[ 1]) * b[ 4]
                 + ((sp_uint64)a[ 2]) * b[ 3]
                 + ((sp_uint64)a[ 3]) * b[ 2]
                 + ((sp_uint64)a[ 4]) * b[ 1]
                 + ((sp_uint64)a[ 5]) * b[ 0];
    sp_uint64 t6   = ((sp_uint64)a[ 0]) * b[ 6]
                 + ((sp_uint64)a[ 1]) * b[ 5]
                 + ((sp_uint64)a[ 2]) * b[ 4]
                 + ((sp_uint64)a[ 3]) * b[ 3]
                 + ((sp_uint64)a[ 4]) * b[ 2]
                 + ((sp_uint64)a[ 5]) * b[ 1]
                 + ((sp_uint64)a[ 6]) * b[ 0];
    sp_uint64 t7   = ((sp_uint64)a[ 0]) * b[ 7]
                 + ((sp_uint64)a[ 1]) * b[ 6]
                 + ((sp_uint64)a[ 2]) * b[ 5]
                 + ((sp_uint64)a[ 3]) * b[ 4]
                 + ((sp_uint64)a[ 4]) * b[ 3]
                 + ((sp_uint64)a[ 5]) * b[ 2]
                 + ((sp_uint64)a[ 6]) * b[ 1]
                 + ((sp_uint64)a[ 7]) * b[ 0];
    sp_uint64 t8   = ((sp_uint64)a[ 0]) * b[ 8]
                 + ((sp_uint64)a[ 1]) * b[ 7]
                 + ((sp_uint64)a[ 2]) * b[ 6]
                 + ((sp_uint64)a[ 3]) * b[ 5]
                 + ((sp_uint64)a[ 4]) * b[ 4]
                 + ((sp_uint64)a[ 5]) * b[ 3]
                 + ((sp_uint64)a[ 6]) * b[ 2]
                 + ((sp_uint64)a[ 7]) * b[ 1]
                 + ((sp_uint64)a[ 8]) * b[ 0];
    sp_uint64 t9   = ((sp_uint64)a[ 0]) * b[ 9]
                 + ((sp_uint64)a[ 1]) * b[ 8]
                 + ((sp_uint64)a[ 2]) * b[ 7]
                 + ((sp_uint64)a[ 3]) * b[ 6]
                 + ((sp_uint64)a[ 4]) * b[ 5]
                 + ((sp_uint64)a[ 5]) * b[ 4]
                 + ((sp_uint64)a[ 6]) * b[ 3]
                 + ((sp_uint64)a[ 7]) * b[ 2]
                 + ((sp_uint64)a[ 8]) * b[ 1]
                 + ((sp_uint64)a[ 9]) * b[ 0];
    sp_uint64 t10  = ((sp_uint64)a[ 0]) * b[10]
                 + ((sp_uint64)a[ 1]) * b[ 9]
                 + ((sp_uint64)a[ 2]) * b[ 8]
                 + ((sp_uint64)a[ 3]) * b[ 7]
                 + ((sp_uint64)a[ 4]) * b[ 6]
                 + ((sp_uint64)a[ 5]) * b[ 5]
                 + ((sp_uint64)a[ 6]) * b[ 4]
                 + ((sp_uint64)a[ 7]) * b[ 3]
                 + ((sp_uint64)a[ 8]) * b[ 2]
                 + ((sp_uint64)a[ 9]) * b[ 1]
                 + ((sp_uint64)a[10]) * b[ 0];
    sp_uint64 t11  = ((sp_uint64)a[ 0]) * b[11]
                 + ((sp_uint64)a[ 1]) * b[10]
                 + ((sp_uint64)a[ 2]) * b[ 9]
                 + ((sp_uint64)a[ 3]) * b[ 8]
                 + ((sp_uint64)a[ 4]) * b[ 7]
                 + ((sp_uint64)a[ 5]) * b[ 6]
                 + ((sp_uint64)a[ 6]) * b[ 5]
                 + ((sp_uint64)a[ 7]) * b[ 4]
                 + ((sp_uint64)a[ 8]) * b[ 3]
                 + ((sp_uint64)a[ 9]) * b[ 2]
                 + ((sp_uint64)a[10]) * b[ 1]
                 + ((sp_uint64)a[11]) * b[ 0];
    sp_uint64 t12  = ((sp_uint64)a[ 1]) * b[11]
                 + ((sp_uint64)a[ 2]) * b[10]
                 + ((sp_uint64)a[ 3]) * b[ 9]
                 + ((sp_uint64)a[ 4]) * b[ 8]
                 + ((sp_uint64)a[ 5]) * b[ 7]
                 + ((sp_uint64)a[ 6]) * b[ 6]
                 + ((sp_uint64)a[ 7]) * b[ 5]
                 + ((sp_uint64)a[ 8]) * b[ 4]
                 + ((sp_uint64)a[ 9]) * b[ 3]
                 + ((sp_uint64)a[10]) * b[ 2]
                 + ((sp_uint64)a[11]) * b[ 1];
    sp_uint64 t13  = ((sp_uint64)a[ 2]) * b[11]
                 + ((sp_uint64)a[ 3]) * b[10]
                 + ((sp_uint64)a[ 4]) * b[ 9]
                 + ((sp_uint64)a[ 5]) * b[ 8]
                 + ((sp_uint64)a[ 6]) * b[ 7]
                 + ((sp_uint64)a[ 7]) * b[ 6]
                 + ((sp_uint64)a[ 8]) * b[ 5]
                 + ((sp_uint64)a[ 9]) * b[ 4]
                 + ((sp_uint64)a[10]) * b[ 3]
                 + ((sp_uint64)a[11]) * b[ 2];
    sp_uint64 t14  = ((sp_uint64)a[ 3]) * b[11]
                 + ((sp_uint64)a[ 4]) * b[10]
                 + ((sp_uint64)a[ 5]) * b[ 9]
                 + ((sp_uint64)a[ 6]) * b[ 8]
                 + ((sp_uint64)a[ 7]) * b[ 7]
                 + ((sp_uint64)a[ 8]) * b[ 6]
                 + ((sp_uint64)a[ 9]) * b[ 5]
                 + ((sp_uint64)a[10]) * b[ 4]
                 + ((sp_uint64)a[11]) * b[ 3];
    sp_uint64 t15  = ((sp_uint64)a[ 4]) * b[11]
                 + ((sp_uint64)a[ 5]) * b[10]
                 + ((sp_uint64)a[ 6]) * b[ 9]
                 + ((sp_uint64)a[ 7]) * b[ 8]
                 + ((sp_uint64)a[ 8]) * b[ 7]
                 + ((sp_uint64)a[ 9]) * b[ 6]
                 + ((sp_uint64)a[10]) * b[ 5]
                 + ((sp_uint64)a[11]) * b[ 4];
    sp_uint64 t16  = ((sp_uint64)a[ 5]) * b[11]
                 + ((sp_uint64)a[ 6]) * b[10]
                 + ((sp_uint64)a[ 7]) * b[ 9]
                 + ((sp_uint64)a[ 8]) * b[ 8]
                 + ((sp_uint64)a[ 9]) * b[ 7]
                 + ((sp_uint64)a[10]) * b[ 6]
                 + ((sp_uint64)a[11]) * b[ 5];
    sp_uint64 t17  = ((sp_uint64)a[ 6]) * b[11]
                 + ((sp_uint64)a[ 7]) * b[10]
                 + ((sp_uint64)a[ 8]) * b[ 9]
                 + ((sp_uint64)a[ 9]) * b[ 8]
                 + ((sp_uint64)a[10]) * b[ 7]
                 + ((sp_uint64)a[11]) * b[ 6];
    sp_uint64 t18  = ((sp_uint64)a[ 7]) * b[11]
                 + ((sp_uint64)a[ 8]) * b[10]
                 + ((sp_uint64)a[ 9]) * b[ 9]
                 + ((sp_uint64)a[10]) * b[ 8]
                 + ((sp_uint64)a[11]) * b[ 7];
    sp_uint64 t19  = ((sp_uint64)a[ 8]) * b[11]
                 + ((sp_uint64)a[ 9]) * b[10]
                 + ((sp_uint64)a[10]) * b[ 9]
                 + ((sp_uint64)a[11]) * b[ 8];
    sp_uint64 t20  = ((sp_uint64)a[ 9]) * b[11]
                 + ((sp_uint64)a[10]) * b[10]
                 + ((sp_uint64)a[11]) * b[ 9];
    sp_uint64 t21  = ((sp_uint64)a[10]) * b[11]
                 + ((sp_uint64)a[11]) * b[10];
    sp_uint64 t22  = ((sp_uint64)a[11]) * b[11];

    t1   += t0  >> 29; r[ 0] = t0  & 0x1fffffff;
    t2   += t1  >> 29; r[ 1] = t1  & 0x1fffffff;
    t3   += t2  >> 29; r[ 2] = t2  & 0x1fffffff;
    t4   += t3  >> 29; r[ 3] = t3  & 0x1fffffff;
    t5   += t4  >> 29; r[ 4] = t4  & 0x1fffffff;
    t6   += t5  >> 29; r[ 5] = t5  & 0x1fffffff;
    t7   += t6  >> 29; r[ 6] = t6  & 0x1fffffff;
    t8   += t7  >> 29; r[ 7] = t7  & 0x1fffffff;
    t9   += t8  >> 29; r[ 8] = t8  & 0x1fffffff;
    t10  += t9  >> 29; r[ 9] = t9  & 0x1fffffff;
    t11  += t10 >> 29; r[10] = t10 & 0x1fffffff;
    t12  += t11 >> 29; r[11] = t11 & 0x1fffffff;
    t13  += t12 >> 29; r[12] = t12 & 0x1fffffff;
    t14  += t13 >> 29; r[13] = t13 & 0x1fffffff;
    t15  += t14 >> 29; r[14] = t14 & 0x1fffffff;
    t16  += t15 >> 29; r[15] = t15 & 0x1fffffff;
    t17  += t16 >> 29; r[16] = t16 & 0x1fffffff;
    t18  += t17 >> 29; r[17] = t17 & 0x1fffffff;
    t19  += t18 >> 29; r[18] = t18 & 0x1fffffff;
    t20  += t19 >> 29; r[19] = t19 & 0x1fffffff;
    t21  += t20 >> 29; r[20] = t20 & 0x1fffffff;
    t22  += t21 >> 29; r[21] = t21 & 0x1fffffff;
    r[23] = (sp_digit)(t22 >> 29);
                       r[22] = t22 & 0x1fffffff;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_12(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    r[ 0] = a[ 0] + b[ 0];
    r[ 1] = a[ 1] + b[ 1];
    r[ 2] = a[ 2] + b[ 2];
    r[ 3] = a[ 3] + b[ 3];
    r[ 4] = a[ 4] + b[ 4];
    r[ 5] = a[ 5] + b[ 5];
    r[ 6] = a[ 6] + b[ 6];
    r[ 7] = a[ 7] + b[ 7];
    r[ 8] = a[ 8] + b[ 8];
    r[ 9] = a[ 9] + b[ 9];
    r[10] = a[10] + b[10];
    r[11] = a[11] + b[11];

    return 0;
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_sub_24(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 24; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }

    return 0;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_24(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 24; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }

    return 0;
}

/* Normalize the values in each word to 29 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_2048_norm_12(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 11; i++) {
        a[i+1] += a[i] >> 29;
        a[i] &= 0x1fffffff;
    }
#else
    a[1] += a[0] >> 29; a[0] &= 0x1fffffff;
    a[2] += a[1] >> 29; a[1] &= 0x1fffffff;
    a[3] += a[2] >> 29; a[2] &= 0x1fffffff;
    a[4] += a[3] >> 29; a[3] &= 0x1fffffff;
    a[5] += a[4] >> 29; a[4] &= 0x1fffffff;
    a[6] += a[5] >> 29; a[5] &= 0x1fffffff;
    a[7] += a[6] >> 29; a[6] &= 0x1fffffff;
    a[8] += a[7] >> 29; a[7] &= 0x1fffffff;
    a[9] += a[8] >> 29; a[8] &= 0x1fffffff;
    a[10] += a[9] >> 29; a[9] &= 0x1fffffff;
    a[11] += a[10] >> 29; a[10] &= 0x1fffffff;
#endif /* WOLFSSL_SP_SMALL */
}

/* Normalize the values in each word to 29 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_2048_norm_24(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 23; i++) {
        a[i+1] += a[i] >> 29;
        a[i] &= 0x1fffffff;
    }
#else
    int i;
    for (i = 0; i < 16; i += 8) {
        a[i+1] += a[i+0] >> 29; a[i+0] &= 0x1fffffff;
        a[i+2] += a[i+1] >> 29; a[i+1] &= 0x1fffffff;
        a[i+3] += a[i+2] >> 29; a[i+2] &= 0x1fffffff;
        a[i+4] += a[i+3] >> 29; a[i+3] &= 0x1fffffff;
        a[i+5] += a[i+4] >> 29; a[i+4] &= 0x1fffffff;
        a[i+6] += a[i+5] >> 29; a[i+5] &= 0x1fffffff;
        a[i+7] += a[i+6] >> 29; a[i+6] &= 0x1fffffff;
        a[i+8] += a[i+7] >> 29; a[i+7] &= 0x1fffffff;
    }
    a[17] += a[16] >> 29; a[16] &= 0x1fffffff;
    a[18] += a[17] >> 29; a[17] &= 0x1fffffff;
    a[19] += a[18] >> 29; a[18] &= 0x1fffffff;
    a[20] += a[19] >> 29; a[19] &= 0x1fffffff;
    a[21] += a[20] >> 29; a[20] &= 0x1fffffff;
    a[22] += a[21] >> 29; a[21] &= 0x1fffffff;
    a[23] += a[22] >> 29; a[22] &= 0x1fffffff;
#endif /* WOLFSSL_SP_SMALL */
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_36(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit p0[24];
    sp_digit p1[24];
    sp_digit p2[24];
    sp_digit p3[24];
    sp_digit p4[24];
    sp_digit p5[24];
    sp_digit t0[24];
    sp_digit t1[24];
    sp_digit t2[24];
    sp_digit a0[12];
    sp_digit a1[12];
    sp_digit a2[12];
    sp_digit b0[12];
    sp_digit b1[12];
    sp_digit b2[12];
    (void)sp_2048_add_12(a0, a, &a[12]);
    sp_2048_norm_12(a0);
    (void)sp_2048_add_12(b0, b, &b[12]);
    sp_2048_norm_12(b0);
    (void)sp_2048_add_12(a1, &a[12], &a[24]);
    sp_2048_norm_12(a1);
    (void)sp_2048_add_12(b1, &b[12], &b[24]);
    sp_2048_norm_12(b1);
    (void)sp_2048_add_12(a2, a0, &a[24]);
    sp_2048_norm_12(a1);
    (void)sp_2048_add_12(b2, b0, &b[24]);
    sp_2048_norm_12(b2);
    sp_2048_mul_12(p0, a, b);
    sp_2048_mul_12(p2, &a[12], &b[12]);
    sp_2048_mul_12(p4, &a[24], &b[24]);
    sp_2048_mul_12(p1, a0, b0);
    sp_2048_mul_12(p3, a1, b1);
    sp_2048_mul_12(p5, a2, b2);
    XMEMSET(r, 0, sizeof(*r)*2U*36U);
    (void)sp_2048_sub_24(t0, p3, p2);
    (void)sp_2048_sub_24(t1, p1, p2);
    (void)sp_2048_sub_24(t2, p5, t0);
    (void)sp_2048_sub_24(t2, t2, t1);
    sp_2048_norm_24(t2);
    (void)sp_2048_sub_24(t0, t0, p4);
    sp_2048_norm_24(t0);
    (void)sp_2048_sub_24(t1, t1, p0);
    sp_2048_norm_24(t1);
    (void)sp_2048_add_24(r, r, p0);
    (void)sp_2048_add_24(&r[12], &r[12], t1);
    (void)sp_2048_add_24(&r[24], &r[24], t2);
    (void)sp_2048_add_24(&r[36], &r[36], t0);
    (void)sp_2048_add_24(&r[48], &r[48], p4);
    sp_2048_norm_72(r);
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_36(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[32] = a[32] + b[32];
    r[33] = a[33] + b[33];
    r[34] = a[34] + b[34];
    r[35] = a[35] + b[35];

    return 0;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_72(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 72; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }

    return 0;
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_sub_72(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 72; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }

    return 0;
}

/* Normalize the values in each word to 29 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_2048_norm_144(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 143; i++) {
        a[i+1] += a[i] >> 29;
        a[i] &= 0x1fffffff;
    }
#else
    int i;
    for (i = 0; i < 136; i += 8) {
        a[i+1] += a[i+0] >> 29; a[i+0] &= 0x1fffffff;
        a[i+2] += a[i+1] >> 29; a[i+1] &= 0x1fffffff;
        a[i+3] += a[i+2] >> 29; a[i+2] &= 0x1fffffff;
        a[i+4] += a[i+3] >> 29; a[i+3] &= 0x1fffffff;
        a[i+5] += a[i+4] >> 29; a[i+4] &= 0x1fffffff;
        a[i+6] += a[i+5] >> 29; a[i+5] &= 0x1fffffff;
        a[i+7] += a[i+6] >> 29; a[i+6] &= 0x1fffffff;
        a[i+8] += a[i+7] >> 29; a[i+7] &= 0x1fffffff;
    }
    a[137] += a[136] >> 29; a[136] &= 0x1fffffff;
    a[138] += a[137] >> 29; a[137] &= 0x1fffffff;
    a[139] += a[138] >> 29; a[138] &= 0x1fffffff;
    a[140] += a[139] >> 29; a[139] &= 0x1fffffff;
    a[141] += a[140] >> 29; a[140] &= 0x1fffffff;
    a[142] += a[141] >> 29; a[141] &= 0x1fffffff;
    a[143] += a[142] >> 29; a[142] &= 0x1fffffff;
#endif /* WOLFSSL_SP_SMALL */
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_72(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[72];
    sp_digit* a1 = z1;
    sp_digit b1[36];
    sp_digit* z2 = r + 72;
    (void)sp_2048_add_36(a1, a, &a[36]);
    sp_2048_norm_36(a1);
    (void)sp_2048_add_36(b1, b, &b[36]);
    sp_2048_norm_36(b1);
    sp_2048_mul_36(z2, &a[36], &b[36]);
    sp_2048_mul_36(z0, a, b);
    sp_2048_mul_36(z1, a1, b1);
    (void)sp_2048_sub_72(z1, z1, z2);
    (void)sp_2048_sub_72(z1, z1, z0);
    (void)sp_2048_add_72(r + 36, r + 36, z1);
    sp_2048_norm_144(r);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_12(sp_digit* r, const sp_digit* a)
{
    sp_uint64 t0   =  ((sp_uint64)a[ 0]) * a[ 0];
    sp_uint64 t1   = (((sp_uint64)a[ 0]) * a[ 1]) * 2;
    sp_uint64 t2   = (((sp_uint64)a[ 0]) * a[ 2]) * 2
                 +  ((sp_uint64)a[ 1]) * a[ 1];
    sp_uint64 t3   = (((sp_uint64)a[ 0]) * a[ 3]
                 +  ((sp_uint64)a[ 1]) * a[ 2]) * 2;
    sp_uint64 t4   = (((sp_uint64)a[ 0]) * a[ 4]
                 +  ((sp_uint64)a[ 1]) * a[ 3]) * 2
                 +  ((sp_uint64)a[ 2]) * a[ 2];
    sp_uint64 t5   = (((sp_uint64)a[ 0]) * a[ 5]
                 +  ((sp_uint64)a[ 1]) * a[ 4]
                 +  ((sp_uint64)a[ 2]) * a[ 3]) * 2;
    sp_uint64 t6   = (((sp_uint64)a[ 0]) * a[ 6]
                 +  ((sp_uint64)a[ 1]) * a[ 5]
                 +  ((sp_uint64)a[ 2]) * a[ 4]) * 2
                 +  ((sp_uint64)a[ 3]) * a[ 3];
    sp_uint64 t7   = (((sp_uint64)a[ 0]) * a[ 7]
                 +  ((sp_uint64)a[ 1]) * a[ 6]
                 +  ((sp_uint64)a[ 2]) * a[ 5]
                 +  ((sp_uint64)a[ 3]) * a[ 4]) * 2;
    sp_uint64 t8   = (((sp_uint64)a[ 0]) * a[ 8]
                 +  ((sp_uint64)a[ 1]) * a[ 7]
                 +  ((sp_uint64)a[ 2]) * a[ 6]
                 +  ((sp_uint64)a[ 3]) * a[ 5]) * 2
                 +  ((sp_uint64)a[ 4]) * a[ 4];
    sp_uint64 t9   = (((sp_uint64)a[ 0]) * a[ 9]
                 +  ((sp_uint64)a[ 1]) * a[ 8]
                 +  ((sp_uint64)a[ 2]) * a[ 7]
                 +  ((sp_uint64)a[ 3]) * a[ 6]
                 +  ((sp_uint64)a[ 4]) * a[ 5]) * 2;
    sp_uint64 t10  = (((sp_uint64)a[ 0]) * a[10]
                 +  ((sp_uint64)a[ 1]) * a[ 9]
                 +  ((sp_uint64)a[ 2]) * a[ 8]
                 +  ((sp_uint64)a[ 3]) * a[ 7]
                 +  ((sp_uint64)a[ 4]) * a[ 6]) * 2
                 +  ((sp_uint64)a[ 5]) * a[ 5];
    sp_uint64 t11  = (((sp_uint64)a[ 0]) * a[11]
                 +  ((sp_uint64)a[ 1]) * a[10]
                 +  ((sp_uint64)a[ 2]) * a[ 9]
                 +  ((sp_uint64)a[ 3]) * a[ 8]
                 +  ((sp_uint64)a[ 4]) * a[ 7]
                 +  ((sp_uint64)a[ 5]) * a[ 6]) * 2;
    sp_uint64 t12  = (((sp_uint64)a[ 1]) * a[11]
                 +  ((sp_uint64)a[ 2]) * a[10]
                 +  ((sp_uint64)a[ 3]) * a[ 9]
                 +  ((sp_uint64)a[ 4]) * a[ 8]
                 +  ((sp_uint64)a[ 5]) * a[ 7]) * 2
                 +  ((sp_uint64)a[ 6]) * a[ 6];
    sp_uint64 t13  = (((sp_uint64)a[ 2]) * a[11]
                 +  ((sp_uint64)a[ 3]) * a[10]
                 +  ((sp_uint64)a[ 4]) * a[ 9]
                 +  ((sp_uint64)a[ 5]) * a[ 8]
                 +  ((sp_uint64)a[ 6]) * a[ 7]) * 2;
    sp_uint64 t14  = (((sp_uint64)a[ 3]) * a[11]
                 +  ((sp_uint64)a[ 4]) * a[10]
                 +  ((sp_uint64)a[ 5]) * a[ 9]
                 +  ((sp_uint64)a[ 6]) * a[ 8]) * 2
                 +  ((sp_uint64)a[ 7]) * a[ 7];
    sp_uint64 t15  = (((sp_uint64)a[ 4]) * a[11]
                 +  ((sp_uint64)a[ 5]) * a[10]
                 +  ((sp_uint64)a[ 6]) * a[ 9]
                 +  ((sp_uint64)a[ 7]) * a[ 8]) * 2;
    sp_uint64 t16  = (((sp_uint64)a[ 5]) * a[11]
                 +  ((sp_uint64)a[ 6]) * a[10]
                 +  ((sp_uint64)a[ 7]) * a[ 9]) * 2
                 +  ((sp_uint64)a[ 8]) * a[ 8];
    sp_uint64 t17  = (((sp_uint64)a[ 6]) * a[11]
                 +  ((sp_uint64)a[ 7]) * a[10]
                 +  ((sp_uint64)a[ 8]) * a[ 9]) * 2;
    sp_uint64 t18  = (((sp_uint64)a[ 7]) * a[11]
                 +  ((sp_uint64)a[ 8]) * a[10]) * 2
                 +  ((sp_uint64)a[ 9]) * a[ 9];
    sp_uint64 t19  = (((sp_uint64)a[ 8]) * a[11]
                 +  ((sp_uint64)a[ 9]) * a[10]) * 2;
    sp_uint64 t20  = (((sp_uint64)a[ 9]) * a[11]) * 2
                 +  ((sp_uint64)a[10]) * a[10];
    sp_uint64 t21  = (((sp_uint64)a[10]) * a[11]) * 2;
    sp_uint64 t22  =  ((sp_uint64)a[11]) * a[11];

    t1   += t0  >> 29; r[ 0] = t0  & 0x1fffffff;
    t2   += t1  >> 29; r[ 1] = t1  & 0x1fffffff;
    t3   += t2  >> 29; r[ 2] = t2  & 0x1fffffff;
    t4   += t3  >> 29; r[ 3] = t3  & 0x1fffffff;
    t5   += t4  >> 29; r[ 4] = t4  & 0x1fffffff;
    t6   += t5  >> 29; r[ 5] = t5  & 0x1fffffff;
    t7   += t6  >> 29; r[ 6] = t6  & 0x1fffffff;
    t8   += t7  >> 29; r[ 7] = t7  & 0x1fffffff;
    t9   += t8  >> 29; r[ 8] = t8  & 0x1fffffff;
    t10  += t9  >> 29; r[ 9] = t9  & 0x1fffffff;
    t11  += t10 >> 29; r[10] = t10 & 0x1fffffff;
    t12  += t11 >> 29; r[11] = t11 & 0x1fffffff;
    t13  += t12 >> 29; r[12] = t12 & 0x1fffffff;
    t14  += t13 >> 29; r[13] = t13 & 0x1fffffff;
    t15  += t14 >> 29; r[14] = t14 & 0x1fffffff;
    t16  += t15 >> 29; r[15] = t15 & 0x1fffffff;
    t17  += t16 >> 29; r[16] = t16 & 0x1fffffff;
    t18  += t17 >> 29; r[17] = t17 & 0x1fffffff;
    t19  += t18 >> 29; r[18] = t18 & 0x1fffffff;
    t20  += t19 >> 29; r[19] = t19 & 0x1fffffff;
    t21  += t20 >> 29; r[20] = t20 & 0x1fffffff;
    t22  += t21 >> 29; r[21] = t21 & 0x1fffffff;
    r[23] = (sp_digit)(t22 >> 29);
                       r[22] = t22 & 0x1fffffff;
}

/* Square a into r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_36(sp_digit* r, const sp_digit* a)
{
    sp_digit p0[24];
    sp_digit p1[24];
    sp_digit p2[24];
    sp_digit p3[24];
    sp_digit p4[24];
    sp_digit p5[24];
    sp_digit t0[24];
    sp_digit t1[24];
    sp_digit t2[24];
    sp_digit a0[12];
    sp_digit a1[12];
    sp_digit a2[12];
    (void)sp_2048_add_12(a0, a, &a[12]);
    sp_2048_norm_12(a0);
    (void)sp_2048_add_12(a1, &a[12], &a[24]);
    sp_2048_norm_12(a1);
    (void)sp_2048_add_12(a2, a0, &a[24]);
    sp_2048_norm_12(a2);
    sp_2048_sqr_12(p0, a);
    sp_2048_sqr_12(p2, &a[12]);
    sp_2048_sqr_12(p4, &a[24]);
    sp_2048_sqr_12(p1, a0);
    sp_2048_sqr_12(p3, a1);
    sp_2048_sqr_12(p5, a2);
    XMEMSET(r, 0, sizeof(*r)*2U*36U);
    (void)sp_2048_sub_24(t0, p3, p2);
    (void)sp_2048_sub_24(t1, p1, p2);
    (void)sp_2048_sub_24(t2, p5, t0);
    (void)sp_2048_sub_24(t2, t2, t1);
    sp_2048_norm_24(t2);
    (void)sp_2048_sub_24(t0, t0, p4);
    sp_2048_norm_24(t0);
    (void)sp_2048_sub_24(t1, t1, p0);
    sp_2048_norm_24(t1);
    (void)sp_2048_add_24(r, r, p0);
    (void)sp_2048_add_24(&r[12], &r[12], t1);
    (void)sp_2048_add_24(&r[24], &r[24], t2);
    (void)sp_2048_add_24(&r[36], &r[36], t0);
    (void)sp_2048_add_24(&r[48], &r[48], p4);
    sp_2048_norm_72(r);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_72(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit z1[72];
    sp_digit* a1 = z1;
    sp_digit* z2 = r + 72;
    (void)sp_2048_add_36(a1, a, &a[36]);
    sp_2048_norm_36(a1);
    sp_2048_sqr_36(z2, &a[36]);
    sp_2048_sqr_36(z0, a);
    sp_2048_sqr_36(z1, a1);
    (void)sp_2048_sub_72(z1, z1, z2);
    (void)sp_2048_sub_72(z1, z1, z0);
    (void)sp_2048_add_72(r + 36, r + 36, z1);
    sp_2048_norm_144(r);
}

#endif /* !WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_72(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 72; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}
#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_sub_72(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 72; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_72(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i;
    int imax;
    int k;
    sp_uint64 c;
    sp_uint64 lo;

    c = ((sp_uint64)a[71]) * b[71];
    r[143] = (sp_digit)(c >> 29);
    c &= 0x1fffffff;
    for (k = 141; k >= 0; k--) {
        if (k >= 72) {
            i = k - 71;
            imax = 71;
        }
        else {
            i = 0;
            imax = k;
        }
        if (imax - i > 15) {
            int imaxlo;
            lo = 0;
            for (imaxlo = i; imaxlo <= imax; imaxlo += 15) {
                for (; i <= imax && i < imaxlo + 15; i++) {
                    lo += ((sp_uint64)a[i]) * b[k - i];
                }
                c += lo >> 29;
                lo &= 0x1fffffff;
            }
            r[k + 2] += (sp_digit)(c >> 29);
            r[k + 1]  = (sp_digit)(c & 0x1fffffff);
            c = lo & 0x1fffffff;
        }
        else {
            lo = 0;
            for (; i <= imax; i++) {
                lo += ((sp_uint64)a[i]) * b[k - i];
            }
            c += lo >> 29;
            r[k + 2] += (sp_digit)(c >> 29);
            r[k + 1]  = (sp_digit)(c & 0x1fffffff);
            c = lo & 0x1fffffff;
        }
    }
    r[0] = (sp_digit)c;
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_72(sp_digit* r, const sp_digit* a)
{
    int i;
    int imax;
    int k;
    sp_uint64 c;
    sp_uint64 t;

    c = ((sp_uint64)a[71]) * a[71];
    r[143] = (sp_digit)(c >> 29);
    c = (c & 0x1fffffff) << 29;
    for (k = 141; k >= 0; k--) {
        i = (k + 1) / 2;
        if ((k & 1) == 0) {
           c += ((sp_uint64)a[i]) * a[i];
           i++;
        }
        if (k < 71) {
            imax = k;
        }
        else {
            imax = 71;
        }
        if (imax - i >= 14) {
            int imaxlo;
            sp_uint64 hi;

            hi = c >> 29;
            c &= 0x1fffffff;
            for (imaxlo = i; imaxlo <= imax; imaxlo += 14) {
                t = 0;
                for (; i <= imax && i < imaxlo + 14; i++) {
                    t += ((sp_uint64)a[i]) * a[k - i];
                }
                c += t * 2;

                hi += c >> 29;
                c &= 0x1fffffff;
            }
            r[k + 2] += (sp_digit)(hi >> 29);
            r[k + 1]  = (sp_digit)(hi & 0x1fffffff);
            c <<= 29;
        }
        else
        {
            t = 0;
            for (; i <= imax; i++) {
                t += ((sp_uint64)a[i]) * a[k - i];
            }
            c += t * 2;

            r[k + 2] += (sp_digit) (c >> 58);
            r[k + 1]  = (sp_digit)((c >> 29) & 0x1fffffff);
            c = (c & 0x1fffffff) << 29;
        }
    }
    r[0] = (sp_digit)(c >> 29);
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
SP_NOINLINE static int sp_2048_add_36(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 36; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}
#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_sub_36(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 36; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

#else
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_sub_36(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }
    r[32] = a[32] - b[32];
    r[33] = a[33] - b[33];
    r[34] = a[34] - b[34];
    r[35] = a[35] - b[35];

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_36(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i;
    int imax;
    int k;
    sp_uint64 c;
    sp_uint64 lo;

    c = ((sp_uint64)a[35]) * b[35];
    r[71] = (sp_digit)(c >> 29);
    c &= 0x1fffffff;
    for (k = 69; k >= 0; k--) {
        if (k >= 36) {
            i = k - 35;
            imax = 35;
        }
        else {
            i = 0;
            imax = k;
        }
        if (imax - i > 15) {
            int imaxlo;
            lo = 0;
            for (imaxlo = i; imaxlo <= imax; imaxlo += 15) {
                for (; i <= imax && i < imaxlo + 15; i++) {
                    lo += ((sp_uint64)a[i]) * b[k - i];
                }
                c += lo >> 29;
                lo &= 0x1fffffff;
            }
            r[k + 2] += (sp_digit)(c >> 29);
            r[k + 1]  = (sp_digit)(c & 0x1fffffff);
            c = lo & 0x1fffffff;
        }
        else {
            lo = 0;
            for (; i <= imax; i++) {
                lo += ((sp_uint64)a[i]) * b[k - i];
            }
            c += lo >> 29;
            r[k + 2] += (sp_digit)(c >> 29);
            r[k + 1]  = (sp_digit)(c & 0x1fffffff);
            c = lo & 0x1fffffff;
        }
    }
    r[0] = (sp_digit)c;
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_36(sp_digit* r, const sp_digit* a)
{
    int i;
    int imax;
    int k;
    sp_uint64 c;
    sp_uint64 t;

    c = ((sp_uint64)a[35]) * a[35];
    r[71] = (sp_digit)(c >> 29);
    c = (c & 0x1fffffff) << 29;
    for (k = 69; k >= 0; k--) {
        i = (k + 1) / 2;
        if ((k & 1) == 0) {
           c += ((sp_uint64)a[i]) * a[i];
           i++;
        }
        if (k < 35) {
            imax = k;
        }
        else {
            imax = 35;
        }
        if (imax - i >= 14) {
            int imaxlo;
            sp_uint64 hi;

            hi = c >> 29;
            c &= 0x1fffffff;
            for (imaxlo = i; imaxlo <= imax; imaxlo += 14) {
                t = 0;
                for (; i <= imax && i < imaxlo + 14; i++) {
                    t += ((sp_uint64)a[i]) * a[k - i];
                }
                c += t * 2;

                hi += c >> 29;
                c &= 0x1fffffff;
            }
            r[k + 2] += (sp_digit)(hi >> 29);
            r[k + 1]  = (sp_digit)(hi & 0x1fffffff);
            c <<= 29;
        }
        else
        {
            t = 0;
            for (; i <= imax; i++) {
                t += ((sp_uint64)a[i]) * a[k - i];
            }
            c += t * 2;

            r[k + 2] += (sp_digit) (c >> 58);
            r[k + 1]  = (sp_digit)((c >> 29) & 0x1fffffff);
            c = (c & 0x1fffffff) << 29;
        }
    }
    r[0] = (sp_digit)(c >> 29);
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
    x &= 0x1fffffff;

    /* rho = -1/m mod b */
    *rho = ((sp_digit)1 << 29) - x;
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_d_72(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 72; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
    }
    r[72] = (sp_digit)t;
#else
    sp_int64 tb = b;
    sp_int64 t = 0;
    sp_digit t2;
    sp_int64 p[4];
    int i;

    for (i = 0; i < 72; i += 4) {
        p[0] = tb * a[i + 0];
        p[1] = tb * a[i + 1];
        p[2] = tb * a[i + 2];
        p[3] = tb * a[i + 3];
        t += p[0];
        t2 = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
        r[i + 0] = (sp_digit)t2;
        t += p[1];
        t2 = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
        r[i + 1] = (sp_digit)t2;
        t += p[2];
        t2 = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
        r[i + 2] = (sp_digit)t2;
        t += p[3];
        t2 = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
        r[i + 3] = (sp_digit)t2;
    }
    r[72] = (sp_digit)(t & 0x1fffffff);
#endif /* WOLFSSL_SP_SMALL */
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 2048 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_2048_mont_norm_36(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<35; i++) {
        r[i] = 0x1fffffff;
    }
#else
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i + 0] = 0x1fffffff;
        r[i + 1] = 0x1fffffff;
        r[i + 2] = 0x1fffffff;
        r[i + 3] = 0x1fffffff;
        r[i + 4] = 0x1fffffff;
        r[i + 5] = 0x1fffffff;
        r[i + 6] = 0x1fffffff;
        r[i + 7] = 0x1fffffff;
    }
    r[32] = 0x1fffffff;
    r[33] = 0x1fffffff;
    r[34] = 0x1fffffff;
#endif /* WOLFSSL_SP_SMALL */
    r[35] = 0x1ffL;

    /* r = (2^n - 1) mod n */
    (void)sp_2048_sub_36(r, r, m);

    /* Add one so r = 2^n mod m */
    r[0] += 1;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_2048_cmp_36(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=35; i>=0; i--) {
        r |= (a[i] - b[i]) & ~(((sp_digit)0 - r) >> 28);
    }
#else
    int i;

    r |= (a[35] - b[35]) & (0 - (sp_digit)1);
    r |= (a[34] - b[34]) & ~(((sp_digit)0 - r) >> 28);
    r |= (a[33] - b[33]) & ~(((sp_digit)0 - r) >> 28);
    r |= (a[32] - b[32]) & ~(((sp_digit)0 - r) >> 28);
    for (i = 24; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & ~(((sp_digit)0 - r) >> 28);
        r |= (a[i + 6] - b[i + 6]) & ~(((sp_digit)0 - r) >> 28);
        r |= (a[i + 5] - b[i + 5]) & ~(((sp_digit)0 - r) >> 28);
        r |= (a[i + 4] - b[i + 4]) & ~(((sp_digit)0 - r) >> 28);
        r |= (a[i + 3] - b[i + 3]) & ~(((sp_digit)0 - r) >> 28);
        r |= (a[i + 2] - b[i + 2]) & ~(((sp_digit)0 - r) >> 28);
        r |= (a[i + 1] - b[i + 1]) & ~(((sp_digit)0 - r) >> 28);
        r |= (a[i + 0] - b[i + 0]) & ~(((sp_digit)0 - r) >> 28);
    }
#endif /* WOLFSSL_SP_SMALL */

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_2048_cond_sub_36(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 36; i++) {
        r[i] = a[i] - (b[i] & m);
    }
#else
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i + 0] = a[i + 0] - (b[i + 0] & m);
        r[i + 1] = a[i + 1] - (b[i + 1] & m);
        r[i + 2] = a[i + 2] - (b[i + 2] & m);
        r[i + 3] = a[i + 3] - (b[i + 3] & m);
        r[i + 4] = a[i + 4] - (b[i + 4] & m);
        r[i + 5] = a[i + 5] - (b[i + 5] & m);
        r[i + 6] = a[i + 6] - (b[i + 6] & m);
        r[i + 7] = a[i + 7] - (b[i + 7] & m);
    }
    r[32] = a[32] - (b[32] & m);
    r[33] = a[33] - (b[33] & m);
    r[34] = a[34] - (b[34] & m);
    r[35] = a[35] - (b[35] & m);
#endif /* WOLFSSL_SP_SMALL */
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_add_36(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifndef WOLFSSL_SP_LARGE_CODE
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 36; i++) {
        t += r[i];
        t += tb * a[i];
        r[i] = ((sp_digit)t) & 0x1fffffff;
        t >>= 29;
    }
    r[36] += (sp_digit)t;
#else
#ifdef WOLFSSL_SP_SMALL
    sp_int64 tb = b;
    sp_int64 t[4];
    int i;

    t[0] = 0;
    for (i = 0; i < 32; i += 4) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        r[i+0] = t[0] & 0x1fffffff;
        t[1] += t[0] >> 29;
        r[i+1] = t[1] & 0x1fffffff;
        t[2] += t[1] >> 29;
        r[i+2] = t[2] & 0x1fffffff;
        t[3] += t[2] >> 29;
        r[i+3] = t[3] & 0x1fffffff;
        t[0]  = t[3] >> 29;
    }
    t[0] += (tb * a[32]) + r[32];
    t[1]  = (tb * a[33]) + r[33];
    t[2]  = (tb * a[34]) + r[34];
    t[3]  = (tb * a[35]) + r[35];
    r[32] = t[0] & 0x1fffffff;
    t[1] += t[0] >> 29;
    r[33] = t[1] & 0x1fffffff;
    t[2] += t[1] >> 29;
    r[34] = t[2] & 0x1fffffff;
    t[3] += t[2] >> 29;
    r[35] = t[3] & 0x1fffffff;
    r[36] +=  (sp_digit)(t[3] >> 29);
#else
    sp_int64 tb = b;
    sp_int64 t[8];
    int i;

    t[0] = 0;
    for (i = 0; i < 32; i += 8) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        t[4]  = (tb * a[i+4]) + r[i+4];
        t[5]  = (tb * a[i+5]) + r[i+5];
        t[6]  = (tb * a[i+6]) + r[i+6];
        t[7]  = (tb * a[i+7]) + r[i+7];
        r[i+0] = t[0] & 0x1fffffff;
        t[1] += t[0] >> 29;
        r[i+1] = t[1] & 0x1fffffff;
        t[2] += t[1] >> 29;
        r[i+2] = t[2] & 0x1fffffff;
        t[3] += t[2] >> 29;
        r[i+3] = t[3] & 0x1fffffff;
        t[4] += t[3] >> 29;
        r[i+4] = t[4] & 0x1fffffff;
        t[5] += t[4] >> 29;
        r[i+5] = t[5] & 0x1fffffff;
        t[6] += t[5] >> 29;
        r[i+6] = t[6] & 0x1fffffff;
        t[7] += t[6] >> 29;
        r[i+7] = t[7] & 0x1fffffff;
        t[0]  = t[7] >> 29;
    }
    t[0] += (tb * a[32]) + r[32];
    t[1]  = (tb * a[33]) + r[33];
    t[2]  = (tb * a[34]) + r[34];
    t[3]  = (tb * a[35]) + r[35];
    r[32] = t[0] & 0x1fffffff;
    t[1] += t[0] >> 29;
    r[33] = t[1] & 0x1fffffff;
    t[2] += t[1] >> 29;
    r[34] = t[2] & 0x1fffffff;
    t[3] += t[2] >> 29;
    r[35] = t[3] & 0x1fffffff;
    r[36] +=  (sp_digit)(t[3] >> 29);
#endif /* WOLFSSL_SP_SMALL */
#endif /* !WOLFSSL_SP_LARGE_CODE */
}

/* Shift the result in the high 1024 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_2048_mont_shift_36(sp_digit* r, const sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    sp_int64 n = a[35] >> 9;
    n += ((sp_int64)a[36]) << 20;

    for (i = 0; i < 35; i++) {
        r[i] = n & 0x1fffffff;
        n >>= 29;
        n += ((sp_int64)a[37 + i]) << 20;
    }
    r[35] = (sp_digit)n;
#else
    int i;
    sp_int64 n = a[35] >> 9;
    n += ((sp_int64)a[36]) << 20;
    for (i = 0; i < 32; i += 8) {
        r[i + 0] = n & 0x1fffffff;
        n >>= 29; n += ((sp_int64)a[i + 37]) << 20;
        r[i + 1] = n & 0x1fffffff;
        n >>= 29; n += ((sp_int64)a[i + 38]) << 20;
        r[i + 2] = n & 0x1fffffff;
        n >>= 29; n += ((sp_int64)a[i + 39]) << 20;
        r[i + 3] = n & 0x1fffffff;
        n >>= 29; n += ((sp_int64)a[i + 40]) << 20;
        r[i + 4] = n & 0x1fffffff;
        n >>= 29; n += ((sp_int64)a[i + 41]) << 20;
        r[i + 5] = n & 0x1fffffff;
        n >>= 29; n += ((sp_int64)a[i + 42]) << 20;
        r[i + 6] = n & 0x1fffffff;
        n >>= 29; n += ((sp_int64)a[i + 43]) << 20;
        r[i + 7] = n & 0x1fffffff;
        n >>= 29; n += ((sp_int64)a[i + 44]) << 20;
    }
    r[32] = n & 0x1fffffff; n >>= 29; n += ((sp_int64)a[69]) << 20;
    r[33] = n & 0x1fffffff; n >>= 29; n += ((sp_int64)a[70]) << 20;
    r[34] = n & 0x1fffffff; n >>= 29; n += ((sp_int64)a[71]) << 20;
    r[35] = (sp_digit)n;
#endif /* WOLFSSL_SP_SMALL */
    XMEMSET(&r[36], 0, sizeof(*r) * 36U);
}

/* Reduce the number back to 2048 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_2048_mont_reduce_36(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_2048_norm_36(a + 36);

    for (i=0; i<35; i++) {
        mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x1fffffff;
        sp_2048_mul_add_36(a+i, m, mu);
        a[i+1] += a[i] >> 29;
    }
    mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x1ffL;
    sp_2048_mul_add_36(a+i, m, mu);
    a[i+1] += a[i] >> 29;
    a[i] &= 0x1fffffff;
    sp_2048_mont_shift_36(a, a);
    over = a[35] - m[35];
    sp_2048_cond_sub_36(a, a, m, ~((over - 1) >> 31));
    sp_2048_norm_36(a);
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
SP_NOINLINE static void sp_2048_mont_mul_36(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_2048_mul_36(r, a, b);
    sp_2048_mont_reduce_36(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_2048_mont_sqr_36(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_2048_sqr_36(r, a);
    sp_2048_mont_reduce_36(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_d_36(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 36; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
    }
    r[36] = (sp_digit)t;
#else
    sp_int64 tb = b;
    sp_int64 t = 0;
    sp_digit t2;
    sp_int64 p[4];
    int i;

    for (i = 0; i < 36; i += 4) {
        p[0] = tb * a[i + 0];
        p[1] = tb * a[i + 1];
        p[2] = tb * a[i + 2];
        p[3] = tb * a[i + 3];
        t += p[0];
        t2 = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
        r[i + 0] = (sp_digit)t2;
        t += p[1];
        t2 = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
        r[i + 1] = (sp_digit)t2;
        t += p[2];
        t2 = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
        r[i + 2] = (sp_digit)t2;
        t += p[3];
        t2 = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
        r[i + 3] = (sp_digit)t2;
    }
    r[36] = (sp_digit)(t & 0x1fffffff);
#endif /* WOLFSSL_SP_SMALL */
}

#ifdef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_2048_cond_add_36(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 36; i++) {
        r[i] = a[i] + (b[i] & m);
    }
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
static void sp_2048_cond_add_36(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i + 0] = a[i + 0] + (b[i + 0] & m);
        r[i + 1] = a[i + 1] + (b[i + 1] & m);
        r[i + 2] = a[i + 2] + (b[i + 2] & m);
        r[i + 3] = a[i + 3] + (b[i + 3] & m);
        r[i + 4] = a[i + 4] + (b[i + 4] & m);
        r[i + 5] = a[i + 5] + (b[i + 5] & m);
        r[i + 6] = a[i + 6] + (b[i + 6] & m);
        r[i + 7] = a[i + 7] + (b[i + 7] & m);
    }
    r[32] = a[32] + (b[32] & m);
    r[33] = a[33] + (b[33] & m);
    r[34] = a[34] + (b[34] & m);
    r[35] = a[35] + (b[35] & m);
}
#endif /* !WOLFSSL_SP_SMALL */

SP_NOINLINE static void sp_2048_rshift_36(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

#ifdef WOLFSSL_SP_SMALL
    for (i=0; i<35; i++) {
        r[i] = ((a[i] >> n) | (a[i + 1] << (29 - n))) & 0x1fffffff;
    }
#else
    for (i=0; i<32; i += 8) {
        r[i+0] = (a[i+0] >> n) | ((a[i+1] << (29 - n)) & 0x1fffffff);
        r[i+1] = (a[i+1] >> n) | ((a[i+2] << (29 - n)) & 0x1fffffff);
        r[i+2] = (a[i+2] >> n) | ((a[i+3] << (29 - n)) & 0x1fffffff);
        r[i+3] = (a[i+3] >> n) | ((a[i+4] << (29 - n)) & 0x1fffffff);
        r[i+4] = (a[i+4] >> n) | ((a[i+5] << (29 - n)) & 0x1fffffff);
        r[i+5] = (a[i+5] >> n) | ((a[i+6] << (29 - n)) & 0x1fffffff);
        r[i+6] = (a[i+6] >> n) | ((a[i+7] << (29 - n)) & 0x1fffffff);
        r[i+7] = (a[i+7] >> n) | ((a[i+8] << (29 - n)) & 0x1fffffff);
    }
    r[32] = (a[32] >> n) | ((a[33] << (29 - n)) & 0x1fffffff);
    r[33] = (a[33] >> n) | ((a[34] << (29 - n)) & 0x1fffffff);
    r[34] = (a[34] >> n) | ((a[35] << (29 - n)) & 0x1fffffff);
#endif /* WOLFSSL_SP_SMALL */
    r[35] = a[35] >> n;
}

static WC_INLINE sp_digit sp_2048_div_word_36(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int64 d = ((sp_int64)d1 << 29) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_uint32 lo = (sp_uint32)d;
    sp_digit hi = (sp_digit)(d >> 32);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 29);
    sp_digit t0 = (sp_digit)(d & 0x1fffffff);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int64 m;

    r = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
    t1 -= dv & (0 - r);
    for (i = 27; i >= 1; i--) {
        t1 += t1 + (((sp_uint32)t0 >> 28) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int64)r * div);
    r += (sp_digit)(m >> 29);
    m = d - ((sp_int64)r * div);
    r += (m >> 58) - (sp_digit)(d >> 58);

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;
   return r;
#else
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 14) + 1;

    t = (sp_digit)(d >> 28);
    t = (t / dv) << 14;
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)(d >> 13);
    t = t / (dv << 1);
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int64)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_2048_word_div_word_36(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint32)(div - d) >> 31);
#endif
}
/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * Full implementation.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_2048_div_36(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_32
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 36 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 72 + 1;
        sd = t2 + 36 + 1;

        sp_2048_mul_d_36(sd, d, (sp_digit)1 << 20);
        sp_2048_mul_d_72(t1, a, (sp_digit)1 << 20);
        dv = sd[35];
        t1[36 + 36] += t1[36 + 36 - 1] >> 29;
        t1[36 + 36 - 1] &= 0x1fffffff;
        for (i=36; i>=0; i--) {
            r1 = sp_2048_div_word_36(t1[36 + i], t1[36 + i - 1], dv);

            sp_2048_mul_d_36(t2, sd, r1);
            (void)sp_2048_sub_36(&t1[i], &t1[i], t2);
            sp_2048_norm_36(&t1[i]);
            t1[36 + i] -= t2[36];
            t1[36 + i] += t1[36 + i - 1] >> 29;
            t1[36 + i - 1] &= 0x1fffffff;
            r1 = sp_2048_div_word_36(-t1[36 + i], -t1[36 + i - 1], dv);
            r1 -= t1[36 + i];
            sp_2048_mul_d_36(t2, sd, r1);
            (void)sp_2048_add_36(&t1[i], &t1[i], t2);
            t1[36 + i] += t1[36 + i - 1] >> 29;
            t1[36 + i - 1] &= 0x1fffffff;
        }
        t1[36 - 1] += t1[36 - 2] >> 29;
        t1[36 - 2] &= 0x1fffffff;
        r1 = sp_2048_word_div_word_36(t1[36 - 1], dv);

        sp_2048_mul_d_36(t2, sd, r1);
        sp_2048_sub_36(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 72U);
        for (i=0; i<35; i++) {
            r[i+1] += r[i] >> 29;
            r[i] &= 0x1fffffff;
        }
        sp_2048_cond_add_36(r, r, sd, r[35] >> 31);

        sp_2048_norm_36(r);
        sp_2048_rshift_36(r, r, 20);
    }


    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_2048_mod_36(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_2048_div_36(a, m, NULL, r);
}

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
static int sp_2048_mod_exp_36(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 72];
    sp_digit* t[3] = {0, 0, 0};
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<3; i++) {
            t[i] = td + (i * 36 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 36U * 2U);
        }

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_36(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_36(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 36U);
        }
    }
    if (err == MP_OKAY) {
        sp_2048_mul_36(t[1], t[1], norm);
        err = sp_2048_mod_36(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 29;
        c = bits % 29;
        n = e[i--] << (29 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 29;
            }

            y = (int)((n >> 28) & 1);
            n <<= 1;

            sp_2048_mont_mul_36(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 36 * 2);
            sp_2048_mont_sqr_36(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 36 * 2);
        }

        sp_2048_mont_reduce_36(t[0], m, mp);
        n = sp_2048_cmp_36(t[0], m);
        sp_2048_cond_sub_36(t[0], t[0], m, ~(n >> 31));
        XMEMCPY(r, t[0], sizeof(*r) * 36 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 72];
    sp_digit* t[3] = {0, 0, 0};
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<3; i++) {
            t[i] = td + (i * 36 * 2);
        }

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_36(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_36(t[1], a, m);
            if (err == MP_OKAY) {
                sp_2048_mul_36(t[1], t[1], norm);
                err = sp_2048_mod_36(t[1], t[1], m);
            }
        }
        else {
            sp_2048_mul_36(t[1], a, norm);
            err = sp_2048_mod_36(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 29;
        c = bits % 29;
        n = e[i--] << (29 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 29;
            }

            y = (int)((n >> 28) & 1);
            n <<= 1;

            sp_2048_mont_mul_36(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 36 * 2);
            sp_2048_mont_sqr_36(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 36 * 2);
        }

        sp_2048_mont_reduce_36(t[0], m, mp);
        n = sp_2048_cmp_36(t[0], m);
        sp_2048_cond_sub_36(t[0], t[0], m, ~(n >> 31));
        XMEMCPY(r, t[0], sizeof(*r) * 36 * 2);
    }


    return err;
#else
    sp_digit td[(32 * 72) + 72];
    sp_digit* t[32];
    sp_digit* rt = NULL;
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<32; i++)
            t[i] = td + i * 72;
        rt = td + 2304;

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_36(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_36(t[1], a, m);
            if (err == MP_OKAY) {
                sp_2048_mul_36(t[1], t[1], norm);
                err = sp_2048_mod_36(t[1], t[1], m);
            }
        }
        else {
            sp_2048_mul_36(t[1], a, norm);
            err = sp_2048_mod_36(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_2048_mont_sqr_36(t[ 2], t[ 1], m, mp);
        sp_2048_mont_mul_36(t[ 3], t[ 2], t[ 1], m, mp);
        sp_2048_mont_sqr_36(t[ 4], t[ 2], m, mp);
        sp_2048_mont_mul_36(t[ 5], t[ 3], t[ 2], m, mp);
        sp_2048_mont_sqr_36(t[ 6], t[ 3], m, mp);
        sp_2048_mont_mul_36(t[ 7], t[ 4], t[ 3], m, mp);
        sp_2048_mont_sqr_36(t[ 8], t[ 4], m, mp);
        sp_2048_mont_mul_36(t[ 9], t[ 5], t[ 4], m, mp);
        sp_2048_mont_sqr_36(t[10], t[ 5], m, mp);
        sp_2048_mont_mul_36(t[11], t[ 6], t[ 5], m, mp);
        sp_2048_mont_sqr_36(t[12], t[ 6], m, mp);
        sp_2048_mont_mul_36(t[13], t[ 7], t[ 6], m, mp);
        sp_2048_mont_sqr_36(t[14], t[ 7], m, mp);
        sp_2048_mont_mul_36(t[15], t[ 8], t[ 7], m, mp);
        sp_2048_mont_sqr_36(t[16], t[ 8], m, mp);
        sp_2048_mont_mul_36(t[17], t[ 9], t[ 8], m, mp);
        sp_2048_mont_sqr_36(t[18], t[ 9], m, mp);
        sp_2048_mont_mul_36(t[19], t[10], t[ 9], m, mp);
        sp_2048_mont_sqr_36(t[20], t[10], m, mp);
        sp_2048_mont_mul_36(t[21], t[11], t[10], m, mp);
        sp_2048_mont_sqr_36(t[22], t[11], m, mp);
        sp_2048_mont_mul_36(t[23], t[12], t[11], m, mp);
        sp_2048_mont_sqr_36(t[24], t[12], m, mp);
        sp_2048_mont_mul_36(t[25], t[13], t[12], m, mp);
        sp_2048_mont_sqr_36(t[26], t[13], m, mp);
        sp_2048_mont_mul_36(t[27], t[14], t[13], m, mp);
        sp_2048_mont_sqr_36(t[28], t[14], m, mp);
        sp_2048_mont_mul_36(t[29], t[15], t[14], m, mp);
        sp_2048_mont_sqr_36(t[30], t[15], m, mp);
        sp_2048_mont_mul_36(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 28) / 29) - 1;
        c = bits % 29;
        if (c == 0) {
            c = 29;
        }
        if (i < 36) {
            n = e[i--] << (32 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (3 - c);
            c += 29;
        }
        y = (int)((n >> 27) & 0x1f);
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 72);
        while ((i >= 0) || (c >= 5)) {
            if (c >= 5) {
                y = (byte)((n >> 27) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--] << 3;
                y = (byte)((n >> 27) & 0x1f);
                n <<= 5;
                c = 24;
            }
            else {
                y = (byte)((n >> 27) & 0x1f);
                n = e[i--] << 3;
                c = 5 - c;
                y |= (byte)((n >> (32 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 29 - c;
            }

            sp_2048_mont_sqr_36(rt, rt, m, mp);
            sp_2048_mont_sqr_36(rt, rt, m, mp);
            sp_2048_mont_sqr_36(rt, rt, m, mp);
            sp_2048_mont_sqr_36(rt, rt, m, mp);
            sp_2048_mont_sqr_36(rt, rt, m, mp);

            sp_2048_mont_mul_36(rt, rt, t[y], m, mp);
        }

        sp_2048_mont_reduce_36(rt, m, mp);
        n = sp_2048_cmp_36(rt, m);
        sp_2048_cond_sub_36(rt, rt, m, ~(n >> 31));
        XMEMCPY(r, rt, sizeof(sp_digit) * 72);
    }


    return err;
#endif
}

#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) | WOLFSSL_HAVE_SP_DH */

/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 2048 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_2048_mont_norm_72(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<70; i++) {
        r[i] = 0x1fffffff;
    }
#else
    int i;

    for (i = 0; i < 64; i += 8) {
        r[i + 0] = 0x1fffffff;
        r[i + 1] = 0x1fffffff;
        r[i + 2] = 0x1fffffff;
        r[i + 3] = 0x1fffffff;
        r[i + 4] = 0x1fffffff;
        r[i + 5] = 0x1fffffff;
        r[i + 6] = 0x1fffffff;
        r[i + 7] = 0x1fffffff;
    }
    r[64] = 0x1fffffff;
    r[65] = 0x1fffffff;
    r[66] = 0x1fffffff;
    r[67] = 0x1fffffff;
    r[68] = 0x1fffffff;
    r[69] = 0x1fffffff;
#endif /* WOLFSSL_SP_SMALL */
    r[70] = 0x3ffffL;
    r[71] = 0;

    /* r = (2^n - 1) mod n */
    (void)sp_2048_sub_72(r, r, m);

    /* Add one so r = 2^n mod m */
    r[0] += 1;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_2048_cmp_72(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=71; i>=0; i--) {
        r |= (a[i] - b[i]) & ~(((sp_digit)0 - r) >> 28);
    }
#else
    int i;

    for (i = 64; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & ~(((sp_digit)0 - r) >> 28);
        r |= (a[i + 6] - b[i + 6]) & ~(((sp_digit)0 - r) >> 28);
        r |= (a[i + 5] - b[i + 5]) & ~(((sp_digit)0 - r) >> 28);
        r |= (a[i + 4] - b[i + 4]) & ~(((sp_digit)0 - r) >> 28);
        r |= (a[i + 3] - b[i + 3]) & ~(((sp_digit)0 - r) >> 28);
        r |= (a[i + 2] - b[i + 2]) & ~(((sp_digit)0 - r) >> 28);
        r |= (a[i + 1] - b[i + 1]) & ~(((sp_digit)0 - r) >> 28);
        r |= (a[i + 0] - b[i + 0]) & ~(((sp_digit)0 - r) >> 28);
    }
#endif /* WOLFSSL_SP_SMALL */

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_2048_cond_sub_72(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 72; i++) {
        r[i] = a[i] - (b[i] & m);
    }
#else
    int i;

    for (i = 0; i < 72; i += 8) {
        r[i + 0] = a[i + 0] - (b[i + 0] & m);
        r[i + 1] = a[i + 1] - (b[i + 1] & m);
        r[i + 2] = a[i + 2] - (b[i + 2] & m);
        r[i + 3] = a[i + 3] - (b[i + 3] & m);
        r[i + 4] = a[i + 4] - (b[i + 4] & m);
        r[i + 5] = a[i + 5] - (b[i + 5] & m);
        r[i + 6] = a[i + 6] - (b[i + 6] & m);
        r[i + 7] = a[i + 7] - (b[i + 7] & m);
    }
#endif /* WOLFSSL_SP_SMALL */
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_add_72(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifndef WOLFSSL_SP_LARGE_CODE
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 72; i++) {
        t += r[i];
        t += tb * a[i];
        r[i] = ((sp_digit)t) & 0x1fffffff;
        t >>= 29;
    }
    r[72] += (sp_digit)t;
#else
#ifdef WOLFSSL_SP_SMALL
    sp_int64 tb = b;
    sp_int64 t[4];
    int i;

    t[0] = 0;
    for (i = 0; i < 68; i += 4) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        r[i+0] = t[0] & 0x1fffffff;
        t[1] += t[0] >> 29;
        r[i+1] = t[1] & 0x1fffffff;
        t[2] += t[1] >> 29;
        r[i+2] = t[2] & 0x1fffffff;
        t[3] += t[2] >> 29;
        r[i+3] = t[3] & 0x1fffffff;
        t[0]  = t[3] >> 29;
    }
    t[0] += (tb * a[68]) + r[68];
    t[1]  = (tb * a[69]) + r[69];
    t[2]  = (tb * a[70]) + r[70];
    t[3]  = (tb * a[71]) + r[71];
    r[68] = t[0] & 0x1fffffff;
    t[1] += t[0] >> 29;
    r[69] = t[1] & 0x1fffffff;
    t[2] += t[1] >> 29;
    r[70] = t[2] & 0x1fffffff;
    t[3] += t[2] >> 29;
    r[71] = t[3] & 0x1fffffff;
    r[72] +=  (sp_digit)(t[3] >> 29);
#else
    sp_int64 tb = b;
    sp_int64 t[8];
    int i;

    t[0] = 0;
    for (i = 0; i < 64; i += 8) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        t[4]  = (tb * a[i+4]) + r[i+4];
        t[5]  = (tb * a[i+5]) + r[i+5];
        t[6]  = (tb * a[i+6]) + r[i+6];
        t[7]  = (tb * a[i+7]) + r[i+7];
        r[i+0] = t[0] & 0x1fffffff;
        t[1] += t[0] >> 29;
        r[i+1] = t[1] & 0x1fffffff;
        t[2] += t[1] >> 29;
        r[i+2] = t[2] & 0x1fffffff;
        t[3] += t[2] >> 29;
        r[i+3] = t[3] & 0x1fffffff;
        t[4] += t[3] >> 29;
        r[i+4] = t[4] & 0x1fffffff;
        t[5] += t[4] >> 29;
        r[i+5] = t[5] & 0x1fffffff;
        t[6] += t[5] >> 29;
        r[i+6] = t[6] & 0x1fffffff;
        t[7] += t[6] >> 29;
        r[i+7] = t[7] & 0x1fffffff;
        t[0]  = t[7] >> 29;
    }
    t[0] += (tb * a[64]) + r[64];
    t[1]  = (tb * a[65]) + r[65];
    t[2]  = (tb * a[66]) + r[66];
    t[3]  = (tb * a[67]) + r[67];
    t[4]  = (tb * a[68]) + r[68];
    t[5]  = (tb * a[69]) + r[69];
    t[6]  = (tb * a[70]) + r[70];
    t[7]  = (tb * a[71]) + r[71];
    r[64] = t[0] & 0x1fffffff;
    t[1] += t[0] >> 29;
    r[65] = t[1] & 0x1fffffff;
    t[2] += t[1] >> 29;
    r[66] = t[2] & 0x1fffffff;
    t[3] += t[2] >> 29;
    r[67] = t[3] & 0x1fffffff;
    t[4] += t[3] >> 29;
    r[68] = t[4] & 0x1fffffff;
    t[5] += t[4] >> 29;
    r[69] = t[5] & 0x1fffffff;
    t[6] += t[5] >> 29;
    r[70] = t[6] & 0x1fffffff;
    t[7] += t[6] >> 29;
    r[71] = t[7] & 0x1fffffff;
    r[72] +=  (sp_digit)(t[7] >> 29);
#endif /* WOLFSSL_SP_SMALL */
#endif /* !WOLFSSL_SP_LARGE_CODE */
}

/* Shift the result in the high 2048 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_2048_mont_shift_72(sp_digit* r, const sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    sp_int64 n = a[70] >> 18;
    n += ((sp_int64)a[71]) << 11;

    for (i = 0; i < 70; i++) {
        r[i] = n & 0x1fffffff;
        n >>= 29;
        n += ((sp_int64)a[72 + i]) << 11;
    }
    r[70] = (sp_digit)n;
#else
    int i;
    sp_int64 n = a[70] >> 18;
    n += ((sp_int64)a[71]) << 11;
    for (i = 0; i < 64; i += 8) {
        r[i + 0] = n & 0x1fffffff;
        n >>= 29; n += ((sp_int64)a[i + 72]) << 11;
        r[i + 1] = n & 0x1fffffff;
        n >>= 29; n += ((sp_int64)a[i + 73]) << 11;
        r[i + 2] = n & 0x1fffffff;
        n >>= 29; n += ((sp_int64)a[i + 74]) << 11;
        r[i + 3] = n & 0x1fffffff;
        n >>= 29; n += ((sp_int64)a[i + 75]) << 11;
        r[i + 4] = n & 0x1fffffff;
        n >>= 29; n += ((sp_int64)a[i + 76]) << 11;
        r[i + 5] = n & 0x1fffffff;
        n >>= 29; n += ((sp_int64)a[i + 77]) << 11;
        r[i + 6] = n & 0x1fffffff;
        n >>= 29; n += ((sp_int64)a[i + 78]) << 11;
        r[i + 7] = n & 0x1fffffff;
        n >>= 29; n += ((sp_int64)a[i + 79]) << 11;
    }
    r[64] = n & 0x1fffffff; n >>= 29; n += ((sp_int64)a[136]) << 11;
    r[65] = n & 0x1fffffff; n >>= 29; n += ((sp_int64)a[137]) << 11;
    r[66] = n & 0x1fffffff; n >>= 29; n += ((sp_int64)a[138]) << 11;
    r[67] = n & 0x1fffffff; n >>= 29; n += ((sp_int64)a[139]) << 11;
    r[68] = n & 0x1fffffff; n >>= 29; n += ((sp_int64)a[140]) << 11;
    r[69] = n & 0x1fffffff; n >>= 29; n += ((sp_int64)a[141]) << 11;
    r[70] = (sp_digit)n;
#endif /* WOLFSSL_SP_SMALL */
    XMEMSET(&r[71], 0, sizeof(*r) * 71U);
}

/* Reduce the number back to 2048 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_2048_mont_reduce_72(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_2048_norm_72(a + 71);

#ifdef WOLFSSL_SP_DH
    if (mp != 1) {
        for (i=0; i<70; i++) {
            mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x1fffffff;
            sp_2048_mul_add_72(a+i, m, mu);
            a[i+1] += a[i] >> 29;
        }
        mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x3ffffL;
        sp_2048_mul_add_72(a+i, m, mu);
        a[i+1] += a[i] >> 29;
        a[i] &= 0x1fffffff;
    }
    else {
        for (i=0; i<70; i++) {
            mu = a[i] & 0x1fffffff;
            sp_2048_mul_add_72(a+i, m, mu);
            a[i+1] += a[i] >> 29;
        }
        mu = a[i] & 0x3ffffL;
        sp_2048_mul_add_72(a+i, m, mu);
        a[i+1] += a[i] >> 29;
        a[i] &= 0x1fffffff;
    }
#else
    for (i=0; i<70; i++) {
        mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x1fffffff;
        sp_2048_mul_add_72(a+i, m, mu);
        a[i+1] += a[i] >> 29;
    }
    mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x3ffffL;
    sp_2048_mul_add_72(a+i, m, mu);
    a[i+1] += a[i] >> 29;
    a[i] &= 0x1fffffff;
#endif
    sp_2048_mont_shift_72(a, a);
    over = a[70] - m[70];
    sp_2048_cond_sub_72(a, a, m, ~((over - 1) >> 31));
    sp_2048_norm_72(a);
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
SP_NOINLINE static void sp_2048_mont_mul_72(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_2048_mul_72(r, a, b);
    sp_2048_mont_reduce_72(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_2048_mont_sqr_72(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_2048_sqr_72(r, a);
    sp_2048_mont_reduce_72(r, m, mp);
}

/* Normalize the values in each word to 29 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_2048_norm_71(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 70; i++) {
        a[i+1] += a[i] >> 29;
        a[i] &= 0x1fffffff;
    }
#else
    int i;
    for (i = 0; i < 64; i += 8) {
        a[i+1] += a[i+0] >> 29; a[i+0] &= 0x1fffffff;
        a[i+2] += a[i+1] >> 29; a[i+1] &= 0x1fffffff;
        a[i+3] += a[i+2] >> 29; a[i+2] &= 0x1fffffff;
        a[i+4] += a[i+3] >> 29; a[i+3] &= 0x1fffffff;
        a[i+5] += a[i+4] >> 29; a[i+4] &= 0x1fffffff;
        a[i+6] += a[i+5] >> 29; a[i+5] &= 0x1fffffff;
        a[i+7] += a[i+6] >> 29; a[i+6] &= 0x1fffffff;
        a[i+8] += a[i+7] >> 29; a[i+7] &= 0x1fffffff;
    }
    a[65] += a[64] >> 29; a[64] &= 0x1fffffff;
    a[66] += a[65] >> 29; a[65] &= 0x1fffffff;
    a[67] += a[66] >> 29; a[66] &= 0x1fffffff;
    a[68] += a[67] >> 29; a[67] &= 0x1fffffff;
    a[69] += a[68] >> 29; a[68] &= 0x1fffffff;
    a[70] += a[69] >> 29; a[69] &= 0x1fffffff;
#endif /* WOLFSSL_SP_SMALL */
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_d_144(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 144; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
    }
    r[144] = (sp_digit)t;
#else
    sp_int64 tb = b;
    sp_int64 t = 0;
    sp_digit t2;
    sp_int64 p[4];
    int i;

    for (i = 0; i < 144; i += 4) {
        p[0] = tb * a[i + 0];
        p[1] = tb * a[i + 1];
        p[2] = tb * a[i + 2];
        p[3] = tb * a[i + 3];
        t += p[0];
        t2 = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
        r[i + 0] = (sp_digit)t2;
        t += p[1];
        t2 = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
        r[i + 1] = (sp_digit)t2;
        t += p[2];
        t2 = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
        r[i + 2] = (sp_digit)t2;
        t += p[3];
        t2 = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
        r[i + 3] = (sp_digit)t2;
    }
    r[144] = (sp_digit)(t & 0x1fffffff);
#endif /* WOLFSSL_SP_SMALL */
}

#ifdef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_2048_cond_add_72(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 72; i++) {
        r[i] = a[i] + (b[i] & m);
    }
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
static void sp_2048_cond_add_72(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 72; i += 8) {
        r[i + 0] = a[i + 0] + (b[i + 0] & m);
        r[i + 1] = a[i + 1] + (b[i + 1] & m);
        r[i + 2] = a[i + 2] + (b[i + 2] & m);
        r[i + 3] = a[i + 3] + (b[i + 3] & m);
        r[i + 4] = a[i + 4] + (b[i + 4] & m);
        r[i + 5] = a[i + 5] + (b[i + 5] & m);
        r[i + 6] = a[i + 6] + (b[i + 6] & m);
        r[i + 7] = a[i + 7] + (b[i + 7] & m);
    }
}
#endif /* !WOLFSSL_SP_SMALL */

SP_NOINLINE static void sp_2048_rshift_72(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

#ifdef WOLFSSL_SP_SMALL
    for (i=0; i<71; i++) {
        r[i] = ((a[i] >> n) | (a[i + 1] << (29 - n))) & 0x1fffffff;
    }
#else
    for (i=0; i<64; i += 8) {
        r[i+0] = (a[i+0] >> n) | ((a[i+1] << (29 - n)) & 0x1fffffff);
        r[i+1] = (a[i+1] >> n) | ((a[i+2] << (29 - n)) & 0x1fffffff);
        r[i+2] = (a[i+2] >> n) | ((a[i+3] << (29 - n)) & 0x1fffffff);
        r[i+3] = (a[i+3] >> n) | ((a[i+4] << (29 - n)) & 0x1fffffff);
        r[i+4] = (a[i+4] >> n) | ((a[i+5] << (29 - n)) & 0x1fffffff);
        r[i+5] = (a[i+5] >> n) | ((a[i+6] << (29 - n)) & 0x1fffffff);
        r[i+6] = (a[i+6] >> n) | ((a[i+7] << (29 - n)) & 0x1fffffff);
        r[i+7] = (a[i+7] >> n) | ((a[i+8] << (29 - n)) & 0x1fffffff);
    }
    r[64] = (a[64] >> n) | ((a[65] << (29 - n)) & 0x1fffffff);
    r[65] = (a[65] >> n) | ((a[66] << (29 - n)) & 0x1fffffff);
    r[66] = (a[66] >> n) | ((a[67] << (29 - n)) & 0x1fffffff);
    r[67] = (a[67] >> n) | ((a[68] << (29 - n)) & 0x1fffffff);
    r[68] = (a[68] >> n) | ((a[69] << (29 - n)) & 0x1fffffff);
    r[69] = (a[69] >> n) | ((a[70] << (29 - n)) & 0x1fffffff);
    r[70] = (a[70] >> n) | ((a[71] << (29 - n)) & 0x1fffffff);
#endif /* WOLFSSL_SP_SMALL */
    r[71] = a[71] >> n;
}

static WC_INLINE sp_digit sp_2048_div_word_72(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int64 d = ((sp_int64)d1 << 29) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_uint32 lo = (sp_uint32)d;
    sp_digit hi = (sp_digit)(d >> 32);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 29);
    sp_digit t0 = (sp_digit)(d & 0x1fffffff);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int64 m;

    r = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
    t1 -= dv & (0 - r);
    for (i = 27; i >= 1; i--) {
        t1 += t1 + (((sp_uint32)t0 >> 28) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int64)r * div);
    r += (sp_digit)(m >> 29);
    m = d - ((sp_int64)r * div);
    r += (m >> 58) - (sp_digit)(d >> 58);

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;
   return r;
#else
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 14) + 1;

    t = (sp_digit)(d >> 28);
    t = (t / dv) << 14;
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)(d >> 13);
    t = t / (dv << 1);
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int64)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_2048_word_div_word_72(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint32)(div - d) >> 31);
#endif
}
/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * Full implementation.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_2048_div_72(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_32
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 72 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 144 + 1;
        sd = t2 + 72 + 1;

        sp_2048_mul_d_72(sd, d, (sp_digit)1 << 11);
        sp_2048_mul_d_144(t1, a, (sp_digit)1 << 11);
        dv = sd[70];
        t1[71 + 71] += t1[71 + 71 - 1] >> 29;
        t1[71 + 71 - 1] &= 0x1fffffff;
        for (i=71; i>=0; i--) {
            r1 = sp_2048_div_word_72(t1[71 + i], t1[71 + i - 1], dv);

            sp_2048_mul_d_72(t2, sd, r1);
            (void)sp_2048_sub_72(&t1[i], &t1[i], t2);
            sp_2048_norm_71(&t1[i]);
            t1[71 + i] += t1[71 + i - 1] >> 29;
            t1[71 + i - 1] &= 0x1fffffff;
            r1 = sp_2048_div_word_72(-t1[71 + i], -t1[71 + i - 1], dv);
            r1 -= t1[71 + i];
            sp_2048_mul_d_72(t2, sd, r1);
            (void)sp_2048_add_72(&t1[i], &t1[i], t2);
            t1[71 + i] += t1[71 + i - 1] >> 29;
            t1[71 + i - 1] &= 0x1fffffff;
        }
        t1[71 - 1] += t1[71 - 2] >> 29;
        t1[71 - 2] &= 0x1fffffff;
        r1 = sp_2048_word_div_word_72(t1[71 - 1], dv);

        sp_2048_mul_d_72(t2, sd, r1);
        sp_2048_sub_72(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 144U);
        for (i=0; i<70; i++) {
            r[i+1] += r[i] >> 29;
            r[i] &= 0x1fffffff;
        }
        sp_2048_cond_add_72(r, r, sd, r[70] >> 31);

        sp_2048_norm_71(r);
        sp_2048_rshift_72(r, r, 11);
        r[71] = 0;
    }


    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_2048_mod_72(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_2048_div_72(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || \
                                                     defined(WOLFSSL_HAVE_SP_DH)
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
static int sp_2048_mod_exp_72(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 144];
    sp_digit* t[3] = {0, 0, 0};
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<3; i++) {
            t[i] = td + (i * 72 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 72U * 2U);
        }

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_72(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_72(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 72U);
        }
    }
    if (err == MP_OKAY) {
        sp_2048_mul_72(t[1], t[1], norm);
        err = sp_2048_mod_72(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 29;
        c = bits % 29;
        n = e[i--] << (29 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 29;
            }

            y = (int)((n >> 28) & 1);
            n <<= 1;

            sp_2048_mont_mul_72(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 72 * 2);
            sp_2048_mont_sqr_72(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 72 * 2);
        }

        sp_2048_mont_reduce_72(t[0], m, mp);
        n = sp_2048_cmp_72(t[0], m);
        sp_2048_cond_sub_72(t[0], t[0], m, ~(n >> 31));
        XMEMCPY(r, t[0], sizeof(*r) * 72 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 144];
    sp_digit* t[3] = {0, 0, 0};
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<3; i++) {
            t[i] = td + (i * 72 * 2);
        }

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_72(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_72(t[1], a, m);
            if (err == MP_OKAY) {
                sp_2048_mul_72(t[1], t[1], norm);
                err = sp_2048_mod_72(t[1], t[1], m);
            }
        }
        else {
            sp_2048_mul_72(t[1], a, norm);
            err = sp_2048_mod_72(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 29;
        c = bits % 29;
        n = e[i--] << (29 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 29;
            }

            y = (int)((n >> 28) & 1);
            n <<= 1;

            sp_2048_mont_mul_72(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 72 * 2);
            sp_2048_mont_sqr_72(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 72 * 2);
        }

        sp_2048_mont_reduce_72(t[0], m, mp);
        n = sp_2048_cmp_72(t[0], m);
        sp_2048_cond_sub_72(t[0], t[0], m, ~(n >> 31));
        XMEMCPY(r, t[0], sizeof(*r) * 72 * 2);
    }


    return err;
#else
    sp_digit td[(16 * 144) + 144];
    sp_digit* t[16];
    sp_digit* rt = NULL;
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<16; i++)
            t[i] = td + i * 144;
        rt = td + 2304;

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_72(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_72(t[1], a, m);
            if (err == MP_OKAY) {
                sp_2048_mul_72(t[1], t[1], norm);
                err = sp_2048_mod_72(t[1], t[1], m);
            }
        }
        else {
            sp_2048_mul_72(t[1], a, norm);
            err = sp_2048_mod_72(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_2048_mont_sqr_72(t[ 2], t[ 1], m, mp);
        sp_2048_mont_mul_72(t[ 3], t[ 2], t[ 1], m, mp);
        sp_2048_mont_sqr_72(t[ 4], t[ 2], m, mp);
        sp_2048_mont_mul_72(t[ 5], t[ 3], t[ 2], m, mp);
        sp_2048_mont_sqr_72(t[ 6], t[ 3], m, mp);
        sp_2048_mont_mul_72(t[ 7], t[ 4], t[ 3], m, mp);
        sp_2048_mont_sqr_72(t[ 8], t[ 4], m, mp);
        sp_2048_mont_mul_72(t[ 9], t[ 5], t[ 4], m, mp);
        sp_2048_mont_sqr_72(t[10], t[ 5], m, mp);
        sp_2048_mont_mul_72(t[11], t[ 6], t[ 5], m, mp);
        sp_2048_mont_sqr_72(t[12], t[ 6], m, mp);
        sp_2048_mont_mul_72(t[13], t[ 7], t[ 6], m, mp);
        sp_2048_mont_sqr_72(t[14], t[ 7], m, mp);
        sp_2048_mont_mul_72(t[15], t[ 8], t[ 7], m, mp);

        bits = ((bits + 3) / 4) * 4;
        i = ((bits + 28) / 29) - 1;
        c = bits % 29;
        if (c == 0) {
            c = 29;
        }
        if (i < 72) {
            n = e[i--] << (32 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 4) {
            n |= e[i--] << (3 - c);
            c += 29;
        }
        y = (int)((n >> 28) & 0xf);
        n <<= 4;
        c -= 4;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 144);
        while ((i >= 0) || (c >= 4)) {
            if (c >= 4) {
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c -= 4;
            }
            else if (c == 0) {
                n = e[i--] << 3;
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c = 25;
            }
            else {
                y = (byte)((n >> 28) & 0xf);
                n = e[i--] << 3;
                c = 4 - c;
                y |= (byte)((n >> (32 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 29 - c;
            }

            sp_2048_mont_sqr_72(rt, rt, m, mp);
            sp_2048_mont_sqr_72(rt, rt, m, mp);
            sp_2048_mont_sqr_72(rt, rt, m, mp);
            sp_2048_mont_sqr_72(rt, rt, m, mp);

            sp_2048_mont_mul_72(rt, rt, t[y], m, mp);
        }

        sp_2048_mont_reduce_72(rt, m, mp);
        n = sp_2048_cmp_72(rt, m);
        sp_2048_cond_sub_72(rt, rt, m, ~(n >> 31));
        XMEMCPY(r, rt, sizeof(sp_digit) * 144);
    }


    return err;
#endif
}
#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) || */
       /* WOLFSSL_HAVE_SP_DH */

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
#ifdef WOLFSSL_SP_SMALL
    sp_digit a[72 * 5];
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit* norm = NULL;
    sp_digit e[1] = {0};
    sp_digit mp = 0;
    int i;
    int err = MP_OKAY;

    if (*outLen < 256U) {
        err = MP_TO_E;
    }

    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 29) {
            err = MP_READ_E;
        }
        else if (inLen > 256U) {
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
        r = a + 72 * 2;
        m = r + 72 * 2;
        norm = r;

        sp_2048_from_bin(a, 72, in, inLen);
#if DIGIT_BIT >= 29
        e[0] = (sp_digit)em->dp[0];
#else
        e[0] = (sp_digit)em->dp[0];
        if (em->used > 1) {
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
        }
#endif
        if (e[0] == 0) {
            err = MP_EXPTMOD_E;
        }
    }

    if (err == MP_OKAY) {
        sp_2048_from_mp(m, 72, mm);

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_72(norm, m);
    }
    if (err == MP_OKAY) {
        sp_2048_mul_72(a, a, norm);
        err = sp_2048_mod_72(a, a, m);
    }
    if (err == MP_OKAY) {
        for (i=28; i>=0; i--) {
            if ((e[0] >> i) != 0) {
                break;
            }
        }

        XMEMCPY(r, a, sizeof(sp_digit) * 72 * 2);
        for (i--; i>=0; i--) {
            sp_2048_mont_sqr_72(r, r, m, mp);

            if (((e[0] >> i) & 1) == 1) {
                sp_2048_mont_mul_72(r, r, a, m, mp);
            }
        }
        sp_2048_mont_reduce_72(r, m, mp);
        mp = sp_2048_cmp_72(r, m);
        sp_2048_cond_sub_72(r, r, m, ~(mp >> 31));

        sp_2048_to_bin_72(r, out);
        *outLen = 256;
    }


    return err;
#else
    sp_digit d[72 * 5];
    sp_digit* a = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit e[1] = {0};
    int err = MP_OKAY;

    if (*outLen < 256U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 29) {
            err = MP_READ_E;
        }
        else if (inLen > 256U) {
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
        a = d;
        r = a + 72 * 2;
        m = r + 72 * 2;

        sp_2048_from_bin(a, 72, in, inLen);
#if DIGIT_BIT >= 29
        e[0] = (sp_digit)em->dp[0];
#else
        e[0] = (sp_digit)em->dp[0];
        if (em->used > 1) {
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
        }
#endif
        if (e[0] == 0) {
            err = MP_EXPTMOD_E;
        }
    }
    if (err == MP_OKAY) {
        sp_2048_from_mp(m, 72, mm);

        if (e[0] == 0x3) {
            sp_2048_sqr_72(r, a);
            err = sp_2048_mod_72(r, r, m);
            if (err == MP_OKAY) {
                sp_2048_mul_72(r, a, r);
                err = sp_2048_mod_72(r, r, m);
            }
        }
        else {
            sp_digit* norm = r;
            int i;
            sp_digit mp;

            sp_2048_mont_setup(m, &mp);
            sp_2048_mont_norm_72(norm, m);

            sp_2048_mul_72(a, a, norm);
            err = sp_2048_mod_72(a, a, m);

            if (err == MP_OKAY) {
                for (i=28; i>=0; i--) {
                    if ((e[0] >> i) != 0) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 144U);
                for (i--; i>=0; i--) {
                    sp_2048_mont_sqr_72(r, r, m, mp);

                    if (((e[0] >> i) & 1) == 1) {
                        sp_2048_mont_mul_72(r, r, a, m, mp);
                    }
                }
                sp_2048_mont_reduce_72(r, m, mp);
                mp = sp_2048_cmp_72(r, m);
                sp_2048_cond_sub_72(r, r, m, ~(mp >> 31));
            }
        }
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin_72(r, out);
        *outLen = 256;
    }


    return err;
#endif /* WOLFSSL_SP_SMALL */
}

#ifndef WOLFSSL_RSA_PUBLIC_ONLY
#if !defined(SP_RSA_PRIVATE_EXP_D) && !defined(RSA_LOW_MEM)
#endif /* !SP_RSA_PRIVATE_EXP_D & !RSA_LOW_MEM */
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
#if defined(WOLFSSL_SP_SMALL)
    sp_digit  d[72 * 4];
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
        a = d + 72;
        m = a + 144;
        r = a;

        sp_2048_from_bin(a, 72, in, inLen);
        sp_2048_from_mp(d, 72, dm);
        sp_2048_from_mp(m, 72, mm);
        err = sp_2048_mod_exp_72(r, a, d, 2048, m, 0);
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin_72(r, out);
        *outLen = 256;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 72);
    }

    return err;
#else
    sp_digit d[72 * 4];
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
        else if (inLen > 256U) {
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
        a = d + 72;
        m = a + 144;
        r = a;

        sp_2048_from_bin(a, 72, in, inLen);
        sp_2048_from_mp(d, 72, dm);
        sp_2048_from_mp(m, 72, mm);
        err = sp_2048_mod_exp_72(r, a, d, 2048, m, 0);
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin_72(r, out);
        *outLen = 256;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 72);
    }

    return err;
#endif /* WOLFSSL_SP_SMALL */
#else
#if defined(WOLFSSL_SP_SMALL)
    sp_digit a[36 * 8];
    sp_digit* p = NULL;
    sp_digit* dp = NULL;
    sp_digit* dq = NULL;
    sp_digit* qi = NULL;
    sp_digit* tmpa = NULL;
    sp_digit* tmpb = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 256U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (inLen > 256) {
            err = MP_READ_E;
        }
        else if (mp_count_bits(mm) != 2048) {
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
    }

    if (err == MP_OKAY) {
        p = a + 72;
        qi = dq = dp = p + 36;
        tmpa = qi + 36;
        tmpb = tmpa + 72;
        r = a;

        sp_2048_from_bin(a, 72, in, inLen);
        sp_2048_from_mp(p, 36, pm);
        sp_2048_from_mp(dp, 36, dpm);
        err = sp_2048_mod_exp_36(tmpa, a, dp, 1024, p, 1);
    }
    if (err == MP_OKAY) {
        sp_2048_from_mp(p, 36, qm);
        sp_2048_from_mp(dq, 36, dqm);
        err = sp_2048_mod_exp_36(tmpb, a, dq, 1024, p, 1);
    }
    if (err == MP_OKAY) {
        sp_2048_from_mp(p, 36, pm);
        (void)sp_2048_sub_36(tmpa, tmpa, tmpb);
        sp_2048_norm_36(tmpa);
        sp_2048_cond_add_36(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[35] >> 31));
        sp_2048_cond_add_36(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[35] >> 31));
        sp_2048_norm_36(tmpa);

        sp_2048_from_mp(qi, 36, qim);
        sp_2048_mul_36(tmpa, tmpa, qi);
        err = sp_2048_mod_36(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_2048_from_mp(p, 36, qm);
        sp_2048_mul_36(tmpa, p, tmpa);
        (void)sp_2048_add_72(r, tmpb, tmpa);
        sp_2048_norm_72(r);

        sp_2048_to_bin_72(r, out);
        *outLen = 256;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 36 * 8);
    }

    return err;
#else
    sp_digit a[36 * 13];
    sp_digit* p = NULL;
    sp_digit* q = NULL;
    sp_digit* dp = NULL;
    sp_digit* dq = NULL;
    sp_digit* qi = NULL;
    sp_digit* tmpa = NULL;
    sp_digit* tmpb = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 256U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (inLen > 256U) {
            err = MP_READ_E;
        }
        else if (mp_count_bits(mm) != 2048) {
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
    }


    if (err == MP_OKAY) {
        p = a + 72 * 2;
        q = p + 36;
        dp = q + 36;
        dq = dp + 36;
        qi = dq + 36;
        tmpa = qi + 36;
        tmpb = tmpa + 72;
        r = a;

        sp_2048_from_bin(a, 72, in, inLen);
        sp_2048_from_mp(p, 36, pm);
        sp_2048_from_mp(q, 36, qm);
        sp_2048_from_mp(dp, 36, dpm);
        sp_2048_from_mp(dq, 36, dqm);
        sp_2048_from_mp(qi, 36, qim);

        err = sp_2048_mod_exp_36(tmpa, a, dp, 1024, p, 1);
    }
    if (err == MP_OKAY) {
        err = sp_2048_mod_exp_36(tmpb, a, dq, 1024, q, 1);
    }

    if (err == MP_OKAY) {
        (void)sp_2048_sub_36(tmpa, tmpa, tmpb);
        sp_2048_norm_36(tmpa);
        sp_2048_cond_add_36(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[35] >> 31));
        sp_2048_cond_add_36(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[35] >> 31));
        sp_2048_norm_36(tmpa);
        sp_2048_mul_36(tmpa, tmpa, qi);
        err = sp_2048_mod_36(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_2048_mul_36(tmpa, tmpa, q);
        (void)sp_2048_add_72(r, tmpb, tmpa);
        sp_2048_norm_72(r);

        sp_2048_to_bin_72(r, out);
        *outLen = 256;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 36 * 13);
    }

    return err;
#endif /* WOLFSSL_SP_SMALL */
#endif /* SP_RSA_PRIVATE_EXP_D || RSA_LOW_MEM */
}

#endif /* !WOLFSSL_RSA_PUBLIC_ONLY */
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
#if DIGIT_BIT == 29
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 72);
        r->used = 72;
        mp_clamp(r);
#elif DIGIT_BIT < 29
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 72; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 29) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 29 - s;
        }
        r->used = (2048 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 72; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 29 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 29 - s;
            }
            else {
                s += 29;
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
#ifdef WOLFSSL_SP_SMALL
    int err = MP_OKAY;
    sp_digit b[72 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
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
        e = b + 72 * 2;
        m = e + 72;
        r = b;

        sp_2048_from_mp(b, 72, base);
        sp_2048_from_mp(e, 72, exp);
        sp_2048_from_mp(m, 72, mod);

        err = sp_2048_mod_exp_72(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_2048_to_mp(r, res);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 72U);
    }
    return err;
#else
    sp_digit b[72 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;
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
        e = b + 72 * 2;
        m = e + 72;
        r = b;

        sp_2048_from_mp(b, 72, base);
        sp_2048_from_mp(e, 72, exp);
        sp_2048_from_mp(m, 72, mod);

        err = sp_2048_mod_exp_72(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_2048_to_mp(r, res);
    }


    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 72U);
    }

    return err;
#endif
}

#ifdef WOLFSSL_HAVE_SP_DH

SP_NOINLINE static void sp_2048_lshift_72(sp_digit* r, const sp_digit* a,
        byte n)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    r[72] = a[71] >> (29 - n);
    for (i=71; i>0; i--) {
        r[i] = ((a[i] << n) | (a[i-1] >> (29 - n))) & 0x1fffffff;
    }
#else
    sp_int_digit s;
    sp_int_digit t;

    s = (sp_int_digit)a[71];
    r[72] = s >> (29U - n);
    s = (sp_int_digit)(a[71]); t = (sp_int_digit)(a[70]);
    r[71] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[70]); t = (sp_int_digit)(a[69]);
    r[70] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[69]); t = (sp_int_digit)(a[68]);
    r[69] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[68]); t = (sp_int_digit)(a[67]);
    r[68] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[67]); t = (sp_int_digit)(a[66]);
    r[67] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[66]); t = (sp_int_digit)(a[65]);
    r[66] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[65]); t = (sp_int_digit)(a[64]);
    r[65] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[64]); t = (sp_int_digit)(a[63]);
    r[64] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[63]); t = (sp_int_digit)(a[62]);
    r[63] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[62]); t = (sp_int_digit)(a[61]);
    r[62] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[61]); t = (sp_int_digit)(a[60]);
    r[61] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[60]); t = (sp_int_digit)(a[59]);
    r[60] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[59]); t = (sp_int_digit)(a[58]);
    r[59] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[58]); t = (sp_int_digit)(a[57]);
    r[58] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[57]); t = (sp_int_digit)(a[56]);
    r[57] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[56]); t = (sp_int_digit)(a[55]);
    r[56] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[55]); t = (sp_int_digit)(a[54]);
    r[55] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[54]); t = (sp_int_digit)(a[53]);
    r[54] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[53]); t = (sp_int_digit)(a[52]);
    r[53] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[52]); t = (sp_int_digit)(a[51]);
    r[52] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[51]); t = (sp_int_digit)(a[50]);
    r[51] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[50]); t = (sp_int_digit)(a[49]);
    r[50] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[49]); t = (sp_int_digit)(a[48]);
    r[49] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[48]); t = (sp_int_digit)(a[47]);
    r[48] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[47]); t = (sp_int_digit)(a[46]);
    r[47] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[46]); t = (sp_int_digit)(a[45]);
    r[46] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[45]); t = (sp_int_digit)(a[44]);
    r[45] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[44]); t = (sp_int_digit)(a[43]);
    r[44] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[43]); t = (sp_int_digit)(a[42]);
    r[43] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[42]); t = (sp_int_digit)(a[41]);
    r[42] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[41]); t = (sp_int_digit)(a[40]);
    r[41] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[40]); t = (sp_int_digit)(a[39]);
    r[40] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[39]); t = (sp_int_digit)(a[38]);
    r[39] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[38]); t = (sp_int_digit)(a[37]);
    r[38] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[37]); t = (sp_int_digit)(a[36]);
    r[37] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[36]); t = (sp_int_digit)(a[35]);
    r[36] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[35]); t = (sp_int_digit)(a[34]);
    r[35] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[34]); t = (sp_int_digit)(a[33]);
    r[34] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[33]); t = (sp_int_digit)(a[32]);
    r[33] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[32]); t = (sp_int_digit)(a[31]);
    r[32] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[31]); t = (sp_int_digit)(a[30]);
    r[31] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[30]); t = (sp_int_digit)(a[29]);
    r[30] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[29]); t = (sp_int_digit)(a[28]);
    r[29] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[28]); t = (sp_int_digit)(a[27]);
    r[28] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[27]); t = (sp_int_digit)(a[26]);
    r[27] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[26]); t = (sp_int_digit)(a[25]);
    r[26] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[25]); t = (sp_int_digit)(a[24]);
    r[25] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[24]); t = (sp_int_digit)(a[23]);
    r[24] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[23]); t = (sp_int_digit)(a[22]);
    r[23] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[22]); t = (sp_int_digit)(a[21]);
    r[22] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[21]); t = (sp_int_digit)(a[20]);
    r[21] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[20]); t = (sp_int_digit)(a[19]);
    r[20] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[19]); t = (sp_int_digit)(a[18]);
    r[19] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[18]); t = (sp_int_digit)(a[17]);
    r[18] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[17]); t = (sp_int_digit)(a[16]);
    r[17] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[16]); t = (sp_int_digit)(a[15]);
    r[16] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[15]); t = (sp_int_digit)(a[14]);
    r[15] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[14]); t = (sp_int_digit)(a[13]);
    r[14] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[13]); t = (sp_int_digit)(a[12]);
    r[13] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[12]); t = (sp_int_digit)(a[11]);
    r[12] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[11]); t = (sp_int_digit)(a[10]);
    r[11] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[10]); t = (sp_int_digit)(a[9]);
    r[10] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[9]); t = (sp_int_digit)(a[8]);
    r[9] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[8]); t = (sp_int_digit)(a[7]);
    r[8] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[7]); t = (sp_int_digit)(a[6]);
    r[7] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[6]); t = (sp_int_digit)(a[5]);
    r[6] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[5]); t = (sp_int_digit)(a[4]);
    r[5] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[4]); t = (sp_int_digit)(a[3]);
    r[4] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[3]); t = (sp_int_digit)(a[2]);
    r[3] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[2]); t = (sp_int_digit)(a[1]);
    r[2] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
    s = (sp_int_digit)(a[1]); t = (sp_int_digit)(a[0]);
    r[1] = ((s << n) | (t >> (29U - n))) & 0x1fffffff;
#endif /* WOLFSSL_SP_SMALL */
    r[0] = (a[0] << n) & 0x1fffffff;
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
static int sp_2048_mod_exp_2_72(sp_digit* r, const sp_digit* e, int bits, const sp_digit* m)
{
    sp_digit td[217];
    sp_digit* norm = NULL;
    sp_digit* tmp = NULL;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit o;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        tmp  = td + 144;
        XMEMSET(td, 0, sizeof(sp_digit) * 217);

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_72(norm, m);

        bits = ((bits + 3) / 4) * 4;
        i = ((bits + 28) / 29) - 1;
        c = bits % 29;
        if (c == 0) {
            c = 29;
        }
        if (i < 72) {
            n = e[i--] << (32 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 4) {
            n |= e[i--] << (3 - c);
            c += 29;
        }
        y = (int)((n >> 28) & 0xf);
        n <<= 4;
        c -= 4;
        sp_2048_lshift_72(r, norm, (byte)y);
        while ((i >= 0) || (c >= 4)) {
            if (c >= 4) {
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c -= 4;
            }
            else if (c == 0) {
                n = e[i--] << 3;
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c = 25;
            }
            else {
                y = (byte)((n >> 28) & 0xf);
                n = e[i--] << 3;
                c = 4 - c;
                y |= (byte)((n >> (32 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 29 - c;
            }

            sp_2048_mont_sqr_72(r, r, m, mp);
            sp_2048_mont_sqr_72(r, r, m, mp);
            sp_2048_mont_sqr_72(r, r, m, mp);
            sp_2048_mont_sqr_72(r, r, m, mp);

            sp_2048_lshift_72(r, r, (byte)y);
            sp_2048_mul_d_72(tmp, norm, (r[71] << 11) + (r[70] >> 18));
            r[71] = 0;
            r[70] &= 0x3ffffL;
            (void)sp_2048_add_72(r, r, tmp);
            sp_2048_norm_72(r);
            o = sp_2048_cmp_72(r, m);
            sp_2048_cond_sub_72(r, r, m, ~(o >> 31));
        }

        sp_2048_mont_reduce_72(r, m, mp);
        n = sp_2048_cmp_72(r, m);
        sp_2048_cond_sub_72(r, r, m, ~(n >> 31));
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
    sp_digit b[72 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    word32 i;
    int err = MP_OKAY;

    if (mp_count_bits(base) > 2048) {
        err = MP_READ_E;
    }
    else if (expLen > 256U) {
        err = MP_READ_E;
    }
    else if (mp_count_bits(mod) != 2048) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mod)) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        e = b + 72 * 2;
        m = e + 72;
        r = b;

        sp_2048_from_mp(b, 72, base);
        sp_2048_from_bin(e, 72, exp, expLen);
        sp_2048_from_mp(m, 72, mod);

        if (base->used == 1 && base->dp[0] == 2U &&
                (m[70] >> 2) == 0xffffL) {
            err = sp_2048_mod_exp_2_72(r, e, expLen * 8U, m);
        }
        else {
            err = sp_2048_mod_exp_72(r, b, e, expLen * 8U, m, 0);
        }
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin_72(r, out);
        *outLen = 256;
        for (i=0; i<256U && out[i] == 0U; i++) {
            /* Search for first non-zero. */
        }
        *outLen -= i;
        XMEMMOVE(out, out + i, *outLen);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 72U);
    }

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
#ifdef WOLFSSL_SP_SMALL
    int err = MP_OKAY;
    sp_digit b[36 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
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
        e = b + 36 * 2;
        m = e + 36;
        r = b;

        sp_2048_from_mp(b, 36, base);
        sp_2048_from_mp(e, 36, exp);
        sp_2048_from_mp(m, 36, mod);

        err = sp_2048_mod_exp_36(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 36, 0, sizeof(*r) * 36U);
        err = sp_2048_to_mp(r, res);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 72U);
    }
    return err;
#else
    sp_digit b[36 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;
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
        e = b + 36 * 2;
        m = e + 36;
        r = b;

        sp_2048_from_mp(b, 36, base);
        sp_2048_from_mp(e, 36, exp);
        sp_2048_from_mp(m, 36, mod);

        err = sp_2048_mod_exp_36(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 36, 0, sizeof(*r) * 36U);
        err = sp_2048_to_mp(r, res);
    }


    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 72U);
    }

    return err;
#endif
}

#endif /* WOLFSSL_HAVE_SP_DH | (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) */

#endif /* !WOLFSSL_SP_NO_2048 */

#ifndef WOLFSSL_SP_NO_3072
#ifdef WOLFSSL_SP_SMALL
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
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = n-1; i >= 0; i--) {
        r[j] |= (((sp_digit)a[i]) << s);
        if (s >= 21U) {
            r[j] &= 0x1fffffff;
            s = 29U - s;
            if (j + 1 >= size) {
                break;
            }
            r[++j] = (sp_digit)a[i] >> s;
            s = 8U - s;
        }
        else {
            s += 8U;
        }
    }

    for (j++; j < size; j++) {
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
#if DIGIT_BIT == 29
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 29
    int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0x1fffffff;
        s = 29U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 29U) <= (word32)DIGIT_BIT) {
            s += 29U;
            r[j] &= 0x1fffffff;
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
        if (s + DIGIT_BIT >= 29) {
            r[j] &= 0x1fffffff;
            if (j + 1 >= size) {
                break;
            }
            s = 29 - s;
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
static void sp_3072_to_bin_106(sp_digit* r, byte* a)
{
    int i;
    int j;
    int s = 0;
    int b;

    for (i=0; i<105; i++) {
        r[i+1] += r[i] >> 29;
        r[i] &= 0x1fffffff;
    }
    j = 3079 / 8 - 1;
    a[j] = 0;
    for (i=0; i<106 && j>=0; i++) {
        b = 0;
        /* lint allow cast of mismatch sp_digit and int */
        a[j--] |= (byte)(r[i] << s); /*lint !e9033*/
        b += 8 - s;
        if (j < 0) {
            break;
        }
        while (b < 29) {
            a[j--] = (byte)(r[i] >> b);
            b += 8;
            if (j < 0) {
                break;
            }
        }
        s = 8 - (b - 29);
        if (j >= 0) {
            a[j] = 0;
        }
        if (s != 0) {
            j++;
        }
    }
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* Normalize the values in each word to 29 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_3072_norm_53(sp_digit* a)
{
    int i;
    for (i = 0; i < 52; i++) {
        a[i+1] += a[i] >> 29;
        a[i] &= 0x1fffffff;
    }
}

#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || WOLFSSL_HAVE_SP_DH */
/* Normalize the values in each word to 29 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_3072_norm_106(sp_digit* a)
{
    int i;
    for (i = 0; i < 105; i++) {
        a[i+1] += a[i] >> 29;
        a[i] &= 0x1fffffff;
    }
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_106(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i;
    int imax;
    int k;
    sp_uint64 c;
    sp_uint64 lo;

    c = ((sp_uint64)a[105]) * b[105];
    r[211] = (sp_digit)(c >> 29);
    c &= 0x1fffffff;
    for (k = 209; k >= 0; k--) {
        if (k >= 106) {
            i = k - 105;
            imax = 105;
        }
        else {
            i = 0;
            imax = k;
        }
        if (imax - i > 15) {
            int imaxlo;
            lo = 0;
            for (imaxlo = i; imaxlo <= imax; imaxlo += 15) {
                for (; i <= imax && i < imaxlo + 15; i++) {
                    lo += ((sp_uint64)a[i]) * b[k - i];
                }
                c += lo >> 29;
                lo &= 0x1fffffff;
            }
            r[k + 2] += (sp_digit)(c >> 29);
            r[k + 1]  = (sp_digit)(c & 0x1fffffff);
            c = lo & 0x1fffffff;
        }
        else {
            lo = 0;
            for (; i <= imax; i++) {
                lo += ((sp_uint64)a[i]) * b[k - i];
            }
            c += lo >> 29;
            r[k + 2] += (sp_digit)(c >> 29);
            r[k + 1]  = (sp_digit)(c & 0x1fffffff);
            c = lo & 0x1fffffff;
        }
    }
    r[0] = (sp_digit)c;
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_106(sp_digit* r, const sp_digit* a)
{
    int i;
    int imax;
    int k;
    sp_uint64 c;
    sp_uint64 t;

    c = ((sp_uint64)a[105]) * a[105];
    r[211] = (sp_digit)(c >> 29);
    c = (c & 0x1fffffff) << 29;
    for (k = 209; k >= 0; k--) {
        i = (k + 1) / 2;
        if ((k & 1) == 0) {
           c += ((sp_uint64)a[i]) * a[i];
           i++;
        }
        if (k < 105) {
            imax = k;
        }
        else {
            imax = 105;
        }
        if (imax - i >= 14) {
            int imaxlo;
            sp_uint64 hi;

            hi = c >> 29;
            c &= 0x1fffffff;
            for (imaxlo = i; imaxlo <= imax; imaxlo += 14) {
                t = 0;
                for (; i <= imax && i < imaxlo + 14; i++) {
                    t += ((sp_uint64)a[i]) * a[k - i];
                }
                c += t * 2;

                hi += c >> 29;
                c &= 0x1fffffff;
            }
            r[k + 2] += (sp_digit)(hi >> 29);
            r[k + 1]  = (sp_digit)(hi & 0x1fffffff);
            c <<= 29;
        }
        else
        {
            t = 0;
            for (; i <= imax; i++) {
                t += ((sp_uint64)a[i]) * a[k - i];
            }
            c += t * 2;

            r[k + 2] += (sp_digit) (c >> 58);
            r[k + 1]  = (sp_digit)((c >> 29) & 0x1fffffff);
            c = (c & 0x1fffffff) << 29;
        }
    }
    r[0] = (sp_digit)(c >> 29);
}

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
    x &= 0x1fffffff;

    /* rho = -1/m mod b */
    *rho = ((sp_digit)1 << 29) - x;
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_d_106(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 106; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
    }
    r[106] = (sp_digit)t;
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_sub_53(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 53; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 3072 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_3072_mont_norm_53(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
    int i;

    for (i=0; i<52; i++) {
        r[i] = 0x1fffffff;
    }
    r[52] = 0xfffffffL;

    /* r = (2^n - 1) mod n */
    (void)sp_3072_sub_53(r, r, m);

    /* Add one so r = 2^n mod m */
    r[0] += 1;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_3072_cmp_53(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
    int i;

    for (i=52; i>=0; i--) {
        r |= (a[i] - b[i]) & ~(((sp_digit)0 - r) >> 28);
    }

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_3072_cond_sub_53(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 53; i++) {
        r[i] = a[i] - (b[i] & m);
    }
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_add_53(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifndef WOLFSSL_SP_LARGE_CODE
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 53; i++) {
        t += r[i];
        t += tb * a[i];
        r[i] = ((sp_digit)t) & 0x1fffffff;
        t >>= 29;
    }
    r[53] += (sp_digit)t;
#else
    sp_int64 tb = b;
    sp_int64 t[4];
    int i;

    t[0] = 0;
    for (i = 0; i < 52; i += 4) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        r[i+0] = t[0] & 0x1fffffff;
        t[1] += t[0] >> 29;
        r[i+1] = t[1] & 0x1fffffff;
        t[2] += t[1] >> 29;
        r[i+2] = t[2] & 0x1fffffff;
        t[3] += t[2] >> 29;
        r[i+3] = t[3] & 0x1fffffff;
        t[0]  = t[3] >> 29;
    }
    t[0] += (tb * a[52]) + r[52];
    r[52] = t[0] & 0x1fffffff;
    r[53] +=  (sp_digit)(t[0] >> 29);
#endif /* !WOLFSSL_SP_LARGE_CODE */
}

/* Shift the result in the high 1536 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_3072_mont_shift_53(sp_digit* r, const sp_digit* a)
{
    int i;
    sp_int64 n = a[52] >> 28;
    n += ((sp_int64)a[53]) << 1;

    for (i = 0; i < 52; i++) {
        r[i] = n & 0x1fffffff;
        n >>= 29;
        n += ((sp_int64)a[54 + i]) << 1;
    }
    r[52] = (sp_digit)n;
    XMEMSET(&r[53], 0, sizeof(*r) * 53U);
}

/* Reduce the number back to 3072 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_3072_mont_reduce_53(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_3072_norm_53(a + 53);

    for (i=0; i<52; i++) {
        mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x1fffffff;
        sp_3072_mul_add_53(a+i, m, mu);
        a[i+1] += a[i] >> 29;
    }
    mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0xfffffffL;
    sp_3072_mul_add_53(a+i, m, mu);
    a[i+1] += a[i] >> 29;
    a[i] &= 0x1fffffff;
    sp_3072_mont_shift_53(a, a);
    over = a[52] - m[52];
    sp_3072_cond_sub_53(a, a, m, ~((over - 1) >> 31));
    sp_3072_norm_53(a);
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_53(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i;
    int imax;
    int k;
    sp_uint64 c;
    sp_uint64 lo;

    c = ((sp_uint64)a[52]) * b[52];
    r[105] = (sp_digit)(c >> 29);
    c &= 0x1fffffff;
    for (k = 103; k >= 0; k--) {
        if (k >= 53) {
            i = k - 52;
            imax = 52;
        }
        else {
            i = 0;
            imax = k;
        }
        if (imax - i > 15) {
            int imaxlo;
            lo = 0;
            for (imaxlo = i; imaxlo <= imax; imaxlo += 15) {
                for (; i <= imax && i < imaxlo + 15; i++) {
                    lo += ((sp_uint64)a[i]) * b[k - i];
                }
                c += lo >> 29;
                lo &= 0x1fffffff;
            }
            r[k + 2] += (sp_digit)(c >> 29);
            r[k + 1]  = (sp_digit)(c & 0x1fffffff);
            c = lo & 0x1fffffff;
        }
        else {
            lo = 0;
            for (; i <= imax; i++) {
                lo += ((sp_uint64)a[i]) * b[k - i];
            }
            c += lo >> 29;
            r[k + 2] += (sp_digit)(c >> 29);
            r[k + 1]  = (sp_digit)(c & 0x1fffffff);
            c = lo & 0x1fffffff;
        }
    }
    r[0] = (sp_digit)c;
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
SP_NOINLINE static void sp_3072_mont_mul_53(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_3072_mul_53(r, a, b);
    sp_3072_mont_reduce_53(r, m, mp);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_53(sp_digit* r, const sp_digit* a)
{
    int i;
    int imax;
    int k;
    sp_uint64 c;
    sp_uint64 t;

    c = ((sp_uint64)a[52]) * a[52];
    r[105] = (sp_digit)(c >> 29);
    c = (c & 0x1fffffff) << 29;
    for (k = 103; k >= 0; k--) {
        i = (k + 1) / 2;
        if ((k & 1) == 0) {
           c += ((sp_uint64)a[i]) * a[i];
           i++;
        }
        if (k < 52) {
            imax = k;
        }
        else {
            imax = 52;
        }
        if (imax - i >= 14) {
            int imaxlo;
            sp_uint64 hi;

            hi = c >> 29;
            c &= 0x1fffffff;
            for (imaxlo = i; imaxlo <= imax; imaxlo += 14) {
                t = 0;
                for (; i <= imax && i < imaxlo + 14; i++) {
                    t += ((sp_uint64)a[i]) * a[k - i];
                }
                c += t * 2;

                hi += c >> 29;
                c &= 0x1fffffff;
            }
            r[k + 2] += (sp_digit)(hi >> 29);
            r[k + 1]  = (sp_digit)(hi & 0x1fffffff);
            c <<= 29;
        }
        else
        {
            t = 0;
            for (; i <= imax; i++) {
                t += ((sp_uint64)a[i]) * a[k - i];
            }
            c += t * 2;

            r[k + 2] += (sp_digit) (c >> 58);
            r[k + 1]  = (sp_digit)((c >> 29) & 0x1fffffff);
            c = (c & 0x1fffffff) << 29;
        }
    }
    r[0] = (sp_digit)(c >> 29);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_3072_mont_sqr_53(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_3072_sqr_53(r, a);
    sp_3072_mont_reduce_53(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_d_53(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 53; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
    }
    r[53] = (sp_digit)t;
}

#ifdef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_3072_cond_add_53(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 53; i++) {
        r[i] = a[i] + (b[i] & m);
    }
}
#endif /* WOLFSSL_SP_SMALL */

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_53(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 53; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}

SP_NOINLINE static void sp_3072_rshift_53(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    for (i=0; i<52; i++) {
        r[i] = ((a[i] >> n) | (a[i + 1] << (29 - n))) & 0x1fffffff;
    }
    r[52] = a[52] >> n;
}

static WC_INLINE sp_digit sp_3072_div_word_53(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int64 d = ((sp_int64)d1 << 29) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_uint32 lo = (sp_uint32)d;
    sp_digit hi = (sp_digit)(d >> 32);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 29);
    sp_digit t0 = (sp_digit)(d & 0x1fffffff);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int64 m;

    r = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
    t1 -= dv & (0 - r);
    for (i = 27; i >= 1; i--) {
        t1 += t1 + (((sp_uint32)t0 >> 28) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int64)r * div);
    r += (sp_digit)(m >> 29);
    m = d - ((sp_int64)r * div);
    r += (m >> 58) - (sp_digit)(d >> 58);

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;
   return r;
#else
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 14) + 1;

    t = (sp_digit)(d >> 28);
    t = (t / dv) << 14;
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)(d >> 13);
    t = t / (dv << 1);
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int64)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_3072_word_div_word_53(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint32)(div - d) >> 31);
#endif
}
/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * Full implementation.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_3072_div_53(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_32
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 53 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 106 + 1;
        sd = t2 + 53 + 1;

        sp_3072_mul_d_53(sd, d, (sp_digit)1 << 1);
        sp_3072_mul_d_106(t1, a, (sp_digit)1 << 1);
        dv = sd[52];
        t1[53 + 53] += t1[53 + 53 - 1] >> 29;
        t1[53 + 53 - 1] &= 0x1fffffff;
        for (i=53; i>=0; i--) {
            r1 = sp_3072_div_word_53(t1[53 + i], t1[53 + i - 1], dv);

            sp_3072_mul_d_53(t2, sd, r1);
            (void)sp_3072_sub_53(&t1[i], &t1[i], t2);
            sp_3072_norm_53(&t1[i]);
            t1[53 + i] -= t2[53];
            t1[53 + i] += t1[53 + i - 1] >> 29;
            t1[53 + i - 1] &= 0x1fffffff;
            r1 = sp_3072_div_word_53(-t1[53 + i], -t1[53 + i - 1], dv);
            r1 -= t1[53 + i];
            sp_3072_mul_d_53(t2, sd, r1);
            (void)sp_3072_add_53(&t1[i], &t1[i], t2);
            t1[53 + i] += t1[53 + i - 1] >> 29;
            t1[53 + i - 1] &= 0x1fffffff;
        }
        t1[53 - 1] += t1[53 - 2] >> 29;
        t1[53 - 2] &= 0x1fffffff;
        r1 = sp_3072_word_div_word_53(t1[53 - 1], dv);

        sp_3072_mul_d_53(t2, sd, r1);
        sp_3072_sub_53(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 106U);
        for (i=0; i<52; i++) {
            r[i+1] += r[i] >> 29;
            r[i] &= 0x1fffffff;
        }
        sp_3072_cond_add_53(r, r, sd, r[52] >> 31);

        sp_3072_norm_53(r);
        sp_3072_rshift_53(r, r, 1);
    }


    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_3072_mod_53(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_3072_div_53(a, m, NULL, r);
}

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
static int sp_3072_mod_exp_53(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 106];
    sp_digit* t[3] = {0, 0, 0};
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<3; i++) {
            t[i] = td + (i * 53 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 53U * 2U);
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_53(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_53(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 53U);
        }
    }
    if (err == MP_OKAY) {
        sp_3072_mul_53(t[1], t[1], norm);
        err = sp_3072_mod_53(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 29;
        c = bits % 29;
        n = e[i--] << (29 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 29;
            }

            y = (int)((n >> 28) & 1);
            n <<= 1;

            sp_3072_mont_mul_53(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 53 * 2);
            sp_3072_mont_sqr_53(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 53 * 2);
        }

        sp_3072_mont_reduce_53(t[0], m, mp);
        n = sp_3072_cmp_53(t[0], m);
        sp_3072_cond_sub_53(t[0], t[0], m, ~(n >> 31));
        XMEMCPY(r, t[0], sizeof(*r) * 53 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 106];
    sp_digit* t[3] = {0, 0, 0};
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<3; i++) {
            t[i] = td + (i * 53 * 2);
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_53(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_53(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_53(t[1], t[1], norm);
                err = sp_3072_mod_53(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_53(t[1], a, norm);
            err = sp_3072_mod_53(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 29;
        c = bits % 29;
        n = e[i--] << (29 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 29;
            }

            y = (int)((n >> 28) & 1);
            n <<= 1;

            sp_3072_mont_mul_53(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 53 * 2);
            sp_3072_mont_sqr_53(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 53 * 2);
        }

        sp_3072_mont_reduce_53(t[0], m, mp);
        n = sp_3072_cmp_53(t[0], m);
        sp_3072_cond_sub_53(t[0], t[0], m, ~(n >> 31));
        XMEMCPY(r, t[0], sizeof(*r) * 53 * 2);
    }


    return err;
#else
    sp_digit td[(32 * 106) + 106];
    sp_digit* t[32];
    sp_digit* rt = NULL;
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<32; i++)
            t[i] = td + i * 106;
        rt = td + 3392;

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_53(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_53(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_53(t[1], t[1], norm);
                err = sp_3072_mod_53(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_53(t[1], a, norm);
            err = sp_3072_mod_53(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_3072_mont_sqr_53(t[ 2], t[ 1], m, mp);
        sp_3072_mont_mul_53(t[ 3], t[ 2], t[ 1], m, mp);
        sp_3072_mont_sqr_53(t[ 4], t[ 2], m, mp);
        sp_3072_mont_mul_53(t[ 5], t[ 3], t[ 2], m, mp);
        sp_3072_mont_sqr_53(t[ 6], t[ 3], m, mp);
        sp_3072_mont_mul_53(t[ 7], t[ 4], t[ 3], m, mp);
        sp_3072_mont_sqr_53(t[ 8], t[ 4], m, mp);
        sp_3072_mont_mul_53(t[ 9], t[ 5], t[ 4], m, mp);
        sp_3072_mont_sqr_53(t[10], t[ 5], m, mp);
        sp_3072_mont_mul_53(t[11], t[ 6], t[ 5], m, mp);
        sp_3072_mont_sqr_53(t[12], t[ 6], m, mp);
        sp_3072_mont_mul_53(t[13], t[ 7], t[ 6], m, mp);
        sp_3072_mont_sqr_53(t[14], t[ 7], m, mp);
        sp_3072_mont_mul_53(t[15], t[ 8], t[ 7], m, mp);
        sp_3072_mont_sqr_53(t[16], t[ 8], m, mp);
        sp_3072_mont_mul_53(t[17], t[ 9], t[ 8], m, mp);
        sp_3072_mont_sqr_53(t[18], t[ 9], m, mp);
        sp_3072_mont_mul_53(t[19], t[10], t[ 9], m, mp);
        sp_3072_mont_sqr_53(t[20], t[10], m, mp);
        sp_3072_mont_mul_53(t[21], t[11], t[10], m, mp);
        sp_3072_mont_sqr_53(t[22], t[11], m, mp);
        sp_3072_mont_mul_53(t[23], t[12], t[11], m, mp);
        sp_3072_mont_sqr_53(t[24], t[12], m, mp);
        sp_3072_mont_mul_53(t[25], t[13], t[12], m, mp);
        sp_3072_mont_sqr_53(t[26], t[13], m, mp);
        sp_3072_mont_mul_53(t[27], t[14], t[13], m, mp);
        sp_3072_mont_sqr_53(t[28], t[14], m, mp);
        sp_3072_mont_mul_53(t[29], t[15], t[14], m, mp);
        sp_3072_mont_sqr_53(t[30], t[15], m, mp);
        sp_3072_mont_mul_53(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 28) / 29) - 1;
        c = bits % 29;
        if (c == 0) {
            c = 29;
        }
        if (i < 53) {
            n = e[i--] << (32 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (3 - c);
            c += 29;
        }
        y = (int)((n >> 27) & 0x1f);
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 106);
        while ((i >= 0) || (c >= 5)) {
            if (c >= 5) {
                y = (byte)((n >> 27) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--] << 3;
                y = (byte)((n >> 27) & 0x1f);
                n <<= 5;
                c = 24;
            }
            else {
                y = (byte)((n >> 27) & 0x1f);
                n = e[i--] << 3;
                c = 5 - c;
                y |= (byte)((n >> (32 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 29 - c;
            }

            sp_3072_mont_sqr_53(rt, rt, m, mp);
            sp_3072_mont_sqr_53(rt, rt, m, mp);
            sp_3072_mont_sqr_53(rt, rt, m, mp);
            sp_3072_mont_sqr_53(rt, rt, m, mp);
            sp_3072_mont_sqr_53(rt, rt, m, mp);

            sp_3072_mont_mul_53(rt, rt, t[y], m, mp);
        }

        sp_3072_mont_reduce_53(rt, m, mp);
        n = sp_3072_cmp_53(rt, m);
        sp_3072_cond_sub_53(rt, rt, m, ~(n >> 31));
        XMEMCPY(r, rt, sizeof(sp_digit) * 106);
    }


    return err;
#endif
}

#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) | WOLFSSL_HAVE_SP_DH */

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_sub_106(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 106; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 3072 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_3072_mont_norm_106(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
    int i;

    for (i=0; i<105; i++) {
        r[i] = 0x1fffffff;
    }
    r[105] = 0x7ffffffL;

    /* r = (2^n - 1) mod n */
    (void)sp_3072_sub_106(r, r, m);

    /* Add one so r = 2^n mod m */
    r[0] += 1;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_3072_cmp_106(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
    int i;

    for (i=105; i>=0; i--) {
        r |= (a[i] - b[i]) & ~(((sp_digit)0 - r) >> 28);
    }

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_3072_cond_sub_106(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 106; i++) {
        r[i] = a[i] - (b[i] & m);
    }
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_add_106(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifndef WOLFSSL_SP_LARGE_CODE
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 106; i++) {
        t += r[i];
        t += tb * a[i];
        r[i] = ((sp_digit)t) & 0x1fffffff;
        t >>= 29;
    }
    r[106] += (sp_digit)t;
#else
    sp_int64 tb = b;
    sp_int64 t[4];
    int i;

    t[0] = 0;
    for (i = 0; i < 104; i += 4) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        r[i+0] = t[0] & 0x1fffffff;
        t[1] += t[0] >> 29;
        r[i+1] = t[1] & 0x1fffffff;
        t[2] += t[1] >> 29;
        r[i+2] = t[2] & 0x1fffffff;
        t[3] += t[2] >> 29;
        r[i+3] = t[3] & 0x1fffffff;
        t[0]  = t[3] >> 29;
    }
    t[0] += (tb * a[104]) + r[104];
    t[1]  = (tb * a[105]) + r[105];
    r[104] = t[0] & 0x1fffffff;
    t[1] += t[0] >> 29;
    r[105] = t[1] & 0x1fffffff;
    r[106] +=  (sp_digit)(t[1] >> 29);
#endif /* !WOLFSSL_SP_LARGE_CODE */
}

/* Shift the result in the high 3072 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_3072_mont_shift_106(sp_digit* r, const sp_digit* a)
{
    int i;
    sp_int64 n = a[105] >> 27;
    n += ((sp_int64)a[106]) << 2;

    for (i = 0; i < 105; i++) {
        r[i] = n & 0x1fffffff;
        n >>= 29;
        n += ((sp_int64)a[107 + i]) << 2;
    }
    r[105] = (sp_digit)n;
    XMEMSET(&r[106], 0, sizeof(*r) * 106U);
}

/* Reduce the number back to 3072 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_3072_mont_reduce_106(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_3072_norm_106(a + 106);

#ifdef WOLFSSL_SP_DH
    if (mp != 1) {
        for (i=0; i<105; i++) {
            mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x1fffffff;
            sp_3072_mul_add_106(a+i, m, mu);
            a[i+1] += a[i] >> 29;
        }
        mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x7ffffffL;
        sp_3072_mul_add_106(a+i, m, mu);
        a[i+1] += a[i] >> 29;
        a[i] &= 0x1fffffff;
    }
    else {
        for (i=0; i<105; i++) {
            mu = a[i] & 0x1fffffff;
            sp_3072_mul_add_106(a+i, m, mu);
            a[i+1] += a[i] >> 29;
        }
        mu = a[i] & 0x7ffffffL;
        sp_3072_mul_add_106(a+i, m, mu);
        a[i+1] += a[i] >> 29;
        a[i] &= 0x1fffffff;
    }
#else
    for (i=0; i<105; i++) {
        mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x1fffffff;
        sp_3072_mul_add_106(a+i, m, mu);
        a[i+1] += a[i] >> 29;
    }
    mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x7ffffffL;
    sp_3072_mul_add_106(a+i, m, mu);
    a[i+1] += a[i] >> 29;
    a[i] &= 0x1fffffff;
#endif
    sp_3072_mont_shift_106(a, a);
    over = a[105] - m[105];
    sp_3072_cond_sub_106(a, a, m, ~((over - 1) >> 31));
    sp_3072_norm_106(a);
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
SP_NOINLINE static void sp_3072_mont_mul_106(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_3072_mul_106(r, a, b);
    sp_3072_mont_reduce_106(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_3072_mont_sqr_106(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_3072_sqr_106(r, a);
    sp_3072_mont_reduce_106(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_d_212(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 212; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
    }
    r[212] = (sp_digit)t;
}

#ifdef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_3072_cond_add_106(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 106; i++) {
        r[i] = a[i] + (b[i] & m);
    }
}
#endif /* WOLFSSL_SP_SMALL */

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_106(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 106; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}

SP_NOINLINE static void sp_3072_rshift_106(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    for (i=0; i<105; i++) {
        r[i] = ((a[i] >> n) | (a[i + 1] << (29 - n))) & 0x1fffffff;
    }
    r[105] = a[105] >> n;
}

static WC_INLINE sp_digit sp_3072_div_word_106(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int64 d = ((sp_int64)d1 << 29) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_uint32 lo = (sp_uint32)d;
    sp_digit hi = (sp_digit)(d >> 32);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 29);
    sp_digit t0 = (sp_digit)(d & 0x1fffffff);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int64 m;

    r = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
    t1 -= dv & (0 - r);
    for (i = 27; i >= 1; i--) {
        t1 += t1 + (((sp_uint32)t0 >> 28) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int64)r * div);
    r += (sp_digit)(m >> 29);
    m = d - ((sp_int64)r * div);
    r += (m >> 58) - (sp_digit)(d >> 58);

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;
   return r;
#else
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 14) + 1;

    t = (sp_digit)(d >> 28);
    t = (t / dv) << 14;
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)(d >> 13);
    t = t / (dv << 1);
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int64)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_3072_word_div_word_106(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint32)(div - d) >> 31);
#endif
}
/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * Full implementation.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_3072_div_106(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_32
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 106 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 212 + 1;
        sd = t2 + 106 + 1;

        sp_3072_mul_d_106(sd, d, (sp_digit)1 << 2);
        sp_3072_mul_d_212(t1, a, (sp_digit)1 << 2);
        dv = sd[105];
        t1[106 + 106] += t1[106 + 106 - 1] >> 29;
        t1[106 + 106 - 1] &= 0x1fffffff;
        for (i=106; i>=0; i--) {
            r1 = sp_3072_div_word_106(t1[106 + i], t1[106 + i - 1], dv);

            sp_3072_mul_d_106(t2, sd, r1);
            (void)sp_3072_sub_106(&t1[i], &t1[i], t2);
            sp_3072_norm_106(&t1[i]);
            t1[106 + i] -= t2[106];
            t1[106 + i] += t1[106 + i - 1] >> 29;
            t1[106 + i - 1] &= 0x1fffffff;
            r1 = sp_3072_div_word_106(-t1[106 + i], -t1[106 + i - 1], dv);
            r1 -= t1[106 + i];
            sp_3072_mul_d_106(t2, sd, r1);
            (void)sp_3072_add_106(&t1[i], &t1[i], t2);
            t1[106 + i] += t1[106 + i - 1] >> 29;
            t1[106 + i - 1] &= 0x1fffffff;
        }
        t1[106 - 1] += t1[106 - 2] >> 29;
        t1[106 - 2] &= 0x1fffffff;
        r1 = sp_3072_word_div_word_106(t1[106 - 1], dv);

        sp_3072_mul_d_106(t2, sd, r1);
        sp_3072_sub_106(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 212U);
        for (i=0; i<105; i++) {
            r[i+1] += r[i] >> 29;
            r[i] &= 0x1fffffff;
        }
        sp_3072_cond_add_106(r, r, sd, r[105] >> 31);

        sp_3072_norm_106(r);
        sp_3072_rshift_106(r, r, 2);
    }


    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_3072_mod_106(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_3072_div_106(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
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
static int sp_3072_mod_exp_106(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 212];
    sp_digit* t[3] = {0, 0, 0};
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<3; i++) {
            t[i] = td + (i * 106 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 106U * 2U);
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_106(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_106(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 106U);
        }
    }
    if (err == MP_OKAY) {
        sp_3072_mul_106(t[1], t[1], norm);
        err = sp_3072_mod_106(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 29;
        c = bits % 29;
        n = e[i--] << (29 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 29;
            }

            y = (int)((n >> 28) & 1);
            n <<= 1;

            sp_3072_mont_mul_106(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 106 * 2);
            sp_3072_mont_sqr_106(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 106 * 2);
        }

        sp_3072_mont_reduce_106(t[0], m, mp);
        n = sp_3072_cmp_106(t[0], m);
        sp_3072_cond_sub_106(t[0], t[0], m, ~(n >> 31));
        XMEMCPY(r, t[0], sizeof(*r) * 106 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 212];
    sp_digit* t[3] = {0, 0, 0};
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<3; i++) {
            t[i] = td + (i * 106 * 2);
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_106(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_106(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_106(t[1], t[1], norm);
                err = sp_3072_mod_106(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_106(t[1], a, norm);
            err = sp_3072_mod_106(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 29;
        c = bits % 29;
        n = e[i--] << (29 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 29;
            }

            y = (int)((n >> 28) & 1);
            n <<= 1;

            sp_3072_mont_mul_106(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 106 * 2);
            sp_3072_mont_sqr_106(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 106 * 2);
        }

        sp_3072_mont_reduce_106(t[0], m, mp);
        n = sp_3072_cmp_106(t[0], m);
        sp_3072_cond_sub_106(t[0], t[0], m, ~(n >> 31));
        XMEMCPY(r, t[0], sizeof(*r) * 106 * 2);
    }


    return err;
#else
    sp_digit td[(16 * 212) + 212];
    sp_digit* t[16];
    sp_digit* rt = NULL;
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<16; i++)
            t[i] = td + i * 212;
        rt = td + 3392;

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_106(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_106(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_106(t[1], t[1], norm);
                err = sp_3072_mod_106(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_106(t[1], a, norm);
            err = sp_3072_mod_106(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_3072_mont_sqr_106(t[ 2], t[ 1], m, mp);
        sp_3072_mont_mul_106(t[ 3], t[ 2], t[ 1], m, mp);
        sp_3072_mont_sqr_106(t[ 4], t[ 2], m, mp);
        sp_3072_mont_mul_106(t[ 5], t[ 3], t[ 2], m, mp);
        sp_3072_mont_sqr_106(t[ 6], t[ 3], m, mp);
        sp_3072_mont_mul_106(t[ 7], t[ 4], t[ 3], m, mp);
        sp_3072_mont_sqr_106(t[ 8], t[ 4], m, mp);
        sp_3072_mont_mul_106(t[ 9], t[ 5], t[ 4], m, mp);
        sp_3072_mont_sqr_106(t[10], t[ 5], m, mp);
        sp_3072_mont_mul_106(t[11], t[ 6], t[ 5], m, mp);
        sp_3072_mont_sqr_106(t[12], t[ 6], m, mp);
        sp_3072_mont_mul_106(t[13], t[ 7], t[ 6], m, mp);
        sp_3072_mont_sqr_106(t[14], t[ 7], m, mp);
        sp_3072_mont_mul_106(t[15], t[ 8], t[ 7], m, mp);

        bits = ((bits + 3) / 4) * 4;
        i = ((bits + 28) / 29) - 1;
        c = bits % 29;
        if (c == 0) {
            c = 29;
        }
        if (i < 106) {
            n = e[i--] << (32 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 4) {
            n |= e[i--] << (3 - c);
            c += 29;
        }
        y = (int)((n >> 28) & 0xf);
        n <<= 4;
        c -= 4;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 212);
        while ((i >= 0) || (c >= 4)) {
            if (c >= 4) {
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c -= 4;
            }
            else if (c == 0) {
                n = e[i--] << 3;
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c = 25;
            }
            else {
                y = (byte)((n >> 28) & 0xf);
                n = e[i--] << 3;
                c = 4 - c;
                y |= (byte)((n >> (32 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 29 - c;
            }

            sp_3072_mont_sqr_106(rt, rt, m, mp);
            sp_3072_mont_sqr_106(rt, rt, m, mp);
            sp_3072_mont_sqr_106(rt, rt, m, mp);
            sp_3072_mont_sqr_106(rt, rt, m, mp);

            sp_3072_mont_mul_106(rt, rt, t[y], m, mp);
        }

        sp_3072_mont_reduce_106(rt, m, mp);
        n = sp_3072_cmp_106(rt, m);
        sp_3072_cond_sub_106(rt, rt, m, ~(n >> 31));
        XMEMCPY(r, rt, sizeof(sp_digit) * 212);
    }


    return err;
#endif
}

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
#ifdef WOLFSSL_SP_SMALL
    sp_digit a[106 * 5];
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit* norm = NULL;
    sp_digit e[1] = {0};
    sp_digit mp = 0;
    int i;
    int err = MP_OKAY;

    if (*outLen < 384U) {
        err = MP_TO_E;
    }

    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 29) {
            err = MP_READ_E;
        }
        else if (inLen > 384U) {
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
        r = a + 106 * 2;
        m = r + 106 * 2;
        norm = r;

        sp_3072_from_bin(a, 106, in, inLen);
#if DIGIT_BIT >= 29
        e[0] = (sp_digit)em->dp[0];
#else
        e[0] = (sp_digit)em->dp[0];
        if (em->used > 1) {
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
        }
#endif
        if (e[0] == 0) {
            err = MP_EXPTMOD_E;
        }
    }

    if (err == MP_OKAY) {
        sp_3072_from_mp(m, 106, mm);

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_106(norm, m);
    }
    if (err == MP_OKAY) {
        sp_3072_mul_106(a, a, norm);
        err = sp_3072_mod_106(a, a, m);
    }
    if (err == MP_OKAY) {
        for (i=28; i>=0; i--) {
            if ((e[0] >> i) != 0) {
                break;
            }
        }

        XMEMCPY(r, a, sizeof(sp_digit) * 106 * 2);
        for (i--; i>=0; i--) {
            sp_3072_mont_sqr_106(r, r, m, mp);

            if (((e[0] >> i) & 1) == 1) {
                sp_3072_mont_mul_106(r, r, a, m, mp);
            }
        }
        sp_3072_mont_reduce_106(r, m, mp);
        mp = sp_3072_cmp_106(r, m);
        sp_3072_cond_sub_106(r, r, m, ~(mp >> 31));

        sp_3072_to_bin_106(r, out);
        *outLen = 384;
    }


    return err;
#else
    sp_digit d[106 * 5];
    sp_digit* a = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit e[1] = {0};
    int err = MP_OKAY;

    if (*outLen < 384U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 29) {
            err = MP_READ_E;
        }
        else if (inLen > 384U) {
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
        a = d;
        r = a + 106 * 2;
        m = r + 106 * 2;

        sp_3072_from_bin(a, 106, in, inLen);
#if DIGIT_BIT >= 29
        e[0] = (sp_digit)em->dp[0];
#else
        e[0] = (sp_digit)em->dp[0];
        if (em->used > 1) {
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
        }
#endif
        if (e[0] == 0) {
            err = MP_EXPTMOD_E;
        }
    }
    if (err == MP_OKAY) {
        sp_3072_from_mp(m, 106, mm);

        if (e[0] == 0x3) {
            sp_3072_sqr_106(r, a);
            err = sp_3072_mod_106(r, r, m);
            if (err == MP_OKAY) {
                sp_3072_mul_106(r, a, r);
                err = sp_3072_mod_106(r, r, m);
            }
        }
        else {
            sp_digit* norm = r;
            int i;
            sp_digit mp;

            sp_3072_mont_setup(m, &mp);
            sp_3072_mont_norm_106(norm, m);

            sp_3072_mul_106(a, a, norm);
            err = sp_3072_mod_106(a, a, m);

            if (err == MP_OKAY) {
                for (i=28; i>=0; i--) {
                    if ((e[0] >> i) != 0) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 212U);
                for (i--; i>=0; i--) {
                    sp_3072_mont_sqr_106(r, r, m, mp);

                    if (((e[0] >> i) & 1) == 1) {
                        sp_3072_mont_mul_106(r, r, a, m, mp);
                    }
                }
                sp_3072_mont_reduce_106(r, m, mp);
                mp = sp_3072_cmp_106(r, m);
                sp_3072_cond_sub_106(r, r, m, ~(mp >> 31));
            }
        }
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_106(r, out);
        *outLen = 384;
    }


    return err;
#endif /* WOLFSSL_SP_SMALL */
}

#ifndef WOLFSSL_RSA_PUBLIC_ONLY
#if !defined(SP_RSA_PRIVATE_EXP_D) && !defined(RSA_LOW_MEM)
#endif /* !SP_RSA_PRIVATE_EXP_D & !RSA_LOW_MEM */
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
#if defined(WOLFSSL_SP_SMALL)
    sp_digit  d[106 * 4];
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
        a = d + 106;
        m = a + 212;
        r = a;

        sp_3072_from_bin(a, 106, in, inLen);
        sp_3072_from_mp(d, 106, dm);
        sp_3072_from_mp(m, 106, mm);
        err = sp_3072_mod_exp_106(r, a, d, 3072, m, 0);
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_106(r, out);
        *outLen = 384;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 106);
    }

    return err;
#else
    sp_digit d[106 * 4];
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
        else if (inLen > 384U) {
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
        a = d + 106;
        m = a + 212;
        r = a;

        sp_3072_from_bin(a, 106, in, inLen);
        sp_3072_from_mp(d, 106, dm);
        sp_3072_from_mp(m, 106, mm);
        err = sp_3072_mod_exp_106(r, a, d, 3072, m, 0);
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_106(r, out);
        *outLen = 384;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 106);
    }

    return err;
#endif /* WOLFSSL_SP_SMALL */
#else
#if defined(WOLFSSL_SP_SMALL)
    sp_digit a[53 * 8];
    sp_digit* p = NULL;
    sp_digit* dp = NULL;
    sp_digit* dq = NULL;
    sp_digit* qi = NULL;
    sp_digit* tmpa = NULL;
    sp_digit* tmpb = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 384U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (inLen > 384) {
            err = MP_READ_E;
        }
        else if (mp_count_bits(mm) != 3072) {
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
    }

    if (err == MP_OKAY) {
        p = a + 106;
        qi = dq = dp = p + 53;
        tmpa = qi + 53;
        tmpb = tmpa + 106;
        r = a;

        sp_3072_from_bin(a, 106, in, inLen);
        sp_3072_from_mp(p, 53, pm);
        sp_3072_from_mp(dp, 53, dpm);
        err = sp_3072_mod_exp_53(tmpa, a, dp, 1536, p, 1);
    }
    if (err == MP_OKAY) {
        sp_3072_from_mp(p, 53, qm);
        sp_3072_from_mp(dq, 53, dqm);
        err = sp_3072_mod_exp_53(tmpb, a, dq, 1536, p, 1);
    }
    if (err == MP_OKAY) {
        sp_3072_from_mp(p, 53, pm);
        (void)sp_3072_sub_53(tmpa, tmpa, tmpb);
        sp_3072_norm_53(tmpa);
        sp_3072_cond_add_53(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[52] >> 31));
        sp_3072_cond_add_53(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[52] >> 31));
        sp_3072_norm_53(tmpa);

        sp_3072_from_mp(qi, 53, qim);
        sp_3072_mul_53(tmpa, tmpa, qi);
        err = sp_3072_mod_53(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_3072_from_mp(p, 53, qm);
        sp_3072_mul_53(tmpa, p, tmpa);
        (void)sp_3072_add_106(r, tmpb, tmpa);
        sp_3072_norm_106(r);

        sp_3072_to_bin_106(r, out);
        *outLen = 384;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 53 * 8);
    }

    return err;
#else
    sp_digit a[53 * 13];
    sp_digit* p = NULL;
    sp_digit* q = NULL;
    sp_digit* dp = NULL;
    sp_digit* dq = NULL;
    sp_digit* qi = NULL;
    sp_digit* tmpa = NULL;
    sp_digit* tmpb = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 384U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (inLen > 384U) {
            err = MP_READ_E;
        }
        else if (mp_count_bits(mm) != 3072) {
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
    }


    if (err == MP_OKAY) {
        p = a + 106 * 2;
        q = p + 53;
        dp = q + 53;
        dq = dp + 53;
        qi = dq + 53;
        tmpa = qi + 53;
        tmpb = tmpa + 106;
        r = a;

        sp_3072_from_bin(a, 106, in, inLen);
        sp_3072_from_mp(p, 53, pm);
        sp_3072_from_mp(q, 53, qm);
        sp_3072_from_mp(dp, 53, dpm);
        sp_3072_from_mp(dq, 53, dqm);
        sp_3072_from_mp(qi, 53, qim);

        err = sp_3072_mod_exp_53(tmpa, a, dp, 1536, p, 1);
    }
    if (err == MP_OKAY) {
        err = sp_3072_mod_exp_53(tmpb, a, dq, 1536, q, 1);
    }

    if (err == MP_OKAY) {
        (void)sp_3072_sub_53(tmpa, tmpa, tmpb);
        sp_3072_norm_53(tmpa);
        sp_3072_cond_add_53(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[52] >> 31));
        sp_3072_cond_add_53(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[52] >> 31));
        sp_3072_norm_53(tmpa);
        sp_3072_mul_53(tmpa, tmpa, qi);
        err = sp_3072_mod_53(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_3072_mul_53(tmpa, tmpa, q);
        (void)sp_3072_add_106(r, tmpb, tmpa);
        sp_3072_norm_106(r);

        sp_3072_to_bin_106(r, out);
        *outLen = 384;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 53 * 13);
    }

    return err;
#endif /* WOLFSSL_SP_SMALL */
#endif /* SP_RSA_PRIVATE_EXP_D || RSA_LOW_MEM */
}

#endif /* !WOLFSSL_RSA_PUBLIC_ONLY */
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
#if DIGIT_BIT == 29
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 106);
        r->used = 106;
        mp_clamp(r);
#elif DIGIT_BIT < 29
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 106; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 29) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 29 - s;
        }
        r->used = (3072 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 106; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 29 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 29 - s;
            }
            else {
                s += 29;
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
#ifdef WOLFSSL_SP_SMALL
    int err = MP_OKAY;
    sp_digit b[106 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
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
        e = b + 106 * 2;
        m = e + 106;
        r = b;

        sp_3072_from_mp(b, 106, base);
        sp_3072_from_mp(e, 106, exp);
        sp_3072_from_mp(m, 106, mod);

        err = sp_3072_mod_exp_106(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_3072_to_mp(r, res);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 106U);
    }
    return err;
#else
    sp_digit b[106 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;
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
        e = b + 106 * 2;
        m = e + 106;
        r = b;

        sp_3072_from_mp(b, 106, base);
        sp_3072_from_mp(e, 106, exp);
        sp_3072_from_mp(m, 106, mod);

        err = sp_3072_mod_exp_106(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_3072_to_mp(r, res);
    }


    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 106U);
    }

    return err;
#endif
}

#ifdef WOLFSSL_HAVE_SP_DH

#ifdef HAVE_FFDHE_3072
SP_NOINLINE static void sp_3072_lshift_106(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    r[106] = a[105] >> (29 - n);
    for (i=105; i>0; i--) {
        r[i] = ((a[i] << n) | (a[i-1] >> (29 - n))) & 0x1fffffff;
    }
    r[0] = (a[0] << n) & 0x1fffffff;
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
static int sp_3072_mod_exp_2_106(sp_digit* r, const sp_digit* e, int bits, const sp_digit* m)
{
    sp_digit td[319];
    sp_digit* norm = NULL;
    sp_digit* tmp = NULL;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit o;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        tmp  = td + 212;
        XMEMSET(td, 0, sizeof(sp_digit) * 319);

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_106(norm, m);

        bits = ((bits + 3) / 4) * 4;
        i = ((bits + 28) / 29) - 1;
        c = bits % 29;
        if (c == 0) {
            c = 29;
        }
        if (i < 106) {
            n = e[i--] << (32 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 4) {
            n |= e[i--] << (3 - c);
            c += 29;
        }
        y = (int)((n >> 28) & 0xf);
        n <<= 4;
        c -= 4;
        sp_3072_lshift_106(r, norm, (byte)y);
        while ((i >= 0) || (c >= 4)) {
            if (c >= 4) {
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c -= 4;
            }
            else if (c == 0) {
                n = e[i--] << 3;
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c = 25;
            }
            else {
                y = (byte)((n >> 28) & 0xf);
                n = e[i--] << 3;
                c = 4 - c;
                y |= (byte)((n >> (32 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 29 - c;
            }

            sp_3072_mont_sqr_106(r, r, m, mp);
            sp_3072_mont_sqr_106(r, r, m, mp);
            sp_3072_mont_sqr_106(r, r, m, mp);
            sp_3072_mont_sqr_106(r, r, m, mp);

            sp_3072_lshift_106(r, r, (byte)y);
            sp_3072_mul_d_106(tmp, norm, (r[106] << 2) + (r[105] >> 27));
            r[106] = 0;
            r[105] &= 0x7ffffffL;
            (void)sp_3072_add_106(r, r, tmp);
            sp_3072_norm_106(r);
            o = sp_3072_cmp_106(r, m);
            sp_3072_cond_sub_106(r, r, m, ~(o >> 31));
        }

        sp_3072_mont_reduce_106(r, m, mp);
        n = sp_3072_cmp_106(r, m);
        sp_3072_cond_sub_106(r, r, m, ~(n >> 31));
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
    sp_digit b[106 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    word32 i;
    int err = MP_OKAY;

    if (mp_count_bits(base) > 3072) {
        err = MP_READ_E;
    }
    else if (expLen > 384U) {
        err = MP_READ_E;
    }
    else if (mp_count_bits(mod) != 3072) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mod)) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        e = b + 106 * 2;
        m = e + 106;
        r = b;

        sp_3072_from_mp(b, 106, base);
        sp_3072_from_bin(e, 106, exp, expLen);
        sp_3072_from_mp(m, 106, mod);

    #ifdef HAVE_FFDHE_3072
        if (base->used == 1 && base->dp[0] == 2U &&
                (m[105] >> 11) == 0xffffL) {
            err = sp_3072_mod_exp_2_106(r, e, expLen * 8U, m);
        }
        else {
    #endif
            err = sp_3072_mod_exp_106(r, b, e, expLen * 8U, m, 0);
    #ifdef HAVE_FFDHE_3072
        }
    #endif
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_106(r, out);
        *outLen = 384;
        for (i=0; i<384U && out[i] == 0U; i++) {
            /* Search for first non-zero. */
        }
        *outLen -= i;
        XMEMMOVE(out, out + i, *outLen);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 106U);
    }

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
#ifdef WOLFSSL_SP_SMALL
    int err = MP_OKAY;
    sp_digit b[53 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
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
        e = b + 53 * 2;
        m = e + 53;
        r = b;

        sp_3072_from_mp(b, 53, base);
        sp_3072_from_mp(e, 53, exp);
        sp_3072_from_mp(m, 53, mod);

        err = sp_3072_mod_exp_53(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 53, 0, sizeof(*r) * 53U);
        err = sp_3072_to_mp(r, res);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 106U);
    }
    return err;
#else
    sp_digit b[53 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;
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
        e = b + 53 * 2;
        m = e + 53;
        r = b;

        sp_3072_from_mp(b, 53, base);
        sp_3072_from_mp(e, 53, exp);
        sp_3072_from_mp(m, 53, mod);

        err = sp_3072_mod_exp_53(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 53, 0, sizeof(*r) * 53U);
        err = sp_3072_to_mp(r, res);
    }


    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 106U);
    }

    return err;
#endif
}

#endif /* WOLFSSL_HAVE_SP_DH | (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) */

#else
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
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = n-1; i >= 0; i--) {
        r[j] |= (((sp_digit)a[i]) << s);
        if (s >= 20U) {
            r[j] &= 0xfffffff;
            s = 28U - s;
            if (j + 1 >= size) {
                break;
            }
            r[++j] = (sp_digit)a[i] >> s;
            s = 8U - s;
        }
        else {
            s += 8U;
        }
    }

    for (j++; j < size; j++) {
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
#if DIGIT_BIT == 28
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 28
    int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0xfffffff;
        s = 28U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 28U) <= (word32)DIGIT_BIT) {
            s += 28U;
            r[j] &= 0xfffffff;
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
        if (s + DIGIT_BIT >= 28) {
            r[j] &= 0xfffffff;
            if (j + 1 >= size) {
                break;
            }
            s = 28 - s;
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
static void sp_3072_to_bin_112(sp_digit* r, byte* a)
{
    int i;
    int j;
    int s = 0;
    int b;

    for (i=0; i<111; i++) {
        r[i+1] += r[i] >> 28;
        r[i] &= 0xfffffff;
    }
    j = 3079 / 8 - 1;
    a[j] = 0;
    for (i=0; i<112 && j>=0; i++) {
        b = 0;
        /* lint allow cast of mismatch sp_digit and int */
        a[j--] |= (byte)(r[i] << s); /*lint !e9033*/
        b += 8 - s;
        if (j < 0) {
            break;
        }
        while (b < 28) {
            a[j--] = (byte)(r[i] >> b);
            b += 8;
            if (j < 0) {
                break;
            }
        }
        s = 8 - (b - 28);
        if (j >= 0) {
            a[j] = 0;
        }
        if (s != 0) {
            j++;
        }
    }
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* Normalize the values in each word to 28 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_3072_norm_56(sp_digit* a)
{
    int i;
    for (i = 0; i < 48; i += 8) {
        a[i+1] += a[i+0] >> 28; a[i+0] &= 0xfffffff;
        a[i+2] += a[i+1] >> 28; a[i+1] &= 0xfffffff;
        a[i+3] += a[i+2] >> 28; a[i+2] &= 0xfffffff;
        a[i+4] += a[i+3] >> 28; a[i+3] &= 0xfffffff;
        a[i+5] += a[i+4] >> 28; a[i+4] &= 0xfffffff;
        a[i+6] += a[i+5] >> 28; a[i+5] &= 0xfffffff;
        a[i+7] += a[i+6] >> 28; a[i+6] &= 0xfffffff;
        a[i+8] += a[i+7] >> 28; a[i+7] &= 0xfffffff;
    }
    a[49] += a[48] >> 28; a[48] &= 0xfffffff;
    a[50] += a[49] >> 28; a[49] &= 0xfffffff;
    a[51] += a[50] >> 28; a[50] &= 0xfffffff;
    a[52] += a[51] >> 28; a[51] &= 0xfffffff;
    a[53] += a[52] >> 28; a[52] &= 0xfffffff;
    a[54] += a[53] >> 28; a[53] &= 0xfffffff;
    a[55] += a[54] >> 28; a[54] &= 0xfffffff;
}

#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || WOLFSSL_HAVE_SP_DH */
/* Normalize the values in each word to 28 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_3072_norm_55(sp_digit* a)
{
    int i;
    for (i = 0; i < 48; i += 8) {
        a[i+1] += a[i+0] >> 28; a[i+0] &= 0xfffffff;
        a[i+2] += a[i+1] >> 28; a[i+1] &= 0xfffffff;
        a[i+3] += a[i+2] >> 28; a[i+2] &= 0xfffffff;
        a[i+4] += a[i+3] >> 28; a[i+3] &= 0xfffffff;
        a[i+5] += a[i+4] >> 28; a[i+4] &= 0xfffffff;
        a[i+6] += a[i+5] >> 28; a[i+5] &= 0xfffffff;
        a[i+7] += a[i+6] >> 28; a[i+6] &= 0xfffffff;
        a[i+8] += a[i+7] >> 28; a[i+7] &= 0xfffffff;
    }
    a[49] += a[48] >> 28; a[48] &= 0xfffffff;
    a[50] += a[49] >> 28; a[49] &= 0xfffffff;
    a[51] += a[50] >> 28; a[50] &= 0xfffffff;
    a[52] += a[51] >> 28; a[51] &= 0xfffffff;
    a[53] += a[52] >> 28; a[52] &= 0xfffffff;
    a[54] += a[53] >> 28; a[53] &= 0xfffffff;
}

/* Normalize the values in each word to 28 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_3072_norm_112(sp_digit* a)
{
    int i;
    for (i = 0; i < 104; i += 8) {
        a[i+1] += a[i+0] >> 28; a[i+0] &= 0xfffffff;
        a[i+2] += a[i+1] >> 28; a[i+1] &= 0xfffffff;
        a[i+3] += a[i+2] >> 28; a[i+2] &= 0xfffffff;
        a[i+4] += a[i+3] >> 28; a[i+3] &= 0xfffffff;
        a[i+5] += a[i+4] >> 28; a[i+4] &= 0xfffffff;
        a[i+6] += a[i+5] >> 28; a[i+5] &= 0xfffffff;
        a[i+7] += a[i+6] >> 28; a[i+6] &= 0xfffffff;
        a[i+8] += a[i+7] >> 28; a[i+7] &= 0xfffffff;
    }
    a[105] += a[104] >> 28; a[104] &= 0xfffffff;
    a[106] += a[105] >> 28; a[105] &= 0xfffffff;
    a[107] += a[106] >> 28; a[106] &= 0xfffffff;
    a[108] += a[107] >> 28; a[107] &= 0xfffffff;
    a[109] += a[108] >> 28; a[108] &= 0xfffffff;
    a[110] += a[109] >> 28; a[109] &= 0xfffffff;
    a[111] += a[110] >> 28; a[110] &= 0xfffffff;
}

/* Normalize the values in each word to 28 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_3072_norm_110(sp_digit* a)
{
    int i;
    for (i = 0; i < 104; i += 8) {
        a[i+1] += a[i+0] >> 28; a[i+0] &= 0xfffffff;
        a[i+2] += a[i+1] >> 28; a[i+1] &= 0xfffffff;
        a[i+3] += a[i+2] >> 28; a[i+2] &= 0xfffffff;
        a[i+4] += a[i+3] >> 28; a[i+3] &= 0xfffffff;
        a[i+5] += a[i+4] >> 28; a[i+4] &= 0xfffffff;
        a[i+6] += a[i+5] >> 28; a[i+5] &= 0xfffffff;
        a[i+7] += a[i+6] >> 28; a[i+6] &= 0xfffffff;
        a[i+8] += a[i+7] >> 28; a[i+7] &= 0xfffffff;
    }
    a[105] += a[104] >> 28; a[104] &= 0xfffffff;
    a[106] += a[105] >> 28; a[105] &= 0xfffffff;
    a[107] += a[106] >> 28; a[106] &= 0xfffffff;
    a[108] += a[107] >> 28; a[107] &= 0xfffffff;
    a[109] += a[108] >> 28; a[108] &= 0xfffffff;
}

#ifndef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_14(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_uint64 t0   = ((sp_uint64)a[ 0]) * b[ 0];
    sp_uint64 t1   = ((sp_uint64)a[ 0]) * b[ 1]
                 + ((sp_uint64)a[ 1]) * b[ 0];
    sp_uint64 t2   = ((sp_uint64)a[ 0]) * b[ 2]
                 + ((sp_uint64)a[ 1]) * b[ 1]
                 + ((sp_uint64)a[ 2]) * b[ 0];
    sp_uint64 t3   = ((sp_uint64)a[ 0]) * b[ 3]
                 + ((sp_uint64)a[ 1]) * b[ 2]
                 + ((sp_uint64)a[ 2]) * b[ 1]
                 + ((sp_uint64)a[ 3]) * b[ 0];
    sp_uint64 t4   = ((sp_uint64)a[ 0]) * b[ 4]
                 + ((sp_uint64)a[ 1]) * b[ 3]
                 + ((sp_uint64)a[ 2]) * b[ 2]
                 + ((sp_uint64)a[ 3]) * b[ 1]
                 + ((sp_uint64)a[ 4]) * b[ 0];
    sp_uint64 t5   = ((sp_uint64)a[ 0]) * b[ 5]
                 + ((sp_uint64)a[ 1]) * b[ 4]
                 + ((sp_uint64)a[ 2]) * b[ 3]
                 + ((sp_uint64)a[ 3]) * b[ 2]
                 + ((sp_uint64)a[ 4]) * b[ 1]
                 + ((sp_uint64)a[ 5]) * b[ 0];
    sp_uint64 t6   = ((sp_uint64)a[ 0]) * b[ 6]
                 + ((sp_uint64)a[ 1]) * b[ 5]
                 + ((sp_uint64)a[ 2]) * b[ 4]
                 + ((sp_uint64)a[ 3]) * b[ 3]
                 + ((sp_uint64)a[ 4]) * b[ 2]
                 + ((sp_uint64)a[ 5]) * b[ 1]
                 + ((sp_uint64)a[ 6]) * b[ 0];
    sp_uint64 t7   = ((sp_uint64)a[ 0]) * b[ 7]
                 + ((sp_uint64)a[ 1]) * b[ 6]
                 + ((sp_uint64)a[ 2]) * b[ 5]
                 + ((sp_uint64)a[ 3]) * b[ 4]
                 + ((sp_uint64)a[ 4]) * b[ 3]
                 + ((sp_uint64)a[ 5]) * b[ 2]
                 + ((sp_uint64)a[ 6]) * b[ 1]
                 + ((sp_uint64)a[ 7]) * b[ 0];
    sp_uint64 t8   = ((sp_uint64)a[ 0]) * b[ 8]
                 + ((sp_uint64)a[ 1]) * b[ 7]
                 + ((sp_uint64)a[ 2]) * b[ 6]
                 + ((sp_uint64)a[ 3]) * b[ 5]
                 + ((sp_uint64)a[ 4]) * b[ 4]
                 + ((sp_uint64)a[ 5]) * b[ 3]
                 + ((sp_uint64)a[ 6]) * b[ 2]
                 + ((sp_uint64)a[ 7]) * b[ 1]
                 + ((sp_uint64)a[ 8]) * b[ 0];
    sp_uint64 t9   = ((sp_uint64)a[ 0]) * b[ 9]
                 + ((sp_uint64)a[ 1]) * b[ 8]
                 + ((sp_uint64)a[ 2]) * b[ 7]
                 + ((sp_uint64)a[ 3]) * b[ 6]
                 + ((sp_uint64)a[ 4]) * b[ 5]
                 + ((sp_uint64)a[ 5]) * b[ 4]
                 + ((sp_uint64)a[ 6]) * b[ 3]
                 + ((sp_uint64)a[ 7]) * b[ 2]
                 + ((sp_uint64)a[ 8]) * b[ 1]
                 + ((sp_uint64)a[ 9]) * b[ 0];
    sp_uint64 t10  = ((sp_uint64)a[ 0]) * b[10]
                 + ((sp_uint64)a[ 1]) * b[ 9]
                 + ((sp_uint64)a[ 2]) * b[ 8]
                 + ((sp_uint64)a[ 3]) * b[ 7]
                 + ((sp_uint64)a[ 4]) * b[ 6]
                 + ((sp_uint64)a[ 5]) * b[ 5]
                 + ((sp_uint64)a[ 6]) * b[ 4]
                 + ((sp_uint64)a[ 7]) * b[ 3]
                 + ((sp_uint64)a[ 8]) * b[ 2]
                 + ((sp_uint64)a[ 9]) * b[ 1]
                 + ((sp_uint64)a[10]) * b[ 0];
    sp_uint64 t11  = ((sp_uint64)a[ 0]) * b[11]
                 + ((sp_uint64)a[ 1]) * b[10]
                 + ((sp_uint64)a[ 2]) * b[ 9]
                 + ((sp_uint64)a[ 3]) * b[ 8]
                 + ((sp_uint64)a[ 4]) * b[ 7]
                 + ((sp_uint64)a[ 5]) * b[ 6]
                 + ((sp_uint64)a[ 6]) * b[ 5]
                 + ((sp_uint64)a[ 7]) * b[ 4]
                 + ((sp_uint64)a[ 8]) * b[ 3]
                 + ((sp_uint64)a[ 9]) * b[ 2]
                 + ((sp_uint64)a[10]) * b[ 1]
                 + ((sp_uint64)a[11]) * b[ 0];
    sp_uint64 t12  = ((sp_uint64)a[ 0]) * b[12]
                 + ((sp_uint64)a[ 1]) * b[11]
                 + ((sp_uint64)a[ 2]) * b[10]
                 + ((sp_uint64)a[ 3]) * b[ 9]
                 + ((sp_uint64)a[ 4]) * b[ 8]
                 + ((sp_uint64)a[ 5]) * b[ 7]
                 + ((sp_uint64)a[ 6]) * b[ 6]
                 + ((sp_uint64)a[ 7]) * b[ 5]
                 + ((sp_uint64)a[ 8]) * b[ 4]
                 + ((sp_uint64)a[ 9]) * b[ 3]
                 + ((sp_uint64)a[10]) * b[ 2]
                 + ((sp_uint64)a[11]) * b[ 1]
                 + ((sp_uint64)a[12]) * b[ 0];
    sp_uint64 t13  = ((sp_uint64)a[ 0]) * b[13]
                 + ((sp_uint64)a[ 1]) * b[12]
                 + ((sp_uint64)a[ 2]) * b[11]
                 + ((sp_uint64)a[ 3]) * b[10]
                 + ((sp_uint64)a[ 4]) * b[ 9]
                 + ((sp_uint64)a[ 5]) * b[ 8]
                 + ((sp_uint64)a[ 6]) * b[ 7]
                 + ((sp_uint64)a[ 7]) * b[ 6]
                 + ((sp_uint64)a[ 8]) * b[ 5]
                 + ((sp_uint64)a[ 9]) * b[ 4]
                 + ((sp_uint64)a[10]) * b[ 3]
                 + ((sp_uint64)a[11]) * b[ 2]
                 + ((sp_uint64)a[12]) * b[ 1]
                 + ((sp_uint64)a[13]) * b[ 0];
    sp_uint64 t14  = ((sp_uint64)a[ 1]) * b[13]
                 + ((sp_uint64)a[ 2]) * b[12]
                 + ((sp_uint64)a[ 3]) * b[11]
                 + ((sp_uint64)a[ 4]) * b[10]
                 + ((sp_uint64)a[ 5]) * b[ 9]
                 + ((sp_uint64)a[ 6]) * b[ 8]
                 + ((sp_uint64)a[ 7]) * b[ 7]
                 + ((sp_uint64)a[ 8]) * b[ 6]
                 + ((sp_uint64)a[ 9]) * b[ 5]
                 + ((sp_uint64)a[10]) * b[ 4]
                 + ((sp_uint64)a[11]) * b[ 3]
                 + ((sp_uint64)a[12]) * b[ 2]
                 + ((sp_uint64)a[13]) * b[ 1];
    sp_uint64 t15  = ((sp_uint64)a[ 2]) * b[13]
                 + ((sp_uint64)a[ 3]) * b[12]
                 + ((sp_uint64)a[ 4]) * b[11]
                 + ((sp_uint64)a[ 5]) * b[10]
                 + ((sp_uint64)a[ 6]) * b[ 9]
                 + ((sp_uint64)a[ 7]) * b[ 8]
                 + ((sp_uint64)a[ 8]) * b[ 7]
                 + ((sp_uint64)a[ 9]) * b[ 6]
                 + ((sp_uint64)a[10]) * b[ 5]
                 + ((sp_uint64)a[11]) * b[ 4]
                 + ((sp_uint64)a[12]) * b[ 3]
                 + ((sp_uint64)a[13]) * b[ 2];
    sp_uint64 t16  = ((sp_uint64)a[ 3]) * b[13]
                 + ((sp_uint64)a[ 4]) * b[12]
                 + ((sp_uint64)a[ 5]) * b[11]
                 + ((sp_uint64)a[ 6]) * b[10]
                 + ((sp_uint64)a[ 7]) * b[ 9]
                 + ((sp_uint64)a[ 8]) * b[ 8]
                 + ((sp_uint64)a[ 9]) * b[ 7]
                 + ((sp_uint64)a[10]) * b[ 6]
                 + ((sp_uint64)a[11]) * b[ 5]
                 + ((sp_uint64)a[12]) * b[ 4]
                 + ((sp_uint64)a[13]) * b[ 3];
    sp_uint64 t17  = ((sp_uint64)a[ 4]) * b[13]
                 + ((sp_uint64)a[ 5]) * b[12]
                 + ((sp_uint64)a[ 6]) * b[11]
                 + ((sp_uint64)a[ 7]) * b[10]
                 + ((sp_uint64)a[ 8]) * b[ 9]
                 + ((sp_uint64)a[ 9]) * b[ 8]
                 + ((sp_uint64)a[10]) * b[ 7]
                 + ((sp_uint64)a[11]) * b[ 6]
                 + ((sp_uint64)a[12]) * b[ 5]
                 + ((sp_uint64)a[13]) * b[ 4];
    sp_uint64 t18  = ((sp_uint64)a[ 5]) * b[13]
                 + ((sp_uint64)a[ 6]) * b[12]
                 + ((sp_uint64)a[ 7]) * b[11]
                 + ((sp_uint64)a[ 8]) * b[10]
                 + ((sp_uint64)a[ 9]) * b[ 9]
                 + ((sp_uint64)a[10]) * b[ 8]
                 + ((sp_uint64)a[11]) * b[ 7]
                 + ((sp_uint64)a[12]) * b[ 6]
                 + ((sp_uint64)a[13]) * b[ 5];
    sp_uint64 t19  = ((sp_uint64)a[ 6]) * b[13]
                 + ((sp_uint64)a[ 7]) * b[12]
                 + ((sp_uint64)a[ 8]) * b[11]
                 + ((sp_uint64)a[ 9]) * b[10]
                 + ((sp_uint64)a[10]) * b[ 9]
                 + ((sp_uint64)a[11]) * b[ 8]
                 + ((sp_uint64)a[12]) * b[ 7]
                 + ((sp_uint64)a[13]) * b[ 6];
    sp_uint64 t20  = ((sp_uint64)a[ 7]) * b[13]
                 + ((sp_uint64)a[ 8]) * b[12]
                 + ((sp_uint64)a[ 9]) * b[11]
                 + ((sp_uint64)a[10]) * b[10]
                 + ((sp_uint64)a[11]) * b[ 9]
                 + ((sp_uint64)a[12]) * b[ 8]
                 + ((sp_uint64)a[13]) * b[ 7];
    sp_uint64 t21  = ((sp_uint64)a[ 8]) * b[13]
                 + ((sp_uint64)a[ 9]) * b[12]
                 + ((sp_uint64)a[10]) * b[11]
                 + ((sp_uint64)a[11]) * b[10]
                 + ((sp_uint64)a[12]) * b[ 9]
                 + ((sp_uint64)a[13]) * b[ 8];
    sp_uint64 t22  = ((sp_uint64)a[ 9]) * b[13]
                 + ((sp_uint64)a[10]) * b[12]
                 + ((sp_uint64)a[11]) * b[11]
                 + ((sp_uint64)a[12]) * b[10]
                 + ((sp_uint64)a[13]) * b[ 9];
    sp_uint64 t23  = ((sp_uint64)a[10]) * b[13]
                 + ((sp_uint64)a[11]) * b[12]
                 + ((sp_uint64)a[12]) * b[11]
                 + ((sp_uint64)a[13]) * b[10];
    sp_uint64 t24  = ((sp_uint64)a[11]) * b[13]
                 + ((sp_uint64)a[12]) * b[12]
                 + ((sp_uint64)a[13]) * b[11];
    sp_uint64 t25  = ((sp_uint64)a[12]) * b[13]
                 + ((sp_uint64)a[13]) * b[12];
    sp_uint64 t26  = ((sp_uint64)a[13]) * b[13];

    t1   += t0  >> 28; r[ 0] = t0  & 0xfffffff;
    t2   += t1  >> 28; r[ 1] = t1  & 0xfffffff;
    t3   += t2  >> 28; r[ 2] = t2  & 0xfffffff;
    t4   += t3  >> 28; r[ 3] = t3  & 0xfffffff;
    t5   += t4  >> 28; r[ 4] = t4  & 0xfffffff;
    t6   += t5  >> 28; r[ 5] = t5  & 0xfffffff;
    t7   += t6  >> 28; r[ 6] = t6  & 0xfffffff;
    t8   += t7  >> 28; r[ 7] = t7  & 0xfffffff;
    t9   += t8  >> 28; r[ 8] = t8  & 0xfffffff;
    t10  += t9  >> 28; r[ 9] = t9  & 0xfffffff;
    t11  += t10 >> 28; r[10] = t10 & 0xfffffff;
    t12  += t11 >> 28; r[11] = t11 & 0xfffffff;
    t13  += t12 >> 28; r[12] = t12 & 0xfffffff;
    t14  += t13 >> 28; r[13] = t13 & 0xfffffff;
    t15  += t14 >> 28; r[14] = t14 & 0xfffffff;
    t16  += t15 >> 28; r[15] = t15 & 0xfffffff;
    t17  += t16 >> 28; r[16] = t16 & 0xfffffff;
    t18  += t17 >> 28; r[17] = t17 & 0xfffffff;
    t19  += t18 >> 28; r[18] = t18 & 0xfffffff;
    t20  += t19 >> 28; r[19] = t19 & 0xfffffff;
    t21  += t20 >> 28; r[20] = t20 & 0xfffffff;
    t22  += t21 >> 28; r[21] = t21 & 0xfffffff;
    t23  += t22 >> 28; r[22] = t22 & 0xfffffff;
    t24  += t23 >> 28; r[23] = t23 & 0xfffffff;
    t25  += t24 >> 28; r[24] = t24 & 0xfffffff;
    t26  += t25 >> 28; r[25] = t25 & 0xfffffff;
    r[27] = (sp_digit)(t26 >> 28);
                       r[26] = t26 & 0xfffffff;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_14(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    r[ 0] = a[ 0] + b[ 0];
    r[ 1] = a[ 1] + b[ 1];
    r[ 2] = a[ 2] + b[ 2];
    r[ 3] = a[ 3] + b[ 3];
    r[ 4] = a[ 4] + b[ 4];
    r[ 5] = a[ 5] + b[ 5];
    r[ 6] = a[ 6] + b[ 6];
    r[ 7] = a[ 7] + b[ 7];
    r[ 8] = a[ 8] + b[ 8];
    r[ 9] = a[ 9] + b[ 9];
    r[10] = a[10] + b[10];
    r[11] = a[11] + b[11];
    r[12] = a[12] + b[12];
    r[13] = a[13] + b[13];

    return 0;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_28(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 24; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[24] = a[24] + b[24];
    r[25] = a[25] + b[25];
    r[26] = a[26] + b[26];
    r[27] = a[27] + b[27];

    return 0;
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_sub_28(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 24; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }
    r[24] = a[24] - b[24];
    r[25] = a[25] - b[25];
    r[26] = a[26] - b[26];
    r[27] = a[27] - b[27];

    return 0;
}

/* Normalize the values in each word to 28 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_3072_norm_14(sp_digit* a)
{
    a[1] += a[0] >> 28; a[0] &= 0xfffffff;
    a[2] += a[1] >> 28; a[1] &= 0xfffffff;
    a[3] += a[2] >> 28; a[2] &= 0xfffffff;
    a[4] += a[3] >> 28; a[3] &= 0xfffffff;
    a[5] += a[4] >> 28; a[4] &= 0xfffffff;
    a[6] += a[5] >> 28; a[5] &= 0xfffffff;
    a[7] += a[6] >> 28; a[6] &= 0xfffffff;
    a[8] += a[7] >> 28; a[7] &= 0xfffffff;
    a[9] += a[8] >> 28; a[8] &= 0xfffffff;
    a[10] += a[9] >> 28; a[9] &= 0xfffffff;
    a[11] += a[10] >> 28; a[10] &= 0xfffffff;
    a[12] += a[11] >> 28; a[11] &= 0xfffffff;
    a[13] += a[12] >> 28; a[12] &= 0xfffffff;
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_28(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[28];
    sp_digit* a1 = z1;
    sp_digit b1[14];
    sp_digit* z2 = r + 28;
    (void)sp_3072_add_14(a1, a, &a[14]);
    sp_3072_norm_14(a1);
    (void)sp_3072_add_14(b1, b, &b[14]);
    sp_3072_norm_14(b1);
    sp_3072_mul_14(z2, &a[14], &b[14]);
    sp_3072_mul_14(z0, a, b);
    sp_3072_mul_14(z1, a1, b1);
    (void)sp_3072_sub_28(z1, z1, z2);
    (void)sp_3072_sub_28(z1, z1, z0);
    (void)sp_3072_add_28(r + 14, r + 14, z1);
    sp_3072_norm_56(r);
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_56(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 56; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }

    return 0;
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_sub_56(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 56; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }

    return 0;
}

/* Normalize the values in each word to 28 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_3072_norm_28(sp_digit* a)
{
    int i;
    for (i = 0; i < 24; i += 8) {
        a[i+1] += a[i+0] >> 28; a[i+0] &= 0xfffffff;
        a[i+2] += a[i+1] >> 28; a[i+1] &= 0xfffffff;
        a[i+3] += a[i+2] >> 28; a[i+2] &= 0xfffffff;
        a[i+4] += a[i+3] >> 28; a[i+3] &= 0xfffffff;
        a[i+5] += a[i+4] >> 28; a[i+4] &= 0xfffffff;
        a[i+6] += a[i+5] >> 28; a[i+5] &= 0xfffffff;
        a[i+7] += a[i+6] >> 28; a[i+6] &= 0xfffffff;
        a[i+8] += a[i+7] >> 28; a[i+7] &= 0xfffffff;
    }
    a[25] += a[24] >> 28; a[24] &= 0xfffffff;
    a[26] += a[25] >> 28; a[25] &= 0xfffffff;
    a[27] += a[26] >> 28; a[26] &= 0xfffffff;
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_56(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[56];
    sp_digit* a1 = z1;
    sp_digit b1[28];
    sp_digit* z2 = r + 56;
    (void)sp_3072_add_28(a1, a, &a[28]);
    sp_3072_norm_28(a1);
    (void)sp_3072_add_28(b1, b, &b[28]);
    sp_3072_norm_28(b1);
    sp_3072_mul_28(z2, &a[28], &b[28]);
    sp_3072_mul_28(z0, a, b);
    sp_3072_mul_28(z1, a1, b1);
    (void)sp_3072_sub_56(z1, z1, z2);
    (void)sp_3072_sub_56(z1, z1, z0);
    (void)sp_3072_add_56(r + 28, r + 28, z1);
    sp_3072_norm_112(r);
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_112(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 112; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }

    return 0;
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_sub_112(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 112; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }

    return 0;
}

/* Normalize the values in each word to 28 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_3072_norm_224(sp_digit* a)
{
    int i;
    for (i = 0; i < 216; i += 8) {
        a[i+1] += a[i+0] >> 28; a[i+0] &= 0xfffffff;
        a[i+2] += a[i+1] >> 28; a[i+1] &= 0xfffffff;
        a[i+3] += a[i+2] >> 28; a[i+2] &= 0xfffffff;
        a[i+4] += a[i+3] >> 28; a[i+3] &= 0xfffffff;
        a[i+5] += a[i+4] >> 28; a[i+4] &= 0xfffffff;
        a[i+6] += a[i+5] >> 28; a[i+5] &= 0xfffffff;
        a[i+7] += a[i+6] >> 28; a[i+6] &= 0xfffffff;
        a[i+8] += a[i+7] >> 28; a[i+7] &= 0xfffffff;
    }
    a[217] += a[216] >> 28; a[216] &= 0xfffffff;
    a[218] += a[217] >> 28; a[217] &= 0xfffffff;
    a[219] += a[218] >> 28; a[218] &= 0xfffffff;
    a[220] += a[219] >> 28; a[219] &= 0xfffffff;
    a[221] += a[220] >> 28; a[220] &= 0xfffffff;
    a[222] += a[221] >> 28; a[221] &= 0xfffffff;
    a[223] += a[222] >> 28; a[222] &= 0xfffffff;
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_112(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[112];
    sp_digit* a1 = z1;
    sp_digit b1[56];
    sp_digit* z2 = r + 112;
    (void)sp_3072_add_56(a1, a, &a[56]);
    sp_3072_norm_56(a1);
    (void)sp_3072_add_56(b1, b, &b[56]);
    sp_3072_norm_56(b1);
    sp_3072_mul_56(z2, &a[56], &b[56]);
    sp_3072_mul_56(z0, a, b);
    sp_3072_mul_56(z1, a1, b1);
    (void)sp_3072_sub_112(z1, z1, z2);
    (void)sp_3072_sub_112(z1, z1, z0);
    (void)sp_3072_add_112(r + 56, r + 56, z1);
    sp_3072_norm_224(r);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_14(sp_digit* r, const sp_digit* a)
{
    sp_uint64 t0   =  ((sp_uint64)a[ 0]) * a[ 0];
    sp_uint64 t1   = (((sp_uint64)a[ 0]) * a[ 1]) * 2;
    sp_uint64 t2   = (((sp_uint64)a[ 0]) * a[ 2]) * 2
                 +  ((sp_uint64)a[ 1]) * a[ 1];
    sp_uint64 t3   = (((sp_uint64)a[ 0]) * a[ 3]
                 +  ((sp_uint64)a[ 1]) * a[ 2]) * 2;
    sp_uint64 t4   = (((sp_uint64)a[ 0]) * a[ 4]
                 +  ((sp_uint64)a[ 1]) * a[ 3]) * 2
                 +  ((sp_uint64)a[ 2]) * a[ 2];
    sp_uint64 t5   = (((sp_uint64)a[ 0]) * a[ 5]
                 +  ((sp_uint64)a[ 1]) * a[ 4]
                 +  ((sp_uint64)a[ 2]) * a[ 3]) * 2;
    sp_uint64 t6   = (((sp_uint64)a[ 0]) * a[ 6]
                 +  ((sp_uint64)a[ 1]) * a[ 5]
                 +  ((sp_uint64)a[ 2]) * a[ 4]) * 2
                 +  ((sp_uint64)a[ 3]) * a[ 3];
    sp_uint64 t7   = (((sp_uint64)a[ 0]) * a[ 7]
                 +  ((sp_uint64)a[ 1]) * a[ 6]
                 +  ((sp_uint64)a[ 2]) * a[ 5]
                 +  ((sp_uint64)a[ 3]) * a[ 4]) * 2;
    sp_uint64 t8   = (((sp_uint64)a[ 0]) * a[ 8]
                 +  ((sp_uint64)a[ 1]) * a[ 7]
                 +  ((sp_uint64)a[ 2]) * a[ 6]
                 +  ((sp_uint64)a[ 3]) * a[ 5]) * 2
                 +  ((sp_uint64)a[ 4]) * a[ 4];
    sp_uint64 t9   = (((sp_uint64)a[ 0]) * a[ 9]
                 +  ((sp_uint64)a[ 1]) * a[ 8]
                 +  ((sp_uint64)a[ 2]) * a[ 7]
                 +  ((sp_uint64)a[ 3]) * a[ 6]
                 +  ((sp_uint64)a[ 4]) * a[ 5]) * 2;
    sp_uint64 t10  = (((sp_uint64)a[ 0]) * a[10]
                 +  ((sp_uint64)a[ 1]) * a[ 9]
                 +  ((sp_uint64)a[ 2]) * a[ 8]
                 +  ((sp_uint64)a[ 3]) * a[ 7]
                 +  ((sp_uint64)a[ 4]) * a[ 6]) * 2
                 +  ((sp_uint64)a[ 5]) * a[ 5];
    sp_uint64 t11  = (((sp_uint64)a[ 0]) * a[11]
                 +  ((sp_uint64)a[ 1]) * a[10]
                 +  ((sp_uint64)a[ 2]) * a[ 9]
                 +  ((sp_uint64)a[ 3]) * a[ 8]
                 +  ((sp_uint64)a[ 4]) * a[ 7]
                 +  ((sp_uint64)a[ 5]) * a[ 6]) * 2;
    sp_uint64 t12  = (((sp_uint64)a[ 0]) * a[12]
                 +  ((sp_uint64)a[ 1]) * a[11]
                 +  ((sp_uint64)a[ 2]) * a[10]
                 +  ((sp_uint64)a[ 3]) * a[ 9]
                 +  ((sp_uint64)a[ 4]) * a[ 8]
                 +  ((sp_uint64)a[ 5]) * a[ 7]) * 2
                 +  ((sp_uint64)a[ 6]) * a[ 6];
    sp_uint64 t13  = (((sp_uint64)a[ 0]) * a[13]
                 +  ((sp_uint64)a[ 1]) * a[12]
                 +  ((sp_uint64)a[ 2]) * a[11]
                 +  ((sp_uint64)a[ 3]) * a[10]
                 +  ((sp_uint64)a[ 4]) * a[ 9]
                 +  ((sp_uint64)a[ 5]) * a[ 8]
                 +  ((sp_uint64)a[ 6]) * a[ 7]) * 2;
    sp_uint64 t14  = (((sp_uint64)a[ 1]) * a[13]
                 +  ((sp_uint64)a[ 2]) * a[12]
                 +  ((sp_uint64)a[ 3]) * a[11]
                 +  ((sp_uint64)a[ 4]) * a[10]
                 +  ((sp_uint64)a[ 5]) * a[ 9]
                 +  ((sp_uint64)a[ 6]) * a[ 8]) * 2
                 +  ((sp_uint64)a[ 7]) * a[ 7];
    sp_uint64 t15  = (((sp_uint64)a[ 2]) * a[13]
                 +  ((sp_uint64)a[ 3]) * a[12]
                 +  ((sp_uint64)a[ 4]) * a[11]
                 +  ((sp_uint64)a[ 5]) * a[10]
                 +  ((sp_uint64)a[ 6]) * a[ 9]
                 +  ((sp_uint64)a[ 7]) * a[ 8]) * 2;
    sp_uint64 t16  = (((sp_uint64)a[ 3]) * a[13]
                 +  ((sp_uint64)a[ 4]) * a[12]
                 +  ((sp_uint64)a[ 5]) * a[11]
                 +  ((sp_uint64)a[ 6]) * a[10]
                 +  ((sp_uint64)a[ 7]) * a[ 9]) * 2
                 +  ((sp_uint64)a[ 8]) * a[ 8];
    sp_uint64 t17  = (((sp_uint64)a[ 4]) * a[13]
                 +  ((sp_uint64)a[ 5]) * a[12]
                 +  ((sp_uint64)a[ 6]) * a[11]
                 +  ((sp_uint64)a[ 7]) * a[10]
                 +  ((sp_uint64)a[ 8]) * a[ 9]) * 2;
    sp_uint64 t18  = (((sp_uint64)a[ 5]) * a[13]
                 +  ((sp_uint64)a[ 6]) * a[12]
                 +  ((sp_uint64)a[ 7]) * a[11]
                 +  ((sp_uint64)a[ 8]) * a[10]) * 2
                 +  ((sp_uint64)a[ 9]) * a[ 9];
    sp_uint64 t19  = (((sp_uint64)a[ 6]) * a[13]
                 +  ((sp_uint64)a[ 7]) * a[12]
                 +  ((sp_uint64)a[ 8]) * a[11]
                 +  ((sp_uint64)a[ 9]) * a[10]) * 2;
    sp_uint64 t20  = (((sp_uint64)a[ 7]) * a[13]
                 +  ((sp_uint64)a[ 8]) * a[12]
                 +  ((sp_uint64)a[ 9]) * a[11]) * 2
                 +  ((sp_uint64)a[10]) * a[10];
    sp_uint64 t21  = (((sp_uint64)a[ 8]) * a[13]
                 +  ((sp_uint64)a[ 9]) * a[12]
                 +  ((sp_uint64)a[10]) * a[11]) * 2;
    sp_uint64 t22  = (((sp_uint64)a[ 9]) * a[13]
                 +  ((sp_uint64)a[10]) * a[12]) * 2
                 +  ((sp_uint64)a[11]) * a[11];
    sp_uint64 t23  = (((sp_uint64)a[10]) * a[13]
                 +  ((sp_uint64)a[11]) * a[12]) * 2;
    sp_uint64 t24  = (((sp_uint64)a[11]) * a[13]) * 2
                 +  ((sp_uint64)a[12]) * a[12];
    sp_uint64 t25  = (((sp_uint64)a[12]) * a[13]) * 2;
    sp_uint64 t26  =  ((sp_uint64)a[13]) * a[13];

    t1   += t0  >> 28; r[ 0] = t0  & 0xfffffff;
    t2   += t1  >> 28; r[ 1] = t1  & 0xfffffff;
    t3   += t2  >> 28; r[ 2] = t2  & 0xfffffff;
    t4   += t3  >> 28; r[ 3] = t3  & 0xfffffff;
    t5   += t4  >> 28; r[ 4] = t4  & 0xfffffff;
    t6   += t5  >> 28; r[ 5] = t5  & 0xfffffff;
    t7   += t6  >> 28; r[ 6] = t6  & 0xfffffff;
    t8   += t7  >> 28; r[ 7] = t7  & 0xfffffff;
    t9   += t8  >> 28; r[ 8] = t8  & 0xfffffff;
    t10  += t9  >> 28; r[ 9] = t9  & 0xfffffff;
    t11  += t10 >> 28; r[10] = t10 & 0xfffffff;
    t12  += t11 >> 28; r[11] = t11 & 0xfffffff;
    t13  += t12 >> 28; r[12] = t12 & 0xfffffff;
    t14  += t13 >> 28; r[13] = t13 & 0xfffffff;
    t15  += t14 >> 28; r[14] = t14 & 0xfffffff;
    t16  += t15 >> 28; r[15] = t15 & 0xfffffff;
    t17  += t16 >> 28; r[16] = t16 & 0xfffffff;
    t18  += t17 >> 28; r[17] = t17 & 0xfffffff;
    t19  += t18 >> 28; r[18] = t18 & 0xfffffff;
    t20  += t19 >> 28; r[19] = t19 & 0xfffffff;
    t21  += t20 >> 28; r[20] = t20 & 0xfffffff;
    t22  += t21 >> 28; r[21] = t21 & 0xfffffff;
    t23  += t22 >> 28; r[22] = t22 & 0xfffffff;
    t24  += t23 >> 28; r[23] = t23 & 0xfffffff;
    t25  += t24 >> 28; r[24] = t24 & 0xfffffff;
    t26  += t25 >> 28; r[25] = t25 & 0xfffffff;
    r[27] = (sp_digit)(t26 >> 28);
                       r[26] = t26 & 0xfffffff;
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_28(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit z1[28];
    sp_digit* a1 = z1;
    sp_digit* z2 = r + 28;
    (void)sp_3072_add_14(a1, a, &a[14]);
    sp_3072_norm_14(a1);
    sp_3072_sqr_14(z2, &a[14]);
    sp_3072_sqr_14(z0, a);
    sp_3072_sqr_14(z1, a1);
    (void)sp_3072_sub_28(z1, z1, z2);
    (void)sp_3072_sub_28(z1, z1, z0);
    (void)sp_3072_add_28(r + 14, r + 14, z1);
    sp_3072_norm_56(r);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_56(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit z1[56];
    sp_digit* a1 = z1;
    sp_digit* z2 = r + 56;
    (void)sp_3072_add_28(a1, a, &a[28]);
    sp_3072_norm_28(a1);
    sp_3072_sqr_28(z2, &a[28]);
    sp_3072_sqr_28(z0, a);
    sp_3072_sqr_28(z1, a1);
    (void)sp_3072_sub_56(z1, z1, z2);
    (void)sp_3072_sub_56(z1, z1, z0);
    (void)sp_3072_add_56(r + 28, r + 28, z1);
    sp_3072_norm_112(r);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_112(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit z1[112];
    sp_digit* a1 = z1;
    sp_digit* z2 = r + 112;
    (void)sp_3072_add_56(a1, a, &a[56]);
    sp_3072_norm_56(a1);
    sp_3072_sqr_56(z2, &a[56]);
    sp_3072_sqr_56(z0, a);
    sp_3072_sqr_56(z1, a1);
    (void)sp_3072_sub_112(z1, z1, z2);
    (void)sp_3072_sub_112(z1, z1, z0);
    (void)sp_3072_add_112(r + 56, r + 56, z1);
    sp_3072_norm_224(r);
}

#endif /* !WOLFSSL_SP_SMALL */
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
    x &= 0xfffffff;

    /* rho = -1/m mod b */
    *rho = ((sp_digit)1 << 28) - x;
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_d_112(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int64 tb = b;
    sp_int64 t = 0;
    sp_digit t2;
    sp_int64 p[4];
    int i;

    for (i = 0; i < 112; i += 4) {
        p[0] = tb * a[i + 0];
        p[1] = tb * a[i + 1];
        p[2] = tb * a[i + 2];
        p[3] = tb * a[i + 3];
        t += p[0];
        t2 = (sp_digit)(t & 0xfffffff);
        t >>= 28;
        r[i + 0] = (sp_digit)t2;
        t += p[1];
        t2 = (sp_digit)(t & 0xfffffff);
        t >>= 28;
        r[i + 1] = (sp_digit)t2;
        t += p[2];
        t2 = (sp_digit)(t & 0xfffffff);
        t >>= 28;
        r[i + 2] = (sp_digit)t2;
        t += p[3];
        t2 = (sp_digit)(t & 0xfffffff);
        t >>= 28;
        r[i + 3] = (sp_digit)t2;
    }
    r[112] = (sp_digit)(t & 0xfffffff);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 3072 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_3072_mont_norm_56(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
    int i;

    for (i = 0; i < 48; i += 8) {
        r[i + 0] = 0xfffffff;
        r[i + 1] = 0xfffffff;
        r[i + 2] = 0xfffffff;
        r[i + 3] = 0xfffffff;
        r[i + 4] = 0xfffffff;
        r[i + 5] = 0xfffffff;
        r[i + 6] = 0xfffffff;
        r[i + 7] = 0xfffffff;
    }
    r[48] = 0xfffffff;
    r[49] = 0xfffffff;
    r[50] = 0xfffffff;
    r[51] = 0xfffffff;
    r[52] = 0xfffffff;
    r[53] = 0xfffffff;
    r[54] = 0xffffffL;
    r[55] = 0;

    /* r = (2^n - 1) mod n */
    (void)sp_3072_sub_56(r, r, m);

    /* Add one so r = 2^n mod m */
    r[0] += 1;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_3072_cmp_56(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
    int i;

    for (i = 48; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & ~(((sp_digit)0 - r) >> 27);
        r |= (a[i + 6] - b[i + 6]) & ~(((sp_digit)0 - r) >> 27);
        r |= (a[i + 5] - b[i + 5]) & ~(((sp_digit)0 - r) >> 27);
        r |= (a[i + 4] - b[i + 4]) & ~(((sp_digit)0 - r) >> 27);
        r |= (a[i + 3] - b[i + 3]) & ~(((sp_digit)0 - r) >> 27);
        r |= (a[i + 2] - b[i + 2]) & ~(((sp_digit)0 - r) >> 27);
        r |= (a[i + 1] - b[i + 1]) & ~(((sp_digit)0 - r) >> 27);
        r |= (a[i + 0] - b[i + 0]) & ~(((sp_digit)0 - r) >> 27);
    }

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_3072_cond_sub_56(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 56; i += 8) {
        r[i + 0] = a[i + 0] - (b[i + 0] & m);
        r[i + 1] = a[i + 1] - (b[i + 1] & m);
        r[i + 2] = a[i + 2] - (b[i + 2] & m);
        r[i + 3] = a[i + 3] - (b[i + 3] & m);
        r[i + 4] = a[i + 4] - (b[i + 4] & m);
        r[i + 5] = a[i + 5] - (b[i + 5] & m);
        r[i + 6] = a[i + 6] - (b[i + 6] & m);
        r[i + 7] = a[i + 7] - (b[i + 7] & m);
    }
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_add_56(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifndef WOLFSSL_SP_LARGE_CODE
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 56; i++) {
        t += r[i];
        t += tb * a[i];
        r[i] = ((sp_digit)t) & 0xfffffff;
        t >>= 28;
    }
    r[56] += (sp_digit)t;
#else
    sp_int64 tb = b;
    sp_int64 t[8];
    int i;

    t[0] = 0;
    for (i = 0; i < 48; i += 8) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        t[4]  = (tb * a[i+4]) + r[i+4];
        t[5]  = (tb * a[i+5]) + r[i+5];
        t[6]  = (tb * a[i+6]) + r[i+6];
        t[7]  = (tb * a[i+7]) + r[i+7];
        r[i+0] = t[0] & 0xfffffff;
        t[1] += t[0] >> 28;
        r[i+1] = t[1] & 0xfffffff;
        t[2] += t[1] >> 28;
        r[i+2] = t[2] & 0xfffffff;
        t[3] += t[2] >> 28;
        r[i+3] = t[3] & 0xfffffff;
        t[4] += t[3] >> 28;
        r[i+4] = t[4] & 0xfffffff;
        t[5] += t[4] >> 28;
        r[i+5] = t[5] & 0xfffffff;
        t[6] += t[5] >> 28;
        r[i+6] = t[6] & 0xfffffff;
        t[7] += t[6] >> 28;
        r[i+7] = t[7] & 0xfffffff;
        t[0]  = t[7] >> 28;
    }
    t[0] += (tb * a[48]) + r[48];
    t[1]  = (tb * a[49]) + r[49];
    t[2]  = (tb * a[50]) + r[50];
    t[3]  = (tb * a[51]) + r[51];
    t[4]  = (tb * a[52]) + r[52];
    t[5]  = (tb * a[53]) + r[53];
    t[6]  = (tb * a[54]) + r[54];
    t[7]  = (tb * a[55]) + r[55];
    r[48] = t[0] & 0xfffffff;
    t[1] += t[0] >> 28;
    r[49] = t[1] & 0xfffffff;
    t[2] += t[1] >> 28;
    r[50] = t[2] & 0xfffffff;
    t[3] += t[2] >> 28;
    r[51] = t[3] & 0xfffffff;
    t[4] += t[3] >> 28;
    r[52] = t[4] & 0xfffffff;
    t[5] += t[4] >> 28;
    r[53] = t[5] & 0xfffffff;
    t[6] += t[5] >> 28;
    r[54] = t[6] & 0xfffffff;
    t[7] += t[6] >> 28;
    r[55] = t[7] & 0xfffffff;
    r[56] +=  (sp_digit)(t[7] >> 28);
#endif /* !WOLFSSL_SP_LARGE_CODE */
}

/* Shift the result in the high 1536 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_3072_mont_shift_56(sp_digit* r, const sp_digit* a)
{
    int i;
    sp_int64 n = a[54] >> 24;
    n += ((sp_int64)a[55]) << 4;
    for (i = 0; i < 48; i += 8) {
        r[i + 0] = n & 0xfffffff;
        n >>= 28; n += ((sp_int64)a[i + 56]) << 4;
        r[i + 1] = n & 0xfffffff;
        n >>= 28; n += ((sp_int64)a[i + 57]) << 4;
        r[i + 2] = n & 0xfffffff;
        n >>= 28; n += ((sp_int64)a[i + 58]) << 4;
        r[i + 3] = n & 0xfffffff;
        n >>= 28; n += ((sp_int64)a[i + 59]) << 4;
        r[i + 4] = n & 0xfffffff;
        n >>= 28; n += ((sp_int64)a[i + 60]) << 4;
        r[i + 5] = n & 0xfffffff;
        n >>= 28; n += ((sp_int64)a[i + 61]) << 4;
        r[i + 6] = n & 0xfffffff;
        n >>= 28; n += ((sp_int64)a[i + 62]) << 4;
        r[i + 7] = n & 0xfffffff;
        n >>= 28; n += ((sp_int64)a[i + 63]) << 4;
    }
    r[48] = n & 0xfffffff; n >>= 28; n += ((sp_int64)a[104]) << 4;
    r[49] = n & 0xfffffff; n >>= 28; n += ((sp_int64)a[105]) << 4;
    r[50] = n & 0xfffffff; n >>= 28; n += ((sp_int64)a[106]) << 4;
    r[51] = n & 0xfffffff; n >>= 28; n += ((sp_int64)a[107]) << 4;
    r[52] = n & 0xfffffff; n >>= 28; n += ((sp_int64)a[108]) << 4;
    r[53] = n & 0xfffffff; n >>= 28; n += ((sp_int64)a[109]) << 4;
    r[54] = (sp_digit)n;
    XMEMSET(&r[55], 0, sizeof(*r) * 55U);
}

/* Reduce the number back to 3072 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_3072_mont_reduce_56(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_3072_norm_56(a + 55);

    for (i=0; i<54; i++) {
        mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0xfffffff;
        sp_3072_mul_add_56(a+i, m, mu);
        a[i+1] += a[i] >> 28;
    }
    mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0xffffffL;
    sp_3072_mul_add_56(a+i, m, mu);
    a[i+1] += a[i] >> 28;
    a[i] &= 0xfffffff;
    sp_3072_mont_shift_56(a, a);
    over = a[54] - m[54];
    sp_3072_cond_sub_56(a, a, m, ~((over - 1) >> 31));
    sp_3072_norm_56(a);
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
SP_NOINLINE static void sp_3072_mont_mul_56(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_3072_mul_56(r, a, b);
    sp_3072_mont_reduce_56(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_3072_mont_sqr_56(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_3072_sqr_56(r, a);
    sp_3072_mont_reduce_56(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_d_56(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int64 tb = b;
    sp_int64 t = 0;
    sp_digit t2;
    sp_int64 p[4];
    int i;

    for (i = 0; i < 56; i += 4) {
        p[0] = tb * a[i + 0];
        p[1] = tb * a[i + 1];
        p[2] = tb * a[i + 2];
        p[3] = tb * a[i + 3];
        t += p[0];
        t2 = (sp_digit)(t & 0xfffffff);
        t >>= 28;
        r[i + 0] = (sp_digit)t2;
        t += p[1];
        t2 = (sp_digit)(t & 0xfffffff);
        t >>= 28;
        r[i + 1] = (sp_digit)t2;
        t += p[2];
        t2 = (sp_digit)(t & 0xfffffff);
        t >>= 28;
        r[i + 2] = (sp_digit)t2;
        t += p[3];
        t2 = (sp_digit)(t & 0xfffffff);
        t >>= 28;
        r[i + 3] = (sp_digit)t2;
    }
    r[56] = (sp_digit)(t & 0xfffffff);
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
static void sp_3072_cond_add_56(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 56; i += 8) {
        r[i + 0] = a[i + 0] + (b[i + 0] & m);
        r[i + 1] = a[i + 1] + (b[i + 1] & m);
        r[i + 2] = a[i + 2] + (b[i + 2] & m);
        r[i + 3] = a[i + 3] + (b[i + 3] & m);
        r[i + 4] = a[i + 4] + (b[i + 4] & m);
        r[i + 5] = a[i + 5] + (b[i + 5] & m);
        r[i + 6] = a[i + 6] + (b[i + 6] & m);
        r[i + 7] = a[i + 7] + (b[i + 7] & m);
    }
}
#endif /* !WOLFSSL_SP_SMALL */

SP_NOINLINE static void sp_3072_rshift_56(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    for (i=0; i<48; i += 8) {
        r[i+0] = (a[i+0] >> n) | ((a[i+1] << (28 - n)) & 0xfffffff);
        r[i+1] = (a[i+1] >> n) | ((a[i+2] << (28 - n)) & 0xfffffff);
        r[i+2] = (a[i+2] >> n) | ((a[i+3] << (28 - n)) & 0xfffffff);
        r[i+3] = (a[i+3] >> n) | ((a[i+4] << (28 - n)) & 0xfffffff);
        r[i+4] = (a[i+4] >> n) | ((a[i+5] << (28 - n)) & 0xfffffff);
        r[i+5] = (a[i+5] >> n) | ((a[i+6] << (28 - n)) & 0xfffffff);
        r[i+6] = (a[i+6] >> n) | ((a[i+7] << (28 - n)) & 0xfffffff);
        r[i+7] = (a[i+7] >> n) | ((a[i+8] << (28 - n)) & 0xfffffff);
    }
    r[48] = (a[48] >> n) | ((a[49] << (28 - n)) & 0xfffffff);
    r[49] = (a[49] >> n) | ((a[50] << (28 - n)) & 0xfffffff);
    r[50] = (a[50] >> n) | ((a[51] << (28 - n)) & 0xfffffff);
    r[51] = (a[51] >> n) | ((a[52] << (28 - n)) & 0xfffffff);
    r[52] = (a[52] >> n) | ((a[53] << (28 - n)) & 0xfffffff);
    r[53] = (a[53] >> n) | ((a[54] << (28 - n)) & 0xfffffff);
    r[54] = (a[54] >> n) | ((a[55] << (28 - n)) & 0xfffffff);
    r[55] = a[55] >> n;
}

static WC_INLINE sp_digit sp_3072_div_word_56(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int64 d = ((sp_int64)d1 << 28) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int64 d = ((sp_int64)d1 << 28) + d0;
    sp_uint32 lo = (sp_uint32)d;
    sp_digit hi = (sp_digit)(d >> 32);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int64 d = ((sp_int64)d1 << 28) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 28);
    sp_digit t0 = (sp_digit)(d & 0xfffffff);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int64 m;

    r = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
    t1 -= dv & (0 - r);
    for (i = 26; i >= 1; i--) {
        t1 += t1 + (((sp_uint32)t0 >> 27) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int64)r * div);
    r += (sp_digit)(m >> 28);
    m = d - ((sp_int64)r * div);
    r += (m >> 56) - (sp_digit)(d >> 56);

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;
   return r;
#else
    sp_int64 d = ((sp_int64)d1 << 28) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 13) + 1;

    t = (sp_digit)(d >> 26);
    t = (t / dv) << 13;
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)(d >> 11);
    t = t / (dv << 2);
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int64)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_3072_word_div_word_56(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint32)(div - d) >> 31);
#endif
}
/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * Full implementation.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_3072_div_56(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_32
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 56 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 112 + 1;
        sd = t2 + 56 + 1;

        sp_3072_mul_d_56(sd, d, (sp_digit)1 << 4);
        sp_3072_mul_d_112(t1, a, (sp_digit)1 << 4);
        dv = sd[54];
        t1[55 + 55] += t1[55 + 55 - 1] >> 28;
        t1[55 + 55 - 1] &= 0xfffffff;
        for (i=55; i>=0; i--) {
            r1 = sp_3072_div_word_56(t1[55 + i], t1[55 + i - 1], dv);

            sp_3072_mul_d_56(t2, sd, r1);
            (void)sp_3072_sub_56(&t1[i], &t1[i], t2);
            sp_3072_norm_55(&t1[i]);
            t1[55 + i] += t1[55 + i - 1] >> 28;
            t1[55 + i - 1] &= 0xfffffff;
            r1 = sp_3072_div_word_56(-t1[55 + i], -t1[55 + i - 1], dv);
            r1 -= t1[55 + i];
            sp_3072_mul_d_56(t2, sd, r1);
            (void)sp_3072_add_56(&t1[i], &t1[i], t2);
            t1[55 + i] += t1[55 + i - 1] >> 28;
            t1[55 + i - 1] &= 0xfffffff;
        }
        t1[55 - 1] += t1[55 - 2] >> 28;
        t1[55 - 2] &= 0xfffffff;
        r1 = sp_3072_word_div_word_56(t1[55 - 1], dv);

        sp_3072_mul_d_56(t2, sd, r1);
        sp_3072_sub_56(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 112U);
        for (i=0; i<54; i++) {
            r[i+1] += r[i] >> 28;
            r[i] &= 0xfffffff;
        }
        sp_3072_cond_add_56(r, r, sd, r[54] >> 31);

        sp_3072_norm_55(r);
        sp_3072_rshift_56(r, r, 4);
        r[55] = 0;
    }


    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_3072_mod_56(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_3072_div_56(a, m, NULL, r);
}

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
static int sp_3072_mod_exp_56(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 112];
    sp_digit* t[3] = {0, 0, 0};
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<3; i++) {
            t[i] = td + (i * 56 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 56U * 2U);
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_56(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_56(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 56U);
        }
    }
    if (err == MP_OKAY) {
        sp_3072_mul_56(t[1], t[1], norm);
        err = sp_3072_mod_56(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 28;
        c = bits % 28;
        n = e[i--] << (28 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 28;
            }

            y = (int)((n >> 27) & 1);
            n <<= 1;

            sp_3072_mont_mul_56(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 56 * 2);
            sp_3072_mont_sqr_56(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 56 * 2);
        }

        sp_3072_mont_reduce_56(t[0], m, mp);
        n = sp_3072_cmp_56(t[0], m);
        sp_3072_cond_sub_56(t[0], t[0], m, ~(n >> 31));
        XMEMCPY(r, t[0], sizeof(*r) * 56 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 112];
    sp_digit* t[3] = {0, 0, 0};
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<3; i++) {
            t[i] = td + (i * 56 * 2);
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_56(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_56(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_56(t[1], t[1], norm);
                err = sp_3072_mod_56(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_56(t[1], a, norm);
            err = sp_3072_mod_56(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 28;
        c = bits % 28;
        n = e[i--] << (28 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 28;
            }

            y = (int)((n >> 27) & 1);
            n <<= 1;

            sp_3072_mont_mul_56(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 56 * 2);
            sp_3072_mont_sqr_56(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 56 * 2);
        }

        sp_3072_mont_reduce_56(t[0], m, mp);
        n = sp_3072_cmp_56(t[0], m);
        sp_3072_cond_sub_56(t[0], t[0], m, ~(n >> 31));
        XMEMCPY(r, t[0], sizeof(*r) * 56 * 2);
    }


    return err;
#else
    sp_digit td[(32 * 112) + 112];
    sp_digit* t[32];
    sp_digit* rt = NULL;
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<32; i++)
            t[i] = td + i * 112;
        rt = td + 3584;

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_56(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_56(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_56(t[1], t[1], norm);
                err = sp_3072_mod_56(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_56(t[1], a, norm);
            err = sp_3072_mod_56(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_3072_mont_sqr_56(t[ 2], t[ 1], m, mp);
        sp_3072_mont_mul_56(t[ 3], t[ 2], t[ 1], m, mp);
        sp_3072_mont_sqr_56(t[ 4], t[ 2], m, mp);
        sp_3072_mont_mul_56(t[ 5], t[ 3], t[ 2], m, mp);
        sp_3072_mont_sqr_56(t[ 6], t[ 3], m, mp);
        sp_3072_mont_mul_56(t[ 7], t[ 4], t[ 3], m, mp);
        sp_3072_mont_sqr_56(t[ 8], t[ 4], m, mp);
        sp_3072_mont_mul_56(t[ 9], t[ 5], t[ 4], m, mp);
        sp_3072_mont_sqr_56(t[10], t[ 5], m, mp);
        sp_3072_mont_mul_56(t[11], t[ 6], t[ 5], m, mp);
        sp_3072_mont_sqr_56(t[12], t[ 6], m, mp);
        sp_3072_mont_mul_56(t[13], t[ 7], t[ 6], m, mp);
        sp_3072_mont_sqr_56(t[14], t[ 7], m, mp);
        sp_3072_mont_mul_56(t[15], t[ 8], t[ 7], m, mp);
        sp_3072_mont_sqr_56(t[16], t[ 8], m, mp);
        sp_3072_mont_mul_56(t[17], t[ 9], t[ 8], m, mp);
        sp_3072_mont_sqr_56(t[18], t[ 9], m, mp);
        sp_3072_mont_mul_56(t[19], t[10], t[ 9], m, mp);
        sp_3072_mont_sqr_56(t[20], t[10], m, mp);
        sp_3072_mont_mul_56(t[21], t[11], t[10], m, mp);
        sp_3072_mont_sqr_56(t[22], t[11], m, mp);
        sp_3072_mont_mul_56(t[23], t[12], t[11], m, mp);
        sp_3072_mont_sqr_56(t[24], t[12], m, mp);
        sp_3072_mont_mul_56(t[25], t[13], t[12], m, mp);
        sp_3072_mont_sqr_56(t[26], t[13], m, mp);
        sp_3072_mont_mul_56(t[27], t[14], t[13], m, mp);
        sp_3072_mont_sqr_56(t[28], t[14], m, mp);
        sp_3072_mont_mul_56(t[29], t[15], t[14], m, mp);
        sp_3072_mont_sqr_56(t[30], t[15], m, mp);
        sp_3072_mont_mul_56(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 27) / 28) - 1;
        c = bits % 28;
        if (c == 0) {
            c = 28;
        }
        if (i < 56) {
            n = e[i--] << (32 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (4 - c);
            c += 28;
        }
        y = (int)((n >> 27) & 0x1f);
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 112);
        while ((i >= 0) || (c >= 5)) {
            if (c >= 5) {
                y = (byte)((n >> 27) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--] << 4;
                y = (byte)((n >> 27) & 0x1f);
                n <<= 5;
                c = 23;
            }
            else {
                y = (byte)((n >> 27) & 0x1f);
                n = e[i--] << 4;
                c = 5 - c;
                y |= (byte)((n >> (32 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 28 - c;
            }

            sp_3072_mont_sqr_56(rt, rt, m, mp);
            sp_3072_mont_sqr_56(rt, rt, m, mp);
            sp_3072_mont_sqr_56(rt, rt, m, mp);
            sp_3072_mont_sqr_56(rt, rt, m, mp);
            sp_3072_mont_sqr_56(rt, rt, m, mp);

            sp_3072_mont_mul_56(rt, rt, t[y], m, mp);
        }

        sp_3072_mont_reduce_56(rt, m, mp);
        n = sp_3072_cmp_56(rt, m);
        sp_3072_cond_sub_56(rt, rt, m, ~(n >> 31));
        XMEMCPY(r, rt, sizeof(sp_digit) * 112);
    }


    return err;
#endif
}

#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) | WOLFSSL_HAVE_SP_DH */

/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 3072 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_3072_mont_norm_112(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
    int i;

    for (i = 0; i < 104; i += 8) {
        r[i + 0] = 0xfffffff;
        r[i + 1] = 0xfffffff;
        r[i + 2] = 0xfffffff;
        r[i + 3] = 0xfffffff;
        r[i + 4] = 0xfffffff;
        r[i + 5] = 0xfffffff;
        r[i + 6] = 0xfffffff;
        r[i + 7] = 0xfffffff;
    }
    r[104] = 0xfffffff;
    r[105] = 0xfffffff;
    r[106] = 0xfffffff;
    r[107] = 0xfffffff;
    r[108] = 0xfffffff;
    r[109] = 0xfffffL;
    r[110] = 0;
    r[111] = 0;

    /* r = (2^n - 1) mod n */
    (void)sp_3072_sub_112(r, r, m);

    /* Add one so r = 2^n mod m */
    r[0] += 1;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_3072_cmp_112(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
    int i;

    for (i = 104; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & ~(((sp_digit)0 - r) >> 27);
        r |= (a[i + 6] - b[i + 6]) & ~(((sp_digit)0 - r) >> 27);
        r |= (a[i + 5] - b[i + 5]) & ~(((sp_digit)0 - r) >> 27);
        r |= (a[i + 4] - b[i + 4]) & ~(((sp_digit)0 - r) >> 27);
        r |= (a[i + 3] - b[i + 3]) & ~(((sp_digit)0 - r) >> 27);
        r |= (a[i + 2] - b[i + 2]) & ~(((sp_digit)0 - r) >> 27);
        r |= (a[i + 1] - b[i + 1]) & ~(((sp_digit)0 - r) >> 27);
        r |= (a[i + 0] - b[i + 0]) & ~(((sp_digit)0 - r) >> 27);
    }

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_3072_cond_sub_112(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 112; i += 8) {
        r[i + 0] = a[i + 0] - (b[i + 0] & m);
        r[i + 1] = a[i + 1] - (b[i + 1] & m);
        r[i + 2] = a[i + 2] - (b[i + 2] & m);
        r[i + 3] = a[i + 3] - (b[i + 3] & m);
        r[i + 4] = a[i + 4] - (b[i + 4] & m);
        r[i + 5] = a[i + 5] - (b[i + 5] & m);
        r[i + 6] = a[i + 6] - (b[i + 6] & m);
        r[i + 7] = a[i + 7] - (b[i + 7] & m);
    }
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_add_112(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifndef WOLFSSL_SP_LARGE_CODE
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 112; i++) {
        t += r[i];
        t += tb * a[i];
        r[i] = ((sp_digit)t) & 0xfffffff;
        t >>= 28;
    }
    r[112] += (sp_digit)t;
#else
    sp_int64 tb = b;
    sp_int64 t[8];
    int i;

    t[0] = 0;
    for (i = 0; i < 104; i += 8) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        t[4]  = (tb * a[i+4]) + r[i+4];
        t[5]  = (tb * a[i+5]) + r[i+5];
        t[6]  = (tb * a[i+6]) + r[i+6];
        t[7]  = (tb * a[i+7]) + r[i+7];
        r[i+0] = t[0] & 0xfffffff;
        t[1] += t[0] >> 28;
        r[i+1] = t[1] & 0xfffffff;
        t[2] += t[1] >> 28;
        r[i+2] = t[2] & 0xfffffff;
        t[3] += t[2] >> 28;
        r[i+3] = t[3] & 0xfffffff;
        t[4] += t[3] >> 28;
        r[i+4] = t[4] & 0xfffffff;
        t[5] += t[4] >> 28;
        r[i+5] = t[5] & 0xfffffff;
        t[6] += t[5] >> 28;
        r[i+6] = t[6] & 0xfffffff;
        t[7] += t[6] >> 28;
        r[i+7] = t[7] & 0xfffffff;
        t[0]  = t[7] >> 28;
    }
    t[0] += (tb * a[104]) + r[104];
    t[1]  = (tb * a[105]) + r[105];
    t[2]  = (tb * a[106]) + r[106];
    t[3]  = (tb * a[107]) + r[107];
    t[4]  = (tb * a[108]) + r[108];
    t[5]  = (tb * a[109]) + r[109];
    t[6]  = (tb * a[110]) + r[110];
    t[7]  = (tb * a[111]) + r[111];
    r[104] = t[0] & 0xfffffff;
    t[1] += t[0] >> 28;
    r[105] = t[1] & 0xfffffff;
    t[2] += t[1] >> 28;
    r[106] = t[2] & 0xfffffff;
    t[3] += t[2] >> 28;
    r[107] = t[3] & 0xfffffff;
    t[4] += t[3] >> 28;
    r[108] = t[4] & 0xfffffff;
    t[5] += t[4] >> 28;
    r[109] = t[5] & 0xfffffff;
    t[6] += t[5] >> 28;
    r[110] = t[6] & 0xfffffff;
    t[7] += t[6] >> 28;
    r[111] = t[7] & 0xfffffff;
    r[112] +=  (sp_digit)(t[7] >> 28);
#endif /* !WOLFSSL_SP_LARGE_CODE */
}

/* Shift the result in the high 3072 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_3072_mont_shift_112(sp_digit* r, const sp_digit* a)
{
    int i;
    sp_int64 n = a[109] >> 20;
    n += ((sp_int64)a[110]) << 8;
    for (i = 0; i < 104; i += 8) {
        r[i + 0] = n & 0xfffffff;
        n >>= 28; n += ((sp_int64)a[i + 111]) << 8;
        r[i + 1] = n & 0xfffffff;
        n >>= 28; n += ((sp_int64)a[i + 112]) << 8;
        r[i + 2] = n & 0xfffffff;
        n >>= 28; n += ((sp_int64)a[i + 113]) << 8;
        r[i + 3] = n & 0xfffffff;
        n >>= 28; n += ((sp_int64)a[i + 114]) << 8;
        r[i + 4] = n & 0xfffffff;
        n >>= 28; n += ((sp_int64)a[i + 115]) << 8;
        r[i + 5] = n & 0xfffffff;
        n >>= 28; n += ((sp_int64)a[i + 116]) << 8;
        r[i + 6] = n & 0xfffffff;
        n >>= 28; n += ((sp_int64)a[i + 117]) << 8;
        r[i + 7] = n & 0xfffffff;
        n >>= 28; n += ((sp_int64)a[i + 118]) << 8;
    }
    r[104] = n & 0xfffffff; n >>= 28; n += ((sp_int64)a[215]) << 8;
    r[105] = n & 0xfffffff; n >>= 28; n += ((sp_int64)a[216]) << 8;
    r[106] = n & 0xfffffff; n >>= 28; n += ((sp_int64)a[217]) << 8;
    r[107] = n & 0xfffffff; n >>= 28; n += ((sp_int64)a[218]) << 8;
    r[108] = n & 0xfffffff; n >>= 28; n += ((sp_int64)a[219]) << 8;
    r[109] = (sp_digit)n;
    XMEMSET(&r[110], 0, sizeof(*r) * 110U);
}

/* Reduce the number back to 3072 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_3072_mont_reduce_112(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_3072_norm_112(a + 110);

#ifdef WOLFSSL_SP_DH
    if (mp != 1) {
        for (i=0; i<109; i++) {
            mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0xfffffff;
            sp_3072_mul_add_112(a+i, m, mu);
            a[i+1] += a[i] >> 28;
        }
        mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0xfffffL;
        sp_3072_mul_add_112(a+i, m, mu);
        a[i+1] += a[i] >> 28;
        a[i] &= 0xfffffff;
    }
    else {
        for (i=0; i<109; i++) {
            mu = a[i] & 0xfffffff;
            sp_3072_mul_add_112(a+i, m, mu);
            a[i+1] += a[i] >> 28;
        }
        mu = a[i] & 0xfffffL;
        sp_3072_mul_add_112(a+i, m, mu);
        a[i+1] += a[i] >> 28;
        a[i] &= 0xfffffff;
    }
#else
    for (i=0; i<109; i++) {
        mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0xfffffff;
        sp_3072_mul_add_112(a+i, m, mu);
        a[i+1] += a[i] >> 28;
    }
    mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0xfffffL;
    sp_3072_mul_add_112(a+i, m, mu);
    a[i+1] += a[i] >> 28;
    a[i] &= 0xfffffff;
#endif
    sp_3072_mont_shift_112(a, a);
    over = a[109] - m[109];
    sp_3072_cond_sub_112(a, a, m, ~((over - 1) >> 31));
    sp_3072_norm_112(a);
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
SP_NOINLINE static void sp_3072_mont_mul_112(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_3072_mul_112(r, a, b);
    sp_3072_mont_reduce_112(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_3072_mont_sqr_112(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_3072_sqr_112(r, a);
    sp_3072_mont_reduce_112(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_d_224(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int64 tb = b;
    sp_int64 t = 0;
    sp_digit t2;
    sp_int64 p[4];
    int i;

    for (i = 0; i < 224; i += 4) {
        p[0] = tb * a[i + 0];
        p[1] = tb * a[i + 1];
        p[2] = tb * a[i + 2];
        p[3] = tb * a[i + 3];
        t += p[0];
        t2 = (sp_digit)(t & 0xfffffff);
        t >>= 28;
        r[i + 0] = (sp_digit)t2;
        t += p[1];
        t2 = (sp_digit)(t & 0xfffffff);
        t >>= 28;
        r[i + 1] = (sp_digit)t2;
        t += p[2];
        t2 = (sp_digit)(t & 0xfffffff);
        t >>= 28;
        r[i + 2] = (sp_digit)t2;
        t += p[3];
        t2 = (sp_digit)(t & 0xfffffff);
        t >>= 28;
        r[i + 3] = (sp_digit)t2;
    }
    r[224] = (sp_digit)(t & 0xfffffff);
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
static void sp_3072_cond_add_112(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 112; i += 8) {
        r[i + 0] = a[i + 0] + (b[i + 0] & m);
        r[i + 1] = a[i + 1] + (b[i + 1] & m);
        r[i + 2] = a[i + 2] + (b[i + 2] & m);
        r[i + 3] = a[i + 3] + (b[i + 3] & m);
        r[i + 4] = a[i + 4] + (b[i + 4] & m);
        r[i + 5] = a[i + 5] + (b[i + 5] & m);
        r[i + 6] = a[i + 6] + (b[i + 6] & m);
        r[i + 7] = a[i + 7] + (b[i + 7] & m);
    }
}
#endif /* !WOLFSSL_SP_SMALL */

SP_NOINLINE static void sp_3072_rshift_112(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    for (i=0; i<104; i += 8) {
        r[i+0] = (a[i+0] >> n) | ((a[i+1] << (28 - n)) & 0xfffffff);
        r[i+1] = (a[i+1] >> n) | ((a[i+2] << (28 - n)) & 0xfffffff);
        r[i+2] = (a[i+2] >> n) | ((a[i+3] << (28 - n)) & 0xfffffff);
        r[i+3] = (a[i+3] >> n) | ((a[i+4] << (28 - n)) & 0xfffffff);
        r[i+4] = (a[i+4] >> n) | ((a[i+5] << (28 - n)) & 0xfffffff);
        r[i+5] = (a[i+5] >> n) | ((a[i+6] << (28 - n)) & 0xfffffff);
        r[i+6] = (a[i+6] >> n) | ((a[i+7] << (28 - n)) & 0xfffffff);
        r[i+7] = (a[i+7] >> n) | ((a[i+8] << (28 - n)) & 0xfffffff);
    }
    r[104] = (a[104] >> n) | ((a[105] << (28 - n)) & 0xfffffff);
    r[105] = (a[105] >> n) | ((a[106] << (28 - n)) & 0xfffffff);
    r[106] = (a[106] >> n) | ((a[107] << (28 - n)) & 0xfffffff);
    r[107] = (a[107] >> n) | ((a[108] << (28 - n)) & 0xfffffff);
    r[108] = (a[108] >> n) | ((a[109] << (28 - n)) & 0xfffffff);
    r[109] = (a[109] >> n) | ((a[110] << (28 - n)) & 0xfffffff);
    r[110] = (a[110] >> n) | ((a[111] << (28 - n)) & 0xfffffff);
    r[111] = a[111] >> n;
}

static WC_INLINE sp_digit sp_3072_div_word_112(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int64 d = ((sp_int64)d1 << 28) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int64 d = ((sp_int64)d1 << 28) + d0;
    sp_uint32 lo = (sp_uint32)d;
    sp_digit hi = (sp_digit)(d >> 32);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int64 d = ((sp_int64)d1 << 28) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 28);
    sp_digit t0 = (sp_digit)(d & 0xfffffff);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int64 m;

    r = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
    t1 -= dv & (0 - r);
    for (i = 26; i >= 1; i--) {
        t1 += t1 + (((sp_uint32)t0 >> 27) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int64)r * div);
    r += (sp_digit)(m >> 28);
    m = d - ((sp_int64)r * div);
    r += (m >> 56) - (sp_digit)(d >> 56);

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;
   return r;
#else
    sp_int64 d = ((sp_int64)d1 << 28) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 13) + 1;

    t = (sp_digit)(d >> 26);
    t = (t / dv) << 13;
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)(d >> 11);
    t = t / (dv << 2);
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int64)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_3072_word_div_word_112(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint32)(div - d) >> 31);
#endif
}
/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * Full implementation.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_3072_div_112(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_32
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 112 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 224 + 1;
        sd = t2 + 112 + 1;

        sp_3072_mul_d_112(sd, d, (sp_digit)1 << 8);
        sp_3072_mul_d_224(t1, a, (sp_digit)1 << 8);
        dv = sd[109];
        t1[110 + 110] += t1[110 + 110 - 1] >> 28;
        t1[110 + 110 - 1] &= 0xfffffff;
        for (i=110; i>=0; i--) {
            r1 = sp_3072_div_word_112(t1[110 + i], t1[110 + i - 1], dv);

            sp_3072_mul_d_112(t2, sd, r1);
            (void)sp_3072_sub_112(&t1[i], &t1[i], t2);
            sp_3072_norm_110(&t1[i]);
            t1[110 + i] += t1[110 + i - 1] >> 28;
            t1[110 + i - 1] &= 0xfffffff;
            r1 = sp_3072_div_word_112(-t1[110 + i], -t1[110 + i - 1], dv);
            r1 -= t1[110 + i];
            sp_3072_mul_d_112(t2, sd, r1);
            (void)sp_3072_add_112(&t1[i], &t1[i], t2);
            t1[110 + i] += t1[110 + i - 1] >> 28;
            t1[110 + i - 1] &= 0xfffffff;
        }
        t1[110 - 1] += t1[110 - 2] >> 28;
        t1[110 - 2] &= 0xfffffff;
        r1 = sp_3072_word_div_word_112(t1[110 - 1], dv);

        sp_3072_mul_d_112(t2, sd, r1);
        sp_3072_sub_112(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 224U);
        for (i=0; i<109; i++) {
            r[i+1] += r[i] >> 28;
            r[i] &= 0xfffffff;
        }
        sp_3072_cond_add_112(r, r, sd, r[109] >> 31);

        sp_3072_norm_110(r);
        sp_3072_rshift_112(r, r, 8);
        r[110] = 0;
        r[111] = 0;
    }


    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_3072_mod_112(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_3072_div_112(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || \
                                                     defined(WOLFSSL_HAVE_SP_DH)
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
static int sp_3072_mod_exp_112(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 224];
    sp_digit* t[3] = {0, 0, 0};
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<3; i++) {
            t[i] = td + (i * 112 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 112U * 2U);
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_112(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_112(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 112U);
        }
    }
    if (err == MP_OKAY) {
        sp_3072_mul_112(t[1], t[1], norm);
        err = sp_3072_mod_112(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 28;
        c = bits % 28;
        n = e[i--] << (28 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 28;
            }

            y = (int)((n >> 27) & 1);
            n <<= 1;

            sp_3072_mont_mul_112(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 112 * 2);
            sp_3072_mont_sqr_112(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 112 * 2);
        }

        sp_3072_mont_reduce_112(t[0], m, mp);
        n = sp_3072_cmp_112(t[0], m);
        sp_3072_cond_sub_112(t[0], t[0], m, ~(n >> 31));
        XMEMCPY(r, t[0], sizeof(*r) * 112 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 224];
    sp_digit* t[3] = {0, 0, 0};
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<3; i++) {
            t[i] = td + (i * 112 * 2);
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_112(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_112(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_112(t[1], t[1], norm);
                err = sp_3072_mod_112(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_112(t[1], a, norm);
            err = sp_3072_mod_112(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 28;
        c = bits % 28;
        n = e[i--] << (28 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 28;
            }

            y = (int)((n >> 27) & 1);
            n <<= 1;

            sp_3072_mont_mul_112(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 112 * 2);
            sp_3072_mont_sqr_112(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 112 * 2);
        }

        sp_3072_mont_reduce_112(t[0], m, mp);
        n = sp_3072_cmp_112(t[0], m);
        sp_3072_cond_sub_112(t[0], t[0], m, ~(n >> 31));
        XMEMCPY(r, t[0], sizeof(*r) * 112 * 2);
    }


    return err;
#else
    sp_digit td[(16 * 224) + 224];
    sp_digit* t[16];
    sp_digit* rt = NULL;
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<16; i++)
            t[i] = td + i * 224;
        rt = td + 3584;

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_112(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_112(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_112(t[1], t[1], norm);
                err = sp_3072_mod_112(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_112(t[1], a, norm);
            err = sp_3072_mod_112(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_3072_mont_sqr_112(t[ 2], t[ 1], m, mp);
        sp_3072_mont_mul_112(t[ 3], t[ 2], t[ 1], m, mp);
        sp_3072_mont_sqr_112(t[ 4], t[ 2], m, mp);
        sp_3072_mont_mul_112(t[ 5], t[ 3], t[ 2], m, mp);
        sp_3072_mont_sqr_112(t[ 6], t[ 3], m, mp);
        sp_3072_mont_mul_112(t[ 7], t[ 4], t[ 3], m, mp);
        sp_3072_mont_sqr_112(t[ 8], t[ 4], m, mp);
        sp_3072_mont_mul_112(t[ 9], t[ 5], t[ 4], m, mp);
        sp_3072_mont_sqr_112(t[10], t[ 5], m, mp);
        sp_3072_mont_mul_112(t[11], t[ 6], t[ 5], m, mp);
        sp_3072_mont_sqr_112(t[12], t[ 6], m, mp);
        sp_3072_mont_mul_112(t[13], t[ 7], t[ 6], m, mp);
        sp_3072_mont_sqr_112(t[14], t[ 7], m, mp);
        sp_3072_mont_mul_112(t[15], t[ 8], t[ 7], m, mp);

        bits = ((bits + 3) / 4) * 4;
        i = ((bits + 27) / 28) - 1;
        c = bits % 28;
        if (c == 0) {
            c = 28;
        }
        if (i < 112) {
            n = e[i--] << (32 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 4) {
            n |= e[i--] << (4 - c);
            c += 28;
        }
        y = (int)((n >> 28) & 0xf);
        n <<= 4;
        c -= 4;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 224);
        while ((i >= 0) || (c >= 4)) {
            if (c >= 4) {
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c -= 4;
            }
            else if (c == 0) {
                n = e[i--] << 4;
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c = 24;
            }
            else {
                y = (byte)((n >> 28) & 0xf);
                n = e[i--] << 4;
                c = 4 - c;
                y |= (byte)((n >> (32 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 28 - c;
            }

            sp_3072_mont_sqr_112(rt, rt, m, mp);
            sp_3072_mont_sqr_112(rt, rt, m, mp);
            sp_3072_mont_sqr_112(rt, rt, m, mp);
            sp_3072_mont_sqr_112(rt, rt, m, mp);

            sp_3072_mont_mul_112(rt, rt, t[y], m, mp);
        }

        sp_3072_mont_reduce_112(rt, m, mp);
        n = sp_3072_cmp_112(rt, m);
        sp_3072_cond_sub_112(rt, rt, m, ~(n >> 31));
        XMEMCPY(r, rt, sizeof(sp_digit) * 224);
    }


    return err;
#endif
}
#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) || */
       /* WOLFSSL_HAVE_SP_DH */

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
#ifdef WOLFSSL_SP_SMALL
    sp_digit a[112 * 5];
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit* norm = NULL;
    sp_digit e[1] = {0};
    sp_digit mp = 0;
    int i;
    int err = MP_OKAY;

    if (*outLen < 384U) {
        err = MP_TO_E;
    }

    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 28) {
            err = MP_READ_E;
        }
        else if (inLen > 384U) {
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
        r = a + 112 * 2;
        m = r + 112 * 2;
        norm = r;

        sp_3072_from_bin(a, 112, in, inLen);
#if DIGIT_BIT >= 28
        e[0] = (sp_digit)em->dp[0];
#else
        e[0] = (sp_digit)em->dp[0];
        if (em->used > 1) {
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
        }
#endif
        if (e[0] == 0) {
            err = MP_EXPTMOD_E;
        }
    }

    if (err == MP_OKAY) {
        sp_3072_from_mp(m, 112, mm);

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_112(norm, m);
    }
    if (err == MP_OKAY) {
        sp_3072_mul_112(a, a, norm);
        err = sp_3072_mod_112(a, a, m);
    }
    if (err == MP_OKAY) {
        for (i=27; i>=0; i--) {
            if ((e[0] >> i) != 0) {
                break;
            }
        }

        XMEMCPY(r, a, sizeof(sp_digit) * 112 * 2);
        for (i--; i>=0; i--) {
            sp_3072_mont_sqr_112(r, r, m, mp);

            if (((e[0] >> i) & 1) == 1) {
                sp_3072_mont_mul_112(r, r, a, m, mp);
            }
        }
        sp_3072_mont_reduce_112(r, m, mp);
        mp = sp_3072_cmp_112(r, m);
        sp_3072_cond_sub_112(r, r, m, ~(mp >> 31));

        sp_3072_to_bin_112(r, out);
        *outLen = 384;
    }


    return err;
#else
    sp_digit d[112 * 5];
    sp_digit* a = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit e[1] = {0};
    int err = MP_OKAY;

    if (*outLen < 384U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 28) {
            err = MP_READ_E;
        }
        else if (inLen > 384U) {
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
        a = d;
        r = a + 112 * 2;
        m = r + 112 * 2;

        sp_3072_from_bin(a, 112, in, inLen);
#if DIGIT_BIT >= 28
        e[0] = (sp_digit)em->dp[0];
#else
        e[0] = (sp_digit)em->dp[0];
        if (em->used > 1) {
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
        }
#endif
        if (e[0] == 0) {
            err = MP_EXPTMOD_E;
        }
    }
    if (err == MP_OKAY) {
        sp_3072_from_mp(m, 112, mm);

        if (e[0] == 0x3) {
            sp_3072_sqr_112(r, a);
            err = sp_3072_mod_112(r, r, m);
            if (err == MP_OKAY) {
                sp_3072_mul_112(r, a, r);
                err = sp_3072_mod_112(r, r, m);
            }
        }
        else {
            sp_digit* norm = r;
            int i;
            sp_digit mp;

            sp_3072_mont_setup(m, &mp);
            sp_3072_mont_norm_112(norm, m);

            sp_3072_mul_112(a, a, norm);
            err = sp_3072_mod_112(a, a, m);

            if (err == MP_OKAY) {
                for (i=27; i>=0; i--) {
                    if ((e[0] >> i) != 0) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 224U);
                for (i--; i>=0; i--) {
                    sp_3072_mont_sqr_112(r, r, m, mp);

                    if (((e[0] >> i) & 1) == 1) {
                        sp_3072_mont_mul_112(r, r, a, m, mp);
                    }
                }
                sp_3072_mont_reduce_112(r, m, mp);
                mp = sp_3072_cmp_112(r, m);
                sp_3072_cond_sub_112(r, r, m, ~(mp >> 31));
            }
        }
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_112(r, out);
        *outLen = 384;
    }


    return err;
#endif /* WOLFSSL_SP_SMALL */
}

#ifndef WOLFSSL_RSA_PUBLIC_ONLY
#if !defined(SP_RSA_PRIVATE_EXP_D) && !defined(RSA_LOW_MEM)
#endif /* !SP_RSA_PRIVATE_EXP_D & !RSA_LOW_MEM */
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
#if defined(WOLFSSL_SP_SMALL)
    sp_digit  d[112 * 4];
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
        a = d + 112;
        m = a + 224;
        r = a;

        sp_3072_from_bin(a, 112, in, inLen);
        sp_3072_from_mp(d, 112, dm);
        sp_3072_from_mp(m, 112, mm);
        err = sp_3072_mod_exp_112(r, a, d, 3072, m, 0);
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_112(r, out);
        *outLen = 384;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 112);
    }

    return err;
#else
    sp_digit d[112 * 4];
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
        else if (inLen > 384U) {
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
        a = d + 112;
        m = a + 224;
        r = a;

        sp_3072_from_bin(a, 112, in, inLen);
        sp_3072_from_mp(d, 112, dm);
        sp_3072_from_mp(m, 112, mm);
        err = sp_3072_mod_exp_112(r, a, d, 3072, m, 0);
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_112(r, out);
        *outLen = 384;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 112);
    }

    return err;
#endif /* WOLFSSL_SP_SMALL */
#else
#if defined(WOLFSSL_SP_SMALL)
    sp_digit a[56 * 8];
    sp_digit* p = NULL;
    sp_digit* dp = NULL;
    sp_digit* dq = NULL;
    sp_digit* qi = NULL;
    sp_digit* tmpa = NULL;
    sp_digit* tmpb = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 384U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (inLen > 384) {
            err = MP_READ_E;
        }
        else if (mp_count_bits(mm) != 3072) {
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
    }

    if (err == MP_OKAY) {
        p = a + 112;
        qi = dq = dp = p + 56;
        tmpa = qi + 56;
        tmpb = tmpa + 112;
        r = a;

        sp_3072_from_bin(a, 112, in, inLen);
        sp_3072_from_mp(p, 56, pm);
        sp_3072_from_mp(dp, 56, dpm);
        err = sp_3072_mod_exp_56(tmpa, a, dp, 1536, p, 1);
    }
    if (err == MP_OKAY) {
        sp_3072_from_mp(p, 56, qm);
        sp_3072_from_mp(dq, 56, dqm);
        err = sp_3072_mod_exp_56(tmpb, a, dq, 1536, p, 1);
    }
    if (err == MP_OKAY) {
        sp_3072_from_mp(p, 56, pm);
        (void)sp_3072_sub_56(tmpa, tmpa, tmpb);
        sp_3072_norm_55(tmpa);
        sp_3072_cond_add_56(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[54] >> 31));
        sp_3072_cond_add_56(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[54] >> 31));
        sp_3072_norm_56(tmpa);

        sp_3072_from_mp(qi, 56, qim);
        sp_3072_mul_56(tmpa, tmpa, qi);
        err = sp_3072_mod_56(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_3072_from_mp(p, 56, qm);
        sp_3072_mul_56(tmpa, p, tmpa);
        (void)sp_3072_add_112(r, tmpb, tmpa);
        sp_3072_norm_112(r);

        sp_3072_to_bin_112(r, out);
        *outLen = 384;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 56 * 8);
    }

    return err;
#else
    sp_digit a[56 * 13];
    sp_digit* p = NULL;
    sp_digit* q = NULL;
    sp_digit* dp = NULL;
    sp_digit* dq = NULL;
    sp_digit* qi = NULL;
    sp_digit* tmpa = NULL;
    sp_digit* tmpb = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 384U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (inLen > 384U) {
            err = MP_READ_E;
        }
        else if (mp_count_bits(mm) != 3072) {
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
    }


    if (err == MP_OKAY) {
        p = a + 112 * 2;
        q = p + 56;
        dp = q + 56;
        dq = dp + 56;
        qi = dq + 56;
        tmpa = qi + 56;
        tmpb = tmpa + 112;
        r = a;

        sp_3072_from_bin(a, 112, in, inLen);
        sp_3072_from_mp(p, 56, pm);
        sp_3072_from_mp(q, 56, qm);
        sp_3072_from_mp(dp, 56, dpm);
        sp_3072_from_mp(dq, 56, dqm);
        sp_3072_from_mp(qi, 56, qim);

        err = sp_3072_mod_exp_56(tmpa, a, dp, 1536, p, 1);
    }
    if (err == MP_OKAY) {
        err = sp_3072_mod_exp_56(tmpb, a, dq, 1536, q, 1);
    }

    if (err == MP_OKAY) {
        (void)sp_3072_sub_56(tmpa, tmpa, tmpb);
        sp_3072_norm_55(tmpa);
        sp_3072_cond_add_56(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[54] >> 31));
        sp_3072_cond_add_56(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[54] >> 31));
        sp_3072_norm_56(tmpa);
        sp_3072_mul_56(tmpa, tmpa, qi);
        err = sp_3072_mod_56(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_3072_mul_56(tmpa, tmpa, q);
        (void)sp_3072_add_112(r, tmpb, tmpa);
        sp_3072_norm_112(r);

        sp_3072_to_bin_112(r, out);
        *outLen = 384;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 56 * 13);
    }

    return err;
#endif /* WOLFSSL_SP_SMALL */
#endif /* SP_RSA_PRIVATE_EXP_D || RSA_LOW_MEM */
}

#endif /* !WOLFSSL_RSA_PUBLIC_ONLY */
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
#if DIGIT_BIT == 28
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 112);
        r->used = 112;
        mp_clamp(r);
#elif DIGIT_BIT < 28
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 112; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 28) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 28 - s;
        }
        r->used = (3072 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 112; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 28 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 28 - s;
            }
            else {
                s += 28;
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
#ifdef WOLFSSL_SP_SMALL
    int err = MP_OKAY;
    sp_digit b[112 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
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
        e = b + 112 * 2;
        m = e + 112;
        r = b;

        sp_3072_from_mp(b, 112, base);
        sp_3072_from_mp(e, 112, exp);
        sp_3072_from_mp(m, 112, mod);

        err = sp_3072_mod_exp_112(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_3072_to_mp(r, res);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 112U);
    }
    return err;
#else
    sp_digit b[112 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;
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
        e = b + 112 * 2;
        m = e + 112;
        r = b;

        sp_3072_from_mp(b, 112, base);
        sp_3072_from_mp(e, 112, exp);
        sp_3072_from_mp(m, 112, mod);

        err = sp_3072_mod_exp_112(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_3072_to_mp(r, res);
    }


    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 112U);
    }

    return err;
#endif
}

#ifdef WOLFSSL_HAVE_SP_DH

#ifdef HAVE_FFDHE_3072
SP_NOINLINE static void sp_3072_lshift_112(sp_digit* r, const sp_digit* a,
        byte n)
{
    sp_int_digit s;
    sp_int_digit t;

    s = (sp_int_digit)a[111];
    r[112] = s >> (28U - n);
    s = (sp_int_digit)(a[111]); t = (sp_int_digit)(a[110]);
    r[111] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[110]); t = (sp_int_digit)(a[109]);
    r[110] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[109]); t = (sp_int_digit)(a[108]);
    r[109] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[108]); t = (sp_int_digit)(a[107]);
    r[108] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[107]); t = (sp_int_digit)(a[106]);
    r[107] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[106]); t = (sp_int_digit)(a[105]);
    r[106] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[105]); t = (sp_int_digit)(a[104]);
    r[105] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[104]); t = (sp_int_digit)(a[103]);
    r[104] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[103]); t = (sp_int_digit)(a[102]);
    r[103] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[102]); t = (sp_int_digit)(a[101]);
    r[102] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[101]); t = (sp_int_digit)(a[100]);
    r[101] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[100]); t = (sp_int_digit)(a[99]);
    r[100] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[99]); t = (sp_int_digit)(a[98]);
    r[99] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[98]); t = (sp_int_digit)(a[97]);
    r[98] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[97]); t = (sp_int_digit)(a[96]);
    r[97] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[96]); t = (sp_int_digit)(a[95]);
    r[96] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[95]); t = (sp_int_digit)(a[94]);
    r[95] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[94]); t = (sp_int_digit)(a[93]);
    r[94] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[93]); t = (sp_int_digit)(a[92]);
    r[93] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[92]); t = (sp_int_digit)(a[91]);
    r[92] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[91]); t = (sp_int_digit)(a[90]);
    r[91] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[90]); t = (sp_int_digit)(a[89]);
    r[90] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[89]); t = (sp_int_digit)(a[88]);
    r[89] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[88]); t = (sp_int_digit)(a[87]);
    r[88] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[87]); t = (sp_int_digit)(a[86]);
    r[87] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[86]); t = (sp_int_digit)(a[85]);
    r[86] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[85]); t = (sp_int_digit)(a[84]);
    r[85] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[84]); t = (sp_int_digit)(a[83]);
    r[84] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[83]); t = (sp_int_digit)(a[82]);
    r[83] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[82]); t = (sp_int_digit)(a[81]);
    r[82] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[81]); t = (sp_int_digit)(a[80]);
    r[81] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[80]); t = (sp_int_digit)(a[79]);
    r[80] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[79]); t = (sp_int_digit)(a[78]);
    r[79] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[78]); t = (sp_int_digit)(a[77]);
    r[78] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[77]); t = (sp_int_digit)(a[76]);
    r[77] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[76]); t = (sp_int_digit)(a[75]);
    r[76] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[75]); t = (sp_int_digit)(a[74]);
    r[75] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[74]); t = (sp_int_digit)(a[73]);
    r[74] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[73]); t = (sp_int_digit)(a[72]);
    r[73] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[72]); t = (sp_int_digit)(a[71]);
    r[72] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[71]); t = (sp_int_digit)(a[70]);
    r[71] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[70]); t = (sp_int_digit)(a[69]);
    r[70] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[69]); t = (sp_int_digit)(a[68]);
    r[69] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[68]); t = (sp_int_digit)(a[67]);
    r[68] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[67]); t = (sp_int_digit)(a[66]);
    r[67] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[66]); t = (sp_int_digit)(a[65]);
    r[66] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[65]); t = (sp_int_digit)(a[64]);
    r[65] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[64]); t = (sp_int_digit)(a[63]);
    r[64] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[63]); t = (sp_int_digit)(a[62]);
    r[63] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[62]); t = (sp_int_digit)(a[61]);
    r[62] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[61]); t = (sp_int_digit)(a[60]);
    r[61] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[60]); t = (sp_int_digit)(a[59]);
    r[60] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[59]); t = (sp_int_digit)(a[58]);
    r[59] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[58]); t = (sp_int_digit)(a[57]);
    r[58] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[57]); t = (sp_int_digit)(a[56]);
    r[57] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[56]); t = (sp_int_digit)(a[55]);
    r[56] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[55]); t = (sp_int_digit)(a[54]);
    r[55] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[54]); t = (sp_int_digit)(a[53]);
    r[54] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[53]); t = (sp_int_digit)(a[52]);
    r[53] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[52]); t = (sp_int_digit)(a[51]);
    r[52] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[51]); t = (sp_int_digit)(a[50]);
    r[51] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[50]); t = (sp_int_digit)(a[49]);
    r[50] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[49]); t = (sp_int_digit)(a[48]);
    r[49] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[48]); t = (sp_int_digit)(a[47]);
    r[48] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[47]); t = (sp_int_digit)(a[46]);
    r[47] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[46]); t = (sp_int_digit)(a[45]);
    r[46] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[45]); t = (sp_int_digit)(a[44]);
    r[45] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[44]); t = (sp_int_digit)(a[43]);
    r[44] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[43]); t = (sp_int_digit)(a[42]);
    r[43] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[42]); t = (sp_int_digit)(a[41]);
    r[42] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[41]); t = (sp_int_digit)(a[40]);
    r[41] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[40]); t = (sp_int_digit)(a[39]);
    r[40] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[39]); t = (sp_int_digit)(a[38]);
    r[39] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[38]); t = (sp_int_digit)(a[37]);
    r[38] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[37]); t = (sp_int_digit)(a[36]);
    r[37] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[36]); t = (sp_int_digit)(a[35]);
    r[36] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[35]); t = (sp_int_digit)(a[34]);
    r[35] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[34]); t = (sp_int_digit)(a[33]);
    r[34] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[33]); t = (sp_int_digit)(a[32]);
    r[33] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[32]); t = (sp_int_digit)(a[31]);
    r[32] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[31]); t = (sp_int_digit)(a[30]);
    r[31] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[30]); t = (sp_int_digit)(a[29]);
    r[30] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[29]); t = (sp_int_digit)(a[28]);
    r[29] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[28]); t = (sp_int_digit)(a[27]);
    r[28] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[27]); t = (sp_int_digit)(a[26]);
    r[27] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[26]); t = (sp_int_digit)(a[25]);
    r[26] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[25]); t = (sp_int_digit)(a[24]);
    r[25] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[24]); t = (sp_int_digit)(a[23]);
    r[24] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[23]); t = (sp_int_digit)(a[22]);
    r[23] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[22]); t = (sp_int_digit)(a[21]);
    r[22] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[21]); t = (sp_int_digit)(a[20]);
    r[21] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[20]); t = (sp_int_digit)(a[19]);
    r[20] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[19]); t = (sp_int_digit)(a[18]);
    r[19] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[18]); t = (sp_int_digit)(a[17]);
    r[18] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[17]); t = (sp_int_digit)(a[16]);
    r[17] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[16]); t = (sp_int_digit)(a[15]);
    r[16] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[15]); t = (sp_int_digit)(a[14]);
    r[15] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[14]); t = (sp_int_digit)(a[13]);
    r[14] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[13]); t = (sp_int_digit)(a[12]);
    r[13] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[12]); t = (sp_int_digit)(a[11]);
    r[12] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[11]); t = (sp_int_digit)(a[10]);
    r[11] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[10]); t = (sp_int_digit)(a[9]);
    r[10] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[9]); t = (sp_int_digit)(a[8]);
    r[9] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[8]); t = (sp_int_digit)(a[7]);
    r[8] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[7]); t = (sp_int_digit)(a[6]);
    r[7] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[6]); t = (sp_int_digit)(a[5]);
    r[6] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[5]); t = (sp_int_digit)(a[4]);
    r[5] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[4]); t = (sp_int_digit)(a[3]);
    r[4] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[3]); t = (sp_int_digit)(a[2]);
    r[3] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[2]); t = (sp_int_digit)(a[1]);
    r[2] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    s = (sp_int_digit)(a[1]); t = (sp_int_digit)(a[0]);
    r[1] = ((s << n) | (t >> (28U - n))) & 0xfffffff;
    r[0] = (a[0] << n) & 0xfffffff;
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
static int sp_3072_mod_exp_2_112(sp_digit* r, const sp_digit* e, int bits, const sp_digit* m)
{
    sp_digit td[337];
    sp_digit* norm = NULL;
    sp_digit* tmp = NULL;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit o;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        tmp  = td + 224;
        XMEMSET(td, 0, sizeof(sp_digit) * 337);

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_112(norm, m);

        bits = ((bits + 3) / 4) * 4;
        i = ((bits + 27) / 28) - 1;
        c = bits % 28;
        if (c == 0) {
            c = 28;
        }
        if (i < 112) {
            n = e[i--] << (32 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 4) {
            n |= e[i--] << (4 - c);
            c += 28;
        }
        y = (int)((n >> 28) & 0xf);
        n <<= 4;
        c -= 4;
        sp_3072_lshift_112(r, norm, (byte)y);
        while ((i >= 0) || (c >= 4)) {
            if (c >= 4) {
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c -= 4;
            }
            else if (c == 0) {
                n = e[i--] << 4;
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c = 24;
            }
            else {
                y = (byte)((n >> 28) & 0xf);
                n = e[i--] << 4;
                c = 4 - c;
                y |= (byte)((n >> (32 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 28 - c;
            }

            sp_3072_mont_sqr_112(r, r, m, mp);
            sp_3072_mont_sqr_112(r, r, m, mp);
            sp_3072_mont_sqr_112(r, r, m, mp);
            sp_3072_mont_sqr_112(r, r, m, mp);

            sp_3072_lshift_112(r, r, (byte)y);
            sp_3072_mul_d_112(tmp, norm, (r[110] << 8) + (r[109] >> 20));
            r[110] = 0;
            r[109] &= 0xfffffL;
            (void)sp_3072_add_112(r, r, tmp);
            sp_3072_norm_112(r);
            o = sp_3072_cmp_112(r, m);
            sp_3072_cond_sub_112(r, r, m, ~(o >> 31));
        }

        sp_3072_mont_reduce_112(r, m, mp);
        n = sp_3072_cmp_112(r, m);
        sp_3072_cond_sub_112(r, r, m, ~(n >> 31));
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
    sp_digit b[112 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    word32 i;
    int err = MP_OKAY;

    if (mp_count_bits(base) > 3072) {
        err = MP_READ_E;
    }
    else if (expLen > 384U) {
        err = MP_READ_E;
    }
    else if (mp_count_bits(mod) != 3072) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mod)) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        e = b + 112 * 2;
        m = e + 112;
        r = b;

        sp_3072_from_mp(b, 112, base);
        sp_3072_from_bin(e, 112, exp, expLen);
        sp_3072_from_mp(m, 112, mod);

    #ifdef HAVE_FFDHE_3072
        if (base->used == 1 && base->dp[0] == 2U &&
                (m[109] >> 4) == 0xffffL) {
            err = sp_3072_mod_exp_2_112(r, e, expLen * 8U, m);
        }
        else {
    #endif
            err = sp_3072_mod_exp_112(r, b, e, expLen * 8U, m, 0);
    #ifdef HAVE_FFDHE_3072
        }
    #endif
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_112(r, out);
        *outLen = 384;
        for (i=0; i<384U && out[i] == 0U; i++) {
            /* Search for first non-zero. */
        }
        *outLen -= i;
        XMEMMOVE(out, out + i, *outLen);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 112U);
    }

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
#ifdef WOLFSSL_SP_SMALL
    int err = MP_OKAY;
    sp_digit b[56 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
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
        e = b + 56 * 2;
        m = e + 56;
        r = b;

        sp_3072_from_mp(b, 56, base);
        sp_3072_from_mp(e, 56, exp);
        sp_3072_from_mp(m, 56, mod);

        err = sp_3072_mod_exp_56(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 56, 0, sizeof(*r) * 56U);
        err = sp_3072_to_mp(r, res);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 112U);
    }
    return err;
#else
    sp_digit b[56 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;
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
        e = b + 56 * 2;
        m = e + 56;
        r = b;

        sp_3072_from_mp(b, 56, base);
        sp_3072_from_mp(e, 56, exp);
        sp_3072_from_mp(m, 56, mod);

        err = sp_3072_mod_exp_56(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 56, 0, sizeof(*r) * 56U);
        err = sp_3072_to_mp(r, res);
    }


    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 112U);
    }

    return err;
#endif
}

#endif /* WOLFSSL_HAVE_SP_DH | (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) */

#endif /* WOLFSSL_SP_SMALL */
#endif /* !WOLFSSL_SP_NO_3072 */

#ifdef WOLFSSL_SP_4096
#ifdef WOLFSSL_SP_SMALL
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
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = n-1; i >= 0; i--) {
        r[j] |= (((sp_digit)a[i]) << s);
        if (s >= 21U) {
            r[j] &= 0x1fffffff;
            s = 29U - s;
            if (j + 1 >= size) {
                break;
            }
            r[++j] = (sp_digit)a[i] >> s;
            s = 8U - s;
        }
        else {
            s += 8U;
        }
    }

    for (j++; j < size; j++) {
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
#if DIGIT_BIT == 29
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 29
    int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0x1fffffff;
        s = 29U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 29U) <= (word32)DIGIT_BIT) {
            s += 29U;
            r[j] &= 0x1fffffff;
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
        if (s + DIGIT_BIT >= 29) {
            r[j] &= 0x1fffffff;
            if (j + 1 >= size) {
                break;
            }
            s = 29 - s;
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
static void sp_4096_to_bin_142(sp_digit* r, byte* a)
{
    int i;
    int j;
    int s = 0;
    int b;

    for (i=0; i<141; i++) {
        r[i+1] += r[i] >> 29;
        r[i] &= 0x1fffffff;
    }
    j = 4103 / 8 - 1;
    a[j] = 0;
    for (i=0; i<142 && j>=0; i++) {
        b = 0;
        /* lint allow cast of mismatch sp_digit and int */
        a[j--] |= (byte)(r[i] << s); /*lint !e9033*/
        b += 8 - s;
        if (j < 0) {
            break;
        }
        while (b < 29) {
            a[j--] = (byte)(r[i] >> b);
            b += 8;
            if (j < 0) {
                break;
            }
        }
        s = 8 - (b - 29);
        if (j >= 0) {
            a[j] = 0;
        }
        if (s != 0) {
            j++;
        }
    }
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
#if defined(WOLFSSL_HAVE_SP_RSA) && !defined(SP_RSA_PRIVATE_EXP_D)
/* Normalize the values in each word to 29 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_4096_norm_71(sp_digit* a)
{
    int i;
    for (i = 0; i < 70; i++) {
        a[i+1] += a[i] >> 29;
        a[i] &= 0x1fffffff;
    }
}

#endif /* WOLFSSL_HAVE_SP_RSA & !SP_RSA_PRIVATE_EXP_D */
#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || WOLFSSL_HAVE_SP_DH */
/* Normalize the values in each word to 29 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_4096_norm_142(sp_digit* a)
{
    int i;
    for (i = 0; i < 141; i++) {
        a[i+1] += a[i] >> 29;
        a[i] &= 0x1fffffff;
    }
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_4096_mul_142(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i;
    int imax;
    int k;
    sp_uint64 c;
    sp_uint64 lo;

    c = ((sp_uint64)a[141]) * b[141];
    r[283] = (sp_digit)(c >> 29);
    c &= 0x1fffffff;
    for (k = 281; k >= 0; k--) {
        if (k >= 142) {
            i = k - 141;
            imax = 141;
        }
        else {
            i = 0;
            imax = k;
        }
        if (imax - i > 15) {
            int imaxlo;
            lo = 0;
            for (imaxlo = i; imaxlo <= imax; imaxlo += 15) {
                for (; i <= imax && i < imaxlo + 15; i++) {
                    lo += ((sp_uint64)a[i]) * b[k - i];
                }
                c += lo >> 29;
                lo &= 0x1fffffff;
            }
            r[k + 2] += (sp_digit)(c >> 29);
            r[k + 1]  = (sp_digit)(c & 0x1fffffff);
            c = lo & 0x1fffffff;
        }
        else {
            lo = 0;
            for (; i <= imax; i++) {
                lo += ((sp_uint64)a[i]) * b[k - i];
            }
            c += lo >> 29;
            r[k + 2] += (sp_digit)(c >> 29);
            r[k + 1]  = (sp_digit)(c & 0x1fffffff);
            c = lo & 0x1fffffff;
        }
    }
    r[0] = (sp_digit)c;
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_4096_sqr_142(sp_digit* r, const sp_digit* a)
{
    int i;
    int imax;
    int k;
    sp_uint64 c;
    sp_uint64 t;

    c = ((sp_uint64)a[141]) * a[141];
    r[283] = (sp_digit)(c >> 29);
    c = (c & 0x1fffffff) << 29;
    for (k = 281; k >= 0; k--) {
        i = (k + 1) / 2;
        if ((k & 1) == 0) {
           c += ((sp_uint64)a[i]) * a[i];
           i++;
        }
        if (k < 141) {
            imax = k;
        }
        else {
            imax = 141;
        }
        if (imax - i >= 14) {
            int imaxlo;
            sp_uint64 hi;

            hi = c >> 29;
            c &= 0x1fffffff;
            for (imaxlo = i; imaxlo <= imax; imaxlo += 14) {
                t = 0;
                for (; i <= imax && i < imaxlo + 14; i++) {
                    t += ((sp_uint64)a[i]) * a[k - i];
                }
                c += t * 2;

                hi += c >> 29;
                c &= 0x1fffffff;
            }
            r[k + 2] += (sp_digit)(hi >> 29);
            r[k + 1]  = (sp_digit)(hi & 0x1fffffff);
            c <<= 29;
        }
        else
        {
            t = 0;
            for (; i <= imax; i++) {
                t += ((sp_uint64)a[i]) * a[k - i];
            }
            c += t * 2;

            r[k + 2] += (sp_digit) (c >> 58);
            r[k + 1]  = (sp_digit)((c >> 29) & 0x1fffffff);
            c = (c & 0x1fffffff) << 29;
        }
    }
    r[0] = (sp_digit)(c >> 29);
}

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
    x &= 0x1fffffff;

    /* rho = -1/m mod b */
    *rho = ((sp_digit)1 << 29) - x;
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_d_142(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 142; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
    }
    r[142] = (sp_digit)t;
}

#if (defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH)) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
#if defined(WOLFSSL_HAVE_SP_RSA) && !defined(SP_RSA_PRIVATE_EXP_D)
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_sub_71(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 71; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 4096 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_4096_mont_norm_71(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
    int i;

    for (i=0; i<70; i++) {
        r[i] = 0x1fffffff;
    }
    r[70] = 0x3ffffL;

    /* r = (2^n - 1) mod n */
    (void)sp_4096_sub_71(r, r, m);

    /* Add one so r = 2^n mod m */
    r[0] += 1;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_4096_cmp_71(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
    int i;

    for (i=70; i>=0; i--) {
        r |= (a[i] - b[i]) & ~(((sp_digit)0 - r) >> 28);
    }

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_4096_cond_sub_71(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 71; i++) {
        r[i] = a[i] - (b[i] & m);
    }
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_add_71(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifndef WOLFSSL_SP_LARGE_CODE
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 71; i++) {
        t += r[i];
        t += tb * a[i];
        r[i] = ((sp_digit)t) & 0x1fffffff;
        t >>= 29;
    }
    r[71] += (sp_digit)t;
#else
    sp_int64 tb = b;
    sp_int64 t[4];
    int i;

    t[0] = 0;
    for (i = 0; i < 68; i += 4) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        r[i+0] = t[0] & 0x1fffffff;
        t[1] += t[0] >> 29;
        r[i+1] = t[1] & 0x1fffffff;
        t[2] += t[1] >> 29;
        r[i+2] = t[2] & 0x1fffffff;
        t[3] += t[2] >> 29;
        r[i+3] = t[3] & 0x1fffffff;
        t[0]  = t[3] >> 29;
    }
    t[0] += (tb * a[68]) + r[68];
    t[1]  = (tb * a[69]) + r[69];
    t[2]  = (tb * a[70]) + r[70];
    r[68] = t[0] & 0x1fffffff;
    t[1] += t[0] >> 29;
    r[69] = t[1] & 0x1fffffff;
    t[2] += t[1] >> 29;
    r[70] = t[2] & 0x1fffffff;
    r[71] +=  (sp_digit)(t[2] >> 29);
#endif /* !WOLFSSL_SP_LARGE_CODE */
}

/* Shift the result in the high 2048 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_4096_mont_shift_71(sp_digit* r, const sp_digit* a)
{
    int i;
    sp_int64 n = a[70] >> 18;
    n += ((sp_int64)a[71]) << 11;

    for (i = 0; i < 70; i++) {
        r[i] = n & 0x1fffffff;
        n >>= 29;
        n += ((sp_int64)a[72 + i]) << 11;
    }
    r[70] = (sp_digit)n;
    XMEMSET(&r[71], 0, sizeof(*r) * 71U);
}

/* Reduce the number back to 4096 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_4096_mont_reduce_71(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_4096_norm_71(a + 71);

    for (i=0; i<70; i++) {
        mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x1fffffff;
        sp_4096_mul_add_71(a+i, m, mu);
        a[i+1] += a[i] >> 29;
    }
    mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x3ffffL;
    sp_4096_mul_add_71(a+i, m, mu);
    a[i+1] += a[i] >> 29;
    a[i] &= 0x1fffffff;
    sp_4096_mont_shift_71(a, a);
    over = a[70] - m[70];
    sp_4096_cond_sub_71(a, a, m, ~((over - 1) >> 31));
    sp_4096_norm_71(a);
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_4096_mul_71(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i;
    int imax;
    int k;
    sp_uint64 c;
    sp_uint64 lo;

    c = ((sp_uint64)a[70]) * b[70];
    r[141] = (sp_digit)(c >> 29);
    c &= 0x1fffffff;
    for (k = 139; k >= 0; k--) {
        if (k >= 71) {
            i = k - 70;
            imax = 70;
        }
        else {
            i = 0;
            imax = k;
        }
        if (imax - i > 15) {
            int imaxlo;
            lo = 0;
            for (imaxlo = i; imaxlo <= imax; imaxlo += 15) {
                for (; i <= imax && i < imaxlo + 15; i++) {
                    lo += ((sp_uint64)a[i]) * b[k - i];
                }
                c += lo >> 29;
                lo &= 0x1fffffff;
            }
            r[k + 2] += (sp_digit)(c >> 29);
            r[k + 1]  = (sp_digit)(c & 0x1fffffff);
            c = lo & 0x1fffffff;
        }
        else {
            lo = 0;
            for (; i <= imax; i++) {
                lo += ((sp_uint64)a[i]) * b[k - i];
            }
            c += lo >> 29;
            r[k + 2] += (sp_digit)(c >> 29);
            r[k + 1]  = (sp_digit)(c & 0x1fffffff);
            c = lo & 0x1fffffff;
        }
    }
    r[0] = (sp_digit)c;
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
SP_NOINLINE static void sp_4096_mont_mul_71(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_4096_mul_71(r, a, b);
    sp_4096_mont_reduce_71(r, m, mp);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_4096_sqr_71(sp_digit* r, const sp_digit* a)
{
    int i;
    int imax;
    int k;
    sp_uint64 c;
    sp_uint64 t;

    c = ((sp_uint64)a[70]) * a[70];
    r[141] = (sp_digit)(c >> 29);
    c = (c & 0x1fffffff) << 29;
    for (k = 139; k >= 0; k--) {
        i = (k + 1) / 2;
        if ((k & 1) == 0) {
           c += ((sp_uint64)a[i]) * a[i];
           i++;
        }
        if (k < 70) {
            imax = k;
        }
        else {
            imax = 70;
        }
        if (imax - i >= 14) {
            int imaxlo;
            sp_uint64 hi;

            hi = c >> 29;
            c &= 0x1fffffff;
            for (imaxlo = i; imaxlo <= imax; imaxlo += 14) {
                t = 0;
                for (; i <= imax && i < imaxlo + 14; i++) {
                    t += ((sp_uint64)a[i]) * a[k - i];
                }
                c += t * 2;

                hi += c >> 29;
                c &= 0x1fffffff;
            }
            r[k + 2] += (sp_digit)(hi >> 29);
            r[k + 1]  = (sp_digit)(hi & 0x1fffffff);
            c <<= 29;
        }
        else
        {
            t = 0;
            for (; i <= imax; i++) {
                t += ((sp_uint64)a[i]) * a[k - i];
            }
            c += t * 2;

            r[k + 2] += (sp_digit) (c >> 58);
            r[k + 1]  = (sp_digit)((c >> 29) & 0x1fffffff);
            c = (c & 0x1fffffff) << 29;
        }
    }
    r[0] = (sp_digit)(c >> 29);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_4096_mont_sqr_71(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_4096_sqr_71(r, a);
    sp_4096_mont_reduce_71(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_d_71(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 71; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
    }
    r[71] = (sp_digit)t;
}

#ifdef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_4096_cond_add_71(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 71; i++) {
        r[i] = a[i] + (b[i] & m);
    }
}
#endif /* WOLFSSL_SP_SMALL */

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_add_71(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 71; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}

SP_NOINLINE static void sp_4096_rshift_71(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    for (i=0; i<70; i++) {
        r[i] = ((a[i] >> n) | (a[i + 1] << (29 - n))) & 0x1fffffff;
    }
    r[70] = a[70] >> n;
}

static WC_INLINE sp_digit sp_4096_div_word_71(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int64 d = ((sp_int64)d1 << 29) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_uint32 lo = (sp_uint32)d;
    sp_digit hi = (sp_digit)(d >> 32);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 29);
    sp_digit t0 = (sp_digit)(d & 0x1fffffff);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int64 m;

    r = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
    t1 -= dv & (0 - r);
    for (i = 27; i >= 1; i--) {
        t1 += t1 + (((sp_uint32)t0 >> 28) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int64)r * div);
    r += (sp_digit)(m >> 29);
    m = d - ((sp_int64)r * div);
    r += (m >> 58) - (sp_digit)(d >> 58);

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;
   return r;
#else
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 14) + 1;

    t = (sp_digit)(d >> 28);
    t = (t / dv) << 14;
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)(d >> 13);
    t = t / (dv << 1);
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int64)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_4096_word_div_word_71(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint32)(div - d) >> 31);
#endif
}
/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * Full implementation.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_4096_div_71(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_32
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 71 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 142 + 1;
        sd = t2 + 71 + 1;

        sp_4096_mul_d_71(sd, d, (sp_digit)1 << 11);
        sp_4096_mul_d_142(t1, a, (sp_digit)1 << 11);
        dv = sd[70];
        t1[71 + 71] += t1[71 + 71 - 1] >> 29;
        t1[71 + 71 - 1] &= 0x1fffffff;
        for (i=71; i>=0; i--) {
            r1 = sp_4096_div_word_71(t1[71 + i], t1[71 + i - 1], dv);

            sp_4096_mul_d_71(t2, sd, r1);
            (void)sp_4096_sub_71(&t1[i], &t1[i], t2);
            sp_4096_norm_71(&t1[i]);
            t1[71 + i] -= t2[71];
            t1[71 + i] += t1[71 + i - 1] >> 29;
            t1[71 + i - 1] &= 0x1fffffff;
            r1 = sp_4096_div_word_71(-t1[71 + i], -t1[71 + i - 1], dv);
            r1 -= t1[71 + i];
            sp_4096_mul_d_71(t2, sd, r1);
            (void)sp_4096_add_71(&t1[i], &t1[i], t2);
            t1[71 + i] += t1[71 + i - 1] >> 29;
            t1[71 + i - 1] &= 0x1fffffff;
        }
        t1[71 - 1] += t1[71 - 2] >> 29;
        t1[71 - 2] &= 0x1fffffff;
        r1 = sp_4096_word_div_word_71(t1[71 - 1], dv);

        sp_4096_mul_d_71(t2, sd, r1);
        sp_4096_sub_71(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 142U);
        for (i=0; i<70; i++) {
            r[i+1] += r[i] >> 29;
            r[i] &= 0x1fffffff;
        }
        sp_4096_cond_add_71(r, r, sd, r[70] >> 31);

        sp_4096_norm_71(r);
        sp_4096_rshift_71(r, r, 11);
    }


    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_4096_mod_71(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_4096_div_71(a, m, NULL, r);
}

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
static int sp_4096_mod_exp_71(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 142];
    sp_digit* t[3] = {0, 0, 0};
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<3; i++) {
            t[i] = td + (i * 71 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 71U * 2U);
        }

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_71(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_71(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 71U);
        }
    }
    if (err == MP_OKAY) {
        sp_4096_mul_71(t[1], t[1], norm);
        err = sp_4096_mod_71(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 29;
        c = bits % 29;
        n = e[i--] << (29 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 29;
            }

            y = (int)((n >> 28) & 1);
            n <<= 1;

            sp_4096_mont_mul_71(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 71 * 2);
            sp_4096_mont_sqr_71(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 71 * 2);
        }

        sp_4096_mont_reduce_71(t[0], m, mp);
        n = sp_4096_cmp_71(t[0], m);
        sp_4096_cond_sub_71(t[0], t[0], m, ~(n >> 31));
        XMEMCPY(r, t[0], sizeof(*r) * 71 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 142];
    sp_digit* t[3] = {0, 0, 0};
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<3; i++) {
            t[i] = td + (i * 71 * 2);
        }

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_71(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_71(t[1], a, m);
            if (err == MP_OKAY) {
                sp_4096_mul_71(t[1], t[1], norm);
                err = sp_4096_mod_71(t[1], t[1], m);
            }
        }
        else {
            sp_4096_mul_71(t[1], a, norm);
            err = sp_4096_mod_71(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 29;
        c = bits % 29;
        n = e[i--] << (29 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 29;
            }

            y = (int)((n >> 28) & 1);
            n <<= 1;

            sp_4096_mont_mul_71(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 71 * 2);
            sp_4096_mont_sqr_71(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 71 * 2);
        }

        sp_4096_mont_reduce_71(t[0], m, mp);
        n = sp_4096_cmp_71(t[0], m);
        sp_4096_cond_sub_71(t[0], t[0], m, ~(n >> 31));
        XMEMCPY(r, t[0], sizeof(*r) * 71 * 2);
    }


    return err;
#else
    sp_digit td[(32 * 142) + 142];
    sp_digit* t[32];
    sp_digit* rt = NULL;
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<32; i++)
            t[i] = td + i * 142;
        rt = td + 4544;

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_71(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_71(t[1], a, m);
            if (err == MP_OKAY) {
                sp_4096_mul_71(t[1], t[1], norm);
                err = sp_4096_mod_71(t[1], t[1], m);
            }
        }
        else {
            sp_4096_mul_71(t[1], a, norm);
            err = sp_4096_mod_71(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_4096_mont_sqr_71(t[ 2], t[ 1], m, mp);
        sp_4096_mont_mul_71(t[ 3], t[ 2], t[ 1], m, mp);
        sp_4096_mont_sqr_71(t[ 4], t[ 2], m, mp);
        sp_4096_mont_mul_71(t[ 5], t[ 3], t[ 2], m, mp);
        sp_4096_mont_sqr_71(t[ 6], t[ 3], m, mp);
        sp_4096_mont_mul_71(t[ 7], t[ 4], t[ 3], m, mp);
        sp_4096_mont_sqr_71(t[ 8], t[ 4], m, mp);
        sp_4096_mont_mul_71(t[ 9], t[ 5], t[ 4], m, mp);
        sp_4096_mont_sqr_71(t[10], t[ 5], m, mp);
        sp_4096_mont_mul_71(t[11], t[ 6], t[ 5], m, mp);
        sp_4096_mont_sqr_71(t[12], t[ 6], m, mp);
        sp_4096_mont_mul_71(t[13], t[ 7], t[ 6], m, mp);
        sp_4096_mont_sqr_71(t[14], t[ 7], m, mp);
        sp_4096_mont_mul_71(t[15], t[ 8], t[ 7], m, mp);
        sp_4096_mont_sqr_71(t[16], t[ 8], m, mp);
        sp_4096_mont_mul_71(t[17], t[ 9], t[ 8], m, mp);
        sp_4096_mont_sqr_71(t[18], t[ 9], m, mp);
        sp_4096_mont_mul_71(t[19], t[10], t[ 9], m, mp);
        sp_4096_mont_sqr_71(t[20], t[10], m, mp);
        sp_4096_mont_mul_71(t[21], t[11], t[10], m, mp);
        sp_4096_mont_sqr_71(t[22], t[11], m, mp);
        sp_4096_mont_mul_71(t[23], t[12], t[11], m, mp);
        sp_4096_mont_sqr_71(t[24], t[12], m, mp);
        sp_4096_mont_mul_71(t[25], t[13], t[12], m, mp);
        sp_4096_mont_sqr_71(t[26], t[13], m, mp);
        sp_4096_mont_mul_71(t[27], t[14], t[13], m, mp);
        sp_4096_mont_sqr_71(t[28], t[14], m, mp);
        sp_4096_mont_mul_71(t[29], t[15], t[14], m, mp);
        sp_4096_mont_sqr_71(t[30], t[15], m, mp);
        sp_4096_mont_mul_71(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 28) / 29) - 1;
        c = bits % 29;
        if (c == 0) {
            c = 29;
        }
        if (i < 71) {
            n = e[i--] << (32 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (3 - c);
            c += 29;
        }
        y = (int)((n >> 27) & 0x1f);
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 142);
        while ((i >= 0) || (c >= 5)) {
            if (c >= 5) {
                y = (byte)((n >> 27) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--] << 3;
                y = (byte)((n >> 27) & 0x1f);
                n <<= 5;
                c = 24;
            }
            else {
                y = (byte)((n >> 27) & 0x1f);
                n = e[i--] << 3;
                c = 5 - c;
                y |= (byte)((n >> (32 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 29 - c;
            }

            sp_4096_mont_sqr_71(rt, rt, m, mp);
            sp_4096_mont_sqr_71(rt, rt, m, mp);
            sp_4096_mont_sqr_71(rt, rt, m, mp);
            sp_4096_mont_sqr_71(rt, rt, m, mp);
            sp_4096_mont_sqr_71(rt, rt, m, mp);

            sp_4096_mont_mul_71(rt, rt, t[y], m, mp);
        }

        sp_4096_mont_reduce_71(rt, m, mp);
        n = sp_4096_cmp_71(rt, m);
        sp_4096_cond_sub_71(rt, rt, m, ~(n >> 31));
        XMEMCPY(r, rt, sizeof(sp_digit) * 142);
    }


    return err;
#endif
}

#endif /* WOLFSSL_HAVE_SP_RSA & !SP_RSA_PRIVATE_EXP_D */
#endif /* (WOLFSSL_HAVE_SP_RSA | WOLFSSL_HAVE_SP_DH) & !WOLFSSL_RSA_PUBLIC_ONLY */

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_sub_142(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 142; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 4096 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_4096_mont_norm_142(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
    int i;

    for (i=0; i<141; i++) {
        r[i] = 0x1fffffff;
    }
    r[141] = 0x7fL;

    /* r = (2^n - 1) mod n */
    (void)sp_4096_sub_142(r, r, m);

    /* Add one so r = 2^n mod m */
    r[0] += 1;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_4096_cmp_142(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
    int i;

    for (i=141; i>=0; i--) {
        r |= (a[i] - b[i]) & ~(((sp_digit)0 - r) >> 28);
    }

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_4096_cond_sub_142(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 142; i++) {
        r[i] = a[i] - (b[i] & m);
    }
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_add_142(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifndef WOLFSSL_SP_LARGE_CODE
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 142; i++) {
        t += r[i];
        t += tb * a[i];
        r[i] = ((sp_digit)t) & 0x1fffffff;
        t >>= 29;
    }
    r[142] += (sp_digit)t;
#else
    sp_int64 tb = b;
    sp_int64 t[4];
    int i;

    t[0] = 0;
    for (i = 0; i < 140; i += 4) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        r[i+0] = t[0] & 0x1fffffff;
        t[1] += t[0] >> 29;
        r[i+1] = t[1] & 0x1fffffff;
        t[2] += t[1] >> 29;
        r[i+2] = t[2] & 0x1fffffff;
        t[3] += t[2] >> 29;
        r[i+3] = t[3] & 0x1fffffff;
        t[0]  = t[3] >> 29;
    }
    t[0] += (tb * a[140]) + r[140];
    t[1]  = (tb * a[141]) + r[141];
    r[140] = t[0] & 0x1fffffff;
    t[1] += t[0] >> 29;
    r[141] = t[1] & 0x1fffffff;
    r[142] +=  (sp_digit)(t[1] >> 29);
#endif /* !WOLFSSL_SP_LARGE_CODE */
}

/* Shift the result in the high 4096 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_4096_mont_shift_142(sp_digit* r, const sp_digit* a)
{
    int i;
    sp_int64 n = a[141] >> 7;
    n += ((sp_int64)a[142]) << 22;

    for (i = 0; i < 141; i++) {
        r[i] = n & 0x1fffffff;
        n >>= 29;
        n += ((sp_int64)a[143 + i]) << 22;
    }
    r[141] = (sp_digit)n;
    XMEMSET(&r[142], 0, sizeof(*r) * 142U);
}

/* Reduce the number back to 4096 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_4096_mont_reduce_142(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_4096_norm_142(a + 142);

#ifdef WOLFSSL_SP_DH
    if (mp != 1) {
        for (i=0; i<141; i++) {
            mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x1fffffff;
            sp_4096_mul_add_142(a+i, m, mu);
            a[i+1] += a[i] >> 29;
        }
        mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x7fL;
        sp_4096_mul_add_142(a+i, m, mu);
        a[i+1] += a[i] >> 29;
        a[i] &= 0x1fffffff;
    }
    else {
        for (i=0; i<141; i++) {
            mu = a[i] & 0x1fffffff;
            sp_4096_mul_add_142(a+i, m, mu);
            a[i+1] += a[i] >> 29;
        }
        mu = a[i] & 0x7fL;
        sp_4096_mul_add_142(a+i, m, mu);
        a[i+1] += a[i] >> 29;
        a[i] &= 0x1fffffff;
    }
#else
    for (i=0; i<141; i++) {
        mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x1fffffff;
        sp_4096_mul_add_142(a+i, m, mu);
        a[i+1] += a[i] >> 29;
    }
    mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x7fL;
    sp_4096_mul_add_142(a+i, m, mu);
    a[i+1] += a[i] >> 29;
    a[i] &= 0x1fffffff;
#endif
    sp_4096_mont_shift_142(a, a);
    over = a[141] - m[141];
    sp_4096_cond_sub_142(a, a, m, ~((over - 1) >> 31));
    sp_4096_norm_142(a);
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
SP_NOINLINE static void sp_4096_mont_mul_142(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_4096_mul_142(r, a, b);
    sp_4096_mont_reduce_142(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_4096_mont_sqr_142(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_4096_sqr_142(r, a);
    sp_4096_mont_reduce_142(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_d_284(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 284; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0x1fffffff);
        t >>= 29;
    }
    r[284] = (sp_digit)t;
}

#ifdef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_4096_cond_add_142(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 142; i++) {
        r[i] = a[i] + (b[i] & m);
    }
}
#endif /* WOLFSSL_SP_SMALL */

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_add_142(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 142; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}

SP_NOINLINE static void sp_4096_rshift_142(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    for (i=0; i<141; i++) {
        r[i] = ((a[i] >> n) | (a[i + 1] << (29 - n))) & 0x1fffffff;
    }
    r[141] = a[141] >> n;
}

static WC_INLINE sp_digit sp_4096_div_word_142(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int64 d = ((sp_int64)d1 << 29) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_uint32 lo = (sp_uint32)d;
    sp_digit hi = (sp_digit)(d >> 32);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 29);
    sp_digit t0 = (sp_digit)(d & 0x1fffffff);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int64 m;

    r = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
    t1 -= dv & (0 - r);
    for (i = 27; i >= 1; i--) {
        t1 += t1 + (((sp_uint32)t0 >> 28) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int64)r * div);
    r += (sp_digit)(m >> 29);
    m = d - ((sp_int64)r * div);
    r += (m >> 58) - (sp_digit)(d >> 58);

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;
   return r;
#else
    sp_int64 d = ((sp_int64)d1 << 29) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 14) + 1;

    t = (sp_digit)(d >> 28);
    t = (t / dv) << 14;
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)(d >> 13);
    t = t / (dv << 1);
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int64)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_4096_word_div_word_142(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint32)(div - d) >> 31);
#endif
}
/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * Full implementation.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_4096_div_142(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_32
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 142 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 284 + 1;
        sd = t2 + 142 + 1;

        sp_4096_mul_d_142(sd, d, (sp_digit)1 << 22);
        sp_4096_mul_d_284(t1, a, (sp_digit)1 << 22);
        dv = sd[141];
        t1[142 + 142] += t1[142 + 142 - 1] >> 29;
        t1[142 + 142 - 1] &= 0x1fffffff;
        for (i=142; i>=0; i--) {
            r1 = sp_4096_div_word_142(t1[142 + i], t1[142 + i - 1], dv);

            sp_4096_mul_d_142(t2, sd, r1);
            (void)sp_4096_sub_142(&t1[i], &t1[i], t2);
            sp_4096_norm_142(&t1[i]);
            t1[142 + i] -= t2[142];
            t1[142 + i] += t1[142 + i - 1] >> 29;
            t1[142 + i - 1] &= 0x1fffffff;
            r1 = sp_4096_div_word_142(-t1[142 + i], -t1[142 + i - 1], dv);
            r1 -= t1[142 + i];
            sp_4096_mul_d_142(t2, sd, r1);
            (void)sp_4096_add_142(&t1[i], &t1[i], t2);
            t1[142 + i] += t1[142 + i - 1] >> 29;
            t1[142 + i - 1] &= 0x1fffffff;
        }
        t1[142 - 1] += t1[142 - 2] >> 29;
        t1[142 - 2] &= 0x1fffffff;
        r1 = sp_4096_word_div_word_142(t1[142 - 1], dv);

        sp_4096_mul_d_142(t2, sd, r1);
        sp_4096_sub_142(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 284U);
        for (i=0; i<141; i++) {
            r[i+1] += r[i] >> 29;
            r[i] &= 0x1fffffff;
        }
        sp_4096_cond_add_142(r, r, sd, r[141] >> 31);

        sp_4096_norm_142(r);
        sp_4096_rshift_142(r, r, 22);
    }


    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_4096_mod_142(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_4096_div_142(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
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
static int sp_4096_mod_exp_142(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 284];
    sp_digit* t[3] = {0, 0, 0};
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<3; i++) {
            t[i] = td + (i * 142 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 142U * 2U);
        }

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_142(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_142(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 142U);
        }
    }
    if (err == MP_OKAY) {
        sp_4096_mul_142(t[1], t[1], norm);
        err = sp_4096_mod_142(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 29;
        c = bits % 29;
        n = e[i--] << (29 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 29;
            }

            y = (int)((n >> 28) & 1);
            n <<= 1;

            sp_4096_mont_mul_142(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 142 * 2);
            sp_4096_mont_sqr_142(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 142 * 2);
        }

        sp_4096_mont_reduce_142(t[0], m, mp);
        n = sp_4096_cmp_142(t[0], m);
        sp_4096_cond_sub_142(t[0], t[0], m, ~(n >> 31));
        XMEMCPY(r, t[0], sizeof(*r) * 142 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 284];
    sp_digit* t[3] = {0, 0, 0};
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<3; i++) {
            t[i] = td + (i * 142 * 2);
        }

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_142(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_142(t[1], a, m);
            if (err == MP_OKAY) {
                sp_4096_mul_142(t[1], t[1], norm);
                err = sp_4096_mod_142(t[1], t[1], m);
            }
        }
        else {
            sp_4096_mul_142(t[1], a, norm);
            err = sp_4096_mod_142(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 29;
        c = bits % 29;
        n = e[i--] << (29 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 29;
            }

            y = (int)((n >> 28) & 1);
            n <<= 1;

            sp_4096_mont_mul_142(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 142 * 2);
            sp_4096_mont_sqr_142(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 142 * 2);
        }

        sp_4096_mont_reduce_142(t[0], m, mp);
        n = sp_4096_cmp_142(t[0], m);
        sp_4096_cond_sub_142(t[0], t[0], m, ~(n >> 31));
        XMEMCPY(r, t[0], sizeof(*r) * 142 * 2);
    }


    return err;
#else
    sp_digit td[(16 * 284) + 284];
    sp_digit* t[16];
    sp_digit* rt = NULL;
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<16; i++)
            t[i] = td + i * 284;
        rt = td + 4544;

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_142(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_142(t[1], a, m);
            if (err == MP_OKAY) {
                sp_4096_mul_142(t[1], t[1], norm);
                err = sp_4096_mod_142(t[1], t[1], m);
            }
        }
        else {
            sp_4096_mul_142(t[1], a, norm);
            err = sp_4096_mod_142(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_4096_mont_sqr_142(t[ 2], t[ 1], m, mp);
        sp_4096_mont_mul_142(t[ 3], t[ 2], t[ 1], m, mp);
        sp_4096_mont_sqr_142(t[ 4], t[ 2], m, mp);
        sp_4096_mont_mul_142(t[ 5], t[ 3], t[ 2], m, mp);
        sp_4096_mont_sqr_142(t[ 6], t[ 3], m, mp);
        sp_4096_mont_mul_142(t[ 7], t[ 4], t[ 3], m, mp);
        sp_4096_mont_sqr_142(t[ 8], t[ 4], m, mp);
        sp_4096_mont_mul_142(t[ 9], t[ 5], t[ 4], m, mp);
        sp_4096_mont_sqr_142(t[10], t[ 5], m, mp);
        sp_4096_mont_mul_142(t[11], t[ 6], t[ 5], m, mp);
        sp_4096_mont_sqr_142(t[12], t[ 6], m, mp);
        sp_4096_mont_mul_142(t[13], t[ 7], t[ 6], m, mp);
        sp_4096_mont_sqr_142(t[14], t[ 7], m, mp);
        sp_4096_mont_mul_142(t[15], t[ 8], t[ 7], m, mp);

        bits = ((bits + 3) / 4) * 4;
        i = ((bits + 28) / 29) - 1;
        c = bits % 29;
        if (c == 0) {
            c = 29;
        }
        if (i < 142) {
            n = e[i--] << (32 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 4) {
            n |= e[i--] << (3 - c);
            c += 29;
        }
        y = (int)((n >> 28) & 0xf);
        n <<= 4;
        c -= 4;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 284);
        while ((i >= 0) || (c >= 4)) {
            if (c >= 4) {
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c -= 4;
            }
            else if (c == 0) {
                n = e[i--] << 3;
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c = 25;
            }
            else {
                y = (byte)((n >> 28) & 0xf);
                n = e[i--] << 3;
                c = 4 - c;
                y |= (byte)((n >> (32 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 29 - c;
            }

            sp_4096_mont_sqr_142(rt, rt, m, mp);
            sp_4096_mont_sqr_142(rt, rt, m, mp);
            sp_4096_mont_sqr_142(rt, rt, m, mp);
            sp_4096_mont_sqr_142(rt, rt, m, mp);

            sp_4096_mont_mul_142(rt, rt, t[y], m, mp);
        }

        sp_4096_mont_reduce_142(rt, m, mp);
        n = sp_4096_cmp_142(rt, m);
        sp_4096_cond_sub_142(rt, rt, m, ~(n >> 31));
        XMEMCPY(r, rt, sizeof(sp_digit) * 284);
    }


    return err;
#endif
}

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
#ifdef WOLFSSL_SP_SMALL
    sp_digit a[142 * 5];
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit* norm = NULL;
    sp_digit e[1] = {0};
    sp_digit mp = 0;
    int i;
    int err = MP_OKAY;

    if (*outLen < 512U) {
        err = MP_TO_E;
    }

    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 29) {
            err = MP_READ_E;
        }
        else if (inLen > 512U) {
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
        r = a + 142 * 2;
        m = r + 142 * 2;
        norm = r;

        sp_4096_from_bin(a, 142, in, inLen);
#if DIGIT_BIT >= 29
        e[0] = (sp_digit)em->dp[0];
#else
        e[0] = (sp_digit)em->dp[0];
        if (em->used > 1) {
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
        }
#endif
        if (e[0] == 0) {
            err = MP_EXPTMOD_E;
        }
    }

    if (err == MP_OKAY) {
        sp_4096_from_mp(m, 142, mm);

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_142(norm, m);
    }
    if (err == MP_OKAY) {
        sp_4096_mul_142(a, a, norm);
        err = sp_4096_mod_142(a, a, m);
    }
    if (err == MP_OKAY) {
        for (i=28; i>=0; i--) {
            if ((e[0] >> i) != 0) {
                break;
            }
        }

        XMEMCPY(r, a, sizeof(sp_digit) * 142 * 2);
        for (i--; i>=0; i--) {
            sp_4096_mont_sqr_142(r, r, m, mp);

            if (((e[0] >> i) & 1) == 1) {
                sp_4096_mont_mul_142(r, r, a, m, mp);
            }
        }
        sp_4096_mont_reduce_142(r, m, mp);
        mp = sp_4096_cmp_142(r, m);
        sp_4096_cond_sub_142(r, r, m, ~(mp >> 31));

        sp_4096_to_bin_142(r, out);
        *outLen = 512;
    }


    return err;
#else
    sp_digit d[142 * 5];
    sp_digit* a = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit e[1] = {0};
    int err = MP_OKAY;

    if (*outLen < 512U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 29) {
            err = MP_READ_E;
        }
        else if (inLen > 512U) {
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
        a = d;
        r = a + 142 * 2;
        m = r + 142 * 2;

        sp_4096_from_bin(a, 142, in, inLen);
#if DIGIT_BIT >= 29
        e[0] = (sp_digit)em->dp[0];
#else
        e[0] = (sp_digit)em->dp[0];
        if (em->used > 1) {
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
        }
#endif
        if (e[0] == 0) {
            err = MP_EXPTMOD_E;
        }
    }
    if (err == MP_OKAY) {
        sp_4096_from_mp(m, 142, mm);

        if (e[0] == 0x3) {
            sp_4096_sqr_142(r, a);
            err = sp_4096_mod_142(r, r, m);
            if (err == MP_OKAY) {
                sp_4096_mul_142(r, a, r);
                err = sp_4096_mod_142(r, r, m);
            }
        }
        else {
            sp_digit* norm = r;
            int i;
            sp_digit mp;

            sp_4096_mont_setup(m, &mp);
            sp_4096_mont_norm_142(norm, m);

            sp_4096_mul_142(a, a, norm);
            err = sp_4096_mod_142(a, a, m);

            if (err == MP_OKAY) {
                for (i=28; i>=0; i--) {
                    if ((e[0] >> i) != 0) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 284U);
                for (i--; i>=0; i--) {
                    sp_4096_mont_sqr_142(r, r, m, mp);

                    if (((e[0] >> i) & 1) == 1) {
                        sp_4096_mont_mul_142(r, r, a, m, mp);
                    }
                }
                sp_4096_mont_reduce_142(r, m, mp);
                mp = sp_4096_cmp_142(r, m);
                sp_4096_cond_sub_142(r, r, m, ~(mp >> 31));
            }
        }
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_142(r, out);
        *outLen = 512;
    }


    return err;
#endif /* WOLFSSL_SP_SMALL */
}

#ifndef WOLFSSL_RSA_PUBLIC_ONLY
#if !defined(SP_RSA_PRIVATE_EXP_D) && !defined(RSA_LOW_MEM)
#endif /* !SP_RSA_PRIVATE_EXP_D & !RSA_LOW_MEM */
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
#if defined(WOLFSSL_SP_SMALL)
    sp_digit  d[142 * 4];
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
        a = d + 142;
        m = a + 284;
        r = a;

        sp_4096_from_bin(a, 142, in, inLen);
        sp_4096_from_mp(d, 142, dm);
        sp_4096_from_mp(m, 142, mm);
        err = sp_4096_mod_exp_142(r, a, d, 4096, m, 0);
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_142(r, out);
        *outLen = 512;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 142);
    }

    return err;
#else
    sp_digit d[142 * 4];
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
        else if (inLen > 512U) {
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
        a = d + 142;
        m = a + 284;
        r = a;

        sp_4096_from_bin(a, 142, in, inLen);
        sp_4096_from_mp(d, 142, dm);
        sp_4096_from_mp(m, 142, mm);
        err = sp_4096_mod_exp_142(r, a, d, 4096, m, 0);
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_142(r, out);
        *outLen = 512;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 142);
    }

    return err;
#endif /* WOLFSSL_SP_SMALL */
#else
#if defined(WOLFSSL_SP_SMALL)
    sp_digit a[71 * 8];
    sp_digit* p = NULL;
    sp_digit* dp = NULL;
    sp_digit* dq = NULL;
    sp_digit* qi = NULL;
    sp_digit* tmpa = NULL;
    sp_digit* tmpb = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 512U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (inLen > 512) {
            err = MP_READ_E;
        }
        else if (mp_count_bits(mm) != 4096) {
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
    }

    if (err == MP_OKAY) {
        p = a + 142;
        qi = dq = dp = p + 71;
        tmpa = qi + 71;
        tmpb = tmpa + 142;
        r = a;

        sp_4096_from_bin(a, 142, in, inLen);
        sp_4096_from_mp(p, 71, pm);
        sp_4096_from_mp(dp, 71, dpm);
        err = sp_4096_mod_exp_71(tmpa, a, dp, 2048, p, 1);
    }
    if (err == MP_OKAY) {
        sp_4096_from_mp(p, 71, qm);
        sp_4096_from_mp(dq, 71, dqm);
        err = sp_4096_mod_exp_71(tmpb, a, dq, 2048, p, 1);
    }
    if (err == MP_OKAY) {
        sp_4096_from_mp(p, 71, pm);
        (void)sp_4096_sub_71(tmpa, tmpa, tmpb);
        sp_4096_norm_71(tmpa);
        sp_4096_cond_add_71(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[70] >> 31));
        sp_4096_cond_add_71(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[70] >> 31));
        sp_4096_norm_71(tmpa);

        sp_4096_from_mp(qi, 71, qim);
        sp_4096_mul_71(tmpa, tmpa, qi);
        err = sp_4096_mod_71(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_4096_from_mp(p, 71, qm);
        sp_4096_mul_71(tmpa, p, tmpa);
        (void)sp_4096_add_142(r, tmpb, tmpa);
        sp_4096_norm_142(r);

        sp_4096_to_bin_142(r, out);
        *outLen = 512;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 71 * 8);
    }

    return err;
#else
    sp_digit a[71 * 13];
    sp_digit* p = NULL;
    sp_digit* q = NULL;
    sp_digit* dp = NULL;
    sp_digit* dq = NULL;
    sp_digit* qi = NULL;
    sp_digit* tmpa = NULL;
    sp_digit* tmpb = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 512U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (inLen > 512U) {
            err = MP_READ_E;
        }
        else if (mp_count_bits(mm) != 4096) {
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
    }


    if (err == MP_OKAY) {
        p = a + 142 * 2;
        q = p + 71;
        dp = q + 71;
        dq = dp + 71;
        qi = dq + 71;
        tmpa = qi + 71;
        tmpb = tmpa + 142;
        r = a;

        sp_4096_from_bin(a, 142, in, inLen);
        sp_4096_from_mp(p, 71, pm);
        sp_4096_from_mp(q, 71, qm);
        sp_4096_from_mp(dp, 71, dpm);
        sp_4096_from_mp(dq, 71, dqm);
        sp_4096_from_mp(qi, 71, qim);

        err = sp_4096_mod_exp_71(tmpa, a, dp, 2048, p, 1);
    }
    if (err == MP_OKAY) {
        err = sp_4096_mod_exp_71(tmpb, a, dq, 2048, q, 1);
    }

    if (err == MP_OKAY) {
        (void)sp_4096_sub_71(tmpa, tmpa, tmpb);
        sp_4096_norm_71(tmpa);
        sp_4096_cond_add_71(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[70] >> 31));
        sp_4096_cond_add_71(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[70] >> 31));
        sp_4096_norm_71(tmpa);
        sp_4096_mul_71(tmpa, tmpa, qi);
        err = sp_4096_mod_71(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_4096_mul_71(tmpa, tmpa, q);
        (void)sp_4096_add_142(r, tmpb, tmpa);
        sp_4096_norm_142(r);

        sp_4096_to_bin_142(r, out);
        *outLen = 512;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 71 * 13);
    }

    return err;
#endif /* WOLFSSL_SP_SMALL */
#endif /* SP_RSA_PRIVATE_EXP_D || RSA_LOW_MEM */
}

#endif /* !WOLFSSL_RSA_PUBLIC_ONLY */
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
#if DIGIT_BIT == 29
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 142);
        r->used = 142;
        mp_clamp(r);
#elif DIGIT_BIT < 29
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 142; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 29) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 29 - s;
        }
        r->used = (4096 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 142; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 29 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 29 - s;
            }
            else {
                s += 29;
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
#ifdef WOLFSSL_SP_SMALL
    int err = MP_OKAY;
    sp_digit b[142 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
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
        e = b + 142 * 2;
        m = e + 142;
        r = b;

        sp_4096_from_mp(b, 142, base);
        sp_4096_from_mp(e, 142, exp);
        sp_4096_from_mp(m, 142, mod);

        err = sp_4096_mod_exp_142(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_4096_to_mp(r, res);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 142U);
    }
    return err;
#else
    sp_digit b[142 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;
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
        e = b + 142 * 2;
        m = e + 142;
        r = b;

        sp_4096_from_mp(b, 142, base);
        sp_4096_from_mp(e, 142, exp);
        sp_4096_from_mp(m, 142, mod);

        err = sp_4096_mod_exp_142(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_4096_to_mp(r, res);
    }


    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 142U);
    }

    return err;
#endif
}

#ifdef WOLFSSL_HAVE_SP_DH

#ifdef HAVE_FFDHE_4096
SP_NOINLINE static void sp_4096_lshift_142(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    r[142] = a[141] >> (29 - n);
    for (i=141; i>0; i--) {
        r[i] = ((a[i] << n) | (a[i-1] >> (29 - n))) & 0x1fffffff;
    }
    r[0] = (a[0] << n) & 0x1fffffff;
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
static int sp_4096_mod_exp_2_142(sp_digit* r, const sp_digit* e, int bits, const sp_digit* m)
{
    sp_digit td[427];
    sp_digit* norm = NULL;
    sp_digit* tmp = NULL;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit o;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        tmp  = td + 284;
        XMEMSET(td, 0, sizeof(sp_digit) * 427);

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_142(norm, m);

        bits = ((bits + 3) / 4) * 4;
        i = ((bits + 28) / 29) - 1;
        c = bits % 29;
        if (c == 0) {
            c = 29;
        }
        if (i < 142) {
            n = e[i--] << (32 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 4) {
            n |= e[i--] << (3 - c);
            c += 29;
        }
        y = (int)((n >> 28) & 0xf);
        n <<= 4;
        c -= 4;
        sp_4096_lshift_142(r, norm, (byte)y);
        while ((i >= 0) || (c >= 4)) {
            if (c >= 4) {
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c -= 4;
            }
            else if (c == 0) {
                n = e[i--] << 3;
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c = 25;
            }
            else {
                y = (byte)((n >> 28) & 0xf);
                n = e[i--] << 3;
                c = 4 - c;
                y |= (byte)((n >> (32 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 29 - c;
            }

            sp_4096_mont_sqr_142(r, r, m, mp);
            sp_4096_mont_sqr_142(r, r, m, mp);
            sp_4096_mont_sqr_142(r, r, m, mp);
            sp_4096_mont_sqr_142(r, r, m, mp);

            sp_4096_lshift_142(r, r, (byte)y);
            sp_4096_mul_d_142(tmp, norm, (r[142] << 22) + (r[141] >> 7));
            r[142] = 0;
            r[141] &= 0x7fL;
            (void)sp_4096_add_142(r, r, tmp);
            sp_4096_norm_142(r);
            o = sp_4096_cmp_142(r, m);
            sp_4096_cond_sub_142(r, r, m, ~(o >> 31));
        }

        sp_4096_mont_reduce_142(r, m, mp);
        n = sp_4096_cmp_142(r, m);
        sp_4096_cond_sub_142(r, r, m, ~(n >> 31));
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
    sp_digit b[142 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    word32 i;
    int err = MP_OKAY;

    if (mp_count_bits(base) > 4096) {
        err = MP_READ_E;
    }
    else if (expLen > 512U) {
        err = MP_READ_E;
    }
    else if (mp_count_bits(mod) != 4096) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mod)) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        e = b + 142 * 2;
        m = e + 142;
        r = b;

        sp_4096_from_mp(b, 142, base);
        sp_4096_from_bin(e, 142, exp, expLen);
        sp_4096_from_mp(m, 142, mod);

    #ifdef HAVE_FFDHE_4096
        if (base->used == 1 && base->dp[0] == 2U &&
                ((m[141] << 9) | (m[140] >> 20)) == 0xffffL) {
            err = sp_4096_mod_exp_2_142(r, e, expLen * 8U, m);
        }
        else {
    #endif
            err = sp_4096_mod_exp_142(r, b, e, expLen * 8U, m, 0);
    #ifdef HAVE_FFDHE_4096
        }
    #endif
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_142(r, out);
        *outLen = 512;
        for (i=0; i<512U && out[i] == 0U; i++) {
            /* Search for first non-zero. */
        }
        *outLen -= i;
        XMEMMOVE(out, out + i, *outLen);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 142U);
    }

    return err;
}
#endif /* WOLFSSL_HAVE_SP_DH */

#endif /* WOLFSSL_HAVE_SP_DH | (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) */

#else
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
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = n-1; i >= 0; i--) {
        r[j] |= (((sp_digit)a[i]) << s);
        if (s >= 18U) {
            r[j] &= 0x3ffffff;
            s = 26U - s;
            if (j + 1 >= size) {
                break;
            }
            r[++j] = (sp_digit)a[i] >> s;
            s = 8U - s;
        }
        else {
            s += 8U;
        }
    }

    for (j++; j < size; j++) {
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
#if DIGIT_BIT == 26
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 26
    int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0x3ffffff;
        s = 26U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 26U) <= (word32)DIGIT_BIT) {
            s += 26U;
            r[j] &= 0x3ffffff;
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
        if (s + DIGIT_BIT >= 26) {
            r[j] &= 0x3ffffff;
            if (j + 1 >= size) {
                break;
            }
            s = 26 - s;
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
static void sp_4096_to_bin_162(sp_digit* r, byte* a)
{
    int i;
    int j;
    int s = 0;
    int b;

    for (i=0; i<161; i++) {
        r[i+1] += r[i] >> 26;
        r[i] &= 0x3ffffff;
    }
    j = 4103 / 8 - 1;
    a[j] = 0;
    for (i=0; i<162 && j>=0; i++) {
        b = 0;
        /* lint allow cast of mismatch sp_digit and int */
        a[j--] |= (byte)(r[i] << s); /*lint !e9033*/
        b += 8 - s;
        if (j < 0) {
            break;
        }
        while (b < 26) {
            a[j--] = (byte)(r[i] >> b);
            b += 8;
            if (j < 0) {
                break;
            }
        }
        s = 8 - (b - 26);
        if (j >= 0) {
            a[j] = 0;
        }
        if (s != 0) {
            j++;
        }
    }
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
#if defined(WOLFSSL_HAVE_SP_RSA) && !defined(SP_RSA_PRIVATE_EXP_D)
/* Normalize the values in each word to 26 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_4096_norm_81(sp_digit* a)
{
    int i;
    for (i = 0; i < 80; i += 8) {
        a[i+1] += a[i+0] >> 26; a[i+0] &= 0x3ffffff;
        a[i+2] += a[i+1] >> 26; a[i+1] &= 0x3ffffff;
        a[i+3] += a[i+2] >> 26; a[i+2] &= 0x3ffffff;
        a[i+4] += a[i+3] >> 26; a[i+3] &= 0x3ffffff;
        a[i+5] += a[i+4] >> 26; a[i+4] &= 0x3ffffff;
        a[i+6] += a[i+5] >> 26; a[i+5] &= 0x3ffffff;
        a[i+7] += a[i+6] >> 26; a[i+6] &= 0x3ffffff;
        a[i+8] += a[i+7] >> 26; a[i+7] &= 0x3ffffff;
    }
}

#endif /* WOLFSSL_HAVE_SP_RSA & !SP_RSA_PRIVATE_EXP_D */
#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || WOLFSSL_HAVE_SP_DH */
/* Normalize the values in each word to 26 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_4096_norm_79(sp_digit* a)
{
    int i;
    for (i = 0; i < 72; i += 8) {
        a[i+1] += a[i+0] >> 26; a[i+0] &= 0x3ffffff;
        a[i+2] += a[i+1] >> 26; a[i+1] &= 0x3ffffff;
        a[i+3] += a[i+2] >> 26; a[i+2] &= 0x3ffffff;
        a[i+4] += a[i+3] >> 26; a[i+3] &= 0x3ffffff;
        a[i+5] += a[i+4] >> 26; a[i+4] &= 0x3ffffff;
        a[i+6] += a[i+5] >> 26; a[i+5] &= 0x3ffffff;
        a[i+7] += a[i+6] >> 26; a[i+6] &= 0x3ffffff;
        a[i+8] += a[i+7] >> 26; a[i+7] &= 0x3ffffff;
    }
    a[73] += a[72] >> 26; a[72] &= 0x3ffffff;
    a[74] += a[73] >> 26; a[73] &= 0x3ffffff;
    a[75] += a[74] >> 26; a[74] &= 0x3ffffff;
    a[76] += a[75] >> 26; a[75] &= 0x3ffffff;
    a[77] += a[76] >> 26; a[76] &= 0x3ffffff;
    a[78] += a[77] >> 26; a[77] &= 0x3ffffff;
}

/* Normalize the values in each word to 26 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_4096_norm_162(sp_digit* a)
{
    int i;
    for (i = 0; i < 160; i += 8) {
        a[i+1] += a[i+0] >> 26; a[i+0] &= 0x3ffffff;
        a[i+2] += a[i+1] >> 26; a[i+1] &= 0x3ffffff;
        a[i+3] += a[i+2] >> 26; a[i+2] &= 0x3ffffff;
        a[i+4] += a[i+3] >> 26; a[i+3] &= 0x3ffffff;
        a[i+5] += a[i+4] >> 26; a[i+4] &= 0x3ffffff;
        a[i+6] += a[i+5] >> 26; a[i+5] &= 0x3ffffff;
        a[i+7] += a[i+6] >> 26; a[i+6] &= 0x3ffffff;
        a[i+8] += a[i+7] >> 26; a[i+7] &= 0x3ffffff;
    }
    a[161] += a[160] >> 26; a[160] &= 0x3ffffff;
}

/* Normalize the values in each word to 26 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_4096_norm_158(sp_digit* a)
{
    int i;
    for (i = 0; i < 152; i += 8) {
        a[i+1] += a[i+0] >> 26; a[i+0] &= 0x3ffffff;
        a[i+2] += a[i+1] >> 26; a[i+1] &= 0x3ffffff;
        a[i+3] += a[i+2] >> 26; a[i+2] &= 0x3ffffff;
        a[i+4] += a[i+3] >> 26; a[i+3] &= 0x3ffffff;
        a[i+5] += a[i+4] >> 26; a[i+4] &= 0x3ffffff;
        a[i+6] += a[i+5] >> 26; a[i+5] &= 0x3ffffff;
        a[i+7] += a[i+6] >> 26; a[i+6] &= 0x3ffffff;
        a[i+8] += a[i+7] >> 26; a[i+7] &= 0x3ffffff;
    }
    a[153] += a[152] >> 26; a[152] &= 0x3ffffff;
    a[154] += a[153] >> 26; a[153] &= 0x3ffffff;
    a[155] += a[154] >> 26; a[154] &= 0x3ffffff;
    a[156] += a[155] >> 26; a[155] &= 0x3ffffff;
    a[157] += a[156] >> 26; a[156] &= 0x3ffffff;
}

#ifndef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_4096_mul_9(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_uint64 t0   = ((sp_uint64)a[ 0]) * b[ 0];
    sp_uint64 t1   = ((sp_uint64)a[ 0]) * b[ 1]
                 + ((sp_uint64)a[ 1]) * b[ 0];
    sp_uint64 t2   = ((sp_uint64)a[ 0]) * b[ 2]
                 + ((sp_uint64)a[ 1]) * b[ 1]
                 + ((sp_uint64)a[ 2]) * b[ 0];
    sp_uint64 t3   = ((sp_uint64)a[ 0]) * b[ 3]
                 + ((sp_uint64)a[ 1]) * b[ 2]
                 + ((sp_uint64)a[ 2]) * b[ 1]
                 + ((sp_uint64)a[ 3]) * b[ 0];
    sp_uint64 t4   = ((sp_uint64)a[ 0]) * b[ 4]
                 + ((sp_uint64)a[ 1]) * b[ 3]
                 + ((sp_uint64)a[ 2]) * b[ 2]
                 + ((sp_uint64)a[ 3]) * b[ 1]
                 + ((sp_uint64)a[ 4]) * b[ 0];
    sp_uint64 t5   = ((sp_uint64)a[ 0]) * b[ 5]
                 + ((sp_uint64)a[ 1]) * b[ 4]
                 + ((sp_uint64)a[ 2]) * b[ 3]
                 + ((sp_uint64)a[ 3]) * b[ 2]
                 + ((sp_uint64)a[ 4]) * b[ 1]
                 + ((sp_uint64)a[ 5]) * b[ 0];
    sp_uint64 t6   = ((sp_uint64)a[ 0]) * b[ 6]
                 + ((sp_uint64)a[ 1]) * b[ 5]
                 + ((sp_uint64)a[ 2]) * b[ 4]
                 + ((sp_uint64)a[ 3]) * b[ 3]
                 + ((sp_uint64)a[ 4]) * b[ 2]
                 + ((sp_uint64)a[ 5]) * b[ 1]
                 + ((sp_uint64)a[ 6]) * b[ 0];
    sp_uint64 t7   = ((sp_uint64)a[ 0]) * b[ 7]
                 + ((sp_uint64)a[ 1]) * b[ 6]
                 + ((sp_uint64)a[ 2]) * b[ 5]
                 + ((sp_uint64)a[ 3]) * b[ 4]
                 + ((sp_uint64)a[ 4]) * b[ 3]
                 + ((sp_uint64)a[ 5]) * b[ 2]
                 + ((sp_uint64)a[ 6]) * b[ 1]
                 + ((sp_uint64)a[ 7]) * b[ 0];
    sp_uint64 t8   = ((sp_uint64)a[ 0]) * b[ 8]
                 + ((sp_uint64)a[ 1]) * b[ 7]
                 + ((sp_uint64)a[ 2]) * b[ 6]
                 + ((sp_uint64)a[ 3]) * b[ 5]
                 + ((sp_uint64)a[ 4]) * b[ 4]
                 + ((sp_uint64)a[ 5]) * b[ 3]
                 + ((sp_uint64)a[ 6]) * b[ 2]
                 + ((sp_uint64)a[ 7]) * b[ 1]
                 + ((sp_uint64)a[ 8]) * b[ 0];
    sp_uint64 t9   = ((sp_uint64)a[ 1]) * b[ 8]
                 + ((sp_uint64)a[ 2]) * b[ 7]
                 + ((sp_uint64)a[ 3]) * b[ 6]
                 + ((sp_uint64)a[ 4]) * b[ 5]
                 + ((sp_uint64)a[ 5]) * b[ 4]
                 + ((sp_uint64)a[ 6]) * b[ 3]
                 + ((sp_uint64)a[ 7]) * b[ 2]
                 + ((sp_uint64)a[ 8]) * b[ 1];
    sp_uint64 t10  = ((sp_uint64)a[ 2]) * b[ 8]
                 + ((sp_uint64)a[ 3]) * b[ 7]
                 + ((sp_uint64)a[ 4]) * b[ 6]
                 + ((sp_uint64)a[ 5]) * b[ 5]
                 + ((sp_uint64)a[ 6]) * b[ 4]
                 + ((sp_uint64)a[ 7]) * b[ 3]
                 + ((sp_uint64)a[ 8]) * b[ 2];
    sp_uint64 t11  = ((sp_uint64)a[ 3]) * b[ 8]
                 + ((sp_uint64)a[ 4]) * b[ 7]
                 + ((sp_uint64)a[ 5]) * b[ 6]
                 + ((sp_uint64)a[ 6]) * b[ 5]
                 + ((sp_uint64)a[ 7]) * b[ 4]
                 + ((sp_uint64)a[ 8]) * b[ 3];
    sp_uint64 t12  = ((sp_uint64)a[ 4]) * b[ 8]
                 + ((sp_uint64)a[ 5]) * b[ 7]
                 + ((sp_uint64)a[ 6]) * b[ 6]
                 + ((sp_uint64)a[ 7]) * b[ 5]
                 + ((sp_uint64)a[ 8]) * b[ 4];
    sp_uint64 t13  = ((sp_uint64)a[ 5]) * b[ 8]
                 + ((sp_uint64)a[ 6]) * b[ 7]
                 + ((sp_uint64)a[ 7]) * b[ 6]
                 + ((sp_uint64)a[ 8]) * b[ 5];
    sp_uint64 t14  = ((sp_uint64)a[ 6]) * b[ 8]
                 + ((sp_uint64)a[ 7]) * b[ 7]
                 + ((sp_uint64)a[ 8]) * b[ 6];
    sp_uint64 t15  = ((sp_uint64)a[ 7]) * b[ 8]
                 + ((sp_uint64)a[ 8]) * b[ 7];
    sp_uint64 t16  = ((sp_uint64)a[ 8]) * b[ 8];

    t1   += t0  >> 26; r[ 0] = t0  & 0x3ffffff;
    t2   += t1  >> 26; r[ 1] = t1  & 0x3ffffff;
    t3   += t2  >> 26; r[ 2] = t2  & 0x3ffffff;
    t4   += t3  >> 26; r[ 3] = t3  & 0x3ffffff;
    t5   += t4  >> 26; r[ 4] = t4  & 0x3ffffff;
    t6   += t5  >> 26; r[ 5] = t5  & 0x3ffffff;
    t7   += t6  >> 26; r[ 6] = t6  & 0x3ffffff;
    t8   += t7  >> 26; r[ 7] = t7  & 0x3ffffff;
    t9   += t8  >> 26; r[ 8] = t8  & 0x3ffffff;
    t10  += t9  >> 26; r[ 9] = t9  & 0x3ffffff;
    t11  += t10 >> 26; r[10] = t10 & 0x3ffffff;
    t12  += t11 >> 26; r[11] = t11 & 0x3ffffff;
    t13  += t12 >> 26; r[12] = t12 & 0x3ffffff;
    t14  += t13 >> 26; r[13] = t13 & 0x3ffffff;
    t15  += t14 >> 26; r[14] = t14 & 0x3ffffff;
    t16  += t15 >> 26; r[15] = t15 & 0x3ffffff;
    r[17] = (sp_digit)(t16 >> 26);
                       r[16] = t16 & 0x3ffffff;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_add_9(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    r[ 0] = a[ 0] + b[ 0];
    r[ 1] = a[ 1] + b[ 1];
    r[ 2] = a[ 2] + b[ 2];
    r[ 3] = a[ 3] + b[ 3];
    r[ 4] = a[ 4] + b[ 4];
    r[ 5] = a[ 5] + b[ 5];
    r[ 6] = a[ 6] + b[ 6];
    r[ 7] = a[ 7] + b[ 7];
    r[ 8] = a[ 8] + b[ 8];

    return 0;
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_sub_18(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 16; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }
    r[16] = a[16] - b[16];
    r[17] = a[17] - b[17];

    return 0;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_add_18(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 16; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[16] = a[16] + b[16];
    r[17] = a[17] + b[17];

    return 0;
}

/* Normalize the values in each word to 26 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_4096_norm_9(sp_digit* a)
{
    a[1] += a[0] >> 26; a[0] &= 0x3ffffff;
    a[2] += a[1] >> 26; a[1] &= 0x3ffffff;
    a[3] += a[2] >> 26; a[2] &= 0x3ffffff;
    a[4] += a[3] >> 26; a[3] &= 0x3ffffff;
    a[5] += a[4] >> 26; a[4] &= 0x3ffffff;
    a[6] += a[5] >> 26; a[5] &= 0x3ffffff;
    a[7] += a[6] >> 26; a[6] &= 0x3ffffff;
    a[8] += a[7] >> 26; a[7] &= 0x3ffffff;
}

/* Normalize the values in each word to 26 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_4096_norm_18(sp_digit* a)
{
    int i;
    for (i = 0; i < 16; i += 8) {
        a[i+1] += a[i+0] >> 26; a[i+0] &= 0x3ffffff;
        a[i+2] += a[i+1] >> 26; a[i+1] &= 0x3ffffff;
        a[i+3] += a[i+2] >> 26; a[i+2] &= 0x3ffffff;
        a[i+4] += a[i+3] >> 26; a[i+3] &= 0x3ffffff;
        a[i+5] += a[i+4] >> 26; a[i+4] &= 0x3ffffff;
        a[i+6] += a[i+5] >> 26; a[i+5] &= 0x3ffffff;
        a[i+7] += a[i+6] >> 26; a[i+6] &= 0x3ffffff;
        a[i+8] += a[i+7] >> 26; a[i+7] &= 0x3ffffff;
    }
    a[17] += a[16] >> 26; a[16] &= 0x3ffffff;
}

/* Normalize the values in each word to 26 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_4096_norm_54(sp_digit* a)
{
    int i;
    for (i = 0; i < 48; i += 8) {
        a[i+1] += a[i+0] >> 26; a[i+0] &= 0x3ffffff;
        a[i+2] += a[i+1] >> 26; a[i+1] &= 0x3ffffff;
        a[i+3] += a[i+2] >> 26; a[i+2] &= 0x3ffffff;
        a[i+4] += a[i+3] >> 26; a[i+3] &= 0x3ffffff;
        a[i+5] += a[i+4] >> 26; a[i+4] &= 0x3ffffff;
        a[i+6] += a[i+5] >> 26; a[i+5] &= 0x3ffffff;
        a[i+7] += a[i+6] >> 26; a[i+6] &= 0x3ffffff;
        a[i+8] += a[i+7] >> 26; a[i+7] &= 0x3ffffff;
    }
    a[49] += a[48] >> 26; a[48] &= 0x3ffffff;
    a[50] += a[49] >> 26; a[49] &= 0x3ffffff;
    a[51] += a[50] >> 26; a[50] &= 0x3ffffff;
    a[52] += a[51] >> 26; a[51] &= 0x3ffffff;
    a[53] += a[52] >> 26; a[52] &= 0x3ffffff;
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_4096_mul_27(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit p0[18];
    sp_digit p1[18];
    sp_digit p2[18];
    sp_digit p3[18];
    sp_digit p4[18];
    sp_digit p5[18];
    sp_digit t0[18];
    sp_digit t1[18];
    sp_digit t2[18];
    sp_digit a0[9];
    sp_digit a1[9];
    sp_digit a2[9];
    sp_digit b0[9];
    sp_digit b1[9];
    sp_digit b2[9];
    (void)sp_4096_add_9(a0, a, &a[9]);
    sp_4096_norm_9(a0);
    (void)sp_4096_add_9(b0, b, &b[9]);
    sp_4096_norm_9(b0);
    (void)sp_4096_add_9(a1, &a[9], &a[18]);
    sp_4096_norm_9(a1);
    (void)sp_4096_add_9(b1, &b[9], &b[18]);
    sp_4096_norm_9(b1);
    (void)sp_4096_add_9(a2, a0, &a[18]);
    sp_4096_norm_9(a1);
    (void)sp_4096_add_9(b2, b0, &b[18]);
    sp_4096_norm_9(b2);
    sp_4096_mul_9(p0, a, b);
    sp_4096_mul_9(p2, &a[9], &b[9]);
    sp_4096_mul_9(p4, &a[18], &b[18]);
    sp_4096_mul_9(p1, a0, b0);
    sp_4096_mul_9(p3, a1, b1);
    sp_4096_mul_9(p5, a2, b2);
    XMEMSET(r, 0, sizeof(*r)*2U*27U);
    (void)sp_4096_sub_18(t0, p3, p2);
    (void)sp_4096_sub_18(t1, p1, p2);
    (void)sp_4096_sub_18(t2, p5, t0);
    (void)sp_4096_sub_18(t2, t2, t1);
    sp_4096_norm_18(t2);
    (void)sp_4096_sub_18(t0, t0, p4);
    sp_4096_norm_18(t0);
    (void)sp_4096_sub_18(t1, t1, p0);
    sp_4096_norm_18(t1);
    (void)sp_4096_add_18(r, r, p0);
    (void)sp_4096_add_18(&r[9], &r[9], t1);
    (void)sp_4096_add_18(&r[18], &r[18], t2);
    (void)sp_4096_add_18(&r[27], &r[27], t0);
    (void)sp_4096_add_18(&r[36], &r[36], p4);
    sp_4096_norm_54(r);
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_add_27(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 24; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[24] = a[24] + b[24];
    r[25] = a[25] + b[25];
    r[26] = a[26] + b[26];

    return 0;
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_sub_54(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 48; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }
    r[48] = a[48] - b[48];
    r[49] = a[49] - b[49];
    r[50] = a[50] - b[50];
    r[51] = a[51] - b[51];
    r[52] = a[52] - b[52];
    r[53] = a[53] - b[53];

    return 0;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_add_54(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 48; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[48] = a[48] + b[48];
    r[49] = a[49] + b[49];
    r[50] = a[50] + b[50];
    r[51] = a[51] + b[51];
    r[52] = a[52] + b[52];
    r[53] = a[53] + b[53];

    return 0;
}

/* Normalize the values in each word to 26 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_4096_norm_27(sp_digit* a)
{
    int i;
    for (i = 0; i < 24; i += 8) {
        a[i+1] += a[i+0] >> 26; a[i+0] &= 0x3ffffff;
        a[i+2] += a[i+1] >> 26; a[i+1] &= 0x3ffffff;
        a[i+3] += a[i+2] >> 26; a[i+2] &= 0x3ffffff;
        a[i+4] += a[i+3] >> 26; a[i+3] &= 0x3ffffff;
        a[i+5] += a[i+4] >> 26; a[i+4] &= 0x3ffffff;
        a[i+6] += a[i+5] >> 26; a[i+5] &= 0x3ffffff;
        a[i+7] += a[i+6] >> 26; a[i+6] &= 0x3ffffff;
        a[i+8] += a[i+7] >> 26; a[i+7] &= 0x3ffffff;
    }
    a[25] += a[24] >> 26; a[24] &= 0x3ffffff;
    a[26] += a[25] >> 26; a[25] &= 0x3ffffff;
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_4096_mul_81(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit p0[54];
    sp_digit p1[54];
    sp_digit p2[54];
    sp_digit p3[54];
    sp_digit p4[54];
    sp_digit p5[54];
    sp_digit t0[54];
    sp_digit t1[54];
    sp_digit t2[54];
    sp_digit a0[27];
    sp_digit a1[27];
    sp_digit a2[27];
    sp_digit b0[27];
    sp_digit b1[27];
    sp_digit b2[27];
    (void)sp_4096_add_27(a0, a, &a[27]);
    sp_4096_norm_27(a0);
    (void)sp_4096_add_27(b0, b, &b[27]);
    sp_4096_norm_27(b0);
    (void)sp_4096_add_27(a1, &a[27], &a[54]);
    sp_4096_norm_27(a1);
    (void)sp_4096_add_27(b1, &b[27], &b[54]);
    sp_4096_norm_27(b1);
    (void)sp_4096_add_27(a2, a0, &a[54]);
    sp_4096_norm_27(a1);
    (void)sp_4096_add_27(b2, b0, &b[54]);
    sp_4096_norm_27(b2);
    sp_4096_mul_27(p0, a, b);
    sp_4096_mul_27(p2, &a[27], &b[27]);
    sp_4096_mul_27(p4, &a[54], &b[54]);
    sp_4096_mul_27(p1, a0, b0);
    sp_4096_mul_27(p3, a1, b1);
    sp_4096_mul_27(p5, a2, b2);
    XMEMSET(r, 0, sizeof(*r)*2U*81U);
    (void)sp_4096_sub_54(t0, p3, p2);
    (void)sp_4096_sub_54(t1, p1, p2);
    (void)sp_4096_sub_54(t2, p5, t0);
    (void)sp_4096_sub_54(t2, t2, t1);
    sp_4096_norm_54(t2);
    (void)sp_4096_sub_54(t0, t0, p4);
    sp_4096_norm_54(t0);
    (void)sp_4096_sub_54(t1, t1, p0);
    sp_4096_norm_54(t1);
    (void)sp_4096_add_54(r, r, p0);
    (void)sp_4096_add_54(&r[27], &r[27], t1);
    (void)sp_4096_add_54(&r[54], &r[54], t2);
    (void)sp_4096_add_54(&r[81], &r[81], t0);
    (void)sp_4096_add_54(&r[108], &r[108], p4);
    sp_4096_norm_162(r);
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_add_81(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 80; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[80] = a[80] + b[80];

    return 0;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_add_162(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 160; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[160] = a[160] + b[160];
    r[161] = a[161] + b[161];

    return 0;
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_sub_162(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 160; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }
    r[160] = a[160] - b[160];
    r[161] = a[161] - b[161];

    return 0;
}

/* Normalize the values in each word to 26 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_4096_norm_324(sp_digit* a)
{
    int i;
    for (i = 0; i < 320; i += 8) {
        a[i+1] += a[i+0] >> 26; a[i+0] &= 0x3ffffff;
        a[i+2] += a[i+1] >> 26; a[i+1] &= 0x3ffffff;
        a[i+3] += a[i+2] >> 26; a[i+2] &= 0x3ffffff;
        a[i+4] += a[i+3] >> 26; a[i+3] &= 0x3ffffff;
        a[i+5] += a[i+4] >> 26; a[i+4] &= 0x3ffffff;
        a[i+6] += a[i+5] >> 26; a[i+5] &= 0x3ffffff;
        a[i+7] += a[i+6] >> 26; a[i+6] &= 0x3ffffff;
        a[i+8] += a[i+7] >> 26; a[i+7] &= 0x3ffffff;
    }
    a[321] += a[320] >> 26; a[320] &= 0x3ffffff;
    a[322] += a[321] >> 26; a[321] &= 0x3ffffff;
    a[323] += a[322] >> 26; a[322] &= 0x3ffffff;
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_4096_mul_162(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[162];
    sp_digit* a1 = z1;
    sp_digit b1[81];
    sp_digit* z2 = r + 162;
    (void)sp_4096_add_81(a1, a, &a[81]);
    sp_4096_norm_81(a1);
    (void)sp_4096_add_81(b1, b, &b[81]);
    sp_4096_norm_81(b1);
    sp_4096_mul_81(z2, &a[81], &b[81]);
    sp_4096_mul_81(z0, a, b);
    sp_4096_mul_81(z1, a1, b1);
    (void)sp_4096_sub_162(z1, z1, z2);
    (void)sp_4096_sub_162(z1, z1, z0);
    (void)sp_4096_add_162(r + 81, r + 81, z1);
    sp_4096_norm_324(r);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_4096_sqr_9(sp_digit* r, const sp_digit* a)
{
    sp_uint64 t0   =  ((sp_uint64)a[ 0]) * a[ 0];
    sp_uint64 t1   = (((sp_uint64)a[ 0]) * a[ 1]) * 2;
    sp_uint64 t2   = (((sp_uint64)a[ 0]) * a[ 2]) * 2
                 +  ((sp_uint64)a[ 1]) * a[ 1];
    sp_uint64 t3   = (((sp_uint64)a[ 0]) * a[ 3]
                 +  ((sp_uint64)a[ 1]) * a[ 2]) * 2;
    sp_uint64 t4   = (((sp_uint64)a[ 0]) * a[ 4]
                 +  ((sp_uint64)a[ 1]) * a[ 3]) * 2
                 +  ((sp_uint64)a[ 2]) * a[ 2];
    sp_uint64 t5   = (((sp_uint64)a[ 0]) * a[ 5]
                 +  ((sp_uint64)a[ 1]) * a[ 4]
                 +  ((sp_uint64)a[ 2]) * a[ 3]) * 2;
    sp_uint64 t6   = (((sp_uint64)a[ 0]) * a[ 6]
                 +  ((sp_uint64)a[ 1]) * a[ 5]
                 +  ((sp_uint64)a[ 2]) * a[ 4]) * 2
                 +  ((sp_uint64)a[ 3]) * a[ 3];
    sp_uint64 t7   = (((sp_uint64)a[ 0]) * a[ 7]
                 +  ((sp_uint64)a[ 1]) * a[ 6]
                 +  ((sp_uint64)a[ 2]) * a[ 5]
                 +  ((sp_uint64)a[ 3]) * a[ 4]) * 2;
    sp_uint64 t8   = (((sp_uint64)a[ 0]) * a[ 8]
                 +  ((sp_uint64)a[ 1]) * a[ 7]
                 +  ((sp_uint64)a[ 2]) * a[ 6]
                 +  ((sp_uint64)a[ 3]) * a[ 5]) * 2
                 +  ((sp_uint64)a[ 4]) * a[ 4];
    sp_uint64 t9   = (((sp_uint64)a[ 1]) * a[ 8]
                 +  ((sp_uint64)a[ 2]) * a[ 7]
                 +  ((sp_uint64)a[ 3]) * a[ 6]
                 +  ((sp_uint64)a[ 4]) * a[ 5]) * 2;
    sp_uint64 t10  = (((sp_uint64)a[ 2]) * a[ 8]
                 +  ((sp_uint64)a[ 3]) * a[ 7]
                 +  ((sp_uint64)a[ 4]) * a[ 6]) * 2
                 +  ((sp_uint64)a[ 5]) * a[ 5];
    sp_uint64 t11  = (((sp_uint64)a[ 3]) * a[ 8]
                 +  ((sp_uint64)a[ 4]) * a[ 7]
                 +  ((sp_uint64)a[ 5]) * a[ 6]) * 2;
    sp_uint64 t12  = (((sp_uint64)a[ 4]) * a[ 8]
                 +  ((sp_uint64)a[ 5]) * a[ 7]) * 2
                 +  ((sp_uint64)a[ 6]) * a[ 6];
    sp_uint64 t13  = (((sp_uint64)a[ 5]) * a[ 8]
                 +  ((sp_uint64)a[ 6]) * a[ 7]) * 2;
    sp_uint64 t14  = (((sp_uint64)a[ 6]) * a[ 8]) * 2
                 +  ((sp_uint64)a[ 7]) * a[ 7];
    sp_uint64 t15  = (((sp_uint64)a[ 7]) * a[ 8]) * 2;
    sp_uint64 t16  =  ((sp_uint64)a[ 8]) * a[ 8];

    t1   += t0  >> 26; r[ 0] = t0  & 0x3ffffff;
    t2   += t1  >> 26; r[ 1] = t1  & 0x3ffffff;
    t3   += t2  >> 26; r[ 2] = t2  & 0x3ffffff;
    t4   += t3  >> 26; r[ 3] = t3  & 0x3ffffff;
    t5   += t4  >> 26; r[ 4] = t4  & 0x3ffffff;
    t6   += t5  >> 26; r[ 5] = t5  & 0x3ffffff;
    t7   += t6  >> 26; r[ 6] = t6  & 0x3ffffff;
    t8   += t7  >> 26; r[ 7] = t7  & 0x3ffffff;
    t9   += t8  >> 26; r[ 8] = t8  & 0x3ffffff;
    t10  += t9  >> 26; r[ 9] = t9  & 0x3ffffff;
    t11  += t10 >> 26; r[10] = t10 & 0x3ffffff;
    t12  += t11 >> 26; r[11] = t11 & 0x3ffffff;
    t13  += t12 >> 26; r[12] = t12 & 0x3ffffff;
    t14  += t13 >> 26; r[13] = t13 & 0x3ffffff;
    t15  += t14 >> 26; r[14] = t14 & 0x3ffffff;
    t16  += t15 >> 26; r[15] = t15 & 0x3ffffff;
    r[17] = (sp_digit)(t16 >> 26);
                       r[16] = t16 & 0x3ffffff;
}

/* Square a into r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_4096_sqr_27(sp_digit* r, const sp_digit* a)
{
    sp_digit p0[18];
    sp_digit p1[18];
    sp_digit p2[18];
    sp_digit p3[18];
    sp_digit p4[18];
    sp_digit p5[18];
    sp_digit t0[18];
    sp_digit t1[18];
    sp_digit t2[18];
    sp_digit a0[9];
    sp_digit a1[9];
    sp_digit a2[9];
    (void)sp_4096_add_9(a0, a, &a[9]);
    sp_4096_norm_9(a0);
    (void)sp_4096_add_9(a1, &a[9], &a[18]);
    sp_4096_norm_9(a1);
    (void)sp_4096_add_9(a2, a0, &a[18]);
    sp_4096_norm_9(a2);
    sp_4096_sqr_9(p0, a);
    sp_4096_sqr_9(p2, &a[9]);
    sp_4096_sqr_9(p4, &a[18]);
    sp_4096_sqr_9(p1, a0);
    sp_4096_sqr_9(p3, a1);
    sp_4096_sqr_9(p5, a2);
    XMEMSET(r, 0, sizeof(*r)*2U*27U);
    (void)sp_4096_sub_18(t0, p3, p2);
    (void)sp_4096_sub_18(t1, p1, p2);
    (void)sp_4096_sub_18(t2, p5, t0);
    (void)sp_4096_sub_18(t2, t2, t1);
    sp_4096_norm_18(t2);
    (void)sp_4096_sub_18(t0, t0, p4);
    sp_4096_norm_18(t0);
    (void)sp_4096_sub_18(t1, t1, p0);
    sp_4096_norm_18(t1);
    (void)sp_4096_add_18(r, r, p0);
    (void)sp_4096_add_18(&r[9], &r[9], t1);
    (void)sp_4096_add_18(&r[18], &r[18], t2);
    (void)sp_4096_add_18(&r[27], &r[27], t0);
    (void)sp_4096_add_18(&r[36], &r[36], p4);
    sp_4096_norm_54(r);
}

/* Square a into r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_4096_sqr_81(sp_digit* r, const sp_digit* a)
{
    sp_digit p0[54];
    sp_digit p1[54];
    sp_digit p2[54];
    sp_digit p3[54];
    sp_digit p4[54];
    sp_digit p5[54];
    sp_digit t0[54];
    sp_digit t1[54];
    sp_digit t2[54];
    sp_digit a0[27];
    sp_digit a1[27];
    sp_digit a2[27];
    (void)sp_4096_add_27(a0, a, &a[27]);
    sp_4096_norm_27(a0);
    (void)sp_4096_add_27(a1, &a[27], &a[54]);
    sp_4096_norm_27(a1);
    (void)sp_4096_add_27(a2, a0, &a[54]);
    sp_4096_norm_27(a2);
    sp_4096_sqr_27(p0, a);
    sp_4096_sqr_27(p2, &a[27]);
    sp_4096_sqr_27(p4, &a[54]);
    sp_4096_sqr_27(p1, a0);
    sp_4096_sqr_27(p3, a1);
    sp_4096_sqr_27(p5, a2);
    XMEMSET(r, 0, sizeof(*r)*2U*81U);
    (void)sp_4096_sub_54(t0, p3, p2);
    (void)sp_4096_sub_54(t1, p1, p2);
    (void)sp_4096_sub_54(t2, p5, t0);
    (void)sp_4096_sub_54(t2, t2, t1);
    sp_4096_norm_54(t2);
    (void)sp_4096_sub_54(t0, t0, p4);
    sp_4096_norm_54(t0);
    (void)sp_4096_sub_54(t1, t1, p0);
    sp_4096_norm_54(t1);
    (void)sp_4096_add_54(r, r, p0);
    (void)sp_4096_add_54(&r[27], &r[27], t1);
    (void)sp_4096_add_54(&r[54], &r[54], t2);
    (void)sp_4096_add_54(&r[81], &r[81], t0);
    (void)sp_4096_add_54(&r[108], &r[108], p4);
    sp_4096_norm_162(r);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_4096_sqr_162(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit z1[162];
    sp_digit* a1 = z1;
    sp_digit* z2 = r + 162;
    (void)sp_4096_add_81(a1, a, &a[81]);
    sp_4096_norm_81(a1);
    sp_4096_sqr_81(z2, &a[81]);
    sp_4096_sqr_81(z0, a);
    sp_4096_sqr_81(z1, a1);
    (void)sp_4096_sub_162(z1, z1, z2);
    (void)sp_4096_sub_162(z1, z1, z0);
    (void)sp_4096_add_162(r + 81, r + 81, z1);
    sp_4096_norm_324(r);
}

#endif /* !WOLFSSL_SP_SMALL */
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
    x &= 0x3ffffff;

    /* rho = -1/m mod b */
    *rho = ((sp_digit)1 << 26) - x;
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_d_162(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int64 tb = b;
    sp_int64 t = 0;
    sp_digit t2;
    sp_int64 p[4];
    int i;

    for (i = 0; i < 160; i += 4) {
        p[0] = tb * a[i + 0];
        p[1] = tb * a[i + 1];
        p[2] = tb * a[i + 2];
        p[3] = tb * a[i + 3];
        t += p[0];
        t2 = (sp_digit)(t & 0x3ffffff);
        t >>= 26;
        r[i + 0] = (sp_digit)t2;
        t += p[1];
        t2 = (sp_digit)(t & 0x3ffffff);
        t >>= 26;
        r[i + 1] = (sp_digit)t2;
        t += p[2];
        t2 = (sp_digit)(t & 0x3ffffff);
        t >>= 26;
        r[i + 2] = (sp_digit)t2;
        t += p[3];
        t2 = (sp_digit)(t & 0x3ffffff);
        t >>= 26;
        r[i + 3] = (sp_digit)t2;
    }
    t += tb * a[160];
    r[160] = (sp_digit)(t & 0x3ffffff);
    t >>= 26;
    t += tb * a[161];
    r[161] = (sp_digit)(t & 0x3ffffff);
    t >>= 26;
    r[162] = (sp_digit)(t & 0x3ffffff);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH)) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
#if defined(WOLFSSL_HAVE_SP_RSA) && !defined(SP_RSA_PRIVATE_EXP_D)
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_sub_81(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 80; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }
    r[80] = a[80] - b[80];

    return 0;
}

/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 4096 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_4096_mont_norm_81(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
    int i;

    for (i = 0; i < 72; i += 8) {
        r[i + 0] = 0x3ffffff;
        r[i + 1] = 0x3ffffff;
        r[i + 2] = 0x3ffffff;
        r[i + 3] = 0x3ffffff;
        r[i + 4] = 0x3ffffff;
        r[i + 5] = 0x3ffffff;
        r[i + 6] = 0x3ffffff;
        r[i + 7] = 0x3ffffff;
    }
    r[72] = 0x3ffffff;
    r[73] = 0x3ffffff;
    r[74] = 0x3ffffff;
    r[75] = 0x3ffffff;
    r[76] = 0x3ffffff;
    r[77] = 0x3ffffff;
    r[78] = 0xfffffL;
    r[79] = 0;
    r[80] = 0;

    /* r = (2^n - 1) mod n */
    (void)sp_4096_sub_81(r, r, m);

    /* Add one so r = 2^n mod m */
    r[0] += 1;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_4096_cmp_81(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
    int i;

    r |= (a[80] - b[80]) & (0 - (sp_digit)1);
    for (i = 72; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & ~(((sp_digit)0 - r) >> 25);
        r |= (a[i + 6] - b[i + 6]) & ~(((sp_digit)0 - r) >> 25);
        r |= (a[i + 5] - b[i + 5]) & ~(((sp_digit)0 - r) >> 25);
        r |= (a[i + 4] - b[i + 4]) & ~(((sp_digit)0 - r) >> 25);
        r |= (a[i + 3] - b[i + 3]) & ~(((sp_digit)0 - r) >> 25);
        r |= (a[i + 2] - b[i + 2]) & ~(((sp_digit)0 - r) >> 25);
        r |= (a[i + 1] - b[i + 1]) & ~(((sp_digit)0 - r) >> 25);
        r |= (a[i + 0] - b[i + 0]) & ~(((sp_digit)0 - r) >> 25);
    }

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_4096_cond_sub_81(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 80; i += 8) {
        r[i + 0] = a[i + 0] - (b[i + 0] & m);
        r[i + 1] = a[i + 1] - (b[i + 1] & m);
        r[i + 2] = a[i + 2] - (b[i + 2] & m);
        r[i + 3] = a[i + 3] - (b[i + 3] & m);
        r[i + 4] = a[i + 4] - (b[i + 4] & m);
        r[i + 5] = a[i + 5] - (b[i + 5] & m);
        r[i + 6] = a[i + 6] - (b[i + 6] & m);
        r[i + 7] = a[i + 7] - (b[i + 7] & m);
    }
    r[80] = a[80] - (b[80] & m);
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_add_81(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifndef WOLFSSL_SP_LARGE_CODE
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 81; i++) {
        t += r[i];
        t += tb * a[i];
        r[i] = ((sp_digit)t) & 0x3ffffff;
        t >>= 26;
    }
    r[81] += (sp_digit)t;
#else
    sp_int64 tb = b;
    sp_int64 t[8];
    int i;

    t[0] = 0;
    for (i = 0; i < 80; i += 8) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        t[4]  = (tb * a[i+4]) + r[i+4];
        t[5]  = (tb * a[i+5]) + r[i+5];
        t[6]  = (tb * a[i+6]) + r[i+6];
        t[7]  = (tb * a[i+7]) + r[i+7];
        r[i+0] = t[0] & 0x3ffffff;
        t[1] += t[0] >> 26;
        r[i+1] = t[1] & 0x3ffffff;
        t[2] += t[1] >> 26;
        r[i+2] = t[2] & 0x3ffffff;
        t[3] += t[2] >> 26;
        r[i+3] = t[3] & 0x3ffffff;
        t[4] += t[3] >> 26;
        r[i+4] = t[4] & 0x3ffffff;
        t[5] += t[4] >> 26;
        r[i+5] = t[5] & 0x3ffffff;
        t[6] += t[5] >> 26;
        r[i+6] = t[6] & 0x3ffffff;
        t[7] += t[6] >> 26;
        r[i+7] = t[7] & 0x3ffffff;
        t[0]  = t[7] >> 26;
    }
    t[0] += (tb * a[80]) + r[80];
    r[80] = t[0] & 0x3ffffff;
    r[81] +=  (sp_digit)(t[0] >> 26);
#endif /* !WOLFSSL_SP_LARGE_CODE */
}

/* Shift the result in the high 2048 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_4096_mont_shift_81(sp_digit* r, const sp_digit* a)
{
    int i;
    sp_int64 n = a[78] >> 20;
    n += ((sp_int64)a[79]) << 6;
    for (i = 0; i < 72; i += 8) {
        r[i + 0] = n & 0x3ffffff;
        n >>= 26; n += ((sp_int64)a[i + 80]) << 6;
        r[i + 1] = n & 0x3ffffff;
        n >>= 26; n += ((sp_int64)a[i + 81]) << 6;
        r[i + 2] = n & 0x3ffffff;
        n >>= 26; n += ((sp_int64)a[i + 82]) << 6;
        r[i + 3] = n & 0x3ffffff;
        n >>= 26; n += ((sp_int64)a[i + 83]) << 6;
        r[i + 4] = n & 0x3ffffff;
        n >>= 26; n += ((sp_int64)a[i + 84]) << 6;
        r[i + 5] = n & 0x3ffffff;
        n >>= 26; n += ((sp_int64)a[i + 85]) << 6;
        r[i + 6] = n & 0x3ffffff;
        n >>= 26; n += ((sp_int64)a[i + 86]) << 6;
        r[i + 7] = n & 0x3ffffff;
        n >>= 26; n += ((sp_int64)a[i + 87]) << 6;
    }
    r[72] = n & 0x3ffffff; n >>= 26; n += ((sp_int64)a[152]) << 6;
    r[73] = n & 0x3ffffff; n >>= 26; n += ((sp_int64)a[153]) << 6;
    r[74] = n & 0x3ffffff; n >>= 26; n += ((sp_int64)a[154]) << 6;
    r[75] = n & 0x3ffffff; n >>= 26; n += ((sp_int64)a[155]) << 6;
    r[76] = n & 0x3ffffff; n >>= 26; n += ((sp_int64)a[156]) << 6;
    r[77] = n & 0x3ffffff; n >>= 26; n += ((sp_int64)a[157]) << 6;
    r[78] = (sp_digit)n;
    XMEMSET(&r[79], 0, sizeof(*r) * 79U);
}

/* Reduce the number back to 4096 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_4096_mont_reduce_81(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_4096_norm_81(a + 79);

    for (i=0; i<78; i++) {
        mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x3ffffff;
        sp_4096_mul_add_81(a+i, m, mu);
        a[i+1] += a[i] >> 26;
    }
    mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0xfffffL;
    sp_4096_mul_add_81(a+i, m, mu);
    a[i+1] += a[i] >> 26;
    a[i] &= 0x3ffffff;
    sp_4096_mont_shift_81(a, a);
    over = a[78] - m[78];
    sp_4096_cond_sub_81(a, a, m, ~((over - 1) >> 31));
    sp_4096_norm_81(a);
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
SP_NOINLINE static void sp_4096_mont_mul_81(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_4096_mul_81(r, a, b);
    sp_4096_mont_reduce_81(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_4096_mont_sqr_81(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_4096_sqr_81(r, a);
    sp_4096_mont_reduce_81(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_d_81(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int64 tb = b;
    sp_int64 t = 0;
    sp_digit t2;
    sp_int64 p[4];
    int i;

    for (i = 0; i < 80; i += 4) {
        p[0] = tb * a[i + 0];
        p[1] = tb * a[i + 1];
        p[2] = tb * a[i + 2];
        p[3] = tb * a[i + 3];
        t += p[0];
        t2 = (sp_digit)(t & 0x3ffffff);
        t >>= 26;
        r[i + 0] = (sp_digit)t2;
        t += p[1];
        t2 = (sp_digit)(t & 0x3ffffff);
        t >>= 26;
        r[i + 1] = (sp_digit)t2;
        t += p[2];
        t2 = (sp_digit)(t & 0x3ffffff);
        t >>= 26;
        r[i + 2] = (sp_digit)t2;
        t += p[3];
        t2 = (sp_digit)(t & 0x3ffffff);
        t >>= 26;
        r[i + 3] = (sp_digit)t2;
    }
    t += tb * a[80];
    r[80] = (sp_digit)(t & 0x3ffffff);
    t >>= 26;
    r[81] = (sp_digit)(t & 0x3ffffff);
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
static void sp_4096_cond_add_81(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 80; i += 8) {
        r[i + 0] = a[i + 0] + (b[i + 0] & m);
        r[i + 1] = a[i + 1] + (b[i + 1] & m);
        r[i + 2] = a[i + 2] + (b[i + 2] & m);
        r[i + 3] = a[i + 3] + (b[i + 3] & m);
        r[i + 4] = a[i + 4] + (b[i + 4] & m);
        r[i + 5] = a[i + 5] + (b[i + 5] & m);
        r[i + 6] = a[i + 6] + (b[i + 6] & m);
        r[i + 7] = a[i + 7] + (b[i + 7] & m);
    }
    r[80] = a[80] + (b[80] & m);
}
#endif /* !WOLFSSL_SP_SMALL */

SP_NOINLINE static void sp_4096_rshift_81(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    for (i=0; i<80; i += 8) {
        r[i+0] = (a[i+0] >> n) | ((a[i+1] << (26 - n)) & 0x3ffffff);
        r[i+1] = (a[i+1] >> n) | ((a[i+2] << (26 - n)) & 0x3ffffff);
        r[i+2] = (a[i+2] >> n) | ((a[i+3] << (26 - n)) & 0x3ffffff);
        r[i+3] = (a[i+3] >> n) | ((a[i+4] << (26 - n)) & 0x3ffffff);
        r[i+4] = (a[i+4] >> n) | ((a[i+5] << (26 - n)) & 0x3ffffff);
        r[i+5] = (a[i+5] >> n) | ((a[i+6] << (26 - n)) & 0x3ffffff);
        r[i+6] = (a[i+6] >> n) | ((a[i+7] << (26 - n)) & 0x3ffffff);
        r[i+7] = (a[i+7] >> n) | ((a[i+8] << (26 - n)) & 0x3ffffff);
    }
    r[80] = a[80] >> n;
}

static WC_INLINE sp_digit sp_4096_div_word_81(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int64 d = ((sp_int64)d1 << 26) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int64 d = ((sp_int64)d1 << 26) + d0;
    sp_uint32 lo = (sp_uint32)d;
    sp_digit hi = (sp_digit)(d >> 32);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int64 d = ((sp_int64)d1 << 26) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 26);
    sp_digit t0 = (sp_digit)(d & 0x3ffffff);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int64 m;

    r = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
    t1 -= dv & (0 - r);
    for (i = 24; i >= 1; i--) {
        t1 += t1 + (((sp_uint32)t0 >> 25) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int64)r * div);
    r += (sp_digit)(m >> 26);
    m = d - ((sp_int64)r * div);
    r += (m >> 52) - (sp_digit)(d >> 52);

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;
   return r;
#else
    sp_int64 d = ((sp_int64)d1 << 26) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 11) + 1;

    t = (sp_digit)(d >> 22);
    t = (t / dv) << 11;
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)(d >> 7);
    t = t / (dv << 4);
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int64)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_4096_word_div_word_81(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint32)(div - d) >> 31);
#endif
}
/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * Full implementation.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_4096_div_81(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_32
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 81 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 162 + 1;
        sd = t2 + 81 + 1;

        sp_4096_mul_d_81(sd, d, (sp_digit)1 << 6);
        sp_4096_mul_d_162(t1, a, (sp_digit)1 << 6);
        dv = sd[78];
        t1[79 + 79] += t1[79 + 79 - 1] >> 26;
        t1[79 + 79 - 1] &= 0x3ffffff;
        for (i=79; i>=0; i--) {
            r1 = sp_4096_div_word_81(t1[79 + i], t1[79 + i - 1], dv);

            sp_4096_mul_d_81(t2, sd, r1);
            (void)sp_4096_sub_81(&t1[i], &t1[i], t2);
            sp_4096_norm_79(&t1[i]);
            t1[79 + i] += t1[79 + i - 1] >> 26;
            t1[79 + i - 1] &= 0x3ffffff;
            r1 = sp_4096_div_word_81(-t1[79 + i], -t1[79 + i - 1], dv);
            r1 -= t1[79 + i];
            sp_4096_mul_d_81(t2, sd, r1);
            (void)sp_4096_add_81(&t1[i], &t1[i], t2);
            t1[79 + i] += t1[79 + i - 1] >> 26;
            t1[79 + i - 1] &= 0x3ffffff;
        }
        t1[79 - 1] += t1[79 - 2] >> 26;
        t1[79 - 2] &= 0x3ffffff;
        r1 = sp_4096_word_div_word_81(t1[79 - 1], dv);

        sp_4096_mul_d_81(t2, sd, r1);
        sp_4096_sub_81(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 162U);
        for (i=0; i<78; i++) {
            r[i+1] += r[i] >> 26;
            r[i] &= 0x3ffffff;
        }
        sp_4096_cond_add_81(r, r, sd, r[78] >> 31);

        sp_4096_norm_79(r);
        sp_4096_rshift_81(r, r, 6);
        r[79] = 0;
        r[80] = 0;
    }


    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_4096_mod_81(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_4096_div_81(a, m, NULL, r);
}

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
static int sp_4096_mod_exp_81(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 162];
    sp_digit* t[3] = {0, 0, 0};
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<3; i++) {
            t[i] = td + (i * 81 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 81U * 2U);
        }

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_81(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_81(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 81U);
        }
    }
    if (err == MP_OKAY) {
        sp_4096_mul_81(t[1], t[1], norm);
        err = sp_4096_mod_81(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 26;
        c = bits % 26;
        n = e[i--] << (26 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 26;
            }

            y = (int)((n >> 25) & 1);
            n <<= 1;

            sp_4096_mont_mul_81(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 81 * 2);
            sp_4096_mont_sqr_81(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 81 * 2);
        }

        sp_4096_mont_reduce_81(t[0], m, mp);
        n = sp_4096_cmp_81(t[0], m);
        sp_4096_cond_sub_81(t[0], t[0], m, ~(n >> 31));
        XMEMCPY(r, t[0], sizeof(*r) * 81 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 162];
    sp_digit* t[3] = {0, 0, 0};
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<3; i++) {
            t[i] = td + (i * 81 * 2);
        }

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_81(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_81(t[1], a, m);
            if (err == MP_OKAY) {
                sp_4096_mul_81(t[1], t[1], norm);
                err = sp_4096_mod_81(t[1], t[1], m);
            }
        }
        else {
            sp_4096_mul_81(t[1], a, norm);
            err = sp_4096_mod_81(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 26;
        c = bits % 26;
        n = e[i--] << (26 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 26;
            }

            y = (int)((n >> 25) & 1);
            n <<= 1;

            sp_4096_mont_mul_81(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 81 * 2);
            sp_4096_mont_sqr_81(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 81 * 2);
        }

        sp_4096_mont_reduce_81(t[0], m, mp);
        n = sp_4096_cmp_81(t[0], m);
        sp_4096_cond_sub_81(t[0], t[0], m, ~(n >> 31));
        XMEMCPY(r, t[0], sizeof(*r) * 81 * 2);
    }


    return err;
#else
    sp_digit td[(32 * 162) + 162];
    sp_digit* t[32];
    sp_digit* rt = NULL;
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<32; i++)
            t[i] = td + i * 162;
        rt = td + 5184;

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_81(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_81(t[1], a, m);
            if (err == MP_OKAY) {
                sp_4096_mul_81(t[1], t[1], norm);
                err = sp_4096_mod_81(t[1], t[1], m);
            }
        }
        else {
            sp_4096_mul_81(t[1], a, norm);
            err = sp_4096_mod_81(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_4096_mont_sqr_81(t[ 2], t[ 1], m, mp);
        sp_4096_mont_mul_81(t[ 3], t[ 2], t[ 1], m, mp);
        sp_4096_mont_sqr_81(t[ 4], t[ 2], m, mp);
        sp_4096_mont_mul_81(t[ 5], t[ 3], t[ 2], m, mp);
        sp_4096_mont_sqr_81(t[ 6], t[ 3], m, mp);
        sp_4096_mont_mul_81(t[ 7], t[ 4], t[ 3], m, mp);
        sp_4096_mont_sqr_81(t[ 8], t[ 4], m, mp);
        sp_4096_mont_mul_81(t[ 9], t[ 5], t[ 4], m, mp);
        sp_4096_mont_sqr_81(t[10], t[ 5], m, mp);
        sp_4096_mont_mul_81(t[11], t[ 6], t[ 5], m, mp);
        sp_4096_mont_sqr_81(t[12], t[ 6], m, mp);
        sp_4096_mont_mul_81(t[13], t[ 7], t[ 6], m, mp);
        sp_4096_mont_sqr_81(t[14], t[ 7], m, mp);
        sp_4096_mont_mul_81(t[15], t[ 8], t[ 7], m, mp);
        sp_4096_mont_sqr_81(t[16], t[ 8], m, mp);
        sp_4096_mont_mul_81(t[17], t[ 9], t[ 8], m, mp);
        sp_4096_mont_sqr_81(t[18], t[ 9], m, mp);
        sp_4096_mont_mul_81(t[19], t[10], t[ 9], m, mp);
        sp_4096_mont_sqr_81(t[20], t[10], m, mp);
        sp_4096_mont_mul_81(t[21], t[11], t[10], m, mp);
        sp_4096_mont_sqr_81(t[22], t[11], m, mp);
        sp_4096_mont_mul_81(t[23], t[12], t[11], m, mp);
        sp_4096_mont_sqr_81(t[24], t[12], m, mp);
        sp_4096_mont_mul_81(t[25], t[13], t[12], m, mp);
        sp_4096_mont_sqr_81(t[26], t[13], m, mp);
        sp_4096_mont_mul_81(t[27], t[14], t[13], m, mp);
        sp_4096_mont_sqr_81(t[28], t[14], m, mp);
        sp_4096_mont_mul_81(t[29], t[15], t[14], m, mp);
        sp_4096_mont_sqr_81(t[30], t[15], m, mp);
        sp_4096_mont_mul_81(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 25) / 26) - 1;
        c = bits % 26;
        if (c == 0) {
            c = 26;
        }
        if (i < 81) {
            n = e[i--] << (32 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (6 - c);
            c += 26;
        }
        y = (int)((n >> 27) & 0x1f);
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 162);
        while ((i >= 0) || (c >= 5)) {
            if (c >= 5) {
                y = (byte)((n >> 27) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--] << 6;
                y = (byte)((n >> 27) & 0x1f);
                n <<= 5;
                c = 21;
            }
            else {
                y = (byte)((n >> 27) & 0x1f);
                n = e[i--] << 6;
                c = 5 - c;
                y |= (byte)((n >> (32 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 26 - c;
            }

            sp_4096_mont_sqr_81(rt, rt, m, mp);
            sp_4096_mont_sqr_81(rt, rt, m, mp);
            sp_4096_mont_sqr_81(rt, rt, m, mp);
            sp_4096_mont_sqr_81(rt, rt, m, mp);
            sp_4096_mont_sqr_81(rt, rt, m, mp);

            sp_4096_mont_mul_81(rt, rt, t[y], m, mp);
        }

        sp_4096_mont_reduce_81(rt, m, mp);
        n = sp_4096_cmp_81(rt, m);
        sp_4096_cond_sub_81(rt, rt, m, ~(n >> 31));
        XMEMCPY(r, rt, sizeof(sp_digit) * 162);
    }


    return err;
#endif
}

#endif /* WOLFSSL_HAVE_SP_RSA & !SP_RSA_PRIVATE_EXP_D */
#endif /* (WOLFSSL_HAVE_SP_RSA | WOLFSSL_HAVE_SP_DH) & !WOLFSSL_RSA_PUBLIC_ONLY */

/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 4096 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_4096_mont_norm_162(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
    int i;

    for (i = 0; i < 152; i += 8) {
        r[i + 0] = 0x3ffffff;
        r[i + 1] = 0x3ffffff;
        r[i + 2] = 0x3ffffff;
        r[i + 3] = 0x3ffffff;
        r[i + 4] = 0x3ffffff;
        r[i + 5] = 0x3ffffff;
        r[i + 6] = 0x3ffffff;
        r[i + 7] = 0x3ffffff;
    }
    r[152] = 0x3ffffff;
    r[153] = 0x3ffffff;
    r[154] = 0x3ffffff;
    r[155] = 0x3ffffff;
    r[156] = 0x3ffffff;
    r[157] = 0x3fffL;
    r[158] = 0;
    r[159] = 0;
    r[160] = 0;
    r[161] = 0;

    /* r = (2^n - 1) mod n */
    (void)sp_4096_sub_162(r, r, m);

    /* Add one so r = 2^n mod m */
    r[0] += 1;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_4096_cmp_162(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
    int i;

    r |= (a[161] - b[161]) & (0 - (sp_digit)1);
    r |= (a[160] - b[160]) & ~(((sp_digit)0 - r) >> 25);
    for (i = 152; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & ~(((sp_digit)0 - r) >> 25);
        r |= (a[i + 6] - b[i + 6]) & ~(((sp_digit)0 - r) >> 25);
        r |= (a[i + 5] - b[i + 5]) & ~(((sp_digit)0 - r) >> 25);
        r |= (a[i + 4] - b[i + 4]) & ~(((sp_digit)0 - r) >> 25);
        r |= (a[i + 3] - b[i + 3]) & ~(((sp_digit)0 - r) >> 25);
        r |= (a[i + 2] - b[i + 2]) & ~(((sp_digit)0 - r) >> 25);
        r |= (a[i + 1] - b[i + 1]) & ~(((sp_digit)0 - r) >> 25);
        r |= (a[i + 0] - b[i + 0]) & ~(((sp_digit)0 - r) >> 25);
    }

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_4096_cond_sub_162(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 160; i += 8) {
        r[i + 0] = a[i + 0] - (b[i + 0] & m);
        r[i + 1] = a[i + 1] - (b[i + 1] & m);
        r[i + 2] = a[i + 2] - (b[i + 2] & m);
        r[i + 3] = a[i + 3] - (b[i + 3] & m);
        r[i + 4] = a[i + 4] - (b[i + 4] & m);
        r[i + 5] = a[i + 5] - (b[i + 5] & m);
        r[i + 6] = a[i + 6] - (b[i + 6] & m);
        r[i + 7] = a[i + 7] - (b[i + 7] & m);
    }
    r[160] = a[160] - (b[160] & m);
    r[161] = a[161] - (b[161] & m);
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_add_162(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifndef WOLFSSL_SP_LARGE_CODE
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 162; i++) {
        t += r[i];
        t += tb * a[i];
        r[i] = ((sp_digit)t) & 0x3ffffff;
        t >>= 26;
    }
    r[162] += (sp_digit)t;
#else
    sp_int64 tb = b;
    sp_int64 t[8];
    int i;

    t[0] = 0;
    for (i = 0; i < 160; i += 8) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        t[4]  = (tb * a[i+4]) + r[i+4];
        t[5]  = (tb * a[i+5]) + r[i+5];
        t[6]  = (tb * a[i+6]) + r[i+6];
        t[7]  = (tb * a[i+7]) + r[i+7];
        r[i+0] = t[0] & 0x3ffffff;
        t[1] += t[0] >> 26;
        r[i+1] = t[1] & 0x3ffffff;
        t[2] += t[1] >> 26;
        r[i+2] = t[2] & 0x3ffffff;
        t[3] += t[2] >> 26;
        r[i+3] = t[3] & 0x3ffffff;
        t[4] += t[3] >> 26;
        r[i+4] = t[4] & 0x3ffffff;
        t[5] += t[4] >> 26;
        r[i+5] = t[5] & 0x3ffffff;
        t[6] += t[5] >> 26;
        r[i+6] = t[6] & 0x3ffffff;
        t[7] += t[6] >> 26;
        r[i+7] = t[7] & 0x3ffffff;
        t[0]  = t[7] >> 26;
    }
    t[0] += (tb * a[160]) + r[160];
    t[1]  = (tb * a[161]) + r[161];
    r[160] = t[0] & 0x3ffffff;
    t[1] += t[0] >> 26;
    r[161] = t[1] & 0x3ffffff;
    r[162] +=  (sp_digit)(t[1] >> 26);
#endif /* !WOLFSSL_SP_LARGE_CODE */
}

/* Shift the result in the high 4096 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_4096_mont_shift_162(sp_digit* r, const sp_digit* a)
{
    int i;
    sp_int64 n = a[157] >> 14;
    n += ((sp_int64)a[158]) << 12;
    for (i = 0; i < 152; i += 8) {
        r[i + 0] = n & 0x3ffffff;
        n >>= 26; n += ((sp_int64)a[i + 159]) << 12;
        r[i + 1] = n & 0x3ffffff;
        n >>= 26; n += ((sp_int64)a[i + 160]) << 12;
        r[i + 2] = n & 0x3ffffff;
        n >>= 26; n += ((sp_int64)a[i + 161]) << 12;
        r[i + 3] = n & 0x3ffffff;
        n >>= 26; n += ((sp_int64)a[i + 162]) << 12;
        r[i + 4] = n & 0x3ffffff;
        n >>= 26; n += ((sp_int64)a[i + 163]) << 12;
        r[i + 5] = n & 0x3ffffff;
        n >>= 26; n += ((sp_int64)a[i + 164]) << 12;
        r[i + 6] = n & 0x3ffffff;
        n >>= 26; n += ((sp_int64)a[i + 165]) << 12;
        r[i + 7] = n & 0x3ffffff;
        n >>= 26; n += ((sp_int64)a[i + 166]) << 12;
    }
    r[152] = n & 0x3ffffff; n >>= 26; n += ((sp_int64)a[311]) << 12;
    r[153] = n & 0x3ffffff; n >>= 26; n += ((sp_int64)a[312]) << 12;
    r[154] = n & 0x3ffffff; n >>= 26; n += ((sp_int64)a[313]) << 12;
    r[155] = n & 0x3ffffff; n >>= 26; n += ((sp_int64)a[314]) << 12;
    r[156] = n & 0x3ffffff; n >>= 26; n += ((sp_int64)a[315]) << 12;
    r[157] = (sp_digit)n;
    XMEMSET(&r[158], 0, sizeof(*r) * 158U);
}

/* Reduce the number back to 4096 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_4096_mont_reduce_162(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_4096_norm_162(a + 158);

#ifdef WOLFSSL_SP_DH
    if (mp != 1) {
        for (i=0; i<157; i++) {
            mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x3ffffff;
            sp_4096_mul_add_162(a+i, m, mu);
            a[i+1] += a[i] >> 26;
        }
        mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x3fffL;
        sp_4096_mul_add_162(a+i, m, mu);
        a[i+1] += a[i] >> 26;
        a[i] &= 0x3ffffff;
    }
    else {
        for (i=0; i<157; i++) {
            mu = a[i] & 0x3ffffff;
            sp_4096_mul_add_162(a+i, m, mu);
            a[i+1] += a[i] >> 26;
        }
        mu = a[i] & 0x3fffL;
        sp_4096_mul_add_162(a+i, m, mu);
        a[i+1] += a[i] >> 26;
        a[i] &= 0x3ffffff;
    }
#else
    for (i=0; i<157; i++) {
        mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x3ffffff;
        sp_4096_mul_add_162(a+i, m, mu);
        a[i+1] += a[i] >> 26;
    }
    mu = ((sp_uint32)a[i] * (sp_uint32)mp) & 0x3fffL;
    sp_4096_mul_add_162(a+i, m, mu);
    a[i+1] += a[i] >> 26;
    a[i] &= 0x3ffffff;
#endif
    sp_4096_mont_shift_162(a, a);
    over = a[157] - m[157];
    sp_4096_cond_sub_162(a, a, m, ~((over - 1) >> 31));
    sp_4096_norm_162(a);
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
SP_NOINLINE static void sp_4096_mont_mul_162(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_4096_mul_162(r, a, b);
    sp_4096_mont_reduce_162(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_4096_mont_sqr_162(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_4096_sqr_162(r, a);
    sp_4096_mont_reduce_162(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_d_324(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int64 tb = b;
    sp_int64 t = 0;
    sp_digit t2;
    sp_int64 p[4];
    int i;

    for (i = 0; i < 324; i += 4) {
        p[0] = tb * a[i + 0];
        p[1] = tb * a[i + 1];
        p[2] = tb * a[i + 2];
        p[3] = tb * a[i + 3];
        t += p[0];
        t2 = (sp_digit)(t & 0x3ffffff);
        t >>= 26;
        r[i + 0] = (sp_digit)t2;
        t += p[1];
        t2 = (sp_digit)(t & 0x3ffffff);
        t >>= 26;
        r[i + 1] = (sp_digit)t2;
        t += p[2];
        t2 = (sp_digit)(t & 0x3ffffff);
        t >>= 26;
        r[i + 2] = (sp_digit)t2;
        t += p[3];
        t2 = (sp_digit)(t & 0x3ffffff);
        t >>= 26;
        r[i + 3] = (sp_digit)t2;
    }
    r[324] = (sp_digit)(t & 0x3ffffff);
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
static void sp_4096_cond_add_162(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 160; i += 8) {
        r[i + 0] = a[i + 0] + (b[i + 0] & m);
        r[i + 1] = a[i + 1] + (b[i + 1] & m);
        r[i + 2] = a[i + 2] + (b[i + 2] & m);
        r[i + 3] = a[i + 3] + (b[i + 3] & m);
        r[i + 4] = a[i + 4] + (b[i + 4] & m);
        r[i + 5] = a[i + 5] + (b[i + 5] & m);
        r[i + 6] = a[i + 6] + (b[i + 6] & m);
        r[i + 7] = a[i + 7] + (b[i + 7] & m);
    }
    r[160] = a[160] + (b[160] & m);
    r[161] = a[161] + (b[161] & m);
}
#endif /* !WOLFSSL_SP_SMALL */

SP_NOINLINE static void sp_4096_rshift_162(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    for (i=0; i<160; i += 8) {
        r[i+0] = (a[i+0] >> n) | ((a[i+1] << (26 - n)) & 0x3ffffff);
        r[i+1] = (a[i+1] >> n) | ((a[i+2] << (26 - n)) & 0x3ffffff);
        r[i+2] = (a[i+2] >> n) | ((a[i+3] << (26 - n)) & 0x3ffffff);
        r[i+3] = (a[i+3] >> n) | ((a[i+4] << (26 - n)) & 0x3ffffff);
        r[i+4] = (a[i+4] >> n) | ((a[i+5] << (26 - n)) & 0x3ffffff);
        r[i+5] = (a[i+5] >> n) | ((a[i+6] << (26 - n)) & 0x3ffffff);
        r[i+6] = (a[i+6] >> n) | ((a[i+7] << (26 - n)) & 0x3ffffff);
        r[i+7] = (a[i+7] >> n) | ((a[i+8] << (26 - n)) & 0x3ffffff);
    }
    r[160] = (a[160] >> n) | ((a[161] << (26 - n)) & 0x3ffffff);
    r[161] = a[161] >> n;
}

static WC_INLINE sp_digit sp_4096_div_word_162(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int64 d = ((sp_int64)d1 << 26) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int64 d = ((sp_int64)d1 << 26) + d0;
    sp_uint32 lo = (sp_uint32)d;
    sp_digit hi = (sp_digit)(d >> 32);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int64 d = ((sp_int64)d1 << 26) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 26);
    sp_digit t0 = (sp_digit)(d & 0x3ffffff);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int64 m;

    r = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
    t1 -= dv & (0 - r);
    for (i = 24; i >= 1; i--) {
        t1 += t1 + (((sp_uint32)t0 >> 25) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint32)(dv - t1)) >> 31);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int64)r * div);
    r += (sp_digit)(m >> 26);
    m = d - ((sp_int64)r * div);
    r += (m >> 52) - (sp_digit)(d >> 52);

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;

    m = d - ((sp_int64)r * div);
    sign = (sp_digit)(0 - ((sp_uint32)m >> 31)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint32)(div - m)) >> 31);
    r += sign * t2;
   return r;
#else
    sp_int64 d = ((sp_int64)d1 << 26) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 11) + 1;

    t = (sp_digit)(d >> 22);
    t = (t / dv) << 11;
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)(d >> 7);
    t = t / (dv << 4);
    r += t;
    d -= (sp_int64)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int64)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_4096_word_div_word_162(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint32)(div - d) >> 31);
#endif
}
/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * Full implementation.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_4096_div_162(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_32
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 162 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 324 + 1;
        sd = t2 + 162 + 1;

        sp_4096_mul_d_162(sd, d, (sp_digit)1 << 12);
        sp_4096_mul_d_324(t1, a, (sp_digit)1 << 12);
        dv = sd[157];
        t1[158 + 158] += t1[158 + 158 - 1] >> 26;
        t1[158 + 158 - 1] &= 0x3ffffff;
        for (i=158; i>=0; i--) {
            r1 = sp_4096_div_word_162(t1[158 + i], t1[158 + i - 1], dv);

            sp_4096_mul_d_162(t2, sd, r1);
            (void)sp_4096_sub_162(&t1[i], &t1[i], t2);
            sp_4096_norm_158(&t1[i]);
            t1[158 + i] += t1[158 + i - 1] >> 26;
            t1[158 + i - 1] &= 0x3ffffff;
            r1 = sp_4096_div_word_162(-t1[158 + i], -t1[158 + i - 1], dv);
            r1 -= t1[158 + i];
            sp_4096_mul_d_162(t2, sd, r1);
            (void)sp_4096_add_162(&t1[i], &t1[i], t2);
            t1[158 + i] += t1[158 + i - 1] >> 26;
            t1[158 + i - 1] &= 0x3ffffff;
        }
        t1[158 - 1] += t1[158 - 2] >> 26;
        t1[158 - 2] &= 0x3ffffff;
        r1 = sp_4096_word_div_word_162(t1[158 - 1], dv);

        sp_4096_mul_d_162(t2, sd, r1);
        sp_4096_sub_162(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 324U);
        for (i=0; i<157; i++) {
            r[i+1] += r[i] >> 26;
            r[i] &= 0x3ffffff;
        }
        sp_4096_cond_add_162(r, r, sd, r[157] >> 31);

        sp_4096_norm_158(r);
        sp_4096_rshift_162(r, r, 12);
        r[158] = 0;
        r[159] = 0;
        r[160] = 0;
        r[161] = 0;
    }


    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_4096_mod_162(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_4096_div_162(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || \
                                                     defined(WOLFSSL_HAVE_SP_DH)
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
static int sp_4096_mod_exp_162(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 324];
    sp_digit* t[3] = {0, 0, 0};
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<3; i++) {
            t[i] = td + (i * 162 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 162U * 2U);
        }

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_162(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_162(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 162U);
        }
    }
    if (err == MP_OKAY) {
        sp_4096_mul_162(t[1], t[1], norm);
        err = sp_4096_mod_162(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 26;
        c = bits % 26;
        n = e[i--] << (26 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 26;
            }

            y = (int)((n >> 25) & 1);
            n <<= 1;

            sp_4096_mont_mul_162(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 162 * 2);
            sp_4096_mont_sqr_162(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 162 * 2);
        }

        sp_4096_mont_reduce_162(t[0], m, mp);
        n = sp_4096_cmp_162(t[0], m);
        sp_4096_cond_sub_162(t[0], t[0], m, ~(n >> 31));
        XMEMCPY(r, t[0], sizeof(*r) * 162 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 324];
    sp_digit* t[3] = {0, 0, 0};
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<3; i++) {
            t[i] = td + (i * 162 * 2);
        }

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_162(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_162(t[1], a, m);
            if (err == MP_OKAY) {
                sp_4096_mul_162(t[1], t[1], norm);
                err = sp_4096_mod_162(t[1], t[1], m);
            }
        }
        else {
            sp_4096_mul_162(t[1], a, norm);
            err = sp_4096_mod_162(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 26;
        c = bits % 26;
        n = e[i--] << (26 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 26;
            }

            y = (int)((n >> 25) & 1);
            n <<= 1;

            sp_4096_mont_mul_162(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 162 * 2);
            sp_4096_mont_sqr_162(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 162 * 2);
        }

        sp_4096_mont_reduce_162(t[0], m, mp);
        n = sp_4096_cmp_162(t[0], m);
        sp_4096_cond_sub_162(t[0], t[0], m, ~(n >> 31));
        XMEMCPY(r, t[0], sizeof(*r) * 162 * 2);
    }


    return err;
#else
    sp_digit td[(16 * 324) + 324];
    sp_digit* t[16];
    sp_digit* rt = NULL;
    sp_digit* norm = NULL;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<16; i++)
            t[i] = td + i * 324;
        rt = td + 5184;

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_162(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_162(t[1], a, m);
            if (err == MP_OKAY) {
                sp_4096_mul_162(t[1], t[1], norm);
                err = sp_4096_mod_162(t[1], t[1], m);
            }
        }
        else {
            sp_4096_mul_162(t[1], a, norm);
            err = sp_4096_mod_162(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_4096_mont_sqr_162(t[ 2], t[ 1], m, mp);
        sp_4096_mont_mul_162(t[ 3], t[ 2], t[ 1], m, mp);
        sp_4096_mont_sqr_162(t[ 4], t[ 2], m, mp);
        sp_4096_mont_mul_162(t[ 5], t[ 3], t[ 2], m, mp);
        sp_4096_mont_sqr_162(t[ 6], t[ 3], m, mp);
        sp_4096_mont_mul_162(t[ 7], t[ 4], t[ 3], m, mp);
        sp_4096_mont_sqr_162(t[ 8], t[ 4], m, mp);
        sp_4096_mont_mul_162(t[ 9], t[ 5], t[ 4], m, mp);
        sp_4096_mont_sqr_162(t[10], t[ 5], m, mp);
        sp_4096_mont_mul_162(t[11], t[ 6], t[ 5], m, mp);
        sp_4096_mont_sqr_162(t[12], t[ 6], m, mp);
        sp_4096_mont_mul_162(t[13], t[ 7], t[ 6], m, mp);
        sp_4096_mont_sqr_162(t[14], t[ 7], m, mp);
        sp_4096_mont_mul_162(t[15], t[ 8], t[ 7], m, mp);

        bits = ((bits + 3) / 4) * 4;
        i = ((bits + 25) / 26) - 1;
        c = bits % 26;
        if (c == 0) {
            c = 26;
        }
        if (i < 162) {
            n = e[i--] << (32 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 4) {
            n |= e[i--] << (6 - c);
            c += 26;
        }
        y = (int)((n >> 28) & 0xf);
        n <<= 4;
        c -= 4;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 324);
        while ((i >= 0) || (c >= 4)) {
            if (c >= 4) {
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c -= 4;
            }
            else if (c == 0) {
                n = e[i--] << 6;
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c = 22;
            }
            else {
                y = (byte)((n >> 28) & 0xf);
                n = e[i--] << 6;
                c = 4 - c;
                y |= (byte)((n >> (32 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 26 - c;
            }

            sp_4096_mont_sqr_162(rt, rt, m, mp);
            sp_4096_mont_sqr_162(rt, rt, m, mp);
            sp_4096_mont_sqr_162(rt, rt, m, mp);
            sp_4096_mont_sqr_162(rt, rt, m, mp);

            sp_4096_mont_mul_162(rt, rt, t[y], m, mp);
        }

        sp_4096_mont_reduce_162(rt, m, mp);
        n = sp_4096_cmp_162(rt, m);
        sp_4096_cond_sub_162(rt, rt, m, ~(n >> 31));
        XMEMCPY(r, rt, sizeof(sp_digit) * 324);
    }


    return err;
#endif
}
#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) || */
       /* WOLFSSL_HAVE_SP_DH */

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
#ifdef WOLFSSL_SP_SMALL
    sp_digit a[162 * 5];
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit* norm = NULL;
    sp_digit e[1] = {0};
    sp_digit mp = 0;
    int i;
    int err = MP_OKAY;

    if (*outLen < 512U) {
        err = MP_TO_E;
    }

    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 26) {
            err = MP_READ_E;
        }
        else if (inLen > 512U) {
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
        r = a + 162 * 2;
        m = r + 162 * 2;
        norm = r;

        sp_4096_from_bin(a, 162, in, inLen);
#if DIGIT_BIT >= 26
        e[0] = (sp_digit)em->dp[0];
#else
        e[0] = (sp_digit)em->dp[0];
        if (em->used > 1) {
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
        }
#endif
        if (e[0] == 0) {
            err = MP_EXPTMOD_E;
        }
    }

    if (err == MP_OKAY) {
        sp_4096_from_mp(m, 162, mm);

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_162(norm, m);
    }
    if (err == MP_OKAY) {
        sp_4096_mul_162(a, a, norm);
        err = sp_4096_mod_162(a, a, m);
    }
    if (err == MP_OKAY) {
        for (i=25; i>=0; i--) {
            if ((e[0] >> i) != 0) {
                break;
            }
        }

        XMEMCPY(r, a, sizeof(sp_digit) * 162 * 2);
        for (i--; i>=0; i--) {
            sp_4096_mont_sqr_162(r, r, m, mp);

            if (((e[0] >> i) & 1) == 1) {
                sp_4096_mont_mul_162(r, r, a, m, mp);
            }
        }
        sp_4096_mont_reduce_162(r, m, mp);
        mp = sp_4096_cmp_162(r, m);
        sp_4096_cond_sub_162(r, r, m, ~(mp >> 31));

        sp_4096_to_bin_162(r, out);
        *outLen = 512;
    }


    return err;
#else
    sp_digit d[162 * 5];
    sp_digit* a = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit e[1] = {0};
    int err = MP_OKAY;

    if (*outLen < 512U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 26) {
            err = MP_READ_E;
        }
        else if (inLen > 512U) {
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
        a = d;
        r = a + 162 * 2;
        m = r + 162 * 2;

        sp_4096_from_bin(a, 162, in, inLen);
#if DIGIT_BIT >= 26
        e[0] = (sp_digit)em->dp[0];
#else
        e[0] = (sp_digit)em->dp[0];
        if (em->used > 1) {
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
        }
#endif
        if (e[0] == 0) {
            err = MP_EXPTMOD_E;
        }
    }
    if (err == MP_OKAY) {
        sp_4096_from_mp(m, 162, mm);

        if (e[0] == 0x3) {
            sp_4096_sqr_162(r, a);
            err = sp_4096_mod_162(r, r, m);
            if (err == MP_OKAY) {
                sp_4096_mul_162(r, a, r);
                err = sp_4096_mod_162(r, r, m);
            }
        }
        else {
            sp_digit* norm = r;
            int i;
            sp_digit mp;

            sp_4096_mont_setup(m, &mp);
            sp_4096_mont_norm_162(norm, m);

            sp_4096_mul_162(a, a, norm);
            err = sp_4096_mod_162(a, a, m);

            if (err == MP_OKAY) {
                for (i=25; i>=0; i--) {
                    if ((e[0] >> i) != 0) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 324U);
                for (i--; i>=0; i--) {
                    sp_4096_mont_sqr_162(r, r, m, mp);

                    if (((e[0] >> i) & 1) == 1) {
                        sp_4096_mont_mul_162(r, r, a, m, mp);
                    }
                }
                sp_4096_mont_reduce_162(r, m, mp);
                mp = sp_4096_cmp_162(r, m);
                sp_4096_cond_sub_162(r, r, m, ~(mp >> 31));
            }
        }
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_162(r, out);
        *outLen = 512;
    }


    return err;
#endif /* WOLFSSL_SP_SMALL */
}

#ifndef WOLFSSL_RSA_PUBLIC_ONLY
#if !defined(SP_RSA_PRIVATE_EXP_D) && !defined(RSA_LOW_MEM)
#endif /* !SP_RSA_PRIVATE_EXP_D & !RSA_LOW_MEM */
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
#if defined(WOLFSSL_SP_SMALL)
    sp_digit  d[162 * 4];
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
        a = d + 162;
        m = a + 324;
        r = a;

        sp_4096_from_bin(a, 162, in, inLen);
        sp_4096_from_mp(d, 162, dm);
        sp_4096_from_mp(m, 162, mm);
        err = sp_4096_mod_exp_162(r, a, d, 4096, m, 0);
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_162(r, out);
        *outLen = 512;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 162);
    }

    return err;
#else
    sp_digit d[162 * 4];
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
        else if (inLen > 512U) {
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
        a = d + 162;
        m = a + 324;
        r = a;

        sp_4096_from_bin(a, 162, in, inLen);
        sp_4096_from_mp(d, 162, dm);
        sp_4096_from_mp(m, 162, mm);
        err = sp_4096_mod_exp_162(r, a, d, 4096, m, 0);
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_162(r, out);
        *outLen = 512;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 162);
    }

    return err;
#endif /* WOLFSSL_SP_SMALL */
#else
#if defined(WOLFSSL_SP_SMALL)
    sp_digit a[81 * 8];
    sp_digit* p = NULL;
    sp_digit* dp = NULL;
    sp_digit* dq = NULL;
    sp_digit* qi = NULL;
    sp_digit* tmpa = NULL;
    sp_digit* tmpb = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 512U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (inLen > 512) {
            err = MP_READ_E;
        }
        else if (mp_count_bits(mm) != 4096) {
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
    }

    if (err == MP_OKAY) {
        p = a + 162;
        qi = dq = dp = p + 81;
        tmpa = qi + 81;
        tmpb = tmpa + 162;
        r = a;

        sp_4096_from_bin(a, 162, in, inLen);
        sp_4096_from_mp(p, 81, pm);
        sp_4096_from_mp(dp, 81, dpm);
        err = sp_4096_mod_exp_81(tmpa, a, dp, 2048, p, 1);
    }
    if (err == MP_OKAY) {
        sp_4096_from_mp(p, 81, qm);
        sp_4096_from_mp(dq, 81, dqm);
        err = sp_4096_mod_exp_81(tmpb, a, dq, 2048, p, 1);
    }
    if (err == MP_OKAY) {
        sp_4096_from_mp(p, 81, pm);
        (void)sp_4096_sub_81(tmpa, tmpa, tmpb);
        sp_4096_norm_79(tmpa);
        sp_4096_cond_add_81(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[78] >> 31));
        sp_4096_cond_add_81(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[78] >> 31));
        sp_4096_norm_81(tmpa);

        sp_4096_from_mp(qi, 81, qim);
        sp_4096_mul_81(tmpa, tmpa, qi);
        err = sp_4096_mod_81(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_4096_from_mp(p, 81, qm);
        sp_4096_mul_81(tmpa, p, tmpa);
        (void)sp_4096_add_162(r, tmpb, tmpa);
        sp_4096_norm_162(r);

        sp_4096_to_bin_162(r, out);
        *outLen = 512;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 81 * 8);
    }

    return err;
#else
    sp_digit a[81 * 13];
    sp_digit* p = NULL;
    sp_digit* q = NULL;
    sp_digit* dp = NULL;
    sp_digit* dq = NULL;
    sp_digit* qi = NULL;
    sp_digit* tmpa = NULL;
    sp_digit* tmpb = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 512U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (inLen > 512U) {
            err = MP_READ_E;
        }
        else if (mp_count_bits(mm) != 4096) {
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
    }


    if (err == MP_OKAY) {
        p = a + 162 * 2;
        q = p + 81;
        dp = q + 81;
        dq = dp + 81;
        qi = dq + 81;
        tmpa = qi + 81;
        tmpb = tmpa + 162;
        r = a;

        sp_4096_from_bin(a, 162, in, inLen);
        sp_4096_from_mp(p, 81, pm);
        sp_4096_from_mp(q, 81, qm);
        sp_4096_from_mp(dp, 81, dpm);
        sp_4096_from_mp(dq, 81, dqm);
        sp_4096_from_mp(qi, 81, qim);

        err = sp_4096_mod_exp_81(tmpa, a, dp, 2048, p, 1);
    }
    if (err == MP_OKAY) {
        err = sp_4096_mod_exp_81(tmpb, a, dq, 2048, q, 1);
    }

    if (err == MP_OKAY) {
        (void)sp_4096_sub_81(tmpa, tmpa, tmpb);
        sp_4096_norm_79(tmpa);
        sp_4096_cond_add_81(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[78] >> 31));
        sp_4096_cond_add_81(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[78] >> 31));
        sp_4096_norm_81(tmpa);
        sp_4096_mul_81(tmpa, tmpa, qi);
        err = sp_4096_mod_81(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_4096_mul_81(tmpa, tmpa, q);
        (void)sp_4096_add_162(r, tmpb, tmpa);
        sp_4096_norm_162(r);

        sp_4096_to_bin_162(r, out);
        *outLen = 512;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 81 * 13);
    }

    return err;
#endif /* WOLFSSL_SP_SMALL */
#endif /* SP_RSA_PRIVATE_EXP_D || RSA_LOW_MEM */
}

#endif /* !WOLFSSL_RSA_PUBLIC_ONLY */
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
#if DIGIT_BIT == 26
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 162);
        r->used = 162;
        mp_clamp(r);
#elif DIGIT_BIT < 26
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 162; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 26) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 26 - s;
        }
        r->used = (4096 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 162; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 26 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 26 - s;
            }
            else {
                s += 26;
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
#ifdef WOLFSSL_SP_SMALL
    int err = MP_OKAY;
    sp_digit b[162 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
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
        e = b + 162 * 2;
        m = e + 162;
        r = b;

        sp_4096_from_mp(b, 162, base);
        sp_4096_from_mp(e, 162, exp);
        sp_4096_from_mp(m, 162, mod);

        err = sp_4096_mod_exp_162(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_4096_to_mp(r, res);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 162U);
    }
    return err;
#else
    sp_digit b[162 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    int err = MP_OKAY;
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
        e = b + 162 * 2;
        m = e + 162;
        r = b;

        sp_4096_from_mp(b, 162, base);
        sp_4096_from_mp(e, 162, exp);
        sp_4096_from_mp(m, 162, mod);

        err = sp_4096_mod_exp_162(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_4096_to_mp(r, res);
    }


    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 162U);
    }

    return err;
#endif
}

#ifdef WOLFSSL_HAVE_SP_DH

#ifdef HAVE_FFDHE_4096
SP_NOINLINE static void sp_4096_lshift_162(sp_digit* r, const sp_digit* a,
        byte n)
{
    sp_int_digit s;
    sp_int_digit t;

    s = (sp_int_digit)a[161];
    r[162] = s >> (26U - n);
    s = (sp_int_digit)(a[161]); t = (sp_int_digit)(a[160]);
    r[161] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[160]); t = (sp_int_digit)(a[159]);
    r[160] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[159]); t = (sp_int_digit)(a[158]);
    r[159] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[158]); t = (sp_int_digit)(a[157]);
    r[158] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[157]); t = (sp_int_digit)(a[156]);
    r[157] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[156]); t = (sp_int_digit)(a[155]);
    r[156] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[155]); t = (sp_int_digit)(a[154]);
    r[155] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[154]); t = (sp_int_digit)(a[153]);
    r[154] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[153]); t = (sp_int_digit)(a[152]);
    r[153] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[152]); t = (sp_int_digit)(a[151]);
    r[152] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[151]); t = (sp_int_digit)(a[150]);
    r[151] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[150]); t = (sp_int_digit)(a[149]);
    r[150] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[149]); t = (sp_int_digit)(a[148]);
    r[149] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[148]); t = (sp_int_digit)(a[147]);
    r[148] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[147]); t = (sp_int_digit)(a[146]);
    r[147] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[146]); t = (sp_int_digit)(a[145]);
    r[146] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[145]); t = (sp_int_digit)(a[144]);
    r[145] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[144]); t = (sp_int_digit)(a[143]);
    r[144] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[143]); t = (sp_int_digit)(a[142]);
    r[143] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[142]); t = (sp_int_digit)(a[141]);
    r[142] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[141]); t = (sp_int_digit)(a[140]);
    r[141] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[140]); t = (sp_int_digit)(a[139]);
    r[140] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[139]); t = (sp_int_digit)(a[138]);
    r[139] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[138]); t = (sp_int_digit)(a[137]);
    r[138] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[137]); t = (sp_int_digit)(a[136]);
    r[137] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[136]); t = (sp_int_digit)(a[135]);
    r[136] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[135]); t = (sp_int_digit)(a[134]);
    r[135] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[134]); t = (sp_int_digit)(a[133]);
    r[134] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[133]); t = (sp_int_digit)(a[132]);
    r[133] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[132]); t = (sp_int_digit)(a[131]);
    r[132] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[131]); t = (sp_int_digit)(a[130]);
    r[131] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[130]); t = (sp_int_digit)(a[129]);
    r[130] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[129]); t = (sp_int_digit)(a[128]);
    r[129] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[128]); t = (sp_int_digit)(a[127]);
    r[128] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[127]); t = (sp_int_digit)(a[126]);
    r[127] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[126]); t = (sp_int_digit)(a[125]);
    r[126] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[125]); t = (sp_int_digit)(a[124]);
    r[125] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[124]); t = (sp_int_digit)(a[123]);
    r[124] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[123]); t = (sp_int_digit)(a[122]);
    r[123] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[122]); t = (sp_int_digit)(a[121]);
    r[122] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[121]); t = (sp_int_digit)(a[120]);
    r[121] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[120]); t = (sp_int_digit)(a[119]);
    r[120] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[119]); t = (sp_int_digit)(a[118]);
    r[119] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[118]); t = (sp_int_digit)(a[117]);
    r[118] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[117]); t = (sp_int_digit)(a[116]);
    r[117] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[116]); t = (sp_int_digit)(a[115]);
    r[116] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[115]); t = (sp_int_digit)(a[114]);
    r[115] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[114]); t = (sp_int_digit)(a[113]);
    r[114] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[113]); t = (sp_int_digit)(a[112]);
    r[113] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[112]); t = (sp_int_digit)(a[111]);
    r[112] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[111]); t = (sp_int_digit)(a[110]);
    r[111] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[110]); t = (sp_int_digit)(a[109]);
    r[110] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[109]); t = (sp_int_digit)(a[108]);
    r[109] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[108]); t = (sp_int_digit)(a[107]);
    r[108] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[107]); t = (sp_int_digit)(a[106]);
    r[107] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[106]); t = (sp_int_digit)(a[105]);
    r[106] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[105]); t = (sp_int_digit)(a[104]);
    r[105] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[104]); t = (sp_int_digit)(a[103]);
    r[104] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[103]); t = (sp_int_digit)(a[102]);
    r[103] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[102]); t = (sp_int_digit)(a[101]);
    r[102] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[101]); t = (sp_int_digit)(a[100]);
    r[101] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[100]); t = (sp_int_digit)(a[99]);
    r[100] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[99]); t = (sp_int_digit)(a[98]);
    r[99] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[98]); t = (sp_int_digit)(a[97]);
    r[98] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[97]); t = (sp_int_digit)(a[96]);
    r[97] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[96]); t = (sp_int_digit)(a[95]);
    r[96] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[95]); t = (sp_int_digit)(a[94]);
    r[95] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[94]); t = (sp_int_digit)(a[93]);
    r[94] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[93]); t = (sp_int_digit)(a[92]);
    r[93] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[92]); t = (sp_int_digit)(a[91]);
    r[92] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[91]); t = (sp_int_digit)(a[90]);
    r[91] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[90]); t = (sp_int_digit)(a[89]);
    r[90] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[89]); t = (sp_int_digit)(a[88]);
    r[89] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[88]); t = (sp_int_digit)(a[87]);
    r[88] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[87]); t = (sp_int_digit)(a[86]);
    r[87] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[86]); t = (sp_int_digit)(a[85]);
    r[86] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[85]); t = (sp_int_digit)(a[84]);
    r[85] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[84]); t = (sp_int_digit)(a[83]);
    r[84] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[83]); t = (sp_int_digit)(a[82]);
    r[83] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[82]); t = (sp_int_digit)(a[81]);
    r[82] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[81]); t = (sp_int_digit)(a[80]);
    r[81] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[80]); t = (sp_int_digit)(a[79]);
    r[80] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[79]); t = (sp_int_digit)(a[78]);
    r[79] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[78]); t = (sp_int_digit)(a[77]);
    r[78] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[77]); t = (sp_int_digit)(a[76]);
    r[77] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[76]); t = (sp_int_digit)(a[75]);
    r[76] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[75]); t = (sp_int_digit)(a[74]);
    r[75] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[74]); t = (sp_int_digit)(a[73]);
    r[74] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[73]); t = (sp_int_digit)(a[72]);
    r[73] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[72]); t = (sp_int_digit)(a[71]);
    r[72] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[71]); t = (sp_int_digit)(a[70]);
    r[71] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[70]); t = (sp_int_digit)(a[69]);
    r[70] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[69]); t = (sp_int_digit)(a[68]);
    r[69] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[68]); t = (sp_int_digit)(a[67]);
    r[68] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[67]); t = (sp_int_digit)(a[66]);
    r[67] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[66]); t = (sp_int_digit)(a[65]);
    r[66] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[65]); t = (sp_int_digit)(a[64]);
    r[65] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[64]); t = (sp_int_digit)(a[63]);
    r[64] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[63]); t = (sp_int_digit)(a[62]);
    r[63] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[62]); t = (sp_int_digit)(a[61]);
    r[62] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[61]); t = (sp_int_digit)(a[60]);
    r[61] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[60]); t = (sp_int_digit)(a[59]);
    r[60] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[59]); t = (sp_int_digit)(a[58]);
    r[59] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[58]); t = (sp_int_digit)(a[57]);
    r[58] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[57]); t = (sp_int_digit)(a[56]);
    r[57] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[56]); t = (sp_int_digit)(a[55]);
    r[56] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[55]); t = (sp_int_digit)(a[54]);
    r[55] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[54]); t = (sp_int_digit)(a[53]);
    r[54] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[53]); t = (sp_int_digit)(a[52]);
    r[53] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[52]); t = (sp_int_digit)(a[51]);
    r[52] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[51]); t = (sp_int_digit)(a[50]);
    r[51] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[50]); t = (sp_int_digit)(a[49]);
    r[50] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[49]); t = (sp_int_digit)(a[48]);
    r[49] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[48]); t = (sp_int_digit)(a[47]);
    r[48] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[47]); t = (sp_int_digit)(a[46]);
    r[47] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[46]); t = (sp_int_digit)(a[45]);
    r[46] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[45]); t = (sp_int_digit)(a[44]);
    r[45] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[44]); t = (sp_int_digit)(a[43]);
    r[44] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[43]); t = (sp_int_digit)(a[42]);
    r[43] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[42]); t = (sp_int_digit)(a[41]);
    r[42] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[41]); t = (sp_int_digit)(a[40]);
    r[41] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[40]); t = (sp_int_digit)(a[39]);
    r[40] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[39]); t = (sp_int_digit)(a[38]);
    r[39] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[38]); t = (sp_int_digit)(a[37]);
    r[38] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[37]); t = (sp_int_digit)(a[36]);
    r[37] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[36]); t = (sp_int_digit)(a[35]);
    r[36] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[35]); t = (sp_int_digit)(a[34]);
    r[35] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[34]); t = (sp_int_digit)(a[33]);
    r[34] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[33]); t = (sp_int_digit)(a[32]);
    r[33] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[32]); t = (sp_int_digit)(a[31]);
    r[32] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[31]); t = (sp_int_digit)(a[30]);
    r[31] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[30]); t = (sp_int_digit)(a[29]);
    r[30] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[29]); t = (sp_int_digit)(a[28]);
    r[29] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[28]); t = (sp_int_digit)(a[27]);
    r[28] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[27]); t = (sp_int_digit)(a[26]);
    r[27] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[26]); t = (sp_int_digit)(a[25]);
    r[26] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[25]); t = (sp_int_digit)(a[24]);
    r[25] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[24]); t = (sp_int_digit)(a[23]);
    r[24] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[23]); t = (sp_int_digit)(a[22]);
    r[23] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[22]); t = (sp_int_digit)(a[21]);
    r[22] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[21]); t = (sp_int_digit)(a[20]);
    r[21] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[20]); t = (sp_int_digit)(a[19]);
    r[20] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[19]); t = (sp_int_digit)(a[18]);
    r[19] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[18]); t = (sp_int_digit)(a[17]);
    r[18] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[17]); t = (sp_int_digit)(a[16]);
    r[17] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[16]); t = (sp_int_digit)(a[15]);
    r[16] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[15]); t = (sp_int_digit)(a[14]);
    r[15] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[14]); t = (sp_int_digit)(a[13]);
    r[14] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[13]); t = (sp_int_digit)(a[12]);
    r[13] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[12]); t = (sp_int_digit)(a[11]);
    r[12] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[11]); t = (sp_int_digit)(a[10]);
    r[11] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[10]); t = (sp_int_digit)(a[9]);
    r[10] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[9]); t = (sp_int_digit)(a[8]);
    r[9] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[8]); t = (sp_int_digit)(a[7]);
    r[8] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[7]); t = (sp_int_digit)(a[6]);
    r[7] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[6]); t = (sp_int_digit)(a[5]);
    r[6] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[5]); t = (sp_int_digit)(a[4]);
    r[5] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[4]); t = (sp_int_digit)(a[3]);
    r[4] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[3]); t = (sp_int_digit)(a[2]);
    r[3] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[2]); t = (sp_int_digit)(a[1]);
    r[2] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    s = (sp_int_digit)(a[1]); t = (sp_int_digit)(a[0]);
    r[1] = ((s << n) | (t >> (26U - n))) & 0x3ffffff;
    r[0] = (a[0] << n) & 0x3ffffff;
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
static int sp_4096_mod_exp_2_162(sp_digit* r, const sp_digit* e, int bits, const sp_digit* m)
{
    sp_digit td[487];
    sp_digit* norm = NULL;
    sp_digit* tmp = NULL;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit o;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        tmp  = td + 324;
        XMEMSET(td, 0, sizeof(sp_digit) * 487);

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_162(norm, m);

        bits = ((bits + 3) / 4) * 4;
        i = ((bits + 25) / 26) - 1;
        c = bits % 26;
        if (c == 0) {
            c = 26;
        }
        if (i < 162) {
            n = e[i--] << (32 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 4) {
            n |= e[i--] << (6 - c);
            c += 26;
        }
        y = (int)((n >> 28) & 0xf);
        n <<= 4;
        c -= 4;
        sp_4096_lshift_162(r, norm, (byte)y);
        while ((i >= 0) || (c >= 4)) {
            if (c >= 4) {
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c -= 4;
            }
            else if (c == 0) {
                n = e[i--] << 6;
                y = (byte)((n >> 28) & 0xf);
                n <<= 4;
                c = 22;
            }
            else {
                y = (byte)((n >> 28) & 0xf);
                n = e[i--] << 6;
                c = 4 - c;
                y |= (byte)((n >> (32 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 26 - c;
            }

            sp_4096_mont_sqr_162(r, r, m, mp);
            sp_4096_mont_sqr_162(r, r, m, mp);
            sp_4096_mont_sqr_162(r, r, m, mp);
            sp_4096_mont_sqr_162(r, r, m, mp);

            sp_4096_lshift_162(r, r, (byte)y);
            sp_4096_mul_d_162(tmp, norm, (r[158] << 12) + (r[157] >> 14));
            r[158] = 0;
            r[157] &= 0x3fffL;
            (void)sp_4096_add_162(r, r, tmp);
            sp_4096_norm_162(r);
            o = sp_4096_cmp_162(r, m);
            sp_4096_cond_sub_162(r, r, m, ~(o >> 31));
        }

        sp_4096_mont_reduce_162(r, m, mp);
        n = sp_4096_cmp_162(r, m);
        sp_4096_cond_sub_162(r, r, m, ~(n >> 31));
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
    sp_digit b[162 * 4];
    sp_digit* e = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    word32 i;
    int err = MP_OKAY;

    if (mp_count_bits(base) > 4096) {
        err = MP_READ_E;
    }
    else if (expLen > 512U) {
        err = MP_READ_E;
    }
    else if (mp_count_bits(mod) != 4096) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mod)) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        e = b + 162 * 2;
        m = e + 162;
        r = b;

        sp_4096_from_mp(b, 162, base);
        sp_4096_from_bin(e, 162, exp, expLen);
        sp_4096_from_mp(m, 162, mod);

    #ifdef HAVE_FFDHE_4096
        if (base->used == 1 && base->dp[0] == 2U &&
                ((m[157] << 2) | (m[156] >> 24)) == 0xffffL) {
            err = sp_4096_mod_exp_2_162(r, e, expLen * 8U, m);
        }
        else {
    #endif
            err = sp_4096_mod_exp_162(r, b, e, expLen * 8U, m, 0);
    #ifdef HAVE_FFDHE_4096
        }
    #endif
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_162(r, out);
        *outLen = 512;
        for (i=0; i<512U && out[i] == 0U; i++) {
            /* Search for first non-zero. */
        }
        *outLen -= i;
        XMEMMOVE(out, out + i, *outLen);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 162U);
    }

    return err;
}
#endif /* WOLFSSL_HAVE_SP_DH */

#endif /* WOLFSSL_HAVE_SP_DH | (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) */

#endif /* WOLFSSL_SP_SMALL */
#endif /* WOLFSSL_SP_4096 */

#endif /* WOLFSSL_HAVE_SP_RSA | WOLFSSL_HAVE_SP_DH */
#endif /* SP_WORD_SIZE == 32 */
#endif /* !WOLFSSL_SP_ASM */
#endif /* WOLFSSL_HAVE_SP_RSA | WOLFSSL_HAVE_SP_DH | WOLFSSL_HAVE_SP_ECC */
