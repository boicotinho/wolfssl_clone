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
#if SP_WORD_SIZE == 64
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
#ifdef WOLFSSL_SP_SMALL
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
        if (s >= 53U) {
            r[j] &= 0x1fffffffffffffffL;
            s = 61U - s;
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
#if DIGIT_BIT == 61
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 61
    int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0x1fffffffffffffffL;
        s = 61U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 61U) <= (word32)DIGIT_BIT) {
            s += 61U;
            r[j] &= 0x1fffffffffffffffL;
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
        if (s + DIGIT_BIT >= 61) {
            r[j] &= 0x1fffffffffffffffL;
            if (j + 1 >= size) {
                break;
            }
            s = 61 - s;
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
static void sp_2048_to_bin_34(sp_digit* r, byte* a)
{
    int i;
    int j;
    int s = 0;
    int b;

    for (i=0; i<33; i++) {
        r[i+1] += r[i] >> 61;
        r[i] &= 0x1fffffffffffffffL;
    }
    j = 2055 / 8 - 1;
    a[j] = 0;
    for (i=0; i<34 && j>=0; i++) {
        b = 0;
        /* lint allow cast of mismatch sp_digit and int */
        a[j--] |= (byte)(r[i] << s); /*lint !e9033*/
        b += 8 - s;
        if (j < 0) {
            break;
        }
        while (b < 61) {
            a[j--] = (byte)(r[i] >> b);
            b += 8;
            if (j < 0) {
                break;
            }
        }
        s = 8 - (b - 61);
        if (j >= 0) {
            a[j] = 0;
        }
        if (s != 0) {
            j++;
        }
    }
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* Normalize the values in each word to 61 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_2048_norm_17(sp_digit* a)
{
    int i;
    for (i = 0; i < 16; i++) {
        a[i+1] += a[i] >> 61;
        a[i] &= 0x1fffffffffffffffL;
    }
}

#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || WOLFSSL_HAVE_SP_DH */
/* Normalize the values in each word to 61 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_2048_norm_34(sp_digit* a)
{
    int i;
    for (i = 0; i < 33; i++) {
        a[i+1] += a[i] >> 61;
        a[i] &= 0x1fffffffffffffffL;
    }
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_34(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i;
    int imax;
    int k;
    sp_uint128 c;
    sp_uint128 lo;

    c = ((sp_uint128)a[33]) * b[33];
    r[67] = (sp_digit)(c >> 61);
    c &= 0x1fffffffffffffffL;
    for (k = 65; k >= 0; k--) {
        if (k >= 34) {
            i = k - 33;
            imax = 33;
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
                    lo += ((sp_uint128)a[i]) * b[k - i];
                }
                c += lo >> 61;
                lo &= 0x1fffffffffffffffL;
            }
            r[k + 2] += (sp_digit)(c >> 61);
            r[k + 1]  = (sp_digit)(c & 0x1fffffffffffffffL);
            c = lo & 0x1fffffffffffffffL;
        }
        else {
            lo = 0;
            for (; i <= imax; i++) {
                lo += ((sp_uint128)a[i]) * b[k - i];
            }
            c += lo >> 61;
            r[k + 2] += (sp_digit)(c >> 61);
            r[k + 1]  = (sp_digit)(c & 0x1fffffffffffffffL);
            c = lo & 0x1fffffffffffffffL;
        }
    }
    r[0] = (sp_digit)c;
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_34(sp_digit* r, const sp_digit* a)
{
    int i;
    int imax;
    int k;
    sp_uint128 c;
    sp_uint128 t;

    c = ((sp_uint128)a[33]) * a[33];
    r[67] = (sp_digit)(c >> 61);
    c = (c & 0x1fffffffffffffffL) << 61;
    for (k = 65; k >= 0; k--) {
        i = (k + 1) / 2;
        if ((k & 1) == 0) {
           c += ((sp_uint128)a[i]) * a[i];
           i++;
        }
        if (k < 33) {
            imax = k;
        }
        else {
            imax = 33;
        }
        if (imax - i >= 14) {
            int imaxlo;
            sp_uint128 hi;

            hi = c >> 61;
            c &= 0x1fffffffffffffffL;
            for (imaxlo = i; imaxlo <= imax; imaxlo += 14) {
                t = 0;
                for (; i <= imax && i < imaxlo + 14; i++) {
                    t += ((sp_uint128)a[i]) * a[k - i];
                }
                c += t * 2;

                hi += c >> 61;
                c &= 0x1fffffffffffffffL;
            }
            r[k + 2] += (sp_digit)(hi >> 61);
            r[k + 1]  = (sp_digit)(hi & 0x1fffffffffffffffL);
            c <<= 61;
        }
        else
        {
            t = 0;
            for (; i <= imax; i++) {
                t += ((sp_uint128)a[i]) * a[k - i];
            }
            c += t * 2;

            r[k + 2] += (sp_digit) (c >> 122);
            r[k + 1]  = (sp_digit)((c >> 61) & 0x1fffffffffffffffL);
            c = (c & 0x1fffffffffffffffL) << 61;
        }
    }
    r[0] = (sp_digit)(c >> 61);
}

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
    x &= 0x1fffffffffffffffL;

    /* rho = -1/m mod b */
    *rho = ((sp_digit)1 << 61) - x;
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_d_34(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t = 0;
    int i;

    for (i = 0; i < 34; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0x1fffffffffffffffL);
        t >>= 61;
    }
    r[34] = (sp_digit)t;
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_sub_17(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 17; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 2048 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_2048_mont_norm_17(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
    int i;

    for (i=0; i<16; i++) {
        r[i] = 0x1fffffffffffffffL;
    }
    r[16] = 0xffffffffffffL;

    /* r = (2^n - 1) mod n */
    (void)sp_2048_sub_17(r, r, m);

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
static sp_digit sp_2048_cmp_17(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
    int i;

    for (i=16; i>=0; i--) {
        r |= (a[i] - b[i]) & ~(((sp_digit)0 - r) >> 60);
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
static void sp_2048_cond_sub_17(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 17; i++) {
        r[i] = a[i] - (b[i] & m);
    }
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_add_17(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t[4];
    int i;

    t[0] = 0;
    for (i = 0; i < 16; i += 4) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        r[i+0] = t[0] & 0x1fffffffffffffffL;
        t[1] += t[0] >> 61;
        r[i+1] = t[1] & 0x1fffffffffffffffL;
        t[2] += t[1] >> 61;
        r[i+2] = t[2] & 0x1fffffffffffffffL;
        t[3] += t[2] >> 61;
        r[i+3] = t[3] & 0x1fffffffffffffffL;
        t[0]  = t[3] >> 61;
    }
    t[0] += (tb * a[16]) + r[16];
    r[16] = t[0] & 0x1fffffffffffffffL;
    r[17] +=  (sp_digit)(t[0] >> 61);
}

/* Shift the result in the high 1024 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_2048_mont_shift_17(sp_digit* r, const sp_digit* a)
{
    int i;
    sp_int128 n = a[16] >> 48;
    n += ((sp_int128)a[17]) << 13;

    for (i = 0; i < 16; i++) {
        r[i] = n & 0x1fffffffffffffffL;
        n >>= 61;
        n += ((sp_int128)a[18 + i]) << 13;
    }
    r[16] = (sp_digit)n;
    XMEMSET(&r[17], 0, sizeof(*r) * 17U);
}

/* Reduce the number back to 2048 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_2048_mont_reduce_17(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_2048_norm_17(a + 17);

    for (i=0; i<16; i++) {
        mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x1fffffffffffffffL;
        sp_2048_mul_add_17(a+i, m, mu);
        a[i+1] += a[i] >> 61;
    }
    mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0xffffffffffffL;
    sp_2048_mul_add_17(a+i, m, mu);
    a[i+1] += a[i] >> 61;
    a[i] &= 0x1fffffffffffffffL;
    sp_2048_mont_shift_17(a, a);
    over = a[16] - m[16];
    sp_2048_cond_sub_17(a, a, m, ~((over - 1) >> 63));
    sp_2048_norm_17(a);
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_17(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i;
    int imax;
    int k;
    sp_uint128 c;
    sp_uint128 lo;

    c = ((sp_uint128)a[16]) * b[16];
    r[33] = (sp_digit)(c >> 61);
    c &= 0x1fffffffffffffffL;
    for (k = 31; k >= 0; k--) {
        if (k >= 17) {
            i = k - 16;
            imax = 16;
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
                    lo += ((sp_uint128)a[i]) * b[k - i];
                }
                c += lo >> 61;
                lo &= 0x1fffffffffffffffL;
            }
            r[k + 2] += (sp_digit)(c >> 61);
            r[k + 1]  = (sp_digit)(c & 0x1fffffffffffffffL);
            c = lo & 0x1fffffffffffffffL;
        }
        else {
            lo = 0;
            for (; i <= imax; i++) {
                lo += ((sp_uint128)a[i]) * b[k - i];
            }
            c += lo >> 61;
            r[k + 2] += (sp_digit)(c >> 61);
            r[k + 1]  = (sp_digit)(c & 0x1fffffffffffffffL);
            c = lo & 0x1fffffffffffffffL;
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
SP_NOINLINE static void sp_2048_mont_mul_17(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_2048_mul_17(r, a, b);
    sp_2048_mont_reduce_17(r, m, mp);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_17(sp_digit* r, const sp_digit* a)
{
    int i;
    int imax;
    int k;
    sp_uint128 c;
    sp_uint128 t;

    c = ((sp_uint128)a[16]) * a[16];
    r[33] = (sp_digit)(c >> 61);
    c = (c & 0x1fffffffffffffffL) << 61;
    for (k = 31; k >= 0; k--) {
        i = (k + 1) / 2;
        if ((k & 1) == 0) {
           c += ((sp_uint128)a[i]) * a[i];
           i++;
        }
        if (k < 16) {
            imax = k;
        }
        else {
            imax = 16;
        }
        if (imax - i >= 14) {
            int imaxlo;
            sp_uint128 hi;

            hi = c >> 61;
            c &= 0x1fffffffffffffffL;
            for (imaxlo = i; imaxlo <= imax; imaxlo += 14) {
                t = 0;
                for (; i <= imax && i < imaxlo + 14; i++) {
                    t += ((sp_uint128)a[i]) * a[k - i];
                }
                c += t * 2;

                hi += c >> 61;
                c &= 0x1fffffffffffffffL;
            }
            r[k + 2] += (sp_digit)(hi >> 61);
            r[k + 1]  = (sp_digit)(hi & 0x1fffffffffffffffL);
            c <<= 61;
        }
        else
        {
            t = 0;
            for (; i <= imax; i++) {
                t += ((sp_uint128)a[i]) * a[k - i];
            }
            c += t * 2;

            r[k + 2] += (sp_digit) (c >> 122);
            r[k + 1]  = (sp_digit)((c >> 61) & 0x1fffffffffffffffL);
            c = (c & 0x1fffffffffffffffL) << 61;
        }
    }
    r[0] = (sp_digit)(c >> 61);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_2048_mont_sqr_17(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_2048_sqr_17(r, a);
    sp_2048_mont_reduce_17(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_d_17(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t = 0;
    int i;

    for (i = 0; i < 17; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0x1fffffffffffffffL);
        t >>= 61;
    }
    r[17] = (sp_digit)t;
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
static void sp_2048_cond_add_17(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 17; i++) {
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
SP_NOINLINE static int sp_2048_add_17(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 17; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}

SP_NOINLINE static void sp_2048_rshift_17(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    for (i=0; i<16; i++) {
        r[i] = ((a[i] >> n) | (a[i + 1] << (61 - n))) & 0x1fffffffffffffffL;
    }
    r[16] = a[16] >> n;
}

static WC_INLINE sp_digit sp_2048_div_word_17(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int128 d = ((sp_int128)d1 << 61) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int128 d = ((sp_int128)d1 << 61) + d0;
    sp_uint64 lo = (sp_uint64)d;
    sp_digit hi = (sp_digit)(d >> 64);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int128 d = ((sp_int128)d1 << 61) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 61);
    sp_digit t0 = (sp_digit)(d & 0x1fffffffffffffffL);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int128 m;

    r = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
    t1 -= dv & (0 - r);
    for (i = 59; i >= 1; i--) {
        t1 += t1 + (((sp_uint64)t0 >> 60) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int128)r * div);
    r += (sp_digit)(m >> 61);
    m = d - ((sp_int128)r * div);
    r += (m >> 122) - (sp_digit)(d >> 122);

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;
   return r;
#else
    sp_int128 d = ((sp_int128)d1 << 61) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 30) + 1;

    t = (sp_digit)(d >> 60);
    t = (t / dv) << 30;
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)(d >> 29);
    t = t / (dv << 1);
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int128)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_2048_word_div_word_17(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint64)(div - d) >> 63);
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
static int sp_2048_div_17(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_64
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 17 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 34 + 1;
        sd = t2 + 17 + 1;

        sp_2048_mul_d_17(sd, d, (sp_digit)1 << 13);
        sp_2048_mul_d_34(t1, a, (sp_digit)1 << 13);
        dv = sd[16];
        t1[17 + 17] += t1[17 + 17 - 1] >> 61;
        t1[17 + 17 - 1] &= 0x1fffffffffffffffL;
        for (i=17; i>=0; i--) {
            r1 = sp_2048_div_word_17(t1[17 + i], t1[17 + i - 1], dv);

            sp_2048_mul_d_17(t2, sd, r1);
            (void)sp_2048_sub_17(&t1[i], &t1[i], t2);
            sp_2048_norm_17(&t1[i]);
            t1[17 + i] -= t2[17];
            t1[17 + i] += t1[17 + i - 1] >> 61;
            t1[17 + i - 1] &= 0x1fffffffffffffffL;
            r1 = sp_2048_div_word_17(-t1[17 + i], -t1[17 + i - 1], dv);
            r1 -= t1[17 + i];
            sp_2048_mul_d_17(t2, sd, r1);
            (void)sp_2048_add_17(&t1[i], &t1[i], t2);
            t1[17 + i] += t1[17 + i - 1] >> 61;
            t1[17 + i - 1] &= 0x1fffffffffffffffL;
        }
        t1[17 - 1] += t1[17 - 2] >> 61;
        t1[17 - 2] &= 0x1fffffffffffffffL;
        r1 = sp_2048_word_div_word_17(t1[17 - 1], dv);

        sp_2048_mul_d_17(t2, sd, r1);
        sp_2048_sub_17(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 34U);
        for (i=0; i<16; i++) {
            r[i+1] += r[i] >> 61;
            r[i] &= 0x1fffffffffffffffL;
        }
        sp_2048_cond_add_17(r, r, sd, r[16] >> 63);

        sp_2048_norm_17(r);
        sp_2048_rshift_17(r, r, 13);
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
static int sp_2048_mod_17(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_2048_div_17(a, m, NULL, r);
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
static int sp_2048_mod_exp_17(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 34];
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
            t[i] = td + (i * 17 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 17U * 2U);
        }

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_17(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_17(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 17U);
        }
    }
    if (err == MP_OKAY) {
        sp_2048_mul_17(t[1], t[1], norm);
        err = sp_2048_mod_17(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 61;
        c = bits % 61;
        n = e[i--] << (61 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 61;
            }

            y = (int)((n >> 60) & 1);
            n <<= 1;

            sp_2048_mont_mul_17(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 17 * 2);
            sp_2048_mont_sqr_17(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 17 * 2);
        }

        sp_2048_mont_reduce_17(t[0], m, mp);
        n = sp_2048_cmp_17(t[0], m);
        sp_2048_cond_sub_17(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 17 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 34];
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
            t[i] = td + (i * 17 * 2);
        }

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_17(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_17(t[1], a, m);
            if (err == MP_OKAY) {
                sp_2048_mul_17(t[1], t[1], norm);
                err = sp_2048_mod_17(t[1], t[1], m);
            }
        }
        else {
            sp_2048_mul_17(t[1], a, norm);
            err = sp_2048_mod_17(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 61;
        c = bits % 61;
        n = e[i--] << (61 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 61;
            }

            y = (int)((n >> 60) & 1);
            n <<= 1;

            sp_2048_mont_mul_17(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 17 * 2);
            sp_2048_mont_sqr_17(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 17 * 2);
        }

        sp_2048_mont_reduce_17(t[0], m, mp);
        n = sp_2048_cmp_17(t[0], m);
        sp_2048_cond_sub_17(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 17 * 2);
    }


    return err;
#else
    sp_digit td[(32 * 34) + 34];
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
            t[i] = td + i * 34;
        rt = td + 1088;

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_17(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_17(t[1], a, m);
            if (err == MP_OKAY) {
                sp_2048_mul_17(t[1], t[1], norm);
                err = sp_2048_mod_17(t[1], t[1], m);
            }
        }
        else {
            sp_2048_mul_17(t[1], a, norm);
            err = sp_2048_mod_17(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_2048_mont_sqr_17(t[ 2], t[ 1], m, mp);
        sp_2048_mont_mul_17(t[ 3], t[ 2], t[ 1], m, mp);
        sp_2048_mont_sqr_17(t[ 4], t[ 2], m, mp);
        sp_2048_mont_mul_17(t[ 5], t[ 3], t[ 2], m, mp);
        sp_2048_mont_sqr_17(t[ 6], t[ 3], m, mp);
        sp_2048_mont_mul_17(t[ 7], t[ 4], t[ 3], m, mp);
        sp_2048_mont_sqr_17(t[ 8], t[ 4], m, mp);
        sp_2048_mont_mul_17(t[ 9], t[ 5], t[ 4], m, mp);
        sp_2048_mont_sqr_17(t[10], t[ 5], m, mp);
        sp_2048_mont_mul_17(t[11], t[ 6], t[ 5], m, mp);
        sp_2048_mont_sqr_17(t[12], t[ 6], m, mp);
        sp_2048_mont_mul_17(t[13], t[ 7], t[ 6], m, mp);
        sp_2048_mont_sqr_17(t[14], t[ 7], m, mp);
        sp_2048_mont_mul_17(t[15], t[ 8], t[ 7], m, mp);
        sp_2048_mont_sqr_17(t[16], t[ 8], m, mp);
        sp_2048_mont_mul_17(t[17], t[ 9], t[ 8], m, mp);
        sp_2048_mont_sqr_17(t[18], t[ 9], m, mp);
        sp_2048_mont_mul_17(t[19], t[10], t[ 9], m, mp);
        sp_2048_mont_sqr_17(t[20], t[10], m, mp);
        sp_2048_mont_mul_17(t[21], t[11], t[10], m, mp);
        sp_2048_mont_sqr_17(t[22], t[11], m, mp);
        sp_2048_mont_mul_17(t[23], t[12], t[11], m, mp);
        sp_2048_mont_sqr_17(t[24], t[12], m, mp);
        sp_2048_mont_mul_17(t[25], t[13], t[12], m, mp);
        sp_2048_mont_sqr_17(t[26], t[13], m, mp);
        sp_2048_mont_mul_17(t[27], t[14], t[13], m, mp);
        sp_2048_mont_sqr_17(t[28], t[14], m, mp);
        sp_2048_mont_mul_17(t[29], t[15], t[14], m, mp);
        sp_2048_mont_sqr_17(t[30], t[15], m, mp);
        sp_2048_mont_mul_17(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 60) / 61) - 1;
        c = bits % 61;
        if (c == 0) {
            c = 61;
        }
        if (i < 17) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (3 - c);
            c += 61;
        }
        y = (int)((n >> 59) & 0x1f);
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 34);
        while ((i >= 0) || (c >= 5)) {
            if (c >= 5) {
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--] << 3;
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c = 56;
            }
            else {
                y = (byte)((n >> 59) & 0x1f);
                n = e[i--] << 3;
                c = 5 - c;
                y |= (byte)((n >> (64 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 61 - c;
            }

            sp_2048_mont_sqr_17(rt, rt, m, mp);
            sp_2048_mont_sqr_17(rt, rt, m, mp);
            sp_2048_mont_sqr_17(rt, rt, m, mp);
            sp_2048_mont_sqr_17(rt, rt, m, mp);
            sp_2048_mont_sqr_17(rt, rt, m, mp);

            sp_2048_mont_mul_17(rt, rt, t[y], m, mp);
        }

        sp_2048_mont_reduce_17(rt, m, mp);
        n = sp_2048_cmp_17(rt, m);
        sp_2048_cond_sub_17(rt, rt, m, ~(n >> 63));
        XMEMCPY(r, rt, sizeof(sp_digit) * 34);
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
SP_NOINLINE static int sp_2048_sub_34(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 34; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 2048 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_2048_mont_norm_34(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
    int i;

    for (i=0; i<33; i++) {
        r[i] = 0x1fffffffffffffffL;
    }
    r[33] = 0x7ffffffffL;

    /* r = (2^n - 1) mod n */
    (void)sp_2048_sub_34(r, r, m);

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
static sp_digit sp_2048_cmp_34(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
    int i;

    for (i=33; i>=0; i--) {
        r |= (a[i] - b[i]) & ~(((sp_digit)0 - r) >> 60);
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
static void sp_2048_cond_sub_34(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 34; i++) {
        r[i] = a[i] - (b[i] & m);
    }
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_add_34(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t[4];
    int i;

    t[0] = 0;
    for (i = 0; i < 32; i += 4) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        r[i+0] = t[0] & 0x1fffffffffffffffL;
        t[1] += t[0] >> 61;
        r[i+1] = t[1] & 0x1fffffffffffffffL;
        t[2] += t[1] >> 61;
        r[i+2] = t[2] & 0x1fffffffffffffffL;
        t[3] += t[2] >> 61;
        r[i+3] = t[3] & 0x1fffffffffffffffL;
        t[0]  = t[3] >> 61;
    }
    t[0] += (tb * a[32]) + r[32];
    t[1]  = (tb * a[33]) + r[33];
    r[32] = t[0] & 0x1fffffffffffffffL;
    t[1] += t[0] >> 61;
    r[33] = t[1] & 0x1fffffffffffffffL;
    r[34] +=  (sp_digit)(t[1] >> 61);
}

/* Shift the result in the high 2048 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_2048_mont_shift_34(sp_digit* r, const sp_digit* a)
{
    int i;
    sp_int128 n = a[33] >> 35;
    n += ((sp_int128)a[34]) << 26;

    for (i = 0; i < 33; i++) {
        r[i] = n & 0x1fffffffffffffffL;
        n >>= 61;
        n += ((sp_int128)a[35 + i]) << 26;
    }
    r[33] = (sp_digit)n;
    XMEMSET(&r[34], 0, sizeof(*r) * 34U);
}

/* Reduce the number back to 2048 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_2048_mont_reduce_34(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_2048_norm_34(a + 34);

#ifdef WOLFSSL_SP_DH
    if (mp != 1) {
        for (i=0; i<33; i++) {
            mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x1fffffffffffffffL;
            sp_2048_mul_add_34(a+i, m, mu);
            a[i+1] += a[i] >> 61;
        }
        mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x7ffffffffL;
        sp_2048_mul_add_34(a+i, m, mu);
        a[i+1] += a[i] >> 61;
        a[i] &= 0x1fffffffffffffffL;
    }
    else {
        for (i=0; i<33; i++) {
            mu = a[i] & 0x1fffffffffffffffL;
            sp_2048_mul_add_34(a+i, m, mu);
            a[i+1] += a[i] >> 61;
        }
        mu = a[i] & 0x7ffffffffL;
        sp_2048_mul_add_34(a+i, m, mu);
        a[i+1] += a[i] >> 61;
        a[i] &= 0x1fffffffffffffffL;
    }
#else
    for (i=0; i<33; i++) {
        mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x1fffffffffffffffL;
        sp_2048_mul_add_34(a+i, m, mu);
        a[i+1] += a[i] >> 61;
    }
    mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x7ffffffffL;
    sp_2048_mul_add_34(a+i, m, mu);
    a[i+1] += a[i] >> 61;
    a[i] &= 0x1fffffffffffffffL;
#endif
    sp_2048_mont_shift_34(a, a);
    over = a[33] - m[33];
    sp_2048_cond_sub_34(a, a, m, ~((over - 1) >> 63));
    sp_2048_norm_34(a);
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
SP_NOINLINE static void sp_2048_mont_mul_34(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_2048_mul_34(r, a, b);
    sp_2048_mont_reduce_34(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_2048_mont_sqr_34(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_2048_sqr_34(r, a);
    sp_2048_mont_reduce_34(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_d_68(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t = 0;
    int i;

    for (i = 0; i < 68; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0x1fffffffffffffffL);
        t >>= 61;
    }
    r[68] = (sp_digit)t;
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
static void sp_2048_cond_add_34(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 34; i++) {
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
SP_NOINLINE static int sp_2048_add_34(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 34; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}

SP_NOINLINE static void sp_2048_rshift_34(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    for (i=0; i<33; i++) {
        r[i] = ((a[i] >> n) | (a[i + 1] << (61 - n))) & 0x1fffffffffffffffL;
    }
    r[33] = a[33] >> n;
}

static WC_INLINE sp_digit sp_2048_div_word_34(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int128 d = ((sp_int128)d1 << 61) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int128 d = ((sp_int128)d1 << 61) + d0;
    sp_uint64 lo = (sp_uint64)d;
    sp_digit hi = (sp_digit)(d >> 64);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int128 d = ((sp_int128)d1 << 61) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 61);
    sp_digit t0 = (sp_digit)(d & 0x1fffffffffffffffL);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int128 m;

    r = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
    t1 -= dv & (0 - r);
    for (i = 59; i >= 1; i--) {
        t1 += t1 + (((sp_uint64)t0 >> 60) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int128)r * div);
    r += (sp_digit)(m >> 61);
    m = d - ((sp_int128)r * div);
    r += (m >> 122) - (sp_digit)(d >> 122);

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;
   return r;
#else
    sp_int128 d = ((sp_int128)d1 << 61) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 30) + 1;

    t = (sp_digit)(d >> 60);
    t = (t / dv) << 30;
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)(d >> 29);
    t = t / (dv << 1);
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int128)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_2048_word_div_word_34(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint64)(div - d) >> 63);
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
static int sp_2048_div_34(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_64
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 34 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 68 + 1;
        sd = t2 + 34 + 1;

        sp_2048_mul_d_34(sd, d, (sp_digit)1 << 26);
        sp_2048_mul_d_68(t1, a, (sp_digit)1 << 26);
        dv = sd[33];
        t1[34 + 34] += t1[34 + 34 - 1] >> 61;
        t1[34 + 34 - 1] &= 0x1fffffffffffffffL;
        for (i=34; i>=0; i--) {
            r1 = sp_2048_div_word_34(t1[34 + i], t1[34 + i - 1], dv);

            sp_2048_mul_d_34(t2, sd, r1);
            (void)sp_2048_sub_34(&t1[i], &t1[i], t2);
            sp_2048_norm_34(&t1[i]);
            t1[34 + i] -= t2[34];
            t1[34 + i] += t1[34 + i - 1] >> 61;
            t1[34 + i - 1] &= 0x1fffffffffffffffL;
            r1 = sp_2048_div_word_34(-t1[34 + i], -t1[34 + i - 1], dv);
            r1 -= t1[34 + i];
            sp_2048_mul_d_34(t2, sd, r1);
            (void)sp_2048_add_34(&t1[i], &t1[i], t2);
            t1[34 + i] += t1[34 + i - 1] >> 61;
            t1[34 + i - 1] &= 0x1fffffffffffffffL;
        }
        t1[34 - 1] += t1[34 - 2] >> 61;
        t1[34 - 2] &= 0x1fffffffffffffffL;
        r1 = sp_2048_word_div_word_34(t1[34 - 1], dv);

        sp_2048_mul_d_34(t2, sd, r1);
        sp_2048_sub_34(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 68U);
        for (i=0; i<33; i++) {
            r[i+1] += r[i] >> 61;
            r[i] &= 0x1fffffffffffffffL;
        }
        sp_2048_cond_add_34(r, r, sd, r[33] >> 63);

        sp_2048_norm_34(r);
        sp_2048_rshift_34(r, r, 26);
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
static int sp_2048_mod_34(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_2048_div_34(a, m, NULL, r);
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
static int sp_2048_mod_exp_34(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 68];
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
            t[i] = td + (i * 34 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 34U * 2U);
        }

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_34(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_34(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 34U);
        }
    }
    if (err == MP_OKAY) {
        sp_2048_mul_34(t[1], t[1], norm);
        err = sp_2048_mod_34(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 61;
        c = bits % 61;
        n = e[i--] << (61 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 61;
            }

            y = (int)((n >> 60) & 1);
            n <<= 1;

            sp_2048_mont_mul_34(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 34 * 2);
            sp_2048_mont_sqr_34(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 34 * 2);
        }

        sp_2048_mont_reduce_34(t[0], m, mp);
        n = sp_2048_cmp_34(t[0], m);
        sp_2048_cond_sub_34(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 34 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 68];
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
            t[i] = td + (i * 34 * 2);
        }

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_34(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_34(t[1], a, m);
            if (err == MP_OKAY) {
                sp_2048_mul_34(t[1], t[1], norm);
                err = sp_2048_mod_34(t[1], t[1], m);
            }
        }
        else {
            sp_2048_mul_34(t[1], a, norm);
            err = sp_2048_mod_34(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 61;
        c = bits % 61;
        n = e[i--] << (61 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 61;
            }

            y = (int)((n >> 60) & 1);
            n <<= 1;

            sp_2048_mont_mul_34(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 34 * 2);
            sp_2048_mont_sqr_34(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 34 * 2);
        }

        sp_2048_mont_reduce_34(t[0], m, mp);
        n = sp_2048_cmp_34(t[0], m);
        sp_2048_cond_sub_34(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 34 * 2);
    }


    return err;
#else
    sp_digit td[(16 * 68) + 68];
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
            t[i] = td + i * 68;
        rt = td + 1088;

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_34(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_34(t[1], a, m);
            if (err == MP_OKAY) {
                sp_2048_mul_34(t[1], t[1], norm);
                err = sp_2048_mod_34(t[1], t[1], m);
            }
        }
        else {
            sp_2048_mul_34(t[1], a, norm);
            err = sp_2048_mod_34(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_2048_mont_sqr_34(t[ 2], t[ 1], m, mp);
        sp_2048_mont_mul_34(t[ 3], t[ 2], t[ 1], m, mp);
        sp_2048_mont_sqr_34(t[ 4], t[ 2], m, mp);
        sp_2048_mont_mul_34(t[ 5], t[ 3], t[ 2], m, mp);
        sp_2048_mont_sqr_34(t[ 6], t[ 3], m, mp);
        sp_2048_mont_mul_34(t[ 7], t[ 4], t[ 3], m, mp);
        sp_2048_mont_sqr_34(t[ 8], t[ 4], m, mp);
        sp_2048_mont_mul_34(t[ 9], t[ 5], t[ 4], m, mp);
        sp_2048_mont_sqr_34(t[10], t[ 5], m, mp);
        sp_2048_mont_mul_34(t[11], t[ 6], t[ 5], m, mp);
        sp_2048_mont_sqr_34(t[12], t[ 6], m, mp);
        sp_2048_mont_mul_34(t[13], t[ 7], t[ 6], m, mp);
        sp_2048_mont_sqr_34(t[14], t[ 7], m, mp);
        sp_2048_mont_mul_34(t[15], t[ 8], t[ 7], m, mp);

        bits = ((bits + 3) / 4) * 4;
        i = ((bits + 60) / 61) - 1;
        c = bits % 61;
        if (c == 0) {
            c = 61;
        }
        if (i < 34) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 4) {
            n |= e[i--] << (3 - c);
            c += 61;
        }
        y = (int)((n >> 60) & 0xf);
        n <<= 4;
        c -= 4;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 68);
        while ((i >= 0) || (c >= 4)) {
            if (c >= 4) {
                y = (byte)((n >> 60) & 0xf);
                n <<= 4;
                c -= 4;
            }
            else if (c == 0) {
                n = e[i--] << 3;
                y = (byte)((n >> 60) & 0xf);
                n <<= 4;
                c = 57;
            }
            else {
                y = (byte)((n >> 60) & 0xf);
                n = e[i--] << 3;
                c = 4 - c;
                y |= (byte)((n >> (64 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 61 - c;
            }

            sp_2048_mont_sqr_34(rt, rt, m, mp);
            sp_2048_mont_sqr_34(rt, rt, m, mp);
            sp_2048_mont_sqr_34(rt, rt, m, mp);
            sp_2048_mont_sqr_34(rt, rt, m, mp);

            sp_2048_mont_mul_34(rt, rt, t[y], m, mp);
        }

        sp_2048_mont_reduce_34(rt, m, mp);
        n = sp_2048_cmp_34(rt, m);
        sp_2048_cond_sub_34(rt, rt, m, ~(n >> 63));
        XMEMCPY(r, rt, sizeof(sp_digit) * 68);
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
 *         Must be at least 256 bytes long.
 * outLen  Number of bytes in result.
 * returns 0 on success, MP_TO_E when the outLen is too small, MP_READ_E when
 * an array is too long and MEMORY_E when dynamic memory allocation fails.
 */
int sp_RsaPublic_2048(const byte* in, word32 inLen, const mp_int* em,
    const mp_int* mm, byte* out, word32* outLen)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit a[34 * 5];
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
        if (mp_count_bits(em) > 61) {
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
        r = a + 34 * 2;
        m = r + 34 * 2;
        norm = r;

        sp_2048_from_bin(a, 34, in, inLen);
#if DIGIT_BIT >= 61
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
        sp_2048_from_mp(m, 34, mm);

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_34(norm, m);
    }
    if (err == MP_OKAY) {
        sp_2048_mul_34(a, a, norm);
        err = sp_2048_mod_34(a, a, m);
    }
    if (err == MP_OKAY) {
        for (i=60; i>=0; i--) {
            if ((e[0] >> i) != 0) {
                break;
            }
        }

        XMEMCPY(r, a, sizeof(sp_digit) * 34 * 2);
        for (i--; i>=0; i--) {
            sp_2048_mont_sqr_34(r, r, m, mp);

            if (((e[0] >> i) & 1) == 1) {
                sp_2048_mont_mul_34(r, r, a, m, mp);
            }
        }
        sp_2048_mont_reduce_34(r, m, mp);
        mp = sp_2048_cmp_34(r, m);
        sp_2048_cond_sub_34(r, r, m, ~(mp >> 63));

        sp_2048_to_bin_34(r, out);
        *outLen = 256;
    }


    return err;
#else
    sp_digit d[34 * 5];
    sp_digit* a = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit e[1] = {0};
    int err = MP_OKAY;

    if (*outLen < 256U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 61) {
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
        r = a + 34 * 2;
        m = r + 34 * 2;

        sp_2048_from_bin(a, 34, in, inLen);
#if DIGIT_BIT >= 61
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
        sp_2048_from_mp(m, 34, mm);

        if (e[0] == 0x3) {
            sp_2048_sqr_34(r, a);
            err = sp_2048_mod_34(r, r, m);
            if (err == MP_OKAY) {
                sp_2048_mul_34(r, a, r);
                err = sp_2048_mod_34(r, r, m);
            }
        }
        else {
            sp_digit* norm = r;
            int i;
            sp_digit mp;

            sp_2048_mont_setup(m, &mp);
            sp_2048_mont_norm_34(norm, m);

            sp_2048_mul_34(a, a, norm);
            err = sp_2048_mod_34(a, a, m);

            if (err == MP_OKAY) {
                for (i=60; i>=0; i--) {
                    if ((e[0] >> i) != 0) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 68U);
                for (i--; i>=0; i--) {
                    sp_2048_mont_sqr_34(r, r, m, mp);

                    if (((e[0] >> i) & 1) == 1) {
                        sp_2048_mont_mul_34(r, r, a, m, mp);
                    }
                }
                sp_2048_mont_reduce_34(r, m, mp);
                mp = sp_2048_cmp_34(r, m);
                sp_2048_cond_sub_34(r, r, m, ~(mp >> 63));
            }
        }
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin_34(r, out);
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
    sp_digit  d[34 * 4];
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
        a = d + 34;
        m = a + 68;
        r = a;

        sp_2048_from_bin(a, 34, in, inLen);
        sp_2048_from_mp(d, 34, dm);
        sp_2048_from_mp(m, 34, mm);
        err = sp_2048_mod_exp_34(r, a, d, 2048, m, 0);
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin_34(r, out);
        *outLen = 256;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 34);
    }

    return err;
#else
    sp_digit d[34 * 4];
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
        a = d + 34;
        m = a + 68;
        r = a;

        sp_2048_from_bin(a, 34, in, inLen);
        sp_2048_from_mp(d, 34, dm);
        sp_2048_from_mp(m, 34, mm);
        err = sp_2048_mod_exp_34(r, a, d, 2048, m, 0);
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin_34(r, out);
        *outLen = 256;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 34);
    }

    return err;
#endif /* WOLFSSL_SP_SMALL */
#else
#if defined(WOLFSSL_SP_SMALL)
    sp_digit a[17 * 8];
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
        p = a + 34;
        qi = dq = dp = p + 17;
        tmpa = qi + 17;
        tmpb = tmpa + 34;
        r = a;

        sp_2048_from_bin(a, 34, in, inLen);
        sp_2048_from_mp(p, 17, pm);
        sp_2048_from_mp(dp, 17, dpm);
        err = sp_2048_mod_exp_17(tmpa, a, dp, 1024, p, 1);
    }
    if (err == MP_OKAY) {
        sp_2048_from_mp(p, 17, qm);
        sp_2048_from_mp(dq, 17, dqm);
        err = sp_2048_mod_exp_17(tmpb, a, dq, 1024, p, 1);
    }
    if (err == MP_OKAY) {
        sp_2048_from_mp(p, 17, pm);
        (void)sp_2048_sub_17(tmpa, tmpa, tmpb);
        sp_2048_norm_17(tmpa);
        sp_2048_cond_add_17(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[16] >> 63));
        sp_2048_cond_add_17(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[16] >> 63));
        sp_2048_norm_17(tmpa);

        sp_2048_from_mp(qi, 17, qim);
        sp_2048_mul_17(tmpa, tmpa, qi);
        err = sp_2048_mod_17(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_2048_from_mp(p, 17, qm);
        sp_2048_mul_17(tmpa, p, tmpa);
        (void)sp_2048_add_34(r, tmpb, tmpa);
        sp_2048_norm_34(r);

        sp_2048_to_bin_34(r, out);
        *outLen = 256;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 17 * 8);
    }

    return err;
#else
    sp_digit a[17 * 13];
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
        p = a + 34 * 2;
        q = p + 17;
        dp = q + 17;
        dq = dp + 17;
        qi = dq + 17;
        tmpa = qi + 17;
        tmpb = tmpa + 34;
        r = a;

        sp_2048_from_bin(a, 34, in, inLen);
        sp_2048_from_mp(p, 17, pm);
        sp_2048_from_mp(q, 17, qm);
        sp_2048_from_mp(dp, 17, dpm);
        sp_2048_from_mp(dq, 17, dqm);
        sp_2048_from_mp(qi, 17, qim);

        err = sp_2048_mod_exp_17(tmpa, a, dp, 1024, p, 1);
    }
    if (err == MP_OKAY) {
        err = sp_2048_mod_exp_17(tmpb, a, dq, 1024, q, 1);
    }

    if (err == MP_OKAY) {
        (void)sp_2048_sub_17(tmpa, tmpa, tmpb);
        sp_2048_norm_17(tmpa);
        sp_2048_cond_add_17(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[16] >> 63));
        sp_2048_cond_add_17(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[16] >> 63));
        sp_2048_norm_17(tmpa);
        sp_2048_mul_17(tmpa, tmpa, qi);
        err = sp_2048_mod_17(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_2048_mul_17(tmpa, tmpa, q);
        (void)sp_2048_add_34(r, tmpb, tmpa);
        sp_2048_norm_34(r);

        sp_2048_to_bin_34(r, out);
        *outLen = 256;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 17 * 13);
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
#if DIGIT_BIT == 61
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 34);
        r->used = 34;
        mp_clamp(r);
#elif DIGIT_BIT < 61
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 34; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 61) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 61 - s;
        }
        r->used = (2048 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 34; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 61 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 61 - s;
            }
            else {
                s += 61;
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
    sp_digit b[34 * 4];
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
        e = b + 34 * 2;
        m = e + 34;
        r = b;

        sp_2048_from_mp(b, 34, base);
        sp_2048_from_mp(e, 34, exp);
        sp_2048_from_mp(m, 34, mod);

        err = sp_2048_mod_exp_34(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_2048_to_mp(r, res);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 34U);
    }
    return err;
#else
    sp_digit b[34 * 4];
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
        e = b + 34 * 2;
        m = e + 34;
        r = b;

        sp_2048_from_mp(b, 34, base);
        sp_2048_from_mp(e, 34, exp);
        sp_2048_from_mp(m, 34, mod);

        err = sp_2048_mod_exp_34(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_2048_to_mp(r, res);
    }


    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 34U);
    }

    return err;
#endif
}

#ifdef WOLFSSL_HAVE_SP_DH

SP_NOINLINE static void sp_2048_lshift_34(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    r[34] = a[33] >> (61 - n);
    for (i=33; i>0; i--) {
        r[i] = ((a[i] << n) | (a[i-1] >> (61 - n))) & 0x1fffffffffffffffL;
    }
    r[0] = (a[0] << n) & 0x1fffffffffffffffL;
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
static int sp_2048_mod_exp_2_34(sp_digit* r, const sp_digit* e, int bits, const sp_digit* m)
{
    sp_digit td[103];
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
        tmp  = td + 68;
        XMEMSET(td, 0, sizeof(sp_digit) * 103);

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_34(norm, m);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 60) / 61) - 1;
        c = bits % 61;
        if (c == 0) {
            c = 61;
        }
        if (i < 34) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (3 - c);
            c += 61;
        }
        y = (int)((n >> 59) & 0x1f);
        n <<= 5;
        c -= 5;
        sp_2048_lshift_34(r, norm, (byte)y);
        while ((i >= 0) || (c >= 5)) {
            if (c >= 5) {
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--] << 3;
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c = 56;
            }
            else {
                y = (byte)((n >> 59) & 0x1f);
                n = e[i--] << 3;
                c = 5 - c;
                y |= (byte)((n >> (64 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 61 - c;
            }

            sp_2048_mont_sqr_34(r, r, m, mp);
            sp_2048_mont_sqr_34(r, r, m, mp);
            sp_2048_mont_sqr_34(r, r, m, mp);
            sp_2048_mont_sqr_34(r, r, m, mp);
            sp_2048_mont_sqr_34(r, r, m, mp);

            sp_2048_lshift_34(r, r, (byte)y);
            sp_2048_mul_d_34(tmp, norm, (r[34] << 26) + (r[33] >> 35));
            r[34] = 0;
            r[33] &= 0x7ffffffffL;
            (void)sp_2048_add_34(r, r, tmp);
            sp_2048_norm_34(r);
            o = sp_2048_cmp_34(r, m);
            sp_2048_cond_sub_34(r, r, m, ~(o >> 63));
        }

        sp_2048_mont_reduce_34(r, m, mp);
        n = sp_2048_cmp_34(r, m);
        sp_2048_cond_sub_34(r, r, m, ~(n >> 63));
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
    sp_digit b[34 * 4];
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
        e = b + 34 * 2;
        m = e + 34;
        r = b;

        sp_2048_from_mp(b, 34, base);
        sp_2048_from_bin(e, 34, exp, expLen);
        sp_2048_from_mp(m, 34, mod);

        if (base->used == 1 && base->dp[0] == 2U &&
                (m[33] >> 3) == 0xffffffffL) {
            err = sp_2048_mod_exp_2_34(r, e, expLen * 8U, m);
        }
        else {
            err = sp_2048_mod_exp_34(r, b, e, expLen * 8U, m, 0);
        }
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin_34(r, out);
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
            ForceZero(e, sizeof(sp_digit) * 34U);
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
    sp_digit b[17 * 4];
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
        e = b + 17 * 2;
        m = e + 17;
        r = b;

        sp_2048_from_mp(b, 17, base);
        sp_2048_from_mp(e, 17, exp);
        sp_2048_from_mp(m, 17, mod);

        err = sp_2048_mod_exp_17(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 17, 0, sizeof(*r) * 17U);
        err = sp_2048_to_mp(r, res);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 34U);
    }
    return err;
#else
    sp_digit b[17 * 4];
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
        e = b + 17 * 2;
        m = e + 17;
        r = b;

        sp_2048_from_mp(b, 17, base);
        sp_2048_from_mp(e, 17, exp);
        sp_2048_from_mp(m, 17, mod);

        err = sp_2048_mod_exp_17(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 17, 0, sizeof(*r) * 17U);
        err = sp_2048_to_mp(r, res);
    }


    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 34U);
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
static void sp_2048_from_bin(sp_digit* r, int size, const byte* a, int n)
{
    int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = n-1; i >= 0; i--) {
        r[j] |= (((sp_digit)a[i]) << s);
        if (s >= 49U) {
            r[j] &= 0x1ffffffffffffffL;
            s = 57U - s;
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
#if DIGIT_BIT == 57
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 57
    int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0x1ffffffffffffffL;
        s = 57U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 57U) <= (word32)DIGIT_BIT) {
            s += 57U;
            r[j] &= 0x1ffffffffffffffL;
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
        if (s + DIGIT_BIT >= 57) {
            r[j] &= 0x1ffffffffffffffL;
            if (j + 1 >= size) {
                break;
            }
            s = 57 - s;
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
static void sp_2048_to_bin_36(sp_digit* r, byte* a)
{
    int i;
    int j;
    int s = 0;
    int b;

    for (i=0; i<35; i++) {
        r[i+1] += r[i] >> 57;
        r[i] &= 0x1ffffffffffffffL;
    }
    j = 2055 / 8 - 1;
    a[j] = 0;
    for (i=0; i<36 && j>=0; i++) {
        b = 0;
        /* lint allow cast of mismatch sp_digit and int */
        a[j--] |= (byte)(r[i] << s); /*lint !e9033*/
        b += 8 - s;
        if (j < 0) {
            break;
        }
        while (b < 57) {
            a[j--] = (byte)(r[i] >> b);
            b += 8;
            if (j < 0) {
                break;
            }
        }
        s = 8 - (b - 57);
        if (j >= 0) {
            a[j] = 0;
        }
        if (s != 0) {
            j++;
        }
    }
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* Normalize the values in each word to 57 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_2048_norm_18(sp_digit* a)
{
    int i;
    for (i = 0; i < 16; i += 8) {
        a[i+1] += a[i+0] >> 57; a[i+0] &= 0x1ffffffffffffffL;
        a[i+2] += a[i+1] >> 57; a[i+1] &= 0x1ffffffffffffffL;
        a[i+3] += a[i+2] >> 57; a[i+2] &= 0x1ffffffffffffffL;
        a[i+4] += a[i+3] >> 57; a[i+3] &= 0x1ffffffffffffffL;
        a[i+5] += a[i+4] >> 57; a[i+4] &= 0x1ffffffffffffffL;
        a[i+6] += a[i+5] >> 57; a[i+5] &= 0x1ffffffffffffffL;
        a[i+7] += a[i+6] >> 57; a[i+6] &= 0x1ffffffffffffffL;
        a[i+8] += a[i+7] >> 57; a[i+7] &= 0x1ffffffffffffffL;
    }
    a[17] += a[16] >> 57; a[16] &= 0x1ffffffffffffffL;
}

#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || WOLFSSL_HAVE_SP_DH */
/* Normalize the values in each word to 57 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_2048_norm_36(sp_digit* a)
{
    int i;
    for (i = 0; i < 32; i += 8) {
        a[i+1] += a[i+0] >> 57; a[i+0] &= 0x1ffffffffffffffL;
        a[i+2] += a[i+1] >> 57; a[i+1] &= 0x1ffffffffffffffL;
        a[i+3] += a[i+2] >> 57; a[i+2] &= 0x1ffffffffffffffL;
        a[i+4] += a[i+3] >> 57; a[i+3] &= 0x1ffffffffffffffL;
        a[i+5] += a[i+4] >> 57; a[i+4] &= 0x1ffffffffffffffL;
        a[i+6] += a[i+5] >> 57; a[i+5] &= 0x1ffffffffffffffL;
        a[i+7] += a[i+6] >> 57; a[i+6] &= 0x1ffffffffffffffL;
        a[i+8] += a[i+7] >> 57; a[i+7] &= 0x1ffffffffffffffL;
    }
    a[33] += a[32] >> 57; a[32] &= 0x1ffffffffffffffL;
    a[34] += a[33] >> 57; a[33] &= 0x1ffffffffffffffL;
    a[35] += a[34] >> 57; a[34] &= 0x1ffffffffffffffL;
}

#ifndef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_9(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_uint128 t0   = ((sp_uint128)a[ 0]) * b[ 0];
    sp_uint128 t1   = ((sp_uint128)a[ 0]) * b[ 1]
                 + ((sp_uint128)a[ 1]) * b[ 0];
    sp_uint128 t2   = ((sp_uint128)a[ 0]) * b[ 2]
                 + ((sp_uint128)a[ 1]) * b[ 1]
                 + ((sp_uint128)a[ 2]) * b[ 0];
    sp_uint128 t3   = ((sp_uint128)a[ 0]) * b[ 3]
                 + ((sp_uint128)a[ 1]) * b[ 2]
                 + ((sp_uint128)a[ 2]) * b[ 1]
                 + ((sp_uint128)a[ 3]) * b[ 0];
    sp_uint128 t4   = ((sp_uint128)a[ 0]) * b[ 4]
                 + ((sp_uint128)a[ 1]) * b[ 3]
                 + ((sp_uint128)a[ 2]) * b[ 2]
                 + ((sp_uint128)a[ 3]) * b[ 1]
                 + ((sp_uint128)a[ 4]) * b[ 0];
    sp_uint128 t5   = ((sp_uint128)a[ 0]) * b[ 5]
                 + ((sp_uint128)a[ 1]) * b[ 4]
                 + ((sp_uint128)a[ 2]) * b[ 3]
                 + ((sp_uint128)a[ 3]) * b[ 2]
                 + ((sp_uint128)a[ 4]) * b[ 1]
                 + ((sp_uint128)a[ 5]) * b[ 0];
    sp_uint128 t6   = ((sp_uint128)a[ 0]) * b[ 6]
                 + ((sp_uint128)a[ 1]) * b[ 5]
                 + ((sp_uint128)a[ 2]) * b[ 4]
                 + ((sp_uint128)a[ 3]) * b[ 3]
                 + ((sp_uint128)a[ 4]) * b[ 2]
                 + ((sp_uint128)a[ 5]) * b[ 1]
                 + ((sp_uint128)a[ 6]) * b[ 0];
    sp_uint128 t7   = ((sp_uint128)a[ 0]) * b[ 7]
                 + ((sp_uint128)a[ 1]) * b[ 6]
                 + ((sp_uint128)a[ 2]) * b[ 5]
                 + ((sp_uint128)a[ 3]) * b[ 4]
                 + ((sp_uint128)a[ 4]) * b[ 3]
                 + ((sp_uint128)a[ 5]) * b[ 2]
                 + ((sp_uint128)a[ 6]) * b[ 1]
                 + ((sp_uint128)a[ 7]) * b[ 0];
    sp_uint128 t8   = ((sp_uint128)a[ 0]) * b[ 8]
                 + ((sp_uint128)a[ 1]) * b[ 7]
                 + ((sp_uint128)a[ 2]) * b[ 6]
                 + ((sp_uint128)a[ 3]) * b[ 5]
                 + ((sp_uint128)a[ 4]) * b[ 4]
                 + ((sp_uint128)a[ 5]) * b[ 3]
                 + ((sp_uint128)a[ 6]) * b[ 2]
                 + ((sp_uint128)a[ 7]) * b[ 1]
                 + ((sp_uint128)a[ 8]) * b[ 0];
    sp_uint128 t9   = ((sp_uint128)a[ 1]) * b[ 8]
                 + ((sp_uint128)a[ 2]) * b[ 7]
                 + ((sp_uint128)a[ 3]) * b[ 6]
                 + ((sp_uint128)a[ 4]) * b[ 5]
                 + ((sp_uint128)a[ 5]) * b[ 4]
                 + ((sp_uint128)a[ 6]) * b[ 3]
                 + ((sp_uint128)a[ 7]) * b[ 2]
                 + ((sp_uint128)a[ 8]) * b[ 1];
    sp_uint128 t10  = ((sp_uint128)a[ 2]) * b[ 8]
                 + ((sp_uint128)a[ 3]) * b[ 7]
                 + ((sp_uint128)a[ 4]) * b[ 6]
                 + ((sp_uint128)a[ 5]) * b[ 5]
                 + ((sp_uint128)a[ 6]) * b[ 4]
                 + ((sp_uint128)a[ 7]) * b[ 3]
                 + ((sp_uint128)a[ 8]) * b[ 2];
    sp_uint128 t11  = ((sp_uint128)a[ 3]) * b[ 8]
                 + ((sp_uint128)a[ 4]) * b[ 7]
                 + ((sp_uint128)a[ 5]) * b[ 6]
                 + ((sp_uint128)a[ 6]) * b[ 5]
                 + ((sp_uint128)a[ 7]) * b[ 4]
                 + ((sp_uint128)a[ 8]) * b[ 3];
    sp_uint128 t12  = ((sp_uint128)a[ 4]) * b[ 8]
                 + ((sp_uint128)a[ 5]) * b[ 7]
                 + ((sp_uint128)a[ 6]) * b[ 6]
                 + ((sp_uint128)a[ 7]) * b[ 5]
                 + ((sp_uint128)a[ 8]) * b[ 4];
    sp_uint128 t13  = ((sp_uint128)a[ 5]) * b[ 8]
                 + ((sp_uint128)a[ 6]) * b[ 7]
                 + ((sp_uint128)a[ 7]) * b[ 6]
                 + ((sp_uint128)a[ 8]) * b[ 5];
    sp_uint128 t14  = ((sp_uint128)a[ 6]) * b[ 8]
                 + ((sp_uint128)a[ 7]) * b[ 7]
                 + ((sp_uint128)a[ 8]) * b[ 6];
    sp_uint128 t15  = ((sp_uint128)a[ 7]) * b[ 8]
                 + ((sp_uint128)a[ 8]) * b[ 7];
    sp_uint128 t16  = ((sp_uint128)a[ 8]) * b[ 8];

    t1   += t0  >> 57; r[ 0] = t0  & 0x1ffffffffffffffL;
    t2   += t1  >> 57; r[ 1] = t1  & 0x1ffffffffffffffL;
    t3   += t2  >> 57; r[ 2] = t2  & 0x1ffffffffffffffL;
    t4   += t3  >> 57; r[ 3] = t3  & 0x1ffffffffffffffL;
    t5   += t4  >> 57; r[ 4] = t4  & 0x1ffffffffffffffL;
    t6   += t5  >> 57; r[ 5] = t5  & 0x1ffffffffffffffL;
    t7   += t6  >> 57; r[ 6] = t6  & 0x1ffffffffffffffL;
    t8   += t7  >> 57; r[ 7] = t7  & 0x1ffffffffffffffL;
    t9   += t8  >> 57; r[ 8] = t8  & 0x1ffffffffffffffL;
    t10  += t9  >> 57; r[ 9] = t9  & 0x1ffffffffffffffL;
    t11  += t10 >> 57; r[10] = t10 & 0x1ffffffffffffffL;
    t12  += t11 >> 57; r[11] = t11 & 0x1ffffffffffffffL;
    t13  += t12 >> 57; r[12] = t12 & 0x1ffffffffffffffL;
    t14  += t13 >> 57; r[13] = t13 & 0x1ffffffffffffffL;
    t15  += t14 >> 57; r[14] = t14 & 0x1ffffffffffffffL;
    t16  += t15 >> 57; r[15] = t15 & 0x1ffffffffffffffL;
    r[17] = (sp_digit)(t16 >> 57);
                       r[16] = t16 & 0x1ffffffffffffffL;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_9(sp_digit* r, const sp_digit* a,
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

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_18(sp_digit* r, const sp_digit* a,
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

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_sub_18(sp_digit* r, const sp_digit* a,
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

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_18(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[18];
    sp_digit* a1 = z1;
    sp_digit b1[9];
    sp_digit* z2 = r + 18;
    (void)sp_2048_add_9(a1, a, &a[9]);
    (void)sp_2048_add_9(b1, b, &b[9]);
    sp_2048_mul_9(z2, &a[9], &b[9]);
    sp_2048_mul_9(z0, a, b);
    sp_2048_mul_9(z1, a1, b1);
    (void)sp_2048_sub_18(z1, z1, z2);
    (void)sp_2048_sub_18(z1, z1, z0);
    (void)sp_2048_add_18(r + 9, r + 9, z1);
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

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_36(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[36];
    sp_digit* a1 = z1;
    sp_digit b1[18];
    sp_digit* z2 = r + 36;
    (void)sp_2048_add_18(a1, a, &a[18]);
    (void)sp_2048_add_18(b1, b, &b[18]);
    sp_2048_mul_18(z2, &a[18], &b[18]);
    sp_2048_mul_18(z0, a, b);
    sp_2048_mul_18(z1, a1, b1);
    (void)sp_2048_sub_36(z1, z1, z2);
    (void)sp_2048_sub_36(z1, z1, z0);
    (void)sp_2048_add_36(r + 18, r + 18, z1);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_9(sp_digit* r, const sp_digit* a)
{
    sp_uint128 t0   =  ((sp_uint128)a[ 0]) * a[ 0];
    sp_uint128 t1   = (((sp_uint128)a[ 0]) * a[ 1]) * 2;
    sp_uint128 t2   = (((sp_uint128)a[ 0]) * a[ 2]) * 2
                 +  ((sp_uint128)a[ 1]) * a[ 1];
    sp_uint128 t3   = (((sp_uint128)a[ 0]) * a[ 3]
                 +  ((sp_uint128)a[ 1]) * a[ 2]) * 2;
    sp_uint128 t4   = (((sp_uint128)a[ 0]) * a[ 4]
                 +  ((sp_uint128)a[ 1]) * a[ 3]) * 2
                 +  ((sp_uint128)a[ 2]) * a[ 2];
    sp_uint128 t5   = (((sp_uint128)a[ 0]) * a[ 5]
                 +  ((sp_uint128)a[ 1]) * a[ 4]
                 +  ((sp_uint128)a[ 2]) * a[ 3]) * 2;
    sp_uint128 t6   = (((sp_uint128)a[ 0]) * a[ 6]
                 +  ((sp_uint128)a[ 1]) * a[ 5]
                 +  ((sp_uint128)a[ 2]) * a[ 4]) * 2
                 +  ((sp_uint128)a[ 3]) * a[ 3];
    sp_uint128 t7   = (((sp_uint128)a[ 0]) * a[ 7]
                 +  ((sp_uint128)a[ 1]) * a[ 6]
                 +  ((sp_uint128)a[ 2]) * a[ 5]
                 +  ((sp_uint128)a[ 3]) * a[ 4]) * 2;
    sp_uint128 t8   = (((sp_uint128)a[ 0]) * a[ 8]
                 +  ((sp_uint128)a[ 1]) * a[ 7]
                 +  ((sp_uint128)a[ 2]) * a[ 6]
                 +  ((sp_uint128)a[ 3]) * a[ 5]) * 2
                 +  ((sp_uint128)a[ 4]) * a[ 4];
    sp_uint128 t9   = (((sp_uint128)a[ 1]) * a[ 8]
                 +  ((sp_uint128)a[ 2]) * a[ 7]
                 +  ((sp_uint128)a[ 3]) * a[ 6]
                 +  ((sp_uint128)a[ 4]) * a[ 5]) * 2;
    sp_uint128 t10  = (((sp_uint128)a[ 2]) * a[ 8]
                 +  ((sp_uint128)a[ 3]) * a[ 7]
                 +  ((sp_uint128)a[ 4]) * a[ 6]) * 2
                 +  ((sp_uint128)a[ 5]) * a[ 5];
    sp_uint128 t11  = (((sp_uint128)a[ 3]) * a[ 8]
                 +  ((sp_uint128)a[ 4]) * a[ 7]
                 +  ((sp_uint128)a[ 5]) * a[ 6]) * 2;
    sp_uint128 t12  = (((sp_uint128)a[ 4]) * a[ 8]
                 +  ((sp_uint128)a[ 5]) * a[ 7]) * 2
                 +  ((sp_uint128)a[ 6]) * a[ 6];
    sp_uint128 t13  = (((sp_uint128)a[ 5]) * a[ 8]
                 +  ((sp_uint128)a[ 6]) * a[ 7]) * 2;
    sp_uint128 t14  = (((sp_uint128)a[ 6]) * a[ 8]) * 2
                 +  ((sp_uint128)a[ 7]) * a[ 7];
    sp_uint128 t15  = (((sp_uint128)a[ 7]) * a[ 8]) * 2;
    sp_uint128 t16  =  ((sp_uint128)a[ 8]) * a[ 8];

    t1   += t0  >> 57; r[ 0] = t0  & 0x1ffffffffffffffL;
    t2   += t1  >> 57; r[ 1] = t1  & 0x1ffffffffffffffL;
    t3   += t2  >> 57; r[ 2] = t2  & 0x1ffffffffffffffL;
    t4   += t3  >> 57; r[ 3] = t3  & 0x1ffffffffffffffL;
    t5   += t4  >> 57; r[ 4] = t4  & 0x1ffffffffffffffL;
    t6   += t5  >> 57; r[ 5] = t5  & 0x1ffffffffffffffL;
    t7   += t6  >> 57; r[ 6] = t6  & 0x1ffffffffffffffL;
    t8   += t7  >> 57; r[ 7] = t7  & 0x1ffffffffffffffL;
    t9   += t8  >> 57; r[ 8] = t8  & 0x1ffffffffffffffL;
    t10  += t9  >> 57; r[ 9] = t9  & 0x1ffffffffffffffL;
    t11  += t10 >> 57; r[10] = t10 & 0x1ffffffffffffffL;
    t12  += t11 >> 57; r[11] = t11 & 0x1ffffffffffffffL;
    t13  += t12 >> 57; r[12] = t12 & 0x1ffffffffffffffL;
    t14  += t13 >> 57; r[13] = t13 & 0x1ffffffffffffffL;
    t15  += t14 >> 57; r[14] = t14 & 0x1ffffffffffffffL;
    t16  += t15 >> 57; r[15] = t15 & 0x1ffffffffffffffL;
    r[17] = (sp_digit)(t16 >> 57);
                       r[16] = t16 & 0x1ffffffffffffffL;
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_18(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit z1[18];
    sp_digit* a1 = z1;
    sp_digit* z2 = r + 18;
    (void)sp_2048_add_9(a1, a, &a[9]);
    sp_2048_sqr_9(z2, &a[9]);
    sp_2048_sqr_9(z0, a);
    sp_2048_sqr_9(z1, a1);
    (void)sp_2048_sub_18(z1, z1, z2);
    (void)sp_2048_sub_18(z1, z1, z0);
    (void)sp_2048_add_18(r + 9, r + 9, z1);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_36(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit z1[36];
    sp_digit* a1 = z1;
    sp_digit* z2 = r + 36;
    (void)sp_2048_add_18(a1, a, &a[18]);
    sp_2048_sqr_18(z2, &a[18]);
    sp_2048_sqr_18(z0, a);
    sp_2048_sqr_18(z1, a1);
    (void)sp_2048_sub_36(z1, z1, z2);
    (void)sp_2048_sub_36(z1, z1, z0);
    (void)sp_2048_add_36(r + 18, r + 18, z1);
}

#endif /* !WOLFSSL_SP_SMALL */
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
    x &= 0x1ffffffffffffffL;

    /* rho = -1/m mod b */
    *rho = ((sp_digit)1 << 57) - x;
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
    sp_int128 tb = b;
    sp_int128 t = 0;
    sp_digit t2;
    sp_int128 p[4];
    int i;

    for (i = 0; i < 36; i += 4) {
        p[0] = tb * a[i + 0];
        p[1] = tb * a[i + 1];
        p[2] = tb * a[i + 2];
        p[3] = tb * a[i + 3];
        t += p[0];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 0] = (sp_digit)t2;
        t += p[1];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 1] = (sp_digit)t2;
        t += p[2];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 2] = (sp_digit)t2;
        t += p[3];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 3] = (sp_digit)t2;
    }
    r[36] = (sp_digit)(t & 0x1ffffffffffffffL);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 2048 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_2048_mont_norm_18(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
    int i;

    for (i = 0; i < 16; i += 8) {
        r[i + 0] = 0x1ffffffffffffffL;
        r[i + 1] = 0x1ffffffffffffffL;
        r[i + 2] = 0x1ffffffffffffffL;
        r[i + 3] = 0x1ffffffffffffffL;
        r[i + 4] = 0x1ffffffffffffffL;
        r[i + 5] = 0x1ffffffffffffffL;
        r[i + 6] = 0x1ffffffffffffffL;
        r[i + 7] = 0x1ffffffffffffffL;
    }
    r[16] = 0x1ffffffffffffffL;
    r[17] = 0x7fffffffffffffL;

    /* r = (2^n - 1) mod n */
    (void)sp_2048_sub_18(r, r, m);

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
static sp_digit sp_2048_cmp_18(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
    int i;

    r |= (a[17] - b[17]) & (0 - (sp_digit)1);
    r |= (a[16] - b[16]) & ~(((sp_digit)0 - r) >> 56);
    for (i = 8; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 6] - b[i + 6]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 5] - b[i + 5]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 4] - b[i + 4]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 3] - b[i + 3]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 2] - b[i + 2]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 1] - b[i + 1]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 0] - b[i + 0]) & ~(((sp_digit)0 - r) >> 56);
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
static void sp_2048_cond_sub_18(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 16; i += 8) {
        r[i + 0] = a[i + 0] - (b[i + 0] & m);
        r[i + 1] = a[i + 1] - (b[i + 1] & m);
        r[i + 2] = a[i + 2] - (b[i + 2] & m);
        r[i + 3] = a[i + 3] - (b[i + 3] & m);
        r[i + 4] = a[i + 4] - (b[i + 4] & m);
        r[i + 5] = a[i + 5] - (b[i + 5] & m);
        r[i + 6] = a[i + 6] - (b[i + 6] & m);
        r[i + 7] = a[i + 7] - (b[i + 7] & m);
    }
    r[16] = a[16] - (b[16] & m);
    r[17] = a[17] - (b[17] & m);
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_add_18(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t[8];
    int i;

    t[0] = tb * a[0]; r[0] += (sp_digit)(t[0] & 0x1ffffffffffffffL);
    for (i = 0; i < 16; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] += (sp_digit)((t[0] >> 57) + (t[1] & 0x1ffffffffffffffL));
        t[2] = tb * a[i+2];
        r[i+2] += (sp_digit)((t[1] >> 57) + (t[2] & 0x1ffffffffffffffL));
        t[3] = tb * a[i+3];
        r[i+3] += (sp_digit)((t[2] >> 57) + (t[3] & 0x1ffffffffffffffL));
        t[4] = tb * a[i+4];
        r[i+4] += (sp_digit)((t[3] >> 57) + (t[4] & 0x1ffffffffffffffL));
        t[5] = tb * a[i+5];
        r[i+5] += (sp_digit)((t[4] >> 57) + (t[5] & 0x1ffffffffffffffL));
        t[6] = tb * a[i+6];
        r[i+6] += (sp_digit)((t[5] >> 57) + (t[6] & 0x1ffffffffffffffL));
        t[7] = tb * a[i+7];
        r[i+7] += (sp_digit)((t[6] >> 57) + (t[7] & 0x1ffffffffffffffL));
        t[0] = tb * a[i+8];
        r[i+8] += (sp_digit)((t[7] >> 57) + (t[0] & 0x1ffffffffffffffL));
    }
    t[1] = tb * a[17];
    r[17] += (sp_digit)((t[0] >> 57) + (t[1] & 0x1ffffffffffffffL));
    r[18] +=  (sp_digit)(t[1] >> 57);
}

/* Shift the result in the high 1024 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_2048_mont_shift_18(sp_digit* r, const sp_digit* a)
{
    sp_uint64 n;
    int i;

    n  = (sp_uint64)a[17];
    n  = n >> 55U;
    for (i = 0; i < 16; i += 8) {
        n += (sp_uint64)a[i+18] << 2U; r[i+0] = n & 0x1ffffffffffffffUL; n >>= 57U;
        n += (sp_uint64)a[i+19] << 2U; r[i+1] = n & 0x1ffffffffffffffUL; n >>= 57U;
        n += (sp_uint64)a[i+20] << 2U; r[i+2] = n & 0x1ffffffffffffffUL; n >>= 57U;
        n += (sp_uint64)a[i+21] << 2U; r[i+3] = n & 0x1ffffffffffffffUL; n >>= 57U;
        n += (sp_uint64)a[i+22] << 2U; r[i+4] = n & 0x1ffffffffffffffUL; n >>= 57U;
        n += (sp_uint64)a[i+23] << 2U; r[i+5] = n & 0x1ffffffffffffffUL; n >>= 57U;
        n += (sp_uint64)a[i+24] << 2U; r[i+6] = n & 0x1ffffffffffffffUL; n >>= 57U;
        n += (sp_uint64)a[i+25] << 2U; r[i+7] = n & 0x1ffffffffffffffUL; n >>= 57U;
    }
    n += (sp_uint64)a[34] << 2U; r[16] = n & 0x1ffffffffffffffUL; n >>= 57U;
    n += (sp_uint64)a[35] << 2U; r[17] = n;
    XMEMSET(&r[18], 0, sizeof(*r) * 18U);
}

/* Reduce the number back to 2048 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_2048_mont_reduce_18(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_2048_norm_18(a + 18);

    for (i=0; i<17; i++) {
        mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x1ffffffffffffffL;
        sp_2048_mul_add_18(a+i, m, mu);
        a[i+1] += a[i] >> 57;
    }
    mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x7fffffffffffffL;
    sp_2048_mul_add_18(a+i, m, mu);
    a[i+1] += a[i] >> 57;
    a[i] &= 0x1ffffffffffffffL;
    sp_2048_mont_shift_18(a, a);
    over = a[17] - m[17];
    sp_2048_cond_sub_18(a, a, m, ~((over - 1) >> 63));
    sp_2048_norm_18(a);
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
SP_NOINLINE static void sp_2048_mont_mul_18(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_2048_mul_18(r, a, b);
    sp_2048_mont_reduce_18(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_2048_mont_sqr_18(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_2048_sqr_18(r, a);
    sp_2048_mont_reduce_18(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_d_18(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t = 0;
    sp_digit t2;
    sp_int128 p[4];
    int i;

    for (i = 0; i < 16; i += 4) {
        p[0] = tb * a[i + 0];
        p[1] = tb * a[i + 1];
        p[2] = tb * a[i + 2];
        p[3] = tb * a[i + 3];
        t += p[0];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 0] = (sp_digit)t2;
        t += p[1];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 1] = (sp_digit)t2;
        t += p[2];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 2] = (sp_digit)t2;
        t += p[3];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 3] = (sp_digit)t2;
    }
    t += tb * a[16];
    r[16] = (sp_digit)(t & 0x1ffffffffffffffL);
    t >>= 57;
    t += tb * a[17];
    r[17] = (sp_digit)(t & 0x1ffffffffffffffL);
    t >>= 57;
    r[18] = (sp_digit)(t & 0x1ffffffffffffffL);
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
static void sp_2048_cond_add_18(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 16; i += 8) {
        r[i + 0] = a[i + 0] + (b[i + 0] & m);
        r[i + 1] = a[i + 1] + (b[i + 1] & m);
        r[i + 2] = a[i + 2] + (b[i + 2] & m);
        r[i + 3] = a[i + 3] + (b[i + 3] & m);
        r[i + 4] = a[i + 4] + (b[i + 4] & m);
        r[i + 5] = a[i + 5] + (b[i + 5] & m);
        r[i + 6] = a[i + 6] + (b[i + 6] & m);
        r[i + 7] = a[i + 7] + (b[i + 7] & m);
    }
    r[16] = a[16] + (b[16] & m);
    r[17] = a[17] + (b[17] & m);
}
#endif /* !WOLFSSL_SP_SMALL */

SP_NOINLINE static void sp_2048_rshift_18(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    for (i=0; i<16; i += 8) {
        r[i+0] = (a[i+0] >> n) | ((a[i+1] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+1] = (a[i+1] >> n) | ((a[i+2] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+2] = (a[i+2] >> n) | ((a[i+3] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+3] = (a[i+3] >> n) | ((a[i+4] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+4] = (a[i+4] >> n) | ((a[i+5] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+5] = (a[i+5] >> n) | ((a[i+6] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+6] = (a[i+6] >> n) | ((a[i+7] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+7] = (a[i+7] >> n) | ((a[i+8] << (57 - n)) & 0x1ffffffffffffffL);
    }
    r[16] = (a[16] >> n) | ((a[17] << (57 - n)) & 0x1ffffffffffffffL);
    r[17] = a[17] >> n;
}

static WC_INLINE sp_digit sp_2048_div_word_18(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int128 d = ((sp_int128)d1 << 57) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int128 d = ((sp_int128)d1 << 57) + d0;
    sp_uint64 lo = (sp_uint64)d;
    sp_digit hi = (sp_digit)(d >> 64);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int128 d = ((sp_int128)d1 << 57) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 57);
    sp_digit t0 = (sp_digit)(d & 0x1ffffffffffffffL);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int128 m;

    r = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
    t1 -= dv & (0 - r);
    for (i = 55; i >= 1; i--) {
        t1 += t1 + (((sp_uint64)t0 >> 56) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int128)r * div);
    r += (sp_digit)(m >> 57);
    m = d - ((sp_int128)r * div);
    r += (m >> 114) - (sp_digit)(d >> 114);

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;
   return r;
#else
    sp_int128 d = ((sp_int128)d1 << 57) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 26) + 1;

    t = (sp_digit)(d >> 52);
    t = (t / dv) << 26;
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)(d >> 21);
    t = t / (dv << 5);
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int128)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_2048_word_div_word_18(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint64)(div - d) >> 63);
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
static int sp_2048_div_18(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_64
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 18 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 36 + 1;
        sd = t2 + 18 + 1;

        sp_2048_mul_d_18(sd, d, (sp_digit)1 << 2);
        sp_2048_mul_d_36(t1, a, (sp_digit)1 << 2);
        dv = sd[17];
        t1[18 + 18] += t1[18 + 18 - 1] >> 57;
        t1[18 + 18 - 1] &= 0x1ffffffffffffffL;
        for (i=18; i>=0; i--) {
            r1 = sp_2048_div_word_18(t1[18 + i], t1[18 + i - 1], dv);

            sp_2048_mul_d_18(t2, sd, r1);
            (void)sp_2048_sub_18(&t1[i], &t1[i], t2);
            sp_2048_norm_18(&t1[i]);
            t1[18 + i] -= t2[18];
            t1[18 + i] += t1[18 + i - 1] >> 57;
            t1[18 + i - 1] &= 0x1ffffffffffffffL;
            r1 = sp_2048_div_word_18(-t1[18 + i], -t1[18 + i - 1], dv);
            r1 -= t1[18 + i];
            sp_2048_mul_d_18(t2, sd, r1);
            (void)sp_2048_add_18(&t1[i], &t1[i], t2);
            t1[18 + i] += t1[18 + i - 1] >> 57;
            t1[18 + i - 1] &= 0x1ffffffffffffffL;
        }
        t1[18 - 1] += t1[18 - 2] >> 57;
        t1[18 - 2] &= 0x1ffffffffffffffL;
        r1 = sp_2048_word_div_word_18(t1[18 - 1], dv);

        sp_2048_mul_d_18(t2, sd, r1);
        sp_2048_sub_18(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 36U);
        for (i=0; i<17; i++) {
            r[i+1] += r[i] >> 57;
            r[i] &= 0x1ffffffffffffffL;
        }
        sp_2048_cond_add_18(r, r, sd, r[17] >> 63);

        sp_2048_norm_18(r);
        sp_2048_rshift_18(r, r, 2);
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
static int sp_2048_mod_18(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_2048_div_18(a, m, NULL, r);
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
static int sp_2048_mod_exp_18(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 36];
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
            t[i] = td + (i * 18 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 18U * 2U);
        }

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_18(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_18(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 18U);
        }
    }
    if (err == MP_OKAY) {
        sp_2048_mul_18(t[1], t[1], norm);
        err = sp_2048_mod_18(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 57;
        c = bits % 57;
        n = e[i--] << (57 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 57;
            }

            y = (int)((n >> 56) & 1);
            n <<= 1;

            sp_2048_mont_mul_18(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 18 * 2);
            sp_2048_mont_sqr_18(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 18 * 2);
        }

        sp_2048_mont_reduce_18(t[0], m, mp);
        n = sp_2048_cmp_18(t[0], m);
        sp_2048_cond_sub_18(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 18 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 36];
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
            t[i] = td + (i * 18 * 2);
        }

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_18(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_18(t[1], a, m);
            if (err == MP_OKAY) {
                sp_2048_mul_18(t[1], t[1], norm);
                err = sp_2048_mod_18(t[1], t[1], m);
            }
        }
        else {
            sp_2048_mul_18(t[1], a, norm);
            err = sp_2048_mod_18(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 57;
        c = bits % 57;
        n = e[i--] << (57 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 57;
            }

            y = (int)((n >> 56) & 1);
            n <<= 1;

            sp_2048_mont_mul_18(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 18 * 2);
            sp_2048_mont_sqr_18(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 18 * 2);
        }

        sp_2048_mont_reduce_18(t[0], m, mp);
        n = sp_2048_cmp_18(t[0], m);
        sp_2048_cond_sub_18(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 18 * 2);
    }


    return err;
#else
    sp_digit td[(32 * 36) + 36];
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
            t[i] = td + i * 36;
        rt = td + 1152;

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_18(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_18(t[1], a, m);
            if (err == MP_OKAY) {
                sp_2048_mul_18(t[1], t[1], norm);
                err = sp_2048_mod_18(t[1], t[1], m);
            }
        }
        else {
            sp_2048_mul_18(t[1], a, norm);
            err = sp_2048_mod_18(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_2048_mont_sqr_18(t[ 2], t[ 1], m, mp);
        sp_2048_mont_mul_18(t[ 3], t[ 2], t[ 1], m, mp);
        sp_2048_mont_sqr_18(t[ 4], t[ 2], m, mp);
        sp_2048_mont_mul_18(t[ 5], t[ 3], t[ 2], m, mp);
        sp_2048_mont_sqr_18(t[ 6], t[ 3], m, mp);
        sp_2048_mont_mul_18(t[ 7], t[ 4], t[ 3], m, mp);
        sp_2048_mont_sqr_18(t[ 8], t[ 4], m, mp);
        sp_2048_mont_mul_18(t[ 9], t[ 5], t[ 4], m, mp);
        sp_2048_mont_sqr_18(t[10], t[ 5], m, mp);
        sp_2048_mont_mul_18(t[11], t[ 6], t[ 5], m, mp);
        sp_2048_mont_sqr_18(t[12], t[ 6], m, mp);
        sp_2048_mont_mul_18(t[13], t[ 7], t[ 6], m, mp);
        sp_2048_mont_sqr_18(t[14], t[ 7], m, mp);
        sp_2048_mont_mul_18(t[15], t[ 8], t[ 7], m, mp);
        sp_2048_mont_sqr_18(t[16], t[ 8], m, mp);
        sp_2048_mont_mul_18(t[17], t[ 9], t[ 8], m, mp);
        sp_2048_mont_sqr_18(t[18], t[ 9], m, mp);
        sp_2048_mont_mul_18(t[19], t[10], t[ 9], m, mp);
        sp_2048_mont_sqr_18(t[20], t[10], m, mp);
        sp_2048_mont_mul_18(t[21], t[11], t[10], m, mp);
        sp_2048_mont_sqr_18(t[22], t[11], m, mp);
        sp_2048_mont_mul_18(t[23], t[12], t[11], m, mp);
        sp_2048_mont_sqr_18(t[24], t[12], m, mp);
        sp_2048_mont_mul_18(t[25], t[13], t[12], m, mp);
        sp_2048_mont_sqr_18(t[26], t[13], m, mp);
        sp_2048_mont_mul_18(t[27], t[14], t[13], m, mp);
        sp_2048_mont_sqr_18(t[28], t[14], m, mp);
        sp_2048_mont_mul_18(t[29], t[15], t[14], m, mp);
        sp_2048_mont_sqr_18(t[30], t[15], m, mp);
        sp_2048_mont_mul_18(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 56) / 57) - 1;
        c = bits % 57;
        if (c == 0) {
            c = 57;
        }
        if (i < 18) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (7 - c);
            c += 57;
        }
        y = (int)((n >> 59) & 0x1f);
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 36);
        while ((i >= 0) || (c >= 5)) {
            if (c >= 5) {
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--] << 7;
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c = 52;
            }
            else {
                y = (byte)((n >> 59) & 0x1f);
                n = e[i--] << 7;
                c = 5 - c;
                y |= (byte)((n >> (64 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 57 - c;
            }

            sp_2048_mont_sqr_18(rt, rt, m, mp);
            sp_2048_mont_sqr_18(rt, rt, m, mp);
            sp_2048_mont_sqr_18(rt, rt, m, mp);
            sp_2048_mont_sqr_18(rt, rt, m, mp);
            sp_2048_mont_sqr_18(rt, rt, m, mp);

            sp_2048_mont_mul_18(rt, rt, t[y], m, mp);
        }

        sp_2048_mont_reduce_18(rt, m, mp);
        n = sp_2048_cmp_18(rt, m);
        sp_2048_cond_sub_18(rt, rt, m, ~(n >> 63));
        XMEMCPY(r, rt, sizeof(sp_digit) * 36);
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
static void sp_2048_mont_norm_36(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i + 0] = 0x1ffffffffffffffL;
        r[i + 1] = 0x1ffffffffffffffL;
        r[i + 2] = 0x1ffffffffffffffL;
        r[i + 3] = 0x1ffffffffffffffL;
        r[i + 4] = 0x1ffffffffffffffL;
        r[i + 5] = 0x1ffffffffffffffL;
        r[i + 6] = 0x1ffffffffffffffL;
        r[i + 7] = 0x1ffffffffffffffL;
    }
    r[32] = 0x1ffffffffffffffL;
    r[33] = 0x1ffffffffffffffL;
    r[34] = 0x1ffffffffffffffL;
    r[35] = 0x1fffffffffffffL;

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
    int i;

    r |= (a[35] - b[35]) & (0 - (sp_digit)1);
    r |= (a[34] - b[34]) & ~(((sp_digit)0 - r) >> 56);
    r |= (a[33] - b[33]) & ~(((sp_digit)0 - r) >> 56);
    r |= (a[32] - b[32]) & ~(((sp_digit)0 - r) >> 56);
    for (i = 24; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 6] - b[i + 6]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 5] - b[i + 5]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 4] - b[i + 4]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 3] - b[i + 3]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 2] - b[i + 2]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 1] - b[i + 1]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 0] - b[i + 0]) & ~(((sp_digit)0 - r) >> 56);
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
static void sp_2048_cond_sub_36(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
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
    sp_int128 tb = b;
    sp_int128 t[8];
    int i;

    t[0] = tb * a[0]; r[0] += (sp_digit)(t[0] & 0x1ffffffffffffffL);
    for (i = 0; i < 32; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] += (sp_digit)((t[0] >> 57) + (t[1] & 0x1ffffffffffffffL));
        t[2] = tb * a[i+2];
        r[i+2] += (sp_digit)((t[1] >> 57) + (t[2] & 0x1ffffffffffffffL));
        t[3] = tb * a[i+3];
        r[i+3] += (sp_digit)((t[2] >> 57) + (t[3] & 0x1ffffffffffffffL));
        t[4] = tb * a[i+4];
        r[i+4] += (sp_digit)((t[3] >> 57) + (t[4] & 0x1ffffffffffffffL));
        t[5] = tb * a[i+5];
        r[i+5] += (sp_digit)((t[4] >> 57) + (t[5] & 0x1ffffffffffffffL));
        t[6] = tb * a[i+6];
        r[i+6] += (sp_digit)((t[5] >> 57) + (t[6] & 0x1ffffffffffffffL));
        t[7] = tb * a[i+7];
        r[i+7] += (sp_digit)((t[6] >> 57) + (t[7] & 0x1ffffffffffffffL));
        t[0] = tb * a[i+8];
        r[i+8] += (sp_digit)((t[7] >> 57) + (t[0] & 0x1ffffffffffffffL));
    }
    t[1] = tb * a[33];
    r[33] += (sp_digit)((t[0] >> 57) + (t[1] & 0x1ffffffffffffffL));
    t[2] = tb * a[34];
    r[34] += (sp_digit)((t[1] >> 57) + (t[2] & 0x1ffffffffffffffL));
    t[3] = tb * a[35];
    r[35] += (sp_digit)((t[2] >> 57) + (t[3] & 0x1ffffffffffffffL));
    r[36] +=  (sp_digit)(t[3] >> 57);
}

/* Shift the result in the high 2048 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_2048_mont_shift_36(sp_digit* r, const sp_digit* a)
{
    sp_digit n;
    sp_digit s;
    int i;

    s = a[36]; n = a[35] >> 53;
    for (i = 0; i < 32; i += 8) {
        n += (s & 0x1ffffffffffffffL) << 4; r[i+0] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+37] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 4; r[i+1] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+38] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 4; r[i+2] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+39] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 4; r[i+3] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+40] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 4; r[i+4] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+41] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 4; r[i+5] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+42] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 4; r[i+6] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+43] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 4; r[i+7] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+44] + (s >> 57);
    }
    n += (s & 0x1ffffffffffffffL) << 4; r[32] = n & 0x1ffffffffffffffL;
    n >>= 57; s = a[69] + (s >> 57);
    n += (s & 0x1ffffffffffffffL) << 4; r[33] = n & 0x1ffffffffffffffL;
    n >>= 57; s = a[70] + (s >> 57);
    n += (s & 0x1ffffffffffffffL) << 4; r[34] = n & 0x1ffffffffffffffL;
    n >>= 57; s = a[71] + (s >> 57);
    n += s << 4;              r[35] = n;
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

#ifdef WOLFSSL_SP_DH
    if (mp != 1) {
        for (i=0; i<35; i++) {
            mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x1ffffffffffffffL;
            sp_2048_mul_add_36(a+i, m, mu);
            a[i+1] += a[i] >> 57;
        }
        mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x1fffffffffffffL;
        sp_2048_mul_add_36(a+i, m, mu);
        a[i+1] += a[i] >> 57;
        a[i] &= 0x1ffffffffffffffL;
    }
    else {
        for (i=0; i<35; i++) {
            mu = a[i] & 0x1ffffffffffffffL;
            sp_2048_mul_add_36(a+i, m, mu);
            a[i+1] += a[i] >> 57;
        }
        mu = a[i] & 0x1fffffffffffffL;
        sp_2048_mul_add_36(a+i, m, mu);
        a[i+1] += a[i] >> 57;
        a[i] &= 0x1ffffffffffffffL;
    }
#else
    for (i=0; i<35; i++) {
        mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x1ffffffffffffffL;
        sp_2048_mul_add_36(a+i, m, mu);
        a[i+1] += a[i] >> 57;
    }
    mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x1fffffffffffffL;
    sp_2048_mul_add_36(a+i, m, mu);
    a[i+1] += a[i] >> 57;
    a[i] &= 0x1ffffffffffffffL;
#endif
    sp_2048_mont_shift_36(a, a);
    over = a[35] - m[35];
    sp_2048_cond_sub_36(a, a, m, ~((over - 1) >> 63));
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
SP_NOINLINE static void sp_2048_mul_d_72(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t = 0;
    sp_digit t2;
    sp_int128 p[4];
    int i;

    for (i = 0; i < 72; i += 4) {
        p[0] = tb * a[i + 0];
        p[1] = tb * a[i + 1];
        p[2] = tb * a[i + 2];
        p[3] = tb * a[i + 3];
        t += p[0];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 0] = (sp_digit)t2;
        t += p[1];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 1] = (sp_digit)t2;
        t += p[2];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 2] = (sp_digit)t2;
        t += p[3];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 3] = (sp_digit)t2;
    }
    r[72] = (sp_digit)(t & 0x1ffffffffffffffL);
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

    for (i=0; i<32; i += 8) {
        r[i+0] = (a[i+0] >> n) | ((a[i+1] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+1] = (a[i+1] >> n) | ((a[i+2] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+2] = (a[i+2] >> n) | ((a[i+3] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+3] = (a[i+3] >> n) | ((a[i+4] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+4] = (a[i+4] >> n) | ((a[i+5] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+5] = (a[i+5] >> n) | ((a[i+6] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+6] = (a[i+6] >> n) | ((a[i+7] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+7] = (a[i+7] >> n) | ((a[i+8] << (57 - n)) & 0x1ffffffffffffffL);
    }
    r[32] = (a[32] >> n) | ((a[33] << (57 - n)) & 0x1ffffffffffffffL);
    r[33] = (a[33] >> n) | ((a[34] << (57 - n)) & 0x1ffffffffffffffL);
    r[34] = (a[34] >> n) | ((a[35] << (57 - n)) & 0x1ffffffffffffffL);
    r[35] = a[35] >> n;
}

static WC_INLINE sp_digit sp_2048_div_word_36(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int128 d = ((sp_int128)d1 << 57) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int128 d = ((sp_int128)d1 << 57) + d0;
    sp_uint64 lo = (sp_uint64)d;
    sp_digit hi = (sp_digit)(d >> 64);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int128 d = ((sp_int128)d1 << 57) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 57);
    sp_digit t0 = (sp_digit)(d & 0x1ffffffffffffffL);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int128 m;

    r = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
    t1 -= dv & (0 - r);
    for (i = 55; i >= 1; i--) {
        t1 += t1 + (((sp_uint64)t0 >> 56) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int128)r * div);
    r += (sp_digit)(m >> 57);
    m = d - ((sp_int128)r * div);
    r += (m >> 114) - (sp_digit)(d >> 114);

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;
   return r;
#else
    sp_int128 d = ((sp_int128)d1 << 57) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 26) + 1;

    t = (sp_digit)(d >> 52);
    t = (t / dv) << 26;
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)(d >> 21);
    t = t / (dv << 5);
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int128)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_2048_word_div_word_36(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint64)(div - d) >> 63);
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
#ifndef WOLFSSL_SP_DIV_64
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

        sp_2048_mul_d_36(sd, d, (sp_digit)1 << 4);
        sp_2048_mul_d_72(t1, a, (sp_digit)1 << 4);
        dv = sd[35];
        t1[36 + 36] += t1[36 + 36 - 1] >> 57;
        t1[36 + 36 - 1] &= 0x1ffffffffffffffL;
        for (i=36; i>=0; i--) {
            r1 = sp_2048_div_word_36(t1[36 + i], t1[36 + i - 1], dv);

            sp_2048_mul_d_36(t2, sd, r1);
            (void)sp_2048_sub_36(&t1[i], &t1[i], t2);
            sp_2048_norm_36(&t1[i]);
            t1[36 + i] -= t2[36];
            t1[36 + i] += t1[36 + i - 1] >> 57;
            t1[36 + i - 1] &= 0x1ffffffffffffffL;
            r1 = sp_2048_div_word_36(-t1[36 + i], -t1[36 + i - 1], dv);
            r1 -= t1[36 + i];
            sp_2048_mul_d_36(t2, sd, r1);
            (void)sp_2048_add_36(&t1[i], &t1[i], t2);
            t1[36 + i] += t1[36 + i - 1] >> 57;
            t1[36 + i - 1] &= 0x1ffffffffffffffL;
        }
        t1[36 - 1] += t1[36 - 2] >> 57;
        t1[36 - 2] &= 0x1ffffffffffffffL;
        r1 = sp_2048_word_div_word_36(t1[36 - 1], dv);

        sp_2048_mul_d_36(t2, sd, r1);
        sp_2048_sub_36(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 72U);
        for (i=0; i<35; i++) {
            r[i+1] += r[i] >> 57;
            r[i] &= 0x1ffffffffffffffL;
        }
        sp_2048_cond_add_36(r, r, sd, r[35] >> 63);

        sp_2048_norm_36(r);
        sp_2048_rshift_36(r, r, 4);
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
        i = bits / 57;
        c = bits % 57;
        n = e[i--] << (57 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 57;
            }

            y = (int)((n >> 56) & 1);
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
        sp_2048_cond_sub_36(t[0], t[0], m, ~(n >> 63));
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
        i = bits / 57;
        c = bits % 57;
        n = e[i--] << (57 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 57;
            }

            y = (int)((n >> 56) & 1);
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
        sp_2048_cond_sub_36(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 36 * 2);
    }


    return err;
#else
    sp_digit td[(16 * 72) + 72];
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
            t[i] = td + i * 72;
        rt = td + 1152;

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

        bits = ((bits + 3) / 4) * 4;
        i = ((bits + 56) / 57) - 1;
        c = bits % 57;
        if (c == 0) {
            c = 57;
        }
        if (i < 36) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 4) {
            n |= e[i--] << (7 - c);
            c += 57;
        }
        y = (int)((n >> 60) & 0xf);
        n <<= 4;
        c -= 4;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 72);
        while ((i >= 0) || (c >= 4)) {
            if (c >= 4) {
                y = (byte)((n >> 60) & 0xf);
                n <<= 4;
                c -= 4;
            }
            else if (c == 0) {
                n = e[i--] << 7;
                y = (byte)((n >> 60) & 0xf);
                n <<= 4;
                c = 53;
            }
            else {
                y = (byte)((n >> 60) & 0xf);
                n = e[i--] << 7;
                c = 4 - c;
                y |= (byte)((n >> (64 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 57 - c;
            }

            sp_2048_mont_sqr_36(rt, rt, m, mp);
            sp_2048_mont_sqr_36(rt, rt, m, mp);
            sp_2048_mont_sqr_36(rt, rt, m, mp);
            sp_2048_mont_sqr_36(rt, rt, m, mp);

            sp_2048_mont_mul_36(rt, rt, t[y], m, mp);
        }

        sp_2048_mont_reduce_36(rt, m, mp);
        n = sp_2048_cmp_36(rt, m);
        sp_2048_cond_sub_36(rt, rt, m, ~(n >> 63));
        XMEMCPY(r, rt, sizeof(sp_digit) * 72);
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
    sp_digit a[36 * 5];
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
        if (mp_count_bits(em) > 57) {
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
        r = a + 36 * 2;
        m = r + 36 * 2;
        norm = r;

        sp_2048_from_bin(a, 36, in, inLen);
#if DIGIT_BIT >= 57
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
        sp_2048_from_mp(m, 36, mm);

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_36(norm, m);
    }
    if (err == MP_OKAY) {
        sp_2048_mul_36(a, a, norm);
        err = sp_2048_mod_36(a, a, m);
    }
    if (err == MP_OKAY) {
        for (i=56; i>=0; i--) {
            if ((e[0] >> i) != 0) {
                break;
            }
        }

        XMEMCPY(r, a, sizeof(sp_digit) * 36 * 2);
        for (i--; i>=0; i--) {
            sp_2048_mont_sqr_36(r, r, m, mp);

            if (((e[0] >> i) & 1) == 1) {
                sp_2048_mont_mul_36(r, r, a, m, mp);
            }
        }
        sp_2048_mont_reduce_36(r, m, mp);
        mp = sp_2048_cmp_36(r, m);
        sp_2048_cond_sub_36(r, r, m, ~(mp >> 63));

        sp_2048_to_bin_36(r, out);
        *outLen = 256;
    }


    return err;
#else
    sp_digit d[36 * 5];
    sp_digit* a = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit e[1] = {0};
    int err = MP_OKAY;

    if (*outLen < 256U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 57) {
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
        r = a + 36 * 2;
        m = r + 36 * 2;

        sp_2048_from_bin(a, 36, in, inLen);
#if DIGIT_BIT >= 57
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
        sp_2048_from_mp(m, 36, mm);

        if (e[0] == 0x3) {
            sp_2048_sqr_36(r, a);
            err = sp_2048_mod_36(r, r, m);
            if (err == MP_OKAY) {
                sp_2048_mul_36(r, a, r);
                err = sp_2048_mod_36(r, r, m);
            }
        }
        else {
            sp_digit* norm = r;
            int i;
            sp_digit mp;

            sp_2048_mont_setup(m, &mp);
            sp_2048_mont_norm_36(norm, m);

            sp_2048_mul_36(a, a, norm);
            err = sp_2048_mod_36(a, a, m);

            if (err == MP_OKAY) {
                for (i=56; i>=0; i--) {
                    if ((e[0] >> i) != 0) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 72U);
                for (i--; i>=0; i--) {
                    sp_2048_mont_sqr_36(r, r, m, mp);

                    if (((e[0] >> i) & 1) == 1) {
                        sp_2048_mont_mul_36(r, r, a, m, mp);
                    }
                }
                sp_2048_mont_reduce_36(r, m, mp);
                mp = sp_2048_cmp_36(r, m);
                sp_2048_cond_sub_36(r, r, m, ~(mp >> 63));
            }
        }
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin_36(r, out);
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
    sp_digit  d[36 * 4];
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
        a = d + 36;
        m = a + 72;
        r = a;

        sp_2048_from_bin(a, 36, in, inLen);
        sp_2048_from_mp(d, 36, dm);
        sp_2048_from_mp(m, 36, mm);
        err = sp_2048_mod_exp_36(r, a, d, 2048, m, 0);
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin_36(r, out);
        *outLen = 256;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 36);
    }

    return err;
#else
    sp_digit d[36 * 4];
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
        a = d + 36;
        m = a + 72;
        r = a;

        sp_2048_from_bin(a, 36, in, inLen);
        sp_2048_from_mp(d, 36, dm);
        sp_2048_from_mp(m, 36, mm);
        err = sp_2048_mod_exp_36(r, a, d, 2048, m, 0);
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin_36(r, out);
        *outLen = 256;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 36);
    }

    return err;
#endif /* WOLFSSL_SP_SMALL */
#else
#if defined(WOLFSSL_SP_SMALL)
    sp_digit a[18 * 8];
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
        p = a + 36;
        qi = dq = dp = p + 18;
        tmpa = qi + 18;
        tmpb = tmpa + 36;
        r = a;

        sp_2048_from_bin(a, 36, in, inLen);
        sp_2048_from_mp(p, 18, pm);
        sp_2048_from_mp(dp, 18, dpm);
        err = sp_2048_mod_exp_18(tmpa, a, dp, 1024, p, 1);
    }
    if (err == MP_OKAY) {
        sp_2048_from_mp(p, 18, qm);
        sp_2048_from_mp(dq, 18, dqm);
        err = sp_2048_mod_exp_18(tmpb, a, dq, 1024, p, 1);
    }
    if (err == MP_OKAY) {
        sp_2048_from_mp(p, 18, pm);
        (void)sp_2048_sub_18(tmpa, tmpa, tmpb);
        sp_2048_norm_18(tmpa);
        sp_2048_cond_add_18(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[17] >> 63));
        sp_2048_cond_add_18(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[17] >> 63));
        sp_2048_norm_18(tmpa);

        sp_2048_from_mp(qi, 18, qim);
        sp_2048_mul_18(tmpa, tmpa, qi);
        err = sp_2048_mod_18(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_2048_from_mp(p, 18, qm);
        sp_2048_mul_18(tmpa, p, tmpa);
        (void)sp_2048_add_36(r, tmpb, tmpa);
        sp_2048_norm_36(r);

        sp_2048_to_bin_36(r, out);
        *outLen = 256;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 18 * 8);
    }

    return err;
#else
    sp_digit a[18 * 13];
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
        p = a + 36 * 2;
        q = p + 18;
        dp = q + 18;
        dq = dp + 18;
        qi = dq + 18;
        tmpa = qi + 18;
        tmpb = tmpa + 36;
        r = a;

        sp_2048_from_bin(a, 36, in, inLen);
        sp_2048_from_mp(p, 18, pm);
        sp_2048_from_mp(q, 18, qm);
        sp_2048_from_mp(dp, 18, dpm);
        sp_2048_from_mp(dq, 18, dqm);
        sp_2048_from_mp(qi, 18, qim);

        err = sp_2048_mod_exp_18(tmpa, a, dp, 1024, p, 1);
    }
    if (err == MP_OKAY) {
        err = sp_2048_mod_exp_18(tmpb, a, dq, 1024, q, 1);
    }

    if (err == MP_OKAY) {
        (void)sp_2048_sub_18(tmpa, tmpa, tmpb);
        sp_2048_norm_18(tmpa);
        sp_2048_cond_add_18(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[17] >> 63));
        sp_2048_cond_add_18(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[17] >> 63));
        sp_2048_norm_18(tmpa);
        sp_2048_mul_18(tmpa, tmpa, qi);
        err = sp_2048_mod_18(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_2048_mul_18(tmpa, tmpa, q);
        (void)sp_2048_add_36(r, tmpb, tmpa);
        sp_2048_norm_36(r);

        sp_2048_to_bin_36(r, out);
        *outLen = 256;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 18 * 13);
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
#if DIGIT_BIT == 57
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 36);
        r->used = 36;
        mp_clamp(r);
#elif DIGIT_BIT < 57
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 36; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 57) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 57 - s;
        }
        r->used = (2048 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 36; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 57 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 57 - s;
            }
            else {
                s += 57;
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
    sp_digit b[36 * 4];
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
        e = b + 36 * 2;
        m = e + 36;
        r = b;

        sp_2048_from_mp(b, 36, base);
        sp_2048_from_mp(e, 36, exp);
        sp_2048_from_mp(m, 36, mod);

        err = sp_2048_mod_exp_36(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_2048_to_mp(r, res);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 36U);
    }
    return err;
#else
    sp_digit b[36 * 4];
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
        e = b + 36 * 2;
        m = e + 36;
        r = b;

        sp_2048_from_mp(b, 36, base);
        sp_2048_from_mp(e, 36, exp);
        sp_2048_from_mp(m, 36, mod);

        err = sp_2048_mod_exp_36(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_2048_to_mp(r, res);
    }


    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 36U);
    }

    return err;
#endif
}

#ifdef WOLFSSL_HAVE_SP_DH

SP_NOINLINE static void sp_2048_lshift_36(sp_digit* r, const sp_digit* a,
        byte n)
{
    sp_int_digit s;
    sp_int_digit t;

    s = (sp_int_digit)a[35];
    r[36] = s >> (57U - n);
    s = (sp_int_digit)(a[35]); t = (sp_int_digit)(a[34]);
    r[35] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[34]); t = (sp_int_digit)(a[33]);
    r[34] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[33]); t = (sp_int_digit)(a[32]);
    r[33] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[32]); t = (sp_int_digit)(a[31]);
    r[32] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[31]); t = (sp_int_digit)(a[30]);
    r[31] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[30]); t = (sp_int_digit)(a[29]);
    r[30] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[29]); t = (sp_int_digit)(a[28]);
    r[29] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[28]); t = (sp_int_digit)(a[27]);
    r[28] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[27]); t = (sp_int_digit)(a[26]);
    r[27] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[26]); t = (sp_int_digit)(a[25]);
    r[26] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[25]); t = (sp_int_digit)(a[24]);
    r[25] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[24]); t = (sp_int_digit)(a[23]);
    r[24] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[23]); t = (sp_int_digit)(a[22]);
    r[23] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[22]); t = (sp_int_digit)(a[21]);
    r[22] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[21]); t = (sp_int_digit)(a[20]);
    r[21] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[20]); t = (sp_int_digit)(a[19]);
    r[20] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[19]); t = (sp_int_digit)(a[18]);
    r[19] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[18]); t = (sp_int_digit)(a[17]);
    r[18] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[17]); t = (sp_int_digit)(a[16]);
    r[17] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[16]); t = (sp_int_digit)(a[15]);
    r[16] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[15]); t = (sp_int_digit)(a[14]);
    r[15] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[14]); t = (sp_int_digit)(a[13]);
    r[14] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[13]); t = (sp_int_digit)(a[12]);
    r[13] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[12]); t = (sp_int_digit)(a[11]);
    r[12] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[11]); t = (sp_int_digit)(a[10]);
    r[11] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[10]); t = (sp_int_digit)(a[9]);
    r[10] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[9]); t = (sp_int_digit)(a[8]);
    r[9] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[8]); t = (sp_int_digit)(a[7]);
    r[8] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[7]); t = (sp_int_digit)(a[6]);
    r[7] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[6]); t = (sp_int_digit)(a[5]);
    r[6] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[5]); t = (sp_int_digit)(a[4]);
    r[5] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[4]); t = (sp_int_digit)(a[3]);
    r[4] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[3]); t = (sp_int_digit)(a[2]);
    r[3] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[2]); t = (sp_int_digit)(a[1]);
    r[2] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[1]); t = (sp_int_digit)(a[0]);
    r[1] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    r[0] = (a[0] << n) & 0x1ffffffffffffffL;
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
static int sp_2048_mod_exp_2_36(sp_digit* r, const sp_digit* e, int bits, const sp_digit* m)
{
    sp_digit td[109];
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
        tmp  = td + 72;
        XMEMSET(td, 0, sizeof(sp_digit) * 109);

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_36(norm, m);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 56) / 57) - 1;
        c = bits % 57;
        if (c == 0) {
            c = 57;
        }
        if (i < 36) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (7 - c);
            c += 57;
        }
        y = (int)((n >> 59) & 0x1f);
        n <<= 5;
        c -= 5;
        sp_2048_lshift_36(r, norm, (byte)y);
        while ((i >= 0) || (c >= 5)) {
            if (c >= 5) {
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--] << 7;
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c = 52;
            }
            else {
                y = (byte)((n >> 59) & 0x1f);
                n = e[i--] << 7;
                c = 5 - c;
                y |= (byte)((n >> (64 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 57 - c;
            }

            sp_2048_mont_sqr_36(r, r, m, mp);
            sp_2048_mont_sqr_36(r, r, m, mp);
            sp_2048_mont_sqr_36(r, r, m, mp);
            sp_2048_mont_sqr_36(r, r, m, mp);
            sp_2048_mont_sqr_36(r, r, m, mp);

            sp_2048_lshift_36(r, r, (byte)y);
            sp_2048_mul_d_36(tmp, norm, (r[36] << 4) + (r[35] >> 53));
            r[36] = 0;
            r[35] &= 0x1fffffffffffffL;
            (void)sp_2048_add_36(r, r, tmp);
            sp_2048_norm_36(r);
            o = sp_2048_cmp_36(r, m);
            sp_2048_cond_sub_36(r, r, m, ~(o >> 63));
        }

        sp_2048_mont_reduce_36(r, m, mp);
        n = sp_2048_cmp_36(r, m);
        sp_2048_cond_sub_36(r, r, m, ~(n >> 63));
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
    sp_digit b[36 * 4];
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
        e = b + 36 * 2;
        m = e + 36;
        r = b;

        sp_2048_from_mp(b, 36, base);
        sp_2048_from_bin(e, 36, exp, expLen);
        sp_2048_from_mp(m, 36, mod);

        if (base->used == 1 && base->dp[0] == 2U &&
                (m[35] >> 21) == 0xffffffffL) {
            err = sp_2048_mod_exp_2_36(r, e, expLen * 8U, m);
        }
        else {
            err = sp_2048_mod_exp_36(r, b, e, expLen * 8U, m, 0);
        }
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin_36(r, out);
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
            ForceZero(e, sizeof(sp_digit) * 36U);
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
    sp_digit b[18 * 4];
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
        e = b + 18 * 2;
        m = e + 18;
        r = b;

        sp_2048_from_mp(b, 18, base);
        sp_2048_from_mp(e, 18, exp);
        sp_2048_from_mp(m, 18, mod);

        err = sp_2048_mod_exp_18(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 18, 0, sizeof(*r) * 18U);
        err = sp_2048_to_mp(r, res);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 36U);
    }
    return err;
#else
    sp_digit b[18 * 4];
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
        e = b + 18 * 2;
        m = e + 18;
        r = b;

        sp_2048_from_mp(b, 18, base);
        sp_2048_from_mp(e, 18, exp);
        sp_2048_from_mp(m, 18, mod);

        err = sp_2048_mod_exp_18(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 18, 0, sizeof(*r) * 18U);
        err = sp_2048_to_mp(r, res);
    }


    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 36U);
    }

    return err;
#endif
}

#endif /* WOLFSSL_HAVE_SP_DH | (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) */

#endif /* WOLFSSL_SP_SMALL */
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
        if (s >= 52U) {
            r[j] &= 0xfffffffffffffffL;
            s = 60U - s;
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
#if DIGIT_BIT == 60
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 60
    int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0xfffffffffffffffL;
        s = 60U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 60U) <= (word32)DIGIT_BIT) {
            s += 60U;
            r[j] &= 0xfffffffffffffffL;
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
        if (s + DIGIT_BIT >= 60) {
            r[j] &= 0xfffffffffffffffL;
            if (j + 1 >= size) {
                break;
            }
            s = 60 - s;
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
static void sp_3072_to_bin_52(sp_digit* r, byte* a)
{
    int i;
    int j;
    int s = 0;
    int b;

    for (i=0; i<51; i++) {
        r[i+1] += r[i] >> 60;
        r[i] &= 0xfffffffffffffffL;
    }
    j = 3079 / 8 - 1;
    a[j] = 0;
    for (i=0; i<52 && j>=0; i++) {
        b = 0;
        /* lint allow cast of mismatch sp_digit and int */
        a[j--] |= (byte)(r[i] << s); /*lint !e9033*/
        b += 8 - s;
        if (j < 0) {
            break;
        }
        while (b < 60) {
            a[j--] = (byte)(r[i] >> b);
            b += 8;
            if (j < 0) {
                break;
            }
        }
        s = 8 - (b - 60);
        if (j >= 0) {
            a[j] = 0;
        }
        if (s != 0) {
            j++;
        }
    }
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* Normalize the values in each word to 60 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_3072_norm_26(sp_digit* a)
{
    int i;
    for (i = 0; i < 25; i++) {
        a[i+1] += a[i] >> 60;
        a[i] &= 0xfffffffffffffffL;
    }
}

#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || WOLFSSL_HAVE_SP_DH */
/* Normalize the values in each word to 60 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_3072_norm_52(sp_digit* a)
{
    int i;
    for (i = 0; i < 51; i++) {
        a[i+1] += a[i] >> 60;
        a[i] &= 0xfffffffffffffffL;
    }
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_52(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i;
    int imax;
    int k;
    sp_uint128 c;
    sp_uint128 lo;

    c = ((sp_uint128)a[51]) * b[51];
    r[103] = (sp_digit)(c >> 60);
    c &= 0xfffffffffffffffL;
    for (k = 101; k >= 0; k--) {
        if (k >= 52) {
            i = k - 51;
            imax = 51;
        }
        else {
            i = 0;
            imax = k;
        }
        lo = 0;
        for (; i <= imax; i++) {
            lo += ((sp_uint128)a[i]) * b[k - i];
        }
        c += lo >> 60;
        r[k + 2] += (sp_digit)(c >> 60);
        r[k + 1]  = (sp_digit)(c & 0xfffffffffffffffL);
        c = lo & 0xfffffffffffffffL;
    }
    r[0] = (sp_digit)c;
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_52(sp_digit* r, const sp_digit* a)
{
    int i;
    int imax;
    int k;
    sp_uint128 c;
    sp_uint128 t;

    c = ((sp_uint128)a[51]) * a[51];
    r[103] = (sp_digit)(c >> 60);
    c = (c & 0xfffffffffffffffL) << 60;
    for (k = 101; k >= 0; k--) {
        i = (k + 1) / 2;
        if ((k & 1) == 0) {
           c += ((sp_uint128)a[i]) * a[i];
           i++;
        }
        if (k < 51) {
            imax = k;
        }
        else {
            imax = 51;
        }
        t = 0;
        for (; i <= imax; i++) {
            t += ((sp_uint128)a[i]) * a[k - i];
        }
        c += t * 2;

        r[k + 2] += (sp_digit) (c >> 120);
        r[k + 1]  = (sp_digit)((c >> 60) & 0xfffffffffffffffL);
        c = (c & 0xfffffffffffffffL) << 60;
    }
    r[0] = (sp_digit)(c >> 60);
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
    x *= 2 - b * x;               /* here x*a==1 mod 2**64 */
    x &= 0xfffffffffffffffL;

    /* rho = -1/m mod b */
    *rho = ((sp_digit)1 << 60) - x;
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_d_52(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t = 0;
    int i;

    for (i = 0; i < 52; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0xfffffffffffffffL);
        t >>= 60;
    }
    r[52] = (sp_digit)t;
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_sub_26(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 26; i++) {
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
static void sp_3072_mont_norm_26(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
    int i;

    for (i=0; i<25; i++) {
        r[i] = 0xfffffffffffffffL;
    }
    r[25] = 0xfffffffffL;

    /* r = (2^n - 1) mod n */
    (void)sp_3072_sub_26(r, r, m);

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
static sp_digit sp_3072_cmp_26(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
    int i;

    for (i=25; i>=0; i--) {
        r |= (a[i] - b[i]) & ~(((sp_digit)0 - r) >> 59);
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
static void sp_3072_cond_sub_26(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 26; i++) {
        r[i] = a[i] - (b[i] & m);
    }
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_add_26(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t[4];
    int i;

    t[0] = 0;
    for (i = 0; i < 24; i += 4) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        r[i+0] = t[0] & 0xfffffffffffffffL;
        t[1] += t[0] >> 60;
        r[i+1] = t[1] & 0xfffffffffffffffL;
        t[2] += t[1] >> 60;
        r[i+2] = t[2] & 0xfffffffffffffffL;
        t[3] += t[2] >> 60;
        r[i+3] = t[3] & 0xfffffffffffffffL;
        t[0]  = t[3] >> 60;
    }
    t[0] += (tb * a[24]) + r[24];
    t[1]  = (tb * a[25]) + r[25];
    r[24] = t[0] & 0xfffffffffffffffL;
    t[1] += t[0] >> 60;
    r[25] = t[1] & 0xfffffffffffffffL;
    r[26] +=  (sp_digit)(t[1] >> 60);
}

/* Shift the result in the high 1536 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_3072_mont_shift_26(sp_digit* r, const sp_digit* a)
{
    int i;
    sp_int128 n = a[25] >> 36;
    n += ((sp_int128)a[26]) << 24;

    for (i = 0; i < 25; i++) {
        r[i] = n & 0xfffffffffffffffL;
        n >>= 60;
        n += ((sp_int128)a[27 + i]) << 24;
    }
    r[25] = (sp_digit)n;
    XMEMSET(&r[26], 0, sizeof(*r) * 26U);
}

/* Reduce the number back to 3072 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_3072_mont_reduce_26(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_3072_norm_26(a + 26);

    for (i=0; i<25; i++) {
        mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0xfffffffffffffffL;
        sp_3072_mul_add_26(a+i, m, mu);
        a[i+1] += a[i] >> 60;
    }
    mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0xfffffffffL;
    sp_3072_mul_add_26(a+i, m, mu);
    a[i+1] += a[i] >> 60;
    a[i] &= 0xfffffffffffffffL;
    sp_3072_mont_shift_26(a, a);
    over = a[25] - m[25];
    sp_3072_cond_sub_26(a, a, m, ~((over - 1) >> 63));
    sp_3072_norm_26(a);
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_26(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i;
    int imax;
    int k;
    sp_uint128 c;
    sp_uint128 lo;

    c = ((sp_uint128)a[25]) * b[25];
    r[51] = (sp_digit)(c >> 60);
    c &= 0xfffffffffffffffL;
    for (k = 49; k >= 0; k--) {
        if (k >= 26) {
            i = k - 25;
            imax = 25;
        }
        else {
            i = 0;
            imax = k;
        }
        lo = 0;
        for (; i <= imax; i++) {
            lo += ((sp_uint128)a[i]) * b[k - i];
        }
        c += lo >> 60;
        r[k + 2] += (sp_digit)(c >> 60);
        r[k + 1]  = (sp_digit)(c & 0xfffffffffffffffL);
        c = lo & 0xfffffffffffffffL;
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
SP_NOINLINE static void sp_3072_mont_mul_26(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_3072_mul_26(r, a, b);
    sp_3072_mont_reduce_26(r, m, mp);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_26(sp_digit* r, const sp_digit* a)
{
    int i;
    int imax;
    int k;
    sp_uint128 c;
    sp_uint128 t;

    c = ((sp_uint128)a[25]) * a[25];
    r[51] = (sp_digit)(c >> 60);
    c = (c & 0xfffffffffffffffL) << 60;
    for (k = 49; k >= 0; k--) {
        i = (k + 1) / 2;
        if ((k & 1) == 0) {
           c += ((sp_uint128)a[i]) * a[i];
           i++;
        }
        if (k < 25) {
            imax = k;
        }
        else {
            imax = 25;
        }
        t = 0;
        for (; i <= imax; i++) {
            t += ((sp_uint128)a[i]) * a[k - i];
        }
        c += t * 2;

        r[k + 2] += (sp_digit) (c >> 120);
        r[k + 1]  = (sp_digit)((c >> 60) & 0xfffffffffffffffL);
        c = (c & 0xfffffffffffffffL) << 60;
    }
    r[0] = (sp_digit)(c >> 60);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_3072_mont_sqr_26(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_3072_sqr_26(r, a);
    sp_3072_mont_reduce_26(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_d_26(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t = 0;
    int i;

    for (i = 0; i < 26; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0xfffffffffffffffL);
        t >>= 60;
    }
    r[26] = (sp_digit)t;
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
static void sp_3072_cond_add_26(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 26; i++) {
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
SP_NOINLINE static int sp_3072_add_26(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 26; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}

SP_NOINLINE static void sp_3072_rshift_26(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    for (i=0; i<25; i++) {
        r[i] = ((a[i] >> n) | (a[i + 1] << (60 - n))) & 0xfffffffffffffffL;
    }
    r[25] = a[25] >> n;
}

static WC_INLINE sp_digit sp_3072_div_word_26(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int128 d = ((sp_int128)d1 << 60) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int128 d = ((sp_int128)d1 << 60) + d0;
    sp_uint64 lo = (sp_uint64)d;
    sp_digit hi = (sp_digit)(d >> 64);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int128 d = ((sp_int128)d1 << 60) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 60);
    sp_digit t0 = (sp_digit)(d & 0xfffffffffffffffL);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int128 m;

    r = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
    t1 -= dv & (0 - r);
    for (i = 58; i >= 1; i--) {
        t1 += t1 + (((sp_uint64)t0 >> 59) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int128)r * div);
    r += (sp_digit)(m >> 60);
    m = d - ((sp_int128)r * div);
    r += (m >> 120) - (sp_digit)(d >> 120);

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;
   return r;
#else
    sp_int128 d = ((sp_int128)d1 << 60) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 29) + 1;

    t = (sp_digit)(d >> 58);
    t = (t / dv) << 29;
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)(d >> 27);
    t = t / (dv << 2);
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int128)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_3072_word_div_word_26(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint64)(div - d) >> 63);
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
static int sp_3072_div_26(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_64
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 26 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 52 + 1;
        sd = t2 + 26 + 1;

        sp_3072_mul_d_26(sd, d, (sp_digit)1 << 24);
        sp_3072_mul_d_52(t1, a, (sp_digit)1 << 24);
        dv = sd[25];
        t1[26 + 26] += t1[26 + 26 - 1] >> 60;
        t1[26 + 26 - 1] &= 0xfffffffffffffffL;
        for (i=26; i>=0; i--) {
            r1 = sp_3072_div_word_26(t1[26 + i], t1[26 + i - 1], dv);

            sp_3072_mul_d_26(t2, sd, r1);
            (void)sp_3072_sub_26(&t1[i], &t1[i], t2);
            sp_3072_norm_26(&t1[i]);
            t1[26 + i] -= t2[26];
            t1[26 + i] += t1[26 + i - 1] >> 60;
            t1[26 + i - 1] &= 0xfffffffffffffffL;
            r1 = sp_3072_div_word_26(-t1[26 + i], -t1[26 + i - 1], dv);
            r1 -= t1[26 + i];
            sp_3072_mul_d_26(t2, sd, r1);
            (void)sp_3072_add_26(&t1[i], &t1[i], t2);
            t1[26 + i] += t1[26 + i - 1] >> 60;
            t1[26 + i - 1] &= 0xfffffffffffffffL;
        }
        t1[26 - 1] += t1[26 - 2] >> 60;
        t1[26 - 2] &= 0xfffffffffffffffL;
        r1 = sp_3072_word_div_word_26(t1[26 - 1], dv);

        sp_3072_mul_d_26(t2, sd, r1);
        sp_3072_sub_26(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 52U);
        for (i=0; i<25; i++) {
            r[i+1] += r[i] >> 60;
            r[i] &= 0xfffffffffffffffL;
        }
        sp_3072_cond_add_26(r, r, sd, r[25] >> 63);

        sp_3072_norm_26(r);
        sp_3072_rshift_26(r, r, 24);
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
static int sp_3072_mod_26(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_3072_div_26(a, m, NULL, r);
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
static int sp_3072_mod_exp_26(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 52];
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
            t[i] = td + (i * 26 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 26U * 2U);
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_26(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_26(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 26U);
        }
    }
    if (err == MP_OKAY) {
        sp_3072_mul_26(t[1], t[1], norm);
        err = sp_3072_mod_26(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 60;
        c = bits % 60;
        n = e[i--] << (60 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 60;
            }

            y = (int)((n >> 59) & 1);
            n <<= 1;

            sp_3072_mont_mul_26(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 26 * 2);
            sp_3072_mont_sqr_26(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 26 * 2);
        }

        sp_3072_mont_reduce_26(t[0], m, mp);
        n = sp_3072_cmp_26(t[0], m);
        sp_3072_cond_sub_26(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 26 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 52];
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
            t[i] = td + (i * 26 * 2);
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_26(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_26(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_26(t[1], t[1], norm);
                err = sp_3072_mod_26(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_26(t[1], a, norm);
            err = sp_3072_mod_26(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 60;
        c = bits % 60;
        n = e[i--] << (60 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 60;
            }

            y = (int)((n >> 59) & 1);
            n <<= 1;

            sp_3072_mont_mul_26(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 26 * 2);
            sp_3072_mont_sqr_26(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 26 * 2);
        }

        sp_3072_mont_reduce_26(t[0], m, mp);
        n = sp_3072_cmp_26(t[0], m);
        sp_3072_cond_sub_26(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 26 * 2);
    }


    return err;
#else
    sp_digit td[(32 * 52) + 52];
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
            t[i] = td + i * 52;
        rt = td + 1664;

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_26(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_26(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_26(t[1], t[1], norm);
                err = sp_3072_mod_26(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_26(t[1], a, norm);
            err = sp_3072_mod_26(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_3072_mont_sqr_26(t[ 2], t[ 1], m, mp);
        sp_3072_mont_mul_26(t[ 3], t[ 2], t[ 1], m, mp);
        sp_3072_mont_sqr_26(t[ 4], t[ 2], m, mp);
        sp_3072_mont_mul_26(t[ 5], t[ 3], t[ 2], m, mp);
        sp_3072_mont_sqr_26(t[ 6], t[ 3], m, mp);
        sp_3072_mont_mul_26(t[ 7], t[ 4], t[ 3], m, mp);
        sp_3072_mont_sqr_26(t[ 8], t[ 4], m, mp);
        sp_3072_mont_mul_26(t[ 9], t[ 5], t[ 4], m, mp);
        sp_3072_mont_sqr_26(t[10], t[ 5], m, mp);
        sp_3072_mont_mul_26(t[11], t[ 6], t[ 5], m, mp);
        sp_3072_mont_sqr_26(t[12], t[ 6], m, mp);
        sp_3072_mont_mul_26(t[13], t[ 7], t[ 6], m, mp);
        sp_3072_mont_sqr_26(t[14], t[ 7], m, mp);
        sp_3072_mont_mul_26(t[15], t[ 8], t[ 7], m, mp);
        sp_3072_mont_sqr_26(t[16], t[ 8], m, mp);
        sp_3072_mont_mul_26(t[17], t[ 9], t[ 8], m, mp);
        sp_3072_mont_sqr_26(t[18], t[ 9], m, mp);
        sp_3072_mont_mul_26(t[19], t[10], t[ 9], m, mp);
        sp_3072_mont_sqr_26(t[20], t[10], m, mp);
        sp_3072_mont_mul_26(t[21], t[11], t[10], m, mp);
        sp_3072_mont_sqr_26(t[22], t[11], m, mp);
        sp_3072_mont_mul_26(t[23], t[12], t[11], m, mp);
        sp_3072_mont_sqr_26(t[24], t[12], m, mp);
        sp_3072_mont_mul_26(t[25], t[13], t[12], m, mp);
        sp_3072_mont_sqr_26(t[26], t[13], m, mp);
        sp_3072_mont_mul_26(t[27], t[14], t[13], m, mp);
        sp_3072_mont_sqr_26(t[28], t[14], m, mp);
        sp_3072_mont_mul_26(t[29], t[15], t[14], m, mp);
        sp_3072_mont_sqr_26(t[30], t[15], m, mp);
        sp_3072_mont_mul_26(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 59) / 60) - 1;
        c = bits % 60;
        if (c == 0) {
            c = 60;
        }
        if (i < 26) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (4 - c);
            c += 60;
        }
        y = (int)((n >> 59) & 0x1f);
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 52);
        while ((i >= 0) || (c >= 5)) {
            if (c >= 5) {
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--] << 4;
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c = 55;
            }
            else {
                y = (byte)((n >> 59) & 0x1f);
                n = e[i--] << 4;
                c = 5 - c;
                y |= (byte)((n >> (64 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 60 - c;
            }

            sp_3072_mont_sqr_26(rt, rt, m, mp);
            sp_3072_mont_sqr_26(rt, rt, m, mp);
            sp_3072_mont_sqr_26(rt, rt, m, mp);
            sp_3072_mont_sqr_26(rt, rt, m, mp);
            sp_3072_mont_sqr_26(rt, rt, m, mp);

            sp_3072_mont_mul_26(rt, rt, t[y], m, mp);
        }

        sp_3072_mont_reduce_26(rt, m, mp);
        n = sp_3072_cmp_26(rt, m);
        sp_3072_cond_sub_26(rt, rt, m, ~(n >> 63));
        XMEMCPY(r, rt, sizeof(sp_digit) * 52);
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
SP_NOINLINE static int sp_3072_sub_52(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 52; i++) {
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
static void sp_3072_mont_norm_52(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
    int i;

    for (i=0; i<51; i++) {
        r[i] = 0xfffffffffffffffL;
    }
    r[51] = 0xfffL;

    /* r = (2^n - 1) mod n */
    (void)sp_3072_sub_52(r, r, m);

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
static sp_digit sp_3072_cmp_52(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
    int i;

    for (i=51; i>=0; i--) {
        r |= (a[i] - b[i]) & ~(((sp_digit)0 - r) >> 59);
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
static void sp_3072_cond_sub_52(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 52; i++) {
        r[i] = a[i] - (b[i] & m);
    }
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_add_52(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t[4];
    int i;

    t[0] = 0;
    for (i = 0; i < 48; i += 4) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        r[i+0] = t[0] & 0xfffffffffffffffL;
        t[1] += t[0] >> 60;
        r[i+1] = t[1] & 0xfffffffffffffffL;
        t[2] += t[1] >> 60;
        r[i+2] = t[2] & 0xfffffffffffffffL;
        t[3] += t[2] >> 60;
        r[i+3] = t[3] & 0xfffffffffffffffL;
        t[0]  = t[3] >> 60;
    }
    t[0] += (tb * a[48]) + r[48];
    t[1]  = (tb * a[49]) + r[49];
    t[2]  = (tb * a[50]) + r[50];
    t[3]  = (tb * a[51]) + r[51];
    r[48] = t[0] & 0xfffffffffffffffL;
    t[1] += t[0] >> 60;
    r[49] = t[1] & 0xfffffffffffffffL;
    t[2] += t[1] >> 60;
    r[50] = t[2] & 0xfffffffffffffffL;
    t[3] += t[2] >> 60;
    r[51] = t[3] & 0xfffffffffffffffL;
    r[52] +=  (sp_digit)(t[3] >> 60);
}

/* Shift the result in the high 3072 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_3072_mont_shift_52(sp_digit* r, const sp_digit* a)
{
    int i;
    sp_int128 n = a[51] >> 12;
    n += ((sp_int128)a[52]) << 48;

    for (i = 0; i < 51; i++) {
        r[i] = n & 0xfffffffffffffffL;
        n >>= 60;
        n += ((sp_int128)a[53 + i]) << 48;
    }
    r[51] = (sp_digit)n;
    XMEMSET(&r[52], 0, sizeof(*r) * 52U);
}

/* Reduce the number back to 3072 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_3072_mont_reduce_52(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_3072_norm_52(a + 52);

#ifdef WOLFSSL_SP_DH
    if (mp != 1) {
        for (i=0; i<51; i++) {
            mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0xfffffffffffffffL;
            sp_3072_mul_add_52(a+i, m, mu);
            a[i+1] += a[i] >> 60;
        }
        mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0xfffL;
        sp_3072_mul_add_52(a+i, m, mu);
        a[i+1] += a[i] >> 60;
        a[i] &= 0xfffffffffffffffL;
    }
    else {
        for (i=0; i<51; i++) {
            mu = a[i] & 0xfffffffffffffffL;
            sp_3072_mul_add_52(a+i, m, mu);
            a[i+1] += a[i] >> 60;
        }
        mu = a[i] & 0xfffL;
        sp_3072_mul_add_52(a+i, m, mu);
        a[i+1] += a[i] >> 60;
        a[i] &= 0xfffffffffffffffL;
    }
#else
    for (i=0; i<51; i++) {
        mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0xfffffffffffffffL;
        sp_3072_mul_add_52(a+i, m, mu);
        a[i+1] += a[i] >> 60;
    }
    mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0xfffL;
    sp_3072_mul_add_52(a+i, m, mu);
    a[i+1] += a[i] >> 60;
    a[i] &= 0xfffffffffffffffL;
#endif
    sp_3072_mont_shift_52(a, a);
    over = a[51] - m[51];
    sp_3072_cond_sub_52(a, a, m, ~((over - 1) >> 63));
    sp_3072_norm_52(a);
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
SP_NOINLINE static void sp_3072_mont_mul_52(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_3072_mul_52(r, a, b);
    sp_3072_mont_reduce_52(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_3072_mont_sqr_52(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_3072_sqr_52(r, a);
    sp_3072_mont_reduce_52(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_d_104(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t = 0;
    int i;

    for (i = 0; i < 104; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0xfffffffffffffffL);
        t >>= 60;
    }
    r[104] = (sp_digit)t;
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
static void sp_3072_cond_add_52(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 52; i++) {
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
SP_NOINLINE static int sp_3072_add_52(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 52; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}

SP_NOINLINE static void sp_3072_rshift_52(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    for (i=0; i<51; i++) {
        r[i] = ((a[i] >> n) | (a[i + 1] << (60 - n))) & 0xfffffffffffffffL;
    }
    r[51] = a[51] >> n;
}

static WC_INLINE sp_digit sp_3072_div_word_52(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int128 d = ((sp_int128)d1 << 60) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int128 d = ((sp_int128)d1 << 60) + d0;
    sp_uint64 lo = (sp_uint64)d;
    sp_digit hi = (sp_digit)(d >> 64);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int128 d = ((sp_int128)d1 << 60) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 60);
    sp_digit t0 = (sp_digit)(d & 0xfffffffffffffffL);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int128 m;

    r = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
    t1 -= dv & (0 - r);
    for (i = 58; i >= 1; i--) {
        t1 += t1 + (((sp_uint64)t0 >> 59) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int128)r * div);
    r += (sp_digit)(m >> 60);
    m = d - ((sp_int128)r * div);
    r += (m >> 120) - (sp_digit)(d >> 120);

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;
   return r;
#else
    sp_int128 d = ((sp_int128)d1 << 60) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 29) + 1;

    t = (sp_digit)(d >> 58);
    t = (t / dv) << 29;
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)(d >> 27);
    t = t / (dv << 2);
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int128)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_3072_word_div_word_52(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint64)(div - d) >> 63);
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
static int sp_3072_div_52(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_64
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 52 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 104 + 1;
        sd = t2 + 52 + 1;

        sp_3072_mul_d_52(sd, d, (sp_digit)1 << 48);
        sp_3072_mul_d_104(t1, a, (sp_digit)1 << 48);
        dv = sd[51];
        t1[52 + 52] += t1[52 + 52 - 1] >> 60;
        t1[52 + 52 - 1] &= 0xfffffffffffffffL;
        for (i=52; i>=0; i--) {
            r1 = sp_3072_div_word_52(t1[52 + i], t1[52 + i - 1], dv);

            sp_3072_mul_d_52(t2, sd, r1);
            (void)sp_3072_sub_52(&t1[i], &t1[i], t2);
            sp_3072_norm_52(&t1[i]);
            t1[52 + i] -= t2[52];
            t1[52 + i] += t1[52 + i - 1] >> 60;
            t1[52 + i - 1] &= 0xfffffffffffffffL;
            r1 = sp_3072_div_word_52(-t1[52 + i], -t1[52 + i - 1], dv);
            r1 -= t1[52 + i];
            sp_3072_mul_d_52(t2, sd, r1);
            (void)sp_3072_add_52(&t1[i], &t1[i], t2);
            t1[52 + i] += t1[52 + i - 1] >> 60;
            t1[52 + i - 1] &= 0xfffffffffffffffL;
        }
        t1[52 - 1] += t1[52 - 2] >> 60;
        t1[52 - 2] &= 0xfffffffffffffffL;
        r1 = sp_3072_word_div_word_52(t1[52 - 1], dv);

        sp_3072_mul_d_52(t2, sd, r1);
        sp_3072_sub_52(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 104U);
        for (i=0; i<51; i++) {
            r[i+1] += r[i] >> 60;
            r[i] &= 0xfffffffffffffffL;
        }
        sp_3072_cond_add_52(r, r, sd, r[51] >> 63);

        sp_3072_norm_52(r);
        sp_3072_rshift_52(r, r, 48);
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
static int sp_3072_mod_52(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_3072_div_52(a, m, NULL, r);
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
static int sp_3072_mod_exp_52(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 104];
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
            t[i] = td + (i * 52 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 52U * 2U);
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_52(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_52(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 52U);
        }
    }
    if (err == MP_OKAY) {
        sp_3072_mul_52(t[1], t[1], norm);
        err = sp_3072_mod_52(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 60;
        c = bits % 60;
        n = e[i--] << (60 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 60;
            }

            y = (int)((n >> 59) & 1);
            n <<= 1;

            sp_3072_mont_mul_52(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 52 * 2);
            sp_3072_mont_sqr_52(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 52 * 2);
        }

        sp_3072_mont_reduce_52(t[0], m, mp);
        n = sp_3072_cmp_52(t[0], m);
        sp_3072_cond_sub_52(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 52 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 104];
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
            t[i] = td + (i * 52 * 2);
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_52(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_52(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_52(t[1], t[1], norm);
                err = sp_3072_mod_52(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_52(t[1], a, norm);
            err = sp_3072_mod_52(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 60;
        c = bits % 60;
        n = e[i--] << (60 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 60;
            }

            y = (int)((n >> 59) & 1);
            n <<= 1;

            sp_3072_mont_mul_52(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 52 * 2);
            sp_3072_mont_sqr_52(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 52 * 2);
        }

        sp_3072_mont_reduce_52(t[0], m, mp);
        n = sp_3072_cmp_52(t[0], m);
        sp_3072_cond_sub_52(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 52 * 2);
    }


    return err;
#else
    sp_digit td[(16 * 104) + 104];
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
            t[i] = td + i * 104;
        rt = td + 1664;

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_52(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_52(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_52(t[1], t[1], norm);
                err = sp_3072_mod_52(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_52(t[1], a, norm);
            err = sp_3072_mod_52(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_3072_mont_sqr_52(t[ 2], t[ 1], m, mp);
        sp_3072_mont_mul_52(t[ 3], t[ 2], t[ 1], m, mp);
        sp_3072_mont_sqr_52(t[ 4], t[ 2], m, mp);
        sp_3072_mont_mul_52(t[ 5], t[ 3], t[ 2], m, mp);
        sp_3072_mont_sqr_52(t[ 6], t[ 3], m, mp);
        sp_3072_mont_mul_52(t[ 7], t[ 4], t[ 3], m, mp);
        sp_3072_mont_sqr_52(t[ 8], t[ 4], m, mp);
        sp_3072_mont_mul_52(t[ 9], t[ 5], t[ 4], m, mp);
        sp_3072_mont_sqr_52(t[10], t[ 5], m, mp);
        sp_3072_mont_mul_52(t[11], t[ 6], t[ 5], m, mp);
        sp_3072_mont_sqr_52(t[12], t[ 6], m, mp);
        sp_3072_mont_mul_52(t[13], t[ 7], t[ 6], m, mp);
        sp_3072_mont_sqr_52(t[14], t[ 7], m, mp);
        sp_3072_mont_mul_52(t[15], t[ 8], t[ 7], m, mp);

        bits = ((bits + 3) / 4) * 4;
        i = ((bits + 59) / 60) - 1;
        c = bits % 60;
        if (c == 0) {
            c = 60;
        }
        if (i < 52) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 4) {
            n |= e[i--] << (4 - c);
            c += 60;
        }
        y = (int)((n >> 60) & 0xf);
        n <<= 4;
        c -= 4;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 104);
        while ((i >= 0) || (c >= 4)) {
            if (c >= 4) {
                y = (byte)((n >> 60) & 0xf);
                n <<= 4;
                c -= 4;
            }
            else if (c == 0) {
                n = e[i--] << 4;
                y = (byte)((n >> 60) & 0xf);
                n <<= 4;
                c = 56;
            }
            else {
                y = (byte)((n >> 60) & 0xf);
                n = e[i--] << 4;
                c = 4 - c;
                y |= (byte)((n >> (64 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 60 - c;
            }

            sp_3072_mont_sqr_52(rt, rt, m, mp);
            sp_3072_mont_sqr_52(rt, rt, m, mp);
            sp_3072_mont_sqr_52(rt, rt, m, mp);
            sp_3072_mont_sqr_52(rt, rt, m, mp);

            sp_3072_mont_mul_52(rt, rt, t[y], m, mp);
        }

        sp_3072_mont_reduce_52(rt, m, mp);
        n = sp_3072_cmp_52(rt, m);
        sp_3072_cond_sub_52(rt, rt, m, ~(n >> 63));
        XMEMCPY(r, rt, sizeof(sp_digit) * 104);
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
    sp_digit a[52 * 5];
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
        if (mp_count_bits(em) > 60) {
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
        r = a + 52 * 2;
        m = r + 52 * 2;
        norm = r;

        sp_3072_from_bin(a, 52, in, inLen);
#if DIGIT_BIT >= 60
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
        sp_3072_from_mp(m, 52, mm);

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_52(norm, m);
    }
    if (err == MP_OKAY) {
        sp_3072_mul_52(a, a, norm);
        err = sp_3072_mod_52(a, a, m);
    }
    if (err == MP_OKAY) {
        for (i=59; i>=0; i--) {
            if ((e[0] >> i) != 0) {
                break;
            }
        }

        XMEMCPY(r, a, sizeof(sp_digit) * 52 * 2);
        for (i--; i>=0; i--) {
            sp_3072_mont_sqr_52(r, r, m, mp);

            if (((e[0] >> i) & 1) == 1) {
                sp_3072_mont_mul_52(r, r, a, m, mp);
            }
        }
        sp_3072_mont_reduce_52(r, m, mp);
        mp = sp_3072_cmp_52(r, m);
        sp_3072_cond_sub_52(r, r, m, ~(mp >> 63));

        sp_3072_to_bin_52(r, out);
        *outLen = 384;
    }


    return err;
#else
    sp_digit d[52 * 5];
    sp_digit* a = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit e[1] = {0};
    int err = MP_OKAY;

    if (*outLen < 384U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 60) {
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
        r = a + 52 * 2;
        m = r + 52 * 2;

        sp_3072_from_bin(a, 52, in, inLen);
#if DIGIT_BIT >= 60
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
        sp_3072_from_mp(m, 52, mm);

        if (e[0] == 0x3) {
            sp_3072_sqr_52(r, a);
            err = sp_3072_mod_52(r, r, m);
            if (err == MP_OKAY) {
                sp_3072_mul_52(r, a, r);
                err = sp_3072_mod_52(r, r, m);
            }
        }
        else {
            sp_digit* norm = r;
            int i;
            sp_digit mp;

            sp_3072_mont_setup(m, &mp);
            sp_3072_mont_norm_52(norm, m);

            sp_3072_mul_52(a, a, norm);
            err = sp_3072_mod_52(a, a, m);

            if (err == MP_OKAY) {
                for (i=59; i>=0; i--) {
                    if ((e[0] >> i) != 0) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 104U);
                for (i--; i>=0; i--) {
                    sp_3072_mont_sqr_52(r, r, m, mp);

                    if (((e[0] >> i) & 1) == 1) {
                        sp_3072_mont_mul_52(r, r, a, m, mp);
                    }
                }
                sp_3072_mont_reduce_52(r, m, mp);
                mp = sp_3072_cmp_52(r, m);
                sp_3072_cond_sub_52(r, r, m, ~(mp >> 63));
            }
        }
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_52(r, out);
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
    sp_digit  d[52 * 4];
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
        a = d + 52;
        m = a + 104;
        r = a;

        sp_3072_from_bin(a, 52, in, inLen);
        sp_3072_from_mp(d, 52, dm);
        sp_3072_from_mp(m, 52, mm);
        err = sp_3072_mod_exp_52(r, a, d, 3072, m, 0);
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_52(r, out);
        *outLen = 384;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 52);
    }

    return err;
#else
    sp_digit d[52 * 4];
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
        a = d + 52;
        m = a + 104;
        r = a;

        sp_3072_from_bin(a, 52, in, inLen);
        sp_3072_from_mp(d, 52, dm);
        sp_3072_from_mp(m, 52, mm);
        err = sp_3072_mod_exp_52(r, a, d, 3072, m, 0);
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_52(r, out);
        *outLen = 384;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 52);
    }

    return err;
#endif /* WOLFSSL_SP_SMALL */
#else
#if defined(WOLFSSL_SP_SMALL)
    sp_digit a[26 * 8];
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
        p = a + 52;
        qi = dq = dp = p + 26;
        tmpa = qi + 26;
        tmpb = tmpa + 52;
        r = a;

        sp_3072_from_bin(a, 52, in, inLen);
        sp_3072_from_mp(p, 26, pm);
        sp_3072_from_mp(dp, 26, dpm);
        err = sp_3072_mod_exp_26(tmpa, a, dp, 1536, p, 1);
    }
    if (err == MP_OKAY) {
        sp_3072_from_mp(p, 26, qm);
        sp_3072_from_mp(dq, 26, dqm);
        err = sp_3072_mod_exp_26(tmpb, a, dq, 1536, p, 1);
    }
    if (err == MP_OKAY) {
        sp_3072_from_mp(p, 26, pm);
        (void)sp_3072_sub_26(tmpa, tmpa, tmpb);
        sp_3072_norm_26(tmpa);
        sp_3072_cond_add_26(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[25] >> 63));
        sp_3072_cond_add_26(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[25] >> 63));
        sp_3072_norm_26(tmpa);

        sp_3072_from_mp(qi, 26, qim);
        sp_3072_mul_26(tmpa, tmpa, qi);
        err = sp_3072_mod_26(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_3072_from_mp(p, 26, qm);
        sp_3072_mul_26(tmpa, p, tmpa);
        (void)sp_3072_add_52(r, tmpb, tmpa);
        sp_3072_norm_52(r);

        sp_3072_to_bin_52(r, out);
        *outLen = 384;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 26 * 8);
    }

    return err;
#else
    sp_digit a[26 * 13];
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
        p = a + 52 * 2;
        q = p + 26;
        dp = q + 26;
        dq = dp + 26;
        qi = dq + 26;
        tmpa = qi + 26;
        tmpb = tmpa + 52;
        r = a;

        sp_3072_from_bin(a, 52, in, inLen);
        sp_3072_from_mp(p, 26, pm);
        sp_3072_from_mp(q, 26, qm);
        sp_3072_from_mp(dp, 26, dpm);
        sp_3072_from_mp(dq, 26, dqm);
        sp_3072_from_mp(qi, 26, qim);

        err = sp_3072_mod_exp_26(tmpa, a, dp, 1536, p, 1);
    }
    if (err == MP_OKAY) {
        err = sp_3072_mod_exp_26(tmpb, a, dq, 1536, q, 1);
    }

    if (err == MP_OKAY) {
        (void)sp_3072_sub_26(tmpa, tmpa, tmpb);
        sp_3072_norm_26(tmpa);
        sp_3072_cond_add_26(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[25] >> 63));
        sp_3072_cond_add_26(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[25] >> 63));
        sp_3072_norm_26(tmpa);
        sp_3072_mul_26(tmpa, tmpa, qi);
        err = sp_3072_mod_26(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_3072_mul_26(tmpa, tmpa, q);
        (void)sp_3072_add_52(r, tmpb, tmpa);
        sp_3072_norm_52(r);

        sp_3072_to_bin_52(r, out);
        *outLen = 384;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 26 * 13);
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
#if DIGIT_BIT == 60
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 52);
        r->used = 52;
        mp_clamp(r);
#elif DIGIT_BIT < 60
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 52; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 60) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 60 - s;
        }
        r->used = (3072 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 52; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 60 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 60 - s;
            }
            else {
                s += 60;
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
    sp_digit b[52 * 4];
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
        e = b + 52 * 2;
        m = e + 52;
        r = b;

        sp_3072_from_mp(b, 52, base);
        sp_3072_from_mp(e, 52, exp);
        sp_3072_from_mp(m, 52, mod);

        err = sp_3072_mod_exp_52(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_3072_to_mp(r, res);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 52U);
    }
    return err;
#else
    sp_digit b[52 * 4];
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
        e = b + 52 * 2;
        m = e + 52;
        r = b;

        sp_3072_from_mp(b, 52, base);
        sp_3072_from_mp(e, 52, exp);
        sp_3072_from_mp(m, 52, mod);

        err = sp_3072_mod_exp_52(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_3072_to_mp(r, res);
    }


    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 52U);
    }

    return err;
#endif
}

#ifdef WOLFSSL_HAVE_SP_DH

#ifdef HAVE_FFDHE_3072
SP_NOINLINE static void sp_3072_lshift_52(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    r[52] = a[51] >> (60 - n);
    for (i=51; i>0; i--) {
        r[i] = ((a[i] << n) | (a[i-1] >> (60 - n))) & 0xfffffffffffffffL;
    }
    r[0] = (a[0] << n) & 0xfffffffffffffffL;
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
static int sp_3072_mod_exp_2_52(sp_digit* r, const sp_digit* e, int bits, const sp_digit* m)
{
    sp_digit td[157];
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
        tmp  = td + 104;
        XMEMSET(td, 0, sizeof(sp_digit) * 157);

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_52(norm, m);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 59) / 60) - 1;
        c = bits % 60;
        if (c == 0) {
            c = 60;
        }
        if (i < 52) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (4 - c);
            c += 60;
        }
        y = (int)((n >> 59) & 0x1f);
        n <<= 5;
        c -= 5;
        sp_3072_lshift_52(r, norm, (byte)y);
        while ((i >= 0) || (c >= 5)) {
            if (c >= 5) {
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--] << 4;
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c = 55;
            }
            else {
                y = (byte)((n >> 59) & 0x1f);
                n = e[i--] << 4;
                c = 5 - c;
                y |= (byte)((n >> (64 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 60 - c;
            }

            sp_3072_mont_sqr_52(r, r, m, mp);
            sp_3072_mont_sqr_52(r, r, m, mp);
            sp_3072_mont_sqr_52(r, r, m, mp);
            sp_3072_mont_sqr_52(r, r, m, mp);
            sp_3072_mont_sqr_52(r, r, m, mp);

            sp_3072_lshift_52(r, r, (byte)y);
            sp_3072_mul_d_52(tmp, norm, (r[52] << 48) + (r[51] >> 12));
            r[52] = 0;
            r[51] &= 0xfffL;
            (void)sp_3072_add_52(r, r, tmp);
            sp_3072_norm_52(r);
            o = sp_3072_cmp_52(r, m);
            sp_3072_cond_sub_52(r, r, m, ~(o >> 63));
        }

        sp_3072_mont_reduce_52(r, m, mp);
        n = sp_3072_cmp_52(r, m);
        sp_3072_cond_sub_52(r, r, m, ~(n >> 63));
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
    sp_digit b[52 * 4];
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
        e = b + 52 * 2;
        m = e + 52;
        r = b;

        sp_3072_from_mp(b, 52, base);
        sp_3072_from_bin(e, 52, exp, expLen);
        sp_3072_from_mp(m, 52, mod);

    #ifdef HAVE_FFDHE_3072
        if (base->used == 1 && base->dp[0] == 2U &&
                ((m[51] << 20) | (m[50] >> 40)) == 0xffffffffL) {
            err = sp_3072_mod_exp_2_52(r, e, expLen * 8U, m);
        }
        else {
    #endif
            err = sp_3072_mod_exp_52(r, b, e, expLen * 8U, m, 0);
    #ifdef HAVE_FFDHE_3072
        }
    #endif
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_52(r, out);
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
            ForceZero(e, sizeof(sp_digit) * 52U);
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
    sp_digit b[26 * 4];
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
        e = b + 26 * 2;
        m = e + 26;
        r = b;

        sp_3072_from_mp(b, 26, base);
        sp_3072_from_mp(e, 26, exp);
        sp_3072_from_mp(m, 26, mod);

        err = sp_3072_mod_exp_26(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 26, 0, sizeof(*r) * 26U);
        err = sp_3072_to_mp(r, res);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 52U);
    }
    return err;
#else
    sp_digit b[26 * 4];
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
        e = b + 26 * 2;
        m = e + 26;
        r = b;

        sp_3072_from_mp(b, 26, base);
        sp_3072_from_mp(e, 26, exp);
        sp_3072_from_mp(m, 26, mod);

        err = sp_3072_mod_exp_26(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 26, 0, sizeof(*r) * 26U);
        err = sp_3072_to_mp(r, res);
    }


    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 52U);
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
        if (s >= 49U) {
            r[j] &= 0x1ffffffffffffffL;
            s = 57U - s;
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
#if DIGIT_BIT == 57
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 57
    int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0x1ffffffffffffffL;
        s = 57U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 57U) <= (word32)DIGIT_BIT) {
            s += 57U;
            r[j] &= 0x1ffffffffffffffL;
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
        if (s + DIGIT_BIT >= 57) {
            r[j] &= 0x1ffffffffffffffL;
            if (j + 1 >= size) {
                break;
            }
            s = 57 - s;
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
static void sp_3072_to_bin_54(sp_digit* r, byte* a)
{
    int i;
    int j;
    int s = 0;
    int b;

    for (i=0; i<53; i++) {
        r[i+1] += r[i] >> 57;
        r[i] &= 0x1ffffffffffffffL;
    }
    j = 3079 / 8 - 1;
    a[j] = 0;
    for (i=0; i<54 && j>=0; i++) {
        b = 0;
        /* lint allow cast of mismatch sp_digit and int */
        a[j--] |= (byte)(r[i] << s); /*lint !e9033*/
        b += 8 - s;
        if (j < 0) {
            break;
        }
        while (b < 57) {
            a[j--] = (byte)(r[i] >> b);
            b += 8;
            if (j < 0) {
                break;
            }
        }
        s = 8 - (b - 57);
        if (j >= 0) {
            a[j] = 0;
        }
        if (s != 0) {
            j++;
        }
    }
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* Normalize the values in each word to 57 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_3072_norm_27(sp_digit* a)
{
    int i;
    for (i = 0; i < 24; i += 8) {
        a[i+1] += a[i+0] >> 57; a[i+0] &= 0x1ffffffffffffffL;
        a[i+2] += a[i+1] >> 57; a[i+1] &= 0x1ffffffffffffffL;
        a[i+3] += a[i+2] >> 57; a[i+2] &= 0x1ffffffffffffffL;
        a[i+4] += a[i+3] >> 57; a[i+3] &= 0x1ffffffffffffffL;
        a[i+5] += a[i+4] >> 57; a[i+4] &= 0x1ffffffffffffffL;
        a[i+6] += a[i+5] >> 57; a[i+5] &= 0x1ffffffffffffffL;
        a[i+7] += a[i+6] >> 57; a[i+6] &= 0x1ffffffffffffffL;
        a[i+8] += a[i+7] >> 57; a[i+7] &= 0x1ffffffffffffffL;
    }
    a[25] += a[24] >> 57; a[24] &= 0x1ffffffffffffffL;
    a[26] += a[25] >> 57; a[25] &= 0x1ffffffffffffffL;
}

#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || WOLFSSL_HAVE_SP_DH */
/* Normalize the values in each word to 57 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_3072_norm_54(sp_digit* a)
{
    int i;
    for (i = 0; i < 48; i += 8) {
        a[i+1] += a[i+0] >> 57; a[i+0] &= 0x1ffffffffffffffL;
        a[i+2] += a[i+1] >> 57; a[i+1] &= 0x1ffffffffffffffL;
        a[i+3] += a[i+2] >> 57; a[i+2] &= 0x1ffffffffffffffL;
        a[i+4] += a[i+3] >> 57; a[i+3] &= 0x1ffffffffffffffL;
        a[i+5] += a[i+4] >> 57; a[i+4] &= 0x1ffffffffffffffL;
        a[i+6] += a[i+5] >> 57; a[i+5] &= 0x1ffffffffffffffL;
        a[i+7] += a[i+6] >> 57; a[i+6] &= 0x1ffffffffffffffL;
        a[i+8] += a[i+7] >> 57; a[i+7] &= 0x1ffffffffffffffL;
    }
    a[49] += a[48] >> 57; a[48] &= 0x1ffffffffffffffL;
    a[50] += a[49] >> 57; a[49] &= 0x1ffffffffffffffL;
    a[51] += a[50] >> 57; a[50] &= 0x1ffffffffffffffL;
    a[52] += a[51] >> 57; a[51] &= 0x1ffffffffffffffL;
    a[53] += a[52] >> 57; a[52] &= 0x1ffffffffffffffL;
}

#ifndef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_9(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_uint128 t0   = ((sp_uint128)a[ 0]) * b[ 0];
    sp_uint128 t1   = ((sp_uint128)a[ 0]) * b[ 1]
                 + ((sp_uint128)a[ 1]) * b[ 0];
    sp_uint128 t2   = ((sp_uint128)a[ 0]) * b[ 2]
                 + ((sp_uint128)a[ 1]) * b[ 1]
                 + ((sp_uint128)a[ 2]) * b[ 0];
    sp_uint128 t3   = ((sp_uint128)a[ 0]) * b[ 3]
                 + ((sp_uint128)a[ 1]) * b[ 2]
                 + ((sp_uint128)a[ 2]) * b[ 1]
                 + ((sp_uint128)a[ 3]) * b[ 0];
    sp_uint128 t4   = ((sp_uint128)a[ 0]) * b[ 4]
                 + ((sp_uint128)a[ 1]) * b[ 3]
                 + ((sp_uint128)a[ 2]) * b[ 2]
                 + ((sp_uint128)a[ 3]) * b[ 1]
                 + ((sp_uint128)a[ 4]) * b[ 0];
    sp_uint128 t5   = ((sp_uint128)a[ 0]) * b[ 5]
                 + ((sp_uint128)a[ 1]) * b[ 4]
                 + ((sp_uint128)a[ 2]) * b[ 3]
                 + ((sp_uint128)a[ 3]) * b[ 2]
                 + ((sp_uint128)a[ 4]) * b[ 1]
                 + ((sp_uint128)a[ 5]) * b[ 0];
    sp_uint128 t6   = ((sp_uint128)a[ 0]) * b[ 6]
                 + ((sp_uint128)a[ 1]) * b[ 5]
                 + ((sp_uint128)a[ 2]) * b[ 4]
                 + ((sp_uint128)a[ 3]) * b[ 3]
                 + ((sp_uint128)a[ 4]) * b[ 2]
                 + ((sp_uint128)a[ 5]) * b[ 1]
                 + ((sp_uint128)a[ 6]) * b[ 0];
    sp_uint128 t7   = ((sp_uint128)a[ 0]) * b[ 7]
                 + ((sp_uint128)a[ 1]) * b[ 6]
                 + ((sp_uint128)a[ 2]) * b[ 5]
                 + ((sp_uint128)a[ 3]) * b[ 4]
                 + ((sp_uint128)a[ 4]) * b[ 3]
                 + ((sp_uint128)a[ 5]) * b[ 2]
                 + ((sp_uint128)a[ 6]) * b[ 1]
                 + ((sp_uint128)a[ 7]) * b[ 0];
    sp_uint128 t8   = ((sp_uint128)a[ 0]) * b[ 8]
                 + ((sp_uint128)a[ 1]) * b[ 7]
                 + ((sp_uint128)a[ 2]) * b[ 6]
                 + ((sp_uint128)a[ 3]) * b[ 5]
                 + ((sp_uint128)a[ 4]) * b[ 4]
                 + ((sp_uint128)a[ 5]) * b[ 3]
                 + ((sp_uint128)a[ 6]) * b[ 2]
                 + ((sp_uint128)a[ 7]) * b[ 1]
                 + ((sp_uint128)a[ 8]) * b[ 0];
    sp_uint128 t9   = ((sp_uint128)a[ 1]) * b[ 8]
                 + ((sp_uint128)a[ 2]) * b[ 7]
                 + ((sp_uint128)a[ 3]) * b[ 6]
                 + ((sp_uint128)a[ 4]) * b[ 5]
                 + ((sp_uint128)a[ 5]) * b[ 4]
                 + ((sp_uint128)a[ 6]) * b[ 3]
                 + ((sp_uint128)a[ 7]) * b[ 2]
                 + ((sp_uint128)a[ 8]) * b[ 1];
    sp_uint128 t10  = ((sp_uint128)a[ 2]) * b[ 8]
                 + ((sp_uint128)a[ 3]) * b[ 7]
                 + ((sp_uint128)a[ 4]) * b[ 6]
                 + ((sp_uint128)a[ 5]) * b[ 5]
                 + ((sp_uint128)a[ 6]) * b[ 4]
                 + ((sp_uint128)a[ 7]) * b[ 3]
                 + ((sp_uint128)a[ 8]) * b[ 2];
    sp_uint128 t11  = ((sp_uint128)a[ 3]) * b[ 8]
                 + ((sp_uint128)a[ 4]) * b[ 7]
                 + ((sp_uint128)a[ 5]) * b[ 6]
                 + ((sp_uint128)a[ 6]) * b[ 5]
                 + ((sp_uint128)a[ 7]) * b[ 4]
                 + ((sp_uint128)a[ 8]) * b[ 3];
    sp_uint128 t12  = ((sp_uint128)a[ 4]) * b[ 8]
                 + ((sp_uint128)a[ 5]) * b[ 7]
                 + ((sp_uint128)a[ 6]) * b[ 6]
                 + ((sp_uint128)a[ 7]) * b[ 5]
                 + ((sp_uint128)a[ 8]) * b[ 4];
    sp_uint128 t13  = ((sp_uint128)a[ 5]) * b[ 8]
                 + ((sp_uint128)a[ 6]) * b[ 7]
                 + ((sp_uint128)a[ 7]) * b[ 6]
                 + ((sp_uint128)a[ 8]) * b[ 5];
    sp_uint128 t14  = ((sp_uint128)a[ 6]) * b[ 8]
                 + ((sp_uint128)a[ 7]) * b[ 7]
                 + ((sp_uint128)a[ 8]) * b[ 6];
    sp_uint128 t15  = ((sp_uint128)a[ 7]) * b[ 8]
                 + ((sp_uint128)a[ 8]) * b[ 7];
    sp_uint128 t16  = ((sp_uint128)a[ 8]) * b[ 8];

    t1   += t0  >> 57; r[ 0] = t0  & 0x1ffffffffffffffL;
    t2   += t1  >> 57; r[ 1] = t1  & 0x1ffffffffffffffL;
    t3   += t2  >> 57; r[ 2] = t2  & 0x1ffffffffffffffL;
    t4   += t3  >> 57; r[ 3] = t3  & 0x1ffffffffffffffL;
    t5   += t4  >> 57; r[ 4] = t4  & 0x1ffffffffffffffL;
    t6   += t5  >> 57; r[ 5] = t5  & 0x1ffffffffffffffL;
    t7   += t6  >> 57; r[ 6] = t6  & 0x1ffffffffffffffL;
    t8   += t7  >> 57; r[ 7] = t7  & 0x1ffffffffffffffL;
    t9   += t8  >> 57; r[ 8] = t8  & 0x1ffffffffffffffL;
    t10  += t9  >> 57; r[ 9] = t9  & 0x1ffffffffffffffL;
    t11  += t10 >> 57; r[10] = t10 & 0x1ffffffffffffffL;
    t12  += t11 >> 57; r[11] = t11 & 0x1ffffffffffffffL;
    t13  += t12 >> 57; r[12] = t12 & 0x1ffffffffffffffL;
    t14  += t13 >> 57; r[13] = t13 & 0x1ffffffffffffffL;
    t15  += t14 >> 57; r[14] = t14 & 0x1ffffffffffffffL;
    t16  += t15 >> 57; r[15] = t15 & 0x1ffffffffffffffL;
    r[17] = (sp_digit)(t16 >> 57);
                       r[16] = t16 & 0x1ffffffffffffffL;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_9(sp_digit* r, const sp_digit* a,
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
SP_NOINLINE static int sp_3072_sub_18(sp_digit* r, const sp_digit* a,
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
SP_NOINLINE static int sp_3072_add_18(sp_digit* r, const sp_digit* a,
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

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_27(sp_digit* r, const sp_digit* a,
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
    (void)sp_3072_add_9(a0, a, &a[9]);
    (void)sp_3072_add_9(b0, b, &b[9]);
    (void)sp_3072_add_9(a1, &a[9], &a[18]);
    (void)sp_3072_add_9(b1, &b[9], &b[18]);
    (void)sp_3072_add_9(a2, a0, &a[18]);
    (void)sp_3072_add_9(b2, b0, &b[18]);
    sp_3072_mul_9(p0, a, b);
    sp_3072_mul_9(p2, &a[9], &b[9]);
    sp_3072_mul_9(p4, &a[18], &b[18]);
    sp_3072_mul_9(p1, a0, b0);
    sp_3072_mul_9(p3, a1, b1);
    sp_3072_mul_9(p5, a2, b2);
    XMEMSET(r, 0, sizeof(*r)*2U*27U);
    (void)sp_3072_sub_18(t0, p3, p2);
    (void)sp_3072_sub_18(t1, p1, p2);
    (void)sp_3072_sub_18(t2, p5, t0);
    (void)sp_3072_sub_18(t2, t2, t1);
    (void)sp_3072_sub_18(t0, t0, p4);
    (void)sp_3072_sub_18(t1, t1, p0);
    (void)sp_3072_add_18(r, r, p0);
    (void)sp_3072_add_18(&r[9], &r[9], t1);
    (void)sp_3072_add_18(&r[18], &r[18], t2);
    (void)sp_3072_add_18(&r[27], &r[27], t0);
    (void)sp_3072_add_18(&r[36], &r[36], p4);
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_27(sp_digit* r, const sp_digit* a,
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

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_54(sp_digit* r, const sp_digit* a,
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

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_sub_54(sp_digit* r, const sp_digit* a,
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

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_54(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[54];
    sp_digit* a1 = z1;
    sp_digit b1[27];
    sp_digit* z2 = r + 54;
    (void)sp_3072_add_27(a1, a, &a[27]);
    (void)sp_3072_add_27(b1, b, &b[27]);
    sp_3072_mul_27(z2, &a[27], &b[27]);
    sp_3072_mul_27(z0, a, b);
    sp_3072_mul_27(z1, a1, b1);
    (void)sp_3072_sub_54(z1, z1, z2);
    (void)sp_3072_sub_54(z1, z1, z0);
    (void)sp_3072_add_54(r + 27, r + 27, z1);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_9(sp_digit* r, const sp_digit* a)
{
    sp_uint128 t0   =  ((sp_uint128)a[ 0]) * a[ 0];
    sp_uint128 t1   = (((sp_uint128)a[ 0]) * a[ 1]) * 2;
    sp_uint128 t2   = (((sp_uint128)a[ 0]) * a[ 2]) * 2
                 +  ((sp_uint128)a[ 1]) * a[ 1];
    sp_uint128 t3   = (((sp_uint128)a[ 0]) * a[ 3]
                 +  ((sp_uint128)a[ 1]) * a[ 2]) * 2;
    sp_uint128 t4   = (((sp_uint128)a[ 0]) * a[ 4]
                 +  ((sp_uint128)a[ 1]) * a[ 3]) * 2
                 +  ((sp_uint128)a[ 2]) * a[ 2];
    sp_uint128 t5   = (((sp_uint128)a[ 0]) * a[ 5]
                 +  ((sp_uint128)a[ 1]) * a[ 4]
                 +  ((sp_uint128)a[ 2]) * a[ 3]) * 2;
    sp_uint128 t6   = (((sp_uint128)a[ 0]) * a[ 6]
                 +  ((sp_uint128)a[ 1]) * a[ 5]
                 +  ((sp_uint128)a[ 2]) * a[ 4]) * 2
                 +  ((sp_uint128)a[ 3]) * a[ 3];
    sp_uint128 t7   = (((sp_uint128)a[ 0]) * a[ 7]
                 +  ((sp_uint128)a[ 1]) * a[ 6]
                 +  ((sp_uint128)a[ 2]) * a[ 5]
                 +  ((sp_uint128)a[ 3]) * a[ 4]) * 2;
    sp_uint128 t8   = (((sp_uint128)a[ 0]) * a[ 8]
                 +  ((sp_uint128)a[ 1]) * a[ 7]
                 +  ((sp_uint128)a[ 2]) * a[ 6]
                 +  ((sp_uint128)a[ 3]) * a[ 5]) * 2
                 +  ((sp_uint128)a[ 4]) * a[ 4];
    sp_uint128 t9   = (((sp_uint128)a[ 1]) * a[ 8]
                 +  ((sp_uint128)a[ 2]) * a[ 7]
                 +  ((sp_uint128)a[ 3]) * a[ 6]
                 +  ((sp_uint128)a[ 4]) * a[ 5]) * 2;
    sp_uint128 t10  = (((sp_uint128)a[ 2]) * a[ 8]
                 +  ((sp_uint128)a[ 3]) * a[ 7]
                 +  ((sp_uint128)a[ 4]) * a[ 6]) * 2
                 +  ((sp_uint128)a[ 5]) * a[ 5];
    sp_uint128 t11  = (((sp_uint128)a[ 3]) * a[ 8]
                 +  ((sp_uint128)a[ 4]) * a[ 7]
                 +  ((sp_uint128)a[ 5]) * a[ 6]) * 2;
    sp_uint128 t12  = (((sp_uint128)a[ 4]) * a[ 8]
                 +  ((sp_uint128)a[ 5]) * a[ 7]) * 2
                 +  ((sp_uint128)a[ 6]) * a[ 6];
    sp_uint128 t13  = (((sp_uint128)a[ 5]) * a[ 8]
                 +  ((sp_uint128)a[ 6]) * a[ 7]) * 2;
    sp_uint128 t14  = (((sp_uint128)a[ 6]) * a[ 8]) * 2
                 +  ((sp_uint128)a[ 7]) * a[ 7];
    sp_uint128 t15  = (((sp_uint128)a[ 7]) * a[ 8]) * 2;
    sp_uint128 t16  =  ((sp_uint128)a[ 8]) * a[ 8];

    t1   += t0  >> 57; r[ 0] = t0  & 0x1ffffffffffffffL;
    t2   += t1  >> 57; r[ 1] = t1  & 0x1ffffffffffffffL;
    t3   += t2  >> 57; r[ 2] = t2  & 0x1ffffffffffffffL;
    t4   += t3  >> 57; r[ 3] = t3  & 0x1ffffffffffffffL;
    t5   += t4  >> 57; r[ 4] = t4  & 0x1ffffffffffffffL;
    t6   += t5  >> 57; r[ 5] = t5  & 0x1ffffffffffffffL;
    t7   += t6  >> 57; r[ 6] = t6  & 0x1ffffffffffffffL;
    t8   += t7  >> 57; r[ 7] = t7  & 0x1ffffffffffffffL;
    t9   += t8  >> 57; r[ 8] = t8  & 0x1ffffffffffffffL;
    t10  += t9  >> 57; r[ 9] = t9  & 0x1ffffffffffffffL;
    t11  += t10 >> 57; r[10] = t10 & 0x1ffffffffffffffL;
    t12  += t11 >> 57; r[11] = t11 & 0x1ffffffffffffffL;
    t13  += t12 >> 57; r[12] = t12 & 0x1ffffffffffffffL;
    t14  += t13 >> 57; r[13] = t13 & 0x1ffffffffffffffL;
    t15  += t14 >> 57; r[14] = t14 & 0x1ffffffffffffffL;
    t16  += t15 >> 57; r[15] = t15 & 0x1ffffffffffffffL;
    r[17] = (sp_digit)(t16 >> 57);
                       r[16] = t16 & 0x1ffffffffffffffL;
}

/* Square a into r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_27(sp_digit* r, const sp_digit* a)
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
    (void)sp_3072_add_9(a0, a, &a[9]);
    (void)sp_3072_add_9(a1, &a[9], &a[18]);
    (void)sp_3072_add_9(a2, a0, &a[18]);
    sp_3072_sqr_9(p0, a);
    sp_3072_sqr_9(p2, &a[9]);
    sp_3072_sqr_9(p4, &a[18]);
    sp_3072_sqr_9(p1, a0);
    sp_3072_sqr_9(p3, a1);
    sp_3072_sqr_9(p5, a2);
    XMEMSET(r, 0, sizeof(*r)*2U*27U);
    (void)sp_3072_sub_18(t0, p3, p2);
    (void)sp_3072_sub_18(t1, p1, p2);
    (void)sp_3072_sub_18(t2, p5, t0);
    (void)sp_3072_sub_18(t2, t2, t1);
    (void)sp_3072_sub_18(t0, t0, p4);
    (void)sp_3072_sub_18(t1, t1, p0);
    (void)sp_3072_add_18(r, r, p0);
    (void)sp_3072_add_18(&r[9], &r[9], t1);
    (void)sp_3072_add_18(&r[18], &r[18], t2);
    (void)sp_3072_add_18(&r[27], &r[27], t0);
    (void)sp_3072_add_18(&r[36], &r[36], p4);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_54(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit z1[54];
    sp_digit* a1 = z1;
    sp_digit* z2 = r + 54;
    (void)sp_3072_add_27(a1, a, &a[27]);
    sp_3072_sqr_27(z2, &a[27]);
    sp_3072_sqr_27(z0, a);
    sp_3072_sqr_27(z1, a1);
    (void)sp_3072_sub_54(z1, z1, z2);
    (void)sp_3072_sub_54(z1, z1, z0);
    (void)sp_3072_add_54(r + 27, r + 27, z1);
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
    x *= 2 - b * x;               /* here x*a==1 mod 2**64 */
    x &= 0x1ffffffffffffffL;

    /* rho = -1/m mod b */
    *rho = ((sp_digit)1 << 57) - x;
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_d_54(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t = 0;
    sp_digit t2;
    sp_int128 p[4];
    int i;

    for (i = 0; i < 52; i += 4) {
        p[0] = tb * a[i + 0];
        p[1] = tb * a[i + 1];
        p[2] = tb * a[i + 2];
        p[3] = tb * a[i + 3];
        t += p[0];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 0] = (sp_digit)t2;
        t += p[1];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 1] = (sp_digit)t2;
        t += p[2];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 2] = (sp_digit)t2;
        t += p[3];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 3] = (sp_digit)t2;
    }
    t += tb * a[52];
    r[52] = (sp_digit)(t & 0x1ffffffffffffffL);
    t >>= 57;
    t += tb * a[53];
    r[53] = (sp_digit)(t & 0x1ffffffffffffffL);
    t >>= 57;
    r[54] = (sp_digit)(t & 0x1ffffffffffffffL);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_sub_27(sp_digit* r, const sp_digit* a,
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

    return 0;
}

/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 3072 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_3072_mont_norm_27(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
    int i;

    for (i = 0; i < 24; i += 8) {
        r[i + 0] = 0x1ffffffffffffffL;
        r[i + 1] = 0x1ffffffffffffffL;
        r[i + 2] = 0x1ffffffffffffffL;
        r[i + 3] = 0x1ffffffffffffffL;
        r[i + 4] = 0x1ffffffffffffffL;
        r[i + 5] = 0x1ffffffffffffffL;
        r[i + 6] = 0x1ffffffffffffffL;
        r[i + 7] = 0x1ffffffffffffffL;
    }
    r[24] = 0x1ffffffffffffffL;
    r[25] = 0x1ffffffffffffffL;
    r[26] = 0x3fffffffffffffL;

    /* r = (2^n - 1) mod n */
    (void)sp_3072_sub_27(r, r, m);

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
static sp_digit sp_3072_cmp_27(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
    int i;

    r |= (a[26] - b[26]) & (0 - (sp_digit)1);
    r |= (a[25] - b[25]) & ~(((sp_digit)0 - r) >> 56);
    r |= (a[24] - b[24]) & ~(((sp_digit)0 - r) >> 56);
    for (i = 16; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 6] - b[i + 6]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 5] - b[i + 5]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 4] - b[i + 4]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 3] - b[i + 3]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 2] - b[i + 2]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 1] - b[i + 1]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 0] - b[i + 0]) & ~(((sp_digit)0 - r) >> 56);
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
static void sp_3072_cond_sub_27(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 24; i += 8) {
        r[i + 0] = a[i + 0] - (b[i + 0] & m);
        r[i + 1] = a[i + 1] - (b[i + 1] & m);
        r[i + 2] = a[i + 2] - (b[i + 2] & m);
        r[i + 3] = a[i + 3] - (b[i + 3] & m);
        r[i + 4] = a[i + 4] - (b[i + 4] & m);
        r[i + 5] = a[i + 5] - (b[i + 5] & m);
        r[i + 6] = a[i + 6] - (b[i + 6] & m);
        r[i + 7] = a[i + 7] - (b[i + 7] & m);
    }
    r[24] = a[24] - (b[24] & m);
    r[25] = a[25] - (b[25] & m);
    r[26] = a[26] - (b[26] & m);
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_add_27(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t[8];
    int i;

    t[0] = tb * a[0]; r[0] += (sp_digit)(t[0] & 0x1ffffffffffffffL);
    for (i = 0; i < 24; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] += (sp_digit)((t[0] >> 57) + (t[1] & 0x1ffffffffffffffL));
        t[2] = tb * a[i+2];
        r[i+2] += (sp_digit)((t[1] >> 57) + (t[2] & 0x1ffffffffffffffL));
        t[3] = tb * a[i+3];
        r[i+3] += (sp_digit)((t[2] >> 57) + (t[3] & 0x1ffffffffffffffL));
        t[4] = tb * a[i+4];
        r[i+4] += (sp_digit)((t[3] >> 57) + (t[4] & 0x1ffffffffffffffL));
        t[5] = tb * a[i+5];
        r[i+5] += (sp_digit)((t[4] >> 57) + (t[5] & 0x1ffffffffffffffL));
        t[6] = tb * a[i+6];
        r[i+6] += (sp_digit)((t[5] >> 57) + (t[6] & 0x1ffffffffffffffL));
        t[7] = tb * a[i+7];
        r[i+7] += (sp_digit)((t[6] >> 57) + (t[7] & 0x1ffffffffffffffL));
        t[0] = tb * a[i+8];
        r[i+8] += (sp_digit)((t[7] >> 57) + (t[0] & 0x1ffffffffffffffL));
    }
    t[1] = tb * a[25];
    r[25] += (sp_digit)((t[0] >> 57) + (t[1] & 0x1ffffffffffffffL));
    t[2] = tb * a[26];
    r[26] += (sp_digit)((t[1] >> 57) + (t[2] & 0x1ffffffffffffffL));
    r[27] +=  (sp_digit)(t[2] >> 57);
}

/* Shift the result in the high 1536 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_3072_mont_shift_27(sp_digit* r, const sp_digit* a)
{
    sp_digit n;
    sp_digit s;
    int i;

    s = a[27]; n = a[26] >> 54;
    for (i = 0; i < 24; i += 8) {
        n += (s & 0x1ffffffffffffffL) << 3; r[i+0] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+28] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 3; r[i+1] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+29] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 3; r[i+2] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+30] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 3; r[i+3] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+31] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 3; r[i+4] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+32] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 3; r[i+5] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+33] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 3; r[i+6] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+34] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 3; r[i+7] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+35] + (s >> 57);
    }
    n += (s & 0x1ffffffffffffffL) << 3; r[24] = n & 0x1ffffffffffffffL;
    n >>= 57; s = a[52] + (s >> 57);
    n += (s & 0x1ffffffffffffffL) << 3; r[25] = n & 0x1ffffffffffffffL;
    n >>= 57; s = a[53] + (s >> 57);
    n += s << 3;              r[26] = n;
    XMEMSET(&r[27], 0, sizeof(*r) * 27U);
}

/* Reduce the number back to 3072 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_3072_mont_reduce_27(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_3072_norm_27(a + 27);

    for (i=0; i<26; i++) {
        mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x1ffffffffffffffL;
        sp_3072_mul_add_27(a+i, m, mu);
        a[i+1] += a[i] >> 57;
    }
    mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x3fffffffffffffL;
    sp_3072_mul_add_27(a+i, m, mu);
    a[i+1] += a[i] >> 57;
    a[i] &= 0x1ffffffffffffffL;
    sp_3072_mont_shift_27(a, a);
    over = a[26] - m[26];
    sp_3072_cond_sub_27(a, a, m, ~((over - 1) >> 63));
    sp_3072_norm_27(a);
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
SP_NOINLINE static void sp_3072_mont_mul_27(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_3072_mul_27(r, a, b);
    sp_3072_mont_reduce_27(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_3072_mont_sqr_27(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_3072_sqr_27(r, a);
    sp_3072_mont_reduce_27(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_d_27(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t = 0;
    sp_digit t2;
    sp_int128 p[4];
    int i;

    for (i = 0; i < 24; i += 4) {
        p[0] = tb * a[i + 0];
        p[1] = tb * a[i + 1];
        p[2] = tb * a[i + 2];
        p[3] = tb * a[i + 3];
        t += p[0];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 0] = (sp_digit)t2;
        t += p[1];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 1] = (sp_digit)t2;
        t += p[2];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 2] = (sp_digit)t2;
        t += p[3];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 3] = (sp_digit)t2;
    }
    t += tb * a[24];
    r[24] = (sp_digit)(t & 0x1ffffffffffffffL);
    t >>= 57;
    t += tb * a[25];
    r[25] = (sp_digit)(t & 0x1ffffffffffffffL);
    t >>= 57;
    t += tb * a[26];
    r[26] = (sp_digit)(t & 0x1ffffffffffffffL);
    t >>= 57;
    r[27] = (sp_digit)(t & 0x1ffffffffffffffL);
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
static void sp_3072_cond_add_27(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 24; i += 8) {
        r[i + 0] = a[i + 0] + (b[i + 0] & m);
        r[i + 1] = a[i + 1] + (b[i + 1] & m);
        r[i + 2] = a[i + 2] + (b[i + 2] & m);
        r[i + 3] = a[i + 3] + (b[i + 3] & m);
        r[i + 4] = a[i + 4] + (b[i + 4] & m);
        r[i + 5] = a[i + 5] + (b[i + 5] & m);
        r[i + 6] = a[i + 6] + (b[i + 6] & m);
        r[i + 7] = a[i + 7] + (b[i + 7] & m);
    }
    r[24] = a[24] + (b[24] & m);
    r[25] = a[25] + (b[25] & m);
    r[26] = a[26] + (b[26] & m);
}
#endif /* !WOLFSSL_SP_SMALL */

SP_NOINLINE static void sp_3072_rshift_27(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    for (i=0; i<24; i += 8) {
        r[i+0] = (a[i+0] >> n) | ((a[i+1] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+1] = (a[i+1] >> n) | ((a[i+2] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+2] = (a[i+2] >> n) | ((a[i+3] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+3] = (a[i+3] >> n) | ((a[i+4] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+4] = (a[i+4] >> n) | ((a[i+5] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+5] = (a[i+5] >> n) | ((a[i+6] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+6] = (a[i+6] >> n) | ((a[i+7] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+7] = (a[i+7] >> n) | ((a[i+8] << (57 - n)) & 0x1ffffffffffffffL);
    }
    r[24] = (a[24] >> n) | ((a[25] << (57 - n)) & 0x1ffffffffffffffL);
    r[25] = (a[25] >> n) | ((a[26] << (57 - n)) & 0x1ffffffffffffffL);
    r[26] = a[26] >> n;
}

static WC_INLINE sp_digit sp_3072_div_word_27(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int128 d = ((sp_int128)d1 << 57) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int128 d = ((sp_int128)d1 << 57) + d0;
    sp_uint64 lo = (sp_uint64)d;
    sp_digit hi = (sp_digit)(d >> 64);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int128 d = ((sp_int128)d1 << 57) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 57);
    sp_digit t0 = (sp_digit)(d & 0x1ffffffffffffffL);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int128 m;

    r = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
    t1 -= dv & (0 - r);
    for (i = 55; i >= 1; i--) {
        t1 += t1 + (((sp_uint64)t0 >> 56) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int128)r * div);
    r += (sp_digit)(m >> 57);
    m = d - ((sp_int128)r * div);
    r += (m >> 114) - (sp_digit)(d >> 114);

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;
   return r;
#else
    sp_int128 d = ((sp_int128)d1 << 57) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 26) + 1;

    t = (sp_digit)(d >> 52);
    t = (t / dv) << 26;
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)(d >> 21);
    t = t / (dv << 5);
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int128)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_3072_word_div_word_27(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint64)(div - d) >> 63);
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
static int sp_3072_div_27(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_64
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 27 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 54 + 1;
        sd = t2 + 27 + 1;

        sp_3072_mul_d_27(sd, d, (sp_digit)1 << 3);
        sp_3072_mul_d_54(t1, a, (sp_digit)1 << 3);
        dv = sd[26];
        t1[27 + 27] += t1[27 + 27 - 1] >> 57;
        t1[27 + 27 - 1] &= 0x1ffffffffffffffL;
        for (i=27; i>=0; i--) {
            r1 = sp_3072_div_word_27(t1[27 + i], t1[27 + i - 1], dv);

            sp_3072_mul_d_27(t2, sd, r1);
            (void)sp_3072_sub_27(&t1[i], &t1[i], t2);
            sp_3072_norm_27(&t1[i]);
            t1[27 + i] -= t2[27];
            t1[27 + i] += t1[27 + i - 1] >> 57;
            t1[27 + i - 1] &= 0x1ffffffffffffffL;
            r1 = sp_3072_div_word_27(-t1[27 + i], -t1[27 + i - 1], dv);
            r1 -= t1[27 + i];
            sp_3072_mul_d_27(t2, sd, r1);
            (void)sp_3072_add_27(&t1[i], &t1[i], t2);
            t1[27 + i] += t1[27 + i - 1] >> 57;
            t1[27 + i - 1] &= 0x1ffffffffffffffL;
        }
        t1[27 - 1] += t1[27 - 2] >> 57;
        t1[27 - 2] &= 0x1ffffffffffffffL;
        r1 = sp_3072_word_div_word_27(t1[27 - 1], dv);

        sp_3072_mul_d_27(t2, sd, r1);
        sp_3072_sub_27(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 54U);
        for (i=0; i<26; i++) {
            r[i+1] += r[i] >> 57;
            r[i] &= 0x1ffffffffffffffL;
        }
        sp_3072_cond_add_27(r, r, sd, r[26] >> 63);

        sp_3072_norm_27(r);
        sp_3072_rshift_27(r, r, 3);
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
static int sp_3072_mod_27(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_3072_div_27(a, m, NULL, r);
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
static int sp_3072_mod_exp_27(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 54];
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
            t[i] = td + (i * 27 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 27U * 2U);
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_27(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_27(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 27U);
        }
    }
    if (err == MP_OKAY) {
        sp_3072_mul_27(t[1], t[1], norm);
        err = sp_3072_mod_27(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 57;
        c = bits % 57;
        n = e[i--] << (57 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 57;
            }

            y = (int)((n >> 56) & 1);
            n <<= 1;

            sp_3072_mont_mul_27(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 27 * 2);
            sp_3072_mont_sqr_27(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 27 * 2);
        }

        sp_3072_mont_reduce_27(t[0], m, mp);
        n = sp_3072_cmp_27(t[0], m);
        sp_3072_cond_sub_27(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 27 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 54];
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
            t[i] = td + (i * 27 * 2);
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_27(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_27(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_27(t[1], t[1], norm);
                err = sp_3072_mod_27(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_27(t[1], a, norm);
            err = sp_3072_mod_27(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 57;
        c = bits % 57;
        n = e[i--] << (57 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 57;
            }

            y = (int)((n >> 56) & 1);
            n <<= 1;

            sp_3072_mont_mul_27(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 27 * 2);
            sp_3072_mont_sqr_27(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 27 * 2);
        }

        sp_3072_mont_reduce_27(t[0], m, mp);
        n = sp_3072_cmp_27(t[0], m);
        sp_3072_cond_sub_27(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 27 * 2);
    }


    return err;
#else
    sp_digit td[(32 * 54) + 54];
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
            t[i] = td + i * 54;
        rt = td + 1728;

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_27(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_27(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_27(t[1], t[1], norm);
                err = sp_3072_mod_27(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_27(t[1], a, norm);
            err = sp_3072_mod_27(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_3072_mont_sqr_27(t[ 2], t[ 1], m, mp);
        sp_3072_mont_mul_27(t[ 3], t[ 2], t[ 1], m, mp);
        sp_3072_mont_sqr_27(t[ 4], t[ 2], m, mp);
        sp_3072_mont_mul_27(t[ 5], t[ 3], t[ 2], m, mp);
        sp_3072_mont_sqr_27(t[ 6], t[ 3], m, mp);
        sp_3072_mont_mul_27(t[ 7], t[ 4], t[ 3], m, mp);
        sp_3072_mont_sqr_27(t[ 8], t[ 4], m, mp);
        sp_3072_mont_mul_27(t[ 9], t[ 5], t[ 4], m, mp);
        sp_3072_mont_sqr_27(t[10], t[ 5], m, mp);
        sp_3072_mont_mul_27(t[11], t[ 6], t[ 5], m, mp);
        sp_3072_mont_sqr_27(t[12], t[ 6], m, mp);
        sp_3072_mont_mul_27(t[13], t[ 7], t[ 6], m, mp);
        sp_3072_mont_sqr_27(t[14], t[ 7], m, mp);
        sp_3072_mont_mul_27(t[15], t[ 8], t[ 7], m, mp);
        sp_3072_mont_sqr_27(t[16], t[ 8], m, mp);
        sp_3072_mont_mul_27(t[17], t[ 9], t[ 8], m, mp);
        sp_3072_mont_sqr_27(t[18], t[ 9], m, mp);
        sp_3072_mont_mul_27(t[19], t[10], t[ 9], m, mp);
        sp_3072_mont_sqr_27(t[20], t[10], m, mp);
        sp_3072_mont_mul_27(t[21], t[11], t[10], m, mp);
        sp_3072_mont_sqr_27(t[22], t[11], m, mp);
        sp_3072_mont_mul_27(t[23], t[12], t[11], m, mp);
        sp_3072_mont_sqr_27(t[24], t[12], m, mp);
        sp_3072_mont_mul_27(t[25], t[13], t[12], m, mp);
        sp_3072_mont_sqr_27(t[26], t[13], m, mp);
        sp_3072_mont_mul_27(t[27], t[14], t[13], m, mp);
        sp_3072_mont_sqr_27(t[28], t[14], m, mp);
        sp_3072_mont_mul_27(t[29], t[15], t[14], m, mp);
        sp_3072_mont_sqr_27(t[30], t[15], m, mp);
        sp_3072_mont_mul_27(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 56) / 57) - 1;
        c = bits % 57;
        if (c == 0) {
            c = 57;
        }
        if (i < 27) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (7 - c);
            c += 57;
        }
        y = (int)((n >> 59) & 0x1f);
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 54);
        while ((i >= 0) || (c >= 5)) {
            if (c >= 5) {
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--] << 7;
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c = 52;
            }
            else {
                y = (byte)((n >> 59) & 0x1f);
                n = e[i--] << 7;
                c = 5 - c;
                y |= (byte)((n >> (64 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 57 - c;
            }

            sp_3072_mont_sqr_27(rt, rt, m, mp);
            sp_3072_mont_sqr_27(rt, rt, m, mp);
            sp_3072_mont_sqr_27(rt, rt, m, mp);
            sp_3072_mont_sqr_27(rt, rt, m, mp);
            sp_3072_mont_sqr_27(rt, rt, m, mp);

            sp_3072_mont_mul_27(rt, rt, t[y], m, mp);
        }

        sp_3072_mont_reduce_27(rt, m, mp);
        n = sp_3072_cmp_27(rt, m);
        sp_3072_cond_sub_27(rt, rt, m, ~(n >> 63));
        XMEMCPY(r, rt, sizeof(sp_digit) * 54);
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
static void sp_3072_mont_norm_54(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
    int i;

    for (i = 0; i < 48; i += 8) {
        r[i + 0] = 0x1ffffffffffffffL;
        r[i + 1] = 0x1ffffffffffffffL;
        r[i + 2] = 0x1ffffffffffffffL;
        r[i + 3] = 0x1ffffffffffffffL;
        r[i + 4] = 0x1ffffffffffffffL;
        r[i + 5] = 0x1ffffffffffffffL;
        r[i + 6] = 0x1ffffffffffffffL;
        r[i + 7] = 0x1ffffffffffffffL;
    }
    r[48] = 0x1ffffffffffffffL;
    r[49] = 0x1ffffffffffffffL;
    r[50] = 0x1ffffffffffffffL;
    r[51] = 0x1ffffffffffffffL;
    r[52] = 0x1ffffffffffffffL;
    r[53] = 0x7ffffffffffffL;

    /* r = (2^n - 1) mod n */
    (void)sp_3072_sub_54(r, r, m);

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
static sp_digit sp_3072_cmp_54(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
    int i;

    r |= (a[53] - b[53]) & (0 - (sp_digit)1);
    r |= (a[52] - b[52]) & ~(((sp_digit)0 - r) >> 56);
    r |= (a[51] - b[51]) & ~(((sp_digit)0 - r) >> 56);
    r |= (a[50] - b[50]) & ~(((sp_digit)0 - r) >> 56);
    r |= (a[49] - b[49]) & ~(((sp_digit)0 - r) >> 56);
    r |= (a[48] - b[48]) & ~(((sp_digit)0 - r) >> 56);
    for (i = 40; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 6] - b[i + 6]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 5] - b[i + 5]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 4] - b[i + 4]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 3] - b[i + 3]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 2] - b[i + 2]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 1] - b[i + 1]) & ~(((sp_digit)0 - r) >> 56);
        r |= (a[i + 0] - b[i + 0]) & ~(((sp_digit)0 - r) >> 56);
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
static void sp_3072_cond_sub_54(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 48; i += 8) {
        r[i + 0] = a[i + 0] - (b[i + 0] & m);
        r[i + 1] = a[i + 1] - (b[i + 1] & m);
        r[i + 2] = a[i + 2] - (b[i + 2] & m);
        r[i + 3] = a[i + 3] - (b[i + 3] & m);
        r[i + 4] = a[i + 4] - (b[i + 4] & m);
        r[i + 5] = a[i + 5] - (b[i + 5] & m);
        r[i + 6] = a[i + 6] - (b[i + 6] & m);
        r[i + 7] = a[i + 7] - (b[i + 7] & m);
    }
    r[48] = a[48] - (b[48] & m);
    r[49] = a[49] - (b[49] & m);
    r[50] = a[50] - (b[50] & m);
    r[51] = a[51] - (b[51] & m);
    r[52] = a[52] - (b[52] & m);
    r[53] = a[53] - (b[53] & m);
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_add_54(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t[8];
    int i;

    t[0] = tb * a[0]; r[0] += (sp_digit)(t[0] & 0x1ffffffffffffffL);
    for (i = 0; i < 48; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] += (sp_digit)((t[0] >> 57) + (t[1] & 0x1ffffffffffffffL));
        t[2] = tb * a[i+2];
        r[i+2] += (sp_digit)((t[1] >> 57) + (t[2] & 0x1ffffffffffffffL));
        t[3] = tb * a[i+3];
        r[i+3] += (sp_digit)((t[2] >> 57) + (t[3] & 0x1ffffffffffffffL));
        t[4] = tb * a[i+4];
        r[i+4] += (sp_digit)((t[3] >> 57) + (t[4] & 0x1ffffffffffffffL));
        t[5] = tb * a[i+5];
        r[i+5] += (sp_digit)((t[4] >> 57) + (t[5] & 0x1ffffffffffffffL));
        t[6] = tb * a[i+6];
        r[i+6] += (sp_digit)((t[5] >> 57) + (t[6] & 0x1ffffffffffffffL));
        t[7] = tb * a[i+7];
        r[i+7] += (sp_digit)((t[6] >> 57) + (t[7] & 0x1ffffffffffffffL));
        t[0] = tb * a[i+8];
        r[i+8] += (sp_digit)((t[7] >> 57) + (t[0] & 0x1ffffffffffffffL));
    }
    t[1] = tb * a[49];
    r[49] += (sp_digit)((t[0] >> 57) + (t[1] & 0x1ffffffffffffffL));
    t[2] = tb * a[50];
    r[50] += (sp_digit)((t[1] >> 57) + (t[2] & 0x1ffffffffffffffL));
    t[3] = tb * a[51];
    r[51] += (sp_digit)((t[2] >> 57) + (t[3] & 0x1ffffffffffffffL));
    t[4] = tb * a[52];
    r[52] += (sp_digit)((t[3] >> 57) + (t[4] & 0x1ffffffffffffffL));
    t[5] = tb * a[53];
    r[53] += (sp_digit)((t[4] >> 57) + (t[5] & 0x1ffffffffffffffL));
    r[54] +=  (sp_digit)(t[5] >> 57);
}

/* Shift the result in the high 3072 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_3072_mont_shift_54(sp_digit* r, const sp_digit* a)
{
    int i;
    sp_int128 n = a[53] >> 51;
    n += ((sp_int128)a[54]) << 6;
    for (i = 0; i < 48; i += 8) {
        r[i + 0] = n & 0x1ffffffffffffffL;
        n >>= 57; n += ((sp_int128)a[i + 55]) << 6;
        r[i + 1] = n & 0x1ffffffffffffffL;
        n >>= 57; n += ((sp_int128)a[i + 56]) << 6;
        r[i + 2] = n & 0x1ffffffffffffffL;
        n >>= 57; n += ((sp_int128)a[i + 57]) << 6;
        r[i + 3] = n & 0x1ffffffffffffffL;
        n >>= 57; n += ((sp_int128)a[i + 58]) << 6;
        r[i + 4] = n & 0x1ffffffffffffffL;
        n >>= 57; n += ((sp_int128)a[i + 59]) << 6;
        r[i + 5] = n & 0x1ffffffffffffffL;
        n >>= 57; n += ((sp_int128)a[i + 60]) << 6;
        r[i + 6] = n & 0x1ffffffffffffffL;
        n >>= 57; n += ((sp_int128)a[i + 61]) << 6;
        r[i + 7] = n & 0x1ffffffffffffffL;
        n >>= 57; n += ((sp_int128)a[i + 62]) << 6;
    }
    r[48] = n & 0x1ffffffffffffffL; n >>= 57; n += ((sp_int128)a[103]) << 6;
    r[49] = n & 0x1ffffffffffffffL; n >>= 57; n += ((sp_int128)a[104]) << 6;
    r[50] = n & 0x1ffffffffffffffL; n >>= 57; n += ((sp_int128)a[105]) << 6;
    r[51] = n & 0x1ffffffffffffffL; n >>= 57; n += ((sp_int128)a[106]) << 6;
    r[52] = n & 0x1ffffffffffffffL; n >>= 57; n += ((sp_int128)a[107]) << 6;
    r[53] = (sp_digit)n;
    XMEMSET(&r[54], 0, sizeof(*r) * 54U);
}

/* Reduce the number back to 3072 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_3072_mont_reduce_54(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_3072_norm_54(a + 54);

#ifdef WOLFSSL_SP_DH
    if (mp != 1) {
        for (i=0; i<53; i++) {
            mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x1ffffffffffffffL;
            sp_3072_mul_add_54(a+i, m, mu);
            a[i+1] += a[i] >> 57;
        }
        mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x7ffffffffffffL;
        sp_3072_mul_add_54(a+i, m, mu);
        a[i+1] += a[i] >> 57;
        a[i] &= 0x1ffffffffffffffL;
    }
    else {
        for (i=0; i<53; i++) {
            mu = a[i] & 0x1ffffffffffffffL;
            sp_3072_mul_add_54(a+i, m, mu);
            a[i+1] += a[i] >> 57;
        }
        mu = a[i] & 0x7ffffffffffffL;
        sp_3072_mul_add_54(a+i, m, mu);
        a[i+1] += a[i] >> 57;
        a[i] &= 0x1ffffffffffffffL;
    }
#else
    for (i=0; i<53; i++) {
        mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x1ffffffffffffffL;
        sp_3072_mul_add_54(a+i, m, mu);
        a[i+1] += a[i] >> 57;
    }
    mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x7ffffffffffffL;
    sp_3072_mul_add_54(a+i, m, mu);
    a[i+1] += a[i] >> 57;
    a[i] &= 0x1ffffffffffffffL;
#endif
    sp_3072_mont_shift_54(a, a);
    over = a[53] - m[53];
    sp_3072_cond_sub_54(a, a, m, ~((over - 1) >> 63));
    sp_3072_norm_54(a);
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
SP_NOINLINE static void sp_3072_mont_mul_54(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_3072_mul_54(r, a, b);
    sp_3072_mont_reduce_54(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_3072_mont_sqr_54(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_3072_sqr_54(r, a);
    sp_3072_mont_reduce_54(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_d_108(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t = 0;
    sp_digit t2;
    sp_int128 p[4];
    int i;

    for (i = 0; i < 108; i += 4) {
        p[0] = tb * a[i + 0];
        p[1] = tb * a[i + 1];
        p[2] = tb * a[i + 2];
        p[3] = tb * a[i + 3];
        t += p[0];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 0] = (sp_digit)t2;
        t += p[1];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 1] = (sp_digit)t2;
        t += p[2];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 2] = (sp_digit)t2;
        t += p[3];
        t2 = (sp_digit)(t & 0x1ffffffffffffffL);
        t >>= 57;
        r[i + 3] = (sp_digit)t2;
    }
    r[108] = (sp_digit)(t & 0x1ffffffffffffffL);
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
static void sp_3072_cond_add_54(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 48; i += 8) {
        r[i + 0] = a[i + 0] + (b[i + 0] & m);
        r[i + 1] = a[i + 1] + (b[i + 1] & m);
        r[i + 2] = a[i + 2] + (b[i + 2] & m);
        r[i + 3] = a[i + 3] + (b[i + 3] & m);
        r[i + 4] = a[i + 4] + (b[i + 4] & m);
        r[i + 5] = a[i + 5] + (b[i + 5] & m);
        r[i + 6] = a[i + 6] + (b[i + 6] & m);
        r[i + 7] = a[i + 7] + (b[i + 7] & m);
    }
    r[48] = a[48] + (b[48] & m);
    r[49] = a[49] + (b[49] & m);
    r[50] = a[50] + (b[50] & m);
    r[51] = a[51] + (b[51] & m);
    r[52] = a[52] + (b[52] & m);
    r[53] = a[53] + (b[53] & m);
}
#endif /* !WOLFSSL_SP_SMALL */

SP_NOINLINE static void sp_3072_rshift_54(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    for (i=0; i<48; i += 8) {
        r[i+0] = (a[i+0] >> n) | ((a[i+1] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+1] = (a[i+1] >> n) | ((a[i+2] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+2] = (a[i+2] >> n) | ((a[i+3] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+3] = (a[i+3] >> n) | ((a[i+4] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+4] = (a[i+4] >> n) | ((a[i+5] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+5] = (a[i+5] >> n) | ((a[i+6] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+6] = (a[i+6] >> n) | ((a[i+7] << (57 - n)) & 0x1ffffffffffffffL);
        r[i+7] = (a[i+7] >> n) | ((a[i+8] << (57 - n)) & 0x1ffffffffffffffL);
    }
    r[48] = (a[48] >> n) | ((a[49] << (57 - n)) & 0x1ffffffffffffffL);
    r[49] = (a[49] >> n) | ((a[50] << (57 - n)) & 0x1ffffffffffffffL);
    r[50] = (a[50] >> n) | ((a[51] << (57 - n)) & 0x1ffffffffffffffL);
    r[51] = (a[51] >> n) | ((a[52] << (57 - n)) & 0x1ffffffffffffffL);
    r[52] = (a[52] >> n) | ((a[53] << (57 - n)) & 0x1ffffffffffffffL);
    r[53] = a[53] >> n;
}

static WC_INLINE sp_digit sp_3072_div_word_54(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int128 d = ((sp_int128)d1 << 57) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int128 d = ((sp_int128)d1 << 57) + d0;
    sp_uint64 lo = (sp_uint64)d;
    sp_digit hi = (sp_digit)(d >> 64);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int128 d = ((sp_int128)d1 << 57) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 57);
    sp_digit t0 = (sp_digit)(d & 0x1ffffffffffffffL);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int128 m;

    r = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
    t1 -= dv & (0 - r);
    for (i = 55; i >= 1; i--) {
        t1 += t1 + (((sp_uint64)t0 >> 56) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int128)r * div);
    r += (sp_digit)(m >> 57);
    m = d - ((sp_int128)r * div);
    r += (m >> 114) - (sp_digit)(d >> 114);

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;
   return r;
#else
    sp_int128 d = ((sp_int128)d1 << 57) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 26) + 1;

    t = (sp_digit)(d >> 52);
    t = (t / dv) << 26;
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)(d >> 21);
    t = t / (dv << 5);
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int128)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_3072_word_div_word_54(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint64)(div - d) >> 63);
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
static int sp_3072_div_54(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_64
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 54 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 108 + 1;
        sd = t2 + 54 + 1;

        sp_3072_mul_d_54(sd, d, (sp_digit)1 << 6);
        sp_3072_mul_d_108(t1, a, (sp_digit)1 << 6);
        dv = sd[53];
        t1[54 + 54] += t1[54 + 54 - 1] >> 57;
        t1[54 + 54 - 1] &= 0x1ffffffffffffffL;
        for (i=54; i>=0; i--) {
            r1 = sp_3072_div_word_54(t1[54 + i], t1[54 + i - 1], dv);

            sp_3072_mul_d_54(t2, sd, r1);
            (void)sp_3072_sub_54(&t1[i], &t1[i], t2);
            sp_3072_norm_54(&t1[i]);
            t1[54 + i] -= t2[54];
            t1[54 + i] += t1[54 + i - 1] >> 57;
            t1[54 + i - 1] &= 0x1ffffffffffffffL;
            r1 = sp_3072_div_word_54(-t1[54 + i], -t1[54 + i - 1], dv);
            r1 -= t1[54 + i];
            sp_3072_mul_d_54(t2, sd, r1);
            (void)sp_3072_add_54(&t1[i], &t1[i], t2);
            t1[54 + i] += t1[54 + i - 1] >> 57;
            t1[54 + i - 1] &= 0x1ffffffffffffffL;
        }
        t1[54 - 1] += t1[54 - 2] >> 57;
        t1[54 - 2] &= 0x1ffffffffffffffL;
        r1 = sp_3072_word_div_word_54(t1[54 - 1], dv);

        sp_3072_mul_d_54(t2, sd, r1);
        sp_3072_sub_54(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 108U);
        for (i=0; i<53; i++) {
            r[i+1] += r[i] >> 57;
            r[i] &= 0x1ffffffffffffffL;
        }
        sp_3072_cond_add_54(r, r, sd, r[53] >> 63);

        sp_3072_norm_54(r);
        sp_3072_rshift_54(r, r, 6);
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
static int sp_3072_mod_54(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_3072_div_54(a, m, NULL, r);
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
static int sp_3072_mod_exp_54(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 108];
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
            t[i] = td + (i * 54 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 54U * 2U);
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_54(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_54(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 54U);
        }
    }
    if (err == MP_OKAY) {
        sp_3072_mul_54(t[1], t[1], norm);
        err = sp_3072_mod_54(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 57;
        c = bits % 57;
        n = e[i--] << (57 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 57;
            }

            y = (int)((n >> 56) & 1);
            n <<= 1;

            sp_3072_mont_mul_54(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 54 * 2);
            sp_3072_mont_sqr_54(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 54 * 2);
        }

        sp_3072_mont_reduce_54(t[0], m, mp);
        n = sp_3072_cmp_54(t[0], m);
        sp_3072_cond_sub_54(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 54 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 108];
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
            t[i] = td + (i * 54 * 2);
        }

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_54(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_54(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_54(t[1], t[1], norm);
                err = sp_3072_mod_54(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_54(t[1], a, norm);
            err = sp_3072_mod_54(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 57;
        c = bits % 57;
        n = e[i--] << (57 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 57;
            }

            y = (int)((n >> 56) & 1);
            n <<= 1;

            sp_3072_mont_mul_54(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 54 * 2);
            sp_3072_mont_sqr_54(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 54 * 2);
        }

        sp_3072_mont_reduce_54(t[0], m, mp);
        n = sp_3072_cmp_54(t[0], m);
        sp_3072_cond_sub_54(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 54 * 2);
    }


    return err;
#else
    sp_digit td[(16 * 108) + 108];
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
            t[i] = td + i * 108;
        rt = td + 1728;

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_54(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_54(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_54(t[1], t[1], norm);
                err = sp_3072_mod_54(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_54(t[1], a, norm);
            err = sp_3072_mod_54(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_3072_mont_sqr_54(t[ 2], t[ 1], m, mp);
        sp_3072_mont_mul_54(t[ 3], t[ 2], t[ 1], m, mp);
        sp_3072_mont_sqr_54(t[ 4], t[ 2], m, mp);
        sp_3072_mont_mul_54(t[ 5], t[ 3], t[ 2], m, mp);
        sp_3072_mont_sqr_54(t[ 6], t[ 3], m, mp);
        sp_3072_mont_mul_54(t[ 7], t[ 4], t[ 3], m, mp);
        sp_3072_mont_sqr_54(t[ 8], t[ 4], m, mp);
        sp_3072_mont_mul_54(t[ 9], t[ 5], t[ 4], m, mp);
        sp_3072_mont_sqr_54(t[10], t[ 5], m, mp);
        sp_3072_mont_mul_54(t[11], t[ 6], t[ 5], m, mp);
        sp_3072_mont_sqr_54(t[12], t[ 6], m, mp);
        sp_3072_mont_mul_54(t[13], t[ 7], t[ 6], m, mp);
        sp_3072_mont_sqr_54(t[14], t[ 7], m, mp);
        sp_3072_mont_mul_54(t[15], t[ 8], t[ 7], m, mp);

        bits = ((bits + 3) / 4) * 4;
        i = ((bits + 56) / 57) - 1;
        c = bits % 57;
        if (c == 0) {
            c = 57;
        }
        if (i < 54) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 4) {
            n |= e[i--] << (7 - c);
            c += 57;
        }
        y = (int)((n >> 60) & 0xf);
        n <<= 4;
        c -= 4;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 108);
        while ((i >= 0) || (c >= 4)) {
            if (c >= 4) {
                y = (byte)((n >> 60) & 0xf);
                n <<= 4;
                c -= 4;
            }
            else if (c == 0) {
                n = e[i--] << 7;
                y = (byte)((n >> 60) & 0xf);
                n <<= 4;
                c = 53;
            }
            else {
                y = (byte)((n >> 60) & 0xf);
                n = e[i--] << 7;
                c = 4 - c;
                y |= (byte)((n >> (64 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 57 - c;
            }

            sp_3072_mont_sqr_54(rt, rt, m, mp);
            sp_3072_mont_sqr_54(rt, rt, m, mp);
            sp_3072_mont_sqr_54(rt, rt, m, mp);
            sp_3072_mont_sqr_54(rt, rt, m, mp);

            sp_3072_mont_mul_54(rt, rt, t[y], m, mp);
        }

        sp_3072_mont_reduce_54(rt, m, mp);
        n = sp_3072_cmp_54(rt, m);
        sp_3072_cond_sub_54(rt, rt, m, ~(n >> 63));
        XMEMCPY(r, rt, sizeof(sp_digit) * 108);
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
    sp_digit a[54 * 5];
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
        if (mp_count_bits(em) > 57) {
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
        r = a + 54 * 2;
        m = r + 54 * 2;
        norm = r;

        sp_3072_from_bin(a, 54, in, inLen);
#if DIGIT_BIT >= 57
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
        sp_3072_from_mp(m, 54, mm);

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_54(norm, m);
    }
    if (err == MP_OKAY) {
        sp_3072_mul_54(a, a, norm);
        err = sp_3072_mod_54(a, a, m);
    }
    if (err == MP_OKAY) {
        for (i=56; i>=0; i--) {
            if ((e[0] >> i) != 0) {
                break;
            }
        }

        XMEMCPY(r, a, sizeof(sp_digit) * 54 * 2);
        for (i--; i>=0; i--) {
            sp_3072_mont_sqr_54(r, r, m, mp);

            if (((e[0] >> i) & 1) == 1) {
                sp_3072_mont_mul_54(r, r, a, m, mp);
            }
        }
        sp_3072_mont_reduce_54(r, m, mp);
        mp = sp_3072_cmp_54(r, m);
        sp_3072_cond_sub_54(r, r, m, ~(mp >> 63));

        sp_3072_to_bin_54(r, out);
        *outLen = 384;
    }


    return err;
#else
    sp_digit d[54 * 5];
    sp_digit* a = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit e[1] = {0};
    int err = MP_OKAY;

    if (*outLen < 384U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 57) {
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
        r = a + 54 * 2;
        m = r + 54 * 2;

        sp_3072_from_bin(a, 54, in, inLen);
#if DIGIT_BIT >= 57
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
        sp_3072_from_mp(m, 54, mm);

        if (e[0] == 0x3) {
            sp_3072_sqr_54(r, a);
            err = sp_3072_mod_54(r, r, m);
            if (err == MP_OKAY) {
                sp_3072_mul_54(r, a, r);
                err = sp_3072_mod_54(r, r, m);
            }
        }
        else {
            sp_digit* norm = r;
            int i;
            sp_digit mp;

            sp_3072_mont_setup(m, &mp);
            sp_3072_mont_norm_54(norm, m);

            sp_3072_mul_54(a, a, norm);
            err = sp_3072_mod_54(a, a, m);

            if (err == MP_OKAY) {
                for (i=56; i>=0; i--) {
                    if ((e[0] >> i) != 0) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 108U);
                for (i--; i>=0; i--) {
                    sp_3072_mont_sqr_54(r, r, m, mp);

                    if (((e[0] >> i) & 1) == 1) {
                        sp_3072_mont_mul_54(r, r, a, m, mp);
                    }
                }
                sp_3072_mont_reduce_54(r, m, mp);
                mp = sp_3072_cmp_54(r, m);
                sp_3072_cond_sub_54(r, r, m, ~(mp >> 63));
            }
        }
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_54(r, out);
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
    sp_digit  d[54 * 4];
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
        a = d + 54;
        m = a + 108;
        r = a;

        sp_3072_from_bin(a, 54, in, inLen);
        sp_3072_from_mp(d, 54, dm);
        sp_3072_from_mp(m, 54, mm);
        err = sp_3072_mod_exp_54(r, a, d, 3072, m, 0);
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_54(r, out);
        *outLen = 384;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 54);
    }

    return err;
#else
    sp_digit d[54 * 4];
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
        a = d + 54;
        m = a + 108;
        r = a;

        sp_3072_from_bin(a, 54, in, inLen);
        sp_3072_from_mp(d, 54, dm);
        sp_3072_from_mp(m, 54, mm);
        err = sp_3072_mod_exp_54(r, a, d, 3072, m, 0);
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_54(r, out);
        *outLen = 384;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 54);
    }

    return err;
#endif /* WOLFSSL_SP_SMALL */
#else
#if defined(WOLFSSL_SP_SMALL)
    sp_digit a[27 * 8];
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
        p = a + 54;
        qi = dq = dp = p + 27;
        tmpa = qi + 27;
        tmpb = tmpa + 54;
        r = a;

        sp_3072_from_bin(a, 54, in, inLen);
        sp_3072_from_mp(p, 27, pm);
        sp_3072_from_mp(dp, 27, dpm);
        err = sp_3072_mod_exp_27(tmpa, a, dp, 1536, p, 1);
    }
    if (err == MP_OKAY) {
        sp_3072_from_mp(p, 27, qm);
        sp_3072_from_mp(dq, 27, dqm);
        err = sp_3072_mod_exp_27(tmpb, a, dq, 1536, p, 1);
    }
    if (err == MP_OKAY) {
        sp_3072_from_mp(p, 27, pm);
        (void)sp_3072_sub_27(tmpa, tmpa, tmpb);
        sp_3072_norm_27(tmpa);
        sp_3072_cond_add_27(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[26] >> 63));
        sp_3072_cond_add_27(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[26] >> 63));
        sp_3072_norm_27(tmpa);

        sp_3072_from_mp(qi, 27, qim);
        sp_3072_mul_27(tmpa, tmpa, qi);
        err = sp_3072_mod_27(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_3072_from_mp(p, 27, qm);
        sp_3072_mul_27(tmpa, p, tmpa);
        (void)sp_3072_add_54(r, tmpb, tmpa);
        sp_3072_norm_54(r);

        sp_3072_to_bin_54(r, out);
        *outLen = 384;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 27 * 8);
    }

    return err;
#else
    sp_digit a[27 * 13];
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
        p = a + 54 * 2;
        q = p + 27;
        dp = q + 27;
        dq = dp + 27;
        qi = dq + 27;
        tmpa = qi + 27;
        tmpb = tmpa + 54;
        r = a;

        sp_3072_from_bin(a, 54, in, inLen);
        sp_3072_from_mp(p, 27, pm);
        sp_3072_from_mp(q, 27, qm);
        sp_3072_from_mp(dp, 27, dpm);
        sp_3072_from_mp(dq, 27, dqm);
        sp_3072_from_mp(qi, 27, qim);

        err = sp_3072_mod_exp_27(tmpa, a, dp, 1536, p, 1);
    }
    if (err == MP_OKAY) {
        err = sp_3072_mod_exp_27(tmpb, a, dq, 1536, q, 1);
    }

    if (err == MP_OKAY) {
        (void)sp_3072_sub_27(tmpa, tmpa, tmpb);
        sp_3072_norm_27(tmpa);
        sp_3072_cond_add_27(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[26] >> 63));
        sp_3072_cond_add_27(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[26] >> 63));
        sp_3072_norm_27(tmpa);
        sp_3072_mul_27(tmpa, tmpa, qi);
        err = sp_3072_mod_27(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_3072_mul_27(tmpa, tmpa, q);
        (void)sp_3072_add_54(r, tmpb, tmpa);
        sp_3072_norm_54(r);

        sp_3072_to_bin_54(r, out);
        *outLen = 384;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 27 * 13);
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
#if DIGIT_BIT == 57
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 54);
        r->used = 54;
        mp_clamp(r);
#elif DIGIT_BIT < 57
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 54; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 57) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 57 - s;
        }
        r->used = (3072 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 54; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 57 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 57 - s;
            }
            else {
                s += 57;
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
    sp_digit b[54 * 4];
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
        e = b + 54 * 2;
        m = e + 54;
        r = b;

        sp_3072_from_mp(b, 54, base);
        sp_3072_from_mp(e, 54, exp);
        sp_3072_from_mp(m, 54, mod);

        err = sp_3072_mod_exp_54(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_3072_to_mp(r, res);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 54U);
    }
    return err;
#else
    sp_digit b[54 * 4];
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
        e = b + 54 * 2;
        m = e + 54;
        r = b;

        sp_3072_from_mp(b, 54, base);
        sp_3072_from_mp(e, 54, exp);
        sp_3072_from_mp(m, 54, mod);

        err = sp_3072_mod_exp_54(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_3072_to_mp(r, res);
    }


    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 54U);
    }

    return err;
#endif
}

#ifdef WOLFSSL_HAVE_SP_DH

#ifdef HAVE_FFDHE_3072
SP_NOINLINE static void sp_3072_lshift_54(sp_digit* r, const sp_digit* a,
        byte n)
{
    sp_int_digit s;
    sp_int_digit t;

    s = (sp_int_digit)a[53];
    r[54] = s >> (57U - n);
    s = (sp_int_digit)(a[53]); t = (sp_int_digit)(a[52]);
    r[53] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[52]); t = (sp_int_digit)(a[51]);
    r[52] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[51]); t = (sp_int_digit)(a[50]);
    r[51] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[50]); t = (sp_int_digit)(a[49]);
    r[50] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[49]); t = (sp_int_digit)(a[48]);
    r[49] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[48]); t = (sp_int_digit)(a[47]);
    r[48] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[47]); t = (sp_int_digit)(a[46]);
    r[47] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[46]); t = (sp_int_digit)(a[45]);
    r[46] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[45]); t = (sp_int_digit)(a[44]);
    r[45] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[44]); t = (sp_int_digit)(a[43]);
    r[44] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[43]); t = (sp_int_digit)(a[42]);
    r[43] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[42]); t = (sp_int_digit)(a[41]);
    r[42] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[41]); t = (sp_int_digit)(a[40]);
    r[41] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[40]); t = (sp_int_digit)(a[39]);
    r[40] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[39]); t = (sp_int_digit)(a[38]);
    r[39] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[38]); t = (sp_int_digit)(a[37]);
    r[38] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[37]); t = (sp_int_digit)(a[36]);
    r[37] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[36]); t = (sp_int_digit)(a[35]);
    r[36] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[35]); t = (sp_int_digit)(a[34]);
    r[35] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[34]); t = (sp_int_digit)(a[33]);
    r[34] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[33]); t = (sp_int_digit)(a[32]);
    r[33] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[32]); t = (sp_int_digit)(a[31]);
    r[32] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[31]); t = (sp_int_digit)(a[30]);
    r[31] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[30]); t = (sp_int_digit)(a[29]);
    r[30] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[29]); t = (sp_int_digit)(a[28]);
    r[29] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[28]); t = (sp_int_digit)(a[27]);
    r[28] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[27]); t = (sp_int_digit)(a[26]);
    r[27] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[26]); t = (sp_int_digit)(a[25]);
    r[26] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[25]); t = (sp_int_digit)(a[24]);
    r[25] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[24]); t = (sp_int_digit)(a[23]);
    r[24] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[23]); t = (sp_int_digit)(a[22]);
    r[23] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[22]); t = (sp_int_digit)(a[21]);
    r[22] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[21]); t = (sp_int_digit)(a[20]);
    r[21] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[20]); t = (sp_int_digit)(a[19]);
    r[20] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[19]); t = (sp_int_digit)(a[18]);
    r[19] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[18]); t = (sp_int_digit)(a[17]);
    r[18] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[17]); t = (sp_int_digit)(a[16]);
    r[17] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[16]); t = (sp_int_digit)(a[15]);
    r[16] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[15]); t = (sp_int_digit)(a[14]);
    r[15] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[14]); t = (sp_int_digit)(a[13]);
    r[14] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[13]); t = (sp_int_digit)(a[12]);
    r[13] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[12]); t = (sp_int_digit)(a[11]);
    r[12] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[11]); t = (sp_int_digit)(a[10]);
    r[11] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[10]); t = (sp_int_digit)(a[9]);
    r[10] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[9]); t = (sp_int_digit)(a[8]);
    r[9] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[8]); t = (sp_int_digit)(a[7]);
    r[8] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[7]); t = (sp_int_digit)(a[6]);
    r[7] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[6]); t = (sp_int_digit)(a[5]);
    r[6] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[5]); t = (sp_int_digit)(a[4]);
    r[5] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[4]); t = (sp_int_digit)(a[3]);
    r[4] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[3]); t = (sp_int_digit)(a[2]);
    r[3] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[2]); t = (sp_int_digit)(a[1]);
    r[2] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[1]); t = (sp_int_digit)(a[0]);
    r[1] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    r[0] = (a[0] << n) & 0x1ffffffffffffffL;
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
static int sp_3072_mod_exp_2_54(sp_digit* r, const sp_digit* e, int bits, const sp_digit* m)
{
    sp_digit td[163];
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
        tmp  = td + 108;
        XMEMSET(td, 0, sizeof(sp_digit) * 163);

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_54(norm, m);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 56) / 57) - 1;
        c = bits % 57;
        if (c == 0) {
            c = 57;
        }
        if (i < 54) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (7 - c);
            c += 57;
        }
        y = (int)((n >> 59) & 0x1f);
        n <<= 5;
        c -= 5;
        sp_3072_lshift_54(r, norm, (byte)y);
        while ((i >= 0) || (c >= 5)) {
            if (c >= 5) {
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--] << 7;
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c = 52;
            }
            else {
                y = (byte)((n >> 59) & 0x1f);
                n = e[i--] << 7;
                c = 5 - c;
                y |= (byte)((n >> (64 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 57 - c;
            }

            sp_3072_mont_sqr_54(r, r, m, mp);
            sp_3072_mont_sqr_54(r, r, m, mp);
            sp_3072_mont_sqr_54(r, r, m, mp);
            sp_3072_mont_sqr_54(r, r, m, mp);
            sp_3072_mont_sqr_54(r, r, m, mp);

            sp_3072_lshift_54(r, r, (byte)y);
            sp_3072_mul_d_54(tmp, norm, (r[54] << 6) + (r[53] >> 51));
            r[54] = 0;
            r[53] &= 0x7ffffffffffffL;
            (void)sp_3072_add_54(r, r, tmp);
            sp_3072_norm_54(r);
            o = sp_3072_cmp_54(r, m);
            sp_3072_cond_sub_54(r, r, m, ~(o >> 63));
        }

        sp_3072_mont_reduce_54(r, m, mp);
        n = sp_3072_cmp_54(r, m);
        sp_3072_cond_sub_54(r, r, m, ~(n >> 63));
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
    sp_digit b[54 * 4];
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
        e = b + 54 * 2;
        m = e + 54;
        r = b;

        sp_3072_from_mp(b, 54, base);
        sp_3072_from_bin(e, 54, exp, expLen);
        sp_3072_from_mp(m, 54, mod);

    #ifdef HAVE_FFDHE_3072
        if (base->used == 1 && base->dp[0] == 2U &&
                (m[53] >> 19) == 0xffffffffL) {
            err = sp_3072_mod_exp_2_54(r, e, expLen * 8U, m);
        }
        else {
    #endif
            err = sp_3072_mod_exp_54(r, b, e, expLen * 8U, m, 0);
    #ifdef HAVE_FFDHE_3072
        }
    #endif
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin_54(r, out);
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
            ForceZero(e, sizeof(sp_digit) * 54U);
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
    sp_digit b[27 * 4];
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
        e = b + 27 * 2;
        m = e + 27;
        r = b;

        sp_3072_from_mp(b, 27, base);
        sp_3072_from_mp(e, 27, exp);
        sp_3072_from_mp(m, 27, mod);

        err = sp_3072_mod_exp_27(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 27, 0, sizeof(*r) * 27U);
        err = sp_3072_to_mp(r, res);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 54U);
    }
    return err;
#else
    sp_digit b[27 * 4];
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
        e = b + 27 * 2;
        m = e + 27;
        r = b;

        sp_3072_from_mp(b, 27, base);
        sp_3072_from_mp(e, 27, exp);
        sp_3072_from_mp(m, 27, mod);

        err = sp_3072_mod_exp_27(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 27, 0, sizeof(*r) * 27U);
        err = sp_3072_to_mp(r, res);
    }


    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 54U);
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
        if (s >= 51U) {
            r[j] &= 0x7ffffffffffffffL;
            s = 59U - s;
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
#if DIGIT_BIT == 59
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 59
    int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0x7ffffffffffffffL;
        s = 59U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 59U) <= (word32)DIGIT_BIT) {
            s += 59U;
            r[j] &= 0x7ffffffffffffffL;
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
        if (s + DIGIT_BIT >= 59) {
            r[j] &= 0x7ffffffffffffffL;
            if (j + 1 >= size) {
                break;
            }
            s = 59 - s;
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
static void sp_4096_to_bin_70(sp_digit* r, byte* a)
{
    int i;
    int j;
    int s = 0;
    int b;

    for (i=0; i<69; i++) {
        r[i+1] += r[i] >> 59;
        r[i] &= 0x7ffffffffffffffL;
    }
    j = 4103 / 8 - 1;
    a[j] = 0;
    for (i=0; i<70 && j>=0; i++) {
        b = 0;
        /* lint allow cast of mismatch sp_digit and int */
        a[j--] |= (byte)(r[i] << s); /*lint !e9033*/
        b += 8 - s;
        if (j < 0) {
            break;
        }
        while (b < 59) {
            a[j--] = (byte)(r[i] >> b);
            b += 8;
            if (j < 0) {
                break;
            }
        }
        s = 8 - (b - 59);
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
/* Normalize the values in each word to 59 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_4096_norm_35(sp_digit* a)
{
    int i;
    for (i = 0; i < 34; i++) {
        a[i+1] += a[i] >> 59;
        a[i] &= 0x7ffffffffffffffL;
    }
}

#endif /* WOLFSSL_HAVE_SP_RSA & !SP_RSA_PRIVATE_EXP_D */
#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || WOLFSSL_HAVE_SP_DH */
/* Normalize the values in each word to 59 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_4096_norm_70(sp_digit* a)
{
    int i;
    for (i = 0; i < 69; i++) {
        a[i+1] += a[i] >> 59;
        a[i] &= 0x7ffffffffffffffL;
    }
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_4096_mul_70(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i;
    int imax;
    int k;
    sp_uint128 c;
    sp_uint128 lo;

    c = ((sp_uint128)a[69]) * b[69];
    r[139] = (sp_digit)(c >> 59);
    c &= 0x7ffffffffffffffL;
    for (k = 137; k >= 0; k--) {
        if (k >= 70) {
            i = k - 69;
            imax = 69;
        }
        else {
            i = 0;
            imax = k;
        }
        lo = 0;
        for (; i <= imax; i++) {
            lo += ((sp_uint128)a[i]) * b[k - i];
        }
        c += lo >> 59;
        r[k + 2] += (sp_digit)(c >> 59);
        r[k + 1]  = (sp_digit)(c & 0x7ffffffffffffffL);
        c = lo & 0x7ffffffffffffffL;
    }
    r[0] = (sp_digit)c;
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_4096_sqr_70(sp_digit* r, const sp_digit* a)
{
    int i;
    int imax;
    int k;
    sp_uint128 c;
    sp_uint128 t;

    c = ((sp_uint128)a[69]) * a[69];
    r[139] = (sp_digit)(c >> 59);
    c = (c & 0x7ffffffffffffffL) << 59;
    for (k = 137; k >= 0; k--) {
        i = (k + 1) / 2;
        if ((k & 1) == 0) {
           c += ((sp_uint128)a[i]) * a[i];
           i++;
        }
        if (k < 69) {
            imax = k;
        }
        else {
            imax = 69;
        }
        t = 0;
        for (; i <= imax; i++) {
            t += ((sp_uint128)a[i]) * a[k - i];
        }
        c += t * 2;

        r[k + 2] += (sp_digit) (c >> 118);
        r[k + 1]  = (sp_digit)((c >> 59) & 0x7ffffffffffffffL);
        c = (c & 0x7ffffffffffffffL) << 59;
    }
    r[0] = (sp_digit)(c >> 59);
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
    x *= 2 - b * x;               /* here x*a==1 mod 2**64 */
    x &= 0x7ffffffffffffffL;

    /* rho = -1/m mod b */
    *rho = ((sp_digit)1 << 59) - x;
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_d_70(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t = 0;
    int i;

    for (i = 0; i < 70; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0x7ffffffffffffffL);
        t >>= 59;
    }
    r[70] = (sp_digit)t;
}

#if (defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH)) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
#if defined(WOLFSSL_HAVE_SP_RSA) && !defined(SP_RSA_PRIVATE_EXP_D)
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_sub_35(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 35; i++) {
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
static void sp_4096_mont_norm_35(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
    int i;

    for (i=0; i<34; i++) {
        r[i] = 0x7ffffffffffffffL;
    }
    r[34] = 0x3ffffffffffL;

    /* r = (2^n - 1) mod n */
    (void)sp_4096_sub_35(r, r, m);

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
static sp_digit sp_4096_cmp_35(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
    int i;

    for (i=34; i>=0; i--) {
        r |= (a[i] - b[i]) & ~(((sp_digit)0 - r) >> 58);
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
static void sp_4096_cond_sub_35(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 35; i++) {
        r[i] = a[i] - (b[i] & m);
    }
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_add_35(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t[4];
    int i;

    t[0] = 0;
    for (i = 0; i < 32; i += 4) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        r[i+0] = t[0] & 0x7ffffffffffffffL;
        t[1] += t[0] >> 59;
        r[i+1] = t[1] & 0x7ffffffffffffffL;
        t[2] += t[1] >> 59;
        r[i+2] = t[2] & 0x7ffffffffffffffL;
        t[3] += t[2] >> 59;
        r[i+3] = t[3] & 0x7ffffffffffffffL;
        t[0]  = t[3] >> 59;
    }
    t[0] += (tb * a[32]) + r[32];
    t[1]  = (tb * a[33]) + r[33];
    t[2]  = (tb * a[34]) + r[34];
    r[32] = t[0] & 0x7ffffffffffffffL;
    t[1] += t[0] >> 59;
    r[33] = t[1] & 0x7ffffffffffffffL;
    t[2] += t[1] >> 59;
    r[34] = t[2] & 0x7ffffffffffffffL;
    r[35] +=  (sp_digit)(t[2] >> 59);
}

/* Shift the result in the high 2048 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_4096_mont_shift_35(sp_digit* r, const sp_digit* a)
{
    int i;
    sp_int128 n = a[34] >> 42;
    n += ((sp_int128)a[35]) << 17;

    for (i = 0; i < 34; i++) {
        r[i] = n & 0x7ffffffffffffffL;
        n >>= 59;
        n += ((sp_int128)a[36 + i]) << 17;
    }
    r[34] = (sp_digit)n;
    XMEMSET(&r[35], 0, sizeof(*r) * 35U);
}

/* Reduce the number back to 4096 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_4096_mont_reduce_35(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_4096_norm_35(a + 35);

    for (i=0; i<34; i++) {
        mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x7ffffffffffffffL;
        sp_4096_mul_add_35(a+i, m, mu);
        a[i+1] += a[i] >> 59;
    }
    mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x3ffffffffffL;
    sp_4096_mul_add_35(a+i, m, mu);
    a[i+1] += a[i] >> 59;
    a[i] &= 0x7ffffffffffffffL;
    sp_4096_mont_shift_35(a, a);
    over = a[34] - m[34];
    sp_4096_cond_sub_35(a, a, m, ~((over - 1) >> 63));
    sp_4096_norm_35(a);
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_4096_mul_35(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i;
    int imax;
    int k;
    sp_uint128 c;
    sp_uint128 lo;

    c = ((sp_uint128)a[34]) * b[34];
    r[69] = (sp_digit)(c >> 59);
    c &= 0x7ffffffffffffffL;
    for (k = 67; k >= 0; k--) {
        if (k >= 35) {
            i = k - 34;
            imax = 34;
        }
        else {
            i = 0;
            imax = k;
        }
        lo = 0;
        for (; i <= imax; i++) {
            lo += ((sp_uint128)a[i]) * b[k - i];
        }
        c += lo >> 59;
        r[k + 2] += (sp_digit)(c >> 59);
        r[k + 1]  = (sp_digit)(c & 0x7ffffffffffffffL);
        c = lo & 0x7ffffffffffffffL;
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
SP_NOINLINE static void sp_4096_mont_mul_35(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_4096_mul_35(r, a, b);
    sp_4096_mont_reduce_35(r, m, mp);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_4096_sqr_35(sp_digit* r, const sp_digit* a)
{
    int i;
    int imax;
    int k;
    sp_uint128 c;
    sp_uint128 t;

    c = ((sp_uint128)a[34]) * a[34];
    r[69] = (sp_digit)(c >> 59);
    c = (c & 0x7ffffffffffffffL) << 59;
    for (k = 67; k >= 0; k--) {
        i = (k + 1) / 2;
        if ((k & 1) == 0) {
           c += ((sp_uint128)a[i]) * a[i];
           i++;
        }
        if (k < 34) {
            imax = k;
        }
        else {
            imax = 34;
        }
        t = 0;
        for (; i <= imax; i++) {
            t += ((sp_uint128)a[i]) * a[k - i];
        }
        c += t * 2;

        r[k + 2] += (sp_digit) (c >> 118);
        r[k + 1]  = (sp_digit)((c >> 59) & 0x7ffffffffffffffL);
        c = (c & 0x7ffffffffffffffL) << 59;
    }
    r[0] = (sp_digit)(c >> 59);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_4096_mont_sqr_35(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_4096_sqr_35(r, a);
    sp_4096_mont_reduce_35(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_d_35(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t = 0;
    int i;

    for (i = 0; i < 35; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0x7ffffffffffffffL);
        t >>= 59;
    }
    r[35] = (sp_digit)t;
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
static void sp_4096_cond_add_35(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 35; i++) {
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
SP_NOINLINE static int sp_4096_add_35(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 35; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}

SP_NOINLINE static void sp_4096_rshift_35(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    for (i=0; i<34; i++) {
        r[i] = ((a[i] >> n) | (a[i + 1] << (59 - n))) & 0x7ffffffffffffffL;
    }
    r[34] = a[34] >> n;
}

static WC_INLINE sp_digit sp_4096_div_word_35(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int128 d = ((sp_int128)d1 << 59) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int128 d = ((sp_int128)d1 << 59) + d0;
    sp_uint64 lo = (sp_uint64)d;
    sp_digit hi = (sp_digit)(d >> 64);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int128 d = ((sp_int128)d1 << 59) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 59);
    sp_digit t0 = (sp_digit)(d & 0x7ffffffffffffffL);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int128 m;

    r = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
    t1 -= dv & (0 - r);
    for (i = 57; i >= 1; i--) {
        t1 += t1 + (((sp_uint64)t0 >> 58) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int128)r * div);
    r += (sp_digit)(m >> 59);
    m = d - ((sp_int128)r * div);
    r += (m >> 118) - (sp_digit)(d >> 118);

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;
   return r;
#else
    sp_int128 d = ((sp_int128)d1 << 59) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 28) + 1;

    t = (sp_digit)(d >> 56);
    t = (t / dv) << 28;
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)(d >> 25);
    t = t / (dv << 3);
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int128)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_4096_word_div_word_35(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint64)(div - d) >> 63);
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
static int sp_4096_div_35(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_64
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 35 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 70 + 1;
        sd = t2 + 35 + 1;

        sp_4096_mul_d_35(sd, d, (sp_digit)1 << 17);
        sp_4096_mul_d_70(t1, a, (sp_digit)1 << 17);
        dv = sd[34];
        t1[35 + 35] += t1[35 + 35 - 1] >> 59;
        t1[35 + 35 - 1] &= 0x7ffffffffffffffL;
        for (i=35; i>=0; i--) {
            r1 = sp_4096_div_word_35(t1[35 + i], t1[35 + i - 1], dv);

            sp_4096_mul_d_35(t2, sd, r1);
            (void)sp_4096_sub_35(&t1[i], &t1[i], t2);
            sp_4096_norm_35(&t1[i]);
            t1[35 + i] -= t2[35];
            t1[35 + i] += t1[35 + i - 1] >> 59;
            t1[35 + i - 1] &= 0x7ffffffffffffffL;
            r1 = sp_4096_div_word_35(-t1[35 + i], -t1[35 + i - 1], dv);
            r1 -= t1[35 + i];
            sp_4096_mul_d_35(t2, sd, r1);
            (void)sp_4096_add_35(&t1[i], &t1[i], t2);
            t1[35 + i] += t1[35 + i - 1] >> 59;
            t1[35 + i - 1] &= 0x7ffffffffffffffL;
        }
        t1[35 - 1] += t1[35 - 2] >> 59;
        t1[35 - 2] &= 0x7ffffffffffffffL;
        r1 = sp_4096_word_div_word_35(t1[35 - 1], dv);

        sp_4096_mul_d_35(t2, sd, r1);
        sp_4096_sub_35(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 70U);
        for (i=0; i<34; i++) {
            r[i+1] += r[i] >> 59;
            r[i] &= 0x7ffffffffffffffL;
        }
        sp_4096_cond_add_35(r, r, sd, r[34] >> 63);

        sp_4096_norm_35(r);
        sp_4096_rshift_35(r, r, 17);
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
static int sp_4096_mod_35(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_4096_div_35(a, m, NULL, r);
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
static int sp_4096_mod_exp_35(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 70];
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
            t[i] = td + (i * 35 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 35U * 2U);
        }

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_35(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_35(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 35U);
        }
    }
    if (err == MP_OKAY) {
        sp_4096_mul_35(t[1], t[1], norm);
        err = sp_4096_mod_35(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 59;
        c = bits % 59;
        n = e[i--] << (59 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 59;
            }

            y = (int)((n >> 58) & 1);
            n <<= 1;

            sp_4096_mont_mul_35(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 35 * 2);
            sp_4096_mont_sqr_35(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 35 * 2);
        }

        sp_4096_mont_reduce_35(t[0], m, mp);
        n = sp_4096_cmp_35(t[0], m);
        sp_4096_cond_sub_35(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 35 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 70];
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
            t[i] = td + (i * 35 * 2);
        }

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_35(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_35(t[1], a, m);
            if (err == MP_OKAY) {
                sp_4096_mul_35(t[1], t[1], norm);
                err = sp_4096_mod_35(t[1], t[1], m);
            }
        }
        else {
            sp_4096_mul_35(t[1], a, norm);
            err = sp_4096_mod_35(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 59;
        c = bits % 59;
        n = e[i--] << (59 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 59;
            }

            y = (int)((n >> 58) & 1);
            n <<= 1;

            sp_4096_mont_mul_35(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 35 * 2);
            sp_4096_mont_sqr_35(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 35 * 2);
        }

        sp_4096_mont_reduce_35(t[0], m, mp);
        n = sp_4096_cmp_35(t[0], m);
        sp_4096_cond_sub_35(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 35 * 2);
    }


    return err;
#else
    sp_digit td[(32 * 70) + 70];
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
            t[i] = td + i * 70;
        rt = td + 2240;

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_35(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_35(t[1], a, m);
            if (err == MP_OKAY) {
                sp_4096_mul_35(t[1], t[1], norm);
                err = sp_4096_mod_35(t[1], t[1], m);
            }
        }
        else {
            sp_4096_mul_35(t[1], a, norm);
            err = sp_4096_mod_35(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_4096_mont_sqr_35(t[ 2], t[ 1], m, mp);
        sp_4096_mont_mul_35(t[ 3], t[ 2], t[ 1], m, mp);
        sp_4096_mont_sqr_35(t[ 4], t[ 2], m, mp);
        sp_4096_mont_mul_35(t[ 5], t[ 3], t[ 2], m, mp);
        sp_4096_mont_sqr_35(t[ 6], t[ 3], m, mp);
        sp_4096_mont_mul_35(t[ 7], t[ 4], t[ 3], m, mp);
        sp_4096_mont_sqr_35(t[ 8], t[ 4], m, mp);
        sp_4096_mont_mul_35(t[ 9], t[ 5], t[ 4], m, mp);
        sp_4096_mont_sqr_35(t[10], t[ 5], m, mp);
        sp_4096_mont_mul_35(t[11], t[ 6], t[ 5], m, mp);
        sp_4096_mont_sqr_35(t[12], t[ 6], m, mp);
        sp_4096_mont_mul_35(t[13], t[ 7], t[ 6], m, mp);
        sp_4096_mont_sqr_35(t[14], t[ 7], m, mp);
        sp_4096_mont_mul_35(t[15], t[ 8], t[ 7], m, mp);
        sp_4096_mont_sqr_35(t[16], t[ 8], m, mp);
        sp_4096_mont_mul_35(t[17], t[ 9], t[ 8], m, mp);
        sp_4096_mont_sqr_35(t[18], t[ 9], m, mp);
        sp_4096_mont_mul_35(t[19], t[10], t[ 9], m, mp);
        sp_4096_mont_sqr_35(t[20], t[10], m, mp);
        sp_4096_mont_mul_35(t[21], t[11], t[10], m, mp);
        sp_4096_mont_sqr_35(t[22], t[11], m, mp);
        sp_4096_mont_mul_35(t[23], t[12], t[11], m, mp);
        sp_4096_mont_sqr_35(t[24], t[12], m, mp);
        sp_4096_mont_mul_35(t[25], t[13], t[12], m, mp);
        sp_4096_mont_sqr_35(t[26], t[13], m, mp);
        sp_4096_mont_mul_35(t[27], t[14], t[13], m, mp);
        sp_4096_mont_sqr_35(t[28], t[14], m, mp);
        sp_4096_mont_mul_35(t[29], t[15], t[14], m, mp);
        sp_4096_mont_sqr_35(t[30], t[15], m, mp);
        sp_4096_mont_mul_35(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 58) / 59) - 1;
        c = bits % 59;
        if (c == 0) {
            c = 59;
        }
        if (i < 35) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (5 - c);
            c += 59;
        }
        y = (int)((n >> 59) & 0x1f);
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 70);
        while ((i >= 0) || (c >= 5)) {
            if (c >= 5) {
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--] << 5;
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c = 54;
            }
            else {
                y = (byte)((n >> 59) & 0x1f);
                n = e[i--] << 5;
                c = 5 - c;
                y |= (byte)((n >> (64 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 59 - c;
            }

            sp_4096_mont_sqr_35(rt, rt, m, mp);
            sp_4096_mont_sqr_35(rt, rt, m, mp);
            sp_4096_mont_sqr_35(rt, rt, m, mp);
            sp_4096_mont_sqr_35(rt, rt, m, mp);
            sp_4096_mont_sqr_35(rt, rt, m, mp);

            sp_4096_mont_mul_35(rt, rt, t[y], m, mp);
        }

        sp_4096_mont_reduce_35(rt, m, mp);
        n = sp_4096_cmp_35(rt, m);
        sp_4096_cond_sub_35(rt, rt, m, ~(n >> 63));
        XMEMCPY(r, rt, sizeof(sp_digit) * 70);
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
SP_NOINLINE static int sp_4096_sub_70(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 70; i++) {
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
static void sp_4096_mont_norm_70(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
    int i;

    for (i=0; i<69; i++) {
        r[i] = 0x7ffffffffffffffL;
    }
    r[69] = 0x1ffffffL;

    /* r = (2^n - 1) mod n */
    (void)sp_4096_sub_70(r, r, m);

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
static sp_digit sp_4096_cmp_70(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
    int i;

    for (i=69; i>=0; i--) {
        r |= (a[i] - b[i]) & ~(((sp_digit)0 - r) >> 58);
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
static void sp_4096_cond_sub_70(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 70; i++) {
        r[i] = a[i] - (b[i] & m);
    }
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_add_70(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t[4];
    int i;

    t[0] = 0;
    for (i = 0; i < 68; i += 4) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        r[i+0] = t[0] & 0x7ffffffffffffffL;
        t[1] += t[0] >> 59;
        r[i+1] = t[1] & 0x7ffffffffffffffL;
        t[2] += t[1] >> 59;
        r[i+2] = t[2] & 0x7ffffffffffffffL;
        t[3] += t[2] >> 59;
        r[i+3] = t[3] & 0x7ffffffffffffffL;
        t[0]  = t[3] >> 59;
    }
    t[0] += (tb * a[68]) + r[68];
    t[1]  = (tb * a[69]) + r[69];
    r[68] = t[0] & 0x7ffffffffffffffL;
    t[1] += t[0] >> 59;
    r[69] = t[1] & 0x7ffffffffffffffL;
    r[70] +=  (sp_digit)(t[1] >> 59);
}

/* Shift the result in the high 4096 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_4096_mont_shift_70(sp_digit* r, const sp_digit* a)
{
    int i;
    sp_int128 n = a[69] >> 25;
    n += ((sp_int128)a[70]) << 34;

    for (i = 0; i < 69; i++) {
        r[i] = n & 0x7ffffffffffffffL;
        n >>= 59;
        n += ((sp_int128)a[71 + i]) << 34;
    }
    r[69] = (sp_digit)n;
    XMEMSET(&r[70], 0, sizeof(*r) * 70U);
}

/* Reduce the number back to 4096 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_4096_mont_reduce_70(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_4096_norm_70(a + 70);

#ifdef WOLFSSL_SP_DH
    if (mp != 1) {
        for (i=0; i<69; i++) {
            mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x7ffffffffffffffL;
            sp_4096_mul_add_70(a+i, m, mu);
            a[i+1] += a[i] >> 59;
        }
        mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x1ffffffL;
        sp_4096_mul_add_70(a+i, m, mu);
        a[i+1] += a[i] >> 59;
        a[i] &= 0x7ffffffffffffffL;
    }
    else {
        for (i=0; i<69; i++) {
            mu = a[i] & 0x7ffffffffffffffL;
            sp_4096_mul_add_70(a+i, m, mu);
            a[i+1] += a[i] >> 59;
        }
        mu = a[i] & 0x1ffffffL;
        sp_4096_mul_add_70(a+i, m, mu);
        a[i+1] += a[i] >> 59;
        a[i] &= 0x7ffffffffffffffL;
    }
#else
    for (i=0; i<69; i++) {
        mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x7ffffffffffffffL;
        sp_4096_mul_add_70(a+i, m, mu);
        a[i+1] += a[i] >> 59;
    }
    mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x1ffffffL;
    sp_4096_mul_add_70(a+i, m, mu);
    a[i+1] += a[i] >> 59;
    a[i] &= 0x7ffffffffffffffL;
#endif
    sp_4096_mont_shift_70(a, a);
    over = a[69] - m[69];
    sp_4096_cond_sub_70(a, a, m, ~((over - 1) >> 63));
    sp_4096_norm_70(a);
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
SP_NOINLINE static void sp_4096_mont_mul_70(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_4096_mul_70(r, a, b);
    sp_4096_mont_reduce_70(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_4096_mont_sqr_70(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_4096_sqr_70(r, a);
    sp_4096_mont_reduce_70(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_d_140(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t = 0;
    int i;

    for (i = 0; i < 140; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0x7ffffffffffffffL);
        t >>= 59;
    }
    r[140] = (sp_digit)t;
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
static void sp_4096_cond_add_70(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 70; i++) {
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
SP_NOINLINE static int sp_4096_add_70(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 70; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}

SP_NOINLINE static void sp_4096_rshift_70(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    for (i=0; i<69; i++) {
        r[i] = ((a[i] >> n) | (a[i + 1] << (59 - n))) & 0x7ffffffffffffffL;
    }
    r[69] = a[69] >> n;
}

static WC_INLINE sp_digit sp_4096_div_word_70(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int128 d = ((sp_int128)d1 << 59) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int128 d = ((sp_int128)d1 << 59) + d0;
    sp_uint64 lo = (sp_uint64)d;
    sp_digit hi = (sp_digit)(d >> 64);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int128 d = ((sp_int128)d1 << 59) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 59);
    sp_digit t0 = (sp_digit)(d & 0x7ffffffffffffffL);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int128 m;

    r = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
    t1 -= dv & (0 - r);
    for (i = 57; i >= 1; i--) {
        t1 += t1 + (((sp_uint64)t0 >> 58) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int128)r * div);
    r += (sp_digit)(m >> 59);
    m = d - ((sp_int128)r * div);
    r += (m >> 118) - (sp_digit)(d >> 118);

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;
   return r;
#else
    sp_int128 d = ((sp_int128)d1 << 59) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 28) + 1;

    t = (sp_digit)(d >> 56);
    t = (t / dv) << 28;
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)(d >> 25);
    t = t / (dv << 3);
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int128)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_4096_word_div_word_70(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint64)(div - d) >> 63);
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
static int sp_4096_div_70(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_64
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 70 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 140 + 1;
        sd = t2 + 70 + 1;

        sp_4096_mul_d_70(sd, d, (sp_digit)1 << 34);
        sp_4096_mul_d_140(t1, a, (sp_digit)1 << 34);
        dv = sd[69];
        t1[70 + 70] += t1[70 + 70 - 1] >> 59;
        t1[70 + 70 - 1] &= 0x7ffffffffffffffL;
        for (i=70; i>=0; i--) {
            r1 = sp_4096_div_word_70(t1[70 + i], t1[70 + i - 1], dv);

            sp_4096_mul_d_70(t2, sd, r1);
            (void)sp_4096_sub_70(&t1[i], &t1[i], t2);
            sp_4096_norm_70(&t1[i]);
            t1[70 + i] -= t2[70];
            t1[70 + i] += t1[70 + i - 1] >> 59;
            t1[70 + i - 1] &= 0x7ffffffffffffffL;
            r1 = sp_4096_div_word_70(-t1[70 + i], -t1[70 + i - 1], dv);
            r1 -= t1[70 + i];
            sp_4096_mul_d_70(t2, sd, r1);
            (void)sp_4096_add_70(&t1[i], &t1[i], t2);
            t1[70 + i] += t1[70 + i - 1] >> 59;
            t1[70 + i - 1] &= 0x7ffffffffffffffL;
        }
        t1[70 - 1] += t1[70 - 2] >> 59;
        t1[70 - 2] &= 0x7ffffffffffffffL;
        r1 = sp_4096_word_div_word_70(t1[70 - 1], dv);

        sp_4096_mul_d_70(t2, sd, r1);
        sp_4096_sub_70(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 140U);
        for (i=0; i<69; i++) {
            r[i+1] += r[i] >> 59;
            r[i] &= 0x7ffffffffffffffL;
        }
        sp_4096_cond_add_70(r, r, sd, r[69] >> 63);

        sp_4096_norm_70(r);
        sp_4096_rshift_70(r, r, 34);
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
static int sp_4096_mod_70(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_4096_div_70(a, m, NULL, r);
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
static int sp_4096_mod_exp_70(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 140];
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
            t[i] = td + (i * 70 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 70U * 2U);
        }

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_70(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_70(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 70U);
        }
    }
    if (err == MP_OKAY) {
        sp_4096_mul_70(t[1], t[1], norm);
        err = sp_4096_mod_70(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 59;
        c = bits % 59;
        n = e[i--] << (59 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 59;
            }

            y = (int)((n >> 58) & 1);
            n <<= 1;

            sp_4096_mont_mul_70(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 70 * 2);
            sp_4096_mont_sqr_70(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 70 * 2);
        }

        sp_4096_mont_reduce_70(t[0], m, mp);
        n = sp_4096_cmp_70(t[0], m);
        sp_4096_cond_sub_70(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 70 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 140];
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
            t[i] = td + (i * 70 * 2);
        }

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_70(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_70(t[1], a, m);
            if (err == MP_OKAY) {
                sp_4096_mul_70(t[1], t[1], norm);
                err = sp_4096_mod_70(t[1], t[1], m);
            }
        }
        else {
            sp_4096_mul_70(t[1], a, norm);
            err = sp_4096_mod_70(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 59;
        c = bits % 59;
        n = e[i--] << (59 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 59;
            }

            y = (int)((n >> 58) & 1);
            n <<= 1;

            sp_4096_mont_mul_70(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 70 * 2);
            sp_4096_mont_sqr_70(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 70 * 2);
        }

        sp_4096_mont_reduce_70(t[0], m, mp);
        n = sp_4096_cmp_70(t[0], m);
        sp_4096_cond_sub_70(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 70 * 2);
    }


    return err;
#else
    sp_digit td[(16 * 140) + 140];
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
            t[i] = td + i * 140;
        rt = td + 2240;

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_70(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_70(t[1], a, m);
            if (err == MP_OKAY) {
                sp_4096_mul_70(t[1], t[1], norm);
                err = sp_4096_mod_70(t[1], t[1], m);
            }
        }
        else {
            sp_4096_mul_70(t[1], a, norm);
            err = sp_4096_mod_70(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_4096_mont_sqr_70(t[ 2], t[ 1], m, mp);
        sp_4096_mont_mul_70(t[ 3], t[ 2], t[ 1], m, mp);
        sp_4096_mont_sqr_70(t[ 4], t[ 2], m, mp);
        sp_4096_mont_mul_70(t[ 5], t[ 3], t[ 2], m, mp);
        sp_4096_mont_sqr_70(t[ 6], t[ 3], m, mp);
        sp_4096_mont_mul_70(t[ 7], t[ 4], t[ 3], m, mp);
        sp_4096_mont_sqr_70(t[ 8], t[ 4], m, mp);
        sp_4096_mont_mul_70(t[ 9], t[ 5], t[ 4], m, mp);
        sp_4096_mont_sqr_70(t[10], t[ 5], m, mp);
        sp_4096_mont_mul_70(t[11], t[ 6], t[ 5], m, mp);
        sp_4096_mont_sqr_70(t[12], t[ 6], m, mp);
        sp_4096_mont_mul_70(t[13], t[ 7], t[ 6], m, mp);
        sp_4096_mont_sqr_70(t[14], t[ 7], m, mp);
        sp_4096_mont_mul_70(t[15], t[ 8], t[ 7], m, mp);

        bits = ((bits + 3) / 4) * 4;
        i = ((bits + 58) / 59) - 1;
        c = bits % 59;
        if (c == 0) {
            c = 59;
        }
        if (i < 70) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 4) {
            n |= e[i--] << (5 - c);
            c += 59;
        }
        y = (int)((n >> 60) & 0xf);
        n <<= 4;
        c -= 4;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 140);
        while ((i >= 0) || (c >= 4)) {
            if (c >= 4) {
                y = (byte)((n >> 60) & 0xf);
                n <<= 4;
                c -= 4;
            }
            else if (c == 0) {
                n = e[i--] << 5;
                y = (byte)((n >> 60) & 0xf);
                n <<= 4;
                c = 55;
            }
            else {
                y = (byte)((n >> 60) & 0xf);
                n = e[i--] << 5;
                c = 4 - c;
                y |= (byte)((n >> (64 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 59 - c;
            }

            sp_4096_mont_sqr_70(rt, rt, m, mp);
            sp_4096_mont_sqr_70(rt, rt, m, mp);
            sp_4096_mont_sqr_70(rt, rt, m, mp);
            sp_4096_mont_sqr_70(rt, rt, m, mp);

            sp_4096_mont_mul_70(rt, rt, t[y], m, mp);
        }

        sp_4096_mont_reduce_70(rt, m, mp);
        n = sp_4096_cmp_70(rt, m);
        sp_4096_cond_sub_70(rt, rt, m, ~(n >> 63));
        XMEMCPY(r, rt, sizeof(sp_digit) * 140);
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
    sp_digit a[70 * 5];
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
        if (mp_count_bits(em) > 59) {
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
        r = a + 70 * 2;
        m = r + 70 * 2;
        norm = r;

        sp_4096_from_bin(a, 70, in, inLen);
#if DIGIT_BIT >= 59
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
        sp_4096_from_mp(m, 70, mm);

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_70(norm, m);
    }
    if (err == MP_OKAY) {
        sp_4096_mul_70(a, a, norm);
        err = sp_4096_mod_70(a, a, m);
    }
    if (err == MP_OKAY) {
        for (i=58; i>=0; i--) {
            if ((e[0] >> i) != 0) {
                break;
            }
        }

        XMEMCPY(r, a, sizeof(sp_digit) * 70 * 2);
        for (i--; i>=0; i--) {
            sp_4096_mont_sqr_70(r, r, m, mp);

            if (((e[0] >> i) & 1) == 1) {
                sp_4096_mont_mul_70(r, r, a, m, mp);
            }
        }
        sp_4096_mont_reduce_70(r, m, mp);
        mp = sp_4096_cmp_70(r, m);
        sp_4096_cond_sub_70(r, r, m, ~(mp >> 63));

        sp_4096_to_bin_70(r, out);
        *outLen = 512;
    }


    return err;
#else
    sp_digit d[70 * 5];
    sp_digit* a = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit e[1] = {0};
    int err = MP_OKAY;

    if (*outLen < 512U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 59) {
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
        r = a + 70 * 2;
        m = r + 70 * 2;

        sp_4096_from_bin(a, 70, in, inLen);
#if DIGIT_BIT >= 59
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
        sp_4096_from_mp(m, 70, mm);

        if (e[0] == 0x3) {
            sp_4096_sqr_70(r, a);
            err = sp_4096_mod_70(r, r, m);
            if (err == MP_OKAY) {
                sp_4096_mul_70(r, a, r);
                err = sp_4096_mod_70(r, r, m);
            }
        }
        else {
            sp_digit* norm = r;
            int i;
            sp_digit mp;

            sp_4096_mont_setup(m, &mp);
            sp_4096_mont_norm_70(norm, m);

            sp_4096_mul_70(a, a, norm);
            err = sp_4096_mod_70(a, a, m);

            if (err == MP_OKAY) {
                for (i=58; i>=0; i--) {
                    if ((e[0] >> i) != 0) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 140U);
                for (i--; i>=0; i--) {
                    sp_4096_mont_sqr_70(r, r, m, mp);

                    if (((e[0] >> i) & 1) == 1) {
                        sp_4096_mont_mul_70(r, r, a, m, mp);
                    }
                }
                sp_4096_mont_reduce_70(r, m, mp);
                mp = sp_4096_cmp_70(r, m);
                sp_4096_cond_sub_70(r, r, m, ~(mp >> 63));
            }
        }
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_70(r, out);
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
    sp_digit  d[70 * 4];
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
        a = d + 70;
        m = a + 140;
        r = a;

        sp_4096_from_bin(a, 70, in, inLen);
        sp_4096_from_mp(d, 70, dm);
        sp_4096_from_mp(m, 70, mm);
        err = sp_4096_mod_exp_70(r, a, d, 4096, m, 0);
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_70(r, out);
        *outLen = 512;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 70);
    }

    return err;
#else
    sp_digit d[70 * 4];
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
        a = d + 70;
        m = a + 140;
        r = a;

        sp_4096_from_bin(a, 70, in, inLen);
        sp_4096_from_mp(d, 70, dm);
        sp_4096_from_mp(m, 70, mm);
        err = sp_4096_mod_exp_70(r, a, d, 4096, m, 0);
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_70(r, out);
        *outLen = 512;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 70);
    }

    return err;
#endif /* WOLFSSL_SP_SMALL */
#else
#if defined(WOLFSSL_SP_SMALL)
    sp_digit a[35 * 8];
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
        p = a + 70;
        qi = dq = dp = p + 35;
        tmpa = qi + 35;
        tmpb = tmpa + 70;
        r = a;

        sp_4096_from_bin(a, 70, in, inLen);
        sp_4096_from_mp(p, 35, pm);
        sp_4096_from_mp(dp, 35, dpm);
        err = sp_4096_mod_exp_35(tmpa, a, dp, 2048, p, 1);
    }
    if (err == MP_OKAY) {
        sp_4096_from_mp(p, 35, qm);
        sp_4096_from_mp(dq, 35, dqm);
        err = sp_4096_mod_exp_35(tmpb, a, dq, 2048, p, 1);
    }
    if (err == MP_OKAY) {
        sp_4096_from_mp(p, 35, pm);
        (void)sp_4096_sub_35(tmpa, tmpa, tmpb);
        sp_4096_norm_35(tmpa);
        sp_4096_cond_add_35(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[34] >> 63));
        sp_4096_cond_add_35(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[34] >> 63));
        sp_4096_norm_35(tmpa);

        sp_4096_from_mp(qi, 35, qim);
        sp_4096_mul_35(tmpa, tmpa, qi);
        err = sp_4096_mod_35(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_4096_from_mp(p, 35, qm);
        sp_4096_mul_35(tmpa, p, tmpa);
        (void)sp_4096_add_70(r, tmpb, tmpa);
        sp_4096_norm_70(r);

        sp_4096_to_bin_70(r, out);
        *outLen = 512;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 35 * 8);
    }

    return err;
#else
    sp_digit a[35 * 13];
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
        p = a + 70 * 2;
        q = p + 35;
        dp = q + 35;
        dq = dp + 35;
        qi = dq + 35;
        tmpa = qi + 35;
        tmpb = tmpa + 70;
        r = a;

        sp_4096_from_bin(a, 70, in, inLen);
        sp_4096_from_mp(p, 35, pm);
        sp_4096_from_mp(q, 35, qm);
        sp_4096_from_mp(dp, 35, dpm);
        sp_4096_from_mp(dq, 35, dqm);
        sp_4096_from_mp(qi, 35, qim);

        err = sp_4096_mod_exp_35(tmpa, a, dp, 2048, p, 1);
    }
    if (err == MP_OKAY) {
        err = sp_4096_mod_exp_35(tmpb, a, dq, 2048, q, 1);
    }

    if (err == MP_OKAY) {
        (void)sp_4096_sub_35(tmpa, tmpa, tmpb);
        sp_4096_norm_35(tmpa);
        sp_4096_cond_add_35(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[34] >> 63));
        sp_4096_cond_add_35(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[34] >> 63));
        sp_4096_norm_35(tmpa);
        sp_4096_mul_35(tmpa, tmpa, qi);
        err = sp_4096_mod_35(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_4096_mul_35(tmpa, tmpa, q);
        (void)sp_4096_add_70(r, tmpb, tmpa);
        sp_4096_norm_70(r);

        sp_4096_to_bin_70(r, out);
        *outLen = 512;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 35 * 13);
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
#if DIGIT_BIT == 59
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 70);
        r->used = 70;
        mp_clamp(r);
#elif DIGIT_BIT < 59
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 70; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 59) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 59 - s;
        }
        r->used = (4096 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 70; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 59 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 59 - s;
            }
            else {
                s += 59;
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
    sp_digit b[70 * 4];
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
        e = b + 70 * 2;
        m = e + 70;
        r = b;

        sp_4096_from_mp(b, 70, base);
        sp_4096_from_mp(e, 70, exp);
        sp_4096_from_mp(m, 70, mod);

        err = sp_4096_mod_exp_70(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_4096_to_mp(r, res);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 70U);
    }
    return err;
#else
    sp_digit b[70 * 4];
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
        e = b + 70 * 2;
        m = e + 70;
        r = b;

        sp_4096_from_mp(b, 70, base);
        sp_4096_from_mp(e, 70, exp);
        sp_4096_from_mp(m, 70, mod);

        err = sp_4096_mod_exp_70(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_4096_to_mp(r, res);
    }


    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 70U);
    }

    return err;
#endif
}

#ifdef WOLFSSL_HAVE_SP_DH

#ifdef HAVE_FFDHE_4096
SP_NOINLINE static void sp_4096_lshift_70(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    r[70] = a[69] >> (59 - n);
    for (i=69; i>0; i--) {
        r[i] = ((a[i] << n) | (a[i-1] >> (59 - n))) & 0x7ffffffffffffffL;
    }
    r[0] = (a[0] << n) & 0x7ffffffffffffffL;
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
static int sp_4096_mod_exp_2_70(sp_digit* r, const sp_digit* e, int bits, const sp_digit* m)
{
    sp_digit td[211];
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
        tmp  = td + 140;
        XMEMSET(td, 0, sizeof(sp_digit) * 211);

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_70(norm, m);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 58) / 59) - 1;
        c = bits % 59;
        if (c == 0) {
            c = 59;
        }
        if (i < 70) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (5 - c);
            c += 59;
        }
        y = (int)((n >> 59) & 0x1f);
        n <<= 5;
        c -= 5;
        sp_4096_lshift_70(r, norm, (byte)y);
        while ((i >= 0) || (c >= 5)) {
            if (c >= 5) {
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--] << 5;
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c = 54;
            }
            else {
                y = (byte)((n >> 59) & 0x1f);
                n = e[i--] << 5;
                c = 5 - c;
                y |= (byte)((n >> (64 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 59 - c;
            }

            sp_4096_mont_sqr_70(r, r, m, mp);
            sp_4096_mont_sqr_70(r, r, m, mp);
            sp_4096_mont_sqr_70(r, r, m, mp);
            sp_4096_mont_sqr_70(r, r, m, mp);
            sp_4096_mont_sqr_70(r, r, m, mp);

            sp_4096_lshift_70(r, r, (byte)y);
            sp_4096_mul_d_70(tmp, norm, (r[70] << 34) + (r[69] >> 25));
            r[70] = 0;
            r[69] &= 0x1ffffffL;
            (void)sp_4096_add_70(r, r, tmp);
            sp_4096_norm_70(r);
            o = sp_4096_cmp_70(r, m);
            sp_4096_cond_sub_70(r, r, m, ~(o >> 63));
        }

        sp_4096_mont_reduce_70(r, m, mp);
        n = sp_4096_cmp_70(r, m);
        sp_4096_cond_sub_70(r, r, m, ~(n >> 63));
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
    sp_digit b[70 * 4];
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
        e = b + 70 * 2;
        m = e + 70;
        r = b;

        sp_4096_from_mp(b, 70, base);
        sp_4096_from_bin(e, 70, exp, expLen);
        sp_4096_from_mp(m, 70, mod);

    #ifdef HAVE_FFDHE_4096
        if (base->used == 1 && base->dp[0] == 2U &&
                ((m[69] << 7) | (m[68] >> 52)) == 0xffffffffL) {
            err = sp_4096_mod_exp_2_70(r, e, expLen * 8U, m);
        }
        else {
    #endif
            err = sp_4096_mod_exp_70(r, b, e, expLen * 8U, m, 0);
    #ifdef HAVE_FFDHE_4096
        }
    #endif
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_70(r, out);
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
            ForceZero(e, sizeof(sp_digit) * 70U);
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
        if (s >= 45U) {
            r[j] &= 0x1fffffffffffffL;
            s = 53U - s;
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
#if DIGIT_BIT == 53
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 53
    int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0x1fffffffffffffL;
        s = 53U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 53U) <= (word32)DIGIT_BIT) {
            s += 53U;
            r[j] &= 0x1fffffffffffffL;
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
        if (s + DIGIT_BIT >= 53) {
            r[j] &= 0x1fffffffffffffL;
            if (j + 1 >= size) {
                break;
            }
            s = 53 - s;
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
static void sp_4096_to_bin_78(sp_digit* r, byte* a)
{
    int i;
    int j;
    int s = 0;
    int b;

    for (i=0; i<77; i++) {
        r[i+1] += r[i] >> 53;
        r[i] &= 0x1fffffffffffffL;
    }
    j = 4103 / 8 - 1;
    a[j] = 0;
    for (i=0; i<78 && j>=0; i++) {
        b = 0;
        /* lint allow cast of mismatch sp_digit and int */
        a[j--] |= (byte)(r[i] << s); /*lint !e9033*/
        b += 8 - s;
        if (j < 0) {
            break;
        }
        while (b < 53) {
            a[j--] = (byte)(r[i] >> b);
            b += 8;
            if (j < 0) {
                break;
            }
        }
        s = 8 - (b - 53);
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
/* Normalize the values in each word to 53 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_4096_norm_39(sp_digit* a)
{
    int i;
    for (i = 0; i < 32; i += 8) {
        a[i+1] += a[i+0] >> 53; a[i+0] &= 0x1fffffffffffffL;
        a[i+2] += a[i+1] >> 53; a[i+1] &= 0x1fffffffffffffL;
        a[i+3] += a[i+2] >> 53; a[i+2] &= 0x1fffffffffffffL;
        a[i+4] += a[i+3] >> 53; a[i+3] &= 0x1fffffffffffffL;
        a[i+5] += a[i+4] >> 53; a[i+4] &= 0x1fffffffffffffL;
        a[i+6] += a[i+5] >> 53; a[i+5] &= 0x1fffffffffffffL;
        a[i+7] += a[i+6] >> 53; a[i+6] &= 0x1fffffffffffffL;
        a[i+8] += a[i+7] >> 53; a[i+7] &= 0x1fffffffffffffL;
    }
    a[33] += a[32] >> 53; a[32] &= 0x1fffffffffffffL;
    a[34] += a[33] >> 53; a[33] &= 0x1fffffffffffffL;
    a[35] += a[34] >> 53; a[34] &= 0x1fffffffffffffL;
    a[36] += a[35] >> 53; a[35] &= 0x1fffffffffffffL;
    a[37] += a[36] >> 53; a[36] &= 0x1fffffffffffffL;
    a[38] += a[37] >> 53; a[37] &= 0x1fffffffffffffL;
}

#endif /* WOLFSSL_HAVE_SP_RSA & !SP_RSA_PRIVATE_EXP_D */
#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || WOLFSSL_HAVE_SP_DH */
/* Normalize the values in each word to 53 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_4096_norm_78(sp_digit* a)
{
    int i;
    for (i = 0; i < 72; i += 8) {
        a[i+1] += a[i+0] >> 53; a[i+0] &= 0x1fffffffffffffL;
        a[i+2] += a[i+1] >> 53; a[i+1] &= 0x1fffffffffffffL;
        a[i+3] += a[i+2] >> 53; a[i+2] &= 0x1fffffffffffffL;
        a[i+4] += a[i+3] >> 53; a[i+3] &= 0x1fffffffffffffL;
        a[i+5] += a[i+4] >> 53; a[i+4] &= 0x1fffffffffffffL;
        a[i+6] += a[i+5] >> 53; a[i+5] &= 0x1fffffffffffffL;
        a[i+7] += a[i+6] >> 53; a[i+6] &= 0x1fffffffffffffL;
        a[i+8] += a[i+7] >> 53; a[i+7] &= 0x1fffffffffffffL;
    }
    a[73] += a[72] >> 53; a[72] &= 0x1fffffffffffffL;
    a[74] += a[73] >> 53; a[73] &= 0x1fffffffffffffL;
    a[75] += a[74] >> 53; a[74] &= 0x1fffffffffffffL;
    a[76] += a[75] >> 53; a[75] &= 0x1fffffffffffffL;
    a[77] += a[76] >> 53; a[76] &= 0x1fffffffffffffL;
}

#ifndef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_4096_mul_13(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_uint128 t0   = ((sp_uint128)a[ 0]) * b[ 0];
    sp_uint128 t1   = ((sp_uint128)a[ 0]) * b[ 1]
                 + ((sp_uint128)a[ 1]) * b[ 0];
    sp_uint128 t2   = ((sp_uint128)a[ 0]) * b[ 2]
                 + ((sp_uint128)a[ 1]) * b[ 1]
                 + ((sp_uint128)a[ 2]) * b[ 0];
    sp_uint128 t3   = ((sp_uint128)a[ 0]) * b[ 3]
                 + ((sp_uint128)a[ 1]) * b[ 2]
                 + ((sp_uint128)a[ 2]) * b[ 1]
                 + ((sp_uint128)a[ 3]) * b[ 0];
    sp_uint128 t4   = ((sp_uint128)a[ 0]) * b[ 4]
                 + ((sp_uint128)a[ 1]) * b[ 3]
                 + ((sp_uint128)a[ 2]) * b[ 2]
                 + ((sp_uint128)a[ 3]) * b[ 1]
                 + ((sp_uint128)a[ 4]) * b[ 0];
    sp_uint128 t5   = ((sp_uint128)a[ 0]) * b[ 5]
                 + ((sp_uint128)a[ 1]) * b[ 4]
                 + ((sp_uint128)a[ 2]) * b[ 3]
                 + ((sp_uint128)a[ 3]) * b[ 2]
                 + ((sp_uint128)a[ 4]) * b[ 1]
                 + ((sp_uint128)a[ 5]) * b[ 0];
    sp_uint128 t6   = ((sp_uint128)a[ 0]) * b[ 6]
                 + ((sp_uint128)a[ 1]) * b[ 5]
                 + ((sp_uint128)a[ 2]) * b[ 4]
                 + ((sp_uint128)a[ 3]) * b[ 3]
                 + ((sp_uint128)a[ 4]) * b[ 2]
                 + ((sp_uint128)a[ 5]) * b[ 1]
                 + ((sp_uint128)a[ 6]) * b[ 0];
    sp_uint128 t7   = ((sp_uint128)a[ 0]) * b[ 7]
                 + ((sp_uint128)a[ 1]) * b[ 6]
                 + ((sp_uint128)a[ 2]) * b[ 5]
                 + ((sp_uint128)a[ 3]) * b[ 4]
                 + ((sp_uint128)a[ 4]) * b[ 3]
                 + ((sp_uint128)a[ 5]) * b[ 2]
                 + ((sp_uint128)a[ 6]) * b[ 1]
                 + ((sp_uint128)a[ 7]) * b[ 0];
    sp_uint128 t8   = ((sp_uint128)a[ 0]) * b[ 8]
                 + ((sp_uint128)a[ 1]) * b[ 7]
                 + ((sp_uint128)a[ 2]) * b[ 6]
                 + ((sp_uint128)a[ 3]) * b[ 5]
                 + ((sp_uint128)a[ 4]) * b[ 4]
                 + ((sp_uint128)a[ 5]) * b[ 3]
                 + ((sp_uint128)a[ 6]) * b[ 2]
                 + ((sp_uint128)a[ 7]) * b[ 1]
                 + ((sp_uint128)a[ 8]) * b[ 0];
    sp_uint128 t9   = ((sp_uint128)a[ 0]) * b[ 9]
                 + ((sp_uint128)a[ 1]) * b[ 8]
                 + ((sp_uint128)a[ 2]) * b[ 7]
                 + ((sp_uint128)a[ 3]) * b[ 6]
                 + ((sp_uint128)a[ 4]) * b[ 5]
                 + ((sp_uint128)a[ 5]) * b[ 4]
                 + ((sp_uint128)a[ 6]) * b[ 3]
                 + ((sp_uint128)a[ 7]) * b[ 2]
                 + ((sp_uint128)a[ 8]) * b[ 1]
                 + ((sp_uint128)a[ 9]) * b[ 0];
    sp_uint128 t10  = ((sp_uint128)a[ 0]) * b[10]
                 + ((sp_uint128)a[ 1]) * b[ 9]
                 + ((sp_uint128)a[ 2]) * b[ 8]
                 + ((sp_uint128)a[ 3]) * b[ 7]
                 + ((sp_uint128)a[ 4]) * b[ 6]
                 + ((sp_uint128)a[ 5]) * b[ 5]
                 + ((sp_uint128)a[ 6]) * b[ 4]
                 + ((sp_uint128)a[ 7]) * b[ 3]
                 + ((sp_uint128)a[ 8]) * b[ 2]
                 + ((sp_uint128)a[ 9]) * b[ 1]
                 + ((sp_uint128)a[10]) * b[ 0];
    sp_uint128 t11  = ((sp_uint128)a[ 0]) * b[11]
                 + ((sp_uint128)a[ 1]) * b[10]
                 + ((sp_uint128)a[ 2]) * b[ 9]
                 + ((sp_uint128)a[ 3]) * b[ 8]
                 + ((sp_uint128)a[ 4]) * b[ 7]
                 + ((sp_uint128)a[ 5]) * b[ 6]
                 + ((sp_uint128)a[ 6]) * b[ 5]
                 + ((sp_uint128)a[ 7]) * b[ 4]
                 + ((sp_uint128)a[ 8]) * b[ 3]
                 + ((sp_uint128)a[ 9]) * b[ 2]
                 + ((sp_uint128)a[10]) * b[ 1]
                 + ((sp_uint128)a[11]) * b[ 0];
    sp_uint128 t12  = ((sp_uint128)a[ 0]) * b[12]
                 + ((sp_uint128)a[ 1]) * b[11]
                 + ((sp_uint128)a[ 2]) * b[10]
                 + ((sp_uint128)a[ 3]) * b[ 9]
                 + ((sp_uint128)a[ 4]) * b[ 8]
                 + ((sp_uint128)a[ 5]) * b[ 7]
                 + ((sp_uint128)a[ 6]) * b[ 6]
                 + ((sp_uint128)a[ 7]) * b[ 5]
                 + ((sp_uint128)a[ 8]) * b[ 4]
                 + ((sp_uint128)a[ 9]) * b[ 3]
                 + ((sp_uint128)a[10]) * b[ 2]
                 + ((sp_uint128)a[11]) * b[ 1]
                 + ((sp_uint128)a[12]) * b[ 0];
    sp_uint128 t13  = ((sp_uint128)a[ 1]) * b[12]
                 + ((sp_uint128)a[ 2]) * b[11]
                 + ((sp_uint128)a[ 3]) * b[10]
                 + ((sp_uint128)a[ 4]) * b[ 9]
                 + ((sp_uint128)a[ 5]) * b[ 8]
                 + ((sp_uint128)a[ 6]) * b[ 7]
                 + ((sp_uint128)a[ 7]) * b[ 6]
                 + ((sp_uint128)a[ 8]) * b[ 5]
                 + ((sp_uint128)a[ 9]) * b[ 4]
                 + ((sp_uint128)a[10]) * b[ 3]
                 + ((sp_uint128)a[11]) * b[ 2]
                 + ((sp_uint128)a[12]) * b[ 1];
    sp_uint128 t14  = ((sp_uint128)a[ 2]) * b[12]
                 + ((sp_uint128)a[ 3]) * b[11]
                 + ((sp_uint128)a[ 4]) * b[10]
                 + ((sp_uint128)a[ 5]) * b[ 9]
                 + ((sp_uint128)a[ 6]) * b[ 8]
                 + ((sp_uint128)a[ 7]) * b[ 7]
                 + ((sp_uint128)a[ 8]) * b[ 6]
                 + ((sp_uint128)a[ 9]) * b[ 5]
                 + ((sp_uint128)a[10]) * b[ 4]
                 + ((sp_uint128)a[11]) * b[ 3]
                 + ((sp_uint128)a[12]) * b[ 2];
    sp_uint128 t15  = ((sp_uint128)a[ 3]) * b[12]
                 + ((sp_uint128)a[ 4]) * b[11]
                 + ((sp_uint128)a[ 5]) * b[10]
                 + ((sp_uint128)a[ 6]) * b[ 9]
                 + ((sp_uint128)a[ 7]) * b[ 8]
                 + ((sp_uint128)a[ 8]) * b[ 7]
                 + ((sp_uint128)a[ 9]) * b[ 6]
                 + ((sp_uint128)a[10]) * b[ 5]
                 + ((sp_uint128)a[11]) * b[ 4]
                 + ((sp_uint128)a[12]) * b[ 3];
    sp_uint128 t16  = ((sp_uint128)a[ 4]) * b[12]
                 + ((sp_uint128)a[ 5]) * b[11]
                 + ((sp_uint128)a[ 6]) * b[10]
                 + ((sp_uint128)a[ 7]) * b[ 9]
                 + ((sp_uint128)a[ 8]) * b[ 8]
                 + ((sp_uint128)a[ 9]) * b[ 7]
                 + ((sp_uint128)a[10]) * b[ 6]
                 + ((sp_uint128)a[11]) * b[ 5]
                 + ((sp_uint128)a[12]) * b[ 4];
    sp_uint128 t17  = ((sp_uint128)a[ 5]) * b[12]
                 + ((sp_uint128)a[ 6]) * b[11]
                 + ((sp_uint128)a[ 7]) * b[10]
                 + ((sp_uint128)a[ 8]) * b[ 9]
                 + ((sp_uint128)a[ 9]) * b[ 8]
                 + ((sp_uint128)a[10]) * b[ 7]
                 + ((sp_uint128)a[11]) * b[ 6]
                 + ((sp_uint128)a[12]) * b[ 5];
    sp_uint128 t18  = ((sp_uint128)a[ 6]) * b[12]
                 + ((sp_uint128)a[ 7]) * b[11]
                 + ((sp_uint128)a[ 8]) * b[10]
                 + ((sp_uint128)a[ 9]) * b[ 9]
                 + ((sp_uint128)a[10]) * b[ 8]
                 + ((sp_uint128)a[11]) * b[ 7]
                 + ((sp_uint128)a[12]) * b[ 6];
    sp_uint128 t19  = ((sp_uint128)a[ 7]) * b[12]
                 + ((sp_uint128)a[ 8]) * b[11]
                 + ((sp_uint128)a[ 9]) * b[10]
                 + ((sp_uint128)a[10]) * b[ 9]
                 + ((sp_uint128)a[11]) * b[ 8]
                 + ((sp_uint128)a[12]) * b[ 7];
    sp_uint128 t20  = ((sp_uint128)a[ 8]) * b[12]
                 + ((sp_uint128)a[ 9]) * b[11]
                 + ((sp_uint128)a[10]) * b[10]
                 + ((sp_uint128)a[11]) * b[ 9]
                 + ((sp_uint128)a[12]) * b[ 8];
    sp_uint128 t21  = ((sp_uint128)a[ 9]) * b[12]
                 + ((sp_uint128)a[10]) * b[11]
                 + ((sp_uint128)a[11]) * b[10]
                 + ((sp_uint128)a[12]) * b[ 9];
    sp_uint128 t22  = ((sp_uint128)a[10]) * b[12]
                 + ((sp_uint128)a[11]) * b[11]
                 + ((sp_uint128)a[12]) * b[10];
    sp_uint128 t23  = ((sp_uint128)a[11]) * b[12]
                 + ((sp_uint128)a[12]) * b[11];
    sp_uint128 t24  = ((sp_uint128)a[12]) * b[12];

    t1   += t0  >> 53; r[ 0] = t0  & 0x1fffffffffffffL;
    t2   += t1  >> 53; r[ 1] = t1  & 0x1fffffffffffffL;
    t3   += t2  >> 53; r[ 2] = t2  & 0x1fffffffffffffL;
    t4   += t3  >> 53; r[ 3] = t3  & 0x1fffffffffffffL;
    t5   += t4  >> 53; r[ 4] = t4  & 0x1fffffffffffffL;
    t6   += t5  >> 53; r[ 5] = t5  & 0x1fffffffffffffL;
    t7   += t6  >> 53; r[ 6] = t6  & 0x1fffffffffffffL;
    t8   += t7  >> 53; r[ 7] = t7  & 0x1fffffffffffffL;
    t9   += t8  >> 53; r[ 8] = t8  & 0x1fffffffffffffL;
    t10  += t9  >> 53; r[ 9] = t9  & 0x1fffffffffffffL;
    t11  += t10 >> 53; r[10] = t10 & 0x1fffffffffffffL;
    t12  += t11 >> 53; r[11] = t11 & 0x1fffffffffffffL;
    t13  += t12 >> 53; r[12] = t12 & 0x1fffffffffffffL;
    t14  += t13 >> 53; r[13] = t13 & 0x1fffffffffffffL;
    t15  += t14 >> 53; r[14] = t14 & 0x1fffffffffffffL;
    t16  += t15 >> 53; r[15] = t15 & 0x1fffffffffffffL;
    t17  += t16 >> 53; r[16] = t16 & 0x1fffffffffffffL;
    t18  += t17 >> 53; r[17] = t17 & 0x1fffffffffffffL;
    t19  += t18 >> 53; r[18] = t18 & 0x1fffffffffffffL;
    t20  += t19 >> 53; r[19] = t19 & 0x1fffffffffffffL;
    t21  += t20 >> 53; r[20] = t20 & 0x1fffffffffffffL;
    t22  += t21 >> 53; r[21] = t21 & 0x1fffffffffffffL;
    t23  += t22 >> 53; r[22] = t22 & 0x1fffffffffffffL;
    t24  += t23 >> 53; r[23] = t23 & 0x1fffffffffffffL;
    r[25] = (sp_digit)(t24 >> 53);
                       r[24] = t24 & 0x1fffffffffffffL;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_add_13(sp_digit* r, const sp_digit* a,
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

    return 0;
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_sub_26(sp_digit* r, const sp_digit* a,
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

    return 0;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_add_26(sp_digit* r, const sp_digit* a,
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

    return 0;
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_4096_mul_39(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit p0[26];
    sp_digit p1[26];
    sp_digit p2[26];
    sp_digit p3[26];
    sp_digit p4[26];
    sp_digit p5[26];
    sp_digit t0[26];
    sp_digit t1[26];
    sp_digit t2[26];
    sp_digit a0[13];
    sp_digit a1[13];
    sp_digit a2[13];
    sp_digit b0[13];
    sp_digit b1[13];
    sp_digit b2[13];
    (void)sp_4096_add_13(a0, a, &a[13]);
    (void)sp_4096_add_13(b0, b, &b[13]);
    (void)sp_4096_add_13(a1, &a[13], &a[26]);
    (void)sp_4096_add_13(b1, &b[13], &b[26]);
    (void)sp_4096_add_13(a2, a0, &a[26]);
    (void)sp_4096_add_13(b2, b0, &b[26]);
    sp_4096_mul_13(p0, a, b);
    sp_4096_mul_13(p2, &a[13], &b[13]);
    sp_4096_mul_13(p4, &a[26], &b[26]);
    sp_4096_mul_13(p1, a0, b0);
    sp_4096_mul_13(p3, a1, b1);
    sp_4096_mul_13(p5, a2, b2);
    XMEMSET(r, 0, sizeof(*r)*2U*39U);
    (void)sp_4096_sub_26(t0, p3, p2);
    (void)sp_4096_sub_26(t1, p1, p2);
    (void)sp_4096_sub_26(t2, p5, t0);
    (void)sp_4096_sub_26(t2, t2, t1);
    (void)sp_4096_sub_26(t0, t0, p4);
    (void)sp_4096_sub_26(t1, t1, p0);
    (void)sp_4096_add_26(r, r, p0);
    (void)sp_4096_add_26(&r[13], &r[13], t1);
    (void)sp_4096_add_26(&r[26], &r[26], t2);
    (void)sp_4096_add_26(&r[39], &r[39], t0);
    (void)sp_4096_add_26(&r[52], &r[52], p4);
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_add_39(sp_digit* r, const sp_digit* a,
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
    r[36] = a[36] + b[36];
    r[37] = a[37] + b[37];
    r[38] = a[38] + b[38];

    return 0;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_add_78(sp_digit* r, const sp_digit* a,
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
    r[72] = a[72] + b[72];
    r[73] = a[73] + b[73];
    r[74] = a[74] + b[74];
    r[75] = a[75] + b[75];
    r[76] = a[76] + b[76];
    r[77] = a[77] + b[77];

    return 0;
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_sub_78(sp_digit* r, const sp_digit* a,
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
    r[72] = a[72] - b[72];
    r[73] = a[73] - b[73];
    r[74] = a[74] - b[74];
    r[75] = a[75] - b[75];
    r[76] = a[76] - b[76];
    r[77] = a[77] - b[77];

    return 0;
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_4096_mul_78(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[78];
    sp_digit* a1 = z1;
    sp_digit b1[39];
    sp_digit* z2 = r + 78;
    (void)sp_4096_add_39(a1, a, &a[39]);
    (void)sp_4096_add_39(b1, b, &b[39]);
    sp_4096_mul_39(z2, &a[39], &b[39]);
    sp_4096_mul_39(z0, a, b);
    sp_4096_mul_39(z1, a1, b1);
    (void)sp_4096_sub_78(z1, z1, z2);
    (void)sp_4096_sub_78(z1, z1, z0);
    (void)sp_4096_add_78(r + 39, r + 39, z1);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_4096_sqr_13(sp_digit* r, const sp_digit* a)
{
    sp_uint128 t0   =  ((sp_uint128)a[ 0]) * a[ 0];
    sp_uint128 t1   = (((sp_uint128)a[ 0]) * a[ 1]) * 2;
    sp_uint128 t2   = (((sp_uint128)a[ 0]) * a[ 2]) * 2
                 +  ((sp_uint128)a[ 1]) * a[ 1];
    sp_uint128 t3   = (((sp_uint128)a[ 0]) * a[ 3]
                 +  ((sp_uint128)a[ 1]) * a[ 2]) * 2;
    sp_uint128 t4   = (((sp_uint128)a[ 0]) * a[ 4]
                 +  ((sp_uint128)a[ 1]) * a[ 3]) * 2
                 +  ((sp_uint128)a[ 2]) * a[ 2];
    sp_uint128 t5   = (((sp_uint128)a[ 0]) * a[ 5]
                 +  ((sp_uint128)a[ 1]) * a[ 4]
                 +  ((sp_uint128)a[ 2]) * a[ 3]) * 2;
    sp_uint128 t6   = (((sp_uint128)a[ 0]) * a[ 6]
                 +  ((sp_uint128)a[ 1]) * a[ 5]
                 +  ((sp_uint128)a[ 2]) * a[ 4]) * 2
                 +  ((sp_uint128)a[ 3]) * a[ 3];
    sp_uint128 t7   = (((sp_uint128)a[ 0]) * a[ 7]
                 +  ((sp_uint128)a[ 1]) * a[ 6]
                 +  ((sp_uint128)a[ 2]) * a[ 5]
                 +  ((sp_uint128)a[ 3]) * a[ 4]) * 2;
    sp_uint128 t8   = (((sp_uint128)a[ 0]) * a[ 8]
                 +  ((sp_uint128)a[ 1]) * a[ 7]
                 +  ((sp_uint128)a[ 2]) * a[ 6]
                 +  ((sp_uint128)a[ 3]) * a[ 5]) * 2
                 +  ((sp_uint128)a[ 4]) * a[ 4];
    sp_uint128 t9   = (((sp_uint128)a[ 0]) * a[ 9]
                 +  ((sp_uint128)a[ 1]) * a[ 8]
                 +  ((sp_uint128)a[ 2]) * a[ 7]
                 +  ((sp_uint128)a[ 3]) * a[ 6]
                 +  ((sp_uint128)a[ 4]) * a[ 5]) * 2;
    sp_uint128 t10  = (((sp_uint128)a[ 0]) * a[10]
                 +  ((sp_uint128)a[ 1]) * a[ 9]
                 +  ((sp_uint128)a[ 2]) * a[ 8]
                 +  ((sp_uint128)a[ 3]) * a[ 7]
                 +  ((sp_uint128)a[ 4]) * a[ 6]) * 2
                 +  ((sp_uint128)a[ 5]) * a[ 5];
    sp_uint128 t11  = (((sp_uint128)a[ 0]) * a[11]
                 +  ((sp_uint128)a[ 1]) * a[10]
                 +  ((sp_uint128)a[ 2]) * a[ 9]
                 +  ((sp_uint128)a[ 3]) * a[ 8]
                 +  ((sp_uint128)a[ 4]) * a[ 7]
                 +  ((sp_uint128)a[ 5]) * a[ 6]) * 2;
    sp_uint128 t12  = (((sp_uint128)a[ 0]) * a[12]
                 +  ((sp_uint128)a[ 1]) * a[11]
                 +  ((sp_uint128)a[ 2]) * a[10]
                 +  ((sp_uint128)a[ 3]) * a[ 9]
                 +  ((sp_uint128)a[ 4]) * a[ 8]
                 +  ((sp_uint128)a[ 5]) * a[ 7]) * 2
                 +  ((sp_uint128)a[ 6]) * a[ 6];
    sp_uint128 t13  = (((sp_uint128)a[ 1]) * a[12]
                 +  ((sp_uint128)a[ 2]) * a[11]
                 +  ((sp_uint128)a[ 3]) * a[10]
                 +  ((sp_uint128)a[ 4]) * a[ 9]
                 +  ((sp_uint128)a[ 5]) * a[ 8]
                 +  ((sp_uint128)a[ 6]) * a[ 7]) * 2;
    sp_uint128 t14  = (((sp_uint128)a[ 2]) * a[12]
                 +  ((sp_uint128)a[ 3]) * a[11]
                 +  ((sp_uint128)a[ 4]) * a[10]
                 +  ((sp_uint128)a[ 5]) * a[ 9]
                 +  ((sp_uint128)a[ 6]) * a[ 8]) * 2
                 +  ((sp_uint128)a[ 7]) * a[ 7];
    sp_uint128 t15  = (((sp_uint128)a[ 3]) * a[12]
                 +  ((sp_uint128)a[ 4]) * a[11]
                 +  ((sp_uint128)a[ 5]) * a[10]
                 +  ((sp_uint128)a[ 6]) * a[ 9]
                 +  ((sp_uint128)a[ 7]) * a[ 8]) * 2;
    sp_uint128 t16  = (((sp_uint128)a[ 4]) * a[12]
                 +  ((sp_uint128)a[ 5]) * a[11]
                 +  ((sp_uint128)a[ 6]) * a[10]
                 +  ((sp_uint128)a[ 7]) * a[ 9]) * 2
                 +  ((sp_uint128)a[ 8]) * a[ 8];
    sp_uint128 t17  = (((sp_uint128)a[ 5]) * a[12]
                 +  ((sp_uint128)a[ 6]) * a[11]
                 +  ((sp_uint128)a[ 7]) * a[10]
                 +  ((sp_uint128)a[ 8]) * a[ 9]) * 2;
    sp_uint128 t18  = (((sp_uint128)a[ 6]) * a[12]
                 +  ((sp_uint128)a[ 7]) * a[11]
                 +  ((sp_uint128)a[ 8]) * a[10]) * 2
                 +  ((sp_uint128)a[ 9]) * a[ 9];
    sp_uint128 t19  = (((sp_uint128)a[ 7]) * a[12]
                 +  ((sp_uint128)a[ 8]) * a[11]
                 +  ((sp_uint128)a[ 9]) * a[10]) * 2;
    sp_uint128 t20  = (((sp_uint128)a[ 8]) * a[12]
                 +  ((sp_uint128)a[ 9]) * a[11]) * 2
                 +  ((sp_uint128)a[10]) * a[10];
    sp_uint128 t21  = (((sp_uint128)a[ 9]) * a[12]
                 +  ((sp_uint128)a[10]) * a[11]) * 2;
    sp_uint128 t22  = (((sp_uint128)a[10]) * a[12]) * 2
                 +  ((sp_uint128)a[11]) * a[11];
    sp_uint128 t23  = (((sp_uint128)a[11]) * a[12]) * 2;
    sp_uint128 t24  =  ((sp_uint128)a[12]) * a[12];

    t1   += t0  >> 53; r[ 0] = t0  & 0x1fffffffffffffL;
    t2   += t1  >> 53; r[ 1] = t1  & 0x1fffffffffffffL;
    t3   += t2  >> 53; r[ 2] = t2  & 0x1fffffffffffffL;
    t4   += t3  >> 53; r[ 3] = t3  & 0x1fffffffffffffL;
    t5   += t4  >> 53; r[ 4] = t4  & 0x1fffffffffffffL;
    t6   += t5  >> 53; r[ 5] = t5  & 0x1fffffffffffffL;
    t7   += t6  >> 53; r[ 6] = t6  & 0x1fffffffffffffL;
    t8   += t7  >> 53; r[ 7] = t7  & 0x1fffffffffffffL;
    t9   += t8  >> 53; r[ 8] = t8  & 0x1fffffffffffffL;
    t10  += t9  >> 53; r[ 9] = t9  & 0x1fffffffffffffL;
    t11  += t10 >> 53; r[10] = t10 & 0x1fffffffffffffL;
    t12  += t11 >> 53; r[11] = t11 & 0x1fffffffffffffL;
    t13  += t12 >> 53; r[12] = t12 & 0x1fffffffffffffL;
    t14  += t13 >> 53; r[13] = t13 & 0x1fffffffffffffL;
    t15  += t14 >> 53; r[14] = t14 & 0x1fffffffffffffL;
    t16  += t15 >> 53; r[15] = t15 & 0x1fffffffffffffL;
    t17  += t16 >> 53; r[16] = t16 & 0x1fffffffffffffL;
    t18  += t17 >> 53; r[17] = t17 & 0x1fffffffffffffL;
    t19  += t18 >> 53; r[18] = t18 & 0x1fffffffffffffL;
    t20  += t19 >> 53; r[19] = t19 & 0x1fffffffffffffL;
    t21  += t20 >> 53; r[20] = t20 & 0x1fffffffffffffL;
    t22  += t21 >> 53; r[21] = t21 & 0x1fffffffffffffL;
    t23  += t22 >> 53; r[22] = t22 & 0x1fffffffffffffL;
    t24  += t23 >> 53; r[23] = t23 & 0x1fffffffffffffL;
    r[25] = (sp_digit)(t24 >> 53);
                       r[24] = t24 & 0x1fffffffffffffL;
}

/* Square a into r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_4096_sqr_39(sp_digit* r, const sp_digit* a)
{
    sp_digit p0[26];
    sp_digit p1[26];
    sp_digit p2[26];
    sp_digit p3[26];
    sp_digit p4[26];
    sp_digit p5[26];
    sp_digit t0[26];
    sp_digit t1[26];
    sp_digit t2[26];
    sp_digit a0[13];
    sp_digit a1[13];
    sp_digit a2[13];
    (void)sp_4096_add_13(a0, a, &a[13]);
    (void)sp_4096_add_13(a1, &a[13], &a[26]);
    (void)sp_4096_add_13(a2, a0, &a[26]);
    sp_4096_sqr_13(p0, a);
    sp_4096_sqr_13(p2, &a[13]);
    sp_4096_sqr_13(p4, &a[26]);
    sp_4096_sqr_13(p1, a0);
    sp_4096_sqr_13(p3, a1);
    sp_4096_sqr_13(p5, a2);
    XMEMSET(r, 0, sizeof(*r)*2U*39U);
    (void)sp_4096_sub_26(t0, p3, p2);
    (void)sp_4096_sub_26(t1, p1, p2);
    (void)sp_4096_sub_26(t2, p5, t0);
    (void)sp_4096_sub_26(t2, t2, t1);
    (void)sp_4096_sub_26(t0, t0, p4);
    (void)sp_4096_sub_26(t1, t1, p0);
    (void)sp_4096_add_26(r, r, p0);
    (void)sp_4096_add_26(&r[13], &r[13], t1);
    (void)sp_4096_add_26(&r[26], &r[26], t2);
    (void)sp_4096_add_26(&r[39], &r[39], t0);
    (void)sp_4096_add_26(&r[52], &r[52], p4);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_4096_sqr_78(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit z1[78];
    sp_digit* a1 = z1;
    sp_digit* z2 = r + 78;
    (void)sp_4096_add_39(a1, a, &a[39]);
    sp_4096_sqr_39(z2, &a[39]);
    sp_4096_sqr_39(z0, a);
    sp_4096_sqr_39(z1, a1);
    (void)sp_4096_sub_78(z1, z1, z2);
    (void)sp_4096_sub_78(z1, z1, z0);
    (void)sp_4096_add_78(r + 39, r + 39, z1);
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
    x *= 2 - b * x;               /* here x*a==1 mod 2**64 */
    x &= 0x1fffffffffffffL;

    /* rho = -1/m mod b */
    *rho = ((sp_digit)1 << 53) - x;
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_d_78(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t = 0;
    sp_digit t2;
    sp_int128 p[4];
    int i;

    for (i = 0; i < 76; i += 4) {
        p[0] = tb * a[i + 0];
        p[1] = tb * a[i + 1];
        p[2] = tb * a[i + 2];
        p[3] = tb * a[i + 3];
        t += p[0];
        t2 = (sp_digit)(t & 0x1fffffffffffffL);
        t >>= 53;
        r[i + 0] = (sp_digit)t2;
        t += p[1];
        t2 = (sp_digit)(t & 0x1fffffffffffffL);
        t >>= 53;
        r[i + 1] = (sp_digit)t2;
        t += p[2];
        t2 = (sp_digit)(t & 0x1fffffffffffffL);
        t >>= 53;
        r[i + 2] = (sp_digit)t2;
        t += p[3];
        t2 = (sp_digit)(t & 0x1fffffffffffffL);
        t >>= 53;
        r[i + 3] = (sp_digit)t2;
    }
    t += tb * a[76];
    r[76] = (sp_digit)(t & 0x1fffffffffffffL);
    t >>= 53;
    t += tb * a[77];
    r[77] = (sp_digit)(t & 0x1fffffffffffffL);
    t >>= 53;
    r[78] = (sp_digit)(t & 0x1fffffffffffffL);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH)) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
#if defined(WOLFSSL_HAVE_SP_RSA) && !defined(SP_RSA_PRIVATE_EXP_D)
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_sub_39(sp_digit* r, const sp_digit* a,
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
    r[36] = a[36] - b[36];
    r[37] = a[37] - b[37];
    r[38] = a[38] - b[38];

    return 0;
}

/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 4096 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A single precision number.
 */
static void sp_4096_mont_norm_39(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i + 0] = 0x1fffffffffffffL;
        r[i + 1] = 0x1fffffffffffffL;
        r[i + 2] = 0x1fffffffffffffL;
        r[i + 3] = 0x1fffffffffffffL;
        r[i + 4] = 0x1fffffffffffffL;
        r[i + 5] = 0x1fffffffffffffL;
        r[i + 6] = 0x1fffffffffffffL;
        r[i + 7] = 0x1fffffffffffffL;
    }
    r[32] = 0x1fffffffffffffL;
    r[33] = 0x1fffffffffffffL;
    r[34] = 0x1fffffffffffffL;
    r[35] = 0x1fffffffffffffL;
    r[36] = 0x1fffffffffffffL;
    r[37] = 0x1fffffffffffffL;
    r[38] = 0x3ffffffffL;

    /* r = (2^n - 1) mod n */
    (void)sp_4096_sub_39(r, r, m);

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
static sp_digit sp_4096_cmp_39(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
    int i;

    r |= (a[38] - b[38]) & (0 - (sp_digit)1);
    r |= (a[37] - b[37]) & ~(((sp_digit)0 - r) >> 52);
    r |= (a[36] - b[36]) & ~(((sp_digit)0 - r) >> 52);
    r |= (a[35] - b[35]) & ~(((sp_digit)0 - r) >> 52);
    r |= (a[34] - b[34]) & ~(((sp_digit)0 - r) >> 52);
    r |= (a[33] - b[33]) & ~(((sp_digit)0 - r) >> 52);
    r |= (a[32] - b[32]) & ~(((sp_digit)0 - r) >> 52);
    for (i = 24; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & ~(((sp_digit)0 - r) >> 52);
        r |= (a[i + 6] - b[i + 6]) & ~(((sp_digit)0 - r) >> 52);
        r |= (a[i + 5] - b[i + 5]) & ~(((sp_digit)0 - r) >> 52);
        r |= (a[i + 4] - b[i + 4]) & ~(((sp_digit)0 - r) >> 52);
        r |= (a[i + 3] - b[i + 3]) & ~(((sp_digit)0 - r) >> 52);
        r |= (a[i + 2] - b[i + 2]) & ~(((sp_digit)0 - r) >> 52);
        r |= (a[i + 1] - b[i + 1]) & ~(((sp_digit)0 - r) >> 52);
        r |= (a[i + 0] - b[i + 0]) & ~(((sp_digit)0 - r) >> 52);
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
static void sp_4096_cond_sub_39(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
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
    r[36] = a[36] - (b[36] & m);
    r[37] = a[37] - (b[37] & m);
    r[38] = a[38] - (b[38] & m);
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_add_39(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t[8];
    int i;

    t[0] = tb * a[0]; r[0] += (sp_digit)(t[0] & 0x1fffffffffffffL);
    for (i = 0; i < 32; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] += (sp_digit)((t[0] >> 53) + (t[1] & 0x1fffffffffffffL));
        t[2] = tb * a[i+2];
        r[i+2] += (sp_digit)((t[1] >> 53) + (t[2] & 0x1fffffffffffffL));
        t[3] = tb * a[i+3];
        r[i+3] += (sp_digit)((t[2] >> 53) + (t[3] & 0x1fffffffffffffL));
        t[4] = tb * a[i+4];
        r[i+4] += (sp_digit)((t[3] >> 53) + (t[4] & 0x1fffffffffffffL));
        t[5] = tb * a[i+5];
        r[i+5] += (sp_digit)((t[4] >> 53) + (t[5] & 0x1fffffffffffffL));
        t[6] = tb * a[i+6];
        r[i+6] += (sp_digit)((t[5] >> 53) + (t[6] & 0x1fffffffffffffL));
        t[7] = tb * a[i+7];
        r[i+7] += (sp_digit)((t[6] >> 53) + (t[7] & 0x1fffffffffffffL));
        t[0] = tb * a[i+8];
        r[i+8] += (sp_digit)((t[7] >> 53) + (t[0] & 0x1fffffffffffffL));
    }
    t[1] = tb * a[33];
    r[33] += (sp_digit)((t[0] >> 53) + (t[1] & 0x1fffffffffffffL));
    t[2] = tb * a[34];
    r[34] += (sp_digit)((t[1] >> 53) + (t[2] & 0x1fffffffffffffL));
    t[3] = tb * a[35];
    r[35] += (sp_digit)((t[2] >> 53) + (t[3] & 0x1fffffffffffffL));
    t[4] = tb * a[36];
    r[36] += (sp_digit)((t[3] >> 53) + (t[4] & 0x1fffffffffffffL));
    t[5] = tb * a[37];
    r[37] += (sp_digit)((t[4] >> 53) + (t[5] & 0x1fffffffffffffL));
    t[6] = tb * a[38];
    r[38] += (sp_digit)((t[5] >> 53) + (t[6] & 0x1fffffffffffffL));
    r[39] +=  (sp_digit)(t[6] >> 53);
}

/* Shift the result in the high 2048 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_4096_mont_shift_39(sp_digit* r, const sp_digit* a)
{
    int i;
    sp_int128 n = a[38] >> 34;
    n += ((sp_int128)a[39]) << 19;
    for (i = 0; i < 32; i += 8) {
        r[i + 0] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((sp_int128)a[i + 40]) << 19;
        r[i + 1] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((sp_int128)a[i + 41]) << 19;
        r[i + 2] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((sp_int128)a[i + 42]) << 19;
        r[i + 3] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((sp_int128)a[i + 43]) << 19;
        r[i + 4] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((sp_int128)a[i + 44]) << 19;
        r[i + 5] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((sp_int128)a[i + 45]) << 19;
        r[i + 6] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((sp_int128)a[i + 46]) << 19;
        r[i + 7] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((sp_int128)a[i + 47]) << 19;
    }
    r[32] = n & 0x1fffffffffffffL; n >>= 53; n += ((sp_int128)a[72]) << 19;
    r[33] = n & 0x1fffffffffffffL; n >>= 53; n += ((sp_int128)a[73]) << 19;
    r[34] = n & 0x1fffffffffffffL; n >>= 53; n += ((sp_int128)a[74]) << 19;
    r[35] = n & 0x1fffffffffffffL; n >>= 53; n += ((sp_int128)a[75]) << 19;
    r[36] = n & 0x1fffffffffffffL; n >>= 53; n += ((sp_int128)a[76]) << 19;
    r[37] = n & 0x1fffffffffffffL; n >>= 53; n += ((sp_int128)a[77]) << 19;
    r[38] = (sp_digit)n;
    XMEMSET(&r[39], 0, sizeof(*r) * 39U);
}

/* Reduce the number back to 4096 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_4096_mont_reduce_39(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_4096_norm_39(a + 39);

    for (i=0; i<38; i++) {
        mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x1fffffffffffffL;
        sp_4096_mul_add_39(a+i, m, mu);
        a[i+1] += a[i] >> 53;
    }
    mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x3ffffffffL;
    sp_4096_mul_add_39(a+i, m, mu);
    a[i+1] += a[i] >> 53;
    a[i] &= 0x1fffffffffffffL;
    sp_4096_mont_shift_39(a, a);
    over = a[38] - m[38];
    sp_4096_cond_sub_39(a, a, m, ~((over - 1) >> 63));
    sp_4096_norm_39(a);
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
SP_NOINLINE static void sp_4096_mont_mul_39(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_4096_mul_39(r, a, b);
    sp_4096_mont_reduce_39(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_4096_mont_sqr_39(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_4096_sqr_39(r, a);
    sp_4096_mont_reduce_39(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_d_39(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t = 0;
    sp_digit t2;
    sp_int128 p[4];
    int i;

    for (i = 0; i < 36; i += 4) {
        p[0] = tb * a[i + 0];
        p[1] = tb * a[i + 1];
        p[2] = tb * a[i + 2];
        p[3] = tb * a[i + 3];
        t += p[0];
        t2 = (sp_digit)(t & 0x1fffffffffffffL);
        t >>= 53;
        r[i + 0] = (sp_digit)t2;
        t += p[1];
        t2 = (sp_digit)(t & 0x1fffffffffffffL);
        t >>= 53;
        r[i + 1] = (sp_digit)t2;
        t += p[2];
        t2 = (sp_digit)(t & 0x1fffffffffffffL);
        t >>= 53;
        r[i + 2] = (sp_digit)t2;
        t += p[3];
        t2 = (sp_digit)(t & 0x1fffffffffffffL);
        t >>= 53;
        r[i + 3] = (sp_digit)t2;
    }
    t += tb * a[36];
    r[36] = (sp_digit)(t & 0x1fffffffffffffL);
    t >>= 53;
    t += tb * a[37];
    r[37] = (sp_digit)(t & 0x1fffffffffffffL);
    t >>= 53;
    t += tb * a[38];
    r[38] = (sp_digit)(t & 0x1fffffffffffffL);
    t >>= 53;
    r[39] = (sp_digit)(t & 0x1fffffffffffffL);
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
static void sp_4096_cond_add_39(sp_digit* r, const sp_digit* a,
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
    r[36] = a[36] + (b[36] & m);
    r[37] = a[37] + (b[37] & m);
    r[38] = a[38] + (b[38] & m);
}
#endif /* !WOLFSSL_SP_SMALL */

SP_NOINLINE static void sp_4096_rshift_39(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    for (i=0; i<32; i += 8) {
        r[i+0] = (a[i+0] >> n) | ((a[i+1] << (53 - n)) & 0x1fffffffffffffL);
        r[i+1] = (a[i+1] >> n) | ((a[i+2] << (53 - n)) & 0x1fffffffffffffL);
        r[i+2] = (a[i+2] >> n) | ((a[i+3] << (53 - n)) & 0x1fffffffffffffL);
        r[i+3] = (a[i+3] >> n) | ((a[i+4] << (53 - n)) & 0x1fffffffffffffL);
        r[i+4] = (a[i+4] >> n) | ((a[i+5] << (53 - n)) & 0x1fffffffffffffL);
        r[i+5] = (a[i+5] >> n) | ((a[i+6] << (53 - n)) & 0x1fffffffffffffL);
        r[i+6] = (a[i+6] >> n) | ((a[i+7] << (53 - n)) & 0x1fffffffffffffL);
        r[i+7] = (a[i+7] >> n) | ((a[i+8] << (53 - n)) & 0x1fffffffffffffL);
    }
    r[32] = (a[32] >> n) | ((a[33] << (53 - n)) & 0x1fffffffffffffL);
    r[33] = (a[33] >> n) | ((a[34] << (53 - n)) & 0x1fffffffffffffL);
    r[34] = (a[34] >> n) | ((a[35] << (53 - n)) & 0x1fffffffffffffL);
    r[35] = (a[35] >> n) | ((a[36] << (53 - n)) & 0x1fffffffffffffL);
    r[36] = (a[36] >> n) | ((a[37] << (53 - n)) & 0x1fffffffffffffL);
    r[37] = (a[37] >> n) | ((a[38] << (53 - n)) & 0x1fffffffffffffL);
    r[38] = a[38] >> n;
}

static WC_INLINE sp_digit sp_4096_div_word_39(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int128 d = ((sp_int128)d1 << 53) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int128 d = ((sp_int128)d1 << 53) + d0;
    sp_uint64 lo = (sp_uint64)d;
    sp_digit hi = (sp_digit)(d >> 64);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int128 d = ((sp_int128)d1 << 53) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 53);
    sp_digit t0 = (sp_digit)(d & 0x1fffffffffffffL);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int128 m;

    r = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
    t1 -= dv & (0 - r);
    for (i = 51; i >= 1; i--) {
        t1 += t1 + (((sp_uint64)t0 >> 52) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int128)r * div);
    r += (sp_digit)(m >> 53);
    m = d - ((sp_int128)r * div);
    r += (m >> 106) - (sp_digit)(d >> 106);

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;
   return r;
#else
    sp_int128 d = ((sp_int128)d1 << 53) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 22) + 1;

    t = (sp_digit)(d >> 44);
    t = (t / dv) << 22;
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)(d >> 13);
    t = t / (dv << 9);
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int128)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_4096_word_div_word_39(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint64)(div - d) >> 63);
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
static int sp_4096_div_39(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_64
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 39 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 78 + 1;
        sd = t2 + 39 + 1;

        sp_4096_mul_d_39(sd, d, (sp_digit)1 << 19);
        sp_4096_mul_d_78(t1, a, (sp_digit)1 << 19);
        dv = sd[38];
        t1[39 + 39] += t1[39 + 39 - 1] >> 53;
        t1[39 + 39 - 1] &= 0x1fffffffffffffL;
        for (i=39; i>=0; i--) {
            r1 = sp_4096_div_word_39(t1[39 + i], t1[39 + i - 1], dv);

            sp_4096_mul_d_39(t2, sd, r1);
            (void)sp_4096_sub_39(&t1[i], &t1[i], t2);
            sp_4096_norm_39(&t1[i]);
            t1[39 + i] -= t2[39];
            t1[39 + i] += t1[39 + i - 1] >> 53;
            t1[39 + i - 1] &= 0x1fffffffffffffL;
            r1 = sp_4096_div_word_39(-t1[39 + i], -t1[39 + i - 1], dv);
            r1 -= t1[39 + i];
            sp_4096_mul_d_39(t2, sd, r1);
            (void)sp_4096_add_39(&t1[i], &t1[i], t2);
            t1[39 + i] += t1[39 + i - 1] >> 53;
            t1[39 + i - 1] &= 0x1fffffffffffffL;
        }
        t1[39 - 1] += t1[39 - 2] >> 53;
        t1[39 - 2] &= 0x1fffffffffffffL;
        r1 = sp_4096_word_div_word_39(t1[39 - 1], dv);

        sp_4096_mul_d_39(t2, sd, r1);
        sp_4096_sub_39(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 78U);
        for (i=0; i<38; i++) {
            r[i+1] += r[i] >> 53;
            r[i] &= 0x1fffffffffffffL;
        }
        sp_4096_cond_add_39(r, r, sd, r[38] >> 63);

        sp_4096_norm_39(r);
        sp_4096_rshift_39(r, r, 19);
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
static int sp_4096_mod_39(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_4096_div_39(a, m, NULL, r);
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
static int sp_4096_mod_exp_39(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 78];
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
            t[i] = td + (i * 39 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 39U * 2U);
        }

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_39(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_39(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 39U);
        }
    }
    if (err == MP_OKAY) {
        sp_4096_mul_39(t[1], t[1], norm);
        err = sp_4096_mod_39(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 53;
        c = bits % 53;
        n = e[i--] << (53 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 53;
            }

            y = (int)((n >> 52) & 1);
            n <<= 1;

            sp_4096_mont_mul_39(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 39 * 2);
            sp_4096_mont_sqr_39(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 39 * 2);
        }

        sp_4096_mont_reduce_39(t[0], m, mp);
        n = sp_4096_cmp_39(t[0], m);
        sp_4096_cond_sub_39(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 39 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 78];
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
            t[i] = td + (i * 39 * 2);
        }

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_39(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_39(t[1], a, m);
            if (err == MP_OKAY) {
                sp_4096_mul_39(t[1], t[1], norm);
                err = sp_4096_mod_39(t[1], t[1], m);
            }
        }
        else {
            sp_4096_mul_39(t[1], a, norm);
            err = sp_4096_mod_39(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 53;
        c = bits % 53;
        n = e[i--] << (53 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 53;
            }

            y = (int)((n >> 52) & 1);
            n <<= 1;

            sp_4096_mont_mul_39(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 39 * 2);
            sp_4096_mont_sqr_39(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 39 * 2);
        }

        sp_4096_mont_reduce_39(t[0], m, mp);
        n = sp_4096_cmp_39(t[0], m);
        sp_4096_cond_sub_39(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 39 * 2);
    }


    return err;
#else
    sp_digit td[(32 * 78) + 78];
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
            t[i] = td + i * 78;
        rt = td + 2496;

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_39(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_39(t[1], a, m);
            if (err == MP_OKAY) {
                sp_4096_mul_39(t[1], t[1], norm);
                err = sp_4096_mod_39(t[1], t[1], m);
            }
        }
        else {
            sp_4096_mul_39(t[1], a, norm);
            err = sp_4096_mod_39(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_4096_mont_sqr_39(t[ 2], t[ 1], m, mp);
        sp_4096_mont_mul_39(t[ 3], t[ 2], t[ 1], m, mp);
        sp_4096_mont_sqr_39(t[ 4], t[ 2], m, mp);
        sp_4096_mont_mul_39(t[ 5], t[ 3], t[ 2], m, mp);
        sp_4096_mont_sqr_39(t[ 6], t[ 3], m, mp);
        sp_4096_mont_mul_39(t[ 7], t[ 4], t[ 3], m, mp);
        sp_4096_mont_sqr_39(t[ 8], t[ 4], m, mp);
        sp_4096_mont_mul_39(t[ 9], t[ 5], t[ 4], m, mp);
        sp_4096_mont_sqr_39(t[10], t[ 5], m, mp);
        sp_4096_mont_mul_39(t[11], t[ 6], t[ 5], m, mp);
        sp_4096_mont_sqr_39(t[12], t[ 6], m, mp);
        sp_4096_mont_mul_39(t[13], t[ 7], t[ 6], m, mp);
        sp_4096_mont_sqr_39(t[14], t[ 7], m, mp);
        sp_4096_mont_mul_39(t[15], t[ 8], t[ 7], m, mp);
        sp_4096_mont_sqr_39(t[16], t[ 8], m, mp);
        sp_4096_mont_mul_39(t[17], t[ 9], t[ 8], m, mp);
        sp_4096_mont_sqr_39(t[18], t[ 9], m, mp);
        sp_4096_mont_mul_39(t[19], t[10], t[ 9], m, mp);
        sp_4096_mont_sqr_39(t[20], t[10], m, mp);
        sp_4096_mont_mul_39(t[21], t[11], t[10], m, mp);
        sp_4096_mont_sqr_39(t[22], t[11], m, mp);
        sp_4096_mont_mul_39(t[23], t[12], t[11], m, mp);
        sp_4096_mont_sqr_39(t[24], t[12], m, mp);
        sp_4096_mont_mul_39(t[25], t[13], t[12], m, mp);
        sp_4096_mont_sqr_39(t[26], t[13], m, mp);
        sp_4096_mont_mul_39(t[27], t[14], t[13], m, mp);
        sp_4096_mont_sqr_39(t[28], t[14], m, mp);
        sp_4096_mont_mul_39(t[29], t[15], t[14], m, mp);
        sp_4096_mont_sqr_39(t[30], t[15], m, mp);
        sp_4096_mont_mul_39(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 52) / 53) - 1;
        c = bits % 53;
        if (c == 0) {
            c = 53;
        }
        if (i < 39) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (11 - c);
            c += 53;
        }
        y = (int)((n >> 59) & 0x1f);
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 78);
        while ((i >= 0) || (c >= 5)) {
            if (c >= 5) {
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--] << 11;
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c = 48;
            }
            else {
                y = (byte)((n >> 59) & 0x1f);
                n = e[i--] << 11;
                c = 5 - c;
                y |= (byte)((n >> (64 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 53 - c;
            }

            sp_4096_mont_sqr_39(rt, rt, m, mp);
            sp_4096_mont_sqr_39(rt, rt, m, mp);
            sp_4096_mont_sqr_39(rt, rt, m, mp);
            sp_4096_mont_sqr_39(rt, rt, m, mp);
            sp_4096_mont_sqr_39(rt, rt, m, mp);

            sp_4096_mont_mul_39(rt, rt, t[y], m, mp);
        }

        sp_4096_mont_reduce_39(rt, m, mp);
        n = sp_4096_cmp_39(rt, m);
        sp_4096_cond_sub_39(rt, rt, m, ~(n >> 63));
        XMEMCPY(r, rt, sizeof(sp_digit) * 78);
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
static void sp_4096_mont_norm_78(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
    int i;

    for (i = 0; i < 72; i += 8) {
        r[i + 0] = 0x1fffffffffffffL;
        r[i + 1] = 0x1fffffffffffffL;
        r[i + 2] = 0x1fffffffffffffL;
        r[i + 3] = 0x1fffffffffffffL;
        r[i + 4] = 0x1fffffffffffffL;
        r[i + 5] = 0x1fffffffffffffL;
        r[i + 6] = 0x1fffffffffffffL;
        r[i + 7] = 0x1fffffffffffffL;
    }
    r[72] = 0x1fffffffffffffL;
    r[73] = 0x1fffffffffffffL;
    r[74] = 0x1fffffffffffffL;
    r[75] = 0x1fffffffffffffL;
    r[76] = 0x1fffffffffffffL;
    r[77] = 0x7fffL;

    /* r = (2^n - 1) mod n */
    (void)sp_4096_sub_78(r, r, m);

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
static sp_digit sp_4096_cmp_78(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
    int i;

    r |= (a[77] - b[77]) & (0 - (sp_digit)1);
    r |= (a[76] - b[76]) & ~(((sp_digit)0 - r) >> 52);
    r |= (a[75] - b[75]) & ~(((sp_digit)0 - r) >> 52);
    r |= (a[74] - b[74]) & ~(((sp_digit)0 - r) >> 52);
    r |= (a[73] - b[73]) & ~(((sp_digit)0 - r) >> 52);
    r |= (a[72] - b[72]) & ~(((sp_digit)0 - r) >> 52);
    for (i = 64; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & ~(((sp_digit)0 - r) >> 52);
        r |= (a[i + 6] - b[i + 6]) & ~(((sp_digit)0 - r) >> 52);
        r |= (a[i + 5] - b[i + 5]) & ~(((sp_digit)0 - r) >> 52);
        r |= (a[i + 4] - b[i + 4]) & ~(((sp_digit)0 - r) >> 52);
        r |= (a[i + 3] - b[i + 3]) & ~(((sp_digit)0 - r) >> 52);
        r |= (a[i + 2] - b[i + 2]) & ~(((sp_digit)0 - r) >> 52);
        r |= (a[i + 1] - b[i + 1]) & ~(((sp_digit)0 - r) >> 52);
        r |= (a[i + 0] - b[i + 0]) & ~(((sp_digit)0 - r) >> 52);
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
static void sp_4096_cond_sub_78(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
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
    r[72] = a[72] - (b[72] & m);
    r[73] = a[73] - (b[73] & m);
    r[74] = a[74] - (b[74] & m);
    r[75] = a[75] - (b[75] & m);
    r[76] = a[76] - (b[76] & m);
    r[77] = a[77] - (b[77] & m);
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_add_78(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t[8];
    int i;

    t[0] = tb * a[0]; r[0] += (sp_digit)(t[0] & 0x1fffffffffffffL);
    for (i = 0; i < 72; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] += (sp_digit)((t[0] >> 53) + (t[1] & 0x1fffffffffffffL));
        t[2] = tb * a[i+2];
        r[i+2] += (sp_digit)((t[1] >> 53) + (t[2] & 0x1fffffffffffffL));
        t[3] = tb * a[i+3];
        r[i+3] += (sp_digit)((t[2] >> 53) + (t[3] & 0x1fffffffffffffL));
        t[4] = tb * a[i+4];
        r[i+4] += (sp_digit)((t[3] >> 53) + (t[4] & 0x1fffffffffffffL));
        t[5] = tb * a[i+5];
        r[i+5] += (sp_digit)((t[4] >> 53) + (t[5] & 0x1fffffffffffffL));
        t[6] = tb * a[i+6];
        r[i+6] += (sp_digit)((t[5] >> 53) + (t[6] & 0x1fffffffffffffL));
        t[7] = tb * a[i+7];
        r[i+7] += (sp_digit)((t[6] >> 53) + (t[7] & 0x1fffffffffffffL));
        t[0] = tb * a[i+8];
        r[i+8] += (sp_digit)((t[7] >> 53) + (t[0] & 0x1fffffffffffffL));
    }
    t[1] = tb * a[73];
    r[73] += (sp_digit)((t[0] >> 53) + (t[1] & 0x1fffffffffffffL));
    t[2] = tb * a[74];
    r[74] += (sp_digit)((t[1] >> 53) + (t[2] & 0x1fffffffffffffL));
    t[3] = tb * a[75];
    r[75] += (sp_digit)((t[2] >> 53) + (t[3] & 0x1fffffffffffffL));
    t[4] = tb * a[76];
    r[76] += (sp_digit)((t[3] >> 53) + (t[4] & 0x1fffffffffffffL));
    t[5] = tb * a[77];
    r[77] += (sp_digit)((t[4] >> 53) + (t[5] & 0x1fffffffffffffL));
    r[78] +=  (sp_digit)(t[5] >> 53);
}

/* Shift the result in the high 4096 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_4096_mont_shift_78(sp_digit* r, const sp_digit* a)
{
    int i;
    sp_int128 n = a[77] >> 15;
    n += ((sp_int128)a[78]) << 38;
    for (i = 0; i < 72; i += 8) {
        r[i + 0] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((sp_int128)a[i + 79]) << 38;
        r[i + 1] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((sp_int128)a[i + 80]) << 38;
        r[i + 2] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((sp_int128)a[i + 81]) << 38;
        r[i + 3] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((sp_int128)a[i + 82]) << 38;
        r[i + 4] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((sp_int128)a[i + 83]) << 38;
        r[i + 5] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((sp_int128)a[i + 84]) << 38;
        r[i + 6] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((sp_int128)a[i + 85]) << 38;
        r[i + 7] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((sp_int128)a[i + 86]) << 38;
    }
    r[72] = n & 0x1fffffffffffffL; n >>= 53; n += ((sp_int128)a[151]) << 38;
    r[73] = n & 0x1fffffffffffffL; n >>= 53; n += ((sp_int128)a[152]) << 38;
    r[74] = n & 0x1fffffffffffffL; n >>= 53; n += ((sp_int128)a[153]) << 38;
    r[75] = n & 0x1fffffffffffffL; n >>= 53; n += ((sp_int128)a[154]) << 38;
    r[76] = n & 0x1fffffffffffffL; n >>= 53; n += ((sp_int128)a[155]) << 38;
    r[77] = (sp_digit)n;
    XMEMSET(&r[78], 0, sizeof(*r) * 78U);
}

/* Reduce the number back to 4096 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_4096_mont_reduce_78(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_4096_norm_78(a + 78);

#ifdef WOLFSSL_SP_DH
    if (mp != 1) {
        for (i=0; i<77; i++) {
            mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x1fffffffffffffL;
            sp_4096_mul_add_78(a+i, m, mu);
            a[i+1] += a[i] >> 53;
        }
        mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x7fffL;
        sp_4096_mul_add_78(a+i, m, mu);
        a[i+1] += a[i] >> 53;
        a[i] &= 0x1fffffffffffffL;
    }
    else {
        for (i=0; i<77; i++) {
            mu = a[i] & 0x1fffffffffffffL;
            sp_4096_mul_add_78(a+i, m, mu);
            a[i+1] += a[i] >> 53;
        }
        mu = a[i] & 0x7fffL;
        sp_4096_mul_add_78(a+i, m, mu);
        a[i+1] += a[i] >> 53;
        a[i] &= 0x1fffffffffffffL;
    }
#else
    for (i=0; i<77; i++) {
        mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x1fffffffffffffL;
        sp_4096_mul_add_78(a+i, m, mu);
        a[i+1] += a[i] >> 53;
    }
    mu = ((sp_uint64)a[i] * (sp_uint64)mp) & 0x7fffL;
    sp_4096_mul_add_78(a+i, m, mu);
    a[i+1] += a[i] >> 53;
    a[i] &= 0x1fffffffffffffL;
#endif
    sp_4096_mont_shift_78(a, a);
    over = a[77] - m[77];
    sp_4096_cond_sub_78(a, a, m, ~((over - 1) >> 63));
    sp_4096_norm_78(a);
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
SP_NOINLINE static void sp_4096_mont_mul_78(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_4096_mul_78(r, a, b);
    sp_4096_mont_reduce_78(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_4096_mont_sqr_78(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_4096_sqr_78(r, a);
    sp_4096_mont_reduce_78(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_d_156(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
    sp_int128 tb = b;
    sp_int128 t = 0;
    sp_digit t2;
    sp_int128 p[4];
    int i;

    for (i = 0; i < 156; i += 4) {
        p[0] = tb * a[i + 0];
        p[1] = tb * a[i + 1];
        p[2] = tb * a[i + 2];
        p[3] = tb * a[i + 3];
        t += p[0];
        t2 = (sp_digit)(t & 0x1fffffffffffffL);
        t >>= 53;
        r[i + 0] = (sp_digit)t2;
        t += p[1];
        t2 = (sp_digit)(t & 0x1fffffffffffffL);
        t >>= 53;
        r[i + 1] = (sp_digit)t2;
        t += p[2];
        t2 = (sp_digit)(t & 0x1fffffffffffffL);
        t >>= 53;
        r[i + 2] = (sp_digit)t2;
        t += p[3];
        t2 = (sp_digit)(t & 0x1fffffffffffffL);
        t >>= 53;
        r[i + 3] = (sp_digit)t2;
    }
    r[156] = (sp_digit)(t & 0x1fffffffffffffL);
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
static void sp_4096_cond_add_78(sp_digit* r, const sp_digit* a,
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
    r[72] = a[72] + (b[72] & m);
    r[73] = a[73] + (b[73] & m);
    r[74] = a[74] + (b[74] & m);
    r[75] = a[75] + (b[75] & m);
    r[76] = a[76] + (b[76] & m);
    r[77] = a[77] + (b[77] & m);
}
#endif /* !WOLFSSL_SP_SMALL */

SP_NOINLINE static void sp_4096_rshift_78(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

    for (i=0; i<72; i += 8) {
        r[i+0] = (a[i+0] >> n) | ((a[i+1] << (53 - n)) & 0x1fffffffffffffL);
        r[i+1] = (a[i+1] >> n) | ((a[i+2] << (53 - n)) & 0x1fffffffffffffL);
        r[i+2] = (a[i+2] >> n) | ((a[i+3] << (53 - n)) & 0x1fffffffffffffL);
        r[i+3] = (a[i+3] >> n) | ((a[i+4] << (53 - n)) & 0x1fffffffffffffL);
        r[i+4] = (a[i+4] >> n) | ((a[i+5] << (53 - n)) & 0x1fffffffffffffL);
        r[i+5] = (a[i+5] >> n) | ((a[i+6] << (53 - n)) & 0x1fffffffffffffL);
        r[i+6] = (a[i+6] >> n) | ((a[i+7] << (53 - n)) & 0x1fffffffffffffL);
        r[i+7] = (a[i+7] >> n) | ((a[i+8] << (53 - n)) & 0x1fffffffffffffL);
    }
    r[72] = (a[72] >> n) | ((a[73] << (53 - n)) & 0x1fffffffffffffL);
    r[73] = (a[73] >> n) | ((a[74] << (53 - n)) & 0x1fffffffffffffL);
    r[74] = (a[74] >> n) | ((a[75] << (53 - n)) & 0x1fffffffffffffL);
    r[75] = (a[75] >> n) | ((a[76] << (53 - n)) & 0x1fffffffffffffL);
    r[76] = (a[76] >> n) | ((a[77] << (53 - n)) & 0x1fffffffffffffL);
    r[77] = a[77] >> n;
}

static WC_INLINE sp_digit sp_4096_div_word_78(sp_digit d1, sp_digit d0,
    sp_digit div)
{
#ifdef SP_USE_DIVTI3
    sp_int128 d = ((sp_int128)d1 << 53) + d0;

    return d / div;
#elif defined(__x86_64__) || defined(__i386__)
    sp_int128 d = ((sp_int128)d1 << 53) + d0;
    sp_uint64 lo = (sp_uint64)d;
    sp_digit hi = (sp_digit)(d >> 64);

    __asm__ __volatile__ (
        "idiv %2"
        : "+a" (lo)
        : "d" (hi), "r" (div)
        : "cc"
    );

    return (sp_digit)lo;
#elif !defined(__aarch64__) &&  !defined(SP_DIV_WORD_USE_DIV)
    sp_int128 d = ((sp_int128)d1 << 53) + d0;
    sp_digit dv = (div >> 1) + 1;
    sp_digit t1 = (sp_digit)(d >> 53);
    sp_digit t0 = (sp_digit)(d & 0x1fffffffffffffL);
    sp_digit t2;
    sp_digit sign;
    sp_digit r;
    int i;
    sp_int128 m;

    r = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
    t1 -= dv & (0 - r);
    for (i = 51; i >= 1; i--) {
        t1 += t1 + (((sp_uint64)t0 >> 52) & 1);
        t0 <<= 1;
        t2 = (sp_digit)(((sp_uint64)(dv - t1)) >> 63);
        r += r + t2;
        t1 -= dv & (0 - t2);
        t1 += t2;
    }
    r += r + 1;

    m = d - ((sp_int128)r * div);
    r += (sp_digit)(m >> 53);
    m = d - ((sp_int128)r * div);
    r += (m >> 106) - (sp_digit)(d >> 106);

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;

    m = d - ((sp_int128)r * div);
    sign = (sp_digit)(0 - ((sp_uint64)m >> 63)) * 2 + 1;
    m *= sign;
    t2 = (sp_digit)(((sp_uint64)(div - m)) >> 63);
    r += sign * t2;
   return r;
#else
    sp_int128 d = ((sp_int128)d1 << 53) + d0;
    sp_digit r = 0;
    sp_digit t;
    sp_digit dv = (div >> 22) + 1;

    t = (sp_digit)(d >> 44);
    t = (t / dv) << 22;
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)(d >> 13);
    t = t / (dv << 9);
    r += t;
    d -= (sp_int128)t * div;
    t = (sp_digit)d;
    t = t / div;
    r += t;
    d -= (sp_int128)t * div;
    return r;
#endif
}
static WC_INLINE sp_digit sp_4096_word_div_word_78(sp_digit d, sp_digit div)
{
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(SP_DIV_WORD_USE_DIV)
    return d / div;
#else
    return (sp_digit)((sp_uint64)(div - d) >> 63);
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
static int sp_4096_div_78(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_64
#endif
    sp_digit dv;
    sp_digit r1;
    sp_digit t1[4 * 78 + 3];
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;


    (void)m;

    if (err == MP_OKAY) {
        t2 = t1 + 156 + 1;
        sd = t2 + 78 + 1;

        sp_4096_mul_d_78(sd, d, (sp_digit)1 << 38);
        sp_4096_mul_d_156(t1, a, (sp_digit)1 << 38);
        dv = sd[77];
        t1[78 + 78] += t1[78 + 78 - 1] >> 53;
        t1[78 + 78 - 1] &= 0x1fffffffffffffL;
        for (i=78; i>=0; i--) {
            r1 = sp_4096_div_word_78(t1[78 + i], t1[78 + i - 1], dv);

            sp_4096_mul_d_78(t2, sd, r1);
            (void)sp_4096_sub_78(&t1[i], &t1[i], t2);
            sp_4096_norm_78(&t1[i]);
            t1[78 + i] -= t2[78];
            t1[78 + i] += t1[78 + i - 1] >> 53;
            t1[78 + i - 1] &= 0x1fffffffffffffL;
            r1 = sp_4096_div_word_78(-t1[78 + i], -t1[78 + i - 1], dv);
            r1 -= t1[78 + i];
            sp_4096_mul_d_78(t2, sd, r1);
            (void)sp_4096_add_78(&t1[i], &t1[i], t2);
            t1[78 + i] += t1[78 + i - 1] >> 53;
            t1[78 + i - 1] &= 0x1fffffffffffffL;
        }
        t1[78 - 1] += t1[78 - 2] >> 53;
        t1[78 - 2] &= 0x1fffffffffffffL;
        r1 = sp_4096_word_div_word_78(t1[78 - 1], dv);

        sp_4096_mul_d_78(t2, sd, r1);
        sp_4096_sub_78(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 156U);
        for (i=0; i<77; i++) {
            r[i+1] += r[i] >> 53;
            r[i] &= 0x1fffffffffffffL;
        }
        sp_4096_cond_add_78(r, r, sd, r[77] >> 63);

        sp_4096_norm_78(r);
        sp_4096_rshift_78(r, r, 38);
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
static int sp_4096_mod_78(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_4096_div_78(a, m, NULL, r);
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
static int sp_4096_mod_exp_78(sp_digit* r, const sp_digit* a, const sp_digit* e,
    int bits, const sp_digit* m, int reduceA)
{
#if defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_FAST_MODEXP)
    sp_digit td[3 * 156];
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
            t[i] = td + (i * 78 * 2);
            XMEMSET(t[i], 0, sizeof(sp_digit) * 78U * 2U);
        }

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_78(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_78(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 78U);
        }
    }
    if (err == MP_OKAY) {
        sp_4096_mul_78(t[1], t[1], norm);
        err = sp_4096_mod_78(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 53;
        c = bits % 53;
        n = e[i--] << (53 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 53;
            }

            y = (int)((n >> 52) & 1);
            n <<= 1;

            sp_4096_mont_mul_78(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 78 * 2);
            sp_4096_mont_sqr_78(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 78 * 2);
        }

        sp_4096_mont_reduce_78(t[0], m, mp);
        n = sp_4096_cmp_78(t[0], m);
        sp_4096_cond_sub_78(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 78 * 2);

    }


    return err;
#elif !defined(WC_NO_CACHE_RESISTANT)
    sp_digit td[3 * 156];
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
            t[i] = td + (i * 78 * 2);
        }

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_78(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_78(t[1], a, m);
            if (err == MP_OKAY) {
                sp_4096_mul_78(t[1], t[1], norm);
                err = sp_4096_mod_78(t[1], t[1], m);
            }
        }
        else {
            sp_4096_mul_78(t[1], a, norm);
            err = sp_4096_mod_78(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 53;
        c = bits % 53;
        n = e[i--] << (53 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 53;
            }

            y = (int)((n >> 52) & 1);
            n <<= 1;

            sp_4096_mont_mul_78(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                                  sizeof(*t[2]) * 78 * 2);
            sp_4096_mont_sqr_78(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                            sizeof(*t[2]) * 78 * 2);
        }

        sp_4096_mont_reduce_78(t[0], m, mp);
        n = sp_4096_cmp_78(t[0], m);
        sp_4096_cond_sub_78(t[0], t[0], m, ~(n >> 63));
        XMEMCPY(r, t[0], sizeof(*r) * 78 * 2);
    }


    return err;
#else
    sp_digit td[(16 * 156) + 156];
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
            t[i] = td + i * 156;
        rt = td + 2496;

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_78(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_78(t[1], a, m);
            if (err == MP_OKAY) {
                sp_4096_mul_78(t[1], t[1], norm);
                err = sp_4096_mod_78(t[1], t[1], m);
            }
        }
        else {
            sp_4096_mul_78(t[1], a, norm);
            err = sp_4096_mod_78(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_4096_mont_sqr_78(t[ 2], t[ 1], m, mp);
        sp_4096_mont_mul_78(t[ 3], t[ 2], t[ 1], m, mp);
        sp_4096_mont_sqr_78(t[ 4], t[ 2], m, mp);
        sp_4096_mont_mul_78(t[ 5], t[ 3], t[ 2], m, mp);
        sp_4096_mont_sqr_78(t[ 6], t[ 3], m, mp);
        sp_4096_mont_mul_78(t[ 7], t[ 4], t[ 3], m, mp);
        sp_4096_mont_sqr_78(t[ 8], t[ 4], m, mp);
        sp_4096_mont_mul_78(t[ 9], t[ 5], t[ 4], m, mp);
        sp_4096_mont_sqr_78(t[10], t[ 5], m, mp);
        sp_4096_mont_mul_78(t[11], t[ 6], t[ 5], m, mp);
        sp_4096_mont_sqr_78(t[12], t[ 6], m, mp);
        sp_4096_mont_mul_78(t[13], t[ 7], t[ 6], m, mp);
        sp_4096_mont_sqr_78(t[14], t[ 7], m, mp);
        sp_4096_mont_mul_78(t[15], t[ 8], t[ 7], m, mp);

        bits = ((bits + 3) / 4) * 4;
        i = ((bits + 52) / 53) - 1;
        c = bits % 53;
        if (c == 0) {
            c = 53;
        }
        if (i < 78) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 4) {
            n |= e[i--] << (11 - c);
            c += 53;
        }
        y = (int)((n >> 60) & 0xf);
        n <<= 4;
        c -= 4;
        XMEMCPY(rt, t[y], sizeof(sp_digit) * 156);
        while ((i >= 0) || (c >= 4)) {
            if (c >= 4) {
                y = (byte)((n >> 60) & 0xf);
                n <<= 4;
                c -= 4;
            }
            else if (c == 0) {
                n = e[i--] << 11;
                y = (byte)((n >> 60) & 0xf);
                n <<= 4;
                c = 49;
            }
            else {
                y = (byte)((n >> 60) & 0xf);
                n = e[i--] << 11;
                c = 4 - c;
                y |= (byte)((n >> (64 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 53 - c;
            }

            sp_4096_mont_sqr_78(rt, rt, m, mp);
            sp_4096_mont_sqr_78(rt, rt, m, mp);
            sp_4096_mont_sqr_78(rt, rt, m, mp);
            sp_4096_mont_sqr_78(rt, rt, m, mp);

            sp_4096_mont_mul_78(rt, rt, t[y], m, mp);
        }

        sp_4096_mont_reduce_78(rt, m, mp);
        n = sp_4096_cmp_78(rt, m);
        sp_4096_cond_sub_78(rt, rt, m, ~(n >> 63));
        XMEMCPY(r, rt, sizeof(sp_digit) * 156);
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
    sp_digit a[78 * 5];
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
        if (mp_count_bits(em) > 53) {
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
        r = a + 78 * 2;
        m = r + 78 * 2;
        norm = r;

        sp_4096_from_bin(a, 78, in, inLen);
#if DIGIT_BIT >= 53
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
        sp_4096_from_mp(m, 78, mm);

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_78(norm, m);
    }
    if (err == MP_OKAY) {
        sp_4096_mul_78(a, a, norm);
        err = sp_4096_mod_78(a, a, m);
    }
    if (err == MP_OKAY) {
        for (i=52; i>=0; i--) {
            if ((e[0] >> i) != 0) {
                break;
            }
        }

        XMEMCPY(r, a, sizeof(sp_digit) * 78 * 2);
        for (i--; i>=0; i--) {
            sp_4096_mont_sqr_78(r, r, m, mp);

            if (((e[0] >> i) & 1) == 1) {
                sp_4096_mont_mul_78(r, r, a, m, mp);
            }
        }
        sp_4096_mont_reduce_78(r, m, mp);
        mp = sp_4096_cmp_78(r, m);
        sp_4096_cond_sub_78(r, r, m, ~(mp >> 63));

        sp_4096_to_bin_78(r, out);
        *outLen = 512;
    }


    return err;
#else
    sp_digit d[78 * 5];
    sp_digit* a = NULL;
    sp_digit* m = NULL;
    sp_digit* r = NULL;
    sp_digit e[1] = {0};
    int err = MP_OKAY;

    if (*outLen < 512U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 53) {
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
        r = a + 78 * 2;
        m = r + 78 * 2;

        sp_4096_from_bin(a, 78, in, inLen);
#if DIGIT_BIT >= 53
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
        sp_4096_from_mp(m, 78, mm);

        if (e[0] == 0x3) {
            sp_4096_sqr_78(r, a);
            err = sp_4096_mod_78(r, r, m);
            if (err == MP_OKAY) {
                sp_4096_mul_78(r, a, r);
                err = sp_4096_mod_78(r, r, m);
            }
        }
        else {
            sp_digit* norm = r;
            int i;
            sp_digit mp;

            sp_4096_mont_setup(m, &mp);
            sp_4096_mont_norm_78(norm, m);

            sp_4096_mul_78(a, a, norm);
            err = sp_4096_mod_78(a, a, m);

            if (err == MP_OKAY) {
                for (i=52; i>=0; i--) {
                    if ((e[0] >> i) != 0) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 156U);
                for (i--; i>=0; i--) {
                    sp_4096_mont_sqr_78(r, r, m, mp);

                    if (((e[0] >> i) & 1) == 1) {
                        sp_4096_mont_mul_78(r, r, a, m, mp);
                    }
                }
                sp_4096_mont_reduce_78(r, m, mp);
                mp = sp_4096_cmp_78(r, m);
                sp_4096_cond_sub_78(r, r, m, ~(mp >> 63));
            }
        }
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_78(r, out);
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
    sp_digit  d[78 * 4];
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
        a = d + 78;
        m = a + 156;
        r = a;

        sp_4096_from_bin(a, 78, in, inLen);
        sp_4096_from_mp(d, 78, dm);
        sp_4096_from_mp(m, 78, mm);
        err = sp_4096_mod_exp_78(r, a, d, 4096, m, 0);
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_78(r, out);
        *outLen = 512;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 78);
    }

    return err;
#else
    sp_digit d[78 * 4];
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
        a = d + 78;
        m = a + 156;
        r = a;

        sp_4096_from_bin(a, 78, in, inLen);
        sp_4096_from_mp(d, 78, dm);
        sp_4096_from_mp(m, 78, mm);
        err = sp_4096_mod_exp_78(r, a, d, 4096, m, 0);
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_78(r, out);
        *outLen = 512;
    }

    {
        /* only "a" and "r" are sensitive and need zeroized (same pointer) */
        if (a != NULL)
            ForceZero(a, sizeof(sp_digit) * 78);
    }

    return err;
#endif /* WOLFSSL_SP_SMALL */
#else
#if defined(WOLFSSL_SP_SMALL)
    sp_digit a[39 * 8];
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
        p = a + 78;
        qi = dq = dp = p + 39;
        tmpa = qi + 39;
        tmpb = tmpa + 78;
        r = a;

        sp_4096_from_bin(a, 78, in, inLen);
        sp_4096_from_mp(p, 39, pm);
        sp_4096_from_mp(dp, 39, dpm);
        err = sp_4096_mod_exp_39(tmpa, a, dp, 2048, p, 1);
    }
    if (err == MP_OKAY) {
        sp_4096_from_mp(p, 39, qm);
        sp_4096_from_mp(dq, 39, dqm);
        err = sp_4096_mod_exp_39(tmpb, a, dq, 2048, p, 1);
    }
    if (err == MP_OKAY) {
        sp_4096_from_mp(p, 39, pm);
        (void)sp_4096_sub_39(tmpa, tmpa, tmpb);
        sp_4096_norm_39(tmpa);
        sp_4096_cond_add_39(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[38] >> 63));
        sp_4096_cond_add_39(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[38] >> 63));
        sp_4096_norm_39(tmpa);

        sp_4096_from_mp(qi, 39, qim);
        sp_4096_mul_39(tmpa, tmpa, qi);
        err = sp_4096_mod_39(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_4096_from_mp(p, 39, qm);
        sp_4096_mul_39(tmpa, p, tmpa);
        (void)sp_4096_add_78(r, tmpb, tmpa);
        sp_4096_norm_78(r);

        sp_4096_to_bin_78(r, out);
        *outLen = 512;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 39 * 8);
    }

    return err;
#else
    sp_digit a[39 * 13];
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
        p = a + 78 * 2;
        q = p + 39;
        dp = q + 39;
        dq = dp + 39;
        qi = dq + 39;
        tmpa = qi + 39;
        tmpb = tmpa + 78;
        r = a;

        sp_4096_from_bin(a, 78, in, inLen);
        sp_4096_from_mp(p, 39, pm);
        sp_4096_from_mp(q, 39, qm);
        sp_4096_from_mp(dp, 39, dpm);
        sp_4096_from_mp(dq, 39, dqm);
        sp_4096_from_mp(qi, 39, qim);

        err = sp_4096_mod_exp_39(tmpa, a, dp, 2048, p, 1);
    }
    if (err == MP_OKAY) {
        err = sp_4096_mod_exp_39(tmpb, a, dq, 2048, q, 1);
    }

    if (err == MP_OKAY) {
        (void)sp_4096_sub_39(tmpa, tmpa, tmpb);
        sp_4096_norm_39(tmpa);
        sp_4096_cond_add_39(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[38] >> 63));
        sp_4096_cond_add_39(tmpa, tmpa, p, 0 - ((sp_int_digit)tmpa[38] >> 63));
        sp_4096_norm_39(tmpa);
        sp_4096_mul_39(tmpa, tmpa, qi);
        err = sp_4096_mod_39(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_4096_mul_39(tmpa, tmpa, q);
        (void)sp_4096_add_78(r, tmpb, tmpa);
        sp_4096_norm_78(r);

        sp_4096_to_bin_78(r, out);
        *outLen = 512;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 39 * 13);
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
#if DIGIT_BIT == 53
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 78);
        r->used = 78;
        mp_clamp(r);
#elif DIGIT_BIT < 53
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 78; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 53) {
                s += DIGIT_BIT;
                r->dp[j++] &= ((sp_digit)1 << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 53 - s;
        }
        r->used = (4096 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 78; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 53 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= ((sp_digit)1 << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 53 - s;
            }
            else {
                s += 53;
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
    sp_digit b[78 * 4];
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
        e = b + 78 * 2;
        m = e + 78;
        r = b;

        sp_4096_from_mp(b, 78, base);
        sp_4096_from_mp(e, 78, exp);
        sp_4096_from_mp(m, 78, mod);

        err = sp_4096_mod_exp_78(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_4096_to_mp(r, res);
    }

    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 78U);
    }
    return err;
#else
    sp_digit b[78 * 4];
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
        e = b + 78 * 2;
        m = e + 78;
        r = b;

        sp_4096_from_mp(b, 78, base);
        sp_4096_from_mp(e, 78, exp);
        sp_4096_from_mp(m, 78, mod);

        err = sp_4096_mod_exp_78(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_4096_to_mp(r, res);
    }


    {
        /* only "e" is sensitive and needs zeroized */
        if (e != NULL)
            ForceZero(e, sizeof(sp_digit) * 78U);
    }

    return err;
#endif
}

#ifdef WOLFSSL_HAVE_SP_DH

#ifdef HAVE_FFDHE_4096
SP_NOINLINE static void sp_4096_lshift_78(sp_digit* r, const sp_digit* a,
        byte n)
{
    sp_int_digit s;
    sp_int_digit t;

    s = (sp_int_digit)a[77];
    r[78] = s >> (53U - n);
    s = (sp_int_digit)(a[77]); t = (sp_int_digit)(a[76]);
    r[77] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[76]); t = (sp_int_digit)(a[75]);
    r[76] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[75]); t = (sp_int_digit)(a[74]);
    r[75] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[74]); t = (sp_int_digit)(a[73]);
    r[74] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[73]); t = (sp_int_digit)(a[72]);
    r[73] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[72]); t = (sp_int_digit)(a[71]);
    r[72] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[71]); t = (sp_int_digit)(a[70]);
    r[71] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[70]); t = (sp_int_digit)(a[69]);
    r[70] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[69]); t = (sp_int_digit)(a[68]);
    r[69] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[68]); t = (sp_int_digit)(a[67]);
    r[68] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[67]); t = (sp_int_digit)(a[66]);
    r[67] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[66]); t = (sp_int_digit)(a[65]);
    r[66] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[65]); t = (sp_int_digit)(a[64]);
    r[65] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[64]); t = (sp_int_digit)(a[63]);
    r[64] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[63]); t = (sp_int_digit)(a[62]);
    r[63] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[62]); t = (sp_int_digit)(a[61]);
    r[62] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[61]); t = (sp_int_digit)(a[60]);
    r[61] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[60]); t = (sp_int_digit)(a[59]);
    r[60] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[59]); t = (sp_int_digit)(a[58]);
    r[59] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[58]); t = (sp_int_digit)(a[57]);
    r[58] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[57]); t = (sp_int_digit)(a[56]);
    r[57] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[56]); t = (sp_int_digit)(a[55]);
    r[56] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[55]); t = (sp_int_digit)(a[54]);
    r[55] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[54]); t = (sp_int_digit)(a[53]);
    r[54] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[53]); t = (sp_int_digit)(a[52]);
    r[53] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[52]); t = (sp_int_digit)(a[51]);
    r[52] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[51]); t = (sp_int_digit)(a[50]);
    r[51] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[50]); t = (sp_int_digit)(a[49]);
    r[50] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[49]); t = (sp_int_digit)(a[48]);
    r[49] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[48]); t = (sp_int_digit)(a[47]);
    r[48] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[47]); t = (sp_int_digit)(a[46]);
    r[47] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[46]); t = (sp_int_digit)(a[45]);
    r[46] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[45]); t = (sp_int_digit)(a[44]);
    r[45] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[44]); t = (sp_int_digit)(a[43]);
    r[44] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[43]); t = (sp_int_digit)(a[42]);
    r[43] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[42]); t = (sp_int_digit)(a[41]);
    r[42] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[41]); t = (sp_int_digit)(a[40]);
    r[41] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[40]); t = (sp_int_digit)(a[39]);
    r[40] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[39]); t = (sp_int_digit)(a[38]);
    r[39] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[38]); t = (sp_int_digit)(a[37]);
    r[38] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[37]); t = (sp_int_digit)(a[36]);
    r[37] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[36]); t = (sp_int_digit)(a[35]);
    r[36] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[35]); t = (sp_int_digit)(a[34]);
    r[35] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[34]); t = (sp_int_digit)(a[33]);
    r[34] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[33]); t = (sp_int_digit)(a[32]);
    r[33] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[32]); t = (sp_int_digit)(a[31]);
    r[32] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[31]); t = (sp_int_digit)(a[30]);
    r[31] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[30]); t = (sp_int_digit)(a[29]);
    r[30] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[29]); t = (sp_int_digit)(a[28]);
    r[29] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[28]); t = (sp_int_digit)(a[27]);
    r[28] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[27]); t = (sp_int_digit)(a[26]);
    r[27] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[26]); t = (sp_int_digit)(a[25]);
    r[26] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[25]); t = (sp_int_digit)(a[24]);
    r[25] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[24]); t = (sp_int_digit)(a[23]);
    r[24] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[23]); t = (sp_int_digit)(a[22]);
    r[23] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[22]); t = (sp_int_digit)(a[21]);
    r[22] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[21]); t = (sp_int_digit)(a[20]);
    r[21] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[20]); t = (sp_int_digit)(a[19]);
    r[20] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[19]); t = (sp_int_digit)(a[18]);
    r[19] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[18]); t = (sp_int_digit)(a[17]);
    r[18] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[17]); t = (sp_int_digit)(a[16]);
    r[17] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[16]); t = (sp_int_digit)(a[15]);
    r[16] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[15]); t = (sp_int_digit)(a[14]);
    r[15] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[14]); t = (sp_int_digit)(a[13]);
    r[14] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[13]); t = (sp_int_digit)(a[12]);
    r[13] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[12]); t = (sp_int_digit)(a[11]);
    r[12] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[11]); t = (sp_int_digit)(a[10]);
    r[11] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[10]); t = (sp_int_digit)(a[9]);
    r[10] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[9]); t = (sp_int_digit)(a[8]);
    r[9] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[8]); t = (sp_int_digit)(a[7]);
    r[8] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[7]); t = (sp_int_digit)(a[6]);
    r[7] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[6]); t = (sp_int_digit)(a[5]);
    r[6] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[5]); t = (sp_int_digit)(a[4]);
    r[5] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[4]); t = (sp_int_digit)(a[3]);
    r[4] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[3]); t = (sp_int_digit)(a[2]);
    r[3] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[2]); t = (sp_int_digit)(a[1]);
    r[2] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[1]); t = (sp_int_digit)(a[0]);
    r[1] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    r[0] = (a[0] << n) & 0x1fffffffffffffL;
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
static int sp_4096_mod_exp_2_78(sp_digit* r, const sp_digit* e, int bits, const sp_digit* m)
{
    sp_digit td[235];
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
        tmp  = td + 156;
        XMEMSET(td, 0, sizeof(sp_digit) * 235);

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_78(norm, m);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 52) / 53) - 1;
        c = bits % 53;
        if (c == 0) {
            c = 53;
        }
        if (i < 78) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (11 - c);
            c += 53;
        }
        y = (int)((n >> 59) & 0x1f);
        n <<= 5;
        c -= 5;
        sp_4096_lshift_78(r, norm, (byte)y);
        while ((i >= 0) || (c >= 5)) {
            if (c >= 5) {
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--] << 11;
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c = 48;
            }
            else {
                y = (byte)((n >> 59) & 0x1f);
                n = e[i--] << 11;
                c = 5 - c;
                y |= (byte)((n >> (64 - c)) & ((1 << c) - 1));
                n <<= c;
                c = 53 - c;
            }

            sp_4096_mont_sqr_78(r, r, m, mp);
            sp_4096_mont_sqr_78(r, r, m, mp);
            sp_4096_mont_sqr_78(r, r, m, mp);
            sp_4096_mont_sqr_78(r, r, m, mp);
            sp_4096_mont_sqr_78(r, r, m, mp);

            sp_4096_lshift_78(r, r, (byte)y);
            sp_4096_mul_d_78(tmp, norm, (r[78] << 38) + (r[77] >> 15));
            r[78] = 0;
            r[77] &= 0x7fffL;
            (void)sp_4096_add_78(r, r, tmp);
            sp_4096_norm_78(r);
            o = sp_4096_cmp_78(r, m);
            sp_4096_cond_sub_78(r, r, m, ~(o >> 63));
        }

        sp_4096_mont_reduce_78(r, m, mp);
        n = sp_4096_cmp_78(r, m);
        sp_4096_cond_sub_78(r, r, m, ~(n >> 63));
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
    sp_digit b[78 * 4];
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
        e = b + 78 * 2;
        m = e + 78;
        r = b;

        sp_4096_from_mp(b, 78, base);
        sp_4096_from_bin(e, 78, exp, expLen);
        sp_4096_from_mp(m, 78, mod);

    #ifdef HAVE_FFDHE_4096
        if (base->used == 1 && base->dp[0] == 2U &&
                ((m[77] << 17) | (m[76] >> 36)) == 0xffffffffL) {
            err = sp_4096_mod_exp_2_78(r, e, expLen * 8U, m);
        }
        else {
    #endif
            err = sp_4096_mod_exp_78(r, b, e, expLen * 8U, m, 0);
    #ifdef HAVE_FFDHE_4096
        }
    #endif
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin_78(r, out);
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
            ForceZero(e, sizeof(sp_digit) * 78U);
    }

    return err;
}
#endif /* WOLFSSL_HAVE_SP_DH */

#endif /* WOLFSSL_HAVE_SP_DH | (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) */

#endif /* WOLFSSL_SP_SMALL */
#endif /* WOLFSSL_SP_4096 */

#endif /* WOLFSSL_HAVE_SP_RSA | WOLFSSL_HAVE_SP_DH */
#endif /* SP_WORD_SIZE == 64 */
#endif /* !WOLFSSL_SP_ASM */
#endif /* WOLFSSL_HAVE_SP_RSA | WOLFSSL_HAVE_SP_DH | WOLFSSL_HAVE_SP_ECC */
