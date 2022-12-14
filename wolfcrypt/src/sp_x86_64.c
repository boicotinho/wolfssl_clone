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

#ifdef WOLFSSL_SP_X86_64_ASM
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
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_from_bin_bswap(sp_digit* r, int size, const byte* a, int n);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_from_bin_movbe(sp_digit* r, int size, const byte* a, int n);
#ifdef __cplusplus
}
#endif
/* Read big endian unsigned byte array into r.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  Byte array.
 * n  Number of bytes in array to read.
 */
static void sp_2048_from_bin(sp_digit* r, int size, const byte* a, int n)
{
#ifndef NO_MOVBE_SUPPORT
    word32 cpuid_flags = cpuid_get_flags();

    if (IS_INTEL_MOVBE(cpuid_flags)) {
        sp_2048_from_bin_movbe(r, size, a, n);
    }
    else
#endif
    {
        sp_2048_from_bin_bswap(r, size, a, n);
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

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_to_bin_bswap_32(sp_digit* r, byte* a);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_to_bin_movbe_32(sp_digit* r, byte* a);
#ifdef __cplusplus
}
#endif
/* Write r as big endian to byte array.
 * Fixed length number of bytes written: 256
 *
 * r  A single precision integer.
 * a  Byte array.
 */
static void sp_2048_to_bin_32(sp_digit* r, byte* a)
{
#ifndef NO_MOVBE_SUPPORT
    word32 cpuid_flags = cpuid_get_flags();

    if (IS_INTEL_MOVBE(cpuid_flags)) {
        sp_2048_to_bin_movbe_32(r, a);
    }
    else
#endif
    {
        sp_2048_to_bin_bswap_32(r, a);
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

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_mul_16(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_mul_avx2_16(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_2048_add_16(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_2048_sub_in_place_32(sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_2048_add_32(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_mul_32(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_mul_avx2_32(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_sqr_16(sp_digit* r, const sp_digit* a);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_sqr_avx2_16(sp_digit* r, const sp_digit* a);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_sqr_32(sp_digit* r, const sp_digit* a);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_sqr_avx2_32(sp_digit* r, const sp_digit* a);
#ifdef __cplusplus
}
#endif

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_2048_sub_in_place_16(sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
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

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_mul_d_32(sp_digit* r, const sp_digit* a, sp_digit b);
#ifdef __cplusplus
}
#endif
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

    ASSERT_SAVED_VECTOR_REGISTERS();

    /* r = 2^n mod m */
    sp_2048_sub_in_place_16(r, m);
}

#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_2048_cond_sub_16(sp_digit* r, const sp_digit* a, const sp_digit* b, sp_digit m);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_mont_reduce_16(sp_digit* a, const sp_digit* m, sp_digit mp);
#ifdef __cplusplus
}
#endif
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

#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_2048_cond_sub_avx2_16(sp_digit* r, const sp_digit* a, const sp_digit* b, sp_digit m);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_mul_d_16(sp_digit* r, const sp_digit* a, sp_digit b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_mul_d_avx2_16(sp_digit* r, const sp_digit* a, const sp_digit b);
#ifdef __cplusplus
}
#endif
#ifdef _WIN64
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit div_2048_word_asm_16(sp_digit d1, sp_digit d0, sp_digit div);
#ifdef __cplusplus
}
#endif
/* Divide the double width number (d1|d0) by the dividend. (d1|d0 / div)
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The dividend.
 * returns the result of the division.
 */
static WC_INLINE sp_digit div_2048_word_16(sp_digit d1, sp_digit d0,
        sp_digit div)
{
    ASSERT_SAVED_VECTOR_REGISTERS();
    return div_2048_word_asm_16(d1, d0, div);
}
#else
/* Divide the double width number (d1|d0) by the dividend. (d1|d0 / div)
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The dividend.
 * returns the result of the division.
 */
static WC_INLINE sp_digit div_2048_word_16(sp_digit d1, sp_digit d0,
        sp_digit div)
{
    ASSERT_SAVED_VECTOR_REGISTERS();
    register sp_digit r asm("rax");
    __asm__ __volatile__ (
        "divq %3"
        : "=a" (r)
        : "d" (d1), "a" (d0), "r" (div)
        :
    );
    return r;
}
#endif /* _WIN64 */
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

#ifdef __cplusplus
extern "C" {
#endif
extern sp_int64 sp_2048_cmp_16(const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
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
    sp_digit t1[32];
    sp_digit t2[17];
    sp_digit div;
    sp_digit r1;
    int i;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

    ASSERT_SAVED_VECTOR_REGISTERS();

    (void)m;

    div = d[15];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 16);
    r1 = sp_2048_cmp_16(&t1[16], d) >= 0;
#ifdef HAVE_INTEL_AVX2
    if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
        sp_2048_cond_sub_avx2_16(&t1[16], &t1[16], d, (sp_digit)0 - r1);
    else
#endif
        sp_2048_cond_sub_16(&t1[16], &t1[16], d, (sp_digit)0 - r1);
    for (i = 15; i >= 0; i--) {
        sp_digit mask = 0 - (t1[16 + i] == div);
        sp_digit hi = t1[16 + i] + mask;
        r1 = div_2048_word_16(hi, t1[16 + i - 1], div);
        r1 |= mask;

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            sp_2048_mul_d_avx2_16(t2, d, r1);
        else
#endif
            sp_2048_mul_d_16(t2, d, r1);
        t1[16 + i] += sp_2048_sub_in_place_16(&t1[i], t2);
        t1[16 + i] -= t2[16];
        sp_2048_mask_16(t2, d, t1[16 + i]);
        t1[16 + i] += sp_2048_add_16(&t1[i], &t1[i], t2);
        sp_2048_mask_16(t2, d, t1[16 + i]);
        t1[16 + i] += sp_2048_add_16(&t1[i], &t1[i], t2);
    }

    r1 = sp_2048_cmp_16(t1, d) >= 0;
#ifdef HAVE_INTEL_AVX2
    if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
        sp_2048_cond_sub_avx2_16(r, t1, d, (sp_digit)0 - r1);
    else
#endif
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
static WC_INLINE int sp_2048_mod_16(sp_digit* r, const sp_digit* a,
        const sp_digit* m)
{
    ASSERT_SAVED_VECTOR_REGISTERS();
    return sp_2048_div_16(a, m, NULL, r);
}

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_get_from_table_16(sp_digit* r, sp_digit** table, int idx);
#ifdef __cplusplus
}
#endif

/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even or exponent is 0.
 */
static int sp_2048_mod_exp_16(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[(33 * 32) + 32];
    sp_digit* t[32];
    sp_digit* rt = NULL;
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<32; i++)
            t[i] = td + i * 32;
        rt = td + 1024;

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_16(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 16);
        if (reduceA) {
            err = sp_2048_mod_16(t[1] + 16, a, m);
            if (err == MP_OKAY)
                err = sp_2048_mod_16(t[1], t[1], m);
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
        /* Number of bits available in top word. */
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        /* Minus the number of top bits to use so rest is a multiple of 5. */
        if ((bits % 5) == 0) {
            c -= 5;
        }
        else {
            c -= bits % 5;
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
    #ifndef WC_NO_CACHE_RESISTANT
        sp_2048_get_from_table_16(r, t, y);
    #else
        XMEMCPY(r, t[y], sizeof(sp_digit) * 16);
    #endif
        for (; i>=0 || c>=5; ) {
            if (c >= 5) {
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 59);
                n <<= 5;
                c = 59;
            }
            else {
                y = (byte)(n >> 59);
                n = e[i--];
                c = 5 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }

            sp_2048_sqr_16(rt, r);
            sp_2048_mont_reduce_16(rt, m, mp);
            sp_2048_sqr_16(r, rt);
            sp_2048_mont_reduce_16(r, m, mp);
            sp_2048_sqr_16(rt, r);
            sp_2048_mont_reduce_16(rt, m, mp);
            sp_2048_sqr_16(r, rt);
            sp_2048_mont_reduce_16(r, m, mp);
            sp_2048_sqr_16(rt, r);
            sp_2048_mont_reduce_16(rt, m, mp);

            #ifndef WC_NO_CACHE_RESISTANT
                sp_2048_get_from_table_16(r, t, y);
                sp_2048_mul_16(r, rt, r);
            #else
                sp_2048_mul_16(r, rt, t[y]);
            #endif
            sp_2048_mont_reduce_16(r, m, mp);
        }

        XMEMSET(&r[16], 0, sizeof(sp_digit) * 16);
        sp_2048_mont_reduce_16(r, m, mp);

        mask = 0 - (sp_2048_cmp_16(r, m) >= 0);
        sp_2048_cond_sub_16(r, r, m, mask);
    }


    return err;
}

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_mont_reduce_avx2_16(sp_digit* a, const sp_digit* m, sp_digit mp);
#ifdef __cplusplus
}
#endif
#ifdef HAVE_INTEL_AVX2
/* Multiply two Montgomery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montgomery form.
 * b   Second number to multiply in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_2048_mont_mul_avx2_16(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_2048_mul_avx2_16(r, a, b);
    sp_2048_mont_reduce_avx2_16(r, m, mp);
}

#endif /* HAVE_INTEL_AVX2 */
#ifdef HAVE_INTEL_AVX2
/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_2048_mont_sqr_avx2_16(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_2048_sqr_avx2_16(r, a);
    sp_2048_mont_reduce_avx2_16(r, m, mp);
}

#endif /* HAVE_INTEL_AVX2 */
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_get_from_table_avx2_16(sp_digit* r, sp_digit** table, int idx);
#ifdef __cplusplus
}
#endif

#ifdef HAVE_INTEL_AVX2
/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even or exponent is 0.
 */
static int sp_2048_mod_exp_avx2_16(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[(33 * 32) + 32];
    sp_digit* t[32];
    sp_digit* rt = NULL;
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<32; i++)
            t[i] = td + i * 32;
        rt = td + 1024;

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_16(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 16);
        if (reduceA) {
            err = sp_2048_mod_16(t[1] + 16, a, m);
            if (err == MP_OKAY)
                err = sp_2048_mod_16(t[1], t[1], m);
        }
        else {
            XMEMCPY(t[1] + 16, a, sizeof(sp_digit) * 16);
            err = sp_2048_mod_16(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_2048_mont_sqr_avx2_16(t[ 2], t[ 1], m, mp);
        sp_2048_mont_mul_avx2_16(t[ 3], t[ 2], t[ 1], m, mp);
        sp_2048_mont_sqr_avx2_16(t[ 4], t[ 2], m, mp);
        sp_2048_mont_mul_avx2_16(t[ 5], t[ 3], t[ 2], m, mp);
        sp_2048_mont_sqr_avx2_16(t[ 6], t[ 3], m, mp);
        sp_2048_mont_mul_avx2_16(t[ 7], t[ 4], t[ 3], m, mp);
        sp_2048_mont_sqr_avx2_16(t[ 8], t[ 4], m, mp);
        sp_2048_mont_mul_avx2_16(t[ 9], t[ 5], t[ 4], m, mp);
        sp_2048_mont_sqr_avx2_16(t[10], t[ 5], m, mp);
        sp_2048_mont_mul_avx2_16(t[11], t[ 6], t[ 5], m, mp);
        sp_2048_mont_sqr_avx2_16(t[12], t[ 6], m, mp);
        sp_2048_mont_mul_avx2_16(t[13], t[ 7], t[ 6], m, mp);
        sp_2048_mont_sqr_avx2_16(t[14], t[ 7], m, mp);
        sp_2048_mont_mul_avx2_16(t[15], t[ 8], t[ 7], m, mp);
        sp_2048_mont_sqr_avx2_16(t[16], t[ 8], m, mp);
        sp_2048_mont_mul_avx2_16(t[17], t[ 9], t[ 8], m, mp);
        sp_2048_mont_sqr_avx2_16(t[18], t[ 9], m, mp);
        sp_2048_mont_mul_avx2_16(t[19], t[10], t[ 9], m, mp);
        sp_2048_mont_sqr_avx2_16(t[20], t[10], m, mp);
        sp_2048_mont_mul_avx2_16(t[21], t[11], t[10], m, mp);
        sp_2048_mont_sqr_avx2_16(t[22], t[11], m, mp);
        sp_2048_mont_mul_avx2_16(t[23], t[12], t[11], m, mp);
        sp_2048_mont_sqr_avx2_16(t[24], t[12], m, mp);
        sp_2048_mont_mul_avx2_16(t[25], t[13], t[12], m, mp);
        sp_2048_mont_sqr_avx2_16(t[26], t[13], m, mp);
        sp_2048_mont_mul_avx2_16(t[27], t[14], t[13], m, mp);
        sp_2048_mont_sqr_avx2_16(t[28], t[14], m, mp);
        sp_2048_mont_mul_avx2_16(t[29], t[15], t[14], m, mp);
        sp_2048_mont_sqr_avx2_16(t[30], t[15], m, mp);
        sp_2048_mont_mul_avx2_16(t[31], t[16], t[15], m, mp);

        i = (bits - 1) / 64;
        n = e[i--];
        /* Number of bits available in top word. */
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        /* Minus the number of top bits to use so rest is a multiple of 5. */
        if ((bits % 5) == 0) {
            c -= 5;
        }
        else {
            c -= bits % 5;
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
    #ifndef WC_NO_CACHE_RESISTANT
        sp_2048_get_from_table_avx2_16(r, t, y);
    #else
        XMEMCPY(r, t[y], sizeof(sp_digit) * 16);
    #endif
        for (; i>=0 || c>=5; ) {
            if (c >= 5) {
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 59);
                n <<= 5;
                c = 59;
            }
            else {
                y = (byte)(n >> 59);
                n = e[i--];
                c = 5 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }

            sp_2048_sqr_avx2_16(rt, r);
            sp_2048_mont_reduce_avx2_16(rt, m, mp);
            sp_2048_sqr_avx2_16(r, rt);
            sp_2048_mont_reduce_avx2_16(r, m, mp);
            sp_2048_sqr_avx2_16(rt, r);
            sp_2048_mont_reduce_avx2_16(rt, m, mp);
            sp_2048_sqr_avx2_16(r, rt);
            sp_2048_mont_reduce_avx2_16(r, m, mp);
            sp_2048_sqr_avx2_16(rt, r);
            sp_2048_mont_reduce_avx2_16(rt, m, mp);

            #ifndef WC_NO_CACHE_RESISTANT
                sp_2048_get_from_table_avx2_16(r, t, y);
                sp_2048_mul_avx2_16(r, rt, r);
            #else
                sp_2048_mul_avx2_16(r, rt, t[y]);
            #endif
            sp_2048_mont_reduce_avx2_16(r, m, mp);
        }

        XMEMSET(&r[16], 0, sizeof(sp_digit) * 16);
        sp_2048_mont_reduce_avx2_16(r, m, mp);

        mask = 0 - (sp_2048_cmp_16(r, m) >= 0);
        sp_2048_cond_sub_avx2_16(r, r, m, mask);
    }


    return err;
}
#endif /* HAVE_INTEL_AVX2 */

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

    ASSERT_SAVED_VECTOR_REGISTERS();

    /* r = 2^n mod m */
    sp_2048_sub_in_place_32(r, m);
}

#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) | WOLFSSL_HAVE_SP_DH */
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_2048_cond_sub_32(sp_digit* r, const sp_digit* a, const sp_digit* b, sp_digit m);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_mont_reduce_32(sp_digit* a, const sp_digit* m, sp_digit mp);
#ifdef __cplusplus
}
#endif
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

#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_2048_sub_32(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_mul_d_avx2_32(sp_digit* r, const sp_digit* a, const sp_digit b);
#ifdef __cplusplus
}
#endif
#ifdef _WIN64
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit div_2048_word_asm_32(sp_digit d1, sp_digit d0, sp_digit div);
#ifdef __cplusplus
}
#endif
/* Divide the double width number (d1|d0) by the dividend. (d1|d0 / div)
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The dividend.
 * returns the result of the division.
 */
static WC_INLINE sp_digit div_2048_word_32(sp_digit d1, sp_digit d0,
        sp_digit div)
{
    ASSERT_SAVED_VECTOR_REGISTERS();
    return div_2048_word_asm_32(d1, d0, div);
}
#else
/* Divide the double width number (d1|d0) by the dividend. (d1|d0 / div)
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The dividend.
 * returns the result of the division.
 */
static WC_INLINE sp_digit div_2048_word_32(sp_digit d1, sp_digit d0,
        sp_digit div)
{
    ASSERT_SAVED_VECTOR_REGISTERS();
    register sp_digit r asm("rax");
    __asm__ __volatile__ (
        "divq %3"
        : "=a" (r)
        : "d" (d1), "a" (d0), "r" (div)
        :
    );
    return r;
}
#endif /* _WIN64 */
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
    sp_digit t1[64];
    sp_digit t2[33];
    sp_digit div;
    sp_digit r1;
    int i;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

    ASSERT_SAVED_VECTOR_REGISTERS();

    (void)m;

    div = d[31];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 32);
    for (i = 31; i > 0; i--) {
        if (t1[i + 32] != d[i])
            break;
    }
    if (t1[i + 32] >= d[i]) {
        sp_2048_sub_in_place_32(&t1[32], d);
    }
    for (i = 31; i >= 0; i--) {
        if (t1[32 + i] == div) {
            r1 = SP_DIGIT_MAX;
        }
        else {
            r1 = div_2048_word_32(t1[32 + i], t1[32 + i - 1], div);
        }

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            sp_2048_mul_d_avx2_32(t2, d, r1);
        else
#endif
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
static WC_INLINE int sp_2048_mod_32_cond(sp_digit* r, const sp_digit* a,
        const sp_digit* m)
{
    ASSERT_SAVED_VECTOR_REGISTERS();
    return sp_2048_div_32_cond(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_2048_cond_sub_avx2_32(sp_digit* r, const sp_digit* a, const sp_digit* b, sp_digit m);
#ifdef __cplusplus
}
#endif
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

#ifdef __cplusplus
extern "C" {
#endif
extern sp_int64 sp_2048_cmp_32(const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
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
    sp_digit t1[64];
    sp_digit t2[33];
    sp_digit div;
    sp_digit r1;
    int i;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

    ASSERT_SAVED_VECTOR_REGISTERS();

    (void)m;

    div = d[31];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 32);
    r1 = sp_2048_cmp_32(&t1[32], d) >= 0;
#ifdef HAVE_INTEL_AVX2
    if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
        sp_2048_cond_sub_avx2_32(&t1[32], &t1[32], d, (sp_digit)0 - r1);
    else
#endif
        sp_2048_cond_sub_32(&t1[32], &t1[32], d, (sp_digit)0 - r1);
    for (i = 31; i >= 0; i--) {
        sp_digit mask = 0 - (t1[32 + i] == div);
        sp_digit hi = t1[32 + i] + mask;
        r1 = div_2048_word_32(hi, t1[32 + i - 1], div);
        r1 |= mask;

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            sp_2048_mul_d_avx2_32(t2, d, r1);
        else
#endif
            sp_2048_mul_d_32(t2, d, r1);
        t1[32 + i] += sp_2048_sub_in_place_32(&t1[i], t2);
        t1[32 + i] -= t2[32];
        sp_2048_mask_32(t2, d, t1[32 + i]);
        t1[32 + i] += sp_2048_add_32(&t1[i], &t1[i], t2);
        sp_2048_mask_32(t2, d, t1[32 + i]);
        t1[32 + i] += sp_2048_add_32(&t1[i], &t1[i], t2);
    }

    r1 = sp_2048_cmp_32(t1, d) >= 0;
#ifdef HAVE_INTEL_AVX2
    if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
        sp_2048_cond_sub_avx2_32(r, t1, d, (sp_digit)0 - r1);
    else
#endif
        sp_2048_cond_sub_32(r, t1, d, (sp_digit)0 - r1);

    return MP_OKAY;
}

#if defined(WOLFSSL_HAVE_SP_DH) || !defined(WOLFSSL_RSA_PUBLIC_ONLY)
/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_2048_mod_32(sp_digit* r, const sp_digit* a,
        const sp_digit* m)
{
    ASSERT_SAVED_VECTOR_REGISTERS();
    return sp_2048_div_32(a, m, NULL, r);
}

#endif /* WOLFSSL_HAVE_SP_DH || !WOLFSSL_RSA_PUBLIC_ONLY */
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_get_from_table_32(sp_digit* r, sp_digit** table, int idx);
#ifdef __cplusplus
}
#endif

/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even or exponent is 0.
 */
static int sp_2048_mod_exp_32(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[(65 * 64) + 64];
    sp_digit* t[64];
    sp_digit* rt = NULL;
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<64; i++)
            t[i] = td + i * 64;
        rt = td + 4096;

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_32(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 32);
        if (reduceA) {
            err = sp_2048_mod_32(t[1] + 32, a, m);
            if (err == MP_OKAY)
                err = sp_2048_mod_32(t[1], t[1], m);
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
        /* Number of bits available in top word. */
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        /* Minus the number of top bits to use so rest is a multiple of 6. */
        if ((bits % 6) == 0) {
            c -= 6;
        }
        else {
            c -= bits % 6;
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
    #ifndef WC_NO_CACHE_RESISTANT
        sp_2048_get_from_table_32(r, t, y);
    #else
        XMEMCPY(r, t[y], sizeof(sp_digit) * 32);
    #endif
        for (; i>=0 || c>=6; ) {
            if (c >= 6) {
                y = (byte)((n >> 58) & 0x3f);
                n <<= 6;
                c -= 6;
            }
            else if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 58);
                n <<= 6;
                c = 58;
            }
            else {
                y = (byte)(n >> 58);
                n = e[i--];
                c = 6 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }

            sp_2048_sqr_32(rt, r);
            sp_2048_mont_reduce_32(rt, m, mp);
            sp_2048_sqr_32(r, rt);
            sp_2048_mont_reduce_32(r, m, mp);
            sp_2048_sqr_32(rt, r);
            sp_2048_mont_reduce_32(rt, m, mp);
            sp_2048_sqr_32(r, rt);
            sp_2048_mont_reduce_32(r, m, mp);
            sp_2048_sqr_32(rt, r);
            sp_2048_mont_reduce_32(rt, m, mp);
            sp_2048_sqr_32(r, rt);
            sp_2048_mont_reduce_32(r, m, mp);
            #ifndef WC_NO_CACHE_RESISTANT
                sp_2048_get_from_table_32(rt, t, y);
                sp_2048_mul_32(r, r, rt);
            #else
                sp_2048_mul_32(r, r, t[y]);
            #endif
            sp_2048_mont_reduce_32(r, m, mp);
        }

        XMEMSET(&r[32], 0, sizeof(sp_digit) * 32);
        sp_2048_mont_reduce_32(r, m, mp);

        mask = 0 - (sp_2048_cmp_32(r, m) >= 0);
        sp_2048_cond_sub_32(r, r, m, mask);
    }


    return err;
}

#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || WOLFSSL_HAVE_SP_DH */
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_mont_reduce_avx2_32(sp_digit* a, const sp_digit* m, sp_digit mp);
#ifdef __cplusplus
}
#endif
#ifdef HAVE_INTEL_AVX2
/* Multiply two Montgomery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montgomery form.
 * b   Second number to multiply in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_2048_mont_mul_avx2_32(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_2048_mul_avx2_32(r, a, b);
    sp_2048_mont_reduce_avx2_32(r, m, mp);
}

#endif /* HAVE_INTEL_AVX2 */
#ifdef HAVE_INTEL_AVX2
/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_2048_mont_sqr_avx2_32(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_2048_sqr_avx2_32(r, a);
    sp_2048_mont_reduce_avx2_32(r, m, mp);
}

#endif /* HAVE_INTEL_AVX2 */
#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_get_from_table_avx2_32(sp_digit* r, sp_digit** table, int idx);
#ifdef __cplusplus
}
#endif

#ifdef HAVE_INTEL_AVX2
/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even or exponent is 0.
 */
static int sp_2048_mod_exp_avx2_32(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[(65 * 64) + 64];
    sp_digit* t[64];
    sp_digit* rt = NULL;
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<64; i++)
            t[i] = td + i * 64;
        rt = td + 4096;

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_32(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 32);
        if (reduceA) {
            err = sp_2048_mod_32(t[1] + 32, a, m);
            if (err == MP_OKAY)
                err = sp_2048_mod_32(t[1], t[1], m);
        }
        else {
            XMEMCPY(t[1] + 32, a, sizeof(sp_digit) * 32);
            err = sp_2048_mod_32(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_2048_mont_sqr_avx2_32(t[ 2], t[ 1], m, mp);
        sp_2048_mont_mul_avx2_32(t[ 3], t[ 2], t[ 1], m, mp);
        sp_2048_mont_sqr_avx2_32(t[ 4], t[ 2], m, mp);
        sp_2048_mont_mul_avx2_32(t[ 5], t[ 3], t[ 2], m, mp);
        sp_2048_mont_sqr_avx2_32(t[ 6], t[ 3], m, mp);
        sp_2048_mont_mul_avx2_32(t[ 7], t[ 4], t[ 3], m, mp);
        sp_2048_mont_sqr_avx2_32(t[ 8], t[ 4], m, mp);
        sp_2048_mont_mul_avx2_32(t[ 9], t[ 5], t[ 4], m, mp);
        sp_2048_mont_sqr_avx2_32(t[10], t[ 5], m, mp);
        sp_2048_mont_mul_avx2_32(t[11], t[ 6], t[ 5], m, mp);
        sp_2048_mont_sqr_avx2_32(t[12], t[ 6], m, mp);
        sp_2048_mont_mul_avx2_32(t[13], t[ 7], t[ 6], m, mp);
        sp_2048_mont_sqr_avx2_32(t[14], t[ 7], m, mp);
        sp_2048_mont_mul_avx2_32(t[15], t[ 8], t[ 7], m, mp);
        sp_2048_mont_sqr_avx2_32(t[16], t[ 8], m, mp);
        sp_2048_mont_mul_avx2_32(t[17], t[ 9], t[ 8], m, mp);
        sp_2048_mont_sqr_avx2_32(t[18], t[ 9], m, mp);
        sp_2048_mont_mul_avx2_32(t[19], t[10], t[ 9], m, mp);
        sp_2048_mont_sqr_avx2_32(t[20], t[10], m, mp);
        sp_2048_mont_mul_avx2_32(t[21], t[11], t[10], m, mp);
        sp_2048_mont_sqr_avx2_32(t[22], t[11], m, mp);
        sp_2048_mont_mul_avx2_32(t[23], t[12], t[11], m, mp);
        sp_2048_mont_sqr_avx2_32(t[24], t[12], m, mp);
        sp_2048_mont_mul_avx2_32(t[25], t[13], t[12], m, mp);
        sp_2048_mont_sqr_avx2_32(t[26], t[13], m, mp);
        sp_2048_mont_mul_avx2_32(t[27], t[14], t[13], m, mp);
        sp_2048_mont_sqr_avx2_32(t[28], t[14], m, mp);
        sp_2048_mont_mul_avx2_32(t[29], t[15], t[14], m, mp);
        sp_2048_mont_sqr_avx2_32(t[30], t[15], m, mp);
        sp_2048_mont_mul_avx2_32(t[31], t[16], t[15], m, mp);
        sp_2048_mont_sqr_avx2_32(t[32], t[16], m, mp);
        sp_2048_mont_mul_avx2_32(t[33], t[17], t[16], m, mp);
        sp_2048_mont_sqr_avx2_32(t[34], t[17], m, mp);
        sp_2048_mont_mul_avx2_32(t[35], t[18], t[17], m, mp);
        sp_2048_mont_sqr_avx2_32(t[36], t[18], m, mp);
        sp_2048_mont_mul_avx2_32(t[37], t[19], t[18], m, mp);
        sp_2048_mont_sqr_avx2_32(t[38], t[19], m, mp);
        sp_2048_mont_mul_avx2_32(t[39], t[20], t[19], m, mp);
        sp_2048_mont_sqr_avx2_32(t[40], t[20], m, mp);
        sp_2048_mont_mul_avx2_32(t[41], t[21], t[20], m, mp);
        sp_2048_mont_sqr_avx2_32(t[42], t[21], m, mp);
        sp_2048_mont_mul_avx2_32(t[43], t[22], t[21], m, mp);
        sp_2048_mont_sqr_avx2_32(t[44], t[22], m, mp);
        sp_2048_mont_mul_avx2_32(t[45], t[23], t[22], m, mp);
        sp_2048_mont_sqr_avx2_32(t[46], t[23], m, mp);
        sp_2048_mont_mul_avx2_32(t[47], t[24], t[23], m, mp);
        sp_2048_mont_sqr_avx2_32(t[48], t[24], m, mp);
        sp_2048_mont_mul_avx2_32(t[49], t[25], t[24], m, mp);
        sp_2048_mont_sqr_avx2_32(t[50], t[25], m, mp);
        sp_2048_mont_mul_avx2_32(t[51], t[26], t[25], m, mp);
        sp_2048_mont_sqr_avx2_32(t[52], t[26], m, mp);
        sp_2048_mont_mul_avx2_32(t[53], t[27], t[26], m, mp);
        sp_2048_mont_sqr_avx2_32(t[54], t[27], m, mp);
        sp_2048_mont_mul_avx2_32(t[55], t[28], t[27], m, mp);
        sp_2048_mont_sqr_avx2_32(t[56], t[28], m, mp);
        sp_2048_mont_mul_avx2_32(t[57], t[29], t[28], m, mp);
        sp_2048_mont_sqr_avx2_32(t[58], t[29], m, mp);
        sp_2048_mont_mul_avx2_32(t[59], t[30], t[29], m, mp);
        sp_2048_mont_sqr_avx2_32(t[60], t[30], m, mp);
        sp_2048_mont_mul_avx2_32(t[61], t[31], t[30], m, mp);
        sp_2048_mont_sqr_avx2_32(t[62], t[31], m, mp);
        sp_2048_mont_mul_avx2_32(t[63], t[32], t[31], m, mp);

        i = (bits - 1) / 64;
        n = e[i--];
        /* Number of bits available in top word. */
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        /* Minus the number of top bits to use so rest is a multiple of 6. */
        if ((bits % 6) == 0) {
            c -= 6;
        }
        else {
            c -= bits % 6;
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
    #ifndef WC_NO_CACHE_RESISTANT
        sp_2048_get_from_table_avx2_32(r, t, y);
    #else
        XMEMCPY(r, t[y], sizeof(sp_digit) * 32);
    #endif
        for (; i>=0 || c>=6; ) {
            if (c >= 6) {
                y = (byte)((n >> 58) & 0x3f);
                n <<= 6;
                c -= 6;
            }
            else if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 58);
                n <<= 6;
                c = 58;
            }
            else {
                y = (byte)(n >> 58);
                n = e[i--];
                c = 6 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }

            sp_2048_sqr_avx2_32(rt, r);
            sp_2048_mont_reduce_avx2_32(rt, m, mp);
            sp_2048_sqr_avx2_32(r, rt);
            sp_2048_mont_reduce_avx2_32(r, m, mp);
            sp_2048_sqr_avx2_32(rt, r);
            sp_2048_mont_reduce_avx2_32(rt, m, mp);
            sp_2048_sqr_avx2_32(r, rt);
            sp_2048_mont_reduce_avx2_32(r, m, mp);
            sp_2048_sqr_avx2_32(rt, r);
            sp_2048_mont_reduce_avx2_32(rt, m, mp);
            sp_2048_sqr_avx2_32(r, rt);
            sp_2048_mont_reduce_avx2_32(r, m, mp);
            #ifndef WC_NO_CACHE_RESISTANT
                sp_2048_get_from_table_avx2_32(rt, t, y);
                sp_2048_mul_avx2_32(r, r, rt);
            #else
                sp_2048_mul_avx2_32(r, r, t[y]);
            #endif
            sp_2048_mont_reduce_avx2_32(r, m, mp);
        }

        XMEMSET(&r[32], 0, sizeof(sp_digit) * 32);
        sp_2048_mont_reduce_avx2_32(r, m, mp);

        mask = 0 - (sp_2048_cmp_32(r, m) >= 0);
        sp_2048_cond_sub_avx2_32(r, r, m, mask);
    }


    return err;
}
#endif /* HAVE_INTEL_AVX2 */

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
    sp_digit* ah;
    sp_digit* m;
    sp_digit* r;
    sp_digit  e = 0;
    int err = MP_OKAY;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

    ASSERT_SAVED_VECTOR_REGISTERS();

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
        r = a + 32 * 2;
        m = r + 32 * 2;
        ah = a + 32;

        sp_2048_from_bin(ah, 32, in, inLen);
#if DIGIT_BIT >= 64
        e = em->dp[0];
#else
        e = em->dp[0];
        if (em->used > 1)
            e |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
#endif
        if (e == 0)
            err = MP_EXPTMOD_E;
    }
    if (err == MP_OKAY) {
        sp_2048_from_mp(m, 32, mm);

        if (e == 0x10001) {
            int i;
            sp_digit mp;

            sp_2048_mont_setup(m, &mp);

            /* Convert to Montgomery form. */
            XMEMSET(a, 0, sizeof(sp_digit) * 32);
            err = sp_2048_mod_32_cond(r, a, m);
            /* Montgomery form: r = a.R mod m */

            if (err == MP_OKAY) {
                /* r = a ^ 0x10000 => r = a squared 16 times */
#ifdef HAVE_INTEL_AVX2
                if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
                    for (i = 15; i >= 0; i--) {
                        sp_2048_mont_sqr_avx2_32(r, r, m, mp);
                    }
                    /* mont_red(r.R.R) = (r.R.R / R) mod m = r.R mod m
                     * mont_red(r.R * a) = (r.R.a / R) mod m = r.a mod m
                     */
                    sp_2048_mont_mul_avx2_32(r, r, ah, m, mp);
                }
                else
#endif
                {
                    for (i = 15; i >= 0; i--) {
                        sp_2048_mont_sqr_32(r, r, m, mp);
                    }
                    /* mont_red(r.R.R) = (r.R.R / R) mod m = r.R mod m
                     * mont_red(r.R * a) = (r.R.a / R) mod m = r.a mod m
                     */
                    sp_2048_mont_mul_32(r, r, ah, m, mp);
                }

                for (i = 31; i > 0; i--) {
                    if (r[i] != m[i])
                        break;
                }
                if (r[i] >= m[i])
                    sp_2048_sub_in_place_32(r, m);
            }
        }
        else if (e == 0x3) {
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
                if (err == MP_OKAY) {
                    sp_2048_sqr_avx2_32(r, ah);
                    err = sp_2048_mod_32_cond(r, r, m);
                }
                if (err == MP_OKAY) {
                    sp_2048_mul_avx2_32(r, ah, r);
                    err = sp_2048_mod_32_cond(r, r, m);
                }
            }
            else
#endif
            {
                if (err == MP_OKAY) {
                    sp_2048_sqr_32(r, ah);
                    err = sp_2048_mod_32_cond(r, r, m);
                }
                if (err == MP_OKAY) {
                    sp_2048_mul_32(r, ah, r);
                    err = sp_2048_mod_32_cond(r, r, m);
                }
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
                for (i=63; i>=0; i--) {
                    if (e >> i) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 32);
#ifdef HAVE_INTEL_AVX2
                if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
                    for (i--; i>=0; i--) {
                        sp_2048_mont_sqr_avx2_32(r, r, m, mp);
                        if (((e >> i) & 1) == 1) {
                            sp_2048_mont_mul_avx2_32(r, r, a, m, mp);
                        }
                    }
                    XMEMSET(&r[32], 0, sizeof(sp_digit) * 32);
                    sp_2048_mont_reduce_avx2_32(r, m, mp);
                }
                else
#endif
                {
                    for (i--; i>=0; i--) {
                        sp_2048_mont_sqr_32(r, r, m, mp);
                        if (((e >> i) & 1) == 1) {
                            sp_2048_mont_mul_32(r, r, a, m, mp);
                        }
                    }
                    XMEMSET(&r[32], 0, sizeof(sp_digit) * 32);
                    sp_2048_mont_reduce_32(r, m, mp);
                }

                for (i = 31; i > 0; i--) {
                    if (r[i] != m[i])
                        break;
                }
                if (r[i] >= m[i])
                    sp_2048_sub_in_place_32(r, m);
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
#if defined(SP_RSA_PRIVATE_EXP_D) || defined(RSA_LOW_MEM)
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
    const mp_int* pm, const mp_int* qm,const  mp_int* dpm, const mp_int* dqm,
    const mp_int* qim, const mp_int* mm, byte* out, word32* outLen)
{
    sp_digit d[32 * 4];
    sp_digit* a;
    sp_digit* m;
    sp_digit* r;
    int err = MP_OKAY;

    ASSERT_SAVED_VECTOR_REGISTERS();

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
        /* only zeroing private "d" */
        ForceZero(d, sizeof(sp_digit) * 32);
    }

    return err;
}

#else
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_2048_cond_add_16(sp_digit* r, const sp_digit* a, const sp_digit* b, sp_digit m);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_2048_cond_add_avx2_16(sp_digit* r, const sp_digit* a, const sp_digit* b, sp_digit m);
#ifdef __cplusplus
}
#endif
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
    sp_digit a[16 * 11];
    sp_digit* p;
    sp_digit* q;
    sp_digit* dp;
    sp_digit* dq;
    sp_digit* qi;
    sp_digit* tmpa;
    sp_digit* tmpb;
    sp_digit* r;
    sp_digit c;
    int err = MP_OKAY;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

    ASSERT_SAVED_VECTOR_REGISTERS();

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
        r = a + 32;

        sp_2048_from_bin(a, 32, in, inLen);
        sp_2048_from_mp(p, 16, pm);
        sp_2048_from_mp(q, 16, qm);
        sp_2048_from_mp(dp, 16, dpm);

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            err = sp_2048_mod_exp_avx2_16(tmpa, a, dp, 1024, p, 1);
        else
#endif
            err = sp_2048_mod_exp_16(tmpa, a, dp, 1024, p, 1);
    }
    if (err == MP_OKAY) {
        sp_2048_from_mp(dq, 16, dqm);
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            err = sp_2048_mod_exp_avx2_16(tmpb, a, dq, 1024, q, 1);
       else
#endif
            err = sp_2048_mod_exp_16(tmpb, a, dq, 1024, q, 1);
    }

    if (err == MP_OKAY) {
        c = sp_2048_sub_in_place_16(tmpa, tmpb);
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
            c += sp_2048_cond_add_avx2_16(tmpa, tmpa, p, c);
            sp_2048_cond_add_avx2_16(tmpa, tmpa, p, c);
        }
        else
#endif
        {
            c += sp_2048_cond_add_16(tmpa, tmpa, p, c);
            sp_2048_cond_add_16(tmpa, tmpa, p, c);
        }

        sp_2048_from_mp(qi, 16, qim);
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
            sp_2048_mul_avx2_16(tmpa, tmpa, qi);
        }
        else
#endif
        {
            sp_2048_mul_16(tmpa, tmpa, qi);
        }
        err = sp_2048_mod_16(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
            sp_2048_mul_avx2_16(tmpa, q, tmpa);
        }
        else
#endif
        {
            sp_2048_mul_16(tmpa, q, tmpa);
        }
        XMEMSET(&tmpb[16], 0, sizeof(sp_digit) * 16);
        sp_2048_add_32(r, tmpb, tmpa);

        sp_2048_to_bin_32(r, out);
        *outLen = 256;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 16 * 11);
    }

    return err;
}
#endif /* SP_RSA_PRIVATE_EXP_D | RSA_LOW_MEM */
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
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif
    int expBits = mp_count_bits(exp);

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (mp_count_bits(base) > 2048 || expBits > 2048 ||
                                                   mp_count_bits(mod) != 2048) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mod)) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        sp_2048_from_mp(b, 32, base);
        sp_2048_from_mp(e, 32, exp);
        sp_2048_from_mp(m, 32, mod);

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            err = sp_2048_mod_exp_avx2_32(r, b, e, expBits, m, 0);
        else
#endif
            err = sp_2048_mod_exp_32(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_2048_to_mp(r, res);
    }

    XMEMSET(e, 0, sizeof(e));

    return err;
}

#ifdef WOLFSSL_HAVE_SP_DH
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_2048_lshift_32(sp_digit* r, const sp_digit* a, int n);
#ifdef __cplusplus
}
#endif
#ifdef HAVE_INTEL_AVX2
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
static int sp_2048_mod_exp_2_avx2_32(sp_digit* r, const sp_digit* e, int bits,
        const sp_digit* m)
{
    sp_digit td[33 + 64];
    sp_digit* norm;
    sp_digit* tmp;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit o;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        tmp = &td[64];

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_32(norm, m);

        i = (bits - 1) / 64;
        n = e[i--];
        /* Number of bits available in top word. */
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        /* Minus the number of top bits to use so rest is a multiple of 6. */
        if ((bits % 6) == 0) {
            c -= 6;
        }
        else {
            c -= bits % 6;
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
        while ((i >= 0) || (c >= 6)) {
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

            sp_2048_mont_sqr_avx2_32(r, r, m, mp);
            sp_2048_mont_sqr_avx2_32(r, r, m, mp);
            sp_2048_mont_sqr_avx2_32(r, r, m, mp);
            sp_2048_mont_sqr_avx2_32(r, r, m, mp);
            sp_2048_mont_sqr_avx2_32(r, r, m, mp);
            sp_2048_mont_sqr_avx2_32(r, r, m, mp);

            sp_2048_lshift_32(r, r, y);
            sp_2048_mul_d_avx2_32(tmp, norm, r[32]);
            r[32] = 0;
            o = sp_2048_add_32(r, r, tmp);
            sp_2048_cond_sub_avx2_32(r, r, m, (sp_digit)0 - o);
        }

        XMEMSET(&r[32], 0, sizeof(sp_digit) * 32);
        sp_2048_mont_reduce_avx2_32(r, m, mp);

        mask = 0 - (sp_2048_cmp_32(r, m) >= 0);
        sp_2048_cond_sub_avx2_32(r, r, m, mask);
    }


    return err;
}
#endif /* HAVE_INTEL_AVX2 */

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
    sp_digit td[33 + 64];
    sp_digit* norm;
    sp_digit* tmp;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit o;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        tmp = &td[64];

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_32(norm, m);

        i = (bits - 1) / 64;
        n = e[i--];
        /* Number of bits available in top word. */
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        /* Minus the number of top bits to use so rest is a multiple of 6. */
        if ((bits % 6) == 0) {
            c -= 6;
        }
        else {
            c -= bits % 6;
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
        while ((i >= 0) || (c >= 6)) {
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

        XMEMSET(&r[32], 0, sizeof(sp_digit) * 32);
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
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (mp_count_bits(base) > 2048 || expLen > 256 ||
                                                   mp_count_bits(mod) != 2048) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mod)) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        sp_2048_from_mp(b, 32, base);
        sp_2048_from_bin(e, 32, exp, expLen);
        sp_2048_from_mp(m, 32, mod);

        if (base->used == 1 && base->dp[0] == 2 && m[31] == (sp_digit)-1) {
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
                err = sp_2048_mod_exp_2_avx2_32(r, e, expLen * 8, m);
            else
#endif
                err = sp_2048_mod_exp_2_32(r, e, expLen * 8, m);
        }
        else
        {
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
                err = sp_2048_mod_exp_avx2_32(r, b, e, expLen * 8, m, 0);
            else
#endif
                err = sp_2048_mod_exp_32(r, b, e, expLen * 8, m, 0);
        }
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
#endif
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
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif
    int expBits = mp_count_bits(exp);

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (mp_count_bits(base) > 1024 || expBits > 1024 ||
                                                   mp_count_bits(mod) != 1024) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mod)) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        sp_2048_from_mp(b, 16, base);
        sp_2048_from_mp(e, 16, exp);
        sp_2048_from_mp(m, 16, mod);

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            err = sp_2048_mod_exp_avx2_16(r, b, e, expBits, m, 0);
        else
#endif
            err = sp_2048_mod_exp_16(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 16, 0, sizeof(*r) * 16);
        err = sp_2048_to_mp(r, res);
    }

    XMEMSET(e, 0, sizeof(e));

    return err;
}

#endif /* WOLFSSL_HAVE_SP_DH | (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) */

#endif /* !WOLFSSL_SP_NO_2048 */

#ifndef WOLFSSL_SP_NO_3072
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_from_bin_bswap(sp_digit* r, int size, const byte* a, int n);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_from_bin_movbe(sp_digit* r, int size, const byte* a, int n);
#ifdef __cplusplus
}
#endif
/* Read big endian unsigned byte array into r.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  Byte array.
 * n  Number of bytes in array to read.
 */
static void sp_3072_from_bin(sp_digit* r, int size, const byte* a, int n)
{
#ifndef NO_MOVBE_SUPPORT
    word32 cpuid_flags = cpuid_get_flags();

    if (IS_INTEL_MOVBE(cpuid_flags)) {
        sp_3072_from_bin_movbe(r, size, a, n);
    }
    else
#endif
    {
        sp_3072_from_bin_bswap(r, size, a, n);
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

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_to_bin_bswap_48(sp_digit* r, byte* a);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_to_bin_movbe_48(sp_digit* r, byte* a);
#ifdef __cplusplus
}
#endif
/* Write r as big endian to byte array.
 * Fixed length number of bytes written: 384
 *
 * r  A single precision integer.
 * a  Byte array.
 */
static void sp_3072_to_bin_48(sp_digit* r, byte* a)
{
#ifndef NO_MOVBE_SUPPORT
    word32 cpuid_flags = cpuid_get_flags();

    if (IS_INTEL_MOVBE(cpuid_flags)) {
        sp_3072_to_bin_movbe_48(r, a);
    }
    else
#endif
    {
        sp_3072_to_bin_bswap_48(r, a);
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

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_mul_12(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_mul_avx2_12(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_3072_add_12(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_3072_sub_in_place_24(sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_3072_add_24(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_mul_24(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_mul_avx2_24(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_3072_sub_in_place_48(sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_3072_add_48(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_mul_48(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_mul_avx2_48(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_sqr_12(sp_digit* r, const sp_digit* a);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_sqr_avx2_12(sp_digit* r, const sp_digit* a);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_sqr_24(sp_digit* r, const sp_digit* a);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_sqr_avx2_24(sp_digit* r, const sp_digit* a);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_sqr_48(sp_digit* r, const sp_digit* a);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_sqr_avx2_48(sp_digit* r, const sp_digit* a);
#ifdef __cplusplus
}
#endif

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
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

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_mul_d_48(sp_digit* r, const sp_digit* a, sp_digit b);
#ifdef __cplusplus
}
#endif
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

    ASSERT_SAVED_VECTOR_REGISTERS();

    /* r = 2^n mod m */
    sp_3072_sub_in_place_24(r, m);
}

#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_3072_cond_sub_24(sp_digit* r, const sp_digit* a, const sp_digit* b, sp_digit m);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_mont_reduce_24(sp_digit* a, const sp_digit* m, sp_digit mp);
#ifdef __cplusplus
}
#endif
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

#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_3072_cond_sub_avx2_24(sp_digit* r, const sp_digit* a, const sp_digit* b, sp_digit m);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_mul_d_24(sp_digit* r, const sp_digit* a, sp_digit b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_mul_d_avx2_24(sp_digit* r, const sp_digit* a, const sp_digit b);
#ifdef __cplusplus
}
#endif
#ifdef _WIN64
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit div_3072_word_asm_24(sp_digit d1, sp_digit d0, sp_digit div);
#ifdef __cplusplus
}
#endif
/* Divide the double width number (d1|d0) by the dividend. (d1|d0 / div)
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The dividend.
 * returns the result of the division.
 */
static WC_INLINE sp_digit div_3072_word_24(sp_digit d1, sp_digit d0,
        sp_digit div)
{
    ASSERT_SAVED_VECTOR_REGISTERS();
    return div_3072_word_asm_24(d1, d0, div);
}
#else
/* Divide the double width number (d1|d0) by the dividend. (d1|d0 / div)
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The dividend.
 * returns the result of the division.
 */
static WC_INLINE sp_digit div_3072_word_24(sp_digit d1, sp_digit d0,
        sp_digit div)
{
    ASSERT_SAVED_VECTOR_REGISTERS();
    register sp_digit r asm("rax");
    __asm__ __volatile__ (
        "divq %3"
        : "=a" (r)
        : "d" (d1), "a" (d0), "r" (div)
        :
    );
    return r;
}
#endif /* _WIN64 */
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

#ifdef __cplusplus
extern "C" {
#endif
extern sp_int64 sp_3072_cmp_24(const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
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
    sp_digit t1[48];
    sp_digit t2[25];
    sp_digit div;
    sp_digit r1;
    int i;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

    ASSERT_SAVED_VECTOR_REGISTERS();

    (void)m;

    div = d[23];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 24);
    r1 = sp_3072_cmp_24(&t1[24], d) >= 0;
#ifdef HAVE_INTEL_AVX2
    if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
        sp_3072_cond_sub_avx2_24(&t1[24], &t1[24], d, (sp_digit)0 - r1);
    else
#endif
        sp_3072_cond_sub_24(&t1[24], &t1[24], d, (sp_digit)0 - r1);
    for (i = 23; i >= 0; i--) {
        sp_digit mask = 0 - (t1[24 + i] == div);
        sp_digit hi = t1[24 + i] + mask;
        r1 = div_3072_word_24(hi, t1[24 + i - 1], div);
        r1 |= mask;

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            sp_3072_mul_d_avx2_24(t2, d, r1);
        else
#endif
            sp_3072_mul_d_24(t2, d, r1);
        t1[24 + i] += sp_3072_sub_in_place_24(&t1[i], t2);
        t1[24 + i] -= t2[24];
        sp_3072_mask_24(t2, d, t1[24 + i]);
        t1[24 + i] += sp_3072_add_24(&t1[i], &t1[i], t2);
        sp_3072_mask_24(t2, d, t1[24 + i]);
        t1[24 + i] += sp_3072_add_24(&t1[i], &t1[i], t2);
    }

    r1 = sp_3072_cmp_24(t1, d) >= 0;
#ifdef HAVE_INTEL_AVX2
    if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
        sp_3072_cond_sub_avx2_24(r, t1, d, (sp_digit)0 - r1);
    else
#endif
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
static WC_INLINE int sp_3072_mod_24(sp_digit* r, const sp_digit* a,
        const sp_digit* m)
{
    ASSERT_SAVED_VECTOR_REGISTERS();
    return sp_3072_div_24(a, m, NULL, r);
}

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_get_from_table_24(sp_digit* r, sp_digit** table, int idx);
#ifdef __cplusplus
}
#endif

/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even or exponent is 0.
 */
static int sp_3072_mod_exp_24(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[(33 * 48) + 48];
    sp_digit* t[32];
    sp_digit* rt = NULL;
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<32; i++)
            t[i] = td + i * 48;
        rt = td + 1536;

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_24(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 24);
        if (reduceA) {
            err = sp_3072_mod_24(t[1] + 24, a, m);
            if (err == MP_OKAY)
                err = sp_3072_mod_24(t[1], t[1], m);
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
        /* Number of bits available in top word. */
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        /* Minus the number of top bits to use so rest is a multiple of 5. */
        if ((bits % 5) == 0) {
            c -= 5;
        }
        else {
            c -= bits % 5;
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
    #ifndef WC_NO_CACHE_RESISTANT
        sp_3072_get_from_table_24(r, t, y);
    #else
        XMEMCPY(r, t[y], sizeof(sp_digit) * 24);
    #endif
        for (; i>=0 || c>=5; ) {
            if (c >= 5) {
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 59);
                n <<= 5;
                c = 59;
            }
            else {
                y = (byte)(n >> 59);
                n = e[i--];
                c = 5 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }

            sp_3072_sqr_24(rt, r);
            sp_3072_mont_reduce_24(rt, m, mp);
            sp_3072_sqr_24(r, rt);
            sp_3072_mont_reduce_24(r, m, mp);
            sp_3072_sqr_24(rt, r);
            sp_3072_mont_reduce_24(rt, m, mp);
            sp_3072_sqr_24(r, rt);
            sp_3072_mont_reduce_24(r, m, mp);
            sp_3072_sqr_24(rt, r);
            sp_3072_mont_reduce_24(rt, m, mp);

            #ifndef WC_NO_CACHE_RESISTANT
                sp_3072_get_from_table_24(r, t, y);
                sp_3072_mul_24(r, rt, r);
            #else
                sp_3072_mul_24(r, rt, t[y]);
            #endif
            sp_3072_mont_reduce_24(r, m, mp);
        }

        XMEMSET(&r[24], 0, sizeof(sp_digit) * 24);
        sp_3072_mont_reduce_24(r, m, mp);

        mask = 0 - (sp_3072_cmp_24(r, m) >= 0);
        sp_3072_cond_sub_24(r, r, m, mask);
    }


    return err;
}

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_mont_reduce_avx2_24(sp_digit* a, const sp_digit* m, sp_digit mp);
#ifdef __cplusplus
}
#endif
#ifdef HAVE_INTEL_AVX2
/* Multiply two Montgomery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montgomery form.
 * b   Second number to multiply in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_3072_mont_mul_avx2_24(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_3072_mul_avx2_24(r, a, b);
    sp_3072_mont_reduce_avx2_24(r, m, mp);
}

#endif /* HAVE_INTEL_AVX2 */
#ifdef HAVE_INTEL_AVX2
/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_3072_mont_sqr_avx2_24(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_3072_sqr_avx2_24(r, a);
    sp_3072_mont_reduce_avx2_24(r, m, mp);
}

#endif /* HAVE_INTEL_AVX2 */
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_get_from_table_avx2_24(sp_digit* r, sp_digit** table, int idx);
#ifdef __cplusplus
}
#endif

#ifdef HAVE_INTEL_AVX2
/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even or exponent is 0.
 */
static int sp_3072_mod_exp_avx2_24(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[(33 * 48) + 48];
    sp_digit* t[32];
    sp_digit* rt = NULL;
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<32; i++)
            t[i] = td + i * 48;
        rt = td + 1536;

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_24(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 24);
        if (reduceA) {
            err = sp_3072_mod_24(t[1] + 24, a, m);
            if (err == MP_OKAY)
                err = sp_3072_mod_24(t[1], t[1], m);
        }
        else {
            XMEMCPY(t[1] + 24, a, sizeof(sp_digit) * 24);
            err = sp_3072_mod_24(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_3072_mont_sqr_avx2_24(t[ 2], t[ 1], m, mp);
        sp_3072_mont_mul_avx2_24(t[ 3], t[ 2], t[ 1], m, mp);
        sp_3072_mont_sqr_avx2_24(t[ 4], t[ 2], m, mp);
        sp_3072_mont_mul_avx2_24(t[ 5], t[ 3], t[ 2], m, mp);
        sp_3072_mont_sqr_avx2_24(t[ 6], t[ 3], m, mp);
        sp_3072_mont_mul_avx2_24(t[ 7], t[ 4], t[ 3], m, mp);
        sp_3072_mont_sqr_avx2_24(t[ 8], t[ 4], m, mp);
        sp_3072_mont_mul_avx2_24(t[ 9], t[ 5], t[ 4], m, mp);
        sp_3072_mont_sqr_avx2_24(t[10], t[ 5], m, mp);
        sp_3072_mont_mul_avx2_24(t[11], t[ 6], t[ 5], m, mp);
        sp_3072_mont_sqr_avx2_24(t[12], t[ 6], m, mp);
        sp_3072_mont_mul_avx2_24(t[13], t[ 7], t[ 6], m, mp);
        sp_3072_mont_sqr_avx2_24(t[14], t[ 7], m, mp);
        sp_3072_mont_mul_avx2_24(t[15], t[ 8], t[ 7], m, mp);
        sp_3072_mont_sqr_avx2_24(t[16], t[ 8], m, mp);
        sp_3072_mont_mul_avx2_24(t[17], t[ 9], t[ 8], m, mp);
        sp_3072_mont_sqr_avx2_24(t[18], t[ 9], m, mp);
        sp_3072_mont_mul_avx2_24(t[19], t[10], t[ 9], m, mp);
        sp_3072_mont_sqr_avx2_24(t[20], t[10], m, mp);
        sp_3072_mont_mul_avx2_24(t[21], t[11], t[10], m, mp);
        sp_3072_mont_sqr_avx2_24(t[22], t[11], m, mp);
        sp_3072_mont_mul_avx2_24(t[23], t[12], t[11], m, mp);
        sp_3072_mont_sqr_avx2_24(t[24], t[12], m, mp);
        sp_3072_mont_mul_avx2_24(t[25], t[13], t[12], m, mp);
        sp_3072_mont_sqr_avx2_24(t[26], t[13], m, mp);
        sp_3072_mont_mul_avx2_24(t[27], t[14], t[13], m, mp);
        sp_3072_mont_sqr_avx2_24(t[28], t[14], m, mp);
        sp_3072_mont_mul_avx2_24(t[29], t[15], t[14], m, mp);
        sp_3072_mont_sqr_avx2_24(t[30], t[15], m, mp);
        sp_3072_mont_mul_avx2_24(t[31], t[16], t[15], m, mp);

        i = (bits - 1) / 64;
        n = e[i--];
        /* Number of bits available in top word. */
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        /* Minus the number of top bits to use so rest is a multiple of 5. */
        if ((bits % 5) == 0) {
            c -= 5;
        }
        else {
            c -= bits % 5;
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
    #ifndef WC_NO_CACHE_RESISTANT
        sp_3072_get_from_table_avx2_24(r, t, y);
    #else
        XMEMCPY(r, t[y], sizeof(sp_digit) * 24);
    #endif
        for (; i>=0 || c>=5; ) {
            if (c >= 5) {
                y = (byte)((n >> 59) & 0x1f);
                n <<= 5;
                c -= 5;
            }
            else if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 59);
                n <<= 5;
                c = 59;
            }
            else {
                y = (byte)(n >> 59);
                n = e[i--];
                c = 5 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }

            sp_3072_sqr_avx2_24(rt, r);
            sp_3072_mont_reduce_avx2_24(rt, m, mp);
            sp_3072_sqr_avx2_24(r, rt);
            sp_3072_mont_reduce_avx2_24(r, m, mp);
            sp_3072_sqr_avx2_24(rt, r);
            sp_3072_mont_reduce_avx2_24(rt, m, mp);
            sp_3072_sqr_avx2_24(r, rt);
            sp_3072_mont_reduce_avx2_24(r, m, mp);
            sp_3072_sqr_avx2_24(rt, r);
            sp_3072_mont_reduce_avx2_24(rt, m, mp);

            #ifndef WC_NO_CACHE_RESISTANT
                sp_3072_get_from_table_avx2_24(r, t, y);
                sp_3072_mul_avx2_24(r, rt, r);
            #else
                sp_3072_mul_avx2_24(r, rt, t[y]);
            #endif
            sp_3072_mont_reduce_avx2_24(r, m, mp);
        }

        XMEMSET(&r[24], 0, sizeof(sp_digit) * 24);
        sp_3072_mont_reduce_avx2_24(r, m, mp);

        mask = 0 - (sp_3072_cmp_24(r, m) >= 0);
        sp_3072_cond_sub_avx2_24(r, r, m, mask);
    }


    return err;
}
#endif /* HAVE_INTEL_AVX2 */

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

    ASSERT_SAVED_VECTOR_REGISTERS();

    /* r = 2^n mod m */
    sp_3072_sub_in_place_48(r, m);
}

#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) | WOLFSSL_HAVE_SP_DH */
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_3072_cond_sub_48(sp_digit* r, const sp_digit* a, const sp_digit* b, sp_digit m);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_mont_reduce_48(sp_digit* a, const sp_digit* m, sp_digit mp);
#ifdef __cplusplus
}
#endif
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

#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_3072_sub_48(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_mul_d_avx2_48(sp_digit* r, const sp_digit* a, const sp_digit b);
#ifdef __cplusplus
}
#endif
#ifdef _WIN64
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit div_3072_word_asm_48(sp_digit d1, sp_digit d0, sp_digit div);
#ifdef __cplusplus
}
#endif
/* Divide the double width number (d1|d0) by the dividend. (d1|d0 / div)
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The dividend.
 * returns the result of the division.
 */
static WC_INLINE sp_digit div_3072_word_48(sp_digit d1, sp_digit d0,
        sp_digit div)
{
    ASSERT_SAVED_VECTOR_REGISTERS();
    return div_3072_word_asm_48(d1, d0, div);
}
#else
/* Divide the double width number (d1|d0) by the dividend. (d1|d0 / div)
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The dividend.
 * returns the result of the division.
 */
static WC_INLINE sp_digit div_3072_word_48(sp_digit d1, sp_digit d0,
        sp_digit div)
{
    ASSERT_SAVED_VECTOR_REGISTERS();
    register sp_digit r asm("rax");
    __asm__ __volatile__ (
        "divq %3"
        : "=a" (r)
        : "d" (d1), "a" (d0), "r" (div)
        :
    );
    return r;
}
#endif /* _WIN64 */
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
    sp_digit t1[96];
    sp_digit t2[49];
    sp_digit div;
    sp_digit r1;
    int i;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

    ASSERT_SAVED_VECTOR_REGISTERS();

    (void)m;

    div = d[47];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 48);
    for (i = 47; i > 0; i--) {
        if (t1[i + 48] != d[i])
            break;
    }
    if (t1[i + 48] >= d[i]) {
        sp_3072_sub_in_place_48(&t1[48], d);
    }
    for (i = 47; i >= 0; i--) {
        if (t1[48 + i] == div) {
            r1 = SP_DIGIT_MAX;
        }
        else {
            r1 = div_3072_word_48(t1[48 + i], t1[48 + i - 1], div);
        }

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            sp_3072_mul_d_avx2_48(t2, d, r1);
        else
#endif
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
static WC_INLINE int sp_3072_mod_48_cond(sp_digit* r, const sp_digit* a,
        const sp_digit* m)
{
    ASSERT_SAVED_VECTOR_REGISTERS();
    return sp_3072_div_48_cond(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_3072_cond_sub_avx2_48(sp_digit* r, const sp_digit* a, const sp_digit* b, sp_digit m);
#ifdef __cplusplus
}
#endif
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

#ifdef __cplusplus
extern "C" {
#endif
extern sp_int64 sp_3072_cmp_48(const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
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
    sp_digit t1[96];
    sp_digit t2[49];
    sp_digit div;
    sp_digit r1;
    int i;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

    ASSERT_SAVED_VECTOR_REGISTERS();

    (void)m;

    div = d[47];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 48);
    r1 = sp_3072_cmp_48(&t1[48], d) >= 0;
#ifdef HAVE_INTEL_AVX2
    if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
        sp_3072_cond_sub_avx2_48(&t1[48], &t1[48], d, (sp_digit)0 - r1);
    else
#endif
        sp_3072_cond_sub_48(&t1[48], &t1[48], d, (sp_digit)0 - r1);
    for (i = 47; i >= 0; i--) {
        sp_digit mask = 0 - (t1[48 + i] == div);
        sp_digit hi = t1[48 + i] + mask;
        r1 = div_3072_word_48(hi, t1[48 + i - 1], div);
        r1 |= mask;

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            sp_3072_mul_d_avx2_48(t2, d, r1);
        else
#endif
            sp_3072_mul_d_48(t2, d, r1);
        t1[48 + i] += sp_3072_sub_in_place_48(&t1[i], t2);
        t1[48 + i] -= t2[48];
        sp_3072_mask_48(t2, d, t1[48 + i]);
        t1[48 + i] += sp_3072_add_48(&t1[i], &t1[i], t2);
        sp_3072_mask_48(t2, d, t1[48 + i]);
        t1[48 + i] += sp_3072_add_48(&t1[i], &t1[i], t2);
    }

    r1 = sp_3072_cmp_48(t1, d) >= 0;
#ifdef HAVE_INTEL_AVX2
    if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
        sp_3072_cond_sub_avx2_48(r, t1, d, (sp_digit)0 - r1);
    else
#endif
        sp_3072_cond_sub_48(r, t1, d, (sp_digit)0 - r1);

    return MP_OKAY;
}

#if defined(WOLFSSL_HAVE_SP_DH) || !defined(WOLFSSL_RSA_PUBLIC_ONLY)
/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_3072_mod_48(sp_digit* r, const sp_digit* a,
        const sp_digit* m)
{
    ASSERT_SAVED_VECTOR_REGISTERS();
    return sp_3072_div_48(a, m, NULL, r);
}

#endif /* WOLFSSL_HAVE_SP_DH || !WOLFSSL_RSA_PUBLIC_ONLY */
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_get_from_table_48(sp_digit* r, sp_digit** table, int idx);
#ifdef __cplusplus
}
#endif

/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even or exponent is 0.
 */
static int sp_3072_mod_exp_48(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[(17 * 96) + 96];
    sp_digit* t[16];
    sp_digit* rt = NULL;
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<16; i++)
            t[i] = td + i * 96;
        rt = td + 1536;

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_48(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 48);
        if (reduceA) {
            err = sp_3072_mod_48(t[1] + 48, a, m);
            if (err == MP_OKAY)
                err = sp_3072_mod_48(t[1], t[1], m);
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
        /* Number of bits available in top word. */
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        /* Minus the number of top bits to use so rest is a multiple of 4. */
        if ((bits % 4) == 0) {
            c -= 4;
        }
        else {
            c -= bits % 4;
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
    #ifndef WC_NO_CACHE_RESISTANT
        sp_3072_get_from_table_48(r, t, y);
    #else
        XMEMCPY(r, t[y], sizeof(sp_digit) * 48);
    #endif
        for (; i>=0 || c>=4; ) {
            if (c >= 4) {
                y = (byte)((n >> 60) & 0xf);
                n <<= 4;
                c -= 4;
            }
            else if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 60);
                n <<= 4;
                c = 60;
            }
            else {
                y = (byte)(n >> 60);
                n = e[i--];
                c = 4 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }

            sp_3072_sqr_48(rt, r);
            sp_3072_mont_reduce_48(rt, m, mp);
            sp_3072_sqr_48(r, rt);
            sp_3072_mont_reduce_48(r, m, mp);
            sp_3072_sqr_48(rt, r);
            sp_3072_mont_reduce_48(rt, m, mp);
            sp_3072_sqr_48(r, rt);
            sp_3072_mont_reduce_48(r, m, mp);
            #ifndef WC_NO_CACHE_RESISTANT
                sp_3072_get_from_table_48(rt, t, y);
                sp_3072_mul_48(r, r, rt);
            #else
                sp_3072_mul_48(r, r, t[y]);
            #endif
            sp_3072_mont_reduce_48(r, m, mp);
        }

        XMEMSET(&r[48], 0, sizeof(sp_digit) * 48);
        sp_3072_mont_reduce_48(r, m, mp);

        mask = 0 - (sp_3072_cmp_48(r, m) >= 0);
        sp_3072_cond_sub_48(r, r, m, mask);
    }


    return err;
}

#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || WOLFSSL_HAVE_SP_DH */
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_mont_reduce_avx2_48(sp_digit* a, const sp_digit* m, sp_digit mp);
#ifdef __cplusplus
}
#endif
#ifdef HAVE_INTEL_AVX2
/* Multiply two Montgomery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montgomery form.
 * b   Second number to multiply in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_3072_mont_mul_avx2_48(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_3072_mul_avx2_48(r, a, b);
    sp_3072_mont_reduce_avx2_48(r, m, mp);
}

#endif /* HAVE_INTEL_AVX2 */
#ifdef HAVE_INTEL_AVX2
/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_3072_mont_sqr_avx2_48(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_3072_sqr_avx2_48(r, a);
    sp_3072_mont_reduce_avx2_48(r, m, mp);
}

#endif /* HAVE_INTEL_AVX2 */
#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_get_from_table_avx2_48(sp_digit* r, sp_digit** table, int idx);
#ifdef __cplusplus
}
#endif

#ifdef HAVE_INTEL_AVX2
/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even or exponent is 0.
 */
static int sp_3072_mod_exp_avx2_48(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[(17 * 96) + 96];
    sp_digit* t[16];
    sp_digit* rt = NULL;
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<16; i++)
            t[i] = td + i * 96;
        rt = td + 1536;

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_48(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 48);
        if (reduceA) {
            err = sp_3072_mod_48(t[1] + 48, a, m);
            if (err == MP_OKAY)
                err = sp_3072_mod_48(t[1], t[1], m);
        }
        else {
            XMEMCPY(t[1] + 48, a, sizeof(sp_digit) * 48);
            err = sp_3072_mod_48(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_3072_mont_sqr_avx2_48(t[ 2], t[ 1], m, mp);
        sp_3072_mont_mul_avx2_48(t[ 3], t[ 2], t[ 1], m, mp);
        sp_3072_mont_sqr_avx2_48(t[ 4], t[ 2], m, mp);
        sp_3072_mont_mul_avx2_48(t[ 5], t[ 3], t[ 2], m, mp);
        sp_3072_mont_sqr_avx2_48(t[ 6], t[ 3], m, mp);
        sp_3072_mont_mul_avx2_48(t[ 7], t[ 4], t[ 3], m, mp);
        sp_3072_mont_sqr_avx2_48(t[ 8], t[ 4], m, mp);
        sp_3072_mont_mul_avx2_48(t[ 9], t[ 5], t[ 4], m, mp);
        sp_3072_mont_sqr_avx2_48(t[10], t[ 5], m, mp);
        sp_3072_mont_mul_avx2_48(t[11], t[ 6], t[ 5], m, mp);
        sp_3072_mont_sqr_avx2_48(t[12], t[ 6], m, mp);
        sp_3072_mont_mul_avx2_48(t[13], t[ 7], t[ 6], m, mp);
        sp_3072_mont_sqr_avx2_48(t[14], t[ 7], m, mp);
        sp_3072_mont_mul_avx2_48(t[15], t[ 8], t[ 7], m, mp);

        i = (bits - 1) / 64;
        n = e[i--];
        /* Number of bits available in top word. */
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        /* Minus the number of top bits to use so rest is a multiple of 4. */
        if ((bits % 4) == 0) {
            c -= 4;
        }
        else {
            c -= bits % 4;
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
    #ifndef WC_NO_CACHE_RESISTANT
        sp_3072_get_from_table_avx2_48(r, t, y);
    #else
        XMEMCPY(r, t[y], sizeof(sp_digit) * 48);
    #endif
        for (; i>=0 || c>=4; ) {
            if (c >= 4) {
                y = (byte)((n >> 60) & 0xf);
                n <<= 4;
                c -= 4;
            }
            else if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 60);
                n <<= 4;
                c = 60;
            }
            else {
                y = (byte)(n >> 60);
                n = e[i--];
                c = 4 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }

            sp_3072_sqr_avx2_48(rt, r);
            sp_3072_mont_reduce_avx2_48(rt, m, mp);
            sp_3072_sqr_avx2_48(r, rt);
            sp_3072_mont_reduce_avx2_48(r, m, mp);
            sp_3072_sqr_avx2_48(rt, r);
            sp_3072_mont_reduce_avx2_48(rt, m, mp);
            sp_3072_sqr_avx2_48(r, rt);
            sp_3072_mont_reduce_avx2_48(r, m, mp);
            #ifndef WC_NO_CACHE_RESISTANT
                sp_3072_get_from_table_avx2_48(rt, t, y);
                sp_3072_mul_avx2_48(r, r, rt);
            #else
                sp_3072_mul_avx2_48(r, r, t[y]);
            #endif
            sp_3072_mont_reduce_avx2_48(r, m, mp);
        }

        XMEMSET(&r[48], 0, sizeof(sp_digit) * 48);
        sp_3072_mont_reduce_avx2_48(r, m, mp);

        mask = 0 - (sp_3072_cmp_48(r, m) >= 0);
        sp_3072_cond_sub_avx2_48(r, r, m, mask);
    }


    return err;
}
#endif /* HAVE_INTEL_AVX2 */

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
    sp_digit* ah;
    sp_digit* m;
    sp_digit* r;
    sp_digit  e = 0;
    int err = MP_OKAY;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

    ASSERT_SAVED_VECTOR_REGISTERS();

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
        r = a + 48 * 2;
        m = r + 48 * 2;
        ah = a + 48;

        sp_3072_from_bin(ah, 48, in, inLen);
#if DIGIT_BIT >= 64
        e = em->dp[0];
#else
        e = em->dp[0];
        if (em->used > 1)
            e |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
#endif
        if (e == 0)
            err = MP_EXPTMOD_E;
    }
    if (err == MP_OKAY) {
        sp_3072_from_mp(m, 48, mm);

        if (e == 0x10001) {
            int i;
            sp_digit mp;

            sp_3072_mont_setup(m, &mp);

            /* Convert to Montgomery form. */
            XMEMSET(a, 0, sizeof(sp_digit) * 48);
            err = sp_3072_mod_48_cond(r, a, m);
            /* Montgomery form: r = a.R mod m */

            if (err == MP_OKAY) {
                /* r = a ^ 0x10000 => r = a squared 16 times */
#ifdef HAVE_INTEL_AVX2
                if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
                    for (i = 15; i >= 0; i--) {
                        sp_3072_mont_sqr_avx2_48(r, r, m, mp);
                    }
                    /* mont_red(r.R.R) = (r.R.R / R) mod m = r.R mod m
                     * mont_red(r.R * a) = (r.R.a / R) mod m = r.a mod m
                     */
                    sp_3072_mont_mul_avx2_48(r, r, ah, m, mp);
                }
                else
#endif
                {
                    for (i = 15; i >= 0; i--) {
                        sp_3072_mont_sqr_48(r, r, m, mp);
                    }
                    /* mont_red(r.R.R) = (r.R.R / R) mod m = r.R mod m
                     * mont_red(r.R * a) = (r.R.a / R) mod m = r.a mod m
                     */
                    sp_3072_mont_mul_48(r, r, ah, m, mp);
                }

                for (i = 47; i > 0; i--) {
                    if (r[i] != m[i])
                        break;
                }
                if (r[i] >= m[i])
                    sp_3072_sub_in_place_48(r, m);
            }
        }
        else if (e == 0x3) {
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
                if (err == MP_OKAY) {
                    sp_3072_sqr_avx2_48(r, ah);
                    err = sp_3072_mod_48_cond(r, r, m);
                }
                if (err == MP_OKAY) {
                    sp_3072_mul_avx2_48(r, ah, r);
                    err = sp_3072_mod_48_cond(r, r, m);
                }
            }
            else
#endif
            {
                if (err == MP_OKAY) {
                    sp_3072_sqr_48(r, ah);
                    err = sp_3072_mod_48_cond(r, r, m);
                }
                if (err == MP_OKAY) {
                    sp_3072_mul_48(r, ah, r);
                    err = sp_3072_mod_48_cond(r, r, m);
                }
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
                for (i=63; i>=0; i--) {
                    if (e >> i) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 48);
#ifdef HAVE_INTEL_AVX2
                if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
                    for (i--; i>=0; i--) {
                        sp_3072_mont_sqr_avx2_48(r, r, m, mp);
                        if (((e >> i) & 1) == 1) {
                            sp_3072_mont_mul_avx2_48(r, r, a, m, mp);
                        }
                    }
                    XMEMSET(&r[48], 0, sizeof(sp_digit) * 48);
                    sp_3072_mont_reduce_avx2_48(r, m, mp);
                }
                else
#endif
                {
                    for (i--; i>=0; i--) {
                        sp_3072_mont_sqr_48(r, r, m, mp);
                        if (((e >> i) & 1) == 1) {
                            sp_3072_mont_mul_48(r, r, a, m, mp);
                        }
                    }
                    XMEMSET(&r[48], 0, sizeof(sp_digit) * 48);
                    sp_3072_mont_reduce_48(r, m, mp);
                }

                for (i = 47; i > 0; i--) {
                    if (r[i] != m[i])
                        break;
                }
                if (r[i] >= m[i])
                    sp_3072_sub_in_place_48(r, m);
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
#if defined(SP_RSA_PRIVATE_EXP_D) || defined(RSA_LOW_MEM)
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
    const mp_int* pm, const mp_int* qm,const  mp_int* dpm, const mp_int* dqm,
    const mp_int* qim, const mp_int* mm, byte* out, word32* outLen)
{
    sp_digit d[48 * 4];
    sp_digit* a;
    sp_digit* m;
    sp_digit* r;
    int err = MP_OKAY;

    ASSERT_SAVED_VECTOR_REGISTERS();

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
        /* only zeroing private "d" */
        ForceZero(d, sizeof(sp_digit) * 48);
    }

    return err;
}

#else
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_3072_cond_add_24(sp_digit* r, const sp_digit* a, const sp_digit* b, sp_digit m);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_3072_cond_add_avx2_24(sp_digit* r, const sp_digit* a, const sp_digit* b, sp_digit m);
#ifdef __cplusplus
}
#endif
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
    sp_digit a[24 * 11];
    sp_digit* p;
    sp_digit* q;
    sp_digit* dp;
    sp_digit* dq;
    sp_digit* qi;
    sp_digit* tmpa;
    sp_digit* tmpb;
    sp_digit* r;
    sp_digit c;
    int err = MP_OKAY;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

    ASSERT_SAVED_VECTOR_REGISTERS();

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
        r = a + 48;

        sp_3072_from_bin(a, 48, in, inLen);
        sp_3072_from_mp(p, 24, pm);
        sp_3072_from_mp(q, 24, qm);
        sp_3072_from_mp(dp, 24, dpm);

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            err = sp_3072_mod_exp_avx2_24(tmpa, a, dp, 1536, p, 1);
        else
#endif
            err = sp_3072_mod_exp_24(tmpa, a, dp, 1536, p, 1);
    }
    if (err == MP_OKAY) {
        sp_3072_from_mp(dq, 24, dqm);
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            err = sp_3072_mod_exp_avx2_24(tmpb, a, dq, 1536, q, 1);
       else
#endif
            err = sp_3072_mod_exp_24(tmpb, a, dq, 1536, q, 1);
    }

    if (err == MP_OKAY) {
        c = sp_3072_sub_in_place_24(tmpa, tmpb);
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
            c += sp_3072_cond_add_avx2_24(tmpa, tmpa, p, c);
            sp_3072_cond_add_avx2_24(tmpa, tmpa, p, c);
        }
        else
#endif
        {
            c += sp_3072_cond_add_24(tmpa, tmpa, p, c);
            sp_3072_cond_add_24(tmpa, tmpa, p, c);
        }

        sp_3072_from_mp(qi, 24, qim);
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
            sp_3072_mul_avx2_24(tmpa, tmpa, qi);
        }
        else
#endif
        {
            sp_3072_mul_24(tmpa, tmpa, qi);
        }
        err = sp_3072_mod_24(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
            sp_3072_mul_avx2_24(tmpa, q, tmpa);
        }
        else
#endif
        {
            sp_3072_mul_24(tmpa, q, tmpa);
        }
        XMEMSET(&tmpb[24], 0, sizeof(sp_digit) * 24);
        sp_3072_add_48(r, tmpb, tmpa);

        sp_3072_to_bin_48(r, out);
        *outLen = 384;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 24 * 11);
    }

    return err;
}
#endif /* SP_RSA_PRIVATE_EXP_D | RSA_LOW_MEM */
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
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif
    int expBits = mp_count_bits(exp);

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (mp_count_bits(base) > 3072 || expBits > 3072 ||
                                                   mp_count_bits(mod) != 3072) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mod)) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        sp_3072_from_mp(b, 48, base);
        sp_3072_from_mp(e, 48, exp);
        sp_3072_from_mp(m, 48, mod);

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            err = sp_3072_mod_exp_avx2_48(r, b, e, expBits, m, 0);
        else
#endif
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
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_3072_lshift_48(sp_digit* r, const sp_digit* a, int n);
#ifdef __cplusplus
}
#endif
#ifdef HAVE_INTEL_AVX2
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
static int sp_3072_mod_exp_2_avx2_48(sp_digit* r, const sp_digit* e, int bits,
        const sp_digit* m)
{
    sp_digit td[49 + 96];
    sp_digit* norm;
    sp_digit* tmp;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit o;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        tmp = &td[96];

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_48(norm, m);

        i = (bits - 1) / 64;
        n = e[i--];
        /* Number of bits available in top word. */
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        /* Minus the number of top bits to use so rest is a multiple of 6. */
        if ((bits % 6) == 0) {
            c -= 6;
        }
        else {
            c -= bits % 6;
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
        while ((i >= 0) || (c >= 6)) {
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

            sp_3072_mont_sqr_avx2_48(r, r, m, mp);
            sp_3072_mont_sqr_avx2_48(r, r, m, mp);
            sp_3072_mont_sqr_avx2_48(r, r, m, mp);
            sp_3072_mont_sqr_avx2_48(r, r, m, mp);
            sp_3072_mont_sqr_avx2_48(r, r, m, mp);
            sp_3072_mont_sqr_avx2_48(r, r, m, mp);

            sp_3072_lshift_48(r, r, y);
            sp_3072_mul_d_avx2_48(tmp, norm, r[48]);
            r[48] = 0;
            o = sp_3072_add_48(r, r, tmp);
            sp_3072_cond_sub_avx2_48(r, r, m, (sp_digit)0 - o);
        }

        XMEMSET(&r[48], 0, sizeof(sp_digit) * 48);
        sp_3072_mont_reduce_avx2_48(r, m, mp);

        mask = 0 - (sp_3072_cmp_48(r, m) >= 0);
        sp_3072_cond_sub_avx2_48(r, r, m, mask);
    }


    return err;
}
#endif /* HAVE_INTEL_AVX2 */

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
    sp_digit td[49 + 96];
    sp_digit* norm;
    sp_digit* tmp;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit o;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        tmp = &td[96];

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_48(norm, m);

        i = (bits - 1) / 64;
        n = e[i--];
        /* Number of bits available in top word. */
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        /* Minus the number of top bits to use so rest is a multiple of 6. */
        if ((bits % 6) == 0) {
            c -= 6;
        }
        else {
            c -= bits % 6;
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
        while ((i >= 0) || (c >= 6)) {
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

        XMEMSET(&r[48], 0, sizeof(sp_digit) * 48);
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
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (mp_count_bits(base) > 3072 || expLen > 384 ||
                                                   mp_count_bits(mod) != 3072) {
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
        if (base->used == 1 && base->dp[0] == 2 && m[47] == (sp_digit)-1) {
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
                err = sp_3072_mod_exp_2_avx2_48(r, e, expLen * 8, m);
            else
#endif
                err = sp_3072_mod_exp_2_48(r, e, expLen * 8, m);
        }
        else
    #endif
        {
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
                err = sp_3072_mod_exp_avx2_48(r, b, e, expLen * 8, m, 0);
            else
#endif
                err = sp_3072_mod_exp_48(r, b, e, expLen * 8, m, 0);
        }
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
#endif
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
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif
    int expBits = mp_count_bits(exp);

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (mp_count_bits(base) > 1536 || expBits > 1536 ||
                                                   mp_count_bits(mod) != 1536) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mod)) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        sp_3072_from_mp(b, 24, base);
        sp_3072_from_mp(e, 24, exp);
        sp_3072_from_mp(m, 24, mod);

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            err = sp_3072_mod_exp_avx2_24(r, b, e, expBits, m, 0);
        else
#endif
            err = sp_3072_mod_exp_24(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 24, 0, sizeof(*r) * 24);
        err = sp_3072_to_mp(r, res);
    }

    XMEMSET(e, 0, sizeof(e));

    return err;
}

#endif /* WOLFSSL_HAVE_SP_DH | (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) */

#endif /* !WOLFSSL_SP_NO_3072 */

#ifdef WOLFSSL_SP_4096
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_4096_from_bin_bswap(sp_digit* r, int size, const byte* a, int n);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_4096_from_bin_movbe(sp_digit* r, int size, const byte* a, int n);
#ifdef __cplusplus
}
#endif
/* Read big endian unsigned byte array into r.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  Byte array.
 * n  Number of bytes in array to read.
 */
static void sp_4096_from_bin(sp_digit* r, int size, const byte* a, int n)
{
#ifndef NO_MOVBE_SUPPORT
    word32 cpuid_flags = cpuid_get_flags();

    if (IS_INTEL_MOVBE(cpuid_flags)) {
        sp_4096_from_bin_movbe(r, size, a, n);
    }
    else
#endif
    {
        sp_4096_from_bin_bswap(r, size, a, n);
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

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_4096_to_bin_bswap_64(sp_digit* r, byte* a);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_4096_to_bin_movbe_64(sp_digit* r, byte* a);
#ifdef __cplusplus
}
#endif
/* Write r as big endian to byte array.
 * Fixed length number of bytes written: 512
 *
 * r  A single precision integer.
 * a  Byte array.
 */
static void sp_4096_to_bin_64(sp_digit* r, byte* a)
{
#ifndef NO_MOVBE_SUPPORT
    word32 cpuid_flags = cpuid_get_flags();

    if (IS_INTEL_MOVBE(cpuid_flags)) {
        sp_4096_to_bin_movbe_64(r, a);
    }
    else
#endif
    {
        sp_4096_to_bin_bswap_64(r, a);
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

#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_4096_sub_in_place_64(sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_4096_add_64(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_4096_mul_64(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_4096_mul_avx2_64(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_4096_sqr_64(sp_digit* r, const sp_digit* a);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_4096_sqr_avx2_64(sp_digit* r, const sp_digit* a);
#ifdef __cplusplus
}
#endif

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

#ifdef __cplusplus
extern "C" {
#endif
extern void sp_4096_mul_d_64(sp_digit* r, const sp_digit* a, sp_digit b);
#ifdef __cplusplus
}
#endif
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

    ASSERT_SAVED_VECTOR_REGISTERS();

    /* r = 2^n mod m */
    sp_4096_sub_in_place_64(r, m);
}

#endif /* (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) | WOLFSSL_HAVE_SP_DH */
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_4096_cond_sub_64(sp_digit* r, const sp_digit* a, const sp_digit* b, sp_digit m);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_4096_mont_reduce_64(sp_digit* a, const sp_digit* m, sp_digit mp);
#ifdef __cplusplus
}
#endif
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

#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_4096_sub_64(sp_digit* r, const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_4096_mul_d_avx2_64(sp_digit* r, const sp_digit* a, const sp_digit b);
#ifdef __cplusplus
}
#endif
#ifdef _WIN64
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit div_4096_word_asm_64(sp_digit d1, sp_digit d0, sp_digit div);
#ifdef __cplusplus
}
#endif
/* Divide the double width number (d1|d0) by the dividend. (d1|d0 / div)
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The dividend.
 * returns the result of the division.
 */
static WC_INLINE sp_digit div_4096_word_64(sp_digit d1, sp_digit d0,
        sp_digit div)
{
    ASSERT_SAVED_VECTOR_REGISTERS();
    return div_4096_word_asm_64(d1, d0, div);
}
#else
/* Divide the double width number (d1|d0) by the dividend. (d1|d0 / div)
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The dividend.
 * returns the result of the division.
 */
static WC_INLINE sp_digit div_4096_word_64(sp_digit d1, sp_digit d0,
        sp_digit div)
{
    ASSERT_SAVED_VECTOR_REGISTERS();
    register sp_digit r asm("rax");
    __asm__ __volatile__ (
        "divq %3"
        : "=a" (r)
        : "d" (d1), "a" (d0), "r" (div)
        :
    );
    return r;
}
#endif /* _WIN64 */
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
    sp_digit t1[128];
    sp_digit t2[65];
    sp_digit div;
    sp_digit r1;
    int i;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

    ASSERT_SAVED_VECTOR_REGISTERS();

    (void)m;

    div = d[63];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 64);
    for (i = 63; i > 0; i--) {
        if (t1[i + 64] != d[i])
            break;
    }
    if (t1[i + 64] >= d[i]) {
        sp_4096_sub_in_place_64(&t1[64], d);
    }
    for (i = 63; i >= 0; i--) {
        if (t1[64 + i] == div) {
            r1 = SP_DIGIT_MAX;
        }
        else {
            r1 = div_4096_word_64(t1[64 + i], t1[64 + i - 1], div);
        }

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            sp_4096_mul_d_avx2_64(t2, d, r1);
        else
#endif
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
static WC_INLINE int sp_4096_mod_64_cond(sp_digit* r, const sp_digit* a,
        const sp_digit* m)
{
    ASSERT_SAVED_VECTOR_REGISTERS();
    return sp_4096_div_64_cond(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_4096_cond_sub_avx2_64(sp_digit* r, const sp_digit* a, const sp_digit* b, sp_digit m);
#ifdef __cplusplus
}
#endif
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

#ifdef __cplusplus
extern "C" {
#endif
extern sp_int64 sp_4096_cmp_64(const sp_digit* a, const sp_digit* b);
#ifdef __cplusplus
}
#endif
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
    sp_digit t1[128];
    sp_digit t2[65];
    sp_digit div;
    sp_digit r1;
    int i;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

    ASSERT_SAVED_VECTOR_REGISTERS();

    (void)m;

    div = d[63];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 64);
    r1 = sp_4096_cmp_64(&t1[64], d) >= 0;
#ifdef HAVE_INTEL_AVX2
    if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
        sp_4096_cond_sub_avx2_64(&t1[64], &t1[64], d, (sp_digit)0 - r1);
    else
#endif
        sp_4096_cond_sub_64(&t1[64], &t1[64], d, (sp_digit)0 - r1);
    for (i = 63; i >= 0; i--) {
        sp_digit mask = 0 - (t1[64 + i] == div);
        sp_digit hi = t1[64 + i] + mask;
        r1 = div_4096_word_64(hi, t1[64 + i - 1], div);
        r1 |= mask;

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            sp_4096_mul_d_avx2_64(t2, d, r1);
        else
#endif
            sp_4096_mul_d_64(t2, d, r1);
        t1[64 + i] += sp_4096_sub_in_place_64(&t1[i], t2);
        t1[64 + i] -= t2[64];
        sp_4096_mask_64(t2, d, t1[64 + i]);
        t1[64 + i] += sp_4096_add_64(&t1[i], &t1[i], t2);
        sp_4096_mask_64(t2, d, t1[64 + i]);
        t1[64 + i] += sp_4096_add_64(&t1[i], &t1[i], t2);
    }

    r1 = sp_4096_cmp_64(t1, d) >= 0;
#ifdef HAVE_INTEL_AVX2
    if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
        sp_4096_cond_sub_avx2_64(r, t1, d, (sp_digit)0 - r1);
    else
#endif
        sp_4096_cond_sub_64(r, t1, d, (sp_digit)0 - r1);

    return MP_OKAY;
}

#if defined(WOLFSSL_HAVE_SP_DH) || !defined(WOLFSSL_RSA_PUBLIC_ONLY)
/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_4096_mod_64(sp_digit* r, const sp_digit* a,
        const sp_digit* m)
{
    ASSERT_SAVED_VECTOR_REGISTERS();
    return sp_4096_div_64(a, m, NULL, r);
}

#endif /* WOLFSSL_HAVE_SP_DH || !WOLFSSL_RSA_PUBLIC_ONLY */
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_4096_get_from_table_64(sp_digit* r, sp_digit** table, int idx);
#ifdef __cplusplus
}
#endif

/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even or exponent is 0.
 */
static int sp_4096_mod_exp_64(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[(17 * 128) + 128];
    sp_digit* t[16];
    sp_digit* rt = NULL;
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<16; i++)
            t[i] = td + i * 128;
        rt = td + 2048;

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_64(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 64);
        if (reduceA) {
            err = sp_4096_mod_64(t[1] + 64, a, m);
            if (err == MP_OKAY)
                err = sp_4096_mod_64(t[1], t[1], m);
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
        /* Number of bits available in top word. */
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        /* Minus the number of top bits to use so rest is a multiple of 4. */
        if ((bits % 4) == 0) {
            c -= 4;
        }
        else {
            c -= bits % 4;
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
    #ifndef WC_NO_CACHE_RESISTANT
        sp_4096_get_from_table_64(r, t, y);
    #else
        XMEMCPY(r, t[y], sizeof(sp_digit) * 64);
    #endif
        for (; i>=0 || c>=4; ) {
            if (c >= 4) {
                y = (byte)((n >> 60) & 0xf);
                n <<= 4;
                c -= 4;
            }
            else if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 60);
                n <<= 4;
                c = 60;
            }
            else {
                y = (byte)(n >> 60);
                n = e[i--];
                c = 4 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }

            sp_4096_sqr_64(rt, r);
            sp_4096_mont_reduce_64(rt, m, mp);
            sp_4096_sqr_64(r, rt);
            sp_4096_mont_reduce_64(r, m, mp);
            sp_4096_sqr_64(rt, r);
            sp_4096_mont_reduce_64(rt, m, mp);
            sp_4096_sqr_64(r, rt);
            sp_4096_mont_reduce_64(r, m, mp);
            #ifndef WC_NO_CACHE_RESISTANT
                sp_4096_get_from_table_64(rt, t, y);
                sp_4096_mul_64(r, r, rt);
            #else
                sp_4096_mul_64(r, r, t[y]);
            #endif
            sp_4096_mont_reduce_64(r, m, mp);
        }

        XMEMSET(&r[64], 0, sizeof(sp_digit) * 64);
        sp_4096_mont_reduce_64(r, m, mp);

        mask = 0 - (sp_4096_cmp_64(r, m) >= 0);
        sp_4096_cond_sub_64(r, r, m, mask);
    }


    return err;
}

#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || WOLFSSL_HAVE_SP_DH */
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_4096_mont_reduce_avx2_64(sp_digit* a, const sp_digit* m, sp_digit mp);
#ifdef __cplusplus
}
#endif
#ifdef HAVE_INTEL_AVX2
/* Multiply two Montgomery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montgomery form.
 * b   Second number to multiply in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_4096_mont_mul_avx2_64(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_4096_mul_avx2_64(r, a, b);
    sp_4096_mont_reduce_avx2_64(r, m, mp);
}

#endif /* HAVE_INTEL_AVX2 */
#ifdef HAVE_INTEL_AVX2
/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery mulitplier.
 */
SP_NOINLINE static void sp_4096_mont_sqr_avx2_64(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_4096_sqr_avx2_64(r, a);
    sp_4096_mont_reduce_avx2_64(r, m, mp);
}

#endif /* HAVE_INTEL_AVX2 */
#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_4096_get_from_table_avx2_64(sp_digit* r, sp_digit** table, int idx);
#ifdef __cplusplus
}
#endif

#ifdef HAVE_INTEL_AVX2
/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns  0 on success
 * returns  MEMORY_E on dynamic memory allocation failure.
 * returns  MP_VAL when base is even or exponent is 0.
 */
static int sp_4096_mod_exp_avx2_64(sp_digit* r, const sp_digit* a, const sp_digit* e,
        int bits, const sp_digit* m, int reduceA)
{
    sp_digit td[(17 * 128) + 128];
    sp_digit* t[16];
    sp_digit* rt = NULL;
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        for (i=0; i<16; i++)
            t[i] = td + i * 128;
        rt = td + 2048;

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_64(norm, m);

        XMEMSET(t[1], 0, sizeof(sp_digit) * 64);
        if (reduceA) {
            err = sp_4096_mod_64(t[1] + 64, a, m);
            if (err == MP_OKAY)
                err = sp_4096_mod_64(t[1], t[1], m);
        }
        else {
            XMEMCPY(t[1] + 64, a, sizeof(sp_digit) * 64);
            err = sp_4096_mod_64(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_4096_mont_sqr_avx2_64(t[ 2], t[ 1], m, mp);
        sp_4096_mont_mul_avx2_64(t[ 3], t[ 2], t[ 1], m, mp);
        sp_4096_mont_sqr_avx2_64(t[ 4], t[ 2], m, mp);
        sp_4096_mont_mul_avx2_64(t[ 5], t[ 3], t[ 2], m, mp);
        sp_4096_mont_sqr_avx2_64(t[ 6], t[ 3], m, mp);
        sp_4096_mont_mul_avx2_64(t[ 7], t[ 4], t[ 3], m, mp);
        sp_4096_mont_sqr_avx2_64(t[ 8], t[ 4], m, mp);
        sp_4096_mont_mul_avx2_64(t[ 9], t[ 5], t[ 4], m, mp);
        sp_4096_mont_sqr_avx2_64(t[10], t[ 5], m, mp);
        sp_4096_mont_mul_avx2_64(t[11], t[ 6], t[ 5], m, mp);
        sp_4096_mont_sqr_avx2_64(t[12], t[ 6], m, mp);
        sp_4096_mont_mul_avx2_64(t[13], t[ 7], t[ 6], m, mp);
        sp_4096_mont_sqr_avx2_64(t[14], t[ 7], m, mp);
        sp_4096_mont_mul_avx2_64(t[15], t[ 8], t[ 7], m, mp);

        i = (bits - 1) / 64;
        n = e[i--];
        /* Number of bits available in top word. */
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        /* Minus the number of top bits to use so rest is a multiple of 4. */
        if ((bits % 4) == 0) {
            c -= 4;
        }
        else {
            c -= bits % 4;
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
    #ifndef WC_NO_CACHE_RESISTANT
        sp_4096_get_from_table_avx2_64(r, t, y);
    #else
        XMEMCPY(r, t[y], sizeof(sp_digit) * 64);
    #endif
        for (; i>=0 || c>=4; ) {
            if (c >= 4) {
                y = (byte)((n >> 60) & 0xf);
                n <<= 4;
                c -= 4;
            }
            else if (c == 0) {
                n = e[i--];
                y = (byte)(n >> 60);
                n <<= 4;
                c = 60;
            }
            else {
                y = (byte)(n >> 60);
                n = e[i--];
                c = 4 - c;
                y |= (byte)(n >> (64 - c));
                n <<= c;
                c = 64 - c;
            }

            sp_4096_sqr_avx2_64(rt, r);
            sp_4096_mont_reduce_avx2_64(rt, m, mp);
            sp_4096_sqr_avx2_64(r, rt);
            sp_4096_mont_reduce_avx2_64(r, m, mp);
            sp_4096_sqr_avx2_64(rt, r);
            sp_4096_mont_reduce_avx2_64(rt, m, mp);
            sp_4096_sqr_avx2_64(r, rt);
            sp_4096_mont_reduce_avx2_64(r, m, mp);
            #ifndef WC_NO_CACHE_RESISTANT
                sp_4096_get_from_table_avx2_64(rt, t, y);
                sp_4096_mul_avx2_64(r, r, rt);
            #else
                sp_4096_mul_avx2_64(r, r, t[y]);
            #endif
            sp_4096_mont_reduce_avx2_64(r, m, mp);
        }

        XMEMSET(&r[64], 0, sizeof(sp_digit) * 64);
        sp_4096_mont_reduce_avx2_64(r, m, mp);

        mask = 0 - (sp_4096_cmp_64(r, m) >= 0);
        sp_4096_cond_sub_avx2_64(r, r, m, mask);
    }


    return err;
}
#endif /* HAVE_INTEL_AVX2 */

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
    sp_digit* ah;
    sp_digit* m;
    sp_digit* r;
    sp_digit  e = 0;
    int err = MP_OKAY;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

    ASSERT_SAVED_VECTOR_REGISTERS();

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
        r = a + 64 * 2;
        m = r + 64 * 2;
        ah = a + 64;

        sp_4096_from_bin(ah, 64, in, inLen);
#if DIGIT_BIT >= 64
        e = em->dp[0];
#else
        e = em->dp[0];
        if (em->used > 1)
            e |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
#endif
        if (e == 0)
            err = MP_EXPTMOD_E;
    }
    if (err == MP_OKAY) {
        sp_4096_from_mp(m, 64, mm);

        if (e == 0x10001) {
            int i;
            sp_digit mp;

            sp_4096_mont_setup(m, &mp);

            /* Convert to Montgomery form. */
            XMEMSET(a, 0, sizeof(sp_digit) * 64);
            err = sp_4096_mod_64_cond(r, a, m);
            /* Montgomery form: r = a.R mod m */

            if (err == MP_OKAY) {
                /* r = a ^ 0x10000 => r = a squared 16 times */
#ifdef HAVE_INTEL_AVX2
                if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
                    for (i = 15; i >= 0; i--) {
                        sp_4096_mont_sqr_avx2_64(r, r, m, mp);
                    }
                    /* mont_red(r.R.R) = (r.R.R / R) mod m = r.R mod m
                     * mont_red(r.R * a) = (r.R.a / R) mod m = r.a mod m
                     */
                    sp_4096_mont_mul_avx2_64(r, r, ah, m, mp);
                }
                else
#endif
                {
                    for (i = 15; i >= 0; i--) {
                        sp_4096_mont_sqr_64(r, r, m, mp);
                    }
                    /* mont_red(r.R.R) = (r.R.R / R) mod m = r.R mod m
                     * mont_red(r.R * a) = (r.R.a / R) mod m = r.a mod m
                     */
                    sp_4096_mont_mul_64(r, r, ah, m, mp);
                }

                for (i = 63; i > 0; i--) {
                    if (r[i] != m[i])
                        break;
                }
                if (r[i] >= m[i])
                    sp_4096_sub_in_place_64(r, m);
            }
        }
        else if (e == 0x3) {
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
                if (err == MP_OKAY) {
                    sp_4096_sqr_avx2_64(r, ah);
                    err = sp_4096_mod_64_cond(r, r, m);
                }
                if (err == MP_OKAY) {
                    sp_4096_mul_avx2_64(r, ah, r);
                    err = sp_4096_mod_64_cond(r, r, m);
                }
            }
            else
#endif
            {
                if (err == MP_OKAY) {
                    sp_4096_sqr_64(r, ah);
                    err = sp_4096_mod_64_cond(r, r, m);
                }
                if (err == MP_OKAY) {
                    sp_4096_mul_64(r, ah, r);
                    err = sp_4096_mod_64_cond(r, r, m);
                }
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
                for (i=63; i>=0; i--) {
                    if (e >> i) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 64);
#ifdef HAVE_INTEL_AVX2
                if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
                    for (i--; i>=0; i--) {
                        sp_4096_mont_sqr_avx2_64(r, r, m, mp);
                        if (((e >> i) & 1) == 1) {
                            sp_4096_mont_mul_avx2_64(r, r, a, m, mp);
                        }
                    }
                    XMEMSET(&r[64], 0, sizeof(sp_digit) * 64);
                    sp_4096_mont_reduce_avx2_64(r, m, mp);
                }
                else
#endif
                {
                    for (i--; i>=0; i--) {
                        sp_4096_mont_sqr_64(r, r, m, mp);
                        if (((e >> i) & 1) == 1) {
                            sp_4096_mont_mul_64(r, r, a, m, mp);
                        }
                    }
                    XMEMSET(&r[64], 0, sizeof(sp_digit) * 64);
                    sp_4096_mont_reduce_64(r, m, mp);
                }

                for (i = 63; i > 0; i--) {
                    if (r[i] != m[i])
                        break;
                }
                if (r[i] >= m[i])
                    sp_4096_sub_in_place_64(r, m);
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
#if defined(SP_RSA_PRIVATE_EXP_D) || defined(RSA_LOW_MEM)
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
    const mp_int* pm, const mp_int* qm,const  mp_int* dpm, const mp_int* dqm,
    const mp_int* qim, const mp_int* mm, byte* out, word32* outLen)
{
    sp_digit d[64 * 4];
    sp_digit* a;
    sp_digit* m;
    sp_digit* r;
    int err = MP_OKAY;

    ASSERT_SAVED_VECTOR_REGISTERS();

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
        /* only zeroing private "d" */
        ForceZero(d, sizeof(sp_digit) * 64);
    }

    return err;
}

#else
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_4096_cond_add_32(sp_digit* r, const sp_digit* a, const sp_digit* b, sp_digit m);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
extern sp_digit sp_4096_cond_add_avx2_32(sp_digit* r, const sp_digit* a, const sp_digit* b, sp_digit m);
#ifdef __cplusplus
}
#endif
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
    sp_digit a[32 * 11];
    sp_digit* p;
    sp_digit* q;
    sp_digit* dp;
    sp_digit* dq;
    sp_digit* qi;
    sp_digit* tmpa;
    sp_digit* tmpb;
    sp_digit* r;
    sp_digit c;
    int err = MP_OKAY;
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

    ASSERT_SAVED_VECTOR_REGISTERS();

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
        r = a + 64;

        sp_4096_from_bin(a, 64, in, inLen);
        sp_4096_from_mp(p, 32, pm);
        sp_4096_from_mp(q, 32, qm);
        sp_4096_from_mp(dp, 32, dpm);

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            err = sp_2048_mod_exp_avx2_32(tmpa, a, dp, 2048, p, 1);
        else
#endif
            err = sp_2048_mod_exp_32(tmpa, a, dp, 2048, p, 1);
    }
    if (err == MP_OKAY) {
        sp_4096_from_mp(dq, 32, dqm);
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            err = sp_2048_mod_exp_avx2_32(tmpb, a, dq, 2048, q, 1);
       else
#endif
            err = sp_2048_mod_exp_32(tmpb, a, dq, 2048, q, 1);
    }

    if (err == MP_OKAY) {
        c = sp_2048_sub_in_place_32(tmpa, tmpb);
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
            c += sp_4096_cond_add_avx2_32(tmpa, tmpa, p, c);
            sp_4096_cond_add_avx2_32(tmpa, tmpa, p, c);
        }
        else
#endif
        {
            c += sp_4096_cond_add_32(tmpa, tmpa, p, c);
            sp_4096_cond_add_32(tmpa, tmpa, p, c);
        }

        sp_2048_from_mp(qi, 32, qim);
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
            sp_2048_mul_avx2_32(tmpa, tmpa, qi);
        }
        else
#endif
        {
            sp_2048_mul_32(tmpa, tmpa, qi);
        }
        err = sp_2048_mod_32(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags)) {
            sp_2048_mul_avx2_32(tmpa, q, tmpa);
        }
        else
#endif
        {
            sp_2048_mul_32(tmpa, q, tmpa);
        }
        XMEMSET(&tmpb[32], 0, sizeof(sp_digit) * 32);
        sp_4096_add_64(r, tmpb, tmpa);

        sp_4096_to_bin_64(r, out);
        *outLen = 512;
    }

    {
        ForceZero(a, sizeof(sp_digit) * 32 * 11);
    }

    return err;
}
#endif /* SP_RSA_PRIVATE_EXP_D | RSA_LOW_MEM */
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
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif
    int expBits = mp_count_bits(exp);

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (mp_count_bits(base) > 4096 || expBits > 4096 ||
                                                   mp_count_bits(mod) != 4096) {
        err = MP_READ_E;
    }
    else if (mp_iseven(mod)) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        sp_4096_from_mp(b, 64, base);
        sp_4096_from_mp(e, 64, exp);
        sp_4096_from_mp(m, 64, mod);

#ifdef HAVE_INTEL_AVX2
        if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
            err = sp_4096_mod_exp_avx2_64(r, b, e, expBits, m, 0);
        else
#endif
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
#ifdef __cplusplus
extern "C" {
#endif
extern void sp_4096_lshift_64(sp_digit* r, const sp_digit* a, int n);
#ifdef __cplusplus
}
#endif
#ifdef HAVE_INTEL_AVX2
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
static int sp_4096_mod_exp_2_avx2_64(sp_digit* r, const sp_digit* e, int bits,
        const sp_digit* m)
{
    sp_digit td[65 + 128];
    sp_digit* norm;
    sp_digit* tmp;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit o;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        tmp = &td[128];

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_64(norm, m);

        i = (bits - 1) / 64;
        n = e[i--];
        /* Number of bits available in top word. */
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        /* Minus the number of top bits to use so rest is a multiple of 6. */
        if ((bits % 6) == 0) {
            c -= 6;
        }
        else {
            c -= bits % 6;
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
        while ((i >= 0) || (c >= 6)) {
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

            sp_4096_mont_sqr_avx2_64(r, r, m, mp);
            sp_4096_mont_sqr_avx2_64(r, r, m, mp);
            sp_4096_mont_sqr_avx2_64(r, r, m, mp);
            sp_4096_mont_sqr_avx2_64(r, r, m, mp);
            sp_4096_mont_sqr_avx2_64(r, r, m, mp);
            sp_4096_mont_sqr_avx2_64(r, r, m, mp);

            sp_4096_lshift_64(r, r, y);
            sp_4096_mul_d_avx2_64(tmp, norm, r[64]);
            r[64] = 0;
            o = sp_4096_add_64(r, r, tmp);
            sp_4096_cond_sub_avx2_64(r, r, m, (sp_digit)0 - o);
        }

        XMEMSET(&r[64], 0, sizeof(sp_digit) * 64);
        sp_4096_mont_reduce_avx2_64(r, m, mp);

        mask = 0 - (sp_4096_cmp_64(r, m) >= 0);
        sp_4096_cond_sub_avx2_64(r, r, m, mask);
    }


    return err;
}
#endif /* HAVE_INTEL_AVX2 */

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
    sp_digit td[65 + 128];
    sp_digit* norm;
    sp_digit* tmp;
    sp_digit mp = 1;
    sp_digit n;
    sp_digit o;
    sp_digit mask;
    int i;
    int c;
    byte y;
    int err = MP_OKAY;

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (bits == 0) {
        err = MP_VAL;
    }


    if (err == MP_OKAY) {
        norm = td;
        tmp = &td[128];

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_64(norm, m);

        i = (bits - 1) / 64;
        n = e[i--];
        /* Number of bits available in top word. */
        c = bits & 63;
        if (c == 0) {
            c = 64;
        }
        /* Minus the number of top bits to use so rest is a multiple of 6. */
        if ((bits % 6) == 0) {
            c -= 6;
        }
        else {
            c -= bits % 6;
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
        while ((i >= 0) || (c >= 6)) {
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

        XMEMSET(&r[64], 0, sizeof(sp_digit) * 64);
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
#ifdef HAVE_INTEL_AVX2
    word32 cpuid_flags = cpuid_get_flags();
#endif

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (mp_count_bits(base) > 4096 || expLen > 512 ||
                                                   mp_count_bits(mod) != 4096) {
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
        if (base->used == 1 && base->dp[0] == 2 && m[63] == (sp_digit)-1) {
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
                err = sp_4096_mod_exp_2_avx2_64(r, e, expLen * 8, m);
            else
#endif
                err = sp_4096_mod_exp_2_64(r, e, expLen * 8, m);
        }
        else
    #endif
        {
#ifdef HAVE_INTEL_AVX2
            if (IS_INTEL_BMI2(cpuid_flags) && IS_INTEL_ADX(cpuid_flags))
                err = sp_4096_mod_exp_avx2_64(r, b, e, expLen * 8, m, 0);
            else
#endif
                err = sp_4096_mod_exp_64(r, b, e, expLen * 8, m, 0);
        }
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
#endif
#endif /* WOLFSSL_HAVE_SP_DH | (WOLFSSL_HAVE_SP_RSA & !WOLFSSL_RSA_PUBLIC_ONLY) */

#endif /* WOLFSSL_SP_4096 */

#endif /* WOLFSSL_HAVE_SP_RSA | WOLFSSL_HAVE_SP_DH */
#endif /* WOLFSSL_SP_X86_64_ASM */
#endif /* WOLFSSL_HAVE_SP_RSA | WOLFSSL_HAVE_SP_DH | WOLFSSL_HAVE_SP_ECC */
