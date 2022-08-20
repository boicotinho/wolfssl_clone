/* bn.h
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

/* bn.h for openssl */

/*!
    \file wolfssl/openssl/bn.h
    \brief bn.h for openssl
*/


#ifndef WOLFSSL_BN_H_
#define WOLFSSL_BN_H_

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/integer.h>

#ifdef __cplusplus
    extern "C" {
#endif

typedef struct WOLFSSL_BIGNUM {
    int neg;        /* openssh deference */
    void *internal; /* our big num */
#if defined(WOLFSSL_SP_MATH_ALL)
    sp_int fp;
#elif !defined(HAVE_WOLF_BIGINT)
    fp_int fp;
#endif
} WOLFSSL_BIGNUM;

#define WOLFSSL_BN_ULONG unsigned long

typedef struct WOLFSSL_BN_CTX   WOLFSSL_BN_CTX;
typedef struct WOLFSSL_BN_GENCB WOLFSSL_BN_GENCB;

WOLFSSL_API WOLFSSL_BN_CTX* wolfSSL_BN_CTX_new(void);
WOLFSSL_API void           wolfSSL_BN_CTX_init(WOLFSSL_BN_CTX* ctx);
WOLFSSL_API void           wolfSSL_BN_CTX_free(WOLFSSL_BN_CTX* ctx);

WOLFSSL_API WOLFSSL_BIGNUM* wolfSSL_BN_new(void);
#if !defined(HAVE_WOLF_BIGINT)
WOLFSSL_API void           wolfSSL_BN_init(WOLFSSL_BIGNUM* bn);
#endif
WOLFSSL_API void           wolfSSL_BN_free(WOLFSSL_BIGNUM* bn);
WOLFSSL_API void           wolfSSL_BN_clear_free(WOLFSSL_BIGNUM* bn);
WOLFSSL_API void           wolfSSL_BN_clear(WOLFSSL_BIGNUM* bn);


WOLFSSL_API int wolfSSL_BN_sub(WOLFSSL_BIGNUM* r, const WOLFSSL_BIGNUM* a,
                             const WOLFSSL_BIGNUM* b);
WOLFSSL_API int wolfSSL_BN_mul(WOLFSSL_BIGNUM *r, WOLFSSL_BIGNUM *a,
                               WOLFSSL_BIGNUM *b, WOLFSSL_BN_CTX *ctx);
WOLFSSL_API int wolfSSL_BN_div(WOLFSSL_BIGNUM* dv, WOLFSSL_BIGNUM* rem,
                   const WOLFSSL_BIGNUM* a, const WOLFSSL_BIGNUM* d,
                   WOLFSSL_BN_CTX* ctx);
#if defined(WOLFSSL_KEY_GEN)
WOLFSSL_API int wolfSSL_BN_gcd(WOLFSSL_BIGNUM* r, WOLFSSL_BIGNUM* a,
                               WOLFSSL_BIGNUM* b, WOLFSSL_BN_CTX* ctx);
#endif
WOLFSSL_API int wolfSSL_BN_mod(WOLFSSL_BIGNUM* r, const WOLFSSL_BIGNUM* a,
                  const WOLFSSL_BIGNUM* b, const WOLFSSL_BN_CTX* c);
WOLFSSL_API int wolfSSL_BN_mod_exp(WOLFSSL_BIGNUM *r, const WOLFSSL_BIGNUM *a,
      const WOLFSSL_BIGNUM *p, const WOLFSSL_BIGNUM *m, WOLFSSL_BN_CTX *ctx);
WOLFSSL_API int wolfSSL_BN_mod_mul(WOLFSSL_BIGNUM *r, const WOLFSSL_BIGNUM *a,
        const WOLFSSL_BIGNUM *p, const WOLFSSL_BIGNUM *m, WOLFSSL_BN_CTX *ctx);
WOLFSSL_API const WOLFSSL_BIGNUM* wolfSSL_BN_value_one(void);


WOLFSSL_API int wolfSSL_BN_num_bytes(const WOLFSSL_BIGNUM* bn);
WOLFSSL_API int wolfSSL_BN_num_bits(const WOLFSSL_BIGNUM* bn);

WOLFSSL_API void wolfSSL_BN_zero(WOLFSSL_BIGNUM* bn);
WOLFSSL_API int wolfSSL_BN_one(WOLFSSL_BIGNUM* bn);
WOLFSSL_API int wolfSSL_BN_is_zero(const WOLFSSL_BIGNUM* bn);
WOLFSSL_API int wolfSSL_BN_is_one(const WOLFSSL_BIGNUM* bn);
WOLFSSL_API int wolfSSL_BN_is_odd(const WOLFSSL_BIGNUM* bn);
WOLFSSL_API int wolfSSL_BN_is_negative(const WOLFSSL_BIGNUM* bn);
WOLFSSL_API int wolfSSL_BN_is_word(const WOLFSSL_BIGNUM* bn, WOLFSSL_BN_ULONG w);

WOLFSSL_API int wolfSSL_BN_cmp(const WOLFSSL_BIGNUM* a, const WOLFSSL_BIGNUM* b);

WOLFSSL_API int wolfSSL_BN_bn2bin(const WOLFSSL_BIGNUM* bn, unsigned char* r);
WOLFSSL_API WOLFSSL_BIGNUM* wolfSSL_BN_bin2bn(const unsigned char* str, int len,
                                              WOLFSSL_BIGNUM* ret);

WOLFSSL_API int wolfSSL_mask_bits(WOLFSSL_BIGNUM* bn, int n);

WOLFSSL_API int wolfSSL_BN_pseudo_rand(WOLFSSL_BIGNUM* bn, int bits, int top,
                                       int bottom);
WOLFSSL_API int wolfSSL_BN_rand_range(WOLFSSL_BIGNUM *r, const WOLFSSL_BIGNUM *range);
WOLFSSL_API int wolfSSL_BN_rand(WOLFSSL_BIGNUM* bn, int bits, int top, int bottom);
WOLFSSL_API int wolfSSL_BN_is_bit_set(const WOLFSSL_BIGNUM* bn, int n);
WOLFSSL_API int wolfSSL_BN_hex2bn(WOLFSSL_BIGNUM** bn, const char* str);

WOLFSSL_API WOLFSSL_BIGNUM* wolfSSL_BN_dup(const WOLFSSL_BIGNUM* bn);
WOLFSSL_API WOLFSSL_BIGNUM* wolfSSL_BN_copy(WOLFSSL_BIGNUM* r,
                                            const WOLFSSL_BIGNUM* bn);

WOLFSSL_API int   wolfSSL_BN_dec2bn(WOLFSSL_BIGNUM** bn, const char* str);
WOLFSSL_API char* wolfSSL_BN_bn2dec(const WOLFSSL_BIGNUM* bn);

WOLFSSL_API int wolfSSL_BN_lshift(WOLFSSL_BIGNUM* r, const WOLFSSL_BIGNUM* bn,
                                  int n);
WOLFSSL_API int wolfSSL_BN_add_word(WOLFSSL_BIGNUM* bn, WOLFSSL_BN_ULONG w);
WOLFSSL_API int wolfSSL_BN_sub_word(WOLFSSL_BIGNUM* bn, WOLFSSL_BN_ULONG w);
WOLFSSL_API int wolfSSL_BN_set_bit(WOLFSSL_BIGNUM* bn, int n);
WOLFSSL_API int wolfSSL_BN_clear_bit(WOLFSSL_BIGNUM* bn, int n);
WOLFSSL_API int wolfSSL_BN_set_word(WOLFSSL_BIGNUM* bn, WOLFSSL_BN_ULONG w);
WOLFSSL_API WOLFSSL_BN_ULONG wolfSSL_BN_get_word(const WOLFSSL_BIGNUM* bn);

WOLFSSL_API int wolfSSL_BN_add(WOLFSSL_BIGNUM* r, WOLFSSL_BIGNUM* a,
                               WOLFSSL_BIGNUM* b);
WOLFSSL_API int wolfSSL_BN_mod_add(WOLFSSL_BIGNUM *r, const WOLFSSL_BIGNUM *a,
                                   const WOLFSSL_BIGNUM *b, const WOLFSSL_BIGNUM *m,
                                   WOLFSSL_BN_CTX *ctx);
WOLFSSL_API char *wolfSSL_BN_bn2hex(const WOLFSSL_BIGNUM* bn);
#if defined(WOLFSSL_KEY_GEN)
WOLFSSL_API int wolfSSL_BN_generate_prime_ex(
    WOLFSSL_BIGNUM* prime, int bits, int safe, const WOLFSSL_BIGNUM* add,
    const WOLFSSL_BIGNUM* rem, WOLFSSL_BN_GENCB* cb);
WOLFSSL_API int wolfSSL_BN_is_prime_ex(const WOLFSSL_BIGNUM *bn, int nbchecks,
                           WOLFSSL_BN_CTX *ctx, WOLFSSL_BN_GENCB *cb);
WOLFSSL_API WOLFSSL_BN_ULONG wolfSSL_BN_mod_word(const WOLFSSL_BIGNUM *bn,
                                                 WOLFSSL_BN_ULONG w);
#endif
#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
    WOLFSSL_API int wolfSSL_BN_print_fp(XFILE fp, const WOLFSSL_BIGNUM *bn);
#endif
WOLFSSL_API int wolfSSL_BN_rshift(WOLFSSL_BIGNUM *r, const WOLFSSL_BIGNUM *bn,
                                  int n);
WOLFSSL_API WOLFSSL_BIGNUM *wolfSSL_BN_CTX_get(WOLFSSL_BN_CTX *ctx);
WOLFSSL_API void wolfSSL_BN_CTX_start(WOLFSSL_BN_CTX *ctx);
WOLFSSL_API WOLFSSL_BIGNUM *wolfSSL_BN_mod_inverse(
    WOLFSSL_BIGNUM *r,
    WOLFSSL_BIGNUM *a,
    const WOLFSSL_BIGNUM *n,
    WOLFSSL_BN_CTX *ctx);




#ifdef __cplusplus
    }  /* extern "C" */
#endif


#endif /* WOLFSSL__H_ */
