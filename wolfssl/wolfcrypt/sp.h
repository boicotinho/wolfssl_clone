/* sp.h
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


#ifndef WOLF_CRYPT_SP_H
#define WOLF_CRYPT_SP_H

#include <wolfssl/wolfcrypt/types.h>

#if defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH)
#ifdef _WIN32_WCE
    typedef __int8           int8_t;
    typedef __int32          int32_t;
    typedef __int64          int64_t;
    typedef unsigned __int8  uint8_t;
    typedef unsigned __int32 uint32_t;
    typedef unsigned __int64 uint64_t;
#else
    #include <stdint.h>
#endif

#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/sp_int.h>

#include <wolfssl/wolfcrypt/ecc.h>

#ifdef noinline
    #define SP_NOINLINE noinline
#elif defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
    #define SP_NOINLINE _Pragma("inline = never")
#elif defined(__GNUC__) || defined(__KEIL__) || defined(__DCC__)
    #define SP_NOINLINE __attribute__((noinline))
#else
    #define SP_NOINLINE
#endif


#ifdef __cplusplus
    extern "C" {
#endif

#ifdef WOLFSSL_HAVE_SP_RSA

/* non-const versions only needed for inlined ARM assembly */

WOLFSSL_LOCAL int sp_RsaPublic_2048(const byte* in, word32 inLen,
    const mp_int* em, const mp_int* mm, byte* out, word32* outLen);
WOLFSSL_LOCAL int sp_RsaPrivate_2048(const byte* in, word32 inLen,
    const mp_int* dm, const mp_int* pm, const mp_int* qm, const mp_int* dpm,
    const mp_int* dqm, const mp_int* qim, const mp_int* mm, byte* out,
    word32* outLen);

WOLFSSL_LOCAL int sp_RsaPublic_3072(const byte* in, word32 inLen,
    const mp_int* em, const mp_int* mm, byte* out, word32* outLen);
WOLFSSL_LOCAL int sp_RsaPrivate_3072(const byte* in, word32 inLen,
    const mp_int* dm, const mp_int* pm, const mp_int* qm, const mp_int* dpm,
    const mp_int* dqm, const mp_int* qim, const mp_int* mm, byte* out,
    word32* outLen);

WOLFSSL_LOCAL int sp_RsaPublic_4096(const byte* in, word32 inLen,
    const mp_int* em, const mp_int* mm, byte* out, word32* outLen);
WOLFSSL_LOCAL int sp_RsaPrivate_4096(const byte* in, word32 inLen,
    const mp_int* dm, const mp_int* pm, const mp_int* qm, const mp_int* dpm,
    const mp_int* dqm, const mp_int* qim, const mp_int* mm, byte* out,
    word32* outLen);


#endif /* WOLFSSL_HAVE_SP_RSA */

#if defined(WOLFSSL_HAVE_SP_DH) || defined(WOLFSSL_HAVE_SP_RSA)

/* non-const versions only needed for inlined ARM assembly */

WOLFSSL_LOCAL int sp_ModExp_1024(const mp_int* base, const mp_int* exp,
    const mp_int* mod, mp_int* res);
WOLFSSL_LOCAL int sp_ModExp_1536(const mp_int* base, const mp_int* exp,
    const mp_int* mod, mp_int* res);
WOLFSSL_LOCAL int sp_ModExp_2048(const mp_int* base, const mp_int* exp,
    const mp_int* mod, mp_int* res);
WOLFSSL_LOCAL int sp_ModExp_3072(const mp_int* base, const mp_int* exp,
    const mp_int* mod, mp_int* res);
WOLFSSL_LOCAL int sp_ModExp_4096(const mp_int* base, const mp_int* exp,
    const mp_int* mod, mp_int* res);


#endif

#ifdef WOLFSSL_HAVE_SP_DH

/* non-const versions only needed for inlined ARM assembly */

WOLFSSL_LOCAL int sp_DhExp_2048(const mp_int* base, const byte* exp,
    word32 expLen, const mp_int* mod, byte* out, word32* outLen);
WOLFSSL_LOCAL int sp_DhExp_3072(const mp_int* base, const byte* exp,
    word32 expLen, const mp_int* mod, byte* out, word32* outLen);
WOLFSSL_LOCAL int sp_DhExp_4096(const mp_int* base, const byte* exp,
    word32 expLen, const mp_int* mod, byte* out, word32* outLen);


#endif /* WOLFSSL_HAVE_SP_DH */



#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH || WOLFSSL_HAVE_SP_ECC */

#endif /* WOLF_CRYPT_SP_H */

