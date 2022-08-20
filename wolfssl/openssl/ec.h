/* ec.h
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

/* ec.h for openssl */

#ifndef WOLFSSL_EC_H_
#define WOLFSSL_EC_H_

#include <wolfssl/openssl/bn.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ecc.h>

#ifdef __cplusplus
extern "C" {
#endif


#ifndef WOLFSSL_EC_TYPE_DEFINED /* guard on redeclaration */
    typedef struct WOLFSSL_EC_KEY           WOLFSSL_EC_KEY;
    typedef struct WOLFSSL_EC_POINT         WOLFSSL_EC_POINT;
    typedef struct WOLFSSL_EC_GROUP         WOLFSSL_EC_GROUP;
    typedef struct WOLFSSL_EC_BUILTIN_CURVE WOLFSSL_EC_BUILTIN_CURVE;
    /* WOLFSSL_EC_METHOD is just an alias of WOLFSSL_EC_GROUP for now */
    typedef struct WOLFSSL_EC_GROUP         WOLFSSL_EC_METHOD;

    #define WOLFSSL_EC_TYPE_DEFINED
#endif

struct WOLFSSL_EC_POINT {
    WOLFSSL_BIGNUM *X;
    WOLFSSL_BIGNUM *Y;
    WOLFSSL_BIGNUM *Z;

    void*          internal;     /* our ECC point */
    char           inSet;        /* internal set from external ? */
    char           exSet;        /* external set from internal ? */
};

struct WOLFSSL_EC_GROUP {
    int curve_idx; /* index of curve, used by WolfSSL as reference */
    int curve_nid; /* NID of curve, used by OpenSSL/OpenSSH as reference */
    int curve_oid; /* OID of curve, used by OpenSSL/OpenSSH as reference */
};

struct WOLFSSL_EC_KEY {
    WOLFSSL_EC_GROUP *group;
    WOLFSSL_EC_POINT *pub_key;
    WOLFSSL_BIGNUM *priv_key;

    void*          internal;     /* our ECC Key */
    void*          heap;
    char           form;         /* Either POINT_CONVERSION_UNCOMPRESSED or
                                  * POINT_CONVERSION_COMPRESSED */
    word16 pkcs8HeaderSz;

    /* option bits */
    byte inSet:1;        /* internal set from external ? */
    byte exSet:1;        /* external set from internal ? */

    wolfSSL_Mutex    refMutex;                       /* ref count mutex */
    int              refCount;                       /* reference count */
};

struct WOLFSSL_EC_BUILTIN_CURVE {
    int nid;
    const char *comment;
};

#define WOLFSSL_EC_KEY_LOAD_PRIVATE 1
#define WOLFSSL_EC_KEY_LOAD_PUBLIC  2

typedef int point_conversion_form_t;

WOLFSSL_API
size_t wolfSSL_EC_get_builtin_curves(WOLFSSL_EC_BUILTIN_CURVE *r,size_t nitems);

WOLFSSL_API
WOLFSSL_EC_KEY *wolfSSL_EC_KEY_dup(const WOLFSSL_EC_KEY *src);
WOLFSSL_API
int wolfSSL_EC_KEY_up_ref(WOLFSSL_EC_KEY* key);

WOLFSSL_API
int wolfSSL_ECPoint_i2d(const WOLFSSL_EC_GROUP *curve,
                        const WOLFSSL_EC_POINT *p,
                        unsigned char *out, unsigned int *len);
WOLFSSL_API
int wolfSSL_ECPoint_d2i(unsigned char *in, unsigned int len,
                        const WOLFSSL_EC_GROUP *curve, WOLFSSL_EC_POINT *p);
WOLFSSL_API
size_t wolfSSL_EC_POINT_point2oct(const WOLFSSL_EC_GROUP *group,
                                  const WOLFSSL_EC_POINT *p,
                                  char form,
                                  byte *buf, size_t len, WOLFSSL_BN_CTX *ctx);
WOLFSSL_API
int wolfSSL_EC_POINT_oct2point(const WOLFSSL_EC_GROUP *group,
                               WOLFSSL_EC_POINT *p, const unsigned char *buf,
                               size_t len, WOLFSSL_BN_CTX *ctx);
WOLFSSL_API
WOLFSSL_EC_KEY *wolfSSL_o2i_ECPublicKey(WOLFSSL_EC_KEY **a, const unsigned char **in,
                                        long len);
WOLFSSL_API
int wolfSSL_i2o_ECPublicKey(const WOLFSSL_EC_KEY *in, unsigned char **out);
WOLFSSL_API
WOLFSSL_EC_KEY *wolfSSL_d2i_ECPrivateKey(WOLFSSL_EC_KEY **key, const unsigned char **in,
                                         long len);
WOLFSSL_API
int wolfSSL_i2d_ECPrivateKey(const WOLFSSL_EC_KEY *in, unsigned char **out);
WOLFSSL_API
void wolfSSL_EC_KEY_set_conv_form(WOLFSSL_EC_KEY *eckey, char form);
WOLFSSL_API
point_conversion_form_t wolfSSL_EC_KEY_get_conv_form(const WOLFSSL_EC_KEY* key);
WOLFSSL_API
WOLFSSL_BIGNUM *wolfSSL_EC_POINT_point2bn(const WOLFSSL_EC_GROUP *group,
                                          const WOLFSSL_EC_POINT *p,
                                          char form,
                                          WOLFSSL_BIGNUM *in, WOLFSSL_BN_CTX *ctx);
WOLFSSL_API
int wolfSSL_EC_POINT_is_on_curve(const WOLFSSL_EC_GROUP *group,
                                 const WOLFSSL_EC_POINT *point,
                                 WOLFSSL_BN_CTX *ctx);

WOLFSSL_API
int wolfSSL_EC_KEY_LoadDer(WOLFSSL_EC_KEY* key,
                           const unsigned char* der, int derSz);
WOLFSSL_API
int wolfSSL_EC_KEY_LoadDer_ex(WOLFSSL_EC_KEY* key,
                              const unsigned char* der, int derSz, int opt);
WOLFSSL_API
void wolfSSL_EC_KEY_free(WOLFSSL_EC_KEY *key);
WOLFSSL_API
WOLFSSL_EC_POINT *wolfSSL_EC_KEY_get0_public_key(const WOLFSSL_EC_KEY *key);
WOLFSSL_API
const WOLFSSL_EC_GROUP *wolfSSL_EC_KEY_get0_group(const WOLFSSL_EC_KEY *key);
WOLFSSL_API
int wolfSSL_EC_KEY_set_private_key(WOLFSSL_EC_KEY *key,
                                   const WOLFSSL_BIGNUM *priv_key);
WOLFSSL_API
WOLFSSL_BIGNUM *wolfSSL_EC_KEY_get0_private_key(const WOLFSSL_EC_KEY *key);
WOLFSSL_API
WOLFSSL_EC_KEY *wolfSSL_EC_KEY_new_by_curve_name(int nid);
WOLFSSL_API const char* wolfSSL_EC_curve_nid2nist(int nid);
WOLFSSL_API int wolfSSL_EC_curve_nist2nid(const char* name);
WOLFSSL_API
WOLFSSL_EC_KEY *wolfSSL_EC_KEY_new_ex(void* heap, int devId);
WOLFSSL_API
WOLFSSL_EC_KEY *wolfSSL_EC_KEY_new(void);
WOLFSSL_API
int wolfSSL_EC_KEY_set_group(WOLFSSL_EC_KEY *key, WOLFSSL_EC_GROUP *group);
WOLFSSL_API
int wolfSSL_EC_KEY_generate_key(WOLFSSL_EC_KEY *key);
WOLFSSL_API
void wolfSSL_EC_KEY_set_asn1_flag(WOLFSSL_EC_KEY *key, int asn1_flag);
WOLFSSL_API
int wolfSSL_EC_KEY_set_public_key(WOLFSSL_EC_KEY *key,
                                  const WOLFSSL_EC_POINT *pub);
WOLFSSL_API int wolfSSL_EC_KEY_check_key(const WOLFSSL_EC_KEY *key);
#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
WOLFSSL_API int wolfSSL_EC_KEY_print_fp(XFILE fp, WOLFSSL_EC_KEY* key,
                                         int indent);
#endif /* !NO_FILESYSTEM && !NO_STDIO_FILESYSTEM */
WOLFSSL_API int wolfSSL_ECDSA_size(const WOLFSSL_EC_KEY *key);
WOLFSSL_API int wolfSSL_ECDSA_sign(int type, const unsigned char *digest,
                                   int digestSz, unsigned char *sig,
                                   unsigned int *sigSz, WOLFSSL_EC_KEY *key);
WOLFSSL_API int wolfSSL_ECDSA_verify(int type, const unsigned char *digest,
                                   int digestSz, const unsigned char *sig,
                                   int sigSz, WOLFSSL_EC_KEY *key);

WOLFSSL_API
void wolfSSL_EC_GROUP_set_asn1_flag(WOLFSSL_EC_GROUP *group, int flag);
WOLFSSL_API
WOLFSSL_EC_GROUP *wolfSSL_EC_GROUP_new_by_curve_name(int nid);
WOLFSSL_API
int wolfSSL_EC_GROUP_cmp(const WOLFSSL_EC_GROUP *a, const WOLFSSL_EC_GROUP *b,
                         WOLFSSL_BN_CTX *ctx);
WOLFSSL_API
WOLFSSL_EC_GROUP *wolfSSL_EC_GROUP_dup(const WOLFSSL_EC_GROUP *src);
WOLFSSL_API
int wolfSSL_EC_GROUP_get_curve_name(const WOLFSSL_EC_GROUP *group);
WOLFSSL_API
int wolfSSL_EC_GROUP_get_degree(const WOLFSSL_EC_GROUP *group);
WOLFSSL_API
int wolfSSL_EC_GROUP_get_order(const WOLFSSL_EC_GROUP *group,
                               WOLFSSL_BIGNUM *order, WOLFSSL_BN_CTX *ctx);
WOLFSSL_API
int wolfSSL_EC_GROUP_order_bits(const WOLFSSL_EC_GROUP *group);
WOLFSSL_API
void wolfSSL_EC_GROUP_free(WOLFSSL_EC_GROUP *group);
WOLFSSL_API
const WOLFSSL_EC_METHOD* wolfSSL_EC_GROUP_method_of(
                                                const WOLFSSL_EC_GROUP *group);
WOLFSSL_API
int wolfSSL_EC_METHOD_get_field_type(const WOLFSSL_EC_METHOD *meth);
WOLFSSL_API
WOLFSSL_EC_POINT *wolfSSL_EC_POINT_new(const WOLFSSL_EC_GROUP *group);
WOLFSSL_API
int wolfSSL_EC_POINT_get_affine_coordinates_GFp(const WOLFSSL_EC_GROUP *group,
                                                const WOLFSSL_EC_POINT *p,
                                                WOLFSSL_BIGNUM *x,
                                                WOLFSSL_BIGNUM *y,
                                                WOLFSSL_BN_CTX *ctx);
WOLFSSL_API
int wolfSSL_EC_POINT_set_affine_coordinates_GFp(const WOLFSSL_EC_GROUP *group,
                                                WOLFSSL_EC_POINT *point,
                                                const WOLFSSL_BIGNUM *x,
                                                const WOLFSSL_BIGNUM *y,
                                                WOLFSSL_BN_CTX *ctx);
WOLFSSL_API
int wolfSSL_EC_POINT_add(const WOLFSSL_EC_GROUP *group, WOLFSSL_EC_POINT *r,
                         const WOLFSSL_EC_POINT *p1,
                         const WOLFSSL_EC_POINT *p2, WOLFSSL_BN_CTX *ctx);
WOLFSSL_API
int wolfSSL_EC_POINT_mul(const WOLFSSL_EC_GROUP *group, WOLFSSL_EC_POINT *r,
                         const WOLFSSL_BIGNUM *n,
                         const WOLFSSL_EC_POINT *q, const WOLFSSL_BIGNUM *m,
                         WOLFSSL_BN_CTX *ctx);
WOLFSSL_API
int wolfSSL_EC_POINT_invert(const WOLFSSL_EC_GROUP *group, WOLFSSL_EC_POINT *a,
                            WOLFSSL_BN_CTX *ctx);
WOLFSSL_API
void wolfSSL_EC_POINT_clear_free(WOLFSSL_EC_POINT *point);
WOLFSSL_API
int wolfSSL_EC_POINT_cmp(const WOLFSSL_EC_GROUP *group,
                         const WOLFSSL_EC_POINT *a, const WOLFSSL_EC_POINT *b,
                         WOLFSSL_BN_CTX *ctx);
WOLFSSL_API int wolfSSL_EC_POINT_copy(WOLFSSL_EC_POINT *dest,
                                      const WOLFSSL_EC_POINT *src);
WOLFSSL_API
void wolfSSL_EC_POINT_free(WOLFSSL_EC_POINT *point);
WOLFSSL_API
int wolfSSL_EC_POINT_is_at_infinity(const WOLFSSL_EC_GROUP *group,
                                    const WOLFSSL_EC_POINT *a);

WOLFSSL_API
char* wolfSSL_EC_POINT_point2hex(const WOLFSSL_EC_GROUP* group,
                                 const WOLFSSL_EC_POINT* point, int form,
                                 WOLFSSL_BN_CTX* ctx);


#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* header */
