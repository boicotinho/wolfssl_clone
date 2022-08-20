/* conf.h
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

/* conf.h for openSSL */

#ifndef WOLFSSL_conf_H_
#define WOLFSSL_conf_H_

#ifdef __cplusplus
    extern "C" {
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/version.h>

typedef struct WOLFSSL_CONF_VALUE {
    char *section;
    char *name;
    char *value;
} WOLFSSL_CONF_VALUE;

/* ssl.h requires WOLFSSL_CONF_VALUE */
#include <wolfssl/ssl.h>

typedef struct WOLFSSL_CONF {
    void *meth_data;
    WOLF_LHASH_OF(WOLFSSL_CONF_VALUE) *data;
} WOLFSSL_CONF;

typedef WOLFSSL_CONF CONF;
typedef WOLFSSL_CONF_VALUE CONF_VALUE;


#ifdef  __cplusplus
} /* extern "C" */
#endif

#endif /* WOLFSSL_conf_H_ */
