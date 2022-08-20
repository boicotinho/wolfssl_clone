/* sniffer.c
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>


/* xctime */
#ifndef XCTIME
   #define XCTIME ctime
#endif

/* only in this file, to avoid confusing future ports leave
 * these defines here. Do not move to wc_port.h */
#ifdef USER_CUSTOM_SNIFFX
    /* To be implemented in user_settings.h */
#else
    /* default */
    #define XINET_NTOA inet_ntoa
    #define XINET_ATON inet_aton
    #define XINET_PTON(a,b,c) inet_pton((a),(b),(c))
    #define XINET_NTOP inet_ntop
    #define XINET_ADDR inet_addr
    #define XHTONS htons
    #define XNTOHS ntohs
    #define XHTONL htonl
    #define XNTOHL ntohl
    #define XINADDR_NONE INADDR_NONE
#endif

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_FILESYSTEM)
#endif /* !WOLFCRYPT_ONLY && !NO_FILESYSTEM */
