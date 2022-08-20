/* memory.h
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


/* submitted by eof */

/*!
    \file wolfssl/wolfcrypt/memory.h
*/

#ifndef WOLFSSL_MEMORY_H
#define WOLFSSL_MEMORY_H

#if !defined(STRING_USER)
#include <stdlib.h>
#endif

#ifndef WOLF_CRYPT_TYPES_H
#include <wolfssl/wolfcrypt/types.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif

#ifdef WOLFSSL_FORCE_MALLOC_FAIL_TEST
    WOLFSSL_API void wolfSSL_SetMemFailCount(int memFailCount);
#endif


    #ifdef WOLFSSL_DEBUG_MEMORY
        typedef void *(*wolfSSL_Malloc_cb)(size_t size, const char* func, unsigned int line);
        typedef void (*wolfSSL_Free_cb)(void *ptr, const char* func, unsigned int line);
        typedef void *(*wolfSSL_Realloc_cb)(void *ptr, size_t size, const char* func, unsigned int line);

        /* Public in case user app wants to use XMALLOC/XFREE */
        WOLFSSL_API void* wolfSSL_Malloc(size_t size, const char* func, unsigned int line);
        WOLFSSL_API void  wolfSSL_Free(void *ptr, const char* func, unsigned int line);
        WOLFSSL_API void* wolfSSL_Realloc(void *ptr, size_t size, const char* func, unsigned int line);
    #else
        typedef void *(*wolfSSL_Malloc_cb)(size_t size);
        typedef void (*wolfSSL_Free_cb)(void *ptr);
        typedef void *(*wolfSSL_Realloc_cb)(void *ptr, size_t size);
        /* Public in case user app wants to use XMALLOC/XFREE */
        WOLFSSL_API void* wolfSSL_Malloc(size_t size);
        WOLFSSL_API void  wolfSSL_Free(void *ptr);
        WOLFSSL_API void* wolfSSL_Realloc(void *ptr, size_t size);
    #endif /* WOLFSSL_DEBUG_MEMORY */

/* Public get/set functions */
WOLFSSL_API int wolfSSL_SetAllocators(wolfSSL_Malloc_cb mf,
                                      wolfSSL_Free_cb ff,
                                      wolfSSL_Realloc_cb rf);
WOLFSSL_API int wolfSSL_GetAllocators(wolfSSL_Malloc_cb* mf,
                                      wolfSSL_Free_cb* ff,
                                      wolfSSL_Realloc_cb* rf);


#ifdef WOLFSSL_STACK_LOG
    WOLFSSL_API void __attribute__((no_instrument_function))
            __cyg_profile_func_enter(void *func,  void *caller);
    WOLFSSL_API void __attribute__((no_instrument_function))
            __cyg_profile_func_exit(void *func, void *caller);
#endif /* WOLFSSL_STACK_LOG */

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_MEMORY_H */

