/* memory.c
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

/* check old macros @wc_fips */
#if defined(USE_CYASSL_MEMORY) && !defined(USE_WOLFSSL_MEMORY)
    #define USE_WOLFSSL_MEMORY
#endif
#if defined(CYASSL_MALLOC_CHECK) && !defined(WOLFSSL_MALLOC_CHECK)
    #define WOLFSSL_MALLOC_CHECK
#endif


/*
Possible memory options:
 * NO_WOLFSSL_MEMORY:               Disables wolf memory callback support. When not defined settings.h defines USE_WOLFSSL_MEMORY.
 * WOLFSSL_STATIC_MEMORY:           Turns on the use of static memory buffers and functions.
                                        This allows for using static memory instead of dynamic.
 * WOLFSSL_STATIC_ALIGN:            Define defaults to 16 to indicate static memory alignment.
 * HAVE_IO_POOL:                    Enables use of static thread safe memory pool for input/output buffers.
 * XMALLOC_OVERRIDE:                Allows override of the XMALLOC, XFREE and XREALLOC macros.
 * XMALLOC_USER:                    Allows custom XMALLOC, XFREE and XREALLOC functions to be defined.
 * WOLFSSL_NO_MALLOC:               Disables the fall-back case to use STDIO malloc/free when no callbacks are set.
 * WOLFSSL_TRACK_MEMORY:            Enables memory tracking for total stats and list of allocated memory.
 * WOLFSSL_DEBUG_MEMORY:            Enables extra function and line number args for memory callbacks.
 * WOLFSSL_DEBUG_MEMORY_PRINT:      Enables printing of each malloc/free.
 * WOLFSSL_MALLOC_CHECK:            Reports malloc or alignment failure using WOLFSSL_STATIC_ALIGN
 * WOLFSSL_FORCE_MALLOC_FAIL_TEST:  Used for internal testing to induce random malloc failures.
 * WOLFSSL_HEAP_TEST:               Used for internal testing of heap hint
 */

#ifdef WOLFSSL_ZEPHYR
#undef realloc
void *z_realloc(void *ptr, size_t size)
{
    if (ptr == NULL)
        ptr = malloc(size);
    else
        ptr = realloc(ptr, size);

    return ptr;
}
#define realloc z_realloc
#endif

#ifdef USE_WOLFSSL_MEMORY

#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#if defined(WOLFSSL_DEBUG_MEMORY) && defined(WOLFSSL_DEBUG_MEMORY_PRINT)
#include <stdio.h>
#endif

#ifdef WOLFSSL_FORCE_MALLOC_FAIL_TEST
    static int gMemFailCountSeed;
    static int gMemFailCount;
    void wolfSSL_SetMemFailCount(int memFailCount)
    {
        if (gMemFailCountSeed == 0) {
            gMemFailCountSeed = memFailCount;
            gMemFailCount = memFailCount;
        }
    }
#endif
#if defined(WOLFSSL_MALLOC_CHECK) || defined(WOLFSSL_TRACK_MEMORY_FULL) || \
                                                     defined(WOLFSSL_MEMORY_LOG)
    #include <stdio.h>
#endif


/* Set these to default values initially. */
static wolfSSL_Malloc_cb  malloc_function = NULL;
static wolfSSL_Free_cb    free_function = NULL;
static wolfSSL_Realloc_cb realloc_function = NULL;

int wolfSSL_SetAllocators(wolfSSL_Malloc_cb  mf,
                          wolfSSL_Free_cb    ff,
                          wolfSSL_Realloc_cb rf)
{
    malloc_function = mf;
    free_function = ff;
    realloc_function = rf;
    return 0;
}

int wolfSSL_GetAllocators(wolfSSL_Malloc_cb*  mf,
                          wolfSSL_Free_cb*    ff,
                          wolfSSL_Realloc_cb* rf)
{
    if (mf) *mf = malloc_function;
    if (ff) *ff = free_function;
    if (rf) *rf = realloc_function;
    return 0;
}

#ifdef WOLFSSL_DEBUG_MEMORY
void* wolfSSL_Malloc(size_t size, const char* func, unsigned int line)
#else
void* wolfSSL_Malloc(size_t size)
#endif
{
    void* res = 0;

    if (malloc_function) {
    #ifdef WOLFSSL_DEBUG_MEMORY
        res = malloc_function(size, func, line);
    #else
        res = malloc_function(size);
    #endif
    }
    else {
        #ifdef WOLFSSL_TRAP_MALLOC_SZ
        if (size > WOLFSSL_TRAP_MALLOC_SZ) {
            WOLFSSL_MSG("Malloc too big!");
            return NULL;
        }
        #endif

        res = malloc(size);
    }

#ifdef WOLFSSL_DEBUG_MEMORY
#if defined(WOLFSSL_DEBUG_MEMORY_PRINT) && !defined(WOLFSSL_TRACK_MEMORY)
    fprintf(stderr, "Alloc: %p -> %u at %s:%u\n", res, (word32)size, func, line);
#else
    (void)func;
    (void)line;
#endif
#endif

#ifdef WOLFSSL_MALLOC_CHECK
    if (res == NULL)
        WOLFSSL_MSG("wolfSSL_malloc failed");
#endif

#ifdef WOLFSSL_FORCE_MALLOC_FAIL_TEST
    if (res && --gMemFailCount == 0) {
        fprintf(stderr, "\n---FORCED MEM FAIL TEST---\n");
        if (free_function) {
        #ifdef WOLFSSL_DEBUG_MEMORY
            free_function(res, func, line);
        #else
            free_function(res);
        #endif
        }
        else {
            free(res); /* clear */
        }
        gMemFailCount = gMemFailCountSeed; /* reset */
        return NULL;
    }
#endif

    return res;
}

#ifdef WOLFSSL_DEBUG_MEMORY
void wolfSSL_Free(void *ptr, const char* func, unsigned int line)
#else
void wolfSSL_Free(void *ptr)
#endif
{
#ifdef WOLFSSL_DEBUG_MEMORY
#if defined(WOLFSSL_DEBUG_MEMORY_PRINT) && !defined(WOLFSSL_TRACK_MEMORY)
    fprintf(stderr, "Free: %p at %s:%u\n", ptr, func, line);
#else
    (void)func;
    (void)line;
#endif
#endif

    if (free_function) {
    #ifdef WOLFSSL_DEBUG_MEMORY
        free_function(ptr, func, line);
    #else
        free_function(ptr);
    #endif
    }
    else {
        free(ptr);
    }
}

#ifdef WOLFSSL_DEBUG_MEMORY
void* wolfSSL_Realloc(void *ptr, size_t size, const char* func, unsigned int line)
#else
void* wolfSSL_Realloc(void *ptr, size_t size)
#endif
{
    void* res = 0;

    if (realloc_function) {
    #ifdef WOLFSSL_DEBUG_MEMORY
        res = realloc_function(ptr, size, func, line);
    #else
        res = realloc_function(ptr, size);
    #endif
    }
    else {
        res = realloc(ptr, size);
    }

    return res;
}


#endif /* USE_WOLFSSL_MEMORY */


#ifdef HAVE_IO_POOL

/* Example for user io pool, shared build may need definitions in lib proper */

#include <wolfssl/wolfcrypt/types.h>
#include <stdlib.h>



/* allow simple per thread in and out pools */
/* use 17k size since max record size is 16k plus overhead */
static THREAD_LS_T byte pool_in[17*1024];
static THREAD_LS_T byte pool_out[17*1024];


void* XMALLOC(size_t n, void* heap, int type)
{
    (void)heap;

    if (type == DYNAMIC_TYPE_IN_BUFFER) {
        if (n < sizeof(pool_in))
            return pool_in;
        else
            return NULL;
    }

    if (type == DYNAMIC_TYPE_OUT_BUFFER) {
        if (n < sizeof(pool_out))
            return pool_out;
        else
            return NULL;
    }

    return malloc(n);
}

void* XREALLOC(void *p, size_t n, void* heap, int type)
{
    (void)heap;

    if (type == DYNAMIC_TYPE_IN_BUFFER) {
        if (n < sizeof(pool_in))
            return pool_in;
        else
            return NULL;
    }

    if (type == DYNAMIC_TYPE_OUT_BUFFER) {
        if (n < sizeof(pool_out))
            return pool_out;
        else
            return NULL;
    }

    return realloc(p, n);
}

void XFREE(void *p, void* heap, int type)
{
    (void)heap;

    if (type == DYNAMIC_TYPE_IN_BUFFER)
        return;  /* do nothing, static pool */

    if (type == DYNAMIC_TYPE_OUT_BUFFER)
        return;  /* do nothing, static pool */

    free(p);
}

#endif /* HAVE_IO_POOL */

#ifdef WOLFSSL_MEMORY_LOG
void *xmalloc(size_t n, void* heap, int type, const char* func,
              const char* file, unsigned int line)
{
    void*   p = NULL;
    word32* p32;

    if (malloc_function)
        p32 = malloc_function(n + sizeof(word32) * 4);
    else
        p32 = malloc(n + sizeof(word32) * 4);

    if (p32 != NULL) {
        p32[0] = (word32)n;
        p = (void*)(p32 + 4);

        fprintf(stderr, "Alloc: %p -> %u (%d) at %s:%s:%u\n", p, (word32)n,
                                                        type, func, file, line);
    }

    (void)heap;

    return p;
}
void *xrealloc(void *p, size_t n, void* heap, int type, const char* func,
               const char* file, unsigned int line)
{
    void*   newp = NULL;
    word32* p32;
    word32* oldp32 = NULL;
    word32  oldLen;

    if (p != NULL) {
        oldp32 = (word32*)p;
        oldp32 -= 4;
        oldLen = oldp32[0];
    }

    if (realloc_function)
        p32 = realloc_function(oldp32, n + sizeof(word32) * 4);
    else
        p32 = realloc(oldp32, n + sizeof(word32) * 4);

    if (p32 != NULL) {
        p32[0] = (word32)n;
        newp = (void*)(p32 + 4);

        fprintf(stderr, "Alloc: %p -> %u (%d) at %s:%s:%u\n", newp, (word32)n,
                                                        type, func, file, line);
        if (p != NULL) {
            fprintf(stderr, "Free: %p -> %u (%d) at %s:%s:%u\n", p, oldLen,
                                                        type, func, file, line);
        }
    }

    (void)heap;

    return newp;
}
void xfree(void *p, void* heap, int type, const char* func, const char* file,
           unsigned int line)
{
    word32* p32 = (word32*)p;

    if (p != NULL) {
        p32 -= 4;

        fprintf(stderr, "Free: %p -> %u (%d) at %s:%s:%u\n", p, p32[0], type,
                                                              func, file, line);

        if (free_function)
            free_function(p32);
        else
            free(p32);
    }

    (void)heap;
}
#endif /* WOLFSSL_MEMORY_LOG */

#ifdef WOLFSSL_STACK_LOG
/* Note: this code only works with GCC using -finstrument-functions. */
void __attribute__((no_instrument_function))
     __cyg_profile_func_enter(void *func,  void *caller)
{
    register void* sp asm("sp");
    fprintf(stderr, "ENTER: %016lx %p\n", (unsigned long)(wc_ptr_t)func, sp);
    (void)caller;
}

void __attribute__((no_instrument_function))
     __cyg_profile_func_exit(void *func, void *caller)
{
    register void* sp asm("sp");
    fprintf(stderr, "EXIT: %016lx %p\n", (unsigned long)(wc_ptr_t)func, sp);
    (void)caller;
}
#endif

