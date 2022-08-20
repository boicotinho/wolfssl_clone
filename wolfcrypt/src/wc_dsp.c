/* wc_dsp.c
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
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>

#if defined(WOLFSSL_DSP)
#include "remote.h"
#include "rpcmem.h"
static wolfSSL_DSP_Handle_cb handle_function = NULL;
static remote_handle64 defaultHandle;
static wolfSSL_Mutex handle_mutex; /* mutex for access to single default handle */

#define WOLFSSL_HANDLE_DONE 1
#define WOLFSSL_HANDLE_GET 0

/* callback function for setting the default handle in single threaded
 * use cases */
static int default_handle_cb(remote_handle64 *handle, int finished, void *ctx)
{
    (void)ctx;
    if (finished == WOLFSSL_HANDLE_DONE) {
        if (wc_UnLockMutex(&handle_mutex) != 0) {
            WOLFSSL_MSG("Unlock handle mutex failed");
            return -1;
        }
    }
    else {
        if (wc_LockMutex(&handle_mutex) != 0) {
            WOLFSSL_MSG("Lock handle mutex failed");
            return -1;
        }
        *handle = defaultHandle;
    }
    return 0;
}


/* Set global callback for getting handle to use
 * return 0 on success */
int wolfSSL_SetHandleCb(wolfSSL_DSP_Handle_cb in)
{
    handle_function = in;
    return 0;
}


/* returns 1 if global handle callback is set and 0 if not */
int wolfSSL_GetHandleCbSet()
{
    return (handle_function != NULL)? 1: 0;
}


/* Local function for setting up default handle
 * returns 0 on success */
int wolfSSL_InitHandle()
{
    char *sp_URI_value;
    int ret;

    sp_URI_value = wolfSSL_URI "&_dom=adsp";
    ret = wolfSSL_open(sp_URI_value, &defaultHandle);
    if (ret != 0) {
        WOLFSSL_MSG("Unable to open aDSP?");
        return -1;
    }
    wolfSSL_SetHandleCb(default_handle_cb);
    ret = wc_InitMutex(&handle_mutex);
    if (ret != 0) {
        WOLFSSL_MSG("Unable to init handle mutex");
        return -1;
    }
    return 0;
}


/* internal function that closes default handle and frees mutex */
void wolfSSL_CleanupHandle()
{
    wolfSSL_close(defaultHandle);
    wc_FreeMutex(&handle_mutex);
}
#endif /* WOLFSSL_DSP */
