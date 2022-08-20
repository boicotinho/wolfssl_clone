/* conf.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

#if !defined(WOLFSSL_CONF_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning conf.c does not need to be compiled separately from ssl.c
    #endif
#else

/*******************************************************************************
 * START OF TXT_DB API
 ******************************************************************************/


/*******************************************************************************
 * END OF TXT_DB API
 ******************************************************************************/

/*******************************************************************************
 * START OF CONF API
 ******************************************************************************/

#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)  || defined(HAVE_STUNNEL)
#ifndef NO_WOLFSSL_STUB
void wolfSSL_OPENSSL_config(char *config_name)
{
    (void)config_name;
    WOLFSSL_STUB("OPENSSL_config");
}
#endif /* !NO_WOLFSSL_STUB */
#endif /* OPENSSL_ALL || WOLFSSL_NGINX || WOLFSSL_HAPROXY || HAVE_STUNNEL*/




/*******************************************************************************
 * END OF CONF API
 ******************************************************************************/

#endif /* WOLFSSL_CONF_INCLUDED */
