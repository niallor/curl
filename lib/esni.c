/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "curl_setup.h"

#ifdef USE_ESNI
#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"
#include "esni.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

void esni_free(struct ESNIstate *esni)
{
  if(esni) {
    free(esni->encservername);
    free(esni->servername);
    free(esni->public_name);
    free(esni->asciirr);
    free(esni);
  }
}

struct ESNIstate *esni_init(void)
{
  struct ESNIstate *esni = calloc(1, sizeof(struct ESNIstate));
  if(!esni)
    return NULL;

  return esni;
}

bool ssl_esni_check(struct Curl_easy *data)
{
  /* Check for consistency and completeness of ESNI options */

  /* TODO: in verbose mode, display what's been specified */

  infof(data, "Entering ssl_esni_check\n");

  if(!data->set.ssl_enable_esni) {
    /* TODO: ASSERT other ESNI options not set, but ignore for now */
    infof(data, "found flag ssl_enable_esni CLEAR\n");
    return TRUE;                /* Not requested: definitely good */
  }
  infof(data, "found flag ssl_enable_esni SET\n");
  infof(data, "found flag ssl_strict_esni %s\n",
        (data->set.ssl_strict_esni ? "SET" : "CLEAR")
        );

  warnf(data->global, "Checking of ESNI options is not yet implemented\n");
  warnf(data->global, "Assuming all are good and returning TRUE\n");
  return TRUE;

  return FALSE;
}

#endif  /* USE_ESNI */
