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

#ifdef(USE_ESNI)
#include <curl/curl.h>
#include "urldata.h"
#include "esni.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

static void esni_free(struct ESNIstate *esni)
{
  free(esni->encservername);
  free(esni->servername);
  free(esni->public_name);
  free(esni->asciirr);
  free(esni);
}

static struct ESNIstate *esni_init(void)
{
  struct ESNIstate *esni = calloc(1, sizeof(struct ESNIstate));
  if (!esni)
    return NULL;

  return esni;
}
