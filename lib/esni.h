#ifndef HEADER_CURL_ESNI_H
#define HEADER_CURL_ESNI_H
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
 *
 ***************************************************************************/
#include "curl_setup.h"

#ifdef USE_ESNI
# include <curl/curl.h>

/* Struct to hold ESNI data, referenced from struct Curl_easy */
/* Expose details here to simplify interface -- may review later */
struct ESNIstate {
  char *encservername;          /* To be used as value of ESNI option */
  char *servername;             /* Name of host for connecting to */
  char *public_name;            /* To be used as value of SNI option */
  char *asciirr;                /* ESNI (formatted as continuous hex) or
                                 * TXT (formatted as base64 with semicolon
                                 *      separators) RRset
                                 */
};

void esni_free(struct ESNIstate *esni);
struct ESNIstate *esni_init(void);

#else  /* ESNI not in use */
#endif  /* USE_ESNI */

#endif  /* HEADER_CURL_ESNI_H */
