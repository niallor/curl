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

/***************************************************************************
 * TODO:
 *
 * Consider whether this source file is appropriate, as ESNI support
 * may better belong in relevant backend-specific source which, by
 * convention, MAY ONLY BE lib/vtls/openssl.c for OpenSSL.
 *
 * Non-backend-specific ESNI support code, if ever there be any, may
 * well belong here.
 ***************************************************************************/

#include "curl_setup.h"

#ifdef USE_ESNI
#include <curl/curl.h>
#include <openssl/esni.h>
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

  bool result;
  SSL_ESNI *esnikeys = NULL;    /* Handle for struct holding ESNI data */
  int nesnis = 0;               /* Count of ESNI keys */
  const char *asciirr = data->set.str[STRING_ESNI_ASCIIRR];

  infof(data, "Entering ssl_esni_check\n");

  if(!data->set.ssl_enable_esni) {
    /* TODO: ASSERT other ESNI options not set, but ignore for now */
    infof(data, "  found flag ssl_enable_esni (CLEAR)\n");
    return TRUE;                /* Not requested: definitely good */
  }

  /* Came this far, so ssl_enable_esni must be set */
  infof(data, "  found flag ssl_enable_esni (SET)\n");

  infof(data, "  found flag ssl_strict_esni %s\n",
        (data->set.ssl_strict_esni ? "(SET)" : "(CLEAR)")
        );

  if(data->set.str[STRING_ESNI_SERVER])
    infof(data, "  found STRING_ESNI_SERVER (%s)\n",
          data->set.str[STRING_ESNI_SERVER]);
  else
    /* We can live with this */
    infof(data, "  missing STRING_ESNI_SERVER\n");

  if(data->set.str[STRING_ESNI_COVER])
    infof(data, "  found STRING_ESNI_COVER (%s)\n",
          data->set.str[STRING_ESNI_COVER]);
  else
    /* We can live with this */
    infof(data, "  missing STRING_ESNI_COVER\n");

  if(data->set.str[STRING_ESNI_ASCIIRR]) {
    infof(data, "  found STRING_ESNI_ASCIIRR (%s)\n",
          data->set.str[STRING_ESNI_ASCIIRR]);

    esnikeys = SSL_ESNI_new_from_buffer(
                                        ESNI_RRFMT_GUESS,
                                        strlen(asciirr), asciirr,
                                        &nesnis);

    infof(data, "  found nesnis (%d)\n", nesnis);
    infof(data, "  found esnikeys handle (%lh)\n", esnikeys);

    if((!nesnis) || (!esnikeys)) {
      result = FALSE;           /* Save for after housekeeping */
      infof(data, "  invalid STRING_ESNI_ASCIIRR\n");
    }
    else {
      result = TRUE;            /* Save for after housekeeping */
      infof(data, "  parsed STRING_ESNI_ASCIIRR; found %d key%s\n",
            nesnis, (nesnis == 1) ? "" : "s"
            );
    }
    /* Always do housekeeping -- we're only testing for now */
    if(esnikeys) {
      SSL_ESNI_free(esnikeys);
      OPENSSL_free(esnikeys);
      esnikeys = NULL;
    }
    return result;              /* Saved value */
  }
  else {
    infof(data, "  missing STRING_ESNI_ASCIIRR\n");
    return FALSE;               /* Signal an ERROR */
  }

  infof(data, "  checking of ESNI options is not yet implemented\n");
  infof(data, "  assuming that nothing is amiss\n");
  infof(data, "Returning from ssl_esni_check with result TRUE\n");
  return TRUE;

}

#endif  /* USE_ESNI */
