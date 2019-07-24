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
 *
 * Non-backend-specific ESNI support code belongs here, such as functions
 * - to check ESNI-related libcurl options
 *   for correctness and consistency
 * - to parse and display ESNI data
 *
 * Backend-specific ESNI support code belongs as additional
 * backend-interface code in one of the existing vlts backend
 * interface source files or in an ESNI-specific source file
 * associated with one of these existing files.
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifdef USE_ESNI
#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"
#include "vtls/vtls.h"
#include "esni.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/**
 * Check completeness of ESNI parameter data present in easy handle
 *
 * @param data is the Curl_easy handle to inspect
 * @return TRUE if complete, FALSE otherwise
 */
bool Curl_ESNI_ready(struct Curl_easy *data) {

  /* TODO: actually inspect ESNI parameters */
  return TRUE;                  /* Stub always returns TRUE */
}

/* *** Unreferenced code begins */
/* *** TODO: strip only after salvaging */
/* /\** */
/*  * Try figure out ESNIKeys encodng */
/*  * */
/*  * Copies from sftcd/openssl/ssl/esni.c because static there and need */
/*  * to have results for debugging here */
/*  * */
/*  * Reformatted to satisfy curl style conventions */
/*  * */
/*  * @param eklen is the length of esnikeys */
/*  * @param esnikeys is encoded ESNIKeys structure */
/*  * @param guessedfmt is our returned guess at the format */
/*  * @return 1 for success, 0 for error */
/*  *\/ */
/* static int esni_guess_fmt(const size_t eklen, */
/*                           const char *esnikeys, */
/*                           short *guessedfmt) */
/* { */
/*   /\* asci hex is easy:-) either case allowed*\/ */
/*   const char *AH_alphabet = "0123456789ABCDEFabcdef"; */
/*   /\* we actually add a semi-colon here as we accept multiple */
/*      semi-colon separated values *\/ */
/*   const char *B64_alphabet */
/*     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=;"; */

/*   if(!guessedfmt || eklen <= 0 || !esnikeys) { */
/*     return (0); */
/*   } */
/*   /\* */
/*    * Try from most constrained to least in that order */
/*    *\/ */
/*   if(eklen <= strspn(esnikeys, AH_alphabet)) { */
/*     *guessedfmt = ESNI_RRFMT_ASCIIHEX; */
/*   } */
/*   else if(eklen <= strspn(esnikeys, B64_alphabet)) { */
/*     *guessedfmt = ESNI_RRFMT_B64TXT; */
/*   } */
/*   else { */
/*     /\* fallback - try binary *\/ */
/*     *guessedfmt = ESNI_RRFMT_BIN; */
/*   } */
/*   return (1); */
/* } */

/* /\** @brief Decode from ASCII HEX RR to binary buffer */
/*  * */
/*  * */
/*  * @param in is the base64 encoded string */
/*  * @param out is the binary equivalent */
/*  * @return is the number of octets in |out| if successful, <=0 for failure */
/*  *\/ */
/* static int esni_ah_decode(char *in, unsigned char **out) */
/* { */
/*   int inlen = (int) strlen(in); */
/*   unsigned char *outbuf; */
/*   unsigned char *outp; */
/*   size_t outlen; */
/*   int i; */

/*   /\* Check arguments *\/ */
/*   if(!out)                      /\* Nowhere to put it *\/ */
/*     return 0; */

/*   if(!inlen) {                  /\* Nothing to find *\/ */
/*     *out = NULL; */
/*     return 0; */
/*   } */

/*   if(inlen%2)                   /\* Odd, indeed! *\/ */
/*     return 0; */

/*   outlen = inlen/2; */
/*   outbuf = malloc(outlen); */

/*   if(!outbuf) */
/*     return 0; */

/*   *out = outbuf; */
/*   outp = outbuf; */

/*   for(i = 0; i < inlen; i++) { */
/*     int v;                      /\* Minimizes compiler noise *\/ */
/*     switch(in[i]) { */
/*     case '0': */
/*     case '1': */
/*     case '2': */
/*     case '3': */
/*     case '4': */
/*     case '5': */
/*     case '6': */
/*     case '7': */
/*     case '8': */
/*     case '9': */
/*       v = in[i] - '0'; */
/*       break; */
/*     case 'A': */
/*     case 'B': */
/*     case 'C': */
/*     case 'D': */
/*     case 'E': */
/*     case 'F': */
/*       v = in[i] - 'A' + 10; */
/*       break; */
/*     case 'a': */
/*     case 'b': */
/*     case 'c': */
/*     case 'd': */
/*     case 'e': */
/*     case 'f': */
/*       v = in[i] - 'a' + 10; */
/*       break; */
/*     default: */
/*       goto err; */
/*     } */
/*     if(i%2) */
/*       /\* Odd: move on after merging in low nybble *\/ */
/*       /\* TODO: avoid compiler noise about conversion *\/ */
/*       *outp++ &= v; */
/*     else */
/*       /\* Even: set high nybble *\/ */
/*       /\* TODO: avoid compiler noise about conversion *\/ */
/*       *outp = v<<4; */
/*   } */

/*   return outlen; */

/*  err: */
/*   free(outbuf); */
/*   *out = NULL; */
/*   return -1; */
/* } */

/* /\** */
/*  * @brief Decode from TXT RR to binary buffer */
/*  * */
/*  * This was the same as ct_base64_decode from crypto/ct/ct_b64.c */
/*  * which function is declared static but could otherwise */
/*  * have been be re-used. Returns -1 for error or length of decoded */
/*  * buffer length otherwise (wasn't clear to me at first */
/*  * glance). Possible future change: re-use the ct code by */
/*  * exporting it. */
/*  * With draft-03, we're extending to allow a set of */
/*  * semi-colon separated strings as the input to handle */
/*  * multivalued RRs. */
/*  * */
/*  * Decodes the base64 string |in| into |out|. */
/*  * A new string will be malloc'd and assigned to |out|. This will be owned by */
/*  * the caller. Do not provide a pre-allocated string in |out|. */
/*  * The input is modified if multivalued (NULL bytes are added in */
/*  * place of semi-colon separators. */
/*  * */
/*  * @param in is the base64 encoded string */
/*  * @param out is the binary equivalent */
/*  * @return is the number of octets in |out| if successful, <=0 for failure */
/*  *\/ */
/* static int esni_base64_decode(char *in, unsigned char **out) */
/* { */
/*   const char *sepstr = ";"; */
/*   size_t inlen = strlen(in); */
/*   int i = 0; */
/*   int outlen = 0; */
/*   unsigned char *outbuf = NULL; */
/*   size_t overallfraglen = 0; */

/*   char *inp = in; */

/*   if(out == NULL) { */
/*     return 0; */
/*   } */
/*   if(inlen == 0) { */
/*     *out = NULL; */
/*     return 0; */
/*   } */

/*   /\* */
/*    * overestimate of space but easier than base64 finding padding right now */
/*    *\/ */
/*   /\* outbuf = OPENSSL_malloc(inlen); *\/ */
/*   outbuf = malloc(inlen); */
/*   if(outbuf == NULL) { */
/*     ESNIerr(ESNI_F_ESNI_BASE64_DECODE, ERR_R_MALLOC_FAILURE); */
/*     goto err; */
/*   } */

/*   while(overallfraglen<inlen) { */

/*     /\* find length of 1st b64 string *\/ */
/*     int ofraglen = 0; */
/*     size_t thisfraglen = strcspn(inp, sepstr); */
/*     unsigned char *outp = outbuf; */

/*     inp[thisfraglen] = '\0'; */
/*     overallfraglen += (thisfraglen + 1); */

/*     ofraglen = EVP_DecodeBlock(outp, (unsigned char *)inp, */
/*                                (int) thisfraglen); */
/*     if(ofraglen < 0) { */
/*       ESNIerr(ESNI_F_ESNI_BASE64_DECODE, ESNI_R_BASE64_DECODE_ERROR); */
/*       goto err; */
/*     } */

/*     /\* Subtract padding bytes from |outlen|.  Any more than 2 is malformed. *\/ */
/*     i = 0; */
/*     while(inp[thisfraglen-i-1] == '=') { */
/*       if(++i > 2) { */
/*         ESNIerr(ESNI_F_ESNI_BASE64_DECODE, ESNI_R_BASE64_DECODE_ERROR); */
/*         goto err; */
/*       } */
/*     } */
/*     outp += (ofraglen-i); */
/*     outlen += (ofraglen-i); */
/*     inp += (thisfraglen + 1); */

/*   } */

/*   *out = outbuf; */
/*   return outlen; */
/*  err: */
/*   /\* OPENSSL_free(outbuf); *\/ */
/*   free(outbuf); */
/*   ESNIerr(ESNI_F_ESNI_BASE64_DECODE, ESNI_R_BASE64_DECODE_ERROR); */
/*   return -1; */
/* } */

/* bool ssl_esni_check(struct Curl_easy *data) */
/* { */
/*   /\* Check for consistency and completeness of ESNI options *\/ */

/*   bool result; */
/*   size_t asciirrlen; */
/*   short guessedfmt; */
/*   SSL_ESNI *esnikeys = NULL;    /\* Handle for struct holding ESNI data *\/ */
/*   int nesnis = 0;               /\* Count of ESNI keys *\/ */
/*   int value; */
/*   unsigned char *binrr = NULL;  /\* Pointer to buffer for decoded RR *\/ */

/*   /\* Pointer to copy of encoded RR *\/ */
/*   /\* char *ekcopy = NULL; *\/ */

/*   /\* Copy string pointer so line-length conforms to style 8-) *\/ */
/*   char *asciirr = data->set.str[STRING_ESNI_ASCIIRR]; */

/*   infof(data, "Entering ssl_esni_check\n"); */

/*   if(!data->set.tls_enable_esni) { */
/*     /\* TODO: ASSERT other ESNI options not set, but ignore for now *\/ */
/*     infof(data, "  found flag ssl_enable_esni (CLEAR)\n"); */
/*     return TRUE;                /\* Not requested: definitely good *\/ */
/*   } */

/*   /\* Came this far, so ssl_enable_esni must be set *\/ */
/*   infof(data, "  found flag ssl_enable_esni (SET)\n"); */

/*   infof(data, "  found flag ssl_strict_esni %s\n", */
/*         (data->set.tls_strict_esni ? "(SET)" : "(CLEAR)") */
/*         ); */

/*   if(data->set.str[STRING_ESNI_SERVER]) */
/*     infof(data, "  found STRING_ESNI_SERVER (%s)\n", */
/*           data->set.str[STRING_ESNI_SERVER]); */
/*   else */
/*     /\* We can live with this *\/ */
/*     infof(data, "  missing STRING_ESNI_SERVER\n"); */

/*   if(data->set.str[STRING_ESNI_COVER]) */
/*     infof(data, "  found STRING_ESNI_COVER (%s)\n", */
/*           data->set.str[STRING_ESNI_COVER]); */
/*   else */
/*     /\* We can live with this *\/ */
/*     infof(data, "  missing STRING_ESNI_COVER\n"); */

/*   if(data->set.str[STRING_ESNI_ASCIIRR]) { */
/*     asciirrlen = strlen(data->set.str[STRING_ESNI_ASCIIRR]); */

/*     infof(data, "  found STRING_ESNI_ASCIIRR %p/%ld (%s)\n", */
/*           data->set.str[STRING_ESNI_ASCIIRR], */
/*           asciirrlen, */
/*           data->set.str[STRING_ESNI_ASCIIRR] */
/*           ); */

/*     value = esni_guess_fmt(asciirrlen, asciirr, &guessedfmt); */

/*     infof(data, "  got value from esni_guess_fmt (%d)\n", value); */
/*     { */
/*       int tdeclen = 0; */
/*       const char *format = "  got format from esni_guess_fmt (%s)\n"; */

/*       switch(guessedfmt) { */
/*       case ESNI_RRFMT_ASCIIHEX: */
/*         infof(data, format, "ESNI_RRFMT_ASCIIHEX"); */
/*         tdeclen = esni_ah_decode(asciirr, &binrr); */
/*         infof(data, */
/*               "  esni_ah_decode returned data %p/%d\n", */
/*               binrr, tdeclen); */
/*         break; */
/*       case ESNI_RRFMT_B64TXT: */
/*         infof(data, format, "ESNI_RRFMT_B64TXT"); */
/*         tdeclen = esni_base64_decode(asciirr, &binrr); */
/*         /\* infof(data, *\/ */
/*         /\*       "  esni_base64_decode returned length (%d)\n", tdeclen); *\/ */
/*         infof(data, */
/*               "  esni_base64_decode returned data %p/%d\n", */
/*               binrr, tdeclen); */
/*         break; */
/*       case ESNI_RRFMT_BIN: */
/*         infof(data, format, "ESNI_RRFMT_BIN"); */
/*         break; */
/*       default: */
/*         infof(data, format, "UNKNOWN"); */
/*         break; */
/*     } */
/*   } */

/*     infof(data, "  TODO: display binary ESNIkeys blob\n"); */

/*     /\* TODO: */
/*      * consider whether there's anything else to check */
/*      * before initializing SSL *\/ */

/*     /\* Further checking needs SSL ready *\/ */
/*     /\* TODO: check whether this conflicts with state engine *\/ */
/*     /\* OPENSSL_init_ssl(0, NULL); *\/ */
/*     SSL_library_init();         /\* More evocative than above *\/ */

/*     /\* Try generic initialization instead *\/ */
/*     /\* Curl_ssl_init(); *\/ */
/*     /\* Doesn't work *\/ */

/*     /\* Build ESNIkeys blob from buffer, if possible *\/ */
/*     esnikeys */
/*       = SSL_ESNI_new_from_buffer(guessedfmt, */
/*                                  asciirrlen, */
/*                                  data->set.str[STRING_ESNI_ASCIIRR], */
/*                                  &nesnis); */
/*     infof(data, */
/*           "  SSL_ESNI_new_from_buffer returned nesnis (%d)\n", */
/*           nesnis); */
/*     infof(data, */
/*           "  SSL_ESNI_new_from_buffer returned esnikeys (%p)\n", */
/*           esnikeys); */

/*     if((!nesnis) || (!esnikeys)) { */
/*       result = FALSE;           /\* Save for after housekeeping *\/ */
/*       infof(data, "  invalid STRING_ESNI_ASCIIRR\n"); */
/*     } */
/*     else { */
/*       result = TRUE;            /\* Save for after housekeeping *\/ */
/*       infof(data, "  parsed STRING_ESNI_ASCIIRR; found %d key%s\n", */
/*             nesnis, (nesnis == 1) ? "" : "s" */
/*             ); */
/*     } */
/*     /\* Always do housekeeping -- we're only testing for now *\/ */
/*     if(esnikeys) { */
/*       SSL_ESNI_free(esnikeys); */
/*       OPENSSL_free(esnikeys); */
/*       esnikeys = NULL; */
/*     } */
/*     return result;              /\* Saved value *\/ */
/*   } */
/*   else { */
/*     infof(data, "  missing STRING_ESNI_ASCIIRR\n"); */
/*     return FALSE;               /\* Signal an ERROR *\/ */
/*   } */

/*   infof(data, "  checking of ESNI options is not yet implemented\n"); */
/*   infof(data, "  assuming that nothing is amiss\n"); */
/*   infof(data, "Returning from ssl_esni_check with result TRUE\n"); */
/*   return TRUE; */

/* } */
/* *** Unreferenced code ends */

#endif  /* USE_ESNI */
