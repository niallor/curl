#ifndef HEADER_CURL_ESNI_H
#define HEADER_CURL_ESNI_H
/***************************************************************************
 *
 * Project DEfO
 *
 * Modelled on altsvc.h
 *
 * Replace with cURL boilerplate when ready
 *
 ***************************************************************************/
#include "curl_setup.h"

#ifdef USE_ESNI
# include <curl/curl.h>

/* Struct to hold ESNI data, referenced by current struct Curl_easy */
struct ESNIstate {
  char *encservername;
  char *servername;
  char *public_name;
  char *asciirr;
};

#else  /* ESNI not in use */
#endif  /* USE_ESNI */

#endif  /* HEADER_CURL_ESNI_H */
