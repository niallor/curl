#ifndef HEADER_CURL_DOH_H
#define HEADER_CURL_DOH_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

#include "urldata.h"
#include "curl_addrinfo.h"
#ifdef USE_HTTPSRR
# include <stdint.h>

#define Curl_freehttpsrrinfo(x) if(x) { \
    Curl_safefree((x)->target);         \
    Curl_safefree((x)->echconfiglist);  \
    Curl_safefree((x)->val); }          \
  Curl_safefree(x)
#endif

#ifndef CURL_DISABLE_DOH

typedef enum {
  DOH_OK,
  DOH_DNS_BAD_LABEL,    /* 1 */
  DOH_DNS_OUT_OF_RANGE, /* 2 */
  DOH_DNS_LABEL_LOOP,   /* 3 */
  DOH_TOO_SMALL_BUFFER, /* 4 */
  DOH_OUT_OF_MEM,       /* 5 */
  DOH_DNS_RDATA_LEN,    /* 6 */
  DOH_DNS_MALFORMAT,    /* 7 */
  DOH_DNS_BAD_RCODE,    /* 8 - no such name */
  DOH_DNS_UNEXPECTED_TYPE,  /* 9 */
  DOH_DNS_UNEXPECTED_CLASS, /* 10 */
  DOH_NO_CONTENT,           /* 11 */
  DOH_DNS_BAD_ID,           /* 12 */
  DOH_DNS_NAME_TOO_LONG,    /* 13 */
  DOH_DNS_ALIAS_PENDING     /* 14 */
} DOHcode;

typedef enum {
  DNS_TYPE_A = 1,
  DNS_TYPE_NS = 2,
  DNS_TYPE_CNAME = 5,
  DNS_TYPE_AAAA = 28,
  DNS_TYPE_DNAME = 39,           /* RFC6672 */
  DNS_TYPE_HTTPS = 65
} DNStype;

/* struct:s RRmap, RRsetmap describe inter-RR dependencies */
struct RRmap {       /* Note: all offsets are from start of message */
  unsigned int base;     /* position of RR in buffer */
  unsigned int name_len; /* length of name in buffer */
  unsigned int name_ref; /* offset to referenced name */
  unsigned int name_org; /* offset to "original" name */
  unsigned short type;
  unsigned int class;
  unsigned int ttl;
  unsigned short rd_len;   /* length of rdata */
  unsigned int rd_ref;   /* position of RDATA in buffer */
  unsigned int tg_len;   /* length of target in rdata (if defined) */
  unsigned int priority; /* priority/preference (if defined) */
};

struct RRsetmap {
  unsigned int base;     /* index into RRmap of first RR */
  unsigned int count;    /* count of RRs in RRset */
  unsigned int ttl;      /* minimum TTL over RRs in set */
  unsigned int type;     /* RR TYPE (common to all RRs in set) */
  unsigned int name_ref; /* offset to referenced name */
  unsigned int name_org; /* offset to "original" name */
};

/* WIP: upstream refactoring of struct doh_probe */
/*

doh: cleanups

Mostly cleanup on identifiers of DoH code.
Always use 'Curl_doh_cleanup()' for releasing resources.

More concise and telling names (ymmv):

* prefix all static functions with 'doh_' for unity builds
* doh_encode -> doh_req_encode
* doh_decode -> doh_resp_decode
* struct dohdata -> struct doh_probes
* probe's 'serverdoh' -> 'resp_body'
* probe's 'dohbuffer' -> 'req_body'
* probe's 'headers' -> 'req_hds'
* 'dohprobe()' -> doh_run_probe()'
* 'DOH_PROBE_SLOTS' -> 'DOH_SLOT_COUNT'
* 'DOH_PROBE_SLOT_IPADDR_V4' -> 'DOH_SLOT_IPV4'
* 'DOH_PROBE_SLOT_IPADDR_V6' -> 'DOH_SLOT_IPV6'
* 'DOH_PROBE_SLOT_HTTPS' -> 'DOH_SLOT_HTTPS_RR'

Closes curl#14783

 */

/* one of these for each DoH request */
struct doh_probe {
  curl_off_t easy_mid; /* multi id of easy handle doing the lookup */
  DNStype dnstype;
  unsigned char req_body[512];
  size_t req_body_len;
  struct dynbuf resp_body;
  /* Proposed extensions */
  DOHcode status;               /* Result from doh_decode (not a CURLcode!) */
  unsigned int rcode;           /* DNS RCODE (possibly extended) */
  unsigned char qname[256];     /* DNS QNAME, if prefixed or aliased */
  unsigned char canonname[256]; /* target of CNAME or AliasMode */
  unsigned int in_work;         /* active, not yet decoded */
  unsigned int qdcount;         /* count of RRs in Question section */
  unsigned int rrcount;         /* count of entries in following tables */
  struct RRmap *rrtab;          /* table of RRs in response */
  struct RRsetmap *settab;      /* table of RRsets in response */
};

#ifdef USE_HTTPSRR
/* Note:
 * According to RFC9460 section 4.2, recursive resolver SHOULD
 * chase aliases, and place results in Additional Section of
 * response. Pending availablity of this functionality, or
 * in case resolver in use is deficient, client has to take
 * care of this instead.
 * */
#define DOH_ALIAS_LIMIT 4 /* count of slots to allow for chasing aliases */
#endif

enum doh_slot_num {
  /* Explicit values for first two symbols so as to match hard-coded
   * constants in existing code
   */
  DOH_SLOT_IPV4 = 0, /* make 'V4' stand out for readability */
  DOH_SLOT_IPV6 = 1, /* 'V6' likewise */

  /* Space here for (possibly build-specific) additional slot definitions */
#ifdef USE_HTTPSRR
  DOH_SLOT_HTTPS_RR = 2,     /* for HTTPS RR */
  DOH_SLOT_LAST_ALIAS = DOH_SLOT_HTTPS_RR + DOH_ALIAS_LIMIT,
#endif

  /* for example */
  /* #ifdef WANT_DOH_FOOBAR_TXT */
  /*   DOH_PROBE_SLOT_FOOBAR_TXT, */
  /* #endif */

  /* AFTER all slot definitions, establish how many we have */
  DOH_SLOT_COUNT
};

/*
 * Curl_doh() resolve a name using DoH (DNS-over-HTTPS). It resolves a name
 * and returns a 'Curl_addrinfo *' with the address information.
 */

struct Curl_addrinfo *Curl_doh(struct Curl_easy *data,
                               const char *hostname,
                               int port,
                               int *waitp);

CURLcode Curl_doh_is_resolved(struct Curl_easy *data,
                              struct Curl_dns_entry **dns);

#define DOH_MAX_ADDR 24
#define DOH_MAX_CNAME 4
#define DOH_MAX_HTTPS 4

struct dohaddr {
  int type;
  union {
    unsigned char v4[4]; /* network byte order */
    unsigned char v6[16];
  } ip;
};

#ifdef USE_HTTPSRR

/*
 * These are the code points for DNS wire format SvcParams as
 * per draft-ietf-dnsop-svcb-https
 * Not all are supported now, and even those that are may need
 * more work in future to fully support the spec.
 */
#define HTTPS_RR_CODE_ALPN            0x01
#define HTTPS_RR_CODE_NO_DEF_ALPN     0x02
#define HTTPS_RR_CODE_PORT            0x03
#define HTTPS_RR_CODE_IPV4            0x04
#define HTTPS_RR_CODE_ECH             0x05
#define HTTPS_RR_CODE_IPV6            0x06

/*
 * These may need escaping when found within an ALPN string
 * value.
 */
#define COMMA_CHAR                    ','
#define BACKSLASH_CHAR                '\\'

struct dohsvcpmap {             /* map of SvcParam data */
  unsigned short key;
  unsigned short dlen;
};

struct dohhttps_rr {
  uint16_t len; /* raw encoded length */
  unsigned char *val; /* raw encoded octets */
  unsigned int targlen; /* length of target field (on wire) */
  /*
   * unsigned short svcpcount;
   * struct dohsvcpmap *svcpmap;
   */
};
#endif

struct dohentry {
  struct dynbuf cname[DOH_MAX_CNAME];
  struct dohaddr addr[DOH_MAX_ADDR];
  int numaddr;
  unsigned int ttl;
  int numcname;
#ifdef USE_HTTPSRR
  struct dohhttps_rr https_rrs[DOH_MAX_HTTPS];
  int numhttps_rrs;
  struct doh_probe *probe;       /* reference to current probe object */
#endif
};

struct doh_probes {
  struct curl_slist *req_hds;
  struct doh_probe probe[DOH_SLOT_COUNT];
  struct dohentry de;           /* Preserve state between passes */
  unsigned int pending;         /* still outstanding requests */
  unsigned int inusect;         /* slots in use == index of next free slot */
  struct doh_probe *follow;      /* reference to probe with alias pending */
  int port;
  const char *host;
};

void Curl_doh_close(struct Curl_easy *data);
void Curl_doh_cleanup(struct Curl_easy *data);

#ifdef UNITTESTS
UNITTEST DOHcode doh_req_encode(const char *host,
                                DNStype dnstype,
                                unsigned char *dnsp,  /* buffer */
                                size_t len,  /* buffer size */
                                size_t *olen);  /* output length */
UNITTEST DOHcode doh_resp_decode(const unsigned char *doh,
                                 size_t dohlen,
                                 DNStype dnstype,
                                 struct dohentry *d);

UNITTEST void de_init(struct dohentry *d);
UNITTEST void de_cleanup(struct dohentry *d);
#endif

extern struct curl_trc_feat Curl_doh_trc;

#else /* if DoH is disabled */
#define Curl_doh(a,b,c,d) NULL
#define Curl_doh_is_resolved(x,y) CURLE_COULDNT_RESOLVE_HOST
#endif

#endif /* HEADER_CURL_DOH_H */
