<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Shortcomings in current processing of DNS responses

## Occurrence and Relevance

The shortcomings described below were observed in DoH response
processing; they are expected also to be found in the processing of
DNS responses obtained using c-ares.

These shortcomings are relevant to processing of the following DNS
record types:

- CNAME
- HTTPS

## CNAME record type

- chained relationship of CNAME records is ignored
- canonical name is not set (in dns-cache entry) from the
  final record of the CNAME chain
- duplicate CNAME strings are saved in case responses for both
  A and AAAA records are processed

## HTTPS record type
- ordered relationship of HTTPS records in RRset is ignored
- AliasMode HTTPS records are not handled adequately
- address hints are not used to compensate for absence of
  A and/or AAAA records



---
