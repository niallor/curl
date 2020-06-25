# TLS: ESNI support in libcurl and curl

## Summary

**ECH** means **Encrypted Client Hello**, a proposed TLS 1.3
extension, documented in [this IETF Draft][tlsesni].

ECH support in *libcurl* and *curl* is expected to be implemented in
the following stages, according to availability of resources.

1. Support in one or more SSL backends.

2. Support for a (set of) *libcurl* option(s) to allow an application
   to specify an ECH configuration to be used by the backend.

3. Support for *curl* command-line syntax to drive the corresponding
   *libcurl* option(s).

4. Support in *libcurl* for retrieving an ECH configuration from the DNS
   using DOH and passing this to the SSL backend.

5. Support in *libcurl* for retrieving and using a full set of service
   binding parameters from [HTTPS and/or SVCB][dnsopsvcbhttps] records
   in the DNS.

Resources are currently available for items 1—4 above, and work is in
progress.

Item 5 is expected to involve significant changes to how *libcurl*
uses the DNS.

## Progress

Progress will be reported here in due course.

---

[tlsesni]:		  https://datatracker.ietf.org/doc/draft-ietf-tls-esni/
[dnsopsvcbhttps]: https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/
