# TLS: ECH support in curl and libcurl

## Summary

**ECH** means **Encrypted Client Hello**, a TLS 1.3 extension which is
currently the subject of an [IETF Draft][tlsesni]. Prior to version 07
of this draft, the goal was to encrypt just the Server Name
Indication, rather than the entire Client Hello, and the extension was
known as ESNI.

Automatic discovery of service-binding parameters, such as ECH
configuration, depends on "extended" DNS resolution, using
[SVCB-like][svcbhttps] resource records.

This file is intended to show the latest current state of ECH support
in **curl** and **libcurl**.

## Resources needed

To build and demonstrate ECH support in **curl** and/or **libcurl**,
you will need

-   a TLS library, supported by **libcurl**, which implements ECH;

-   an edition of **curl** and/or **libcurl** which supports the ECH
    implementation of the chosen TLS library;

-   an environment for building and running **curl**, and at least
    building the chosen TLS library;

-   a server, supporting ECH, against which to run a demonstration
    and perhaps a specific target URL;

-   some instructions.

## Progress

### PR 6022 (Sep 2020)

-   Updates PR 4011

-   Renamed configuration option: `--enable-ech`;

-   Build-time check for availability of resources needed for ECH
    support;

-   Renamed pre-processor symbol `USE_ECH` for conditional compilation of
    ECH support code, subject to configuration option and
    availability of needed resources.

## TODO

-   (WIP) Verify or refactor build-time checks

-   (WIP) Refactor libcurl ESNI options to set ECH parameters.

-   (WIP) Refactor libcurl ESNI code to drive backend API
    (experimental OpenSSL implementation expected early/mid 2021)

-   (WIP) Refactor curl tool command line options to set ECH
    configuration.

-   (WIP) Demonstrate ECH using curl tool command line options

-   Extend libcurl DNS resolution to allow discovery and use of
    service-binding parameters, including ECH configuration (not
    trivial)

-   Identify and implement any changes needed for CMake.

-   Optimize build-time checking of available resources.

-   Encourage ECH support work on other TLS/SSL backends.

---

## Earlier work

### PR 4011 (Jun 2019)

-   Details [below](#pr4011);

-   New configuration option: `--enable-esni`;

-   Build-time check for availability of resources needed for ESNI
    support;

-   Pre-processor symbol `USE_ESNI` for conditional compilation of
    ECH support code, subject to configuration option and
    availability of needed resources.

### Demonstration of ESNI (Aug 2019)

At end of August 2019, the [DEfO Project][defoproj] demonstrated ESNI,
with an [experimental fork of curl][niallorcurl], built using an
[ESNI-capable experimental fork of OpenSSL][sftcdopenssl],
interoperating with a server belonging to the [DEfO
Project][defoproj].

This demonstration used the resources shown below.

| Set  | Component    | Location                      | Remarks                                    |
|:-----|:-------------|:------------------------------|:-------------------------------------------|
| DEfO | TLS library  | [sftcd/openssl][sftcdopenssl] | Tag *esni-2019-08-30* avoids bleeding edge |
|      | curl fork    | [niallor/curl][niallorcurl]   | Tag *esni-2019-08-30* likewise             |
|      | instructions | [ESNI-README][niallorreadme]  |                                            |

This work has now been overtaken by events. In particular, server support
for the now-deprecated ESNI operation is no longer available.

---

## References

Firefox blog: [Encrypted Client Hello: the future of ESNI in Firefox
][echffox]

Cloudflare blog: [Good-bye ESNI, hello ECH!][helloech]

Cloudflare blog: [Encrypting SNI: Fixing One of the Core Internet
Bugs][corebug]

Cloudflare blog: [Encrypt it or lose it: how encrypted SNI
works][esniworks]

IETF ECH Draft: [Encrypted Server Name Indication for TLS
1.3][tlsesni]

IETF SVCB Draft: [Service binding and parameter specification via the
DNS][svcbhttps]

---

[tlsesni]:		https://datatracker.ietf.org/doc/draft-ietf-tls-esni/
[helloech]:     https://blog.cloudflare.com/encrypted-client-hello/
[esniworks]:	https://blog.cloudflare.com/encrypted-sni/
[corebug]:		https://blog.cloudflare.com/esni/
[defoproj]:		https://defo.ie/
[sftcdopenssl]: https://github.com/sftcd/openssl/
[niallorcurl]:	https://github.com/niallor/curl/
[niallorreadme]: https://github.com/niallor/curl/blob/master/ESNI-README.md
[svcbhttps]:    https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-httpssvc/
[echffox]:      https://blog.mozilla.org/security/2021/01/07/encrypted-client-hello-the-future-of-esni-in-firefox/
