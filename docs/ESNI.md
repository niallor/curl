# TLS: ESNI support in curl and libcurl

## Summary

**ESNI** means **Encrypted Server Name Indication**, a TLS 1.3
extension which is currently the subject of an
[IETF Draft][tlsesni].

This file is intended to show the latest current state of ESNI support
in **curl** and **libcurl**.

At end of August 2019, an [experimental fork of curl][niallorcurl],
built using an [experimental fork of OpenSSL][sftcdopenssl], which in
turn provided an implementation of ESNI, was demonstrated
interoperating with a server belonging to the [DEfO
Project][defoproj].

Further sections here describe

-   resources needed for building and demonstrating **curl** support
    for ESNI,

-   progress to date,

-   TODO items, and

-   additional details of specific stages of the progress.

## Resources needed

To build and demonstrate ESNI support in **curl** and/or **libcurl**,
you will need

-   a TLS library, supported by **libcurl**, which implements ESNI;

-   an edition of **curl** and/or **libcurl** which supports the ESNI
    implementation of the chosen TLS library;

-   an environment for building and running **curl**, and at least
    building **OpenSSL**;

-   a server, supporting ESNI, against which to run a demonstration
    and perhaps a specific target URL;

-   some instructions.

The following set of resources is currently known to be available.

| Set  | Component    | Location                      | Remarks                                           |
|:-----|:-------------|:------------------------------|:--------------------------------------------------|
| DEfO | TLS library  | [sftcd/openssl][sftcdopenssl] | Tag *esni-2019-08-30* avoids bleeding edge        |
|      | curl fork    | [niallor/curl][niallorcurl]   | Branch *ESNI-demo*                                |
|      |              |                               | Tag *esni-2019-08-30* (superseded by *ESNI-demo*) |
|      | instructions | [ESNI-README][niallorreadme]  |                                                   |

## Progress

### ESNI-demo (PR 4468, Oct 2019)

-   Add libcurl options to set ESNI parameters.

-   Add support code to propagate parameters to TLS backend

-   Add curl tool command line options to set ESNI parameters.

### PR 4011 (Jun 2019) expected in curl release 7.67.0 (Oct 2019)

-   Details [below](#pr4011);

-   New **curl** feature: `CURL_VERSION_ESNI`;

-   New configuration option: `--enable-esni`;

-   Build-time check for availability of resources needed for ESNI
    support;

-   Pre-processor symbol `USE_ESNI` for conditional compilation of
    ESNI support code, subject to configuration option and
    availability of needed resources.

## TODO

-   (WIP) Extend DoH functions so that published ESNI parameters can be
    retrieved from DNS instead of being required as options.

-   (WIP) Work with OpenSSL community to finalize ESNI API.

-   Track OpenSSL ESNI API in libcurl

-   Identify and implement any changes needed for CMake.

-   Optimize existing build-time checking of available resources.

-   Encourage ESNI support work on other TLS/SSL backends.

-   Extend build-time checking of available resources to
    accommodate other TLS/SSL backends as thes become available.

## Additional detail

### ESNI-demo (PR 4468)

**TLS: Provide demonstration ESNI implementation for curl and libcurl**

-   Define libcurl options for ESNI

    -   New options with associated man pages:

        -   `CURLOPT_ESNI_ASCIIRR`
        -   `CURLOPT_ESNI_COVER`
        -   `CURLOPT_ESNI_SERVER`
        -   `CURLOPT_ESNI_STATUS`

-   Implement libcurl support for ESNI

-   Implement curl tool support for ESNI

    -   New command-line options with associated man pages:

        -   `--esni`\
            (boolean: on unless first ESNI option is `--no-esni`)

        -   `--esni-cover=HOSTNAME` (cover name to send as SNI)

        -   `--esni-load=ESNIKEYS` (Base64, hex, or binary file)

        -   `--esni-server=HOSTNAME`\
            (over-rides URL hostname as name to send as encrypted SNI)

        -   `--strict-esni` (boolean: off by default)

-   Update documentation file, *docs/ESNI.md*

-   Limitations not covered by TODO list:

    -   ESNI parameters must be discovered externally and passed to
        *libcurl* as options instead of being fetched from the DNS.

    -   Book-keeping for new options needs real release number
        instead of `DUMMY`.

### PR 4011

**TLS: Provide ESNI support framework for curl and libcurl**

The proposed change provides a framework to facilitate work to
implement ESNI support in curl and libcurl. It is not intended
either to provide ESNI functionality or to favour any particular
TLS-providing backend. Specifically, the change reserves a
feature bit for ESNI support (symbol `CURL_VERSION_ESNI`),
implements setting and reporting of this bit, includes dummy
book-keeping for the symbol, adds a build-time configuration
option (`--enable-esni`), provides an extensible check for
resources available to provide ESNI support, and defines a
compiler pre-processor symbol (`USE_ESNI`) accordingly.

Proposed-by: @niallor (Niall O'Reilly)\
Encouraged-by: @sftcd (Stephen Farrell)\
See-also: [this message](https://curl.haxx.se/mail/lib-2019-05/0108.html)

Limitations:
-   Book-keeping (symbols-in-versions) needs real release number, not 'DUMMY'.

-   Framework is incomplete, as it covers autoconf, but not CMake.

-   Check for available resources, although extensible, refers only to
    specific work in progress ([described
    here](https://github.com/sftcd/openssl/tree/master/esnistuff)) to
    implement ESNI for OpenSSL, as this is the immediate motivation
    for the proposed change.

## References

Cloudflare blog: [Encrypting SNI: Fixing One of the Core Internet Bugs][corebug]

Cloudflare blog: [Encrypt it or lose it: how encrypted SNI works][esniworks]

IETF Draft: [Encrypted Server Name Indication for TLS 1.3][tlsesni]

---

[tlsesni]:		https://datatracker.ietf.org/doc/draft-ietf-tls-esni/
[esniworks]:	https://blog.cloudflare.com/encrypted-sni/
[corebug]:		https://blog.cloudflare.com/esni/
[defoproj]:		https://defo.ie/
[sftcdopenssl]: https://github.com/sftcd/openssl/
[niallorcurl]:	https://github.com/niallor/curl/
[niallorreadme]: https://github.com/niallor/curl/blob/master/ESNI-README.md
