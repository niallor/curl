# TLS: ECH support in *curl* and *libcurl*

## Summary

- **ECH (Encrypted Client Hello)**:

    proposed privacy-enhancing TLS 1.3 extension.

- **ESNI (Encrypted Server Name Indication)**:

    earlier work, with narrower scope, now re-purposed as ECH.

- **ECHCONFIG**:

    data structure which carries the configuration to be used in
    setting up a TLS connection using ECH; can be published in the DNS
    using an SVCB-compatible RR type.

- **SVCB (Service Binding)**:

    DNS RR type intended as a base type for defining other,
    service-specific, **SVCB-compatible** RR types; allows a service
    client to discover, for a given service origin, alternative
    endpoints and corresponding connection parameters.

- **DNS HTTPS RR type**:

    SVCB-compatible RR type which provides special handling for
    **https** and **http** origins.

- **SVCB resolution**:

    Extended DNS resolution retrieving other necessary connection
    parameters in addition to IP addresses.

## Specification

No standards are yet (mid-2021) available.

- [IETF ECH draft][tlsesni]

- [IETF SVCB/HTTPS draft][svcbhttps]

## Proof of concept (April 2021)

Instructions are [documented separately][howto-ech]

- [OpenSSL fork][sftcd/openssl] implementing ECH

- [Curl fork][niallor/curl] supporting ECH using wrapper script and OpenSSL

- Wrapper script performing SVCB resolution and feeding configuration
  data in CLI option to *curl*

- Interoperation with [Cloudflare demonstration service][cfdemo]

## TODO

- Provide SVCB resolution within *libcurl*

- Extend DNS cacheing in *libcurl* to accommodate results of SVCB
  resolution.

- Use results of SVCB resolution to drive endpoint discovery and ECH,
  and to optimize alt-svc negotiation.



---

[tlsesni]:		 https://datatracker.ietf.org/doc/draft-ietf-tls-esni/
[svcbhttps]:     https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/
[cfechdemo]:     https://crypto.cloudflare.com//cdn-cgi/trace
[sftcd/openssl]: https://github.com/sftcd/openssl/
[niallor/curl]:  https://github.com/niallor/curl/
[rthalley/dnspython]: https://github.com/rthalley/dnspython
[howto-ech]:     HOWTO-ECH.md
