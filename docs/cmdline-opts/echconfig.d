c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: echconfig
Help: ECH configuration data
Arg: <string/@file>
Protocols: TLS
Added: DUMMY
See-also: ech
Category: tls
Example: --echconfig ENCODED_ECHCONFIG $URL
Multi: single
---
Specify echconfig data as a hexadecimal or base-64 encoded string
for use instead of fetching these data from the DNS.

The value used on the command line may be either the encoded string
itself or the '@'-escaped name of a text file containing the string.

Multiple echconfig data structures may be specified using hexadecimal
encoding by simply concatenating the individual encoded strings, or
using base-64 encoding by using a semicolon between each individual
encoded string and the following one.

Implies --ech.

If specified more than once, or together with --no-ech, only the
first specification has effect.

This description of the --echconfig option is PROVISIONAL, as
ECH support is work in progress.
