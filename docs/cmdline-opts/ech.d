c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ech
Help: Use encrypted Client Hello
Protocols: TLS
Added: DUMMY
See-also: echconfig
Category: tls
Example: --ech $URL
Multi: boolean
---
Forces curl to attempt to use encrypted Client Hello or, as --no-ech,
to avoid using encrypted Client Hello.

Implied by use of the --echconfig option.

Unless ECHCONFIG data can be retrieved automatically from
the DNS, this data must be specified using the --echconfig option.

If --ech and --no-ech are both specified, only the first one
has effect.

This description of the --ech option is PROVISIONAL, as
ECH support is work in progress.
