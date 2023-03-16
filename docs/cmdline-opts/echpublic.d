c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: echpublic
Help: Public SNI name to use instead of authority hostname
Arg: <string/@file>
Protocols: TLS
Added: 8.0.0-DEV
See-also: ech echconfig
Category: tls
Example: --ech --echpublic other.example.net $URL
Multi: single
---
Specify a public SNI name using this option in case it is missing
from available ECHCONFIG data, or should be over-ridden.

TODO: cross-check interactions with --ech, --echconfig.

This description of the --echpuiblic option is PROVISIONAL, as
ECH support is work in progress.
