Long: strict-esni
Help: Insist that server cert matches specified ESNI name
Protocols: TLS
---
Specify whether to insist that the server cert matches specified ESNI name

Implies --esni.

This option is normally set by default. Specifying '--no-strict-esni'
causes processing to continue even if the server cert does not match
the name specified in the ESNI option.

If specified more than once, or together with --no-esni, only the
first specification has effect.

This description of the --strict-esni option is PROVISIONAL, as
ESNI support is work in progress.
