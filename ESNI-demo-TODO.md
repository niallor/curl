# TODO list for preparing ESNI-demo PR

## Synopsis

After merge of ESNI-build PR into upstream, next stage is to prepare
the ESNI-demo PR based on upstream master and origin tag
esni-2019-08-30. The following stages appear to be necessary and
sufficient.

-   List files relevant to ESNI at tag esni-2019-08-30
-   Identify corresponding changes to be included in PR
-   Group files needing upstream changes in goal-oriented batches
-   Apply updates to the ESNI-demo branch, committing batch by batch

## Changes to be included in PR

| Scope    | Action | File                                         |
|:---------|:-------|:---------------------------------------------|
| Config   | ?      | ./configure.ac                               |
| Tool     | Update | ./docs/cmdline-opts/esni-cover.d             |
| Tool     | Update | ./docs/cmdline-opts/esni-load.d              |
| Tool     | Update | ./docs/cmdline-opts/esni-server.d            |
| Tool     | Update | ./docs/cmdline-opts/esni.d                   |
| Tool     | Update | ./docs/cmdline-opts/strict-esni.d            |
| Lib      | Update | ./docs/libcurl/curl\_easy\_setopt.3          |
| Lib      | Update | ./docs/libcurl/opts/CURLOPT\_ESNI\_ASCIIRR.3 |
| Lib      | Update | ./docs/libcurl/opts/CURLOPT\_ESNI\_COVER.3   |
| Lib      | Update | ./docs/libcurl/opts/CURLOPT\_ESNI\_SERVER.3  |
| Lib      | Update | ./docs/libcurl/opts/CURLOPT\_ESNI\_STATUS.3  |
| Lib      | Update | ./docs/libcurl/symbols-in-versions           |
| ?        | ?      | ./docs/ROADMAP.md                            |
| Tracking | None   | ./ESNI-demo-TODO.md                          |
| Obsolete | Delete | ./ESNI-FRAMEWORK-README.md                   |
| Config   | ?      | ./include/curl/curl.h                        |
| Lib      | Update | ./lib/doh.c                                  |
| Lib      | Update | ./lib/doh.h                                  |
| Lib      | Update | ./lib/esni.c                                 |
| Lib      | Update | ./lib/esni.h                                 |
| ?        | ?      | ./lib/Makefile.inc                           |
| Lib      | Update | ./lib/setopt.c                               |
| Lib      | Update | ./lib/url.c                                  |
| Lib      | Update | ./lib/urldata.h                              |
| Lib      | Update | ./lib/version.c                              |
| Lib      | Update | ./lib/vtls/openssl.c                         |
| Lib      | Update | ./lib/vtls/wolfssl.c                         |
| ?        | ?      | ./m4/curl-confopts.m4                        |
| Tool     | Update | ./src/tool\_cfgable.c                        |
| Tool     | Update | ./src/tool\_cfgable.h                        |
| Tool     | Update | ./src/tool\_getparam.c                       |
| Tool     | Update | ./src/tool\_help.c                           |
| Tool     | Update | ./src/tool\_operate.c                        |

## Batching

## Updates

