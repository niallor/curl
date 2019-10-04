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

| Action | Scope    | File                                         |
|:-------|:---------|:---------------------------------------------|
| None   | Config   | ./configure.ac                               |
| None   | Config   | ./m4/curl-confopts.m4                        |
| None   | Goals    | ./docs/ROADMAP.md                            |
| None   | Later    | ./lib/doh.c                                  |
| None   | Later    | ./lib/doh.h                                  |
| None   | Obsolete | ./ESNI-FRAMEWORK-README.md                   |
| None   | Other    | ./lib/vtls/wolfssl.c                         |
| None   | Tracking | ./ESNI-demo-TODO.md                          |
| Update | Global   | ./docs/libcurl/symbols-in-versions           |
| Update | Global   | ./include/curl/curl.h                        |
| Update | Lib      | ./docs/libcurl/curl\_easy\_setopt.3          |
| Copy   | Lib      | ./docs/libcurl/opts/CURLOPT\_ESNI\_ASCIIRR.3 |
| Copy   | Lib      | ./docs/libcurl/opts/CURLOPT\_ESNI\_COVER.3   |
| Copy   | Lib      | ./docs/libcurl/opts/CURLOPT\_ESNI\_SERVER.3  |
| Copy   | Lib      | ./docs/libcurl/opts/CURLOPT\_ESNI\_STATUS.3  |
| Update | Lib      | ./lib/Makefile.inc                           |
| Update | Lib      | ./lib/esni.c                                 |
| Update | Lib      | ./lib/esni.h                                 |
| Update | Lib      | ./lib/setopt.c                               |
| Update | Lib      | ./lib/url.c                                  |
| Update | Lib      | ./lib/urldata.h                              |
| Update | Lib      | ./lib/version.c                              |
| Update | Lib      | ./lib/vtls/openssl.c                         |
| Update | Tool     | ./src/tool\_cfgable.c                        |
| Update | Tool     | ./src/tool\_cfgable.h                        |
| Update | Tool     | ./src/tool\_getparam.c                       |
| Update | Tool     | ./src/tool\_help.c                           |
| Update | Tool     | ./src/tool\_operate.c                        |
| Copy   | Tool     | ./docs/cmdline-opts/esni-cover.d             |
| Copy   | Tool     | ./docs/cmdline-opts/esni-load.d              |
| Copy   | Tool     | ./docs/cmdline-opts/esni-server.d            |
| Copy   | Tool     | ./docs/cmdline-opts/esni.d                   |
| Copy   | Tool     | ./docs/cmdline-opts/strict-esni.d            |

## Batching

| Batch    | Category   | Detail                                        |
| :----    | :-------   | :-----                                        |
| libdef   | Title      | Define libcurl options for ESNI               |
|          | Files (7)  | ./include/curl/curl.h                         |
|          |            | ./docs/libcurl/symbols-in-versions (CURLOPT)  |
|          |            | ./docs/libcurl/curl\_easy\_setopt.3           |
|          |            | ./docs/libcurl/opts/CURLOPT\_ESNI\_ASCIIRR.3  |
|          |            | ./docs/libcurl/opts/CURLOPT\_ESNI\_COVER.3    |
|          |            | ./docs/libcurl/opts/CURLOPT\_ESNI\_SERVER.3   |
|          |            | ./docs/libcurl/opts/CURLOPT\_ESNI\_STATUS.3   |
|          |            | <hr />                                        |
| libcode  | Title      | Implement libcurl support for ESNI            |
|          | Files (8)  | ./lib/esni.c                                  |
|          |            | ./lib/esni.h                                  |
|          |            | ./lib/setopt.c                                |
|          |            | ./lib/url.c                                   |
|          |            | ./lib/urldata.h                               |
|          |            | ./lib/version.c                               |
|          |            | ./lib/vtls/openssl.c                          |
|          |            | ./lib/Makefile.inc                            |
|          |            | <hr />                                        |
| toolcode | Title      | Implement curl tool support for ESNI          |
|          | Files (11) | ./src/tool\_cfgable.c                         |
|          |            | ./src/tool\_cfgable.h                         |
|          |            | ./src/tool\_getparam.c                        |
|          |            | ./src/tool\_help.c                            |
|          |            | ./src/tool\_operate.c                         |
|          |            | ./docs/libcurl/symbols-in-versions (CURLESNI) |
|          |            | ./docs/cmdline-opts/esni-cover.d              |
|          |            | ./docs/cmdline-opts/esni-load.d               |
|          |            | ./docs/cmdline-opts/esni-server.d             |
|          |            | ./docs/cmdline-opts/esni.d                    |
|          |            | ./docs/cmdline-opts/strict-esni.d             |
|          |            | <hr />                                        |

## Updates

