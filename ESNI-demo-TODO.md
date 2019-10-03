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
| Config   | None   | ./configure.ac                               |
| Tool     | Copy   | ./docs/cmdline-opts/esni-cover.d             |
| Tool     | Copy   | ./docs/cmdline-opts/esni-load.d              |
| Tool     | Copy   | ./docs/cmdline-opts/esni-server.d            |
| Tool     | Copy   | ./docs/cmdline-opts/esni.d                   |
| Tool     | Copy   | ./docs/cmdline-opts/strict-esni.d            |
| Lib      | Update | ./docs/libcurl/curl\_easy\_setopt.3          |
| Lib      | Update | ./docs/libcurl/opts/CURLOPT\_ESNI\_ASCIIRR.3 |
| Lib      | Update | ./docs/libcurl/opts/CURLOPT\_ESNI\_COVER.3   |
| Lib      | Update | ./docs/libcurl/opts/CURLOPT\_ESNI\_SERVER.3  |
| Lib      | Update | ./docs/libcurl/opts/CURLOPT\_ESNI\_STATUS.3  |
| Global   | ?      | ./docs/libcurl/symbols-in-versions           |
| Goals    | None   | ./docs/ROADMAP.md                            |
| Tracking | None   | ./ESNI-demo-TODO.md                          |
| Obsolete | None   | ./ESNI-FRAMEWORK-README.md                   |
| Config   | ?      | ./include/curl/curl.h                        |
| Lib      | ?      | ./lib/doh.c                                  |
| Lib      | ?      | ./lib/doh.h                                  |
| Lib      | Update | ./lib/esni.c                                 |
| Lib      | Update | ./lib/esni.h                                 |
| Build    | ?      | ./lib/Makefile.inc                           |
| Lib      | Update | ./lib/setopt.c                               |
| Lib      | Update | ./lib/url.c                                  |
| Lib      | Update | ./lib/urldata.h                              |
| Lib      | Update | ./lib/version.c                              |
| Lib      | Update | ./lib/vtls/openssl.c                         |
| Other    | None   | ./lib/vtls/wolfssl.c                         |
| ?        | ?      | ./m4/curl-confopts.m4                        |
| Tool     | Update | ./src/tool\_cfgable.c                        |
| Tool     | Update | ./src/tool\_cfgable.h                        |
| Tool     | Update | ./src/tool\_getparam.c                       |
| Tool     | Update | ./src/tool\_help.c                           |
| Tool     | Update | ./src/tool\_operate.c                        |

## Batching

| Batch    | Category | Detail                                       |
| :----    | :------- | :-----                                       |
| libdef   | Title    | Define libcurl options for ESNI              |
|          | Files    | ./docs/libcurl/curl\_easy\_setopt.3          |
|          |          | ./docs/libcurl/opts/CURLOPT\_ESNI\_ASCIIRR.3 |
|          |          | ./docs/libcurl/opts/CURLOPT\_ESNI\_COVER.3   |
|          |          | ./docs/libcurl/opts/CURLOPT\_ESNI\_SERVER.3  |
|          |          | ./docs/libcurl/opts/CURLOPT\_ESNI\_STATUS.3  |
|          |          | <hr />                                       |
| libcode  | Title    | Implement libcurl support for ESNI           |
|          | Files    | ./lib/esni.c                                 |
|          |          | ./lib/esni.h                                 |
|          |          | ./lib/setopt.c                               |
|          |          | ./lib/url.c                                  |
|          |          | ./lib/urldata.h                              |
|          |          | ./lib/version.c                              |
|          |          | ./lib/vtls/openssl.c                         |
|          |          | <hr />                                       |
| toolcode | Title    | Implement curl tool support for ESNI         |
|          | Files    | ./src/tool\_cfgable.c                        |
|          |          | ./src/tool\_cfgable.h                        |
|          |          | ./src/tool\_getparam.c                       |
|          |          | ./src/tool\_help.c                           |
|          |          | ./src/tool\_operate.c                        |


## Updates

