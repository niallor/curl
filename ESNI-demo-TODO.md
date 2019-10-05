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

| Action | Scope  | File                                         |
|:-------|:-------|:---------------------------------------------|
| Update | Global | ./include/curl/curl.h                        |
| Copy   | Lib    | ./docs/libcurl/opts/CURLOPT\_ESNI\_ASCIIRR.3 |
| Copy   | Lib    | ./docs/libcurl/opts/CURLOPT\_ESNI\_COVER.3   |
| Copy   | Lib    | ./docs/libcurl/opts/CURLOPT\_ESNI\_SERVER.3  |
| Copy   | Lib    | ./docs/libcurl/opts/CURLOPT\_ESNI\_STATUS.3  |
| Copy   | Lib    | ./lib/esni.c                                 |
| Copy   | Lib    | ./lib/esni.h                                 |
| Update | Lib    | ./docs/libcurl/curl\_easy\_setopt.3          |
| Update | Lib    | ./docs/libcurl/symbols-in-versions           |
| Update | Lib    | ./lib/Makefile.inc                           |
| Update | Lib    | ./lib/setopt.c                               |
| Update | Lib    | ./lib/urldata.h                              |
| Update | Lib    | ./lib/vtls/openssl.c                         |
| Copy   | Tool   | ./docs/cmdline-opts/esni-cover.d             |
| Copy   | Tool   | ./docs/cmdline-opts/esni-load.d              |
| Copy   | Tool   | ./docs/cmdline-opts/esni-server.d            |
| Copy   | Tool   | ./docs/cmdline-opts/esni.d                   |
| Copy   | Tool   | ./docs/cmdline-opts/strict-esni.d            |
| Update | Tool   | ./src/tool\_cfgable.c                        |
| Update | Tool   | ./src/tool\_cfgable.h                        |
| Update | Tool   | ./src/tool\_getparam.c                       |
| Update | Tool   | ./src/tool\_help.c                           |
| Update | Tool   | ./src/tool\_operate.c                        |

## Batching

| Batch    | Property | Detail                                       |
| :----    | :------- | :-----                                       |
| libdef   | Title    | Define libcurl options for ESNI              |
|          | Files    | (7)                                          |
|          |          | ./docs/libcurl/curl\_easy\_setopt.3          |
|          |          | ./docs/libcurl/opts/CURLOPT\_ESNI\_ASCIIRR.3 |
|          |          | ./docs/libcurl/opts/CURLOPT\_ESNI\_COVER.3   |
|          |          | ./docs/libcurl/opts/CURLOPT\_ESNI\_SERVER.3  |
|          |          | ./docs/libcurl/opts/CURLOPT\_ESNI\_STATUS.3  |
|          |          | ./docs/libcurl/symbols-in-versions           |
|          |          | ./include/curl/curl.h                        |
|          |          | <hr />                                       |
| libcode  | Title    | Implement libcurl support for ESNI           |
|          | Files    | (6)                                          |
|          |          | ./lib/Makefile.inc                           |
|          |          | ./lib/esni.c                                 |
|          |          | ./lib/esni.h                                 |
|          |          | ./lib/setopt.c                               |
|          |          | ./lib/urldata.h                              |
|          |          | ./lib/vtls/openssl.c                         |
|          |          | <hr />                                       |
| toolcode | Title    | Implement curl tool support for ESNI         |
|          | Files    | (10)                                         |
|          |          | ./docs/cmdline-opts/esni-cover.d             |
|          |          | ./docs/cmdline-opts/esni-load.d              |
|          |          | ./docs/cmdline-opts/esni-server.d            |
|          |          | ./docs/cmdline-opts/esni.d                   |
|          |          | ./docs/cmdline-opts/strict-esni.d            |
|          |          | ./src/tool\_cfgable.c                        |
|          |          | ./src/tool\_cfgable.h                        |
|          |          | ./src/tool\_getparam.c                       |
|          |          | ./src/tool\_help.c                           |
|          |          | ./src/tool\_operate.c                        |
|          |          | <hr />                                       |

## Updates

-   Commit ded2d93
    -   Files (7)
        -   docs/libcurl/curl\_easy\_setopt.3
        -   docs/libcurl/opts/CURLOPT\_ESNI\_ASCIIRR.3
        -   docs/libcurl/opts/CURLOPT\_ESNI\_COVER.3
        -   docs/libcurl/opts/CURLOPT\_ESNI\_SERVER.3
        -   docs/libcurl/opts/CURLOPT\_ESNI\_STATUS.3
        -   docs/libcurl/symbols-in-versions
        -   include/curl/curl.h
    -   Build: clean
    -   Tests: clean
    -   Demo: none (as expected)

-   Commit 81a2c59
    -   Files (6)
        -   lib/Makefile.inc
        -   lib/esni.c
        -   lib/esni.h
        -   lib/setopt.c
        -   lib/urldata.h
        -   lib/vtls/openssl.c
    -   Build: clean
    -   Tests: clean
    -   Demo: none (as expected)

-   Commit fa0f793
    -   Files (10)
        -   docs/cmdline-opts/esni-cover.d
        -   docs/cmdline-opts/esni-load.d
        -   docs/cmdline-opts/esni-server.d
        -   docs/cmdline-opts/esni.d
        -   docs/cmdline-opts/strict-esni.d
        -   src/tool\_cfgable.c
        -   src/tool\_cfgable.h
        -   src/tool\_getparam.c
        -   src/tool\_help.c
        -   src/tool\_operate.c
    -   Build: clean
    -   Tests: all clean but case 1456, likely due to IPv6 connectivity trouble
    -   Demo: postponed until better IPv6 environment available


