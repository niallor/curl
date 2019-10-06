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
-   Check for differences between ESNI-demo and master branched
-   Update and commit to resolve any such differences
-   Roll back and repackage commits as appropriate

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
    -   Tests: all clean but case 1456 due to IPv6 problem; clean when resolved
    -   Demo: clean after updating wrapper script to select desirred RRset

## Unexpected differences

-   lib/esni.c (OK: include updates since tag esni-2019-09-30)
-   lib/vtls/openssl.c (OK: include updates since esni-2019-09-30)
-   src/tool\_cfgable.h (OK: ESNI-demo is closer to upstream than master)
-   src/tool\_help.c (OK: correct obsolete use of OPENSSL\_NO\_ESNI)
-   src/tool\_operate.c (OK: ESNI-demo differs only by having ESNI code)

## Rollback/re-commit

-   Preparation:

    -   Commands:
        `git reset b902b0632d82945636d53bec325645540c4926a6`
        `git push --force`

1.   Batch:

    -   Commands:
        `git add docs/libcurl/curl_easy_setopt.3`
        `git add docs/libcurl/opts/CURLOPT_ESNI_*`
        `git add docs/libcurl/symbols-in-versions`
        `git add include/curl/curl.h`
        `git commit`
        `git push`
    -   Commit: 26f7fc1b8
    -   Files (7):
        -   docs/libcurl/curl\_easy\_setopt.3
        -   docs/libcurl/opts/CURLOPT\_ESNI\_ASCIIRR.3
        -   docs/libcurl/opts/CURLOPT\_ESNI\_COVER.3
        -   docs/libcurl/opts/CURLOPT\_ESNI\_SERVER.3
        -   docs/libcurl/opts/CURLOPT\_ESNI\_STATUS.3
        -   docs/libcurl/symbols-in-versions
        -   include/curl/curl.h
    -   Build: OK
    -   Tests: OK
    -   Demo: not attempted -- needs additional updates

2.  Batch:
    -   Commands
        `git add lib/Makefile.inc`
        `git add lib/esni.?`
        `git add lib/setopt.c`
        `git add lib/urldata.h`
        `git add lib/vtls/openssl.c`
        `git commit`
        `git push`
    -   Commit: 006af8a86
    -   Files (6):
        -   lib/Makefile.inc
        -   lib/esni.c
        -   lib/esni.h
        -   lib/setopt.c
        -   lib/urldata.h
        -   lib/vtls/openssl.c
    -   Build: OK
    -   Tests: OK
    -   Demo: not attempted -- needs additional update

3.  Batch:
    -   Commands:
        `git add docs/cmdline-opts/*esni*.d`
        `git add src/tool\_cfgable.?`
        `git add src/tool\_getparam.c`
        `git add src/tool\_help.c`
        `git add src/tool\_operate.c`
        `git commit`
        `git push`
    -   Commit: 10a59e687
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
    -   Build: OK
    -   Tests: OK, except for case 1139; OK after full clean rebuild
    -   Demo: OK

---
