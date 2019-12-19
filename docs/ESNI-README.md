# ESNI support in *curl* and *libcurl*

## Overview

The [IETF TLS Working Group](https://datatracker.ietf.org/wg/tls/about/)
has [work in progress](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/)
on **Encrypted Server Name Indication for TLS 1.3** (ESNI).

This fork contains code for ESNI support in **libcurl** and the
**curl** application; the code currently depends on development work
in an [**OpenSSL** fork](https://github.com/sftcd/openssl) which
implements ESNI as defined in IEFT drafts 2 and 3, and is expected
to implement draft 4 in the near future, as well as continuing to
track subsequent IETF work on ESNI.

## Caveat

Until completion of the ESNI work in the IETF and inclusion of ESNI
support in official **OpenSSL** and **curl** releases, all of this
work must be considered experimental.

## Progress

| Tag             | Functionality                                                                   |
|:----------------|:--------------------------------------------------------------------------------|
| esni-2019-08-30 | client-server operation, using ESNI parameters passed through from command line |
| HEAD            | use URL to determine server name                                                |
| (future)        | use DNS to determine ESNI data                                                  |

## Building and demonstrating **curl** with ESNI support

If you wish to build the code contained here and demonstrate ESNI
operation, you will need a compatible edition of an SSL/TLS library.

The developers of this fork and of the **OpenSSL** fork mentioned
above will from time to time mark compatible editions of the
respective code with a common tag identifier.

The most recent common tag identifier in use is *esni-2019-08-30*.

The commands shown below should be sufficient to build and demonstrate
**curl** with ESNI support.

-   Select a working directory and a tag identifier

    Use of a fresh temporary directory is shown in the example below.

    ```
    $ cd `mktemp -d`
    $ WORK=$PWD

    $ EDITION_TAG=esni-2019-08-30
    ```

-   Provide a subdirectory for installing packages

    ```
    $ mkdir Installed
    $ INST_DIR=$WORK/Installed
    ```

-   Clone, build, and install an edition of **OpenSSL** which supports ESNI

    ```
    $ cd $WORK
    $ git clone --branch $EDITION_TAG \
      https://github.com/sftcd/openssl
    $ cd openssl
    $ ./config --prefix=$INST_DIR
    $ make
    $ make install
    ```

-   Clone and build a matching edition of **curl** which supports ESNI

    ```
    $ cd $WORK
    $ git clone --branch $EDITION_TAG \
      https://github.com/niallor/curl
    $ cd curl
    $ ./buildconf
    $ ./configure --with-ssl=$INST_DIR \
      --enable-esni --enable-debug
    $ make
    ```

-   Optionally, run the standard *curl* test suite

    ```
    $ LD_LIBRARY_PATH=$INST_DIR/lib make test
    ```

-   Optionally, run a *curl* ESNI demo

    ```
    $ LD_LIBRARY_PATH=$INST_DIR/lib \
      $WORK/openssl/esnistuff/curl-esni \
      https://only.esni.defo.ie/stats

    ```

---
