# ESNI support in *curl* and *libcurl*

## Building and demonstrating *curl* with ESNI support

-   Select a working directory

    ```
    $ cd `mktemp -d`
    $ export WORK=$PWD
    ```

-   Provide a subdirectory for installing packages

    ```
    $ mkdir Installed
    $ export INST_DIR=$WORK/Installed
    ```

-   Clone, build, and install an edition of *OpenSSL* which supports ESNI

    ```
    $ cd $WORK
    $ git clone --branch esni-2019-08-30 \
      https://github.com/sftcd/openssl
    $ cd openssl
    $ ./config --prefix=$INST_DIR
    $ make
    $ make install
    ```

-   Optionally, run an *OpenSSL* ESNI demo

    ```
    $ cd esnistuff
    $ make
    $ TOP=$WORK/openssl ./testclient.sh -H ietf.org
    ```

-   Clone and build an edition of *curl* which supports ESNI

    ```
    $ cd $WORK
    $ git clone --branch esni-2019-08-30 \
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
