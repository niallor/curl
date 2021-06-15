# Building curl to demonstrate ECH

## Resources

- ECH-capable [OpenSSL fork][sftcd/openssl] (branch ECH-without-ESNI)

- ECH-capable [curl fork][niallor/curl] (branch ECH-WIP)

- ECH-capable [reference host][cfechdemo]

- Python3

- Python package [dnspython][rthalley/dnspython] (version 2.2 or later)

## Procedure

### Decide on directories to use, for example:

- *$HOME/repo/ECH-WIP/*:

    parent directory for local clones of git repositories

- *$HOME/build/ECH-WIP/*:

    parent directory for parallel build directories, if desired

- *$HOME/installed/ECH-WIP/*:

    directory tree to use as prefix for building and installing OpenSSL

### Make local copies of the repositories

    $ cd $HOME/repo/ECH-WIP/
    $ git clone https://github.com/sftcd/openssl
    $ git clone https://github.com/niallor/curl

### Build **OpenSSL** from the branch *ECH-without-ESNI*

    $ REPODIR=$HOME/repo/ECH-WIP/openssl
    $ cd $REPODIR
    $ git checkout ECH-without-ESNI

    $ BUILDIR=$REPODIR

The OpenSSL repository is laid out so as to facilitate using a
parallel build directory; if this is desired, give the following
command:

    $ BUILDIR=$HOME/build/ECH-WIP/openssl

Then continue.

    $ cd $BUILDIR
    $ $REPODIR/config --prefix=$HOME/installed/ECH-WIP
    $ make
    $ make install_sw

Using the target *install_sw* instead of the usual *install* saves
significant time by avoiding the formatting and installation of
the numerous documentation files.

Optionally, demonstrate ECH interworking with a demonstration host
using a wrapper script around *s_client*

    $ export TOP=$BUILDIR
    $ $REPODIR/esnistuff/echcli.sh -dN -f /cdn-cgi/trace

Output lines beginning `sni=encrypted` and `ECH: success:` give
confirmation that ECH was used.

### Build **curl** from the branch *ECH-WIP*

    $ REPODIR=$HOME/repo/ECH-WIP/curl
    $ cd $REPODIR
    $ git checkout ECH-WIP

    $ BUILDIR=$REPODIR

The *curl* repository is not arranged so as to facilitate using
a parallel build directory; if this approach is nevertheless
desired, the following three commands may be used to set it up:

    $ BUILDIR=$HOME/build/ECH-WIP/curl
    $ tar -C $REPODIR -cf - . | tar -C $BUILDIR -xpBf -
    $ chmod 0755 $BUILDIR

Then continue.

    $ cd $BUILDIR
    $ autoreconf -fi
    $ env LDFLAGS="-Wl,-rpath,$HOME/installed/ECH-WIP/lib" \
        ./configure \
        --disable-shared --enable-debug --enable-maintainer-mode \
        --with-ssl=$HOME/installed/ECH-WIP --enable-ech
    $ make

### Set up the Python3 package *dnspython*

This package is used by the wrapper script which performs SVCB
resolution and provides the ECH configuration to *curl*.

Note that a sufficiently recent version of *dnspython* is required,
which may not yet be available using *pip*.

Version 2.1.0 is not recent enough; version 2.2 is satisfactory,
as are some intermediate versions. The key indicator is the
"internal version" of dnspython.

#### Using *pip*

    $ sudo pip3 install dnspython

If *pip3* reports `Successfully installed dnspython-2.1.0`,
the package must be removed and reinstalled from the
repository.

In case of doubt, the "internal version" of the package
may be checked interactively as shown below.

    $ python3
    >>> from dns import __version__ as dnspython_version
    >>> dnspython_version
    '2.2.0dev0'
    >>> quit()
    $

If (as shown abovew) the reported version string is later than '2.2'
(in lexicograhic order), the version is expected to be suitable.

If the package must be removed, the following command is
appropriate.

    $ sudo pip3 uninstall dnspython

#### Installing the current development version of *dnspython*

This will be necessary if a suitable version is not yet
available using *pip*.

    $ cd $HOME/repo/ECH-WIP/
    $ git clone https://github.com/rthalley/dnspython
    $ cd dnspython
    $ make PYTHON=python3
    $ sudo make PYTHON=python3 install

The "internal version" of the package may be verified
as described above.

### Demonstrate interoperation between *curl* and a demonstration host

    $ cd $BUILDIR
    $ install ech-tools/svcbwrap.py3 $HOME/bin/svcbwrap

    $ $HOME/bin/svcbwrap src/curl \
        https://crypto.cloudflare.com/cdn-cgi/trace

An output line `sni=encrypted` confirms that ECH has
been used.

The wrapper script can pass the `--no-ech` option to *curl*,
disabling ECH.

    $ $HOME/bin/svcbwrap src/curl \
        --passthrough=--no-ech \
        https://crypto.cloudflare.com/cdn-cgi/trace

In this case, the demonstration host output includes the indication
`sni=plaintext`.

If desired, the wrapper script can pass the `--echpublic` option to
*curl*, over-riding the ECH.public_name component of the ECH
configuration. The effect of this will be hidden unless either the
`--verbose` option is also passed to *curl* or the packets exchanged
with the server host are captured.

    $ $HOME/bin/svcbwrap src/curl \
        --passthrough=--verbose \
        --passthrough='--echpublic any.old.example' \
        https://crypto.cloudflare.com/cdn-cgi/trace

The `--dry-run` (`-n`) option to the wrapper script causes it to
display the generated command which would be used to invoke curl.

    $ $HOME/bin/svcbwrap src/curl \
        --dry-run \
        --passthrough=--no-ech \
        https://crypto.cloudflare.com/cdn-cgi/trace

---

[cfechdemo]:     https://crypto.cloudflare.com//cdn-cgi/trace
[sftcd/openssl]: https://github.com/sftcd/openssl/
[niallor/curl]:  https://github.com/niallor/curl/
[rthalley/dnspython]: https://github.com/rthalley/dnspython
