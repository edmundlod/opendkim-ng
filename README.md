# OpenDKIM

OpenDKIM is a community effort to develop and maintain an open source
library for producing DKIM-aware applications, and a milter-based filter
for providing DKIM signing and verification service to mail servers.

This is the modernised **opendkim-ng** fork of the original
[trusteddomainproject/OpenDKIM](https://github.com/trusteddomainproject/OpenDKIM),
updated for current cryptographic standards, a modern build system, and
actively maintained dependencies.

## What's New in 3.0

- **OpenSSL 3** — all cryptography ported to the EVP high-level API
- **Ed25519** — signing and verification per RFC 8463
- **LMDB** — replaces unmaintained BerkeleyDB for key storage
- **CMake** — replaces autoconf/automake
- **Lua 5.4** — updated from Lua 5.1
- Removed: VBR, ATPS, RBL, reputation subsystems, LDAP, SQL/OpenDBX,
  GnuTLS, BerkeleyDB, `diffheaders` (tre dependency)
- RSA-SHA1 signing dropped; RSA-SHA1 verification retained for
  interoperability with legacy signed mail
- Minimum RSA signing key size: 2048 bits

## Dependencies

To build the library and filter you will need:

- A C17-capable compiler (GCC 8+ or Clang 5+)
- CMake >= 3.20
- OpenSSL >= 3.0
- LMDB
- libmilter (from Sendmail or as a standalone package)
- libresolv

Optional:

- Lua 5.4 — policy scripting hooks (`-DWITH_LUA=ON`)
- libunbound — DNSSEC-aware DNS resolution (`-DWITH_UNBOUND=ON`)
- libbsd — provides `strlcpy`/`strlcat` on systems without them
  (not needed on glibc 2.38+, FreeBSD, or OpenBSD)

### Debian / Ubuntu

```
apt install build-essential cmake libssl-dev liblmdb-dev \
            libmilter-dev liblua5.4-dev
```

### RHEL / AlmaLinux / Rocky

```
dnf install gcc cmake openssl-devel lmdb-devel sendmail-devel lua-devel
```

### FreeBSD

```
pkg install cmake openssl lmdb milter lua54
```

## Building

```
cmake -B build
cmake --build build
ctest --test-dir build
```

Common build options:

| Option | Default | Description |
|---|---|---|
| `-DWITH_LUA=ON` | OFF | Enable Lua 5.4 policy scripting |
| `-DWITH_UNBOUND=ON` | ON | Enable libunbound DNSSEC resolver |
| `-DCMAKE_BUILD_TYPE=Release` | `RelWithDebInfo` | Build type (Debug/Release/RelWithDebInfo/MinSizeRel) |

To install:

```
cmake --install build
```

## Configuration

See `opendkim.conf(5)` for the full list of configuration options.
A sample configuration file, which needs editing, is installed at
`/usr/share/doc/opendkim-ng/opendkim.conf.sample`.

For an example on using multiple signatures per e-mail (e.g. Ed25519 with
an RSA key as fall-back), see `docs/multisigning.md`.

The filter integrates with Postfix and Sendmail via the milter protocol.
For Postfix, add to `main.cf`:

```
smtpd_milters = unix:/run/opendkim/opendkim.sock
non_smtpd_milters = unix:/run/opendkim/opendkim.sock
milter_default_action = accept
```

A systemd service unit is included and installed automatically.

## Key Generation

_Note: Run the following in the directory where you want your keys, e.g.
`/etc/dkimkeys/domain.com/`, or move the files after generating them._

Generate an RSA-2048 or Ed25519 signing keypair with `opendkim-genkey`:

```
# RSA
opendkim-genkey -b 2048 -d domain.com -s selector

# Ed25519
opendkim-genkey -t ed25519 -d domain.com -s selector
```

## Platforms

- Linux (glibc 2.17+)
- FreeBSD 13+
- OpenBSD 7+

## Documentation

Man pages are installed for `opendkim(8)`, `opendkim.conf(5)`,
`opendkim-genkey(8)`, `opendkim-genzone(8)`, `opendkim-testkey(8)`,
`opendkim-testmsg(8)`, and `opendkim-lua(3)`.

RFC and draft reference documents are in the `docs/` directory.

## Known Runtime Issues

### WARNING: symbol 'X' not available

The filter attempted to read an MTA macro that the MTA did not provide.
For Postfix, ensure the relevant macros are configured. For Sendmail,
regenerate `sendmail.cf` from your M4 configuration.

### MTA Timeouts

DNS queries for key records may exceed the default MTA milter timeout.
Increase `milter_timeout` in Postfix, or the milter timeout in Sendmail
if you encounter this.

### EVP key decode failures

A public key record was retrieved but could not be decoded. Possible
causes: memory exhaustion, or a corrupted or malformed key record in
DNS. If using tempfail mode the sender will retry; a repeated failure
indicates a problem with the published key.

### Sendmail Header Rewriting

If you use Sendmail's `MASQUERADE_AS` or `FEATURE(genericstable)`,
opendkim signs headers before Sendmail rewrites them. The verifying
side will see rewritten headers that do not match the signature.
Solutions: disable the rewriting features, use a two-MTA setup where
the signing MTA does no rewriting, or use multiple `DaemonPortOptions`
entries to separate rewriting from signing.

## Licence

The licence for this package is in the `LICENSE` file. Portions of
the code originating from Sendmail are covered by the Sendmail Open
Source Licence, found in `LICENSE.Sendmail`. See the copyright notice
in each source file for which licence(s) apply.

## Legal notice
A number of legal regimes restrict the use or export of cryptography. If you are potentially subject to such restrictions you should seek legal advice before using, developing, or distributing cryptographic code.

## Bugs and Contributions

Please report bugs and submit contributions via GitHub:

https://github.com/edmundlod/opendkim-ng
