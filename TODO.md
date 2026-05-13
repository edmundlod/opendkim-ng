/home/builder/projects/opendkim-ng/opendkim/opendkim.c: In function ‘mlfi_eom’:
/home/builder/projects/opendkim-ng/opendkim/opendkim.c:12408:47: warning: ‘%s’ directive output may be truncated writing up to 4096 bytes into a region of size 4073 [-Wformat-truncation=]
12408 |                                          "%s: %s",
      |                                               ^~
In file included from /usr/include/stdio.h:970,
                 from /home/builder/projects/opendkim-ng/opendkim/opendkim.c:42:
In function ‘snprintf’,
    inlined from ‘mlfi_eom’ at /home/builder/projects/opendkim-ng/opendkim/opendkim.c:12407:5:
/usr/include/x86_64-linux-gnu/bits/stdio2.h:68:10: note: ‘__builtin___snprintf_chk’ output between 25 and 4121 bytes into a destination of size 4097
   68 |   return __builtin___snprintf_chk (__s, __n, __USE_FORTIFY_LEVEL - 1,
      |          ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   69 |                                    __glibc_objsize (__s), __fmt,
      |                                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   70 |                                    __va_arg_pack ());
      |                                    ~~~~~~~~~~~~~~~~~

========================


## Database backends — full audit and modernisation

### Phase 1 — audit (Sonnet, no code changes)

Produce AUDIT-BACKENDS.md covering:

**Existing backends in opendkim-db.c — for each, document:**
- What it actually does (key lookup? policy lookup? signing table?
  all of the above?)
- Which CMake USE_* flag gates it
- Whether it is wired into the current CMakeLists.txt or silently
  excluded
- Upstream library status (maintained/abandoned/forked)
- Real-world deployment relevance in 2026

**Backends to assess:**
- Flat file / refile (always present)
- LDAP (`USE_LDAP`) — already on SCOPE removal list; confirm status
- SQL via OpenDBX (`USE_ODBX`) — already on SCOPE removal list
- BerkeleyDB (`USE_BDB` / `USE_LIBDB`)
- LMDB (`USE_MDB`)
- memcached (`USE_LIBMEMCACHED`)
- Erlang (`USE_ERLANG`)

**Modern backends — research only, no implementation yet:**
- PostgreSQL — native libpq, no OpenDBX wrapper
- MySQL/MariaDB — native connector
- SQLite — embedded, zero-daemon dependency
- MongoDB — libmongoc
- Redis — hiredis; would replace memcached use case

For each modern backend answer:
- Is there a C client library with a stable API and active upstream?
- What is the natural opendkim use case (signing table? key cache?
  policy store?)
- What would a minimal read-only implementation look like?

**Also document:**
- What dkimf_db_get / dkimf_db_open / dkimf_db_close actually
  abstract — is the interface clean enough to add new backends
  without touching existing code?
- Whether the current abstraction layer needs refactoring before
  new backends are added

### Phase 2 — decision (after reading AUDIT-BACKENDS.md)

Remove dead/abandoned backends. Decide which modern backends
are worth implementing. Design first, then implement.

========================

USE_REDIS not reported in `opendkim -V` output. The `-V` code in opendkim/opendkim.c
has `#ifdef` blocks for USE_LUA, USE_MDB, USE_UNBOUND but none for USE_REDIS.
Add a `#ifdef USE_REDIS` printf to the version output so Redis support is visible.

========================

Configure COPR for RPM builds (Fedora/RHEL/CentOS/AlmaLinux).
Set up a .spec file and wire the CI to dispatch to COPR on tag push,
similar to the Debian apt dispatch step.

========================

Go through all the issues at https://github.com/trusteddomainproject/OpenDKIM/issues and see if any apply to our version.

Also look at distro's (Fedora, OpenSUSE, Debian, Gentoo, e.a.) that might have created their own patches. Something useful for us?

Debian (debian/ package config as well as patches):
https://salsa.debian.org/debian/opendkim/-/tree/master/debian?ref_type=heads

https://codeberg.org/gentoo/gentoo/src/branch/master/mail-filter/opendkim/files
For OpenRC:
https://codeberg.org/gentoo/gentoo/src/branch/master/mail-filter/opendkim/files/opendkim-2.10.3-openrc.patch

https://www.freshports.org/mail/opendkim/
https://codeberg.org/FreeBSD/freebsd-ports/src/branch/main/mail/opendkim/files
FreeBSD rc.conf:
https://codeberg.org/FreeBSD/freebsd-ports/src/branch/main/mail/opendkim/files/milter-opendkim.in

https://github.com/openbsd/ports/tree/master/mail/opendkim
OpenBSD rc.conf
https://github.com/openbsd/ports/blob/master/mail/opendkim/pkg/opendkim.rc
