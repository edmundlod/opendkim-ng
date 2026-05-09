# Backend Audit — OpenDKIM-ng

Audit date: 2026-05-09. No source files were modified.
Files reviewed: `opendkim/opendkim-db.c`, `opendkim/CMakeLists.txt`,
`SCOPE.md`, `TODO.md`, `AUDIT-BUFFERS.md`.

---

## Section 1 — The Abstraction Layer

### What is DKIMF_DB?

`DKIMF_DB` is an opaque pointer to `struct dkimf_db` (defined at
`opendkim-db.c:150`). The struct contains:

| Field | Type | Purpose |
|---|---|---|
| `db_flags` | `u_int` | Caller-visible flags (READONLY, ICASE, SOFTSTART, …) |
| `db_iflags` | `u_int` | Internal flags (FREEARRAY, RECONNECT) |
| `db_type` | `u_int` | Backend type constant (DKIMF_DB_TYPE_*) |
| `db_status` | `int` | Last backend-specific error code |
| `db_nrecs` | `int` | Record count (flat file / CSL only) |
| `db_lock` | `pthread_mutex_t *` | Shared or owned mutex |
| `db_handle` | `void *` | Primary library handle (DB*, odbx_t*, LDAP*, memcached_st*) |
| `db_data` | `void *` | Auxiliary data (DSN struct, LMDB struct, Lua struct, key prefix string) |
| `db_cursor` | `void *` | Cursor for `dkimf_db_walk` |
| `db_entry` | `void *` | LDAP walk: current `LDAPMessage *` entry |
| `db_array` | `char **` | Owned string array (some contexts) |

### Operations supported

| Function | Description | Backends that implement it |
|---|---|---|
| `dkimf_db_open` | Parse URI, allocate, connect | All |
| `dkimf_db_close` | Disconnect, free resources | All |
| `dkimf_db_get` | Key lookup → fill DKIMF_DBDATA array | All |
| `dkimf_db_put` | Write key/value pair | BDB, LMDB only |
| `dkimf_db_delete` | Remove key | BDB only |
| `dkimf_db_walk` | Sequential scan (cursor) | All except refile and Lua |
| `dkimf_db_type` | Return type constant | All |
| `dkimf_db_strerror` | Format backend error string | All |
| `dkimf_db_flags` | Set process-wide global flags | — |

The `DKIMF_DBDATA` array mechanism in `dkimf_db_get` allows callers to
request multiple named fields in one call. For flat-file and BDB backends
the values are colon-separated in the stored string and split by
`dkimf_db_datasplit`. For LDAP the field names are LDAP attribute names.
For SQL (ODBX) column position determines order. This design papers over
significant semantic differences between backends.

### How backends are selected

Backend selection is by **URI scheme prefix**, resolved in `dkimf_db_open`
(`opendkim-db.c:1506`):

1. Find the first `:` in the name string. If none is found, infer the type
   from the path: trailing `.db` → BDB (compile-time), leading `/` → flat
   file, otherwise → CSL.
2. Compare the extracted scheme against the `dbtypes[]` table
   (`opendkim-db.c:242`). Each entry maps a string to a
   `DKIMF_DB_TYPE_*` constant. Only entries guarded by a matching
   `#ifdef USE_*` are present at compile time.
3. Dispatch to a `switch` case in `dkimf_db_open`.

The scheme-to-type table is the only place that requires a one-line edit to
register a new name. Everything else requires adding new `switch` cases.

### Is the interface clean enough to add a new backend?

**No — adding a backend requires touching 5–7 switch statements** spread
across the file:

| Location | Required change |
|---|---|
| `opendkim-db.h` | Add `DKIMF_DB_TYPE_*` constant |
| `opendkim-db.c` includes section | `#ifdef USE_NEW / #include <newlib.h>` |
| `struct dkimf_db_*` section | New per-backend data struct |
| `dbtypes[]` table | One new entry |
| `dkimf_db_open` switch | Connection/init case |
| `dkimf_db_get` switch | Lookup case (required) |
| `dkimf_db_close` switch | Teardown case (required) |
| `dkimf_db_strerror` switch | Error-string case (required) |
| `dkimf_db_walk` switch | Cursor case (optional) |
| `dkimf_db_put` / `dkimf_db_delete` | Write/delete case (optional) |

This is workable for a small backend set but does not scale. A vtable
approach (function pointers embedded in `struct dkimf_db`) would make each
backend self-contained. See Section 5.

### Critical bug in the existing LMDB backend

**The `dkimf_db_get` MDB case (`opendkim-db.c:4079`) reads from
`db->db_handle`, but `dkimf_db_open` stores the `struct dkimf_db_mdb *` in
`db->db_data` (`opendkim-db.c:2788`). `db->db_handle` is never set for MDB
and is always NULL.**

`dkimf_db_close` uses `db->db_data` correctly (`opendkim-db.c:4313`), as
does `dkimf_db_put` (`opendkim-db.c:3209`). The get path alone is wrong.

Any call to `dkimf_db_get` on an LMDB-backed database will dereference NULL
at the first field access (`mdb->mdb_txn`) and crash the daemon. This bug
is not in AUDIT-BUFFERS.md and must be fixed before the LMDB backend is
useful.

**Fix**: change `opendkim-db.c:4079` from `db->db_handle` to `db->db_data`.

---

## Section 2 — Existing Backends

### Backend inventory table

| Backend | USE_* flag (source) | In CMakeLists.txt? | Library | Library status (2026) | Use case | Recommendation |
|---|---|---|---|---|---|---|
| Flat file / refile / CSL | None (unconditional) | Yes (unconditional) | POSIX libc | N/A — no dependency | Any table: signing table, key file, domain policy. Primary backend for most installations. | **Keep** |
| LDAP | `USE_LDAP` (+ `USE_SASL`) | **No** | OpenLDAP (`libldap`) | Actively maintained | Directory-backed signing / policy lookup | **Remove** (SCOPE.md mandates) |
| SQL via OpenDBX | `USE_ODBX` | **No** | OpenDBX (`libopendbx`) | **Dead** — last release 1.4.6 (~2012); Debian orphaned (bug #916331, 2018); uscan cannot find upstream in 2025 | SQL-backed signing/policy/key table via abstraction layer | **Remove** (SCOPE.md mandates) |
| BerkeleyDB | `USE_DB` (not `USE_BDB`/`USE_LIBDB`) | **No** | Oracle BDB (`libdb`) | **Effectively dead** — last open-source release 18.1.40 (2019); AGPL-licensed; dropped by most distributions | Binary key/value store for any table | **Remove** (SCOPE.md mandates; LMDB is replacement) |
| LMDB | `USE_MDB` | **Yes** (required; always defined `USE_MDB=1`) | LMDB (`liblmdb`) | Actively maintained by Symas/OpenLDAP project; repo updated April 2026 | Binary key/value store; crash-safe; memory-mapped; O(log n) lookup | **Keep** (core replacement for BDB) |
| memcached | `USE_LIBMEMCACHED` | **No** | libmemcached | Original upstream (`libmemcached.org`) abandoned; community "awesomized" fork active (releases through 2025–2026) | Distributed key cache (TTL-based values); remote lookup for pre-cached signing data | **Remove or replace with hiredis** |
| Erlang | `USE_ERLANG` | **No** | Erlang/OTP `erl_interface` (`liberl_interface`, `libei`) | Actively maintained within OTP; OTP 28.5 / erl_interface 5.7 released April 2026 | RPC call into a distributed Erlang node for arbitrary key lookup | **Remove** (niche; no known deployments; carries 2 Medium buffer bugs) |

### Notes on individual backends

**Flat file / refile / CSL**

The flat file backend is loaded entirely into memory at `dkimf_db_open` time
as a linked list (`struct dkimf_db_list`). All lookups are O(n) linear
scans. The refile backend compiles POSIX extended regexes at open time and
scans them linearly. CSL is a comma-separated list parsed inline. None of
these have external library dependencies.

**BerkeleyDB (flag: `USE_DB`)**

Note: the source uses `USE_DB`, not `USE_BDB` or `USE_LIBDB` as TODO.md
describes. The CMakeLists.txt does not detect or define `USE_DB`, so BDB is
**silently excluded from every build** produced by the current build system.
The code supports DB versions 1.x through 4.x via extensive `DB_VERSION_CHECK`
preprocessor guards, indicating significant historical maintenance debt.

**LDAP (flag: `USE_LDAP`)**

The LDAP implementation is the most complex backend: ~500 lines of C
including reconnect logic, SASL binding, TLS start, keepalive tuning,
RFC 2254 query escaping, and URI-list failover. A known bug exists in
`dkimf_db_mkldapquery` (`opendkim-db.c:586`): in the `else` branch for
unknown `$` escape sequences, the code writes `*q++ = *p` into `q` (a
pointer into the query source string) instead of `*o++ = *p` (the output
pointer), silently corrupting the source and producing wrong output. This is
in code that SCOPE.md has already marked for deletion.

**LMDB (flag: `USE_MDB`)**

The open path correctly creates an environment, opens a transaction, and
opens the default database. The `dkimf_db_walk` cursor is created on first
use. The `dkimf_db_put` path starts a separate read-write transaction for
each write, which is correct for LMDB. The critical bug (wrong pointer in
get) is described in Section 1.

**Erlang (flag: `USE_ERLANG`)**

The Erlang backend connects fresh to a node on every `dkimf_db_get` call
(creates a new `ei_cnode`, connects, calls `ei_rpc`, closes). There is no
persistent connection or connection pool. For a daemon processing many
messages this is extremely inefficient. The connection is authenticated with a
shared cookie but not encrypted by default.

---

## Section 3 — Modern Backends (Research Only)

### PostgreSQL (libpq)

**1. C client library**: `libpq` — yes. Ships with PostgreSQL itself, stable
API for 20+ years, actively maintained. Available as `libpq-dev` on
Debian/Ubuntu and `postgresql-devel` on Fedora/RHEL.

**2. Natural use case**: Signing table, domain/key policy store. Organisations
already running PostgreSQL for mail infrastructure (Postfix maps, quota,
virtual hosting) can store DKIM signing tables in the same database.

**3. Minimal read-only implementation**:

```
open:  parse "dsn:postgresql://user:pass@host/db?table=T&keycol=K&datacol=D"
       PQconnectdb(connstr) → check PQstatus == CONNECTION_OK
get:   PQexecParams(conn, "SELECT $datacol FROM $table WHERE $keycol = $1",
                   1, NULL, &key, NULL, NULL, 0)
       → check PGRES_TUPLES_OK → copy PQgetvalue(res,0,0) into req buffer
       → PQclear(res)
close: PQfinish(conn)
```

Use `PQexecParams` with a `$1` parameter placeholder — never string-format
the key into the query string.

**4. Effort**: **Medium**. Parameterized queries are straightforward.
Connection management for a multi-threaded daemon requires care (one
connection per thread or a mutex-protected single connection; a pool
would be `_FFR_DB_HANDLE_POOLS` territory).

---

### MySQL / MariaDB (libmysqlclient / MariaDB Connector/C)

**1. C client library**: Both `libmysqlclient` (MySQL) and MariaDB
Connector/C provide a C API with stable, long-lived interfaces. Both are
actively maintained. They share an API lineage but diverge in newer
features.

**2. Natural use case**: Same as PostgreSQL — signing table, policy store.
Relevant for organisations whose mail infrastructure is already MySQL/MariaDB
backed (cPanel stacks, ISP-grade Postfix setups).

**3. Minimal read-only implementation**:

```
open:  parse DSN; mysql_init(NULL) → mysql_real_connect(...)
get:   mysql_stmt_init + mysql_stmt_prepare("SELECT col FROM t WHERE key=?")
       → mysql_stmt_bind_param(key) → mysql_stmt_execute()
       → mysql_stmt_bind_result → mysql_stmt_fetch → copy value
close: mysql_close(conn)
```

**4. Effort**: **Medium**. Two competing libraries (MySQL vs MariaDB) means
potentially maintaining two codepaths or accepting one as canonical.
If SQL backends are added at all, prefer PostgreSQL (one stable library,
cleaner API, parameterized query semantics are clearer).

---

### SQLite (sqlite3 — embedded, zero daemon dependency)

**1. C client library**: `sqlite3` — yes. Single-file amalgamation,
extremely stable API (the SQLite project guarantees backwards compatibility
to 2050), actively maintained, ships in every Linux/BSD/macOS distribution.
No separate daemon process.

**2. Natural use case**: Local signing table or key database. The natural
O(log n) indexed replacement for the flat file backend, with full SQL query
capability, atomic updates, and no process dependency. Particularly useful
for large signing tables (thousands of domains) where O(n) flat-file scans
are slow.

**3. Minimal read-only implementation**:

```
open:  sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, NULL)
       sqlite3_prepare_v2(db, "SELECT val FROM t WHERE key=?1", -1, &stmt, NULL)
get:   sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC)
       sqlite3_step(stmt) → SQLITE_ROW → sqlite3_column_text(stmt, 0)
       → strlcpy into req buffer
       sqlite3_reset(stmt)
close: sqlite3_finalize(stmt); sqlite3_close(db)
```

The prepared statement can be cached in `db_data` and reused across get
calls (thread-safe with `SQLITE_OPEN_FULLMUTEX`).

**4. Effort**: **Small**. SQLite has the simplest API of any SQL engine.
No authentication, no network, no connection management. A complete
read-only implementation would be approximately 100–150 lines.

---

### MongoDB (libmongoc)

**1. C client library**: `libmongoc` (mongo-c-driver) — yes, maintained by
MongoDB Inc. Version 2.3.0 current (2026). Requires `libbson` as a
companion. API is relatively stable; v1.x is deprecated. Large and complex
dependency tree.

**2. Natural use case**: Key/policy store in organisations already using
MongoDB. The document model does not map naturally to the key-value pair
that opendkim uses — it would require selecting a collection, querying by
domain field, and extracting BSON sub-fields. Technically possible but
architecturally awkward.

**3. Minimal read-only implementation**:

```
open:  mongoc_client_new(uri_string) → mongoc_client_get_collection(...)
get:   bson_t *filter = BCON_NEW("key", BCON_UTF8(key));
       mongoc_cursor_t *cur = mongoc_collection_find_with_opts(coll, filter, NULL, NULL);
       mongoc_cursor_next(cur, &doc) → bson_iter_find(&iter, "value")
       → bson_iter_utf8 → copy into req buffer
close: mongoc_client_destroy(client)
```

**4. Effort**: **Large**. The `libbson` + `libmongoc` dependency pair is a
significant addition (large CMake integration, BSON type handling adds
complexity). The use case is ill-served by a document store. Not recommended.

---

### Redis (hiredis — replacement for memcached)

**1. C client library**: `hiredis` — yes. Maintained by the Redis/Valkey core
team. Version 1.3 (2025), stable API (the `redisCommand` / `redisConnect`
surface has been stable for many years). Available as `libhiredis-dev` /
`hiredis-devel` on all major distributions.

**2. Natural use case**: Direct functional replacement for the memcached
backend. Distributed key lookup from a Redis/Valkey cluster. Also useful as
a signing table source in organisations that use Redis as their central
configuration store (common in container-based mail infrastructure).
More widely deployed than memcached in modern environments.

**3. Minimal read-only implementation**:

```
open:  parse "redis://host:port/prefix" → redisConnect(host, port)
       store prefix string in db_data
get:   snprintf(query, sizeof query, "GET %s:%s", prefix, (char *)key)
       redisCommand(ctx, "GET %s:%s", prefix, key)  → check reply->type
       REDIS_REPLY_STRING → strlcpy(req[0].dbdata_buffer, reply->str, ...)
       REDIS_REPLY_NIL    → *exists = FALSE
       freeReplyObject(reply)
close: redisFree(ctx)
```

Hash-style lookups (`HGET`, `HMGET`) could retrieve multiple fields in one
round-trip, mapping cleanly to the `DKIMF_DBDATA` array.

**4. Effort**: **Small**. The hiredis API is nearly as simple as the existing
memcached backend. Approximately 100 lines for a complete read-only
implementation. A natural first candidate if any new backend is added.

---

## Section 4 — AUDIT-BUFFERS.md Cross-Reference

### Findings in backend code

All findings from AUDIT-BUFFERS.md that fall inside `opendkim/opendkim-db.c`:

| Finding | Line(s) | Backend | Risk | Notes |
|---|---|---|---|---|
| B-1 | 1300–1302 | **Erlang** | Medium | `n = snprintf(...); req[0].dbdata_buflen = n + 1` — `n` not checked for -1 or truncation before use as a buffer-length value |
| B-2 | 1370–1371 | **Erlang** | Medium | Identical structural issue: `n = snprintf(key, *keylen, ...); *keylen = n + 1` |
| B-3 | 1537 | Shared parsing (dkimf_db_open) | Low | `strncpy(dbtype, name, clen)` with pre-zeroed buffer — safe in practice, misleading style; no backend-specific |
| B-4 | 3649–3655 | **ODBX** (dkimf_db_get) | Low | `snprintf(query, sizeof query, "SELECT ... WHERE ... = '%s'...", escaped)` — no truncation check |
| B-5 | 4021 | **memcached** (dkimf_db_get) | Low | `snprintf(query, sizeof query, "%s:%s", key, buf)` — no truncation check |
| B-6 | 4611–4613 | **ODBX** (dkimf_db_walk) | Low | `snprintf(query, sizeof query, "SELECT %s,%s FROM %s", ...)` — no truncation check |

**Total: 6 findings (2 Medium, 4 Low) in backend code.**

The remaining AUDIT-BUFFERS.md findings are in `libopendkim/` or in
`opendkim/opendkim.c`, `opendkim-ar.c`, and `util.c` — not in backend code.

### Findings that disappear automatically on backend removal

| Backend removed | Findings eliminated | Net effect |
|---|---|---|
| Erlang | B-1 (Medium), B-2 (Medium) | Both Medium findings in opendkim-db.c gone |
| ODBX | B-4 (Low), B-6 (Low) | Two Low findings gone |
| memcached | B-5 (Low) | One Low finding gone |
| BerkeleyDB | None | No AUDIT-BUFFERS.md findings in BDB code |
| LDAP | None | No AUDIT-BUFFERS.md findings in LDAP code |

**Removing Erlang, ODBX, and memcached eliminates all 5 backend-specific
findings and leaves only B-3 (the strncpy style issue in shared
URL-scheme parsing code).**

### Additional finding not in AUDIT-BUFFERS.md

**NULL pointer dereference in LMDB `dkimf_db_get` (Critical)**

`opendkim-db.c:4079`: `mdb = (struct dkimf_db_mdb *) db->db_handle`

`db->db_handle` is never assigned for MDB; the struct is stored in
`db->db_data` at open time (`opendkim-db.c:2788`). Every call to
`dkimf_db_get` on an LMDB handle will dereference NULL and crash the daemon.
This bug is not in AUDIT-BUFFERS.md because AUDIT-BUFFERS.md covers
buffer-handling patterns only. The fix is a one-line change.

---

## Section 5 — Recommendations

### Existing backends: remove

| Backend | Reason |
|---|---|
| BerkeleyDB (`USE_DB`) | Already silently excluded from the build (CMakeLists.txt has no `USE_DB` definition). SCOPE.md mandates removal. Oracle AGPL licence incompatible with many distro policies. ~200 lines of version-compat machinery for ancient DB versions 1–4. Delete all `#ifdef USE_DB` blocks. |
| LDAP (`USE_LDAP`) | SCOPE.md mandates removal. LDAP directory lookup is wrong architecture for a signing daemon. The implementation (~500 lines) contains a known pointer bug in `dkimf_db_mkldapquery`. Delete all `#ifdef USE_LDAP` and `#ifdef USE_SASL` blocks. |
| SQL via OpenDBX (`USE_ODBX`) | SCOPE.md mandates removal. OpenDBX upstream is dead (last release ~2012, Debian orphaned 2018). Carries 2 Low buffer bugs (B-4, B-6). Delete all `#ifdef USE_ODBX` blocks. |
| Erlang (`USE_ERLANG`) | Not wired into CMake. No known production deployments. Opens a fresh network connection on every lookup (prohibitively slow). Carries the 2 highest-risk buffer bugs in the file (B-1, B-2 — Medium). The Lua backend provides a cleaner and more flexible remote-lookup mechanism. Delete all `#ifdef USE_ERLANG` blocks. |
| memcached (`USE_LIBMEMCACHED`) | Not wired into CMake. Original libmemcached upstream is dead. The use case is better served by Redis/hiredis (more modern, more widely deployed). Carries 1 Low buffer bug (B-5). Delete and replace with a hiredis backend if caching is needed. |

### Modern backends: implementation order

**1. SQLite (small effort — implement first)**

Zero daemon dependency, single-file database, O(log n) indexed lookup.
The most compelling new backend: it directly replaces the flat file backend
for large signing tables without requiring any server infrastructure. A
complete read-only implementation is approximately 100–150 lines. URI scheme
suggestion: `sqlite:/path/to/db.sqlite?table=T&keycol=K&datacol=D`. Introduce
as `-DWITH_SQLITE=ON` (default OFF until tested).

**2. Redis / hiredis (small effort — implement second)**

Direct replacement for the memcached use case. hiredis has a clean, stable
API. Approximately 100 lines for a complete read-only implementation. URI
scheme: `redis://host:port/prefix` or `redis:///path/to/socket/prefix`.
Covers the distributed key-cache use case without pulling in a dead library.
Introduce as `-DWITH_REDIS=ON` (default OFF).

**3. PostgreSQL / libpq (medium effort — implement third, if SQL is needed)**

For organisations that already maintain PostgreSQL for mail infrastructure.
Medium effort primarily because of connection management in a threaded daemon.
If implemented, use `PQexecParams` with parameterized queries; never
string-format the lookup key into the query. URI scheme: reuse the existing
`dsn:postgresql://...` scheme (without OpenDBX), or a new `pgsql://` scheme.

**Not recommended now**:

- **MySQL/MariaDB**: Two competing libraries; split ecosystem. If SQL is
  needed, PostgreSQL covers the use case more cleanly. Defer indefinitely.
- **MongoDB**: Large dependency, document model poorly suited to key-value
  lookup. Not recommended.

### Abstraction layer: refactoring recommendation

**Defer vtable refactoring until after backend removal.**

The current switch-statement approach is workable at the current scale
(3 backends after removal: flat file/refile/CSL, LMDB, Lua). Adding SQLite
and Redis would bring the total to 5, which is still manageable.

If more than 5–6 backends are ever active simultaneously, consider replacing
the switch statements with a vtable (`struct dkimf_db_ops` with function
pointers for `open`, `get`, `close`, `walk`, `put`, `strerror`). This would
let each backend be a self-contained `.c` file with no changes needed to
shared code.

**Do not refactor before removing dead backends** — there is no point
investing in a cleaner abstraction over code that is about to be deleted.

**Fix the LMDB NULL pointer dereference first** (one-line fix at
`opendkim-db.c:4079`) — the primary mandated backend is currently broken.

### Security concerns with the current backend interface

**1. No key sanitisation at the abstraction boundary**

`dkimf_db_get` receives a key derived from email headers (the sender domain,
the selector string, or other external data) and passes it directly to each
backend. The abstraction layer performs no validation or escaping. Each
backend must handle this independently:

- Flat file / refile / CSL: safe (only string comparison and regex match)
- LMDB: safe (binary key-value store; no query language)
- ODBX: uses `odbx_escape()` (fragile; see below)
- LDAP: uses `dkimf_db_mkldapquery` RFC 2254 escaping (buggy; see Section 2)

**2. ODBX SQL injection risk**

The ODBX backend constructs queries using `odbx_escape()` followed by
`snprintf` embedding the escaped value as a string literal:

```c
snprintf(query, sizeof query,
         "SELECT %s FROM %s WHERE %s = '%s'...", ..., escaped, ...);
```

This is the classic fragile "escape and embed" pattern. If `odbx_escape`
has any edge case (multi-byte character sequences, NULL bytes), SQL injection
remains possible. The correct approach is parameterized queries, which OpenDBX
does not support. This is an argument for removing ODBX rather than fixing it.

**3. No transport security enforcement for network backends**

The memcached backend has no authentication or TLS. The LDAP backend makes
TLS optional via a config flag (`DKIMF_LDAP_PARAM_USETLS`). The Erlang
backend uses the Erlang distribution cookie for authentication but no
encryption by default. An attacker with network access to these services can
inject arbitrary signing table entries, causing the daemon to sign mail with
attacker-chosen keys or selectors.

**4. Erlang distribution protocol trust model**

The Erlang cookie mechanism is authentication-by-shared-secret, not
cryptographic. A compromised node on the network can read the cookie from the
Erlang process and then send malicious RPC responses. The
`dkimf_db_erl_decode_response` parser trusts whatever the node returns. This
is a fundamentally unsafe trust model for a daemon that controls mail signing.

**5. LMDB: no read-isolation between open and get**

The LMDB backend opens a read-write transaction at `dkimf_db_open` time
(`mdb_txn_begin` with flags `0`, not `MDB_RDONLY`) and holds it open for the
lifetime of the handle. This is non-standard use of LMDB: a long-lived
read-write transaction that is never committed blocks writers. The correct
pattern is to open a `MDB_RDONLY` transaction (or use `MDB_NOTLS` with
per-operation transactions). Fix alongside the NULL pointer bug.

---

*End of audit. No source files were modified.*
