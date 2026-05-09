  Read SCOPE.md, TODO.md, AUDIT-BACKENDS.md, and AUDIT-BUFFERS.md in full
  before touching any source file.

  This session implements the backend changes prescribed by AUDIT-BACKENDS.md.
  Work in five ordered steps. Each step must end with a clean build before the
  next step begins. Do not mix steps.

  ---
  
  ## Step 1 — Remove dead backends

  Remove all code guarded by the following preprocessor symbols. Delete the
  guards and everything inside them. Do not leave dead code or empty #ifdef
  blocks.

    USE_DB          (BerkeleyDB)
    USE_ODBX        (OpenDBX / SQL)
    USE_LDAP        (OpenLDAP)
    USE_SASL        (Cyrus SASL — only used inside USE_LDAP blocks)
    USE_LIBMEMCACHED (memcached)
    USE_ERLANG      (Erlang/OTP)

  Specific things that must be deleted entirely (not just their guards):

  In opendkim-db.c:
    - struct dkimf_db_dsn, struct dkimf_db_ldap, struct dkimf_db_erlang
    - static dkimf_db_ldap_param[] global array
    - static global DKIMF_LDAP_* macros and constants
    - DKIMF_LDAP_MAXURIS, DKIMF_LDAP_DEFTIMEOUT macros
    - ISRFC2254CHR and ADDRFC2254CHR macros
    - STRORNULL macro (only used by ODBX)
    - DB_STRERROR, DKIMF_DBCLOSE, DB_VERSION_CHECK macros (BDB compat shims)
    - Functions: dkimf_db_saslinteract, dkimf_db_open_ldap, dkimf_db_open_sql,
                 dkimf_db_mkldapquery, dkimf_db_hexdigit, dkimf_db_nextpunct,
                 dkimf_db_erl_connect, dkimf_db_erl_free,
                 dkimf_db_erl_alloc_buffer, dkimf_db_erl_decode_atom,
                 dkimf_db_erl_decode_tuple, dkimf_db_erl_decode_bitstring,
                 dkimf_db_erl_decode_int, dkimf_db_erl_decode_response
    - All switch cases for: DKIMF_DB_TYPE_BDB, DKIMF_DB_TYPE_DSN,
      DKIMF_DB_TYPE_LDAP, DKIMF_DB_TYPE_MEMCACHE, DKIMF_DB_TYPE_ERLANG
      in every function (open, get, put, delete, walk, close, strerror)
    - The OPENDKIM_DB_ONLY block that undef's USE_LDAP/USE_SASL/USE_ODBX/USE_LUA
    - References to DKIMF_DB_TYPE_REPUTE in dkimf_db_put and dkimf_db_delete

  In opendkim-db.h:
    - DKIMF_DB_TYPE_BDB, DKIMF_DB_TYPE_DSN, DKIMF_DB_TYPE_LDAP,
      DKIMF_DB_TYPE_MEMCACHE, DKIMF_DB_TYPE_ERLANG, DKIMF_DB_TYPE_REPUTE
    - All DKIMF_LDAP_PARAM_* constants and DKIMF_LDAP_PARAM_MAX
    - Any function declarations for the deleted functions above

  In the dbtypes[] table (opendkim-db.c):
    - Remove entries: "db", "dsn", "ldap", "ldapi", "ldaps", "memcache", "erlang"

  In opendkim/CMakeLists.txt:
    - Remove any detection or linkage for: libdb, libopendbx, libldap, libsasl,
      libmemcached, liberl_interface/libei
    - These were never wired in, but remove any stale comments or variables that
      reference them

  Also apply these two low-cost fixes from AUDIT-BUFFERS.md while the file is
  open (they are in shared code unrelated to any specific backend):

    B-3: opendkim-db.c:1537 — replace strncpy with strlcpy
         (change: strncpy(dbtype, name, clen)
          to:     strlcpy(dbtype, name, MIN(sizeof dbtype, (size_t)(p - name) + 1)))

  Build clean. Run ctest. No new warnings.

  ---
  
  ## Step 2 — Fix the LMDB backend

  AUDIT-BACKENDS.md Section 1 documents two bugs in the existing LMDB
  backend. Fix both.

  Bug 1 — NULL pointer dereference in dkimf_db_get (Critical):
    opendkim-db.c in the USE_MDB / DKIMF_DB_TYPE_MDB case of dkimf_db_get,
    the line:
      mdb = (struct dkimf_db_mdb *) db->db_handle;
    must become:
      mdb = (struct dkimf_db_mdb *) db->db_data;
    (db->db_handle is never set for MDB; the struct is stored in db->db_data
    at open time on opendkim-db.c:2788. db->db_close already uses db->db_data
    correctly.)

  Bug 2 — Long-lived read-write transaction blocks writers:
    In dkimf_db_open, the MDB case calls:
      mdb_txn_begin(mdb->mdb_env, NULL, 0, &mdb->mdb_txn)
    The third argument 0 opens a read-write transaction. Change it to
    MDB_RDONLY. The signing daemon only reads these databases; opening a
    read-write transaction for the lifetime of the handle blocks any external
    writer from updating the LMDB file.

  Build clean. Run ctest.
  
  ---

  ## Step 3 — Redis backend (hiredis)

  Add a Redis backend. The backend must be off by default and enabled with
  -DWITH_REDIS=ON.

  ### CMakeLists.txt (opendkim/CMakeLists.txt)

  Add an option block for hiredis, mirroring the Lua block:

    option(WITH_REDIS "Build with Redis (hiredis) backend support" OFF)
    if(WITH_REDIS)
        find_library(HIREDIS_LIBRARY NAMES hiredis)
        find_path(HIREDIS_INCLUDE_DIR NAMES hiredis/hiredis.h)
        if(NOT HIREDIS_LIBRARY OR NOT HIREDIS_INCLUDE_DIR)
            message(FATAL_ERROR "hiredis not found. Install libhiredis-dev / hiredis-devel.")
        endif()
    endif()

  In configure_daemon_target(), add:

    if(WITH_REDIS)
        target_compile_definitions(${tgt} PRIVATE USE_REDIS=1)
        target_include_directories(${tgt} PRIVATE ${HIREDIS_INCLUDE_DIR})
        target_link_libraries(${tgt} PRIVATE ${HIREDIS_LIBRARY})
    endif()

  ### opendkim-db.h
  
  Add:
    DKIMF_DB_TYPE_REDIS

  ### opendkim-db.c

  Include (inside #ifdef USE_REDIS):
    #include <hiredis/hiredis.h>

  Add struct (inside #ifdef USE_REDIS):
    struct dkimf_db_redis
    {
        redisContext *  redis_ctx;
        char *          redis_prefix;
    };

  URI scheme: redis://host:port/prefix
    - host and port are standard
    - prefix is mandatory; it is prepended to every key as "prefix:key"
    - Example: redis://127.0.0.1:6379/dkim-signing-table

  Add to dbtypes[]:
    #ifdef USE_REDIS
    { "redis", DKIMF_DB_TYPE_REDIS },
    #endif

  Implement the following in dkimf_db_open, dkimf_db_get, dkimf_db_close,
  dkimf_db_strerror, dkimf_db_walk:

    open:
      Parse "host:port/prefix" from the URI (after "redis://").
      Parse host, port (default 6379), prefix (required; everything after '/').
      Call redisConnect(host, port).
      Check ctx != NULL and ctx->err == 0; return error otherwise.
      Allocate struct dkimf_db_redis; store ctx and strdup'd prefix.
      Store struct in db->db_data. Store ctx also in db->db_handle
      (for consistency with every other backend that stores its primary
      handle in db_handle; db_data holds the full struct).

    get:
      mcs = (struct dkimf_db_redis *) db->db_data;
      Build the lookup key: snprintf(query, sizeof query, "%s:%s",
          r->redis_prefix, (char *)buf);
      Check snprintf result; return -1 on truncation.
      reply = redisCommand(r->redis_ctx, "GET %s", query);
      If reply == NULL: set db_status, return -1.
      If reply->type == REDIS_REPLY_NIL: *exists = FALSE; freeReplyObject; return 0.
      If reply->type == REDIS_REPLY_STRING:
          *exists = TRUE;
          if reqnum > 0: dkimf_db_datasplit(reply->str, reply->len, req, reqnum)
          freeReplyObject; return 0.
      Any other reply type: freeReplyObject; return -1.

    close:
      r = (struct dkimf_db_redis *) db->db_data;
      redisFree(r->redis_ctx);
      free(r->redis_prefix);
      free(r);
      free(db);
      return 0;
  
    walk:
      return -1;   /* Redis keyspace enumeration (SCAN) is not appropriate
                      for the opendkim use case */

    strerror:
      r = (struct dkimf_db_redis *) db->db_data;
      if (r->redis_ctx != NULL && r->redis_ctx->errstr[0] != '\0')
          return strlcpy(err, r->redis_ctx->errstr, errlen);
      return strlcpy(err, "Redis error", errlen);

  ### Code quality requirements for this step

    - Every snprintf call must be checked for -1 and truncation.
    - The prefix/key combined lookup string is config+external-data; truncation
      must be an error, not a silent cache miss.
    - Do not store db_status as a hiredis enum value; cast to int.

  Build clean with -DWITH_REDIS=ON. Run ctest. Build clean with
  -DWITH_REDIS=OFF. Run ctest.

  ---

  ## Step 4 — SQLite backend

  Add a SQLite backend. Off by default; enabled with -DWITH_SQLITE=ON.

  ### CMakeLists.txt
  
    option(WITH_SQLITE "Build with SQLite backend support" OFF)
    if(WITH_SQLITE)
        find_library(SQLITE3_LIBRARY NAMES sqlite3)
        find_path(SQLITE3_INCLUDE_DIR NAMES sqlite3.h)
        if(NOT SQLITE3_LIBRARY OR NOT SQLITE3_INCLUDE_DIR)
            message(FATAL_ERROR "sqlite3 not found. Install libsqlite3-dev / sqlite-devel.")
        endif()
    endif()
  
  In configure_daemon_target() add:

    if(WITH_SQLITE)
        target_compile_definitions(${tgt} PRIVATE USE_SQLITE=1)
        target_include_directories(${tgt} PRIVATE ${SQLITE3_INCLUDE_DIR})
        target_link_libraries(${tgt} PRIVATE ${SQLITE3_LIBRARY})
    endif()

  ### opendkim-db.h

  Add:
    DKIMF_DB_TYPE_SQLITE

  ### opendkim-db.c

  Include (inside #ifdef USE_SQLITE):
    #include <sqlite3.h>

  Add struct:
    struct dkimf_db_sqlite
    {
        sqlite3 *       sq_db;
        sqlite3_stmt *  sq_get;    /* prepared SELECT for dkimf_db_get */
        sqlite3_stmt *  sq_walk;   /* prepared SELECT for dkimf_db_walk */
        char            sq_keycol[BUFRSZ];
        char            sq_datacol[BUFRSZ];
        char            sq_table[BUFRSZ];
    };

  URI scheme: sqlite:/absolute/path/to/file.db?table=T&keycol=K&datacol=D
    - All three query parameters (table, keycol, datacol) are required.
    - keycol is the column looked up by the caller's key string.
    - datacol is the column(s) returned. For multi-value returns, store
      colon-separated data in the column; dkimf_db_datasplit handles splitting.

  Add to dbtypes[]:
    #ifdef USE_SQLITE
    { "sqlite", DKIMF_DB_TYPE_SQLITE },
    #endif

  Implement in dkimf_db_open, dkimf_db_get, dkimf_db_close, dkimf_db_walk,
  dkimf_db_strerror:

    open:
      Parse path and query parameters (table, keycol, datacol) from the URI.
      Call sqlite3_open_v2(path, &sq->sq_db,
                           SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, NULL).
      Check return; return -1 with error string on failure.
      Prepare the get statement:
        "SELECT <datacol> FROM <keytable> WHERE <keycol> = ?1"
      (Substitute the actual column/table names from config at prepare time;
      they come from the config file, not from mail, so this is safe.
      The ?1 placeholder binds the runtime lookup key.)
      Prepare the walk statement:
        "SELECT <keycol>, <datacol> FROM <table>"
      Store struct in db->db_data.

    get:
      sq = (struct dkimf_db_sqlite *) db->db_data;
      sqlite3_bind_text(sq->sq_get, 1, (char *)buf, buflen ? buflen : strlen(buf),
                        SQLITE_STATIC);
      rc = sqlite3_step(sq->sq_get);
      if rc == SQLITE_ROW:
          *exists = TRUE;
          val = (const char *) sqlite3_column_text(sq->sq_get, 0);
          vlen = sqlite3_column_bytes(sq->sq_get, 0);
          if reqnum > 0: dkimf_db_datasplit((char *)val, vlen, req, reqnum)
      else if rc == SQLITE_DONE:
          *exists = FALSE;
      else:
          db->db_status = rc; sqlite3_reset(sq->sq_get); return -1;
      sqlite3_reset(sq->sq_get);
      return 0;

    walk:
      sq = (struct dkimf_db_sqlite *) db->db_data;
      if first: sqlite3_reset(sq->sq_walk);
      rc = sqlite3_step(sq->sq_walk);
      if rc == SQLITE_ROW:
          copy key from column 0 into key/keylen
          copy data from column 1 via dkimf_db_datasplit
          return 0;
      if rc == SQLITE_DONE: return 1;
      db->db_status = rc; return -1;

    close:
      sq = (struct dkimf_db_sqlite *) db->db_data;
      sqlite3_finalize(sq->sq_get);
      sqlite3_finalize(sq->sq_walk);
      sqlite3_close(sq->sq_db);
      free(sq);
      free(db);
      return 0;

    strerror:
      sq = (struct dkimf_db_sqlite *) db->db_data;
      return strlcpy(err, sqlite3_errmsg(sq->sq_db), errlen);

  Build clean with -DWITH_SQLITE=ON and OFF. Run ctest both ways.

  ---
  
  ## Step 5 — PostgreSQL backend

  Add a PostgreSQL backend. Off by default; enabled with -DWITH_PGSQL=ON.

  ### CMakeLists.txt

    option(WITH_PGSQL "Build with PostgreSQL (libpq) backend support" OFF)
    if(WITH_PGSQL)
        find_package(PkgConfig QUIET)
        pkg_check_modules(LIBPQ libpq)
        if(NOT LIBPQ_FOUND)
            find_library(LIBPQ_LIBRARY NAMES pq)
            find_path(LIBPQ_INCLUDE_DIR NAMES libpq-fe.h)
            if(NOT LIBPQ_LIBRARY OR NOT LIBPQ_INCLUDE_DIR)
                message(FATAL_ERROR "libpq not found. Install libpq-dev / postgresql-devel.")
            endif()
            set(LIBPQ_LIBRARIES ${LIBPQ_LIBRARY})
            set(LIBPQ_INCLUDE_DIRS ${LIBPQ_INCLUDE_DIR})
        endif()
    endif()
  
  In configure_daemon_target() add:

    if(WITH_PGSQL)
        target_compile_definitions(${tgt} PRIVATE USE_PGSQL=1)
        target_include_directories(${tgt} PRIVATE ${LIBPQ_INCLUDE_DIRS})
        target_link_libraries(${tgt} PRIVATE ${LIBPQ_LIBRARIES})
    endif()

  ### opendkim-db.h

  Add:
    DKIMF_DB_TYPE_PGSQL

  ### opendkim-db.c

  Include (inside #ifdef USE_PGSQL):
    #include <libpq-fe.h>

  Add struct:
    struct dkimf_db_pgsql
    {
        PGconn *    pg_conn;
        char        pg_stmtname[32];   /* unique prepared statement name */
        char        pg_walksql[BUFRSZ];
        char        pg_keycol[BUFRSZ];
        char        pg_datacol[BUFRSZ];
        char        pg_table[BUFRSZ];
    };

  URI scheme: pgsql://[user[:pass]@][host][:port]/dbname?table=T&keycol=K&datacol=D
    Strip the leading "pgsql:" and pass the remainder directly to PQconnectdb()
    as a connection string — libpq parses it natively. Append the connection
    string with sslmode=prefer if not already specified. Extract table, keycol,
    datacol from the ?key=val portion before passing the rest to libpq.

  Add to dbtypes[]:
    #ifdef USE_PGSQL
    { "pgsql", DKIMF_DB_TYPE_PGSQL },
    #endif

  Implement in dkimf_db_open, dkimf_db_get, dkimf_db_close, dkimf_db_walk,
  dkimf_db_strerror:

    open:
      Parse table/keycol/datacol from ?-parameters, strip them, pass remainder
      to PQconnectdb(). Check PQstatus(conn) == CONNECTION_OK.
      Prepare a named statement (use snprintf + a counter or the db pointer
      address to make the name unique across handles):
        PQprepare(conn, stmtname,
                  "SELECT <datacol> FROM <table> WHERE <keycol> = $1",
                  1, NULL)
      (Substitute column/table names at prepare time — they come from config,
      not from mail. The $1 placeholder binds the runtime key.)
      Check PQresultStatus == PGRES_COMMAND_OK; return -1 on failure.
      Store connstr (without ?params) in pg struct if reconnect is ever needed.
      Store struct in db->db_data. Store conn in db->db_handle.

    get:
      pg = (struct dkimf_db_pgsql *) db->db_data;
      conn = (PGconn *) db->db_handle;
      const char *params[1] = { (char *) buf };
      res = PQexecPrepared(conn, pg->pg_stmtname, 1, params, NULL, NULL, 0);
      if PQresultStatus(res) != PGRES_TUPLES_OK: PQclear; return -1.
      if PQntuples(res) == 0: *exists = FALSE; PQclear; return 0.
      *exists = TRUE;
      val = PQgetvalue(res, 0, 0);
      vlen = PQgetlength(res, 0, 0);
      if reqnum > 0: dkimf_db_datasplit((char *)val, vlen, req, reqnum)
      PQclear(res);
      return 0;

    walk:
      pg = (struct dkimf_db_pgsql *) db->db_data;
      conn = (PGconn *) db->db_handle;
      If first (or db->db_cursor == NULL):
          PGresult *res = PQexec(conn, pg->pg_walksql);
          /* pg_walksql = "SELECT <keycol>,<datacol> FROM <table>" built at open */
          if PQresultStatus != PGRES_TUPLES_OK: return -1.
          store res in db->db_cursor; store row index 0 in db->db_nrecs (reuse field).
      else:
          res = (PGresult *) db->db_cursor;
          row = db->db_nrecs;
      if row >= PQntuples(res): PQclear(res); db->db_cursor = NULL; return 1.
      copy PQgetvalue(res, row, 0) → key/keylen
      copy PQgetvalue(res, row, 1) via dkimf_db_datasplit → req
      return 0;
      
    close:
      pg = (struct dkimf_db_pgsql *) db->db_data;
      if db->db_cursor != NULL: PQclear(db->db_cursor);
      PQfinish((PGconn *) db->db_handle);
      free(pg);
      free(db);
      return 0;
      
    strerror:
      return strlcpy(err, PQerrorMessage((PGconn *) db->db_handle), errlen);
      
  ### Security requirement
  
    Never construct a SQL string with the lookup key embedded in it.
    ALL runtime key data must flow through PQexecPrepared's parameter array.
    This is mandatory, not optional.
    
  Build clean with -DWITH_PGSQL=ON and OFF. Run ctest both ways.
  
  ---
  
  ## Cross-cutting requirements for all steps
  
  - Every snprintf call introduced by this session must check the return value
    for -1 and for >= sizeof(buffer). Return an error on truncation; never
    silently truncate and proceed.
  - Use strlcpy / strlcat (never strncpy / strncat) for string copies.
  - No new comments explaining what the code does. Add a comment only when
    there is a non-obvious constraint (e.g. the MDB_RDONLY rationale).
  - The build must be clean (zero warnings with the project's existing warning
    flags) after every step, not just at the end.
  - Do not touch any test file that is currently passing.
  - Do not add any new configuration file options beyond what is needed to
    specify the backend URI — the URI carries all backend-specific parameters.
