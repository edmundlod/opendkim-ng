Read AUDIT-BUFFERS.md in full before touching any code.

  Your job is to apply every fix described in that document. Work through
  the priority levels in order. Do not modify any file under
  libopendkim/tests/ or opendkim/tests/ — test files are frozen.

  ---

  ## Phase 1 — Medium-risk fixes (do these one file at a time)

  Fix all six Medium-risk findings. After editing each file, run:

    cmake --build build && ctest --test-dir build -j$(nproc)

  and confirm it is clean before moving to the next file.

  ### 1. libopendkim/dkim.c — dkim_get_sigsubstring (line ~7954)

  The strncpy does not NUL-terminate when minlen == *buflen.
  Replace the block:

    minlen = MIN(*buflen, dkim->dkim_minsiglen);
    strncpy(buf, b1, minlen);
    if (minlen < *buflen)
        buf[minlen] = '\0';
    *buflen = minlen;

  with:

    minlen = MIN(*buflen > 0 ? *buflen - 1 : 0, dkim->dkim_minsiglen);
    strncpy(buf, b1, minlen);
    buf[minlen] = '\0';
    *buflen = minlen;

  This guarantees NUL termination and preserves the existing API
  semantics (*buflen on return = bytes written, excluding NUL).

  ### 2. libopendkim/dkim-cache.c — dkim_cache_query (line ~234)

  After strlcpy, set *buflen to the number of bytes actually in buf,
  not to strlen of the source:

    strlcpy(buf, ce.cache_data, *buflen);
    *buflen = strlen(buf);           /* bytes actually present, NUL-safe */

  ### 3. libopendkim/dkim-report.c — dkim_repinfo (line ~97)

  Add a truncation check using the same pattern as dkim-keys.c:106:

    int n = snprintf((char *)query, sizeof query, "%s.%s",
                     DKIM_REPORT_PREFIX, (char *)sdomain);
    if (n < 0 || (size_t)n >= sizeof query)
        return DKIM_STAT_INVALID;

  ### 4. opendkim/opendkim-ar.c — ares_parse host accumulation (lines ~430, 444)

  For each of the two strlcat calls that build ares_host, check the
  return value and return -1 on overflow:

    if (strlcat((char *)ar->ares_host, (char *)tokens[c],
                sizeof ar->ares_host) >= sizeof ar->ares_host)
        return -1;
  
  ### 5 & 6. opendkim/opendkim-db.c — Erlang backend (lines ~1300 and ~1370)

  Both sites store the snprintf result directly into a buffer-length
  field without validation. Fix both with the same pattern:

    n = snprintf(req[0].dbdata_buffer, req[0].dbdata_buflen, "%ld", val);
    if (n < 0 || (size_t)n >= req[0].dbdata_buflen)
        return -1;
    req[0].dbdata_buflen = (size_t)n + 1;

  Apply identically to line ~1370 (the *keylen variant).

  ---
  
  ## Phase 2 — Low-risk cleanup (single pass across all files)

  Do this only after Phase 1 is green.
  
  ### A. Wrong truncation check — opendkim/util.c lines ~453 and ~485

  Replace `if (sz >= sizeof ipbuf)` with the correct remaining-space check:

    if (sz < 0 || (size_t)sz >= dst_len)
        return FALSE;

  ### B. strncpy with pre-zeroed buffer — opendkim/opendkim-db.c line ~1537

  Replace strncpy with strlcpy for consistency with project idiom:

    strlcpy(dbtype, name, MIN(sizeof dbtype, (size_t)(p - name) + 1));

  ### C. snprintf on SQL/memcached query buffers — opendkim/opendkim-db.c
     lines ~3649, ~4021, ~4611

  These are backends slated for removal per SCOPE.md, but they exist
  now and silently truncated SQL will just fail mysteriously. Add a
  check and return an error:

    int n = snprintf(query, sizeof query, ...);
    if (n < 0 || (size_t)n >= sizeof query)
        return error_value;   /* use whatever the existing error return is */
  ### D. snprintf on error-message paths — opendkim/opendkim.c and
     opendkim/opendkim-db.c (the many snprintf(err, errlen, ...) calls)
     
  For all callers that write purely into an err/error string buffer
  (dkimf_checkfsnode, dkimf_config_load, etc.) and where truncated
  messages are acceptable, add a (void) cast to document intent and
  silence static-analysis warnings:
  
    (void)snprintf(err, errlen, "...", ...);
    
  ### E. strlcpy/strlcat on auth-result reason/value/property fields
     opendkim/opendkim-ar.c lines ~531, ~572, ~620, ~643
     
  These are lower-stakes fields (logged strings, not policy inputs).
  Add (void) casts:
  
    (void)strlcpy((char *)ar->ares_result[n-1].result_reason, ...);
    
  ### F. opendkim/opendkim.c:3474 tight-fit snprintf
  
  Cast to void — the size arithmetic is correct but should be explicit:
  
    (void)snprintf(header, sizeof header, "rfc822;%s", a->a_addr);
    
  ---
  
  ## Definition of done
  
  - cmake --build build succeeds with no new warnings.
  - ctest --test-dir build passes 100%.
  - No test file under libopendkim/tests/ or opendkim/tests/ was modified.
  - git diff --stat shows changes only in the files named above. 
  
  If you encounter a finding that conflicts with the fix plan (e.g. the
  surrounding code changed since the audit), stop and describe the
  conflict rather than guessing. 

  ---
  A few notes on using this:
  
  - Build directory: the prompt assumes build/ at the repo root (matching the existing CMake setup). If yours differs, adjust the cmake paths.
  - Opus vs Sonnet: Opus is worth it here — Phase 2 touches ~50 call-sites scattered across large files; Opus is less likely to get confused about which instance to edit or to conflate two
  similar patterns.
  - One session: keep everything in one session so the model remembers that Phase 1 passed before starting Phase 2. If you have to restart, prefix with "Phase 1 is already done and tests
  are green; begin at Phase 2."
