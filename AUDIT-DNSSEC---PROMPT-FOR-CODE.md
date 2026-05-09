Model: Sonnet. The fixes are surgical and well-specified — no architectural reasoning needed. Opus is overkill here and the C changes are straightforward enough that Sonnet won't drift.

  Here is the prompt:

  ---

  Read AUDIT-DNSSEC.md in full before touching any file.

  Fix the five defects listed below, in this order. Stop after each one and
  verify the build is clean before proceeding to the next. Do not touch any
  file in libopendkim/tests/ for any reason.

  ## Fix 1 — bogus callback (AUDIT-DNSSEC.md §5 Bug 1)
  File: opendkim/opendkim-dns.c, function dkimf_unbound_cb (~line 189)

  In the `result->bogus` branch, before the early return:
    - call ub_resolve_free(result)
    - set ubdata->ubd_done = TRUE

  The existing code at the end of the function (ub_resolve_free + ubd_done = TRUE)
  handles the secure and insecure cases; the bogus branch must reach the same
  terminal state. Do not restructure the function beyond this.

  ## Fix 2 — Auth-Results insecure label (AUDIT-DNSSEC.md §5 Bug 3)
  File: opendkim/opendkim.c, function dkimf_add_ar_fields (~line 9584)

  Change:
    dnssec = "unprotected";
  To:
    dnssec = "insecure";

  One line. Nothing else in this function changes.

  ## Fix 3 — syslog warning for bogus (AUDIT-DNSSEC.md §5 Bug 4)
  File: opendkim/opendkim.c, DKIM_DNSSEC_BOGUS case in dkimf_add_ar_fields

  Add a syslog(LOG_WARNING, ...) call that names the job ID, domain, and selector
  of the signature with the bogus key record. Place it before the break. Use the
  
  ## Fix 4 — _FFR_DNSSEC guard (AUDIT-DNSSEC.md §5 Bug 2)
  File: libopendkim/dkim.c, lines 4236-4238
  
  Replace #ifdef _FFR_DNSSEC / #endif with #ifdef USE_UNBOUND / #endif.
  The FEATURE_ADD line inside is unchanged.
  
  ## Fix 5 — mctx_dnssec_key (AUDIT-DNSSEC.md §5 Gap 5)
  File: opendkim/opendkim.c
  
  mctx_dnssec_key is set at ~line 12313 and never read. Two options —
  choose whichever is smaller:
    a) Add a conf_dolog-guarded syslog(LOG_INFO, ...) immediately after
       line 12313 that logs the DNSSEC status of the primary signature
       (using a switch on the four DKIM_DNSSEC_* values), OR 
    b) Remove the field entirely: the #ifdef USE_UNBOUND block in struct
       msgctx (~line 350), the initialiser (~line 8033), and the assignment
       (~line 12313).
       
  Do not add the syslog if it would duplicate information already emitted
  by Fix 3. If the message is already covered, take option (b).
  
  ## After all five fixes
  
  Run: cmake --build build && ctest --test-dir build -V
  All tests must pass. If any test fails, diagnose and fix the root cause —
  do not disable the test or work around it.
  
  ## Constraints
  - Do not modify any file under libopendkim/tests/
  - Do not modify AUDIT-DNSSEC.md
  - Do not touch the AD bit / libresolv path (AUDIT-DNSSEC.md §8) —
    that is a separate task 
  - Do not add comments explaining what the fix does; the code should be
    self-evident
  - Do not refactor anything beyond the specific lines each fix touches

  ---
  The ordering matters: Fix 1 unblocks the bogus code path so Fix 3's syslog is actually reachable; Fixes 2 and 4 are single-liners that carry no risk; Fix 5 is last because it depends on
  whether Fix 3 makes the syslog redundant.
