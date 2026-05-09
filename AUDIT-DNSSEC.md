# AUDIT-DNSSEC.md — DNSSEC Support Audit

**Date:** 2026-05-09  
**Branch:** master  
**Reference standard:** RFC 8601 §2.7.1 (Authentication-Results dkim method properties)  
**Reference model:** Postfix `smtp_log_tls_feature_status` — dkim= result should carry DNSSEC status
as a parenthetical: `dkim=pass (2048-bit key; secure)`.

---

## 1. Every `_FFR_DNSSEC`-guarded block

There is exactly **one** `_FFR_DNSSEC` block in the entire codebase.

| File | Lines | What it does |
|---|---|---|
| `libopendkim/dkim.c` | 4236–4238 | `FEATURE_ADD(libhandle, DKIM_FEATURE_DNSSEC)` — registers feature index 6 in the library feature list |

```c
/* libopendkim/dkim.c:4236 */
#ifdef _FFR_DNSSEC
    FEATURE_ADD(libhandle, DKIM_FEATURE_DNSSEC);
#endif /* _FFR_DNSSEC */
```

**`_FFR_DNSSEC` is never defined anywhere** — not in `build-config.h.cmake.in`, not in any
`CMakeLists.txt`, not passed as a compiler flag. This block is permanently dead code in the
current build regardless of whether libunbound is found. `DKIM_FEATURE_DNSSEC` (feature index 6,
`dkim.h:1374`) is therefore never advertised by `dkim_libfeature()`. No code in this codebase
currently calls `dkim_libfeature(lib, DKIM_FEATURE_DNSSEC)`, so there is no active breakage, but
the inconsistency is a latent documentation failure.

The `USE_UNBOUND` symbol (which actually controls all the real DNSSEC code) is a completely
separate mechanism from `_FFR_DNSSEC`. The two were never connected.

---

## 2. The `USE_UNBOUND` integration — build system status

`USE_UNBOUND` is the operative guard for all functional DNSSEC code. The build system is correct
and complete.

**`libopendkim/CMakeLists.txt` (lines 133–161):**

```cmake
option(WITH_UNBOUND "Enable libunbound DNSSEC async resolver support" ON)
if(WITH_UNBOUND)
    pkg_check_modules(UNBOUND IMPORTED_TARGET libunbound)
    if(NOT UNBOUND_FOUND)
        # Fallback for BSD/macOS: find_path + find_library
        ...
    endif()
    if(UNBOUND_FOUND)
        set(USE_UNBOUND 1)
        set(HAVE_UNBOUND_H 1)
    endif()
endif()
```

When libunbound is found:
- `USE_UNBOUND=1` and `HAVE_UNBOUND_H=1` are written into `build-config.h` via a
  `#cmakedefine` (lines 23–25 of `build-config.h.cmake.in`).
- `libopendkim` targets receive `USE_UNBOUND=1` via `target_compile_definitions`
  (`libopendkim/CMakeLists.txt:356–359`).
- `opendkim/` daemon targets pick up `USE_UNBOUND=1` through the generated `build-config.h`
  which they include via `${CMAKE_BINARY_DIR}/libopendkim` on their include path
  (`opendkim/CMakeLists.txt:87`).
- All binaries link against `/usr/lib/libunbound.so`.

**Current build state (confirmed from `build/libopendkim/build-config.h`):**

```c
#define USE_UNBOUND 1
#define HAVE_UNBOUND_H 1
```

libunbound is present and active. All `#ifdef USE_UNBOUND` blocks compile in.

**Gap in `opendkim/CMakeLists.txt`:** Lines 60 and 121–123 find and link `UNBOUND_LIBRARY`
without adding a `target_compile_definitions(… USE_UNBOUND=1)`. This works only because
`build-config.h` provides the define transitively. If the daemon headers were ever reorganised
away from the `libopendkim` build directory, this would silently drop DNSSEC support from the
daemon without a warning.

---

## 3. What the DNSSEC code path does when active

The full call chain from DNS query to signature validation result, with `USE_UNBOUND` active.

### 3a. Startup

`dkimf_config_setlib()` in `opendkim.c:7466–7468` calls:

```c
#ifdef USE_UNBOUND
    (void) dkimf_unbound_setup(lib);
#endif
```

`dkimf_unbound_setup()` (`opendkim-dns.c:693–707`) installs eight function pointers into the
libopendkim resolver slot: `dkimf_ub_query`, `dkimf_ub_cancel`, `dkimf_ub_waitreply`,
`dkimf_ub_init`, `dkimf_ub_close`, `dkimf_ub_nslist`, `dkimf_ub_config`,
`dkimf_ub_trustanchor`. From this point every DNS lookup by libopendkim goes through libunbound.

A trust anchor file is loaded if `TrustAnchorFile` is configured (`opendkim.c:7368–7385`).
Without a trust anchor, libunbound cannot perform DNSSEC validation and all results will be
`DKIM_DNSSEC_INSECURE`.

### 3b. Per-message: message context initialisation

`dkimf_new_msgctx()` (`opendkim.c:8032–8034`) initialises:

```c
#ifdef USE_UNBOUND
    ctx->mctx_dnssec_key = DKIM_DNSSEC_UNKNOWN;
#endif
```

### 3c. Key retrieval — `dkim_get_key_dns()` (`libopendkim/dkim-keys.c:70–228`)

1. Builds the TXT query name: `{selector}._domainkey.{domain}`.
2. If no simulated DNS reply is queued (production path):
   - Calls `lib->dkiml_dns_init()` → `dkimf_ub_init()`: creates a `struct ub_ctx`,
     sets async mode, initialises the mutex and condvar.
   - Calls `lib->dkiml_dns_start()` → `dkimf_ub_query()`: mallocs a
     `dkimf_unbound_cb_data`, calls `dkimf_unbound_queue()` which calls
     `ub_resolve_async()` with `dkimf_unbound_cb` as callback and the cbdata as `mydata`.
     Returns the cbdata pointer as the query handle.
   - Calls `lib->dkiml_dns_waitreply()` → `dkimf_ub_waitreply()`: calls
     `dkimf_unbound_wait()` which uses a mutex+condvar loop. One thread at a time polls
     `ub_fd()` via `select()` then calls `ub_process()`, which fires the callback when the
     answer arrives. Other threads wait on the condvar.
3. When the wait completes, `dkimf_ub_waitreply()` copies `ubdata->ubd_result` into `*dnssec`.
4. `sig->sig_dnssec_key = dnssec` (`dkim-keys.c:227`) — stores the status on the signature.

### 3d. The callback — `dkimf_unbound_cb()` (`opendkim-dns.c:159–206`)

```c
static void
dkimf_unbound_cb(void *mydata, int err, struct ub_result *result)
{
    ...
    ubdata->ubd_done = FALSE;          /* reset done flag */
    ubdata->ubd_stat = DKIM_STAT_NOKEY;
    ubdata->ubd_rcode = result->rcode;
    memcpy(ubdata->ubd_buf, result->answer_packet, ...);

    if (result->secure)
        ubdata->ubd_result = DKIM_DNSSEC_SECURE;
    else if (result->bogus)
    {
        ubdata->ubd_result = DKIM_DNSSEC_BOGUS;
        return;                        /* ← BUG: early return, ubd_done stays FALSE */
    }
    else
        ubdata->ubd_result = DKIM_DNSSEC_INSECURE;

    if (result->havedata && !result->nxdomain && result->rcode == NOERROR)
        ubdata->ubd_stat = DKIM_STAT_OK;

    ub_resolve_free(result);
    ubdata->ubd_done = TRUE;           /* ← never reached for bogus case */
}
```

The `result->secure` and `result->bogus` fields come directly from libunbound's DNSSEC
validation state.

### 3e. Auth-Results construction — `dkimf_add_ar_fields()` (`opendkim.c:9577–9613`)

After verification, for each signature:

```c
switch (dkim_sig_getdnssec(sigs[c]))
{
  case DKIM_DNSSEC_UNKNOWN:   break;                      /* no annotation */
  case DKIM_DNSSEC_INSECURE:  dnssec = "unprotected"; ... break;
  case DKIM_DNSSEC_BOGUS:     dnssec = "bogus";       ... break;
  case DKIM_DNSSEC_SECURE:    dnssec = "secure";          break;
}
```

The string is embedded in the Auth-Results header via:

```c
APPEND("...dkim=%s%s (%u-bit key%s%s)...",
       result, comment, keybits,
       dnssec == NULL ? "" : "; ",
       dnssec == NULL ? "" : dnssec, ...);
```

Producing, for example: `dkim=pass (2048-bit key; secure)`.

### 3f. `mctx_dnssec_key` — end-of-message

`opendkim.c:12310–12313` stores the primary signature's DNSSEC status:

```c
#ifdef USE_UNBOUND
    sig = dkim_getsignature(dfc->mctx_dkimv);
    if (sig != NULL)
        dfc->mctx_dnssec_key = dkim_sig_getdnssec(sig);
#endif
```

`mctx_dnssec_key` is populated but never read again. See §5.

---

## 4. What is complete and appears correct

- **libunbound context lifecycle**: `dkimf_ub_init()`, `dkimf_ub_close()`, `ub_ctx_create()`,
  `ub_ctx_async()`, mutex/condvar initialisation and teardown are all correct.
- **Async threading model**: The `ub_poller` flag and mutex+condvar in `dkimf_unbound_wait()`
  correctly coordinate multiple milter threads competing to call `ub_process()`. Only one thread
  polls at a time; others wait. This is correct libunbound async usage.
- **Query dispatch**: `dkimf_ub_query()` → `dkimf_unbound_queue()` → `ub_resolve_async()`.
  Query handle is the `dkimf_unbound_cb_data` pointer. Correct.
- **Cancel path**: `dkimf_ub_cancel()` calls `ub_cancel()` and frees the cbdata. Correct.
- **DNSSEC state extraction**: `result->secure` and `result->bogus` flags from libunbound are
  the authoritative in-process DNSSEC validation result. Mapping them to
  `DKIM_DNSSEC_SECURE`/`DKIM_DNSSEC_BOGUS`/`DKIM_DNSSEC_INSECURE` is correct.
- **`sig_dnssec_key` field**: Initialised to `DKIM_DNSSEC_UNKNOWN` at signature allocation
  (`dkim.c:1801`), populated from the DNS waitreply, readable via `dkim_sig_getdnssec()`.
- **`dkim_sig_setdnssec()`** (`dkim.c:6795–6812`): Validates the enum, defaults to UNKNOWN for
  invalid values. Correct.
- **Config options** (`opendkim-config.h:39–41`, `169–171`): `BogusKey` and `UnprotectedKey`
  config items are parsed with three actions — `none`, `neutral`, `fail` — and defaulted to
  `fail` and `none` respectively. Logic in `dkimf_add_ar_fields()` applies them correctly to
  `*status`.
- **Trust anchor and nameserver wiring**: `dkimf_ub_trustanchor()` calls `ub_ctx_add_ta_file()`;
  `dkimf_ub_nslist()` calls `ub_ctx_set_fwd()`. Both are hooked into libopendkim's resolver
  abstraction. Correct.
- **`dkimf_unbound_setup()` called at startup**: `opendkim.c:7466–7468`. Correct placement.
- **Switch covers all four states**: `DKIM_DNSSEC_UNKNOWN`, `DKIM_DNSSEC_INSECURE`,
  `DKIM_DNSSEC_BOGUS`, `DKIM_DNSSEC_SECURE` are all present in the switch at `opendkim.c:9578`.

---

## 5. What is stubbed, incomplete, or wired to nothing

### Bug 1 — Critical: bogus callback does not set `ubd_done = TRUE`

**Location:** `opendkim-dns.c:189–194`

When `result->bogus` is true, `dkimf_unbound_cb()` does an early return after setting
`ubd_result = DKIM_DNSSEC_BOGUS`. It does NOT:
- set `ubdata->ubd_done = TRUE`
- call `ub_resolve_free(result)`

Consequences:
1. `dkimf_unbound_wait()` loops until the configured DNS timeout (typically 10 seconds)
   because `ubd_done` stays `FALSE`. Every bogus DKIM key causes a 10-second stall per
   message.
2. `result` is never freed — memory leak per bogus query.
3. After timeout, `dkimf_ub_waitreply()` returns `DKIM_DNS_EXPIRED`, which causes
   `dkim_get_key_dns()` to return `DKIM_STAT_KEYFAIL` — the bogus status is lost; the
   signature is treated as a key retrieval failure, not a bogus-DNSSEC failure.

The intended flow (bogus result surfaces as `DKIM_DNSSEC_BOGUS` to the policy engine) is
completely broken. This is the most severe bug in the implementation.

**Fix required:** In the bogus branch, call `ub_resolve_free(result)` and then set
`ubdata->ubd_done = TRUE` before returning. Also signal the condvar:

```c
else if (result->bogus)
{
    ubdata->ubd_result = DKIM_DNSSEC_BOGUS;
    ub_resolve_free(result);      /* ← add */
    ubdata->ubd_done = TRUE;      /* ← add */
    /* condvar signal happens in dkimf_unbound_wait() loop, not here */
    return;
}
```

### Bug 2 — `_FFR_DNSSEC` never defined; `DKIM_FEATURE_DNSSEC` never advertised

**Location:** `libopendkim/dkim.c:4236–4238`

`_FFR_DNSSEC` does not appear in `build-config.h.cmake.in` or any CMakeLists.txt. The
`FEATURE_ADD(libhandle, DKIM_FEATURE_DNSSEC)` call is permanently compiled out, even when
`USE_UNBOUND=1` is active. No code in this codebase currently queries
`dkim_libfeature(lib, DKIM_FEATURE_DNSSEC)`, so there is no active runtime breakage, but the
feature registry is a lie.

**Fix required:** Replace `#ifdef _FFR_DNSSEC` with `#ifdef USE_UNBOUND` (matching the guard
used everywhere else), or remove the guard entirely since `HAVE_SHA256` above it is also
unconditional.

### Bug 3 — Auth-Results label for insecure is "unprotected", not "insecure"

**Location:** `opendkim.c:9583–9595`

```c
case DKIM_DNSSEC_INSECURE:
    dnssec = "unprotected";
```

The reference model specifies `dkim=pass (2048-bit key; insecure)`. The `test.c` tool
(line 724) correctly uses the string `"insecure"`. The daemon uses `"unprotected"`, which is
inconsistent with the reference model, RFC 8601, and the tool output. Receivers parsing
Authentication-Results headers programmatically would see a non-standard token.

**Fix required:** Change `"unprotected"` to `"insecure"`.

### Bug 4 — No syslog warning for bogus keys

**Location:** `opendkim.c:9597–9607`

The `DKIM_DNSSEC_BOGUS` case sets `*status = DKIMF_STATUS_BAD` (or neutral) and places
`"bogus"` in the Auth-Results comment. It does not call `syslog()`. The requirement states:
"The bogus case must produce a syslog warning in addition to the Auth-Results annotation."
A bogus DNSSEC result is an active attack indicator; silent Auth-Results annotation alone is
insufficient for operational visibility.

Note: even if Bug 1 (callback) is fixed, this syslog call is still absent.

**Fix required:** Add before the break:

```c
syslog(LOG_WARNING,
    "%s: DNSSEC validation failed (bogus) for key record of signature "
    "from %s (selector %s); possible attack",
    dfc->mctx_jobid, domain, selector);
```

### Gap 5 — `mctx_dnssec_key` is populated but never used

**Location:** `opendkim.c:12310–12313`, `opendkim.c:350–352`

`mctx_dnssec_key` is declared in `struct msgctx` (`opendkim.c:350–352`), initialised to
`DKIM_DNSSEC_UNKNOWN` (`opendkim.c:8033`), and set at end-of-message (`opendkim.c:12313`).
No code reads it. It appears to be scaffolding for a planned per-message syslog statement
that was never written.

**Fix required:** Either use it (e.g., in a `conf_dolog` syslog block after line 12314) or
remove it.

### Gap 6 — Standard resolver path ignores the AD bit

**Location:** `libopendkim/dkim-dns.c:197`

```c
rq->rq_dnssec = DKIM_DNSSEC_UNKNOWN;
```

The libresolv fallback path (`dkim_res_query` / `dkim_res_waitreply`) always returns
`DKIM_DNSSEC_UNKNOWN`. Even if a local validating resolver sets the AD bit in the response,
it is not read. See §8 for full analysis.

### Gap 7 — No DNSSEC test coverage

The libopendkim test suite (`libopendkim/tests/`) has no tests exercising DNSSEC paths.
`t-test73.c` registers a custom DNS callback that returns `DKIM_DNSSEC_UNKNOWN` unconditionally
(`libopendkim/tests/t-test73.c:150`). There are no tests that inject replies with
`DKIM_DNSSEC_SECURE`, `DKIM_DNSSEC_BOGUS`, or `DKIM_DNSSEC_INSECURE` status and verify the
resulting Auth-Results header.

### Gap 8 — Error reporting in `dkimf_ub_waitreply` on error

**Location:** `opendkim-dns.c:550–551`

```c
if (error != NULL && status == -1)
    *error = status;    /* XXX -- improve this */
```

On processing error, `*error` is set to -1 (the return code of `dkimf_unbound_wait`), not a
meaningful errno or libunbound error code. The XXX comment is the original developer's
acknowledgement. Low priority but noted.

---

## 6. What would be needed to make it fully functional and testable

In priority order:

1. **Fix Bug 1** (bogus callback): `ub_resolve_free()` + `ubd_done = TRUE` in the bogus
   branch. This is the only change that prevents a live correctness failure on every bogus reply.

2. **Fix Bug 3** (Auth-Results label): `"unprotected"` → `"insecure"`. One-line change.

3. **Fix Bug 4** (syslog warning): Add `syslog(LOG_WARNING, ...)` in the `DKIM_DNSSEC_BOGUS`
   branch in `dkimf_add_ar_fields()`.

4. **Fix Bug 2** (`_FFR_DNSSEC`): Replace with `#ifdef USE_UNBOUND` so
   `DKIM_FEATURE_DNSSEC` is correctly advertised.

5. **Resolve Gap 5** (`mctx_dnssec_key`): Implement the intended per-message syslog line or
   remove the dead field.

6. **Trust anchor**: Document (or enforce in configuration validation) that
   `TrustAnchorFile` must point to a valid root trust anchor (e.g., `/etc/unbound/root.key`)
   for DNSSEC validation to produce `SECURE` results. Without it, all results are `INSECURE`.

7. **Test coverage**: Add tests that exercise all four DNSSEC states using a mock DNS reply
   mechanism similar to the existing `dkim_set_dns_callback()` / `dkim_test_dns_put()`
   infrastructure, but with DNSSEC status injection. Specifically:
   - `DKIM_DNSSEC_SECURE`: verify `dkim=pass (2048-bit key; secure)` in Auth-Results
   - `DKIM_DNSSEC_INSECURE`: verify `dkim=pass (2048-bit key; insecure)`
   - `DKIM_DNSSEC_BOGUS`: verify `dkim=fail` (after fix), syslog warning, and correct status
   - `DKIM_DNSSEC_UNKNOWN`: verify no annotation in Auth-Results

8. **Promote `_FFR_DNSSEC` to non-FFR**: Once the above are done, remove the `_FFR_DNSSEC`
   guard (after replacing with `USE_UNBOUND` per item 4) and update `TODO.md`.

---

## 7. Auth-Results header construction — all four DNSSEC states

Relevant code at `opendkim.c:9575–9654`.

```c
dnssec = NULL;                               /* initialised per-sig */

#ifdef USE_UNBOUND
switch (dkim_sig_getdnssec(sigs[c]))
{
  case DKIM_DNSSEC_UNKNOWN:
    break;                                   /* dnssec stays NULL → no annotation */

  case DKIM_DNSSEC_INSECURE:
    dnssec = "unprotected";                  /* ← WRONG: should be "insecure" */
    if (conf->conf_unprotectedkey == DKIMF_KEYACTIONS_FAIL)
    {
        *status = DKIMF_STATUS_BAD;
        result = "policy";
    }
    else if (conf->conf_unprotectedkey == DKIMF_KEYACTIONS_NEUTRAL)
    {
        *status = DKIMF_STATUS_VERIFYERR;
        result = "neutral";
    }
    break;

  case DKIM_DNSSEC_BOGUS:
    dnssec = "bogus";
    if (conf->conf_boguskey == DKIMF_KEYACTIONS_FAIL)
    {
        *status = DKIMF_STATUS_BAD;
        /* result unchanged: stays "fail" or whatever it was */
    }
    else if (conf->conf_boguskey == DKIMF_KEYACTIONS_NEUTRAL)
    {
        *status = DKIMF_STATUS_VERIFYERR;
        result = "neutral";
    }
    /* ← MISSING: syslog(LOG_WARNING, ...) */
    break;

  case DKIM_DNSSEC_SECURE:
    dnssec = "secure";
    break;
}
#endif /* USE_UNBOUND */

APPEND("%s%sdkim=%s%s (%u-bit key%s%s) header.d=%s header.i=%s%s%s",
    c == 0 ? "" : ";",
    DELIMITER, result, comment,
    keybits,
    dnssec == NULL ? "" : "; ",
    dnssec == NULL ? "" : dnssec,
    domain, val, ...);
```

**Summary of the four states against the reference model:**

| State | Expected output | Actual output | Correct? |
|---|---|---|---|
| `DKIM_DNSSEC_UNKNOWN` | no DNSSEC annotation | no annotation (`dnssec = NULL`) | ✓ |
| `DKIM_DNSSEC_SECURE` | `dkim=pass (2048-bit key; secure)` | `dkim=pass (2048-bit key; secure)` | ✓ |
| `DKIM_DNSSEC_INSECURE` | `dkim=pass (2048-bit key; insecure)` | `dkim=pass (2048-bit key; unprotected)` | ✗ wrong label |
| `DKIM_DNSSEC_BOGUS` | `dkim=fail (bogus)` + syslog WARNING | `dkim=fail (bogus)` — no syslog | ✗ missing syslog |

The code reaches all four states syntactically, but two of them have defects.

Note: for the bogus state, because Bug 1 causes a timeout before the callback result is
processed, in practice the output under a real bogus reply is `dkim=temperror` (key retrieval
timed out), not `dkim=fail (bogus)`. The switch is structurally correct but unreachable for
the bogus case in a live deployment until Bug 1 is fixed.

---

## 8. AD bit as an alternative to libunbound

### What the AD bit is

The Authenticated Data (AD) bit is bit 5 of the second flags word in the DNS response header
(`HEADER.ad` in `<arpa/nameser.h>`). A validating resolver sets it when the response has been
successfully DNSSEC-validated end-to-end. It is defined in RFC 4035 §3.2.3.

### What the standard resolver path currently does

`dkim-dns.c:197`:
```c
rq->rq_dnssec = DKIM_DNSSEC_UNKNOWN;
```

The response bytes written to `buf` by `res_send()` / `res_nsend()` include the full DNS wire
format, including the flags word. The AD bit is present in the buffer but the code does not
inspect it.

### How AD bit reading would work

After `res_send()` returns, the AD bit can be read from the raw response:

```c
HEADER hdr;
if ((size_t)ret >= HFIXEDSZ) {
    memcpy(&hdr, buf, HFIXEDSZ);
    if (hdr.ad)
        rq->rq_dnssec = DKIM_DNSSEC_SECURE;
    else
        rq->rq_dnssec = DKIM_DNSSEC_INSECURE;
}
```

For this to work the query must also set the AD bit in the outgoing query (RFC 4035 §3.2.1 —
a recursive resolver only sets AD in the response if the client set AD in the query, or if it
is configured to always set it). The `RES_USE_DNSSEC` resolver option sets the EDNS0 DO bit
and the AD bit in outgoing queries. The current `res_nmkquery()` call does not set either.

Additionally, to get the answer packet with the AD bit intact rather than having `libresolv`
strip it, the query needs the EDNS0 DO bit. On some glibc versions `RES_USE_DNSSEC` is set
via `statp->options |= RES_USE_DNSSEC` before `res_ninit()`.

### Sufficiency for typical deployments

A "typical deployment" for a DKIM-signing mail server almost always has a local validating
resolver on `127.0.0.1` — BIND9 with `dnssec-validation auto`, Knot Resolver, systemd-resolved
with `DNSSEC=yes` (default on many distributions), or Unbound itself configured as a forwarder.
All of these perform DNSSEC validation and set the AD bit.

For such deployments, AD bit reading would give:
- **Correct `SECURE` detection**: AD bit set means the local resolver validated the chain.
- **Correct `INSECURE` detection**: AD bit absent means no DNSSEC for the zone.
- **No explicit `BOGUS` detection**: see below.

### Security tradeoff: libunbound in-process vs. AD bit trust-chain

| Property | libunbound (in-process) | AD bit (system resolver) |
|---|---|---|
| Trust chain | Root trust anchor → DNSSEC chain validated entirely inside the process. No external trust required. | Trust is delegated entirely to the local resolver. The process trusts the resolver unconditionally. |
| Transport to resolver | None — validation is local | Unencrypted UDP/TCP to 127.0.0.1 (or LAN). Loopback is practically safe; LAN nameserver is a soft boundary. |
| Can detect `BOGUS` | Yes — libunbound distinguishes validation failure from absent DNSSEC. | No — a failing DNSSEC chain typically produces `SERVFAIL` (treated as key lookup failure, not bogus). The distinction between "zone is unsigned" and "DNSSEC validation failed" is lost. |
| Detects `SERVFAIL` as bogus | Not applicable (libunbound gives the actual validation state) | No — `SERVFAIL` looks like a temporary DNS error to libresolv callers; no way to know if it was caused by DNSSEC failure. |
| Compromised resolver | Bogus results caught in-process regardless. | A compromised resolver that strips the AD bit reports `INSECURE` instead of `BOGUS` — active attacks are invisible. |
| Deployment complexity | Requires libunbound, trust anchor file, and correct configuration. | Requires only `RES_USE_DNSSEC` in the query flags. Works with any validating resolver. |
| CPU/memory overhead | DNSSEC validation crypto runs in-process per query. | Negligible — just bit inspection. |

### Conclusion

AD bit reading is **sufficient for the secure/insecure distinction** and appropriate for
deployments where a trusted local validating resolver is present, which covers the large majority
of modern mail server deployments. It requires no additional libraries beyond libresolv and a
two-line query flag change plus a header inspection.

The critical gap is **bogus detection**. A bogus result — indicating active DNSSEC tampering —
produces `SERVFAIL` at the libresolv level, which is indistinguishable from an ordinary DNS
failure. There is no way to surface the "actively suspicious" distinction without in-process
DNSSEC validation.

**Recommendation:** AD bit reading is a low-complexity path worth implementing in the libresolv
fallback in `dkim-dns.c`, so that deployments without libunbound still get secure/insecure
discrimination. It should not replace the libunbound path for deployments that need the bogus
case explicitly detected and loudly logged. The two paths are complementary:

- `USE_UNBOUND`: full three-state DNSSEC reporting (secure / insecure / bogus) with in-process
  trust chain. Required when `BogusKey` policy enforcement or explicit syslog warnings on
  tampered queries are needed.
- AD bit (libresolv fallback): two-state reporting (secure / insecure). Sufficient when a
  trusted local validating resolver is guaranteed to be present and bogus-specific policy
  is not needed.

---

*Audit complete. No source files were modified.*
