# Security Audit Prompt A — C Memory Safety

**Task**: Read-only memory-safety audit. Do NOT modify any source files.

**Model guidance**: Use maximum reasoning depth. This is adversarial analysis
of internet-facing C code. Treat all untrusted inputs as attacker-controlled.

**Audit discipline**:
- Read each file completely before reporting findings for it
- Trace pointer arithmetic fully before concluding safe/unsafe
- For every SAFE verdict, explain the specific bound that prevents exploitation
- For integer overflow checks, verify wrap behavior at SIZE_MAX, not just
  typical values
- Cross-file findings (e.g. value assigned in dkim.c, used in dkim-keys.c)
  must cite both files and line numbers
  
**Code reading discipline**
Read source files top-to-bottom before searching. Identify function boundaries,
shared state, and call relationships before forming any finding. Do not grep
for a pattern before you have read the surrounding context. Grep is a last
resort for locating a known symbol, not a substitute for reading.

---

## Threat model

An attacker can deliver an email with:
- Arbitrarily long or malformed `DKIM-Signature:` header fields
- Malformed `From:`, `To:`, `Cc:` headers
- A crafted DNS TXT response (if DNS is not fully trusted / DNSSEC is unavailable)
- Oversized or binary-embedded body data

All of the above flow through the code you are auditing before any
signature verification succeeds or fails.

---

## What is already known / fixed

The following issues are supposed to be resolved in the working tree:

- CVE-2020-35766: `/tmp/testkeys` TOCTOU — fixed in test harness only, no daemon impact
- CVE-2022-48521: A-R header stripping ordinal bug — fixed (reverse-order traversal)
- `QUERY_CACHE` use-after-free in `mlfi_close()` — all `#ifdef QUERY_CACHE` blocks removed
- `conf_refcnt` assert-abort — replaced with safe guard
- Division by zero in `Minimum 100%` with empty body — fixed
- `dkimf_securefile` critical-section widened (issue #8)
- `ub_ctx_config()` mutex-protected (issue #14)
- `dkim_mail_parse_multi()` quote-handling fixed

---

## Files to read and audit

Work through these in order.  Read each file completely before reporting
findings for it.  If any potential security flaw / error is missing from the list,
check for it, and report it as well.

### 1. `libopendkim/dkim-keys.c` — DNS TXT record parser
   **Focus**: `dkim_get_key_dns()`.  This function parses a raw DNS wire-format
   response stored in `ansbuf[MAXPACKET]` (8192 bytes).  It uses manual pointer
   arithmetic (`cp`, `eom`, `eob`) and libresolv macros (`GETSHORT`, `GETLONG`,
   `dn_expand`, `dn_skipname`).  This is the highest-priority area.

   Look for:
   - `cp` advancing past `eom` before bounds check
   - `rdlength` used to copy into `buf` without checking `buflen`
   - Underflow if `rdlength` is zero or negative
   - Off-by-one in the inner `while (c > 0 && p < eob)` loop
   - Whether `dn_expand` return value is used correctly
   - What happens if `ancount` is unreasonably large (e.g. 65535)

### 2. `libopendkim/dkim-canon.c` — canonicalization / hashing
   **Focus**: `dkim_canon_buffer()` (around line 199) and the buffer-growth path.

   Look for:
   - Integer overflow in `canon->canon_hashbuflen + buflen` before the size check
     at line 216 — if both are near `SIZE_MAX`, the addition wraps to a small value,
     bypassing the reallocation branch
   - Whether `dkim_canon_fixcrlf()` can produce output longer than its input, and
     whether the destination is sized for that
   - In `dkim_canon_header_string()` (line 256): `hdrlen` used in size arithmetic —
     check for overflow before any malloc

### 3. `libopendkim/dkim.c` — core DKIM header parser
   **Focus**: `dkim_process_set()` (line 439).  This parses raw `DKIM-Signature`
   tag=value pairs from untrusted header data.

   Look for:
   - Whether the `hcopy` allocation of `len + 1` can overflow if `len` is near
     `SIZE_MAX`
   - The character validation loop at line 500 — does it correctly reject all
     bytes that could confuse downstream parsers?
   - `dkim_add_plist()` — is the plist bounded?  Can an attacker stuff the plist
     by supplying many repeated tags?
   - In `dkim_getsig()` (around line 1800): the `sig_domain` and `sig_selector`
     pointer assignments — are they validated for length before use in `snprintf`
     calls in `dkim-keys.c`?

   Also read `dkim_sig_domainok()` (line 1522) and the `d=` processing in the
   key-lookup path.  The Debian CVE-2020-12272 patch adds a character-set loop
   that rejects anything not in `[A-Za-z0-9._-]` from the `d=` value **in the
   inbound verification path**.  Determine whether this validation exists here,
   or only in the signing path (`dkim_sign()`).  Report the status clearly —
   present or absent, with file and line number.

### 4. `libopendkim/dkim-mailparse.c` — email address parser
   **Focus**: `dkim_mail_parse()` and `dkim_mail_parse_multi()`.

   Look for:
   - `memmove(w, tok_s, tok_e - tok_s)` — verify `tok_e >= tok_s` always holds;
     if not, `tok_e - tok_s` wraps to a huge value
   - `dkim_mail_matching_paren()` — can `s` advance past `e`, producing an
     out-of-bounds read?
   - In `dkim_mail_parse_multi()`: the `realloc` path at line ~582 — after
     `realloc(uout)` succeeds, `realloc(dout)` can fail; at that point `uout`
     has been freed but `dout` is leaked.  Also check that `uout[n]` and
     `dout[n]` sentinel writes at lines ~611-612 are within the allocated bounds

### 5. `libopendkim/base64.c` — base64 decoder
   Read the full file.  Look for:
   - Output buffer overruns: does the caller-supplied `buf` / `buflen` bound
     the output correctly in all decoding paths?
   - Negative-index reads from the decoding table if a non-base64 byte slips through

### 6. `opendkim/opendkim-ar.c` — Authentication-Results parser
   **Focus**: `ares_tokenize()` and `ares_parse()`.

   Look for:
   - `strlcpy` / `strlcat` return value checks — silent truncation of an
     `ares_host` or `result_value` that is then used as a security decision
   - `ARES_MAXTOKENS` limit — what happens if a crafted A-R header has more
     tokens than the fixed array?
   - Whether the parser handles embedded CRLF or NUL in the header value

### 7. `opendkim/opendkim.c` — the daemon
   **Focus**:
   - Line 12407–12408: the known `Wformat-truncation` warning.  The `snprintf`
     writes up to 4096+25 bytes into a 4097-byte buffer.  Assess exact overflow
     risk: what fields feed into the format string, are they bounded, can an
     attacker control them?
   - `dkimf_securefile()` (line 4147): the function itself notes a TOCTOU race
     between stat and open.  The recent widening of the critical section (issue #8)
     used `pthread_mutex_lock(&pwdb_lock)` around the `getpwnam`/`getgrnam`
     calls.  Check whether the race between the final permission check and the
     subsequent `open()` of the file is closed, or still present.
   - All `snprintf` calls where the format string contains `%s` and the argument
     comes from external input (email headers, config loaded from untrusted path).

### 8. `opendkim/opendkim-db.c` — flat-file database backend
   **Focus**: the `fgets` loops at lines ~724 and ~927.

   Look for:
   - Line length: `BUFRSZ` is 1024. Are key or value fields in the signing table
     or key table bounded to fit?  What happens if a line is exactly 1024 bytes
     (no newline in the buffer)?
   - The `memmove` in `dkim_get_key_file()` (`libopendkim/dkim-keys.c:497`):
     `memmove(buf, p2, strlen(p2) + 1)` — `p2` points into `buf`; is the overlap
     handled correctly by `memmove`?  Is `strlen(p2) + 1` bounded by `buflen`?

---

## Output format

For each finding, write one entry:

```
### [SEVERITY] file:line_range — short title

**What**: one sentence describing the bug class.
**Why it matters**: what an attacker can achieve (crash, information leak, RCE).
**Evidence**: the specific lines and values that demonstrate the issue.
**Suggested fix**: the minimal change.
```

Severity levels: **CRITICAL** (exploitable remotely), **HIGH** (likely exploitable),
**MEDIUM** (exploitable under specific conditions), **LOW** (hardening gap, no
direct exploit path), **INFO** (style/quality issue that degrades auditability).

If a suspected issue turns out to be safe after tracing through the code, write a
**SAFE** entry briefly explaining why, so the next auditor does not re-examine it.

At the end, write a one-paragraph summary of the overall memory-safety posture.
