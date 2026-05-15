# Memory-Safety Audit Findings — opendkim-ng

Audit scope: read-only memory-safety review of internet-facing C code, per
`AUDIT-PROMPT-A-memory-safety.md`. No source files were modified.

## Findings

### [MEDIUM] libopendkim/dkim-keys.c:379-389 — TXT record chunk-length unchecked against `rdlength`

**What**: The TXT-record payload-extraction loop reads `c = *cp++` as a per-chunk
length byte (0–255), then reads `c` bytes into the caller's buffer without
checking that `c <= rdlength`. The inner loop only stops on `c == 0 || p >= eob`,
so a crafted DNS reply with a chunk length larger than the remaining rdata
advances `cp` past `eom` (and potentially past `ansbuf[MAXPACKET]`), making
`rdlength` (signed `int`) go negative.

**Why it matters**: An attacker controlling the DNS TXT response (or capable of
spoofing one when DNSSEC is unavailable) can force this code to read up to 254
bytes beyond the valid rdata. Because `ansbuf` is a stack array, the OOB read
can spill adjacent stack contents (other locals in `dkim_get_key_dns`, then
padding/canary/saved frame on x86_64) into the caller-supplied key buffer. The
bytes end up parsed as a DKIM key record and may surface in error logs or
downstream APIs that quote the key, yielding a stack info-leak primitive.

**Evidence**:
- Line 369 checks only the *outer* bound: `if (cp + rdlength > eom)` for the
  whole rdata.
- Line 379 outer loop: `while (rdlength > 0 && p < eob)`.
- Line 381–382: `c = *cp++; rdlength--;`
- Line 383–388: inner `while (c > 0 && p < eob) { *p++ = *cp++; c--; rdlength--; }`
  — no `cp < eom` check; `rdlength` can underflow to negative and the loop keeps
  reading.

**Suggested fix**: tighten the inner loop to
`while (c > 0 && p < eob && rdlength > 0)` (or clamp
`c = MIN(c, (size_t)rdlength)` immediately after the length-byte read).

---

### [LOW] libopendkim/dkim-keys.c:241 — `dn_expand()` return value not checked

**What**: In the qdcount loop,
`dn_expand((unsigned char *) &ansbuf, eom, cp, (char *) qname, sizeof qname)`
is cast to `(void)`. If `dn_expand` fails (e.g., `cp >= eom` from a truncated
answer), `qname` is left in a partial/garbage state and is later used in
`dkim_error()` format strings.

**Why it matters**: Not directly exploitable (the next call `dn_skipname` *is*
checked at line 244 and bails on error), but the unchecked write into `qname`
followed by use of `qname` as a printf-style `%s` argument means stale or
partially-overwritten contents are logged. Quality/auditability issue.

**Evidence**: `dkim-keys.c:241–244`.

**Suggested fix**: check the return value of `dn_expand` and return
`DKIM_STAT_KEYFAIL` if negative.

---

### [LOW] libopendkim/dkim-keys.c:108, 462 — Off-by-one in snprintf truncation detection

**What**: Two query-name builders use the pattern:

```c
n = snprintf(qname, sizeof qname - 1, "...");
if (n == -1 || n > sizeof qname - 1) /* truncated */
```

Truncation actually occurs when `n >= sizeof qname - 1` (snprintf returns the
number of bytes it *would* have written). The `>` check misses
`n == sizeof qname - 1`.

**Why it matters**: At the exact boundary, a truncated query name is silently
used. The resulting DNS query is for the wrong name (last char dropped), giving
NXDOMAIN or in pathological cases the wrong subdomain's key. Not a
memory-safety bug — no buffer overflow — but a logic gap. The same off-by-one
is repeated in `dkim_get_key_file()` at line 462.

**Suggested fix**: change `>` to `>=`, or pass `sizeof qname` and check
`n >= sizeof qname`.

---

### [LOW] libopendkim/dkim.c:463-469 — `len + 1` malloc/strlcpy wrap for SIZE_MAX-sized header

**What**: In `dkim_process_set()`, `hcopy = DKIM_MALLOC(dkim, len + 1)`;
`strlcpy(hcopy, str, len + 1)`. If `len == SIZE_MAX` the addition wraps to 0 —
`malloc(0)` returns either NULL or a minimal allocation, and
`strlcpy(..., ..., 0)` writes nothing. The subsequent
`for (p = hcopy; *p != '\0'; p++)` then reads uninitialized memory.

**Why it matters**: Defense-in-depth only; in practice the caller passes header
values bounded by milter input sizes (well under `DKIM_MAXHEADER` = 4096). Not
reachable from any attacker-controlled path observed in the audit.

**Evidence**: `dkim.c:463`.

**Suggested fix**: `if (len >= SIZE_MAX - 1) return DKIM_STAT_NORESOURCE;`
before the malloc.

---

### [LOW] opendkim/opendkim-ar.c:464, 533, 574, 622, 645 — Silent truncation of A-R fields used in security decisions

**What**: `ares_parse()` populates `ares_version`, `result_reason`,
`result_property[]`, and `result_value[]` (each `MAXAVALUE + 1` = 257 bytes)
with `strlcpy`/`strlcat` calls whose return values are *not* checked. A crafted
Authentication-Results header longer than 256 bytes per field is silently
truncated.

**Why it matters**: A downstream caller (`opendkim.c`) inspects `result_value`
to make trust decisions (e.g., matching `header.d=...` against the local
domain). Truncation can convert a non-match into a match — e.g., a value
`"example.com.attacker.tld"` truncated to `"example.com..."`. The `ares_host`
strlcat at line 432 *does* check truncation correctly; the others do not.

**Evidence**: `opendkim-ar.c:464` (`ares_version`), `:533` (`result_reason`),
`:574` (`result_value` append), `:622` (`result_property`), `:645`
(`result_value` first write).

**Suggested fix**: check each strlcpy/strlcat return value against the
destination size and return `-1` (the parser's existing error path) on
truncation.

---

### [LOW] opendkim/opendkim-ar.c:413, 419-423 — Dead `;` branch in state 0

**What**: In state 0, line 419–421 returns -1 if `tokens[c][0]` is not
`isalnum`. Line 423 then checks `tokens[c][0] == ';'` — but `;` is not alnum,
so the earlier check has already returned. The `;`-prefixed authserv-id form
(RFC 8601 §2.3 says the authserv-id is mandatory, but several intermediaries
omit it) is unreachable.

**Why it matters**: Not a memory-safety issue; logic/parsing gap. Affects
accuracy of A-R interpretation, which is itself fed into trust decisions.

**Evidence**: `opendkim-ar.c:419–423`.

---

### [LOW] libopendkim/dkim-canon.c:216 — Theoretical integer overflow in hashbuf size check

**What**:
`if (canon->canon_hashbuflen + buflen > canon->canon_hashbufsize)` — both
operands are `size_t`; if both are near `SIZE_MAX` the sum wraps.

**Why it matters**: After tracing both branches, the wrap is contained: the
subsequent `if (buflen >= canon->canon_hashbufsize)` (line 228) catches the
large-`buflen` case and writes through `dkim_canon_write` directly, never
indexing into `canon_hashbuf` at the wrapped offset. So a wrap does not cause
memory corruption — but it *does* mean the previously-buffered bytes are not
flushed before the direct write, corrupting hash-input ordering. In practice
`buflen` is bounded by milter chunk sizes (≪ SIZE_MAX), so unreachable.

**Evidence**: `dkim-canon.c:216, 228`.

**Suggested fix**: write the comparison as
`buflen > canon->canon_hashbufsize - canon->canon_hashbuflen` (with
appropriate ordering), or assert `buflen < SIZE_MAX/2`.

---

### [INFO] libopendkim/dkim-canon.c:324, 329 — Reliance on hdr-text NUL termination past `hdrlen`

**What**: In `dkim_canon_header_string()`, the bounded loop at line 280
(`p < hdr + hdrlen`) is followed by two NUL-terminated loops
(`while (*p != '\0' && DKIM_ISLWSP(*p))` and
`for (; *p != '\0'; p++)`) which read past `hdr + hdrlen - 1` if the header is
not NUL-terminated at index `hdrlen`.

**Why it matters**: Currently `hdr_text` *is* NUL-terminated at `hdr_textlen`
(set by `dkim_strdup` in `dkim_header()`, which copies `len` bytes and writes
`new[len] = '\0'`), so all reads land on the trailing NUL. The contract is not
enforced by signature, however — if any future caller passes a non-terminated
buffer, this becomes an OOB read.

**Evidence**: `dkim-canon.c:324, 329`; contract honored by `dkim-util.c:96`
(`dkim_strdup`).

**Suggested fix**: replace `*p != '\0'` with `p < hdr + hdrlen && *p != '\0'`
to make the bound explicit.

---

## SAFE entries (verified, no fix needed)

### SAFE libopendkim/dkim-keys.c:497 — `memmove(buf, p2, strlen(p2) + 1)`

`p2` is always within `buf` and `p2 > buf`;
`strlen(p2) + 1 <= buflen - (p2 - buf)`. `memmove` handles overlap. The
leftward shift is within bounds.

### SAFE libopendkim/dkim-mailparse.c:582-605 — `realloc(uout)` then `realloc(dout)` failure path

Audit prompt suggested a leak/UAF here. Traced: on second `realloc` failure,
`uout` holds the *new* (still valid) pointer from the first successful realloc;
`dout` holds the *original* pointer (because the failing realloc preserves it
per spec). Both `free(uout)` and `free(dout)` are called. No leak, no
double-free, no UAF.

### SAFE libopendkim/dkim-mailparse.c:120-144 — `dkim_mail_matching_paren` escape handling

The `s[1]` read when `*s == '\\'` could read past `e`, but the buffer is always
terminated by `*e == '\0'` (caller computes `e = line + strlen(line)`), so the
read sees NUL and the no-op branch is taken.

### SAFE libopendkim/dkim-mailparse.c:422-464 — `memmove(w, tok_s, tok_e - tok_s)`

For every code path setting `tok_s`/`tok_e` in `dkim_mail_token()`,
`tok_e >= tok_s` (token_end is either set to `p+1`, advanced from `p+1` via
`matching_paren` to its return, or advanced via the in-place forward loop). The
invariant `w <= tok_s` is maintained across iterations, so memmove never wraps
the length.

### SAFE libopendkim/base64.c (entire file)

- Decoder table is 256 entries; index `(int)*c` is in [0,255] since `c` is
  `u_char *`.
- Output bound is checked (`n + 3 > buflen`, `n + 1`, `n + 2`) before every
  write. Trailing-group switch also bounded.
- Theoretical `int` overflow on `n` requires multi-GB inputs (unreachable from
  header/key sizes).

### SAFE libopendkim/dkim.c:728-743 — `d=` character validation in verification path

The Debian CVE-2020-12272 character-set check IS present in the inbound path:
lines 728–743 of `dkim_process_set()` (called from `dkim_get_sig_internal` →
`dkim_process_set(..., DKIM_SETTYPE_SIGNATURE, ...)`) reject any byte not in
`[A-Za-z0-9._\-]`. The signing path (`dkim_sign()` at line 4958) uses only the
weaker `dkim_strisprint()` check (accepts any `isprint` byte) — this is
acceptable because in the signing path the `d=` value comes from local
configuration, not from an attacker.

### SAFE opendkim/opendkim.c:4146-4279 + 4316-4351 / 6896-6986 — `dkimf_securefile` race window

The audit prompt asked whether the race between the final permission check and
the subsequent open is closed. Traced both callers:

- `dkimf_loadkey` (line 4316):
  `open() → fstat(fd, &s) → dkimf_securefile(path, &ino) → compare s.st_ino vs ino`.
- inner `dkimf_loadkey` (line 6896): same order.

The `open()` precedes `securefile()`, so the prompt's described ordering
(permission-check then open) does not exist in this code. The remaining race —
file replaced between `fstat` and the internal `stat` inside `securefile()` —
is detected by the `ino != s.st_ino` comparison, after which
`*insecure = TRUE` and the caller refuses to use the key when `conf_safekeys`
is set. The `pthread_mutex_lock(&pwdb_lock)` widening from issue #8 is for the
orthogonal concern of `getpwuid`/`getgrgid` returning thread-shared static
buffers — not the TOCTOU file race.

### SAFE opendkim/opendkim.c:12321, 12382 — snprintf into `header[DKIM_MAXHEADER + sizeof(AUTHRESULTSHDR) + 2]`

The buffer is `4096 + 23 + 2 = 4121` bytes.
`snprintf(header, sizeof header, "%s: %s", AUTHRESULTSHDR, dfc->mctx_dkimar)`
writes `22 + 2 + ≤4096 + 1 = ≤4121` bytes — exactly fits. The other snprintf at
line 12382 writes `"rfc822;%s"` (7 + addrlen + 1), bounded by snprintf itself.
The `Wformat-truncation` compiler warning reflects the theoretical worst case
at the boundary; it cannot overflow.

### SAFE opendkim/opendkim-db.c:724, 927 — `fgets(line, BUFRSZ, f)` into `char line[BUFRSZ + 1]`

fgets writes at most BUFRSZ bytes (BUFRSZ-1 chars + NUL); buffer is BUFRSZ+1 =
1025 bytes with one byte to spare. A 1024+ byte line is silently split across
fgets calls — a parsing/logic concern (a partial value could yield a bogus
key-value entry on the next read), not memory corruption.

### SAFE opendkim/opendkim-ar.c — `ARES_MAXTOKENS` overflow

`ares_tokenize()` increments `n` even past `ntokens`, but writes to `tokens[n]`
are guarded by `n < ntokens`. The caller `ares_parse()` then rejects
`ntoks > ARES_MAXTOKENS` at line 404 *before* iterating, so no OOB read of
`tokens[]`. Comment and parens tokens that may be unterminated when `q == end`
cause `ares_tokenize` to return `-1` (line 270 `q >= end`), so the caller never
inspects them.

---

## Overall memory-safety posture

The codebase is generally defensive: bounds checks are typically present on
stack buffers, `strlcpy`/`strlcat` is used in place of `strcpy`/`strcat`, and
the most-recent fixes (CVE-2020-12272 `d=` check, `dkim_mail_parse_multi`
realloc handling, `dkimf_securefile` inode comparison, removal of `QUERY_CACHE`
use-after-free) close the historic high-severity bugs. The one remaining
substantive memory-safety issue is the DNS TXT chunk-length under-check in
`dkim-keys.c:379-389`, which is a real out-of-bounds read on `ansbuf` driven by
an attacker-controlled DNS response and warrants a `MIN(c, rdlength)` clamp.
Several minor hardening gaps — silent strlcat truncation in `opendkim-ar.c`,
off-by-one in snprintf-truncation detection, `len + 1` malloc on possibly-
SIZE_MAX input — should be fixed for defense in depth but are not reachable
from observed attacker-controlled paths. No CRITICAL or HIGH findings.
