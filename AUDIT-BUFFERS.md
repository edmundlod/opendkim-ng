# Buffer Handling Audit — OpenDKIM-ng

Audited files: all `.c` and `.h` under `libopendkim/` and `opendkim/`.
Audit date: 2026-05-09. No source files were modified.

---

## Scope and Methodology

Five categories were checked:

1. `strcpy` / `strcat` / `sprintf` — unconditional red flags (none found in scope files)
2. `strncpy` / `strncat` — checked for size and NUL-termination
3. `strlcpy` / `strlcat` — checked that result is used when truncation matters
4. Fixed-size stack buffers receiving external input
5. `snprintf` result stored/used without checking for -1 or truncation (`>= size`)

**Key finding**: the codebase has already migrated away from `strcpy`/`strcat`/`sprintf`. No instances of those three patterns appear in `libopendkim/` or `opendkim/` outside of LDAP escaping code that SCOPE.md already designates for deletion. The remaining issues are all in the `snprintf`-result-ignored and `strlcpy`-return-ignored categories.

---

## Verified Safe Patterns (Reference)

The following calls are correctly bounded and checked; they are the model to follow for fixes:

| File | Lines | Notes |
|---|---|---|
| `libopendkim/dkim-keys.c` | 106–111, 460–466 | `n = snprintf(...); if (n == -1 \|\| n > sizeof buf) return error` |
| `libopendkim/dkim-util.c` | 144–158 | `if (n < 0 \|\| (size_t)n >= sizeof path) return error` |
| `opendkim/opendkim.c` | 5041–5044, 5066–5069, 5078–5081, 5090–5093 | `int n = snprintf(...); if (n < 0 \|\| ...)` |
| `opendkim/opendkim-db.c` | 2533–2544 | `plen = snprintf(...); if (plen >= rem) return error` |

---

## Findings by File

### `libopendkim/dkim.c`

| Line | Function | Pattern | Risk | Notes |
|---|---|---|---|---|
| 1523 | `dkim_sig_isidentity` | snprintf-no-check | Low | `snprintf((char *)addr, sizeof addr, "@%s", d)` where `d` is the `d=` tag from an inbound signature. `addr` is large enough for any valid domain, but truncation is not detected. A malformed oversized `d=` tag produces a silently wrong identity string. |
| 7954 | `dkim_get_sigsubstring` | strncpy-missing-nul | Med | `minlen = MIN(*buflen, dkim->dkim_minsiglen); strncpy(buf, b1, minlen);` followed by `if (minlen < *buflen) buf[minlen] = '\0';`. When `minlen == *buflen` (caller provides a buffer exactly as large as the required substring), no NUL is written. The caller receives an unterminated string. `b1` is the `b=` tag value from an inbound signature (network data). Any caller that subsequently uses `buf` as a C string without honouring `*buflen` will read past the end. |
| 8799 | `dkim_sig_getdnssec` | snprintf-no-check | Low | `snprintf((char *)newp->dq_name, sizeof newp->dq_name, "%s.%s.%s", sig->sig_selector, DKIM_DNSKEYNAME, sig->sig_domain)`. `dq_name` is `DKIM_MAXHOSTNAMELEN + 1` (257 bytes); selector + key-name prefix + domain could exceed this for a pathological selector. Silent truncation produces a wrong DNS query name with no error path. |

---

### `libopendkim/dkim-cache.c`

| Line | Function | Pattern | Risk | Notes |
|---|---|---|---|---|
| 234–235 | `dkim_cache_query` | strlcpy-wrong-buflen | Med | `strlcpy(buf, ce.cache_data, *buflen);` then `*buflen = strlen(ce.cache_data);`. If cached data is longer than the caller's buffer, `strlcpy` truncates silently and the function still reports `*buflen = strlen(ce.cache_data)` — the full source length, not the number of bytes actually written. The caller receives a truncated buffer but thinks it holds complete data, leading to downstream processing of an incomplete key record. |

---

### `libopendkim/dkim-keys.c`

No issues. Both `snprintf` calls at lines 106 and 460 are correctly checked with explicit `-1 || n > sizeof buf` guards. **Reference implementation.**

---

### `libopendkim/dkim-report.c`

| Line | Function | Pattern | Risk | Notes |
|---|---|---|---|---|
| 97–98 | `dkim_repinfo` | snprintf-no-check | Med | `snprintf(query, sizeof query, "%s.%s", DKIM_REPORT_PREFIX, (char *)sdomain)` where `query` is `DKIM_MAXHOSTNAMELEN + 1` (257 bytes), `DKIM_REPORT_PREFIX` is `"_report._domainkey"` (18 chars), and `sdomain` comes from the DKIM signature's `d=` tag (external, network-controlled). A domain of 239 or more chars causes `snprintf` to silently truncate `query`. The truncated string is then passed directly to the DNS resolver. No overflow (snprintf bounds correctly), but wrong DNS query name is used and no error is returned to the caller. |

---

### `libopendkim/dkim-util.c`

No issues. Both `snprintf` calls at lines 144 and 150 check `n < 0 || (size_t)n >= sizeof path` and return an error on truncation. The `vsnprintf` calls at 599 and 611 are part of a dynamic-string growth loop. **Reference implementation.**

---

### `opendkim/opendkim-ar.c`

| Line | Function | Pattern | Risk | Notes |
|---|---|---|---|---|
| 430, 444 | `ares_parse` (state machine) | strlcat-no-check | Med | `strlcat((char *)ar->ares_host, (char *)tokens[c], sizeof ar->ares_host)` called in two separate states without checking the return value. Tokens come from the `Authentication-Results:` header (external input from upstream MTA). If the header contains an abnormally long host component, the host name is silently truncated; downstream policy code then operates on a corrupt `ares_host` value. |
| 531 | `ares_parse` | strlcpy-no-check | Low | `strlcpy(result_reason, tokens[c], sizeof result_reason)`. Reason string from external header. Silently truncated; low consequence — only affects logged reason text. |
| 572, 643 | `ares_parse` | strlcat-no-check | Low | `strlcat(result_value[r], tokens[c], sizeof result_value[r])`. Result value tokens from external header. Silently truncated; affects result value string used in policy. |
| 620 | `ares_parse` | strlcpy-no-check | Low | `strlcpy(result_property[r], tokens[c], sizeof result_property[r])`. Property name from external header. Silently truncated. |

---

### `opendkim/opendkim-db.c`

| Line | Function | Pattern | Risk | Notes |
|---|---|---|---|---|
| 1300–1302 | `dkimf_db_erlang` | snprintf-result-stored-unchecked | Med | `n = snprintf(req[0].dbdata_buffer, req[0].dbdata_buflen, "%ld", val); req[0].dbdata_buflen = n + 1;`. `val` is decoded from an Erlang term received over the network. `snprintf` result `n` is not checked before use: if `n` is -1 (encoding error), `dbdata_buflen` is set to 0; if truncation occurred (`n >= dbdata_buflen`), `dbdata_buflen` is set larger than the actual buffer, enabling a subsequent caller to read past the allocation. |
| 1370–1371 | `dkimf_db_erlang` | snprintf-result-stored-unchecked | Med | `n = snprintf(key, *keylen, "%ld", val); *keylen = n + 1;`. Identical structural problem to line 1300. The decoded integer is formatted into a caller-supplied key buffer; if `n` is invalid, the key length is corrupted. |
| 1537 | `dkimf_db_open` | strncpy-pre-zeroed | Low | `strncpy(dbtype, name, clen)` where `clen = MIN(sizeof(dbtype)-1, p-name)` and the buffer was pre-zeroed with `memset`. Safe in practice: pre-zeroing guarantees NUL termination. Documented because `strncpy` here is misleading style; `strlcpy` would be clearer. |
| 3649–3655 | `dkimf_db_odbx_query` | snprintf-no-check | Low | `snprintf(query, sizeof query, "SELECT %s FROM %s WHERE %s = '%s'%s%s", ...)` constructs an SQL query from config-file column/table names and an escaped user value. Buffer is 1024 bytes; no truncation check. A pathologically long config name causes a silently truncated SQL statement that will fail to parse. (LDAP/SQL backends are on the SCOPE removal list but not yet deleted.) |
| 4021 | `dkimf_db_memcached` | snprintf-no-check | Low | `snprintf(query, sizeof query, "%s:%s", key, (char *)buf)` builds a memcached lookup key. No truncation check. `key` is config-file data; `buf` is the lookup value. Silently truncated key produces a cache miss. |
| 4611–4613 | `dkimf_db_odbx_query` | snprintf-no-check | Low | `snprintf(query, sizeof query, "SELECT %s,%s FROM %s", ...)`. Config-file column/table names only; same analysis as line 3649. |

---

### `opendkim/opendkim-genzone.c`

| Line | Function | Pattern | Risk | Notes |
|---|---|---|---|---|
| 748, 760, 769 | `main` | snprintf-no-check | Low | `snprintf(tmpbuf, sizeof tmpbuf, "update add %s%s%s...", selector, ...)` where `tmpbuf` is `LARGEBUFRSZ` (8192 bytes). Arguments come from command-line flags. No truncation check, but the large buffer makes overflow unlikely in practice. This is a command-line key-generation tool, not a daemon. |

---

### `opendkim/opendkim.c`

| Line | Function | Pattern | Risk | Notes |
|---|---|---|---|---|
| 3474 | `dkimf_milter_eom` | snprintf-no-check | Low | `snprintf(header, sizeof header, "rfc822;%s", a->a_addr)` where `header` is `MAXADDRESS + 8` (264 bytes) and `a->a_addr` is an email address from the message envelope (external). `"rfc822;"` consumes 7 bytes, leaving 256 bytes for the address — exactly `MAXADDRESS`. Since `a->a_addr` is stored in a `MAXADDRESS+1` field, this is a tight but correct fit. However, there is no return-value check; a defensive `n < 0` guard is still warranted. |
| 3980, 4005, 4031, 4049, 4066, 4089, 4115, 4135 | `dkimf_checkfsnode` | snprintf-no-check | Low | Eight `snprintf(err, errlen, ...)` calls formatting error messages that include `path` (a filesystem path, from config), UID/GID values (integers), and `pw_name`/`gr_mem[]` (system user/group names). All calls are bounded by `errlen`. The only consequence of truncation is an incomplete error message; no memory safety issue. |
| 5536, 5581 | `dkimf_config_load` | snprintf-no-check | Low | Two `snprintf(err, errlen, ...)` calls for config parse errors embedding a config key or value string. Bounded by `errlen`. Low consequence. |
| 6044–6896 (≈40 calls) | `dkimf_config_load` | snprintf-no-check | Low | Large block of `snprintf(err, errlen, ...)` calls for config-load error reporting. All bounded by `errlen`; content is config file paths and names. Truncated error messages are the worst outcome. Not enumerated individually; fix pattern is the same throughout. |

---

### `opendkim/util.c`

| Line | Function | Pattern | Risk | Notes |
|---|---|---|---|---|
| 328 | `dkimf_checkhost` | snprintf-no-check | Low | `snprintf(buf, sizeof buf, "!%s", p)` prepends `!` to a hostname for negative-match lookup. `buf` is 1024 bytes; DNS hostnames are capped at 253 chars. In practice this can never overflow, but there is no check. |
| 453, 485 | `dkimf_checkip` | snprintf-wrong-check | Low | `sz = snprintf(dst, dst_len, "%d", 128 - bits)` then `if (sz >= sizeof ipbuf) return FALSE`. The guard compares against `sizeof ipbuf` (257) instead of the remaining space `dst_len`. Since the formatted value is at most 3 digits, `sz` never approaches either limit in practice, so the wrong comparison never fires. Logically incorrect; impossible to trigger with valid IPv6 prefix lengths. |
| 592, 613 | `dkimf_checkip` | snprintf-no-check | Low | `snprintf(&ipbuf[c], sizeof ipbuf - c, "%d", bits)` for IPv4 prefix length (0–32, at most 2 digits). Remaining space is always sufficient; no check needed in practice. |

---

## Summary Table

| Risk | Count | Files |
|---|---|---|
| **Medium** | 6 | `dkim.c` (×2), `dkim-cache.c` (×1), `dkim-report.c` (×1), `opendkim-ar.c` (×1), `opendkim-db.c` (×2) |
| **Low** | 20+ | `dkim.c` (×2), `opendkim-ar.c` (×3), `opendkim-db.c` (×4), `opendkim-genzone.c` (×3), `opendkim.c` (×50+), `util.c` (×4) |
| **High** | 0 | — (no `strcpy`/`strcat`/`sprintf` present; all buffers use size-bounded calls) |

---

## Highest-Density Files

1. **`opendkim/opendkim.c`** — ~50 unchecked `snprintf(err, errlen, ...)` calls throughout `dkimf_config_load` and `dkimf_checkfsnode`. All Low severity (error strings, bounded by `errlen`), but the sheer volume means any future change that makes an error path carry user-controlled data would be silently truncated without any signal.

2. **`opendkim/opendkim-db.c`** — 6 findings of mixed severity. Two Medium-risk issues in the Erlang backend (lines 1300, 1370) where snprintf results are stored directly into buffer-length fields without validation. Four Low-risk SQL/memcached query strings.

3. **`opendkim/opendkim-ar.c`** — 6 `strlcpy`/`strlcat` calls without result checks. Two Medium-risk (the `ares_host` field that feeds downstream policy); four Low-risk (reason/value/property strings).

---

## Prioritised Fix Plan

### Priority 1 — Medium risk: fix first

**1a. `libopendkim/dkim.c:7954` — `dkim_get_sigsubstring`**

The NUL-termination logic is fragile. Replace the conditional write with unconditional termination:

```c
minlen = MIN(*buflen - 1, dkim->dkim_minsiglen);  /* leave room for NUL */
strncpy(buf, b1, minlen);
buf[minlen] = '\0';
*buflen = minlen;
```

Alternatively, use `strlcpy(buf, b1, *buflen)` and set `*buflen` to the return value capped at `*buflen - 1`. The public API contract should be documented: `buf` is always NUL-terminated; `*buflen` on return is the number of bytes written excluding NUL.

**1b. `libopendkim/dkim-cache.c:234` — `dkim_cache_query`**

Set `*buflen` to the number of bytes actually copied, not the source length:

```c
size_t copied = strlcpy(buf, ce.cache_data, *buflen);
*buflen = (copied >= *buflen) ? *buflen - 1 : copied;
```

Or simply: `*buflen = strlen(buf)` after the `strlcpy` (safe because `strlcpy` always NUL-terminates when `*buflen > 0`).

**1c. `libopendkim/dkim-report.c:97` — `dkim_repinfo`**

Add a pre-flight length check before constructing the query, mirroring the pattern in `dkim-keys.c`:

```c
int n = snprintf((char *)query, sizeof query, "%s.%s",
                 DKIM_REPORT_PREFIX, (char *)sdomain);
if (n < 0 || (size_t)n >= sizeof query)
    return DKIM_STAT_INVALID;
```

**1d. `opendkim/opendkim-ar.c:430,444` — `ares_parse` host accumulation**

Check `strlcat` return values; bail out if the host buffer would overflow:

```c
if (strlcat((char *)ar->ares_host, (char *)tokens[c],
            sizeof ar->ares_host) >= sizeof ar->ares_host)
    return -1;
```

**1e. `opendkim/opendkim-db.c:1300–1302, 1370–1371` — Erlang backend length corruption**

Check `snprintf` before storing the result as a buffer length:

```c
n = snprintf(req[0].dbdata_buffer, req[0].dbdata_buflen, "%ld", val);
if (n < 0 || (size_t)n >= req[0].dbdata_buflen)
    return -1;
req[0].dbdata_buflen = (size_t)n + 1;
```

Apply identically to line 1370 (the `*keylen` variant).

---

### Priority 2 — Low risk: fix in a single cleanup pass

All remaining findings follow one of two patterns. Fix them uniformly rather than case-by-case.

**Pattern A — `snprintf` result not checked (error-message paths)**

In `opendkim.c` (`dkimf_checkfsnode`, `dkimf_config_load`) and `opendkim-db.c` (query builders), add post-call guards:

```c
/* Before (current): */
snprintf(err, errlen, "some message %s", str);

/* After: */
(void)snprintf(err, errlen, "some message %s", str);
/* cast to void is enough here — truncation of an error message is acceptable,
   but the explicit cast signals the intent and silences static-analysis warnings */
```

For SQL/memcached query buffers where truncation means a logic failure, add a check and log/abort:

```c
int n = snprintf(query, sizeof query, "SELECT %s FROM %s ...", ...);
if (n < 0 || (size_t)n >= sizeof query)
{
    /* query was truncated — abort the DB operation */
    return error_code;
}
```

**Pattern B — `strlcpy`/`strlcat` return value ignored (opendkim-ar.c reason/value fields)**

For the four Low-severity `strlcpy`/`strlcat` calls in `opendkim-ar.c` (lines 531, 572, 620, 643), cast to `(void)` to document intent, or add a debug-mode assertion:

```c
(void)strlcpy((char *)ar->ares_result[n-1].result_reason,
              (char *)tokens[c],
              sizeof ar->ares_result[n-1].result_reason);
```

**Pattern C — wrong truncation check (`util.c:453,485`)**

Replace `if (sz >= sizeof ipbuf)` with `if (sz < 0 || (size_t)sz >= dst_len)`:

```c
sz = snprintf(dst, dst_len, "%d", 128 - bits);
if (sz < 0 || (size_t)sz >= dst_len)
    return FALSE;
```

**Pattern D — `strncpy` with pre-zeroed buffer (`opendkim-db.c:1537`)**

Replace with `strlcpy` for clarity (both are safe here, but `strlcpy` is the project idiom):

```c
strlcpy(dbtype, name, MIN(sizeof dbtype, (size_t)(p - name) + 1));
```

---

### Priority 3 — Deferred / won't-fix

- `opendkim/opendkim.c:3474` — mathematically correct tight fit; add `(void)` cast only.
- `opendkim/opendkim-db.c:3649,4021,4611` — LDAP/SQL/memcached backends targeted for removal per SCOPE.md; fix if those backends are retained, otherwise delete.
- `opendkim/opendkim-genzone.c:748,760,769` — command-line tool with 8 KB buffer; low priority.
- `libopendkim/dkim.c:8799` — selector+domain length is validated upstream; add check for correctness but not urgent.

---

## Absent Patterns (Confirmed Clean)

- **`strcpy` / `strcat` / `sprintf`**: Zero occurrences in `libopendkim/` or `opendkim/` source files (LDAP escaping macro in `opendkim-db.c` uses `snprintf` and is on the removal list).
- **`gets`**: Not present.
- **`strncat`**: Not present in scope files.
- **`scanf`/`fscanf` with `%s`**: Not present in scope files.

---

*End of audit. No source files were modified.*
