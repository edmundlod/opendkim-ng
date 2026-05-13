# PATCHES.md — External patch/issue review for opendkim-ng

Generated: 2026-05-13. Sources: upstream GitHub issues (open + recently closed),
Debian `salsa.debian.org/debian/opendkim` patch queue, FreeBSD ports rc script,
OpenBSD ports Makefile + rc script, Gentoo initd (404 — file not found at
enumerated path).

Cross-referenced against:
- SCOPE.md goals
- `git log --oneline 92951a3a..HEAD` (our fork history)
- Working tree (grep/source inspection)

---

## 1. Prioritised table

### Apply — security bugs first

| Priority | Source | ID / File | Summary | Recommendation | Notes |
|----------|--------|-----------|---------|----------------|-------|
| 1 | Debian patch | `cve-2020-12272.patch` | Missing character-set validation on the `d=` tag value in DKIM-Signature header. A crafted signature with illegal chars (e.g. newline, NUL, shell metachar) passes through `dkim_process_set()` unrejected. | **Apply** to `libopendkim/dkim.c` around the `d=` NULL check (~line 712). Add loop: reject any char not in `[A-Za-z0-9._-]`. | Upstream never merged this Debian-specific patch. Our tree has no such loop — verified by grep. |
| 2 | GitHub issue | #260 / CVE-2020-35766 | Insecure fixed `/tmp/testkeys` path in test harness. `t-testdata.h` defines `KEYFILE` as `/tmp/testkeys`; `t-setup.c` creates it with bare `fopen()` — susceptible to symlink/TOCTOU attack. No runtime daemon impact; exploitable only during test execution. Distinct from CVE-2022-48521 (A-R header ordering, fixed in f238cdcd). | **Applied** (commit `cve-2020-35766`): changed `KEYFILE` to relative `"testkeys"` and replaced `fopen()` with `open(O_CREAT\|O_EXCL\|O_NOFOLLOW)` + `fdopen()` in `t-setup.c`. PR #260 diff reviewed before applying. | ✓ Fixed |
| 3 | GitHub issue | #185 | `Authentication-Results` headers from external sources are stripped using wrong ordinal numbering, allowing a crafted inbound message to survive with a fake A-R header that OpenDKIM believes it already removed. Security bypass in verification mode. | Already fixed by commit `f238cdcd` (CVE-2022-48521): reverse-order traversal with stable ordinal tracking. Issue is CLOSED upstream. | ✓ Fixed (f238cdcd) |

### Apply — crashes and correctness

| Priority | Source | ID / File | Summary | Recommendation | Notes |
|----------|--------|-----------|---------|----------------|-------|
| 4 | Debian patch | `conf_refcnt.patch` | `dkimf_config_free()` contains `assert(conf->conf_refcnt == 0)` at `opendkim/opendkim.c:5374`. Under certain reload/close timing the count may be non-zero, aborting the daemon. | **Applied**: replaced assert with `syslog(LOG_CRIT, …); return;` guard — never aborts, logs if it fires (improvement over Debian's silent removal). | ✓ Fixed |
| 5 | Debian patch | `mlfi_close.patch` | `#ifdef QUERY_CACHE` block in `mlfi_close()` dereferences `cc->cctx_config` **after** the `if (cc != NULL)` block that decrements the refcount and frees `cc`. Use-after-free (or NULL deref). | **Applied**: removed all 6 `#ifdef QUERY_CACHE` blocks from `opendkim.c` (2 global variable declarations, 1 in config-load, 1 in main init, 1 in `dkimf_config_load`, 1 the use-after-free block in `mlfi_close`). `QUERY_CACHE` was never defined. | ✓ Fixed |
| 6 | Debian patch | `insheader.patch` | All calls to `dkimf_insheader(ctx, 1, …)` should be `dkimf_insheader(ctx, 0, …)`. Index 1 inserts *after* the first existing header; index 0 inserts *before all* headers. Affects `Authentication-Results`, `DKIM-Signature`, and `X-OpenDKIM` insertion order. | **Apply** to `opendkim/opendkim.c` lines 3292, 3726, 11809, 12638, 12688. Change all `dkimf_insheader(ctx, 1,` → `dkimf_insheader(ctx, 0,`. | Confirmed: all five call sites still use index 1. The Debian patch covers identical lines. |
| 7 | Debian patch | `fix-miltertest-data.patch` | `miltertest/miltertest.c`: the `mt.data()` function asserts `STATE_DATA` (wrong — it transitions *to* DATA from ENVRCPT) and the `mt.header()` function asserts `STATE_ENVRCPT` (wrong — headers come after DATA). The two state checks are swapped. | **Apply**: in `mt.data()` (~line 2614) change `STATE_DATA` → `STATE_ENVRCPT`; in `mt.header()` (~line 2711) change `STATE_ENVRCPT` → `STATE_DATA`. | Confirmed present. Causes misleading test-framework error messages and may hide milter sequencing bugs in integration tests. |
| 8 | Debian patch | `fix-miltertest-eom-check-smtpreply.patch` | `miltertest.c:3693–3694`: when `MT_SMTPREPLY` is checked, `esc` and `text` are passed directly to `snprintf` even when NULL. Undefined behaviour (NULL pointer in `%s` format argument is not guaranteed to produce `"(null)"` on all platforms). | **Apply**: change `esc` → `esc == NULL ? "" : esc` and `text` → `text == NULL ? "" : text`. | Confirmed at miltertest.c:3693. One-line fix per pointer. |
| 9 | GitHub issue | #222 / #223 | Segfault when `Minimum 100%` is set in config and an inbound message has an empty body. The `l=` tag body-limit handling does not guard against zero-length body before computing the percentage ratio. | **Investigate** `opendkim.c` around `conf_minimum` / `Minimum` config parsing (~line 5759 / 6920) and the body-canonicalisation path. Check for division by zero or NULL body pointer dereference. | Issue #223 is the proposed fix PR. Still open upstream. |
| 10 | GitHub issue | #229 / #230 | `dkimf_config_load()` sign-table consistency walk: `dkimf_db_walk()` error return is not checked correctly, causing the walk to continue on error and potentially produce a false "config OK" result. | **Investigate** `opendkim.c` signing-table validation walk in `dkimf_config_load()`. Verify that `dkimf_db_walk()` return codes are handled for both `SigningTable` and `KeyTable`. | PR #230 proposes the fix. Still open upstream. |
| 11 | GitHub issue | #262 | `DKIM_STAT_KEYFAIL` error from `dkim_eoh()` is handled in `mlfi_eom()` error path but the matching path in `mlfi_eoh()` itself (around line 10378) may not surface the error correctly, causing the milter to continue processing a message whose key retrieval already failed. | **Investigate** `mlfi_eoh()` return path when `dkimf_libstatus()` returns `DKIM_STAT_KEYFAIL`. Confirm that the milter returns `SMFIS_TEMPFAIL` rather than `SMFIS_CONTINUE`. | PR #262 addresses this. Still open upstream. |

### Investigate — lower priority

| Priority | Source | ID / File | Summary | Recommendation | Notes |
|----------|--------|-----------|---------|----------------|-------|
| 12 | GitHub issue | #233 / #234 | When a `DKIM_SIGFLAG_IGNORE`-marked signature is encountered, OpenDKIM records `dkim=fail` in `Authentication-Results` instead of `dkim=policy`. RFC 8601 §2.7.1 distinguishes these results. | **Investigate** `mlfi_eom()` result-string selection logic. | PR #234 proposes the one-line fix. Correctness issue affecting downstream policy evaluation. |
| 13 | GitHub issue | #244 | Enhanced compiler warnings on Debian/Fedora expose string-pointer aliasing issues in `opendkim.c` (vbr.c is already removed). Mis-used string pointers can produce wrong signing domain under pathological conditions. | **Investigate** with `-Wextra -Waddress` on `opendkim.c`. | PR #244 is open upstream. Low practical risk but worth auditing given the compiler warning evidence. |
| 14 | Debian patch | `nsupdate_output.patch` | `opendkim-genzone -u` (nsupdate mode) outputs bare key data without the required `v=DKIM1; k=rsa;` prefix, and does not chunk the key into 255-byte DNS TXT strings. Also adds `-M` flag to restrict key to email use (`s=email`). | **Investigate** `opendkim-genzone.c` nsupdate output path. The fix is mechanical; verify our code has the same defect before applying. | Our genzone.c has no `mailrestrict` or `subdomains` variable — the patch adds both. Apply only the nsupdate format fix; skip the `subdomains` block (that logic differs from ours). |
| 15 | Debian patch | `suppress-brackets-syslog.patch` | Startup syslog message `opendkim vX.Y.Z starting ()` prints empty parentheses when no arguments are logged. | **Apply** cosmetically: guard the `(%s)` format with a ternary, or omit parens when `argstr` is empty. | Confirmed at `opendkim.c:14484`. One-line fix. Low priority. |

### Skip

| Source | ID / File | Reason |
|--------|-----------|--------|
| Debian patch | `fix-RSA_Sign-call.patch` | Patches `RSA_sign()` type mismatch — function replaced by EVP APIs in our fork (Session 6). |
| Debian patch | `2048bit-genkey.patch` | Default key size already enforced at 2048 bits in our fork (`MinKeyBits`, commit `0e4aad7d`). |
| Debian patch | `replace-headers.patch` | Adds `ReplaceHeaders` config inside `#ifdef _FFR_REPLACE_RULES`. Feature removed per SCOPE.md. |
| Debian patch | `fix-genzone-subdomains.patch` | Fixes a `subdomains` flag logic block in `opendkim-genzone.c`. Our genzone has no `subdomains` variable — the feature was not ported. N/A. |
| Debian patch | `lua-5.3.patch` | `lua_dump()` extra-arg and `luaL_newlib` already handled in our Lua 5.4 port (commit `a87e550b`, `opendkim-lua.c:538` confirmed). |
| Debian patch | `ares-missing-space.patch` | c-ares / libar removed per SCOPE.md (commit `c3f6e3f9`). |
| Debian patch | `rev-ares-deletion.patch` | libar removed. |
| Debian patch | `opendkim-genkey-typo.patch` | Upstream man-page typo in `.8.in` — we have rewritten man pages, not the autotools `.in` versions. |
| GitHub issue | #255, #235, #236 | Website / opendkim.org dead links. Not software. |
| GitHub issue | #258, #257 | `SingleAuthResult` in sample config — already absent from our `opendkim.conf.sample`. |
| GitHub issue | #248, #251 | MySQL password / auth plugin issues — MySQL backend removed per SCOPE.md. |
| GitHub issue | #224 | `librbl/rbl.c` typo — librbl removed per SCOPE.md. |
| GitHub issue | #237 | Python `twisted.internet.defer.returnValue` — not C code, not in scope. |
| GitHub issue | #249 | macOS port group membership issue — macOS is not a target platform. |
| GitHub issue | #253 | VSZ memory growth under load test — operational question, not a code defect. |
| GitHub issue | #165 | Systemd `network-online.target` — already in our `debian/opendkim.service`. |
| GitHub issue | #38 | `/var/run` vs `/run` path — already resolved by `RuntimeDirectory=opendkim` in our service unit. |
| GitHub issue | #242 | `AlwaysAddARHeader` default — feature request, out of scope for this session. |
| GitHub issue | #241 | Lua `final` hook header mutation — feature request, out of scope. |
| GitHub issue | #232 | Config option to require `d=` matches `From:` — feature request, out of scope. |
| GitHub issue | #246 | Ed25519 in opendkim-genkey — already added in our fork (commit `3858b88d`). |
| GitHub issue | #243 | Ed25519 tests — partially addressed; `dkim_free()` memory leak subpoint needs separate investigation. |
| GitHub issue | #221 | Config option case sensitivity — documentation / user question, not a defect. |
| GitHub issue | #225 | Test failures on upstream autotools build — our CMake build passes. Not applicable. |

---

## 2. RC/init patterns worth adopting

Comparing **FreeBSD** `milter-opendkim.in` and **OpenBSD** `opendkim.rc` against our
`debian/opendkim.service`. Items marked ★ are currently missing from our service unit.

- **★ Additional systemd hardening directives.** Our unit has `ProtectSystem=strict` and
  `ProtectHome=true` but is missing `NoNewPrivileges=true`, `PrivateTmp=true`,
  `LockPersonality=true`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, and
  `MemoryDenyWriteExecute=true`. FreeBSD and OpenBSD achieve equivalent isolation
  through `jail(8)` and `pledge(2)` — on Linux, systemd sandboxing directives are the
  idiomatic equivalent.

- **Socket cleanup on stop.** FreeBSD's `stop_postcmd` unconditionally removes the Unix
  domain socket file (`rm -f "$socket"`) when `socket_type == local|unix`. Our
  `RuntimeDirectory=opendkim` causes systemd to clean `/run/opendkim/` on stop, so this
  is already covered on systemd systems. Worth documenting for any future non-systemd
  init script (e.g. OpenRC for Gentoo/Alpine).

- **PidFile auto-detection from opendkim.conf.** FreeBSD reads the `PidFile` value
  directly from the config file at rc-script runtime (`get_pidfile_from_conf`), rather
  than hardcoding `/var/run/milteropendkim/pid`. This avoids divergence when the admin
  changes `PidFile` in opendkim.conf. Our systemd unit does not manage a pidfile
  (`Type=simple`), so this is irrelevant for systemd but matters for portable rc scripts.

- **★ Multi-instance / profile support.** FreeBSD supports running several opendkim
  instances under different `rc.conf` profiles (e.g. `milteropendkim_profiles="sign
  verify"`), each with its own socket and config. This maps directly to SCOPE.md's
  `resign` / multi-tenant use cases. Worth documenting as an rc.conf pattern even if
  we do not ship a FreeBSD rc script initially.

- **Socket directory and permission creation with `install -d`.** FreeBSD uses
  `install -d -o uid -g gid -m mode dir` to atomically create the socket directory with
  correct ownership in a single command, rather than the common `mkdir -p; chown; chmod`
  three-step. Safer against TOCTOU races on tmpfs. Our `RuntimeDirectory=opendkim` + 
  `RuntimeDirectoryMode=0750` does this atomically on systemd — the same principle.

- **★ `_opendkim` account name.** OpenBSD and Debian both use an underscore-prefixed
  (`_opendkim`) or unprefixed (`opendkim`) system account. OpenBSD convention is
  underscore-prefix for all system daemons to distinguish them from login accounts
  (`_nsd`, `_smtpd`, etc.). Our Debian package uses `opendkim` without a prefix.
  FreeBSD defaults to `mailnull:mailnull`. Adopt `_opendkim` if we ever ship an
  OpenBSD port.

- **OpenBSD disables reload (`rc_reload=NO`).** OpenBSD's rc script has no `USR1`
  reload — it simply restarts. Our systemd unit implements `ExecReload=/bin/kill -USR1
  $MAINPID` which is the correct behaviour for live config reload without dropping
  connections. Do not follow OpenBSD's simplification here.

- **Privilege drop via daemon `-u` flag vs. init-system `User=`.** OpenBSD passes
  `-u _opendkim` on the command line; FreeBSD passes `-u uid:gid`. Our unit uses
  `User=opendkim` (systemd). The daemon's own `-u` flag works on all platforms and is a
  useful fallback for deployments without systemd (e.g. Docker, manual invocation). Keep
  `-u` as a documented CLI option even on systemd deployments.

---

## 3. Init/service scripts for contrib/

The following scripts are collected verbatim from upstream distro sources for eventual
placement in `contrib/`. Each is annotated with its source URL and the version of
opendkim it was written for. They will need adaptation for opendkim-ng paths
(`/usr/sbin/opendkim`, `/etc/opendkim.conf`, user name, socket path).

---

### FreeBSD — `contrib/freebsd/milter-opendkim`

Source: `https://codeberg.org/FreeBSD/freebsd-ports/raw/branch/main/mail/opendkim/files/milter-opendkim.in`  
Upstream version: opendkim 2.10.3

```sh
#!/bin/sh

# PROVIDE: milter-opendkim
# REQUIRE: DAEMON
# BEFORE: mail
# KEYWORD: shutdown

# Define these milteropendkim_* variables in one of these files:
#	/etc/rc.conf
#	/etc/rc.conf.local
#	/etc/rc.conf.d/milteropendkim
#
# milteropendkim_enable (bool):   Set to "NO" by default.
#                             Set it to "YES" to enable dkim-milter
# milteropendkim_uid (str):       Set username to run milter.
# milteropendkim_gid (str):       Set group to run milter.
# milteropendkim_profiles (list): Set to "" by default.
#                             Define your profiles here.
# milteropendkim_cfgfile (str):   Configuration file. See opendkim.conf(5)
#
# milteropendkim_${profile}_* :   Variables per profile.
#                             Sockets must be different from each other.
#
# milteropendkim_socket_perms (str):
#                                 Permissions for local|unix socket.
#
#  all parameters below now can be set in opendkim.conf(5).
# milteropendkim_socket (str):    Path to the milter socket.
# milteropendkim_domain (str):    Domainpart of From: in mails to sign.
# milteropendkim_key (str):       Path to the private key file to sign with.
# milteropendkim_selector (str):  Selector to use when signing
# milteropendkim_alg (str):       Algorithm to use when signing
# milteropendkim_flags (str):     Flags passed to start command.

. /etc/rc.subr

name="milteropendkim"
rcvar=milteropendkim_enable

extra_commands="reload"
start_precmd="dkim_prepcmd"
start_postcmd="dkim_start_postcmd"
stop_postcmd="dkim_postcmd"
command="%%PREFIX%%/sbin/opendkim"
_piddir="/var/run/milteropendkim"
pidfile="${_piddir}/pid"
sig_reload="USR1"

load_rc_config $name

#
# DO NOT CHANGE THESE DEFAULT VALUES HERE
#
: ${milteropendkim_enable:="NO"}
: ${milteropendkim_uid:="mailnull"}
: ${milteropendkim_gid:="mailnull"}
: ${milteropendkim_cfgfile:="%%PREFIX%%/etc/mail/opendkim.conf"}
: ${milteropendkim_socket_perms:="0755"}

# Options other than above can be set with $milteropendkim_flags.
# see dkim-milter documentation for detail.

extra_commands="reload"
start_precmd="dkim_prepcmd"
start_postcmd="dkim_start_postcmd"
stop_postcmd="dkim_cleansockets"
command="%%PREFIX%%/sbin/opendkim"
sig_reload="USR1"

dkim_cleansockets()
{
    case ${milteropendkim_socket%:*} in
    local|unix)
	rm -f "${milteropendkim_socket#*:}"
	;;
    esac
}

dkim_get_pidfile()
{
	if get_pidfile_from_conf PidFile ${milteropendkim_cfgfile#-x }; then
		pidfile="$_pidfile_from_conf"
	else
		pidfile="/var/run/milteropendkim/${profile:-pid}"
	fi
}

dkim_prepcmd()
{
    dkim_cleansockets
    dkim_get_pidfile
    if [ ! -d "$(dirname "$pidfile")" ]; then
        mkdir "$(dirname "$pidfile")"
    fi
    case ${milteropendkim_socket%:*} in
    local|unix)
	socketfile=${milteropendkim_socket#*:}
	install -d -o ${milteropendkim_uid%:*} -g $milteropendkim_gid \
	    -m ${milteropendkim_socket_perms} \
	       ${pidfile%/*} ${socketfile%/*}
	;;
    esac
}

dkim_start_postcmd()
{
    case ${milteropendkim_socket%:*} in
    local|unix)
	# postcmd is executed too fast and socket is not created before checking...
	sleep 1
	chmod -f ${milteropendkim_socket_perms} ${milteropendkim_socket#*:}
	;;
    esac
}

if [ -n "$2" ]; then
    profile="$2"
    if [ -n "${milteropendkim_profiles}" ]; then
	pidfile="${_piddir}/${profile}.pid"
	eval milteropendkim_enable="\${milteropendkim_${profile}_enable:-${milteropendkim_enable}}"
	eval milteropendkim_socket="\${milteropendkim_${profile}_socket:-}"
	eval milteropendkim_socket_perms="\${milteropendkim_${profile}_socket_perms:-}"
	if [ -z "${milteropendkim_socket}" ];then
	    echo "You must define a socket (milteropendkim_${profile}_socket)"
	    exit 1
	fi
	eval milteropendkim_cfgfile="\${milteropendkim_${profile}_cfgfile:-${milteropendkim_cfgfile}}"
	eval milteropendkim_domain="\${milteropendkim_${profile}_domain:-${milteropendkim_domain}}"
	eval milteropendkim_key="\${milteropendkim_${profile}_key:-${milteropendkim_key}}"
	eval milteropendkim_selector="\${milteropendkim_${profile}_selector:-${milteropendkim_selector}}"
	eval milteropendkim_alg="\${milteropendkim_${profile}_alg:-${milteropendkim_alg}}"
	eval milteropendkim_flags="\${milteropendkim_${profile}_flags:-${milteropendkim_flags}}"
	if [ -f "${milteropendkim_cfgfile}" ];then
	    milteropendkim_cfgfile="-x ${milteropendkim_cfgfile}"
	else
	    milteropendkim_cfgfile=""
	fi
	if [ -n "${milteropendkim_socket}" ];then
	    _socket_prefix="-p"
	fi
	if [ -n "${milteropendkim_uid}" ];then
	    _uid_prefix="-u"
	    if [ -n "${milteropendkim_gid}" ];then
		milteropendkim_uid=${milteropendkim_uid}:${milteropendkim_gid}
	    fi
	fi
	if [ -n "${milteropendkim_domain}" ];then
	    milteropendkim_domain="-d ${milteropendkim_domain}"
	fi
	if [ -n "${milteropendkim_key}" ];then
	    milteropendkim_key="-k ${milteropendkim_key}"
	fi
	if [ -n "${milteropendkim_selector}" ];then
	    milteropendkim_selector="-s ${milteropendkim_selector}"
	fi
	if [ -n "${milteropendkim_alg}" ];then
	    milteropendkim_alg="-S ${milteropendkim_alg}"
	fi
	dkim_get_pidfile
	command_args="-l ${_socket_prefix} ${milteropendkim_socket} ${_uid_prefix} ${milteropendkim_uid} -P ${pidfile} ${milteropendkim_cfgfile} ${milteropendkim_domain} ${milteropendkim_key} ${milteropendkim_selector} ${milteropendkim_alg}"
    else
	echo "$0: extra argument ignored"
    fi
else
    if [ -n "${milteropendkim_profiles}" ] && [ -n "$1" ]; then
	if [ "$1" != "restart" ]; then
	    for profile in ${milteropendkim_profiles}; do
		echo "===> milteropendkim profile: ${profile}"
		%%PREFIX%%/etc/rc.d/milter-opendkim $1 ${profile}
		retcode="$?"
		if [ "${retcode}" -ne 0 ]; then
		    failed="${profile} (${retcode}) ${failed:-}"
		else
		    success="${profile} ${success:-}"
		fi
	    done
	    exit 0
	else
	    restart_precmd=""
	fi
    else
	if [ -f "${milteropendkim_cfgfile}" ];then
	    milteropendkim_cfgfile="-x ${milteropendkim_cfgfile}"
	else
	    milteropendkim_cfgfile=""
	fi
	if [ -n "${milteropendkim_socket}" ];then
	    _socket_prefix="-p"
	fi
	if [ -n "${milteropendkim_uid}" ];then
	    _uid_prefix="-u"
	    if [ -n "${milteropendkim_gid}" ];then
		milteropendkim_uid=${milteropendkim_uid}:${milteropendkim_gid}
	    fi
	fi
	if [ -n "${milteropendkim_domain}" ];then
	    milteropendkim_domain="-d ${milteropendkim_domain}"
	fi
	if [ -n "${milteropendkim_key}" ];then
	    milteropendkim_key="-k ${milteropendkim_key}"
	fi
	if [ -n "${milteropendkim_selector}" ];then
	    milteropendkim_selector="-s ${milteropendkim_selector}"
	fi
	if [ -n "${milteropendkim_alg}" ];then
	    milteropendkim_alg="-S ${milteropendkim_alg}"
	fi
	dkim_get_pidfile
	command_args="-l ${_socket_prefix} ${milteropendkim_socket} ${_uid_prefix} ${milteropendkim_uid} -P ${pidfile} ${milteropendkim_cfgfile} ${milteropendkim_domain} ${milteropendkim_key} ${milteropendkim_selector} ${milteropendkim_alg}"
    fi
fi

run_rc_command "$1"
```

**Adaptation notes for opendkim-ng:**
- Replace `%%PREFIX%%` with `/usr/local` (FreeBSD) or the install prefix.
- Default user/group: change `mailnull:mailnull` → `opendkim:opendkim`.
- Config path: `%%PREFIX%%/etc/mail/opendkim.conf` → `/usr/local/etc/opendkim.conf`.
- The `dkim_get_pidfile` helper reads `PidFile` from the config at start time —
  useful if the admin sets a custom pidfile path.
- The profile mechanism (multiple instances via `milteropendkim_profiles`) is directly
  useful for the `Resign` / multi-tenant use case in SCOPE.md.

---

### OpenBSD — `contrib/openbsd/opendkim.rc`

Source: `https://raw.githubusercontent.com/openbsd/ports/master/mail/opendkim/pkg/opendkim.rc`  
Upstream version: opendkim 2.10.3 (revision 3)

```ksh
#!/bin/ksh

daemon="${TRUEPREFIX}/sbin/opendkim"
daemon_flags="-x ${SYSCONFDIR}/opendkim.conf -u _opendkim"

. /etc/rc.d/rc.subr

rc_reload=NO

rc_cmd $1
```

**Adaptation notes for opendkim-ng:**
- `${TRUEPREFIX}` and `${SYSCONFDIR}` are substituted by the OpenBSD ports framework at
  package-install time; for a manual install use `/usr/local` and `/etc` respectively.
- User is `_opendkim` (OpenBSD convention: underscore-prefix for system daemons).
- `rc_reload=NO` deliberately omits the `USR1` reload — OpenBSD restarts instead.
  For opendkim-ng, consider enabling reload: set `rc_reload=YES` and add
  `rc_reload_signal=USR1` (supported in OpenBSD 7.0+).

---

### OpenRC (Alpine Linux) — `contrib/openrc/opendkim.initd`

Source: `https://raw.githubusercontent.com/alpinelinux/aports/master/community/opendkim/opendkim.initd`  
Upstream version: opendkim as packaged in Alpine community

```sh
#!/sbin/openrc-run

owner=opendkim
pidfile=/run/opendkim/opendkim.pid
cfgfile=/etc/opendkim/opendkim.conf
command=/usr/sbin/opendkim
command_args="$command_args -u $owner -f"
command_background=yes
required_files="$cfgfile"

depend() {
	need net
	before mta
}

start_pre() {
	local socket=$(grep ^Socket.*local: $cfgfile | cut -d: -f2)
	local basedir=$(grep ^BaseDirectory $cfgfile | awk '{print $2}')
	[ "${socket:0:1}" = "/" ] && checkpath -d -o $owner ${socket%/*}
	[ "$basedir" ] && checkpath -d -o $owner $basedir
	checkpath -d -o $owner ${pidfile%/*}
}
```

Companion `conf.d/opendkim` (Alpine):

```sh
# Extra arguments to pass to command line
#command_args=""
```

**Adaptation notes for opendkim-ng:**
- Config path matches our installed location (`/etc/opendkim/opendkim.conf` or
  `/etc/opendkim.conf` — adjust to whichever the package installs).
- `start_pre()` parses `Socket` and `BaseDirectory` from opendkim.conf using grep/awk
  to create required directories before start — this is the OpenRC idiomatic equivalent
  of systemd's `RuntimeDirectory=`.
- `command_background=yes` tells OpenRC to manage the pidfile itself; remove if
  opendkim writes its own pidfile (controlled by the `PidFile` config key).
- `need net` + `before mta` correctly expresses the dependency: network up, mail daemon
  not started yet.
- The `Socket` grep is fragile (`^Socket.*local:`) — it misses `inet:` sockets and
  breaks if the config has leading whitespace. Consider improving the parser if adopting
  this script.

---

### Runit (Void Linux) — `contrib/runit/opendkim/run`

Source: `https://raw.githubusercontent.com/void-linux/void-packages/master/srcpkgs/opendkim/files/opendkim/run`  
Upstream version: opendkim as packaged in Void Linux

```sh
#!/bin/sh
exec 2>&1
[ -r ./conf ] && . ./conf
exec opendkim -f ${OPTS}
```

Companion `conf` file (place in the service directory, e.g. `/etc/sv/opendkim/conf`):

```sh
# OPTS="-x /etc/opendkim.conf -u opendkim"
OPTS="-x /etc/opendkim.conf -u opendkim"
```

**Adaptation notes for opendkim-ng:**
- Void Linux did not ship a `log/run` script; add one if svlogd logging is desired:

  ```sh
  #!/bin/sh
  exec svlogd -tt /var/log/opendkim
  ```

- The `exec 2>&1` redirect merges stderr into stdout so runit/svlogd captures all
  output. opendkim logs via syslog by default; `-f` keeps it in the foreground without
  forking (required for runit supervision).
- `${OPTS}` must include at minimum `-x /path/to/opendkim.conf`. The `-u opendkim`
  privilege drop is done on the command line here rather than in the config file.
- The `conf` sourcing pattern is the Void/runit convention for per-service environment
  variables; it is equivalent to systemd `EnvironmentFile=`.
