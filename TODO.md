## _FFR_DNSSEC — DNSSEC validation support (future work)
The `_FFR_DNSSEC` guards are intentionally preserved. This feature adds DNSSEC
validation of DNS responses used in DKIM key lookups. It was partially implemented
but not completed. Future work:
- Audit existing `_FFR_DNSSEC` blocks for correctness
- Wire up the resolver to pass DNSSEC-validated status through to the policy engine
- Add test coverage
- Once complete, promote to unconditional (remove guards) or make a configure option

## _FFR_DB_HANDLE_POOLS — DB connection pooling (needs CMake integration)
The pooling implementation in `opendkim-db.c` provides connection reuse for
database backends (MySQL, PostgreSQL, etc.) in high-volume deployments.
The code exists behind `_FFR_DB_HANDLE_POOLS` guards but was never wired
into the build system — no configure option or CMake option exists for it.

Future work:
- Audit the pooling code in opendkim-db.c for correctness
- Add a CMake option: -DENABLE_DB_HANDLE_POOLS=ON (default OFF)
- Add the corresponding define to the generated build-config.h
- Test under concurrent load with MySQL/PostgreSQL backends
- If validated, make it the default and remove the guards

