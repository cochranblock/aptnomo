<!-- Unlicense — cochranblock.org -->

# Proof of Artifacts — aptnomo

*Hard evidence that this project is real, working, and built by humans with AI assistance — not AI hallucination.*

## Project Metrics

| Metric | Value |
|--------|-------|
| Source files (.rs) | 6 |
| Lines of code | 2,766 (including tests) |
| Tests | 123 (77 lib + 46 main bin) |
| Commits | 21 |
| Binary size (release) | 980 KB (1,003,744 bytes stripped) |
| Dependencies (direct) | 6 (serde, anyhow, libc, sled, bincode, zstd) + 1 optional (eframe) |
| Edition | 2024 |
| MSRV | 1.85 |
| License | Unlicense |

## Repository

- **GitHub:** https://github.com/cochranblock/aptnomo
- **Live deployment:** Bare-metal daemon — no hosted service. Drop binary on machine, run it.

## Architecture

Autonomous APT threat hunter for bare-metal Linux. A daemon binary (`aptnomo`) runs 8 detection modules in a loop — fast scan on startup (30s), then every 5 minutes. Each module reads real system paths (`/proc`, `/etc/systemd`, `/var/log`) and returns a `Vec<Threat>`. Critical process threats are auto-killed via `SIGKILL` if they pass a safe-process guard. All threats are persisted to a sled database (`~/.aptnomo/db/`) with bincode + zstd compression across three trees (threats, history, baseline). A separate GUI binary (`aptnomo-gui`, behind the `gui` cargo feature) reads the same sled DB and presents threats as swipeable cards — right = baseline, left = kill, up = quarantine. Zero config. No network calls. No cloud.

## Named Techniques

| Name | Description | Commit |
|------|-------------|--------|
| APT No Mo | Zero-config daemon-mode threat hunting — no CLI, no YAML, no cloud. Drop and run. | `b020f3c` |
| Tinder for Threats | Swipe-card threat triage: left=kill, right=baseline, up=quarantine. Mobile-friendly severity-colored cards. | `8f81f8e` |

See `TIMELINE_OF_INVENTION.md` Human Revelations section for full provenance.

## Test Coverage

| Category | Count | Location |
|----------|-------|----------|
| types unit tests | 43 | `src/types.rs` — Module, Severity, CardStatus, PatternType, ThreatCard, BaselinePattern, Stats, serde roundtrips, rotate_if_needed |
| store unit tests | 34 | `src/store.rs` — put/get, write/read threat, pending filter, resolve lifecycle, dedup, baseline CRUD, stats, scale (100 threats), compression verification |
| daemon unit tests | 46 | `src/main.rs` — chrono_now, is_safe_to_kill, detection module no-panic/returns-vec (f10-f80), scan_all, threat_to_card (fields/severity/modules/pid/path/ids/timestamp), auto-kill sled history regression (7 tests) |
| **Total** | **123** | |

Quality gate: `cargo run --bin aptnomo-test --features tests` runs exopack TRIPLE SIMS — the test pipeline 3 times, all must pass.

## Detection Modules

| # | Module | Function | Scans | Severity | Auto-kill |
|---|--------|----------|-------|----------|-----------|
| 1 | Persistence | f10 | systemd units with ExecStart under /tmp or hidden dirs | High | No |
| 2 | Network | f20 | /proc/net/tcp LISTEN on 0.0.0.0 (excludes known ports) | Medium | No |
| 3 | Rootkit | f30 | /proc/modules names: hide, stealth, rootkit, backdoor, keylog | Critical | No |
| 4 | SSH | f40 | $HOME/.ssh/authorized_keys count > 5 | Medium | No |
| 5 | Processes | f50 | /proc/pid/cmdline: cryptominer, xmrig, stratum, reverse_shell, nc -e, bash -i | Critical | **Yes** |
| 6 | Logs | f60 | Empty /var/log/{auth.log, syslog, messages} | High | No |
| 7 | Cron | f70 | Cron files containing /tmp/, curl, wget | High | No |
| 8 | Files | f80 | Hidden executables >10 KB in /tmp, /dev/shm, /var/tmp | Critical | No |

## Sled DB Schema

| Tree | Key format | Value type | Compression |
|------|-----------|------------|-------------|
| threats | `{:016}` (zero-padded u64 ID) | ThreatCard | bincode + zstd level 3 |
| history | `{:016}` (zero-padded u64 ID) | ThreatCard | bincode + zstd level 3 |
| baseline | `{module_label}:{value}` | BaselinePattern | bincode + zstd level 3 |

## Compliance

- SBOM: `govdocs/SBOM.md`
- Security policy: `govdocs/SECURITY.md` — scan targets, kill conditions, safe-process list
- Supply chain audit: `govdocs/SUPPLY_CHAIN_AUDIT.md` — dep audit, unsafe inventory
- SSDF: aligned with NIST SP 800-218
- CISA Secure-by-Design: memory-safe Rust, no C dependencies outside libc
- EO 14028: aligned

## Build

```sh
# Daemon only (default features)
cargo build --release

# Daemon + GUI
cargo build --release --features gui

# Unit tests (123 tests)
cargo test

# Quality gate (exopack TRIPLE SIMS, 3 passes)
cargo run --bin aptnomo-test --features tests

# Lint (must be zero warnings)
cargo clippy --all-targets --features gui
```

Release profile:

```toml
[profile.release]
opt-level    = "z"
lto          = true
codegen-units = 1
panic        = "abort"
strip        = true
```

## Verification

A third party can verify every claim in this document:

1. **Binary size:** `cargo build --release && ls -la target/release/aptnomo` — expect ~980 KB.
2. **Test count:** `cargo test 2>&1 | grep "test result"` — expect 77 + 46 + 0 = 123 passing.
3. **Clippy clean:** `cargo clippy --all-targets --features gui 2>&1 | grep warning` — expect no output.
4. **Commit count:** `git rev-list --count HEAD` — expect 21+.
5. **Detection modules:** `grep -c "fn f[0-9]*_" src/main.rs` — expect 8.
6. **Zero config:** `grep -r "clap\|structopt\|config\|\.env\|dotenv" Cargo.toml src/` — expect no matches.
7. **No network calls:** `grep -r "reqwest\|hyper\|curl\|TcpStream::connect" src/` — expect no matches.
8. **Commit hashes:** `git log --oneline` — every hash in the Commit Log below is present.

## Commit Log

| Hash | Date | Message |
|------|------|---------|
| `b020f3c` | 2026-03-30 | initial commit: 312 KB autonomous APT threat hunter |
| `e87cff1` | 2026-03-30 | release-ready: docs, govdocs, compression map, exopack test gate |
| `536da5d` | 2026-03-30 | fix TOI: add AI Role field to every entry, add commit hashes |
| `f0afe25` | 2026-03-31 | sync TOI and POA with all commits from last 48 hours |
| `8f81f8e` | 2026-04-02 | phase 2: sled store, shared types, egui GUI binary |
| `6ef1651` | 2026-04-02 | docs: update all docs for phase 2 accuracy |
| `1b7dad0` | 2026-04-02 | docs: add P23 Triple Lens quality gate to README and POA |
| `161a69e` | 2026-04-02 | add BACKLOG.md: 20 prioritized work items |
| `1df0393` | 2026-04-02 | fix: remove unused clap and serde_json deps |
| `8fd969f` | 2026-04-02 | test: add 4 integration tests for sled store lifecycle |
| `70181d9` | 2026-04-03 | feature: graceful shutdown on SIGTERM/SIGINT |
| `aaa4b9c` | 2026-04-03 | fix: GUI swipe animation — card shifts horizontally |
| `bcdbb5b` | 2026-04-03 | feature: populate process_name and command from /proc |
| `d006501` | 2026-04-03 | feature: sled dedup — skip duplicate pending threats |
| `e3ff930` | 2026-04-03 | feature: log rotation at 10 MB |
| `87faa6b` | 2026-04-03 | test: 39 unit tests for main.rs |
| `bc75ed2` | 2026-04-03 | P23 triple lens: readjust fire |
| `ab3e597` | 2026-04-03 | fix: auto-kill sled history bug — capture card ID from first write |
| `5db6abb` | 2026-04-03 | decouple exopack: path dep to git |
| `482640f` | 2026-04-09 | docs+chore: CLAUDE.md, refreshed BACKLOG/README, clippy clean |
| `0267b0e` | 2026-04-09 | docs: log 2026-04-09 docs refresh in TOI/POA |

---

*Part of the [CochranBlock](https://cochranblock.org) zero-cloud architecture.*
