# Proof of Artifacts — [aptnomo](https://cochranblock.org)

## Binaries

| Binary | Feature | Size (release, stripped) | Purpose |
|--------|---------|--------------------------|---------|
| aptnomo | default | ~980 KB | Headless daemon |
| aptnomo-gui | gui | ~3.5 MB | Threat review UI (egui) |
| aptnomo-test | tests | — | Quality gate (TRIPLE SIMS) |

| Metric | Value |
|--------|-------|
| Language | Rust (edition 2024) |
| Target | x86_64-unknown-linux-gnu / aarch64-apple-darwin |
| Dependencies (daemon) | 6 (serde, anyhow, libc, sled, bincode, zstd) |
| Dependencies (GUI) | +1 (eframe, optional) |
| External services | 0 — no network, no cloud |
| Config files | 0 — zero config |
| Storage | sled DB at ~/.aptnomo/db/ (bincode + zstd) |

## Detection Modules

| # | Module | Function | Severity Range | Auto-kill |
|---|--------|----------|----------------|-----------|
| 1 | Persistence | f10 | High | No |
| 2 | Network | f20 | Medium | No |
| 3 | Rootkit | f30 | Critical | No |
| 4 | SSH | f40 | Medium | No |
| 5 | Processes | f50 | Critical | Yes |
| 6 | Logs | f60 | High | No |
| 7 | Cron | f70 | High | No |
| 8 | Files | f80 | Critical | No |

**Module count: 8**

## Detection Categories

| Category | Modules | Description |
|----------|---------|-------------|
| Persistence | f10, f70 | Systemd units, cron jobs pointing to temp/hidden paths |
| Network | f20 | Unknown listeners on all interfaces |
| Kernel | f30 | Suspicious kernel module names |
| Authentication | f40 | SSH authorized_keys anomalies |
| Process | f50 | Known malware process signatures |
| Integrity | f60, f80 | Log tampering, hidden executables in temp dirs |

## Sled DB Schema

| Tree | Key format | Value type | Compression |
|------|-----------|------------|-------------|
| threats | `{:016}` (zero-padded id) | ThreatCard | bincode + zstd level 3 |
| baseline | `{module}:{value}` | BaselinePattern | bincode + zstd level 3 |
| history | `{:016}` (zero-padded id) | ThreatCard | bincode + zstd level 3 |

## GUI Functions

| Token | Name | Purpose |
|-------|------|---------|
| f90 | gui_main | eframe entry point, 420x720 viewport |
| f91 | render_card | Severity-colored card with module, title, details |
| f92 | swipe_handler | Drag detection: right=baseline, left=kill, up=quarantine |
| f93 | baseline_learn | Extract pattern from card, write to baseline tree |
| f94 | stats_screen | Counts per status and module |
| f95 | sled_read | Poll sled every 1s for pending threats |
| f96 | get | Generic sled get with bincode+zstd decompression |
| f97 | put | Generic sled put with bincode+zstd compression |
| f98 | apply_theme | Dark theme with severity color palette |

## Build Verification

```bash
# Build release daemon
cargo build --release -p aptnomo

# Build release GUI
cargo build --release -p aptnomo --features gui

# Run unit tests (6 store tests)
cargo test

# Run test gate (exopack TRIPLE SIMS)
cargo run -p aptnomo --bin aptnomo-test --features tests
# Expected: exit 0, 3/3 PASS
```

## Release Profile

```toml
[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

## Source Stats

| Metric | Value |
|--------|-------|
| Source files | 6 (lib.rs, types.rs, store.rs, main.rs, aptnomo-gui.rs, aptnomo-test.rs) |
| Lines of code | ~2,750 (including tests) |
| Unsafe blocks | 3 in daemon (signal handlers + libc::kill), 2 in GUI (libc::kill, libc::SIGSTOP) |
| Feature gates | 2 (gui -> eframe, tests -> exopack) |
| Unit tests | **123** (77 lib: types + store; 46 main bin: detection + threat_to_card + auto-kill regression) |
| Clippy | `cargo clippy --all-targets --features gui` — **0 warnings** |
| Release binary | `target/release/aptnomo` — **1,003,744 bytes** (~980 KB stripped) |

## P23: Triple Lens

| Lens | Question | aptnomo Answer |
|------|----------|----------------|
| **Technical** | Compile, test, run on real hardware? | 6 store unit tests pass. TRIPLE SIMS 3/3. Daemon + GUI build clean. Release profile: LTO, strip, panic=abort. |
| **Product** | Solve a real problem? | Autonomous APT detection on bare metal. Zero config, zero cloud, zero telemetry. 8 detection modules covering persistence, network, rootkit, SSH, processes, logs, cron, files. |
| **Honest** | Claims verifiable? | Binary sizes from `ls -la`. Every detection module reads real `/proc` and `/etc` paths. SBOM and supply chain audit in `govdocs/`. Every commit hash in `TIMELINE_OF_INVENTION.md`. |

## Commit Log

| Hash | Date | Message |
|------|------|---------|
| `b020f3c` | 2026-03-30 | initial commit: 312 KB autonomous APT threat hunter |
| `e87cff1` | 2026-03-30 | release-ready: docs, govdocs, compression map, exopack test gate |
| `536da5d` | 2026-03-30 | fix TOI: add AI Role field to every entry, add commit hashes |
| `f0afe25` | 2026-03-31 | sync TOI and POA with all commits from last 48 hours |
| `8f81f8e` | 2026-04-02 | phase 2: sled store, shared types, egui GUI binary |
| `482640f` | 2026-04-09 | docs+chore: CLAUDE.md, refreshed BACKLOG/README, clippy clean across the board |

## 2026-04-09 — Docs refresh + clippy clean (`482640f`)

**What landed:**
- New `CLAUDE.md` — project oneliner, build/test commands, full module map, detection-module table, sled schema, conventions
- Rewritten `BACKLOG.md` — 20 prioritized work items grounded in current code, each anchored to file/function
- Production-grade `README.md` — accurate test count (123), measured release size (~980 KB), corrected detection table, clarified auto-kill model, ASCII flow diagram
- `src/main.rs` — test mod relocated to file end (fixes `clippy::items_after_test_module`); nested `if`/`if let` blocks collapsed via 2024-edition let-chains; `DoubleEndedIterator::last` → `next_back`
- `src/store.rs` — `stats()` rebuilt via struct-update syntax (fixes `clippy::field_reassign_with_default`)
- `src/types.rs` — `rotate_if_needed` collapsed via let-chain
- `src/bin/aptnomo-gui.rs` — two pid-bounds let-chain collapses

**Verification (run on commit `482640f`):**

```text
$ cargo clippy --all-targets --features gui
    Finished `dev` profile [unoptimized + debuginfo] target(s)
    (zero warnings)

$ cargo test
test result: ok. 77 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 46 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok.  0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
                  ────────
                  123 / 123

$ cargo build --release && ls -la target/release/aptnomo
-rwxr-xr-x  1 mcochran  staff  1003744  Apr  9 12:42  target/release/aptnomo
```

**Diff stat:** 8 files changed, 1316 insertions(+), 371 deletions(-)

**AI Role:** AI (Claude Opus 4.6, 1M context, via Claude Code) read the full source tree, drafted the three docs files, restructured `src/main.rs` for the test-module relocation, applied let-chain collapses across four files, and verified clippy + test cleanliness before commit. Human (GotEmCoach) directed the docs refresh and clippy-clean requirement.
