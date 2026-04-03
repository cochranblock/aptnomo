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
| Lines of code | ~1,200 |
| Unsafe blocks | 1 in daemon (libc::kill), 2 in GUI (libc::kill, libc::SIGSTOP) |
| Feature gates | 2 (gui -> eframe, tests -> exopack) |
| Unit tests | 6 (store: write/read, pending filter, resolve, baseline, stats, id monotonic) |

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
