# Timeline of Invention — [aptnomo](https://cochranblock.org)

## 2026-03-30 — Initial scaffold

**Commit:** `b020f3c` — initial commit: 312 KB autonomous APT threat hunter

**What:** Single-file autonomous APT threat hunter. 312 KB binary. 8 detection modules (persistence, network, rootkit, SSH, processes, logs, cron, files). Daemon loop with adaptive scan interval (30s fast, 5m steady). Auto-kill for critical process threats with safe-process guard list. Zero config — drop and run.

**AI Role:** AI (Claude Opus 4.6) implemented the daemon architecture, 8 detection modules, auto-kill logic, and safe-process list from human direction. Human (GotEmCoach) specified the autonomous daemon concept, Tinder-style GUI design, zero-config philosophy, and the aptnomo name (APT No Mo). Gemini Pro 3 generated the product hero image.

**Artifacts created:**
- `src/main.rs` — full daemon with all 8 detection modules
- `src/bin/aptnomo-test.rs` — exopack TRIPLE SIMS test binary
- `Cargo.toml` — release profile tuned for 312 KB
- `docs/GUI_DESIGN.md` — Tinder-for-threats swipe UI design
- `govdocs/` — SBOM, SECURITY, SUPPLY_CHAIN_AUDIT
- `docs/compression_map.md` — f0-f80 function tokenization
- `PROOF_OF_ARTIFACTS.md` — binary size, module count, detection categories
- `UNLICENSE` — public domain

**Architecture decisions:**
- Single binary, no config files, no CLI flags needed
- Daemon-first: runs forever, silent when clean
- Auto-kill only for processes, only when safe (never user shells/editors)
- Future GUI communicates via shared sled DB, not IPC
- exopack TRIPLE SIMS for quality gate

---

## 2026-03-30 — Release-ready docs and test gate

**Commit:** `e87cff1` — release-ready: docs, govdocs, compression map, exopack test gate

**What:** Full documentation suite: PROOF_OF_ARTIFACTS.md, TIMELINE_OF_INVENTION.md, govdocs/SECURITY.md (scan targets, kill conditions, safe-process list), govdocs/SUPPLY_CHAIN_AUDIT.md (dep audit, unsafe inventory), docs/compression_map.md (f0-f80 tokenization). Updated SBOM. Wired aptnomo-test binary to exopack TRIPLE SIMS f61 with 3-pass gate.

**AI Role:** AI (Claude Opus 4.6) wrote all documentation, govdocs, compression map, and wired the exopack TRIPLE SIMS test binary from human direction. Human (GotEmCoach) specified the release-ready checklist, document requirements, and GitHub repo creation.

---

## 2026-03-30 — TOI format fix

**Commit:** `536da5d` — fix TOI: add AI Role field to every entry, add commit hashes

**What:** Added AI Role field to all TIMELINE_OF_INVENTION.md entries. Added commit hashes to each entry. Added second entry for the release-ready docs commit. Established the TOI format: Date, Commit, What, AI Role, Artifacts, Architecture decisions.

**AI Role:** AI (Claude Opus 4.6) updated TOI format from human direction. Human (GotEmCoach) specified the AI Role requirement and provided the role description for the initial scaffold entry.

---

## 2026-03-31 — TOI/POA sync

**Commit:** `f0afe25` — sync TOI and POA with all commits from last 48 hours

**What:** Added missing 536da5d entry to TOI with AI Role. Added commit log table to PROOF_OF_ARTIFACTS with all 3 commits, dates, and hashes.

**AI Role:** AI (Claude Opus 4.6) synced documentation from human direction.

---

## 2026-04-02 — Phase 2: sled store + GUI binary

**What:** Full Phase 2 implementation. Added shared types module (ThreatCard, BaselinePattern, CardStatus, Module, Severity), sled database with bincode + zstd compression (6 unit tests), daemon integration (writes threats to sled alongside flat files), and egui "Tinder for Threats" GUI binary with swipe-card interface, stats screen, and baseline learning. Daemon binary grew from 312 KB to ~980 KB (sled/bincode/zstd deps). GUI binary: ~3.5 MB. Version bumped to 0.2.0.

**AI Role:** AI (Claude Opus 4.6) implemented the full Phase 2 from the GUI_DESIGN.md spec: types module, sled store (ported from illbethejudgeofthat pattern), daemon sled integration, egui GUI with card rendering/swipe gestures/stats/theme, and all unit tests. Human (GotEmCoach) directed the phase, approved the plan, and specified IRONHIVE cluster context.

**Artifacts created:**
- `src/lib.rs` — crate root for shared modules
- `src/types.rs` — t10-t13 shared types (ThreatCard, BaselinePattern, CardStatus, PatternType)
- `src/store.rs` — sled DB with bincode + zstd, 6 unit tests
- `src/bin/aptnomo-gui.rs` — egui swipe-card GUI (f90-f95, f98; f96-f97 in store.rs)
- `src/main.rs` — modified: sled integration, threat_to_card converter

**Architecture decisions:**
- Single crate with lib.rs exposing shared modules (no separate -core crate)
- sled + bincode + zstd pattern ported from illbethejudgeofthat
- GUI feature-gated behind `gui` feature to keep daemon binary small
- Daemon keeps flat file output as fallback if sled fails
- Theme ported from kova's egui pattern with aptnomo severity colors

---

## 2026-04-09 — Docs refresh + clippy clean across the board

**Commit:** `482640f` — docs+chore: CLAUDE.md, refreshed BACKLOG/README, clippy clean across the board

**What:** Full documentation refresh anchored on the current code state. Wrote `CLAUDE.md` from scratch (project oneliner, build/test commands, complete module map across `lib.rs` / `types.rs` / `store.rs` / `main.rs` / `aptnomo-gui.rs` / `aptnomo-test.rs`, detection-module table, sled schema, conventions). Rewrote `BACKLOG.md` with 20 prioritized items grounded in actual code (top items: f50 NUL-delimited cmdline signature bug, daemon ignores learned baselines, macOS detection backends). Polished `README.md` to production-grade with accurate metrics (123 unit tests, ~980 KB measured release binary, corrected detection table, ASCII flow diagram, clarified auto-kill model). Repaired all clippy warnings: moved test mod after detection modules in `main.rs` to fix `items_after_test_module`; collapsed nested `if`/`if let` blocks via 2024-edition let-chains in `main.rs`, `types.rs`, `store.rs`, and `aptnomo-gui.rs`; switched `DoubleEndedIterator::last` → `next_back`; rebuilt `store::stats()` via struct-update syntax instead of post-init field reassignment.

**AI Role:** AI (Claude Opus 4.6, 1M context, via Claude Code) read the full source tree, drafted CLAUDE.md / BACKLOG.md / README.md, restructured `src/main.rs` to satisfy `clippy::items_after_test_module`, applied let-chain collapses across four files, and verified `cargo clippy --all-targets --features gui` reports zero warnings and `cargo test` passes 123/123. Human (GotEmCoach) directed the docs refresh and clippy-clean requirement.

**Artifacts created/updated:**
- `CLAUDE.md` *(new)* — project notes for Claude Code sessions
- `BACKLOG.md` — 20 prioritized work items
- `README.md` — production-grade refresh
- `src/main.rs` — test mod relocated to file end; let-chain collapses; `next_back` fix
- `src/store.rs` — `stats()` struct-update form
- `src/types.rs` — `rotate_if_needed` let-chain
- `src/bin/aptnomo-gui.rs` — two pid-bounds let-chain collapses

**Verification:**
- `cargo clippy --all-targets --features gui` → zero warnings
- `cargo test` → 123 passed / 0 failed (77 lib + 46 main bin + 0 doc tests)
- `cargo build --release` → `target/release/aptnomo` 1,003,744 bytes (~980 KB stripped)

**Architecture decisions:**
- 2024-edition let-chains adopted as the canonical style for collapsing nested `if let`/`if` blocks
- Test modules live at the *end* of source files in this crate (lint-clean by construction)
- BACKLOG entries reference the file/function they touch so contributors can pick them up cold
- CLAUDE.md is the single source of truth for build/test commands; README is the public face
