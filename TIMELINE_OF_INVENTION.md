<!-- Unlicense — cochranblock.org -->

# Timeline of Invention — aptnomo

*Dated, commit-level record of what was built, when, and why. Proves human-piloted AI development — not generated spaghetti.*

> Every entry below maps to real commits. Run `git log --oneline` to verify.

## How to Read This Document

Each entry follows this format:

- **Date**: When the work shipped (not when it was started)
- **What**: Concrete deliverable — binary, feature, fix, architecture change
- **Why**: Business or technical reason driving the decision
- **Commit**: Short hash(es) for traceability
- **AI Role**: What the AI did vs. what the human directed
- **Proof**: Link to artifact, screenshot, test output, or live URL

This document exists because AI-assisted code has a trust problem. Anyone can generate 10,000 lines of spaghetti. This timeline proves that a human pilot directed every decision, verified every output, and shipped working software.

---

## Human Revelations — Invented Techniques

*Novel ideas that came from human insight, not AI suggestion. These are original contributions to the field.*

### APT No Mo: Drop-and-Run Threat Hunting (2026-03-30)

**Invention:** Zero-config autonomous APT threat hunter that requires no CLI interaction, no config files, no cloud, no agent platform.

**The Problem:** Every APT detection tool on the market requires configuration, cloud connectivity, agent infrastructure, or manual operation. Bare-metal Linux boxes in edge deployments get no protection because nobody maintains the tooling.

**The Insight:** Treat threat hunting like a daemon, not a tool. No config means no misconfiguration. No cloud means no data exfil risk. No interaction means it works on forgotten machines in closets. Name it what it does: APT? No mo.

**The Technique:** Single Rust binary, 8 detection modules reading /proc and /etc directly, adaptive scan interval (fast after threats, slow when clean), auto-kill only for process-based Critical threats that pass a safe-process guard list. All state in a local sled DB — no network calls ever.

**Result:** Sub-1 MB binary. 8 detection categories. Runs unattended on bare metal with zero setup. Threat review via a separate GUI binary sharing the same sled DB.

**Named:** APT No Mo (aptnomo)
**Commit:** `b020f3c`
**Origin:** GotEmCoach — observed that edge Linux boxes in his fleet had no APT coverage because every tool required cloud or config. Specified the name, daemon-first philosophy, and "Tinder for Threats" GUI concept.

### Tinder for Threats: Swipe-Card Threat Review (2026-04-02)

**Invention:** Mobile-friendly threat triage via left/right/up swipe gestures on severity-colored cards.

**The Problem:** Threat review interfaces are desktop-first dashboards with tables and filters. Reviewing threats on a phone over SSH is painful. Security analysts on-call need a one-handed review flow.

**The Insight:** Threat triage is a binary decision (kill or ignore) with one escape hatch (quarantine). That's exactly a dating-app swipe pattern. Right = baseline (this is fine), left = kill, up = quarantine. No menus, no forms.

**The Technique:** egui cards with severity-colored borders (green/yellow/orange/red), horizontal drag detection with threshold-based commit, baseline pattern learning on right-swipe that writes to a shared sled DB tree for future daemon suppression.

**Result:** Full threat triage in 3 gestures. Baseline patterns learned from swipes. Stats screen shows resolution breakdown. 420x720 viewport sized for mobile.

**Named:** Tinder for Threats
**Commit:** `8f81f8e`
**Origin:** GotEmCoach — specified in `docs/GUI_DESIGN.md` before any code was written. The swipe-to-triage concept and severity color mapping came from human UX design, not AI suggestion.

---

## Entries

*Reverse chronological. Most recent first.*

### 2026-04-09 — Docs refresh + clippy clean across the board

**What:** Full documentation refresh: new `CLAUDE.md` (project oneliner, build/test commands, complete module map, detection-module table, sled schema, conventions), rewritten `BACKLOG.md` (20 prioritized items grounded in actual code), production-grade `README.md` (accurate 123-test count, measured ~980 KB release binary, corrected detection table, ASCII flow diagram, clarified auto-kill model). Repaired all clippy warnings: test mod relocated to file end in `main.rs`, nested `if`/`if let` blocks collapsed via 2024-edition let-chains across 4 files, `DoubleEndedIterator::last` replaced with `next_back`, `store::stats()` rebuilt via struct-update syntax.
**Why:** Project had grown from 312 KB scaffold to 2,766 LOC with 123 tests but docs still referenced "6 store tests" and "312 KB binary." Clippy had accumulated 11+ warnings from rapid feature work. Needed a docs+lint reset before the next feature push.
**Commit:** `482640f`
**AI Role:** AI (Claude Opus 4.6, 1M context, via Claude Code) read the full source tree, drafted CLAUDE.md / BACKLOG.md / README.md, restructured `src/main.rs` for test-module relocation, applied let-chain collapses across four files, and verified `cargo clippy --all-targets --features gui` reports zero warnings and `cargo test` passes 123/123. Human (GotEmCoach) directed the docs refresh and clippy-clean requirement.
**Proof:** `cargo test` 123/123, `cargo clippy --all-targets --features gui` zero warnings, `target/release/aptnomo` 1,003,744 bytes. Diff stat: 8 files changed, +1316 / -371.

---

### 2026-04-03 — Auto-kill sled history bug fix

**What:** Fixed a bug where auto-killed threats stayed in the `threats` (pending) tree forever. Root cause: `threat_to_card` was called twice in the kill path, generating two different IDs — `resolve_threat` used the second ID (never written to the threats tree), so the card was never moved to history. Fix: capture the card ID from the first `write_threat` call and reuse it in `resolve_threat`.
**Why:** The GUI showed auto-killed threats as still pending. Users had to manually swipe-left on already-killed processes.
**Commit:** `ab3e597`
**AI Role:** AI (Claude Opus 4.6) diagnosed the double-ID bug from code review and implemented the capture-and-reuse fix with 7 regression tests (simulate_main_loop_iteration, auto_kill_card_moves_to_history_not_pending, auto_kill_id_is_same_in_threats_and_history, auto_kill_dedup_skips_while_pending, auto_kill_re_detection_after_resolve_is_new_event, multiple_auto_kill_threats_all_move_to_history). Human (GotEmCoach) reported the symptom and directed the fix.
**Proof:** 7 regression tests passing; auto-killed cards now appear in history tree, not pending.

---

### 2026-04-03 — Log rotation + unit tests + dedup + process fields

**What:** Batch of daemon improvements across 5 commits: log rotation at 10 MB for threats.log and kills.log (`e3ff930`), 39 unit tests for main.rs detection modules / is_safe_to_kill / threat_to_card / chrono_now (`87faa6b`), sled dedup to skip writing duplicate pending threats (`d006501`), populate process_name and command fields from /proc/[pid]/cmdline into ThreatCard (`bcdbb5b`), graceful shutdown on SIGTERM/SIGINT with sled flush (`70181d9`).
**Why:** The daemon was feature-complete but operationally rough: logs grew without bound, duplicate threats accumulated in sled every scan cycle, ThreatCards lacked process metadata for the GUI, and there was no clean shutdown path.
**Commit:** `e3ff930`, `87faa6b`, `d006501`, `bcdbb5b`, `70181d9`
**AI Role:** AI (Claude Opus 4.6) implemented all five features from human direction. Human (GotEmCoach) specified the requirements, prioritized the batch, and approved the final commit sequence.
**Proof:** 39 new unit tests passing; `rotate_if_needed` tested with small/large/nonexistent files; dedup verified via `is_duplicate` + `simulate_main_loop_iteration` tests; signal handling verified via SIGTERM on running daemon.

---

### 2026-04-02 — Phase 2: sled store + GUI binary

**What:** Full Phase 2 implementation. Added shared types module (ThreatCard, BaselinePattern, CardStatus, Module, Severity), sled database with bincode + zstd compression (6 unit tests), daemon integration (writes threats to sled alongside flat files), and egui "Tinder for Threats" GUI binary with swipe-card interface, stats screen, and baseline learning. Daemon binary grew from 312 KB to ~980 KB (sled/bincode/zstd deps). GUI binary: ~3.5 MB. Version bumped to 0.2.0.
**Why:** Phase 1 daemon was headless-only. Needed structured storage for multi-binary communication and a mobile-friendly review UI. GUI spec was already written (`docs/GUI_DESIGN.md`).
**Commit:** `8f81f8e`
**AI Role:** AI (Claude Opus 4.6) implemented the full Phase 2 from the GUI_DESIGN.md spec: types module, sled store (ported from illbethejudgeofthat pattern), daemon sled integration, egui GUI with card rendering/swipe gestures/stats/theme, and all unit tests. Human (GotEmCoach) directed the phase, approved the plan, and specified IRONHIVE cluster context.
**Proof:** `cargo build --features gui` produces both binaries. 6 store unit tests passing. GUI renders severity-colored cards with drag-to-swipe.

---

### 2026-03-31 — TOI/POA sync

**What:** Added missing 536da5d entry to TOI with AI Role. Added commit log table to PROOF_OF_ARTIFACTS with all 3 commits, dates, and hashes.
**Why:** Documentation audit revealed gaps — not all commits were tracked in TOI.
**Commit:** `f0afe25`
**AI Role:** AI (Claude Opus 4.6) synced documentation from human direction.
**Proof:** All commits from b020f3c through 536da5d tracked in both TOI and POA.

---

### 2026-03-30 — TOI format fix

**What:** Added AI Role field to all TIMELINE_OF_INVENTION.md entries. Added commit hashes to each entry. Established the TOI format: Date, Commit, What, AI Role, Artifacts, Architecture decisions.
**Why:** Original TOI entries lacked AI Role attribution, making it impossible to distinguish human vs AI contributions.
**Commit:** `536da5d`
**AI Role:** AI (Claude Opus 4.6) updated TOI format from human direction. Human (GotEmCoach) specified the AI Role requirement and provided the role description for the initial scaffold entry.
**Proof:** Every TOI entry now has AI Role field and commit hash.

---

### 2026-03-30 — Release-ready docs and test gate

**What:** Full documentation suite: PROOF_OF_ARTIFACTS.md, TIMELINE_OF_INVENTION.md, govdocs/SECURITY.md (scan targets, kill conditions, safe-process list), govdocs/SUPPLY_CHAIN_AUDIT.md (dep audit, unsafe inventory), docs/compression_map.md (f0-f80 tokenization). Updated SBOM. Wired aptnomo-test binary to exopack TRIPLE SIMS f61 with 3-pass gate.
**Why:** Code was functional but undocumented. Needed release-ready provenance, security docs, and a quality gate before publishing.
**Commit:** `e87cff1`
**AI Role:** AI (Claude Opus 4.6) wrote all documentation, govdocs, compression map, and wired the exopack TRIPLE SIMS test binary from human direction. Human (GotEmCoach) specified the release-ready checklist, document requirements, and GitHub repo creation.
**Proof:** All docs present in repo. `cargo run --bin aptnomo-test --features tests` exits 0 with 3/3 PASS.

---

### 2026-03-30 — Initial scaffold

**What:** Single-file autonomous APT threat hunter. 312 KB binary. 8 detection modules (persistence, network, rootkit, SSH, processes, logs, cron, files). Daemon loop with adaptive scan interval (30s fast, 5m steady). Auto-kill for critical process threats with safe-process guard list. Zero config — drop and run.
**Why:** Edge Linux boxes in the fleet had no APT coverage because every existing tool required cloud connectivity or manual configuration. Needed a fire-and-forget binary.
**Commit:** `b020f3c`
**AI Role:** AI (Claude Opus 4.6) implemented the daemon architecture, 8 detection modules, auto-kill logic, and safe-process list from human direction. Human (GotEmCoach) specified the autonomous daemon concept, Tinder-style GUI design, zero-config philosophy, and the aptnomo name (APT No Mo). Gemini Pro 3 generated the product hero image.
**Proof:** `target/release/aptnomo` 312 KB. 8 detection modules reading real `/proc` and `/etc` paths. `cargo build --release` exits 0.

---

*Part of the [CochranBlock](https://cochranblock.org) zero-cloud architecture. All source under the Unlicense.*
