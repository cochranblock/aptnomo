# Timeline of Invention — aptnomo

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
