# Timeline of Invention — aptnomo

## 2026-03-30 — Initial scaffold

**Commit:** Initial scaffold — daemon-mode APT hunter with 8 detection modules.

**What:** Single-file autonomous APT threat hunter. 312 KB binary. 8 detection modules (persistence, network, rootkit, SSH, processes, logs, cron, files). Daemon loop with adaptive scan interval (30s fast, 5m steady). Auto-kill for critical process threats with safe-process guard list. Zero config — drop and run.

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
