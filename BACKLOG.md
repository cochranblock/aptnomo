# Backlog — aptnomo

Prioritized. Top = most important. Tags: [build] [test] [docs] [feature] [fix] [research]

1. ~~[fix] Remove unused deps: clap, serde_json not used in any source file — dead weight in binary~~ DONE 2026-04-03
2. [test] Add integration test: seed sled DB with ThreatCards, verify daemon reads back correctly
3. [feature] Baseline engine (Phase 4): pattern extraction from right-swipes, fuzzy matching, 30-day decay
4. [feature] Signal handling: catch SIGTERM for graceful sled flush and shutdown
5. [fix] GUI swipe animation: drag_offset translates card but current impl doesn't visually shift — wire offset into paint transform
6. [feature] Daemon: extract process_name and command fields from /proc/[pid]/cmdline into ThreatCard (currently None)
7. [feature] Daemon sled dedup: check if identical threat already pending before writing new card each scan cycle
8. [test] GUI smoke test: headless eframe test that opens app with temp sled DB, verifies no panic (dep: exopack)
9. [feature] Log rotation: rotate /tmp/aptnomo/threats.log and kills.log at 10 MB
10. [feature] macOS detection stubs: platform-gated modules that scan launchd plists, lsof, kextstat instead of /proc
11. [fix] Daemon: threat_to_card generates new ID per scan cycle for same threat — needs stable ID or dedup key
12. [feature] CLI args via clap: --once (single scan, exit), --json (structured output), --db-path (custom sled location)
13. [docs] Add CONTRIBUTING.md with build instructions, test commands, compression map convention
14. [feature] Quarantine dir: implement ~/.aptnomo/quarantine/ for file-based quarantine from GUI swipe-up on file threats
15. [research] Evaluate sled 1.0 (ivf-based) vs 0.34 — breaking API changes, performance, stability
16. [feature] Notification: optional desktop notification via notify-rust when new Critical threat detected
17. [build] CI: GitHub Actions workflow — cargo test, cargo build --release, cargo build --features gui, binary size check
18. [feature] Android GUI: eframe NativeActivity target (pattern from kova/pixel-forge) — dep: kova android/ reference
19. [research] YARA rule integration: load .yar files for file scanning in f80 — evaluate yara-rust crate weight
20. [feature] PWA: web-based threat review from phone browser — dep: kova src/web.rs WASM thin client pattern

Cross-project deps:
- exopack (path ../exopack): TRIPLE SIMS test gate. Published crates.io v0.1.0.
- kova: GUI/theme patterns, Android target reference, WASM thin client pattern.
- illbethejudgeofthat: sled+bincode+zstd store pattern (already ported).
