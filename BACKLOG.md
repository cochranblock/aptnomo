# Backlog — aptnomo

Prioritized. Top = most important. Tags: [build] [test] [docs] [feature] [fix] [research]

1. [fix] Auto-kill sled history bug: threat_to_card called twice in kill path generates two different IDs — second resolve_threat call uses an ID never written to threats tree, so auto-killed cards stay Pending forever in GUI. Fix: capture card from first write, reuse its ID in resolve_threat after kill.
2. [feature] Daemon baseline check: before writing a new ThreatCard, load all_baselines and check for module+value match — skip writing if baselined. Right-swipes currently have zero effect on future daemon scans; the core learn-and-suppress loop is entirely missing from main.rs.
3. [fix] f50 cmdline signature mismatch: /proc/[pid]/cmdline is NUL-delimited so "nc -e" and "bash -i" (space-containing) will never match the raw string. Join split-on-NUL parts with spaces before matching, or match individual tokens. These two highest-value reverse-shell signatures silently fail on every system.
4. ~~[feature] Signal handling: catch SIGTERM for graceful sled flush and shutdown~~ DONE 2026-04-03
5. ~~[fix] GUI swipe animation: drag_offset translates card but current impl doesn't visually shift — wire offset into paint transform~~ DONE 2026-04-03
6. ~~[feature] Daemon: extract process_name and command fields from /proc/[pid]/cmdline into ThreatCard (currently None)~~ DONE 2026-04-03
7. ~~[feature] Daemon sled dedup: check if identical threat already pending before writing new card each scan cycle~~ DONE 2026-04-03
8. [test] GUI smoke test: headless eframe test that opens app with temp sled DB, verifies no panic (dep: exopack)
9. ~~[feature] Log rotation: rotate /tmp/aptnomo/threats.log and kills.log at 10 MB~~ DONE 2026-04-03
10. [feature] macOS detection stubs: platform-gated modules that scan launchd plists, lsof, kextstat instead of /proc
11. ~~[fix] Daemon: threat_to_card generates new ID per scan cycle for same threat — needs stable ID or dedup key~~ DONE 2026-04-03 (resolved by item #7 dedup)
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
