# Backlog — aptnomo

Prioritized. Top = highest impact. Tags: `[fix]` `[feature]` `[test]` `[build]` `[docs]` `[research]`

Each item references the file/function it touches so it can be picked up cold.

---

1. **[fix] f50 reverse-shell signatures never match** — `src/main.rs::f50_processes` reads `/proc/<pid>/cmdline` raw (NUL-delimited) and substring-matches against `"nc -e"` and `"bash -i"`. Spaces inside arg separators mean those signatures fire 0% of the time. Fix: split on `\0`, join with spaces, then match — or test individual tokens. Two of the highest-value reverse-shell strings are silently dead.

2. **[feature] Daemon honors learned baselines** — `src/main.rs` never calls `store::all_baselines`. Right-swipes in the GUI write `BaselinePattern`s that the daemon completely ignores, so users re-see the same threats forever. Before `write_threat`, look up the matching pattern (process_name, listen_port, file_path, cron pattern, ssh key) and skip writing if found. Bump `swipe_count` on hit. This closes the learn-and-suppress loop the GUI was built for.

3. **[feature] macOS detection backends** — Every detection module currently reads Linux-only paths (`/proc/...`, `/etc/systemd`, `/var/log/auth.log`). On macOS the modules return `Vec::new()` and the daemon is effectively a no-op. Add `#[cfg(target_os = "macos")]` variants: launchd plists for persistence, `lsof -iTCP -sTCP:LISTEN` for network, `kextstat` for rootkit, `~/Library/Logs/` for log wipes, `launchctl list` for cron equivalents.

4. **[fix] f50 walks every PID with no perms check** — `f50_processes` reads every `/proc/*/cmdline`. When run as non-root most reads silently fail; when run as root it scans thousands of dirs every cycle. Add an early `meta.uid()` filter or bound the scan to processes started in the last N seconds via `/proc/<pid>/stat` start_time vs uptime.

5. **[fix] f10/f70 read full file contents** — `f10_persistence` and `f70_cron` call `std::fs::read_to_string` on every unit/cron file every cycle. On a busy host that's hundreds of files. Replace with `BufReader::lines` early-exit on first match, and skip files larger than ~64 KB (real units don't need that).

6. **[feature] Quarantine directory** — GUI swipe-up sends `SIGSTOP` and resolves the card as `Quarantined`, but no file ever moves. Add `~/.aptnomo/quarantine/` and, for file-backed threats, copy + chmod 000 + remove the original under that path. Record the original path in the history card so a future "restore" action is possible.

7. **[feature] CLI args via clap or hand-rolled parser** — `src/main.rs::main` ignores `argv` entirely. Add at minimum: `--once` (single scan, exit non-zero if threats), `--json` (line-delimited JSON to stdout instead of human stderr), `--db-path PATH`, `--scan-interval SECS`, `--no-auto-kill`. Hand-rolled is fine — keeps the binary tiny and avoids a clap dependency.

8. **[feature] Notifier hook** — Optional `--notify CMD` flag. On every new Critical threat, spawn `CMD` with the threat description on stdin. Lets users wire `osascript -e display notification`, `notify-send`, ntfy.sh, Slack webhook, etc., without aptnomo taking on a notification dep.

9. **[build] GitHub Actions CI** — No `.github/workflows` exists. Add a single workflow: `cargo fmt --check`, `cargo clippy --all-targets --features gui -- -D warnings`, `cargo test`, `cargo build --release`, then a binary-size check (fail if `target/release/aptnomo` > 1.5 MB stripped). Run on push to main + PRs.

10. **[test] GUI smoke test** — `src/bin/aptnomo-gui.rs` has zero test coverage. Add a `#[cfg(test)]` block that constructs an `AptnomoApp` with a temporary sled DB pre-seeded with one card per module, then drives `update()` against a headless `egui::Context` once and asserts no panic. Catches drift in `f91_render_card` / `f93_baseline_learn`.

11. **[test] Cross-platform proc fixtures** — Most `f10`-`f80` tests on macOS only verify "doesn't panic when paths missing." Drop a `tests/fixtures/proc/` tree (proc/net/tcp, proc/modules, proc/<pid>/cmdline) and add a feature-gated path override so detection modules can read from a fixture root. Lets us actually assert detection logic on CI.

12. **[fix] `f20_network` IPv6 listeners** — Only reads `/proc/net/tcp`. Most modern Linux services bind via IPv6 and surface in `/proc/net/tcp6` instead. Add a second pass that parses `tcp6`, decodes the IPv6 address (mind endianness), and applies the same known-port filter.

13. **[fix] `is_safe_to_kill` is whitelist-by-substring** — `src/main.rs::is_safe_to_kill` matches `cmdline.contains("vim")`, which spares anything containing "vim" in any arg. Walk the parsed argv[0] basename instead, and load the user-process whitelist from `~/.aptnomo/safe_processes` so users can extend it without recompiling.

14. **[feature] Stable threat fingerprints** — `store::is_duplicate` matches `(module, description)` exact-equal. The description embeds dynamic fields like a PID or path-with-timestamp, so "the same" threat dedups poorly. Add a `Threat::fingerprint()` that hashes the stable subset (module + process basename or file inode) and use that for dedup keys.

15. **[feature] sled DB on-disk size cap** — There's no upper bound on `~/.aptnomo/db/`. After a noisy week the history tree can grow without limit. Add a cycle-end task that prunes history older than N days (default 30) and emits a single line to stderr noting how many cards were pruned.

16. **[docs] CONTRIBUTING.md** — No contributor entry doc exists. Pull build commands, test commands, the compression-map convention, and the "no `#[allow]` without justification" rule out of CLAUDE.md and into a checked-in CONTRIBUTING.md.

17. **[research] sled 0.34 → 1.0 / replacement** — `Cargo.toml` pins `sled = "0.34"`. 0.34 is the last published release; 1.0 has been "next release" for years. Evaluate whether to (a) stay on 0.34 (proven, slow corruption recovery), (b) move to redb (active, similar API), or (c) move to fjall. Document the call before the next storage feature lands.

18. **[feature] Stats-screen detail drilldown** — `f94_stats_screen` shows totals only. Add a per-module breakdown table (counts by `Module` × `CardStatus`) and a "last 24h" rolling histogram so users can see if a module is trigger-happy.

19. **[research] YARA-rs for `f80_files`** — `f80_files` flags any hidden executable >10 KB. That's high false-positive on dev boxes. Evaluate `yara-rust` as an optional feature (`--features yara`) that lets users drop `.yar` files into `~/.aptnomo/rules/` and only flag matches. Measure binary size impact before committing.

20. **[feature] Web review thin client** — `aptnomo-gui` is desktop-only. Borrow the kova `src/web.rs` WASM thin client pattern: a tiny HTTP listener on localhost (axum or hand-rolled) that serves a single HTML page polling `/api/pending` and `/api/resolve`. Lets users review threats from a phone over Tailscale without an Android build.

---

## Cross-project deps

- **exopack** (`tests` feature, git): TRIPLE SIMS quality gate. Pinned to git rev — flip to crates.io once published.
- **kova**: pattern source for web thin client (item 20), GUI theme, Android target (out of scope for now).
- **illbethejudgeofthat**: original sled + bincode + zstd store pattern (already ported).
