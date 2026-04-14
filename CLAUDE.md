# aptnomo — Claude Code Project Notes

Tiny binary autonomous APT threat hunter for bare-metal Linux. Single Rust crate. Daemon scans every 5m, auto-kills critical processes when safe, persists threat cards to a sled DB. Optional egui swipe-card review GUI. No cloud, no agent platform, no telemetry.

## Build

```sh
cargo build                              # daemon only (default features)
cargo build --release                    # size-first daemon (~1 MB)
cargo build --features gui               # daemon + GUI binary
cargo build --release --features gui     # release GUI build
cargo build --features tests             # test binary (pulls exopack from git)
```

## Test

```sh
cargo test                               # unit tests for lib + main bin (~110 tests)
cargo clippy --all-targets --features gui  # lint everything; must be warning-free
cargo run --bin aptnomo-test --features tests  # exopack TRIPLE SIMS gate (3 runs)
```

## Run

```sh
./target/release/aptnomo                 # start the daemon (no args, no config)
./target/release/aptnomo-gui             # launch the swipe-card GUI
```

Daemon writes:
- `/tmp/aptnomo/pid` — PID file
- `/tmp/aptnomo/threats.log` — flat-file threat log (rotates at 10 MB)
- `/tmp/aptnomo/kills.log` — auto-kill audit log (rotates at 10 MB)
- `~/.aptnomo/db/` — sled database (bincode + zstd compressed)

Stops cleanly on SIGTERM/SIGINT (flushes sled, removes pidfile).

## Module Map

| File | Purpose |
|------|---------|
| `src/lib.rs` | Crate root. Re-exports `types` and `store` for the daemon, GUI, and tests. |
| `src/types.rs` | Shared serializable types: `Module`, `Severity`, `CardStatus`, `ThreatCard`, `BaselinePattern`, `Stats`. Helpers: `module_from_str`, `rotate_if_needed`. |
| `src/store.rs` | sled DB layer. Three trees: `threats` (pending), `baseline` (learned patterns), `history` (resolved). Bincode + zstd compression via `f96_get` / `f97_put`. Daemon helpers: `next_threat_id`, `write_threat`, `is_duplicate`, `pending_threats`. GUI helpers: `resolve_threat`, `add_baseline`, `all_baselines`, `history_cards`, `stats`. |
| `src/main.rs` | Daemon binary. `scan_all` runs every detection module each cycle. Reports each threat to stderr + flat log + sled. Auto-kills critical processes that pass `is_safe_to_kill`. Captures the written card ID so the resolve step moves the *same* card to history. |
| `src/bin/aptnomo-gui.rs` | egui GUI (`gui` feature). Tinder-style threat card swipes: right = baseline + learn pattern, left = SIGKILL, up = SIGSTOP quarantine. Polls sled once per second. |
| `src/bin/aptnomo-test.rs` | exopack TRIPLE SIMS quality gate (`tests` feature). Runs the test pipeline 3 times; all must pass. |

### Detection modules (in `src/main.rs`)

| Function | Module label | What it scans | Auto-kill? |
|----------|--------------|---------------|------------|
| `f10_persistence` | `persistence` | systemd unit files in `/etc/systemd/system`, `/usr/lib/systemd/system` for `ExecStart` paths under `/tmp/` or hidden dirs | no |
| `f20_network` | `network` | `/proc/net/tcp` LISTEN sockets on `0.0.0.0` (skips known ports 22/80/443/8080/8081/3000/3001/8000) | no |
| `f30_rootkit` | `rootkit` | `/proc/modules` names containing `hide`, `stealth`, `rootkit`, `backdoor`, `keylog` | no |
| `f40_ssh` | `ssh` | `$HOME/.ssh/authorized_keys` count > 5 | no |
| `f50_processes` | `processes` | `/proc/<pid>/cmdline` matches against `cryptominer`, `xmrig`, `stratum`, `reverse_shell`, `nc -e`, `bash -i` | yes |
| `f60_logs` | `logs` | Empty `/var/log/{auth.log,syslog,messages}` (possible wipe) | no |
| `f70_cron` | `cron` | Cron files referencing `/tmp/`, `curl `, or `wget ` | no |
| `f80_files` | `files` | Hidden executables (>10 KB, exec bit set) under `/tmp`, `/dev/shm`, `/var/tmp` | no |

`scan_all` returns a `Vec<Threat>`; the main loop maps each `Threat` → `ThreatCard` via `threat_to_card`, dedups against pending entries with `store::is_duplicate`, writes to sled, and only enters the kill path when `severity >= Critical && auto_kill && is_safe_to_kill`.

### Severity mapping

Internal `Severity` (`Info`/`Low`/`Medium`/`High`/`Critical`) → public `types::Severity` (`Green`/`Yellow`/`Orange`/`Orange`/`Red`). Only `Red` + `auto_kill: true` triggers auto-kill.

## Sled schema

```
~/.aptnomo/db/
  threats/   key: zero-padded u64 ID  → ThreatCard (status = Pending)
  history/   key: zero-padded u64 ID  → ThreatCard (status = Killed/Baselined/Quarantined/AutoKilled)
  baseline/  key: "{module_label}:{value}" → BaselinePattern
```

Keys are zero-padded so lexicographic order matches numeric order. IDs come from `db.generate_id()`.

## Conventions

- Edition `2024`. Let-chains (`if let X = y && z`) preferred over nested `if`.
- No external test framework. The test binary IS the gate.
- No `#[allow(...)]` without justification. Clippy must stay clean (`cargo clippy --all-targets --features gui` reports zero warnings).
- All source files start with `// Unlicense — cochranblock.org` + `// Contributors:` header.
- Compression map (function tokens `f10`-`f97`, type tokens `t10`-`t13`) lives in `docs/compression_map.md`.
- See `docs/GUI_DESIGN.md` for the swipe-card UX spec.
