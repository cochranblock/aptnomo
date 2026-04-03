# aptnomo

![aptnomo](assets/aptnomo-hero.png)

Autonomous APT threat hunter. Rust. Zero config.

Drop it on a machine. It watches. It reports. It kills threats when safe. No CLI interaction needed.

## What it does

aptnomo is a daemon-mode binary that continuously scans bare metal Linux systems for Advanced Persistent Threat indicators. It runs in a loop — fast scan on startup (30s interval), then settles to every 5 minutes. When it finds something critical, it kills the process automatically if safe. Everything else gets logged for review.

Zero config. No YAML. No TOML config files. No environment variables. No cloud. No agent platform. No telemetry. Just a single binary.

## How it works

```
aptnomo starts
    |
    v
scan_all() — runs all 8 detection modules
    |
    v
threats empty? --yes--> sleep 5m, repeat
    | no
    v
report each threat to stderr + /tmp/aptnomo/threats.log + sled DB
    |
    v
severity == Critical AND auto_kill? --yes--> is_safe_to_kill()? --yes--> SIGKILL
    | no                                                           | no
    v                                                              v
sleep 30s (faster scan after threats)                         log only, skip
```

### Daemon mode

Run it. Walk away. It writes its PID to `/tmp/aptnomo/pid`. Threats go to `/tmp/aptnomo/threats.log` and `~/.aptnomo/db/` (sled). Kills go to `/tmp/aptnomo/kills.log`. Silent when clean — no output on a healthy system.

### Structured storage

Threats are written to a sled database at `~/.aptnomo/db/` with bincode + zstd compression. Three trees:

| Tree | Contents |
|------|----------|
| `threats` | Pending threat cards awaiting review |
| `baseline` | Learned patterns from user swipes |
| `history` | Resolved cards (killed, baselined, quarantined) |

Flat file output to `/tmp/aptnomo/` is kept as a fallback. If sled fails to open, the daemon continues with flat files only.

### Auto-kill safety

Before killing any process, aptnomo checks:
- Never kills PID 1 or PID 2
- Never kills user processes: vim, nano, bash, zsh, fish, code, chrome, firefox, tmux
- Only kills processes flagged as Critical severity AND marked auto_kill by the detection module

## Detection Modules

| Module | Function | What it detects |
|--------|----------|-----------------|
| **Persistence** | `f10` | Suspicious systemd units with ExecStart pointing to /tmp or hidden directories |
| **Network** | `f20` | Unknown services listening on 0.0.0.0 (excludes ports 22, 80, 443, 8080, 8081, 3000, 3001, 8000) |
| **Rootkit** | `f30` | Kernel modules with names containing: hide, stealth, rootkit, backdoor, keylog |
| **SSH** | `f40` | Excessive SSH authorized_keys (>5 keys triggers alert) |
| **Processes** | `f50` | Processes matching: cryptominer, xmrig, stratum, reverse_shell, nc -e, bash -i — auto-kill eligible |
| **Logs** | `f60` | Empty log files (auth.log, syslog, messages) indicating log wipe |
| **Cron** | `f70` | Cron jobs referencing /tmp, curl, or wget |
| **Files** | `f80` | Hidden executables (>10KB, exec bit set) in /tmp, /dev/shm, /var/tmp |

## GUI — Tinder for Threats

A second binary (`aptnomo-gui`) presents threats as swipeable cards:

- **Swipe RIGHT** -> Baseline (learn this pattern, stop alerting)
- **Swipe LEFT** -> Kill (SIGKILL / delete / disable)
- **Swipe UP** -> Quarantine (SIGSTOP / move to quarantine dir)

Built with egui. Reads from the shared sled DB at `~/.aptnomo/db/`. No sockets, no IPC. See [docs/GUI_DESIGN.md](docs/GUI_DESIGN.md) for the full design.

### Card colors

| Severity | Border | Fill | Meaning |
|----------|--------|------|---------|
| Green | #50b432 | #2d5a2d | Informational — new but likely benign |
| Yellow | #d4d432 | #5a5a2d | Unusual — worth reviewing |
| Orange | #ff7814 | #5a3a1a | Suspicious — likely needs action |
| Red | #c83232 | #5a1a1a | Critical — auto-killed, review after |

## Architecture

```
src/
  lib.rs         — crate root: shared modules
  types.rs       — ThreatCard, BaselinePattern, CardStatus, Module, Severity
  store.rs       — sled DB with bincode + zstd (put/get/scan/stats)
  main.rs        — daemon: scan loop, 8 detection modules, sled writes
  bin/
    aptnomo-gui.rs   — egui swipe-card interface
    aptnomo-test.rs  — exopack TRIPLE SIMS test gate
```

| Binary | Feature | Size | Purpose |
|--------|---------|------|---------|
| `aptnomo` | default | ~980 KB | Headless daemon |
| `aptnomo-gui` | `gui` | ~3.5 MB | Threat review UI |
| `aptnomo-test` | `tests` | — | Quality gate |

## Binary size

Achieved via:
- `opt-level = "z"` — size-focused optimization
- `lto = true` — link-time optimization
- `codegen-units = 1` — single codegen unit
- `panic = "abort"` — no unwinding
- `strip = true` — no debug symbols

## Install

```
cargo install aptnomo
```

Or build from source:

```
# Daemon only
cargo build --release -p aptnomo

# Daemon + GUI
cargo build --release -p aptnomo --features gui
```

## Usage

```
# Just run it. That's it. Zero config.
./aptnomo

# It will:
# - Print version and PID on startup
# - Open sled DB at ~/.aptnomo/db/
# - Scan all 8 modules every 30s (first pass) then every 5m
# - Log threats to /tmp/aptnomo/threats.log + sled DB
# - Auto-kill critical processes when safe
# - Run forever until you kill it

# Launch the GUI to review threats:
./aptnomo-gui
```

## Test

```
cargo run -p aptnomo --bin aptnomo-test --features tests
```

Uses [exopack](https://github.com/cochranblock/exopack) TRIPLE SIMS — runs the test suite 3 times, all must pass.

Unit tests for the sled store:

```
cargo test
```

## License

Unlicense — public domain. [cochranblock.org](https://cochranblock.org)
