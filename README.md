# aptnomo

![aptnomo](assets/aptnomo-hero.png)

Autonomous APT threat hunter. 312 KB. Rust. Zero config.

Drop it on a machine. It watches. It reports. It kills threats when safe. No CLI interaction needed.

## What it does

aptnomo is a daemon-mode binary that continuously scans bare metal Linux systems for Advanced Persistent Threat indicators. It runs in a loop — fast scan on startup (30s interval), then settles to every 5 minutes. When it finds something critical, it kills the process automatically if safe. Everything else gets logged for review.

Zero config. No YAML. No TOML config files. No environment variables. No cloud. No agent platform. No telemetry. Just a single binary.

## How it works

```
aptnomo starts
    │
    ▼
scan_all() — runs all 8 detection modules
    │
    ▼
threats empty? ──yes──▶ sleep 5m, repeat
    │ no
    ▼
report each threat to stderr + /tmp/aptnomo/threats.log
    │
    ▼
severity == Critical AND auto_kill? ──yes──▶ is_safe_to_kill()? ──yes──▶ SIGKILL
    │ no                                                           │ no
    ▼                                                              ▼
sleep 30s (faster scan after threats)                         log only, skip
```

### Daemon mode

Run it. Walk away. It writes its PID to `/tmp/aptnomo/pid`. Threats go to `/tmp/aptnomo/threats.log`. Kills go to `/tmp/aptnomo/kills.log`. Silent when clean — no output on a healthy system.

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

## Binary size

312 KB stripped release binary. Achieved via:
- `opt-level = "z"` — size-focused optimization
- `lto = true` — link-time optimization
- `codegen-units = 1` — single codegen unit
- `panic = "abort"` — no unwinding
- `strip = true` — no debug symbols

## GUI Roadmap — Tinder for Threats

A second binary (`aptnomo gui`) will present threats as swipeable cards:

- **Swipe RIGHT** → Baseline (learn this pattern, stop alerting)
- **Swipe LEFT** → Kill (SIGKILL / delete / disable)
- **Swipe UP** → Quarantine (SIGSTOP / move to quarantine dir)

Daemon writes threats to a shared sled DB at `~/.aptnomo/db/`. GUI reads from it. No sockets, no IPC. See [docs/GUI_DESIGN.md](docs/GUI_DESIGN.md) for the full design.

## Install

```
cargo install aptnomo
```

Or build from source:

```
cargo build --release -p aptnomo
# Binary at target/release/aptnomo — 312 KB
```

## Usage

```
# Just run it. That's it. Zero config.
./aptnomo

# It will:
# - Print version and PID on startup
# - Scan all 8 modules every 30s (first pass) then every 5m
# - Log threats to /tmp/aptnomo/threats.log
# - Auto-kill critical processes when safe
# - Run forever until you kill it
```

## Test

```
cargo run -p aptnomo --bin aptnomo-test --features tests
```

Uses [exopack](https://github.com/cochranblock/exopack) TRIPLE SIMS — runs the test suite 3 times, all must pass.

## License

Unlicense — public domain. [cochranblock.org](https://cochranblock.org)
