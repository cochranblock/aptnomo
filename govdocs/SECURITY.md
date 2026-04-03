# Security — aptnomo

## What it scans

aptnomo reads the following system paths and files. It does NOT modify them (except for kill actions on processes).

### Read-only scan targets

| Path | Module | What it looks for |
|------|--------|-------------------|
| `/etc/systemd/system/*.service` | f10 | ExecStart pointing to /tmp or hidden dirs |
| `/usr/lib/systemd/system/*.service` | f10 | Same |
| `/proc/net/tcp` | f20 | Listening sockets on 0.0.0.0 with unknown ports |
| `/proc/modules` | f30 | Kernel modules with suspicious names |
| `~/.ssh/authorized_keys` | f40 | Key count > 5 |
| `/proc/[pid]/cmdline` | f50 | Process names matching known malware |
| `/var/log/auth.log` | f60 | Zero-length file (wipe indicator) |
| `/var/log/syslog` | f60 | Same |
| `/var/log/messages` | f60 | Same |
| `/etc/cron.d/*` | f70 | Cron jobs with /tmp, curl, wget |
| `/var/spool/cron/crontabs/*` | f70 | Same |
| `/etc/cron.daily/*` | f70 | Same |
| `/tmp/*` | f80 | Hidden executables > 10 KB |
| `/dev/shm/*` | f80 | Same |
| `/var/tmp/*` | f80 | Same |

## What it kills

aptnomo will SIGKILL a process only when ALL of the following are true:

1. The detection module flagged `auto_kill: true` (only f50/processes does this)
2. The threat severity is `Critical`
3. The process PID is > 2
4. The process is NOT in the safe-process list

The GUI (`aptnomo-gui`) can also kill or quarantine processes via user swipe actions:
- **Left swipe (Kill):** SIGKILL, same PID > 2 guard
- **Up swipe (Quarantine):** SIGSTOP, same PID > 2 guard

### Safe-process list

These processes are NEVER killed, regardless of detection results:

| Process | Reason |
|---------|--------|
| vim | User editor |
| nano | User editor |
| bash | User shell |
| zsh | User shell |
| fish | User shell |
| code | VS Code |
| chrome | User browser |
| firefox | User browser |
| tmux | Terminal multiplexer |

The safe-process check reads `/proc/[pid]/cmdline` and matches against these names.

## What it writes

| Path | Contents | Purpose |
|------|----------|---------|
| `/tmp/aptnomo/pid` | PID number | Process management |
| `/tmp/aptnomo/threats.log` | Threat reports (append) | Audit trail |
| `/tmp/aptnomo/kills.log` | Kill records (append) | Kill audit trail |
| `~/.aptnomo/db/` | sled database (bincode + zstd) | Structured threat storage |

### Sled DB trees

| Tree | Contents | Written by |
|------|----------|------------|
| `threats` | Pending ThreatCards | Daemon |
| `baseline` | Learned patterns from user swipes | GUI |
| `history` | Resolved cards (killed, baselined, quarantined) | GUI |

## Unsafe code

| Location | Code | Justification |
|----------|------|---------------|
| `src/main.rs` kill_threat() | `libc::kill(pid, SIGKILL)` | Process termination. PID validated (> 2, not in safe list). |
| `src/bin/aptnomo-gui.rs` f92 (kill) | `libc::kill(pid, SIGKILL)` | User-initiated kill via left swipe. PID validated (> 2). |
| `src/bin/aptnomo-gui.rs` f92 (quarantine) | `libc::kill(pid, SIGSTOP)` | User-initiated quarantine via up swipe. PID validated (> 2). |

## Attack surface

- No network listeners — aptnomo does not bind any ports
- No config file parsing — no deserialization attacks
- No user input — daemon runs autonomously
- No privilege escalation — runs with whatever permissions it's given
- Reads only well-known system paths
- GUI reads only from local sled DB — no network calls
- Sled DB uses bincode (binary format) — no injection vectors

---

Unlicense — public domain — [cochranblock.org](https://cochranblock.org)
