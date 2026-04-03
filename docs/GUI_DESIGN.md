# aptnomo GUI Design — Tinder for Threats

## Architecture

Two binaries. One sled DB. No coupling.

```
┌─────────────────┐     ┌──────────────┐
│  aptnomo daemon  │────▶│   sled DB    │◀────│  aptnomo gui  │
│  ~980 KB,headless│     │ ~/.aptnomo/  │     │ ~3.5MB, egui  │
│  scans every 5m  │     │  db/         │     │  swipe cards   │
└─────────────────┘     └──────────────┘     └──────────────┘
```

- **Daemon** scans, writes threats to sled. Runs on servers without a display.
- **GUI** reads threats from sled, presents cards. Runs on desktop/mobile.
- Either can run alone. Both can run together.
- Communication: sled DB at `~/.aptnomo/db/`. No sockets, no IPC, no ports.

## Threat Queue

Daemon writes a `ThreatCard` per finding:

```rust
struct ThreatCard {
    id: u64,                    // monotonic, sled key
    timestamp: u64,             // unix epoch
    module: Module,             // network | process | cron | ssh | files
    severity: Severity,         // green | yellow | orange | red
    title: String,              // "New listening port: 8443"
    description: String,        // "Process nginx (PID 2041) bound TCP 0.0.0.0:8443"
    process_name: Option<String>,
    pid: Option<u32>,
    file_path: Option<String>,
    command: Option<String>,    // full cmdline if process
    status: CardStatus,         // pending | baselined | killed | quarantined | auto_killed
}

enum Module { Network, Process, Cron, Ssh, Files }
enum Severity { Green, Yellow, Orange, Red }
enum CardStatus { Pending, Baselined, Killed, Quarantined, AutoKilled }
```

Serialized with bincode. Sled tree: `threats` for pending, `baseline` for learned patterns, `history` for resolved.

## GUI Layout

Single screen. One card at a time. Touch-first.

```
┌─────────────────────────────────────────┐
│  ⚡ aptnomo            3 threats pending │
├─────────────────────────────────────────┤
│                                         │
│   ┌─────────────────────────────────┐   │
│   │  🔴 RED — Critical              │   │
│   │                                 │   │
│   │  New SUID binary detected       │   │
│   │                                 │   │
│   │  /tmp/.hidden/escalate          │   │
│   │  owner: root  mode: 4755       │   │
│   │  created: 2 min ago            │   │
│   │  sha256: a3f8c1...             │   │
│   │                                 │   │
│   │  ⚠️  AUTO-KILLED                │   │
│   └─────────────────────────────────┘   │
│                                         │
│  ◀ KILL    ▲ QUARANTINE    BASELINE ▶   │
│                                         │
│  ─────────────────────────────────────  │
│  reviewed: 47  baselined: 41  killed: 3 │
└─────────────────────────────────────────┘
```

### Card Colors

| Severity | Color | Border | Meaning |
|----------|-------|--------|---------|
| Green | #2d5a2d | #50b432 | Informational — new but likely benign |
| Yellow | #5a5a2d | #d4d432 | Unusual — worth reviewing |
| Orange | #5a3a1a | #ff7814 | Suspicious — likely needs action |
| Red | #5a1a1a | #c83232 | Critical — auto-killed, review after |

### Swipe Actions

| Gesture | Action | Effect |
|---------|--------|--------|
| Swipe RIGHT | Baseline | Pattern added to baseline. Daemon won't alert on this again. Card moves to history. |
| Swipe LEFT | Kill | SIGKILL if process. Delete if file. Disable if cron job. Card moves to history with status=killed. |
| Swipe UP | Quarantine | Process: SIGSTOP (suspend). File: move to `~/.aptnomo/quarantine/`. Cron: comment out. Card moves to history. |
| No swipe | Auto-kill (Red) | Critical threats killed automatically by daemon. Card appears with "AUTO-KILLED" badge. User reviews after the fact. |

### Module Icons

| Module | Icon | Example Threats |
|--------|------|-----------------|
| Network | 🌐 | New listening port, unexpected outbound connection, DNS to known-bad domain |
| Process | ⚙️ | Unknown process, high CPU, SUID binary, process from /tmp |
| Cron | ⏰ | New cron job, modified crontab, at job |
| SSH | 🔑 | New authorized_key, failed login spike, SSH tunnel |
| Files | 📁 | New SUID, modified system binary, file in /tmp with exec bit, world-writable config |

## Baseline Learning

The baseline is a pattern matcher, not an exact match. Learned patterns:

```rust
struct BaselinePattern {
    module: Module,
    pattern_type: PatternType,
    value: String,              // regex or exact match
    learned_at: u64,
    swipe_count: u32,           // how many times user baselined this
}

enum PatternType {
    ProcessName,                // "nginx" — always baseline
    ListenPort,                 // "8443" — known service
    FilePath,                   // "/usr/local/bin/myapp"
    CronPattern,               // "0 * * * * /usr/bin/logrotate"
    SshKey,                     // fingerprint hash
}
```

After right-swiping "nginx listening on 8443" three times, the daemon learns:
- Process "nginx" is baselined
- Port 8443 is expected
- Future alerts about nginx on 8443 are suppressed

The baseline grows over ~1 week of daily use. After that, alerts are rare — only genuinely new activity triggers a card.

## Threat Card Lifecycle

```
Daemon detects anomaly
        │
        ▼
  Is pattern in baseline? ──yes──▶ (silent, no card)
        │ no
        ▼
  severity == Red? ──yes──▶ AUTO-KILL ──▶ Card with KILLED badge
        │ no
        ▼
  Write to sled (status=Pending)
        │
        ▼
  GUI shows card
        │
   ┌────┼────┐
   ▼    ▼    ▼
 KILL  QUAR  BASELINE
   │    │    │
   ▼    ▼    ▼
 history    baseline pattern created
```

## Stats Screen

Accessible via a tab or button. Shows:

```
THREAT OVERVIEW
═══════════════
Total scanned:    1,247
Threats found:       89
Baselined:           72
Killed:               8
Quarantined:          4
Auto-killed:          5
Pending review:       0

BY MODULE
─────────
Network:    34 found, 31 baselined, 2 killed
Process:    28 found, 22 baselined, 3 killed
Files:      15 found, 12 baselined, 2 quarantined
Cron:        8 found,  5 baselined, 1 killed
SSH:         4 found,  2 baselined, 0 killed

BASELINE HEALTH
───────────────
Patterns learned:    72
Oldest pattern:      7 days ago
False positive rate: 3.2% (decreasing)
```

## Platform Support

| Platform | Binary | GUI | Notes |
|----------|--------|-----|-------|
| Linux (desktop) | daemon + gui | egui native | Primary target |
| Linux (server) | daemon only | headless | No display needed |
| macOS | daemon + gui | egui native | Development |
| Android | daemon + gui | egui NativeActivity | Future — same pattern as pixel-forge |
| Web | — | PWA | Future — review from phone browser |

## Implementation Plan

### Phase 1: Shared types + sled schema
- `ThreatCard`, `BaselinePattern`, `CardStatus` in a shared lib crate
- Sled DB setup with `threats`, `baseline`, `history` trees
- Serialization: bincode (same as pixel-forge training data)

### Phase 2: GUI binary
- egui app with card display, swipe gestures, stats screen
- Reads from sled, writes back swipe decisions
- Touch targets: 60px minimum (mobile-safe)
- Color scheme: dark bg (#0c0c12), severity-colored cards

### Phase 3: Daemon integration
- Daemon writes threats to sled instead of just stdout/log
- GUI picks them up on next frame refresh (poll sled every 1s)
- Kill/quarantine actions execute via daemon RPC or direct syscalls from GUI

### Phase 4: Baseline engine
- Pattern extraction from right-swipes
- Fuzzy matching (process name, port, path prefix)
- Decay: patterns not seen in 30 days get re-evaluated

## Design Constraints

- GUI binary must be < 5 MB (same size discipline as pixel-forge)
- No network calls from GUI (local sled only)
- No dependencies beyond egui, sled, bincode, clap
- Works offline, air-gapped, on classified networks
- Daemon and GUI share ZERO code paths at runtime — only the sled schema

---

Unlicense — public domain — [cochranblock.org](https://cochranblock.org)
