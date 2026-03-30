# Compression Map — aptnomo

## Functions

| Token | Name | Module | Signature |
|-------|------|--------|-----------|
| f0 | main | main | `fn main()` |
| f1 | scan_all | main | `fn scan_all() -> Vec<Threat>` |
| f2 | report | main | `fn report(t: &Threat)` |
| f3 | is_safe_to_kill | main | `fn is_safe_to_kill(t: &Threat) -> bool` |
| f4 | kill_threat | main | `fn kill_threat(t: &Threat)` |
| f5 | chrono_now | main | `fn chrono_now() -> String` |
| f10 | persistence | detection | `fn f10_persistence() -> Vec<Threat>` |
| f20 | network | detection | `fn f20_network() -> Vec<Threat>` |
| f30 | rootkit | detection | `fn f30_rootkit() -> Vec<Threat>` |
| f40 | ssh | detection | `fn f40_ssh() -> Vec<Threat>` |
| f50 | processes | detection | `fn f50_processes() -> Vec<Threat>` |
| f60 | logs | detection | `fn f60_logs() -> Vec<Threat>` |
| f70 | cron | detection | `fn f70_cron() -> Vec<Threat>` |
| f80 | files | detection | `fn f80_files() -> Vec<Threat>` |

## Types

| Token | Name | Fields |
|-------|------|--------|
| t0 | Severity | Info, Low, Medium, High, Critical |
| t1 | Threat | module, severity, description, pid, path, auto_kill |

## Constants

| Token | Name | Value |
|-------|------|-------|
| k0 | SCAN_INTERVAL | 300s (5 minutes) |
| k1 | FAST_SCAN | 30s |

## Detection module ranges

| Range | Module |
|-------|--------|
| f10 | Persistence (systemd, init, shell rc) |
| f20 | Network (listeners, connections) |
| f30 | Rootkit (kernel modules) |
| f40 | SSH (authorized_keys) |
| f50 | Processes (known malware signatures) |
| f60 | Logs (tampering detection) |
| f70 | Cron (suspicious jobs) |
| f80 | Files (hidden executables in temp dirs) |

## GUI functions (planned)

| Token | Name | Module | Description |
|-------|------|--------|-------------|
| f90 | gui_main | gui | egui app entry point |
| f91 | render_card | gui | Draw a ThreatCard |
| f92 | swipe_handler | gui | Process swipe gestures |
| f93 | baseline_learn | gui | Add pattern to baseline |
| f94 | stats_screen | gui | Render stats/overview |
| f95 | sled_read | gui | Read threats from sled DB |
| f96 | sled_write | gui | Write swipe decisions |

## GUI types (planned)

| Token | Name | Fields |
|-------|------|--------|
| t10 | ThreatCard | id, timestamp, module, severity, title, description, process_name, pid, file_path, command, status |
| t11 | BaselinePattern | module, pattern_type, value, learned_at, swipe_count |
| t12 | CardStatus | Pending, Baselined, Killed, Quarantined, AutoKilled |
| t13 | PatternType | ProcessName, ListenPort, FilePath, CronPattern, SshKey |
