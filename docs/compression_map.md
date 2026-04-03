# Compression Map — [aptnomo](https://cochranblock.org)

## Functions

| Token | Name | Module | Signature |
|-------|------|--------|-----------|
| f0 | main | main | `fn main()` |
| f1 | scan_all | main | `fn scan_all() -> Vec<Threat>` |
| f2 | report | main | `fn report(t: &Threat)` |
| f3 | is_safe_to_kill | main | `fn is_safe_to_kill(t: &Threat) -> bool` |
| f4 | kill_threat | main | `fn kill_threat(t: &Threat)` |
| f5 | chrono_now | main | `fn chrono_now() -> String` |
| f6 | threat_to_card | main | `fn threat_to_card(db: &sled::Db, t: &Threat) -> Result<ThreatCard>` |
| f10 | persistence | detection | `fn f10_persistence() -> Vec<Threat>` |
| f20 | network | detection | `fn f20_network() -> Vec<Threat>` |
| f30 | rootkit | detection | `fn f30_rootkit() -> Vec<Threat>` |
| f40 | ssh | detection | `fn f40_ssh() -> Vec<Threat>` |
| f50 | processes | detection | `fn f50_processes() -> Vec<Threat>` |
| f60 | logs | detection | `fn f60_logs() -> Vec<Threat>` |
| f70 | cron | detection | `fn f70_cron() -> Vec<Threat>` |
| f80 | files | detection | `fn f80_files() -> Vec<Threat>` |
| f90 | gui_main | gui | `fn f90_gui_main() -> Result<()>` |
| f91 | render_card | gui | `fn f91_render_card(ui, card, drag_offset) -> Response` |
| f92 | swipe_handler | gui | `fn f92_swipe_handler(response, db, card, ...)` |
| f93 | baseline_learn | gui | `fn f93_baseline_learn(db, card)` |
| f94 | stats_screen | gui | `fn f94_stats_screen(ui, db)` |
| f95 | sled_read | gui | `fn f95_sled_read(&mut self)` |
| f96 | get | store | `fn f96_get<V>(db, tree, key) -> Result<Option<V>>` |
| f97 | put | store | `fn f97_put<V>(db, tree, key, value) -> Result<()>` |
| f98 | apply_theme | gui | `fn f98_apply_theme(ctx: &egui::Context)` |

## Types

| Token | Name | Fields |
|-------|------|--------|
| t0 | Severity (internal) | Info, Low, Medium, High, Critical |
| t1 | Threat (internal) | module, severity, description, pid, path, auto_kill |
| t10 | ThreatCard | id, timestamp, module, severity, title, description, process_name, pid, file_path, command, status, auto_kill |
| t11 | BaselinePattern | module, pattern_type, value, learned_at, swipe_count |
| t12 | CardStatus | Pending, Baselined, Killed, Quarantined, AutoKilled |
| t13 | PatternType | ProcessName, ListenPort, FilePath, CronPattern, SshKey |

## Shared types

| Token | Name | Variants |
|-------|------|----------|
| Module | Module | Persistence, Network, Rootkit, Ssh, Process, Logs, Cron, Files |
| Severity (GUI) | Severity | Green, Yellow, Orange, Red |
| Stats | Stats | total_threats, pending, baselined, killed, quarantined, auto_killed |

## Constants

| Token | Name | Value |
|-------|------|-------|
| k0 | SCAN_INTERVAL | 300s (5 minutes) |
| k1 | FAST_SCAN | 30s |

## Sled trees

| Tree | Contents |
|------|----------|
| threats | Pending ThreatCards |
| baseline | Learned BaselinePatterns |
| history | Resolved ThreatCards |

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
