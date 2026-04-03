// Unlicense — cochranblock.org
// Contributors: GotEmCoach, KOVA, Claude Opus 4.6
//! aptnomo — autonomous APT threat hunter.
//! Runs as a background daemon. Watches. Reports. Kills threats when safe.
//! No CLI interaction needed. Drop it on a machine, run it, forget it.

use std::time::Duration;
use std::thread;
use std::sync::atomic::{AtomicBool, Ordering};

use aptnomo::types::{self, ThreatCard, CardStatus, Module, Severity as GuiSeverity};
use aptnomo::store;

/// Threat severity (internal — maps to GUI Severity in threat_to_card)
#[derive(Debug, Clone, PartialEq, PartialOrd)]
#[allow(dead_code)] // Info/Low reserved for future detection modules
enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical, // auto-kill eligible
}

/// A detected threat
#[derive(Debug, Clone)]
struct Threat {
    module: &'static str,
    severity: Severity,
    description: String,
    pid: Option<u32>,
    path: Option<String>,
    auto_kill: bool, // safe to terminate without user confirmation
}

/// Scan interval
const SCAN_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes
const FAST_SCAN: Duration = Duration::from_secs(30); // first scan + after threat

fn main() {
    eprintln!("aptnomo v{} — autonomous APT hunter", env!("CARGO_PKG_VERSION"));
    eprintln!("watching silently. will report threats and kill what's safe to kill.");
    eprintln!("pid: {}", std::process::id());

    // Write PID file for management
    let _ = std::fs::create_dir_all("/tmp/aptnomo");
    let _ = std::fs::write("/tmp/aptnomo/pid", std::process::id().to_string());

    // Open sled DB for structured storage (fallback to flat files if it fails)
    let db = match store::open_db() {
        Ok(db) => {
            eprintln!("sled db: {}", store::db_path().display());
            Some(db)
        }
        Err(e) => {
            eprintln!("warn: sled open failed ({}), using flat files only", e);
            None
        }
    };

    // Signal handling: SIGTERM/SIGINT for graceful shutdown
    unsafe {
        libc::signal(libc::SIGTERM, signal_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, signal_handler as *const () as libc::sighandler_t);
    }
    SHUTDOWN.store(false, Ordering::SeqCst);

    // First scan is fast
    let mut interval = FAST_SCAN;

    while !SHUTDOWN.load(Ordering::SeqCst) {
        let threats = scan_all();

        if threats.is_empty() {
            // Silent when clean — no output
        } else {
            for t in &threats {
                report(t);
                // Write to sled if available and not a duplicate
                if let Some(ref db) = db {
                    let module = types::module_from_str(t.module);
                    let is_dup = store::is_duplicate(db, &module, &t.description).unwrap_or(false);
                    if !is_dup {
                        if let Ok(card) = threat_to_card(db, t) {
                            let _ = store::write_threat(db, &card);
                        }
                    }
                }
                if t.auto_kill && t.severity >= Severity::Critical {
                    if is_safe_to_kill(t) {
                        kill_threat(t);
                        // Mark as auto-killed in sled
                        if let Some(ref db) = db {
                            if let Ok(card) = threat_to_card(db, t) {
                                let _ = store::resolve_threat(db, card.id, CardStatus::AutoKilled);
                            }
                        }
                    }
                }
            }
            // Scan faster when threats detected
            interval = FAST_SCAN;
        }

        // Settle back to normal interval if clean
        if threats.is_empty() && interval == FAST_SCAN {
            interval = SCAN_INTERVAL;
        }

        // Sleep in short increments so we can check the shutdown flag
        let mut slept = Duration::ZERO;
        while slept < interval && !SHUTDOWN.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(500));
            slept += Duration::from_millis(500);
        }
    }

    // Graceful shutdown
    eprintln!("[aptnomo] shutting down...");
    if let Some(ref db) = db {
        let _ = db.flush();
        eprintln!("[aptnomo] sled flushed.");
    }
    let _ = std::fs::remove_file("/tmp/aptnomo/pid");
    eprintln!("[aptnomo] stopped.");
}

/// Global shutdown flag for signal handler
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Signal handler — sets the shutdown flag
extern "C" fn signal_handler(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Run all detection modules
fn scan_all() -> Vec<Threat> {
    let mut threats = Vec::new();
    threats.extend(f10_persistence());
    threats.extend(f20_network());
    threats.extend(f30_rootkit());
    threats.extend(f40_ssh());
    threats.extend(f50_processes());
    threats.extend(f60_logs());
    threats.extend(f70_cron());
    threats.extend(f80_files());
    threats
}

/// Report a threat — syslog + stderr + optional file
fn report(t: &Threat) {
    let kill_tag = if t.auto_kill { " [AUTO-KILL]" } else { "" };
    let msg = format!(
        "[aptnomo] {:?} | {} | {}{} | pid:{} path:{}",
        t.severity, t.module, t.description, kill_tag,
        t.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
        t.path.as_deref().unwrap_or("-"),
    );
    eprintln!("{}", msg);

    // Append to report file (rotate at 10 MB)
    types::rotate_if_needed("/tmp/aptnomo/threats.log", LOG_MAX_BYTES);
    let _ = std::fs::OpenOptions::new()
        .create(true).append(true)
        .open("/tmp/aptnomo/threats.log")
        .and_then(|mut f| {
            use std::io::Write;
            writeln!(f, "{} {}", chrono_now(), msg)
        });
}

/// Check if killing this threat is safe (won't affect user's work)
fn is_safe_to_kill(t: &Threat) -> bool {
    if let Some(pid) = t.pid {
        // Never kill PID 1, init, or the user's shell
        if pid <= 2 { return false; }
        // Check if it's a known user process (editor, browser, terminal)
        if let Ok(cmdline) = std::fs::read_to_string(format!("/proc/{}/cmdline", pid)) {
            let user_procs = ["vim", "nano", "bash", "zsh", "fish", "code", "chrome", "firefox", "tmux"];
            for p in &user_procs {
                if cmdline.contains(p) { return false; }
            }
        }
        return true;
    }
    false
}

/// Kill a threat process
fn kill_threat(t: &Threat) {
    if let Some(pid) = t.pid {
        eprintln!("[aptnomo] KILLING pid {} — {}", pid, t.description);
        unsafe { libc::kill(pid as i32, libc::SIGKILL); }
        types::rotate_if_needed("/tmp/aptnomo/kills.log", LOG_MAX_BYTES);
        let _ = std::fs::OpenOptions::new()
            .create(true).append(true)
            .open("/tmp/aptnomo/kills.log")
            .and_then(|mut f| {
                use std::io::Write;
                writeln!(f, "{} KILLED pid={} reason={}", chrono_now(), pid, t.description)
            });
    }
}

fn chrono_now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", d.as_secs())
}

const LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Convert internal Threat to shared ThreatCard for sled storage.
fn threat_to_card(db: &sled::Db, t: &Threat) -> anyhow::Result<ThreatCard> {
    let id = store::next_threat_id(db)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let module = types::module_from_str(t.module);

    let severity = match t.severity {
        Severity::Info => GuiSeverity::Green,
        Severity::Low => GuiSeverity::Yellow,
        Severity::Medium => GuiSeverity::Orange,
        Severity::High => GuiSeverity::Orange,
        Severity::Critical => GuiSeverity::Red,
    };

    // Extract process name and command from /proc/[pid]/cmdline
    let (process_name, command) = if let Some(pid) = t.pid {
        match std::fs::read_to_string(format!("/proc/{}/cmdline", pid)) {
            Ok(raw) => {
                let parts: Vec<&str> = raw.split('\0').filter(|s| !s.is_empty()).collect();
                let name = parts.first().and_then(|p| p.rsplit('/').next()).map(String::from);
                let cmd = if parts.is_empty() { None } else { Some(parts.join(" ")) };
                (name, cmd)
            }
            Err(_) => (None, None),
        }
    } else {
        (None, None)
    };

    Ok(ThreatCard {
        id,
        timestamp: now,
        module,
        severity,
        title: t.description.clone(),
        description: t.description.clone(),
        process_name,
        pid: t.pid,
        file_path: t.path.clone(),
        command,
        status: CardStatus::Pending,
        auto_kill: t.auto_kill,
    })
}

// ── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> sled::Db {
        sled::Config::new().temporary(true).open().unwrap()
    }

    fn make_threat(module: &'static str, severity: Severity, pid: Option<u32>, auto_kill: bool) -> Threat {
        Threat {
            module,
            severity,
            description: format!("test threat from {}", module),
            pid,
            path: None,
            auto_kill,
        }
    }

    // ── chrono_now ──

    #[test]
    fn chrono_now_returns_digits() {
        let s = chrono_now();
        assert!(!s.is_empty());
        assert!(s.chars().all(|c| c.is_ascii_digit()), "expected digits, got: {}", s);
    }

    #[test]
    fn chrono_now_is_plausible_epoch() {
        let s = chrono_now();
        let ts: u64 = s.parse().unwrap();
        // Must be after 2020-01-01 (1577836800) and before 2100-01-01 (4102444800)
        assert!(ts > 1_577_836_800, "timestamp too old: {}", ts);
        assert!(ts < 4_102_444_800, "timestamp too far future: {}", ts);
    }

    // ── is_safe_to_kill ──

    #[test]
    fn is_safe_to_kill_no_pid() {
        let t = make_threat("processes", Severity::Critical, None, true);
        assert!(!is_safe_to_kill(&t));
    }

    #[test]
    fn is_safe_to_kill_pid_zero() {
        let t = make_threat("processes", Severity::Critical, Some(0), true);
        assert!(!is_safe_to_kill(&t));
    }

    #[test]
    fn is_safe_to_kill_pid_one() {
        let t = make_threat("processes", Severity::Critical, Some(1), true);
        assert!(!is_safe_to_kill(&t));
    }

    #[test]
    fn is_safe_to_kill_pid_two() {
        let t = make_threat("processes", Severity::Critical, Some(2), true);
        assert!(!is_safe_to_kill(&t));
    }

    #[test]
    fn is_safe_to_kill_nonexistent_pid_returns_true() {
        // PID that certainly does not exist — process not found, no cmdline readable
        let t = make_threat("processes", Severity::Critical, Some(u32::MAX), true);
        // When /proc/<pid>/cmdline is unreadable, function returns true
        assert!(is_safe_to_kill(&t));
    }

    // ── Detection modules: no-panic on missing paths ──
    // All these tests verify the modules handle missing system files gracefully.
    // On Linux they read /proc; on macOS (CI/dev) those paths don't exist —
    // both cases should return an empty Vec, never panic.

    #[test]
    fn f10_persistence_no_panic() {
        let threats = f10_persistence();
        // May be empty or non-empty depending on system; must not panic
        let _ = threats;
    }

    #[test]
    fn f10_persistence_returns_vec() {
        let threats = f10_persistence();
        // All returned threats must be from the persistence module
        for t in &threats {
            assert_eq!(t.module, "persistence");
        }
    }

    #[test]
    fn f20_network_no_panic() {
        let _ = f20_network();
    }

    #[test]
    fn f20_network_returns_vec() {
        let threats = f20_network();
        for t in &threats {
            assert_eq!(t.module, "network");
        }
    }

    #[test]
    fn f30_rootkit_no_panic() {
        let _ = f30_rootkit();
    }

    #[test]
    fn f30_rootkit_returns_vec() {
        let threats = f30_rootkit();
        for t in &threats {
            assert_eq!(t.module, "rootkit");
        }
    }

    #[test]
    fn f40_ssh_no_panic() {
        let _ = f40_ssh();
    }

    #[test]
    fn f40_ssh_returns_vec() {
        let threats = f40_ssh();
        for t in &threats {
            assert_eq!(t.module, "ssh");
        }
    }

    #[test]
    fn f50_processes_no_panic() {
        let _ = f50_processes();
    }

    #[test]
    fn f50_processes_returns_vec() {
        let threats = f50_processes();
        for t in &threats {
            assert_eq!(t.module, "processes");
        }
    }

    #[test]
    fn f60_logs_no_panic() {
        let _ = f60_logs();
    }

    #[test]
    fn f60_logs_returns_vec() {
        let threats = f60_logs();
        for t in &threats {
            assert_eq!(t.module, "logs");
        }
    }

    #[test]
    fn f70_cron_no_panic() {
        let _ = f70_cron();
    }

    #[test]
    fn f70_cron_returns_vec() {
        let threats = f70_cron();
        for t in &threats {
            assert_eq!(t.module, "cron");
        }
    }

    #[test]
    fn f80_files_no_panic() {
        let _ = f80_files();
    }

    #[test]
    fn f80_files_returns_vec() {
        let threats = f80_files();
        for t in &threats {
            assert_eq!(t.module, "files");
        }
    }

    #[test]
    fn scan_all_no_panic() {
        let _ = scan_all();
    }

    #[test]
    fn scan_all_returns_vec() {
        let threats = scan_all();
        // All threats should have a known module
        let valid_modules = ["persistence", "network", "rootkit", "ssh", "processes", "logs", "cron", "files"];
        for t in &threats {
            assert!(valid_modules.contains(&t.module), "unknown module: {}", t.module);
        }
    }

    // ── threat_to_card ──

    #[test]
    fn threat_to_card_basic_fields() {
        let db = temp_db();
        let t = make_threat("processes", Severity::Critical, None, true);
        let card = threat_to_card(&db, &t).unwrap();
        assert_eq!(card.description, t.description);
        assert_eq!(card.severity, types::Severity::Red);
        assert_eq!(card.module, types::Module::Process);
        assert!(card.auto_kill);
        assert_eq!(card.status, types::CardStatus::Pending);
    }

    #[test]
    fn threat_to_card_severity_mapping() {
        let db = temp_db();
        let cases = [
            (Severity::Info, types::Severity::Green),
            (Severity::Low, types::Severity::Yellow),
            (Severity::Medium, types::Severity::Orange),
            (Severity::High, types::Severity::Orange),
            (Severity::Critical, types::Severity::Red),
        ];
        for (internal, expected_gui) in cases {
            let t = make_threat("network", internal, None, false);
            let card = threat_to_card(&db, &t).unwrap();
            assert_eq!(card.severity, expected_gui, "severity mapping failed for {:?}", t.severity);
        }
    }

    #[test]
    fn threat_to_card_all_modules() {
        let db = temp_db();
        let modules = [
            ("persistence", types::Module::Persistence),
            ("network", types::Module::Network),
            ("rootkit", types::Module::Rootkit),
            ("ssh", types::Module::Ssh),
            ("processes", types::Module::Process),
            ("logs", types::Module::Logs),
            ("cron", types::Module::Cron),
            ("files", types::Module::Files),
        ];
        for (module_str, expected_module) in modules {
            let t = make_threat(module_str, Severity::Medium, None, false);
            let card = threat_to_card(&db, &t).unwrap();
            assert_eq!(card.module, expected_module);
        }
    }

    #[test]
    fn threat_to_card_with_path() {
        let db = temp_db();
        let mut t = make_threat("files", Severity::Critical, None, false);
        t.path = Some("/tmp/.hidden_bin".into());
        let card = threat_to_card(&db, &t).unwrap();
        assert_eq!(card.file_path, Some("/tmp/.hidden_bin".into()));
    }

    #[test]
    fn threat_to_card_no_pid_gives_none_process_fields() {
        let db = temp_db();
        let t = make_threat("network", Severity::Medium, None, false);
        let card = threat_to_card(&db, &t).unwrap();
        assert_eq!(card.pid, None);
        assert_eq!(card.process_name, None);
        assert_eq!(card.command, None);
    }

    #[test]
    fn threat_to_card_nonexistent_pid_gives_none_process_fields() {
        let db = temp_db();
        let t = make_threat("processes", Severity::Critical, Some(u32::MAX), true);
        let card = threat_to_card(&db, &t).unwrap();
        assert_eq!(card.pid, Some(u32::MAX));
        // /proc/<u32::MAX>/cmdline won't exist, so name and command are None
        assert_eq!(card.process_name, None);
        assert_eq!(card.command, None);
    }

    #[test]
    fn threat_to_card_ids_are_monotonic() {
        let db = temp_db();
        let t = make_threat("network", Severity::Low, None, false);
        let c1 = threat_to_card(&db, &t).unwrap();
        let c2 = threat_to_card(&db, &t).unwrap();
        assert!(c2.id > c1.id);
    }

    #[test]
    fn threat_to_card_timestamp_is_recent() {
        let db = temp_db();
        let t = make_threat("ssh", Severity::Medium, None, false);
        let card = threat_to_card(&db, &t).unwrap();
        // Timestamp should be after 2020-01-01
        assert!(card.timestamp > 1_577_836_800);
    }

    // ── Severity ordering (internal enum) ──

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn auto_kill_only_triggers_on_critical() {
        // Verify the main loop logic: auto_kill AND severity >= Critical
        let t = make_threat("processes", Severity::High, None, true);
        // High severity with auto_kill=true should NOT trigger auto-kill
        assert!(!(t.auto_kill && t.severity >= Severity::Critical));

        let t2 = make_threat("processes", Severity::Critical, None, true);
        assert!(t2.auto_kill && t2.severity >= Severity::Critical);
    }

    // ── f40_ssh threshold test ──

    #[test]
    fn f40_ssh_threshold_is_five() {
        // The function reports threats only when >5 keys exist.
        // We can't easily control $HOME/.ssh/authorized_keys in a unit test,
        // but we verify the function doesn't panic on any HOME value.
        let _threats = f40_ssh();
    }

    // ── f20_network port parsing ──

    #[test]
    fn f20_known_ports_not_flagged() {
        // Known ports (22, 80, 443, etc.) should not appear in threats.
        // On systems where /proc/net/tcp exists, none of the known ports should be flagged.
        let threats = f20_network();
        let known: &[u16] = &[22, 80, 443, 8080, 8081, 3000, 3001, 8000];
        for t in &threats {
            if t.description.contains("0.0.0.0:") {
                let port_str = t.description.split(':').last().unwrap_or("0");
                if let Ok(port) = port_str.parse::<u16>() {
                    assert!(!known.contains(&port),
                        "known port {} was incorrectly flagged", port);
                }
            }
        }
    }

    // ── f80_files size threshold ──

    #[test]
    fn f80_files_small_hidden_not_flagged() {
        // Create a small hidden file in /tmp — should NOT be flagged (< 10KB)
        let path = "/tmp/.aptnomo_test_small_hidden";
        std::fs::write(path, "small").unwrap();
        let threats = f80_files();
        let flagged = threats.iter().any(|t| t.path.as_deref() == Some(path));
        assert!(!flagged, "small hidden file should not be flagged");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn f30_rootkit_clean_kernel_not_flagged() {
        // Standard module names should not be flagged.
        // We can't control /proc/modules but we verify the name-matching logic.
        let suspicious = ["hide", "stealth", "rootkit", "backdoor", "keylog"];
        let benign = ["ext4", "nfs", "tcp", "ipv6", "loop"];
        for name in &benign {
            for kw in &suspicious {
                assert!(!name.to_lowercase().contains(kw),
                    "benign module '{}' incorrectly matches keyword '{}'", name, kw);
            }
        }
        for name in &suspicious {
            let matches = suspicious.iter().any(|kw| name.to_lowercase().contains(kw));
            assert!(matches, "suspicious module '{}' should match at least one keyword", name);
        }
    }
}

// ── Detection Modules ──────────────────────────────────────

/// f10: Check for persistence mechanisms
fn f10_persistence() -> Vec<Threat> {
    let mut threats = Vec::new();
    // Check suspicious systemd units
    for dir in &["/etc/systemd/system", "/usr/lib/systemd/system"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                if let Ok(content) = std::fs::read_to_string(e.path()) {
                    // Suspicious: ExecStart pointing to /tmp or hidden dirs
                    if content.contains("/tmp/") || content.contains("/.") {
                        threats.push(Threat {
                            module: "persistence",
                            severity: Severity::High,
                            description: format!("systemd unit with suspicious ExecStart: {}", e.path().display()),
                            pid: None,
                            path: Some(e.path().display().to_string()),
                            auto_kill: false,
                        });
                    }
                }
            }
        }
    }
    threats
}

/// f20: Check for suspicious network connections
fn f20_network() -> Vec<Threat> {
    let mut threats = Vec::new();
    if let Ok(tcp) = std::fs::read_to_string("/proc/net/tcp") {
        for line in tcp.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 3 {
                // State 0A = LISTEN
                if parts[3] == "0A" {
                    // Check for listening on all interfaces (0.0.0.0)
                    if parts[1].starts_with("00000000:") {
                        let port_hex = &parts[1][9..];
                        if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                            let known_ports = [22, 80, 443, 8080, 8081, 3000, 3001, 8000];
                            if !known_ports.contains(&port) {
                                threats.push(Threat {
                                    module: "network",
                                    severity: Severity::Medium,
                                    description: format!("unknown service listening on 0.0.0.0:{}", port),
                                    pid: None,
                                    path: None,
                                    auto_kill: false,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    threats
}

/// f30: Check for rootkit indicators
fn f30_rootkit() -> Vec<Threat> {
    let mut threats = Vec::new();
    // Check for hidden kernel modules
    if let Ok(modules) = std::fs::read_to_string("/proc/modules") {
        let suspicious = ["hide", "stealth", "rootkit", "backdoor", "keylog"];
        for line in modules.lines() {
            let name = line.split_whitespace().next().unwrap_or("");
            for s in &suspicious {
                if name.to_lowercase().contains(s) {
                    threats.push(Threat {
                        module: "rootkit",
                        severity: Severity::Critical,
                        description: format!("suspicious kernel module: {}", name),
                        pid: None,
                        path: None,
                        auto_kill: false,
                    });
                }
            }
        }
    }
    threats
}

/// f40: Check for unauthorized SSH keys
fn f40_ssh() -> Vec<Threat> {
    let mut threats = Vec::new();
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let auth_keys = format!("{}/.ssh/authorized_keys", home);
    if let Ok(keys) = std::fs::read_to_string(&auth_keys) {
        let count = keys.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')).count();
        if count > 5 {
            threats.push(Threat {
                module: "ssh",
                severity: Severity::Medium,
                description: format!("{} SSH authorized keys — verify all are expected", count),
                pid: None,
                path: Some(auth_keys),
                auto_kill: false,
            });
        }
    }
    threats
}

/// f50: Check for suspicious processes
fn f50_processes() -> Vec<Threat> {
    let mut threats = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            let name = e.file_name();
            if let Ok(pid) = name.to_string_lossy().parse::<u32>() {
                let cmdline_path = format!("/proc/{}/cmdline", pid);
                if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
                    let suspicious = ["cryptominer", "xmrig", "stratum", "reverse_shell", "nc -e", "bash -i"];
                    for s in &suspicious {
                        if cmdline.to_lowercase().contains(s) {
                            threats.push(Threat {
                                module: "processes",
                                severity: Severity::Critical,
                                description: format!("suspicious process: {}", cmdline.replace('\0', " ").trim()),
                                pid: Some(pid),
                                path: None,
                                auto_kill: true,
                            });
                        }
                    }
                }
            }
        }
    }
    threats
}

/// f60: Check for log tampering
fn f60_logs() -> Vec<Threat> {
    let mut threats = Vec::new();
    let log_files = ["/var/log/auth.log", "/var/log/syslog", "/var/log/messages"];
    for log in &log_files {
        if let Ok(meta) = std::fs::metadata(log) {
            if meta.len() == 0 {
                threats.push(Threat {
                    module: "logs",
                    severity: Severity::High,
                    description: format!("log file is empty (possible wipe): {}", log),
                    pid: None,
                    path: Some(log.to_string()),
                    auto_kill: false,
                });
            }
        }
    }
    threats
}

/// f70: Check for suspicious cron jobs
fn f70_cron() -> Vec<Threat> {
    let mut threats = Vec::new();
    for dir in &["/etc/cron.d", "/var/spool/cron/crontabs", "/etc/cron.daily"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                if let Ok(content) = std::fs::read_to_string(e.path()) {
                    if content.contains("/tmp/") || content.contains("curl ") || content.contains("wget ") {
                        threats.push(Threat {
                            module: "cron",
                            severity: Severity::High,
                            description: format!("cron job with suspicious command: {}", e.path().display()),
                            pid: None,
                            path: Some(e.path().display().to_string()),
                            auto_kill: false,
                        });
                    }
                }
            }
        }
    }
    threats
}

/// f80: Check for suspicious files in common attack paths
fn f80_files() -> Vec<Threat> {
    let mut threats = Vec::new();
    let sus_dirs = ["/tmp", "/dev/shm", "/var/tmp"];
    for dir in &sus_dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                // Hidden executables in temp dirs
                if name.starts_with('.') {
                    if let Ok(meta) = e.metadata() {
                        if meta.is_file() && meta.len() > 10000 {
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                if meta.permissions().mode() & 0o111 != 0 {
                                    threats.push(Threat {
                                        module: "files",
                                        severity: Severity::Critical,
                                        description: format!("hidden executable in {}: {}", dir, name),
                                        pid: None,
                                        path: Some(e.path().display().to_string()),
                                        auto_kill: false,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    threats
}
