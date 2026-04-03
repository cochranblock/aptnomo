// Unlicense — cochranblock.org
// Contributors: GotEmCoach, KOVA, Claude Opus 4.6
//! aptnomo — autonomous APT threat hunter.
//! Runs as a background daemon. Watches. Reports. Kills threats when safe.
//! No CLI interaction needed. Drop it on a machine, run it, forget it.

use std::time::Duration;
use std::thread;

use aptnomo::types::{ThreatCard, CardStatus, Module, Severity as GuiSeverity};
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

    // First scan is fast
    let mut interval = FAST_SCAN;

    loop {
        let threats = scan_all();

        if threats.is_empty() {
            // Silent when clean — no output
        } else {
            for t in &threats {
                report(t);
                // Write to sled if available
                if let Some(ref db) = db {
                    if let Ok(card) = threat_to_card(db, t) {
                        let _ = store::write_threat(db, &card);
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

        thread::sleep(interval);
    }
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

    // Append to report file
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
    // Simple timestamp without chrono dep
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", d.as_secs())
}

/// Convert internal Threat to shared ThreatCard for sled storage.
fn threat_to_card(db: &sled::Db, t: &Threat) -> anyhow::Result<ThreatCard> {
    let id = store::next_threat_id(db)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let module = match t.module {
        "persistence" => Module::Persistence,
        "network" => Module::Network,
        "rootkit" => Module::Rootkit,
        "ssh" => Module::Ssh,
        "processes" => Module::Process,
        "logs" => Module::Logs,
        "cron" => Module::Cron,
        "files" => Module::Files,
        _ => Module::Process,
    };

    let severity = match t.severity {
        Severity::Info => GuiSeverity::Green,
        Severity::Low => GuiSeverity::Yellow,
        Severity::Medium => GuiSeverity::Orange,
        Severity::High => GuiSeverity::Orange,
        Severity::Critical => GuiSeverity::Red,
    };

    Ok(ThreatCard {
        id,
        timestamp: now,
        module,
        severity,
        title: t.description.clone(),
        description: t.description.clone(),
        process_name: None,
        pid: t.pid,
        file_path: t.path.clone(),
        command: None,
        status: CardStatus::Pending,
        auto_kill: t.auto_kill,
    })
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
