// Unlicense — cochranblock.org
// Contributors: GotEmCoach, KOVA, Claude Opus 4.6
//! Shared types for aptnomo daemon and GUI.
//! t10-t13 from compression map.

use serde::{Deserialize, Serialize};

/// Detection module identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Module {
    Persistence, // f10
    Network,     // f20
    Rootkit,     // f30
    Ssh,         // f40
    Process,     // f50
    Logs,        // f60
    Cron,        // f70
    Files,       // f80
}

impl Module {
    pub fn label(&self) -> &'static str {
        match self {
            Module::Persistence => "persistence",
            Module::Network => "network",
            Module::Rootkit => "rootkit",
            Module::Ssh => "ssh",
            Module::Process => "processes",
            Module::Logs => "logs",
            Module::Cron => "cron",
            Module::Files => "files",
        }
    }
}

/// 4-level severity matching GUI color scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Green,  // informational
    Yellow, // unusual
    Orange, // suspicious
    Red,    // critical — auto-kill eligible
}

/// t12: Card status in the threat lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CardStatus {
    Pending,
    Baselined,
    Killed,
    Quarantined,
    AutoKilled,
}

/// t10: A threat card written by the daemon, read by the GUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatCard {
    pub id: u64,
    pub timestamp: u64,
    pub module: Module,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub process_name: Option<String>,
    pub pid: Option<u32>,
    pub file_path: Option<String>,
    pub command: Option<String>,
    pub status: CardStatus,
    pub auto_kill: bool,
}

/// t13: What dimension a baseline pattern matches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternType {
    ProcessName,
    ListenPort,
    FilePath,
    CronPattern,
    SshKey,
}

/// t11: A learned baseline pattern from right-swipes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselinePattern {
    pub module: Module,
    pub pattern_type: PatternType,
    pub value: String,
    pub learned_at: u64,
    pub swipe_count: u32,
}

/// Aggregated stats for the stats screen.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub total_threats: usize,
    pub pending: usize,
    pub baselined: usize,
    pub killed: usize,
    pub quarantined: usize,
    pub auto_killed: usize,
}

/// Map internal module string to Module enum.
pub fn module_from_str(s: &str) -> Module {
    match s {
        "persistence" => Module::Persistence,
        "network" => Module::Network,
        "rootkit" => Module::Rootkit,
        "ssh" => Module::Ssh,
        "processes" => Module::Process,
        "logs" => Module::Logs,
        "cron" => Module::Cron,
        "files" => Module::Files,
        _ => Module::Process,
    }
}

/// Rotate a log file if it exceeds max_bytes. Renames to .old.
pub fn rotate_if_needed(path: &str, max_bytes: u64) {
    if let Ok(meta) = std::fs::metadata(path)
        && meta.len() > max_bytes
    {
        let old = format!("{}.old", path);
        let _ = std::fs::rename(path, &old);
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    // ── Module ──

    #[test]
    fn module_label_persistence() { assert_eq!(Module::Persistence.label(), "persistence"); }
    #[test]
    fn module_label_network() { assert_eq!(Module::Network.label(), "network"); }
    #[test]
    fn module_label_rootkit() { assert_eq!(Module::Rootkit.label(), "rootkit"); }
    #[test]
    fn module_label_ssh() { assert_eq!(Module::Ssh.label(), "ssh"); }
    #[test]
    fn module_label_process() { assert_eq!(Module::Process.label(), "processes"); }
    #[test]
    fn module_label_logs() { assert_eq!(Module::Logs.label(), "logs"); }
    #[test]
    fn module_label_cron() { assert_eq!(Module::Cron.label(), "cron"); }
    #[test]
    fn module_label_files() { assert_eq!(Module::Files.label(), "files"); }

    #[test]
    fn module_equality() {
        assert_eq!(Module::Process, Module::Process);
        assert_ne!(Module::Process, Module::Network);
    }

    #[test]
    fn module_clone() {
        let m = Module::Rootkit;
        let m2 = m;
        assert_eq!(m, m2);
    }

    #[test]
    fn module_debug_format() {
        let s = format!("{:?}", Module::Ssh);
        assert_eq!(s, "Ssh");
    }

    // ── module_from_str ──

    #[test]
    fn module_from_str_all_known() {
        assert_eq!(module_from_str("persistence"), Module::Persistence);
        assert_eq!(module_from_str("network"), Module::Network);
        assert_eq!(module_from_str("rootkit"), Module::Rootkit);
        assert_eq!(module_from_str("ssh"), Module::Ssh);
        assert_eq!(module_from_str("processes"), Module::Process);
        assert_eq!(module_from_str("logs"), Module::Logs);
        assert_eq!(module_from_str("cron"), Module::Cron);
        assert_eq!(module_from_str("files"), Module::Files);
    }

    #[test]
    fn module_from_str_unknown_defaults_to_process() {
        assert_eq!(module_from_str(""), Module::Process);
        assert_eq!(module_from_str("unknown"), Module::Process);
        assert_eq!(module_from_str("NETWORK"), Module::Process); // case sensitive
    }

    // ── Severity ──

    #[test]
    fn severity_ordering() {
        assert!(Severity::Green < Severity::Yellow);
        assert!(Severity::Yellow < Severity::Orange);
        assert!(Severity::Orange < Severity::Red);
    }

    #[test]
    fn severity_min_max() {
        let sevs = [Severity::Red, Severity::Green, Severity::Orange, Severity::Yellow];
        assert_eq!(*sevs.iter().min().unwrap(), Severity::Green);
        assert_eq!(*sevs.iter().max().unwrap(), Severity::Red);
    }

    #[test]
    fn severity_equality() {
        assert_eq!(Severity::Red, Severity::Red);
        assert_ne!(Severity::Green, Severity::Red);
    }

    #[test]
    fn severity_clone_copy() {
        let s = Severity::Orange;
        let s2 = s;
        assert_eq!(s, s2);
    }

    // ── CardStatus ──

    #[test]
    fn card_status_equality() {
        assert_eq!(CardStatus::Pending, CardStatus::Pending);
        assert_ne!(CardStatus::Pending, CardStatus::Killed);
    }

    #[test]
    fn card_status_all_variants() {
        let variants = [
            CardStatus::Pending,
            CardStatus::Baselined,
            CardStatus::Killed,
            CardStatus::Quarantined,
            CardStatus::AutoKilled,
        ];
        assert_eq!(variants.len(), 5);
        // All distinct
        for i in 0..variants.len() {
            for j in (i+1)..variants.len() {
                assert_ne!(variants[i], variants[j]);
            }
        }
    }

    // ── PatternType ──

    #[test]
    fn pattern_type_all_variants() {
        let variants = [
            PatternType::ProcessName,
            PatternType::ListenPort,
            PatternType::FilePath,
            PatternType::CronPattern,
            PatternType::SshKey,
        ];
        assert_eq!(variants.len(), 5);
        for i in 0..variants.len() {
            for j in (i+1)..variants.len() {
                assert_ne!(variants[i], variants[j]);
            }
        }
    }

    // ── ThreatCard ──

    fn sample_card() -> ThreatCard {
        ThreatCard {
            id: 42,
            timestamp: 1700000000,
            module: Module::Process,
            severity: Severity::Red,
            title: "xmrig".into(),
            description: "cryptominer detected".into(),
            process_name: Some("xmrig".into()),
            pid: Some(1234),
            file_path: None,
            command: Some("/usr/bin/xmrig --donate-level 1".into()),
            status: CardStatus::Pending,
            auto_kill: true,
        }
    }

    #[test]
    fn threat_card_fields() {
        let c = sample_card();
        assert_eq!(c.id, 42);
        assert_eq!(c.timestamp, 1700000000);
        assert_eq!(c.module, Module::Process);
        assert_eq!(c.severity, Severity::Red);
        assert_eq!(c.title, "xmrig");
        assert_eq!(c.description, "cryptominer detected");
        assert_eq!(c.process_name, Some("xmrig".into()));
        assert_eq!(c.pid, Some(1234));
        assert_eq!(c.file_path, None);
        assert_eq!(c.command, Some("/usr/bin/xmrig --donate-level 1".into()));
        assert_eq!(c.status, CardStatus::Pending);
        assert!(c.auto_kill);
    }

    #[test]
    fn threat_card_clone() {
        let c = sample_card();
        let c2 = c.clone();
        assert_eq!(c.id, c2.id);
        assert_eq!(c.title, c2.title);
    }

    #[test]
    fn threat_card_none_optionals() {
        let c = ThreatCard {
            id: 1, timestamp: 0, module: Module::Network, severity: Severity::Yellow,
            title: "t".into(), description: "d".into(),
            process_name: None, pid: None, file_path: None, command: None,
            status: CardStatus::Pending, auto_kill: false,
        };
        assert_eq!(c.process_name, None);
        assert_eq!(c.pid, None);
        assert_eq!(c.file_path, None);
        assert_eq!(c.command, None);
        assert!(!c.auto_kill);
    }

    #[test]
    fn threat_card_serde_roundtrip() {
        let c = sample_card();
        let json = serde_json::to_string(&c).unwrap();
        let c2: ThreatCard = serde_json::from_str(&json).unwrap();
        assert_eq!(c.id, c2.id);
        assert_eq!(c.module, c2.module);
        assert_eq!(c.severity, c2.severity);
        assert_eq!(c.title, c2.title);
        assert_eq!(c.status, c2.status);
        assert_eq!(c.auto_kill, c2.auto_kill);
    }

    #[test]
    fn threat_card_serde_all_modules() {
        for module in [Module::Persistence, Module::Network, Module::Rootkit, Module::Ssh,
                       Module::Process, Module::Logs, Module::Cron, Module::Files] {
            let c = ThreatCard {
                id: 1, timestamp: 0, module, severity: Severity::Green,
                title: "t".into(), description: "d".into(),
                process_name: None, pid: None, file_path: None, command: None,
                status: CardStatus::Pending, auto_kill: false,
            };
            let json = serde_json::to_string(&c).unwrap();
            let c2: ThreatCard = serde_json::from_str(&json).unwrap();
            assert_eq!(c.module, c2.module);
        }
    }

    #[test]
    fn threat_card_serde_all_severities() {
        for sev in [Severity::Green, Severity::Yellow, Severity::Orange, Severity::Red] {
            let c = ThreatCard {
                id: 1, timestamp: 0, module: Module::Network, severity: sev,
                title: "t".into(), description: "d".into(),
                process_name: None, pid: None, file_path: None, command: None,
                status: CardStatus::Pending, auto_kill: false,
            };
            let json = serde_json::to_string(&c).unwrap();
            let c2: ThreatCard = serde_json::from_str(&json).unwrap();
            assert_eq!(c.severity, c2.severity);
        }
    }

    #[test]
    fn threat_card_serde_all_statuses() {
        for status in [CardStatus::Pending, CardStatus::Baselined, CardStatus::Killed,
                       CardStatus::Quarantined, CardStatus::AutoKilled] {
            let c = ThreatCard {
                id: 1, timestamp: 0, module: Module::Network, severity: Severity::Green,
                title: "t".into(), description: "d".into(),
                process_name: None, pid: None, file_path: None, command: None,
                status, auto_kill: false,
            };
            let json = serde_json::to_string(&c).unwrap();
            let c2: ThreatCard = serde_json::from_str(&json).unwrap();
            assert_eq!(c.status, c2.status);
        }
    }

    // ── BaselinePattern ──

    #[test]
    fn baseline_pattern_fields() {
        let p = BaselinePattern {
            module: Module::Network,
            pattern_type: PatternType::ListenPort,
            value: "8443".into(),
            learned_at: 1700000000,
            swipe_count: 5,
        };
        assert_eq!(p.module, Module::Network);
        assert_eq!(p.pattern_type, PatternType::ListenPort);
        assert_eq!(p.value, "8443");
        assert_eq!(p.learned_at, 1700000000);
        assert_eq!(p.swipe_count, 5);
    }

    #[test]
    fn baseline_pattern_serde_roundtrip() {
        let p = BaselinePattern {
            module: Module::Files,
            pattern_type: PatternType::FilePath,
            value: "/usr/local/bin/app".into(),
            learned_at: 1234,
            swipe_count: 3,
        };
        let json = serde_json::to_string(&p).unwrap();
        let p2: BaselinePattern = serde_json::from_str(&json).unwrap();
        assert_eq!(p.module, p2.module);
        assert_eq!(p.pattern_type, p2.pattern_type);
        assert_eq!(p.value, p2.value);
    }

    #[test]
    fn baseline_pattern_all_pattern_types_serde() {
        for pt in [PatternType::ProcessName, PatternType::ListenPort, PatternType::FilePath,
                    PatternType::CronPattern, PatternType::SshKey] {
            let p = BaselinePattern {
                module: Module::Process, pattern_type: pt,
                value: "test".into(), learned_at: 0, swipe_count: 0,
            };
            let json = serde_json::to_string(&p).unwrap();
            let p2: BaselinePattern = serde_json::from_str(&json).unwrap();
            assert_eq!(p.pattern_type, p2.pattern_type);
        }
    }

    // ── Stats ──

    #[test]
    fn stats_default() {
        let s = Stats::default();
        assert_eq!(s.total_threats, 0);
        assert_eq!(s.pending, 0);
        assert_eq!(s.baselined, 0);
        assert_eq!(s.killed, 0);
        assert_eq!(s.quarantined, 0);
        assert_eq!(s.auto_killed, 0);
    }

    // ── rotate_if_needed ──

    #[test]
    fn rotate_nonexistent_file_is_noop() {
        // Should not panic on missing file
        rotate_if_needed("/tmp/aptnomo_test_nonexistent_file.log", 100);
    }

    #[test]
    fn rotate_small_file_stays() {
        let path = "/tmp/aptnomo_test_small.log";
        std::fs::write(path, "small content").unwrap();
        rotate_if_needed(path, 1_000_000);
        assert!(std::fs::metadata(path).is_ok()); // still exists
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rotate_large_file_renamed() {
        let path = "/tmp/aptnomo_test_large.log";
        let old = format!("{}.old", path);
        // Write 200 bytes, rotate at 100
        std::fs::write(path, "x".repeat(200)).unwrap();
        rotate_if_needed(path, 100);
        assert!(std::fs::metadata(path).is_err()); // original gone
        assert!(std::fs::metadata(&old).is_ok()); // .old exists
        let content = std::fs::read_to_string(&old).unwrap();
        assert_eq!(content.len(), 200);
        let _ = std::fs::remove_file(&old);
    }

    // ── Edge cases: empty/long strings ──

    #[test]
    fn threat_card_empty_strings() {
        let c = ThreatCard {
            id: 0, timestamp: 0, module: Module::Network, severity: Severity::Green,
            title: "".into(), description: "".into(),
            process_name: Some("".into()), pid: None, file_path: Some("".into()), command: Some("".into()),
            status: CardStatus::Pending, auto_kill: false,
        };
        let json = serde_json::to_string(&c).unwrap();
        let c2: ThreatCard = serde_json::from_str(&json).unwrap();
        assert_eq!(c2.title, "");
        assert_eq!(c2.process_name, Some("".into()));
    }

    #[test]
    fn threat_card_unicode_strings() {
        let c = ThreatCard {
            id: 1, timestamp: 0, module: Module::Files, severity: Severity::Orange,
            title: "hidden file: /tmp/.悪意のある".into(),
            description: "unicode path detected".into(),
            process_name: None, pid: None,
            file_path: Some("/tmp/.悪意のある".into()),
            command: None, status: CardStatus::Pending, auto_kill: false,
        };
        let json = serde_json::to_string(&c).unwrap();
        let c2: ThreatCard = serde_json::from_str(&json).unwrap();
        assert_eq!(c2.title, "hidden file: /tmp/.悪意のある");
        assert_eq!(c2.file_path, Some("/tmp/.悪意のある".into()));
    }

    #[test]
    fn threat_card_max_id() {
        let c = ThreatCard {
            id: u64::MAX, timestamp: u64::MAX, module: Module::Process, severity: Severity::Red,
            title: "t".into(), description: "d".into(),
            process_name: None, pid: Some(u32::MAX), file_path: None, command: None,
            status: CardStatus::Pending, auto_kill: true,
        };
        let json = serde_json::to_string(&c).unwrap();
        let c2: ThreatCard = serde_json::from_str(&json).unwrap();
        assert_eq!(c2.id, u64::MAX);
        assert_eq!(c2.timestamp, u64::MAX);
        assert_eq!(c2.pid, Some(u32::MAX));
    }

    #[test]
    fn baseline_pattern_empty_value() {
        let p = BaselinePattern {
            module: Module::Ssh, pattern_type: PatternType::SshKey,
            value: "".into(), learned_at: 0, swipe_count: 0,
        };
        let json = serde_json::to_string(&p).unwrap();
        let p2: BaselinePattern = serde_json::from_str(&json).unwrap();
        assert_eq!(p2.value, "");
    }

    #[test]
    fn module_label_roundtrip_via_from_str() {
        // Every module's label should map back to itself via module_from_str
        let modules = [Module::Persistence, Module::Network, Module::Rootkit, Module::Ssh,
                       Module::Logs, Module::Cron, Module::Files];
        for m in modules {
            assert_eq!(module_from_str(m.label()), m, "roundtrip failed for {:?}", m);
        }
        // Process is special: label is "processes" but module_from_str expects "processes"
        assert_eq!(module_from_str(Module::Process.label()), Module::Process);
    }
}
