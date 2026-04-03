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
