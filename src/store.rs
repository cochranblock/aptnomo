// Unlicense — cochranblock.org
// Contributors: GotEmCoach, KOVA, Claude Opus 4.6
//! store — sled DB with bincode + zstd compression.
//! Pattern ported from illbethejudgeofthat/src/legal/store.rs.

use crate::types::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ── Tree names ──

pub const TREE_THREATS: &str = "threats";
pub const TREE_BASELINE: &str = "baseline";
pub const TREE_HISTORY: &str = "history";

// ── DB setup ──

pub fn db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".aptnomo").join("db")
}

pub fn open_db() -> anyhow::Result<sled::Db> {
    let path = db_path();
    std::fs::create_dir_all(&path)?;
    Ok(sled::open(&path)?)
}

// ── Generic helpers ──

/// f97: Put a value into a named sled tree with bincode + zstd.
pub fn f97_put<V: Serialize>(db: &sled::Db, tree_name: &str, key: &str, value: &V) -> anyhow::Result<()> {
    let tree = db.open_tree(tree_name)?;
    let encoded = bincode::serde::encode_to_vec(value, bincode::config::standard())?;
    let compressed = zstd::encode_all(encoded.as_slice(), 3)?;
    tree.insert(key.as_bytes(), compressed)?;
    Ok(())
}

/// f96: Get a value from a named sled tree.
pub fn f96_get<V: for<'de> Deserialize<'de>>(db: &sled::Db, tree_name: &str, key: &str) -> anyhow::Result<Option<V>> {
    let tree = db.open_tree(tree_name)?;
    match tree.get(key.as_bytes())? {
        Some(bytes) => {
            let decompressed = zstd::decode_all(bytes.as_ref())?;
            let (value, _) = bincode::serde::decode_from_slice(&decompressed, bincode::config::standard())?;
            Ok(Some(value))
        }
        None => Ok(None),
    }
}

/// Scan all entries in a tree with a key prefix.
pub fn scan_prefix<V: for<'de> Deserialize<'de>>(db: &sled::Db, tree_name: &str, prefix: &str) -> anyhow::Result<Vec<(String, V)>> {
    let tree = db.open_tree(tree_name)?;
    let mut results = Vec::new();
    for item in tree.scan_prefix(prefix.as_bytes()) {
        let (key_bytes, val_bytes) = item?;
        let key = String::from_utf8_lossy(&key_bytes).to_string();
        let decompressed = zstd::decode_all(val_bytes.as_ref())?;
        let (value, _): (V, _) = bincode::serde::decode_from_slice(&decompressed, bincode::config::standard())?;
        results.push((key, value));
    }
    Ok(results)
}

/// Count entries in a tree.
pub fn count(db: &sled::Db, tree_name: &str) -> anyhow::Result<usize> {
    let tree = db.open_tree(tree_name)?;
    Ok(tree.len())
}

// ── Typed helpers: daemon ──

fn threat_key(id: u64) -> String {
    format!("{:016}", id)
}

/// Get next monotonic threat ID.
pub fn next_threat_id(db: &sled::Db) -> anyhow::Result<u64> {
    Ok(db.generate_id()?)
}

/// Write a ThreatCard to the threats tree.
pub fn write_threat(db: &sled::Db, card: &ThreatCard) -> anyhow::Result<()> {
    f97_put(db, TREE_THREATS, &threat_key(card.id), card)
}

/// Read all pending threats (for GUI).
pub fn pending_threats(db: &sled::Db) -> anyhow::Result<Vec<ThreatCard>> {
    let all: Vec<(String, ThreatCard)> = scan_prefix(db, TREE_THREATS, "")?;
    Ok(all.into_iter()
        .map(|(_, c)| c)
        .filter(|c| c.status == CardStatus::Pending)
        .collect())
}

/// Check if a threat with the same module and description is already pending.
pub fn is_duplicate(db: &sled::Db, module: &Module, description: &str) -> anyhow::Result<bool> {
    let tree = db.open_tree(TREE_THREATS)?;
    for item in tree.iter() {
        let (_, val_bytes) = item?;
        let decompressed = zstd::decode_all(val_bytes.as_ref())?;
        let (card, _): (ThreatCard, _) = bincode::serde::decode_from_slice(&decompressed, bincode::config::standard())?;
        if card.status == CardStatus::Pending && &card.module == module && card.description == description {
            return Ok(true);
        }
    }
    Ok(false)
}

// ── Typed helpers: GUI ──

/// Move a threat from the threats tree to history with a new status.
pub fn resolve_threat(db: &sled::Db, id: u64, status: CardStatus) -> anyhow::Result<()> {
    let key = threat_key(id);
    if let Some(mut card) = f96_get::<ThreatCard>(db, TREE_THREATS, &key)? {
        card.status = status;
        f97_put(db, TREE_HISTORY, &key, &card)?;
        let tree = db.open_tree(TREE_THREATS)?;
        tree.remove(key.as_bytes())?;
    }
    Ok(())
}

/// Add a baseline pattern.
pub fn add_baseline(db: &sled::Db, pattern: &BaselinePattern) -> anyhow::Result<()> {
    let key = format!("{}:{}", pattern.module.label(), pattern.value);
    f97_put(db, TREE_BASELINE, &key, pattern)
}

/// Get all baseline patterns.
pub fn all_baselines(db: &sled::Db) -> anyhow::Result<Vec<BaselinePattern>> {
    let all: Vec<(String, BaselinePattern)> = scan_prefix(db, TREE_BASELINE, "")?;
    Ok(all.into_iter().map(|(_, p)| p).collect())
}

/// Get all history cards.
pub fn history_cards(db: &sled::Db) -> anyhow::Result<Vec<ThreatCard>> {
    let all: Vec<(String, ThreatCard)> = scan_prefix(db, TREE_HISTORY, "")?;
    Ok(all.into_iter().map(|(_, c)| c).collect())
}

/// Compute stats across all trees.
pub fn stats(db: &sled::Db) -> anyhow::Result<Stats> {
    let pending: Vec<(String, ThreatCard)> = scan_prefix(db, TREE_THREATS, "")?;
    let history: Vec<(String, ThreatCard)> = scan_prefix(db, TREE_HISTORY, "")?;

    let mut s = Stats {
        pending: pending.len(),
        total_threats: pending.len() + history.len(),
        ..Default::default()
    };
    for (_, card) in &history {
        match card.status {
            CardStatus::Baselined => s.baselined += 1,
            CardStatus::Killed => s.killed += 1,
            CardStatus::Quarantined => s.quarantined += 1,
            CardStatus::AutoKilled => s.auto_killed += 1,
            CardStatus::Pending => {} // shouldn't be in history
        }
    }
    Ok(s)
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> sled::Db {
        sled::Config::new().temporary(true).open().unwrap()
    }

    fn sample_card(id: u64) -> ThreatCard {
        ThreatCard {
            id,
            timestamp: 1234567890,
            module: Module::Process,
            severity: Severity::Red,
            title: "xmrig cryptominer".into(),
            description: "suspicious process: xmrig --donate-level 1".into(),
            process_name: Some("xmrig".into()),
            pid: Some(42),
            file_path: None,
            command: Some("xmrig --donate-level 1".into()),
            status: CardStatus::Pending,
            auto_kill: true,
        }
    }

    #[test]
    fn write_and_read_threat() {
        let db = temp_db();
        let card = sample_card(1);
        write_threat(&db, &card).unwrap();
        let back: Option<ThreatCard> = f96_get(&db, TREE_THREATS, &threat_key(1)).unwrap();
        let back = back.unwrap();
        assert_eq!(back.id, 1);
        assert_eq!(back.title, "xmrig cryptominer");
        assert_eq!(back.severity, Severity::Red);
    }

    #[test]
    fn pending_threats_filter() {
        let db = temp_db();
        let mut c1 = sample_card(1);
        c1.status = CardStatus::Pending;
        let mut c2 = sample_card(2);
        c2.status = CardStatus::AutoKilled;
        write_threat(&db, &c1).unwrap();
        write_threat(&db, &c2).unwrap();
        let pending = pending_threats(&db).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, 1);
    }

    #[test]
    fn resolve_moves_to_history() {
        let db = temp_db();
        let card = sample_card(1);
        write_threat(&db, &card).unwrap();
        resolve_threat(&db, 1, CardStatus::Killed).unwrap();

        assert!(f96_get::<ThreatCard>(&db, TREE_THREATS, &threat_key(1)).unwrap().is_none());
        let hist: Option<ThreatCard> = f96_get(&db, TREE_HISTORY, &threat_key(1)).unwrap();
        assert_eq!(hist.unwrap().status, CardStatus::Killed);
    }

    #[test]
    fn baseline_roundtrip() {
        let db = temp_db();
        let pattern = BaselinePattern {
            module: Module::Network,
            pattern_type: PatternType::ListenPort,
            value: "8443".into(),
            learned_at: 1234567890,
            swipe_count: 3,
        };
        add_baseline(&db, &pattern).unwrap();
        let all = all_baselines(&db).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].value, "8443");
    }

    #[test]
    fn stats_computation() {
        let db = temp_db();
        write_threat(&db, &sample_card(1)).unwrap();
        write_threat(&db, &sample_card(2)).unwrap();
        resolve_threat(&db, 1, CardStatus::Killed).unwrap();

        let s = stats(&db).unwrap();
        assert_eq!(s.pending, 1);
        assert_eq!(s.killed, 1);
        assert_eq!(s.total_threats, 2);
    }

    #[test]
    fn next_id_monotonic() {
        let db = temp_db();
        let a = next_threat_id(&db).unwrap();
        let b = next_threat_id(&db).unwrap();
        assert!(b > a);
    }

    // ── Integration tests ──

    fn card_for_module(id: u64, module: Module, severity: Severity) -> ThreatCard {
        ThreatCard {
            id,
            timestamp: 1700000000 + id,
            module,
            severity,
            title: format!("threat from {:?}", module),
            description: format!("test threat id={} module={:?} sev={:?}", id, module, severity),
            process_name: if module == Module::Process { Some("evil".into()) } else { None },
            pid: if module == Module::Process { Some(9999) } else { None },
            file_path: if module == Module::Files { Some("/tmp/.hidden".into()) } else { None },
            command: None,
            status: CardStatus::Pending,
            auto_kill: severity == Severity::Red && module == Module::Process,
        }
    }

    #[test]
    fn full_lifecycle_all_modules() {
        let db = temp_db();

        // Seed one card per module at varying severities
        let cards = vec![
            card_for_module(1, Module::Persistence, Severity::Orange),
            card_for_module(2, Module::Network, Severity::Yellow),
            card_for_module(3, Module::Rootkit, Severity::Red),
            card_for_module(4, Module::Ssh, Severity::Yellow),
            card_for_module(5, Module::Process, Severity::Red),
            card_for_module(6, Module::Logs, Severity::Orange),
            card_for_module(7, Module::Cron, Severity::Orange),
            card_for_module(8, Module::Files, Severity::Red),
        ];

        for c in &cards {
            write_threat(&db, c).unwrap();
        }

        // All 8 should be pending
        let pending = pending_threats(&db).unwrap();
        assert_eq!(pending.len(), 8);

        // Resolve each with a different status
        resolve_threat(&db, 1, CardStatus::Baselined).unwrap();
        resolve_threat(&db, 2, CardStatus::Baselined).unwrap();
        resolve_threat(&db, 3, CardStatus::AutoKilled).unwrap();
        resolve_threat(&db, 4, CardStatus::Baselined).unwrap();
        resolve_threat(&db, 5, CardStatus::Killed).unwrap();
        resolve_threat(&db, 6, CardStatus::Quarantined).unwrap();
        resolve_threat(&db, 7, CardStatus::Baselined).unwrap();
        // 8 stays pending

        // Verify pending count
        let pending = pending_threats(&db).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, 8);

        // Verify history
        let hist = history_cards(&db).unwrap();
        assert_eq!(hist.len(), 7);

        // Verify stats
        let s = stats(&db).unwrap();
        assert_eq!(s.total_threats, 8);
        assert_eq!(s.pending, 1);
        assert_eq!(s.baselined, 4);
        assert_eq!(s.killed, 1);
        assert_eq!(s.quarantined, 1);
        assert_eq!(s.auto_killed, 1);
    }

    #[test]
    fn cross_tree_consistency() {
        let db = temp_db();

        // Write, resolve, verify card is NOT in threats tree and IS in history
        let card = sample_card(1);
        write_threat(&db, &card).unwrap();
        assert_eq!(count(&db, TREE_THREATS).unwrap(), 1);
        assert_eq!(count(&db, TREE_HISTORY).unwrap(), 0);

        resolve_threat(&db, 1, CardStatus::Killed).unwrap();
        assert_eq!(count(&db, TREE_THREATS).unwrap(), 0);
        assert_eq!(count(&db, TREE_HISTORY).unwrap(), 1);

        // History card has updated status
        let hist = history_cards(&db).unwrap();
        assert_eq!(hist[0].status, CardStatus::Killed);
        // Original fields preserved
        assert_eq!(hist[0].title, "xmrig cryptominer");
        assert_eq!(hist[0].pid, Some(42));
    }

    #[test]
    fn baseline_dedup_by_key() {
        let db = temp_db();

        // Same module+value should overwrite, not duplicate
        let p1 = BaselinePattern {
            module: Module::Network,
            pattern_type: PatternType::ListenPort,
            value: "8443".into(),
            learned_at: 1000,
            swipe_count: 1,
        };
        let p2 = BaselinePattern {
            module: Module::Network,
            pattern_type: PatternType::ListenPort,
            value: "8443".into(),
            learned_at: 2000,
            swipe_count: 2,
        };
        add_baseline(&db, &p1).unwrap();
        add_baseline(&db, &p2).unwrap();

        let all = all_baselines(&db).unwrap();
        assert_eq!(all.len(), 1); // key is module:value, so second overwrites first
        assert_eq!(all[0].swipe_count, 2);
        assert_eq!(all[0].learned_at, 2000);
    }

    #[test]
    fn is_duplicate_detects_same_threat() {
        let db = temp_db();
        let card = sample_card(1);
        write_threat(&db, &card).unwrap();

        assert!(is_duplicate(&db, &Module::Process, "suspicious process: xmrig --donate-level 1").unwrap());
        assert!(!is_duplicate(&db, &Module::Process, "different threat").unwrap());
        assert!(!is_duplicate(&db, &Module::Network, "suspicious process: xmrig --donate-level 1").unwrap());
    }

    #[test]
    fn resolve_nonexistent_is_noop() {
        let db = temp_db();
        resolve_threat(&db, 9999, CardStatus::Killed).unwrap();
        assert_eq!(count(&db, TREE_HISTORY).unwrap(), 0);
    }

    // ── Generic helper tests ──

    #[test]
    fn f96_get_nonexistent_key_returns_none() {
        let db = temp_db();
        let result: Option<ThreatCard> = f96_get(&db, TREE_THREATS, "does_not_exist").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn f97_put_f96_get_with_empty_key() {
        let db = temp_db();
        let card = sample_card(1);
        f97_put(&db, TREE_THREATS, "", &card).unwrap();
        let back: Option<ThreatCard> = f96_get(&db, TREE_THREATS, "").unwrap();
        assert!(back.is_some());
        assert_eq!(back.unwrap().id, 1);
    }

    #[test]
    fn f97_put_overwrites_same_key() {
        let db = temp_db();
        let mut c1 = sample_card(1);
        c1.title = "first".into();
        let mut c2 = sample_card(2);
        c2.title = "second".into();
        f97_put(&db, TREE_THREATS, "key1", &c1).unwrap();
        f97_put(&db, TREE_THREATS, "key1", &c2).unwrap();
        let back: Option<ThreatCard> = f96_get(&db, TREE_THREATS, "key1").unwrap();
        assert_eq!(back.unwrap().title, "second");
        assert_eq!(count(&db, TREE_THREATS).unwrap(), 1);
    }

    #[test]
    fn scan_prefix_with_specific_prefix() {
        let db = temp_db();
        f97_put(&db, "test_tree", "alpha:1", &sample_card(1)).unwrap();
        f97_put(&db, "test_tree", "alpha:2", &sample_card(2)).unwrap();
        f97_put(&db, "test_tree", "beta:1", &sample_card(3)).unwrap();

        let alpha: Vec<(String, ThreatCard)> = scan_prefix(&db, "test_tree", "alpha:").unwrap();
        assert_eq!(alpha.len(), 2);
        let beta: Vec<(String, ThreatCard)> = scan_prefix(&db, "test_tree", "beta:").unwrap();
        assert_eq!(beta.len(), 1);
        let all: Vec<(String, ThreatCard)> = scan_prefix(&db, "test_tree", "").unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn scan_prefix_no_matches() {
        let db = temp_db();
        f97_put(&db, "test_tree", "alpha:1", &sample_card(1)).unwrap();
        let empty: Vec<(String, ThreatCard)> = scan_prefix(&db, "test_tree", "zzz").unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn count_empty_tree() {
        let db = temp_db();
        assert_eq!(count(&db, TREE_THREATS).unwrap(), 0);
        assert_eq!(count(&db, TREE_HISTORY).unwrap(), 0);
        assert_eq!(count(&db, TREE_BASELINE).unwrap(), 0);
    }

    #[test]
    fn count_after_inserts_and_deletes() {
        let db = temp_db();
        write_threat(&db, &sample_card(1)).unwrap();
        write_threat(&db, &sample_card(2)).unwrap();
        write_threat(&db, &sample_card(3)).unwrap();
        assert_eq!(count(&db, TREE_THREATS).unwrap(), 3);
        resolve_threat(&db, 1, CardStatus::Killed).unwrap();
        assert_eq!(count(&db, TREE_THREATS).unwrap(), 2);
        assert_eq!(count(&db, TREE_HISTORY).unwrap(), 1);
    }

    // ── threat_key format ──

    #[test]
    fn threat_key_zero_padded() {
        assert_eq!(threat_key(0), "0000000000000000");
        assert_eq!(threat_key(1), "0000000000000001");
        assert_eq!(threat_key(999), "0000000000000999");
        assert_eq!(threat_key(u64::MAX), "18446744073709551615");
    }

    #[test]
    fn threat_key_ordering_is_chronological() {
        // Lexicographic order of zero-padded keys matches numeric order
        let k1 = threat_key(1);
        let k2 = threat_key(2);
        let k100 = threat_key(100);
        assert!(k1 < k2);
        assert!(k2 < k100);
    }

    // ── Write/overwrite ──

    #[test]
    fn write_threat_same_id_overwrites() {
        let db = temp_db();
        let mut c = sample_card(1);
        c.title = "original".into();
        write_threat(&db, &c).unwrap();
        c.title = "updated".into();
        write_threat(&db, &c).unwrap();
        assert_eq!(count(&db, TREE_THREATS).unwrap(), 1);
        let back: Option<ThreatCard> = f96_get(&db, TREE_THREATS, &threat_key(1)).unwrap();
        assert_eq!(back.unwrap().title, "updated");
    }

    // ── pending_threats edge cases ──

    #[test]
    fn pending_threats_empty_db() {
        let db = temp_db();
        let pending = pending_threats(&db).unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn pending_threats_all_resolved() {
        let db = temp_db();
        write_threat(&db, &sample_card(1)).unwrap();
        write_threat(&db, &sample_card(2)).unwrap();
        resolve_threat(&db, 1, CardStatus::Killed).unwrap();
        resolve_threat(&db, 2, CardStatus::Baselined).unwrap();
        let pending = pending_threats(&db).unwrap();
        assert!(pending.is_empty());
    }

    // ── history_cards ──

    #[test]
    fn history_cards_empty() {
        let db = temp_db();
        assert!(history_cards(&db).unwrap().is_empty());
    }

    #[test]
    fn history_cards_mixed_statuses() {
        let db = temp_db();
        write_threat(&db, &sample_card(1)).unwrap();
        write_threat(&db, &sample_card(2)).unwrap();
        write_threat(&db, &sample_card(3)).unwrap();
        resolve_threat(&db, 1, CardStatus::Killed).unwrap();
        resolve_threat(&db, 2, CardStatus::Baselined).unwrap();
        resolve_threat(&db, 3, CardStatus::Quarantined).unwrap();
        let hist = history_cards(&db).unwrap();
        assert_eq!(hist.len(), 3);
        let statuses: Vec<CardStatus> = hist.iter().map(|c| c.status).collect();
        assert!(statuses.contains(&CardStatus::Killed));
        assert!(statuses.contains(&CardStatus::Baselined));
        assert!(statuses.contains(&CardStatus::Quarantined));
    }

    // ── stats edge cases ──

    #[test]
    fn stats_empty_db() {
        let db = temp_db();
        let s = stats(&db).unwrap();
        assert_eq!(s.total_threats, 0);
        assert_eq!(s.pending, 0);
        assert_eq!(s.baselined, 0);
        assert_eq!(s.killed, 0);
        assert_eq!(s.quarantined, 0);
        assert_eq!(s.auto_killed, 0);
    }

    #[test]
    fn stats_only_pending() {
        let db = temp_db();
        write_threat(&db, &sample_card(1)).unwrap();
        write_threat(&db, &sample_card(2)).unwrap();
        let s = stats(&db).unwrap();
        assert_eq!(s.total_threats, 2);
        assert_eq!(s.pending, 2);
        assert_eq!(s.killed, 0);
    }

    #[test]
    fn stats_all_auto_killed() {
        let db = temp_db();
        for i in 1..=5 {
            write_threat(&db, &sample_card(i)).unwrap();
            resolve_threat(&db, i, CardStatus::AutoKilled).unwrap();
        }
        let s = stats(&db).unwrap();
        assert_eq!(s.total_threats, 5);
        assert_eq!(s.pending, 0);
        assert_eq!(s.auto_killed, 5);
    }

    // ── is_duplicate edge cases ──

    #[test]
    fn is_duplicate_empty_db() {
        let db = temp_db();
        assert!(!is_duplicate(&db, &Module::Process, "anything").unwrap());
    }

    #[test]
    fn is_duplicate_after_resolve() {
        let db = temp_db();
        let card = sample_card(1);
        write_threat(&db, &card).unwrap();
        assert!(is_duplicate(&db, &Module::Process, &card.description).unwrap());
        resolve_threat(&db, 1, CardStatus::Killed).unwrap();
        // After resolving, it's no longer in threats tree
        assert!(!is_duplicate(&db, &Module::Process, &card.description).unwrap());
    }

    // ── Baseline tests ──

    #[test]
    fn add_baseline_all_modules() {
        let db = temp_db();
        let modules = [Module::Persistence, Module::Network, Module::Rootkit, Module::Ssh,
                       Module::Process, Module::Logs, Module::Cron, Module::Files];
        for (i, m) in modules.iter().enumerate() {
            let p = BaselinePattern {
                module: *m, pattern_type: PatternType::ProcessName,
                value: format!("val{}", i), learned_at: 0, swipe_count: 1,
            };
            add_baseline(&db, &p).unwrap();
        }
        assert_eq!(all_baselines(&db).unwrap().len(), 8);
    }

    #[test]
    fn add_baseline_all_pattern_types() {
        let db = temp_db();
        let types = [PatternType::ProcessName, PatternType::ListenPort, PatternType::FilePath,
                     PatternType::CronPattern, PatternType::SshKey];
        for (i, pt) in types.iter().enumerate() {
            let p = BaselinePattern {
                module: Module::Process, pattern_type: *pt,
                value: format!("val{}", i), learned_at: 0, swipe_count: 1,
            };
            add_baseline(&db, &p).unwrap();
        }
        // All have module=Process but different values, so different keys
        assert_eq!(all_baselines(&db).unwrap().len(), 5);
    }

    #[test]
    fn all_baselines_empty() {
        let db = temp_db();
        assert!(all_baselines(&db).unwrap().is_empty());
    }

    // ── Scale test ──

    #[test]
    fn scale_100_threats() {
        let db = temp_db();
        let modules = [Module::Persistence, Module::Network, Module::Rootkit, Module::Ssh,
                       Module::Process, Module::Logs, Module::Cron, Module::Files];
        for i in 0..100u64 {
            let c = card_for_module(i, modules[(i % 8) as usize], Severity::Orange);
            write_threat(&db, &c).unwrap();
        }
        assert_eq!(count(&db, TREE_THREATS).unwrap(), 100);
        assert_eq!(pending_threats(&db).unwrap().len(), 100);

        // Resolve half
        for i in 0..50u64 {
            resolve_threat(&db, i, CardStatus::Baselined).unwrap();
        }
        assert_eq!(count(&db, TREE_THREATS).unwrap(), 50);
        assert_eq!(count(&db, TREE_HISTORY).unwrap(), 50);
        assert_eq!(pending_threats(&db).unwrap().len(), 50);

        let s = stats(&db).unwrap();
        assert_eq!(s.total_threats, 100);
        assert_eq!(s.pending, 50);
        assert_eq!(s.baselined, 50);
    }

    // ── Resolve with all statuses ──

    #[test]
    fn resolve_with_every_status() {
        let db = temp_db();
        let statuses = [CardStatus::Baselined, CardStatus::Killed, CardStatus::Quarantined, CardStatus::AutoKilled];
        for (i, status) in statuses.iter().enumerate() {
            let id = i as u64 + 1;
            write_threat(&db, &sample_card(id)).unwrap();
            resolve_threat(&db, id, *status).unwrap();
            let hist: Option<ThreatCard> = f96_get(&db, TREE_HISTORY, &threat_key(id)).unwrap();
            assert_eq!(hist.unwrap().status, *status);
        }
    }

    // ── Bincode+zstd compression verification ──

    #[test]
    fn compressed_data_is_smaller_than_json() {
        let db = temp_db();
        let card = ThreatCard {
            id: 1, timestamp: 1700000000, module: Module::Process, severity: Severity::Red,
            title: "a]".repeat(100), // repetitive data compresses well
            description: "b".repeat(100),
            process_name: Some("long_process_name".into()),
            pid: Some(12345), file_path: Some("/very/long/path/to/file".into()),
            command: Some("cmd --with --many --flags --and --arguments".into()),
            status: CardStatus::Pending, auto_kill: true,
        };
        let json_size = serde_json::to_vec(&card).unwrap().len();
        write_threat(&db, &card).unwrap();
        // Read raw bytes from sled
        let tree = db.open_tree(TREE_THREATS).unwrap();
        let raw = tree.get(threat_key(1).as_bytes()).unwrap().unwrap();
        assert!(raw.len() < json_size, "compressed ({}) should be < json ({})", raw.len(), json_size);
    }

    // ── db_path ──

    #[test]
    fn db_path_contains_aptnomo() {
        let path = db_path();
        assert!(path.to_str().unwrap().contains(".aptnomo"));
        assert!(path.to_str().unwrap().contains("db"));
    }

    // ── Multiple trees independent ──

    #[test]
    fn trees_are_independent() {
        let db = temp_db();
        f97_put(&db, TREE_THREATS, "key1", &sample_card(1)).unwrap();
        f97_put(&db, TREE_HISTORY, "key1", &sample_card(2)).unwrap();
        f97_put(&db, TREE_BASELINE, "key1", &BaselinePattern {
            module: Module::Ssh, pattern_type: PatternType::SshKey,
            value: "fingerprint".into(), learned_at: 0, swipe_count: 1,
        }).unwrap();
        assert_eq!(count(&db, TREE_THREATS).unwrap(), 1);
        assert_eq!(count(&db, TREE_HISTORY).unwrap(), 1);
        assert_eq!(count(&db, TREE_BASELINE).unwrap(), 1);
    }
}
