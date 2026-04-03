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

    let mut s = Stats::default();
    s.pending = pending.len();
    for (_, card) in &history {
        match card.status {
            CardStatus::Baselined => s.baselined += 1,
            CardStatus::Killed => s.killed += 1,
            CardStatus::Quarantined => s.quarantined += 1,
            CardStatus::AutoKilled => s.auto_killed += 1,
            CardStatus::Pending => {} // shouldn't be in history
        }
    }
    s.total_threats = s.pending + history.len();
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
}
