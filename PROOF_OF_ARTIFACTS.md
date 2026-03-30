# Proof of Artifacts — aptnomo

## Binary

| Metric | Value |
|--------|-------|
| Binary name | aptnomo |
| Binary size (release, stripped) | 312 KB |
| Language | Rust (edition 2024) |
| Target | x86_64-unknown-linux-gnu |
| Dependencies (runtime) | 4 (clap, serde, serde_json, anyhow, libc) |
| External services | 0 — no network, no cloud, no DB |
| Config files | 0 — zero config |

## Detection Modules

| # | Module | Function | Severity Range | Auto-kill |
|---|--------|----------|----------------|-----------|
| 1 | Persistence | f10 | High | No |
| 2 | Network | f20 | Medium | No |
| 3 | Rootkit | f30 | Critical | No |
| 4 | SSH | f40 | Medium | No |
| 5 | Processes | f50 | Critical | Yes |
| 6 | Logs | f60 | High | No |
| 7 | Cron | f70 | High | No |
| 8 | Files | f80 | Critical | No |

**Module count: 8**

## Detection Categories

| Category | Modules | Description |
|----------|---------|-------------|
| Persistence | f10, f70 | Systemd units, cron jobs pointing to temp/hidden paths |
| Network | f20 | Unknown listeners on all interfaces |
| Kernel | f30 | Suspicious kernel module names |
| Authentication | f40 | SSH authorized_keys anomalies |
| Process | f50 | Known malware process signatures |
| Integrity | f60, f80 | Log tampering, hidden executables in temp dirs |

## Build Verification

```bash
# Build release binary
cargo build --release -p aptnomo

# Verify size
ls -la target/release/aptnomo
# Expected: ~312 KB

# Run test gate (exopack TRIPLE SIMS)
cargo run -p aptnomo --bin aptnomo-test --features tests
# Expected: exit 0
```

## Release Profile

```toml
[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

## Source Stats

| Metric | Value |
|--------|-------|
| Source files | 2 (main.rs, aptnomo-test.rs) |
| Lines of code | ~370 |
| Unsafe blocks | 1 (libc::kill for SIGKILL) |
| Feature gates | 1 (tests → exopack) |
