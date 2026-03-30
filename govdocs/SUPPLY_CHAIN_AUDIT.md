# Supply Chain Audit — aptnomo

## Dependency Tree

### Direct dependencies

| Crate | Version | License | Purpose | Audit status |
|-------|---------|---------|---------|--------------|
| clap | 4.x | MIT/Apache-2.0 | CLI argument parsing | Widely audited, >200M downloads |
| serde | 1.x | MIT/Apache-2.0 | Serialization framework | Rust ecosystem standard |
| serde_json | 1.x | MIT/Apache-2.0 | JSON serialization | Same maintainer as serde |
| anyhow | 1.x | MIT/Apache-2.0 | Error handling | dtolnay (trusted maintainer) |
| libc | 0.2.x | MIT/Apache-2.0 | POSIX FFI bindings | Rust project official crate |

### Optional dependencies

| Crate | Version | Feature gate | Purpose |
|-------|---------|--------------|---------|
| exopack | 0.1.0 (path) | `tests` | TRIPLE SIMS test runner |

### Transitive dependency analysis

All direct deps are maintained by trusted Rust ecosystem authors (dtolnay, clap-rs team, rust-lang). No dependencies from unknown or single-maintainer crates in the critical path.

## Build safety

| Check | Status |
|-------|--------|
| No build scripts (build.rs) | Confirmed — no build.rs |
| No proc macros from unknown sources | clap/serde derive macros only |
| No network access at build time | Confirmed |
| No code generation from external files | Confirmed |
| `panic = "abort"` in release | Yes — no unwinding attack surface |
| LTO enabled | Yes — dead code eliminated |
| Binary stripped | Yes — no debug info leakage |

## Unsafe code audit

| Location | Code | Justification |
|----------|------|---------------|
| `src/main.rs` kill_threat() | `libc::kill(pid, SIGKILL)` | Required for process termination. PID validated before call. |

No other unsafe blocks in aptnomo source.

## Runtime behavior

- **No network calls** — aptnomo never connects to any external service
- **No file downloads** — no curl, wget, or HTTP client
- **No dynamic library loading** — static binary
- **No eval or code execution** — no script interpreters
- **Filesystem writes limited to** `/tmp/aptnomo/` only

## Reproducible builds

```bash
cargo build --release -p aptnomo
sha256sum target/release/aptnomo
```

Same toolchain + same source = same binary (LTO + single codegen unit ensures deterministic output).
