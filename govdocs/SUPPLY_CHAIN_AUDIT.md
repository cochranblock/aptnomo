# Supply Chain Audit — aptnomo

## Dependency Tree

### Direct dependencies

| Crate | Version | License | Purpose | Audit status |
|-------|---------|---------|---------|--------------|
| serde | 1.x | MIT/Apache-2.0 | Serialization framework | Rust ecosystem standard |
| anyhow | 1.x | MIT/Apache-2.0 | Error handling | dtolnay (trusted maintainer) |
| libc | 0.2.x | MIT/Apache-2.0 | POSIX FFI bindings | Rust project official crate |
| sled | 0.34.x | MIT/Apache-2.0 | Embedded key-value database | spacejam (trusted), widely used |
| bincode | 2.x | MIT | Binary serialization | Mature, >50M downloads |
| zstd | 0.13.x | MIT | Zstandard compression | Wrapper around Facebook's zstd C lib |

### Optional dependencies

| Crate | Version | Feature gate | Purpose |
|-------|---------|--------------|---------|
| exopack | 0.1.0 (path) | `tests` | TRIPLE SIMS test runner |
| eframe | 0.31.x | `gui` | egui native GUI framework |

### Transitive dependency analysis

All direct deps are maintained by trusted Rust ecosystem authors (dtolnay, rust-lang, spacejam, emilk). No dependencies from unknown or single-maintainer crates in the critical path. eframe brings in egui ecosystem (emilk, trusted) and platform windowing (winit, glutin).

## Build safety

| Check | Status |
|-------|--------|
| No build scripts (build.rs) | Confirmed — no build.rs |
| No proc macros from unknown sources | serde/bincode derive macros only |
| No network access at build time | Confirmed |
| No code generation from external files | Confirmed |
| `panic = "abort"` in release | Yes — no unwinding attack surface |
| LTO enabled | Yes — dead code eliminated |
| Binary stripped | Yes — no debug info leakage |

## Unsafe code audit

| Location | Code | Justification |
|----------|------|---------------|
| `src/main.rs` kill_threat() | `libc::kill(pid, SIGKILL)` | Required for process termination. PID validated before call. |
| `src/bin/aptnomo-gui.rs` f92 | `libc::kill(pid, SIGKILL)` | User-initiated kill via swipe. PID > 2 guard. |
| `src/bin/aptnomo-gui.rs` f92 | `libc::kill(pid, SIGSTOP)` | User-initiated quarantine via swipe. PID > 2 guard. |

No other unsafe blocks in aptnomo source.

## Runtime behavior

- **No outbound network calls** — aptnomo never connects to any external service
- **No file downloads** — no curl, wget, or HTTP client
- **No dynamic library loading** — static binary
- **No eval or code execution** — no script interpreters
- **Daemon filesystem writes limited to** `/tmp/aptnomo/` and `~/.aptnomo/db/`
- **GUI filesystem writes limited to** `~/.aptnomo/db/` (sled)
- **Sled DB** uses file-level locking, safe for concurrent daemon + GUI access

## Reproducible builds

```bash
cargo build --release -p aptnomo
sha256sum target/release/aptnomo
```

Same toolchain + same source = same binary (LTO + single codegen unit ensures deterministic output).

---

Unlicense — public domain — [cochranblock.org](https://cochranblock.org)
