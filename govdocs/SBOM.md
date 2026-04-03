# SBOM — aptnomo

Software Bill of Materials. Generated from Cargo.toml.

## Direct dependencies

| Crate | Version | License | Feature flags |
|-------|---------|---------|---------------|
| clap | 4.x | MIT/Apache-2.0 | derive |
| serde | 1.x | MIT/Apache-2.0 | derive |
| serde_json | 1.x | MIT/Apache-2.0 | — |
| anyhow | 1.x | MIT/Apache-2.0 | — |
| libc | 0.2.x | MIT/Apache-2.0 | — |
| sled | 0.34.x | MIT/Apache-2.0 | — |
| bincode | 2.x | MIT | serde |
| zstd | 0.13.x | MIT | — |

## Optional dependencies

| Crate | Version | Feature gate | License |
|-------|---------|--------------|---------|
| exopack | 0.1.0 (path) | tests | Unlicense |
| eframe | 0.31.x | gui | MIT/Apache-2.0 |

## License summary

All dependencies are dual-licensed MIT/Apache-2.0 (bincode is MIT only). aptnomo itself is Unlicense (public domain).

## Supply chain notes

- Zero external runtime services
- No network dependencies
- All crates sourced from crates.io (except exopack, which is a local path dependency)
- Daemon stores threat data locally in sled DB at `~/.aptnomo/db/`
- See [SUPPLY_CHAIN_AUDIT.md](SUPPLY_CHAIN_AUDIT.md) for full audit

---

Unlicense — public domain — [cochranblock.org](https://cochranblock.org)
