# modules/deep-research/src — navigation

Native Rust modules, shared SDK contracts, or maintainer assets. Feature code belongs in module crates.

| File or folder | Role |
| --- | --- |
| [coordinator.rs](coordinator.rs) | Research agent scheduling, command semantics, checkpoints and human plan approval. |
| [definitions.rs](definitions.rs) | Plugin-defined agent tool schemas and guidance. |
| [ledger.rs](ledger.rs) | Persistent source admission, report versions and fact-check bindings. |
| [lib.rs](lib.rs) | Public Rust API and supporting module exports. |
| [main.rs](main.rs) | Native framed IPC executable entry point. |

[Parent waypoint](../AGENTS.md).
