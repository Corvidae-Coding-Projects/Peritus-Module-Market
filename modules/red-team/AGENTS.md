# modules/red-team — navigation

Self-contained native Rust Red Team plugin. Peritus supplies only generic module discovery,
permissions, scoped-source capture, disposable source copies, bounded worker execution, persistence,
and UI transport. This module owns every security class, adapter registry, target binding, runtime
driver, oracle, canary, evidence schema, skeptic, repair replay, report, corpus, and browser campaign.
Browser campaigns request only the generic managed browser runtime resource, while Bun campaigns
request a generic credential-free Bun executable/cache projection. Their entry points, scripts,
routes, actions, oracles, evidence, and interpretation remain entirely module-owned.

The plugin accepts only the application source explicitly opened in Peritus. Runtime work occurs in
host-contained disposable copies, while the module decides what security behavior to exercise and
how observed bytes and state map to findings. Applying returned patches to the original project is a
separate user action.

| File or folder | Role |
| --- | --- |
| [Cargo.toml](Cargo.toml) | Rust package and source-only dependencies, including the module-private contract SDK. |
| [module.toml.in](module.toml.in) | Source-build template rendered by Peritus's generic package builder. |
| [README.md](README.md) | Installation, operation, evidence interpretation, exports, troubleshooting, and safety guide. |
| [REAL_TESTING.md](REAL_TESTING.md) | Reproducible real-interface evidence for generic and application-specific runtime campaigns. |
| [corpus](corpus/AGENTS.md) | Licensed vulnerable/safe executable pairs and adversarial interface controls. |
| [resources](resources/AGENTS.md) | Browser drivers and versioned durable-state migration fixtures. |
| [sdk](sdk/AGENTS.md) | Private Rust wire/evidence contracts owned and versioned by this module. |
| [skills](skills/AGENTS.md) | Canonical Red Team agent guidance. |
| [src](src/AGENTS.md) | Coordinator, adapter implementations, disposable target runtime, evidence admission, repair, and reports. |

[Parent waypoint](../AGENTS.md).
