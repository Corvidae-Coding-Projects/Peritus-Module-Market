# Red Team private SDK — navigation

Private Rust crate used by the Red Team executable. It mirrors generic Peritus framing so the
plugin can speak the stable wire protocol, then adds Red Team-owned adapter, campaign, receipt, and
evidence contracts. Those additions are deliberately absent from the shared market SDK and Peritus.

| File or folder | Role |
| --- | --- |
| [Cargo.toml](Cargo.toml) | Private contract crate manifest. |
| [src](src/AGENTS.md) | Wire, manifest, generic envelope, and Red Team-owned contract definitions. |

[Parent waypoint](../AGENTS.md).
