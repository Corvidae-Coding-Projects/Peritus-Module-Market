# Red Team private SDK source — navigation

The ordinary framing/manifest files preserve compatibility with native Peritus modules.
`module_host.rs` additionally defines the Red Team module's private adapter and evidence schemas;
Peritus treats their serialized JSON as opaque worker input/output.

| File | Role |
| --- | --- |
| [lib.rs](lib.rs) | Private exports used by the Red Team binary. |
| [module_host.rs](module_host.rs) | Generic host envelopes and named runtime resources plus Red Team-owned worker, adapter, campaign, finding, replay, and report contracts. |
| [module.rs](module.rs) | Generic module actions and menu records. |
| [protocol.rs](protocol.rs) | Native process request/response protocol. |
| [framing.rs](framing.rs) | Bounded native frame encoding. |
| [manifest.rs](manifest.rs) | Native module manifest contract. |
| [canonical.rs](canonical.rs) | Canonical JSON encoding. |
| [identity.rs](identity.rs) | Plugin and request identities. |
| [payload.rs](payload.rs) | Bounded JSON payload. |
| [error.rs](error.rs) | Contract validation errors. |
| [manifest](manifest/AGENTS.md) | Explicit manifest wire encoding. |
| [protocol](protocol/AGENTS.md) | Explicit request/response wire encoding. |

[Parent waypoint](../AGENTS.md).
