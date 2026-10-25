# Native plugin SDK source — navigation

Data contracts and framing only. The module crate implements feature behavior; Peritus owns host-service authority.

| File | Responsibility |
| --- | --- |
| [lib.rs](lib.rs) | Public SDK exports. |
| [canonical.rs](canonical.rs) | Stable canonical JSON encoding for identity and payload contracts. |
| [error.rs](error.rs) | Typed SDK validation and protocol errors. |
| [framing.rs](framing.rs) | Four-byte big-endian, length-bounded request/result frames. |
| [identity.rs](identity.rs) | Plugin/request identifiers, numeric versions and manifest digests. |
| [manifest.rs](manifest.rs) | Strict native/process manifest, capabilities, quotas and canonical identity. |
| [module.rs](module.rs) | Generic native module actions, provider/function requests, menus and attachments. |
| [module_host.rs](module_host.rs) | Versioned host-service discovery, request/result envelopes, scoped-source, owned-job/source-build identity, typed managed-adapter lifecycle, normalized static-analysis contracts, and host-captured HTTP/API, browser, identity/access, file/parser fuzz, workflow/state, and boundary-authority observations. |
| [payload.rs](payload.rs) | Bounded canonical JSON payload validation. |
| [protocol.rs](protocol.rs) | Versioned initialization, invocation, cancellation, health and shutdown contracts. |
| [manifest/](manifest/AGENTS.md) | Explicit manifest wire encoding. |
| [protocol/](protocol/AGENTS.md) | Explicit request/result tagged wire encoding. |

[Parent waypoint](../AGENTS.md). [Market contract](../../../CATALOG.md).
