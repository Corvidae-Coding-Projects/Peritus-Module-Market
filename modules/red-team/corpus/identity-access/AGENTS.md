# Phase 15 identity corpus

The vulnerable and safe twins expose the same private HTTP identity/session/access-control surface.
They are copied into module-owned target runtimes inside disposable workers and never run in place.

| Folder | Role |
| --- | --- |
| [vulnerable](vulnerable/AGENTS.md) | Deliberately broken authentication, session invalidation, ownership, role, and tenant enforcement. |
| [safe](safe/AGENTS.md) | Interface-compatible control enforcing the same declared security properties. |

[Parent map](../AGENTS.md).
