# Red Team real-interface corpus

Small MIT-licensed executable applications used through the real contained proof interface.

| Folder or file | Role |
| --- | --- |
| [known-disclosure](known-disclosure/AGENTS.md) | Described vulnerable/safe disclosure pair. |
| [unknown-diagnostic](unknown-diagnostic/AGENTS.md) | Source-led unknown-discovery pair with a non-obvious trigger. |
| [adversarial](adversarial/AGENTS.md) | Forged-success, prompt-injection, boundary, lifecycle, and resource-exhaustion controls. |
| [profile-mixed](profile-mixed/README.md) | Phase 9 mixed command-line/browser source fixture for target-graph and selective-invalidation replay. |
| [laboratory-mixed](laboratory-mixed/README.md) | Copied Python application/backing-service fixture for disposable laboratory lifecycle and containment replay. |
| [static-analysis](static-analysis/README.md) | Phase 12 vulnerable/safe language and configuration twins plus dead-code, test-only, unreachable-advisory, and forged-scanner controls. |
| [http-api](http-api/AGENTS.md) | Phase 13 HTTP/API and Phase 14 browser/client vulnerable/safe twins for host-captured traffic, browser effects and copied-state oracles. |
| [identity-access](identity-access/AGENTS.md) | Phase 15 multi-user vulnerable/safe twins for host-private credentials, lifecycle, ownership, role, and tenant differential oracles. |
| [file-parser](file-parser/AGENTS.md) | Phase 16 vulnerable/safe twins for file, link, temporary-name, permission, TAR, structured-parser, and child-native-fault oracles. |
| [workflow-state](workflow-state/AGENTS.md) | Phase 17 vulnerable/safe twins for approval, accounting, retry, cancellation, crash-recovery, quota, and deterministic concurrency oracles. |
| [boundary-authority](boundary-authority/AGENTS.md) | Phase 18 vulnerable/safe twins for host-private network peers, TLS policy, contained privilege, and delegated-authority oracles. |
| [LICENSE](LICENSE) | MIT license covering the corpus programs. |
| [README.md](README.md) | Corpus purpose and authority boundary. |

These fixtures establish only the exact exercised adapter behavior.
