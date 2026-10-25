# modules/red-team/src — navigation

| File | Role |
| --- | --- |
| [main.rs](main.rs) | Version-one framed native executable entry point and lifecycle. |
| [lib.rs](lib.rs) | Hardened commands, scoped-source and owned-job host requests, receipt admission, checkpoints, complete human-interface actions, findings, diffs, and menus. |
| [adapter.rs](adapter.rs) | Phase 10 typed adapter catalog, staged install/cancel/complete/status/reuse/remove/execute coordinator and human-readable lifecycle projection. |
| [attack_graph.rs](attack_graph.rs) | Phase 19 cross-adapter graph commands, receipt admission, causal-path validation, counterfactual/rejection checks, repair replay review, coverage, and history. |
| [browser_client.rs](browser_client.rs) | Phase 14 browser/client adapter commands, receipt admission, browser/server oracle correlation, coverage mapping, artifacts, history, and rejection probes. |
| [coverage.rs](coverage.rs) | Phase 9 target-profile compiler, versioned property mappings, method registry, exact coverage cells, receipt-only transitions, and selective invalidation. |
| [http_api.rs](http_api.rs) | Phase 13 HTTP/API adapter commands, runtime-receipt admission, pinned-oracle validation, replay identity, coverage mapping, and result/history projection. |
| [identity_access.rs](identity_access.rs) | Phase 15 host-private identity/session/access-control commands, receipt admission, redaction validation, lifecycle graph, differential oracles, coverage, and history. |
| [file_fuzz.rs](file_fuzz.rs) | Phase 16 file/archive/parser/native-fault commands, exact-input validation, finding admission, coverage/resource receipts, history, and rejection probes. |
| [workflow_state.rs](workflow_state.rs) | Phase 17 stateful workflow/concurrency commands, invariant-provenance validation, exact action and schedule receipts, finding admission, history, and rejection probes. |
| [boundary_authority.rs](boundary_authority.rs) | Phase 18 private-network, TLS, platform-policy, contained-privilege, and delegated-authority commands, receipt validation, coverage, history, and rejection probes. |
| [investigation.rs](investigation.rs) | Bounded inventory, separate discovery/skeptic roles, hypothesis and probe scheduling, steering, reuse and evidence-gated adjudication. |
| [journey.rs](journey.rs) | Phase 20 complete-campaign planner and durable one-operation scheduler with shared TUI/WebUI controls, pause, steering, retry, skip, abort cleanup, restart recovery, and step-level evidence admission. |
| [laboratory.rs](laboratory.rs) | Phase 11 copied-application laboratory commands, typed lifecycle requests, opaque-handle projection, host-receipt admission, and TUI/WebUI status. |
| [repair.rs](repair.rs) | Automatic root-cause patch planning, copy-only replay matrices, independent patch review, and final original-byte verification. |
| [records.rs](records.rs) | Version-one campaign, scope, source, coverage, hypothesis, evidence, finding, patch, review, and report contracts. |
| [report.rs](report.rs) | Honest Markdown/JSON/SARIF reports, exact patch files, complete-journey state, and replay bundles exposed through the final export projection. |
| [source_analysis.rs](source_analysis.rs) | Phase 12 registered static-analyzer commands, typed receipt admission, source-lead validation, coverage mapping, and human-readable result/history projections. |
| [state.rs](state.rs) | Atomic schema-eighteen/Phase 20 campaign checkpoint, earlier-phase migration, complete-journey progress, investigation/repair state, class-specific and attack-graph evidence, laboratory lifecycles, corruption fail-closed behavior, and selective invalidation. |

[Parent waypoint](../AGENTS.md).
