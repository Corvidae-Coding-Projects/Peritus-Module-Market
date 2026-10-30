# modules/red-team/resources — navigation

| File | Role |
| --- | --- |
| [browser_campaign.py](browser_campaign.py) | Module-owned Playwright campaign routed exclusively to module-owned private Unix target sockets. |
| [attack_graph_browser.py](attack_graph_browser.py) | Module-owned stored-content browser replay used by the receipt-backed attack graph. |
| [diamond_browser_campaign.py](diamond_browser_campaign.py) | Module-owned Playwright campaign for the real Diamond HTTP runtime, with origin-preserving private transport, CSP-aware form replay, cookie checks, and off-scope blocking. |
| [generic_web_browser.py](generic_web_browser.py) | Loopback-only Playwright campaign for generic query-script execution and the Comms signup/CSP/injection profile, with off-scope request blocking. |
| [skeleton-state-v1.json](skeleton-state-v1.json) | Legacy Phase 1 checkpoint used to exercise forward migration. |
| [phase2-state-v2.json](phase2-state-v2.json) | Canonical empty Phase 2 campaign checkpoint fixture. |
| [phase3-state-v3.json](phase3-state-v3.json) | Canonical empty Phase 3 campaign-and-jobs checkpoint fixture. |
| [phase5-state-v5.json](phase5-state-v5.json) | Canonical empty Phase 5 investigation checkpoint fixture. |
| [phase6-state-v6.json](phase6-state-v6.json) | Canonical empty Phase 6 investigation and copy-only repair checkpoint fixture. |
| [phase9-state-v7.json](phase9-state-v7.json) | Phase 9 target-profile checkpoint retained for additive migration replay. |
| [phase10-state-v8.json](phase10-state-v8.json) | Canonical empty Phase 10 target-coverage and managed-adapter lifecycle checkpoint fixture. |
| [phase11-state-v9.json](phase11-state-v9.json) | Canonical empty Phase 11 disposable-application laboratory checkpoint fixture. |
| [phase12-state-v10.json](phase12-state-v10.json) | Canonical empty Phase 12 static-analysis and source-lead checkpoint fixture. |
| [phase13-state-v11.json](phase13-state-v11.json) | Canonical empty Phase 13 HTTP/API campaign checkpoint fixture. |
| [phase14-state-v12.json](phase14-state-v12.json) | Canonical empty Phase 14 browser/client campaign checkpoint fixture. |
| [phase15-state-v13.json](phase15-state-v13.json) | Canonical empty Phase 15 identity/session/access-control checkpoint fixture. |
| [phase16-state-v14.json](phase16-state-v14.json) | Canonical empty Phase 16 file/archive/parser/native-fuzz checkpoint fixture. |
| [phase17-state-v15.json](phase17-state-v15.json) | Canonical empty Phase 17 state, concurrency, and business-workflow checkpoint fixture. |
| [phase18-state-v16.json](phase18-state-v16.json) | Canonical empty Phase 18 private-network, TLS, policy, privilege, and delegated-authority checkpoint fixture. |
| [phase19-state-v17.json](phase19-state-v17.json) | Canonical empty Phase 19 cross-adapter attack-graph, counterfactual, skeptic, and repair-replay checkpoint fixture. |
| [phase20-state-v18.json](phase20-state-v18.json) | Canonical empty Phase 20 complete-campaign, shared-controls, restart-recovery, cleanup, and SARIF checkpoint fixture. |
| [phase22-state-v19.json](phase22-state-v19.json) | Canonical empty schema-19/Phase 22 autonomous-research contract checkpoint with integrity-bound empty v2 collections. |
| [research_poc.py](research_poc.py) | Stage 5 standalone private-destination stored-content canary PoC with exact target, identity, cleanup, and safe-twin checks. |
| [repair_regression.py](repair_regression.py) | Stage 6 real-browser legitimate, malformed, adjacent, and bounded mutation matrix over one private patched twin, with literal destination and synthetic-identity refusal controls. |
| [emulation-recipes/](emulation-recipes/AGENTS.md) | Inert licensed public-knowledge recipes with exact provenance, evidence class, harmless laboratory substitutions, adapter mappings, and explicit unsupported gaps. |

[Parent waypoint](../AGENTS.md).
