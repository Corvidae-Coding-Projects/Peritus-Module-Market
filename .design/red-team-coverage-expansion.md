# Feature: Expert-grade Red Team coverage expansion

Status: staged implementation plan for work after the completed Red Team 0.2.0 foundation.

Date: 2026-10-24.

Canonical foundation designs: [red-team.md](red-team.md) and
[red-team-phases.md](red-team-phases.md).

Intended source repositories:

- https://github.com/Corvidae-Coding-Projects/Peritus-Module-Market for the Rust module, canonical
  skill, adapter descriptions, schemas and small licensed fixtures; and
- https://github.com/Corvidae-Coding-Projects/Project-Peritus for host-owned capabilities,
  isolation, managed runtimes and TUI/WebUI projection.

## Summary

Expand Red Team from a containment-first security investigation framework with one trusted Linux
canary-disclosure adapter into an expert-grade autonomous application-security platform. Preserve
the existing explicit scope, disposable-copy, host-authored evidence, skeptical review, recovery,
copy-only repair and artifact-delivery contracts. Add a coverage compiler, a versioned Rust adapter
contract, an automatically managed disposable application laboratory, and class-specific static and
dynamic adapters that exercise the real application interfaces relevant to each security claim.

The intended end state is not an agent that says it considered every security category. It is a
system in which every applicable coverage claim identifies an actual surface, attacker/configuration,
security property, testing method, adapter, oracle, execution receipt and remaining uncertainty.
Models plan, prioritize, form novel hypotheses, chain effects and interpret evidence. Host-owned
adapters perform deterministic analysis and real-interface execution. Neither may independently
manufacture an `examined` or `confirmed` result.

This plan deliberately defers comparative benchmarking, statistical detection claims and an
"experienced pentester replacement" marketing claim. Each phase still requires direct behavioral
evidence that its new adapter works and distinguishes vulnerable from corresponding safe behavior.
A later qualification program will measure per-class recall, false positives, attack-surface
discovery, human-expert parity, time and cost across hidden and public corpora.

## User-visible behavior

The completed journey should be:

1. The user opens one authorized application in Peritus and selects Red Team.
2. Red Team identifies supported application profiles, components, entry points, identities,
   stores, protocols and trust boundaries from the exact scoped source and user-supplied facts.
3. Peritus shows the proposed laboratory: application services, disposable data stores, test
   identities, private endpoints, managed tools, required preparation and unavailable prerequisites.
4. A coverage compiler maps each surface and attacker/configuration to concrete source and runtime
   methods. It shows why a check is applicable, not applicable, blocked or pending.
5. After Start, Peritus automatically prepares pinned tools and dependencies, launches the copied
   application inside a private laboratory, and advances through applicable adapters. The user does
   not manually install scanners, browsers, containers or language tooling.
6. The user sees concrete work: routes or functions discovered, adapter and case running, identities
   involved, observed effects, code/runtime coverage, retained evidence and unresolved gaps.
7. Discovery agents generate additional hypotheses from architecture and behavior. The Rust
   coordinator admits only hypotheses with a supported evidence path or labels them analysis-only.
8. A separate skeptic evaluates reachability, target identity, oracle, legitimate controls,
   counterevidence and claimed impact before a finding is confirmed.
9. Confirmed findings advance through disposable root-cause repair and the adapter-specific attack,
   legitimate, malformed and adjacent-case replay matrix.
10. The user receives Markdown, JSON, SARIF-compatible findings, exact patches, reproduction bundles,
    laboratory descriptions and an explicit coverage/gap ledger. Applying any patch to the original
    remains separate.

Pause, Resume, Steer, Report, Revoke and source refresh retain their current meanings. Steering can
change priorities or supply application facts; it cannot expand source, effects, identities or
external targets.

## Requirements

| ID | Requirement |
| --- | --- |
| C1 | Define versioned target profiles for the application shapes Red Team can prepare and exercise. A profile states its supported operating systems, languages, services, stores, interfaces and unavailable claims. |
| C2 | Compile coverage as surface × attacker/configuration × security property × method. A model statement alone cannot change a cell to `examined`, `not_applicable` or `confirmed`. |
| C3 | Map applicable work to versioned ASVS, WSTG and CWE identifiers where they fit, without treating checklist membership as evidence or excluding uncatalogued business-logic defects. |
| C4 | Add a versioned Rust adapter contract that declares discovery, preparation, effects, identities, secrets, network policy, resources, oracle, controls, evidence, reset and cleanup. |
| C5 | Keep adapters host-owned and allowlisted. Module requests select typed operations and bounded inputs, never arbitrary host commands, environments, evaluators or network policies. |
| C6 | Automatically provision exact supported adapter dependencies into a private managed cache with version, digest, license and provenance records. End users do not perform container or scanner setup. |
| C7 | Prepare a disposable application laboratory with copied source, private services, controlled DNS/networking, opaque test identities, snapshots, telemetry, reset and cleanup. It never attaches to production or unrelated local services. |
| C8 | Add deterministic source, configuration, secret, dependency and infrastructure analysis whose raw results remain leads until reachability, applicability and impact are adjudicated. |
| C9 | Add HTTP/API discovery and active testing over actual locally launched services, including OpenAPI, GraphQL, WebSocket and relevant protocol schemas when present. |
| C10 | Add real-browser client testing for navigation, DOM/storage behavior, cookies, origins, CSRF, CSP, client/server validation and observable script effects. |
| C11 | Add opaque multi-identity session, authentication, recovery, authorization and tenancy testing with differential state and output observations. Models never receive credential values. |
| C12 | Add filesystem, path, archive, upload, parser, native instrumentation and coverage-guided fuzzing adapters with minimized durable reproducers. |
| C13 | Add ordering, retry, replay, concurrency, crash-recovery, quota, accounting and business-workflow state exploration with explicit invariants and resettable fixtures. |
| C14 | Add controlled private-network, protocol, redirect, DNS, TLS and out-of-band callback adapters without granting proof jobs general internet egress. |
| C15 | Add privilege, sandbox, container, infrastructure-as-code, local cloud-policy and agent/tool-authority adapters only where their effects can be contained and independently observed. |
| C16 | Build a durable attack graph whose nodes record prerequisites and effects so Red Team can test multi-step exploit chains without exaggerating disconnected findings. |
| C17 | Normalize adapter observations into content-addressed host receipts. Preserve raw tool output separately; scanner severity or model prose cannot become a trusted verdict. |
| C18 | Extend copy-only repair so each finding replays through the same adapter and oracle that established it, plus declared legitimate, malformed and adjacent cases. |
| C19 | Preserve cancellation, pause/resume, source revocation, owner-loss recovery, bounded resources, original-workspace verification and useful partial reporting across every adapter. |
| C20 | Show exact adapter activity, coverage, evidence, laboratory state, diffs and gaps through both TUI and WebUI without exposing secrets or requiring hidden terminal work. |
| C21 | Export stable Markdown, JSON, replay bundles, patches and SARIF-compatible findings, with exact versions and mappings rather than an unsupported certification or clean-codebase claim. |
| C22 | Do not claim statistical coverage, superiority to a named security product, or human-expert replacement until the separately authorized benchmark program is complete. |

## Acceptance criteria

These criteria validate functionality and containment. They are not the deferred benchmark program.

| ID | Requirements | Observable completion evidence |
| --- | --- | --- |
| E1 | C1–C3 | A real mixed application produces a durable surface/threat-boundary model and requirement-level coverage plan. Every cell names its method and adapter or an exact gap. Removing a surface or changing an identity/configuration selectively invalidates affected cells. |
| E2 | C4–C6 | A clean machine builds/installs the source module, prepares a pinned adapter dependency automatically, records its provenance, reuses it by identity, and rejects a wrong digest, unsupported platform or unapproved executable without running it. |
| E3 | C5, C7, C19 | A target build script and application attempt host-file, credential, private-service, network and descendant-process escape. The effects remain absent, cleanup is complete, and revocation fences queued/running work. |
| E4 | C7 | Peritus launches a copied multi-service application with disposable data, private addresses and retained service identities, proves readiness through real interfaces, resets it to a known snapshot, and leaves the original and unrelated host services unchanged. |
| E5 | C8, C17 | Static/configuration/dependency adapters distinguish at least one vulnerable and safe pair per supported analyzer class, retain raw output and exact source identities, and keep an unreachable or inapplicable warning out of `confirmed`. |
| E6 | C9, C17 | The HTTP/API adapter discovers and exercises real routes and schema-derived operations, retains exact requests/responses and server effects, confirms a deliberately vulnerable case and does not confirm the safe twin or an unreachable route. |
| E7 | C10, C17 | The managed browser executes a vulnerable and safe client workflow. Host observations distinguish script execution, forged page text, navigation, storage and server-side effects; closing or reconnecting the client does not lose evidence. |
| E8 | C11, C17 | Anonymous, ordinary, privileged and cross-tenant opaque identities exercise the same operations. A real authorization/session violation is distinguished from expected denial, expired/revoked state and invalid setup without revealing credentials to a model or report. |
| E9 | C12, C17 | File/archive/native/fuzz adapters run actual targets with instrumentation, retain exact minimized inputs and coverage/resource observations, distinguish target defects from harness crashes, and replay a retained failure in a fresh laboratory. |
| E10 | C13 | A stateful target is exercised across reordered, repeated, concurrent and crash/restart actions. The receipt retains schedule/action order and independently evaluates documented invariants rather than merely detecting a nonzero exit. |
| E11 | C14 | Private DNS, redirect, TLS and callback services establish both vulnerable and safe observations. An attempted external or unrelated-host connection remains blocked and cannot be relabeled as a successful probe. |
| E12 | C15 | Each enabled privilege/IaC/agent-authority adapter demonstrates one genuine contained policy violation and its safe twin. Unsupported platforms and effects remain visible gaps without ambient fallback. |
| E13 | C16–C17 | A multi-step vulnerable fixture confirms a chain only when every prerequisite/effect edge has a trusted receipt. Removing one prerequisite breaks the chain; unrelated findings are not merged merely because the model proposes a narrative. |
| E14 | C18 | A generated copy-only fix stops the original adapter-specific violation and preserves the legitimate workflow. Feature disabling, oracle weakening, detector suppression, target substitution or an unrelated edit fails independent review. |
| E15 | C19–C20 | A long mixed-adapter campaign survives TUI/WebUI disconnect, daemon restart and provider-context renewal; Pause, Resume, Steer, Revoke and Report operate through both clients with exact current progress and no repeated completed effect. |
| E16 | C20–C22 | Final exports contain exact scope, profiles, versions, methods, receipts, findings, patches and gaps in Markdown/JSON/replay/SARIF-compatible form. The product describes the result as bounded functional coverage and does not publish a benchmark or expert-replacement claim. |

## Current architecture

The completed 0.2.0 foundation already supplies important ownership boundaries:

| Owner | Current behavior and consequence |
| --- | --- |
| `modules/red-team/src/investigation.rs` | Performs one retained inventory, routes all 15 families, persists hypotheses and skeptical classifications, and schedules only hypotheses representable by the current adapter. It must evolve from family routing into method-backed coverage compilation. |
| `modules/red-team/src/repair.rs` | Produces exact-preimage copy-only fixes and four-category replay for the current canary adapter. It should retain this lifecycle while accepting adapter-specific replay matrices and receipts. |
| `modules/red-team/src/state.rs`, `records.rs`, `report.rs` | Own durable campaign state, evidence/finding identities and honest reporting. New profile, surface, coverage-cell, adapter, laboratory, execution and attack-graph records require additive migration. |
| `sdk/peritus-plugin-sdk/src/module_host.rs` | Defines `ModuleJobRequest`, bounded limits, lifecycle, logs and host-authored receipts. The request already carries an operation and structured specification, but version one has no typed adapter metadata, laboratory identity, identity handles, private-network policy or method-specific evidence. |
| Project Peritus `.../native/owned_jobs.rs` | Allows only `linux.canary-disclosure.v1`, `linux.patched-canary-replay.v1` and constrained dependency preparation. It is the current enforcement owner and must not become a generic shell escape. |
| Project Peritus `.../native/scoped_source.rs` | Supplies immutable scoped source, bounded observations, revocation, reuse and original-byte verification. New work consumes this service rather than creating another source reader. |
| Project Peritus `peritus-tools-computer` | Already provides managed Playwright/Chromium installation and persistent real-browser control for coding runs. Security-browser adapters should reuse its managed-runtime and observation patterns through a new module-host boundary, not lend unrestricted developer tools to module roles. |
| Project Peritus sandbox/process crates | Already own process, filesystem, network, environment, terminal, resource and descendant constraints. The laboratory and adapters should compile typed policies through these owners rather than implementing isolation inside the module. |
| Module market source-build | Resolves a clean pinned source revision, prepares dependencies and installs the resulting module disabled. Adapter dependencies need a parallel host-owned managed-runtime lifecycle, not binaries committed to the module repository. |

The existing native package still executes with the user's OS authority. Expanding target adapters
must not be confused with sandboxing the plugin executable itself. Module package trust and target
execution isolation remain separate boundaries.

## Proposed design

### Target profiles and coverage compiler

A target profile is a versioned host/module agreement, not an agent label. It contains detected and
user-confirmed application characteristics, supported preparation recipes and the adapter set capable
of producing evidence for that profile. Initial profiles should cover locally launchable Linux CLI,
native, web, API, browser and multi-service applications. Profile composition permits one repository
to contain several application shapes.

The durable coverage key is:

```text
source snapshot
  + target profile and configuration
  + surface/entry point
  + attacker or role
  + security property
  + method and adapter version
```

Coverage states remain `unexamined`, `examined`, `not_applicable` and `blocked`, but transitions are
validated. `examined` requires at least one admitted method result. `not_applicable` requires retained
counterevidence about the surface/profile. `blocked` identifies the exact missing prerequisite.
Neither state is a security verdict.

### Versioned adapter and laboratory contracts

The preferred design adds an additive module-host capability version rather than weakening
`module.owned-jobs@1`. Version one remains available for existing packages. The new contract adds:

- adapter descriptors and digests;
- preparation/runtime identities and provenance;
- laboratory creation, readiness, reset, snapshot and teardown;
- opaque service, endpoint, browser, store and identity handles;
- adapter-specific typed case specifications;
- controlled private-network and callback policies;
- structured method observations plus complete raw artifacts;
- execution/coverage/resource measurements;
- oracle and legitimate-control identities; and
- adapter-specific copy-only replay requests.

The module selects only advertised adapters and supplies validated structured cases. The host resolves
handles, secrets, commands, binaries, policies and oracles. Existing job submit, poll, log and cancel
semantics remain the lifecycle model.

### Managed adapter dependencies

Managed preparation resolves a pinned adapter manifest, verifies digest/provenance/license, downloads
only during a constrained preparation step, and installs outside Git under Peritus-owned state. It
publishes a content-addressed runtime identity. Execution receives only the prepared identity and the
minimum target/laboratory handles. Preparation failure cannot fall back to a host PATH executable or
unversioned network download.

The Rust plugin remains self-contained source. It may coordinate established open security engines
through host adapters. Reimplementing mature parsers, browser scanners, advisory databases and
coverage-guided fuzzers solely to keep every transitive tool written in Rust is not required.

### Disposable application laboratory

One laboratory belongs to one scope revision and configuration. It owns copied source, target build
artifacts, services, stores, identities, private endpoints, callback collectors, browser contexts,
telemetry and reset points. All names exposed to the module are opaque handles. The host records the
resolved target identities privately in receipts.

Proof-time networking defaults to deny-all. A method may receive an adapter-specific private network
containing only declared laboratory services. Internet, host-loopback, LAN and unrelated Peritus
services remain unreachable. Dependency preparation remains separate.

### Findings, attack graph and repair

Raw analyzer results, runtime observations and model hypotheses are leads. A finding requires a
security property, reachability, prerequisites, exact target, adapter/method evidence, oracle,
counterevidence and skeptical adjudication. An attack graph links only receipt-backed prerequisites
and effects. A chain's impact cannot exceed its weakest unresolved edge.

Repair remains automatic in disposable copies. The adapter that established the finding supplies or
selects the replay method, while the host preserves the original oracle and builds the diff. Cross-
adapter fixes may depend on earlier patch identities, but every affected method must replay before the
patch can be described as validated for those cases.

## Staged implementation

Phase numbering continues from the completed foundation plan. Each phase should be split into small
issues with one observable behavior and durable handoff. Later phases consume exact retained records
instead of rediscovering settled architecture.

### Phase 9 — target profiles and coverage compiler

**Objective:** Replace prose-only family routing with durable surface/method coverage obligations.

**Build**

- Profile, component, surface, trust-boundary, identity/configuration and method records.
- Versioned mappings for ASVS/WSTG/CWE identifiers and uncatalogued custom properties.
- Validated coverage transitions and selective invalidation.
- TUI/WebUI views showing profiles, cells, required methods and exact gaps.
- Compatibility behavior that maps the current canary operation as one narrow adapter.

**Exit evidence:** Exercise a mixed CLI/web fixture and a copied brownfield repository through the
real module. Observe a stable surface graph, method-backed plan, explicit unsupported cells and
selective invalidation after a scoped change. No new runtime class is claimed in this phase.

**Handoff:** profile/schema versions, coverage identities, standards mappings and current-adapter map.

#### Phase 9 implementation record — 2026-10-24

Phase 9 is implemented by Red Team 0.3.0. The module now persists schema-seven/Phase 9 target
profiles, components, entry surfaces, directed trust boundaries, attacker identity/configurations,
security properties, method descriptors and exact coverage cells. The compiler validates
cross-record identities, captured-manifest paths, supported profile/surface kinds, ASVS 5.0.0,
WSTG 4.2, CWE 4.18 and `PERITUS` v1 identifier formats. Inventory prose can create only
`unexamined`, `not_applicable`, or `blocked` cells; only a coordinator-admitted method receipt can
advance a compatible exact cell to `examined`.

The current adapter map is deliberately narrow. `analysis.scoped-source-review.v1` records bounded
source analysis without claiming runtime behavior. `runtime.linux-canary-disclosure.v1` maps only to
Linux command/native disclosure properties identified by ASVS 5.0.0 V14.2.6 or CWE 4.18 CWE-200.
`gap.no-compatible-runtime.v1` keeps every other missing runtime class visibly blocked. No new
runtime vulnerability class is claimed.

The optimized framed native executable passed a mixed command/browser fixture replay with one
profile, two surfaces and 30 exact method cells. Changing only the command source invalidated its two
compatible cells while all 28 browser cells retained their prior state; restarting the native
process reopened the same graph. A fresh-process v6 fixture replay initially exposed that read-only
migration was not publishing v7. The migration path now writes the new checkpoint atomically, and
the same replay passes.

A separate disposable clone of Project Peritus `develop` exercised a real 7,376-file, 56,755,036-byte
brownfield manifest through 15 pages. The module compiled one multi-service profile, two concrete
CLI/WebUI surfaces, 30 method-backed cells and 15 explicit unsupported-runtime cells. The optimized
0.3.0 package then installed disabled, enabled explicitly, and appeared as selected/enabled in the
real Peritus TUI from an isolated user state. The WebUI gateway served its real asset shell against
that isolated state, but Chrome extension policy blocked opening the loopback tab; browser visual
interaction and the older installed gateway's missing module-query route were not counted as
additional behavioral evidence. Direct native replies for profiles, surfaces, methods and coverage
retained readable Markdown and the complete generic action set consumed by current clients. Unit
tests and formal verification were not run.

Architect verdict: **ready for Phase 10** at the Phase 9 coverage boundary. The target graph and
coverage plan are durable and selectively invalidated, but broad runtime classes remain explicit
gaps until typed host adapters are added.

### Phase 10 — adapter SDK and managed-runtime lifecycle

**Objective:** Establish the typed extension boundary without adding arbitrary execution.

**Build**

- Additive adapter/laboratory SDK contracts in both canonical SDK copies.
- Host registry for allowlisted descriptors, operations, schemas and receipt decoders.
- Automatic pinned dependency preparation, private installation, reuse and removal.
- Compatibility projection for older modules and hosts.
- Adapter status, installation and retained-error presentation in both clients.

**Exit evidence:** Install one harmless diagnostic adapter on a clean isolated Peritus state root,
reuse it by digest, reject tampered metadata/binary/platform inputs, cancel preparation, recover after
restart and prove that an unregistered operation cannot execute.

**Handoff:** capability/version matrix, descriptor schema, runtime identity, provenance receipt and
rollback instructions.

#### Phase 10 implementation record — 2026-10-24

Phase 10 is implemented by Red Team 0.4.0 and the additive Peritus
`module.adapter-runtime@1` host capability. The two SDK projections define the same version-one
catalog, descriptor, platform, operation, prepare/complete/cancel/status/remove/execute, lifecycle,
runtime-identity, provenance and execution-receipt shapes. Red Team persists schema-eight/Phase 10
adapter catalogs, preparations, statuses, receipts and retained errors; schema-seven/Phase 9 state
migrates additively. Existing modules may ignore the new capability. On an older host, Red Team
leaves managed adapters blocked and explicitly refuses ambient executable, `PATH`, shell-command or
developer-tool fallback.

The host registry currently contains only `peritus.diagnostic` 1.0.0. On the exercised Linux
x86-64 host its descriptor digest is
`1be5da5c6cb6b817507ddc2e41e9ffc4f0a68e707379aeb2cfd85822b2a39f06`; it pins an 84-byte MIT
artifact with digest `b49e6bb0e5f8713b621d0cad44bfca0c567dc0d42b2faf58e2134f521734621f`, the sole
`diagnostic.echo.v1` operation, input schema `peritus.diagnostic.echo.input@1`, receipt schema
`peritus.diagnostic.echo.receipt@1`, and decoder `peritus.diagnostic.echo.decoder@1`. The resulting
runtime digest is `c15b957845e9ad8c09c9ba4f02385c60b74f25f9f0269b5f88f505ee407f599d`.
Its provenance names `peritus-host-registry/diagnostic-artifact@1`, the exact descriptor/artifact
digests and byte count, and the MIT license. Neither descriptor nor module input can supply a path,
binary, process, environment, network target or receipt decoder.

The optimized 0.4.0 package installed disabled and was explicitly enabled in a clean isolated user
state. Through the real TUI and daemon, a never-installed adapter reported `NotInstalled`; staging
survived client exit and daemon restart; cancellation removed staged bytes; completion installed the
exact registered bytes; an independently distinct message returned a host-authored receipt; and a
second real staging/completion transaction reused the same runtime digest. Exact tampered metadata,
wrong-platform and unregistered-operation requests were rejected without execution. A staged
artifact changed on disk was detected during restart, retained as `Failed`, and rejected as
`adapter_artifact_mismatch`. Removal deleted runtime bytes while retaining identity and provenance,
and a later execution request did not reach the host adapter. The exercise exposed and corrected
three lifecycle defects before acceptance: absent state mislabeled as removed, reuse bypassing a
real staging transaction, and restart-detected artifact mismatch reported only as a generic phase
error.

The actual loopback WebUI gateway served its asset shell, reopened the retained run from daemon run
history, rendered the full lifecycle and receipt transcript, showed the nine current Red Team
actions including Managed adapters, Install diagnostic adapter, Adapter status and Adapter history,
and invoked Adapter status from Chrome to a new durable result. Direct gateway inspection matched
the installed 0.4.0 package digest and selected run. The Chrome automation extension initially
blocked opening loopback itself; the user-opened tab then supported the complete visual replay, so
that extension policy is not counted as a product failure. A separate isolated run with the older
installed Peritus host showed `module.adapter-runtime@1` missing and performed no fallback. Unit
tests and formal verification were not run.

Capability/version matrix: current host + current module enables v1; current host + older modules is
additive because the capability is merely advertised; older host + current module remains readable
but adapter work is blocked; unsupported platforms receive no matching descriptor. Operational
rollback is `adapter-remove` for exact private runtime bytes, followed by disabling or removing the
module package if desired. Host rollback stops advertising `module.adapter-runtime@1`; retained
module checkpoints, runtime identity, provenance, execution receipts and errors remain readable,
and no ambient execution path is activated.

Architect verdict: **ready for Phase 11** at the Phase 10 adapter-foundation boundary. The managed
diagnostic proves the registry and lifecycle, not a security class; real application execution and
isolation remain explicit Phase 11 work.

### Phase 11 — disposable application laboratory

**Objective:** Launch realistic copied applications and their dependencies inside host-owned private
environments that can be reset and observed.

**Build**

- Laboratory create, prepare, launch, readiness, snapshot, reset, stop and teardown operations.
- Private service network, DNS and opaque endpoint handles.
- Disposable store/service recipes selected from target profiles.
- Opaque identity/secret handles and target-visible injected values that models cannot read.
- Process, filesystem, network, request, coverage and resource telemetry.
- Automatic managed setup; no required user knowledge of containers or sandbox implementation.

**Exit evidence:** Launch, use, reset and tear down a copied multi-service application through the
real TUI and WebUI. Retain exact receipts across client/daemon restart. Host, LAN, credentials and the
original checkout remain inaccessible and unchanged under hostile target behavior.

**Handoff:** laboratory schema, service recipes, isolation backend matrix and cleanup/recovery record.

#### Phase 11 implementation record — 2026-10-24

Phase 11 is implemented by Red Team 0.5.0 and the additive Peritus
`module.application-laboratory@1` host capability. The two SDK projections define the same
version-one catalog, create, lifecycle, invoke, opaque-handle, status, telemetry and receipt shapes.
Red Team persists schema-nine/Phase 11 laboratory catalogs, lifecycle snapshots, receipts and
retained errors; schema-eight/Phase 10 state migrates additively. Older hosts leave laboratory work
explicitly unavailable. The module cannot provide an executable, resolved path, network target,
socket name, credential, secret value or sandbox policy.

The initial host registry contains only `linux.python-unix-store.v1`: one copied Python application
and one copied Python key/value service connected through a private abstract Unix socket. The host
materializes exact bytes from the immutable source authority, rehashes them before launch, creates a
random target-only secret, clears ambient environment, denies IP networking, constrains filesystem
access and descendants, bounds resources and input/output, and returns opaque application, backing,
endpoint, identity and secret handles. It independently observes readiness, store round trips,
snapshots, resets, source integrity and process-tree cleanup. A maximum of four laboratories may be
active. Source revocation, module replacement, run cancellation or provider cancellation stops the
owned process tree; restart never relaunches a previously ready target ambiently.

The optimized host and 0.5.0 module completed the real WebUI lifecycle in an isolated Peritus state:
catalog, create, prepare, launch, status, application write/readback with a distinct value, snapshot,
a second write/readback, reset, stop and teardown. The target's own hostile probes observed no
credential variables, could not read `/etc/passwd`, could not connect to a host loopback canary or
an external test address, and could not start an unregistered shell descendant. Host readback
independently matched the application value and reset state. Wrong opaque endpoints and
unregistered operations were rejected without changing retained state.

The same run survived a WebUI gateway/client restart with its ready laboratory and receipts intact.
After a daemon restart, the host killed the owned application/service process tree, removed its
cgroup and reconciled the formerly ready laboratory to `Quarantined` without relaunching it. A
hostile fixture that printed its injected secret was quarantined during readiness; the raw value did
not enter the module state, workbench record or client transcript. Protected host process evidence
may retain raw target output and is not represented as user-visible module evidence. A separate
source-revocation replay stopped the running target and still allowed teardown, which removed all
disposable bytes and explicitly recorded that original-source revalidation was unavailable. Each
teardown with live authority proved the original source bytes unchanged.

The real Markdown, JSON and replay-bundle exporters retained Phase 11 statuses, receipts, errors and
the bounded recipe limitation. The packaged TUI reopened the retained run after the client and
daemon exercises and rendered its laboratory history plus the advertised host capability. After
the private Chrome extension was loaded, it opened the actual loopback WebUI and the visible module
controls carried the copied two-service fixture through scope, create, prepare, launch, two exact
round trips (including Unicode), snapshot, reset, client reload, stop, daemon restart, history and
teardown. The restarted daemon returned all seven pre-teardown receipts; teardown recorded complete
cleanup and unchanged original source. Independent host checks found no copied service process,
laboratory cgroup or laboratory-identity path, and the disposable Git source remained clean with its
two fixture hashes unchanged. The exercise found and corrected two Linux isolation defects before
acceptance: descendant removal omitted file unlink rights, and legacy libc path syscalls were denied
even when Landlock granted the corresponding operation. It also replaced a filesystem Unix socket
that exceeded deep private-path limits with an abstract private socket. Unit tests and formal
verification were not run.

Isolation matrix: current Linux host with its configured native job backend advertises and executes
the single registered recipe; an unsupported platform or host without that backend does not
advertise the capability; older modules ignore the additive capability; older hosts leave the new
module commands blocked without fallback. Recovery retains host-authored history, quarantines
unowned active records, and permits cleanup even after source revocation. Operational rollback is to
stop and tear down exact opaque laboratory handles, then disable or remove the module package; host
rollback stops advertising the capability and does not create an ambient execution path.

Architect verdict: **ready for Phase 12** at the Phase 11 laboratory-foundation boundary. The
laboratory proves one realistic private multi-service recipe and its lifecycle; broader languages,
protocols, data stores and arbitrary dependency graphs remain explicit gaps for later registered
recipes and adapters.

### Phase 12 — static, dependency, secret and configuration adapters

**Objective:** Supply broad deterministic source leads before dynamic work, while preserving honest
reachability and evidence boundaries.

**Build**

- Language/manifest discovery and a pinned initial analyzer set for Rust, C/C++, JavaScript/TypeScript,
  Python, Go and Java where supported.
- Syntax/pattern and available data-flow analysis normalized from raw tool output.
- Resolved dependency/SBOM and advisory analysis with reachability status.
- Secret, configuration, container and infrastructure-definition analysis with redaction.
- Finding deduplication by root cause and mappings into coverage cells.

**Exit evidence:** Run vulnerable/safe twins and one mixed brownfield repository. Retain raw results,
exact rule/tool versions and source identities. Demonstrate that dead code, test-only configuration,
unreachable dependency advisories and fake scanner output do not become runtime-confirmed findings.

**Handoff:** supported language/tool matrix, normalized observation schema and unresolved analyzer gaps.

#### Phase 12 implementation record — 2026-10-24

Phase 12 is complete at its bounded initial-adapter scope. Peritus now advertises a registered
content-addressed `peritus.source-analysis` runtime whose only operation reads an immutable scoped
source snapshot under host-enforced file and byte bounds. The host pins the analyzer, rule and
advisory identities; discovers Rust, C/C++, JavaScript/TypeScript, Python, Go and Java; parses Cargo,
npm, Python requirements, Go module and Maven dependencies; records a normalized SBOM and bounded
reachability; examines secrets, configuration, Dockerfiles, Kubernetes/YAML and Terraform; and
retains both redacted pre-deduplication matches and root-cause-grouped leads. The module validates the
host identity and schema, retains results durably, maps the static method into coverage, and exports
the observations in Markdown, JSON and replay bundles. Every result is structurally limited to
`source_lead`.

The real terminal/daemon/plugin campaign operated 15-file vulnerable and safe twins, a seven-file
adversarial mixed repository, and a 167-file copied brownfield repository. The vulnerable twin
produced 27 raw matches grouped into 26 leads across all six languages and all five dependency
ecosystems; the safe twin produced none. The mixed case retained dead code and unused dependency
advisories as `unreachable`, test configuration and dependency evidence as `test_only`, and ignored a
forged scanner-shaped runtime confirmation. A secret-shaped literal was absent from state and all
delivery artifacts. Client/daemon restart retained the exact result digest, revoked source rejected
a rescan, adapter removal was durable, and every copied source tree remained byte-identical.

Exact binaries, run identities, counts, report digests and the retained replay driver are recorded in
the Peritus repository's `docs/testing/red-team-phase12-*` evidence. Unit tests and formal
verification were not run. The current adapter deliberately leaves cross-file semantic flow, macros,
generated code, dynamic imports, comprehensive advisory freshness, and runtime exploitability to
later phases.

### Phase 13 — HTTP and API adapter family

**Objective:** Discover and actively test actual locally launched service interfaces.

**Build**

- HTTP traffic capture, route and parameter inventory, schema import and response/state oracles.
- REST, OpenAPI, GraphQL, WebSocket and supported RPC discovery.
- Injection, parsing, method/content-type, error, redirect, header and request-sequence cases.
- Target-side effect observation through laboratory stores and telemetry.
- Request minimization and exact replay artifacts.

**Exit evidence:** Use real vulnerable/safe services, including dynamic and schema-described routes.
Confirm only independently observed violations, preserve ordinary operations, distinguish unreachable
and rejected inputs, and replay minimized requests after a fresh laboratory launch.

**Handoff:** supported protocol/schema matrix, route coverage, request receipt and known blind spots.

#### Phase 13 implementation record — 2026-10-24

Phase 13 is complete at its bounded initial HTTP/API-adapter scope. Peritus now advertises the
content-addressed `peritus.http-api` runtime and a copied Linux Python HTTP laboratory. The host
imports the running service's OpenAPI 3.1 document, inventories routes and query parameters, emits
and captures exact HTTP/1.1 and WebSocket traffic, observes copied target state before and after each
request, redacts target-only values, and classifies passed, rejected, unreachable, and independently
confirmed violation outcomes. The module admits only the registered adapter identity, schema,
decoder, laboratory handle, bounds, receipts, and pinned oracle results; its Markdown, JSON, and
bundle exports preserve exact request and traffic identities.

The final real TUI/daemon/plugin campaign operated vulnerable and safe service twins through REST,
OpenAPI, GraphQL, WebSocket, and JSON-RPC. Both executed the same 21 cases across 12 discovered
routes. The vulnerable twin retained nine runtime-confirmed violations; the safe twin retained none,
while both preserved nine ordinary successes and distinguished rejected input from an unreachable
route. A reset, stop, and fresh laboratory launch reproduced the exact ordered request and traffic
digests. Invalid endpoint and budget requests failed closed, target-only secret bytes never entered
state or delivery artifacts, source trees remained byte-identical, adapter removal completed, and
live cgroup inspection found no post-campaign residue.

Exact binary identities, run IDs, counts, result digests, limitations, and the replay driver are
recorded in the Peritus repository's `docs/testing/red-team-phase13-*` evidence. Unit tests and
formal verification were not run. HTTP/2, HTTP/3, TLS, multipart bodies, arbitrary schema-driven
generation, authentication/session state, browser trust, broad framework discovery, and non-Linux
laboratories remain later-phase work.

### Phase 14 — browser and client-trust adapter family

**Objective:** Test client-side security properties through a managed real browser.

**Build**

- Isolated browser contexts bound to laboratory endpoints and test identities.
- DOM/script, navigation, origin, cookie, storage, CSP, CSRF and client/server-validation observations.
- Traditional and client-rendered crawling with bounded action graphs.
- Download/upload and browser-to-server correlation.
- Browser reset, reconnect and retained screenshot/trace/traffic artifacts.

**Exit evidence:** Exercise stored/reflected/DOM behavior, CSRF and origin/cookie safe twins in a real
browser. A page printing `success` cannot replace host-observed script, request and state effects.
Pause, restart and resume preserve the exact browser case without leaking host browser state.

**Handoff:** browser operation/schema version, client coverage graph and replay artifacts.

#### Phase 14 implementation record — 2026-10-24

Phase 14 is complete at its bounded initial browser/client-trust scope. Red Team 0.8.0 now consumes
the registered `peritus.browser-client` host adapter against only an exact ready copied HTTP
laboratory. The host creates two temporary loopback bridges to the private Unix service, launches
fresh managed Chromium contexts, denies off-scope requests, correlates browser effects with copied
target state, and retains content-addressed screenshots, trace, traffic, download, and upload
artifacts. The module receives opaque identities and validated receipts, never arbitrary URLs,
resolved laboratory paths, target secrets, or an ambient browser profile.

The final real TUI/daemon/plugin campaign ran 14 cases against interface-compatible vulnerable and
safe twins. Both executed 28 browser actions; the vulnerable twin observed 30 allowed requests and
produced eight runtime-confirmed violations, while the safe twin observed 23 allowed requests,
rejected all seven attack-effect cases, and produced no findings. Traditional and client-rendered
crawling found `/linked` and `/rendered-link`; exact upload/download bytes, three screenshots,
Playwright traces, and traffic records were admitted under aggregate bounds. Wrong endpoint and
undersized budget requests failed closed.

The campaign also exposed and repaired two integration defects: fresh isolated profiles did not
automatically prepare their Chromium cache, and daemon shutdown could reconcile a cancelled
laboratory process before its detached owner published the durable stopped state. Automatic setup
now validates the current cache, and shutdown explicitly cancels background module effects and waits
for both process and owner-state settlement. After repair, client disconnect, clean daemon restart,
laboratory reset/relaunch, and exact case replay retained evidence without source changes or browser,
process, or cgroup residue. Exact evidence and the replay driver are recorded under the Peritus
repository's `docs/testing/red-team-phase14-*` paths. Unit tests and formal verification were not run.

The adapter deliberately covers one pinned Chromium suite. Other engines and application-specific
authenticated business workflows remain explicit Phase 15-or-later gaps. Architect verdict:
**ready for Phase 15** at the declared browser/client-trust boundary.

### Phase 15 — authentication, session, authorization and tenancy adapters

**Objective:** Give the system controlled identities and differential oracles needed for access-control
and lifecycle testing.

**Build**

- User-supplied or laboratory-generated opaque identity roles and tenant membership.
- Login, logout, recovery, MFA/test-factor, token rotation, expiry, revocation and concurrent-session
  state machines where the application supports them.
- Differential operation/state comparison across anonymous, ordinary, privileged and cross-tenant
  identities.
- Ownership/object-ID mutation and adjacent-route comparisons.
- Credential redaction and revocation through the entire evidence/export path.

**Exit evidence:** Run multi-user vulnerable/safe applications through the real clients. Confirm a
cross-role or cross-tenant violation using independent state/output evidence, reject invalid setup,
observe token/session lifecycle, and show that no provider-visible content contains credential bytes.

**Handoff:** identity-role schema, session state graph, differential oracle and redaction record.

#### Phase 15 implementation record — 2026-10-24

Phase 15 is complete at its bounded initial identity/access-control scope. Red Team 0.9.0 consumes
the registered `peritus.identity-access` host adapter against only an exact ready copied HTTP
laboratory. Durable schema 13 adds `runtime.identity-access.v1` coverage, opaque identity and
session records, lifecycle transitions, differential case results, host-authored redaction facts,
and additive migration from every earlier retained state. The module receives no passwords,
factors, recovery material, session tokens, resolved endpoints, or arbitrary policy definitions.

The final real TUI/daemon/plugin campaign ran the same 33 real HTTP operations and 20 cases against
vulnerable and safe multi-user twins. Each used five opaque identities across two tenants and
retained nine session transitions. The vulnerable twin produced twelve runtime-confirmed findings
covering missing authentication, vertical authorization, tenant isolation, object ownership,
adjacent routes, MFA, logout, rotation, expiry, revocation, concurrent-session revocation, and
recovery invalidation. The safe twin produced zero findings and thirteen expected denials while
preserving seven ordinary successful cases.

The independent driver reconstructed 37 possible credential representations from host-private
laboratory material and confirmed that none appeared in public run records, transcripts, module
state, attachments, or exports. Wrong-endpoint and undersized-budget requests failed closed. A
clean daemon restart, client disconnection after durable input admission, `/retry`, laboratory
reset/relaunch, and a fresh campaign reproduced the same case identities without changing either
source tree or leaving new cgroup state. Adapter removal and laboratory teardown completed.

Real execution exposed one request-boundary defect before acceptance: serialized JSON bodies lacked
`Content-Length`, so the copied service correctly observed an empty login body. The host adapter now
serializes the body once and binds that exact byte length into the request. Exact binary, package,
run, source, count, replay, redaction, and cleanup evidence is retained in the Peritus repository's
`docs/testing/red-team-phase15-*` records. Unit tests and formal verification were not run.

This evidence covers one pinned five-identity, two-tenant topology. Application-specific policy
discovery, federated SSO, OAuth/OIDC semantics, and hardware-backed authenticators remain gaps.
Architect verdict: **ready for Phase 16** at the declared identity/access-control boundary.

### Phase 16 — files, parsers, native instrumentation and fuzzing

**Objective:** Exercise untrusted bytes and filesystem boundaries at scale with strong runtime oracles.

**Build**

- Path, link, temporary-file, archive, extraction, upload and permission-boundary adapters.
- Managed sanitizer/instrumentation toolchains where supported.
- Coverage-guided and structure-aware fuzzing with seed/dictionary generation.
- Corpus minimization, crash deduplication, schedule/resource observation and fresh-process replay.
- Clear separation between target defects, harness failures and unavailable instrumentation.

**Exit evidence:** Demonstrate traversal/archive and parser/native vulnerable/safe pairs through actual
interfaces. Preserve minimized inputs, coverage deltas, sanitizer/controller receipts and resource
facts. Replay every retained defect after process and laboratory restart.

**Handoff:** instrumentation/platform matrix, corpus schema, minimized reproducers and unsupported ABI
or language paths.

#### Phase 16 implementation record — 2026-10-24

Phase 16 is complete at its declared initial Linux file/archive/parser/native-fault boundary. Red
Team 0.10.0 consumes the registered `peritus.file-parser` adapter only against an exact ready copied
HTTP laboratory. Durable schema 14 adds `runtime.file-parser-fuzz.v1` coverage, bounded exact input
bytes, case dispositions, minimized replay inputs, finding bindings, behavioral-edge and resource
facts, native signals, crash groups, explicit instrumentation gaps, and additive migration from all
earlier retained states. Resolved endpoints and private filesystem canaries remain host-owned.

The final real TUI/daemon/plugin campaign executed the same 27 operations and 26 cases against
vulnerable and safe twins. The vulnerable application demonstrated five filesystem-boundary
violations and fifteen parser/native crash cases, including a real child `SIGSEGV`; the safe twin
rejected all twenty hostile cases while preserving six legitimate controls and produced no finding.
Neither campaign produced a harness failure or an unavailable-instrumentation result.

Every case retained exact bounded base64, byte length, SHA-256, replay identity, response/state
identity and host-observed behavioral edges. Generated parser failures were minimized, equivalent
crashes were deduplicated into one crash group, and wall-time/operation/request/byte facts were
retained. Wrong-endpoint and undersized-budget requests failed closed. A daemon restart, fresh
laboratory launch/reset, and second complete vulnerable campaign reproduced the same campaign and
per-case replay identities. Both fixture trees remained byte-identical and adapter/laboratory
cleanup left no new cgroup leaves.

Real execution exposed and repaired one fixture readiness defect before acceptance: the new copied
controllers omitted the host-required target-secret digest, so launch correctly quarantined the
laboratory. The controllers now derive and report that digest without exposing secret bytes. Exact
binary, package, run, source, case and cleanup evidence is retained in the Peritus repository's
`docs/testing/red-team-phase16-*` records. Unit tests and formal verification were not run.

The retained edge set is host-observed behavioral coverage, not compiler source coverage. Managed
ASan/UBSan target builds, non-Linux native faults, in-process native libraries and arbitrary
application grammars remain explicit adapter gaps. Architect verdict: **ready for Phase 17** at the
declared file/archive/parser/native-fault boundary.

### Phase 17 — state, concurrency and business-workflow adapters

**Objective:** Find violations that exist only across action sequences, timing, retries or domain state.

**Build**

- Explicit user/documented invariants and model-proposed candidate invariants with separate status.
- Stateful action generators over real interfaces and identities.
- Reordering, duplication, replay, retry, cancellation, crash/restart and bounded schedule variation.
- Transaction/store observations and deterministic schedule retention where possible.
- Quota, accounting, approval and illegal-transition oracles.

**Exit evidence:** Exercise vulnerable/safe workflow and concurrency targets. Retain exact action order,
identity, timing/schedule, starting snapshot and final state. An unrelated timeout or crash cannot prove
the proposed domain violation.

**Handoff:** invariant/action schema, sequence/schedule receipts and non-determinism report.

#### Phase 17 implementation record — 2026-10-24

Phase 17 is complete at its declared initial Linux approval/accounting workflow boundary. Red Team
0.11.0 consumes the registered `peritus.workflow-state` adapter only against an exact ready copied
HTTP laboratory. Durable schema 15 adds `runtime.workflow-state.v1` coverage, provenance-labelled
documented and model-proposed invariants, ordered identities and actions, before/after copied-state
digests, response classes, timings, deterministic schedule receipts, exact semantic replay
identities, nondeterminism facts, documented-invariant finding bindings, and additive migration from
all earlier retained states. Proposed invariants cannot support findings until promoted by an
explicit user or application contract.

The final real TUI/daemon/plugin campaign executed 50 real actions per twin across nine retained
sequences: legitimate approval and charge, approval bypass, duplicate/replay, ambiguous committed
retry, cancellation followed by illegal transitions, three-request quota pressure, child-worker
crash/recovery, a deterministic two-worker read/read/write/write schedule, and a legal counterexample
to a model-proposed invariant. The vulnerable twin produced seven documented-invariant findings;
the interface-compatible safe twin passed all nine sequences and produced none. The proposed
approval-irreversibility candidate was refuted in both and never became a finding.

The concurrency schedule ran three times per campaign with identical final state and response class.
Wrong-endpoint and undersized-action requests failed closed and produced no domain finding. Every
sequence retained its starting snapshot, exact actor/action/request order, response status,
before/after state digests, final state, schedule identity, duration, and semantic replay digest. A
daemon shutdown/restart, client reattachment, laboratory relaunch/reset, and second vulnerable
campaign reproduced the same campaign and per-sequence semantic identities. Both fixture trees
remained byte-identical, Markdown/JSON/bundle exports included workflow evidence, and adapter plus
laboratory cleanup left no new cgroup leaves.

Real execution exposed and repaired one identity-design defect before acceptance: elapsed wall time
was included in semantic replay and campaign digests, so otherwise identical replays received
different identities. Timing remains retained as evidence, while stable identities now cover the
request, response class, copied-state transition, action order, and schedule only. Exact binary,
package, run, source, sequence, schedule, export and cleanup evidence is retained in the Peritus
repository's `docs/testing/red-team-phase17-*` records. Unit tests and formal verification were not
run.

The retained schedule is one deterministic two-worker interleaving, not exhaustive concurrency
coverage. Application-specific invariants, arbitrary schedules, distributed consensus, external
queues and databases outside copied state, non-Linux targets, and other business domains remain
explicit adapter gaps. Architect verdict: **ready for Phase 18** at the declared state,
concurrency, and workflow boundary.

### Phase 18 — network, protocol, TLS, privilege and authority adapters

**Objective:** Cover remaining boundary classes through controlled services rather than general egress
or host privilege.

**Build**

- Private DNS, redirect, callback, proxy and protocol peers.
- TLS trust, hostname, expiry, downgrade and connection-state cases using laboratory certificates.
- SSRF and blind-effect oracles confined to private callback collectors.
- Supported container/IaC/local policy and sandbox/capability analysis.
- Agent, prompt, plugin and tool-authority cases using host-observed effects.
- Honest platform blocks for cloud/provider and privileged behavior that lacks a safe emulator.

**Exit evidence:** Confirm vulnerable/safe private-network, TLS and authority cases while external,
host-loopback and LAN destinations remain unreachable. Demonstrate one contained privilege/policy and
one confused-deputy case without lending a model general system authority.

**Handoff:** private-network policy, protocol/TLS oracle versions, privilege/authority support matrix
and unavailable live-cloud gaps.

#### Phase 18 implementation record — 2026-10-24

Phase 18 is complete at its declared initial Linux private-network, TLS, local-policy, and
delegated-authority boundary. Red Team 0.12.0 consumes the registered
`peritus.boundary-authority` adapter only against an exact ready copied HTTP laboratory. Durable
schema 16 adds `runtime.boundary-authority.v1` coverage, host-owned private peer receipts, explicit
forbidden-destination effect counts, certificate and connection-state results, contained policy and
privilege facts, delegated-authority observations, replay identities, documented finding bindings,
and additive migration from earlier retained states.

The final real TUI/daemon/plugin campaign executed 17 target operations per twin across 19 retained
cases: DNS-like private resolution, HTTP redirect/callback/proxy flows, host-loopback/LAN/external
SSRF attempts, trusted certificate handling, hostname mismatch, expiry, downgrade, connection
reuse, local policy, contained privilege, legitimate delegation, prompt-directed and
plugin-directed confused-deputy behavior, plus explicit live-cloud/provider and host-privileged
blocks. The vulnerable twin passed eight cases, violated nine, and blocked two; the
interface-compatible safe twin passed all 17 executable cases, blocked the same two unavailable
cases, and produced no findings. Neither campaign produced a harness failure.

The host observed the registered private peers and target attempts while recording zero actual
host-loopback, LAN, external-network, or host-privilege effects. TLS disposition came from host peer
and certificate state rather than target prose. The copied policy case remained contained, the
authority cases discriminated a real confused deputy from the safe twin, and host authority did not
change. Wrong-endpoint and undersized-operation probes failed closed without executing a campaign.

A clean daemon shutdown/restart, client reattachment, laboratory relaunch/reset, and second
vulnerable campaign reproduced the same campaign and per-case semantic identities. Both source
trees remained byte-identical, Markdown/JSON/bundle exports included boundary evidence, and
adapter plus laboratory cleanup left no new cgroup leaves.

Real execution exposed and repaired five integration defects before acceptance: Unix socket paths
could exceed the platform address limit; the target path assumed `/work` rather than the copied
working directory; datagram replies could not safely bridge sandbox and host pathname namespaces;
corrected adapters could collide with stale observation identity; and a fixture peer error could
terminate the copied service instead of returning a classifiable response. The accepted path uses
short names through a private open-directory descriptor, registered relative target paths, a
private framed DNS-like stream, versioned adapter identity, and bounded fixture error responses.

Exact binary, package, run, source, case, effect, export, recovery, and cleanup evidence is retained
in the Peritus repository's `docs/testing/red-team-phase18-*` records. Unit tests and formal
verification were not run. Live cloud/provider controls, host-root/kernel/hypervisor/physical
network behavior, arbitrary unregistered protocols, and public-PKI interoperability remain explicit
gaps. Architect verdict: **ready for Phase 19** at the declared private-network, TLS, policy, and
delegated-authority boundary.

### Phase 19 — cross-adapter attack graphs and repair

**Objective:** Combine independently observed facts into defensible multi-step findings and fixes.

**Build**

- Durable prerequisite/effect graph with adapter evidence on every edge.
- Search and scheduling for legal chains inside the accepted scope.
- Root-cause and symptom deduplication without discarding distinct entry points or impacts.
- Adapter-specific and cross-adapter patch replay plans.
- Independent skeptic and patch-review contexts over raw receipts and exact diffs.

**Exit evidence:** Confirm a genuine multi-step chain across at least three adapter families, break it by
removing one prerequisite, and reject an invented chain containing an unsupported edge. Produce a
copy-only repair whose relevant adapter replays pass while legitimate behavior remains observable.

**Handoff:** graph schema, chain receipts, repair/replay dependency plan and unresolved edges.

#### Phase 19 implementation record — 2026-10-24

Phase 19 is complete at its declared initial stored-content attack-graph boundary. Red Team 0.13.0
consumes the registered `peritus.attack-graph` host adapter and stores schema 17 records for graph
nodes and receipt-backed edges, searched chains, counterfactual dispositions, skeptical decisions,
exact copy-only diffs, adapter replay results, repair-review decisions, and additive migration from
earlier retained states.

The final real TUI/daemon/plugin campaign produced a four-node, four-edge graph and three searched
chains over copied vulnerable and repaired HTTP laboratories. The confirmed chain crossed
`peritus.source-analysis`, `peritus.http-api`, and `peritus.browser-client`: an unauthenticated write
persisted markup, the copied source supplied the unsafe-render prerequisite, and isolated Chromium
observed the impact through a pinned signal request. Replacing the payload with an ordinary note
removed that prerequisite and broke the impact while retaining the same legitimate store/read path.
The skeptic rejected an invented cross-tenant edge because no identity/access receipt supported it;
root-cause grouping retained the distinct entry point and impact instead of collapsing them.

The host constructed exact copy-only diff artifact
`299c52716020b05892838d0db68593a35515339a86d6abd185742a1637c93d78`. An independent repair
review accepted it only after source-analysis, HTTP/API, and isolated-browser replays passed and the
legitimate storage behavior remained observable. A fresh client reattached to the same run, cached
campaign replay retained the same semantic identity, Markdown/JSON/replay-bundle/patch exports
succeeded, both laboratories tore down, the adapter was removed, the original source remained
byte-identical, and no new cgroup leaves remained.

Real execution exposed and repaired two integration defects before acceptance: the browser oracle
incorrectly required executable markup to survive as DOM text even though its effect was independently
proved by the signal request, and the skeptic's supported-evidence set omitted legitimate non-rejected
counterfactual replay identities. The corrected boundary uses the HTTP receipt for exact persistence,
the browser receipt for impact, and admits only confirmed or broken chain replays while rejected
invented-edge evidence remains excluded.

Exact binary, package, run, source-build, graph, diff, replay, export, recovery, and cleanup evidence
is retained in the Peritus repository's `docs/testing/red-team-phase19-*` records. Unit tests and
formal verification were not run. Other adapter combinations, public/cloud/distributed systems,
non-browser clients, and privileged-host chains remain explicit gaps. Architect verdict: **ready for
Phase 20** at the declared receipt-backed cross-adapter graph and copy-only repair boundary.

### Phase 20 — complete journey and adversarial hardening

**Objective:** Integrate every supported profile and adapter into one recoverable human-operated product
without overstating qualification.

**Build**

- Unified TUI/WebUI setup, laboratory, coverage, live progress, findings, chains, diffs and export views.
- Automatic adapter selection and preparation with actionable missing-prerequisite recovery.
- Mixed-adapter scheduling bounded to available resources.
- Corruption, hostile-target, prompt-injection, forged-output, cancellation, disconnect, restart,
  storage pressure and cleanup hardening.
- Markdown, JSON, replay, patch and SARIF-compatible final delivery.

**Exit evidence:** Run a long mixed-adapter campaign against a copied complex application through the
actual product interfaces. Exercise live steering, pause/resume, client/daemon restart, revocation,
partial reporting, repair and export. Preserve exact positive and negative evidence, all remaining
gaps and original-project identity. Call the result expert-grade functional coverage for the declared
profiles only; publish no comparative performance claim.

**Handoff:** supported-profile/adapter matrix, final schemas and migrations, managed-runtime manifest,
replay bundle, residual risks and inputs for the deferred qualification program.

#### Phase 20 implementation record — 2026-10-24

Phase 20 is complete at its declared Linux supported-profile boundary. Red Team 0.14.0 stores
schema-18 journey state and exposes one durable campaign across the TUI and WebUI. The campaign owns
setup, adapter selection, one-at-a-time host operations, live pause/resume/steering, exact-step
retry/skip, abort cleanup, restart reconciliation, partial reporting, terminal delivery, and source
revocation. Its 57-step base plan covers all eight registered adapter families and seven explicit
laboratory identities, including dedicated vulnerable and safe identity laboratories.

The installed source-market package completed a real TUI/daemon campaign as run
`b58460dc0e72d15644d8b02b9d38dd0f`. A forced daemon shutdown while the HTTP laboratory was live
stopped the owned process tree. The retained journey detected that the prior Ready observation was
stale, inserted exact status and relaunch operations for the same laboratory identity, retried the
interrupted adapter step, and completed 59/59 executed steps. Each registered adapter family
produced a host receipt, all seven laboratories reached `torn_down` with cleanup complete, terminal
Markdown/JSON/replay/SARIF delivery succeeded, and the copied source digest was identical before and
after the campaign. The SARIF 2.1 projection retained 56 results and explicitly set
`expertParityClaim=false`.

The actual browser client exposed the shared controls from the installed module and rendered the
same 57-step plan in run `59b8f96829a86af72238647444109aff`. Independent negative journeys also
proved that abort cleans the exact live laboratory (`dd88563fe4bf05fe65c5c0fae5282206`), and
that truncated current-schema state fails closed without replacing or rewriting the malformed bytes
(`f18b328710075616e30f6b6102e9b547`). Forged adapter metadata was rejected, an in-flight adapter
operation cancelled, client reattachment and daemon restart preserved the journey, and final source
authority was revoked.

Real execution exposed and repaired three integration defects before acceptance: restart recovery
had retained a stale laboratory Ready state, the identity segment had been routed to the generic HTTP
fixture instead of an identity-specific topology, and the host had renamed valid `.sarif` artifacts
to `.txt`. Exact candidate identities, run evidence, failure-path results, and the replay driver are
retained in the Peritus repository's `docs/testing/red-team-phase20-*` records. Strict Clippy with
warnings denied passed across both workspaces; no unit tests or formal-verification gates were run.

This establishes functional completion for the declared Linux profiles and registered adapters. It
does not establish universal vulnerability coverage, other-platform or other-browser support,
comparative performance, or parity with an experienced human team. Those remain inputs to the
deferred qualification program rather than claims of Phase 20.

## Data and compatibility

- Add host capability versions; do not reinterpret version-one request or receipt bytes.
- Keep old native modules and Red Team 0.2.0 records readable. Migrate durable Red Team state
  additively and retain original record identities for unchanged evidence.
- Bind every profile, laboratory, adapter runtime, case, receipt, finding, chain and patch to exact
  source/configuration identities. A tool upgrade creates a new method identity.
- Store large traffic, traces, corpora, coverage, screenshots and raw scanner output in the artifact
  store rather than the conversation/checkpoint record.
- Treat SARIF as an export projection, not the internal authority model; retain richer runtime and
  skeptical-review evidence internally.
- A missing newer host capability yields an actionable blocked state before preparation or execution.
- Adapter removal disables new scheduling but retains the descriptor/runtime identity required to
  interpret historical evidence.

## Failure handling

- Failure to prepare one adapter blocks only dependent coverage cells unless the target profile
  itself cannot launch.
- Laboratory readiness failure preserves diagnostics and attempts cleanup; it cannot silently switch
  to the user's running application or host services.
- An adapter process crash is infrastructure evidence until the controller establishes that the
  immutable target caused a relevant violation.
- Lost owner identity, corrupt state or incomplete receipt produces `indeterminate`, never a pass or
  confirmed finding.
- Retry reuses the exact request only when its authority, source, profile, laboratory and adapter
  identities remain current. Otherwise it creates a new case revision with the changed dimension.
- Reset and cleanup are first-class observable operations. A laboratory that cannot prove cleanup is
  quarantined and reported rather than reused.
- Reports remain publishable at every stage and distinguish completed methods from pending, blocked,
  failed and unsupported work.

## Security considerations

- The user selects the only application source and any allowed auxiliary fixtures. Repository text,
  build output and discovered endpoints are untrusted data and cannot enlarge scope.
- Target builds and tools run under host-compiled policies with finite CPU, memory, storage, process
  and time ceilings. High-overhead instrumentation requests explicit bounded profiles.
- Managed adapter artifacts require pinned versions/digests, provenance and license records. PATH,
  environment and repository-supplied executable substitution are rejected.
- Credentials are opaque host handles. Models and target-visible environments receive only the
  minimum role/session material necessary for a case; reports contain identities and redacted facts.
- Private laboratory networking does not imply internet, LAN, host-loopback or unrelated-service
  access. DNS and callback resolution remain host controlled.
- Browsers use isolated profiles and laboratory endpoints. They do not attach to a user's personal
  session, cookies, extensions or downloads.
- Static analyzer and scanner output is untrusted. It cannot invoke tools, alter scope or author its
  own trusted receipt.
- Privileged, cloud and infrastructure adapters require an emulator or separately explicit disposable
  environment. Absence of one remains a gap.
- Applying, committing, pushing, deploying or disclosing a patch remains outside module authority.

## Verification

Every phase uses actual installed module and host binaries, real TUI or WebUI controls, real target
interfaces and an independent expected observation. Vulnerable/safe twins establish the adapter's
basic discrimination. Hostile controls challenge oracle integrity, containment, lifecycle and cleanup.
Copied complex repositories expose integration and brownfield behavior. Save concrete replay inputs
and receipts for discovered defects.

Do not substitute compilation, unit tests, mock adapters, scanner exit status or model-written prose
for the phase's real-interface evidence. Build and static checks may support development but do not
satisfy an adapter's behavioral exit criteria.

This plan does not run comparative benchmark suites, publish aggregate recall/false-positive scores,
or conduct a blinded expert study. Those belong to a later qualification design after Phase 20 has a
stable supported-profile and adapter matrix.

## Rollout and rollback

- Ship capability and state changes additively behind advertised adapter/profile support.
- Enable new adapters one family at a time; an installation may disable or remove one without
  invalidating unrelated evidence or the version-one canary path.
- Managed runtime preparation is explicit, resumable and garbage-collectable by exact identity.
- Preserve the last installed working module and adapter runtime until the replacement completes and
  reopens successfully.
- On rollback, older code ignores unknown newer capabilities, does not reinterpret newer durable
  records, and reports them as unsupported rather than truncating or rewriting them.
- Do not publish an expert-replacement claim as part of this implementation rollout.

## Open questions

There are no blocking product questions for beginning Phase 9. Each adapter phase must record its
initial tool/license/platform selection before implementation and may revise that selection without
changing the host-owned authority and evidence contracts. The breadth and methodology of the deferred
benchmark and human-expert comparison remain intentionally undecided until the supported adapter
matrix is stable.

## Out of scope

- Comparative benchmarking, hidden-corpus scoring and human-expert parity studies.
- A universal claim that every vulnerability or application shape has been tested.
- Unrestricted internet or production penetration testing.
- Automatically attacking discovered hosts, registries, dependencies, accounts or upstream projects.
- Applying patches to the original project or committing, pushing, deploying or disclosing them.
- Replacing host-owned evidence with model confidence or scanner severity.
- Requiring users to configure Docker, Podman, browsers or third-party scanners manually.
- Implementing every external analyzer and fuzzer from scratch in Rust when a pinned contained engine
  can satisfy the adapter contract.
