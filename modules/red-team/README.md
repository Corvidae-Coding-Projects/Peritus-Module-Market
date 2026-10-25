# Peritus Red Team

Red Team investigates an application you explicitly open in Peritus, tests supported security
claims in disposable contained copies, challenges the evidence with a separate skeptic, and hands
back reports, reproduction material, and copy-only patches.

It is intended for authorized defensive testing of source code you own or are permitted to assess.
It does not scan the rest of your computer, apply patches to the original project, publish findings,
or claim that an application is secure because a probe found nothing.

## Before you begin

You need:

- a current Peritus installation with native modules and source builds;
- Linux x86-64 GNU for the currently published build recipe;
- the Rust toolchain and Bubblewrap required by Peritus's source-build screen; and
- a configured writer and reviewer provider in Peritus.

Open the exact application you want to assess:

```sh
peritus open /path/to/application
```

The workspace opened by that command is the maximum source boundary. Red Team steering, source
text, repository instructions, and target output cannot expand it.

## Install from the Module Market

### Terminal interface

1. Enter `/modules`.
2. Press `r` to refresh the market.
3. Select **Red Team** with the arrow keys.
4. Press `b` to **Build and install**.
5. Wait for `Source build: installed`. New installs remain disabled.
6. Press `e` to enable the installed package.
7. Press Enter to select **Use module**.

The module menu supports Up/Down to choose a module, Left/Right or Tab/Shift-Tab to choose an
action, and Enter to run the selected action. Number keys remain shortcuts for the first nine
actions.

### Browser interface

1. Open **Modules**.
2. Refresh the market.
3. On the **Red Team** card, select **Build and install**.
4. When the build is installed, select **Enable**, then **Use module**.

### CLI-only installation

The interactive interfaces are recommended because they show build progress and retained errors.
For a scripted installation:

```sh
peritus modules refresh
peritus modules market
peritus modules build-install-market peritus.red-team SOURCE_DIGEST_FROM_MARKET_OUTPUT
peritus modules enable peritus.red-team
```

The source digest is mandatory: it binds the exact catalog commit and prevents a different source
revision from being installed accidentally.

## Run your first investigation

The shortest useful workflow is:

1. **Check compatibility**. Red Team should report scoped source, private state, checkpoints,
   disposable laboratories, and isolated module workers as available.
2. **Scope current workspace**. This creates an inert immutable snapshot; it does not execute the
   project.
3. Select **Install static analyzers**, then **Analyze scoped source** to collect deterministic
   language, dependency, secret and configuration leads before dynamic work.
4. Optionally **Steer investigation** with the threat model, high-value boundaries, or behavior that
   must remain working.
5. Select **Start autonomous investigation**.
6. Follow **Investigation status**, **Coverage ledger**, **Findings**, and **Contained jobs** while it
   runs.
7. When repair finishes, inspect **Patches and exact diffs**, then export the Markdown report, JSON
   report, and replay bundle.

The equivalent terminal commands are:

```text
/module peritus.red-team compatibility
/module peritus.red-team scope exclude .git,target,node_modules,dist
/module peritus.red-team analyzer-install
/module peritus.red-team analyze
/module peritus.red-team steer Treat an unauthenticated remote client as the attacker. Prioritize authentication, path handling, command construction, and secret disclosure. Preserve documented CLI behavior.
/module peritus.red-team start
```

Exclusions are source-relative paths separated by commas or spaces. Exclude generated output and
large dependency caches that are not part of the application you intend to examine. Do not exclude
security-relevant source merely to make the campaign faster.

Steering is retained for later discovery, skeptical review, repair, and patch-review contexts. It
can narrow priorities and clarify requirements, but it cannot grant new filesystem, network,
credential, or execution authority.

## What Red Team does

After `start`, the module coordinates this sequence:

1. Capture one bounded inventory from the selected immutable source snapshot.
2. Map security families to concrete application surfaces and leave unsupported areas visibly
   unexamined or blocked.
3. Register small falsifiable hypotheses before execution.
4. Run supported proofs through Red Team's own adapters inside generic Peritus worker containment,
   with finite resources, cleared credentials, deny-all ambient networking, and module-authored
   receipts derived from observed target bytes and copied state.
5. Give the raw evidence and counterevidence to a separately persisted skeptic.
6. For confirmed findings, propose root-cause fixes in disposable copies and replay attack,
   legitimate, malformed, and adjacent cases.
7. Give the exact diff and replay receipts to an independent patch reviewer.
8. Compare the original workspace with its starting byte-and-executable-mode manifest before
   publishing delivery artifacts.

### Where the implementation lives

All security behavior lives in this module:

- adapter registration, preparation, execution, and receipt decoding;
- source-analysis rules and dependency/configuration/secret observations;
- HTTP/API, browser, identity/access, file/parser, workflow/state, boundary/authority, and
  attack-graph campaign implementations;
- target entrypoint selection, private Unix transport, target state oracles, canaries, Chromium
  setup, skeptic decisions, repair replay, and report generation; and
- the private Rust contracts that describe those observations.

Peritus does not know these adapter names or evidence schemas. It exposes only generic module
discovery and lifecycle, scoped-source capture, source builds, persistent module state, complete
disposable source copies, bounded opaque worker execution, original-source verification, and shared
TUI/WebUI transport. This separation lets the Red Team module evolve or be replaced without adding
security-class code to Peritus itself.

Dependency preparation is separate from proof execution. A campaign may fetch an explicitly
declared, digest-pinned public HTTPS dependency during preparation; contained proof jobs do not gain
that network access.

## Steering, pausing, and recovery

You can steer active work without restarting it:

```text
/module peritus.red-team steer Recheck tenant isolation around the admin export path. A fix must preserve ordinary member exports.
```

Pause and resume from either interface, or use:

```text
/module peritus.red-team pause
/module peritus.red-team resume
```

Pause preserves the source snapshot, observations, hypotheses, receipts, findings, patch plans, and
current stage. A submitted module worker remains bounded by the current Peritus call; cancel the
active Peritus run if that worker must be stopped.

If the client disconnects, reopen the same Peritus run and use **Investigation status** or `resume`.
If a retained host request was interrupted, `resume` reissues that exact request instead of starting
an unrelated effect.

To invalidate the current source authority and stop work tied to it:

```text
/module peritus.red-team revoke
```

After intentional source changes, use **Refresh source**. Unchanged observations and coverage cells
are reused. Only surfaces and method obligations whose declared source paths changed or disappeared
are invalidated; an unsupported adapter remains an explicit blocked gap rather than becoming fake
work.

## Understand the target and coverage plan

The bounded inventory compiles a durable target graph instead of leaving a prose checklist. Inspect
it from either the terminal or browser interface:

```text
/module peritus.red-team profiles
/module peritus.red-team surfaces
/module peritus.red-team methods
/module peritus.red-team coverage
```

Each coverage cell binds one target profile, surface, attacker identity/configuration, security
property, and method. Properties carry a versioned ASVS 5.0.0, WSTG 4.2, CWE 4.18, or module-owned
`PERITUS` v1 identifier. Unknown or uncatalogued properties use the module-owned namespace instead
of inventing an external standards reference.

The registry advertises the narrow runtime method `runtime.linux-canary-disclosure.v1` for
compatible Linux command/native disclosure properties and the Phase 12 source-only method
`analysis.static-source.v1`. Other missing runtime classes remain
`gap.no-compatible-runtime.v1`. The compiler rejects inventory prose that calls work “examined”;
only an admitted host receipt can make that transition.

## Deterministic source analysis

Phase 12 adds a registered module analyzer that reads only the immutable snapshot created by `scope`:

```text
/module peritus.red-team analyzers
/module peritus.red-team analyzer-install
/module peritus.red-team analyze
/module peritus.red-team analysis-history
```

The initial pinned analyzer set discovers Rust, C/C++, JavaScript/TypeScript, Python, Go and Java;
applies deterministic syntax/pattern checks; performs bounded same-file source-to-sink analysis for
Python and JavaScript/TypeScript; parses Cargo, npm, Python requirements, Go module and Maven
dependency inputs; builds a normalized SBOM; attaches a small pinned advisory dataset; and examines
Dockerfiles, Kubernetes/YAML and Terraform configuration. Potential secret values are never
returned: the receipt includes only type, byte length and a digest fingerprint.

Each dependency is labeled `runtime_referenced`, `test_only`, `unreachable`, or `unknown` from the
captured source. Every analyzer result is labeled `source_lead`, including critical-looking rules.
Dead code, test fixtures, unreachable advisories and scanner-shaped JSON inside the target cannot
become `confirmed`; that state still requires a separate module-authored real-interface receipt and
independent review. The report retains the exact analyzer, rule and advisory versions, redacted raw
matches and their digest, deduplicated root causes, scanned source identity, skipped/truncated
counts and explicit semantic-analysis gaps.

## Managed adapter lifecycle

The Red Team module owns its typed adapter registry separately from Peritus developer tools. The
module includes one harmless diagnostic adapter so you can inspect the lifecycle before security
adapters rely on it:

```text
/module peritus.red-team adapters
/module peritus.red-team adapter-install diagnostic
/module peritus.red-team adapter-status
/module peritus.red-team adapter-run hello-from-the-managed-adapter
/module peritus.red-team adapter-history
/module peritus.red-team adapter-remove
```

Installation stages exact module-registered bytes, verifies their digest and platform, and records a
content-addressed runtime identity plus module-authored provenance. Reinstalling identical bytes
reuses that identity. Removal deletes the module-private runtime bytes while retaining the historical
identity and provenance. A host without the generic `module.worker@1` service reports the missing
capability and the module does not fall back to `PATH`, a shell command, or a caller-supplied
executable.

To inspect cancellation explicitly, use `adapter-stage diagnostic`, followed by `adapter-cancel`.
`adapter-complete` finishes a retained staged preparation after a reconnect or daemon restart. These
diagnostic commands prove lifecycle behavior only; they do not claim that any security class was
tested.

## Test an arbitrary source repository

The default laboratory copies the complete selected immutable source tree into private resettable
storage. The target does not need to contain special files, implement a Peritus protocol, emit
readiness JSON, or expose a fake state service. The Red Team module discovers common entry points and
can run an explicit real entry point with a module-selected runtime, literal argv, bounded stdin, cleared
credential-free environment, denied proof-time networking, process-tree containment, and a
predeclared exit/output oracle. Static analysis still runs when a repository has no executable
surface or its required toolchain is unavailable; that dynamic limitation is recorded as a gap,
not as a clean result.

Run the source-bound path after opening the application repository and selecting `scope`:

```text
/module peritus.red-team analyzer-install
/module peritus.red-team analyze
/module peritus.red-team lab-create source
/module peritus.red-team lab-prepare
/module peritus.red-team lab-launch
/module peritus.red-team lab-run-auto
/module peritus.red-team lab-snapshot
/module peritus.red-team lab-reset
/module peritus.red-team lab-stop
/module peritus.red-team lab-teardown
```

`lab-run-auto` uses the highest-confidence entry point discovered from the copied source. Use
`lab-run RUNTIME ENTRYPOINT [ARGS...]` when the repository has a different entry point. For exact
stdin, environment, exit codes, and stdout/stderr fragments, use `lab-run-json` with the
`ModuleLaboratoryProcessInput` shape. Supported module runtime families are `direct`, `python3`,
`node`, `bash`, `ruby`, `php`, `perl`, `cargo`, `go`, `java`, `dotnet`, and `make`; availability is
reported from the actual worker environment. These names select module-owned runtime launchers, not
arbitrary shell commands, and no argument receives shell parsing or expansion.

## Compatibility laboratory fixtures

The older Phase 11 fixture recipes copy two exact files, launch a controlled application/backing
store pair, and return opaque identities plus module-authored receipts. They exist to qualify the
HTTP, browser, identity, parser, workflow, boundary, and graph adapters. They are not a requirement
on user applications and their results are never a substitute for testing the selected source.

Run the included real multi-service fixture after `scope`:

```text
/module peritus.red-team laboratories
/module peritus.red-team lab-create fixture
/module peritus.red-team lab-prepare
/module peritus.red-team lab-launch
/module peritus.red-team lab-use a-distinct-value
/module peritus.red-team lab-snapshot
/module peritus.red-team lab-reset
/module peritus.red-team lab-stop
/module peritus.red-team lab-teardown
/module peritus.red-team laboratory-history
```

`lab-status` is read-only and can be used after reconnecting. `lab-use` performs a real write and
readback through the application boundary; `lab-reset` independently checks that the backing state
is empty; and `lab-stop` waits for complete process-tree cleanup. `lab-teardown` attempts to verify
the original source snapshot again, but cleanup remains available after source authority is revoked:
it deletes copied source, state, sockets, snapshots, and secret material while recording that the
original-source check was unavailable. Completed receipts survive client and daemon restarts.

The compatibility recipes remain deliberately exact. The complete-source recipe is protocol-free
and language-neutral at the source boundary; dynamic execution depends only on a supported runtime
being present and a real entry point being selected. Missing toolchains or application-specific
service topology are reported as gaps. There is no shell-string evaluation, container requirement,
host-network, credential, or production-endpoint fallback. Users do not need to know or configure a
container runtime.

## Test a real HTTP/API laboratory

Phase 13 registers `peritus.http-api`, a content-addressed module adapter that can address only a ready
`linux.python-http-api.v1` disposable laboratory. The module receives opaque generic laboratory
identities; its worker resolves the private Unix socket, emits and captures wire bytes, reads copied
target state, and redacts laboratory-only secrets before returning evidence.

Point the laboratory at two regular files in the captured target snapshot: a controller and its API
service. For a target whose files are `application.py` and `service.py`, run:

```text
/module peritus.red-team lab-create-http application.py service.py
/module peritus.red-team lab-prepare
/module peritus.red-team lab-launch
/module peritus.red-team api-install
/module peritus.red-team api-run
/module peritus.red-team api-history
/module peritus.red-team report
/module peritus.red-team report-json
/module peritus.red-team bundle
/module peritus.red-team lab-reset
/module peritus.red-team lab-stop
/module peritus.red-team lab-teardown
/module peritus.red-team api-remove
```

The `lab-create http-vulnerable` and `lab-create http-safe` shortcuts address the corresponding
paths only when the Peritus Module Market repository itself is the scoped target; installed module
resources are never silently added to another project's execution scope. Each campaign imports the live OpenAPI document,
records discovered routes and parameters, then sends pinned ordinary and adversarial REST, OpenAPI,
GraphQL, WebSocket, and JSON-RPC requests. It distinguishes `passed`, `rejected`, `unreachable`, and
`violation`; only a violation independently established by a module response/state oracle becomes a
`runtime_confirmed` finding. Rejected input is not called unreachable, a 404 is not called safe, and
an imported schema or target-authored message is never its own oracle.

The retained case ledger includes the exact minimized request, response status and digest, copied
state before/after, changed state keys, and oracle decision. The replay bundle includes the same
request identities so a fresh reset and relaunch can reproduce them. The current adapter covers
HTTP/1.1, live OpenAPI, REST, GraphQL queries, single-frame WebSocket text, and JSON-RPC over HTTP.
HTTP/2, HTTP/3, TLS, multipart bodies, arbitrary schema-derived generation, authentication,
multi-tenant differentials, GraphQL subscriptions, and WebSocket extensions remain explicit gaps.

## Test browser and client trust

Phase 14 registers `peritus.browser-client`. It can address only the exact ready
`linux.python-http-api.v1` laboratory selected by its opaque handles. The module creates isolated
Chromium contexts, exposes the copied service through two temporary loopback origins, and runs a
pinned action graph. The module cannot choose a URL, attach to a user's browser, or inherit browser
profiles, cookies, credentials, extensions, or downloads.

After the Phase 13 laboratory has been created, prepared, and launched, run:

```text
/module peritus.red-team browser-install
/module peritus.red-team browser-run
/module peritus.red-team browser-history
/module peritus.red-team report
/module peritus.red-team report-json
/module peritus.red-team bundle
```

The campaign exercises ordinary navigation, traditional and client-rendered crawling, reflected,
stored, and DOM script execution, CSP enforcement, cookie flags, cross-origin mutation, CSRF,
server-side validation, uploads, downloads, off-scope request blocking, and fresh-context replay.
The module correlates browser effects with its own copied-state oracle rather than trusting page text.
It retains content-addressed screenshots, a Playwright trace, traffic metadata, and exact upload and
download bytes. Reset the laboratory and run `browser-run` again to obtain a new bounded campaign;
an interrupted request with the same durable identity reuses its completed observation.

`browser-probe-wrong-endpoint` and `browser-probe-small-budget` are explicit rejection checks. Use
`browser-remove` to remove private adapter bytes while retaining historical observations. This
phase covers one pinned Chromium campaign, not every browser engine or application-specific
authenticated workflow; those remain visible gaps.

## Test authentication, sessions, authorization, and tenancy

Phase 15 registers `peritus.identity-access` for a ready copied multi-user HTTP laboratory. The
module creates and holds every credential, resolves them only while sending an exact request to the
selected private service, and gives the module opaque identity and session handles. Neither the
provider prompt nor the public campaign receipt contains passwords, factors, recovery tokens, or
session-token bytes.

Create the bundled vulnerable identity twin, prepare and launch it, then run:

```text
/module peritus.red-team lab-create identity-vulnerable
/module peritus.red-team lab-prepare
/module peritus.red-team lab-launch
/module peritus.red-team identity-install
/module peritus.red-team identity-run
/module peritus.red-team identity-history
/module peritus.red-team report
/module peritus.red-team report-json
/module peritus.red-team bundle
/module peritus.red-team lab-stop
/module peritus.red-team lab-teardown
```

Use `lab-create identity-safe` for the matched negative control. These shortcuts resolve only when
the Module Market repository is the scoped source; another project must name its compatible
controller and service explicitly with `lab-create-http`.

The pinned campaign applies the same operations across anonymous, ordinary, privileged,
same-tenant, and cross-tenant identities. It exercises login, MFA challenge and factor handling,
logout, rotation, expiry, revocation, concurrent-session revocation, and recovery, together with
owned-object access, object-identifier mutation, vertical privilege, cross-tenant access, and an
adjacent private route. Expected denials remain distinct from demonstrated violations and from
indeterminate infrastructure outcomes. A target response never decides its own verdict: the module
correlates response bytes with copied-state observations and the expected role, tenant, ownership,
and session transition.

Use `identity` or `identity-status` to inspect the registered method and current private runtime,
and `identity-history` to inspect retained cases, findings, lifecycle transitions, redaction facts,
and replay identities. `identity-probe-wrong-endpoint` and `identity-probe-small-budget` exercise
host rejection. `identity-remove` deletes the adapter's private runtime bytes while retaining the
historical receipts needed to interpret prior results.

This initial adapter covers one pinned five-identity, two-tenant topology. It does not claim broad
application-specific policy discovery, federated SSO, OAuth/OIDC protocol conformance, or
hardware-backed authenticator coverage; those remain explicit gaps.

## Test files, archives, parsers, and native boundaries

Phase 16 registers `peritus.file-parser`. Start from the file/parser corpus twins (or use the two
explicit `lab-create-http` paths), then install and run the adapter:

```text
/module peritus.red-team lab-create file-vulnerable
/module peritus.red-team lab-prepare
/module peritus.red-team lab-launch
/module peritus.red-team file-fuzz-install
/module peritus.red-team file-fuzz-run
/module peritus.red-team file-fuzz-history
```

The module submits real uploads, predictable-temporary operations, TAR records, valid and malformed
`PH16` grammar inputs, and a child-only native-FFI fault token. Fixed module-private canaries decide
path traversal, symbolic-link, temporary-file, permission, and archive effects. Exact inputs are
retained as bounded base64 with digests; generated failures are minimized and deduplicated before
reporting. The controller records resource use, response/state identities, native signals, and
module-observed behavioral edges. Those edges are deliberately not described as compiler source
coverage.

Run the matched negative control with `lab-create file-safe`. Hostile cases must be rejected, the
legitimate file/archive/parser controls must still pass, no boundary canary may change, and the
laboratory must remain responsive. Use `file-fuzz-probe-wrong-endpoint` and
`file-fuzz-probe-small-budget` to exercise host rejection. `file-fuzz-remove` removes only the
private adapter bytes and retains historical receipts.

The current Linux profile observes a CPython-to-libc child signal but does not compile arbitrary
targets under ASan/UBSan or claim language-specific edge coverage. Other operating systems, ABIs,
in-process libraries, and application grammars require separately registered adapters and remain
visible gaps.

## Test stateful workflows and concurrency

Phase 17 registers `peritus.workflow-state`. Start from either matched workflow twin, then install
and run the adapter:

```text
/module peritus.red-team lab-create workflow-vulnerable
/module peritus.red-team lab-prepare
/module peritus.red-team lab-launch
/module peritus.red-team workflow-install
/module peritus.red-team workflow-run
/module peritus.red-team workflow-history
```

The module drives real create, approve, charge, duplicate, replay, ambiguous retry, cancel,
crash/recovery, quota, and deterministic two-worker operations. It reads the copied state file
before and after every action and retains the exact identity, request, order, state digests,
schedule, timing, and replay identity. Documented invariants can support findings; model-proposed
candidate invariants remain visibly separate and may be refuted without creating a vulnerability.
An unrelated transport timeout or controller crash is classified as a harness failure, never as
proof of a business-rule violation.

Run the matched negative control with `lab-create workflow-safe`. All documented invariants must
hold while the legitimate create/approve/charge path remains functional. The fixed concurrent
schedule is replayed three times and any divergent final state is reported as nondeterminism. Use
`workflow-probe-wrong-endpoint` and `workflow-probe-small-budget` to exercise host rejection.
`workflow-remove` removes only private adapter runtime bytes while retaining prior receipts.

This profile covers one pinned approval/accounting domain and one deterministic two-worker
schedule. Application-specific contracts, arbitrary schedules, distributed consensus, external
queues and stores, and non-Linux targets require separate profiles and remain explicit gaps.

## Test network, TLS, platform, and delegated-authority boundaries

Phase 18 registers `peritus.boundary-authority`. Start from either matched boundary twin, then
install and run the adapter:

```text
/module peritus.red-team lab-create boundary-vulnerable
/module peritus.red-team lab-prepare
/module peritus.red-team lab-launch
/module peritus.red-team boundary-install
/module peritus.red-team boundary-run
/module peritus.red-team boundary-history
```

The module creates private Unix-socket DNS, redirect, callback, proxy, and TLS peers plus valid and
expired laboratory certificates. The target receives only private socket paths and certificate
bytes; ordinary IP networking remains denied. The campaign distinguishes legitimate private
traffic from blind SSRF attempts, validates trust, hostname, expiry, downgrade and connection-state
behavior, attempts contained privilege operations, checks local policy, and tests whether untrusted
prompt or plugin data can trigger a privileged copied-application action. Module-side peer counters,
copied state, TLS outcomes, and unchanged host authority are the oracles.

Run the negative control with `lab-create boundary-safe`. It must retain legitimate private DNS,
TLS and scoped delegation behavior while rejecting every hostile case. Public, LAN, host-loopback,
live-cloud and host-privileged execution are never enabled: the first three must have zero effects,
and the last two remain explicit `blocked` records until a separately registered emulator exists.
Use `boundary-probe-wrong-endpoint` and `boundary-probe-small-budget` to exercise host rejection.
`boundary-remove` removes only private adapter bytes while retaining prior receipts.

## Build a receipt-backed cross-adapter attack graph

Phase 19 registers `peritus.attack-graph`. It composes a real chain from exact source, private
HTTP, and isolated Chromium observations, then tests both a removed prerequisite and the repaired
twin. Create and launch the vulnerable twin first, then the safe twin; both remain live while the
module executes the graph:

```text
/module peritus.red-team lab-create http-vulnerable
/module peritus.red-team lab-prepare
/module peritus.red-team lab-launch
/module peritus.red-team lab-create http-safe
/module peritus.red-team lab-prepare
/module peritus.red-team lab-launch
/module peritus.red-team graph-install
/module peritus.red-team graph-run
/module peritus.red-team graph-history
```

The confirmed path must contain evidence from all three registered adapter families. The module also
stores an ordinary value through the vulnerable service to break the persisted-markup prerequisite
and prove the browser impact disappears. A deliberately proposed identity/access edge has no raw
receipt and must be retained as rejected. Root-cause grouping preserves the independently observed
entry and impact nodes.

The result includes an exact full-file unified diff from the vulnerable copied service to the safe
twin plus separate source-analysis, HTTP/API, and browser-client replays. The repair reviewer
accepts it only when all three pass and the legitimate store/read path remains operational. This
does not apply the patch to the selected project. Use `graph-probe-single-lab` and
`graph-probe-small-budget` to exercise host rejection. Use `lab-select PREFIX` before stop and
teardown when cleaning up each retained twin.

## Run the complete supported campaign

Phase 20 adds one durable operator journey across every currently registered adapter. It is the
easiest way to exercise the supported profiles without manually remembering adapter installation,
laboratory order, twin selection, cleanup, or export commands:

```text
/module peritus.red-team scope
/module peritus.red-team campaign-plan
/module peritus.red-team campaign-start
/module peritus.red-team campaign-next
```

`campaign-plan` shows the fixed plan before any effect. `campaign-start` binds that plan to the
current immutable source snapshot. Each `campaign-next` dispatches at most one module-owned operation;
invoke it again only after the preceding operation settles. The TUI and browser UI expose the same
controls and retained progress.

Use `campaign-pause` between operations and `campaign-resume` to continue after a pause, client
disconnect, daemon restart, or machine restart. `campaign-steer TEXT` records operator guidance for
visibility but cannot change source scope, adapter authority, network access, credentials, resource
bounds, or the fixed execution plan. A failed or malformed receipt blocks the current step rather
than counting it as complete. Use `campaign-retry` after correcting a prerequisite, or
`campaign-skip` to retain an explicit coverage gap and continue independent work.

`campaign-abort` converts every still-live laboratory into a one-at-a-time cleanup plan. Continue
until each one has a module-authored torn-down receipt. `campaign` shows every planned, waiting,
completed, skipped, or blocked step plus retained steering and failures. Partial reports remain
available throughout. Completion exports Markdown, JSON, SARIF 2.1.0, exact patch artifacts, and a
replay bundle. It means the registered profiles completed or were explicitly recorded as gaps; it
does not mean every vulnerability class or target technology was tested.

## Read the results correctly

| Finding state | Meaning |
| --- | --- |
| `confirmed` | Trusted execution evidence demonstrated the specified violation on the exact target, with independent review. |
| `analysis_supported` | Source or configuration evidence supports the weakness, but the runtime effect was not demonstrated. |
| `refuted` | Counterevidence disproved a necessary premise for this exact claim. |
| `not_reproduced` | Legal attempts ran without demonstrating the violation; the broader question remains open. |
| `inconclusive` | The available observations do not settle the claim or impact. |
| `blocked` | A named prerequisite, permission, dependency, environment, or supported adapter was unavailable. |

`examined` in the coverage ledger means the exact named method ran for that exact surface,
identity/configuration, and property. It does not mean the surface is secure. An empty
confirmed-finding list is not a clean bill of health.

Patch states are equally bounded. `validated_for_recorded_cases` means the disposable patched copy
passed the recorded replay matrix and independent review. It is not proof against every input, and
Red Team still does not apply the patch to your original checkout.

## Reports and patches

You can publish useful partial results at any time:

```text
/module peritus.red-team coverage
/module peritus.red-team findings
/module peritus.red-team patches
/module peritus.red-team report
/module peritus.red-team report-json
/module peritus.red-team sarif
/module peritus.red-team bundle
```

The TUI and browser interface show each exported artifact's stable local path, byte count, and
SHA-256. A completed delivery can contain:

- a human-readable Markdown report;
- a machine-readable JSON report;
- a SARIF 2.1.0 projection for compatible result consumers;
- exact unified patch files;
- a reproduction bundle with recorded inputs, prerequisites, receipts, reviews, and replay
  instructions; and
- explicit unsupported, blocked, inconclusive, and unexamined areas.

Applying a patch, committing it, pushing it, deploying it, opening an issue, or disclosing a finding
is a separate user-controlled action.

## Useful commands

| Command | Purpose |
| --- | --- |
| `campaign-plan` / `campaign-start` | Preview and bind the complete supported-profile journey to the current source snapshot. |
| `campaign` / `campaign-next` | Inspect durable step-by-step progress or dispatch the next single bounded host operation. |
| `campaign-pause` / `campaign-resume` | Pause between operations or continue the exact retained journey after reconnect/restart. |
| `campaign-steer TEXT` | Retain visible operator guidance without enlarging authority or rewriting the fixed plan. |
| `campaign-retry` / `campaign-skip` | Retry the exact blocked step or preserve it as an explicit gap and continue. |
| `campaign-abort` | Stop scheduling coverage and replace the remainder with observable laboratory cleanup steps. |
| `status` | Show campaign, investigation, repair, evidence, job, finding, patch, and coverage counts. |
| `scope [exclude PATHS]` | Capture the explicitly opened workspace with optional source-relative exclusions. |
| `start` | Start or recover the autonomous investigation and copy-only repair chain. |
| `steer TEXT` | Retain bounded guidance for current and later roles. |
| `pause` / `resume` | Suspend or continue while preserving durable state. |
| `refresh` | Re-observe the selected source and selectively invalidate stale evidence. |
| `profiles` | Show compiled application shapes, interfaces, languages, services, stores, and unavailable claims. |
| `surfaces` | Show components, concrete entry surfaces, source dependencies, trust boundaries, and refresh state. |
| `methods` | Show available and unsupported examination methods with their exact host operation and limitation. |
| `manifest` | Inspect the captured source manifest. |
| `coverage` | Show every surface × identity/configuration × property × method cell, standards mapping, state, and exact gap. |
| `analyzers`, `analyzer-status`, `analysis-history` | Inspect supported static analysis, its content-addressed runtime, and retained scan receipts. |
| `analyzer-install`, `analyze`, `analyzer-remove` | Install the registered analyzer, scan the exact scoped snapshot, or remove its private runtime bytes. |
| `api`, `api-status`, `api-history` | Inspect the registered HTTP/API method, its private runtime, and retained real-traffic campaigns. |
| `api-install`, `api-run`, `api-remove` | Install the registered HTTP/API adapter, run its pinned real-interface campaign, or remove its private runtime bytes. |
| `browser`, `browser-status`, `browser-history` | Inspect the registered browser/client method, private runtime, retained campaigns, cases, findings, and artifacts. |
| `browser-install`, `browser-run`, `browser-remove` | Install the registered browser adapter, execute its bounded campaign against the selected laboratory, or remove its private runtime bytes. |
| `browser-probe-wrong-endpoint`, `browser-probe-small-budget` | Exercise host rejection of an unowned endpoint or an out-of-profile campaign bound. |
| `identity`, `identity-status`, `identity-history` | Inspect the registered identity/access method, private runtime, retained differential campaigns, lifecycle transitions, redaction facts, cases, and findings. |
| `identity-install`, `identity-run`, `identity-remove` | Install the registered identity adapter, run its pinned role/tenant/session campaign, or remove its private runtime bytes. |
| `identity-probe-wrong-endpoint`, `identity-probe-small-budget` | Exercise host rejection of an unowned endpoint or an out-of-profile identity campaign bound. |
| `file-fuzz`, `file-fuzz-status`, `file-fuzz-history` | Inspect the registered file/parser method, runtime, exact minimized cases, coverage/resource receipt, gaps, and findings. |
| `file-fuzz-install`, `file-fuzz-run`, `file-fuzz-remove` | Install the registered adapter, run its bounded real-interface campaign, or remove private runtime bytes. |
| `file-fuzz-probe-wrong-endpoint`, `file-fuzz-probe-small-budget` | Exercise host rejection of an unowned endpoint or out-of-profile case bound. |
| `workflow`, `workflow-status`, `workflow-history` | Inspect the workflow/state method, runtime, documented/proposed invariants, exact action/schedule receipts, nondeterminism, gaps, and findings. |
| `workflow-install`, `workflow-run`, `workflow-remove` | Install the registered workflow adapter, run its bounded real-interface campaign, or remove private runtime bytes. |
| `workflow-probe-wrong-endpoint`, `workflow-probe-small-budget` | Exercise host rejection of an unowned endpoint or out-of-profile action bound. |
| `boundary`, `boundary-status`, `boundary-history` | Inspect the private-network, TLS, platform-policy, and delegated-authority method, runtime, retained cases, gaps, effects, and findings. |
| `boundary-install`, `boundary-run`, `boundary-remove` | Install the registered boundary adapter, run its bounded real-interface campaign, or remove private runtime bytes. |
| `boundary-probe-wrong-endpoint`, `boundary-probe-small-budget` | Exercise host rejection of an unowned endpoint or out-of-profile operation bound. |
| `graph`, `graph-status`, `graph-history` | Inspect the receipt-backed cross-adapter method, runtime, graph nodes and edges, searched paths, skeptic decision, repair plan, and replay results. |
| `graph-install`, `graph-run`, `graph-remove` | Install the registered attack-graph adapter, execute the three-family campaign over two ready twins, or remove private runtime bytes. |
| `graph-probe-single-lab`, `graph-probe-small-budget` | Exercise host rejection of a non-distinct twin set or an out-of-profile campaign bound. |
| `adapters`, `adapter-status`, `adapter-history` | Inspect registered adapters, current lifecycle state, receipts, and retained errors. |
| `adapter-install diagnostic`, `adapter-run MESSAGE`, `adapter-remove` | Prepare, operate, and remove the harmless managed diagnostic adapter. |
| `laboratories`, `lab-status`, `laboratory-history` | Inspect registered application recipes, the latest retained lifecycle state, receipts, and errors. |
| `lab-create fixture`, `lab-create http-vulnerable`, `lab-create http-safe`, `lab-create identity-vulnerable`, `lab-create identity-safe`, `lab-create file-vulnerable`, `lab-create file-safe`, `lab-create workflow-vulnerable`, `lab-create workflow-safe`, `lab-create boundary-vulnerable`, `lab-create boundary-safe` | Create a copied state fixture or a repository-local HTTP/API, identity/access, file/parser, workflow/state, or boundary-authority corpus twin from exact scoped source. |
| `lab-create-http APPLICATION SERVICE` | Create an HTTP/API laboratory from two explicit snapshot-relative target files. |
| `lab-prepare`, `lab-launch`, `lab-use VALUE` | Prepare, launch, and operate a compatible copied laboratory through its real application boundary. |
| `lab-select PREFIX` | Select one uniquely matching retained laboratory so lifecycle and cleanup commands act on that twin. |
| `lab-snapshot`, `lab-reset`, `lab-stop`, `lab-teardown` | Preserve state evidence, restore an empty store, terminate the process tree, and remove disposable bytes. |
| `findings` | Show skeptical classifications and bound evidence. |
| `patches` | Show patch lifecycle, exact diffs, replay cases, and reviews. |
| `jobs` | List contained module worker operations and their current states. |
| `report`, `report-json`, `sarif`, `bundle` | Export the current evidence-backed Markdown, JSON, SARIF, or replay delivery. |
| `revoke` | Revoke the current source authority and cancel dependent work. |
| `compatibility` | Explain which required host capabilities are available or missing. |
| `contract` | Display the source, execution, evidence, repair, and original-preservation contract. |
| `checkpoint` | Publish a durable investigation checkpoint. |

The low-level `observe`, `probe`, `job`, `job-log`, and `job-cancel` commands are mainly
for focused manual replay and diagnosis. Normal investigations should let the coordinator schedule
them so hypotheses, authority, receipts, and reviews remain connected.

## Troubleshooting

**Red Team is not listed.** Refresh the Module Market and confirm you are using a current Peritus
build. Older releases that only understand prebuilt `market.toml` entries cannot discover the
source-only Red Team entry in `sources.toml`.

**The source build is unsupported or fails before compilation.** The published recipe currently
targets Linux x86-64 GNU. Read the retained build detail for a missing pinned Rust toolchain,
Bubblewrap, dependency-preparation failure, or unsupported platform.

**Compatibility reports a missing capability.** Update Peritus. Red Team will not replace scoped
source or contained jobs with ambient filesystem access or unrestricted shell execution.

**The module says a host request is unfinished.** Use `resume` to continue that exact durable
request. Do not repeatedly submit `start` or a second scope.

**A complete-campaign step is blocked.** Read `campaign` for the exact step and retained error.
Correct the named prerequisite and use `campaign-retry`, or use `campaign-skip` to preserve the
gap. Do not edit the state file or create a replacement laboratory.

**The durable state is unreadable.** Red Team stops without substituting an empty campaign and
prints the exact retained state path. Preserve that file, restore it from a known-good copy, or
inspect its bytes before retrying.

**A result is blocked, inconclusive, or not reproduced.** That is a valid bounded outcome. Read the
named prerequisite and retained evidence; do not reinterpret it as either a confirmed defect or a
security guarantee.

## Security and platform boundaries

- Only the explicitly opened application workspace can become source authority.
- Unsafe paths, path traversal, and escaping symbolic links are rejected.
- Target programs cannot choose the hidden canary, evaluator, or host receipt.
- Proof jobs run in the supported Linux private-filesystem backend with finite CPU, memory, storage,
  process, and wall-time limits.
- Network and credential access are denied during proof execution.
- Application laboratories use opaque service, endpoint, identity, and secret handles; target-only
  secret bytes are quarantined if they appear in target output.
- HTTP/API campaigns can reach only an exact ready disposable-laboratory handle. The module owns the
  private route, traffic capture, state oracle, secret redaction, resource bounds, and receipt.
- Browser campaigns can reach only two module-created loopback bridges to that exact private service.
  They use fresh managed profiles, block off-scope requests, retain bounded evidence, and never
  attach to an ambient user browser.
- Identity/access campaigns can use only module-generated credentials for the exact selected
  laboratory and registered topology. Public receipts contain opaque identity/session handles and
  redaction facts, while role, tenant, ownership, response, and copied-state observations remain
  independently correlated by the module.
- Static analysis reads only immutable scoped-source artifacts under host-enforced file and byte
  bounds; it cannot execute target code and cannot promote a source lead to runtime confirmation.
- Active laboratory process trees are cancelled when run authority, required permissions, selected
  source authority, or the installed module identity is revoked.
- Patches are created and tested only in disposable copies.
- The original workspace is checked again before final delivery.
- macOS, Windows, other architectures, and security properties without a suitable module adapter are
  not claimed tested by the current Linux recipe.

For implementation details and the retained acceptance history, see the
[product design](../../.design/red-team.md) and
[phased implementation record](../../.design/red-team-phases.md). The bundled
[Red Team skill](skills/red-team/SKILL.md) defines the evidence discipline supplied to each model
role.
