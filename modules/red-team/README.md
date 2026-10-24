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

1. **Check compatibility**. Red Team should report scoped source, private state, checkpoints, and
   contained jobs as available.
2. **Scope current workspace**. This creates an inert immutable snapshot; it does not execute the
   project.
3. Optionally **Steer investigation** with the threat model, high-value boundaries, or behavior that
   must remain working.
4. Select **Start autonomous investigation**.
5. Follow **Investigation status**, **Coverage ledger**, **Findings**, and **Contained jobs** while it
   runs.
6. When repair finishes, inspect **Patches and exact diffs**, then export the Markdown report, JSON
   report, and replay bundle.

The equivalent terminal commands are:

```text
/module peritus.red-team compatibility
/module peritus.red-team scope exclude .git,target,node_modules,dist
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
4. Run only supported proofs through host-owned contained adapters with finite resources, cleared
   credentials, deny-all proof-time networking, and host-authored receipts.
5. Give the raw evidence and counterevidence to a separately persisted skeptic.
6. For confirmed findings, propose root-cause fixes in disposable copies and replay attack,
   legitimate, malformed, and adjacent cases.
7. Give the exact diff and replay receipts to an independent patch reviewer.
8. Compare the original workspace with its starting byte-and-executable-mode manifest before
   publishing delivery artifacts.

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
current stage. An already submitted host job remains host-owned; inspect **Contained jobs** and
cancel its exact identity if needed.

If the client disconnects, reopen the same Peritus run and use **Investigation status** or `resume`.
If a retained host request was interrupted, `resume` reissues that exact request instead of starting
an unrelated effect.

To invalidate the current source authority and stop work tied to it:

```text
/module peritus.red-team revoke
```

After intentional source changes, use **Refresh source**. Unchanged observations are reused and
evidence that depended on changed or removed paths is invalidated.

## Read the results correctly

| Finding state | Meaning |
| --- | --- |
| `confirmed` | Trusted execution evidence demonstrated the specified violation on the exact target, with independent review. |
| `analysis_supported` | Source or configuration evidence supports the weakness, but the runtime effect was not demonstrated. |
| `refuted` | Counterevidence disproved a necessary premise for this exact claim. |
| `not_reproduced` | Legal attempts ran without demonstrating the violation; the broader question remains open. |
| `inconclusive` | The available observations do not settle the claim or impact. |
| `blocked` | A named prerequisite, permission, dependency, environment, or supported adapter was unavailable. |

`examined` in the coverage ledger means named methods examined that surface. It does not mean the
surface is secure. An empty confirmed-finding list is not a clean bill of health.

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
/module peritus.red-team bundle
```

The TUI and browser interface show each exported artifact's stable local path, byte count, and
SHA-256. A completed delivery can contain:

- a human-readable Markdown report;
- a machine-readable JSON report;
- exact unified patch files;
- a reproduction bundle with recorded inputs, prerequisites, receipts, reviews, and replay
  instructions; and
- explicit unsupported, blocked, inconclusive, and unexamined areas.

Applying a patch, committing it, pushing it, deploying it, opening an issue, or disclosing a finding
is a separate user-controlled action.

## Useful commands

| Command | Purpose |
| --- | --- |
| `status` | Show campaign, investigation, repair, evidence, job, finding, patch, and coverage counts. |
| `scope [exclude PATHS]` | Capture the explicitly opened workspace with optional source-relative exclusions. |
| `start` | Start or recover the autonomous investigation and copy-only repair chain. |
| `steer TEXT` | Retain bounded guidance for current and later roles. |
| `pause` / `resume` | Suspend or continue while preserving durable state. |
| `refresh` | Re-observe the selected source and selectively invalidate stale evidence. |
| `manifest` | Inspect the captured source manifest. |
| `coverage` | Show every security-family state and its reason. |
| `findings` | Show skeptical classifications and bound evidence. |
| `patches` | Show patch lifecycle, exact diffs, replay cases, and reviews. |
| `jobs` | List contained host-owned jobs and their current states. |
| `report`, `report-json`, `bundle` | Export the current evidence-backed delivery. |
| `revoke` | Revoke the current source authority and cancel dependent work. |
| `compatibility` | Explain which required host capabilities are available or missing. |
| `contract` | Display the source, execution, evidence, repair, and original-preservation contract. |
| `checkpoint` | Publish a durable investigation checkpoint. |

The low-level `observe`, `prepare`, `probe`, `job`, `job-log`, and `job-cancel` commands are mainly
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
- Patches are created and tested only in disposable copies.
- The original workspace is checked again before final delivery.
- macOS, Windows, other architectures, and security properties without a suitable host adapter are
  not claimed tested by the current Linux recipe.

For implementation details and the retained acceptance history, see the
[product design](../../.design/red-team.md) and
[phased implementation record](../../.design/red-team-phases.md). The bundled
[Red Team skill](skills/red-team/SKILL.md) defines the evidence discipline supplied to each model
role.
