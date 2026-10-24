# Peritus Red Team

Source-only Rust module for authorized defensive investigation of an explicitly selected application.
The canonical product design is [../../.design/red-team.md](../../.design/red-team.md), and the phased
implementation plan is [../../.design/red-team-phases.md](../../.design/red-team-phases.md).

Phases 1 through 8 implement the native skeleton, canonical skill, versioned host-service envelope,
capability discovery, version-one record identities, and a schema-six durable campaign checkpoint.
The host-enforced scoped-source service captures the explicit original workspace without executing
it, publishes content-addressed file and manifest artifacts, returns revocable opaque handles,
supports bounded reads and paging, recovers interrupted publication, reuses verified unchanged
content, and identifies changed or removed dependencies. The module selectively invalidates source
observations and publishes honest partial Markdown or JSON reports with every unsupported security
family shown as unexamined. Phase 3 adds asynchronous host-owned jobs: credential-free,
digest-pinned HTTPS preparation is separate from proof execution, while proof cases run in the
Linux private-filesystem backend with cleared environment, deny-all network and secrets, finite
resources, live authority monitoring, host-generated canaries, host-authored receipts, cancellation,
logs, durable status, and no automatic relaunch after owner loss.

Phase 4 makes the source module discoverable through the additive source catalog. The explicit
host-owned build path revalidates the exact clean commit, canonical source tree, lockfile, pinned
toolchain, target, and fixed recipe. It prepares locked public dependencies without credentials,
compiles offline in a bounded Linux scope, validates separate binary and package identities, and
atomically installs outside Git in the disabled state. Interrupted or failed attempts retain their
records and never displace a prior installed selection.

Phase 5 adds a Rust-owned campaign coordinator. It performs one bounded inventory, routes every
supported family, gives the canonical skill directly to separate discovery and skeptic contexts,
registers falsifiable hypotheses before execution, and schedules only exact host-owned contained
probes. Models receive module functions over retained source and evidence, not ambient filesystem or
process tools. Exact observations, provider/model routes, steering, reuse measurements, hypotheses,
probe inputs, host receipts, reviews and classifications survive provider-context renewal and
process restart. Pause, Resume, Steer and Report now are native module actions.

Phase 6 advances confirmed findings without asking for per-stage approval. A fixer proposes an exact
preimage-bound root-cause replacement and four-category replay matrix. The host constructs the
unified diff, materializes the replacement only in private disposable job storage, preserves its
own canary and evaluator, and requires both nondisclosure and declared legitimate output. Attack,
legitimate, malformed, and adjacent cases retain separate receipts. An independent reviewer sees
the exact diff and raw host receipts and rejects hollow implementations, feature disabling,
detector suppression, changed proof requirements, hard-coded case handling, unrelated edits, or
unmet prerequisites. A final host pass rereads all included original-project bytes and executable
bits against the starting snapshot. Markdown, JSON, exact patch files, and a machine-readable replay
bundle are published from durable state; no patch is applied to the selected original checkout.

Phase 7 integrates that engine into both ordinary human interfaces. The module publishes a generic,
exact-run action menu plus bounded progress, a Markdown summary, and the identity of the latest
user-selected export. The host durably merges progress without erasing actions or artifacts. The
TUI exposes every action with keyboard navigation instead of silently limiting the menu to nine;
the WebUI renders the same progress, formatted summary, exact action set, export byte count,
SHA-256, and stable local path. Client and daemon restart reopen the same projection and campaign
records rather than republishing work. Findings and exact copy-only diffs are explicit actions, and
their output remains part of the ordinary conversation transcript.

Phase 8 hardens the integrated path against hostile repositories and deceptive targets. The saved
corpus now covers target-authored prompt injection and forged success, unrelated crashes, host-file,
network, home-directory and credential-environment probes, deadline enforcement, descendant
cancellation, and memory, process and storage pressure. Final acceptance is based on real TUI and
WebUI operation, daemon/client restart, corrupted-state rejection, source-build installation from a
clean catalog checkout, a copied complex Rust browser repository, and an A1–A14 evidence ledger.
The campaign deliberately leaves unsupported adapters and unexamined families visible; publication
does not turn a bounded Linux sample into a universal security claim.

The MIT-licensed corpus contains two genuine vulnerable/safe executable pairs plus forged-success,
prompt-injection, unrelated-crash, boundary, lifecycle, and resource-pressure controls. They
exercise the actual canary-disclosure interface: the host
selects the target, generates the hidden value and evaluates stdout independently. This establishes
only the exercised cases. Unexamined families remain gaps; an unsuccessful probe never becomes a
clean result. Findings and patches keep confirmed, analysis-supported, refuted, not-reproduced,
inconclusive, blocked, proposed, applied-to-copy, validated-for-recorded-cases, and failed states
distinct. A validated patch is still bounded to its retained cases and is only handed back as an
artifact; application, commit, push, deployment, disclosure, and issue creation stay separate.

`module.toml.in` is a source-build template, not an installable package. The module remains absent
from legacy `market.toml` and is discovered by current clients through `sources.toml`. Do not commit
generated executables, packages, build caches, campaign data, or transcripts for this module.
