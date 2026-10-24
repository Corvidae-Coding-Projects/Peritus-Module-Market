# Peritus Red Team

Source-only Rust module for authorized defensive investigation of an explicitly selected application.
The canonical product design is [../../.design/red-team.md](../../.design/red-team.md), and the phased
implementation plan is [../../.design/red-team-phases.md](../../.design/red-team-phases.md).

Phases 1 through 5 implement the native skeleton, canonical skill, versioned host-service envelope,
capability discovery, version-one record identities, and a schema-five durable campaign checkpoint.
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

The initial MIT-licensed corpus contains two genuine vulnerable/safe executable pairs plus forged
success and unrelated-crash controls. They exercise the actual canary-disclosure interface: the host
selects the target, generates the hidden value and evaluates stdout independently. This establishes
only the exercised cases. Unexamined families remain gaps; an unsuccessful probe never becomes a
clean result. Phase 5 classifies confirmed, analysis-supported, refuted, not-reproduced,
inconclusive and blocked claims, but does not create or apply fixes. Patch work remains Phase 6.

`module.toml.in` is a source-build template, not an installable package. The module remains absent
from legacy `market.toml` and is discovered by current clients through `sources.toml`. Do not commit
generated executables, packages, build caches, campaign data, or transcripts for this module.
