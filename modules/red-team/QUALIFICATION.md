# Red Team autonomous exploit-research qualification

Version 0.25.0 completes Stage 8 qualification and enables the Stage 2–7 research path only inside
the bounded profile below. This is an installed-product qualification boundary, not a claim that
an application is secure, that every exploit class is covered, or that the module matches a human
red team.

## Supported profile

| Boundary | Qualified value |
| --- | --- |
| Host platform | Linux x86-64 GNU |
| Module transport | Native module ABI 1, four-byte framed IPC |
| Clients | Installed Peritus TUI and source-built single-user localhost WebUI |
| Target | Selected ordinary source plus disposable private copies; the complete Stage 4–7 path is qualified for the checked-in hidden Python vulnerable/safe application pair |
| Primitive adapters | `source.scan.v1`, `http.campaign.v1`, and `browser.campaign.v1` |
| Chain workers | `research-chain.confirm.v1` and `research-chain.repair.v1` through the registered attack-graph adapter |
| Source services | Immutable scoped-source capture, manifest, read, refresh, revoke, and final byte verification |
| Browser | Managed Chromium/Chrome with a fresh context and a private Unix target transport |
| Identity | Literal synthetic `ordinary-user:credential-free`; no ambient credential or personal profile |
| Network | Private worker/laboratory transport only during proof; no public callback or disclosure transport |
| Default Stage 4 bounds | 12 model turns, 8 experiments, cost 16; one host operation at a time |
| Default graph bounds | 256 nodes, 512 edges, depth 6, 128 open candidates, zero cycles, cost 12 |
| Stage 5/6 bounds | Fixed action, request, mutation, artifact, process, memory, storage, CPU, and deadline limits enforced by the module and host |
| Artifacts | Module-private directories mode `0700`, files mode `0600`, content identities retained in bounded state |

The configured writer and reviewer routes may use different provider/model identities. Provider
prose remains untrusted: Rust validates the closed operation, target, identity, authority, budget,
receipt, oracle, and disposition. Provider loss, timeout, or resource failure retains an incomplete
terminal fact and admits no partial primitive.

## Acceptance boundary

- A hidden vulnerable target produced receipt-backed source, HTTP, and browser primitives and a
  compatibility-discovered chain. Invented authority, temporal-only, stale-target, forged-output,
  and prompt-injected paths did not become supported evidence.
- Fresh full-chain, removed-prerequisite, and safe-twin replays preceded confirmation. The emitted
  PoC then reproduced only its harmless canary on a fresh vulnerable twin outside Peritus, reported
  no signal on the safe twin, rejected a non-private destination before launch, cleaned up, and
  preserved target bytes.
- The exact-preimage copy-only repair blocked the PoC and full chain across the registered
  legitimate, malformed, adjacent, adapter, counterfactual, and bounded mutation matrix. The
  independent reviewer rejected feature disabling, oracle suppression, safe-fixture substitution,
  and patching only a later symptom.
- The private package contains advisory JSON and Markdown, PoCs, evidence identities, exact patch,
  regression matrix, channel templates, redaction review, export manifest, and a no-delivery
  receipt. A source-scoped contact is retained with its exact quoted line and provenance; absent
  contact remains unresolved instead of guessed.
- Installed TUI and WebUI clients expose the same module command/action projection. Pause/resume,
  restart, steering, cancellation, provider loss, timeout, resource failure, migration, corrupt
  state, refresh invalidation, idempotent export, and original-source preservation have bounded
  actual-interface evidence.

## Explicit gaps

- macOS, Windows, non-GNU Linux, and non-x86-64 builds are not qualified by this run.
- Arbitrary products, non-Python Stage 5/6 targets, other browser engines, remote services, LAN or
  public endpoints, production identities, destructive effects, persistence, propagation,
  credential access, and exploit impacts beyond the harmless canary are unsupported or explicit
  gaps.
- Emulation recipes are inert public-knowledge hypotheses. They contain no executable incident
  content and create no finding, primitive, edge, or target effect without independent receipts
  from the exact selected target.
- Product name, component, affected release range, discovery date, workarounds, embargo, vendor
  acknowledgement, CNA, and CVE facts remain placeholders unless separately verified.
- Email, portal, repository issue, CNA/CVE request, publication, deployment, and patch application
  are not module operations. Local export grants no transport authority.

Use `research-qualification` to reopen this matrix. Unsupported combinations remain blocked or
visible as gaps; they do not silently fall back to a weaker adapter, target, identity, provider, or
authority.
