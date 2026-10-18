# Deep Research — native Rust plugin

The implementation is in `src/coordinator.rs`, `src/ledger.rs`, and `src/definitions.rs`.
`src/main.rs` is the native IPC executable. `workflow.toml` is internal configuration
compiled into this plugin; Peritus does not interpret it or implement these stages.

Select **Use module** and enter a research topic, or send:

```text
/module peritus.deep-research YOUR QUESTION
```

The planner saves substantive answer criteria and evidence needs as well as scope and material clarifications. Review **View plan**, revise
when needed, and select **Start research**. Preparation has no network tools. Start
binds the exact plan digest; resume cannot silently approve a plan.

The Rust coordinator then runs a gatherer, an independent skeptic, a synthesis agent,
and a final skeptic pass. Original-source passages, claim-specific admission decisions,
independence chains, uncertainty, report versions, and exact-report checks persist in
private plugin state. Unvetted blogs and generated summaries are discovery leads, not support.
Original investigations with assessable methods can support attributed allegations; original
scholarly arguments are assessed within their assumptions. Neither counts as adjudicated fact
merely because its publisher is prominent.
Synthesis sees admitted/qualified evidence, and the final skeptic must inspect the
actual report and reread its cited passages. Structural checks support this process;
they cannot guarantee semantic truth. Honest insufficient-evidence reports are valid.

The skeptic independently searches for missing perspectives and can return concrete gaps to
the gatherer without changing the approved plan or discarding evidence. Final checking saves
a judgment for each citation against the exact report digest. Progress distinguishes source
reads from actual judgments; completed checks remain durable across context reconstruction.
Successful stage commits yield directly to the coordinator rather than waiting for extra prose.
The investigation maintains an evolving explanation: supporting and contrary evidence,
source relationships/dependencies, material uncertainty and useful next actions. The skeptic
challenges that explanation, rather than merely certifying quoted sentences. Source provenance
distinguishes subject, affiliated, external and unclear relationships and identifies what was
actually checked. An organization's response remains its own account when quoted in journalism.
Qualified self-reports alone cannot answer an independent-assessment question about conduct,
funding/control or outcomes. Primary evidence is proximity to events/data, not a preference for
the subject's website. Source interests require claim-specific assessment, not automatic dismissal.

Coverage accounts for every substantive criterion in the approved plan. Genuinely unavailable
facts retain specific gaps with actual alternative search attempts; caveats are not substitutes
for an answerable investigation. Report length is presentation, not an investigation budget.
Conclusions connect observations to public reasoning, alternatives and calibrated uncertainty.
A followup targets what could change a material answer; optional unrelated enrichment does not
restart the whole inquiry. The reviewer may reject a deficient explanation early without
pretending unchecked citations were checked. Approval still checks every actual citation and
records a separate inquiry assessment. These structures improve inspectability, not certainty.

Actions include plan, revise, status, sources, show, evidence NUMBER, inquiry, resume, reassess,
and Use in Design. Inquiry exposes the current explanatory model and unanswered criteria.
The primary report has a concise source list; exact passages and assessment details are opened
separately with evidence NUMBER.
Stop uses Peritus's normal control. Completed stages survive daemon restart. Show and
source lists are paged; following a continuation does not start a new research job.
Use in Design attaches the exact checked report as reference without launching coding.

Legacy approved-plan identities and evidence remain readable. Earlier source-check approvals
are not inherited as current independent-inquiry approval; reassess reopens assessment against
the same approved question. It preserves useful observations and immutable historical reports.
Package-digest state directories remain isolated; this is not automatic cross-package migration.

Build from this repository root with `cargo build --locked --release --jobs 2 -p
peritus-deep-research`; package with `python3 scripts/package.py deep-research --skip-build`.
The supplied executable is Linux x86-64 GNU. Other native targets require their own
artifact. Provider access reuses Peritus; no separate research API account is required.
The native web reader's unsupported PDF/scanned/script-generated content remains a
limitation; the plugin must report it, not fabricate extracted evidence.

### Delivery and stopping

Draft from a useful vetted subset instead of clearing the discovery queue. Approved questions
remain the inquiry map; nonessential criteria can be explicitly deferred without claiming that
they were exhaustively investigated. Such questions remain partial or unknown. Relevant current
evidence can support several questions when the explanation establishes relevance.

`finish` (also available in the menu) requests a report from retained evidence. It preserves
source reads and final citation checks while disabling new searches, opens and follow-up agendas.
`reassess` explicitly reopens investigation. The final reviewer checks the actual explanation
and exact cited passages; deferred detail never becomes fabricated certainty.

Compact `admission_index` and `candidate_index` ledger views support source selection without
repeating every quotation and provenance record. Selected `research_item` details retain exact
scope and evidence. Full historical inspection pages remain available.

### Controversy research

A dedicated agent searches live for consequential criticism and controversies before skeptical assessment. Reports include a separate **Controversies and criticism** section presenting specific accusations, attribution, responses and documented outcomes. The roles verify source attribution; they do not decide guilt or require proof of an allegation before reporting its existence. `/module peritus.deep-research remake DETAILS` reuses saved evidence and starts this targeted pass. Draft corrections can be incremental, and rejected attempts remain saved.

### Continuous, steerable research

Normal research is the default. Select **Start Sicko mode** or send
`/module peritus.deep-research sicko` to keep researching the approved topic. Checked
report checkpoints are presented while research continues; no cumulative token, time,
source or round budget stops the mode. Per-operation resource bounds and cancellation remain.
This version needs the updated Peritus host with continuing checkpoint support.

- `steer DETAILS` changes the current direction without discarding evidence or changing the
  approved plan. Older directions remain journaled on disk.
- `pause` saves the stage and mode; `resume` continues them, including after restart.
- `normal` pauses and disables continuous research. Resume then follows the ordinary workflow.
- `finish` disables continuous research and requests a report from current evidence.
- `checkpoint [REPORT_DIGEST] [BYTE_OFFSET]` reads the latest completed report even while newer research
  is unfinished. **Use latest checked report in Design** attaches those exact saved bytes.

The module menu provides the same controls in GUI and TUI. **Steer research** prepares an
editable command; it does not silently submit a direction. The source policy still applies:
controversy research identifies accusations and responses, not guilt verdicts. Original
statements establish attribution only; uncertain relationships to the subject remain uncertain.

Checkpoint page continuations and evidence commands carry an exact report digest, so new
reports cannot change an older page sequence or the meaning of its numbered sources.

Read-only status/report/source inspection during active Sicko mode publishes its answer
and continues the retained stage. Design reuse is an explicit handoff: it pauses continuous
research while attaching the immutable report; **Resume research** continues it afterward.
