# Deep Research

An installable, read-only research workflow for Peritus. It uses your selected writer
for planning, gathering and synthesis, and your selected reviewer for skepticism and
final fact-checking. No extra research account, paid search API, Docker or Python is
needed. Native search and ordinary HTML/text reading run in the host.

1. Select **Use module** and enter `/research YOUR QUESTION`.
2. Answer material questions with `/research revise DETAILS`, or review `/research plan`.
3. Approve that exact saved plan using **Start research** or `/research start PLAN_DIGEST`.
4. The gatherer collects original passages; the skeptic admits, qualifies or rejects
   them; synthesis writes from admitted evidence; a fresh skeptic checks the actual
   report. Corrections return to synthesis and another check before presentation.
5. Inspect `/research status`, `/research sources` or `/research show [BYTE_OFFSET]`.
   Stop retains the ledger and checkpoints; `/research resume` continues committed work.
6. `/research use-in-design` attaches the exact checked report to the conversation's
   Design context. It does not start implementation or alter project files.

The terminal market's `s` key starts the displayed saved plan; the GUI offers the
same Start button. A stale plan digest is rejected. Material unanswered clarification
questions prevent Start. Preparation has no web tools and cannot start gathering.

Evidence admission follows [the policy](resources/source-policy.md). Unvetted blogs,
SEO, social posts, aggregators and AI summaries stay discovery-only. Claims include
their qualifications, original evidence chain, source URL and exact retained passage.
Question coverage can honestly finish as unknown; missing evidence is never positive
evidence of absence. All agents remain fallible; source-checking is not a truth guarantee.

Private state is retained beside the owning Peritus run: approved plan, actual read
observations, candidates, admissions, gaps, drafts and digest-bound checks. It stays
off the project filesystem and survives fresh clients and daemon restart. No unit or
repository verification pipeline is used by this module.

Text-bearing PDF and script-rendering availability follows the installed host's web
reader capabilities. Unsupported/scanned/blocked sources are visible limitations;
prefer authoritative HTML equivalents when available. Multi-hour and native-platform
testing claims belong in observed evidence, not in this package's promises.
