# Evidence states

| State | Required meaning |
| --- | --- |
| Confirmed | A valid scenario reaches the exact scoped target and demonstrates the specified security-property violation with trusted execution evidence and independent review. |
| Analysis-supported | Concrete source or configuration evidence supports the weakness, but the claimed runtime effect has not been demonstrated. |
| Refuted | Counterevidence disproves a necessary premise for the bound source and configuration. It does not generalize beyond that claim. |
| Not reproduced | Legal attempts ran without demonstrating the claimed violation. The broader question remains open. |
| Inconclusive | Available observations do not settle the claim or its impact. |
| Blocked | A named prerequisite, permission, dependency, environment, or supported execution backend prevented the required investigation. |

Trusted evidence binds the intended observation and actual result to source, target, configuration,
input/action sequence, oracle, and controller identities. Model prose, printed success markers,
unrelated crashes, invalid scenarios, and setup failures cannot manufacture confirmation.
