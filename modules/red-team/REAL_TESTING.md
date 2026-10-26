# Red Team real-interface evidence

## 2026-10-26 generic application campaign

The `0.17.0` module executable was driven through its real native worker boundary against
disposable application copies. No unit-test or mock target was used.

| Target | Runtime | Executed result |
| --- | --- | --- |
| `/home/doll/flt/Comms` disposable copy | Bun | 15 operations: 12 raw HTTP exchanges and 3 Chromium actions; all seven common surfaces retained; eight security families exercised; zero gaps; complete process cleanup. |
| Minimal framework-neutral Bun service | Bun | 15 operations: 13 raw HTTP exchanges and 2 Chromium actions; all seven common surfaces retained; zero gaps; complete process cleanup. |
| Minimal plain Node service launched through `npm run start` | Node/npm | 15 operations: 13 raw HTTP exchanges and 2 Chromium actions; all seven common surfaces retained; zero gaps; complete process cleanup. |

The seven required surface receipts were `http_api`, `browser_client`, `identity_access`,
`file_parser`, `workflow_state`, `boundary_authority`, and `attack_graph`. Generic campaigns used
source-discovered routes plus bounded common fallbacks. Responses without an independent contract
were retained as observations rather than promoted to findings.

For a failure oracle, a second disposable Comms copy had its adapter-identity rejection disabled.
The final executable detected both the direct broker adapter-confusion failure and the resulting
cross-surface authority chain as runtime-confirmed high-severity findings. The unmodified disposable
copy produced no findings under the same 15 operations. The original Comms checkout was not
modified; its pre-existing working-tree entries remained byte-for-byte outside the campaign.

Retained local replay outputs:

- `/tmp/peritus-comms-common-surfaces.json`
- `/tmp/peritus-comms-mutant-common-surfaces.json`
- `/tmp/peritus-generic-bun-surfaces.json`
- `/tmp/peritus-generic-node-surfaces.json`

These results are bounded to the listed applications, versions, operations, and oracles. They do
not claim exhaustive security coverage.
