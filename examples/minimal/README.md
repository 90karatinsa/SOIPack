# Minimal Workspace Scenarios

The demo workspace ships three ready-to-run configurations so you can exercise
the full DO-178C objective catalog at different certification levels:

| Scenario | Config File | Notes |
| --- | --- | --- |
| Level A | `soipack.levelA.config.yaml` | Enables objectives such as `A-5-10` (MC/DC) that only apply to Level A projects. |
| Level B | `soipack.levelB.config.yaml` | Includes structural coverage down to decision coverage (`A-5-09`) while skipping MC/DC. |
| Level C | `soipack.config.yaml` | Focuses on high/low level requirement verification without structural coverage objectives beyond statement level. |

All scenarios reference the canonical objective catalog at
`data/objectives/do178c_objectives.min.json`. You can inspect the translated
catalog directly with `npm run --workspace @soipack/cli build` followed by
`node packages/cli/dist/index.js objectives list --license data/licenses/demo-license.key`.
The artifact map was updated to
match the new evidence vocabulary (`plan`, `analysis`, `test`, `trace`,
`coverage_stmt`, `cm_record`, …). You can run a scenario with the CLI:

```bash
npm run demo -- --config examples/minimal/soipack.levelA.config.yaml
```

The generated reports in `dist/level-*/reports` will highlight which Annex A
objectives are covered, partially satisfied, or still missing evidence.

## Static Analysis Fixtures

The minimal workspace now bundles example outputs for the Polyspace, LDRA and
VectorCAST adapters:

- `polyspace/report.json` – static analysis findings with justification
  statuses.
- `ldra/tbvision.json` – rule violations plus statement coverage extracted from
  LDRA unit test runs.
- `vectorcast/coverage.json` – decision and MC/DC coverage with VectorCAST test
  observations.

When you run the Level A/B/C scenarios the resulting `workspace.json` includes
these findings under the `findings` array and structural coverage metrics under
`structuralCoverage`. The `EXPECTED/target_comparison.json` file captures how
coverage objectives evaluate across levels for the demo data set.
