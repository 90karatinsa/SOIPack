# Minimal Workspace Scenarios

The demo workspace ships three ready-to-run configurations so you can exercise
the full DO-178C objective catalog at different certification levels:

| Scenario | Config File | Notes |
| --- | --- | --- |
| Level A | `soipack.levelA.config.yaml` | Enables objectives such as `A-5-10` (MC/DC) that only apply to Level A projects. |
| Level B | `soipack.levelB.config.yaml` | Includes structural coverage down to decision coverage (`A-5-09`) while skipping MC/DC. |
| Level C | `soipack.config.yaml` | Focuses on high/low level requirement verification without structural coverage objectives beyond statement level. |

All scenarios reference the canonical objective catalog at
`data/objectives/do178c_objectives.min.json`. The artifact map was updated to
match the new evidence vocabulary (`plan`, `analysis`, `test`, `trace`,
`coverage_stmt`, `cm_record`, …). You can run a scenario with the CLI:

```bash
npm run demo -- --config examples/minimal/soipack.levelA.config.yaml
```

The generated reports in `dist/level-*/reports` will highlight which Annex A
objectives are covered, partially satisfied, or still missing evidence.
