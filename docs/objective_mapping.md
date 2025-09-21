# Objective Mapping Rules

The objective mapper evaluates every DO-178C Annex A objective defined in
`data/objectives/do178c_objectives.min.json`. Each objective declares:

- `table`, `name`, and `desc` values describing its origin (A-3 … A-7) and
  intent.
- A `levels` applicability matrix indicating which certification levels (A–E)
  must satisfy the objective.
- An `independence` hint (`none`, `recommended`, or `required`).
- A list of required artifact types. The canonical artifact vocabulary is:

  `plan`, `standard`, `review`, `analysis`, `test`, `coverage_stmt`,
  `coverage_dec`, `coverage_mcdc`, `trace`, `cm_record`, `qa_record`,
  `problem_report`, `conformity`.

The mapper inspects the bundle's `evidenceIndex` for each artifact type. The
resulting coverage status follows these rules:

| Condition | Status | Notes |
| --- | --- | --- |
| Every required artifact type has at least one matching evidence entry | `covered` | Evidence references are recorded as `<artifactType>:<path>` strings. |
| Some artifact types have evidence but others are missing | `partial` | Gap analysis groups the missing artifacts by category (plans, reviews, coverage, configuration, etc.). |
| None of the required artifacts are present | `missing` | The objective is reported as missing and highlighted in every relevant gap bucket. |

## Example

Consider the following fragment from an `ImportBundle` that represents one
Level A verification objective:

```ts
const bundle = {
  objectives: [
    {
      id: 'A-5-06',
      table: 'A-5',
      name: 'Test Stratejisi Uygulandı',
      desc: 'Gereksinim-tabanlı testler koşuldu; sonuçlar kaydedildi.',
      artifacts: ['test', 'trace', 'analysis'],
      levels: { A: true, B: true, C: true, D: true, E: false },
      independence: 'required',
    },
  ],
  evidenceIndex: {
    test: [
      { source: 'junit', path: 'reports/junit.xml', summary: 'Test yürütmesi', timestamp: '2024-01-10T10:00:00Z' },
    ],
    trace: [
      { source: 'git', path: 'artifacts/trace-map.csv', summary: 'İzlenebilirlik matrisi', timestamp: '2024-01-10T10:00:00Z' },
    ],
    analysis: [
      { source: 'other', path: 'reports/safety-analysis.pdf', summary: 'Güvenlik analizi', timestamp: '2024-01-10T10:00:00Z' },
    ],
  },
};
```

The mapper produces the following `ObjectiveCoverage` entry:

```json
{
  "objectiveId": "A-5-06",
  "status": "covered",
  "evidenceRefs": [
    "test:reports/junit.xml",
    "trace:artifacts/trace-map.csv",
    "analysis:reports/safety-analysis.pdf"
  ],
  "satisfiedArtifacts": ["test", "trace", "analysis"],
  "missingArtifacts": []
}
```

If the trace artifact were missing, the status would change to `partial` and
`missingArtifacts` would include `trace`. This information feeds the gap
analysis, which now exposes separate buckets for plans, reviews, analysis,
tests, coverage, traceability, configuration management, quality assurance,
problem tracking, and conformity evidence so remediation can be assigned to the
right teams.
